#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""E2E test of record for AdrenoMetal's draw packages (design S3 plug-in side, WP4.3). No A16, no GPU submission.

A real AdrenoMetal.bundle (built with its qualified compiler runtime) is driven through the public Metal API by
gpu/adreno-kext/plugin/harness/native-texture.m on the host AGX provider: an IOSurface-backed 37x23 BGRA8 target
(1024-byte rows, 32 KiB, every byte seeded 0x69), a real air2ir3 render pipeline, render passes (Clear or Load) and
draws, then the plug-in's own commit with only -[IOGPUMetalCommandBuffer commit] replaced by a capture of the
reserved kernel commands. Each capture is checked three ways:

 1. package: the rules compat/adreno-submit.h states for ADRENO_KCMD_IB (header, sizes, zero padding, relocation
    kind/access/alignment/placeholders/distinct targets/bounds, RESOURCE accesses within the published usage) and
    the kext validator's address rule (design 3.3): every address register and UBO descriptor / index base in the
    IB is relocated (both halves, the high half being the same field's second dword) or zero, and the GPU-written
    targets (RB_MRT_BASE, RB_A2D_DEST_BUFFER_BASE) carry WRITE. Kernel commands keep encoder order: FILL32s
    recorded before a render pass precede its package, the fence is last.
 2. plan: with each relocation resolved to the address the plan used for the same object, the IB equals q1n1's
    builder output dword for dword: the committed offline plans (tools/plan-adreno-native-triangle.py
    draw-plan-v2 / draw-plan-varyings-v1, hash-verified) or, for the uniforms scene, a16gpu_render.build_ib run
    here on the captured programs with the plan tool's own adapter. Documented differences (design S3): no
    trailing batch fence (emit_ib_fence), and a Clear pass carries build_p7_ib's sysmem 2D-clear block, generated
    by q1n1's own emit_flushes/emit_2d_clear, before RB_RENDER_CNTL. Several draws repeat the draw section;
    several passes concatenate. Relocated objects are checked by identity and content.
 3. model: q1n1's CP/SMMU/cache model (tools/test-a16gpu-render.py FakeRender) runs the package through the
    `render` command's own path (tables, uploads, a7xx ring words, IB fetch through CB0, register allowlist, draw
    state checks incl. UBO contents and blend state, fence, readback, tolerance compare, guard bands) and must
    reproduce the host AGX golden of the same scene. The model cannot execute ir3: when the state is right it
    writes the golden, so this leg proves state and addressing, not shading. Added here: the target as the draw
    sees it must already hold the clear colour (Clear) or the seed (Load), and a driver constant-data UBO must
    point at the code's constant data.
Plus: instanced, UInt16-indexed and multi-draw packets, encoder order with blit fills, two passes, and the refusal
without the kext's IB ABI.

  python3 tools/test-adreno-draw-package.py --bundle BUNDLE --output NEW-DIR [--harness native-texture]
"""
from __future__ import annotations

import argparse
import collections
import contextlib
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
Q = ROOT.parent / 'q1n1' / 'tools'
PLANS = ROOT / 'build/adreno-pipeline-compiler-20260927'
HARNESS_SOURCE = ROOT / 'gpu/adreno-kext/plugin/harness/native-texture.m'
Geometry = collections.namedtuple('Geometry', 'w h pitch allocation')
DEFAULT = Geometry(37, 23, 1024, 32768)      # the S5 / offline-plan target: 1024-byte rows, 32 KiB
LARGE = Geometry(1024, 512, 4096, 2 << 20)   # large enough for a non-trivial guardband on both axes
FILL_BYTES = 256
CLEAR = (0.25, 0.5, 0.75, 1.0)
NO_HI = 0xFFFFFFFF
REFUSAL = "Adreno shader draws need the kext's IB ABI (AdrenoIBABI = 1), which this accelerator does not publish"
# harness uniforms scene: vertex_id positions (setVertexBytes buffer(1)), fragment tint MTLBuffer at buffer(0)
POINTS = struct.pack('<12f', -0.6, -0.7, 0, 0, 0.7, -0.5, 0, 0, 0.0, 0.8, 0, 0)
POINTS2 = struct.pack('<12f', -0.5, 0.6, 0, 0, 0.6, 0.7, 0, 0, 0.1, -0.8, 0, 0)      # passes after the first
TINT = struct.pack('<4f', 0.9, 0.8, 0.7, 0.75)
PREMULTIPLIED_OVER = {'enabled': True, 'rgb_op': 'add', 'alpha_op': 'add', 'src_rgb': 'one', 'src_alpha': 'one',
                      'dst_rgb': 'one_minus_source_alpha', 'dst_alpha': 'one_minus_source_alpha'}
sha = lambda data: hashlib.sha256(data).hexdigest()

sys.path.insert(0, str(Q))
import adreno_x2 as R          # noqa: E402
import a8xx_regs as X          # noqa: E402
import a16gpu_p6p7 as M        # noqa: E402
import a16gpu_render as RD     # noqa: E402

PLAN = RD.plan                 # q1n1's own layout planner (model_run points RD.plan at a wrapper of it)

# NDC vertices of each source: the model's edge pixels.
NDC = {'plan-v2': [(-0.5, -0.5), (0.5, -0.5), (0.0, 0.5)], 'varyings': [(-0.5, -0.5), (0.5, -0.5), (0.0, 0.5)],
       'uniforms': [(-0.6, -0.7), (0.7, -0.5), (0.0, 0.8)], 'device': [(-0.6, -0.7), (0.7, -0.5), (0.0, 0.8)]}


class Fail(Exception):
    pass


def need(condition, what):
    if not condition:
        raise Fail(what)


# ------------------------------------------------------------------------------------------------------------------
# Kernel commands and the ADRENO_KCMD_IB package (compat/adreno-submit.h)
# ------------------------------------------------------------------------------------------------------------------
def kernel_commands(blob):
    out, at = [], 0
    while at < len(blob):
        need(at + 8 <= len(blob), 'truncated kernel command header')
        kind, size = struct.unpack_from('<II', blob, at)
        need(size >= 8 and size % 4 == 0 and at + size <= len(blob), f'kernel command {kind:#x} size {size}')
        out.append((kind, blob[at:at + size]))
        at += size
    return out


def align64(v):
    return (v + 63) & ~63


def parse_package(cmd):
    kind, size, version, flags, ib_dwords, data_bytes, nrel, res0, res1a, res1b = struct.unpack_from('<IIIIIIIIQQ', cmd, 0)
    need(kind == 0x1002 and size == len(cmd), 'ADRENO_KCMD_IB header')
    need(version == 1 and flags == 0 and res0 == 0 and res1a == 0 and res1b == 0, 'version/flags/reserved')
    need(1 <= ib_dwords <= 0x40000 and data_bytes % 64 == 0 and data_bytes <= 0x100000 and nrel <= 16384, 'limits')
    data_off = align64(4 * ib_dwords)
    package_bytes = data_off + data_bytes
    need(size == 48 + package_bytes + 32 * nrel, 'command size = 48 + P + 32 * relocs')
    package = bytearray(cmd[48:48 + package_bytes])
    need(not any(package[4 * ib_dwords:data_off]), 'IB padding is zero')
    relocs = []
    for i in range(nrel):
        lo, hi, rkind, access, align, hi_bits, rid, offset, length = struct.unpack_from('<IIBBBBIQQ', cmd, 48 + package_bytes + 32 * i)
        relocs.append(dict(lo=lo, hi=hi, kind=rkind, access=access, align=align, hi_bits=hi_bits, resource_id=rid,
                           offset=offset, length=length))
    return dict(ib_dwords=ib_dwords, data_bytes=data_bytes, data_offset=data_off, package=package, relocs=relocs,
                command=bytes(cmd))


def check_relocs(pkg, published):
    """compat/adreno-submit.h relocation rules; published: {resource id: (usage, size)}."""
    package, P = pkg['package'], len(pkg['package'])
    targets = set()
    for i, r in enumerate(pkg['relocs']):
        what = f'reloc {i}'
        need(r['kind'] in (1, 2, 3), f'{what}: kind')
        need(r['access'] and not r['access'] & ~3, f'{what}: access')
        need(r['length'] > 0 and r['align'] <= 12, f'{what}: length/alignment')
        need(r['offset'] % (1 << r['align']) == 0, f'{what}: offset alignment')
        for half in ('lo', 'hi'):
            at = r[half]
            if half == 'hi' and at == NO_HI:
                continue
            need(at % 4 == 0 and at + 4 <= P and at not in targets, f'{what}: {half} target {at:#x}')
            targets.add(at)
        need(struct.unpack_from('<I', package, r['lo'])[0] & ~((1 << r['align']) - 1) == 0, f'{what}: lo placeholder')
        if r['hi'] != NO_HI:
            need(1 <= r['hi_bits'] <= 32, f'{what}: hi_bits')
            need(struct.unpack_from('<I', package, r['hi'])[0] & ((1 << r['hi_bits']) - 1) == 0, f'{what}: hi placeholder')
        if r['kind'] == 1:
            need(r['resource_id'] in published, f'{what}: resource {r["resource_id"]} is not in the published list')
            usage, size = published[r['resource_id']]
            need(not (r['access'] & 1) or usage & (1 | 4), f'{what}: READ outside the published usage')
            need(not (r['access'] & 2) or usage & 2, f'{what}: WRITE outside the published usage')
            need(r['offset'] + r['length'] <= size, f'{what}: extent beyond the resource')
        else:
            need(r['resource_id'] == 0 and r['access'] == 1, f'{what}: package/zero relocations are read-only, no ID')
            limit = P if r['kind'] == 2 else 0x4000
            need(r['offset'] + r['length'] <= limit, f'{what}: extent beyond the package/zero page')
    return len(targets)


# IB structure: which dword is which register value / packet payload.
ADDR64 = {}
for _name, (_off, _bits, _fields, _stride, _len) in X.REGS.items():
    if _bits == 64 and any(f[4] in ('address', 'waddress') for f in _fields):
        for _i in range(_len):
            ADDR64[_off + _i * _stride] = _name
GPU_WRITTEN = {X.REGS['RB_MRT_BASE'][0] + i * X.REGS['RB_MRT_BASE'][3] for i in range(8)} | {X.REGS['RB_A2D_DEST_BUFFER_BASE'][0]}


def walk_ib(words):
    """[(dword index of a register value, register offset)] and [(packet opcode, payload start, payload)]."""
    regs, packets, i = [], [], 0
    while i < len(words):
        h = words[i]
        if h >> 28 == 4:
            cnt, off = h & 0x7F, (h >> 8) & 0x3FFFF
            need(M.pkt4_header(off, cnt) == h and i + 1 + cnt <= len(words), f'PKT4 header at {i}')
            regs += [(i + 1 + k, off + k) for k in range(cnt)]
            i += 1 + cnt
            continue
        cnt, op = h & 0x3FFF, (h >> 16) & 0x7F
        need(h >> 28 == 7 and R.pkt7(op, cnt) == h and i + 1 + cnt <= len(words), f'PKT7 header at {i}')
        body = words[i + 1:i + 1 + cnt]
        if op == R.CP_CONTEXT_REG_BUNCH:
            regs += [(i + 2 + 2 * k, body[2 * k]) for k in range(cnt // 2)]
        elif op == R.CP_NON_CONTEXT_REG_BUNCH:
            need(body[:2] == [1, 0], 'NCRB header')
            regs += [(i + 4 + 2 * k, body[2 + 2 * k]) for k in range(cnt // 2 - 1)]
        packets.append((op, i + 1, body))
        i += 1 + cnt
    return regs, packets


def ib_words(pkg):
    return list(struct.unpack_from(f'<{pkg["ib_dwords"]}I', pkg['package'], 0))


def check_addresses(pkg):
    """Design 3.3's address rule on the IB, and each relocation's high half = the same field's second dword."""
    words = ib_words(pkg)
    regs, packets = walk_ib(words)
    by_lo = {r['lo']: r for r in pkg['relocs'] if r['lo'] < 4 * pkg['ib_dwords']}
    value_at = {pos: off for pos, off in regs}
    checked = set()
    for pos, off in regs:
        if off not in ADDR64:
            continue
        # the high dword is the next register value of the same packet: +2 in a (reg, value) bunch, +1 in a PKT4
        hi_pos = next((p for p in (pos + 2, pos + 1) if value_at.get(p) == off + 1), None)
        need(hi_pos is not None, f'{ADDR64[off]}: no high dword next to the low one')
        r = by_lo.get(4 * pos)
        if r is None:
            need(words[pos] == 0 and words[hi_pos] == 0, f'{ADDR64[off]} carries an address without a relocation')
            continue
        need(r['hi'] == 4 * hi_pos and r['hi_bits'] == 32, f'{ADDR64[off]}: high half is not the register\'s second dword')
        if off in GPU_WRITTEN:
            need(r['access'] & 2, f'{ADDR64[off]} is GPU-written but relocated without WRITE')
        checked.add(r['lo'])
    for op, start, body in packets:
        if op in (R.CP_LOAD_STATE6_GEOM, R.CP_LOAD_STATE6_FRAG):
            w0 = body[0]
            stype, src, n = (w0 >> 14) & 3, (w0 >> 16) & 3, w0 >> 22
            if stype == X.ENUMS['a6xx_state_type']['ST6_UBO'] and src == X.ENUMS['a6xx_state_src']['SS6_DIRECT']:
                need(len(body) == 3 + 2 * n, 'UBO payload length')
                for k in range(n):
                    lo = 4 * (start + 3 + 2 * k)
                    r = by_lo.get(lo)
                    if r is None:
                        need(body[3 + 2 * k] == 0 and body[4 + 2 * k] & 0x1FFFF == 0, f'UBO descriptor {k} unrelocated')
                        continue
                    need(r['hi'] == lo + 4 and r['hi_bits'] == 17, f'UBO descriptor {k}: BASE_HI half')
                    need(16 * (body[4 + 2 * k] >> 17) <= r['length'], f'UBO descriptor {k}: SIZE beyond its relocation')
                    checked.add(lo)
        if op == R.CP_DRAW_INDX_OFFSET and (body[0] >> 6) & 3 == X.ENUMS['pc_di_src_sel']['DI_SRC_SEL_DMA']:
            need(len(body) == 7, 'indexed draw has 7 payload dwords')
            lo = 4 * (start + 4)
            r = by_lo.get(lo)
            need(r is not None and r['hi'] == lo + 4 and r['hi_bits'] == 32, 'INDX_BASE is relocated as a reg64')
            need(body[6] * 2 <= r['length'], 'MAX_INDICES * 2 exceeds the index relocation')
            checked.add(lo)
    stray = sorted(r['lo'] for r in pkg['relocs'] if r['lo'] < 4 * pkg['ib_dwords'] and r['lo'] not in checked)
    need(not stray, f'relocations outside any address field: {stray}')
    return len(checked)


def resolve(pkg, addr_of):
    """The package with every relocation patched; addr_of(reloc) -> the address it names."""
    package = bytearray(pkg['package'])
    for r in pkg['relocs']:
        addr = addr_of(r)
        need(addr % (1 << r['align']) == 0, 'resolved address alignment')
        lo = struct.unpack_from('<I', package, r['lo'])[0] | (addr & 0xFFFFFFFF)
        struct.pack_into('<I', package, r['lo'], lo)
        if r['hi'] != NO_HI:
            hi = struct.unpack_from('<I', package, r['hi'])[0] | ((addr >> 32) & ((1 << r['hi_bits']) - 1))
            struct.pack_into('<I', package, r['hi'], hi)
        else:
            need(addr >> 32 == 0, 'an address without a high half is below 4 GiB')
    return package


def by_bases(bases):
    return lambda r: (bases[('resource', r['resource_id'])] if r['kind'] == 1 else
                      bases['zero' if r['kind'] == 3 else 'package']) + r['offset']


# ------------------------------------------------------------------------------------------------------------------
# Plans and expected IBs
# ------------------------------------------------------------------------------------------------------------------
def load_plan(name):
    """A committed offline plan, every artifact re-hashed against its qualification."""
    d = PLANS / name
    q = json.loads((d / 'qualification.json').read_text())
    need(q['status'] == 'NATIVE_PIPELINE_SYMBOLIC_DRAW_PLAN_VERIFIED', f'{name} is a verified plan')
    for artifact, digest in q['artifacts_sha256'].items():
        if artifact != 'qualification.json':
            need(sha((d / artifact).read_bytes()) == digest, f'{name}/{artifact} matches its qualification')
    words = json.loads((d / 'draw.words.json').read_text())
    need(struct.pack(f'<{len(words)}I', *words) == (d / 'draw.ib.bin').read_bytes(), f'{name}: words = ib.bin')
    refs = {}
    for r in json.loads((d / 'references.json').read_text()):
        refs.setdefault(r['what'], r)
    uploads = {RD.region_va(u['region'], u['offset']): (d / u['file']).read_bytes()
               for u in json.loads((d / 'scene.json').read_text())['uploads']}
    return dict(name=name, dir=str(d.relative_to(ROOT)), words=words, refs=refs, uploads=uploads,
                sha256=sha((d / 'qualification.json').read_bytes()),
                vs=(d / 'upload-0.bin').read_bytes(), fs=(d / 'upload-1.bin').read_bytes())


def application_ubos(original):
    def table(variant):          # plan-adreno-native-triangle.py: Mesa loads driver UBOs separately
        v = copy.deepcopy(variant)
        v['sidecar']['ir3']['driver_ubos'] = []
        return original(v)
    return table


@contextlib.contextmanager
def patched(obj, **values):
    saved = {k: getattr(obj, k) for k in values}
    for k, v in values.items():
        setattr(obj, k, v)
    try:
        yield
    finally:
        for k, v in saved.items():
            setattr(obj, k, v)


def native_scene(name, source, case, buffers, blend, seed):
    g = case['geom']
    px = [((x + 1) / 2 * g.w, (1 - y) / 2 * g.h) for x, y in NDC[source]]
    return {'name': name, 'lib': 'native', 'vs': 'vs', 'fs': 'fs', 'fc': {'vs': {}, 'fs': {}}, 'width': g.w, 'height': g.h,
            'vertex': {'data': b'', 'stride': 0, 'count': 3, 'attributes': [], 'triangles_px': px},
            'buffers': buffers, 'textures': [], 'samplers': [], 'blend': blend,
            'rts': [{'index': 0, 'format': 'bgra8', 'init': seed}],
            'tolerance': M.P7['tolerance'], 'edge_budget': M.P7['edge_budget'],
            'realistic': 'AdrenoMetal draw package (WP4.3)', 'group': 'native'}


def plan_function(scene, pair, geom):
    """RD.plan for one scene with the plan tool's adapter; the target takes the IOSurface's padded rows."""
    B = RD.B
    with patched(B, ubo_table=application_ubos(B.ubo_table)):
        p = PLAN([scene], dict(pipelines={scene['name']: pair}))
    f = p['functions'][0]
    rt = f['rts'][0]
    rt.update(pitch=geom.pitch, size=RD.RT_GUARD + geom.allocation)
    p['rt_end'] = rt['slot'] + rt['size'] + RD.RT_GUARD
    return p, f


def driver_constant_words(window, f, pair):
    """plan-adreno-native-triangle.py's separate driver constant-data loads, immediately before the draw."""
    loads = []
    for stage, opcode, block in (('vs', R.CP_LOAD_STATE6_GEOM, 'SB6_VS_SHADER'), ('fs', R.CP_LOAD_STATE6_FRAG, 'SB6_FS_SHADER')):
        v = pair[stage]
        for driver in v['sidecar']['ir3']['driver_ubos']:
            slot, size, offset = driver['ubo'], 16 * driver['size_vec4'], v['info']['constant_data_offset']
            address = window.addr('r_code', f['code'][stage] + offset, size, False, stage + ' driver constant data')
            state = M.pkt_word('CP_LOAD_STATE6_0', dst_off=slot, state_type='ST6_UBO', state_src='SS6_DIRECT',
                               state_block=block, num_unit=1)
            loads += [R.pkt7(opcode, 5), state, 0, 0, *M.ubo_desc(address, size)]
    return loads


def live_plan(name, case, source, buffers, blend):
    """q1n1's build_ib on the captured programs (what plan-adreno-native-triangle.py does for its plans)."""
    pair = {'vs': case['vs'], 'fs': case['fs'], 'link_vs_fs': case['linkage']}
    g = case['geom']
    p, f = plan_function(native_scene(name, source, case, buffers, blend, bytes(4 * g.w * g.h)), pair, g)
    window = RD.Window(0)
    driver = driver_constant_words(window, f, pair)

    class DriverConstantCS(M.CS):
        def pkt7(self, opcode, *payload):
            if opcode == R.CP_DRAW_INDX_OFFSET and driver:
                self.raw(*driver)
            super().pkt7(opcode, *payload)
    with patched(M, CS=DriverConstantCS):
        cs = RD.build_ib(window, p, f, 0x534e7001)
    uploads = {RD.region_va(region, offset): data for region, offset, data, _what in RD.data_uploads(window, p, f)}
    refs = {}
    for r in window.refs:
        refs.setdefault(r['what'], r)
    return dict(name='live q1n1 build_ib', words=cs.w, refs=refs, uploads=uploads)


def clear_block(rt_va, geom):
    """build_p7_ib's sysmem clear (emit_sysmem_clears) for this target, by q1n1's own functions."""
    cs = M.CS(RD.Window(0), 'clear')
    M.emit_flushes(cs, ccu_color=True, inv_ccu_color=True, inv_cche=True, wfi=True)
    M.emit_2d_clear(cs, rt_va, geom.pitch, 'bgra', (0, 0, geom.w, geom.h), CLEAR)
    M.emit_flushes(cs, ccu_color=True, inv_ccu_color=True)
    M.emit_flushes(cs, ccu_color=True, inv_ccu_color=True, inv_cche=True, wfi=True)
    cs.marker('RM6_DIRECT_RENDER')
    return cs.w


def expected_ib(plan, load, geom=DEFAULT):
    words = list(plan['words'])
    fence = [R.pkt7(R.CP_EVENT_WRITE7, 4), M.pkt_word('CP_EVENT_WRITE7_0', event='CACHE_FLUSH_TS', write_src='EV_WRITE_USER_32B',
                                                      write_dst='EV_DST_RAM', write_enabled=True)]
    need(words[-5:-3] == fence, 'the plan ends with its batch fence (emit_ib_fence)')
    words = words[:-5]
    if not load:
        _regs, packets = walk_ib(words)
        at = next(start - 1 for op, start, body in packets
                  if op == R.CP_CONTEXT_REG_BUNCH and body[0] == X.REGS['RB_RENDER_CNTL'][0])
        words = words[:at] + clear_block(plan['refs']['render target 0']['va'], geom) + words[at:]
    return words


def draw_section(words):
    """(start, end) of the draw section: from the VFD_INDEX_OFFSET bunch through CP_DRAW_INDX_OFFSET."""
    _regs, packets = walk_ib(words)
    start = next(s - 1 for op, s, body in packets if op == R.CP_CONTEXT_REG_BUNCH and body[0] == X.REGS['VFD_INDEX_OFFSET'][0])
    draws = [(s, body) for op, s, body in packets if op == R.CP_DRAW_INDX_OFFSET]
    need(len(draws) == 1, 'one draw')
    return start, draws[0][0] + len(draws[0][1])


def repeat_draws(words, n):
    start, end = draw_section(words)
    return words[:start] + words[start:end] * n + words[end:]


def draw_packet_variant(words, instances=None, indexed=None):
    """The expected IB with the draw packet re-encoded (q1n1's XML packers; Mesa fd6_draw.cc draw_emit layout)."""
    _regs, packets = walk_ib(words)
    draws = [(start, body) for op, start, body in packets if op == R.CP_DRAW_INDX_OFFSET]
    need(len(draws) == 1, 'one draw')
    start, body = draws[0]
    end = start + len(body)
    body = list(body)
    if instances is not None:
        body[1] = M.pkt_word('CP_DRAW_INDX_OFFSET_1', num_instances=instances)
    if indexed is not None:
        base, max_indices = indexed
        body = [M.pkt_word('CP_DRAW_INDX_OFFSET_0', prim_type='DI_PT_TRILIST', source_select='DI_SRC_SEL_DMA',
                           vis_cull='USE_VISIBILITY', index_size='INDEX4_SIZE_16_BIT', patch_type='TESS_QUADS'),
                body[1], body[2], M.pkt_word('CP_DRAW_INDX_OFFSET_3', first_indx=0), base & 0xFFFFFFFF, base >> 32,
                M.pkt_word('A5XX_CP_DRAW_INDX_OFFSET_6', max_indices=max_indices)]
    return words[:start - 1] + [R.pkt7(R.CP_DRAW_INDX_OFFSET, len(body))] + body + words[end:]


def compare_words(words, expect, what):
    diffs = [(i, f'{words[i]:#x}', f'{expect[i]:#x}') for i in range(min(len(words), len(expect))) if words[i] != expect[i]]
    need(len(words) == len(expect) and not diffs,
         f'{what}: IB differs from the plan: {len(words)} vs {len(expect)} dwords, first differences {diffs[:8]}')


def check_programs(case, plan):
    """The programs the IB points at are the plan's programs, in code buffers of the right size."""
    for stage, blob in (('vs', case['vs_code']), ('fs', case['fs_code'])):
        prog, upload = case[stage], plan[stage]
        need(blob[:len(upload)] == upload and not any(blob[len(upload):]), f'{stage} code buffer = the plan\'s upload')
        need(bytes.fromhex(prog['code_hex']) == upload, f'{stage} program export = the plan\'s upload')
        need(len(blob) % 256 == 0 and len(blob) >= max(len(upload), 128 * prog['instrlen']), f'{stage} code buffer size')


def committed_bases(case, plan):
    roles, refs = case['roles'], plan['refs']
    bases = {('resource', roles['target']['id']): refs['render target 0']['va'],
             ('resource', roles['vs_code']['id']): refs['VS code']['va'],
             ('resource', roles['fs_code']['id']): refs['FS code']['va'],
             'zero': refs['border colour table (zeroed)']['va'], 'package': 0x7FFF0000}
    need(refs['bindless descriptor sets (empty)']['va'] == bases['zero'], 'the plan uses one zero page')
    need(refs['vs driver constant data']['va'] == bases[('resource', roles['vs_code']['id'])] + case['vs']['info']['constant_data_offset'],
         'the plan\'s driver constant data is the VS code\'s constant data')
    if 'index_buffer' in roles:
        bases[('resource', roles['index_buffer']['id'])] = 0x2_0000_4000       # above 4 GiB: exercises the high half
    return bases


def resolve_from_plan(case, pkg, expect, plan, objects, later=None):
    """Live-plan normalisation: an IB relocation takes the address the plan has at the same dwords, which must be
    the plan's address of the object it names; a data-area relocation (driver-table u64) takes the plan's address
    of the resource it names. After patching, package data must equal the plan's upload at the address its
    descriptor received (so a driver table is checked with its relocated entries), and named buffers must hold
    the plan's contents."""
    roles = {v['id']: k for k, v in case['roles'].items()}
    ib_bytes, addresses = 4 * pkg['ib_dwords'], []
    # later = (IB byte offset where the second pass starts, its plan): its package data is checked against that plan
    plan_of = lambda r: later[1] if later and r['lo'] >= later[0] and r['lo'] < ib_bytes else plan
    for r in pkg['relocs']:
        need(r['hi'] != NO_HI, 'every relocation in these cases has a high half')
        if r['lo'] < ib_bytes:
            mask = (1 << r['align']) - 1
            addr = (expect[r['lo'] // 4] & ~mask & 0xFFFFFFFF) | ((expect[r['hi'] // 4] & ((1 << r['hi_bits']) - 1)) << 32)
            need(addr, f'no plan address at package byte {r["lo"]:#x}')
        else:
            need(r['kind'] == 1, 'data-area relocations name resources in these cases')
            addr = plan['refs'][objects[roles[r['resource_id']]]]['va'] + r['offset']
        if r['kind'] == 1:
            role = roles[r['resource_id']]
            ref = plan['refs'][objects[role]]
            need(addr == ref['va'] + r['offset'], f'{role} relocation names {addr:#x}, the plan has {ref["va"] + r["offset"]:#x}')
            if role in case['buffers']:
                data = plan['uploads'][ref['va']]
                need(case['buffers'][role][r['offset']:r['offset'] + len(data)] == data, f'{role}: contents differ from the plan')
        elif r['kind'] == 3:
            need(addr == plan['refs']['border colour table (zeroed)']['va'] + r['offset'], 'zero page address')
        addresses.append(addr)
    order = iter(addresses)
    package = resolve(pkg, lambda r: next(order))
    for r, addr in zip(pkg['relocs'], addresses):
        if r['kind'] == 2:
            data = plan_of(r)['uploads'].get(addr)
            need(data is not None, f'package relocation at {addr:#x} names no plan upload')
            need(bytes(package[r['offset']:r['offset'] + len(data)]) == data and r['length'] >= len(data),
                 f'package data at {r["offset"]:#x} differs from the plan\'s upload at {addr:#x}')
    return package


def reloc_table(case, pkg):
    ids = {v['id']: k for k, v in case['roles'].items()}
    kinds = {1: 'resource', 2: 'package', 3: 'zero'}
    return [dict(r, kind=kinds[r['kind']], role=ids.get(r['resource_id']) if r['kind'] == 1 else kinds[r['kind']],
                 hi=None if r['hi'] == NO_HI else r['hi']) for r in pkg['relocs']]


# ------------------------------------------------------------------------------------------------------------------
# The harness
# ------------------------------------------------------------------------------------------------------------------
def run_harness(harness, bundle, out, name, *flags):
    report, capture = out / f'{name}.json', out / name
    with (out / f'{name}.log').open('x') as log:
        proc = subprocess.run([str(harness), str(bundle), str(report), *flags, '--out', str(capture)],
                              cwd=ROOT, stdout=log, stderr=subprocess.STDOUT, timeout=240)
    data = json.loads(report.read_text()) if report.exists() else {}
    return proc.returncode, data, capture


def capture_case(harness, bundle, out, name, source, load, *extra, layout=(0x1002, 0x1000), geom=DEFAULT):
    flags = ['--draw', '--commit', '--ib-abi', '--source', source] + (['--load'] if load == 'load' else []) + list(extra)
    if geom != DEFAULT:
        flags += ['--size', str(geom.w), str(geom.h)]
    code, report, cap = run_harness(harness, bundle, out, name, *flags)
    need(code == 0 and report.get('status') == 'NATIVE_DRAW_COMMIT_CAPTURED_NOT_SUBMITTED',
         f'{name}: harness exit {code}, status {report.get("status")}, {report.get("exception")}')
    commands = kernel_commands((cap / 'commands.bin').read_bytes())
    need(tuple(k for k, _c in commands) == tuple(layout), f'{name}: kernel commands {[hex(k) for k, _c in commands]}')
    need(commands[-1][1] == struct.pack('<II', 0x1000, 8), f'{name}: the fence is the last command')
    resources = json.loads((cap / 'resources.json').read_text())
    published = {}
    for r in resources['published']:
        usage, size = published.get(r['id'], (0, r['size']))
        published[r['id']] = (usage | r['usage'], size)
    roles = resources['roles']
    t = roles['target']
    need((t['width'], t['height'], t['row_bytes'], t['size']) == tuple(geom), f'{name}: target geometry {t}')
    return dict(report=report, capture=cap, commands=commands, published=published, roles=roles, geom=geom,
                packages=[parse_package(c) for k, c in commands if k == 0x1002],
                vs=json.loads((cap / 'vertex.program.json').read_text()),
                fs=json.loads((cap / 'fragment.program.json').read_text()),
                linkage=json.loads((cap / 'linkage.json').read_text()),
                vs_code=(cap / 'vs.code.bin').read_bytes(), fs_code=(cap / 'fs.code.bin').read_bytes(),
                buffers={name: (cap / f'{name}.bin').read_bytes() for name in roles
                         if name not in ('target', 'vs_code', 'fs_code')})


def check_package(case, pkg, row):
    row.setdefault('packages', []).append(dict(ib_dwords=pkg['ib_dwords'], data_bytes=pkg['data_bytes'],
                                               relocations=len(pkg['relocs']), command_bytes=len(pkg['command']),
                                               command_sha256=sha(pkg['command']),
                                               reloc_targets=check_relocs(pkg, case['published']),
                                               address_fields_relocated=check_addresses(pkg)))


def save_package(out, name, case, pkg, words, index=0):
    suffix = f'.{index}' if index else ''
    (out / name / f'package{suffix}.bin').write_bytes(pkg['command'])
    (out / name / f'relocated{suffix}.ib.bin').write_bytes(struct.pack(f'<{len(words)}I', *words))
    (out / name / f'relocs{suffix}.json').write_text(json.dumps(reloc_table(case, pkg), indent=2) + '\n')


# ------------------------------------------------------------------------------------------------------------------
# The q1n1 CP model
# ------------------------------------------------------------------------------------------------------------------
def load_model():
    spec = importlib.util.spec_from_file_location('q1n1_render_model', Q / 'test-a16gpu-render.py')
    T = importlib.util.module_from_spec(spec)
    with contextlib.redirect_stdout(sys.stderr):
        spec.loader.exec_module(T)
    return T


def model_run(T, name, case, source, load, golden, buffers=None, blend=None, placements=None):
    """q1n1's `render` over the captured package. Only the scene source changes: select/load_assets/plan/build_ib/
    data_uploads are pointed at this capture; the ring, tables, walk, fence, readback and compare are q1n1's."""
    B, SC, S3, T3 = T.B, T.SC, T.S3, T.T3
    vs, fs, link = case['vs'], case['fs'], case['linkage']
    vs_names = {v['name']: 32 + v['slot'] for v in vs['sidecar']['reflection']['varyings']}
    pipe = {'vs': vs, 'fs': fs, 'link_vs_fs': link, 'vs_function': 'vs', 'lib': 'native', 'compile': {},
            'varying_map': [{'fs_slot': 32 + v['slot'], 'vs_slot': vs_names.get(v['name']), 'name': v['name']}
                            for v in fs['sidecar']['reflection']['varyings']]}
    g = case['geom']
    seed = bytes([0x69]) * (g.w * g.h * 4)
    scene = native_scene(name, source, case, buffers or {'vs': [], 'fs': []}, blend or {}, seed)
    pipe['scene_digest'] = SC.scene_digest(scene)
    goldens = {name: {'digest': pipe['scene_digest'], 'images': {0: golden}}}
    pkg = case['packages'][0]
    pre = {'clear': bytes((round(CLEAR[2] * 255), round(CLEAR[1] * 255), round(CLEAR[0] * 255), 255)) * (g.w * g.h),
           'load': seed}[load]
    roles = case['roles']

    def relocated(win, f):
        """The package resolved to this window: the plan's slots for the code and the scene's buffers; the
        package data area 8 KiB into the function's data slot."""
        bases = {'zero': win.addr('r_misc', 0, 0x1000, False, 'zero page (border colours, empty bindless sets)'),
                 ('resource', roles['target']['id']): win.addr('r_rt', f['rts'][0]['image'], g.pitch * g.h, True, 'render target 0'),
                 ('resource', roles['vs_code']['id']): win.addr('r_code', f['code']['vs'], len(case['vs_code']), False, 'VS code'),
                 ('resource', roles['fs_code']['id']): win.addr('r_code', f['code']['fs'], len(case['fs_code']), False, 'FS code')}
        for role, (stage, index) in (placements or {}).items():
            b = f['buffers'][stage][index]
            bases[('resource', roles[role]['id'])] = win.addr('r_data', b['offset'], b['size'], False, f'{stage} buffer({index})')
        bases['package'] = 0
        if pkg['data_bytes']:
            at = f['data_base'] + 0x2000
            need(at + pkg['data_bytes'] <= f['data_base'] + RD.DATA_SLOT, 'package data fits the data slot')
            bases['package'] = win.addr('r_data', at, pkg['data_bytes'], False, 'package data') - pkg['data_offset']
        return resolve(pkg, by_bases(bases))

    def build_ib(win, p, f, fence):
        cs = M.CS(win, f'native {name}')
        cs.raw(*struct.unpack_from(f'<{pkg["ib_dwords"]}I', relocated(win, f), 0))
        # q1n1's render_submit reads the batch fence the IB itself writes; the monitor's ring words replace it on
        # the A16 (design 5.3), so the model gets q1n1's emit_ib_fence appended to the package's IB.
        M.emit_ib_fence(cs, win.addr('memptrs', 0, 0x100, True, 'batch fence (memptrs)'), fence)
        cs.fence, cs.link = fence, None
        return cs

    def data_uploads(win, p, f):
        ups = [('r_code', f['code']['vs'], case['vs_code'], 'native VS code buffer'),
               ('r_code', f['code']['fs'], case['fs_code'], 'native FS code buffer')]
        for role, (stage, index) in (placements or {}).items():
            b = f['buffers'][stage][index]
            ups.append(('r_data', b['offset'], case['buffers'][role].ljust(b['size'], b'\0')[:b['size']],
                        f'native {stage} buffer({index})'))
        if pkg['data_bytes']:
            ups.append(('r_data', f['data_base'] + 0x2000, bytes(relocated(win, f)[pkg['data_offset']:]), 'package data'))
        return ups

    original = dict(select=RD.select, load_assets=RD.load_assets, plan=RD.plan, build_ib=RD.build_ib,
                    data_uploads=RD.data_uploads, check_pipeline=B.check_pipeline)

    def plan(scenes, shaders):
        return plan_function(scenes[0], shaders['pipelines'][scenes[0]['name']], g)[0]

    def check_pipeline(p):                       # q1n1's R0 policy refuses flat varyings; interp_regs builds them
        return [problem for problem in original['check_pipeline'](p) if 'flat/center interpolation' not in problem]

    class DrawModel(T.FakeRender):
        def __init__(self, **kw):
            super().__init__(**kw)
            self.loads6, self.pre_draw = [], None

        def load_state(self, op, body):
            self.loads6.append((op, list(body)))
            super().load_state(op, body)

        def draw(self, body):
            base, pitch = self.r64('RB_MRT_BASE', 0), self.r('RB_MRT_PITCH', 0) << 6
            self.pre_draw = b''.join(self.gpu_read(base + y * pitch, 4 * g.w, 'target before the draw') or b'' for y in range(g.h))
            super().draw(body)

    T.SHADERS['pipelines'][name], T.SCENES[name], T.GOLDENS[name] = pipe, scene, goldens[name]
    RD.select = lambda names=None, xr=False, probes=False: [scene]
    RD.load_assets = lambda check=True: ({'pipelines': {name: pipe}}, goldens, {'shaders_sha256': None, 'goldens_sha256': None})
    RD.plan, RD.build_ib, RD.data_uploads, B.check_pipeline = plan, build_ib, data_uploads, check_pipeline
    try:
        with T3.synthetic_firmware() as fw, tempfile.TemporaryDirectory() as tmp:
            fake = DrawModel()
            with contextlib.redirect_stdout(sys.stderr):
                T.ready(fake, fw)
                status, out = S3.run(fake, 'render', S3.Args(functions=name, image_prefix=str(Path(tmp) / 'r')))
    finally:
        RD.select, RD.load_assets, RD.plan = original['select'], original['load_assets'], original['plan']
        RD.build_ib, RD.data_uploads, B.check_pipeline = original['build_ib'], original['data_uploads'], original['check_pipeline']
        for table in (T.SHADERS['pipelines'], T.SCENES, T.GOLDENS):
            table.pop(name, None)
    result = out.get('render', {}).get('results', {}).get(name, {})
    need(status == 0 and out['order'][-1] == 'render_matches_goldens',
         f'model render: status {status}, stopped {out.get("stopped")}, violations {fake.violations[:4]}')
    need(not fake.violations and fake.render_draws == [name], f'model violations {fake.violations[:4]}')
    rt = result['rts'][0]
    need(result['ok'] and rt['identical'] and rt['guards_intact'], f'model readback {rt}')
    need(fake.pre_draw == pre, f'the target before the draw is not the {load} contents')
    # A driver constant-data UBO (the model's UBO table ignores DST_OFF): descriptor at consts_ubo, contents = the
    # code's constant data, read through CB0.
    driver_checked = 0
    for stage, prog, code, opcode in (('vs', vs, case['vs_code'], R.CP_LOAD_STATE6_GEOM), ('fs', fs, case['fs_code'], R.CP_LOAD_STATE6_FRAG)):
        for driver in prog['sidecar']['ir3']['driver_ubos']:
            consts = prog['const_state']['consts_ubo']
            loads = [(body[3] | (body[4] & 0x1FFFF) << 32, body[4] >> 17) for op, body in fake.loads6
                     if op == opcode and body[0] & 0x3FFF == consts and (body[0] >> 22) == 1]
            need(len(loads) == 1, f'{stage}: one driver constant-data load at UBO {consts}')
            base, vec4 = loads[0]
            off, size = prog['info']['constant_data_offset'], 16 * driver['size_vec4']
            need(vec4 * 16 >= size and fake.gpu_read(base, size, 'driver constant data') == code[off:off + size],
                 f'{stage}: the driver constant-data UBO holds the code buffer\'s constant data')
            driver_checked += 1
    sub = out['submissions'][0]
    return dict(status=status, order=out['order'][-3:], identical=rt['identical'], guards_intact=rt['guards_intact'],
                max_abs_diff=rt['max_abs_diff'], readback_sha256=rt['sha256'], pre_draw_sha256=sha(fake.pre_draw),
                refs_walked=sub['refs_walked'], fence=sub['fence'], ib_dwords=sub['ib']['dwords'],
                blits=len(fake.blits), events=len(fake.p67_events), driver_ubos_checked=driver_checked)


# ------------------------------------------------------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--bundle', type=Path, required=True)
    ap.add_argument('--output', type=Path, required=True)
    ap.add_argument('--harness', type=Path, help='a prebuilt native-texture (default: build it from the checkout)')
    args = ap.parse_args()
    out, bundle = args.output.resolve(), args.bundle.resolve()
    need(not out.exists(), 'preserve prior evidence: the output directory must not exist')
    out.mkdir(parents=True)
    executable = bundle / 'Contents/MacOS/AdrenoMetal'
    record = dict(status='RUNNING', started=time.time(), a16_access=False, gpu_submission=False,
                  boundary='Host capture of the plug-in\'s real kernel commands (AGX provider, commit captured), q1n1\'s '
                           'hardware-proven builder (committed offline plans and live build_ib) and q1n1\'s CP/SMMU '
                           'model. No A16, no Adreno execution, no shader pixels.',
                  bundle=str(bundle), bundle_executable_sha256=sha(executable.read_bytes()),
                  sources_sha256={str(p.relative_to(ROOT)): sha(p.read_bytes()) for p in
                                  sorted((ROOT / 'gpu/adreno-kext/plugin').rglob('*'))
                                  if p.is_file() and p.suffix in ('.m', '.h', '.sh') and 'out' not in p.parts} |
                                 {str(Path(__file__).relative_to(ROOT)): sha(Path(__file__).read_bytes())},
                  q1n1_sha256={p.name: sha(p.read_bytes()) for p in (Q / 'a16gpu_render.py', Q / 'a16gpu_p6p7.py',
                               Q / 'a16gpu_bindings.py', Q / 'a8xx_regs.py', Q / 'adreno_x2.py', Q / 'test-a16gpu-render.py',
                               Q / 'test-a16gpu-p6p7.py')},
                  cases={})
    try:
        harness = args.harness
        if harness is None:
            harness = out / 'native-texture'
            with (out / 'build.log').open('x') as log:
                subprocess.run(['xcrun', 'clang', '-arch', 'arm64e', '-mmacosx-version-min=27.0', '-fobjc-arc',
                                '-fobjc-arc-exceptions', '-O1', '-g', '-Wall', '-Werror', str(HARNESS_SOURCE),
                                '-framework', 'Foundation', '-framework', 'Metal', '-framework', 'IOSurface',
                                '-framework', 'IOKit', '-o', str(harness)], stdout=log, stderr=subprocess.STDOUT, check=True)
                subprocess.run(['codesign', '-f', '-s', '-', str(harness)], stdout=log, stderr=subprocess.STDOUT, check=True)
        record['harness_sha256'] = sha(Path(harness).read_bytes())
        plans = {name: load_plan(name) for name in ('draw-plan-v2', 'draw-plan-varyings-v1')}
        record['plans'] = {name: dict(dir=p['dir'], qualification_sha256=p['sha256']) for name, p in plans.items()}
        goldens = {}
        for source, load, geom in (('plan-v2', 'clear', DEFAULT), ('plan-v2', 'load', DEFAULT), ('varyings', 'clear', DEFAULT),
                                   ('varyings', 'load', DEFAULT), ('uniforms', 'clear', DEFAULT), ('device', 'clear', DEFAULT),
                                   ('plan-v2', 'clear', LARGE)):
            label = f'{source}-{load}' + ('' if geom == DEFAULT else f'-{geom.w}x{geom.h}')
            code, report, cap = run_harness(harness, bundle, out, f'golden-{label}', '--golden', '--source', source,
                                            *(['--load'] if load == 'load' else []),
                                            *([] if geom == DEFAULT else ['--size', str(geom.w), str(geom.h)]))
            need(code == 0 and report.get('status') == 'HOST_METAL_GOLDEN_RENDERED', f'golden {label}: {report.get("exception")}')
            goldens[source, load, geom] = (cap / 'golden.bgra').read_bytes()
            need(len(goldens[source, load, geom]) == 4 * geom.w * geom.h, f'golden {label} size')
            record.setdefault('goldens', {})[label] = dict(device=report['golden_device'], sha256=sha(goldens[source, load, geom]))
        T = load_model()
        cases = record['cases']
        # 1. The committed offline plans: package, dword equality, model.
        for name, source, load, plan_name in (('plan-v2-clear', 'plan-v2', 'clear', 'draw-plan-v2'),
                                              ('plan-v2-load', 'plan-v2', 'load', 'draw-plan-v2'),
                                              ('varyings-clear', 'varyings', 'clear', 'draw-plan-varyings-v1'),
                                              ('varyings-load', 'varyings', 'load', 'draw-plan-varyings-v1')):
            case, plan = capture_case(harness, bundle, out, name, source, load), plans[plan_name]
            row = cases[name] = dict(source=source, load_action=load, plan=plan_name,
                                     published_resources=case['report']['published_resources'])
            pkg = case['packages'][0]
            check_package(case, pkg, row)
            words = ib_words(dict(pkg, package=resolve(pkg, by_bases(committed_bases(case, plan)))))
            compare_words(words, expected_ib(plan, load == 'load'), name)
            check_programs(case, plan)
            row['plan_equal_dwords'] = len(words)
            save_package(out, name, case, pkg, words)
            row['model'] = model_run(T, f'native-{name}', case, source, load, goldens[source, load, DEFAULT])
            row['result'] = 'PASS'
        # 2. Constant buffers (setVertexBytes -> package data, a fragment MTLBuffer -> resource) and premultiplied
        #    source-over blending, against build_ib run on the same programs, then the model (UBO contents, blend).
        name = 'uniforms-clear'
        case = capture_case(harness, bundle, out, name, 'uniforms', 'clear')
        buffers = {'vs': [{'index': 1, 'data': POINTS, 'device': False}], 'fs': [{'index': 0, 'data': TINT, 'device': False}]}
        blend = {0: dict(PREMULTIPLIED_OVER)}
        need(case['buffers']['fragment_buffer'] == TINT, 'the fragment buffer holds the tint')
        plan = live_plan(f'native-{name}-plan', case, 'uniforms', buffers, blend)
        plan['vs'], plan['fs'] = bytes.fromhex(case['vs']['code_hex']), bytes.fromhex(case['fs']['code_hex'])
        row = cases[name] = dict(source='uniforms', load_action='clear', plan=plan['name'],
                                 published_resources=case['report']['published_resources'])
        pkg = case['packages'][0]
        check_package(case, pkg, row)
        need(pkg['data_bytes'] and any(r['kind'] == 2 for r in pkg['relocs']), 'setVertexBytes lands in the package data')
        expect = expected_ib(plan, False)
        words = ib_words(dict(pkg, package=resolve_from_plan(case, pkg, expect, plan, {
            'target': 'render target 0', 'vs_code': 'VS code', 'fs_code': 'FS code', 'fragment_buffer': 'fs UBO 0 = buffer(0)'})))
        compare_words(words, expect, name)
        check_programs(case, plan)
        row['plan_equal_dwords'] = len(words)
        save_package(out, name, case, pkg, words)
        row['model'] = model_run(T, f'native-{name}', case, 'uniforms', 'clear', goldens['uniforms', 'clear', DEFAULT], buffers,
                                 blend, {'fragment_buffer': ('fs', 0)})
        row['result'] = 'PASS'
        # 2c. Two passes with setBytes data in one package: each pass's descriptor must reach its own data chunk
        #     (package offsets rebased per pass); the second pass binds other positions.
        name = 'uniforms-two-passes'
        case = capture_case(harness, bundle, out, name, 'uniforms', 'clear', '--sequence', 'draw-draw')
        first = live_plan(f'native-{name}-plan', case, 'uniforms', buffers, blend)
        second = live_plan(f'native-{name}-plan2', case, 'uniforms',
                           {'vs': [{'index': 1, 'data': POINTS2, 'device': False}], 'fs': buffers['fs']}, blend)
        row = cases[name] = dict(source='uniforms', sequence='draw-draw', plan=first['name'])
        pkg = case['packages'][0]
        check_package(case, pkg, row)
        head = expected_ib(first, False)
        expect = head + expected_ib(first, True)
        need(expected_ib(second, True) == expected_ib(first, True), 'the two plans differ only in data')
        words = ib_words(dict(pkg, package=resolve_from_plan(case, pkg, expect, first, {
            'target': 'render target 0', 'vs_code': 'VS code', 'fs_code': 'FS code', 'fragment_buffer': 'fs UBO 0 = buffer(0)'},
            later=(4 * len(head), second))))
        compare_words(words, expect, name)
        need(sum(r['kind'] == 2 for r in pkg['relocs']) == 2, 'one package relocation per pass')
        row['plan_equal_dwords'] = len(words)
        save_package(out, name, case, pkg, words)
        row['result'] = 'PASS'
        # 2a. A device buffer through the driver table (setVertexBuffer at a device pointer): the table lives in the
        #     package data with its u64 relocated (design R3); the tint arrives through setFragmentBytes.
        name = 'device-clear'
        case = capture_case(harness, bundle, out, name, 'device', 'clear')
        buffers = {'vs': [{'index': 1, 'data': POINTS, 'device': True}], 'fs': [{'index': 0, 'data': TINT, 'device': False}]}
        need(case['buffers']['vertex_buffer'] == POINTS, 'the device buffer holds the points')
        plan = live_plan(f'native-{name}-plan', case, 'device', buffers, {})
        plan['vs'], plan['fs'] = bytes.fromhex(case['vs']['code_hex']), bytes.fromhex(case['fs']['code_hex'])
        row = cases[name] = dict(source='device', load_action='clear', plan=plan['name'],
                                 published_resources=case['report']['published_resources'])
        pkg = case['packages'][0]
        check_package(case, pkg, row)
        data_relocs = [r for r in pkg['relocs'] if r['lo'] >= 4 * pkg['ib_dwords']]
        need(len(data_relocs) == 1 and data_relocs[0]['kind'] == 1 and data_relocs[0]['access'] == 3,
             'the driver table carries one read/write resource address')
        expect = expected_ib(plan, False)
        words = ib_words(dict(pkg, package=resolve_from_plan(case, pkg, expect, plan, {
            'target': 'render target 0', 'vs_code': 'VS code', 'fs_code': 'FS code', 'vertex_buffer': 'vs device buffer(1)'})))
        compare_words(words, expect, name)
        check_programs(case, plan)
        row['plan_equal_dwords'] = len(words)
        save_package(out, name, case, pkg, words)
        row['model'] = model_run(T, f'native-{name}', case, 'device', 'clear', goldens['device', 'clear', DEFAULT], buffers,
                                 {}, {'vertex_buffer': ('vs', 1)})
        row['result'] = 'PASS'
        # 2b. A 1024x512 target (rows 4096 bytes, 2 MiB): the guardband is no longer 0x1FF on either axis and the
        #     scissor/2D fields grow; against build_ib run on the same programs, then the model.
        name = 'plan-v2-large-clear'
        case = capture_case(harness, bundle, out, name, 'plan-v2', 'clear', geom=LARGE)
        plan = live_plan(f'native-{name}-plan', case, 'plan-v2', {'vs': [], 'fs': []}, {})
        plan['vs'], plan['fs'] = bytes.fromhex(case['vs']['code_hex']), bytes.fromhex(case['fs']['code_hex'])
        row = cases[name] = dict(source='plan-v2', load_action='clear', plan=plan['name'], target=LARGE._asdict(),
                                 published_resources=case['report']['published_resources'])
        pkg = case['packages'][0]
        check_package(case, pkg, row)
        expect = expected_ib(plan, False, LARGE)
        words = ib_words(dict(pkg, package=resolve_from_plan(case, pkg, expect, plan, {
            'target': 'render target 0', 'vs_code': 'VS code', 'fs_code': 'FS code'})))
        compare_words(words, expect, name)
        check_programs(case, plan)
        gb = X.REGS['GRAS_CL_GUARDBAND_CLIP_ADJ'][0]
        row['guardband'] = [hex(v) for pos, off in walk_ib(words)[0] if off == gb for v in [words[pos]]]
        row['plan_equal_dwords'] = len(words)
        save_package(out, name, case, pkg, words)
        row['model'] = model_run(T, f'native-{name}', case, 'plan-v2', 'clear', goldens['plan-v2', 'clear', LARGE])
        row['result'] = 'PASS'
        # 3. Draw-packet variants against the plan-v2 Load IB (packet-level; the model draws neither).
        load_ib = expected_ib(plans['draw-plan-v2'], True)
        clear_ib = expected_ib(plans['draw-plan-v2'], False)
        for name, extra, variant in (
                ('plan-v2-instanced', ['--instances', '2'], lambda c, b: draw_packet_variant(load_ib, instances=2)),
                ('plan-v2-indexed', ['--indexed'], lambda c, b: draw_packet_variant(
                    load_ib, indexed=(b[('resource', c['roles']['index_buffer']['id'])], c['roles']['index_buffer']['length'] // 2))),
                ('plan-v2-three-draws', ['--draws', '3'], lambda c, b: repeat_draws(load_ib, 3))):
            case = capture_case(harness, bundle, out, name, 'plan-v2', 'load', *extra)
            row = cases[name] = dict(source='plan-v2', load_action='load', plan='draw-plan-v2')
            pkg = case['packages'][0]
            check_package(case, pkg, row)
            bases = committed_bases(case, plans['draw-plan-v2'])
            words = ib_words(dict(pkg, package=resolve(pkg, by_bases(bases))))
            compare_words(words, variant(case, bases), name)
            row['plan_equal_dwords'] = len(words)
            save_package(out, name, case, pkg, words)
            row['result'] = 'PASS'
        # 4. Encoder order: blit fills and render passes keep their order as kernel commands; consecutive passes
        #    share a package.
        IB, FILL, FENCE = 0x1002, 0x1001, 0x1000
        for name, sequence, layout, expects in (
                ('fill-then-draw', 'fill-draw', (FILL, IB, FENCE), [clear_ib]),
                ('draw-then-fill', 'draw-fill', (IB, FILL, FENCE), [clear_ib]),
                ('draw-fill-draw', 'draw-fill-draw', (IB, FILL, IB, FENCE), [clear_ib, load_ib]),
                ('two-passes', 'draw-draw', (IB, FENCE), [clear_ib + load_ib])):
            case = capture_case(harness, bundle, out, name, 'plan-v2', 'clear', '--sequence', sequence, layout=layout)
            row = cases[name] = dict(source='plan-v2', sequence=sequence, layout=[hex(k) for k in layout])
            fill = case['roles']['fill_buffer'] if 'fill' in sequence else None
            for kind, command in case['commands']:
                if kind == FILL:
                    need(command == struct.pack('<IIIIQQ', FILL, 32, fill['id'], 0x5A5A5A5A, 0, FILL_BYTES),
                         f'{name}: FILL32 command {command.hex()}')
                    need(case['published'][fill['id']][0] & 2, f'{name}: the fill buffer is published writable')
            bases = committed_bases(case, plans['draw-plan-v2'])
            for index, (pkg, expect) in enumerate(zip(case['packages'], expects)):
                check_package(case, pkg, row)
                words = ib_words(dict(pkg, package=resolve(pkg, by_bases(bases))))
                compare_words(words, expect, f'{name} package {index}')
                save_package(out, name, case, pkg, words, index)
            need(len(case['packages']) == len(expects), f'{name}: package count')
            row['result'] = 'PASS'
        # 5. Without the kext's IB ABI the pipeline is refused explicitly, and nothing is committed.
        code, report, _cap = run_harness(harness, bundle, out, 'no-ib-abi', '--draw', '--commit', '--source', 'plan-v2')
        need(code == 2 and report.get('exception', {}).get('reason') == REFUSAL and 'commit' not in report,
             f'no IB ABI: exit {code} {report.get("exception")}')
        cases['no-ib-abi'] = dict(result='PASS', refusal=REFUSAL)
        # 6. With the IB ABI, a pass the IB builder does not build yet (here an RGBA8Unorm target) keeps the FILL32
        #    clear it had without the ABI, byte for byte, instead of failing the command buffer; a BGRA8 clear-only
        #    pass is one IB package.
        runs = {}
        for label, flags in (('clear-rgba8-no-ib-abi', ('--commit', '--rgba8')), ('clear-rgba8-ib-abi', ('--commit', '--ib-abi', '--rgba8')),
                             ('clear-bgra8-ib-abi', ('--commit', '--ib-abi'))):
            code, report, cap = run_harness(harness, bundle, out, label, *flags)
            need(code == 0 and report.get('status') == 'NATIVE_CLEAR_COMMIT_CAPTURED_NOT_SUBMITTED',
                 f'{label}: harness exit {code}, status {report.get("status")}, {report.get("exception")}')
            runs[label] = kernel_commands((cap / 'commands.bin').read_bytes())
        kinds = [k for k, _c in runs['clear-rgba8-no-ib-abi']]
        need(len(kinds) >= 2 and set(kinds[:-1]) == {FILL} and kinds[-1] == FENCE,
             f'RGBA8 clear without the IB ABI is FILL32s (one per padded row) + fence: {[hex(k) for k in kinds]}')
        need(runs['clear-rgba8-ib-abi'] == runs['clear-rgba8-no-ib-abi'],
             'a pass the IB builder refuses keeps its FILL32 clear under the IB ABI')
        need([k for k, _c in runs['clear-bgra8-ib-abi']] == [IB, FENCE], 'a BGRA8 clear-only pass under the IB ABI is one package')
        cases['refused-pass-keeps-fill32'] = dict(result='PASS')
        record['status'] = 'ADRENO_DRAW_PACKAGES_MATCH_PLAN_AND_MODEL'
    except (Fail, subprocess.CalledProcessError, subprocess.TimeoutExpired) as error:
        record.update(status='FAILED', error=str(error))
    finally:
        record['finished'] = time.time()
        record['artifacts_sha256'] = {str(p.relative_to(out)): sha(p.read_bytes()) for p in sorted(out.rglob('*'))
                                      if p.is_file() and p.name != 'qualification.json' and '.dSYM' not in str(p)}
        (out / 'qualification.json').write_text(json.dumps(record, indent=2, default=str) + '\n')
    print(json.dumps({k: record.get(k) for k in ('status', 'error')} |
                     {'cases': {k: v.get('result') for k, v in record['cases'].items()}}))
    return 0 if record['status'] != 'FAILED' else 1


if __name__ == '__main__':
    sys.exit(main())

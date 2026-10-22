#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Replay CoreAnimation's generic-pipeline draws from captured Adreno packages on llvmpipe and on the host GPU.

The project's shader conformance method (gpu/air2ir3/tools/exec.py: our compiler's NIR on llvmpipe versus real
Metal on the M3 Max) applied to the draws CoreAnimation really issued with its generic pipeline (VfxXg + Xgc) in
captured scenes (tools/capture-ca-candidate-scenes.py). For every such draw this reads, from the command package
our plug-in built and the captured resources:
  - both stages' constant buffers (CP_LOAD_STATE6 ST6_UBO descriptors) and device buffers (the driver table);
  - the fragment T# and S# arrays (SP_PS_TEXMEMOBJ_BASE / SP_PS_SAMPLER_BASE): texture contents, formats and sizes,
    the API samplers' filters and address modes;
  - the draw packet (indices or vertex start), viewport and blend state;
and writes an exec scene. The Metal side runs CoreAnimation's own specialized functions (the captured AIR packaged
with xcrun metallib); the llvmpipe side runs the NIR our compiler builds from the same AIR. Both render into the same
cleared BGRA8 target (scissor not applied on either side) and are compared as exec.py does (tolerance 3/255).
What this does not show: Adreno execution. The registers our plug-in programs are checked separately
(tools/inspect-ca-point-draws.py); pixels from the A16 need the hardware replay. Captured contents of private
targets rendered earlier in the frame are the capture's labelled replay seeds, identical on both sides.

  python3 tools/conform-ca-generic-draws.py --capture DIR/SCENE-adreno.json [...] --air-dir DIR --nirexec BIN
          --mtlgold BIN --output NEW-DIR
"""
from pathlib import Path
import argparse
import hashlib
import importlib.util
import json
import math
import os
import re
import struct
import subprocess

ROOT = Path(__file__).resolve().parents[1]
sha = lambda p: hashlib.sha256(Path(p).read_bytes()).hexdigest()
spec = importlib.util.spec_from_file_location('inspect_ca_point_draws', ROOT / 'tools/inspect-ca-point-draws.py')
INSPECT = importlib.util.module_from_spec(spec)
spec.loader.exec_module(INSPECT)
HEADER = INSPECT.HEADER
TEXT = HEADER.read_text()
REGS, ENUMS = INSPECT.registers()
GENERIC = ('VfxXg', 'Xgc')
CLEAR = [0.2, 0.4, 0.6, 1.0]
TOLERANCE = 3


def field(prefix, value):
    shift = int(re.search(r'^#define A8XX_%s__SHIFT (\d+)u$' % prefix, TEXT, re.M).group(1))
    width = int(re.search(r'^#define A8XX_%s__WIDTH (\d+)u$' % prefix, TEXT, re.M).group(1))
    return (value >> shift) & ((1 << width) - 1)


def f32(bits):
    return struct.unpack('<f', struct.pack('<I', bits))[0]


def walk(words, relocs, copy=None):
    """Register writes, the last UBO descriptors per stage/slot and every draw packet, in order. CP_MEMCPY (the
    plug-in stages unaligned constant buffers with it at draw time) is applied through `copy` as the CP would."""
    state, ubos, pos = {}, {'vs': {}, 'fs': {}}, 0
    def write(reg, value, at):
        state[reg] = (value, at)
    while pos < len(words):
        h = words[pos]
        kind = h >> 28
        n = h & (0x7f if kind == 4 else 0x3fff)
        if kind == 4:
            reg = (h >> 8) & 0x7ffff
            for k in range(n):
                write(reg + k, words[pos + 1 + k], pos + 1 + k)
        elif kind == 7:
            op, body = (h >> 16) & 0x7f, words[pos + 1:pos + 1 + n]
            if op == ENUMS['CP_CONTEXT_REG_BUNCH']:
                for k in range(0, n, 2):
                    write(body[k], body[k + 1], pos + 2 + k)
            elif op == ENUMS['CP_NON_CONTEXT_REG_BUNCH']:
                for k in range(2, n, 2):
                    write(body[k], body[k + 1], pos + 2 + k)
            elif op in (ENUMS['CP_LOAD_STATE6_GEOM'], ENUMS['CP_LOAD_STATE6_FRAG']):
                p0 = body[0]
                if field('PKT_CP_LOAD_STATE6_0__STATE_TYPE', p0) == ENUMS['ST6_UBO'] and \
                        field('PKT_CP_LOAD_STATE6_0__STATE_SRC', p0) == ENUMS['SS6_DIRECT']:
                    block = field('PKT_CP_LOAD_STATE6_0__STATE_BLOCK', p0)
                    stage = 'vs' if block == ENUMS['SB6_VS_SHADER'] else 'fs' if block == ENUMS['SB6_FS_SHADER'] else None
                    assert stage, block
                    dst, units = field('PKT_CP_LOAD_STATE6_0__DST_OFF', p0), field('PKT_CP_LOAD_STATE6_0__NUM_UNIT', p0)
                    for i in range(units):
                        lo_at = pos + 4 + 2 * i
                        size = field('DESC_A6XX_UBO_1__SIZE', words[lo_at + 1]) * 16
                        ubos[stage][dst + i] = (relocs.get(4 * lo_at), size)
            elif op == ENUMS['CP_MEMCPY'] and copy is not None:
                assert n == 5 and body[0]
                copy(relocs[4 * (pos + 2)], relocs[4 * (pos + 4)], 4 * body[0])
            elif op == ENUMS['CP_DRAW_INDX_OFFSET']:
                yield pos, body, dict(state), {s: dict(u) for s, u in ubos.items()}
        pos += 1 + n


class Capture:
    def __init__(self, path):
        self.path = path
        self.data = json.loads(path.read_text())
        assert self.data['status'] == 'ADRENO_CA_COMMANDS_CAPTURED_NOT_SUBMITTED'
        self.command, self.words, self.relocs = INSPECT.package(self.data)
        self.files = {r['id']: r for r in self.data['commits'][0]['published_resources']}
        self.layouts = {r['resource_id']: r for r in self.data['layout_publications']}
        self.programs = [tuple(json.loads(Path(p[s]['path']).read_text()) for s in ('vertex', 'fragment'))
                         for p in self.data['programs']]
        self.mem = {}          # resource id -> its contents as the CP has changed them so far (captured snapshot + copies)
        self.copies = 0

    def resource(self, rid):
        if rid not in self.mem:
            f = self.files[rid]
            assert sha(f['path']) == f['sha256']
            self.mem[rid] = bytearray(Path(f['path']).read_bytes())
        return self.mem[rid]

    def copy(self, src, dst, length):
        assert src[2] == dst[2] == 1 and length <= min(src[8], dst[8])
        data = bytes(self.resource(src[6])[src[7]:src[7] + length])
        self.resource(dst[6])[dst[7]:dst[7] + length] = data
        self.copies += 1

    def span(self, reloc, length=None):
        """Bytes a relocation names: a captured resource or this package's data area."""
        _, _, kind, _, _, _, rid, offset, rlen = reloc
        length = rlen if length is None else length
        if kind == 1:
            return bytes(self.resource(rid)[offset:offset + length])
        assert kind == 2
        return self.command[48 + offset:48 + offset + length]

    def code(self, state, name):
        value, at = state[REGS[name]]
        r = self.relocs[4 * at]
        return self.span(r)


def bindings(program, kind):
    return [b for b in program['sidecar']['reflection']['bindings'] if b['kind'] == kind and (b.get('present') or b.get('used'))]


def texture_format(fmt, swap):
    if fmt == ENUMS['FMT6_8_8_8_8_UNORM']:
        return ('bgra8' if swap == ENUMS['WXYZ'] else 'rgba8'), 4
    return {ENUMS['FMT6_8_UNORM']: ('r8', 1), ENUMS['FMT6_8_8_UNORM']: ('rg8', 2),
            ENUMS['FMT6_16_16_16_16_FLOAT']: ('rgba16f', 8)}[fmt]


WRAP = {ENUMS['A6XX_TEX_CLAMP_TO_EDGE']: 'clamp_to_edge', ENUMS['A6XX_TEX_REPEAT']: 'repeat',
        ENUMS['A6XX_TEX_MIRROR_REPEAT']: 'mirrored_repeat', ENUMS['A6XX_TEX_CLAMP_TO_BORDER']: 'clamp_to_zero'}
MTL_FACTOR = {ENUMS['FACTOR_ZERO']: 0, ENUMS['FACTOR_ONE']: 1, ENUMS['FACTOR_SRC_ALPHA']: 4, ENUMS['FACTOR_ONE_MINUS_SRC_ALPHA']: 5,
              ENUMS['FACTOR_DST_ALPHA']: 8, ENUMS['FACTOR_ONE_MINUS_DST_ALPHA']: 9}
MTL_OP = {ENUMS['BLEND_DST_PLUS_SRC']: 0, ENUMS['BLEND_SRC_MINUS_DST']: 1, ENUMS['BLEND_DST_MINUS_SRC']: 2,
          ENUMS['BLEND_MIN_DST_SRC']: 3, ENUMS['BLEND_MAX_DST_SRC']: 4}


def scene_for(cap, pos, body, state, ubos, vs, fs, air, metallib, out):
    out.mkdir(parents=True)
    def save(name, data):
        (out / name).write_bytes(data)
        return str(out / name)
    buffers = {}
    for stage, program in (('vertex', vs), ('fragment', fs)):
        table = ubos['vs' if stage == 'vertex' else 'fs']
        rows = []
        for b in bindings(program, 'ubo'):
            reloc, size = table[b['slot']]
            rows.append(dict(index=b['metal_index'], file=save(f'{stage}-ubo{b["slot"]}.bin', cap.span(reloc, size))))
        devices = bindings(program, 'device_buffer')
        if devices:
            dt = devices[0]['driver_table_ubo']
            table_reloc, _ = table[dt]
            assert table_reloc[2] == 2
            for b in devices:
                entry = cap.relocs.get(table_reloc[7] + b['slot'])
                if entry is None:
                    continue
                rows.append(dict(index=b['metal_index'], device=True,
                                 file=save(f'{stage}-device{b["metal_index"]}.bin', cap.span(entry))))
        buffers[stage] = rows
    textures, samplers = [], []
    tex_value, tex_at = state[REGS['SP_PS_TEXMEMOBJ_BASE']]
    tex_base = cap.relocs[4 * tex_at]
    samp_value, samp_at = state[REGS['SP_PS_SAMPLER_BASE']]
    samp_base = cap.relocs[4 * samp_at]
    for b in bindings(fs, 'texture'):
        at = tex_base[7] + 64 * b['slot']
        d = struct.unpack_from('<16I', cap.command, 48 + at)
        r = cap.relocs[at]
        ttype, depth = field('DESC_A8XX_TEX_MEMOBJ_1__TYPE', d[1]), field('DESC_A8XX_TEX_MEMOBJ_1__DEPTH', d[1])
        w, h = field('DESC_A8XX_TEX_MEMOBJ_2__WIDTH', d[2]), field('DESC_A8XX_TEX_MEMOBJ_2__HEIGHT', d[2])
        fmt, bpp = texture_format(field('DESC_A8XX_TEX_MEMOBJ_3__FMT', d[3]), field('DESC_A8XX_TEX_MEMOBJ_3__SWAP', d[3]))
        pitch = field('DESC_A8XX_TEX_MEMOBJ_6__TEX_LINE_OFFSET', d[6]) // 8
        raw = bytes(cap.resource(r[6]))
        rows = b''.join(raw[r[7] + y * pitch:r[7] + y * pitch + w * bpp] for y in range(h))
        entry = dict(index=b['metal_index'], format=fmt, width=w, height=h, file=save(f'tex{b["metal_index"]}.bin', rows))
        if ttype == ENUMS['A6XX_TEX_3D']:
            assert depth == 1
            entry.update(type='3d', depth=1)
        textures.append(entry)
    for b in bindings(fs, 'sampler'):
        s0 = struct.unpack_from('<I', cap.command, 48 + samp_base[7] + 16 * b['slot'])[0]
        filt = lambda v: 'linear' if v == ENUMS['A6XX_TEX_LINEAR'] else 'nearest'
        samplers.append(dict(index=b['metal_index'],
                             min_filter=filt(field('DESC_A8XX_TEX_SAMP_0__XY_MIN', s0)),
                             mag_filter=filt(field('DESC_A8XX_TEX_SAMP_0__XY_MAG', s0)),
                             address_s=WRAP[field('DESC_A8XX_TEX_SAMP_0__WRAP_S', s0)],
                             address_t=WRAP[field('DESC_A8XX_TEX_SAMP_0__WRAP_T', s0)],
                             address_r=WRAP[field('DESC_A8XX_TEX_SAMP_0__WRAP_R', s0)]))
    prim = field('PKT_CP_DRAW_INDX_OFFSET_0__PRIM_TYPE', body[0])
    count = body[2]
    vertex = dict(data=dict(floats=[]), stride=0, count=count, attributes=[],
                  primitive={ENUMS['DI_PT_TRILIST']: 'triangle', ENUMS['DI_PT_TRISTRIP']: 'triangle_strip',
                             ENUMS['DI_PT_POINTLIST']: 'point'}[prim])
    if field('PKT_CP_DRAW_INDX_OFFSET_0__SOURCE_SELECT', body[0]) == ENUMS['DI_SRC_SEL_DMA']:
        index_reloc = cap.relocs[4 * (pos + 1 + int(re.search(r'A5XX_CP_DRAW_INDX_OFFSET_INDX_BASE (\d+)u', TEXT).group(1)))]
        indices = cap.span(index_reloc, 2 * count)
    else:
        start = state[REGS['VFD_INDEX_OFFSET']][0]
        indices = struct.pack('<%dH' % count, *range(start, start + count))   # vertex_id includes the start
    vertex['indices'] = dict(file=save('indices.bin', indices))
    xo, xs = f32(state[REGS['GRAS_CL_VIEWPORT_XOFFSET']][0]), f32(state[REGS['GRAS_CL_VIEWPORT_XSCALE']][0])
    yo, ys = f32(state[REGS['GRAS_CL_VIEWPORT_YOFFSET']][0]), f32(state[REGS['GRAS_CL_VIEWPORT_YSCALE']][0])
    viewport = dict(x=xo - xs, y=yo + ys, w=2 * xs, h=-2 * ys)
    rt_value, rt_at = state[REGS['RB_MRT_BASE']]
    target = cap.layouts[cap.relocs[4 * rt_at][6]]
    control, blend_control = state[REGS['RB_MRT_CONTROL']][0], state[REGS['RB_MRT_BLEND_CONTROL']][0]
    blend = dict(enabled=field('REG_RB_MRT_CONTROL__COLOR_BLEND_EN', control))
    if blend['enabled']:
        blend.update(rgb_op=MTL_OP[field('REG_RB_MRT_BLEND_CONTROL__RGB_BLEND_OPCODE', blend_control)],
                     alpha_op=MTL_OP[field('REG_RB_MRT_BLEND_CONTROL__ALPHA_BLEND_OPCODE', blend_control)],
                     src_rgb=MTL_FACTOR[field('REG_RB_MRT_BLEND_CONTROL__RGB_SRC_FACTOR', blend_control)],
                     dst_rgb=MTL_FACTOR[field('REG_RB_MRT_BLEND_CONTROL__RGB_DEST_FACTOR', blend_control)],
                     src_alpha=MTL_FACTOR[field('REG_RB_MRT_BLEND_CONTROL__ALPHA_SRC_FACTOR', blend_control)],
                     dst_alpha=MTL_FACTOR[field('REG_RB_MRT_BLEND_CONTROL__ALPHA_DEST_FACTOR', blend_control)])
    scene = dict(width=target['width'], height=target['height'], clear=CLEAR, rt=dict(format='bgra8'), blend=blend,
                 viewport=viewport, vertex=vertex, buffers=buffers, textures=textures, samplers=samplers,
                 vs=dict(bc=air[vs['sidecar']['key_inputs']['air_hash']], metallib=metallib, function=GENERIC[0]),
                 fs=dict(bc=air[fs['sidecar']['key_inputs']['air_hash']], metallib=metallib, function=GENERIC[1]))
    (out / 'scene.json').write_text(json.dumps(scene, indent=1) + '\n')
    return scene


def compare(a, b, w, h):
    assert len(a) == len(b) == w * h * 4
    diffs = [abs(x - y) for x, y in zip(a, b)]
    over = sum(1 for i in range(0, len(diffs), 4) if max(diffs[i:i + 4]) > TOLERANCE)
    mse = sum(d * d for d in diffs) / len(diffs)
    clear = bytes(round(c * 255) for c in (CLEAR[2], CLEAR[1], CLEAR[0], CLEAR[3]))     # BGRA bytes
    drawn = sum(1 for i in range(0, len(a), 4) if a[i:i + 4] != clear)
    return dict(max_abs_diff=max(diffs), mean_abs_diff=round(sum(diffs) / len(diffs), 4), pixels_over_tolerance=over,
                psnr_db=round(10 * math.log10(255 * 255 / mse), 2) if mse else 'inf', metal_pixels_drawn=drawn)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--capture', type=Path, action='append', required=True)
    ap.add_argument('--air-dir', type=Path, required=True)
    ap.add_argument('--nirexec', type=Path, required=True)
    ap.add_argument('--mtlgold', type=Path, required=True)
    ap.add_argument('--output', type=Path, required=True)
    ap.add_argument('--fold-config', action='store_true',
                    help='llvmpipe side: fold the fragment config buffer (constant buffer 0, constant for the draw) into '
                         'the NIR before execution (nirexec NIREXEC_FOLD_UBO=0), which avoids an llvmpipe mis-execution '
                         'of the uber shader\'s dynamic branches on this AArch64 host')
    args = ap.parse_args()
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    air = {}
    for p in sorted(args.air_dir.glob('*.bc')):
        digest = p.name.split('-', 1)[0]
        assert sha(p) == digest
        air[digest] = str(p.resolve())
    report = dict(status='RUNNING', source_sha256=sha(__file__), nirexec_sha256=sha(args.nirexec), mtlgold_sha256=sha(args.mtlgold),
                  tolerance=TOLERANCE, clear=CLEAR, gpu_execution_of_adreno_commands=False, a16_access=False,
                  llvmpipe_config_folded=args.fold_config, draws=[])
    metallib = None
    for path in args.capture:
        cap = Capture(path.resolve())
        scene_name = cap.data['scene']
        for pos, body, state, ubos in walk(cap.words, cap.relocs, cap.copy):
            vs_code, fs_code = cap.code(state, 'SP_VS_BASE'), cap.code(state, 'SP_PS_BASE')
            match = [p for p in cap.programs if vs_code.startswith(bytes.fromhex(p[0]['code_hex'])) and
                     fs_code.startswith(bytes.fromhex(p[1]['code_hex']))]
            assert match, pos
            vs, fs = match[0]
            if (vs['sidecar']['key_inputs']['entry'], fs['sidecar']['key_inputs']['entry']) != GENERIC:
                continue
            if metallib is None:
                pieces = [air[vs['sidecar']['key_inputs']['air_hash']], air[fs['sidecar']['key_inputs']['air_hash']]]
                lib = out / 'generic'
                lib.mkdir()
                for i, p in enumerate(pieces):
                    (lib / f'{i}.air').write_bytes(Path(p).read_bytes())
                metallib = str(lib / 'generic.metallib')
                subprocess.run(['xcrun', '-sdk', 'macosx', 'metallib', str(lib / '0.air'), str(lib / '1.air'), '-o', metallib], check=True)
            d = out / f'{scene_name}-draw-{pos}'
            scene = scene_for(cap, pos, body, state, ubos, vs, fs, air, metallib, d)
            row = dict(scene=scene_name, dword=pos, cp_copies_applied=cap.copies, width=scene['width'], height=scene['height'],
                       viewport=scene['viewport'],
                       count=scene['vertex']['count'], primitive=scene['vertex']['primitive'], blend=scene['blend'],
                       textures=[(t['index'], t['format'], t['width'], t['height'], t.get('type', '2d')) for t in scene['textures']],
                       scene_sha256=sha(d / 'scene.json'))
            for tool, ext in ((args.mtlgold, 'metal'), (args.nirexec, 'lp')):
                env = dict(os.environ)
                if ext == 'lp' and args.fold_config:
                    env['NIREXEC_FOLD_UBO'] = '0'
                r = subprocess.run([str(tool), str(d / 'scene.json'), str(d / f'{ext}.bgra'), '--frames', '3'],
                                   capture_output=True, text=True, env=env)
                (d / f'{ext}.log').write_text(r.stdout + r.stderr)
                row[f'{ext}_exit'] = r.returncode
            if row['metal_exit'] == 0 and row['lp_exit'] == 0:
                row.update(compare((d / 'metal.bgra').read_bytes(), (d / 'lp.bgra').read_bytes(), scene['width'], scene['height']))
                row['metal_sha256'], row['lp_sha256'] = sha(d / 'metal.bgra'), sha(d / 'lp.bgra')
            report['draws'].append(row)
            (out / 'report.json').write_text(json.dumps(report, indent=1) + '\n')
            print(json.dumps({k: row.get(k) for k in ('scene', 'dword', 'count', 'metal_exit', 'lp_exit', 'max_abs_diff',
                                                         'pixels_over_tolerance', 'metal_pixels_drawn')}), flush=True)
    rows = report['draws']
    ok = [r for r in rows if r.get('metal_exit') == 0 and r.get('lp_exit') == 0]
    report['status'] = ('CA_GENERIC_DRAWS_LLVMPIPE_MATCH_METAL' if rows and len(ok) == len(rows) and
                        all(r['pixels_over_tolerance'] == 0 for r in ok) else 'CA_GENERIC_DRAWS_DIFFER_OR_FAILED')
    report['summary'] = dict(draws=len(rows), rendered=len(ok), within_tolerance=sum(1 for r in ok if r['pixels_over_tolerance'] == 0),
                             max_abs_diff=max((r['max_abs_diff'] for r in ok), default=None),
                             pixels_compared=sum(r['width'] * r['height'] for r in ok),
                             metal_pixels_drawn=sum(r['metal_pixels_drawn'] for r in ok))
    (out / 'report.json').write_text(json.dumps(report, indent=1) + '\n')
    print(json.dumps(dict(status=report['status'], summary=report['summary'], output=str(out / 'report.json'))))


if __name__ == '__main__':
    main()

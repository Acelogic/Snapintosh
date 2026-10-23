#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Qualify the kext's ADRENO_KCMD_IB path (design S3 kext side, sections 3.1-3.6) on the host. No hardware access,
no GPU submission, no AuxKC.

Captured segments (an IOGPU segment resource list, and the kernel commands with one ADRENO_KCMD_IB package in the
plug-in's wire format of compat/adreno-submit.h, then the uniform FENCE) are built from q1n1 command streams:
  plan-v2      build/adreno-pipeline-compiler-20260927/draw-plan-v2 (the native Metal triangle, draw-plan-v2)
  varyings-v1  build/adreno-pipeline-compiler-20260927/draw-plan-varyings-v1
  p7           q1n1 a16gpu_p6p7.build_p7_ib, the A16-proven P7 triangle: 2D clear, vertex buffer, a UBO, T#/S# (the
               descriptors move into the package data area, the texture base is a relocation inside the T#)
  stress       plan-v2 repeated 48 times with its relocations shuffled (a 190 KB IB, 576 relocations)
Every address field becomes a zero placeholder plus a relocation against a fixture resource, the kernel zero page
or the package (the plug-in's job, done here independently from q1n1's own tables); the batch fence at the end of
each q1n1 stream (CACHE_FLUSH_TS with WRITE_ENABLED into memptrs) is removed, as design 5.3 specifies.
An expected-refusal matrix is derived from plan-v2 (malicious registers, nested IBs, memory writes, relocation
abuse, oversize and malformed headers, ...).

tools/test-adreno-ib-command.c replays each segment through the production kext core (adreno_kernel_command,
adreno_ib_submit), the production resource list and the monitor's FENCE/CACHE/IB against the RAM/SMMU/CP model,
and reports the relocated package, the words the modeled CP fetched and every relocated address walked through CB0.
This script then proves: the relocated IB equals the source stream dword for dword after address normalisation
(the only difference: the removed batch fence); every refusal has its expected code with no HVC, no cache
maintenance, no frozen list and no latch; an old-dispatch simulation refuses the IB command, and the pinned
historical resource-list source loses CPU stores to the post-submit invalidate. The optional kext build checks
IB symbols. Everything is hash-bound in OUTPUT/qualification.json.

  python3 tools/qualify-adreno-ib-command.py --output DIR [--segment CAPTURED_DIR ...] [--skip-kext]
"""
from pathlib import Path
import argparse
import hashlib
import json
import os
import random
import re
import shutil
import struct
import subprocess
import sys
from source_text import source_files

ROOT = Path(__file__).resolve().parents[1]
Q1N1 = ROOT.parent / 'q1n1' / 'tools'
PLANS = ROOT / 'build' / 'adreno-pipeline-compiler-20260927'
sha = lambda p: hashlib.sha256(Path(p).read_bytes()).hexdigest()

WINDOW = 0x40000000
KCMD_FENCE, KCMD_FILL32, KCMD_IB = 0x1000, 0x1001, 0x1002
RESOURCE, PACKAGE, ZERO = 1, 2, 3
READ, WRITE = 1, 2
NO_HI = 0xffffffff
E = dict(FORMAT=-120, RELOC=-121, PACKET=-122, REGISTER=-123, ADDRESS=-124, CAPACITY=-125, BOUNDS=-126,
         SUBMIT_COMMAND=-91, SUBMIT_UNCERTAIN=-92, SUBMIT_INACTIVE=-93)
OP = dict(NOP=0x10, THREAD_CONTROL=0x17, SKIP_IB2_GLOBAL=0x1d, DRAW_INDIRECT=0x28, BLIT=0x2c, LOAD_STATE6_GEOM=0x32,
          LOAD_STATE6_FRAG=0x34, DRAW_INDX_OFFSET=0x38, REG_TO_MEM=0x3e, WAIT_REG_MEM=0x3c, MEM_WRITE=0x3d,
          INDIRECT_BUFFER=0x3f, MEM_TO_REG=0x42, SET_DRAW_STATE=0x43, EVENT_WRITE7=0x46, SMMU_TABLE_UPDATE=0x53,
          INDIRECT_BUFFER_CHAIN=0x57, CRB=0x5c, NCRB=0x5d, SET_MODE=0x63)


def parity(v):
    v &= 0xffffffff
    return (0x9669 >> (0xf & (v ^ v >> 4 ^ v >> 8 ^ v >> 12 ^ v >> 16 ^ v >> 20 ^ v >> 24 ^ v >> 28))) & 1


def pkt7(op, n):
    return 0x70000000 | n | parity(n) << 15 | (op & 0x7f) << 16 | parity(op) << 23


def pkt4(reg, n):
    return 0x40000000 | n | parity(n) << 7 | (reg & 0x3ffff) << 8 | parity(reg) << 27


def align64(n):
    return (n + 63) & ~63


# ---- the plug-in's wire format -----------------------------------------------------------------------------------
def reloc_record(r):
    return struct.pack('<IIBBBBIQQ', r['lo'], r['hi'], r['kind'], r['access'], r['align'], r['hi_bits'],
                       r['id'], r['offset'], r['length'])


def ib_command(words, data, relocs, **o):
    ib = struct.pack(f'<{len(words)}I', *words)
    package = ib + bytes(align64(len(ib)) - len(ib)) + data
    tail = b''.join(reloc_record(r) for r in relocs)
    size = o.get('size', 48 + len(package) + len(tail))
    head = struct.pack('<IIIIIIIIQQ', o.get('type', KCMD_IB), size, o.get('version', 1), o.get('flags', 0),
                       o.get('ib_dwords', len(words)), o.get('data_bytes', len(data)), o.get('reloc_count', len(relocs)),
                       o.get('reserved0', 0), o.get('reserved1', 0), 0)
    return head + package + tail + o.get('extra', b'')


def resource_list(entries):
    groups = [entries[i:i + 6] for i in range(0, len(entries), 6)]
    out = bytearray(32 + 64 * len(groups))
    struct.pack_into('<I', out, 28, len(groups))
    for g, group in enumerate(groups):
        base = 32 + 64 * g
        for i, (rid, usage) in enumerate(group):
            struct.pack_into('<I', out, base + 4 * i, rid)
            struct.pack_into('<H', out, base + 48 + 2 * i, usage)
        struct.pack_into('<H', out, base + 62, len(group))
    return bytes(out)


FENCE = struct.pack('<II', KCMD_FENCE, 8)


# ---- address fields, found with q1n1's own register/packet tables (independent of the kext validator) -----------
class Tables:
    def __init__(self):
        sys.path.insert(0, str(Q1N1))
        import a8xx_regs as X
        self.X = X
        self.address = {}                         # dword offset -> (name, index, half)
        self.known = set()
        for name, (off, bits, _f, stride, count) in X.REGS.items():
            for i in range(count):
                for h in range(2 if bits == 64 else 1):
                    self.known.add(off + i * stride + h)
                    if bits == 64:
                        self.address[off + i * stride + h] = (name, i, h)
        self.enum = X.ENUMS

    def reg(self, name, i=0):
        off, _bits, _f, stride, _count = self.X.REGS[name]
        return off + i * stride


def packets(words):
    i = 0
    while i < len(words):
        h = words[i]
        if h >> 28 == 4:
            n, reg = h & 0x7f, (h >> 8) & 0x3ffff
            assert h == pkt4(reg, n), hex(h)
            yield 4, i, reg, n
        elif h >> 28 == 7:
            n, op = h & 0x3fff, (h >> 16) & 0x7f
            assert h == pkt7(op, n), hex(h)
            yield 7, i, op, n
        else:
            raise AssertionError(f'bad header {h:#x} at {i}')
        i += 1 + n


def address_fields(words, T):
    """Every 64-bit address in the stream: register pairs, UBO descriptors, LOAD_STATE6 sources, index bases."""
    out = []

    def writes(pairs):
        pairs = list(pairs)
        k = 0
        while k < len(pairs):
            reg, at = pairs[k]
            info = T.address.get(reg)
            if info and info[2] == 0:
                assert k + 1 < len(pairs) and pairs[k + 1][0] == reg + 1, f'{info} without its high half'
                hi_at = pairs[k + 1][1]
                low_other = 3 if info[0] == 'SP_GFX_BINDLESS_BASE_DESCRIPTOR' else 0
                value = (words[at] & ~low_other & 0xffffffff) | words[hi_at] << 32
                out.append(dict(kind='reg', reg=info[0], index=info[1], lo=at, hi=hi_at, value=value,
                                low_other=words[at] & low_other))
                k += 2
                continue
            k += 1
    for t, i, a, n in packets(words):
        if t == 4:
            writes((a + k, i + 1 + k) for k in range(n))
        elif a in (OP['CRB'], OP['NCRB']):
            first = 2 if a == OP['NCRB'] else 0
            writes((words[i + 1 + first + 2 * k], i + 2 + first + 2 * k) for k in range((n - first) // 2))
        elif a in (OP['LOAD_STATE6_GEOM'], OP['LOAD_STATE6_FRAG']):
            w0 = words[i + 1]
            stype, src, units = (w0 >> 14) & 3, (w0 >> 16) & 3, w0 >> 22
            if stype == 2 and src == 0:                               # ST6_UBO, SS6_DIRECT
                for u in range(units):
                    lo, hi = i + 4 + 2 * u, i + 5 + 2 * u
                    value = words[lo] | (words[hi] & 0x1ffff) << 32
                    out.append(dict(kind='ubo', lo=lo, hi=hi, value=value, size=(words[hi] >> 17) * 16))
            elif src == 2:                                            # SS6_INDIRECT
                value = (words[i + 2] & ~3) | words[i + 3] << 32
                out.append(dict(kind='ext', lo=i + 2, hi=i + 3, value=value, units=units,
                                unit=16 if stype == 0 else 64))
        elif a == OP['DRAW_INDX_OFFSET'] and n == 7:
            out.append(dict(kind='index', lo=i + 5, hi=i + 6, value=words[i + 5] | words[i + 6] << 32))
    return [f for f in out if f['value']]


REG_ALIGN = {'RB_MRT_BASE': 6, 'RB_COLOR_FLAG_BUFFER_ADDR': 6, 'RB_A2D_DEST_BUFFER_BASE': 6, 'SP_VS_BASE': 8,
             'SP_PS_BASE': 8, 'SP_PS_SAMPLER_BASE': 4, 'SP_PS_TEXMEMOBJ_BASE': 6, 'SP_GFX_BINDLESS_BASE_DESCRIPTOR': 6,
             'TPL1_GFX_BORDER_COLOR_BASE': 6, 'TPL1_CS_BORDER_COLOR_BASE': 6, 'VFD_VERTEX_BUFFER_BASE': 2}
REG_ACCESS = {'RB_MRT_BASE': READ | WRITE, 'RB_A2D_DEST_BUFFER_BASE': WRITE}


def strip_batch_fence(words, refs):
    """design 5.3: the plug-in never emits the q1n1/gallium batch fence (a CP memory write into memptrs)."""
    tail = words[-5:]
    memptrs = next(r for r in refs if r['window'] == 'memptrs')
    assert tail[0] == pkt7(OP['EVENT_WRITE7'], 4) and tail[1] & (1 << 27), 'no trailing batch fence'
    assert memptrs['va'] <= (tail[2] | tail[3] << 32) < memptrs['va'] + memptrs['size']
    return words[:-5], tail


def make_segment(spec):
    """spec: words, data, relocs, resources [(id, va, length, usage)]. Returns the segment's files."""
    command = ib_command(spec['words'], spec['data'], spec['relocs'], **spec.get('header', {}))
    return {'list.bin': resource_list([(r[0], r[3]) for r in spec['resources']]),
            'commands.bin': command + spec.get('after', FENCE),
            'resources.txt': ''.join(f'{r[0]:x} {r[1]:x} {r[2]:x}\n' for r in spec['resources']).encode()}


def build_fields(words, T, target):
    """Placeholders and relocations for every address field; target(field) -> (kind, id, offset, length)."""
    words = list(words)
    relocs, expected = [], []
    for f in address_fields(words, T):
        kind, rid, offset, length, fixture_base = target(f)
        if f['kind'] == 'reg':
            align, hi_bits = REG_ALIGN[f['reg']], 32
            access = REG_ACCESS.get(f['reg'], READ)
            words[f['lo']], words[f['hi']] = f['low_other'], 0
        elif f['kind'] == 'ubo':
            align, hi_bits, access = 6, 17, READ
            words[f['lo']], words[f['hi']] = 0, words[f['hi']] & ~0x1ffff
        elif f['kind'] == 'ext':
            align = {16: 4, 64: 6}[f['unit']]
            hi_bits, access = 32, READ
            words[f['lo']], words[f['hi']] = words[f['lo']] & 3, 0
        else:
            align, hi_bits, access = 1, 32, READ
            words[f['lo']], words[f['hi']] = 0, 0
        relocs.append(dict(lo=4 * f['lo'], hi=4 * f['hi'], kind=kind, access=access, align=align, hi_bits=hi_bits,
                           id=rid, offset=offset, length=length, field=f))
        expected.append((f, fixture_base))
    return words, relocs, expected


def expected_relocated(words, relocs, bases):
    """The relocated IB words, computed independently: placeholder | fixture address (lo), | high bits (hi)."""
    out = list(words)
    for r in relocs:
        if r['lo'] >= 4 * len(words):
            continue
        address = bases[(r['kind'], r['id'])] + r['offset']
        out[r['lo'] // 4] |= address & 0xffffffff
        if r['hi'] != NO_HI:
            mask = (1 << r['hi_bits']) - 1
            out[r['hi'] // 4] |= (address >> 32) & mask
    return out


# ---- fixtures ------------------------------------------------------------------------------------------------------
RT, VS, FS, TEX, VBO = 0x101, 0x102, 0x103, 0x104, 0x105
FIXTURE_VA = {RT: WINDOW + 0x100000, VS: WINDOW + 0x200000, FS: WINDOW + 0x300000, TEX: WINDOW + 0x400000,
              VBO: WINDOW + 0x500000}


def plan_fixture(plan, T):
    words = list(struct.unpack(f'<{(plan / "draw.ib.bin").stat().st_size // 4}I', (plan / 'draw.ib.bin').read_bytes()))
    refs = json.loads((plan / 'references.json').read_text())
    source, fence = strip_batch_fence(words, refs)
    ref = {r['what']: r for r in refs}
    rt, vs, fs, misc = ref['render target 0'], ref['VS code'], ref['FS code'], ref['border colour table (zeroed)']
    resources = [(RT, FIXTURE_VA[RT], 0x8000, READ | WRITE), (VS, FIXTURE_VA[VS], align64(vs['size']), READ),
                 (FS, FIXTURE_VA[FS], max(0x100, align64(fs['size'])), READ)]

    def target(f):
        v = f['value']
        if misc['va'] <= v < misc['va'] + misc['size']:
            return ZERO, 0, v - misc['va'], misc['size'] - (v - misc['va']), None
        if rt['va'] <= v < rt['va'] + rt['size']:
            return RESOURCE, RT, v - rt['va'], rt['size'] - (v - rt['va']), None
        if vs['va'] <= v < vs['va'] + vs['size']:
            length = f['size'] if f['kind'] == 'ubo' else vs['size'] - (v - vs['va'])
            return RESOURCE, VS, v - vs['va'], length, None
        if fs['va'] <= v < fs['va'] + fs['size']:
            return RESOURCE, FS, v - fs['va'], fs['size'] - (v - fs['va']), None
        raise AssertionError(f'address {v:#x} of {f} is in no reference')
    placeholders, relocs, _ = build_fields(source, T, target)
    return dict(source=source, stripped=fence, words=placeholders, data=b'', relocs=relocs, resources=resources,
                plan_refs=refs)


def p7_fixture(T):
    import a16gpu_p6p7 as M
    sh, _golden, shaders_sha = M.p7_assets(check=False)
    assert shaders_sha == M.P7_SHADERS_SHA256, 'q1n1 P7 shaders changed'
    problems, _findings, sampling = M.variant_checks(sh)
    assert not problems, problems
    win = M.Window(0)
    cs, _link = M.build_p7_ib(win, sh, sampling, 7)
    source, fence = strip_batch_fence(list(cs.w), win.refs)
    refs = win.refs
    data_at = align64(4 * len(source))
    tex_ref = dict(va=M.region_va('p7_tex'), size=M.P7['texture']['pitch'] * M.P7['texture']['height'])
    # Package data: T# at +0, S# at +64, the mvp UBO at +128 (design D10/D11: descriptors and setBytes data).
    tdesc = M.texture_descriptor(0, M.P7['texture']['width'], M.P7['texture']['height'], M.P7['texture']['pitch'], 'rgba')
    data = bytearray(192)
    struct.pack_into('<16I', data, 0, *tdesc)
    struct.pack_into('<4I', data, 64, *M.sampler_descriptor())
    data[128:192] = M.p7_ubo()
    in_data = {'T#': (0, 64), 'S#': (64, 16), 'UBO 1 (mvp)': (128, 64)}
    code = {w: r for r in refs if r['window'] == 'p7_code' for w in [r['what']]}
    vs_size, fs_size = code['VS code']['size'], code['FS code']['size']
    resources = [(RT, FIXTURE_VA[RT], 0x8000, READ | WRITE), (VS, FIXTURE_VA[VS], align64(vs_size), READ),
                 (FS, FIXTURE_VA[FS], align64(fs_size), READ), (TEX, FIXTURE_VA[TEX], tex_ref['size'], READ),
                 (VBO, FIXTURE_VA[VBO], 64, READ)]
    which = {'P7 render target': RT, 'VS code': VS, 'FS code': FS, 'vertex buffer': VBO}

    def target(f):
        v = f['value']
        hits = [r for r in refs if r['va'] <= v < r['va'] + r['size'] and r['window'] != 'memptrs']
        r = min(hits, key=lambda h: h['size'])
        off = v - r['va']
        if r['window'] == 'p67_misc':
            return ZERO, 0, off, r['size'] - off, None
        if r['what'] in in_data:
            at, size = in_data[r['what']]
            return PACKAGE, 0, data_at + at + off, size - off, None
        return RESOURCE, which[r['what']], off, r['size'] - off, None
    placeholders, relocs, _ = build_fields(source, T, target)
    relocs.append(dict(lo=data_at, hi=data_at + 4, kind=RESOURCE, access=READ, align=6, hi_bits=17, id=TEX, offset=0,
                       length=tex_ref['size'], field=dict(kind='tex-base')))
    return dict(source=source, stripped=fence, words=placeholders, data=bytes(data), relocs=relocs, resources=resources,
                plan_refs=refs, tdesc=tdesc)


def stress_fixture(base, copies=48, seed=0x5eed):
    words = base['words'] * copies
    relocs = []
    for c in range(copies):
        for r in base['relocs']:
            relocs.append(dict(r, lo=r['lo'] + 4 * len(base['words']) * c, hi=r['hi'] + 4 * len(base['words']) * c))
    random.Random(seed).shuffle(relocs)                        # the kext must not depend on relocation order
    return dict(base, source=base['source'] * copies, words=words, relocs=relocs)


def refusal_matrix(base, T):
    """(name, spec, expected code): each must be refused before any HVC or cache maintenance."""
    out = []

    def case(name, code, words=None, relocs=None, data=None, header=None, resources=None, after=None):
        spec = dict(base, words=list(words if words is not None else base['words']),
                    relocs=[dict(r) for r in (relocs if relocs is not None else base['relocs'])],
                    data=data if data is not None else base['data'], header=header or {},
                    resources=resources or base['resources'])
        if after is not None:
            spec['after'] = after
        out.append((name, spec, code))
    W, R = base['words'], base['relocs']
    crb = next(i for t, i, a, n in packets(W) if t == 7 and a == OP['CRB'] and n >= 4)
    rt_reloc = next(i for i, r in enumerate(R) if r['field'].get('reg') == 'RB_MRT_BASE')
    vs_reloc = next(i for i, r in enumerate(R) if r['field'].get('reg') == 'SP_VS_BASE')
    ubo_reloc = next(i for i, r in enumerate(R) if r['field']['kind'] == 'ubo')
    bindless = next(i for i, r in enumerate(R) if r['field'].get('reg') == 'SP_GFX_BINDLESS_BASE_DESCRIPTOR')
    draw = next(i for t, i, a, n in packets(W) if t == 7 and a == OP['DRAW_INDX_OFFSET'])
    unknown = next(o for o in range(0x8000, 0x10000) if o not in T.known and o not in T.address)
    with_words = lambda f: (lambda w: (f(w), w)[1])(list(W))
    with_reloc = lambda i, **k: [dict(r, **k) if j == i else dict(r) for j, r in enumerate(R)]
    # malicious register writes
    case('register-protected-cp', E['REGISTER'], words=with_words(lambda w: w.__setitem__(crb + 1, 0x0800)))
    case('register-protected-rbbm', E['REGISTER'], words=with_words(lambda w: w.__setitem__(crb + 1, 0x0014)))
    case('register-unknown', E['REGISTER'], words=with_words(lambda w: w.__setitem__(crb + 1, unknown)))
    case('register-high-bits', E['REGISTER'], words=with_words(lambda w: w.__setitem__(crb + 1, w[crb + 1] | 0x10000000)))
    pkt4_at = next(i for t, i, a, n in packets(W) if t == 4)
    case('pkt4-protected', E['REGISTER'], words=with_words(lambda w: w.__setitem__(pkt4_at, pkt4(0x0800, w[pkt4_at] & 0x7f))))
    # opcodes outside the allowlist (appended after the last packet: nothing else changes)
    ext = lambda *extra: (W + list(extra))
    case('nested-ib', E['PACKET'], words=ext(pkt7(OP['INDIRECT_BUFFER'], 3), 0x40000000, 0, 16))
    case('nested-ib-chain', E['PACKET'], words=ext(pkt7(OP['INDIRECT_BUFFER_CHAIN'], 3), 0x40000000, 0, 16))
    case('draw-state-group', E['PACKET'], words=ext(pkt7(OP['SET_DRAW_STATE'], 3), (3 << 24) | 4, 0x40000000, 0))
    case('cp-mem-write', E['PACKET'], words=ext(pkt7(OP['MEM_WRITE'], 3), 0x10200080, 0, 0x534e7001))
    case('cp-reg-to-mem', E['PACKET'], words=ext(pkt7(OP['REG_TO_MEM'], 3), 0x0800, 0x40000000, 0))
    case('cp-mem-to-reg', E['PACKET'], words=ext(pkt7(OP['MEM_TO_REG'], 3), 0x0800, 0x40000000, 0))
    case('cp-wait-reg-mem', E['PACKET'], words=ext(pkt7(OP['WAIT_REG_MEM'], 5), 0, 0x40000000, 0, 0, 0))
    case('smmu-table-update', E['PACKET'], words=ext(pkt7(OP['SMMU_TABLE_UPDATE'], 4), 0, 0, 0, 0))
    case('draw-indirect', E['PACKET'], words=ext(pkt7(OP['DRAW_INDIRECT'], 3), 0, 0, 0))
    case('event-write-enabled', E['PACKET'], words=W + base['stripped'])            # the q1n1 batch fence itself
    case('event-irq', E['PACKET'], words=ext(pkt7(OP['EVENT_WRITE7'], 1), 0x31 | 1 << 31))
    case('event-not-allowed', E['PACKET'], words=ext(pkt7(OP['EVENT_WRITE7'], 1), 0x04))   # CACHE_FLUSH_TS
    case('set-mode', E['PACKET'], words=ext(pkt7(OP['SET_MODE'], 1), 1))
    case('thread-control-bits', E['PACKET'], words=ext(pkt7(OP['THREAD_CONTROL'], 1), 1 | 1 << 20))
    case('ncrb-header', E['PACKET'], words=ext(pkt7(OP['NCRB'], 4), 2, 0, T.reg('GRAS_SC_CNTL'), 0))
    case('type3-packet', E['PACKET'], words=ext(0xc0001000))
    case('bad-parity', E['PACKET'], words=ext(pkt7(OP['NOP'], 0) ^ 0x8000))
    case('draw-gs', E['PACKET'], words=with_words(lambda w: w.__setitem__(draw + 1, w[draw + 1] | 1 << 16)))
    case('truncated-packet', E['PACKET'], words=W[:-1])
    # relocation abuse
    missing = [dict(r) for j, r in enumerate(R) if j != rt_reloc]
    case('missing-reloc-rt', E['ADDRESS'], relocs=missing,
         words=with_words(lambda w: w.__setitem__(R[rt_reloc]['lo'] // 4, FIXTURE_VA[RT] & 0xffffffff)))
    case('missing-reloc-ubo', E['ADDRESS'], relocs=[dict(r) for j, r in enumerate(R) if j != ubo_reloc],
         words=with_words(lambda w: w.__setitem__(R[ubo_reloc]['lo'] // 4, FIXTURE_VA[VS] + 0x180)))
    case('rt-read-only', E['ADDRESS'], relocs=with_reloc(rt_reloc, access=READ))
    case('rt-package-kind', E['ADDRESS'], relocs=with_reloc(rt_reloc, kind=PACKAGE, id=0, access=READ, offset=0, length=64))
    case('bindless-resource', E['ADDRESS'], relocs=with_reloc(bindless, kind=RESOURCE, id=VS, offset=0, length=64))
    case('ubo-size-over', E['BOUNDS'], relocs=with_reloc(ubo_reloc, length=R[ubo_reloc]['length'] - 16))
    hi_target = next(4 * i for i in range(len(W)) if W[i] == 0 and all(4 * i not in (r['lo'], r['hi']) for r in R))
    case('reloc-hi-elsewhere', E['ADDRESS'], relocs=with_reloc(rt_reloc, hi=hi_target))
    case('reloc-in-padding', E['RELOC'], relocs=R + [dict(R[bindless], lo=4 * len(W), hi=NO_HI, hi_bits=0)])
    case('reloc-overlap', E['RELOC'], relocs=R + [dict(R[rt_reloc])])
    flag = next(i for i, r in enumerate(R) if r['field'].get('reg') == 'RB_COLOR_FLAG_BUFFER_ADDR')
    case('reloc-shared-hi', E['RELOC'], relocs=with_reloc(flag, hi=R[rt_reloc]['hi']))   # two halves, one dword
    case('reloc-write-on-read-usage', E['RELOC'], relocs=with_reloc(vs_reloc, access=READ | WRITE))
    case('reloc-unknown-resource', E['RELOC'], relocs=with_reloc(rt_reloc, id=0x999))
    case('reloc-out-of-range', E['RELOC'], relocs=with_reloc(rt_reloc, offset=0x7f00, length=0x200))
    case('reloc-misaligned', E['RELOC'], relocs=with_reloc(rt_reloc, offset=4))
    case('reloc-placeholder-bits', E['RELOC'],
         words=with_words(lambda w: w.__setitem__(R[rt_reloc]['lo'] // 4, 0x1000)))
    case('reloc-bad-kind', E['RELOC'], relocs=with_reloc(rt_reloc, kind=4))
    case('reloc-zero-length', E['RELOC'], relocs=with_reloc(rt_reloc, length=0))
    case('reloc-zero-write', E['RELOC'], relocs=with_reloc(bindless, access=READ | WRITE))
    nop = W + [pkt7(OP['NOP'], 2), 0, 0]
    case('reloc-in-nop', E['RELOC'], words=nop,
         relocs=R + [dict(R[bindless], lo=4 * (len(W) + 1), hi=4 * (len(W) + 2), hi_bits=32)])
    # oversize and malformed headers
    case('oversize-ib-dwords', E['FORMAT'], header=dict(ib_dwords=0x40001))
    case('oversize-data', E['FORMAT'], header=dict(data_bytes=0x100040))
    case('oversize-relocs', E['FORMAT'], header=dict(reloc_count=16385))
    case('size-mismatch', E['FORMAT'], header=dict(size=48 + align64(4 * len(W)) + 32 * len(R) + 4), after=b'\0' * 4 + FENCE)
    case('data-not-64', E['FORMAT'], data=b'\0' * 32)
    case('version', E['FORMAT'], header=dict(version=2))
    case('flags', E['FORMAT'], header=dict(flags=1))
    case('reserved', E['FORMAT'], header=dict(reserved1=1))
    case('zero-dwords', E['FORMAT'], words=[])
    padded = list(W) + [0]           # one dword of real padding room, then a non-zero padding byte
    case('padding-nonzero', E['FORMAT'], words=padded, header=dict(ib_dwords=len(W)))
    return out


def texture_refusals(p7):
    """Descriptor checks (design R3) and S#/T# bounds, on the P7 package whose data area holds T#, S# and a UBO."""
    out = []
    W, R, D = p7['words'], p7['relocs'], align64(4 * len(p7['words']))

    def case(name, code, relocs=None, data=None, words=None):
        out.append((name, dict(p7, words=list(words or W), relocs=[dict(r) for r in (relocs or R)],
                               data=bytes(data if data is not None else p7['data']), header={}), code))
    base = next(i for i, r in enumerate(R) if r['field']['kind'] == 'tex-base')
    texmem = next(i for i, r in enumerate(R) if r['field'].get('reg') == 'SP_PS_TEXMEMOBJ_BASE')
    sampler_load = next(i for i, r in enumerate(R) if r['field']['kind'] == 'ext' and r['field']['unit'] == 16)
    with_reloc = lambda i, **k: [dict(r, **k) if j == i else dict(r) for j, r in enumerate(R)]
    literal = bytearray(p7['data'])
    struct.pack_into('<I', literal, 0, FIXTURE_VA[TEX] & 0xffffffff)
    case('t-sharp-literal-base', E['ADDRESS'], relocs=[r for j, r in enumerate(R) if j != base], data=literal)
    flag = bytearray(p7['data'])
    struct.pack_into('<I', flag, 16, struct.unpack_from('<I', flag, 16)[0] | 0x40001000)   # FLAG_LO / BASE_U_LO bits
    case('t-sharp-flag-address', E['ADDRESS'], data=flag)
    case('t-sharp-base-align', E['ADDRESS'], relocs=with_reloc(base, align=2))
    case('t-sharp-base-hi-bits', E['ADDRESS'], relocs=with_reloc(base, hi_bits=16))
    case('t-sharp-reloc-inside', E['RELOC'], relocs=R + [dict(R[base], lo=D + 40, hi=NO_HI, hi_bits=0, kind=ZERO,
                                                                id=0, offset=0, length=64)])
    case('t-sharp-array-in-resource', E['ADDRESS'], relocs=with_reloc(texmem, kind=RESOURCE, id=TEX, offset=0, length=64))
    case('t-sharp-array-in-ib', E['ADDRESS'], relocs=with_reloc(texmem, offset=0, length=64))
    case('sampler-count-over', E['BOUNDS'], relocs=with_reloc(sampler_load, length=8, align=2))
    return out


# ---- running ------------------------------------------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--output', type=Path, required=True)
    ap.add_argument('--segment', type=Path, action='append', default=[],
                    help='an externally captured segment directory (list.bin, commands.bin, resources.txt)')
    ap.add_argument('--skip-kext', action='store_true')
    ap.add_argument('--pre-change-ref', default='2cdbae5af3c7ac7d608a9d4ca7609fda3817163b',
                    help='commit before the IB command and resource-list cache fix')
    args = ap.parse_args()
    pre_change_ref = subprocess.check_output(
        ['git', 'rev-parse', '--verify', args.pre_change_ref + '^{commit}'], cwd=ROOT, text=True).strip()
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    commands, record = [], dict(status='RUNNING', a16_access=False, gpu_submission=False)

    def run(name, argv, env=None, expect=0, cwd=ROOT):
        commands.append(argv)
        result = subprocess.run(argv, cwd=cwd, env=dict(os.environ, **(env or {})), text=True,
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        (out / f'{name}.log').write_text(result.stdout)
        if expect is not None:
            assert result.returncode == expect, (name, result.returncode, str(out / f'{name}.log'))
        return result
    env = dict(PYTHONDONTWRITEBYTECODE='1')
    run('tables-fresh', [sys.executable, 'tools/gen-adreno-ib-tables.py', '--check'], env)
    monitor = (ROOT / 'compat/adreno-ib.c').exists()
    sources = ['tools/test-adreno-ib-command.c', 'compat/adreno-ib-command.c'] + (['compat/adreno-ib.c'] if monitor else []) + [
        'compat/adreno-fill-command.c', 'compat/adreno-fill.c', 'compat/adreno-submit.c', 'compat/adreno-resource.c',
        'compat/adreno-resource-list.c', 'compat/adreno.c', 'compat/irq-forward.c', 'shadow/stage2.c',
        'shadow/shadow.c', 'shadow/mmu.c']
    cflags = ['clang', '-std=gnu11', '-Icompat', '-Ishadow', '-O1', '-g', '-fsanitize=address,undefined', '-Wall',
              '-Wextra', '-Werror']
    binary = out / 'test-adreno-ib-command'
    run('build', cflags + sources + ['-o', str(binary)])
    selftest = run('selftest', [str(binary)]).stdout
    assert re.search(r'^PASS: \d+ IB command checks; monitor_ib %d' % monitor, selftest, re.M), 'IB self test'
    assert re.search(r'^PASS: \d+ fill command path checks', selftest, re.M) and 'FAIL' not in selftest

    T = Tables()
    plan_v2 = plan_fixture(PLANS / 'draw-plan-v2', T)
    fixtures = {'plan-v2': plan_v2, 'varyings-v1': plan_fixture(PLANS / 'draw-plan-varyings-v1', T),
                'p7': p7_fixture(T), 'stress': stress_fixture(plan_v2)}
    segments = out / 'segments'
    report = dict(positive={}, refusals={}, external={})

    def replay(name, spec_or_dir, expect_codes):
        d = segments / name
        if isinstance(spec_or_dir, Path):
            shutil.copytree(spec_or_dir, d)
        else:
            d.mkdir(parents=True)
            for f, b in make_segment(spec_or_dir).items():
                (d / f).write_bytes(b)
        if expect_codes is not None:
            (d / 'expect.txt').write_text(''.join(f'{i} {c}\n' for i, c in expect_codes))
        res = run(f'replay-{name}', [str(binary), '--replay', str(d)], expect=None)
        text = (d / 'result.txt').read_text()
        lines = [dict(zip(l.split()[0::2], l.split()[1::2])) for l in text.splitlines() if l.startswith('command ')]
        return res, d, text, lines

    for name, fx in fixtures.items():
        res, d, text, lines = replay(name, fx, [(0, 0), (1, 0)])
        assert res.returncode == 0 and 'failures 0' in text, (name, text)
        assert len(lines) == 2 and lines[0]['rings'] == '1' and lines[0]['from_device'] == '1', lines
        info = dict(l.split(' ', 1) for l in text.splitlines() if not l.startswith('command '))
        bases = {(RESOURCE, r[0]): r[1] for r in fx['resources']}
        bases[(PACKAGE, 0)] = int(info['package_gpu'], 16)
        bases[(ZERO, 0)] = int(info['zero_gpu'], 16)
        package = (d / 'package.bin').read_bytes()
        n = len(fx['words'])
        relocated = list(struct.unpack(f'<{n}I', package[:4 * n]))
        want = expected_relocated(fx['words'], fx['relocs'], bases)
        assert relocated == want, f'{name}: relocated IB differs from the independent prediction'
        # Normalise addresses back to the source stream's: equal dword for dword (the batch fence was removed).
        normal = list(relocated)
        field_words = set()
        for r in fx['relocs']:
            if r['lo'] < 4 * n:
                f = r['field']
                normal[r['lo'] // 4], normal[r['hi'] // 4] = fx['source'][r['lo'] // 4], fx['source'][r['hi'] // 4]
                field_words |= {r['lo'] // 4, r['hi'] // 4}
        assert normal == fx['source'], f'{name}: not equal to the source stream after address normalisation'
        data_equal = None
        if fx['data']:
            data = bytearray(package[align64(4 * n):])
            expect_data = bytearray(fx['data'])
            for r in fx['relocs']:
                if r['lo'] >= 4 * n:
                    address = bases[(r['kind'], r['id'])] + r['offset']
                    struct.pack_into('<I', expect_data, r['lo'] - align64(4 * n),
                                     struct.unpack_from('<I', expect_data, r['lo'] - align64(4 * n))[0] | address & 0xffffffff)
                    struct.pack_into('<I', expect_data, r['hi'] - align64(4 * n),
                                     struct.unpack_from('<I', expect_data, r['hi'] - align64(4 * n))[0] |
                                     (address >> 32) & ((1 << r['hi_bits']) - 1))
            data_equal = bytes(data) == bytes(expect_data)
            assert data_equal, f'{name}: data area'
        fetched_equal = None
        if monitor:
            fetched_equal = (d / 'fetched.bin').read_bytes() == package[:4 * n]
            assert fetched_equal, f'{name}: the CP did not fetch the validated words'
        refs = (d / 'refs.txt').read_text().splitlines()
        assert len(refs) == len(fx['relocs'])
        for line in refs:
            v = dict(zip(line.split()[1::2], line.split()[2::2]))
            if int(v['access']) & WRITE:
                assert v['rdonly'] == '0', line
            if int(v['kind']) != RESOURCE:
                assert v['rdonly'] == '1', line
        report['positive'][name] = dict(ib_dwords=n, data_bytes=len(fx['data']), relocations=len(fx['relocs']),
            source_dwords=len(fx['source']) + len(fx['stripped']), removed=[hex(w) for w in fx['stripped']],
            relocated_equals_prediction=True, equals_source_after_normalisation=True, data_area_equal=data_equal,
            cp_fetched_validated_words=fetched_equal, references_walked=len(refs), result=lines,
            package_sha256=sha(d / 'package.bin'))
    for name, spec, code in refusal_matrix(plan_v2, T) + texture_refusals(fixtures['p7']):
        if name == 'padding-nonzero':
            cmd = bytearray(make_segment(spec)['commands.bin'])
            n = len(plan_v2['words'])
            assert (4 * n) % 64, 'plan-v2 leaves no padding after its IB'
            struct.pack_into('<I', cmd, 48 + 4 * n, 0xff)   # the extra dword, now padding, carries a byte
            d = segments / name
            d.mkdir(parents=True)
            seg = make_segment(spec)
            seg['commands.bin'] = bytes(cmd)
            for f, b in seg.items():
                (d / f).write_bytes(b)
            (d / 'expect.txt').write_text(f'0 {code}\n')
            res = run(f'replay-{name}', [str(binary), '--replay', str(d)], expect=None)
            text = (d / 'result.txt').read_text()
            lines = [dict(zip(l.split()[0::2], l.split()[1::2])) for l in text.splitlines() if l.startswith('command ')]
        else:
            res, d, text, lines = replay(name, spec, [(0, code)])
        first = lines[0]
        ok = (res.returncode == 0 and first['result'] == str(code) and first['rings'] == '0' and
              first['to_device'] == '0' and first['from_device'] == '0' and first['frozen'] == '0' and
              first['latched'] == '0' and len(lines) == 1)
        assert ok, (name, code, text)
        report['refusals'][name] = dict(expected=code, result=int(first['result']), error_at=first['error_at'])
    for i, seg in enumerate(args.segment):
        res, d, text, lines = replay(f'external-{i}', seg.resolve(), None)
        report['external'][str(seg)] = dict(returncode=res.returncode, result=lines)

    # ---- negative controls: historical resource-list source and explicit old-dispatch simulation -------------
    pre = out / 'pre-change-tree'
    for sub in ('compat', 'shadow', 'tools', 'gpu/adreno-kext/include'):
        shutil.copytree(ROOT / sub, pre / sub, ignore=shutil.ignore_patterns('__pycache__'))
    historical = lambda path: subprocess.check_output(['git', '-C', str(ROOT), 'show', f'{pre_change_ref}:{path}'])
    pre_resource_list = historical('compat/adreno-resource-list.c')
    (pre / 'compat/adreno-resource-list.c').write_bytes(pre_resource_list)
    fill_pre = run('pre-change-fill-command-build', cflags + [
        'tools/test-adreno-fill-command.c', 'compat/adreno-fill-command.c', 'compat/adreno-fill.c', 'compat/adreno-submit.c',
        'compat/adreno-resource.c', 'compat/adreno-resource-list.c', 'compat/adreno.c', 'compat/irq-forward.c',
        'shadow/stage2.c', 'shadow/shadow.c', 'shadow/mmu.c', '-o', str(out / 'pre-change-fill-command')], cwd=pre)
    fill_run = run('pre-change-fill-command', [str(out / 'pre-change-fill-command')], expect=1)
    assert 'usage_syncs' in fill_run.stdout and '!dirty[line]' in fill_run.stdout
    head_binary = out / 'test-adreno-ib-command-head-dispatch'
    run('pre-change-dispatch-build', cflags + ['-DADRENO_REPLAY_HEAD_DISPATCH'] + sources + ['-o', str(head_binary)])
    d = segments / 'pre-change-plan-v2'
    d.mkdir(parents=True)
    for f, b in make_segment(plan_v2).items():
        (d / f).write_bytes(b)
    (d / 'expect.txt').write_text('0 0\n')
    head_run = run('pre-change-replay-plan-v2', [str(head_binary), '--replay', str(d)], expect=1)
    head_lines = [l for l in (d / 'result.txt').read_text().splitlines() if l.startswith('command ')]
    assert f'result {E["SUBMIT_COMMAND"]}' in head_lines[0] and 'rings 0' in head_lines[0]
    for f in ('compat/adreno-ib-command.c', 'compat/adreno-ib-command.h', 'compat/adreno-ib-tables.h'):
        (pre / f).unlink()
    ib_pre = run('pre-change-ib-build', cflags + [s for s in sources if s != 'compat/adreno-ib-command.c'] +
                 ['-o', str(out / 'pre-change-ib')], cwd=pre, expect=None)
    assert ib_pre.returncode != 0 and 'adreno-ib-command.h' in ib_pre.stdout
    shutil.rmtree(pre)
    record['pre_change'] = dict(
        ref=pre_change_ref,
        resource_list_sha256=hashlib.sha256(pre_resource_list).hexdigest(),
        boundary='Historical resource-list source in current fixtures; old dispatch and missing IB are simulated.',
        fill_command=dict(returncode=fill_run.returncode,
                          failures=[l for l in fill_run.stdout.splitlines() if l.startswith('FAIL')]),
        head_dispatch_replay=dict(returncode=head_run.returncode, first_command=head_lines[0]),
        ib_test_build=dict(returncode=ib_pre.returncode, error=[l for l in ib_pre.stdout.splitlines() if 'error' in l][:3]))

    if not args.skip_kext:
        kext_env = dict(OUT=str(out / 'kext'))
        run('kext-build', ['sh', 'gpu/adreno-kext/kext/build.sh'], kext_env)
        kext = out / 'kext/AdrenoX2.kext'
        run('kext-signature', ['codesign', '--verify', '--strict', '--verbose=2', str(kext)])
        kbin = kext / 'Contents/MacOS/AdrenoX2'
        raw = kbin.read_bytes()
        assert b'snapintosh,guest-ib-abi\0' in raw and b'AdrenoIBABI\0' in raw
        symbols = run('kext-symbols', ['nm', str(kbin)]).stdout
        for name in ('_adreno_ib_submit', '_adreno_ib_validate', '_adreno_ib_relocate', '_adreno_kernel_command',
                     '_adreno_submit_gated', '_adreno_fence_classify', '_adreno_ib_probe'):
            assert re.search(r'\bT ' + re.escape(name) + r'$', symbols, re.M), name
        disasm = run('kext-disassembly', ['xcrun', 'llvm-objdump', '-d', '--no-show-raw-insn', str(kbin)]).stdout
        ring = disasm[disasm.index('AdrenoAcceleratorX26ibRing'):].split('\n\n')[0]
        assert re.search(r'mov\s+w0, #0x5', ring) and re.search(r'movk\s+w0, #0x1, lsl #16', ring)
        assert 'dsb\tish' in ring and 'hvc\t#0xad16' in ring
        record['kext'] = dict(sha256=sha(kbin), bytes=len(raw), ib_ring=ring.strip().splitlines())

    inputs = ['tools/qualify-adreno-ib-command.py', 'tools/gen-adreno-ib-tables.py', 'compat/adreno-ib-tables.h',
              'gpu/adreno-kext/include/AdrenoA8xxRegs.h', 'gpu/adreno-kext/include/AdrenoContract.h',
              'compat/adreno-ib-command.h', 'compat/adreno-submit.h', 'compat/adreno-guest.h',
              'compat/adreno-resource-list.h', 'compat/adreno.h', 'tools/test-adreno.c', 'tools/test-adreno-fill.c',
              'tools/test-adreno-fill-command.c'] + sources
    if monitor:
        inputs.append('compat/adreno-ib.h')
    for kext_source in ('AdrenoX2.cpp', 'AdrenoX2.h', 'AdrenoSegmentList.cpp', 'AdrenoMemoryMap.cpp'):
        for path in source_files(ROOT / f'gpu/adreno-kext/kext/src/{kext_source}'):   # with its ordered parts
            inputs.append(str(path.relative_to(ROOT)))
    inputs.append('gpu/adreno-kext/kext/build.sh')
    inputs += [str(q.relative_to(ROOT)) for p in inputs if p.endswith('.c') for q in source_files(ROOT / p)[1:]]
    external = {str(p): sha(p) for p in [PLANS / 'draw-plan-v2/draw.ib.bin', PLANS / 'draw-plan-v2/references.json',
                                         PLANS / 'draw-plan-varyings-v1/draw.ib.bin',
                                         PLANS / 'draw-plan-varyings-v1/references.json',
                                         Q1N1 / 'a16gpu_p6p7.py', Q1N1 / 'adreno_x2.py', Q1N1 / 'a8xx_regs.py',
                                         Q1N1 / 'a16gpu-p7/p7-shaders.json']}
    record.update(status='KEXT_IB_PATH_HOST_QUALIFIED_NOT_INSTALLED', monitor_ib_linked=monitor,
                  selftest=[l for l in selftest.splitlines() if l.startswith(('PASS', 'FAIL'))], replay=report,
                  refusal_count=len(report['refusals']), commands=commands,
                  sources_sha256={p: sha(ROOT / p) for p in sorted(set(inputs))}, external_sha256=external,
                  artifacts_sha256={str(p.relative_to(out)): sha(p) for p in sorted(out.rglob('*')) if p.is_file()},
                  boundary='Host model only: the kext core, resource list and monitor FENCE/FILL32/CACHE/IB are the '
                           'production C; IOGPU retain/prepare, the IOKit glue in AdrenoX2.cpp and the CP are models '
                           '(the CP fetches the IB and runs the ring words; it does not execute draws). No A16, no '
                           'AuxKC, no pixels. The kext is built, not installed.')
    (out / 'qualification.json').write_text(json.dumps(record, indent=2) + '\n')
    print(json.dumps(dict(status=record['status'], positives=list(report['positive']),
                          refusals=len(report['refusals']), monitor_ib=monitor, report=str(out / 'qualification.json'))))


if __name__ == '__main__':
    main()

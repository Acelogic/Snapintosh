#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""E2E test of record for depth/stencil render passes in AdrenoMetal (docs/ADRENO-DEPTH-STENCIL-20261017.md).

No A16, no GPU submission. The real AdrenoMetal.bundle is driven through the public Metal API by
gpu/adreno-kext/plugin/harness/target-coverage.m on the host AGX provider (as tools/test-adreno-targets.py does):
a BGRA8 colour target plus a private depth/stencil target, Clear or Load, optionally one draw with a
depth-stencil state, stencil references, a colour write mask, UInt32 indices or a depth-writing fragment function.
The checks read the captured ADRENO_KCMD_IB package register by register against Mesa's gallium a8xx path:
  emit_zs            RB_DEPTH_BUFFER_INFO (format, TILE6_3), pitch, array pitch, base relocation (the depth/stencil
                     texture, written), GRAS_SU_DEPTH_BUFFER_INFO, RB_STENCIL_BUFFER_INFO 0 (packed, no separate)
  emit_sysmem_clears the depth/stencil 2D clear: blit and destination formats, IFMT, TILE6_3/WZYX, the clear words
                     (emit_clear_color), the D24S8 keep-one-aspect PIXEL_OP_BLENDING factors, rectangle and pitch
  fd6_zsa            RB_STENCIL_CNTL (both faces), masks, write masks, RB_STENCIL_REF_CNTL, RB_DEPTH_CNTL,
                     GRAS_SU_DEPTH_CNTL, GRAS_SU_STENCIL_CNTL; RB_PS_OUTPUT_CNTL.FRAG_WRITES_Z
  fd6_blend          RB_MRT_CONTROL.COMPONENT_ENABLE / SP_MRT_BLEND_CNTL_REG.COMPONENT_WRITE_MASK from the write mask
  fd6_draw           CP_DRAW_INDX_OFFSET INDEX4_SIZE_32_BIT with a 4-byte-aligned index relocation
Every captured command stream is then replayed through the production kext validator (compat/adreno-ib-command.c,
tools/test-adreno-ib-command.c --replay): the new register writes must be in the kext's IB register set and every
relocation must be admitted, or the A16 would refuse the IB.

    python3 tools/test-adreno-depth-stencil.py --bundle BUNDLE --output NEW-DIR [--expect-before]

--expect-before checks the unchanged plug-in instead: every pass with a depth or stencil attachment is refused as on
the A16 (the draw builder logs "depth/stencil attachments, layered rendering, MSAA and visibility results are not
supported yet"; the FILL32 clear path then raises "Unsupported Adreno render-pass attachments").
"""
import argparse
import importlib.util
import json
from pathlib import Path
import struct
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, ROOT / path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


T = load('targets', 'tools/test-adreno-targets.py')
P, X, need, Fail = T.P, T.X, T.need, T.Fail
E = X.ENUMS
OLD_REFUSAL = 'depth/stencil attachments, layered rendering, MSAA and visibility results are not supported yet'
D16, D32, S8, D32S8 = 250, 252, 253, 260
W, H = 64, 32
# format: (depth format, 2D destination format, 2D blit format, IFMT, cpp, has depth, has stencil, packed)
ZS = {D16: ('DEPTH6_16', 'FMT6_16_UNORM', 'FMT6_16_UNORM', 'R2D_FLOAT32', 2, True, False, False),
      D32: ('DEPTH6_32', 'FMT6_32_FLOAT', 'FMT6_32_FLOAT', 'R2D_FLOAT32', 4, True, False, False),
      S8: ('DEPTH6_24_8', 'FMT6_Z24_UNORM_S8_UINT_AS_R8G8B8A8', 'FMT6_Z24_UNORM_S8_UINT', 'R2D_INT8', 4, False, True, True),
      D32S8: ('DEPTH6_24_8', 'FMT6_Z24_UNORM_S8_UINT_AS_R8G8B8A8', 'FMT6_Z24_UNORM_S8_UINT', 'R2D_INT8', 4, True, True, True)}
check = T.check
HEADER = (ROOT / 'gpu/adreno-kext/include/AdrenoA8xxRegs.h').read_text()


def header_value(name):
    for line in HEADER.splitlines():
        parts = line.split()
        if len(parts) >= 3 and parts[0] == '#define' and parts[1] == name:
            return int(parts[2].rstrip('uUlL'), 0)
    raise KeyError(name)


STENCIL_OP = {n: header_value(f'A8XX_E_{n}') for n in ('STENCIL_KEEP', 'STENCIL_ZERO', 'STENCIL_INVERT', 'STENCIL_INCR_WRAP',
                                                       'STENCIL_DECR_WRAP')}
INDEX_SIZE = (header_value('A8XX_PKT_CP_DRAW_INDX_OFFSET_0__INDEX_SIZE__SHIFT'),
              header_value('A8XX_PKT_CP_DRAW_INDX_OFFSET_0__INDEX_SIZE__MASK'))
INDX_BASE = header_value('A8XX_PKT_A5XX_CP_DRAW_INDX_OFFSET_INDX_BASE')
field, enum, registers, last = T.field, T.enum, T.registers, T.last


def f32(x):
    return struct.unpack('<I', struct.pack('<f', x))[0]


def zs_layout(fmt):
    cpp = ZS[fmt][4]
    pitch = (W * cpp + 255) & ~255
    return pitch, pitch * ((H + 15) & ~15)


def written(regs, name, index=0):
    off = X.REGS[name][0] + index * X.REGS[name][3]
    return [v for o, v in regs if o == off]


def reloc_at(pkg, words, name):
    base = X.REGS[name][0]
    at = [i for i, o in P.walk_ib(words)[0] if o == base]
    need(at, f'{name} not written')
    return [{r['lo']: r for r in pkg['relocs']}.get(4 * a) for a in at]


def check_zs(name, report, cap, case):
    fmt = case['zs']
    check(report.get('status') == 'TARGET_COMMIT_CAPTURED_NOT_SUBMITTED', f'{name}: {report.get("status")} {report.get("exception")}')
    pkg = T.ib_of(cap)
    words = P.ib_words(pkg)
    regs = registers(words)
    dfmt, dest, blit, ifmt, _cpp, has_d, has_s, packed = ZS[fmt]
    pitch, layer = zs_layout(fmt)
    zs_id = report['zs']['id']
    info = last(regs, 'RB_DEPTH_BUFFER_INFO')
    check(enum('a6xx_depth_format', field('RB_DEPTH_BUFFER_INFO', info, 'DEPTH_FORMAT')) == dfmt, f'{name}: depth format')
    check(enum('a6xx_tile_mode', field('RB_DEPTH_BUFFER_INFO', info, 'TILEMODE')) == 'TILE6_3', f'{name}: depth tile mode')
    check(last(regs, 'RB_DEPTH_BUFFER_PITCH') == pitch >> 6, f'{name}: depth pitch')
    check(last(regs, 'RB_DEPTH_BUFFER_ARRAY_PITCH') == layer >> 6, f'{name}: depth array pitch')
    check(enum('a6xx_depth_format', field('GRAS_SU_DEPTH_BUFFER_INFO', last(regs, 'GRAS_SU_DEPTH_BUFFER_INFO'), 'DEPTH_FORMAT')) == dfmt,
          f'{name}: GRAS_SU_DEPTH_BUFFER_INFO')
    check(last(regs, 'RB_STENCIL_BUFFER_INFO') == 0, f'{name}: no separate stencil')
    r = reloc_at(pkg, words, 'RB_DEPTH_BUFFER_BASE')[-1]
    check(r is not None and r['kind'] == 1 and r['resource_id'] == zs_id and r['access'] & 2 and r['length'] == layer,
          f'{name}: RB_DEPTH_BUFFER_BASE relocation {r}')
    # The 2D clears: colour first, then the depth/stencil buffer when an attached aspect clears.
    clears_zs = (report['zs']['depth'] and not report['zs']['load_depth']) or (report['zs']['stencil'] and not report['zs']['load_stencil'])
    dests = written(regs, 'RB_A2D_DEST_BUFFER_INFO')
    check(len(dests) == 1 + int(clears_zs), f'{name}: {len(dests)} 2D clears')
    if clears_zs:
        d = dests[-1]
        check(enum('a6xx_format', field('RB_A2D_DEST_BUFFER_INFO', d, 'COLOR_FORMAT')) == dest, f'{name}: 2D destination format')
        check(enum('a6xx_tile_mode', field('RB_A2D_DEST_BUFFER_INFO', d, 'TILE_MODE')) == 'TILE6_3', f'{name}: 2D tile mode')
        check(enum('a3xx_color_swap', field('RB_A2D_DEST_BUFFER_INFO', d, 'COLOR_SWAP')) == 'WZYX', f'{name}: 2D swap')
        cntl = last(regs, 'RB_A2D_BLT_CNTL')
        check(enum('a6xx_format', field('RB_A2D_BLT_CNTL', cntl, 'COLOR_FORMAT')) == blit and
              enum('a6xx_2d_ifmt', field('RB_A2D_BLT_CNTL', cntl, 'IFMT')) == ifmt and field('RB_A2D_BLT_CNTL', cntl, 'MASK') == 0xF,
              f'{name}: RB_A2D_BLT_CNTL')
        g = last(regs, 'GRAS_A2D_BLT_CNTL')
        check(enum('a6xx_format', field('GRAS_A2D_BLT_CNTL', g, 'COLOR_FORMAT')) == blit, f'{name}: GRAS_A2D_BLT_CNTL')
        o = last(regs, 'SP_A2D_OUTPUT_INFO')
        check(enum('a6xx_format', field('SP_A2D_OUTPUT_INFO', o, 'COLOR_FORMAT')) == blit and field('SP_A2D_OUTPUT_INFO', o, 'IFMT_TYPE') == 0,
              f'{name}: SP_A2D_OUTPUT_INFO')
        # Unattached aspects keep Metal's defaults (clearDepth 1.0, clearStencil 0); a kept aspect's word is unused.
        depth = 0.5 if report['zs']['depth'] else 1.0
        stencil = 0x5a if report['zs']['stencil'] else 0
        if packed:
            z24 = int(struct.unpack('<f', struct.pack('<f', struct.unpack('<f', struct.pack('<f', depth))[0] * float((1 << 24) - 1)))[0])
            want = [z24 & 0xff, (z24 >> 8) & 0xff, (z24 >> 16) & 0xff, stencil]
        else:
            want = [f32(depth), stencil, 0, 0]
        got = [last(regs, f'RB_A2D_CLEAR_COLOR_DW{i}') for i in range(4)]
        check(got == want, f'{name}: clear words {[hex(x) for x in got]} != {[hex(x) for x in want]}')
        px = last(regs, 'RB_A2D_PIXEL_CNTL')
        op = enum('a6xx_a2d_pixel_op', field('RB_A2D_PIXEL_CNTL', px, 'PIXEL_OP'))
        keep_s = packed and has_s and (not report['zs']['stencil'] or report['zs']['load_stencil'])
        keep_d = packed and has_d and (not report['zs']['depth'] or report['zs']['load_depth'])
        if keep_s:
            check(op == 'PIXEL_OP_BLENDING' and field('RB_A2D_PIXEL_CNTL', px, 'COLOR_SRC_FACTOR') == E['adreno_rb_blend_factor']['FACTOR_ONE']
                  and field('RB_A2D_PIXEL_CNTL', px, 'ALPHA_DST_FACTOR') == E['adreno_rb_blend_factor']['FACTOR_ONE']
                  and field('RB_A2D_PIXEL_CNTL', px, 'COLOR_DST_FACTOR') == 0 and field('RB_A2D_PIXEL_CNTL', px, 'ALPHA_SRC_FACTOR') == 0,
                  f'{name}: depth-only clear keeps stencil')
        elif keep_d:
            check(op == 'PIXEL_OP_BLENDING' and field('RB_A2D_PIXEL_CNTL', px, 'COLOR_DST_FACTOR') == E['adreno_rb_blend_factor']['FACTOR_ONE']
                  and field('RB_A2D_PIXEL_CNTL', px, 'ALPHA_SRC_FACTOR') == E['adreno_rb_blend_factor']['FACTOR_ONE']
                  and field('RB_A2D_PIXEL_CNTL', px, 'COLOR_SRC_FACTOR') == 0 and field('RB_A2D_PIXEL_CNTL', px, 'ALPHA_DST_FACTOR') == 0,
                  f'{name}: stencil-only clear keeps depth')
        else:
            check(op == 'PIXEL_OP_DISABLED', f'{name}: whole-buffer clear')
        br = last(regs, 'GRAS_A2D_DEST_BR')
        check((field('GRAS_A2D_DEST_BR', br, 'X'), field('GRAS_A2D_DEST_BR', br, 'Y')) == (W - 1, H - 1), f'{name}: 2D rectangle')
        check(written(regs, 'RB_A2D_DEST_BUFFER_PITCH')[-1] == pitch >> 6, f'{name}: 2D pitch')
        rr = reloc_at(pkg, words, 'RB_A2D_DEST_BUFFER_BASE')[-1]
        check(rr is not None and rr['resource_id'] == zs_id and rr['access'] == 2, f'{name}: 2D destination relocation {rr}')
    if not case.get('draw'):
        return
    check(any(op == P.R.CP_DRAW_INDX_OFFSET for op, _s, _b in P.walk_ib(words)[1]), f'{name}: draw packet')
    ds = case.get('ds')
    depth_on = ds in ('depth', 'both') and report['zs']['depth']
    stencil_on = ds in ('stencil', 'both') and report['zs']['stencil']
    dc = last(regs, 'RB_DEPTH_CNTL')
    func = E['adreno_compare_func']
    check(field('RB_DEPTH_CNTL', dc, 'Z_TEST_ENABLE') == int(depth_on) and field('RB_DEPTH_CNTL', dc, 'Z_WRITE_ENABLE') == int(depth_on)
          and field('RB_DEPTH_CNTL', dc, 'Z_READ_ENABLE') == int(depth_on)
          and field('RB_DEPTH_CNTL', dc, 'ZFUNC') == (func['FUNC_LEQUAL'] if depth_on else func['FUNC_NEVER'])
          and field('RB_DEPTH_CNTL', dc, 'Z_CLAMP_ENABLE') == 1 and field('RB_DEPTH_CNTL', dc, 'O_DEPTH_01_CLAMP_EN') == 1,
          f'{name}: RB_DEPTH_CNTL {dc:#x}')
    check(last(regs, 'GRAS_SU_DEPTH_CNTL') == int(depth_on), f'{name}: GRAS_SU_DEPTH_CNTL')
    sc = last(regs, 'RB_STENCIL_CNTL')
    op = STENCIL_OP
    if stencil_on:
        want = dict(STENCIL_ENABLE=1, STENCIL_ENABLE_BF=1, STENCIL_READ=1, FUNC=func['FUNC_ALWAYS'], FAIL=op['STENCIL_KEEP'],
                    ZPASS=op['STENCIL_INCR_WRAP'], ZFAIL=op['STENCIL_KEEP'], FUNC_BF=func['FUNC_NOTEQUAL'],
                    FAIL_BF=op['STENCIL_ZERO'], ZPASS_BF=op['STENCIL_DECR_WRAP'], ZFAIL_BF=op['STENCIL_INVERT'])
        got = {k: field('RB_STENCIL_CNTL', sc, k) for k in want}
        check(got == want, f'{name}: RB_STENCIL_CNTL {got}')
        m = last(regs, 'RB_STENCIL_MASK')
        check((field('RB_STENCIL_MASK', m, 'MASK'), field('RB_STENCIL_MASK', m, 'BFMASK')) == (0xf0, 0x0f), f'{name}: stencil masks')
        wm = last(regs, 'RB_STENCIL_WRITE_MASK')
        check((field('RB_STENCIL_WRITE_MASK', wm, 'WRMASK'), field('RB_STENCIL_WRITE_MASK', wm, 'BFWRMASK')) == (0x3c, 0xc3),
              f'{name}: stencil write masks')
        ref = last(regs, 'RB_STENCIL_REF_CNTL')
        check((field('RB_STENCIL_REF_CNTL', ref, 'REF'), field('RB_STENCIL_REF_CNTL', ref, 'BFREF')) == (0x12, 0x34), f'{name}: references')
        check(last(regs, 'GRAS_SU_STENCIL_CNTL') == 1, f'{name}: GRAS_SU_STENCIL_CNTL')
    else:
        check(sc == 0 and last(regs, 'RB_STENCIL_MASK') == 0 and last(regs, 'RB_STENCIL_WRITE_MASK') == 0 and
              last(regs, 'GRAS_SU_STENCIL_CNTL') == 0, f'{name}: stencil off')
    mask = case.get('write_mask', 0xF)
    comps = (1 if mask & 8 else 0) | (2 if mask & 4 else 0) | (4 if mask & 2 else 0) | (8 if mask & 1 else 0)
    check(field('RB_MRT_CONTROL', last(regs, 'RB_MRT_CONTROL'), 'COMPONENT_ENABLE') == comps and
          field('SP_MRT_BLEND_CNTL_REG', last(regs, 'SP_MRT_BLEND_CNTL_REG'), 'COMPONENT_WRITE_MASK') == comps, f'{name}: write mask')
    out = last(regs, 'RB_PS_OUTPUT_CNTL')
    check(field('RB_PS_OUTPUT_CNTL', out, 'FRAG_WRITES_Z') == int(bool(case.get('frag_depth'))), f'{name}: FRAG_WRITES_Z')
    if case.get('index32'):
        draws = [start for code, start, _b in P.walk_ib(words)[1] if code == P.R.CP_DRAW_INDX_OFFSET]
        check(len(draws) == 1, f'{name}: one draw')
        start = draws[0]                                  # payload dword 0
        size = (words[start] & INDEX_SIZE[1]) >> INDEX_SIZE[0]
        check(size == E['a4xx_index_size']['INDEX4_SIZE_32_BIT'], f'{name}: index size {size}')
        rel = {r['lo']: r for r in pkg['relocs']}.get(4 * (start + INDX_BASE))
        check(rel is not None and rel['resource_id'] == report['index_buffer']['id'] and rel['align'] == 2 and rel['length'] == 12,
              f'{name}: index relocation {rel}')


def resource_list(entries):
    """tools/qualify-adreno-ib-command.py resource_list: IOGPU segment resource list groups of six (id, usage)."""
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


def build_replay(out, guest_size=0x400000, arena=0x300000, fixtures=24, capacity=48, name='kernel-replay', arena_pages=17):
    """The production validator in a host replay; larger guest windows hold larger captures (icon rendering)."""
    sources = ['tools/test-adreno-ib-command.c', 'compat/adreno-ib-command.c']
    if (ROOT / 'compat/adreno-ib.c').exists():
        sources.append('compat/adreno-ib.c')
    sources += ['compat/adreno-fill-command.c', 'compat/adreno-fill.c', 'compat/adreno-submit.c', 'compat/adreno-resource.c',
                'compat/adreno-resource-list.c', 'compat/adreno.c', 'compat/irq-forward.c', 'shadow/stage2.c', 'shadow/shadow.c',
                'shadow/mmu.c']
    exe = out / name
    flags = ['clang', '-std=gnu11', '-Icompat', '-Ishadow', f'-DGUEST_SIZE={guest_size:#x}', f'-DIB_ARENA_OFFSET={arena:#x}',
             f'-DIB_FIXTURES={fixtures}', f'-DIB_REPLAY_CAPACITY={capacity}', f'-DIB_ARENA_PAGES={arena_pages}u',
             '-O1', '-g', '-Wall', '-Wextra', '-Werror']
    r = subprocess.run(flags + sources + ['-o', str(exe)], cwd=ROOT, capture_output=True, text=True, timeout=300)
    (out / f'{name}-build.log').write_text(r.stdout + r.stderr)
    need(r.returncode == 0, 'kernel replay build failed')
    return exe


def replay(exe, cap, name, window=0x200000):
    """The capture through the production kext validator: every package admitted, nothing refused."""
    blob = (cap / 'commands.bin').read_bytes()
    resources = {}
    for kind, command in P.kernel_commands(blob):
        if kind != 0x1002:
            continue
        for rel in P.parse_package(command)['relocs']:
            if rel['kind'] == 1:
                rid = rel['resource_id']
                size, usage = resources.get(rid, (0, 0))
                resources[rid] = (max(size, rel['offset'] + rel['length']), usage | (rel['access'] & 3))
    d = cap / 'replay'
    d.mkdir()
    va, rows = 0x40100000, []
    for rid, (size, usage) in sorted(resources.items()):
        mapped = (size + 0x3fff) & ~0x3fff
        rows.append((rid, va, mapped, usage))
        va += mapped
    need(va <= 0x40100000 + window, f'{name}: replay fixtures exceed the host guest window')
    (d / 'commands.bin').write_bytes(blob)
    (d / 'list.bin').write_bytes(resource_list([(r[0], r[3]) for r in rows]))
    (d / 'resources.txt').write_text(''.join(f'{rid:x} {v:x} {n:x}\n' for rid, v, n, _ in rows))
    (d / 'expect.txt').write_text('0 0\n1 0\n')
    r = subprocess.run([str(exe), '--replay', str(d)], cwd=ROOT, capture_output=True, text=True, timeout=120)
    (d / 'replay.log').write_text(r.stdout + r.stderr)
    text = (d / 'result.txt').read_text() if (d / 'result.txt').exists() else ''
    lines = [dict(zip(l.split()[0::2], l.split()[1::2])) for l in text.splitlines() if l.startswith('command ')]
    check(r.returncode == 0 and lines and all(int(l['result']) == 0 for l in lines) and 'failures 0' in text,
          f'{name}: kext replay {[(l.get("type"), l.get("result"), l.get("error_at")) for l in lines]} rc={r.returncode}')


CASES = [
    # name, harness flags, case options
    ('clear-d32', ['--zs', '252'], dict(zs=D32)),
    ('clear-d16', ['--zs', '250'], dict(zs=D16)),
    ('clear-s8', ['--zs', '253'], dict(zs=S8)),
    ('clear-d32s8', ['--zs', '260'], dict(zs=D32S8)),
    ('clear-d32s8-depth-keeps-stencil', ['--zs', '260', '--zs-load-stencil'], dict(zs=D32S8)),
    ('clear-d32s8-stencil-keeps-depth', ['--zs', '260', '--zs-load-depth'], dict(zs=D32S8)),
    ('clear-d32s8-depth-only-attached', ['--zs', '260', '--zs-attach', 'depth'], dict(zs=D32S8)),
    ('load-d32s8', ['--zs', '260', '--zs-load'], dict(zs=D32S8)),
    ('draw-stencil-s8', ['--zs', '253', '--draw', '--ds', 'stencil', '--write-mask', '0'],
     dict(zs=S8, draw=True, ds='stencil', write_mask=0)),
    ('draw-both-d32s8', ['--zs', '260', '--draw', '--ds', 'both'], dict(zs=D32S8, draw=True, ds='both')),
    ('draw-depth-d32-index32', ['--zs', '252', '--draw', '--ds', 'depth', '--index32'],
     dict(zs=D32, draw=True, ds='depth', index32=True)),
    ('draw-default-state-d32s8', ['--zs', '260', '--draw'], dict(zs=D32S8, draw=True)),
    ('draw-depth-writes-d32', ['--zs', '252', '--draw', '--ds', 'depth', '--frag-depth'],
     dict(zs=D32, draw=True, ds='depth', frag_depth=True)),
    ('draw-mask-rgb-d32', ['--zs', '252', '--draw', '--write-mask', '14'], dict(zs=D32, draw=True, write_mask=14)),
]


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--bundle', type=Path, required=True)
    ap.add_argument('--output', type=Path, required=True)
    ap.add_argument('--expect-before', action='store_true')
    args = ap.parse_args()
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    exe = T.build_harness(out)
    kernel = None if args.expect_before else build_replay(out)
    results = {}
    for name, flags, case in CASES:
        report, cap = T.run(exe, args.bundle.resolve(), out, name, '--kind', 'private', '--format', '80', '--size', str(W), str(H), *flags)
        reason = (report.get('exception') or {}).get('reason', '')
        results[name] = dict(status=report.get('status'), reason=reason)
        try:
            if args.expect_before:
                # The draw builder's refusal (OLD_REFUSAL, logged on the A16 by SecurityAgent) sends the pass to the
                # FILL32 clear path, which raises its own refusal for the depth/stencil attachment.
                check(report.get('status') == 'TARGET_EXCEPTION' and (OLD_REFUSAL in reason or
                      reason == 'Unsupported Adreno render-pass attachments'), f'{name}: unchanged plug-in: {reason!r}')
            else:
                check_zs(name, report, cap, case)
                replay(kernel, cap, name)
            results[name]['result'] = 'ok'
        except Fail as error:
            results[name]['result'] = f'FAIL: {error}'
    (out / 'result.json').write_text(json.dumps(dict(bundle=str(args.bundle.resolve()), expect_before=args.expect_before,
                                                     checks=T.checks, cases=results), indent=2, sort_keys=True))
    failed = [n for n, r in results.items() if r['result'] != 'ok']
    for n in failed:
        print(f'{n}: {results[n]["result"]}')
    if failed:
        print(f'FAIL: {len(failed)} of {len(CASES)} cases; {out / "result.json"}')
        return 1
    print(f'PASS: {len(CASES)} depth/stencil cases, {T.checks} checks ({"unchanged plug-in" if args.expect_before else "candidate"}); '
          f'{out / "result.json"}')
    return 0


if __name__ == '__main__':
    sys.exit(main())

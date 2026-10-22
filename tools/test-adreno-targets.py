#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""E2E test of record for WindowServer-shaped render targets in AdrenoMetal (docs/ADRENO-WINDOWSERVER-TARGETS-20261017.md).

No A16, no GPU submission. A real AdrenoMetal.bundle is driven through the public Metal API by
gpu/adreno-kext/plugin/harness/target-coverage.m on the host AGX provider. Each case creates one target
(IOSurface texture, private texture or texture view), encodes a Clear render pass (and optionally one draw),
commits through the plug-in's own commit with the IB ABI simulated, and captures the reserved kernel commands.
The checks read the ADRENO_KCMD_IB package (tools/test-adreno-draw-package.py's parser) and pin, per format:
RB_MRT_BUF_INFO (format, swap), RB_MRT_PITCH, SP_PS_MRT_REG, GRAS_LRZ_MRT_BUFFER_INFO_0, RB_SRGB_CNTL,
SP_SRGB_CNTL, and the 2D clear (RB/GRAS_A2D_BLT_CNTL format and IFMT, SP_A2D_OUTPUT_INFO,
RB_A2D_DEST_BUFFER_INFO format/swap/sRGB, the four clear words, GRAS_A2D_DEST_BR and the destination pitch),
plus the relocation of RB_MRT_BASE to the target's resource. Refusals are pinned by their exception text.

    python3 tools/test-adreno-targets.py --bundle BUNDLE --output NEW-DIR [--expect-before]

--expect-before checks the unchanged plug-in instead: the cases this change adds must fail as the A16 does.

Framebuffer fetch (docs/ADRENO-DEPTH-STENCIL-20261017.md, "Plug-in: framebuffer fetch"; the 'fb' cases). Failure modes
pinned, each from a case below:
  - the pipeline is still refused ("fb_fetch bindings are not supported yet": v29's Dock icon tiles stay blank);
  - the read still goes through bindless set 4, which the kext admits only as the empty zero page (the A16 would refuse
    the whole IB): every SP_GFX_BINDLESS_BASE_DESCRIPTOR must stay a ZERO relocation and no bindless cat5 instruction
    may remain in the uploaded code;
  - the rewritten read names the wrong T# (an application texture's slot, one outside NTEX/SP_PS_TSIZE) or the wrong
    attachment (colour n of an MRT pass), or other code words change;
  - the T# describes the wrong surface: resource, level offset, pitch, size, format, swap, sRGB decode, swizzle, or
    a relocation with write access;
  - the layer input stays FLAT (A16 run 1: the fetch read 0) or the sample id is not delivered;
  - a draw that reads what an earlier draw or the clear wrote misses the feedback barrier (CCU clean, cache clean
    and invalidate, wait for idle), or SINGLE_PRIM_MODE is not FLUSH_PER_OVERLAP_AND_OVERWRITE for the fetch draw;
  - a draw without a fetch changes; a shape that is not built (a storage texture write) is accepted;
  - the production kext validator refuses the package (every 'fb' capture is replayed through it).
"""
import argparse
import importlib.util
import json
import math
from pathlib import Path
import struct
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
HARNESS = ROOT / 'gpu/adreno-kext/plugin/harness/target-coverage.m'
spec = importlib.util.spec_from_file_location('drawpkg', ROOT / 'tools/test-adreno-draw-package.py')
assert spec and spec.loader
P = importlib.util.module_from_spec(spec)
spec.loader.exec_module(P)
X, need, Fail = P.X, P.need, P.Fail
E = X.ENUMS

GEOMETRY = "Adreno clear texture geometry is unavailable or inconsistent"
CLEAR = (0.25, 0.5, 0.75, 1.0)
FMT = {'bgra8': 80, 'bgra8_srgb': 81, 'rgba8': 70, 'rgba8_srgb': 71, 'rgba16f': 115, 'bgr10a2': 94, 'rgb10a2': 90}
# format: (RB format, swap, bytes per pixel, sRGB, 2D IFMT)
HW = {80: ('FMT6_8_8_8_8_UNORM', 'WXYZ', 4, False, 'R2D_UNORM8'),
      81: ('FMT6_8_8_8_8_UNORM', 'WXYZ', 4, True, 'R2D_UNORM8'),
      70: ('FMT6_8_8_8_8_UNORM', 'WZYX', 4, False, 'R2D_UNORM8'),
      71: ('FMT6_8_8_8_8_UNORM', 'WZYX', 4, True, 'R2D_UNORM8'),
      115: ('FMT6_16_16_16_16_FLOAT', 'WZYX', 8, False, 'R2D_FLOAT16'),
      # v18 (docs/ADRENO-DEPTH-STENCIL-20261017.md, "Formats and swizzles"): one- and two-channel targets
      10: ('FMT6_8_UNORM', 'WZYX', 1, False, 'R2D_UNORM8'),
      30: ('FMT6_8_8_UNORM', 'WZYX', 2, False, 'R2D_UNORM8'),
      25: ('FMT6_16_FLOAT', 'WZYX', 2, False, 'R2D_FLOAT16'),
      65: ('FMT6_16_16_FLOAT', 'WZYX', 4, False, 'R2D_FLOAT16'),
      # v35 (ControlCenter's 'l10r' status items): fd6_format_table.c B10G10R10A2_UNORM / R10G10B10A2_UNORM render as
      # 10_10_10_2_UNORM_DEST with R2D_FLOAT16; Metal's BGR10A2Unorm keeps blue in bits 0..9 (measured on the M3 Max)
      94: ('FMT6_10_10_10_2_UNORM_DEST', 'WXYZ', 4, False, 'R2D_FLOAT16'),
      90: ('FMT6_10_10_10_2_UNORM_DEST', 'WZYX', 4, False, 'R2D_FLOAT16')}
# emit_blit_setup: SP_A2D_OUTPUT_INFO takes FMT6_16_16_16_16_FLOAT for a 10_10_10_2_UNORM_DEST destination
A2D_OUTPUT = {'FMT6_10_10_10_2_UNORM_DEST': 'FMT6_16_16_16_16_FLOAT'}
HEADER_TEXT = (ROOT / 'gpu/adreno-kext/include/AdrenoA8xxRegs.h').read_text()


def header_value(name):
    for line in HEADER_TEXT.splitlines():
        parts = line.split()
        if len(parts) >= 3 and parts[0] == '#define' and parts[1] == name:
            return int(parts[2].rstrip('uUlL'), 0)
    raise KeyError(name)


def desc_field(word, name):
    shift = header_value(f'A8XX_DESC_A8XX_TEX_MEMOBJ_3__{name}__SHIFT')
    width = header_value(f'A8XX_DESC_A8XX_TEX_MEMOBJ_3__{name}__WIDTH')
    return (word >> shift) & ((1 << width) - 1)


SWIZ = {c: header_value(f'A8XX_E_A8XX_SWIZ_{c}') for c in ('ZERO', 'ONE', 'X', 'Y', 'Z', 'W')}
# sampled format: (TEX format, the format's own channel mapping as SWIZ names)
SAMPLED = {70: ('FMT6_8_8_8_8_UNORM', ('X', 'Y', 'Z', 'W')), 10: ('FMT6_8_UNORM', ('X', 'ZERO', 'ZERO', 'ONE')),
           25: ('FMT6_16_FLOAT', ('X', 'ZERO', 'ZERO', 'ONE')), 65: ('FMT6_16_16_FLOAT', ('X', 'Y', 'ZERO', 'ONE')),
           1: ('FMT6_8_UNORM', ('ZERO', 'ZERO', 'ZERO', 'X')), 20: ('FMT6_16_UNORM', ('X', 'ZERO', 'ZERO', 'ONE')),
           60: ('FMT6_16_16_UNORM', ('X', 'Y', 'ZERO', 'ONE')), 110: ('FMT6_16_16_16_16_UNORM', ('X', 'Y', 'Z', 'W')),
           55: ('FMT6_32_FLOAT', ('X', 'ZERO', 'ZERO', 'ONE')), 105: ('FMT6_32_32_FLOAT', ('X', 'Y', 'ZERO', 'ONE')),
           125: ('FMT6_32_32_32_32_FLOAT', ('X', 'Y', 'Z', 'W')),
           94: ('FMT6_10_10_10_2_UNORM', ('X', 'Y', 'Z', 'W')), 90: ('FMT6_10_10_10_2_UNORM', ('X', 'Y', 'Z', 'W'))}
SAMPLED_SWAP = {94: 'WXYZ', 90: 'WZYX', 70: 'WZYX'}


def check_level(name, report, cap, fmt, w, h, pitch, offset):
    """A pass into one mip level (or a single-level view of it): that level's pitch, size and offset in the allocation."""
    check(report.get('status') == 'TARGET_COMMIT_CAPTURED_NOT_SUBMITTED', f'{name}: {report.get("status")} {report.get("exception")}')
    pkg = ib_of(cap)
    words = P.ib_words(pkg)
    regs = registers(words)
    rb = HW[fmt][0]
    check(enum('a6xx_format', field('RB_MRT_BUF_INFO', last(regs, 'RB_MRT_BUF_INFO'), 'COLOR_FORMAT')) == rb, f'{name}: format')
    check(last(regs, 'RB_MRT_PITCH') == pitch >> 6, f'{name}: RB_MRT_PITCH {last(regs, "RB_MRT_PITCH")} != {pitch >> 6}')
    at = [i for i, o in P.walk_ib(words)[0] if o == X.REGS['RB_MRT_BASE'][0]]
    need(at, f'{name}: RB_MRT_BASE not written')
    r = {x['lo']: x for x in pkg['relocs']}.get(4 * at[-1])
    check(r is not None and r['resource_id'] == report['texture']['id'] and r['offset'] == offset and r['length'] == pitch * h,
          f'{name}: RB_MRT_BASE relocation {r} (want offset {offset}, length {pitch * h})')
    br = last(regs, 'GRAS_A2D_DEST_BR')
    check((field('GRAS_A2D_DEST_BR', br, 'X'), field('GRAS_A2D_DEST_BR', br, 'Y')) == (w - 1, h - 1), f'{name}: 2D clear covers the level')
    check(last(regs, 'RB_A2D_DEST_BUFFER_PITCH') == pitch >> 6, f'{name}: 2D clear pitch')


BLEND_RB = {0: 'FACTOR_ZERO', 1: 'FACTOR_ONE', 2: 'FACTOR_SRC_COLOR', 3: 'FACTOR_ONE_MINUS_SRC_COLOR', 4: 'FACTOR_SRC_ALPHA',
            5: 'FACTOR_ONE_MINUS_SRC_ALPHA', 6: 'FACTOR_DST_COLOR', 7: 'FACTOR_ONE_MINUS_DST_COLOR', 8: 'FACTOR_DST_ALPHA',
            9: 'FACTOR_ONE_MINUS_DST_ALPHA', 10: 'FACTOR_SRC_ALPHA_SATURATE', 11: 'FACTOR_CONSTANT_COLOR',
            12: 'FACTOR_ONE_MINUS_CONSTANT_COLOR', 13: 'FACTOR_CONSTANT_ALPHA', 14: 'FACTOR_ONE_MINUS_CONSTANT_ALPHA'}


def check_blend(name, report, cap, src, dst):
    """Attachment 0's RB_MRT_BLEND_CONTROL factors, blend enables, and the blend colour constants."""
    check(report.get('status') == 'TARGET_COMMIT_CAPTURED_NOT_SUBMITTED', f'{name}: {report.get("status")} {report.get("exception")}')
    regs = registers(P.ib_words(ib_of(cap)))
    b = last(regs, 'RB_MRT_BLEND_CONTROL')
    for f, want in (('RGB_SRC_FACTOR', src), ('ALPHA_SRC_FACTOR', src), ('RGB_DEST_FACTOR', dst), ('ALPHA_DEST_FACTOR', dst)):
        check(enum('adreno_rb_blend_factor', field('RB_MRT_BLEND_CONTROL', b, f)) == BLEND_RB[want], f'{name}: {f}')
    c = last(regs, 'RB_MRT_CONTROL')
    check(field('RB_MRT_CONTROL', c, 'COLOR_BLEND_EN') == 1 and field('RB_MRT_CONTROL', c, 'ALPHA_BLEND_EN') == 1, f'{name}: blend enables')
    check(field('SP_BLEND_CNTL', last(regs, 'SP_BLEND_CNTL'), 'ENABLE_BLEND') == 1, f'{name}: SP_BLEND_CNTL')
    check([last(regs, f'RB_BLEND_CONSTANT_{c}_FP32') for c in ('RED', 'GREEN', 'BLUE', 'ALPHA')] ==
          [struct.unpack('<I', struct.pack('<f', v))[0] for v in (0.5, 0.25, 0.125, 1.0)], f'{name}: blend constants')


def check_sample(name, report, cap, fmt, swizzle, size=(64, 32), offset=0, levels=1, pitch=None, length=None):
    """The fragment T# (SP_PS_TEXMEMOBJ_BASE, in the package data): format and the swizzle composed with the format's;
    its level count (MIPLVLS), level-0 pitch and lower levels' pitch alignment (MIN_LINE_OFFSET, 256 bytes where the
    pitch allows it), and the relocation's span (every level the GPU may read)."""
    check(report.get('status') == 'TARGET_COMMIT_CAPTURED_NOT_SUBMITTED', f'{name}: {report.get("status")} {report.get("exception")}')
    pkg = ib_of(cap)
    words = P.ib_words(pkg)
    base = X.REGS['SP_PS_TEXMEMOBJ_BASE'][0]
    at = [i for i, o in P.walk_ib(words)[0] if o == base]
    table = {r['lo']: r for r in pkg['relocs']}
    rels = [table.get(4 * a) for a in at]
    rels = [r for r in rels if r and r['kind'] == 2]
    need(rels, f'{name}: no package relocation for SP_PS_TEXMEMOBJ_BASE')
    d = struct.unpack_from('<16I', pkg['package'], rels[-1]['offset'])
    want_fmt, own = SAMPLED[fmt]
    check(enum('a6xx_format', desc_field(d[3], 'FMT')) == want_fmt, f'{name}: T# format')
    if fmt in SAMPLED_SWAP:
        check(enum('a3xx_color_swap', desc_field(d[3], 'SWAP')) == SAMPLED_SWAP[fmt], f'{name}: T# swap')
    pick = {'0': 'ZERO', '1': 'ONE', 'r': own[0], 'g': own[1], 'b': own[2], 'a': own[3]}
    want = [SWIZ[pick[c]] for c in swizzle]
    got = [desc_field(d[3], f'SWIZ_{c}') for c in 'XYZW']
    check(got == want, f'{name}: T# swizzle {got} != {want}')
    rel = [r for r in pkg['relocs'] if r['kind'] == 1 and r['resource_id'] == report['sampled']['id']]
    check(rel and all(r['access'] == 1 for r in rel), f'{name}: sampled texture relocation {rel}')
    check(all(r['offset'] == offset for r in rel), f'{name}: sampled texture offset {[r["offset"] for r in rel]} != {offset}')
    width = (d[2] >> header_value('A8XX_DESC_A8XX_TEX_MEMOBJ_2__WIDTH__SHIFT')) & ((1 << header_value('A8XX_DESC_A8XX_TEX_MEMOBJ_2__WIDTH__WIDTH')) - 1)
    height = (d[2] >> header_value('A8XX_DESC_A8XX_TEX_MEMOBJ_2__HEIGHT__SHIFT')) & ((1 << header_value('A8XX_DESC_A8XX_TEX_MEMOBJ_2__HEIGHT__WIDTH')) - 1)
    check((width, height) == size, f'{name}: T# size {(width, height)} != {size}')
    f6 = lambda f: (d[6] >> header_value(f'A8XX_DESC_A8XX_TEX_MEMOBJ_6__{f}__SHIFT')) & \
        ((1 << header_value(f'A8XX_DESC_A8XX_TEX_MEMOBJ_6__{f}__WIDTH')) - 1)
    check(f6('MIPLVLS') == levels - 1, f'{name}: T# MIPLVLS {f6("MIPLVLS")} != {levels - 1}')
    if pitch is not None:
        check(f6('TEX_LINE_OFFSET') == pitch * 8, f'{name}: T# pitch {f6("TEX_LINE_OFFSET") // 8} != {pitch}')
        want_line = min(2, (pitch & -pitch).bit_length() - 1 - 6)
        check(f6('MIN_LINE_OFFSET') == want_line, f'{name}: T# MIN_LINE_OFFSET {f6("MIN_LINE_OFFSET")} != {want_line}')
    if length is not None:
        check(all(r['length'] == length for r in rel), f'{name}: sampled texture span {[r["length"] for r in rel]} != {length}')


# Framebuffer fetch. The compiler's read: a bindless isamm (cat5 DESC_MODE 5 = CAT5_BINDLESS_UNIFORM, base 4) whose s2en
# register an alias.tex group sets to the descriptor 55 + n and the sampler 0 (BINDING-ABI 3.6).
FB_DESCRIPTOR = 55
VARYING_SLOT_LAYER, INTERP_ZERO = 22, 2
# attachment format: (TEX format, swap, sRGB, the format's own channel mapping)
FETCH = {80: ('FMT6_8_8_8_8_UNORM', 'WXYZ', 0, 'XYZW'), 81: ('FMT6_8_8_8_8_UNORM', 'WXYZ', 1, 'XYZW'),
         70: ('FMT6_8_8_8_8_UNORM', 'WZYX', 0, 'XYZW'), 71: ('FMT6_8_8_8_8_UNORM', 'WZYX', 1, 'XYZW'),
         115: ('FMT6_16_16_16_16_FLOAT', 'WZYX', 0, 'XYZW'),
         10: ('FMT6_8_UNORM', 'WZYX', 0, ('X', 'ZERO', 'ZERO', 'ONE')), 30: ('FMT6_8_8_UNORM', 'WZYX', 0, ('X', 'Y', 'ZERO', 'ONE')),
         25: ('FMT6_16_FLOAT', 'WZYX', 0, ('X', 'ZERO', 'ZERO', 'ONE')), 65: ('FMT6_16_16_FLOAT', 'WZYX', 0, ('X', 'Y', 'ZERO', 'ONE')),
         94: ('FMT6_10_10_10_2_UNORM', 'WXYZ', 0, 'XYZW'), 90: ('FMT6_10_10_10_2_UNORM', 'WZYX', 0, 'XYZW')}
FETCH_CPP = {80: 4, 81: 4, 70: 4, 71: 4, 115: 8, 10: 1, 30: 2, 25: 2, 65: 4, 94: 4, 90: 4}


def bits(w, lo, hi):
    return (w >> lo) & ((1 << (hi - lo + 1)) - 1)


def dfield(word, desc, name):
    for f in X.DESC[desc][2]:
        if f[0] == name:
            return bits(word, f[1], f[2]) << f[3]
    raise KeyError(name)


def instructions(blob):
    return list(struct.unpack(f'<{len(blob) // 8}Q', blob[:len(blob) // 8 * 8]))


def bindless_cat5(w):
    return w >> 61 == 5 and bits(w, 51, 51) and bits(w, 29, 31) in (1, 2, 3, 5, 6, 7)


def alias_group(code, i):
    """The alias.tex entries directly before instruction i: {dst register: (source type, b32, immediate)}."""
    out, j = {}, i - 1
    while j >= 0 and code[j] >> 61 == 7 and bits(code[j], 55, 58) == 0b1000 and \
            (bits(code[j], 49, 49) << 1 | bits(code[j], 47, 47)) == 0:
        out[bits(code[j], 32, 39)] = (bits(code[j], 51, 52), bits(code[j], 50, 50), bits(code[j], 0, 31))
        j -= 1
    return out


def rewritten(w, slot):
    """The non-bindless form of the read: S2EN_BINDLESS, BASE_HI, BASE_LO cleared, SAMP 0, TEX = slot."""
    return (w & ~((1 << 51) | (1 << 47) | (3 << 19) | (0x7FF << 21))) | (slot << 25)


def state_at(regs, at, name, index=0):
    off = X.REGS[name][0] + index * X.REGS[name][3]
    vals = [(p, v) for p, o, v in regs if o == off and p < at]
    need(vals, f'{name} is not written before dword {at}')
    return vals[-1]


def reloc_lo(pkg, lo):
    return {r['lo']: r for r in pkg['relocs']}.get(lo)


def check_fb(name, report, cap, case):
    """A pass whose fragment function reads colour attachments: the read rewritten to a non-bindless T#, that T# the
    attachment's view, the draw state, the feedback barrier, and the kext's validator admitting the package."""
    check(report.get('status') == 'TARGET_COMMIT_CAPTURED_NOT_SUBMITTED', f'{name}: {report.get("status")} {report.get("exception")}')
    pkg = ib_of(cap)
    words = P.ib_words(pkg)
    regpos, packets = P.walk_ib(words)
    regs = [(p, o, words[p]) for p, o in regpos]
    program = json.loads((cap / 'fs-program.json').read_text())
    stats = program['sidecar']['ir3']['stats']
    base, num_samp = max(stats['ntex'], stats['nsamp']), program['num_samp']
    reads = sorted(set(case['reads']))
    slots = {n: base + k for k, n in enumerate(reads)}
    check(program['fb_read'] == 1 and program['bindless'] == [1, 0, 0, 0], f'{name}: the compiler did not report a bindless fb read')
    check(max(slots.values()) < num_samp, f'{name}: fetch slots {slots} beyond num_samp {num_samp}')
    # Attachments: n -> (texture id, format, level width, height, pitch, offset)
    att = {0: (report['texture']['id'], report['format'], *case.get('level0', (case['w'], case['h'], case['pitch'], 0)))}
    for a in (report.get('mrt') or {}).get('attachments', []):
        lay = a['layout']
        att[a['index']] = (a['id'], a['format'], lay['width'], lay['height'], lay['row_bytes'], lay['offset'])
    # The uploaded code: only the reads change, each into `isamm.a ... s#0, t#slot`; no bindless instruction is left.
    orig, patched = (cap / 'fs-original.bin').read_bytes(), (cap / 'fs-patched.bin').read_bytes()
    check(len(patched) >= len(orig) and not any(patched[len(orig):]), f'{name}: code buffer size or padding')
    code, new = instructions(orig), instructions(patched[:len(orig)])
    found = {}
    for i, w in enumerate(code):
        if not bindless_cat5(w):
            check(new[i] == w, f'{name}: code word {i} changed ({w:#018x} -> {new[i]:#018x})')
            continue
        src3 = bits(w, 21, 28)
        group = alias_group(code, i)
        tex, samp = group.get(src3), group.get(src3 + 1)
        need(bits(w, 54, 58) == 0b00010 and bits(w, 29, 31) == 5 and (bits(w, 19, 20) * 2 | bits(w, 47, 47)) == 4,
             f'{name}: bindless word {i} is not the compiler\'s read: {w:#018x}')
        need(tex and tex[0] == 2 and tex[1] == 1 and FB_DESCRIPTOR <= tex[2] < FB_DESCRIPTOR + 8 and samp == (2, 1, 0),
             f'{name}: read {i} alias group {group}')
        n = tex[2] - FB_DESCRIPTOR
        found.setdefault(n, []).append(i)
        check(n in slots and new[i] == rewritten(w, slots[n]), f'{name}: read {i} of colour {n}: {new[i]:#018x} != '
              f'{rewritten(w, slots.get(n, 0)):#018x}')
    check(sorted(found) == reads, f'{name}: reads of colours {sorted(found)}, expected {reads}')
    check(not any(bindless_cat5(w) for w in new), f'{name}: a bindless texture instruction is left in the code')
    # The draws: the fetch draws are the last `draws`; with --fb-sequence one plain draw precedes them.
    draws = [s for op, s, _b in packets if op == P.R.CP_DRAW_INDX_OFFSET]
    check(len(draws) == case.get('draws', 1) + (1 if case.get('sequence') else 0), f'{name}: {len(draws)} draw packets')
    events = [(s, b[0] & 0xFF) for op, s, b in packets if op == P.R.CP_EVENT_WRITE7]
    wfis = [s for op, s, _b in packets if op == P.R.CP_WAIT_FOR_IDLE]
    blits = [s for op, s, _b in packets if op == P.R.CP_BLIT]
    ev = X.ENUMS['vgt_event_type']
    if case.get('sequence'):
        check(field('GRAS_SC_CNTL', state_at(regs, draws[0], 'GRAS_SC_CNTL')[1], 'SINGLE_PRIM_MODE') == 0,
              f'{name}: the plain draw left NO_FLUSH')
    for k, at in enumerate(draws[len(draws) - case.get('draws', 1):]):
        what = f'{name}: fetch draw {k}'
        check(field('GRAS_SC_CNTL', state_at(regs, at, 'GRAS_SC_CNTL')[1], 'SINGLE_PRIM_MODE') ==
              X.ENUMS['a6xx_single_prim_mode']['FLUSH_PER_OVERLAP_AND_OVERWRITE'], f'{what}: SINGLE_PRIM_MODE')
        cfg = state_at(regs, at, 'SP_PS_CONFIG')[1]
        check(field('SP_PS_CONFIG', cfg, 'BINDLESS_TEX') == 0 and field('SP_PS_CONFIG', cfg, 'NTEX') == num_samp and
              field('SP_PS_CONFIG', cfg, 'NSAMP') == num_samp, f'{what}: SP_PS_CONFIG {cfg:#x}')
        check(state_at(regs, at, 'SP_PS_TSIZE')[1] == num_samp, f'{what}: SP_PS_TSIZE')
        for i in range(5):
            p, _v = state_at(regs, at, 'SP_GFX_BINDLESS_BASE_DESCRIPTOR', i)
            r = reloc_lo(pkg, 4 * p)
            check(r is not None and r['kind'] == 3, f'{what}: bindless set {i} is not the zero page ({r})')
        p, _v = state_at(regs, at, 'SP_PS_TEXMEMOBJ_BASE')
        tr = reloc_lo(pkg, 4 * p)
        need(tr is not None and tr['kind'] == 2 and tr['length'] >= 64 * num_samp, f'{what}: SP_PS_TEXMEMOBJ_BASE {tr}')
        for n, slot in slots.items():
            rid, fmt, w, h, pitch, offset = att[n]
            d = struct.unpack_from('<16I', pkg['package'], tr['offset'] + 64 * slot)
            tfmt, swap, srgb, own = FETCH[fmt]
            check(dfield(d[1], 'A8XX_TEX_MEMOBJ_1', 'TYPE') == X.ENUMS['a6xx_tex_type']['A6XX_TEX_2D'] and
                  dfield(d[1], 'A8XX_TEX_MEMOBJ_1', 'DEPTH') == 1, f'{what}: colour {n} T# type')
            check((dfield(d[2], 'A8XX_TEX_MEMOBJ_2', 'WIDTH'), dfield(d[2], 'A8XX_TEX_MEMOBJ_2', 'HEIGHT')) == (w, h) and
                  dfield(d[2], 'A8XX_TEX_MEMOBJ_2', 'SAMPLES') == 0, f'{what}: colour {n} T# size')
            check(enum('a6xx_format', dfield(d[3], 'A8XX_TEX_MEMOBJ_3', 'FMT')) == tfmt and
                  enum('a3xx_color_swap', dfield(d[3], 'A8XX_TEX_MEMOBJ_3', 'SWAP')) == swap, f'{what}: colour {n} T# format')
            check([dfield(d[3], 'A8XX_TEX_MEMOBJ_3', f'SWIZ_{c}') for c in 'XYZW'] == [SWIZ[c] for c in own],
                  f'{what}: colour {n} T# swizzle')
            check(dfield(d[4], 'A8XX_TEX_MEMOBJ_4', 'TILE_MODE') == 0 and dfield(d[4], 'A8XX_TEX_MEMOBJ_4', 'SRGB') == srgb,
                  f'{what}: colour {n} T# tile mode / sRGB')
            check(dfield(d[6], 'A8XX_TEX_MEMOBJ_6', 'TEX_LINE_OFFSET') == pitch * 8 and
                  dfield(d[6], 'A8XX_TEX_MEMOBJ_6', 'MIPLVLS') == 0, f'{what}: colour {n} T# pitch')
            r = reloc_lo(pkg, tr['offset'] + 64 * slot)
            check(r is not None and r['kind'] == 1 and r['resource_id'] == rid and r['access'] == 1 and
                  r['offset'] == offset and r['length'] == pitch * h, f'{what}: colour {n} T# relocation {r}')
        layer = [x for x in program['inputs'] if x['slot'] == VARYING_SLOT_LAYER and x['compmask'] & 1 and x['bary']]
        check(len(layer) == 1, f'{what}: the layer input {layer}')
        loc = layer[0]['inloc']
        mode = state_at(regs, at, 'VPC_VARYING_INTERP_MODE_MODE', loc // 16)[1]
        check((mode >> (2 * (loc % 16))) & 3 == INTERP_ZERO, f'{what}: layer at {loc} not INTERP_ZERO ({mode:#x})')
        sid = program['sysval_regids']['SYSTEM_VALUE_SAMPLE_ID']
        check(sid != 0xFC and field('SP_REG_PROG_ID_0', state_at(regs, at, 'SP_REG_PROG_ID_0')[1], 'SAMPLEID') == sid and
              field('RB_PS_INPUT_CNTL', state_at(regs, at, 'RB_PS_INPUT_CNTL')[1], 'SAMPLEID') == 1, f'{what}: sample id')
        # The feedback barrier after the last colour write (the 2D clear or an earlier draw), before this draw.
        last = max([s for s in blits + draws if s < at], default=None)
        if case.get('barrier', True) or k or case.get('sequence'):
            need(last is not None, f'{what}: nothing wrote the attachments before it')
            seq = [e for s, e in events if last < s < at]
            want = [ev['CCU_CLEAN_COLOR'], ev['CACHE_CLEAN'], ev['CACHE_INVALIDATE7']]
            it = iter(seq)
            check(all(x in it for x in want), f'{what}: barrier events {seq}')
            inval = max(s for s, e in events if last < s < at and e == ev['CACHE_INVALIDATE7']) if \
                ev['CACHE_INVALIDATE7'] in seq else at
            check(any(inval < s < at for s in wfis), f'{what}: no wait for idle after the invalidate')
        else:
            check(sum(1 for s, e in events if s < at and e == ev['CACHE_INVALIDATE7']) == 1,
                  f'{what}: a barrier in a Load pass before any write')
def check_shape(name, report, cap, case):
    """v38's declared-but-unsupplied bindings (com.apple.dock.extra, loginwindow): the draw is built; a used texture left
    unbound reads a 1x1 RGBA8 T# on the zero page, a used unbound sampler Metal's default state; a binding the code never
    reads (above ntex/nsamp, or without uses) gets nothing; an unused device buffer leaves no driver table."""
    check(report.get('status') == 'TARGET_COMMIT_CAPTURED_NOT_SUBMITTED', f'{name}: {report.get("status")} {report.get("exception")}')
    pkg = ib_of(cap)
    words = P.ib_words(pkg)
    regpos, packets = P.walk_ib(words)
    regs = [(p_, o, words[p_]) for p_, o in regpos]
    program = json.loads((cap / 'fs-program.json').read_text())
    draws = [s_ for op, s_, _b in packets if op == P.R.CP_DRAW_INDX_OFFSET]
    check(len(draws) == 1, f'{name}: {len(draws)} draw packets')
    at, shape = draws[0], case['shape']
    num_samp = program['num_samp']
    if shape in ('unbound-texture', 'unused-texture1', 'unbound-sampler', 'range-texture', 'lod-sampler'):
        check(state_at(regs, at, 'SP_PS_TSIZE')[1] == num_samp == 1, f'{name}: SP_PS_TSIZE / num_samp {num_samp}')
        p_, _v = state_at(regs, at, 'SP_PS_TEXMEMOBJ_BASE')
        tr = reloc_lo(pkg, 4 * p_)
        need(tr is not None and tr['kind'] == 2, f'{name}: SP_PS_TEXMEMOBJ_BASE {tr}')
        d = struct.unpack_from('<16I', pkg['package'], tr['offset'])
        r = reloc_lo(pkg, tr['offset'])
        if shape == 'unbound-texture':
            check(r is not None and r['kind'] == 3 and r['access'] == 1, f'{name}: T#0 is not the zero page ({r})')
            check((dfield(d[2], 'A8XX_TEX_MEMOBJ_2', 'WIDTH'), dfield(d[2], 'A8XX_TEX_MEMOBJ_2', 'HEIGHT')) == (1, 1) and
                  enum('a6xx_format', dfield(d[3], 'A8XX_TEX_MEMOBJ_3', 'FMT')) == 'FMT6_8_8_8_8_UNORM' and
                  dfield(d[1], 'A8XX_TEX_MEMOBJ_1', 'TYPE') == X.ENUMS['a6xx_tex_type']['A6XX_TEX_2D'], f'{name}: zero T# shape')
        else:
            check(r is not None and r['kind'] == 1 and r['resource_id'] == report['sampled']['id'], f'{name}: T#0 {r}')
        p_, _v = state_at(regs, at, 'SP_PS_SAMPLER_BASE')
        sr = reloc_lo(pkg, 4 * p_)
        need(sr is not None and sr['kind'] == 2, f'{name}: SP_PS_SAMPLER_BASE {sr}')
        s0 = struct.unpack_from('<I', pkg['package'], sr['offset'])[0]
        if shape in ('range-texture', 'lod-sampler'):
            # --sampler-edge: linear filters; the default S# (unbound) would be nearest
            check(dfield(s0, 'A8XX_TEX_SAMP_0', 'XY_MAG') != 0 and dfield(s0, 'A8XX_TEX_SAMP_0', 'XY_MIN') != 0,
                  f'{name}: S#0 {s0:#x} is not the bound linear sampler')
        if shape == 'unbound-sampler':
            clamp = X.ENUMS['a6xx_tex_clamp']['A6XX_TEX_CLAMP_TO_EDGE']
            check([dfield(s0, 'A8XX_TEX_SAMP_0', f) for f in ('MIPMAPING_DIS', 'XY_MAG', 'XY_MIN', 'WRAP_S', 'WRAP_T', 'WRAP_R')] ==
                  [1, 0, 0, clamp, clamp, clamp], f'{name}: S#0 {s0:#x} is not the default sampler')
    else:
        ubo = [(s_, b) for op, s_, b in packets if op == P.R.CP_LOAD_STATE6_FRAG and s_ < at and
               bits(b[0], 14, 15) == X.ENUMS['a6xx_state_type']['ST6_UBO'] and bits(b[0], 0, 13) == 0]
        need(ubo, f'{name}: no fragment UBO table')
        s_, b = ubo[-1]
        n = bits(b[0], 22, 31)
        check(n == program['const_state']['num_app_ubos'], f'{name}: {n} UBO descriptors, ir3 loads {program["const_state"]["num_app_ubos"]}')
        relocated = [k for k in range(n) if reloc_lo(pkg, 4 * (s_ + 3 + 2 * k))]
        check(relocated == [0], f'{name}: UBO descriptors relocated {relocated}, expected only constant buffer(0)')
        check(all(b[3 + 2 * k] == 0 and b[4 + 2 * k] == 0 for k in range(1, n)), f'{name}: unread UBO descriptors are not empty')
        check(program['sidecar']['ir3']['stats']['driver_table_ubo'] == -1 and
              not any(r['kind'] == 2 and r['length'] == 384 for r in pkg['relocs']), f'{name}: a driver table was written')


def check_prim(name, report, cap, want):
    """v80: a line list or line strip draw is built with the matching DI_PT (fd6 primtypes[]): exactly one
    CP_DRAW_INDX_OFFSET whose PRIM_TYPE field is DI_PT_LINELIST / DI_PT_LINESTRIP."""
    check(report.get('status') == 'TARGET_COMMIT_CAPTURED_NOT_SUBMITTED', f'{name}: {report.get("status")} {report.get("exception")}')
    pkg = ib_of(cap)
    draws = [b for op, _s, b in P.walk_ib(P.ib_words(pkg))[1] if op == P.R.CP_DRAW_INDX_OFFSET]
    check(len(draws) == 1, f'{name}: {len(draws)} draw packets')
    if draws:
        prim = draws[0][0] & 0x3f
        check(prim == X.ENUMS['pc_di_primtype'][want], f'{name}: PRIM_TYPE {prim:#x}, want {want}')


def check_mrt_formats(name, report, cap, n_att, draw):
    """emit_mrt per attachment (RB_MRT_BUF_INFO format/swap, RB_MRT_PITCH, SP_PS_MRT_REG, RB_MRT_BASE on the attachment)
    and each attachment's 2D clear (format, swap, the A2D output format, its own colour as half words)."""
    check(report.get('status') == 'TARGET_COMMIT_CAPTURED_NOT_SUBMITTED', f'{name}: {report.get("status")} {report.get("exception")}')
    pkg = ib_of(cap)
    words = P.ib_words(pkg)
    regs = registers(words)
    att = [(report['texture']['id'], report['format'], report['layout']['row_bytes'])] + \
          [(a['id'], a['format'], a['layout']['row_bytes']) for a in report['mrt']['attachments']]
    check(len(att) == n_att, f'{name}: {len(att)} attachments')
    for n, (rid, fmt, pitch) in enumerate(att):
        rb, swap = HW[fmt][0], HW[fmt][1]
        info = last(regs, 'RB_MRT_BUF_INFO', n)
        check(enum('a6xx_format', field('RB_MRT_BUF_INFO', info, 'COLOR_FORMAT')) == rb and
              enum('a3xx_color_swap', field('RB_MRT_BUF_INFO', info, 'COLOR_SWAP')) == swap, f'{name}: RB_MRT_BUF_INFO({n})')
        check(last(regs, 'RB_MRT_PITCH', n) == pitch >> 6, f'{name}: RB_MRT_PITCH({n})')
        check(enum('a6xx_format', field('SP_PS_MRT_REG', last(regs, 'SP_PS_MRT_REG', n), 'COLOR_FORMAT')) == rb, f'{name}: SP_PS_MRT_REG({n})')
        off = X.REGS['RB_MRT_BASE'][0] + n * X.REGS['RB_MRT_BASE'][3]
        at = [i for i, o in P.walk_ib(words)[0] if o == off]
        r = {x['lo']: x for x in pkg['relocs']}.get(4 * at[-1]) if at else None
        check(r is not None and r['resource_id'] == rid and r['access'] & 2, f'{name}: RB_MRT_BASE({n}) {r}')
    dests = [v for o, v in regs if o == X.REGS['RB_A2D_DEST_BUFFER_INFO'][0]]
    outs = [v for o, v in regs if o == X.REGS['SP_A2D_OUTPUT_INFO'][0]]
    check(len(dests) == n_att and len(outs) == n_att, f'{name}: {len(dests)} 2D clears')
    for n, (rid, fmt, pitch) in enumerate(att):
        rb, swap = HW[fmt][0], HW[fmt][1]
        check(enum('a6xx_format', field('RB_A2D_DEST_BUFFER_INFO', dests[n], 'COLOR_FORMAT')) == rb and
              enum('a3xx_color_swap', field('RB_A2D_DEST_BUFFER_INFO', dests[n], 'COLOR_SWAP')) == swap and
              enum('a6xx_format', field('SP_A2D_OUTPUT_INFO', outs[n], 'COLOR_FORMAT')) == A2D_OUTPUT.get(rb, rb),
              f'{name}: attachment {n} 2D clear formats')
    if draw:
        check(field('RB_PS_MRT_CNTL', last(regs, 'RB_PS_MRT_CNTL'), 'MRT') == n_att, f'{name}: RB_PS_MRT_CNTL')
        check(any(op == P.R.CP_DRAW_INDX_OFFSET for op, _s, _b in P.walk_ib(words)[1]), f'{name}: draw packet')


checks = 0


def check(condition, what):
    global checks
    checks += 1
    need(condition, what)


def enum(table, value):
    """The enumerator name of value in table (first match)."""
    for name, v in E[table].items():
        if v == value:
            return name
    raise KeyError(f'{table} {value}')


def unorm8(x):
    """AdrenoFillCommands.m clearChannel / AdrenoClearByte: float, clamp, floorf(x * 255 + 0.5)."""
    f = struct.unpack('<f', struct.pack('<f', min(max(x, 0.0), 1.0)))[0]
    s = struct.unpack('<f', struct.pack('<f', f * 255.0))[0]
    return int(math.floor(struct.unpack('<f', struct.pack('<f', s + 0.5))[0]))


def srgb(x):
    """IEC 61966-2-1 linear to sRGB, the encoding a sRGB target stores."""
    x = min(max(x, 0.0), 1.0)
    return 12.92 * x if x <= 0.0031308 else 1.055 * x ** (1 / 2.4) - 0.055


def half(x):
    return struct.unpack('<H', struct.pack('<e', x))[0]


def clear_words(fmt):
    rb, swap, cpp, is_srgb, ifmt = HW[fmt]
    if ifmt == 'R2D_FLOAT16':
        return [half(c) for c in CLEAR]
    return [unorm8(srgb(c)) if is_srgb and i < 3 else unorm8(c) for i, c in enumerate(CLEAR)]


def field(name, value, fname):
    for f in X.REGS[name][2]:
        if f[0] == fname:
            lo, hi = f[1], f[2]
            return (value >> lo) & ((1 << (hi - lo + 1)) - 1)
    raise KeyError(fname)


def registers(words):
    """Every register write in the IB, in order: [(offset, value)]."""
    regs, _packets = P.walk_ib(words)
    return [(off, words[at]) for at, off in regs]


def last(regs, name, index=0):
    off = X.REGS[name][0] + index * X.REGS[name][3]
    vals = [v for o, v in regs if o == off]
    need(vals, f'{name} is not written')
    return vals[-1]


def build_harness(out):
    exe = out / 'target-coverage'
    subprocess.run(['xcrun', 'clang', '-arch', 'arm64e', '-fobjc-arc', '-O1', '-o', str(exe), str(HARNESS),
                    '-framework', 'Foundation', '-framework', 'Metal', '-framework', 'IOKit', '-framework', 'IOSurface'],
                   check=True)
    subprocess.run(['codesign', '-f', '-s', '-', str(exe)], check=True, capture_output=True)
    return exe


def run(exe, bundle, out, name, *flags):
    report, cap = out / f'{name}.json', out / name
    with (out / f'{name}.log').open('x') as log:
        proc = subprocess.run([str(exe), str(bundle), str(report), '--out', str(cap), *flags],
                              cwd=ROOT, stdout=log, stderr=subprocess.STDOUT, timeout=300)
    data = json.loads(report.read_text()) if report.exists() else {}
    data['returncode'] = proc.returncode
    return data, cap


def ib_of(cap):
    commands = P.kernel_commands((cap / 'commands.bin').read_bytes())
    packages = [P.parse_package(c) for k, c in commands if k == 0x1002]
    need(len(packages) == 1, f'{len(packages)} IB packages')
    return packages[0]


def check_target(name, report, cap, fmt, w, h, pitch, draw):
    """The pass built by the IB builder for a target of fmt, w x h, pitch bytes per row."""
    check(report.get('status') == 'TARGET_COMMIT_CAPTURED_NOT_SUBMITTED',
          f'{name}: {report.get("status")} {report.get("exception")}')
    pkg = ib_of(cap)
    words = P.ib_words(pkg)
    regs = registers(words)
    rb, swap, cpp, is_srgb, ifmt = HW[fmt]
    v = last(regs, 'RB_MRT_BUF_INFO')
    check(enum('a6xx_format', field('RB_MRT_BUF_INFO', v, 'COLOR_FORMAT')) == rb, f'{name}: RB_MRT_BUF_INFO format')
    check(enum('a3xx_color_swap', field('RB_MRT_BUF_INFO', v, 'COLOR_SWAP')) == swap, f'{name}: RB_MRT_BUF_INFO swap')
    check(last(regs, 'RB_MRT_PITCH') == pitch >> 6, f'{name}: RB_MRT_PITCH')   # 64-byte units
    check(enum('a6xx_format', field('SP_PS_MRT_REG', last(regs, 'SP_PS_MRT_REG'), 'COLOR_FORMAT')) == rb, f'{name}: SP_PS_MRT_REG')
    check(enum('a6xx_format', field('GRAS_LRZ_MRT_BUFFER_INFO_0', last(regs, 'GRAS_LRZ_MRT_BUFFER_INFO_0'), 'COLOR_FORMAT')) == rb,
          f'{name}: GRAS_LRZ_MRT_BUFFER_INFO_0')
    check(last(regs, 'RB_SRGB_CNTL') == int(is_srgb) and last(regs, 'SP_SRGB_CNTL') == int(is_srgb), f'{name}: sRGB controls')
    if not report['load']:
        cntl = last(regs, 'RB_A2D_BLT_CNTL')
        check(enum('a6xx_format', field('RB_A2D_BLT_CNTL', cntl, 'COLOR_FORMAT')) == rb, f'{name}: RB_A2D_BLT_CNTL format')
        check(enum('a6xx_2d_ifmt', field('RB_A2D_BLT_CNTL', cntl, 'IFMT')) == ifmt, f'{name}: RB_A2D_BLT_CNTL IFMT')
        gcntl = last(regs, 'GRAS_A2D_BLT_CNTL')
        check(enum('a6xx_format', field('GRAS_A2D_BLT_CNTL', gcntl, 'COLOR_FORMAT')) == rb and
              enum('a6xx_2d_ifmt', field('GRAS_A2D_BLT_CNTL', gcntl, 'IFMT')) == ifmt, f'{name}: GRAS_A2D_BLT_CNTL')
        out_info = last(regs, 'SP_A2D_OUTPUT_INFO')
        check(enum('a6xx_format', field('SP_A2D_OUTPUT_INFO', out_info, 'COLOR_FORMAT')) == A2D_OUTPUT.get(rb, rb) and
              field('SP_A2D_OUTPUT_INFO', out_info, 'SRGB') == 0, f'{name}: SP_A2D_OUTPUT_INFO')
        dst = last(regs, 'RB_A2D_DEST_BUFFER_INFO')
        check(enum('a6xx_format', field('RB_A2D_DEST_BUFFER_INFO', dst, 'COLOR_FORMAT')) == rb, f'{name}: 2D dest format')
        check(enum('a3xx_color_swap', field('RB_A2D_DEST_BUFFER_INFO', dst, 'COLOR_SWAP')) == swap, f'{name}: 2D dest swap')
        check(field('RB_A2D_DEST_BUFFER_INFO', dst, 'SRGB') == 0, f'{name}: 2D dest stores encoded bytes (SRGB clear)')
        got = [last(regs, f'RB_A2D_CLEAR_COLOR_DW{i}') for i in range(4)]
        check(got == clear_words(fmt), f'{name}: clear words {[hex(g) for g in got]} != {[hex(c) for c in clear_words(fmt)]}')
        br = last(regs, 'GRAS_A2D_DEST_BR')
        check((field('GRAS_A2D_DEST_BR', br, 'X'), field('GRAS_A2D_DEST_BR', br, 'Y')) == (w - 1, h - 1), f'{name}: 2D rectangle')
        check(last(regs, 'RB_A2D_DEST_BUFFER_PITCH') == pitch >> 6, f'{name}: 2D pitch')
    # The target is the relocated, GPU-written resource of RB_MRT_BASE.
    mrt_base = X.REGS['RB_MRT_BASE'][0]
    at = [i for i, o in P.walk_ib(words)[0] if o == mrt_base]
    need(at, f'{name}: RB_MRT_BASE not written')
    relocs = {r['lo']: r for r in pkg['relocs']}
    r = relocs.get(4 * at[-1])
    check(r is not None and r['kind'] == 1 and r['resource_id'] == report['texture']['id'] and r['access'] & 2,
          f'{name}: RB_MRT_BASE relocation {r}')
    if draw:
        check(any(op == P.R.CP_DRAW_INDX_OFFSET for op, _s, _b in P.walk_ib(words)[1]), f'{name}: draw packet')


CASES = [
    # name, flags, expectation after: ('pass', fmt, w, h, pitch, draw) or ('refuse', substrings);
    # unchanged: True when the unchanged plug-in passes the same checks, 'fill32' when it clears with FILL32 instead.
    ('surface-bgra8', ['--kind', 'surface', '--format', '80', '--size', '64', '32'], ('pass', 80, 64, 32, 256, False), True),
    ('surface-bgra8-plane', ['--kind', 'surface', '--format', '80', '--size', '64', '32', '--planes', '1'],
     ('pass', 80, 64, 32, 256, False), False),
    ('surface-bgra8-padded', ['--kind', 'surface', '--format', '80', '--size', '64', '32', '--surface-size', '80', '40'],
     ('pass', 80, 64, 32, 320, False), False),
    ('view-bgra8-srgb', ['--kind', 'view', '--parent-format', '80', '--format', '81', '--size', '64', '32'],
     ('pass', 81, 64, 32, 256, False), False),
    ('view4-bgra8-srgb', ['--kind', 'view', '--parent-format', '80', '--format', '81', '--size', '64', '32', '--view4'],
     ('pass', 81, 64, 32, 256, False), False),
    ('private-bgra8-srgb', ['--kind', 'private', '--format', '81', '--size', '64', '32'], ('pass', 81, 64, 32, 256, False), False),
    ('private-rgba8', ['--kind', 'private', '--format', '70', '--size', '64', '32'], ('pass', 70, 64, 32, 256, False), 'fill32'),
    ('private-rgba8-srgb', ['--kind', 'private', '--format', '71', '--size', '64', '32'], ('pass', 71, 64, 32, 256, False), False),
    ('private-rgba16f', ['--kind', 'private', '--format', '115', '--size', '64', '32'], ('pass', 115, 64, 32, 512, False), False),
    ('surface-rgba16f', ['--kind', 'surface', '--format', '115', '--fourcc', 'RGhA', '--bpe', '8', '--size', '64', '32'],
     ('pass', 115, 64, 32, 512, False), False),
    ('surface-bgra8-fullscreen', ['--kind', 'surface', '--format', '80', '--size', '2880', '1800'],
     ('pass', 80, 2880, 1800, 11520, False), True),
    ('draw-bgra8', ['--kind', 'surface', '--format', '80', '--size', '64', '32', '--draw'], ('pass', 80, 64, 32, 256, True), True),
    ('draw-bgra8-srgb', ['--kind', 'private', '--format', '81', '--size', '64', '32', '--draw'], ('pass', 81, 64, 32, 256, True), False),
    ('draw-rgba16f', ['--kind', 'private', '--format', '115', '--size', '64', '32', '--draw'], ('pass', 115, 64, 32, 512, True), False),
    # v18: WindowServer's R8 masks and RG16Float second attachments; their neighbours RG8 and R16Float
    ('private-r8', ['--kind', 'private', '--format', '10', '--size', '64', '32'], ('pass', 10, 64, 32, 64, False), False),
    ('private-rg8', ['--kind', 'private', '--format', '30', '--size', '64', '32'], ('pass', 30, 64, 32, 128, False), False),
    ('private-r16f', ['--kind', 'private', '--format', '25', '--size', '64', '32'], ('pass', 25, 64, 32, 128, False), False),
    ('private-rg16f', ['--kind', 'private', '--format', '65', '--size', '64', '32'], ('pass', 65, 64, 32, 256, False), False),
    ('draw-r8', ['--kind', 'private', '--format', '10', '--size', '412', '412', '--draw'], ('pass', 10, 412, 412, 448, True), False),
    ('draw-rg16f', ['--kind', 'private', '--format', '65', '--size', '64', '32', '--draw'], ('pass', 65, 64, 32, 256, True), False),
    # Sampled textures with a descriptor swizzle (the A8-style mask "000r"), and the 16-bit float formats
    ('sample-r8-alpha-mask', ['--kind', 'private', '--format', '80', '--size', '64', '32', '--draw', '--sample', '10',
                              '--swizzle', '000r'], ('sample', 10, '000r'), False),
    ('sample-rgba8-bgra', ['--kind', 'private', '--format', '80', '--size', '64', '32', '--draw', '--sample', '70',
                           '--swizzle', 'bgra'], ('sample', 70, 'bgra'), False),
    ('sample-rgba8-identity', ['--kind', 'private', '--format', '80', '--size', '64', '32', '--draw', '--sample', '70'],
     ('sample', 70, 'rgba'), True),
    ('sample-r16f-splat', ['--kind', 'private', '--format', '80', '--size', '64', '32', '--draw', '--sample', '25',
                           '--swizzle', 'rrr1'], ('sample', 25, 'rrr1'), False),
    ('sample-rg16f', ['--kind', 'private', '--format', '80', '--size', '64', '32', '--draw', '--sample', '65'],
     ('sample', 65, 'rgba'), False),
    # v31: WindowServer's A8 masks and RGBA16Unorm icon images, plus the other unorm/float formats with linear entries
    *[(f'sample-fmt{f}', ['--kind', 'private', '--format', '80', '--size', '64', '32', '--draw', '--sample', str(f)],
       ('sample', f, 'rgba'), False) for f in (1, 20, 60, 110, 55, 105, 125)],
    ('sample-a8-swizzled', ['--kind', 'private', '--format', '80', '--size', '64', '32', '--draw', '--sample', '1',
                            '--swizzle', 'aaaa'], ('sample', 1, 'aaaa'), False),
    # v29: the Dock's icon renderer's sampler (infinite LOD clamp, lodAverage, anisotropy 3) is clamped/rounded, not refused
    ('sample-sampler-edge', ['--kind', 'private', '--format', '80', '--size', '64', '32', '--draw', '--sample', '70',
                             '--sampler-edge'], ('sample', 70, 'rgba'), False),
    # Mip levels (v22: WindowServer's 3-level 1408x128 blur targets and sampled level views). BGRA8 64x32, 3 levels, the
    # pitches the GPU derives from level 0's (align(256 >> k, 256); docs/USERSPACE-GRAPHICS-20261019.md, "Fix: mip levels
    # the GPU can sample"): level 0 at 0 (pitch 256), level 1 at 8192 (32x16, pitch 256), level 2 at 12288 (16x8, pitch 256).
    ('mip-level0-bgra8', ['--kind', 'private', '--format', '80', '--size', '64', '32', '--mips', '3', '--level', '0', '--draw'],
     ('level', 80, 64, 32, 256, 0), False),
    ('mip-level1-bgra8', ['--kind', 'private', '--format', '80', '--size', '64', '32', '--mips', '3', '--level', '1', '--draw'],
     ('level', 80, 32, 16, 256, 8192), False),
    ('mip-level2-bgra8', ['--kind', 'private', '--format', '80', '--size', '64', '32', '--mips', '3', '--level', '2'],
     ('level', 80, 16, 8, 256, 12288), False),
    ('mip-view-level1-bgra8', ['--kind', 'private', '--format', '80', '--size', '64', '32', '--mips', '3', '--view-level', '1',
                               '--draw'], ('level', 80, 32, 16, 256, 8192), False),
    ('sample-mips3-rgba8', ['--kind', 'private', '--format', '80', '--size', '64', '32', '--draw', '--sample', '70',
                            '--sample-mips', '3'], ('sample', 70, 'rgba', (64, 32), 0, 3, 256, 14336), False),
    ('sample-view-level1-rgba8', ['--kind', 'private', '--format', '80', '--size', '64', '32', '--draw', '--sample', '70',
                                  '--sample-mips', '3', '--sample-view-level', '1'], ('sample', 70, 'rgba', (32, 16), 8192, 1, 256), False),
    # Every single-source Metal blend factor (v27: the Dock's icon draws use OneMinusSourceColor, factor 3)
    *[(f'blend-{s}-{d}', ['--kind', 'private', '--format', '80', '--size', '64', '32', '--draw', '--blend', str(s), str(d)],
       ('blend', s, d), False) for s, d in ((1, 3), (2, 7), (6, 9), (10, 1), (11, 12), (13, 14), (4, 5))],
    # v29: ControlCenter's '&BGA' (lossless BGRA, 16x16 elements of 1024 bytes) layer surfaces, used as linear BGRA
    ('surface-lossless-bgra', ['--kind', 'surface', '--format', '80', '--fourcc', '&BGA', '--bpe', '1024', '--element', '16', '16',
                               '--row', '4096', '--size', '64', '32', '--surface-size', '64', '32', '--draw'],
     ('pass', 80, 64, 32, 256, True), False),
    # v69: NotificationCenter/WindowServer '&RhA' (lossless RGBA16Float, 16x16 elements of 2048 bytes) surfaces, used as
    # linear RGBA16Float (docs/USERSPACE-GRAPHICS-20261019.md); 352x352 is the retained real shape (row 2816, 64-aligned)
    ('surface-lossless-rgbahalf', ['--kind', 'surface', '--format', '115', '--fourcc', '&RhA', '--bpe', '2048', '--element', '16',
                                   '16', '--row', '8192', '--size', '64', '32', '--surface-size', '64', '32', '--draw'],
     ('pass', 115, 64, 32, 512, True), False),
    ('surface-lossless-rgbahalf-352', ['--kind', 'surface', '--format', '115', '--fourcc', '&RhA', '--bpe', '2048', '--element',
                                       '16', '16', '--row', '45056', '--size', '352', '352', '--surface-size', '352', '352', '--draw'],
     ('pass', 115, 352, 352, 2816, True), False),
    # Only the exact pairs: '&RhA' with an 8-byte format other than RGBA16Float, or a 4-byte one, stays refused
    ('surface-lossless-rgbahalf-as-bgra8', ['--kind', 'surface', '--format', '80', '--fourcc', '&RhA', '--bpe', '2048', '--element',
                                            '16', '16', '--row', '8192', '--size', '64', '32', '--surface-size', '64', '32'],
     ('refuse', ['linear layout', 'IOSurface element 16x16 of 2048 bytes']), True),
    ('surface-lossless-bgra-as-rgbahalf', ['--kind', 'surface', '--format', '115', '--fourcc', '&BGA', '--bpe', '1024', '--element',
                                           '16', '16', '--row', '4096', '--size', '64', '32', '--surface-size', '64', '32'],
     ('refuse', ['linear layout', 'IOSurface element 16x16 of 1024 bytes']), True),
    # v35: ControlCenter's status items render into 'l10r' (ARGB2101010 little-endian) IOSurfaces with BGR10A2Unorm
    # textures (refused until then: "format 94 has no linear entry"); RGB10A2Unorm beside it
    ('surface-bgr10a2', ['--kind', 'surface', '--format', '94', '--fourcc', 'l10r', '--size', '64', '32'],
     ('pass', 94, 64, 32, 256, False), False),
    ('surface-l10r-140x188', ['--kind', 'surface', '--format', '94', '--fourcc', 'l10r', '--bpe', '4', '--size', '140', '188',
                              '--row', '576', '--draw'], ('pass', 94, 140, 188, 576, True), False),
    ('surface-l10r-498x190', ['--kind', 'surface', '--format', '94', '--fourcc', 'l10r', '--bpe', '4', '--size', '498', '190',
                              '--row', '2048', '--draw'], ('pass', 94, 498, 190, 2048, True), False),
    ('private-bgr10a2', ['--kind', 'private', '--format', '94', '--size', '64', '32'], ('pass', 94, 64, 32, 256, False), False),
    ('private-rgb10a2', ['--kind', 'private', '--format', '90', '--size', '64', '32'], ('pass', 90, 64, 32, 256, False), False),
    ('draw-bgr10a2', ['--kind', 'private', '--format', '94', '--size', '64', '32', '--draw'], ('pass', 94, 64, 32, 256, True), False),
    ('draw-rgb10a2', ['--kind', 'private', '--format', '90', '--size', '64', '32', '--draw'], ('pass', 90, 64, 32, 256, True), False),
    ('blend-bgr10a2-4-5', ['--kind', 'private', '--format', '94', '--size', '64', '32', '--draw', '--blend', '4', '5'],
     ('blend', 4, 5), False),
    ('mrt-bgra8-bgr10a2-rgb10a2', ['--kind', 'private', '--format', '80', '--size', '64', '32', '--draw', '--mrt', '3',
                                   '--mrt-format', '94', '--attachment-format', '2', '90'], ('mrt', 3, True), False),
    ('mrt-l10r-rgb10a2-clear', ['--kind', 'surface', '--format', '94', '--fourcc', 'l10r', '--size', '64', '32', '--mrt', '2',
                          '--mrt-format', '90'], ('mrt', 2, False), False),
    ('sample-fmt94', ['--kind', 'private', '--format', '80', '--size', '64', '32', '--draw', '--sample', '94'],
     ('sample', 94, 'rgba'), False),
    ('sample-fmt90', ['--kind', 'private', '--format', '80', '--size', '64', '32', '--draw', '--sample', '90'],
     ('sample', 90, 'rgba'), False),
    ('sample-fmt94-swizzled', ['--kind', 'private', '--format', '80', '--size', '64', '32', '--draw', '--sample', '94',
                               '--swizzle', 'bgr1'], ('sample', 94, 'bgr1'), False),
    ('fb-blend-fmt94-l10r', ['--kind', 'surface', '--format', '94', '--fourcc', 'l10r', '--bpe', '4', '--size', '140', '188',
                             '--row', '576', '--draw', '--fb-fetch', 'blend', '--dump-code'],
     ('fb', dict(reads=[0], w=140, h=188, pitch=576)), False),
    ('fb-blend-fmt90', ['--kind', 'private', '--format', '90', '--size', '64', '32', '--draw', '--fb-fetch', 'blend', '--dump-code'],
     ('fb', dict(reads=[0], w=64, h=32, pitch=256)), False),
    # v38: draws com.apple.dock.extra (RenderBox) and loginwindow dropped, reproduced: a used texture or sampler left
    # unbound ("texture none"), a declared texture the code never samples ("texture(1) maps to invalid or duplicate slot
    # 1"), a declared device buffer it never reads ("driver table UBO 1 collides or is not loaded"), an unread constant
    # buffer left unbound
    *[(f'shape-{sh}', ['--kind', 'private', '--format', '80', '--size', '64', '32', '--draw', '--sample', '70', '--fs-shape', sh,
                       '--dump-code'], ('shape', dict(shape=sh, before=before)), False) for sh, before in (
        ('unbound-texture', 'texture on this device; texture none'), ('unbound-sampler', 'sampler(0) is missing'),
        ('unused-texture1', 'texture(1) maps to invalid or duplicate slot 1'),
        ('unused-device-buffer', 'driver table UBO 1 collides or is not loaded'),
        ('unused-constant-buffer', 'constant buffer(2) is not bound'))],
    # v80: WindowServer's line draws ("primitive type 1 is not supported yet"); plain and indexed
    *[(f'prim-{p}{"-u32" if ix else ""}', ['--kind', 'private', '--format', '80', '--size', '64', '32', '--draw', '--primitive', p,
                                         *(['--index32'] if ix else [])], ('prim', want), False)
      for p, want in (('line', 'DI_PT_LINELIST'), ('line-strip', 'DI_PT_LINESTRIP')) for ix in (False, True)],
    # v78: bindings made through the range and LOD-clamp setters (Apple's base encoder owns those unless the plug-in
    # forwards them; a used slot then read the zero texture or refused the unbound buffer)
    *[(f'shape-{sh}', ['--kind', 'private', '--format', '80', '--size', '64', '32', '--draw', '--sample', '70', '--sampler-edge',
                       '--fs-shape', sh, '--dump-code'], ('shape', dict(shape=sh, before=before)), False) for sh, before in (
        ('range-texture', 'texture on this device; texture none'), ('lod-sampler', 'sampler(0) is missing'),
        ('range-buffer', 'buffer(0) is not bound'))],
    ('fb-mrt2-bgr10a2-color1', ['--kind', 'private', '--format', '80', '--size', '64', '32', '--draw', '--mrt', '2', '--mrt-format',
                                '94', '--fb-fetch', 'mrt1', '--dump-code'], ('fb', dict(reads=[1], w=64, h=32, pitch=256)), False),
    # Framebuffer fetch (v29: com.apple.dock.extra dropped its pipelines, "fb_fetch bindings are not supported yet").
    # A blend done in the shader by reading color(0), in every target format the builder renders.
    *[(f'fb-blend-fmt{f}', ['--kind', 'private', '--format', str(f), '--size', '64', '32', '--draw', '--fb-fetch', 'blend',
                            '--dump-code'],
       ('fb', dict(reads=[0], w=64, h=32, pitch=(64 * FETCH_CPP[f] + 63) & ~63)), False) for f in (80, 81, 70, 71, 115, 10, 30, 25, 65)],
    ('fb-half-bgra8', ['--kind', 'private', '--format', '80', '--size', '64', '32', '--draw', '--fb-fetch', 'half', '--dump-code'],
     ('fb', dict(reads=[0], w=64, h=32, pitch=256)), False),
    ('fb-load-bgra8', ['--kind', 'private', '--format', '80', '--size', '64', '32', '--draw', '--load', '--fb-fetch', 'blend',
                       '--dump-code'], ('fb', dict(reads=[0], w=64, h=32, pitch=256, barrier=False)), False),
    # A draw sequence: the fetch draw reads what the plain draw wrote, then what the first fetch draw wrote.
    ('fb-sequence-bgra8', ['--kind', 'private', '--format', '80', '--size', '64', '32', '--draw', '--load', '--fb-fetch', 'blend',
                           '--fb-sequence', '--fb-draws', '2', '--dump-code'],
     ('fb', dict(reads=[0], w=64, h=32, pitch=256, draws=2, sequence=True)), False),
    ('fb-draws3-rgba16f', ['--kind', 'private', '--format', '115', '--size', '64', '32', '--draw', '--fb-fetch', 'blend',
                           '--fb-draws', '3', '--dump-code'], ('fb', dict(reads=[0], w=64, h=32, pitch=512, draws=3)), False),
    # The fetch takes the T# after the application's texture(0)
    ('fb-with-sample-bgra8', ['--kind', 'private', '--format', '80', '--size', '64', '32', '--draw', '--sample', '70',
                              '--fb-fetch', 'blend', '--dump-code'], ('fb', dict(reads=[0], w=64, h=32, pitch=256)), False),
    # MRT: color(1), and color(0) and color(1) of a BGRA8 + RG16Float pass; a sequence over MRT
    ('fb-mrt2-color1', ['--kind', 'private', '--format', '80', '--size', '64', '32', '--draw', '--mrt', '2', '--fb-fetch', 'mrt1',
                        '--dump-code'], ('fb', dict(reads=[1], w=64, h=32, pitch=256)), False),
    ('fb-mrt2-rg16f-color01', ['--kind', 'private', '--format', '80', '--size', '64', '32', '--draw', '--mrt', '2', '--mrt-format',
                               '65', '--fb-fetch', 'mrt01', '--dump-code'], ('fb', dict(reads=[0, 1], w=64, h=32, pitch=256)), False),
    ('fb-mrt3-sequence', ['--kind', 'private', '--format', '81', '--size', '64', '32', '--draw', '--mrt', '3', '--mrt-format', '115',
                          '--fb-fetch', 'mrt1', '--fb-sequence', '--dump-code'],
     ('fb', dict(reads=[1], w=64, h=32, pitch=256, sequence=True)), False),
    # Level and view attachments (the 3-level 64x32 BGRA8 of the mip cases) and the '&BGA' lossless-as-linear surface
    ('fb-mip-level1-bgra8', ['--kind', 'private', '--format', '80', '--size', '64', '32', '--mips', '3', '--level', '1', '--draw',
                             '--fb-fetch', 'blend', '--dump-code'],
     ('fb', dict(reads=[0], w=64, h=32, pitch=256, level0=(32, 16, 256, 8192))), False),
    ('fb-view-level1-bgra8', ['--kind', 'private', '--format', '80', '--size', '64', '32', '--mips', '3', '--view-level', '1',
                              '--draw', '--fb-fetch', 'blend', '--dump-code'],
     ('fb', dict(reads=[0], w=64, h=32, pitch=256, level0=(32, 16, 256, 8192))), False),
    ('fb-surface-lossless-bgra', ['--kind', 'surface', '--format', '80', '--fourcc', '&BGA', '--bpe', '1024', '--element', '16', '16',
                                  '--row', '4096', '--size', '64', '32', '--surface-size', '64', '32', '--draw', '--fb-fetch', 'blend',
                                  '--dump-code'], ('fb', dict(reads=[0], w=64, h=32, pitch=256)), False),
    ('fb-surface-lossless-rgbahalf', ['--kind', 'surface', '--format', '115', '--fourcc', '&RhA', '--bpe', '2048', '--element',
                                      '16', '16', '--row', '8192', '--size', '64', '32', '--surface-size', '64', '32', '--draw',
                                      '--fb-fetch', 'blend', '--dump-code'], ('fb', dict(reads=[0], w=64, h=32, pitch=512)), False),
    # The real shapes, from the host's QuartzCore default.metallib through the Metal path the Dock uses: CA's path blit
    # reads its float coverage mask, color(2), and writes three attachments; inplace_copy writes a storage texture.
    ('fb-qc-path-blit', ['--kind', 'private', '--format', '80', '--size', '64', '32', '--draw', '--mrt', '3',
                         '--attachment-format', '2', '25', '--qc-fb', 'path_blit_frag_lph', '--dump-code'],
     ('fb', dict(reads=[2], w=64, h=32, pitch=256)), False),
    ('fb-qc-path-blit-eo', ['--kind', 'private', '--format', '80', '--size', '64', '32', '--draw', '--mrt', '3',
                            '--attachment-format', '2', '25', '--qc-fb', 'path_blit_frag_eo_lph', '--dump-code'],
     ('fb', dict(reads=[2], w=64, h=32, pitch=256)), False),
    ('fb-qc-inplace-copy', ['--kind', 'private', '--format', '80', '--size', '64', '32', '--draw', '--qc-fb', 'inplace_copy_lph'],
     ('refuse', ['fragment: storage_texture bindings are not built']), False),
]


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--bundle', type=Path, required=True)
    ap.add_argument('--output', type=Path, required=True)
    ap.add_argument('--expect-before', action='store_true')
    ap.add_argument('--only', nargs='+', metavar='NAME', help='run only these cases (each must exist)')
    args = ap.parse_args()
    cases = CASES
    if args.only:
        known = {n for n, _f, _e, _u in CASES}
        missing = [n for n in args.only if n not in known]
        if missing:
            ap.error(f'unknown cases: {missing}')
        cases = [c for c in CASES if c[0] in args.only]
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    exe = build_harness(out)
    kernel = DS = None
    if not args.expect_before and any(e[0] in ('fb', 'shape', 'prim') for _n, _f, e, _u in cases):
        # The production kext validator (tools/test-adreno-depth-stencil.py's replay of tools/test-adreno-ib-command.c)
        spec = importlib.util.spec_from_file_location('depth_stencil', ROOT / 'tools/test-adreno-depth-stencil.py')
        assert spec and spec.loader
        DS = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(DS)
        kernel = DS.build_replay(out)
    results = {}
    for name, flags, expect, unchanged in cases:
        report, cap = run(exe, args.bundle.resolve(), out, name, *flags)
        reason = (report.get('exception') or {}).get('reason', '')
        results[name] = dict(status=report.get('status'), reason=reason, layout=report.get('layout'))
        try:
            if args.expect_before and unchanged == 'fill32':
                # The unchanged plug-in clears a small RGBA8 target with FILL32 commands, not an IB package.
                check(report.get('status') == 'TARGET_COMMIT_CAPTURED_NOT_SUBMITTED', f'{name}: {reason!r}')
                kinds = [k for k, _c in P.kernel_commands((cap / 'commands.bin').read_bytes())]
                check(0x1002 not in kinds and 0x1001 in kinds, f'{name}: kernel commands {[hex(k) for k in kinds]}')
            elif args.expect_before and not unchanged:
                # The unchanged plug-in: every added case fails the way the A16 does (or with a format refusal).
                check(report.get('status') == 'TARGET_EXCEPTION', f'{name}: the unchanged plug-in accepted it')
                check(reason.startswith(GEOMETRY) or 'not supported yet' in reason or 'linear layout' in reason or
                      (isinstance(expect[1], dict) and expect[1].get('before', '\0') in reason),
                      f'{name}: unexpected refusal {reason!r}')
            elif expect[0] == 'sample':
                check_sample(name, report, cap, *expect[1:])
            elif expect[0] == 'blend':
                check_blend(name, report, cap, *expect[1:])
            elif expect[0] == 'level':
                check_level(name, report, cap, *expect[1:])
            elif expect[0] == 'mrt':
                check_mrt_formats(name, report, cap, *expect[1:])
            elif expect[0] == 'prim':
                check_prim(name, report, cap, expect[1])
                try:
                    DS.replay(kernel, cap, name)
                    admitted = ''
                except Exception as error:          # the replay module's own Fail class
                    admitted = str(error)
                check(not admitted, f'{name}: {admitted}')
            elif expect[0] == 'shape':
                check_shape(name, report, cap, expect[1])
                try:
                    DS.replay(kernel, cap, name)
                    admitted = ''
                except Exception as error:          # the replay module's own Fail class
                    admitted = str(error)
                check(not admitted, f'{name}: {admitted}')
            elif expect[0] == 'fb':
                check_fb(name, report, cap, expect[1])
                try:
                    DS.replay(kernel, cap, name)
                    admitted = ''
                except Exception as error:          # the replay module's own Fail class
                    admitted = str(error)
                check(not admitted, f'{name}: {admitted}')
            elif expect[0] == 'pass':
                _, fmt, w, h, pitch, draw = expect
                check_target(name, report, cap, fmt, w, h, pitch, draw)
            else:
                check(report.get('status') == 'TARGET_EXCEPTION', f'{name}: not refused')
                for s in expect[1]:
                    check(s in reason, f'{name}: {s!r} not in {reason!r}')
            results[name]['result'] = 'ok'
        except Fail as error:
            results[name]['result'] = f'FAIL: {error}'
    (out / 'result.json').write_text(json.dumps(dict(bundle=str(args.bundle.resolve()), expect_before=args.expect_before, only=args.only,
                                                     checks=checks, cases=results), indent=2, sort_keys=True))
    failed = [n for n, r in results.items() if r['result'] != 'ok']
    for n in failed:
        print(f'{n}: {results[n]["result"]}')
    if failed:
        print(f'FAIL: {len(failed)} of {len(cases)} cases; {out / "result.json"}')
        return 1
    print(f'PASS: {len(cases)} target cases, {checks} checks ({"unchanged plug-in" if args.expect_before else "candidate"}); '
          f'{out / "result.json"}')
    return 0


if __name__ == '__main__':
    sys.exit(main())

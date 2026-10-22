#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""E2E test of record for render passes with several colour attachments in AdrenoMetal (docs/ADRENO-DEPTH-STENCIL-20261017.md,
"Multiple colour attachments").

No A16, no GPU submission. As tools/test-adreno-depth-stencil.py: the real AdrenoMetal.bundle is driven through the public
Metal API by gpu/adreno-kext/plugin/harness/target-coverage.m (--mrt N: attachment 0 the target, 1..N-1 private textures)
on the host AGX provider, the captured ADRENO_KCMD_IB package is read register by register against Mesa's gallium a8xx
path, and every capture is replayed through the production kext validator (tools/test-adreno-ib-command.c --replay).

Failure modes this pins (v17 on the A16: WindowServer's passes with a second colour attachment were refused, "Adreno
draw: more than one colour attachment is not supported yet", and the panel stayed black):
  - a pass or a pipeline with attachments 1..7 is still refused, or one with a gap is accepted
  - emit_mrt writes only MRT 0: RB_MRT_BUF_INFO/PITCH/BASE(n) or SP_PS_MRT_REG(n) missing, a wrong format or pitch, or
    RB_MRT_BASE(n) relocated to the wrong resource or without write access
  - RB_SRGB_CNTL/SP_SRGB_CNTL miss bit n of an sRGB attachment
  - the 2D clears skip attachments 1..N-1, clear the wrong resource, or use attachment 0's colour
  - PROG_FB_RAST still programs one MRT (RB_PS_MRT_CNTL, SP_PS_MRT_CNTL, SP/RB_PS_OUTPUT_MASK) or the fragment outputs
    1..N-1 are not mapped (SP_PS_OUTPUT_REG(n) invalid or aliased)
  - blend state only for attachment 0: RB_MRT_CONTROL(n)/SP_MRT_BLEND_CNTL_REG(n)/RB_MRT_BLEND_CONTROL(n) missing,
    ENABLE_BLEND / BLEND_READS_DEST not the mask of blending attachments, or INDEPENDENT_BLEND off with N > 1
  - the kext's IB register set lacks the MRT 1..7 registers, so the A16 refuses the IB

    python3 tools/test-adreno-mrt.py --bundle BUNDLE --output NEW-DIR [--expect-before]

--expect-before checks the unchanged plug-in instead: every multi-attachment case is refused as on the A16.
"""
import argparse
import importlib.util
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, ROOT / path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


DS = load('depth_stencil', 'tools/test-adreno-depth-stencil.py')
T = DS.T
P, X, need, Fail = T.P, T.X, T.need, T.Fail
check, field, enum, registers, last, written = T.check, T.field, T.enum, T.registers, T.last, DS.written
OLD_REFUSALS = ('more than one colour attachment is not supported yet', 'Unsupported Adreno render-pass attachments',
                'color attachment0 only')
W, H = 64, 32
INVALID_REG = 0xFC


def pitch_of(fmt):
    return (W * T.HW[fmt][2] + 63) & ~63


def clear_words(fmt, colour):
    saved = T.CLEAR
    try:
        T.CLEAR = colour
        return T.clear_words(fmt)
    finally:
        T.CLEAR = saved


def relocs_of(pkg, words, name):
    """The relocation of every write of name (a 64-bit address register), in IB order."""
    base = X.REGS[name][0]
    at = [i for i, o in P.walk_ib(words)[0] if o == base]
    table = {r['lo']: r for r in pkg['relocs']}
    return [table.get(4 * a) for a in at]


def check_mrt(name, report, cap, case):
    check(report.get('status') == 'TARGET_COMMIT_CAPTURED_NOT_SUBMITTED', f'{name}: {report.get("status")} {report.get("exception")}')
    pkg = T.ib_of(cap)
    words = P.ib_words(pkg)
    regs = registers(words)
    n_att = case['mrt']
    fmts = [case['format']] + [case.get('mrt_format', case['format'])] * (n_att - 1)
    ids = [report['texture']['id']] + [a['id'] for a in report['mrt']['attachments']]
    check(len(ids) == n_att, f'{name}: {len(ids)} attachments reported')
    srgb = 0
    for n in range(n_att):
        rb, swap, is_srgb = T.HW[fmts[n]][0], T.HW[fmts[n]][1], T.HW[fmts[n]][3]
        srgb |= int(is_srgb) << n
        info = last(regs, 'RB_MRT_BUF_INFO', n)
        check(enum('a6xx_format', field('RB_MRT_BUF_INFO', info, 'COLOR_FORMAT')) == rb, f'{name}: RB_MRT_BUF_INFO({n}) format')
        check(enum('a3xx_color_swap', field('RB_MRT_BUF_INFO', info, 'COLOR_SWAP')) == swap, f'{name}: RB_MRT_BUF_INFO({n}) swap')
        check(last(regs, 'RB_MRT_PITCH', n) == pitch_of(fmts[n]) >> 6, f'{name}: RB_MRT_PITCH({n})')
        check(enum('a6xx_format', field('SP_PS_MRT_REG', last(regs, 'SP_PS_MRT_REG', n), 'COLOR_FORMAT')) == rb, f'{name}: SP_PS_MRT_REG({n})')
        off = X.REGS['RB_MRT_BASE'][0] + n * X.REGS['RB_MRT_BASE'][3]
        at = [i for i, o in P.walk_ib(words)[0] if o == off]
        need(at, f'{name}: RB_MRT_BASE({n}) not written')
        r = {x['lo']: x for x in pkg['relocs']}.get(4 * at[-1])
        check(r is not None and r['kind'] == 1 and r['resource_id'] == ids[n] and r['access'] & 2,
              f'{name}: RB_MRT_BASE({n}) relocation {r}')
    for n in range(n_att, 8):
        check(not written(regs, 'RB_MRT_BUF_INFO', n), f'{name}: RB_MRT_BUF_INFO({n}) written past the attachments')
    check(last(regs, 'RB_SRGB_CNTL') == srgb and last(regs, 'SP_SRGB_CNTL') == srgb, f'{name}: sRGB controls {srgb:#x}')
    # The 2D clears: one per attachment, in order, each on its own resource with its own colour.
    dests = written(regs, 'RB_A2D_DEST_BUFFER_INFO')
    if case.get('load'):
        check(not dests, f'{name}: {len(dests)} 2D clears in a Load pass')
    else:
        check(len(dests) == n_att, f'{name}: {len(dests)} 2D clears for {n_att} attachments')
        bases = relocs_of(pkg, words, 'RB_A2D_DEST_BUFFER_BASE')
        check([b and b['resource_id'] for b in bases] == ids, f'{name}: 2D clear destinations {[b and b["resource_id"] for b in bases]}')
        got = [written(regs, f'RB_A2D_CLEAR_COLOR_DW{i}') for i in range(4)]
        for n in range(n_att):
            colour = (0.25, 0.5, 0.75, 1) if n == 0 else (n / 8, 0.875, 0.5, 1)
            want = clear_words(fmts[n], colour)
            have = [got[i][n] if n < len(got[i]) else None for i in range(4)]
            check(have == want, f'{name}: attachment {n} clear words {have} != {want}')
            check(enum('a6xx_format', field('RB_A2D_DEST_BUFFER_INFO', dests[n], 'COLOR_FORMAT')) == T.HW[fmts[n]][0],
                  f'{name}: attachment {n} 2D destination format')
    if not case.get('draw'):
        return
    mask = (1 << (4 * n_att)) - 1
    check(field('RB_PS_MRT_CNTL', last(regs, 'RB_PS_MRT_CNTL'), 'MRT') == n_att and
          field('SP_PS_MRT_CNTL', last(regs, 'SP_PS_MRT_CNTL'), 'MRT') == n_att, f'{name}: PS MRT count')
    check(last(regs, 'SP_PS_OUTPUT_MASK') == mask and last(regs, 'RB_PS_OUTPUT_MASK') == mask, f'{name}: PS output masks')
    # emit_fs_outputs: output n comes from a register or from an aliased constant (alias.rt), never from neither.
    outs = [field('SP_PS_OUTPUT_REG', last(regs, 'SP_PS_OUTPUT_REG', n), 'REGID') for n in range(n_att)]
    alias = last(regs, 'SP_PS_OUTPUT_CONST_MASK')
    live = [o for o in outs if o != INVALID_REG]
    check(all(o != INVALID_REG or (alias >> (4 * n)) & 0xF for n, o in enumerate(outs)) and len(set(live)) == len(live),
          f'{name}: fragment outputs {outs} alias {alias:#x}')
    check(len(live) == n_att, f'{name}: position-dependent outputs in registers {outs}')
    blending = 0b10 if case.get('blend') else 0
    for n in range(n_att):
        on = (blending >> n) & 1
        c = last(regs, 'RB_MRT_CONTROL', n)
        check(field('RB_MRT_CONTROL', c, 'COMPONENT_ENABLE') == 0xF, f'{name}: RB_MRT_CONTROL({n}) components')
        check(field('RB_MRT_CONTROL', c, 'COLOR_BLEND_EN') == on and field('RB_MRT_CONTROL', c, 'ALPHA_BLEND_EN') == on,
              f'{name}: RB_MRT_CONTROL({n}) blend')
        s = last(regs, 'SP_MRT_BLEND_CNTL_REG', n)
        check(field('SP_MRT_BLEND_CNTL_REG', s, 'COLOR_BLEND_EN') == on and
              field('SP_MRT_BLEND_CNTL_REG', s, 'COMPONENT_WRITE_MASK') == 0xF, f'{name}: SP_MRT_BLEND_CNTL_REG({n})')
        b = last(regs, 'RB_MRT_BLEND_CONTROL', n)
        src, dst = (('FACTOR_SRC_ALPHA', 'FACTOR_ONE_MINUS_SRC_ALPHA') if on else ('FACTOR_ZERO', 'FACTOR_ZERO'))
        check(enum('adreno_rb_blend_factor', field('RB_MRT_BLEND_CONTROL', b, 'RGB_SRC_FACTOR')) == src and
              enum('adreno_rb_blend_factor', field('RB_MRT_BLEND_CONTROL', b, 'RGB_DEST_FACTOR')) == dst and
              enum('adreno_rb_blend_factor', field('RB_MRT_BLEND_CONTROL', b, 'ALPHA_SRC_FACTOR')) == src and
              enum('adreno_rb_blend_factor', field('RB_MRT_BLEND_CONTROL', b, 'ALPHA_DEST_FACTOR')) == dst,
              f'{name}: RB_MRT_BLEND_CONTROL({n}) factors')
    sp, rb = last(regs, 'SP_BLEND_CNTL'), last(regs, 'RB_BLEND_CNTL')
    check(field('SP_BLEND_CNTL', sp, 'ENABLE_BLEND') == blending and field('SP_BLEND_CNTL', sp, 'INDEPENDENT_BLEND_EN') == 1,
          f'{name}: SP_BLEND_CNTL {sp:#x}')
    check(field('RB_BLEND_CNTL', rb, 'BLEND_READS_DEST') == blending and field('RB_BLEND_CNTL', rb, 'INDEPENDENT_BLEND') == 1 and
          field('RB_BLEND_CNTL', rb, 'SAMPLE_MASK') == 0xFFFF, f'{name}: RB_BLEND_CNTL {rb:#x}')
    check(any(p[0] == P.R.CP_DRAW_INDX_OFFSET for p in P.walk_ib(words)[1]), f'{name}: draw packet')


CASES = [
    # name, harness flags, case options
    ('clear-mrt2', ['--mrt', '2'], dict(mrt=2)),
    ('clear-mrt4', ['--mrt', '4'], dict(mrt=4)),
    ('load-mrt2-draw', ['--mrt', '2', '--load', '--draw'], dict(mrt=2, load=True, draw=True)),
    ('clear-mrt2-srgb-rgba16f', ['--format', '81', '--mrt', '2', '--mrt-format', '115'], dict(mrt=2, format=81, mrt_format=115)),
    ('draw-mrt2', ['--mrt', '2', '--draw'], dict(mrt=2, draw=True)),
    ('draw-mrt2-blend1', ['--mrt', '2', '--draw', '--mrt-blend'], dict(mrt=2, draw=True, blend=True)),
    ('draw-mrt3-rgba16f', ['--mrt', '3', '--mrt-format', '115', '--draw'], dict(mrt=3, mrt_format=115, draw=True)),
    ('draw-mrt8', ['--mrt', '8', '--draw'], dict(mrt=8, draw=True)),
    # v18's shape: BGRA8 attachment 0 with a private RG16Float attachment 1
    ('draw-mrt2-rg16f', ['--mrt', '2', '--mrt-format', '65', '--draw'], dict(mrt=2, mrt_format=65, draw=True)),
    ('draw-mrt2-d32', ['--mrt', '2', '--draw', '--zs', '252', '--zs-load', '--ds', 'depth'], dict(mrt=2, draw=True)),
    ('refuse-gap', ['--mrt', '3', '--mrt-gap'], dict(refuse='colour attachments with gaps')),
    ('refuse-gap-pipeline', ['--mrt', '3', '--mrt-gap', '--draw'], dict(refuse='colour attachments with gaps')),
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
    kernel = None if args.expect_before else DS.build_replay(out)
    results = {}
    for name, flags, case in CASES:
        case.setdefault('format', 80)
        flags = flags if '--format' in flags else ['--format', '80', *flags]
        report, cap = T.run(exe, args.bundle.resolve(), out, name, '--kind', 'private', '--size', str(W), str(H), *flags)
        reason = (report.get('exception') or {}).get('reason', '')
        results[name] = dict(status=report.get('status'), reason=reason)
        try:
            if args.expect_before or 'refuse' in case:
                check(report.get('status') == 'TARGET_EXCEPTION', f'{name}: accepted ({report.get("status")})')
                wanted = OLD_REFUSALS if args.expect_before else (case['refuse'],)
                check(any(w in reason for w in wanted), f'{name}: unexpected refusal {reason!r}')
            else:
                check_mrt(name, report, cap, case)
                DS.replay(kernel, cap, name)
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
    print(f'PASS: {len(CASES)} multiple-attachment cases, {T.checks} checks ({"unchanged plug-in" if args.expect_before else "candidate"}); '
          f'{out / "result.json"}')
    return 0


if __name__ == '__main__':
    sys.exit(main())

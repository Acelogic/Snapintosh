#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""xrrand.py - random XR blend scenes: llvmpipe (the compiler's XR lowering + hw_blend) vs Metal.

verify3 item 2 generated 48 random blend states into MTLPixelFormatBGR10_XR / BGRA10_XR attachments
(xrscenes/v3xr*.json, copied unchanged from ../verify3/tree/scenes); 10 of them, all min/max, failed
because hw_blend carried the app's factors.  This re-runs them, plus fresh ones generated here
(xrscenes/f3xr*.json, --gen), which also put blend-colour factors (11..14) on min/max channels (Metal
ignores factors there; ABI v3 refused them).

Fix round 4 (verify4 item 3) adds verify4's scenes unchanged (xrscenes/v4xr*.json: 64 random ones weighted
to min/max/subtract; xrscenes/a55*_*.json: 20 with source alpha 0.6 and 1.2 per blend state) and fresh
ones with source alpha outside [0, 1] (xrscenes/f4xr*.json, `--gen 64 --seed 4 --alpha -0.4,1.8 --prefix
f4xr`): Metal clamps the source alpha to [0, 1] where it is a blend factor, and on BGRA10_XR also the
alpha value itself.

  python3 tools/xrrand.py [--gen N --seed S [--alpha LO,HI] [--prefix P]]
                          -> results/xrrand/{compare.json,*.bgra}, summary on stdout
"""
import json, os, random, subprocess, sys
from concurrent.futures import ThreadPoolExecutor
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SC = os.path.join(ROOT, 'xrscenes'); OUT = os.path.join(ROOT, 'results', 'xrrand')

def gen(n, seed, alpha=(0.2, 1.0), prefix='f3xr'):
    rnd = random.Random(seed)
    tmpl = json.load(open(os.path.join(SC, 'v3xr554_00.json')))
    for i in range(n):
        tag = '554' if i % 2 == 0 else '552'
        s = json.loads(json.dumps(tmpl))
        s['rt'] = dict(format='bgr10_xr' if tag == '554' else 'bgra10_xr', init_file=f'scenes/data/xrinit_{tag}.bin')
        tint = [round(rnd.uniform(-0.9, 1.6), 3) for _ in range(3)] + [round(rnd.uniform(*alpha), 2), 1.25, 0, 0, 0]
        s['buffers']['fragment'] = [dict(index=0, floats=tint)]
        def chan():
            op = rnd.choice([0, 0, 1, 2, 3, 4])
            if op in (3, 4): return op, rnd.randint(0, 14), rnd.randint(0, 14)     # ignored: blend colour allowed
            return op, rnd.randint(0, 10), rnd.randint(0, 10)
        ro, sr, dr = chan(); ao, sa, da = chan()
        s['blend'] = dict(enabled=1, rgb_op=ro, alpha_op=ao, src_rgb=sr, dst_rgb=dr, src_alpha=sa, dst_alpha=da)
        s['name'] = f'{prefix}{tag}_{i:02d}'
        json.dump(s, open(os.path.join(SC, s['name'] + '.json'), 'w'), indent=1)

def run(name):
    sc = os.path.join(SC, name + '.json'); r = {}
    for tool, ext in (('mtlgold', 'metal'), ('nirexec', 'lp')):
        p = subprocess.run([os.path.join(ROOT, 'build', tool), sc, os.path.join(OUT, f'{name}.{ext}.bgra'), '--frames', '3'],
                           capture_output=True, text=True, cwd=ROOT)
        r[tool] = (p.returncode, (p.stdout + p.stderr).strip()[-300:])
    return name, r

def main():
    a = sys.argv[1:]
    if '--gen' in a:
        gen(int(a[a.index('--gen') + 1]), int(a[a.index('--seed') + 1]) if '--seed' in a else 3,
            tuple(float(x) for x in a[a.index('--alpha') + 1].split(',')) if '--alpha' in a else (0.2, 1.0),
            a[a.index('--prefix') + 1] if '--prefix' in a else 'f3xr')
    os.makedirs(OUT, exist_ok=True)
    for f in os.listdir(OUT): os.remove(os.path.join(OUT, f))
    names = sorted(f[:-5] for f in os.listdir(SC) if f.endswith('.json'))
    with ThreadPoolExecutor(8) as ex: res = dict(ex.map(run, names))
    fails = {n: r for n, r in res.items() if any(v[0] for v in r.values())}
    for n, r in fails.items(): print('TOOL FAILURE', n, r)
    p = subprocess.run([sys.executable, os.path.join(ROOT, 'tools', 'compare.py'), OUT, '--scenes', SC], capture_output=True, text=True)
    cmp = json.load(open(os.path.join(OUT, 'compare.json')))
    bad = {n: c for n, c in cmp.items() if c['status'] != 'PASS'}
    for n, c in sorted(bad.items()): print('FAIL', n, c['blend'], 'max', c['max_abs_diff'], 'px over tol', c['pixels_over_tol'])
    mm = sum(1 for c in cmp.values() if c['blend'].get('rgb_op') in (3, 4) or c['blend'].get('alpha_op') in (3, 4))
    hi = sorted(n for n in cmp if any(b['index'] == 0 and not 0 <= b['floats'][3] <= 1
                                      for b in json.load(open(os.path.join(SC, n + '.json')))['buffers'].get('fragment', [])))
    worst = max(c['max_abs_diff'] for c in cmp.values())
    hiw = max([cmp[n]['max_abs_diff'] for n in hi] or [0])
    print(f'xrrand: {len(cmp) - len(bad)}/{len(cmp)} scenes within tolerance ({mm} use min/max, {len(hi)} source alpha outside [0, 1], '
          f'worst there {hiw}), worst {worst} XR10 codes; tool failures {len(fails)}')
    json.dump(dict(passed=len(cmp) - len(bad), of=len(cmp), minmax=mm, alpha_outside_01=len(hi), worst_alpha_outside=hiw, worst=worst,
                   failures=sorted(bad), tool_failures=sorted(fails)),
              open(os.path.join(ROOT, 'results', 'xrrand.json'), 'w'), indent=1)
    sys.exit(1 if bad or fails else 0)

if __name__ == '__main__':
    main()

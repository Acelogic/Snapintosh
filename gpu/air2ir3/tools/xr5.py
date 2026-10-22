#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""xr5.py - verify5's XR blend grid (verify5 work/xr/xr5.py, ported into the tree by fix round 5; the
generator and its seed are unchanged, so it reproduces verify5's 834 scenes): every blend op x every
factor position x factor 0..10 x source alpha {-0.35, 1.45, 3.0} x both XR formats, plus 240 random
mixed-op states with alpha in [-1, 3] and colour in [-1.2, 2.0].  llvmpipe (this tree's build) vs Metal.
verify5 item 1: r554_204 (source colour as an RGB factor, colour outside [0, 1]) failed on the RB path.

  python3 tools/xr5.py      -> xr5scenes/ (generated), results/xr5/{compare.json,*.bgra}, results/xr5.json
                               exit status 1 on any scene over tolerance or tool failure
"""
import json, os, random, subprocess, sys
from concurrent.futures import ThreadPoolExecutor
TREE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
# generated scenes live directly under the tree: scene paths (scenes/data/..., corpus/...) resolve from the scene dir's parent
SC = os.path.join(TREE, 'xr5scenes'); OUT = os.path.join(TREE, 'results', 'xr5')
def main():
    os.makedirs(SC, exist_ok=True); os.makedirs(OUT, exist_ok=True)
    for f in os.listdir(SC): os.remove(os.path.join(SC, f))
    for f in os.listdir(OUT): os.remove(os.path.join(OUT, f))
    tmpl = json.load(open(os.path.join(TREE, 'xrscenes', 'v3xr554_00.json')))
    rnd = random.Random(5150)
    names = []
    def mk(name, tag, tint, blend):
        s = json.loads(json.dumps(tmpl))
        s['rt'] = dict(format='bgr10_xr' if tag == '554' else 'bgra10_xr', init_file=f'scenes/data/xrinit_{tag}.bin')
        s['buffers']['fragment'] = [dict(index=0, floats=tint + [1.25, 0, 0, 0])]
        s['blend'] = dict(enabled=1, **blend); s['name'] = name
        json.dump(s, open(os.path.join(SC, name + '.json'), 'w'), indent=1); names.append(name)
    pos = ['src_rgb', 'dst_rgb', 'src_alpha', 'dst_alpha']
    n = 0
    for tag in ('554', '552'):
        for op in (0, 1, 2):
            for p in pos:
                if tag == '554' and p in ('src_alpha', 'dst_alpha'): continue
                for f in range(11):
                    for al in (-0.35, 1.45, 3.0):
                        b = dict(rgb_op=op, alpha_op=op, src_rgb=rnd.randint(0, 10), dst_rgb=rnd.randint(0, 10), src_alpha=rnd.randint(0, 10), dst_alpha=rnd.randint(0, 10))
                        b[p] = f
                        tint = [round(rnd.uniform(-0.9, 1.6), 3) for _ in range(3)] + [al]
                        mk(f'g{tag}_o{op}_{p}_{f}_{al}', tag, tint, b); n += 1
    for i in range(240):
        tag = rnd.choice(['554', '552'])
        def chan():
            o = rnd.choice([0, 1, 2, 3, 4])
            if o in (3, 4): return o, rnd.randint(0, 14), rnd.randint(0, 14)
            return o, rnd.randint(0, 10), rnd.randint(0, 10)
        ro, sr, dr = chan(); ao, sa, da = chan()
        al = rnd.choice([-1.0, -0.5, -0.05, 1.02, 1.3, 2.0, 3.0, rnd.uniform(-1, 3)])
        tint = [round(rnd.uniform(-1.2, 2.0), 3) for _ in range(3)] + [round(al, 3)]
        mk(f'r{tag}_{i:03d}', tag, tint, dict(rgb_op=ro, alpha_op=ao, src_rgb=sr, dst_rgb=dr, src_alpha=sa, dst_alpha=da))
    def run(name):
        sc = os.path.join(SC, name + '.json'); r = {}
        for tool, ext in (('mtlgold', 'metal'), ('nirexec', 'lp')):
            p = subprocess.run([os.path.join(TREE, 'build', tool), sc, os.path.join(OUT, f'{name}.{ext}.bgra'), '--frames', '3'], capture_output=True, text=True, cwd=TREE)
            r[tool] = (p.returncode, (p.stdout + p.stderr).strip()[-300:])
        return name, r
    with ThreadPoolExecutor(10) as ex: res = dict(ex.map(run, names))
    fails = {k: v for k, v in res.items() if any(x[0] for x in v.values())}
    for k, v in sorted(fails.items())[:3]: print('TOOL', k, v)
    subprocess.run([sys.executable, os.path.join(TREE, 'tools', 'compare.py'), OUT, '--scenes', SC], capture_output=True, text=True)
    cmp = json.load(open(os.path.join(OUT, 'compare.json')))
    bad = {k: c for k, c in cmp.items() if c['status'] != 'PASS'}
    for k, c in sorted(bad.items(), key=lambda kv: -kv[1]['max_abs_diff']): print('FAIL', k, c['blend'], 'max', c['max_abs_diff'], 'over', c['pixels_over_tol'])
    hist = {}
    for c in cmp.values(): hist[c['max_abs_diff']] = hist.get(c['max_abs_diff'], 0) + 1
    print(f'xr5: {len(cmp)-len(bad)}/{len(cmp)} pass, tool failures {len(fails)}, maxdiff hist {sorted(hist.items())}')
    json.dump(dict(passed=len(cmp)-len(bad), of=len(cmp), bad=sorted(bad), tool=sorted(fails)), open(os.path.join(TREE, 'results', 'xr5.json'), 'w'), indent=1)
    sys.exit(1 if bad or fails else 0)

if __name__ == '__main__':
    main()

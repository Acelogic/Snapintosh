#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Broad llvmpipe(AIR-NIR) vs Metal(M3 Max) differential over many FC variants with generated
uniforms (layouts from Metal reflection).  Output: results/vexec/<id>.{metal,lp}.bgra + summary."""
import json, os, random, struct, subprocess, sys, collections, hashlib
from concurrent.futures import ThreadPoolExecutor
V = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
R = os.path.join(V, 'results', 'fixed'); C = os.path.join(V, 'cache')
OUT = os.path.join(V, 'results', 'vexec' + os.environ.get('JIT', '')); SC = os.path.join(V, 'vscenes'); os.makedirs(OUT, exist_ok=True); os.makedirs(SC + '/data', exist_ok=True)
SL = '/System/Library/PrivateFrameworks/SkyLight.framework/Versions/A/Resources/SkyLightShaders.air64.metallib'
CD = '/System/Library/Frameworks/CoreDisplay.framework/Versions/A/Resources/default.metallib'
LIB = {'SkyLight': SL, 'CoreDisplay': CD}
SLIB = {'SkyLight': '@SkyLight', 'CoreDisplay': '@CoreDisplay'}   # scene files carry no absolute paths
W, H = 96, 64
rnd = random.Random(int(sys.argv[1]) if len(sys.argv) > 1 else 11)
SIZES = {3: ('f', 1, 4), 4: ('f', 2, 4), 5: ('f', 3, 4), 6: ('f', 4, 4), 16: ('e', 1, 2), 17: ('e', 2, 2), 18: ('e', 3, 2), 19: ('e', 4, 2),
         29: ('i', 1, 4), 30: ('i', 2, 4), 31: ('i', 3, 4), 32: ('i', 4, 4), 33: ('I', 1, 4), 34: ('I', 2, 4), 35: ('I', 3, 4), 36: ('I', 4, 4),
         37: ('h', 1, 2), 38: ('h', 2, 2), 41: ('H', 1, 2), 42: ('H', 2, 2), 45: ('b', 1, 1), 49: ('B', 1, 1), 50: ('B', 2, 1), 52: ('B', 4, 1),
         53: ('?', 1, 1), 54: ('?', 2, 1), 56: ('?', 4, 1)}
MAT = {7: (2, 2, 8), 8: (2, 3, 16), 9: (2, 4, 16), 10: (3, 2, 8), 11: (3, 3, 16), 12: (3, 4, 16), 13: (4, 2, 8), 14: (4, 3, 16), 15: (4, 4, 16)}
def val(k):
    if k in 'fe': return rnd.uniform(0.25, 0.95)
    if k == '?': return rnd.random() < 0.5
    return rnd.choice([0, 1, 2])
def fill(layout, name):
    size = max(layout.get('size', 16), 16); mem = layout.get('members', [])
    if not mem:
        dt = layout.get('dtype', 3); size = max(size, 2048)
        k, n, sz = SIZES.get(dt, ('f', 1, 4)); mem = [[o, dt] for o in range(0, 2048, sz * n)]
    b = bytearray(size + 64)
    for off, dt in mem:
        if dt in MAT:
            cols, rows, cs = MAT[dt]
            for c in range(cols):
                for r in range(rows): struct.pack_into('<f', b, off + c * cs + r * 4, rnd.uniform(0.25, 0.95))
            continue
        if dt not in SIZES: continue
        k, n, sz = SIZES[dt]
        for i in range(n): struct.pack_into('<' + k, b, off + i * sz, val(k))
    p = os.path.join(SC, 'data', hashlib.sha1(bytes(b)).hexdigest()[:16] + '.bin'); open(p, 'wb').write(b)
    return os.path.relpath(p, V)
def ortho(w, h): return [2.0 / w, 0, 0, 0, 0, -2.0 / h, 0, 0, 0, 0, 1, 0, -1, 1, 0, 1]
AT = {3: ('float', 1), 4: ('float2', 2), 5: ('float3', 3), 6: ('float4', 4)}
TEX = os.path.relpath(os.path.join(V, 'scenes', 'data', 'window64.bin'), V)

# ---- pick variants ----
rows = {}
for g in ['skylight_base', 'coredisplay', 'skylight_exhaustive', 'shadow_structured', 'skylight_fc410']:
    for l in open(os.path.join(R, g + '.jsonl')):
        r = json.loads(l)
        if r.get('safe'): continue          # safe_constlen variants: same NIR as their base variant
        rows.setdefault((g, r['function']), []).append(r)
pick = []
QUOTA = dict(UberCompositeFragment=150, BlurComposite=60, UberResampleLanczosFragmentBGRA=40, StyledDebugFillFragment=30,
             ShadowCompositeFragment=16, ShadowHorizontalBlurFragment=40, ShadowVerticalBlurFragment=30, ShadowVerticalBlurRGBAFragment=40)
for (g, fn), rs in sorted(rows.items()):
    if g in ('skylight_base', 'coredisplay'):
        pick += rs
    elif g in ('skylight_exhaustive', 'shadow_structured') and fn in QUOTA:
        pick += rnd.sample(rs, min(QUOTA[fn], len(rs)))
jobs, meta = [], {}
for r in pick:
    if r['rc'] != 0: continue           # ABI v4 refuses base variants whose unset constants decide their body
    side = json.load(open(os.path.join(C, 'entries', r['cache_key'][:2], r['cache_key'] + '.json')))
    refl = side['reflection']
    if refl['stage'] != 'fragment' or refl['uses_fb_fetch']: continue
    if [(t['index'], t['components']) for t in refl['render_targets']] != [(0, 4)]: continue
    if any(b['kind'] == 'texture' and not b['type'].startswith('texture2d') for b in refl['bindings']): continue
    if any(b['kind'] == 'device_buffer' for b in refl['bindings']): continue
    if r['group'] == 'skylight_base' and any(not f['defined'] for f in refl['function_constants']): continue
    fc = {str(f['index']): f['value'] for f in refl['function_constants'] if f['defined']}
    lib = r['lib']
    jobs.append(dict(id=r['id'], metallib=LIB[lib], fn=r['function'], stage='fragment', fc=fc,
                     vs_candidates=['SimpleVertex', 'SimpleVertexShadow', 'SimpleColorVertex', 'UberCompositeVertex', 'BlurCompositeVertex',
                                    'SimpleTextureLightingVertex', 'StyledDebugFillVertex', 'SimpleMeshVertex'] if lib == 'SkyLight' else ['ViewportToNDC'],
                     vs_metallib=LIB[lib], vs_fc={}, rt=[80]))
    meta[r['id']] = (r, refl)
p = subprocess.run([os.path.join(V, 'build', 'mtlrefl')], input='\n'.join(json.dumps(j) for j in jobs), capture_output=True, text=True)
refs = {json.loads(l)['id']: json.loads(l) for l in p.stdout.splitlines()}
if len(refs) != len(jobs): print(p.stderr[-1500:]); sys.exit(1)
scenes = []
for j in jobs:
    m = refs[j['id']]; r, refl = meta[j['id']]
    if not m.get('ok') or not m.get('vs'): print('skip (metal)', j['id'], m.get('err', '')[:100]); continue
    vsn = m['vs']
    if any(t not in AT for _, t in m['vattrs']): print('skip (vattr)', j['id'], m['vattrs']); continue
    pixel = any(b['kind'] == 'constexpr_sampler' and b['state']['coord'] == 'pixel' for b in refl['bindings'])
    S = 64.0 if pixel else 1.0
    J = float(os.environ.get('JIT', '0'))
    x0, x1, y0, y1, uo = 16 + J, 80 - J * 0.7, 0 + J * 0.5, 64 - J * 0.3, J * 0.0137
    corners = [(x0, y0, uo, uo), (x1, y0, 1 + uo, uo), (x0, y1, uo, 1 + uo), (x1, y0, 1 + uo, uo), (x1, y1, 1 + uo, 1 + uo), (x0, y1, uo, 1 + uo)]
    attrs, off = [], 0
    for idx, t in sorted(m['vattrs']):
        attrs.append(dict(index=idx, format=AT[t][0], offset=off)); off += 4 * AT[t][1]
    data = []
    vr = random.Random(5)
    for (x, y, u, v) in corners:
        for a, (idx, t) in zip(attrs, sorted(m['vattrs'])):
            n = AT[t][1]
            if idx == 0: comp = [x, y, 0, 1][:n]
            elif idx == 1: comp = ([(u * 1.1 - 0.05) * S, (v * 1.1 - 0.05) * S, 0, 1])[:n]
            else: comp = [vr.uniform(0.3, 0.9) for _ in range(n)]
            data += comp
    vbufs = []
    for b in m['vbindings']:
        if b['t'] != 'buffer' or b['i'] == 30: continue
        if b['name'] == 'mvp_matrix' or b['i'] == 1:
            fp = fill(b['layout'], b['name']); d = bytearray(open(os.path.join(V, fp), 'rb').read()); d[0:64] = struct.pack('<16f', *ortho(W, H))
            fp2 = fp[:-4] + '_mvp.bin'; open(os.path.join(V, fp2), 'wb').write(d); vbufs.append(dict(index=b['i'], file=fp2))
        else: vbufs.append(dict(index=b['i'], file=fill(b['layout'], b['name'])))
    fbufs, texs, samps = [], [], []
    for b in m['bindings']:
        if b['t'] == 'buffer': fbufs.append(dict(index=b['i'], file=fill(b['layout'], b['name'])))
        elif b['t'] == 'texture': texs.append(dict(index=b['i'], width=64, height=64, format='rgba8', file=TEX))
        elif b['t'] == 'sampler': samps.append(dict(index=b['i'], filter='linear', address='clamp_to_edge'))
    vbc = os.path.relpath(os.path.join(V, 'corpus', r['lib'], vsn + '.bc'), V)
    fbc = os.path.relpath(os.path.join(V, 'corpus', r['lib'], r['function'] + '.bc'), V)
    # VS function constants: all declared set to 0 explicitly on both sides
    # (--list-fcs reads the declarations without compiling: ABI v4 refuses the unset base variant)
    vj = subprocess.run([os.path.join(V, 'build', 'air2ir3'), '--list-fcs', os.path.join(V, vbc)], capture_output=True, text=True).stdout
    try: vfc = {str(f['index']): 0 for f in json.loads(vj)['function_constants']}
    except Exception: vfc = {}
    sc = dict(vs=dict(bc=vbc, metallib=SLIB[r['lib']], function=vsn, fc=vfc), fs=dict(bc=fbc, metallib=SLIB[r['lib']], function=r['function'], fc=j['fc']),
              vertex=dict(stride=off, data=dict(floats=data), count=6, primitive='triangle', attributes=attrs),
              buffers=dict(vertex=vbufs, fragment=fbufs), textures=texs, samplers=samps, name=j['id'],
              width=W, height=H, clear=[0.1, 0.2, 0.3, 1.0], frames=3, format='bgra8', blend_premul_over=False)
    name = j['id'].replace('/', '__')
    sp = os.path.join(SC, name + '.json'); json.dump(sc, open(sp, 'w'), indent=1); scenes.append((name, sp))
def run(ns):
    name, sp = ns; res = {}
    for tool, ext in (('mtlgold', 'metal'), ('nirexec', 'lp')):
        q = subprocess.run([os.path.join(V, 'build', tool), sp, os.path.join(OUT, f'{name}.{ext}.bgra'), '--frames', '3'], capture_output=True, text=True)
        if q.returncode: return name, dict(err=f'{tool}: ' + (q.stdout + q.stderr).strip()[-300:])
    a = open(os.path.join(OUT, name + '.metal.bgra'), 'rb').read(); b = open(os.path.join(OUT, name + '.lp.bgra'), 'rb').read()
    d = [abs(x - y) for x, y in zip(a, b)]
    return name, dict(max=max(d), over=sum(1 for x in d if x > 3), ncol=len(set(a[i:i + 4] for i in range(0, len(a), 4))))
with ThreadPoolExecutor(8) as ex: res = dict(ex.map(run, scenes))
json.dump(res, open(os.path.join(OUT, 'summary.json'), 'w'), indent=1)
c = collections.Counter(); byfn = collections.defaultdict(lambda: [0, 0, 0])
for n, r in res.items():
    fn = n.split('__')[1]
    if 'err' in r: c['err'] += 1; byfn[fn][2] += 1; print('ERR', n, r['err'][:200]); continue
    ok = r['over'] == 0; c['pass' if ok else 'fail'] += 1; byfn[fn][0 if ok else 1] += 1
    if not ok: print('FAIL', n, r)
print(dict(c), 'scenes', len(scenes))
for fn, v in sorted(byfn.items()): print(f'  {fn:36s} pass {v[0]:4d} fail {v[1]:3d} err {v[2]}')
print('trivial (<=2 colours):', sum(1 for r in res.values() if r.get('ncol', 99) <= 2))

#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Compare air2ir3 reflection (cache sidecars) with Metal's own reflection (M3 Max, MTLBinding.isUsed)
for sampled sweep variants.  usage: reflcmp.py [N_per_big_group]
(verify/vtools/reflcmp.py, run on the fix tree: results/fixed + cache/.  ABI v2 bindings carry
"present" (Metal's notion: the argument exists) next to "used"; an absent argument that the code
still reads is bound through by the command stream and is compared as absent, like Metal.)"""
import json, os, random, subprocess, sys, collections
V = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
R = os.path.join(V, 'results', 'fixed'); C = os.path.join(V, 'cache')
IX = {(e['lib'], e['function']): e for e in json.load(open(os.path.join(V, 'corpus', 'index.json')))}
LIB = {'SkyLight': '/System/Library/PrivateFrameworks/SkyLight.framework/Versions/A/Resources/SkyLightShaders.air64.metallib',
       'CoreDisplay': '/System/Library/Frameworks/CoreDisplay.framework/Versions/A/Resources/default.metallib'}
VS = {'SkyLight': ['SimpleVertex', 'SimpleColorVertex', 'SimpleVertexShadow', 'SimpleTextureLightingVertex', 'UberCompositeVertex',
                   'BlurCompositeVertex', 'StyledDebugFillVertex', 'SimpleMeshVertex'],
      'CoreDisplay': ['ViewportToNDC']}
N = int(sys.argv[1]) if len(sys.argv) > 1 else 400
random.seed(7)
jobs, ours = [], {}
for g in ['skylight_base', 'coredisplay', 'skylight_fc410', 'skylight_exhaustive', 'shadow_structured']:
    if not os.path.exists(os.path.join(R, g + '.jsonl')): continue      # a partial sweep (tools/cleanroom.sh)
    rows = [r for r in (json.loads(l) for l in open(os.path.join(R, g + '.jsonl'))) if not r.get('safe')]
    if len(rows) > N: rows = random.sample(rows, N)
    for r in rows:
        if r['rc'] != 0: continue
        side = json.load(open(os.path.join(C, 'entries', r['cache_key'][:2], r['cache_key'] + '.json')))
        refl = side['reflection']
        fc = {str(f['index']): f['value'] for f in refl['function_constants'] if f['defined']}
        st = refl['stage']
        j = dict(id=r['id'], metallib=LIB[r['lib']], fn=r['function'], stage=st, fc=fc, vs_candidates=VS[r['lib']])
        # Metal requires the attachments the FS writes
        if st == 'fragment':
            j['rt'] = [80] * (1 + max([t['index'] for t in refl['render_targets']] or [0]))
            for t in refl['render_targets']:
                if t['components'] == 1: j['rt'][t['index']] = 10
                elif t['components'] == 2: j['rt'][t['index']] = 30
        jobs.append(j); ours[r['id']] = refl
p = subprocess.run([os.path.join(V, 'build', 'mtlrefl')], input='\n'.join(json.dumps(j) for j in jobs), capture_output=True, text=True)
if p.returncode: print(p.stderr[-2000:]); sys.exit(1)
KMAP = {'ubo': 'buffer', 'device_buffer': 'buffer', 'texture': 'texture', 'sampler': 'sampler'}
stats = collections.Counter(); bad = []
for l in p.stdout.splitlines():
    m = json.loads(l); refl = ours[m['id']]
    if not m.get('ok'): stats['metal_fail'] += 1; bad.append((m['id'], 'METAL FAIL ' + m.get('err', ''))); continue
    mt = {(b['t'], b['i']): b['used'] for b in m['bindings'] if b['t'] in ('buffer', 'texture', 'sampler') and not (b['t'] == 'buffer' and b['i'] == 30)}
    ou = {}
    for b in refl['bindings']:
        if b['kind'] in KMAP and b.get('present', True): ou[(KMAP[b['kind']], b['metal_index'])] = b.get('used', True)
    # Metal lists arguments that are present (active); isUsed = statically referenced.
    mused = {k for k, u in mt.items() if u}; oused = {k for k, u in ou.items() if u}
    if set(mt) != set(ou): stats['present_mismatch'] += 1; bad.append((m['id'], f'present metal={sorted(mt)} ours={sorted(ou)}'))
    elif mused != oused: stats['used_mismatch'] += 1; bad.append((m['id'], f'used metal={sorted(mused)} ours={sorted(oused)}'))
    else: stats['match'] += 1
print(dict(stats), 'of', len(jobs))
for b in bad[:40]: print(' ', b)
json.dump(dict(stats=dict(stats), of=len(jobs), bad=bad), open(os.path.join(V, 'results', 'reflcmp.json'), 'w'), indent=1)

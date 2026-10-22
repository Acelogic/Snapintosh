#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""qcrefl.py - the 36 QuartzCore stages (18 pipelines) against the Metal reflection local-cts recorded
for them on the M3 Max (vertexArguments / fragmentArguments).  Compares the set of present
buffer/texture/sampler arguments (index, type) and their used flag.  Vertex buffers fetched by the
vertex descriptor are not ABI bindings (BINDING-ABI.md 4.2) and are listed separately."""
import json, os, sys
V = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(V, 'tools')); import sweep
KMAP = {'ubo': 'buffer', 'device_buffer': 'buffer', 'texture': 'texture', 'sampler': 'sampler'}
rows = {json.loads(l)['id']: json.loads(l) for l in open(os.path.join(V, 'results', 'fixed', 'qc_pipelines.jsonl'))}
res, bad = [], []
for i, p in enumerate(json.load(open(sweep.REQ_PIPES))):
    label = p['label'].replace('com.apple.coreanimation.', '')
    for st, args in (('vertex', p.get('vertexArguments', [])), ('fragment', p.get('fragmentArguments', []))):
        r = rows[f'qc_pipelines/{i:02d}_{label}/{st}']
        side = json.load(open(os.path.join(V, 'cache', 'entries', r['cache_key'][:2], r['cache_key'] + '.json')))
        ours = {(KMAP[b['kind']], b['metal_index']): b['used'] for b in side['reflection']['bindings'] if b['kind'] in KMAP and b['present']}
        metal = {(a['type'], a['index']): a.get('used', True) for a in args if a['type'] in ('buffer', 'texture', 'sampler')}
        vfetch = {k for k in metal if st == 'vertex' and k not in ours and k[0] == 'buffer'}
        m2 = {k: v for k, v in metal.items() if k not in vfetch}
        ok = set(m2) == set(ours) and all(ours[k] == m2[k] or not m2[k] for k in m2)
        res.append(dict(id=r['id'], ok=ok, vertex_fetch_buffers=sorted(vfetch)))
        if not ok: bad.append(dict(id=r['id'], metal=sorted(m2.items()), ours=sorted(ours.items())))
out = dict(stages=len(res), match=sum(r['ok'] for r in res), bad=bad)
json.dump(out, open(os.path.join(V, 'results', 'qcrefl.json'), 'w'), indent=1)
print(f"{out['match']}/{out['stages']} QuartzCore stages match Metal's recorded reflection")
for b in bad: print(' ', b)

#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""fix2diff.py - what the fix2 compiler changed in the swept variants, against the fix-round-1 sweep
(results/fix1, a copy of ../fix/results/fixed).  Per group: variants whose ir3 statistics changed,
that now report num_samp / need_pixlod (item 9), whose driver_params UBO moved (item 3), whose XR
blend path changed (item 7), and the new safe_constlen variants (item 1).  The exact code bytes of
the A16-verified P7 pair are compared by make-p7-shaders.sh (CHANGES.md item 9).
  python3 tools/fix2diff.py -> results/fix2diff.json"""
import collections, json, os, sys
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
A, B = os.path.join(ROOT, 'results', 'fix1'), os.path.join(ROOT, 'results', 'fixed')
if not os.path.isdir(A) or not any(f.endswith('.jsonl') for f in os.listdir(A)):
    # verify3 item 5: in a clean-room copy (sources only) this printed nothing at all
    print('SKIP: baseline results/fix1 (fix round 1 sweep) is not in this tree; a clean-room copy has no results/')
    json.dump(dict(skipped='no results/fix1'), open(os.path.join(ROOT, 'results', 'fix2diff.json'), 'w')); sys.exit(0)
out = {}
for f in sorted(os.listdir(B)):
    if not f.endswith('.jsonl') or not os.path.exists(os.path.join(A, f)): continue
    old = {json.loads(l)['id']: json.loads(l) for l in open(os.path.join(A, f))}
    new = [json.loads(l) for l in open(os.path.join(B, f))]
    c = collections.Counter()
    for r in new:
        if r.get('safe'): c['safe_constlen (new)'] += 1; continue
        o = old.get(r['id'])
        if not o: c['new id'] += 1; continue
        if (o['rc'] == 0) != (r['rc'] == 0): c['status changed'] += 1; continue
        if r['rc'] != 0: c['failed both'] += 1; continue
        c['compared'] += 1
        so, sn = o['stats'], r['stats']
        if (so['instrs'], so['dwords'], so['constlen'], so['full_regs']) != (sn['instrs'], sn['dwords'], sn['constlen'], sn['full_regs']):
            c['instrs/dwords/constlen/regs changed'] += 1
        if sn.get('need_pixlod'): c['need_pixlod now 1'] += 1
        if sn.get('num_samp', 0) > 0: c['num_samp now > 0'] += 1
        dpo = [d['ubo'] for d in o.get('driver_ubos', []) if d['kind'] == 'driver_params']
        dpn = [d['ubo'] for d in r.get('driver_ubos', []) if d['kind'] == 'driver_params']
        if dpo != dpn: c['driver_params UBO moved'] += 1
        lo = [(l['index'], l.get('dual_source'), l['hw_blend']['enabled']) for l in o.get('rt_lowering', [])]
        ln = [(l['index'], l.get('dual_source'), l['hw_blend']['enabled']) for l in r.get('rt_lowering', [])]
        if lo != ln: c['XR blend path changed'] += 1
    out[f[:-6]] = dict(c)
json.dump(out, open(os.path.join(ROOT, 'results', 'fix2diff.json'), 'w'), indent=1)
for g, c in out.items(): print(f'{g:22s}', ', '.join(f'{k} {v}' for k, v in c.items()))

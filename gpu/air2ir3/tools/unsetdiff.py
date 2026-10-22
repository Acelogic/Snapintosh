#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""unsetdiff.py - must-fix 7 report: what changed between the hardened sweep (unset constant = 0) and
this tree's (Metal semantics) for every group both have.  A variant "changed" when its ir3 blob,
its present bindings or its absent-but-read list differ.
  python3 tools/unsetdiff.py [--old results/hardened] [--new results/fixed] [--out results/unsetdiff.json]
The baseline is the hardened round's results/ directory, which a clean-room copy (tools/cleanroom.sh,
sources only) does not have: then this prints "SKIP: ..." and writes {"skipped": ...} (verify4 item 5;
before, it printed nothing, the defect verify3 item 5 found in fix2diff.py)."""
import argparse, json, os, sys
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ap = argparse.ArgumentParser()
ap.add_argument('--old', default=os.path.join(ROOT, 'results', 'hardened')); ap.add_argument('--new', default=os.path.join(ROOT, 'results', 'fixed'))
ap.add_argument('--out', default=os.path.join(ROOT, 'results', 'unsetdiff.json'))
a = ap.parse_args()
GROUPS = ('skylight_base', 'coredisplay', 'qc_pipelines', 'templates', 'skylight_fc410', 'skylight_exhaustive', 'shadow_structured')
OUT = a.out
common = [g for g in GROUPS if os.path.exists(os.path.join(a.old, g + '.jsonl')) and os.path.exists(os.path.join(a.new, g + '.jsonl'))]
if not common:
    why = (f'baseline {os.path.relpath(a.old, ROOT)} (hardened sweep, unset constant = 0) is not in this tree'
           if not os.path.isdir(a.old) else f'no group is in both {os.path.relpath(a.old, ROOT)} and {os.path.relpath(a.new, ROOT)}')
    msg = f'SKIP: {why}; a clean-room copy has no results/'
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    print(msg); json.dump(dict(skipped=msg), open(OUT, 'w'), indent=1); sys.exit(0)
out = {}
for g in common:
    po, pn = os.path.join(a.old, g + '.jsonl'), os.path.join(a.new, g + '.jsonl')
    if not (os.path.exists(po) and os.path.exists(pn)): continue
    O = {json.loads(l)['id']: json.loads(l) for l in open(po)}; N = {json.loads(l)['id']: json.loads(l) for l in open(pn)}
    same, changed = 0, []
    for k, n in N.items():
        o = O.get(k)
        if not o: continue
        if n['rc'] != 0:            # ABI v4/v5: refused (an unset constant decides something, BINDING-ABI.md 3.7)
            changed.append(dict(id=k, blob_same=False, instrs=(o.get('stats', {}).get('instrs'), None), bindings_removed=[], bindings_added=[],
                                absent_but_read=[], refused=n.get('error', '')[:160])); continue
        ob = sorted(map(tuple, o.get('bindings', []))); nb = sorted(tuple(b) for b in n.get('bindings', []))
        absent = n.get('absent_but_read', [])
        if o.get('blob_sha256') == n.get('blob_sha256') and ob == nb and not absent: same += 1; continue
        changed.append(dict(id=k, blob_same=o.get('blob_sha256') == n.get('blob_sha256'), instrs=(o['stats']['instrs'], n['stats']['instrs']),
                            bindings_removed=sorted(set(ob) - set(nb)), bindings_added=sorted(set(nb) - set(ob)), absent_but_read=absent))
    out[g] = dict(variants=len(N), unchanged=same, changed=len(changed), details=changed[:40])
json.dump(out, open(OUT, 'w'), indent=1)
for g, r in out.items():
    print(f"{g:22s} {r['variants']:6d} variants: {r['unchanged']} unchanged, {r['changed']} changed")
    for c in r['details'][:12]: print('   ', c['id'], 'blob same' if c['blob_same'] else 'blob differs', 'instrs', c['instrs'], 'absent-but-read', c['absent_but_read'])

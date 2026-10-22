#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""rounddiff.py - what this compiler changed in the swept variants against a previous round's sweep.

  python3 tools/rounddiff.py [baseline_dir] [label] [out.json]   (default results/fix2 = ../fix2/results/fixed,
                                                       copied into this tree) -> results/rounddiff.json
Fix round 6 baselines: results/abi6 (the sweep of adreno-render-fix/work/fix4abi6, the compiler of A16
render run 2) and results/fix5 (fix round 5's sweep).
Per group: variants compared, status changes (with the new error lines), variants whose code blob
changed, instruction-count deltas (min..max and histogram), register/constlen changes, bindings
changes, constexpr sampler masks, and the per-draw descriptor counts (NTEX/NSAMP) before and after:
ABI v3 programmed both from ir3's num_samp, ABI v4 and v5 from ir3.stats.ntex / nsamp (BINDING-ABI.md 3.4;
v5 counts the s# of every texture instruction).

The baseline is a results/ directory, which a clean-room copy does not have (tools/cleanroom.sh
copies sources only): then this prints "SKIP: ..." and writes {"skipped": ...}, instead of the
empty output fix2diff.py gave (verify3 item 5)."""
import collections, json, os, sys
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
A = sys.argv[1] if len(sys.argv) > 1 else os.path.join(ROOT, 'results', 'fix2')
LABEL = sys.argv[2] if len(sys.argv) > 2 else 'fix round 2'
B = os.path.join(ROOT, 'results', 'fixed')
OUT = sys.argv[3] if len(sys.argv) > 3 else os.path.join(ROOT, 'results', 'rounddiff.json')
if not os.path.isdir(A) or not any(f.endswith('.jsonl') for f in os.listdir(A)):
    msg = f'SKIP: baseline {os.path.relpath(A, ROOT)} ({LABEL} sweep) is not in this tree; a clean-room copy has no results/'
    print(msg); json.dump(dict(skipped=msg), open(OUT, 'w'), indent=1); sys.exit(0)
out = dict(baseline=os.path.relpath(A, ROOT), label=LABEL, groups={}, descriptors={})
desc_old, desc_new = collections.Counter(), collections.Counter()
for f in sorted(os.listdir(B)):
    if not f.endswith('.jsonl') or not os.path.exists(os.path.join(A, f)): continue
    old = {json.loads(l)['id']: json.loads(l) for l in open(os.path.join(A, f))}
    c = collections.Counter(); dins = collections.Counter(); errs = collections.Counter()
    for l in open(os.path.join(B, f)):
        r = json.loads(l)
        if r.get('safe'): c['safe variants'] += 1; continue
        o = old.get(r['id'])
        if not o: c['new id'] += 1; continue
        if (o['rc'] == 0) != (r['rc'] == 0):
            c['compiled -> refused' if o['rc'] == 0 else 'refused -> compiled'] += 1
            if r['rc'] != 0: errs[r.get('error', '?')[:150]] += 1
            continue
        if r['rc'] != 0: c['refused both'] += 1; continue
        c['compared'] += 1
        so, sn = o['stats'], r['stats']
        if o.get('blob_sha256') != r.get('blob_sha256'): c['blob changed'] += 1
        dins[sn['instrs'] - so['instrs']] += 1
        if (so['full_regs'], so['half_regs'], so['constlen']) != (sn['full_regs'], sn['half_regs'], sn['constlen']): c['regs/constlen changed'] += 1
        if o.get('bindings') != r.get('bindings'): c['bindings changed'] += 1
        if so.get('max_ubo_index') != sn.get('max_ubo_index'): c['max_ubo_index changed'] += 1
        if o.get('constexpr_sampler_mask') != r.get('constexpr_sampler_mask'): c['constexpr sampler slots changed'] += 1
        if [l2.get('hw_blend') for l2 in o.get('rt_lowering', [])] != [l2.get('hw_blend') for l2 in r.get('rt_lowering', [])]: c['XR hw_blend changed'] += 1
        if sn.get('per_sample_shading_if_msaa'): c['per-sample shading flag set'] += 1
        if 'ntex' in so: desc_old[(so['ntex'], so['nsamp'])] += 1          # baseline of ABI v4 or later: its own counts
        else: n0 = so.get('num_samp', 0); desc_old[(n0, n0)] += 1           # ABI v3: NTEX = NSAMP = num_samp
        desc_new[(sn.get('ntex', 0), sn.get('nsamp', 0))] += 1
        if (so.get('ntex'), so.get('nsamp')) != (sn.get('ntex'), sn.get('nsamp')) and 'ntex' in so: c['ntex/nsamp changed'] += 1
        if o.get('requires_no_attachment') != r.get('requires_no_attachment') and r.get('requires_no_attachment'): c['requires_no_attachment set'] += 1
    g = dict(c)
    if dins: g['instr_delta'] = dict(min=min(dins), max=max(dins), hist={str(k): v for k, v in sorted(dins.items())})
    if errs: g['new_refusals'] = dict(errs.most_common(8))
    out['groups'][f[:-6]] = g
def summ(cn):
    tot = sum(cn.values()); t16 = sum(v for (a, b), v in cn.items() if a >= 16); s16 = sum(v for (a, b), v in cn.items() if b >= 16)
    return dict(variants=tot, ntex_ge16=t16, nsamp_ge16=s16, mean_ntex=round(sum(a * v for (a, b), v in cn.items()) / max(tot, 1), 2),
                mean_nsamp=round(sum(b * v for (a, b), v in cn.items()) / max(tot, 1), 2), total_descriptors=sum((a + b) * v for (a, b), v in cn.items()),
                top=[[f'{a}/{b}', v] for (a, b), v in cn.most_common(8)])
v4base = any('ntex' in json.loads(l).get('stats', {}) for f in os.listdir(A) if f.endswith('.jsonl') for l in open(os.path.join(A, f)) if '"stats"' in l)
out['descriptors'] = {('before (' + LABEL + ': ntex / nsamp)' if v4base else 'before (ABI v3: NTEX = NSAMP = num_samp)'): summ(desc_old),
                      'after (this tree: ntex / nsamp)': summ(desc_new)}
json.dump(out, open(OUT, 'w'), indent=1)
print(f'against {out["baseline"]} ({LABEL}):')
for g, c in out['groups'].items(): print(f'{g:22s}', json.dumps(c)[:400])
for k, v in out['descriptors'].items(): print(k, json.dumps(v))

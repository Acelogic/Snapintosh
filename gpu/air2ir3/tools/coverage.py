#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""coverage.py - turn the sweep results into the tables of COVERAGE.md.

  python3 tools/coverage.py [--v0 results/v0] [--hardened results/hardened] [--fixed results/fixed] > results/coverage.md
Also writes results/coverage.json (per-group counts, failure classes, per-function stats, cache
integrity: distinct keys, keys mapping to more than one blob).
"""
import argparse, collections, json, os, re, statistics

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
GROUPS = ['skylight_base', 'coredisplay', 'qc_pipelines', 'templates', 'skylight_fc410', 'skylight_exhaustive', 'shadow_structured']
NEW_GROUPS = ['qc_all', 'xr_targets', 'xr_textures', 'coredisplay_gpupass']

def load(d, g, safe=False):
    """the group's rows; safe_constlen rows (id suffix /safe, fix2) only with safe=True"""
    p = os.path.join(d, g + '.jsonl')
    rows = [json.loads(l) for l in open(p)] if os.path.exists(p) else []
    return [r for r in rows if bool(r.get('safe')) == safe]

def err_class(e):
    e = e or '?'
    if 'did not reach a fixpoint' in e: return 'LLVM instcombine fixpoint abort (needs instcombine<no-verify-fixpoint>)'
    if 'value not translated: ptr addrspace(1)' in e: return 'gated device-buffer argument not translated (implicit FC predicate not evaluated)'
    if 'unused_lod_bias' in e: return 'constant global used as value (unused_lod_bias) not translated'
    if 'bit size mismatch' in e: return '64-bit phi'
    m = re.search(r'unset function constant (\w+) \(index \d+\).*? (decides a \w+|reaches[\w ]*?) in the function body', e)
    if m: return f'refused by design (ABI v5): unset constant {m.group(1)} {m.group(2)}'
    m = re.search(r'the presence predicate (\w+) (depends on the value|is the same for every value)', e)
    if m: return f'refused by design (ABI v5): presence predicate depends on an unset constant'
    return re.sub(r'\s+', ' ', e)[:100]

def stats_line(rs):
    ins = [r['stats']['instrs'] for r in rs if r.get('stats')]
    if not ins: return '-'
    return f"{min(ins)} / {int(statistics.median(ins))} / {max(ins)}"

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--v0', default=os.path.join(ROOT, 'results', 'v0'))
    ap.add_argument('--hardened', default=os.path.join(ROOT, 'results', 'hardened'))
    ap.add_argument('--fixed', default=os.path.join(ROOT, 'results', 'fixed'))
    a = ap.parse_args()
    out, J = [], dict(groups={}, cache={})
    out.append('| group | variants | v0 prototype ok | hardened ok | this tree ok | failure classes (this tree; v0) |')
    out.append('|---|---:|---:|---:|---:|---|')
    keyblob = collections.defaultdict(set)
    warn = collections.Counter()
    for g in GROUPS + NEW_GROUPS:
        v0, hd, fx = load(a.v0, g), load(a.hardened, g), load(a.fixed, g)
        c = collections.Counter(err_class(r.get('error')) for r in v0 if r['rc'] != 0)
        fc = collections.Counter(err_class(r.get('error')) for r in fx if r['rc'] != 0)
        J['groups'][g] = dict(variants=len(fx), v0_ok=sum(r['rc'] == 0 for r in v0), v0_n=len(v0), hardened_ok=sum(r['rc'] == 0 for r in hd),
                              hardened_n=len(hd), ok=sum(r['rc'] == 0 for r in fx), v0_failures=dict(c), failures=dict(fc),
                              absent_but_read=sum(1 for r in fx if r.get('absent_but_read')),
                              driver_ubos=dict(collections.Counter(d['kind'] for r in fx for d in r.get('driver_ubos', []))),
                              max_ubo_index=max((r['stats'].get('max_ubo_index', -1) for r in fx if r.get('stats')), default=-1))
        cls = '; '.join(f'{k}: {v}' for k, v in fc.most_common()) or '-'
        if c: cls += ' (v0: ' + '; '.join(f'{k}: {v}' for k, v in c.most_common()) + ')'
        out.append(f"| {g} | {len(fx)} | {J['groups'][g]['v0_ok']}/{len(v0) if v0 else '-'} | "
                   f"{str(J['groups'][g]['hardened_ok']) + '/' + str(len(hd)) if hd else '-'} | {J['groups'][g]['ok']}/{len(fx)} | {cls} |")
        for r in fx + load(a.fixed, g, True):
            if r.get('cache_key') and g != 'templates': keyblob[r['cache_key']].add(r['blob_sha256'])
    tot = sum(J['groups'][g]['variants'] for g in GROUPS); ok = sum(J['groups'][g]['ok'] for g in GROUPS)
    v0ok = sum(J['groups'][g]['v0_ok'] for g in GROUPS); v0n = sum(J['groups'][g]['v0_n'] for g in GROUPS)
    hok = sum(J['groups'][g]['hardened_ok'] for g in GROUPS)
    out.append(f'| **coverage targets** | **{tot}** | **{v0ok}/{v0n}** | **{hok}/{tot}** | **{ok}/{tot}** | |')
    J['cache'] = dict(results_with_key=sum(len(v) > 0 for v in keyblob.values()), distinct_keys=len(keyblob),
                      keys_with_multiple_blobs=sum(1 for v in keyblob.values() if len(v) > 1),
                      distinct_blobs=len(set().union(*keyblob.values())) if keyblob else 0)
    # fix2: const budget (safe_constlen variants) and private memory
    out.append('')
    out.append('Const budget and private memory (BINDING-ABI.md 5.2 and 3.10), per group:')
    out.append('')
    out.append('| group | ok variants | constlen > max_const_safe | safe_constlen variants ok | max constlen | max safe constlen | variants with pvtmem | pvtmem BO needed (MiB: variants) |')
    out.append('|---|---:|---:|---:|---:|---:|---:|---|')
    pvall = collections.Counter(); J['budget'] = {}
    for g in GROUPS + NEW_GROUPS:
        fx = [r for r in load(a.fixed, g) if r['rc'] == 0]; sf = load(a.fixed, g, True)
        if not fx: continue
        ex = [r for r in fx if r.get('const_budget', {}).get('exceeds_safe_constlen')]
        pv = collections.Counter(r['pvtmem']['total_size'] >> 20 for r in fx + [x for x in sf if x['rc'] == 0] if r.get('pvtmem', {}).get('total_size'))
        if g != 'templates': pvall.update(pv)
        J['budget'][g] = dict(ok=len(fx), exceeds_safe=len(ex), safe_ok=sum(r['rc'] == 0 for r in sf), safe_n=len(sf),
                              max_constlen=max((r['stats']['constlen'] for r in fx), default=0),
                              max_safe_constlen=max((r['stats']['constlen'] for r in sf if r['rc'] == 0), default=0),
                              pvtmem_variants=sum(pv.values()), pvtmem_mib=dict(sorted(pv.items())))
        b = J['budget'][g]
        out.append(f"| {g} | {len(fx)} | {len(ex)} | {b['safe_ok']}/{len(sf)} | {b['max_constlen']} | {b['max_safe_constlen'] or '-'} | "
                   f"{b['pvtmem_variants']} | {', '.join(f'{k}: {v}' for k, v in sorted(pv.items())) or '-'} |")
    J['pvtmem_mib_all'] = dict(sorted(pvall.items()))
    # fix3: per-draw descriptor counts (BINDING-ABI.md 3.4) and per-sample shading (4.6)
    out.append('')
    out.append('Per-draw T#/S# descriptor counts (ABI v4 NTEX = ir3.stats.ntex, NSAMP = nsamp; ABI v3 programmed both from num_samp) '
               'and fragment variants flagged for per-sample shading on MSAA (BINDING-ABI.md 3.4, 4.6):')
    out.append('')
    out.append('| group | ok variants | v3 (fix2 sweep) NTEX = NSAMP >= 16 | v4 NTEX >= 16 | v4 NSAMP >= 16 | mean v3 T#+S# per draw | mean v4 T#+S# per draw | most common v4 NTEX/NSAMP | per-sample if MSAA (reasons) |')
    out.append('|---|---:|---:|---:|---:|---:|---:|---|---|')
    J['descriptors'] = {}
    for g in GROUPS + NEW_GROUPS:
        fx = [r for r in load(a.fixed, g) if r['rc'] == 0 and r.get('stats')]
        if not fx: continue
        n = len(fx); st = [r['stats'] for r in fx]
        # v3: the same variant in the fix-round-2 sweep (results/fix2), where NTEX = NSAMP = num_samp
        base = {r['id']: r for r in load(os.path.join(ROOT, 'results', 'fix2'), g) if r['rc'] == 0 and r.get('stats')}
        v3s = [base[r['id']]['stats'].get('num_samp', 0) for r in fx if r['id'] in base]
        v3 = sum(1 for x in v3s if x >= 16); t16 = sum(1 for x in st if x.get('ntex', 0) >= 16); s16 = sum(1 for x in st if x.get('nsamp', 0) >= 16)
        m3 = sum(2 * x for x in v3s) / max(len(v3s), 1); m4 = sum(x.get('ntex', 0) + x.get('nsamp', 0) for x in st) / n
        top = collections.Counter(f"{x.get('ntex', 0)}/{x.get('nsamp', 0)}" for x in st).most_common(3)
        ps = collections.Counter(rs for r in fx for rs in (r.get('sample_shading') or {}).get('reasons', []))
        nps = sum(1 for r in fx if (r.get('sample_shading') or {}).get('per_sample_if_msaa'))
        J['descriptors'][g] = dict(ok=n, v3_compared=len(v3s), v3_num_samp_ge16=v3, ntex_ge16=t16, nsamp_ge16=s16, mean_v3=round(m3, 2), mean_v4=round(m4, 2),
                                   top=top, per_sample=nps, per_sample_reasons=dict(ps))
        out.append(f"| {g} | {n} | {v3} | {t16} | {s16} | {m3:.2f} | {m4:.2f} | {', '.join(f'{k} ({v})' for k, v in top)} | "
                   f"{nps}{' (' + ', '.join(f'{k} {v}' for k, v in ps.items()) + ')' if ps else ''} |")
    # fix4 (verify4 items 1-2): refusals per group, why, and what changed against fix round 3
    out.append('')
    out.append('Refusals per group (ABI v5), by reason; "unset" = variants that leave at least one declared function constant unset; '
               'round 3 = the same variants in results/fix3 (fix round 3, ABI v4):')
    out.append('')
    out.append('| group | variants | with unset constants | refused | unset constant decides the body | presence predicate on an unset constant | other refusals | round 3 refused | newly refused | newly compiled |')
    out.append('|---|---:|---:|---:|---:|---:|---|---:|---:|---:|')
    J['refusals'] = {}
    for g in GROUPS + NEW_GROUPS:
        fx = load(a.fixed, g)
        if not fx: continue
        base = {r['id']: r for r in load(os.path.join(ROOT, 'results', 'fix3'), g)}
        unset = sum(1 for r in fx if r.get('unset_constants'))
        ref = [r for r in fx if r['rc'] != 0]
        body = [r for r in ref if re.search(r'unset function constant \w+ \(index \d+\).*? (decides|reaches)', r.get('error') or '')]
        pred = [r for r in ref if 'presence predicate' in (r.get('error') or '')]
        other = collections.Counter(err_class(r.get('error')) for r in ref if r not in body and r not in pred)
        r3 = sum(1 for r in fx if r['id'] in base and base[r['id']]['rc'] != 0)
        newly = sorted(r['id'] for r in ref if r['id'] in base and base[r['id']]['rc'] == 0)
        newok = sorted(r['id'] for r in fx if r['rc'] == 0 and r['id'] in base and base[r['id']]['rc'] != 0)
        J['refusals'][g] = dict(variants=len(fx), unset=unset, refused=len(ref), body=len(body), presence=len(pred), other=dict(other),
                                round3_refused=r3, newly_refused=newly[:50], newly_refused_n=len(newly), newly_compiled=newok[:50], newly_compiled_n=len(newok),
                                body_constants=dict(collections.Counter(re.search(r'unset function constant (\w+)', r['error']).group(1) for r in body)))
        out.append(f"| {g} | {len(fx)} | {unset} | {len(ref)} | {len(body)} | {len(pred)} | {'; '.join(f'{k}: {v}' for k, v in other.items()) or '-'} | "
                   f"{r3} | {len(newly)}{' (' + ', '.join(x.split('/', 1)[1] for x in newly[:6]) + (', ...' if len(newly) > 6 else '') + ')' if newly else ''} | {len(newok)} |")
    out.append('')
    out.append('Per-function ir3 instruction counts, min / median / max over the variants swept:')
    out.append('')
    out.append('| group | function | variants | ok | ir3 instrs min / median / max | max full regs | max constlen |')
    out.append('|---|---|---:|---:|---|---:|---:|')
    for g in ['skylight_fc410', 'skylight_exhaustive', 'shadow_structured', 'templates']:
        by = collections.defaultdict(list)
        for r in load(a.fixed, g):
            key = r['function'] if g != 'templates' else (r['extra'].get('template', '?') + ' ' + r['function'])
            by[key].append(r)
        for fn, rs in sorted(by.items()):
            st = [r['stats'] for r in rs if r.get('stats')]
            out.append(f"| {g} | {fn} | {len(rs)} | {sum(r['rc'] == 0 for r in rs)} | {stats_line(rs)} | "
                       f"{max((s['full_regs'] for s in st), default='-')} | {max((s['constlen'] for s in st), default='-')} |")
    out.append('')
    for g, title in [('skylight_base', 'SkyLight (33 functions, no function constants set)'), ('coredisplay', 'CoreDisplay (4)'),
                     ('qc_pipelines', 'QuartzCore: the 18 pipelines CA builds under the adreno profile (vertex + fragment, exact constants)')]:
        out.append(f'**{title}**')
        out.append('')
        out.append('| variant | function | stage | status | instrs | dwords | full regs | constlen | preamble | max waves | bindings |')
        out.append('|---|---|---|---|---:|---:|---:|---:|---:|---:|---|')
        for r in load(a.fixed, g):
            s = r.get('stats') or {}
            ab = {tuple(x) for x in r.get('absent_but_read', [])}
            b = ' '.join((f"{k[0]}{k[1] if k[1] >= 0 else ''}>{k[2]}" + ('(absent)' if (k[0], k[1]) in ab else '')).replace('constexpr_sampler', 'cs')
                         .replace('device_buffer', 'dev').replace('storage_texture', 'img').replace('threadgroup_buffer', 'tg')
                         .replace('texture', 't').replace('sampler', 's').replace('fb_fetch', 'fbf') for k in [tuple(x) for x in r.get('bindings', [])])
            name = r['id'].split('/', 1)[1]
            out.append(f"| {name} | {r['function']} | {r['stage']} | {'ok' if r['rc'] == 0 else 'FAIL: ' + r.get('error', '')} | "
                       f"{s.get('instrs', '-')} | {s.get('dwords', '-')} | {s.get('full_regs', '-')} | {s.get('constlen', '-')} | "
                       f"{s.get('preamble_instrs', '-')} | {s.get('max_waves', '-')} | {b} |")
        out.append('')
    json.dump(J, open(os.path.join(ROOT, 'results', 'coverage.json'), 'w'), indent=1)
    print('\n'.join(out))
    print(f"\ncache: {J['cache']}")

if __name__ == '__main__':
    main()

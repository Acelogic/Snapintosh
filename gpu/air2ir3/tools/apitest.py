#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""apitest.py - online compile of SkyLight's runtime templates through the C library (must-fix 2).

WindowServer builds these 5 templates at run time (newLibraryWithSource:); with our driver the
MSL -> AIR step runs in Apple's MTLCompilerService and the plug-in receives each function's AIR,
then calls air2ir3_compile().  This measures that call on the M3 Max for every instantiation
(183 fragment functions + the templates' SimpleVertex), one compiler handle, 5 repetitions
each, and also times Apple's MSL -> AIR front end (xcrun metal -c + metallib) for the smallest
and largest instantiation of each template as the other half of the online cost.
Checks: every compile succeeds, is deterministic, and is byte-identical when compiled from 8
threads at once on the same handle.
Then (verify2 item 4) online == cached: up to 120 cache entries of each kind (safe_constlen,
lowered attachment, texture class, constexpr samplers, driver UBOs, private memory, other), spread
evenly over the key space, are recompiled through air2ir3_compile() from their key inputs; the returned
sidecar must equal the entry file byte for byte, and air2ir3_cache_key() must give the same key
without compiling (build/api_test cached).
  python3 tools/apitest.py  -> results/api/timing.json, results/api/timing.md, results/api/cached.log
"""
import json, os, statistics, subprocess, sys, tempfile, time
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, 'results', 'api')

def main():
    os.makedirs(OUT, exist_ok=True)
    man = json.load(open(os.path.join(ROOT, 'build', 'templates', 'manifest.json')))
    lines, meta, seen = [], [], set()
    for v in man['variants']:
        fr = v['functions'][v['entry']]
        lines.append(f"{os.path.join(ROOT, fr['bc'])}\t{v['entry']}\tfragment\t80"); meta.append((v['template'], v['variant'], v['params'], 'fragment'))
        if v['template'] not in seen:
            seen.add(v['template'])
            lines.append(f"{os.path.join(ROOT, v['functions']['SimpleVertex']['bc'])}\tSimpleVertex\tvertex\t0"); meta.append((v['template'], v['variant'], {}, 'vertex'))
    jl = os.path.join(OUT, 'jobs.txt'); open(jl, 'w').write('\n'.join(lines) + '\n')
    p = subprocess.run([os.path.join(ROOT, 'build', 'api_test'), 'list', jl, '--repeat', '5', '--threads', '8'], capture_output=True, text=True)
    open(os.path.join(OUT, 'api_test.log'), 'w').write(p.stdout + p.stderr)
    rows = []
    res = [l.split('\t') for l in p.stdout.splitlines() if l.startswith('ok\t') or l.startswith('FAIL\t')]
    for (tmpl, var, params, st), r in zip(meta, res):
        if r[0] != 'ok': rows.append(dict(template=tmpl, variant=var, stage=st, ok=False, error=r[3])); continue
        rows.append(dict(template=tmpl, variant=var, params=params, stage=st, ok=True, min_ms=float(r[4].split()[1]),
                         median_ms=float(r[5].split()[1]), blob=int(r[6].split()[1])))
    thr = [l for l in p.stdout.splitlines() if l.startswith('# threads')]
    # Apple front end (MSL -> AIR -> metallib) for the smallest and largest instantiation of each template
    fe = {}
    for tmpl in sorted({v['template'] for v in man['variants']}):
        vs = [v for v in man['variants'] if v['template'] == tmpl]
        for v in (vs[0], vs[-1]):
            ts = []
            with tempfile.TemporaryDirectory(dir=os.path.join(ROOT, 'scratch')) as td:
                for _ in range(3):
                    t0 = time.time()
                    subprocess.run(['xcrun', '-sdk', 'macosx', 'metal', '-c', os.path.join(ROOT, v['metal']), '-o', os.path.join(td, 'a.air')], check=True)
                    subprocess.run(['xcrun', '-sdk', 'macosx', 'metallib', os.path.join(td, 'a.air'), '-o', os.path.join(td, 'a.metallib')], check=True)
                    ts.append((time.time() - t0) * 1e3)
            fe[v['variant']] = round(min(ts), 1)
    summ = {}
    for tmpl in sorted({r['template'] for r in rows}):
        fr = [r for r in rows if r['template'] == tmpl and r['stage'] == 'fragment' and r['ok']]
        vs = [r for r in rows if r['template'] == tmpl and r['stage'] == 'vertex' and r['ok']]
        med = [r['median_ms'] for r in fr]
        big = max(fr, key=lambda r: r['median_ms'])
        summ[tmpl] = dict(instantiations=len(fr), median_of_medians_ms=round(statistics.median(med), 1), min_ms=round(min(r['min_ms'] for r in fr), 1),
                          max_median_ms=round(big['median_ms'], 1), slowest=big['variant'], vertex_median_ms=vs[0]['median_ms'] if vs else None)
    ok = all(r['ok'] for r in rows) and p.returncode == 0
    json.dump(dict(ok=ok, host=subprocess.run(['sysctl', '-n', 'machdep.cpu.brand_string'], capture_output=True, text=True).stdout.strip(),
                   compiles=len(rows), threads=thr, per_template=summ, apple_front_end_ms=fe, rows=rows), open(os.path.join(OUT, 'timing.json'), 'w'), indent=1)
    md = ['| template | instantiations | air2ir3_compile median of medians (ms) | fastest (ms) | slowest median (ms) | slowest variant | SimpleVertex (ms) |',
          '|---|---:|---:|---:|---:|---|---:|']
    for t, s in summ.items():
        md.append(f"| {t} | {s['instantiations']} | {s['median_of_medians_ms']} | {s['min_ms']} | {s['max_median_ms']} | {s['slowest']} | {s['vertex_median_ms']} |")
    md.append('')
    md.append('Apple MSL -> AIR (xcrun metal -c + metallib, best of 3): ' + ', '.join(f'{k} {v} ms' for k, v in fe.items()))
    md.append('')
    md.append((thr[0][2:] if thr else 'no thread test') + f'; {len(rows)} compiles, all ok: {ok}')
    cok, cline = cached_check()
    md.append(cline)
    open(os.path.join(OUT, 'timing.md'), 'w').write('\n'.join(md) + '\n')
    print('\n'.join(md))
    sys.exit(0 if ok and cok else 1)

CLASS_FMT = {0: 80, 1: 554, 2: 552}
PER_CAT = 120
def cached_check(cache=os.path.join(ROOT, 'cache')):
    cats = {}
    for d in sorted(os.listdir(os.path.join(cache, 'entries'))):
        for f in sorted(os.listdir(os.path.join(cache, 'entries', d))):
            if f.endswith('.src.json'): continue
            ep = os.path.join(cache, 'entries', d, f)
            e = json.load(open(ep)); ki = e['key_inputs']
            cat = ('safe_constlen' if ki['safe_constlen'] else 'lowered_attachment' if any(ki['rt_classes']) else
                   'texture_class' if any(ki['texture_classes']) else 'constexpr_samplers' if e['constant_samplers']['samplers'] else
                   'driver_ubos' if e['ir3']['driver_ubos'] else 'pvtmem' if e['ir3']['pvtmem']['pvtmem_size'] else 'other')
            cats.setdefault(cat, []).append(ep)
    # a spread of at most PER_CAT entries per category (every k-th in key order)
    ents = []
    for cat, eps in sorted(cats.items()):
        k = max(1, len(eps) // PER_CAT)
        ents += [(ep, json.load(open(ep))) for ep in eps[::k][:PER_CAT]]
    lines = []
    for ep, e in ents:
        src = json.load(open(ep[:-5] + '.src.json')); ki = e['key_inputs']
        fr = e['reflection']['stage'] == 'fragment'
        fmts = ','.join(str(CLASS_FMT[c] if fr else 0) for c in ki['rt_classes'])
        bl = []
        for i in range(8):
            b = ki['blend'].get(str(i))
            bl.append(','.join(['1', *(str(b[k]) for k in ('rgb_op', 'alpha_op', 'src_rgb', 'dst_rgb', 'src_alpha', 'dst_alpha'))]) if b and b['enabled'] else '0,0,0,1,0,1,0')
        consts = ';'.join(f"{c['index']}=" + ','.join(repr(float(v)) for v in c['value']) for c in e['reflection']['function_constants'] if c['defined']) or '-'
        lines.append('\t'.join([os.path.join(ROOT, src['source']), e['reflection']['function'], e['reflection']['stage'], fmts, ';'.join(bl),
                                ','.join(str(c) for c in ki['texture_classes']), '1' if ki['safe_constlen'] else '0', consts, ep]))
    jl = os.path.join(OUT, 'cached_jobs.txt'); open(jl, 'w').write('\n'.join(lines) + '\n')
    p = subprocess.run([os.path.join(ROOT, 'build', 'api_test'), 'cached', jl], capture_output=True, text=True)
    open(os.path.join(OUT, 'cached.log'), 'w').write(p.stdout + p.stderr)
    last = [l for l in p.stdout.splitlines() if l.startswith('# cached')]
    per = ', '.join(f'{c} {min(len(v), PER_CAT)}' for c, v in sorted(cats.items()))
    return p.returncode == 0, 'online == cached: ' + (last[0][2:] + f' ({per})' if last else 'api_test cached failed: ' + (p.stderr or p.stdout)[-300:])

if __name__ == '__main__':
    main()

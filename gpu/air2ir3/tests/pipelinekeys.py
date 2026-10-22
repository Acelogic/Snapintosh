#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""pipelinekeys.py - verifier must-fix 1+3: keys derived from REAL MTLRenderPipelineDescriptors must hit
the swept cache (CACHE-FORMAT.md 4).

Descriptor sets (all built and accepted by Metal on this Mac by build/pipelinekey):
  qc        the 18 QuartzCore pipelines CA builds under the adreno profile (local-cts), exact
            constants, formats, blending and sample count
  skylight  the 28 WindowServer VS/FS pairs (windowserver-metal-usage/cts/specs.json) into the
            SDR-path destination formats bgra8Unorm (80, framebuffer and window backings) and
            rgba16Float (115), blending off and premultiplied source-over; functions with function
            constants get every constant set, with vectors from the exhaustive / structured selector
            space.  (Which constants WindowServer really sets is not known; a pipeline with some
            constants unset has its own key, defined=0, and hits only the variants the sweep made
            that way, e.g. the skylight_base group with none set.)
  coredisplay  ViewportToNDC + TextureCopy / ColorFill into CoreDisplay's IOSurface formats 80, 90,
            94, 115 (CD_MTLPixelFormatForIOSurface), and GPUPass specialised with its two uint
            masks (availableFeatures, optionalFeatures) drawn from the five bits it tests
  msaa      SkyLight pairs with rasterSampleCount 4 (the sample count is not key material in
            format 3: they must hit the single-sample entries)
  xr        SkyLight pairs into BGR10_XR (554) and BGRA10_XR (552) (EDR path, shader-lowered)
  templates SkyLight's runtime templates: expected to MISS (compiled online, evidence only)
A hit means entries/<k>/<key>.json exists, its blob exists, and its function/stage match.
Const budget (BINDING-ABI.md 5.2): for every accepted descriptor the VS and FS constlens from the hit
entries go through air2ir3_trim_constlen (build/air2ir3 --trim-constlen); each trimmed stage's
safe_constlen key must hit too, and the pipeline's final constlen must fit max_const_pipeline.
  python3 tests/pipelinekeys.py [--cache cache]   -> results/pipelinekeys.json
"""
import argparse, json, os, random, subprocess, sys
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, 'tools'))
import cachekey, sweep

import scrdir
SCR = scrdir.scratchpad()
SPECS = os.path.join(SCR, 'adreno', 'windowserver-metal-usage', 'cts', 'specs.json')
PREMUL = dict(enabled=1, rgb_op=0, alpha_op=0, src_rgb=1, dst_rgb=5, src_alpha=1, dst_alpha=5)

def main():
    ap = argparse.ArgumentParser(); ap.add_argument('--cache', default=os.path.join(ROOT, 'cache')); a = ap.parse_args()
    ix = sweep.load_index()
    h = lambda lib, fn: ix[(lib, fn)]['air_hash']
    decls = {}
    def names(lib, fn):
        if (lib, fn) not in decls: decls[(lib, fn)] = [d['name'] for d in sweep.fc_decls(os.path.join(ROOT, 'build', 'air2ir3'), os.path.join(ROOT, ix[(lib, fn)]['bc']))]
        return decls[(lib, fn)]
    rnd = random.Random(5)
    def fc_vectors(lib, fn, k=3):
        n = names(lib, fn)
        if not n: return [{}]
        if fn.startswith('Shadow') and 'Blur' in fn:
            sel = list(sweep.shadow_selectors(n)); return [{kk: [v] for kk, v in s[1].items()} for s in rnd.sample(sel, k)]
        return [{kk: [rnd.randint(0, 1)] for kk in n} for _ in range(k)]
    jobs = []
    # qc
    for i, p in enumerate(json.load(open(sweep.REQ_PIPES))):
        c = lambda st: {x['name']: x['values'] for x in p['pipeline'][st].get('constants', [])}
        jobs.append(dict(set='qc', id=f'qc/{i:02d}', metallib=os.path.relpath(os.path.join(ROOT, 'corpus', 'QuartzCore.metallib'), ROOT) if False else None,
                         vertex=p['vertex'], fragment=p['fragment'], vs_constants=c('vertex'), fs_constants=c('fragment'),
                         attachments=[dict(format=cachekey.MTL_PIXEL_FORMAT[x['format']], blend=sweep.blend_of(x.get('blend'))) for x in p['pipeline']['colorAttachments']],
                         sample_count=p['pipeline'].get('sampleCount', 1), lib='QuartzCore'))
    # skylight SDR + xr
    for sp in json.load(open(SPECS)):
        if sp['lib'] != 'SkyLight': continue
        vs, fs = sp['vertex']['name'], sp['fragment']['name']
        rt = [o for o in sp['fragment']['outs'] if o['kind'] == 'air.render_target']
        comps = int(rt[0]['type'][-1]) if rt and rt[0]['type'][-1].isdigit() else 1
        # destination formats of the SDR path by output width: R8 (WSPixelFormat 1, shadows), BGRA8, RGBA16F
        sdr = [10] if comps == 1 else [30] if comps == 2 else [80, 115]
        for fsv in fc_vectors('SkyLight', fs):
            vsv = fc_vectors('SkyLight', vs, 1)[0]
            for fmt, st in [(f, 'skylight') for f in sdr] + ([(554, 'xr'), (552, 'xr')] if comps >= 3 else []):
                for bl in (dict(enabled=0), PREMUL):
                    if st == 'xr' and fsv: continue          # the xr sweep covers the base (no-constant) variants
                    jobs.append(dict(set=st, id=f'{st}/{vs}+{fs}/{fmt}/{"premul" if bl["enabled"] else "noblend"}/{len(jobs)}', lib='SkyLight',
                                     vertex=vs, fragment=fs, vs_constants=vsv, fs_constants=fsv, attachments=[dict(format=fmt, blend=bl)]))
    for fs in ('TextureCopy', 'GPUPass', 'ColorFill'):
        for fmt in (80, 90, 94, 115):
            for k in range(4 if fs == 'GPUPass' else 1):
                fsc = dict(availableFeatures=[rnd.randint(0, 31)], optionalFeatures=[rnd.randint(0, 31)]) if fs == 'GPUPass' else {}
                jobs.append(dict(set='coredisplay', id=f'coredisplay/ViewportToNDC+{fs}/{fmt}/{k}', lib='CoreDisplay', vertex='ViewportToNDC', fragment=fs,
                                 fs_constants=fsc, attachments=[dict(format=fmt, blend=dict(enabled=0))]))
    # MSAA: rasterSampleCount 4 (verify2: 0/23 MSAA probes hit in format 2)
    for sp in json.load(open(SPECS)):
        if sp['lib'] != 'SkyLight': continue
        rt = [o for o in sp['fragment']['outs'] if o['kind'] == 'air.render_target']
        comps = int(rt[0]['type'][-1]) if rt and rt[0]['type'][-1].isdigit() else 1
        if comps < 3: continue
        vs, fs = sp['vertex']['name'], sp['fragment']['name']
        # fix round 3: with constants set as the skylight set does (ABI v4 refuses the base variants of
        # functions whose unset constants decide their body; round 2 used no constants here)
        jobs.append(dict(set='msaa', id=f'msaa/{vs}+{fs}/80/4x', lib='SkyLight', vertex=vs, fragment=fs,
                         vs_constants=fc_vectors('SkyLight', vs, 1)[0], fs_constants=fc_vectors('SkyLight', fs, 1)[0],
                         attachments=[dict(format=80, blend=PREMUL)], sample_count=4))
    lines = []
    for j in jobs:
        lib = j.pop('lib')
        j['metallib'] = {'SkyLight': '@SkyLight', 'CoreDisplay': '@CoreDisplay', 'QuartzCore': os.path.join(ROOT, 'build', 'QuartzCore.air64_v29.metallib')}[lib]
        j['vertex_air_hash'], j['fragment_air_hash'] = h(lib, j['vertex']), h(lib, j['fragment'])
        j['vertex_descriptor_from_function'] = True
        lines.append(json.dumps(j))
    # templates: the runtime library holds SimpleVertex + the blur
    man = json.load(open(os.path.join(ROOT, 'build', 'templates', 'manifest.json')))
    for v in man['variants'][:12]:
        lines.append(json.dumps(dict(set='templates', id='templates/' + v['variant'], metallib=os.path.join(ROOT, 'build', 'templates', v['variant'] + '.metallib'),
                                     vertex='SimpleVertex', fragment=v['entry'], vertex_air_hash=v['functions']['SimpleVertex']['air_hash'],
                                     fragment_air_hash=v['functions'][v['entry']]['air_hash'], attachments=[dict(format=80)],
                                     vertex_descriptor_from_function=True)))
    qlib = os.path.join(ROOT, 'build', 'QuartzCore.air64_v29.metallib')
    if not os.path.exists(qlib):
        src = os.path.join(SCR, 'adreno', 'windowserver-metal-usage', 'libs', 'QuartzCore.air64_v29.metallib')
        subprocess.run(['cp', src, qlib], check=True)
    exe = os.path.join(ROOT, 'build', 'pipelinekey')
    if not os.path.exists(exe) or os.path.getmtime(exe) < os.path.getmtime(os.path.join(ROOT, 'tools', 'pipelinekey.swift')):
        subprocess.run(['swiftc', '-O', os.path.join(ROOT, 'tools', 'pipelinekey.swift'), '-o', exe], check=True)
    p = subprocess.run([exe], input='\n'.join(lines) + '\n', capture_output=True, text=True)
    if p.returncode: sys.exit(p.stderr[-2000:])
    sets = {json.loads(l)['id']: json.loads(l)['set'] for l in lines}
    stats, misses, rows = {}, [], []
    def lookup(k, which):
        e = os.path.join(a.cache, 'entries', k[:2], k + '.json')
        if not os.path.exists(e): return None
        ent = json.load(open(e))
        ok = os.path.exists(os.path.join(a.cache, ent['blob']['path'])) and ent['reflection']['stage'] == ('vertex' if which == 'vs' else 'fragment')
        return ent if ok else None
    trim_cache = {}
    def trim(vc, fc):
        if (vc, fc) not in trim_cache:
            o = subprocess.run([os.path.join(ROOT, 'build', 'air2ir3'), '--trim-constlen', f'{vc},{fc}'], capture_output=True, text=True, check=True).stdout
            trim_cache[(vc, fc)] = int(o.split()[-1])
        return trim_cache[(vc, fc)]
    budget = dict(pipelines=0, trimmed=0, safe_hits=0, max_final=0, over=0, trimmed_ids=[])
    for l in p.stdout.splitlines():
        r = json.loads(l); st = sets[r['id']]; s = stats.setdefault(st, dict(descriptors=0, metal_ok=0, vs_hit=0, fs_hit=0))
        s['descriptors'] += 1
        if not r['ok']: misses.append((r['id'], 'METAL: ' + r['err'])); continue
        s['metal_ok'] += 1
        ents = {}
        for k, which in ((r['vs_key'], 'vs'), (r['fs_key'], 'fs')):
            ent = lookup(k, which); hit = ent is not None; ents[which] = ent
            s[which + '_hit'] += hit
            if not hit and st != 'templates': misses.append((r['id'], which, k))
            rows.append(dict(id=r['id'], set=st, stage=which, key=k, hit=hit, classes=r.get('fs_classes'), samples=r.get('sample_count')))
        # ABI v5 (BINDING-ABI.md 3.7): an FS entry whose colour output presence an unset constant decides
        # is valid only when the pipeline has no attachment there; the plug-in refuses otherwise
        if ents['fs']:
            need = ents['fs']['reflection'].get('requires_no_attachment', [])
            clash = [k for k in need if (r.get('fs_formats') or [0] * 8)[k]]
            if need: budget.setdefault('requires_no_attachment', []).append((r['id'], need, clash))
            if clash: misses.append((r['id'], f'requires_no_attachment {need} but the descriptor has attachment(s) {clash}'))
        if ents['vs'] and ents['fs']:
            cl = [ents['vs']['ir3']['const_budget']['constlen'], ents['fs']['ir3']['const_budget']['constlen']]
            limit = ents['fs']['ir3']['const_budget']['max_const_pipeline']
            t = trim(*cl); budget['pipelines'] += 1
            if t:
                budget['trimmed'] += 1; budget['trimmed_ids'].append(r['id'])
                for bit, which in ((1, 'vs'), (2, 'fs')):
                    if not t & bit: continue
                    se = lookup(r[which + '_key_safe'], which)
                    if se is None: misses.append((r['id'], which + ' safe_constlen', r[which + '_key_safe'])); continue
                    budget['safe_hits'] += 1
                    cl[bit - 1] = se['ir3']['const_budget']['constlen']
            budget['max_final'] = max(budget['max_final'], sum(cl))
            if sum(cl) > limit: budget['over'] += 1; misses.append((r['id'], f'const budget {cl} > {limit}'))
    ok = not misses and all(s['metal_ok'] == s['descriptors'] for s in stats.values()) and stats.get('templates', {}).get('fs_hit', 0) == 0
    json.dump(dict(ok=ok, stats=stats, const_budget=budget, misses=misses[:50], rows=rows), open(os.path.join(ROOT, 'results', 'pipelinekeys.json'), 'w'), indent=1)
    print(f"const budget: {budget['pipelines']} VS+FS pipelines, {budget['trimmed']} need a safe_constlen stage "
          f"({budget['safe_hits']} safe variants hit: {', '.join(budget['trimmed_ids'][:4])}), largest final VS+FS constlen "
          f"{budget['max_final']}, over the limit: {budget['over']}")
    for st, s in stats.items(): print(f"{st:12s} {s['descriptors']:4d} descriptors, Metal accepted {s['metal_ok']}, VS hits {s['vs_hit']}, FS hits {s['fs_hit']}")
    for m in misses[:10]: print('MISS', m)
    tot = sum(s['descriptors'] for k, s in stats.items() if k != 'templates')
    hits = sum(s['vs_hit'] + s['fs_hit'] for k, s in stats.items() if k != 'templates')
    print(f"{'PASS' if ok else 'FAIL'}: {hits}/{2 * tot} VS+FS keys from {tot} real descriptors hit the cache; templates miss by design "
          f"({stats.get('templates', {}).get('fs_hit', 0)} hits)")
    sys.exit(0 if ok else 1)

if __name__ == '__main__':
    main()

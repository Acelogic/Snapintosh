#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""sweep.py - Stage-6 coverage sweep: compile every WindowServer pipeline/function variant with
air2ir3, record status + ir3 stats, and (optionally) fill the precompiled cache.

  python3 tools/sweep.py --out results/fixed [--bin build/air2ir3] [--legacy] [--cache cache]
                         [--groups skylight_base,coredisplay,qc_pipelines,templates,skylight_fc410,
                                   skylight_exhaustive,shadow_structured,qc_all,xr_targets,xr_textures] [--jobs 14]

Groups
  skylight_base        the 33 SkyLight functions, no function constants set
  coredisplay          the 4 CoreDisplay functions
  qc_pipelines         the 18 QuartzCore pipelines CA builds under the adreno profile (local-cts
                       bundle/ca-goldens/adreno-fetch-required-pipelines.json), vertex + fragment
                       with the exact function-constant values and colour formats
  templates            SkyLight's 5 runtime MSL templates, instantiated (tools/templates.py)
  skylight_fc410       the review's 410 random function-constant variants (fcfuzz2.py, seed 1234)
  skylight_exhaustive  every FC combination of the SkyLight functions with <= 14 FCs
  shadow_structured    Shadow*Blur* variants enumerated as structured selectors
  qc_all               all 240 QuartzCore functions, no constants (imageblock/threadgroup coverage)
  xr_targets           every SkyLight/CoreDisplay fragment function rendering into BGR10_XR (554) and
                       BGRA10_XR (552), without blending and with premultiplied source-over
  xr_textures          every SkyLight/CoreDisplay fragment function with each sampled T# given the
                       draw-time class of a 554 / 552 texture
  coredisplay_gpupass  CoreDisplay GPUPass specialised with its uint masks availableFeatures and
                       optionalFeatures (setConstantValue:type:atIndex:), every pair of values inside the
                       five feature bits the function tests (0..31 x 0..31)
After each group, every successful compile whose constlen exceeds ir3's max_const_safe is compiled
again as its safe_constlen variant (id suffix "/safe"), as Turnip does (BINDING-ABI.md 5.2).
Keys are cache format 3 (CACHE-FORMAT.md); the key the library puts in the sidecar is re-derived with
tools/cachekey.py for every entry.  An entry file is the library's sidecar, byte for byte
(entries/<k>/<key>.json), with provenance next to it (<key>.src.json).  Template entries are compile
evidence only: they go to <cache>/evidence/templates.jsonl, never into entries/ (the plug-in
compiles templates online).
--legacy runs a prototype binary (no --json/--entry/--fc-name support) for before/after numbers.
"""
import argparse, hashlib, itertools, json, os, random, re, shutil, subprocess, sys, tempfile, time
from concurrent.futures import ThreadPoolExecutor

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, 'tools'))
import cachekey

import scrdir
SCRATCH = scrdir.scratchpad()
REQ_PIPES = os.path.join(SCRATCH, 'adreno', 'local-cts', 'bundle', 'ca-goldens', 'adreno-fetch-required-pipelines.json')
CHIP = 0x44070041

def load_index():
    idx = json.load(open(os.path.join(ROOT, 'corpus', 'index.json')))
    return {(e['lib'], e['function']): e for e in idx}

def fc_decls(binary, bc):
    """function constants declared by a function (air2ir3 --list-fcs: metadata only; ABI v4/v5 refuse the
    unspecialised compile of a function whose unset constants decide something)"""
    p = subprocess.run([binary, '--list-fcs', bc], capture_output=True, text=True)
    if p.returncode: return []
    return json.loads(p.stdout)['function_constants']

# ------------------------------------------------------------------------------ job generation --
def job(group, tag, lib, fn, bc, stage=None, fc=None, fcname=None, entry=None, rt=None, pipeline=None, extra=None,
        blend=None, tex_classes=None):
    return dict(group=group, id=f'{group}/{tag}', lib=lib, function=fn, bc=bc, stage=stage, fc=fc or {},
                fcname=fcname or {}, entry=entry, rt_formats=rt or [], pipeline=pipeline, extra=extra or {},
                blend=blend or {}, tex_classes=tex_classes or {})

MTL_OP = dict(add=0, subtract=1, reverseSubtract=2, min=3, max=4)
MTL_FACTOR = dict(zero=0, one=1, sourceColor=2, oneMinusSourceColor=3, sourceAlpha=4, oneMinusSourceAlpha=5,
                  destinationColor=6, oneMinusDestinationColor=7, destinationAlpha=8, oneMinusDestinationAlpha=9,
                  sourceAlphaSaturated=10, blendColor=11, oneMinusBlendColor=12, blendAlpha=13, oneMinusBlendAlpha=14)
def blend_of(b):
    """local-cts colorAttachments[i].blend -> key blend record"""
    if not b or not b.get('enabled'): return dict(enabled=0)
    return dict(enabled=1, rgb_op=MTL_OP[b['rgbOp']], alpha_op=MTL_OP[b['alphaOp']], src_rgb=MTL_FACTOR[b['srcRGB']],
                dst_rgb=MTL_FACTOR[b['dstRGB']], src_alpha=MTL_FACTOR[b['srcAlpha']], dst_alpha=MTL_FACTOR[b['dstAlpha']])
PREMUL_OVER = dict(enabled=1, rgb_op=0, alpha_op=0, src_rgb=1, dst_rgb=5, src_alpha=1, dst_alpha=5)

def g_skylight_base(ix, b):
    return [job('skylight_base', fn, 'SkyLight', fn, os.path.join(ROOT, e['bc']))
            for (lib, fn), e in sorted(ix.items()) if lib == 'SkyLight']

def g_coredisplay(ix, b):
    return [job('coredisplay', fn, 'CoreDisplay', fn, os.path.join(ROOT, e['bc']))
            for (lib, fn), e in sorted(ix.items()) if lib == 'CoreDisplay']

def g_qc_pipelines(ix, b):
    pipes = json.load(open(REQ_PIPES))
    jobs = []
    for i, p in enumerate(pipes):
        label = p['label'].replace('com.apple.coreanimation.', '')
        fmts = [cachekey.MTL_PIXEL_FORMAT[c['format']] for c in p['pipeline']['colorAttachments']]
        blends = {i: blend_of(c.get('blend')) for i, c in enumerate(p['pipeline']['colorAttachments'])}
        for st in ('vertex', 'fragment'):
            fn = p[st]
            consts = {c['name']: c['values'] for c in p['pipeline'][st].get('constants', [])}
            e = ix[('QuartzCore', fn)]
            jobs.append(job('qc_pipelines', f'{i:02d}_{label}/{st}', 'QuartzCore', fn, os.path.join(ROOT, e['bc']),
                            stage=st, fcname=consts, rt=fmts if st == 'fragment' else [], pipeline=f'{i:02d}_{label}',
                            extra=dict(sample_count=p['pipeline'].get('sampleCount', 1)), blend=blends if st == 'fragment' else {}))
    return jobs

def g_templates(ix, b):
    man = json.load(open(os.path.join(ROOT, 'build', 'templates', 'manifest.json')))
    jobs, seen_vs = [], set()
    for v in man['variants']:
        fr = v['functions'][v['entry']]
        jobs.append(job('templates', v['variant'] + '/fragment', 'SkyLight-runtime', v['entry'], os.path.join(ROOT, fr['bc']),
                        stage='fragment', rt=[80], pipeline=v['variant'], entry=v['entry'],
                        extra=dict(template=v['template'], params=v['params'], air_hash=fr['air_hash'])))
        if v['template'] not in seen_vs:     # the template's SimpleVertex is identical for all fills
            seen_vs.add(v['template'])
            vr = v['functions']['SimpleVertex']
            jobs.append(job('templates', v['template'] + '/SimpleVertex', 'SkyLight-runtime', 'SimpleVertex',
                            os.path.join(ROOT, vr['bc']), stage='vertex', pipeline=v['template'] + '/vertex', entry='SimpleVertex',
                            extra=dict(template=v['template'], air_hash=vr['air_hash'])))
    return jobs

FUZZ_FNS = ["BlurComposite", "ShadowCompositeFragment", "UberCompositeVertex", "ShadowHorizontalBlurFragment",
            "ShadowVerticalBlurFragment", "ShadowVerticalBlurRGBAFragment", "StyledDebugFillFragment",
            "UberCompositeFragment", "UberResampleLanczosFragmentYCbCr", "UberResampleLanczosFragmentBGRA"]

def g_skylight_fc410(ix, b):
    """exactly the variant sequence of shader-compiler-review/fcfuzz2.py (random.seed(1234))"""
    random.seed(1234)
    jobs = []
    for n in FUZZ_FNS:
        bc = os.path.join(ROOT, ix[('SkyLight', n)]['bc'])
        ll = subprocess.run(['/opt/homebrew/opt/llvm/bin/llvm-dis', bc, '-o', '-'], capture_output=True, text=True).stdout
        idx = sorted(set(int(x) for x in re.findall(r"MTL_FC_INIT_(\d+)_b", ll)))
        combos = [{i: 1 for i in idx}]
        for k in range(40):
            p = random.choice([0.1, 0.3, 0.5, 0.7])
            combos.append({i: (1 if random.random() < p else 0) for i in idx})
        for k, c in enumerate(combos):
            jobs.append(job('skylight_fc410', f'{n}/{k:02d}', 'SkyLight', n, bc, fc=c))
    return jobs

def g_skylight_exhaustive(ix, b):
    jobs = []
    for (lib, fn), e in sorted(ix.items()):
        if lib != 'SkyLight': continue
        bc = os.path.join(ROOT, e['bc'])
        d = fc_decls(b, bc)
        if not d or len(d) > 14: continue
        idx = [f['index'] for f in d]
        for bits in range(1 << len(idx)):
            c = {i: (bits >> k) & 1 for k, i in enumerate(idx)}
            jobs.append(job('skylight_exhaustive', f'{fn}/{bits:05x}', 'SkyLight', fn, bc, fc=c))
    return jobs

EQ = [0, 12, 23, 24, 34, 46, 51, 56, 68, 102, 112]

def shadow_selectors(names):
    """Structured selector space of the SkyLight shadow blur functions (see COVERAGE.md):
       radius r -> is_radius_eq_X = (r == X) for the 11 baked radii, is_radius_ge_T = (r >= T);
       rim state: none | hard_square | hard_round | soft; rim radius: eq_0..4 | uncommon (only with a rim);
       inner rim (fc 4, when declared) off | on, inner rim radius 0..4 (when declared and inner on);
       is_horizontal 0 | 1."""
    ge = sorted(int(n.split('_')[-1]) for n in names if n.startswith('is_radius_ge_'))
    radii = sorted(set(EQ) | {1} | set(ge))           # every eq radius and one radius per ge-interval
    rims = [None, 'is_rim_state_hard_square', 'is_rim_state_hard_round', 'is_rim_state_soft']
    rim_r = ['is_rim_radius_eq_0', 'is_rim_radius_eq_1', 'is_rim_radius_eq_2', 'is_rim_radius_eq_3',
             'is_rim_radius_eq_4', 'is_rim_radius_uncommon']
    has_inner = 'is_rim_state_inner' in names
    inner_r = [n for n in ['is_inner_rim_radius_%d' % i for i in range(5)] if n in names]
    for r in radii:
        for horiz in (0, 1):
            for rim in rims:
                for rr in (rim_r if rim else [None]):
                    for inner in ((0, 1) if has_inner else (0,)):
                        for ir in (inner_r if (inner and inner_r) else [None]):
                            v = {n: 0 for n in names}
                            v['is_horizontal'] = horiz
                            for x in EQ:
                                if f'is_radius_eq_{x}' in v: v[f'is_radius_eq_{x}'] = int(r == x)
                            for t in ge: v[f'is_radius_ge_{t}'] = int(r >= t)
                            if rim: v[rim] = 1; v[rr] = 1
                            if inner: v['is_rim_state_inner'] = 1
                            if ir: v[ir] = 1
                            tag = f'r{r}_h{horiz}_{(rim or "norim").replace("is_rim_state_", "")}' \
                                  f'{"_" + rr.replace("is_rim_radius_", "rr") if rr else ""}' \
                                  f'{"_inner" if inner else ""}{"_" + ir.replace("is_inner_rim_radius_", "ir") if ir else ""}'
                            yield tag, v

def g_shadow_structured(ix, b):
    jobs = []
    for fn in ['ShadowHorizontalBlurFragment', 'ShadowVerticalBlurFragment', 'ShadowVerticalBlurRGBAFragment']:
        bc = os.path.join(ROOT, ix[('SkyLight', fn)]['bc'])
        names = [f['name'] for f in fc_decls(b, bc)]
        for tag, v in shadow_selectors(names):
            jobs.append(job('shadow_structured', f'{fn}/{tag}', 'SkyLight', fn, bc, fcname=v))
    return jobs

def g_qc_all(ix, b):
    return [job('qc_all', fn, 'QuartzCore', fn, os.path.join(ROOT, e['bc']))
            for (lib, fn), e in sorted(ix.items()) if lib == 'QuartzCore']

def _ws_fragments(ix):
    for (lib, fn), e in sorted(ix.items()):
        if lib in ('SkyLight', 'CoreDisplay') and e.get('type') == 'fragment':
            yield lib, fn, os.path.join(ROOT, e['bc'])

def _zero_fcs(b, bc):
    """every declared function constant set to 0 (ABI v4/v5 refuse a variant whose unset constants decide
    something, which is most of the base variants; the XR groups test the lowering, not unset constants)"""
    return {d['index']: 0 for d in fc_decls(b, bc)}

def g_xr_targets(ix, b):
    """lowered colour attachments: every WS fragment function x {554, 552} x {no blend, premultiplied over}.
    Function constants: every declared one set to 0 (fix round 3; before: none set, the base variant)."""
    jobs = []
    for lib, fn, bc in _ws_fragments(ix):
        fc = _zero_fcs(b, bc)
        for fmt in (554, 552):
            for bn, bl in (('noblend', dict(enabled=0)), ('premul_over', PREMUL_OVER)):
                jobs.append(job('xr_targets', f'{fn}/{fmt}_{bn}', lib, fn, bc, stage='fragment', rt=[fmt], blend={0: bl}, fc=fc))
    return jobs

def g_xr_textures(ix, b):
    """draw-time texture classes: every sampled T# of every WS fragment function as a 554 / 552 texture
    (declared constants set to 0, as in xr_targets)"""
    jobs = []
    for lib, fn, bc in _ws_fragments(ix):
        fc = _zero_fcs(b, bc)
        with tempfile.TemporaryDirectory(dir=os.path.join(ROOT, 'scratch')) as td:
            j = os.path.join(td, 'r.json')
            subprocess.run([b, '--quiet', '--json', j] + [x for i, v in fc.items() for x in ('--fc', f'{i}={v}')] + [bc], capture_output=True)
            if not os.path.exists(j): continue
            ts = sorted({x['slot'] for x in json.load(open(j))['reflection']['bindings'] if x['kind'] == 'texture' and x['used']})
        if not ts: continue
        for cls in (1, 2):
            jobs.append(job('xr_textures', f'{fn}/class{cls}', lib, fn, bc, stage='fragment', tex_classes={t: cls for t in ts}, fc=fc))
    return jobs

def g_coredisplay_gpupass(ix, b):
    """verify2 item 6: CoreDisplay specialises GPUPass with two uint masks.  The function tests bits 0-4
    of (available & ~optional) | (optional & runtime flags); every (available, optional) pair inside
    those bits is swept.  Masks with higher bits set miss and are compiled online."""
    e = ix[('CoreDisplay', 'GPUPass')]
    return [job('coredisplay_gpupass', f'GPUPass/a{av:02d}_o{op:02d}', 'CoreDisplay', 'GPUPass', os.path.join(ROOT, e['bc']),
                stage='fragment', fcname=dict(availableFeatures=av, optionalFeatures=op))
            for av in range(32) for op in range(32)]

GROUPS = dict(skylight_base=g_skylight_base, coredisplay=g_coredisplay, qc_pipelines=g_qc_pipelines,
              templates=g_templates, skylight_fc410=g_skylight_fc410, skylight_exhaustive=g_skylight_exhaustive,
              shadow_structured=g_shadow_structured, qc_all=g_qc_all, xr_targets=g_xr_targets, xr_textures=g_xr_textures,
              coredisplay_gpupass=g_coredisplay_gpupass)
EVIDENCE_ONLY = {'templates'}

# ------------------------------------------------------------------------------------ running --
ERR_RE = re.compile(r'UNSUPPORTED/ERROR: .*|LLVM ERROR: .*|Assertion .*|NIR validation failed.*|error: .*|Segmentation.*|TIMEOUT')

def compiler_id(binary):
    """the identity baked into the binary (tools/compiler_id.py, CACHE-FORMAT.md 2.3); --legacy
    runs (prototype binary) use the binary hash"""
    if binary.endswith('-v0'):
        return 'air2ir3-v0-' + hashlib.sha256(open(binary, 'rb').read()).hexdigest()[:16]
    return subprocess.run([binary, '--compiler-id'], capture_output=True, text=True, check=True).stdout.strip()

_DECL_CACHE = {}
def names_to_indices(j, helper):
    """--fc-name values resolved to indices so the legacy prototype can take them too."""
    if not j['fcname']: return dict(j['fc'])
    if j['bc'] not in _DECL_CACHE: _DECL_CACHE[j['bc']] = fc_decls(helper, j['bc'])
    by = {d['name']: d['index'] for d in _DECL_CACHE[j['bc']]}
    fc = dict(j['fc'])
    for n, v in j['fcname'].items():
        if n in by: fc[by[n]] = v
    return fc

def run_job(j, a, ix, cid):
    args = [a.bin]
    if not a.legacy: args += ['--quiet']
    for i, v in sorted(names_to_indices(j, a.helper).items(), key=lambda kv: int(kv[0])):
        vv = v if isinstance(v, list) else [v]
        args += ['--fc', f'{i}=' + ','.join(str(int(x)) if float(x).is_integer() else str(x) for x in vv)]
    if not a.legacy:
        if j['entry']: args += ['--entry', j['entry']]
        if j['stage']: args += ['--stage', j['stage']]
        if j['stage'] != 'vertex':
            for i, f in enumerate(j['rt_formats']):
                if f: args += ['--rt-format', f'{i}={f}']
            for i, bl in j['blend'].items():
                if bl.get('enabled'):
                    args += ['--blend', f'{i}=1,' + ','.join(str(bl[k]) for k in cachekey.BLEND_FIELDS)]
        for t, c in j['tex_classes'].items(): args += ['--tex-class', f'{t}={c}']
        if j.get('safe'): args += ['--safe-constlen']
    td = tempfile.mkdtemp(dir=os.path.join(ROOT, 'scratch'))
    jp, vp = os.path.join(td, 'r.json'), os.path.join(td, 'v.bin')
    if not a.legacy: args += ['--json', jp, '--variant', vp]
    args.append(j['bc'])
    t0 = time.time()
    try:
        p = subprocess.run(args, capture_output=True, text=True, timeout=a.timeout)
        out, rc = p.stdout + p.stderr, p.returncode
    except subprocess.TimeoutExpired:
        out, rc = 'TIMEOUT', -9
    r = dict(id=j['id'], group=j['group'], lib=j['lib'], function=j['function'], pipeline=j['pipeline'],
             stage=j['stage'], rc=rc, secs=round(time.time() - t0, 3), fc=j['fc'], fcname=j['fcname'],
             rt_formats=j['rt_formats'], extra=j['extra'], blend=j['blend'], tex_classes=j['tex_classes'], safe=bool(j.get('safe')))
    if not a.legacy:
        # fix4: the declared constants this variant leaves unset (COVERAGE.md refusal accounting, BINDING-ABI.md 3.7)
        if j['bc'] not in _DECL_CACHE: _DECL_CACHE[j['bc']] = fc_decls(a.helper, j['bc'])
        given = {int(k) for k in names_to_indices(j, a.helper)}
        r['unset_constants'] = sorted(d['name'] for d in _DECL_CACHE[j['bc']] if d['index'] not in given)
    if rc != 0:
        m = ERR_RE.search(out)
        r['error'] = re.sub(r'%\d+', '%v', (m.group(0) if m else (out.strip().splitlines() or ['rc=%d' % rc])[-1]))[:240]
    m = re.search(r'ir3: (\d+) instructions, (\d+) dwords, full regs (-?\d+), half regs (-?\d+), constlen (\d+), branchstack (\d+)', out)
    if m:
        r['stats'] = dict(instrs=int(m.group(1)), dwords=int(m.group(2)), full_regs=int(m.group(3)),
                          half_regs=int(m.group(4)), constlen=int(m.group(5)), branchstack=int(m.group(6)))
    if rc == 0 and not a.legacy and os.path.exists(jp):
        side_bytes = open(jp, 'rb').read()
        side = json.loads(side_bytes)
        r['stats'] = side['ir3']['stats']
        r['const_budget'] = side['ir3']['const_budget']
        r['pvtmem'] = side['ir3']['pvtmem']
        refl = side['reflection']
        r['stage'] = refl['stage']
        r['bindings'] = [(b['kind'], b['metal_index'], b['slot']) for b in refl['bindings']]
        r['absent_but_read'] = [(b['kind'], b['metal_index']) for b in refl['bindings'] if not b.get('present', True)]
        r['warnings'] = refl['warnings']
        r['driver_ubos'] = side['ir3']['driver_ubos']
        r['sample_shading'] = side['ir3']['sample_shading']
        r['rt_lowering'] = refl.get('rt_lowering', [])
        r['varyings'] = [(v['name'], v['slot'], v['components'], v['type']) for v in refl['varyings']]
        r['uses_fb_fetch'] = refl['uses_fb_fetch']
        r['constexpr_sampler_mask'] = refl['constexpr_sampler_mask']
        # ABI v5: a colour output whose presence an unset constant decides is valid only for a pipeline
        # without that attachment (BINDING-ABI.md 3.7); check it against the pipeline's real formats
        r['requires_no_attachment'] = refl.get('requires_no_attachment', [])
        clash = [k for k in r['requires_no_attachment'] if k < len(j['rt_formats']) and j['rt_formats'][k]]
        if clash and j['pipeline']:
            r['rc'] = 4; r['error'] = f'pipeline has colour attachment(s) {clash} that the variant requires absent (BINDING-ABI.md 3.7)'
        blob = open(vp, 'rb').read()
        r['blob_sha256'] = hashlib.sha256(blob).hexdigest()
        key = side['key']
        r['cache_key'] = key
        e = ix.get((j['lib'], j['function']))
        want_hash = e['air_hash'] if e else j['extra']['air_hash']
        if cachekey.key_of_sidecar(side) != key: r['rc'] = 3; r['error'] = 'KEY MISMATCH: library key != tools/cachekey.py'
        elif side['key_inputs']['air_hash'] != want_hash: r['rc'] = 3; r['error'] = 'AIR HASH MISMATCH: bitcode SHA-256 != metallib HASH tag'
        elif side['compiler_id'] != cid: r['rc'] = 3; r['error'] = 'COMPILER ID MISMATCH'
        elif side['blob']['sha256'] != r['blob_sha256'] or side['blob']['size'] != len(blob): r['rc'] = 3; r['error'] = 'BLOB MISMATCH: sidecar blob record'
        elif a.cache:
            write_cache_entry(a.cache, j, e, side, side_bytes, blob, r['blob_sha256'])
    shutil.rmtree(td, ignore_errors=True)
    return r

def write_cache_entry(cache, j, e, side, side_bytes, blob, blob_sha):
    """CACHE-FORMAT.md section 3: entries/<k>/<key>.json is the library's sidecar byte for byte (what
    air2ir3_compile returns online), <key>.src.json its provenance; template groups go to evidence/"""
    os.makedirs(os.path.join(cache, 'blobs'), exist_ok=True)
    bp = os.path.join(cache, side['blob']['path'])
    if not os.path.exists(bp):
        fd, tp = tempfile.mkstemp(dir=os.path.dirname(bp)); os.write(fd, blob); os.close(fd)
        os.replace(tp, bp)
    key, refl = side['key'], side['reflection']
    src = dict(key=key, id=j['id'], group=j['group'], library=j['lib'], library_sha256=(e or {}).get('lib_sha256'),
               function=refl['function'], stage=refl['stage'], source=os.path.relpath(j['bc'], ROOT), pipeline=j['pipeline'])
    if j['group'] in EVIDENCE_ONLY:
        ent = dict(side); ent.update(src); ent['lookup'] = False
        ev = os.path.join(cache, 'evidence'); os.makedirs(ev, exist_ok=True)
        with EVIDENCE_LOCK:
            with open(os.path.join(ev, j['group'] + '.jsonl'), 'a') as f: f.write(json.dumps(ent) + '\n')
        return
    d = os.path.join(cache, 'entries', key[:2]); os.makedirs(d, exist_ok=True)
    for name, data in ((key + '.json', side_bytes), (key + '.src.json', (json.dumps(src, indent=1) + '\n').encode())):
        fd, tp = tempfile.mkstemp(dir=d)
        with os.fdopen(fd, 'wb') as f: f.write(data)
        os.replace(tp, os.path.join(d, name))

import threading
EVIDENCE_LOCK = threading.Lock()

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--bin', default=os.path.join(ROOT, 'build', 'air2ir3'))
    ap.add_argument('--out', required=True)
    ap.add_argument('--groups', default='skylight_base,coredisplay,qc_pipelines,templates,skylight_fc410,skylight_exhaustive,shadow_structured,qc_all,xr_targets,xr_textures,coredisplay_gpupass')
    ap.add_argument('--no-safe', action='store_true', help='skip the safe_constlen pass')
    ap.add_argument('--jobs', type=int, default=14)
    ap.add_argument('--timeout', type=int, default=600)
    ap.add_argument('--legacy', action='store_true')
    ap.add_argument('--cache')
    a = ap.parse_args()
    a.bin = os.path.abspath(a.bin)
    if a.cache: a.cache = os.path.abspath(a.cache)
    os.makedirs(a.out, exist_ok=True); os.makedirs(os.path.join(ROOT, 'scratch'), exist_ok=True)
    ix = load_index()
    helper = os.path.join(ROOT, 'build', 'air2ir3')     # FC reflection always via the hardened binary
    a.helper = helper
    cid = compiler_id(a.bin)
    if a.cache:
        os.makedirs(a.cache, exist_ok=True)
        for g in a.groups.split(','):
            if g in EVIDENCE_ONLY and os.path.exists(os.path.join(a.cache, 'evidence', g + '.jsonl')):
                os.remove(os.path.join(a.cache, 'evidence', g + '.jsonl'))
        json.dump(dict(format_version=cachekey.CACHE_FORMAT_VERSION, abi_version=cachekey.ABI_VERSION,
                       compiler_id=cid, chip_id='0x%x' % CHIP, created=time.strftime('%Y-%m-%dT%H:%M:%S')),
                  open(os.path.join(a.cache, 'manifest.json'), 'w'), indent=1)
    for g in a.groups.split(','):
        jobs = GROUPS[g](ix, helper)
        if a.legacy: jobs = [j for j in jobs if not j['tex_classes'] and g not in ('xr_targets', 'xr_textures', 'qc_all')]
        t0 = time.time()
        with ThreadPoolExecutor(a.jobs) as ex:
            res = list(ex.map(lambda j: run_job(j, a, ix, cid), jobs))
            if not a.legacy and not a.no_safe:
                # BINDING-ABI.md 5.2: the safe_constlen variant of every stage above max_const_safe
                byid = {j['id']: j for j in jobs}
                sj = [dict(byid[r['id']], id=r['id'] + '/safe', safe=True) for r in res
                      if r['rc'] == 0 and r.get('const_budget', {}).get('exceeds_safe_constlen')]
                res += list(ex.map(lambda j: run_job(j, a, ix, cid), sj))
        with open(os.path.join(a.out, g + '.jsonl'), 'w') as f:
            for r in res: f.write(json.dumps(r) + '\n')
        ok = sum(r['rc'] == 0 for r in res)
        print(f'{g:22s} {ok:6d}/{len(res):<6d} ok  ({time.time() - t0:.0f}s)', flush=True)

if __name__ == '__main__':
    main()

#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""regress.py - regression tests for the Stage-6 air2ir3 fixes.

Each test compiles a fixture (tests/fixtures/*.metal -> AIR with this Mac's Metal toolchain, or a
real WindowServer function from corpus/) with the hardened compiler and checks the result.  The
same input is also fed to the unmodified prototype (build/air2ir3-v0) to show the bug the test
guards against ("v0" column; expected to fail or to produce the wrong binding).

  python3 tests/regress.py            # exit status 0 when every hardened check passes
"""
import hashlib, json, os, re, struct, subprocess, sys, tempfile
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'tools'))
import cachekey
# Production compiles skip Mesa's per-pass NIR validation; the tests keep it, so a pass that breaks the IR stops there.
os.environ.setdefault('AIR2IR3_NIR_VALIDATE', '1')

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
NEW = os.path.join(ROOT, 'build', 'air2ir3')
V0 = os.path.join(ROOT, 'build', 'air2ir3-v0')
FIX = os.path.join(ROOT, 'tests', 'fixtures')
OUT = os.path.join(ROOT, 'build', 'tests')
SCR = os.path.join(ROOT, 'scratch')
import scrdir
QC_PIPES = os.path.join(scrdir.scratchpad(), 'adreno', 'local-cts', 'bundle', 'ca-goldens',
                        'adreno-fetch-required-pipelines.json')

class Skip(Exception): pass

def air(name, src=None):
    src = src or os.path.join(FIX, name + '.metal')
    dst = os.path.join(OUT, name + '.air')
    if not os.path.exists(dst) or os.path.getmtime(dst) < os.path.getmtime(src):
        subprocess.run(['xcrun', '-sdk', 'macosx', 'metal', '-c', src, '-o', dst], check=True)
    return dst

def corpus(lib, fn):
    return os.path.join(ROOT, 'corpus', lib, fn + '.bc')

def run(binary, path, args=(), json_out=True):
    a = [binary] + list(args)
    jp = os.path.join(SCR, 'regress.json')
    if os.path.exists(jp): os.remove(jp)
    if json_out and binary == NEW: a += ['--json', jp]
    a.append(path)
    p = subprocess.run(a, capture_output=True, text=True, timeout=600)
    out = p.stdout + p.stderr
    j = json.load(open(jp)) if (json_out and binary == NEW and p.returncode == 0 and os.path.exists(jp)) else None
    return p.returncode, out, j

def err(out):
    m = re.search(r'UNSUPPORTED/ERROR: .*|LLVM ERROR: [^\n]*|Assertion[^\n]*|ra validation fail[^\n]*|NIR validation failed[^\n]*', out)
    return m.group(0)[:110] if m else ''

def bindings(j, kind):
    return [(b['metal_index'], b['slot']) for b in j['reflection']['bindings'] if b['kind'] == kind]

def fcargs(d):
    a = []
    for k, v in d.items(): a += ['--fc', f'{k}={v}']
    return a

def qc_args(i, stage):
    p = json.load(open(QC_PIPES))[i]
    a = []
    for c in p['pipeline'][stage].get('constants', []):
        a += ['--fc-name', c['name'] + '=' + ','.join(str(int(v)) for v in c['values'])]
    return p[stage], a

TESTS = []
def test(name, bug):
    def deco(f):
        TESTS.append((name, bug, f)); return f
    return deco

# ------------------------------------------------------------------------------------ tests --
@test('phi64_frag', '64-bit phi')
def _():
    rc, out, j = run(NEW, air('phi64_frag'))
    assert rc == 0, err(out)
    rc0, out0, _ = run(V0, air('phi64_frag'), json_out=False)
    return 'ir3 %d instrs' % j['ir3']['stats']['instrs'], (rc0, err(out0))

@test('phi64_kernel', '64-bit phi')
def _():
    rc, out, j = run(NEW, air('phi64_kernel'))
    assert rc == 0, err(out)
    assert any(b[0] == 0 for b in bindings(j, 'device_buffer')), 'device buffer 0 not bound'
    rc0, out0, _ = run(V0, air('phi64_kernel'), json_out=False)
    return 'ir3 %d instrs' % j['ir3']['stats']['instrs'], (rc0, err(out0))

for fcv in [(0, 0), (1, 0), (0, 1), (1, 1)]:
    def mk(fcv):
        @test(f'fc_rt use_fetch={fcv[0]} write_second={fcv[1]}', 'gated render_target = colour -1')
        def _():
            args = fcargs({0: fcv[0], 1: fcv[1]})
            rc, out, j = run(NEW, air('fc_rt'), args)
            assert rc == 0, err(out)
            r = j['reflection']
            rts = sorted(t['index'] for t in r['render_targets'])
            want = [0, 2] if (fcv[0] or fcv[1]) else [0]
            assert rts == want, f'render targets {rts} != {want}'
            fb = bindings(j, 'fb_fetch')
            assert fb == ([(2, 57)] if fcv[0] else []), f'fb_fetch {fb}'
            outs = [o['slot'] for o in j['ir3']['outputs']]
            assert 1 not in outs, 'FRAG_RESULT_SAMPLE_MASK output present'
            rc0, out0, _ = run(V0, air('fc_rt'), args, json_out=False)
            bad0 = 'colour -1' in out0 or 'location 3\n' in out0 or rc0 != 0
            return f'RTs {rts}, fb_fetch {fb}', (rc0, err(out0) or ('reads colour -1 / writes SAMPLE_MASK' if bad0 else 'ok'))
    mk(fcv)

@test('fbfetch_slots', 'fb-fetch slot = 32+32-1-max_rts')
def _():
    rc, out, j = run(NEW, air('fbfetch_slots'))
    assert rc == 0, err(out)
    fb = bindings(j, 'fb_fetch')
    assert fb == [(0, 55), (2, 57)], fb
    rc2, out2, _ = run(NEW, air('fbfetch_slots'), json_out=False)
    assert '(0x37)' in out2 and '(0x39)' in out2, 'bindless tex index 55/57 not in disassembly'
    assert j['ir3']['stats']['bindless_tex'] and j['ir3']['stats']['fb_read']
    rc0, out0, _ = run(V0, air('fbfetch_slots'), json_out=False)
    slots0 = re.findall(r'alias\.tex\.b32\.0 r\d+\.x, \((0x[0-9a-f]+)\)', out0)
    return f'bindless set 4 slots {[s for _, s in fb]}', (rc0, f'slots {[int(s, 16) for s in slots0]} (65 > 63: outside the 64-entry set)')

@test('attr_expr', 'binding index from function-constant expression')
def _():
    rc, out, j = run(NEW, air('attr_expr'), fcargs({0: 2, 1: 3}))
    assert rc == 0, err(out)
    assert bindings(j, 'texture') == [(3, 3)], bindings(j, 'texture')
    assert bindings(j, 'ubo') == [(6, 6)], bindings(j, 'ubo')
    rc0, out0, _ = run(V0, air('attr_expr'), fcargs({0: 2, 1: 3}), json_out=False)
    m = re.findall(r'texture\((-?\d+)\)|buffer\((-?\d+)\)', out0)
    return 'texture(3) buffer(6)', (rc0, err(out0) or 'bound ' + ', '.join(a or b for a, b in m))

@test('varying_order', 'varyings: sorted-name slots + by-name link table')
def _():
    rc, out, jv = run(NEW, air('varying_order_vs'))
    assert rc == 0, err(out)
    rc, out, jf = run(NEW, air('varying_order_fs'))
    assert rc == 0, err(out)
    vsl = jv['reflection']['varyings']; fsl = jf['reflection']['varyings']
    for lst in (vsl, fsl):   # slots follow sorted-name order, independent of declaration order
        assert [v['name'] for v in sorted(lst, key=lambda v: v['slot'])] == sorted(v['name'] for v in lst), lst
    vs = {v['name']: v for v in vsl}
    link = {}
    for f in fsl:            # BINDING-ABI.md 4: FS input <- VS output with the same name
        assert f['name'] in vs and vs[f['name']]['components'] >= f['components'], f
        link[f['name']] = (vs[f['name']]['slot'], f['slot'])
    _, ov, _ = run(V0, air('varying_order_vs'), json_out=False)
    _, of, _ = run(V0, air('varying_order_fs'), json_out=False)
    v0vs = re.findall(r'-> location (\d+)', ov); v0fs = re.findall(r'(user\(\w+\)) varying slot (\d+)', of)
    return f'link (vs_slot, fs_slot) {link}', (0, f'declaration-order slots VS {v0vs[1:]} (zz,mm,aa) FS {v0fs}; no names exported')

@test('constexpr_samplers', 'constexpr samplers inside S#0..15 (ABI v4: lowest free slots)')
def _():
    rc, out, j = run(NEW, air('constexpr_samplers'))
    assert rc == 0, err(out)
    r = j['reflection']
    cs = sorted(b['slot'] for b in r['bindings'] if b['kind'] == 'constexpr_sampler')
    assert cs == [2, 3] and r['constexpr_sampler_mask'] == '0x000c', (cs, r['constexpr_sampler_mask'])
    assert j['constant_samplers']['bitmask'] == '0x000c'
    st = j['ir3']['stats']; assert (st['ntex'], st['nsamp']) == (2, 4), st
    px = [b for b in r['bindings'] if b['kind'] == 'constexpr_sampler' and b['state']['coord'] == 'pixel']
    assert px and int(px[0]['a8xx_tex_samp'][1], 16) & 0x80000000, 'UNNORM_COORDS not set'
    rc0, out0, _ = run(V0, air('constexpr_samplers'), json_out=False)
    return f'S# {cs}, mask 0x000c, NTEX 2 NSAMP 4', (rc0, 'slots ' + str(re.findall(r'sampler slot (\d+)', out0)))

@test('fixpoint StyledDebugFill', 'instcombine<no-verify-fixpoint>')
def _():
    args = fcargs({0: 1, 1: 1, 2: 1, 3: 1, 4: 1, 5: 1})
    rc, out, j = run(NEW, corpus('SkyLight', 'StyledDebugFillFragment'), args)
    assert rc == 0, err(out)
    rc0, out0, _ = run(V0, corpus('SkyLight', 'StyledDebugFillFragment'), args, json_out=False)
    return 'ir3 %d instrs' % j['ir3']['stats']['instrs'], (rc0, err(out0))

@test('dynamic insertelement (QC PBGRA_Xgfc vertex+fragment)', 'dynamic insertelement')
def _():
    fn, args = qc_args(2, 'fragment')
    rc, out, j = run(NEW, corpus('QuartzCore', fn), args)
    assert rc == 0, err(out)
    return 'ir3 %d instrs' % j['ir3']['stats']['instrs'], (None, 'v0 has no --fc-name; prototype failed with "dynamic insertelement"')

@test('predicate RA (QC PBGRA_Xgfc fragment)', 'Mesa ir3_ra_predicates live-in merge')
def _():
    fn, args = qc_args(2, 'fragment')
    rc, out, j = run(NEW, corpus('QuartzCore', fn), args, json_out=False)
    assert rc == 0 and 'ra validation fail' not in out, err(out)
    return 'no RA validation failure', (None, 'unpatched Mesa: "ra validation fail: wrong definition reaches source"')

@test('gated buffer via normalize predicate', 'fc predicate evaluation')
def _():
    # every constant defined, no is_radius_eq_* set: is_radius_low_priority = true -> gaussianWeightBuf present
    rc, out, j = run(NEW, corpus('SkyLight', 'ShadowHorizontalBlurFragment'), fcargs({i: 0 for i in range(52)}))
    assert rc == 0, err(out)
    ubos = [(b['metal_index'], b.get('arg')) for b in j['reflection']['bindings'] if b['kind'] == 'ubo' and b['present']]
    assert (2, 'gaussianWeightBuf') in ubos, ubos
    rc, out, j = run(NEW, corpus('SkyLight', 'ShadowHorizontalBlurFragment'), fcargs({i: 0 for i in range(52)} | {6: 1}))
    ubos2 = [(b['metal_index'], b.get('arg')) for b in j['reflection']['bindings'] if b['kind'] == 'ubo' and b['present']]
    assert (2, 'gaussianWeightBuf') not in ubos2, ubos2
    return f'present UBOs {ubos} (radius 12: {ubos2})', (None, 'prototype bound every buffer')

@test('variant blob round trip', 'cache payload = Mesa ir3_store_variant')
def _():
    vb = os.path.join(SCR, 'regress.ir3v')
    rc, out, j = run(NEW, corpus('SkyLight', 'SimpleTextureFragment'), ['--variant', vb])
    assert rc == 0, err(out)
    p = subprocess.run([NEW, '--verify-variant', vb, '--stage', 'fragment'], capture_output=True, text=True)
    assert p.returncode == 0 and ('instrs %d' % j['ir3']['stats']['instrs']) in p.stdout, p.stdout + p.stderr
    return p.stdout.strip().splitlines()[-1][:80], (None, 'n/a')


# ------------------------------------------------------------------ verifier must-fix items --
def mustfix(n): return f'must-fix {n}'

@test('cache_key_fields', mustfix('1+3') + ': key = hash + stage + entry + FC + format classes')
def _():
    assert cachekey.selftest_key() == cachekey.SELFTEST, 'python self-test vector'
    keys = {}
    for args in (['--entry', 'SimpleVertex'], ['--entry', 'HorizontalBackgroundBlur'], ['--stage', 'vertex'], ['--stage', 'fragment'],
                 ['--entry', 'HorizontalBackgroundBlur', '--rt-format', '0=80'], ['--entry', 'HorizontalBackgroundBlur', '--rt-format', '0=115'],
                 ['--entry', 'HorizontalBackgroundBlur', '--rt-format', '0=554'],
                 ['--entry', 'HorizontalBackgroundBlur', '--rt-format', '0=554', '--blend', '0=1,0,0,1,5,1,5'],
                 ['--entry', 'HorizontalBackgroundBlur', '--rt-format', '1=554', '--blend', '0=1,0,0,1,5,1,5'],
                 ['--entry', 'HorizontalBackgroundBlur', '--blend', '0=1,0,0,1,5,1,5'],
                 ['--entry', 'HorizontalBackgroundBlur', '--tex-class', '0=1'],
                 ['--entry', 'HorizontalBackgroundBlur', '--tex-class', '9=1'],
                 ['--entry', 'HorizontalBackgroundBlur', '--samples', '4'],
                 ['--entry', 'HorizontalBackgroundBlur', '--safe-constlen']):
        rc, out, j = run(NEW, os.path.join(ROOT, 'build', 'templates', 'hbb_r8.air'), args)
        assert rc == 0, err(out)
        assert j['key'] == cachekey.key_of_sidecar(j), 'C key != python key for ' + ' '.join(args)
        keys[' '.join(args)] = (j['key'], j['key_inputs']['air_hash'], j['key_inputs']['stage'], j['key_inputs']['entry'])
    k = lambda a: keys[a][0]
    vs, fs = keys['--entry SimpleVertex'], keys['--entry HorizontalBackgroundBlur']
    assert vs[1] == fs[1], 'one module: the AIR hash must be shared'
    assert vs[0] != fs[0], 'vertex and fragment function of one module collide (verifier item 3)'
    assert k('--stage vertex') == vs[0] and k('--stage fragment') == fs[0], 'stage selection'
    E = '--entry HorizontalBackgroundBlur'
    assert k(E) == k(E + ' --rt-format 0=80') == k(E + ' --rt-format 0=115'), 'native formats must share the key (class 0)'
    assert k(E + ' --rt-format 0=554') != k(E), 'BGR10_XR must change the key'
    assert k(E + ' --rt-format 0=554 --blend 0=1,0,0,1,5,1,5') != k(E + ' --rt-format 0=554'), 'blend is key material for a lowered attachment'
    assert k(E + ' --blend 0=1,0,0,1,5,1,5') == k(E), 'blend of a native attachment must not change the key'
    assert k(E + ' --tex-class 0=1') != k(E), 'draw-time texture class must change the key'
    assert k(E + ' --tex-class 9=1') == k(E), 'class of a T# the function does not declare must not change the key (verify2 item 6)'
    assert k(E + ' --samples 4') == k(E), 'the raster sample count is not key material (format 3)'
    assert k(E + ' --safe-constlen') != k(E), 'safe_constlen is key material (format 3)'
    for a, kk in keys.items():   # the metadata-only key (air2ir3_cache_key) equals the compile's
        ko = subprocess.run([NEW, '--key-only'] + a.split() + [os.path.join(ROOT, 'build', 'templates', 'hbb_r8.air')], capture_output=True, text=True).stdout.split()[-1]
        assert ko == kk[0], f'--key-only {a}: {ko} != {kk[0]}'
    return f'vs/fs of hbb_r8.air: {vs[0][:8]} / {fs[0][:8]}; 80,115,none,4x,undeclared T# share; 554, blend(554), T#0 class, safe differ', (None, 'v1 key: same key for vs and fs')

@test('pipeline_keys_hit_cache', mustfix('1+3') + ': real MTLRenderPipelineDescriptors hit the swept cache')
def _():
    if not os.path.exists(os.path.join(ROOT, 'cache', 'manifest.json')): raise Skip('no cache/: run tools/sweep.py first')
    p = subprocess.run([sys.executable, os.path.join(ROOT, 'tests', 'pipelinekeys.py')], capture_output=True, text=True, timeout=900)
    last = (p.stdout.strip().splitlines() or [''])[-1]
    assert p.returncode == 0, p.stdout[-600:] + p.stderr[-400:]
    return last[:110], (None, 'v1: 0 of the fragment keys hit (formats zeroed in the sweep)')

@test('api_online_compile', mustfix(2) + ': C library, blob identical to the CLI, thread-safe')
def _():
    man = json.load(open(os.path.join(ROOT, 'build', 'templates', 'manifest.json')))
    jl = os.path.join(SCR, 'api_jobs.txt'); od = tempfile.mkdtemp(dir=SCR)
    vs = [v for v in man['variants'] if v['variant'] in ('hbb_r8', 'shb_r56_rim2_glow2', 'svbrgba_r236_rim4_glow0')]
    lines = []
    for v in vs:
        for fn in (v['entry'], 'SimpleVertex'):
            lines.append(f"{os.path.join(ROOT, v['air'])}\t{fn}\t{'vertex' if fn == 'SimpleVertex' else 'fragment'}\t80")
    open(jl, 'w').write('\n'.join(lines) + '\n')
    p = subprocess.run([os.path.join(ROOT, 'build', 'api_test'), 'list', jl, '--repeat', '2', '--threads', '6', '--out', od],
                       capture_output=True, text=True, timeout=600)
    assert p.returncode == 0, p.stdout[-500:] + p.stderr[-300:]
    for n, l in enumerate(lines):
        path, fn, st, _ = l.split('\t')
        vb = os.path.join(SCR, 'api_cli.ir3v')
        rc, out, j = run(NEW, path, ['--entry', fn, '--rt-format', '0=80', '--variant', vb])
        assert rc == 0, err(out)
        assert open(vb, 'rb').read() == open(os.path.join(od, f'{n}.ir3v'), 'rb').read(), f'job {n}: API blob != CLI blob'
        assert json.load(open(os.path.join(od, f'{n}.json')))['key'] == j['key'], f'job {n}: API key != CLI key'
    th = [l for l in p.stdout.splitlines() if l.startswith('# threads')][0]
    return f'{len(lines)} template functions: API == CLI; {th[2:60]}', (None, 'v1: no library entry point')

@test('compare_funcs', mustfix(4) + ': constexpr compare_func -> Adreno COMPARE_FUNC, all 9 values')
def _():
    # Metal ground truth on this Mac: result of sample_compare(ref) against texels [0.25, 0.75]
    gold = {}
    exe = os.path.join(OUT, 'cmpgold')
    if not os.path.exists(exe) or os.path.getmtime(exe) < os.path.getmtime(os.path.join(FIX, 'cmpgold.swift')):
        subprocess.run(['swiftc', '-O', os.path.join(FIX, 'cmpgold.swift'), '-o', exe], check=True, capture_output=True)
    for l in subprocess.run([exe], capture_output=True, text=True, check=True).stdout.splitlines():
        n, *v = l.split(); gold[n] = tuple(int(x) for x in v)
    # GL/Vulkan semantics of the Adreno COMPARE_FUNC values (adreno_compare_func): ref OP texel
    ops = {0: lambda r, t: False, 1: lambda r, t: r < t, 2: lambda r, t: r == t, 3: lambda r, t: r <= t,
           4: lambda r, t: r > t, 5: lambda r, t: r != t, 6: lambda r, t: r >= t, 7: lambda r, t: True}
    rows = []
    for name in ['none', 'less', 'less_equal', 'greater', 'greater_equal', 'equal', 'not_equal', 'always', 'never']:
        cf = '' if name == 'none' else f', compare_func::{name}'
        src = os.path.join(OUT, f'cmp_{name}.metal')
        open(src, 'w').write('#include <metal_stdlib>\nusing namespace metal;\nfragment float4 f(texture2d<float> t [[texture(0)]], float4 p [[position]]) {\n'
                             f'  constexpr sampler s(filter::linear{cf});\n  return t.sample(s, p.xy);\n}}\n')
        rc, out, j = run(NEW, air(f'cmp_{name}', src))
        assert rc == 0, err(out)
        cs = [b for b in j['reflection']['bindings'] if b['kind'] == 'constexpr_sampler'][0]
        field = (int(cs['a8xx_tex_samp'][1], 16) >> 26) & 7
        assert cs['state']['adreno_compare_func'] == field, (name, cs['state'])
        got = tuple(int(ops[field](r, t)) for r in (0.5, 0.25) for t in (0.25, 0.75))
        assert got == gold[name], f'{name}: AIR {cs["state"]["air_compare"]} -> Adreno {field} gives {got}, Metal {gold[name]}'
        rows.append(f'{name}:{cs["state"]["air_compare"]}->{field}')
    return ' '.join(rows)[:120], (None, 'v1 copied the AIR value: 5 of 7 compare functions wrong')

@test('xr_lowering', mustfix(5) + ': XR attachments/textures lowered, others refused, render == Metal')
def _():
    fs = corpus('SkyLight', 'SimpleTextureFragment')
    rc, out, j = run(NEW, fs, ['--rt-format', '0=554', '--blend', '0=1,0,0,1,5,1,5'])
    assert rc == 0, err(out)
    l = j['reflection']['rt_lowering'][0]
    assert l['class'] == 1 and l['hw_write_mask_clear'] == 'A' and not l['dual_source'], l
    rc, out, j = run(NEW, fs, ['--rt-format', '0=552', '--blend', '0=1,0,0,4,5,4,5'])
    l = j['reflection']['rt_lowering'][0]
    assert l['class'] == 2 and l['dual_source'] and l['hw_blend']['dst_rgb'] == 18 and j['ir3']['stats']['dual_src_blend'], l
    rc, out, j = run(NEW, fs, ['--rt-format', '0=552', '--blend', '0=1,0,0,1,5,1,5'])
    l = j['reflection']['rt_lowering'][0]
    assert l['blend_in_shader'] and not l['hw_blend']['enabled'] and j['ir3']['stats']['fb_read'], l
    rc, out, j = run(NEW, fs, ['--tex-class', '0=1'])
    assert rc == 0 and j['reflection']['texture_classes'] == {'0': 1}, err(out)
    refused = []
    for args in (['--rt-format', '0=550'], ['--rt-format', '0=555'], ['--rt-format', '0=508'], ['--tex-class', '0=3'],
                 ['--rt-format', '0=554', '--blend', '0=1,0,0,11,0,1,0'], ['--rt-format', '0=552', '--blend', '0=1,0,0,1,15,1,15']):
        rc, out, _ = run(NEW, fs, args, json_out=False)
        assert rc == 2 and 'UNSUPPORTED/ERROR' in out, args
        refused.append(args[1][2:] + ('+' + args[3][2:] if len(args) > 2 else ''))
    # render check against Metal: one lowered target with blending, one lowered texture
    od = os.path.join(SCR, 'xr_render'); os.makedirs(od, exist_ok=True)
    for f in os.listdir(od): os.remove(os.path.join(od, f))
    for n in ('xr554_tint_premul_over', 'xr552_tint_src_alpha', 'xr554_sample_linear', 'xr552_fbfetch_sover'):
        sc = os.path.join(ROOT, 'scenes', n + '.json')
        for tool, ext in (('mtlgold', 'metal'), ('nirexec', 'lp')):
            p = subprocess.run([os.path.join(ROOT, 'build', tool), sc, os.path.join(od, f'{n}.{ext}.bgra')], capture_output=True, text=True)
            assert p.returncode == 0, (tool, n, p.stderr[-300:])
    p = subprocess.run([sys.executable, os.path.join(ROOT, 'tools', 'compare.py'), od], capture_output=True, text=True)
    assert p.returncode == 0, p.stdout[-600:]
    cmp = json.load(open(os.path.join(od, 'compare.json')))
    return f"lowered 554/552 + tex; refused {len(refused)}; Metal max {max(r['max_abs_diff'] for r in cmp.values())} LSB", (None, 'v1: format ignored')

@test('driver_ubos', mustfix(6) + ': ir3 driver UBOs reported, bound per spec, limit enforced')
def _():
    rc, out, j = run(NEW, air('const_table'))
    assert rc == 0, err(out)
    du = j['ir3']['driver_ubos']; st = j['ir3']['stats']
    cd = [d for d in du if d['kind'] == 'constant_data']
    # ABI v6: buffer(0) constant, the driver table (device buffer(3)) at UBO 1, ir3's constant data at UBO 2
    assert cd and cd[0]['ubo'] == st['max_ubo_index'] == 2 and st['driver_table_ubo'] == 1 and cd[0]['size_vec4'] == 64, (du, st)
    rc2, out2, j2 = run(NEW, air('tg_args'))
    assert rc2 == 0, err(out2)
    dp = [d for d in j2['ir3']['driver_ubos'] if d['kind'] == 'driver_params']
    assert dp and dp[0]['struct'] == 'ir3_driver_params_cs', j2['ir3']['driver_ubos']
    rc3, out3, _ = run(NEW, air('const_table'), ['--test-abi-max-ubo', '1'], json_out=False)
    assert rc3 == 2 and 'beyond the ABI v6 limit' in out3, out3[-300:]
    return f"constant data at UBO {cd[0]['ubo']} ({cd[0]['size_vec4']} vec4), CS params UBO {dp[0]['ubo']}; limit -> error", (None, 'v1: unreported')

@test('unset_fc_semantics', 'verify3 item 1: unset constants never decide anything in the body; the rest == Metal')
def _():
    exe = os.path.join(OUT, 'fcread')
    if not os.path.exists(exe) or os.path.getmtime(exe) < os.path.getmtime(os.path.join(FIX, 'fcread.swift')):
        subprocess.run(['swiftc', '-O', os.path.join(FIX, 'fcread.swift'), '-o', exe], check=True, capture_output=True)
    cases = [f'0={a} 1={b} 2={c} 3={n}' for a in 'u01' for b in 'u01' for c in 'u01' for n in 'u0123']
    res = {}
    from concurrent.futures import ThreadPoolExecutor
    for fx in ('fcsem', 'fc2', 'fc3', 'fc4', 'fc5'):        # fc4/fc5: verify3's fixtures (select/branch/switch shapes)
        lib = os.path.join(OUT, fx + '.metallib')
        subprocess.run(['xcrun', '-sdk', 'macosx', 'metallib', air(fx), '-o', lib], check=True, capture_output=True)
        p = subprocess.run([exe, lib], input='\n'.join(cases) + '\n', capture_output=True, text=True, check=True)
        metal = {}
        for l in p.stdout.splitlines():
            m = re.match(r'(.*) -> (\[.*?\]) read (\[.*?\])', l); assert m, l
            metal[m.group(1)] = (m.group(2), m.group(3))
        def ours(c):
            a = [NEW, '--quiet', '--json', os.path.join(SCR, f'unset_{fx}_{c.replace(" ", "_").replace("=", "")}.json')]
            for t in c.split():
                if not t.endswith('=u'): a += ['--fc', t]
            q = subprocess.run(a + [air(fx)], capture_output=True, text=True)
            if q.returncode:
                assert 'unset function constant' in q.stderr + q.stdout and 'u' in c, (c, err(q.stdout + q.stderr))
                return 'refused'
            j = json.load(open(a[3])); os.remove(a[3])
            ub = [b for b in j['reflection']['bindings'] if b['kind'] == 'ubo']
            return str(sorted(b['metal_index'] for b in ub if b['present'])), str(sorted(b['metal_index'] for b in ub if b['used']))
        with ThreadPoolExecutor(12) as ex: got = dict(zip(cases, ex.map(ours, cases)))
        bad = [(c, got[c], metal[c]) for c in cases if got[c] != 'refused' and got[c] != metal[c]]
        assert not bad, f'{fx}: {len(bad)} compiled cases differ from Metal, e.g. {bad[:2]}'
        res[fx] = (sum(1 for c in cases if got[c] != 'refused'), sum(1 for c in cases if got[c] == 'refused'))
    # independence: an unset constant whose value cannot matter is accepted (and matches Metal)
    exe2 = os.path.join(OUT, 'fcrand')
    if not os.path.exists(exe2) or os.path.getmtime(exe2) < os.path.getmtime(os.path.join(FIX, 'fcrand.swift')):
        subprocess.run(['swiftc', '-O', os.path.join(FIX, 'fcrand.swift'), '-o', exe2], check=True, capture_output=True)
    lib = os.path.join(OUT, 'fc_indep.metallib')
    subprocess.run(['xcrun', '-sdk', 'macosx', 'metallib', air('fc_indep'), '-o', lib], check=True, capture_output=True)
    ind = {'0=u 1=0 2=1 3=u': 'ok', '0=u 1=1 2=1 3=u': 'refused', '0=u 1=0 2=0 3=u': 'refused', '0=u 1=u 2=1 3=u': 'refused', '0=1 1=1 2=0 3=u': 'ok'}
    p = subprocess.run([exe2], input=''.join(f'{lib}\t{c}\n' for c in ind), capture_output=True, text=True, check=True)
    mread = {}
    for l in p.stdout.splitlines():
        k, r = l.split(' -> '); x = int(struct.unpack('<f', struct.pack('<I', int(r.split(' px ')[1].split()[0], 16)))[0])
        mread[k.split('\t')[1]] = sorted(i for i in range(12) if x >> i & 1)
    for c, want in ind.items():
        a = [NEW, '--quiet', '--entry', 'f', '--json', os.path.join(SCR, 'indep.json')]
        for t in c.split():
            if not t.endswith('=u'): a += ['--fc', t]
        q = subprocess.run(a + [air('fc_indep')], capture_output=True, text=True)
        assert (q.returncode == 0) == (want == 'ok'), (c, want, err(q.stdout + q.stderr))
        if want == 'ok':
            j = json.load(open(a[5])); used = sorted(b['metal_index'] for b in j['reflection']['bindings'] if b['kind'] == 'ubo' and b['used'])
            assert used == mread[c], (c, used, mread[c])
    # the SkyLight base variants whose unset constants decide branches are refused, naming the constant
    for fn in ('StyledDebugFillFragment', 'ShadowHorizontalBlurFragment', 'ShadowCompositeFragment'):
        rc, out, j = run(NEW, corpus('SkyLight', fn))
        assert rc != 0 and re.search(r'unset function constant \w+ \(index \d+\) decides a branch', out), (fn, err(out))
    return (', '.join(f'{k} {v[0]} == Metal + {v[1]} refused' for k, v in res.items()))[:120], (None, 'fix round 2: fc4 60/135, fc5 64/135 read sets (verify3 item 1)')

@test('unset_fc_random', 'verify3 item 1: randomized differential test against Metal (tests/fcrand.py, small run)')
def _():
    p = subprocess.run([sys.executable, os.path.join(ROOT, 'tests', 'fcrand.py'), '--shaders', '40', '--cases', '12', '--seed', '7',
                        '--out', os.path.join(ROOT, 'results', 'fcrand-regress.json')],
                       capture_output=True, text=True, timeout=1800)
    assert p.returncode == 0, p.stdout[-600:]
    return p.stdout.splitlines()[0][:120], (None, 'fix round 2 rule (false side): 826/960 on the seed-1 run')

@test('threadgroup_args', mustfix(8) + ': threadgroup(n) buffers; imageblocks refused precisely')
def _():
    rc, out, j = run(NEW, air('tg_args'))
    assert rc == 0, err(out)
    tg = sorted((b['metal_index'], b['slot']) for b in j['reflection']['bindings'] if b['kind'] == 'threadgroup_buffer')
    assert tg == [(0, 256), (2, 264)], tg
    assert j['reflection']['threadgroup_bytes'] == 64, j['reflection']['threadgroup_bytes']
    rc, out, j = run(NEW, corpus('QuartzCore', 'compute_apl'))
    assert rc == 0, err(out)
    rc, out, _ = run(NEW, corpus('QuartzCore', 'blur_downsample_lpf') if os.path.exists(corpus('QuartzCore', 'blur_downsample_lpf')) else corpus('QuartzCore', IMAGEBLOCK_FN), json_out=False)
    assert rc == 2 and 'air.imageblock' in out, out[-200:]
    rc0, out0, _ = run(V0, air('tg_args'), json_out=False)
    v0 = 'threadgroup(n) bound as device buffer(n) through the VA table: silent wrong code' if 'addrspace 3 -> global' in out0 else err(out0)
    return f'tg(0)->256 tg(2)->264, static 64 B; compute_apl ok; imageblock refused', (rc0, v0)

@test('rebuild_hygiene', mustfix(9) + ': library-only Mesa targets, relative scene paths, build options in compiler_id')
def _():
    ninja = open(os.path.join(ROOT, 'tools', 'mesa-ninja.sh')).read()
    assert 'TARGETS=(' in ninja and 'libfreedreno_ir3.a' in ninja, 'mesa-ninja.sh must name library targets'
    bad = []
    for f in os.listdir(os.path.join(ROOT, 'scenes')):
        if f.endswith('.json') and re.search(r'"/', open(os.path.join(ROOT, 'scenes', f)).read()): bad.append(f)
    assert not bad, 'absolute paths in scenes: ' + ', '.join(bad)
    cid = subprocess.run([NEW, '--compiler-id'], capture_output=True, text=True).stdout.strip()
    ref = subprocess.run([sys.executable, os.path.join(ROOT, 'tools', 'compiler_id.py')], capture_output=True, text=True).stdout.strip()
    assert cid == ref and re.search(r'\+mesa-[0-9a-f]{12}-p[0-9a-f]{8}-o[0-9a-f]{8}\+llvm-', cid), (cid, ref)
    cr = os.path.join(ROOT, 'results', 'cleanroom.json')
    note = ''
    if os.path.exists(cr):
        c = json.load(open(cr)); assert c['ok'], c
        note = f"; clean-tree rebuild {c['date']}: {c['summary']}"
    return (cid + note)[:120], (None, 'v1: bare ninja fails on bison 2.3; absolute scene paths')

# ------------------------------------------------------------- verify2 must-fix items (fix2) --
@test('safe_constlen', 'verify2 item 1: pipeline const budget via ir3 safe_constlen variants (Turnip)')
def _():
    fv, av = qc_args(2, 'vertex'); ff, af = qc_args(2, 'fragment')      # CA 02_PBGRA_Xgfc
    rc, out, jv = run(NEW, corpus('QuartzCore', fv), af[:0] + av); assert rc == 0, err(out)
    rc, out, jf = run(NEW, corpus('QuartzCore', ff), af + ['--rt-format', '0=80']); assert rc == 0, err(out)
    cv, cf = jv['ir3']['const_budget'], jf['ir3']['const_budget']
    assert cv['constlen'] + cf['constlen'] > cf['max_const_pipeline'] and cf['exceeds_safe_constlen'], (cv, cf)
    t = int(subprocess.run([NEW, '--trim-constlen', f"{cv['constlen']},{cf['constlen']}"], capture_output=True, text=True).stdout.split()[-1])
    assert t == 2, f'trim mask {t}: the fragment stage must be trimmed'
    rc, out, js = run(NEW, corpus('QuartzCore', ff), af + ['--rt-format', '0=80', '--safe-constlen']); assert rc == 0, err(out)
    cs = js['ir3']['const_budget']
    assert cs['safe_constlen'] and cs['constlen'] <= cs['max_const_safe'] and js['key'] != jf['key'] and js['key'] == cachekey.key_of_sidecar(js), cs
    total = cv['constlen'] + cs['constlen']
    assert total <= cf['max_const_pipeline'], total
    return f"02_PBGRA_Xgfc: VS {cv['constlen']} + FS {cf['constlen']} = {cv['constlen'] + cf['constlen']} > 512 -> FS safe {cs['constlen']}: {total} fits", (None, 'fix round 1: no safe variant, 528 > 512')

@test('pvtmem', 'verify2 item 2: private memory in the sidecar, Turnip sizing, budget enforced')
def _():
    args = []
    for l in open(os.path.join(ROOT, 'results', 'fixed', 'shadow_structured.jsonl')) if os.path.exists(os.path.join(ROOT, 'results', 'fixed', 'shadow_structured.jsonl')) else []:
        r = json.loads(l)
        if r['id'].endswith('/r662_h0_norim_inner'):
            for k, v in r['fcname'].items(): args += ['--fc-name', f'{k}={v}']
            break
    if not args:   # the selector of that variant, if the sweep has not run (every other declared constant 0: ABI v4
                   # refuses a variant whose unset constants decide its body)
        ones = {f'is_radius_ge_{r}' for r in [3, 18, 31, 40, 52, 59, 74, 80, 87, 96, 108, 130, 152, 171, 192, 214, 236, 255, 276, 298,
                                              320, 339, 360, 410, 460, 510, 560, 612, 662]} | {'is_rim_state_inner'}
        decl = json.loads(subprocess.run([NEW, '--list-fcs', corpus('SkyLight', 'ShadowHorizontalBlurFragment')], capture_output=True, text=True).stdout)
        for d in decl['function_constants']:
            args += ['--fc-name', f"{d['name']}={1 if d['name'] in ones else 0}"]
    rc, out, j = run(NEW, corpus('SkyLight', 'ShadowHorizontalBlurFragment'), args); assert rc == 0, err(out)
    pv = j['ir3']['pvtmem']
    assert pv['pvtmem_size'] > 0 and j['ir3']['stats']['pvtmem_size'] > 0, pv
    pf = 512
    while pf < pv['pvtmem_size']: pf *= 2
    assert pv['per_fiber_size'] == pf and pv['per_sp_size'] == pf * 4096 and pv['total_size'] == 8 * pf * 4096, pv
    assert pv['total_size'] <= pv['budget'] and not pv['pvtmem_per_wave'], pv
    rc, out, _ = run(NEW, corpus('SkyLight', 'ShadowHorizontalBlurFragment'), args + ['--test-pvtmem-budget', '64'], json_out=False)
    assert rc == 2 and 'over the ABI v5 budget' in out, out[-300:]
    rc, out, j0 = run(NEW, corpus('SkyLight', 'SimpleTextureFragment')); assert j0['ir3']['pvtmem']['total_size'] == 0
    return f"ShadowHBlur r662 inner: {pv['pvtmem_size']} B/fiber -> {pv['per_fiber_size']} x 4096 x 8 = {pv['total_size'] >> 20} MiB <= {pv['budget'] >> 20}; 64 MiB budget refuses", (None, 'fix round 1: not reported')

@test('driver_ubo_declared', 'verify2 item 3: driver UBOs above every DECLARED constant buffer')
def _():
    rc, out, j = run(NEW, air('dpk'), ['--entry', 'dpk']); assert rc == 0, err(out)
    b1 = [b for b in j['reflection']['bindings'] if b['kind'] == 'ubo' and b['metal_index'] == 1]
    assert b1 and not b1[0]['used'], b1
    dp = [d for d in j['ir3']['driver_ubos'] if d['kind'] == 'driver_params']
    assert dp and dp[0]['ubo'] == 2 == j['ir3']['stats']['driver_ubo_base'], (dp, j['ir3']['stats']['driver_ubo_base'])
    rc, out, j2 = run(NEW, air('dpk'), ['--entry', 'dpk2']); assert rc == 0, err(out)
    dp2 = [d for d in j2['ir3']['driver_ubos'] if d['kind'] == 'driver_params']
    assert dp2 and dp2[0]['ubo'] == 6, dp2
    return f"dpk: buffer(1) declared, unread -> driver_params at UBO {dp[0]['ubo']} (was 1); dpk2: buffer(5) -> UBO {dp2[0]['ubo']}", (None, 'fix round 1: driver_params at UBO 1, on top of buffer(1)')

@test('online_sidecar', 'verify2 item 4: air2ir3_compile sidecar == cache entry (constant samplers in the library)')
def _():
    lines = []
    for name, args in (('constexpr_samplers', []), ('const_table', [])):
        ep = os.path.join(SCR, f'online_{name}.json')
        a = [NEW, '--quiet', '--json', ep] + args + [air(name)]
        assert subprocess.run(a, capture_output=True).returncode == 0
        e = json.load(open(ep))
        assert 'constant_samplers' in e and e['blob']['sha256'], 'sidecar lacks constant_samplers/blob'
        st = e['reflection']['stage']
        lines.append('\t'.join([air(name), e['reflection']['function'], st, ','.join('0' * 8), ';'.join(['0,0,0,1,0,1,0'] * 8),
                                ','.join('0' * 16), '0', '-', ep]))
    cs = json.load(open(os.path.join(SCR, 'online_constexpr_samplers.json')))['constant_samplers']
    assert cs['bitmask'] == '0x000c' and len(cs['samplers']) == 2 and cs['set_id'].startswith('0x'), cs
    jl = os.path.join(SCR, 'online_jobs.txt'); open(jl, 'w').write('\n'.join(lines) + '\n')
    p = subprocess.run([os.path.join(ROOT, 'build', 'api_test'), 'cached', jl], capture_output=True, text=True)
    assert p.returncode == 0, p.stdout[-400:] + p.stderr[-300:]
    return f"CLI sidecar == API sidecar byte for byte (constexpr samplers, set_id {cs['set_id']}); whole cache: tools/apitest.py", (None, 'fix round 1: constant_samplers added by sweep.py only')

@test('xr_corners', 'verify2 item 7: premultiplied over outside its precondition; dual-source with MRT')
def _():
    fx = air('fc_rt')
    rc, out, j = run(NEW, fx, fcargs({0: 0, 1: 0}) + ['--rt-format', '0=552', '--blend', '0=1,0,0,4,5,4,5']); assert rc == 0, err(out)
    l = j['reflection']['rt_lowering'][0]; assert l['dual_source'] and not l['blend_in_shader'], l
    rc, out, j = run(NEW, fx, fcargs({0: 0, 1: 1}) + ['--rt-format', '0=552', '--blend', '0=1,0,0,4,5,4,5']); assert rc == 0, err(out)
    l = j['reflection']['rt_lowering'][0]
    assert not l['dual_source'] and l['blend_in_shader'] and not j['ir3']['stats']['dual_src_blend'], l
    rc, out, j = run(NEW, fx, fcargs({0: 0, 1: 1}) + ['--rt-format', '0=552', '--blend', '0=1,0,0,1,5,1,5']); assert rc == 0, err(out)
    assert j['reflection']['rt_lowering'][0]['blend_in_shader'], j['reflection']['rt_lowering']
    od = os.path.join(SCR, 'xr_corners'); os.makedirs(od, exist_ok=True)
    for f in os.listdir(od): os.remove(os.path.join(od, f))
    for n in ('xr554_negtint_premul_over', 'xr552_negtint_premul_over', 'xr552_tint_additive', 'xr554_tint_revsub', 'xr552_tint_dst_color'):
        sc = os.path.join(ROOT, 'scenes', n + '.json')
        for tool, ext in (('mtlgold', 'metal'), ('nirexec', 'lp')):
            p = subprocess.run([os.path.join(ROOT, 'build', tool), sc, os.path.join(od, f'{n}.{ext}.bgra')], capture_output=True, text=True)
            assert p.returncode == 0, (tool, n, p.stderr[-300:])
    p = subprocess.run([sys.executable, os.path.join(ROOT, 'tools', 'compare.py'), od], capture_output=True, text=True)
    assert p.returncode == 0, p.stdout[-600:]
    cmp = json.load(open(os.path.join(od, 'compare.json')))
    return f"MRT: dual-source -> shader blend; negative tint + additive/revsub/dst-colour vs Metal max {max(r['max_abs_diff'] for r in cmp.values())} LSB", (None, 'fix round 1: 26 codes off; dual-source accepted with RT2 written')

@test('gather_info', 'A16 run 3 (item 9): num_samp / need_pixlod from nir_shader_gather_info')
def _():
    rc, out, j = run(NEW, corpus('SkyLight', 'SimpleTextureFragment'), ['--rt-format', '0=80']); assert rc == 0, err(out)
    st = j['ir3']['stats']
    assert st['num_samp'] == 1 and st['need_pixlod'], st
    rc, out2, _ = run(NEW, corpus('SkyLight', 'SimpleTextureFragment'), ['--rt-format', '0=80'], json_out=False)
    assert '(eq)(rpt5)nop' in out2, 'helper-invocation end (eq) missing from the P7 fragment shader'
    rc, out, jv = run(NEW, corpus('SkyLight', 'SimpleVertex')); assert jv['ir3']['stats']['num_samp'] == 0
    got = {}
    for e in ('split', 'readonly_tex', 'explicit_lod'):
        rc, out, j = run(NEW, air('texsamp'), ['--entry', e]); assert rc == 0, err(out)
        got[e] = (j['ir3']['stats']['num_samp'], j['ir3']['stats']['need_pixlod'])
    assert got == {'split': (6, True), 'readonly_tex': (2, False), 'explicit_lod': (1, False)}, got
    return f"SimpleTextureFragment num_samp 1 need_pixlod 1 (+ (eq)); T#2/S#5 -> 6; read -> no pixlod", (None, 'fix round 1: num_samp 0, need_pixlod 0 (P7 programmed them from reflection)')

# ------------------------------------------------------------- verify3 must-fix items (fix3) --
@test('xr_minmax', 'verify3 item 2: min/max on XR attachments: hw_blend ONE/ONE, no dual-source, blend-colour factors ignored')
def _():
    fx = air('fc_rt')
    got = {}
    for tag, fc, blend in (('min+src/blend-colour factors', {0: 0, 1: 0}, '0=1,3,4,2,3,11,12'),
                           ('max, second attachment written', {0: 0, 1: 1}, '0=1,4,3,4,5,13,14'),
                           ('max rgb + premul-over alpha', {0: 0, 1: 0}, '0=1,4,0,2,6,1,5')):
        rc, out, j = run(NEW, fx, fcargs(fc) + ['--rt-format', '0=552', '--blend', blend]); assert rc == 0, (tag, err(out))
        l = j['reflection']['rt_lowering'][0]; hb = l['hw_blend']
        got[tag] = (hb['src_rgb'], hb['dst_rgb'], hb['src_alpha'], hb['dst_alpha'], l['dual_source'], l['blend_in_shader'], hb['enabled'])
    assert got['min+src/blend-colour factors'] == (1, 1, 1, 1, False, False, True), got
    assert got['max, second attachment written'] == (1, 1, 1, 1, False, False, True), got
    assert got['max rgb + premul-over alpha'][5:] == (True, False), got    # alpha source-over -> blended in the shader, RB off
    od = os.path.join(SCR, 'xr_minmax'); os.makedirs(od, exist_ok=True)
    for f in os.listdir(od): os.remove(os.path.join(od, f))
    xs = os.path.join(ROOT, 'xrscenes')
    for n in ('v3xr552_01', 'v3xr552_25', 'v3xr554_06', 'v3xr554_40'):      # 3 min/max scenes that failed in verify3, + the subtract one
        for tool, ext in (('mtlgold', 'metal'), ('nirexec', 'lp')):
            p = subprocess.run([os.path.join(ROOT, 'build', tool), os.path.join(xs, n + '.json'), os.path.join(od, f'{n}.{ext}.bgra')],
                               capture_output=True, text=True, cwd=ROOT)
            assert p.returncode == 0, (tool, n, p.stderr[-300:])
    p = subprocess.run([sys.executable, os.path.join(ROOT, 'tools', 'compare.py'), od, '--scenes', xs], capture_output=True, text=True)
    cmp = json.load(open(os.path.join(od, 'compare.json')))
    assert p.returncode == 0, {k: v['max_abs_diff'] for k, v in cmp.items()}
    return f"hw ONE/ONE, no dual, blend colour accepted; 4 scenes max {max(r['max_abs_diff'] for r in cmp.values())} codes", (None, 'fix round 2: app factors + SRC1 + dual-source; 243-955 codes off; v3xr554_40 3 codes')

@test('descriptor_counts', 'verify3 item 3: NTEX / NSAMP exported separately; fb read not counted; constexpr in the lowest free S#')
def _():
    got = {}
    for e in ('split', 'readonly_tex', 'explicit_lod'):
        rc, out, j = run(NEW, air('texsamp'), ['--entry', e]); assert rc == 0, err(out)
        st = j['ir3']['stats']; got[e] = (st['ntex'], st['nsamp'], st['num_samp'])
    assert got == {'split': (3, 6, 6), 'readonly_tex': (2, 1, 2), 'explicit_lod': (1, 1, 1)}, got   # ABI v5: read()'s isam names s#0
    rc, out, j = run(NEW, air('fbfetch_slots')); st = j['ir3']['stats']
    assert (st['ntex'], st['nsamp']) == (0, 0) and st['num_samp'] >= 1 and st['fb_read'], st      # ir3 adds one per bindless fb read
    rc, out, j = run(NEW, corpus('SkyLight', 'SimpleTextureFragment'), ['--rt-format', '0=80']); st = j['ir3']['stats']
    assert (st['ntex'], st['nsamp'], st['num_samp']) == (1, 1, 1), st
    rc, out, j = run(NEW, corpus('SkyLight', 'ShadowCompositeFragment'), fcargs({0: 1, 1: 1, 2: 1, 3: 1})); st = j['ir3']['stats']
    cs = sorted(b['slot'] for b in j['reflection']['bindings'] if b['kind'] == 'constexpr_sampler')
    assert cs == list(range(len(cs))) and st['nsamp'] == len(cs), (cs, st['ntex'], st['nsamp'])
    return f"texsamp {got}; fb read NTEX/NSAMP 0 (ir3 num_samp {j and 'n/a'}); ShadowComposite constexpr S# {cs}", (None, 'fix round 2: one num_samp, constexpr from S#15: 16/16 per draw, 17 with a fb read')

@test('sample_shading', 'verify3 item 4: per-sample shading flag (sample_id, sample interpolation, fb fetch, XR shader blend) == Metal')
def _():
    got = {}
    for e in ('ms_sample_id', 'ms_sample_interp', 'ms_fbfetch', 'ms_plain'):
        rc, out, j = run(NEW, air('msaa_fs'), ['--entry', e]); assert rc == 0, err(out)
        ss = j['ir3']['sample_shading']; got[e] = (ss['per_sample_if_msaa'], ss['reasons'])
        assert j['ir3']['stats']['per_sample_shading_if_msaa'] == ss['per_sample_if_msaa']
    assert got == {'ms_sample_id': (True, ['sample_id']), 'ms_sample_interp': (True, ['sample_interpolation']),
                   'ms_fbfetch': (True, ['framebuffer_fetch']), 'ms_plain': (False, [])}, got
    rc, out, j = run(NEW, air('fc_rt'), fcargs({0: 0, 1: 0}) + ['--rt-format', '0=552', '--blend', '0=1,0,0,1,5,1,5']); assert rc == 0, err(out)
    assert j['ir3']['sample_shading'] == {'per_sample_if_msaa': True, 'reasons': ['xr_shader_blend'], 'ir3_sample_shading': False}, j['ir3']['sample_shading']
    rc, out, j = run(NEW, corpus('SkyLight', 'SimpleTextureFragment'), ['--rt-format', '0=80'])
    assert not j['ir3']['sample_shading']['per_sample_if_msaa']
    exe = os.path.join(OUT, 'msaa_probe')
    if not os.path.exists(exe) or os.path.getmtime(exe) < os.path.getmtime(os.path.join(FIX, 'msaa_probe.swift')):
        subprocess.run(['swiftc', '-O', os.path.join(FIX, 'msaa_probe.swift'), '-o', exe], check=True, capture_output=True)
    m = dict(l.split()[:2] for l in subprocess.run([exe], capture_output=True, text=True, check=True).stdout.splitlines())
    assert m == {'fbfetch': 'per_sample', 'plain': 'per_pixel', 'sample_interp': 'per_sample', 'center_interp': 'per_pixel'}, m
    return 'flags == Metal 4x MSAA probe (fb fetch per sample, plain per pixel); XR shader blend flagged', (None, 'fix round 2: no flag; ir3 sample_shading false for all')

# ------------------------------------------------------------- verify4 must-fix items (fix4) --
MIN = os.path.join(FIX, 'unset_min')
def fcrand_exe():
    exe = os.path.join(OUT, 'fcrand')
    if not os.path.exists(exe) or os.path.getmtime(exe) < os.path.getmtime(os.path.join(FIX, 'fcrand.swift')):
        subprocess.run(['swiftc', '-O', os.path.join(FIX, 'fcrand.swift'), '-o', exe], check=True, capture_output=True)
    return exe
def metal_present_read(lib, cases):
    """Metal on this Mac: {case: (present buffer indices, buffers read)} (tests/fixtures/fcrand.swift; buffer k
    holds float4(2^k, 0, 0, 1), the red channel of the rendered pixel is the read set)"""
    p = subprocess.run([fcrand_exe()], input=''.join(f'{lib}\t{c}\n' for c in cases), capture_output=True, text=True, check=True)
    r = {}
    for l in p.stdout.splitlines():
        k, v = l.split(' -> '); assert not v.startswith('ERR'), l
        pres = json.loads(v.split(' px ')[0]); x = int(struct.unpack('<f', struct.pack('<I', int(v.split(' px ')[1].split()[0], 16)))[0])
        r[k.split('\t')[1]] = (sorted(pres), sorted(i for i in range(12) if x >> i & 1))
    return r
def ours_present_read(airp, case, entry='f'):
    jp = os.path.join(SCR, 'v4_' + os.path.basename(airp) + '_' + case.replace(' ', '_').replace('=', '') + '.json')
    a = [NEW, '--quiet', '--entry', entry, '--json', jp]
    for t in case.split():
        if not t.endswith('=u'): a += ['--fc', t]
    q = subprocess.run(a + [airp], capture_output=True, text=True)
    if q.returncode: return ('refused', (q.stdout + q.stderr).strip().splitlines()[-1])
    j = json.load(open(jp)); os.remove(jp)
    ub = [b for b in j['reflection']['bindings'] if b['kind'] == 'ubo']
    return (sorted(b['metal_index'] for b in ub if b['present']), sorted(b['metal_index'] for b in ub if b['used']))
def min_fixture(n):
    a = air('unset_min_' + n, os.path.join(MIN, n + '.metal'))
    lib = os.path.join(OUT, 'unset_min_' + n + '.metallib')
    subprocess.run(['xcrun', '-sdk', 'macosx', 'metallib', a, '-o', lib], check=True, capture_output=True)
    return a, lib

@test('unset_fc_proof', 'verify4 item 1: an unset number constant folds only when provably value-independent (m0..m6, fcv4)')
def _():
    from concurrent.futures import ThreadPoolExecutor
    cases = [f'0={a} 1={b} 2={c} 3={n}' for a in '01' for b in '01' for c in '01' for n in ('u', '4', '0', '7', '-5')]
    tot = dict(match=0, refused=0)
    for i in range(7):
        a, lib = min_fixture(f'm{i}')
        metal = metal_present_read(lib, cases)
        with ThreadPoolExecutor(12) as ex: got = dict(zip(cases, ex.map(lambda c: ours_present_read(a, c), cases)))
        for c in cases:
            if got[c][0] == 'refused':
                assert '3=u' in c and 'unset function constant N' in got[c][1], (f'm{i}', c, got[c][1][:160])
                tot['refused'] += 1
            else:
                assert '3=u' not in c, (f'm{i}', c, 'compiled with N unset', got[c], metal[c])    # N decides a value in every m*
                assert got[c] == metal[c], (f'm{i}', c, got[c], metal[c]); tot['match'] += 1
    # the proof rule itself: independent uses still fold (fc_indep, unset_fc_semantics) and ranges are exact
    m = err(run(NEW, air('fc_indep'), ['--entry', 'f', '--fc', '1=0', '--fc', '2=1'])[1])
    assert not m, m
    # verify4's randomized run (tests/fcv4.py, generator unchanged): hole mode, seed 41 = 60 shaders x 6 cases
    p = subprocess.run([sys.executable, os.path.join(ROOT, 'tests', 'fcv4.py'), '--mode', 'hole', '--seed', '41', '--shaders', '60', '--cases', '6',
                        '--out', os.path.join(ROOT, 'results', 'fcv4-regress-hole-41.json')], capture_output=True, text=True, timeout=1800)
    assert p.returncode == 0, p.stdout[-600:]
    st = json.loads([l for l in p.stdout.splitlines() if l.startswith('{')][0].replace("'", '"'))
    return (f"m0..m6: {tot['match']} == Metal, {tot['refused']} refused (every N-unset case); fcv4 hole-41: {st['match']} match, "
            f"{st['refused']} refused, 0 mismatches"), (None, 'fix round 3: m0..m6 all compiled with N unset, all 7 read sets != Metal; fcv4 hole-41 32 read mismatches')

@test('presence_predicates', 'verify4 item 2: a gating predicate on an unset constant: direct (absent) or value-independent, else refused')
def _():
    cases = ['0=u 1=0 2=0 3=2'] + [f'0={a} 1={b} 2={c} 3={n}' for a in 'u01' for b in 'u01' for c in '0' for n in ('u', '0', '1', '2', '3')]
    want = {'p0': 'refused', 'p1': 'refused', 'p2': 'absent', 'p3': 'absent'}          # the verify4 case: only A unset
    tot = dict(match=0, refused=0)
    from concurrent.futures import ThreadPoolExecutor
    for n, w in want.items():
        a, lib = min_fixture(n)
        metal = metal_present_read(lib, cases)
        with ThreadPoolExecutor(12) as ex: got = dict(zip(cases, ex.map(lambda c: ours_present_read(a, c), cases)))
        g0 = got['0=u 1=0 2=0 3=2']
        if w == 'refused': assert g0[0] == 'refused' and 'presence predicate' in g0[1], (n, g0)
        else: assert g0 != 'refused' and 10 not in g0[0] and g0 == metal['0=u 1=0 2=0 3=2'], (n, g0, metal['0=u 1=0 2=0 3=2'])
        for c in cases:
            if got[c][0] == 'refused':
                assert 'u' in c and 'unset function constant' in got[c][1], (n, c, got[c][1][:160]); tot['refused'] += 1
            else: assert got[c] == metal[c], (n, c, got[c], metal[c]); tot['match'] += 1
    # a COLOUR OUTPUT gated by such a predicate: not written, valid only without that attachment (CA 02_PBGRA_Xgfc,
    # [[color(1)]]/[[color(2)]] gated by frg_has_color1/2 on fc_dest_index, unset in CA's pipeline, one attachment)
    fn, args = qc_args(2, 'fragment')
    rc, out, j = run(NEW, corpus('QuartzCore', fn), args + ['--rt-format', '0=80']); assert rc == 0, err(out)
    rna = j['reflection']['requires_no_attachment']; assert rna == [1, 2], rna
    assert [r['index'] for r in j['reflection']['render_targets'] if r['written']] == [0], j['reflection']['render_targets']
    rc, out, _ = run(NEW, corpus('QuartzCore', fn), args + ['--rt-format', '0=80', '--rt-format', '1=552'])
    assert rc != 0 and 'presence predicate' in out and 'XR attachment' in out, err(out)
    # verify4's randomized predicate run (tests/fcv4.py --mode pred, seed 43 = 60 shaders x 6 cases): refuse or match
    p = subprocess.run([sys.executable, os.path.join(ROOT, 'tests', 'fcv4.py'), '--mode', 'pred', '--seed', '43', '--shaders', '60', '--cases', '6',
                        '--out', os.path.join(ROOT, 'results', 'fcv4-regress-pred-43.json')], capture_output=True, text=True, timeout=1800)
    assert p.returncode == 0, p.stdout[-600:]
    st = json.loads([l for l in p.stdout.splitlines() if l.startswith('{')][0].replace("'", '"'))
    return (f"p0/p1 refused, p2/p3 absent == Metal; CA 02 FS requires no attachment 1, 2; {tot['match']} == Metal + {tot['refused']} refused; fcv4 pred-43 {st['match']} match "
            f"+ {st['refused']} refused"), (None, 'fix round 3: p0 (fcrand seed 23 shader 38) compiled absent, Metal present')

@test('xr_alpha_clamp', 'verify4 item 3: XR shader/RB blending with source alpha outside [0, 1] == Metal (alpha factor clamped)')
def _():
    od = os.path.join(SCR, 'xr_alpha'); os.makedirs(od, exist_ok=True)
    for f in os.listdir(od): os.remove(os.path.join(od, f))
    xs = os.path.join(ROOT, 'xrscenes')
    names = sorted(f[:-5] for f in os.listdir(xs) if f.startswith('a55') and f.endswith('.json')) + ['v4xr552_09']
    assert len(names) == 21, names
    from concurrent.futures import ThreadPoolExecutor
    def one(n):
        for tool, ext in (('mtlgold', 'metal'), ('nirexec', 'lp')):
            p = subprocess.run([os.path.join(ROOT, 'build', tool), os.path.join(xs, n + '.json'), os.path.join(od, f'{n}.{ext}.bgra'), '--frames', '3'],
                               capture_output=True, text=True, cwd=ROOT)
            assert p.returncode == 0, (tool, n, p.stderr[-300:])
    with ThreadPoolExecutor(8) as ex: list(ex.map(one, names))
    p = subprocess.run([sys.executable, os.path.join(ROOT, 'tools', 'compare.py'), od, '--scenes', xs], capture_output=True, text=True)
    cmp = json.load(open(os.path.join(od, 'compare.json')))
    assert p.returncode == 0 and len(cmp) == 21, {k: v['max_abs_diff'] for k, v in cmp.items() if v['status'] != 'PASS'}
    hi = [n for n in names if any(not 0 <= b['floats'][3] <= 1 for b in json.load(open(os.path.join(xs, n + '.json')))['buffers'].get('fragment', []))]
    return f"21 scenes ({len(hi)} with source alpha > 1) max {max(r['max_abs_diff'] for r in cmp.values())} XR10 codes", (None, 'fix round 3: alpha 1.2 premul-over 117, source-over (552) 102, subtract 104/224, v4xr552_09 38 codes')

@test('nsamp_every_tex', 'verify4 item 4: NSAMP >= 1 + the s# of every texture instruction (isam included), == disassembly')
def _():
    rx = re.compile(r'\b(s|t)#(\d+)')
    def check(path, args):
        rc, out, j = run(NEW, path, list(args)); assert rc == 0, (path, args, err(out))
        mt = ms = -1
        for line in out.splitlines():
            for k, n in rx.findall(line):
                if k == 't': mt = max(mt, int(n))
                else: ms = max(ms, int(n))
        st = j['ir3']['stats']
        assert st['ntex'] >= mt + 1 and st['nsamp'] >= ms + 1, (path, args, st['ntex'], st['nsamp'], mt, ms)
        return st['ntex'], st['nsamp'], mt + 1, ms + 1
    got = {}
    d = air('desc_counts')
    for e, a in (('d_unused_api', ()), ('d_gated_api', ('--fc', '0=0')), ('d_mixed', ()), ('d_hi', ()), ('d_read', ()), ('d_fb_and_tex', ()), ('d_vs', ())):
        got[e] = check(d, ('--entry', e) + a)
    assert got['d_read'] == (6, 1, 6, 1), got['d_read']                                   # texture(5).read(): isam t#5 s#0
    ro = ('compute_apl', 'compute_average_luma', 'dynamic_system_ootf_decimate', 'read_surf_frag', 'read_surf_frag_rg_uint',
          'read_write_surf_compute', 'sdf_gen_field_lpf', 'sdf_gen_field_lph', 'sdf_gen_gradients_lpf', 'sdf_gen_gradients_lph')
    for fn in ro:
        got[fn] = check(corpus('QuartzCore', fn), ())
        assert got[fn][1] == got[fn][3] == 1, (fn, got[fn])                                  # no sampler: exactly the isam's s#0
    return f"7 probes + the 10 read()-only QuartzCore functions: NSAMP >= 1 + max s# (read-only: {sorted(set(got[f][1] for f in ro))})", (None, 'fix round 3: the 10 read()-only variants reported nsamp 0 while their isam names s#0')

@test('ubo_slots_16', 'q1n1 A16 render run 1: a load from UBO 31 read zeros (CB0 fault at VA 0); every UBO index < 16')
def _():
    # CoreDisplay ViewportToNDC (device buffers 0..2, no constant buffer): the table was UBO 31 (32 descriptors)
    rc, out, j = run(NEW, corpus('CoreDisplay', 'ViewportToNDC'), ['--stage', 'vertex']); assert rc == 0, err(out)
    st = j['ir3']['stats']
    dt = {b['driver_table_ubo'] for b in j['reflection']['bindings'] if b['kind'] == 'device_buffer'}
    assert st['driver_table_ubo'] == 0 and dt == {0} and st['max_ubo_index'] == 0 and st['num_app_ubos'] == 1 and st['ubo_slots'] == 16, (st, dt)
    vb = os.path.join(SCR, 'ubo_slots.ir3v')
    subprocess.run([NEW, '--quiet', '--stage', 'vertex', '--variant', vb, corpus('CoreDisplay', 'ViewportToNDC')], check=True)
    dis = subprocess.run([NEW, '--verify-variant', vb], capture_output=True, text=True).stdout
    ldc = re.findall(r'ldc\.[^\n]*?, (\d+)\n', dis)
    assert ldc and set(ldc) == {'0'}, ldc
    # constant buffer(2) + device buffer(9): table at 3
    rc, out, j = run(NEW, air('ubo_slots'), ['--entry', 'table_low']); assert rc == 0, err(out)
    assert j['ir3']['stats']['driver_table_ubo'] == 3 and j['ir3']['stats']['max_ubo_index'] == 3, j['ir3']['stats']
    # refusals: constant buffer(16); constant buffer(15) with a device buffer (the table would be 16)
    rc1, out1, _ = run(NEW, air('ubo_slots'), ['--entry', 'const_hi'], json_out=False)
    assert rc1 == 2 and 'a8xx honours only UBO 0..15' in out1, out1[-300:]
    rc2, out2, _ = run(NEW, air('ubo_slots'), ['--entry', 'table_no_room'], json_out=False)
    assert rc2 == 2 and 'the driver table would be UBO 16' in out2, out2[-300:]
    # the probe-only option accepts them and says so in the sidecar
    rc3, out3, j3 = run(NEW, air('ubo_slots'), ['--entry', 'const_hi', '--test-ubo-slots', '32']); assert rc3 == 0, err(out3)
    assert j3['ir3']['stats']['ubo_slots'] == 32 and j3['ir3']['stats']['max_ubo_index'] == 16, j3['ir3']['stats']
    rc0, out0, _ = run(V0, corpus('CoreDisplay', 'ViewportToNDC'), json_out=False)
    return f"ViewportToNDC: table UBO 0 (was 31), 1 descriptor (was 32); buffer(2)+device -> 3; buffer(16) and no-room refused", (rc0, 'ABI v5: driver table at UBO 31, which a8xx does not honour')

@test('unsetdiff_skip', 'verify4 item 5: tools/unsetdiff.py prints SKIP when its baseline is missing (clean room)')
def _():
    jp = os.path.join(SCR, 'unsetdiff-skip.json')
    p = subprocess.run([sys.executable, os.path.join(ROOT, 'tools', 'unsetdiff.py'), '--old', os.path.join(SCR, 'no-such-baseline'), '--out', jp],
                       capture_output=True, text=True)
    assert p.returncode == 0 and p.stdout.startswith('SKIP: '), p.stdout + p.stderr
    j = json.load(open(jp)); assert 'skipped' in j, j
    return p.stdout.strip()[:100], (None, 'fix round 3: printed nothing (tools/cleanroom.sh now also checks the three diff tools)')

# ------------------------------------------------------------- verify5 must-fix items (fix5) --
V5 = os.path.join(FIX, 'v5')
def fcv5_exe():
    exe = os.path.join(OUT, 'fcv5metal'); src = os.path.join(FIX, 'fcv5.swift')
    if not os.path.exists(exe) or os.path.getmtime(exe) < os.path.getmtime(src):
        subprocess.run(['swiftc', '-O', src, '-o', exe], check=True, capture_output=True)
    return exe
def v5_fixture(n, d=None, pre='v5_'):
    a = air(pre + n, os.path.join(d or V5, n + '.metal'))
    lib = os.path.join(OUT, pre + n + '.metallib')
    if not os.path.exists(lib) or os.path.getmtime(lib) < os.path.getmtime(a):
        subprocess.run(['xcrun', '-sdk', 'macosx', 'metallib', a, '-o', lib], check=True, capture_output=True)
    return a, lib
def f32(h): return struct.unpack('<f', struct.pack('<I', int(h, 16)))[0]
def metal5(lib, cases):
    """Metal on this Mac (tests/fixtures/fcv5.swift, verify5's harness: 12 constant types by index):
    {case: 'ERR' | (present buffer indices, pixel)}"""
    p = subprocess.run([fcv5_exe()], input=''.join(f'{lib}\t{c}\n' for c in cases), capture_output=True, text=True, check=True)
    r = {}
    for l in p.stdout.splitlines():
        k, v = l.split(' -> ', 1); c = k.split('\t')[1]
        if v.startswith('ERR'): r[c] = 'ERR'; continue
        pr, px = v.split(' px '); r[c] = (json.loads(pr), [f32(h) for h in px.split()])
    return r
def sidecar(path):
    # cache format 5 (fix round 6): the sidecar is valid JSON for every constant value (NaN / inf are strings)
    return json.load(open(path))
def ours5(airp, case, pixel=True):
    """our side: ('refused', message) | (present buffer indices, llvmpipe pixel or None)"""
    tag = re.sub(r'[^0-9a-z_.-]', '', case.replace(' ', '_'))
    jp = os.path.join(SCR, f'v5_{os.path.basename(airp)}_{tag}.json')
    fc = {t.split('=')[0]: t.split('=')[1] for t in case.split() if not t.endswith('=u')}
    q = subprocess.run([NEW, '--quiet', '--entry', 'f', '--json', jp] + fcargs(fc) + [airp], capture_output=True, text=True)
    if q.returncode: return ('refused', (q.stdout + q.stderr).strip().splitlines()[-1])
    j = sidecar(jp); os.remove(jp)
    pres = sorted(b['metal_index'] for b in j['reflection']['bindings'] if b['kind'] == 'ubo' and b['present'])
    if not pixel: return (pres, None)
    import math
    fcn = {k: (float(v) if math.isfinite(float(v)) else v) for k, v in fc.items()}   # nirexec reads "nan" / "-inf" strings (fix round 6)
    sc = dict(name='v5', width=1, height=1, frames=1, format='rgba32f', clear=[0, 0, 0, 0],
              vs=dict(bc=airp, entry='v', function='v', fc=fcn), fs=dict(bc=airp, entry='f', function='f', fc=fcn),
              vertex=dict(stride=0, data=dict(floats=[]), count=3, primitive='triangle', attributes=[]),
              buffers=dict(fragment=[dict(index=k, floats=[float(1 << k), 0.5, 0.25, 1] + [0.0] * 12) for k in range(16)]), rt=dict(format='rgba32f'))
    sp, op = jp[:-5] + '.scene.json', jp[:-5] + '.f32'
    json.dump(sc, open(sp, 'w'))
    r = subprocess.run([os.path.join(ROOT, 'build', 'nirexec'), sp, op, '--frames', '1'], capture_output=True, text=True)
    assert r.returncode == 0, (airp, case, r.stderr[-300:])
    px = list(struct.unpack('<4f', open(op, 'rb').read()[:16])); os.remove(sp); os.remove(op)
    return (pres, px)
def v5_compare(n, cases, pixel=True, allowed=(), d=None, pre='v5_'):
    """every case: ours == Metal, or refused with one of the `allowed` message fragments; returns counts"""
    from concurrent.futures import ThreadPoolExecutor
    a, lib = v5_fixture(n, d, pre)
    metal = metal5(lib, cases)
    with ThreadPoolExecutor(12) as ex: got = dict(zip(cases, ex.map(lambda c: ours5(a, c, pixel), cases)))
    st = dict(match=0, refused=0, both_refuse=0); why = {}
    for c in cases:
        m, o = metal[c], got[c]
        if o[0] == 'refused':
            assert any(x in o[1] for x in allowed), (n, c, o[1][:220], m)
            st['refused'] += 1; st['both_refuse'] += m == 'ERR'; why[c] = o[1]
            continue
        assert m != 'ERR', (n, c, 'Metal rejects the pipeline, we compiled it', o)
        assert o[0] == m[0], (n, c, 'present', o[0], m[0])
        if pixel: assert all(abs(x - y) <= 1e-5 * max(1, abs(y)) for x, y in zip(o[1], m[1])), (n, c, 'pixel', o[1], m[1])
        st['match'] += 1
    return st, got, metal, why

@test('xr_srccolor_rgb', 'verify5 item 1: source colour (2, 3) as an RGB factor on XR: shader blend (the RB clamps SRC1 to [0, 1])')
def _():
    fx = air('fc_rt')
    got = {}
    for tag, fmt, blend in (('554 (sc, 1-sc)', '554', '0=1,0,0,2,3,1,0'), ('552 (0, sc)', '552', '0=1,0,0,0,2,1,0'),
                            ('554 (0, 1-sc)', '554', '0=1,0,0,0,3,1,0'), ('552 (1-sc, sc)', '552', '0=1,0,0,3,2,1,0'),
                            ('552 rgb (sa, 1-sa), alpha (sc, 1-sc)', '552', '0=1,0,0,4,5,2,3')):
        rc, out, j = run(NEW, fx, fcargs({0: 0, 1: 0}) + ['--rt-format', '0=' + fmt, '--blend', blend]); assert rc == 0, (tag, err(out))
        l = j['reflection']['rt_lowering'][0]; got[tag] = (l['blend_in_shader'], l['dual_source'])
    assert all(v == (True, False) for k, v in got.items() if 'alpha (sc' not in k), got       # shader path, RB off
    assert got['552 rgb (sa, 1-sa), alpha (sc, 1-sc)'] == (False, True), got                   # source colour on ALPHA reads the (clamped) alpha: RB
    od = os.path.join(SCR, 'xr_srccolor'); os.makedirs(od, exist_ok=True)
    for f in os.listdir(od): os.remove(os.path.join(od, f))
    xs = os.path.join(ROOT, 'xrscenes')
    names = sorted(f[:-5] for f in os.listdir(xs) if f.startswith('v5') and f.endswith('.json'))
    assert len(names) == 37, names                                                             # verify5's p000..p035 + r554_204
    from concurrent.futures import ThreadPoolExecutor
    def one(n):
        for tool, ext in (('mtlgold', 'metal'), ('nirexec', 'lp')):
            p = subprocess.run([os.path.join(ROOT, 'build', tool), os.path.join(xs, n + '.json'), os.path.join(od, f'{n}.{ext}.bgra'), '--frames', '3'],
                               capture_output=True, text=True, cwd=ROOT)
            assert p.returncode == 0, (tool, n, p.stderr[-300:])
    with ThreadPoolExecutor(8) as ex: list(ex.map(one, names))
    p = subprocess.run([sys.executable, os.path.join(ROOT, 'tools', 'compare.py'), od, '--scenes', xs], capture_output=True, text=True)
    cmp = json.load(open(os.path.join(od, 'compare.json')))
    assert p.returncode == 0 and len(cmp) == 37, {k: v['max_abs_diff'] for k, v in cmp.items() if v['status'] != 'PASS'}
    return (f"4 RGB source-colour states -> shader blend; 37 verify5 scenes max {max(r['max_abs_diff'] for r in cmp.values())} XR10 codes"), \
           (None, 'fix round 4: RB + dual-source; 17 of the 37 scenes 76..342 codes off (colour outside [0, 1])')

@test('conv_predicates', 'verify5 item 2: presence predicates through AIR conversions: folded (all set), refused when unknown, never "present if used"')
def _():
    tot = dict(match=0, refused=0)
    # verify5's fixtures, every constant set (F: float 4, H: half 10, N: int 3)
    fv, hv = ['0', '2', '0.25', '-7.5', '2.9', '-0.5', '1'], ['0', '1.5', '-2', '65504', '1']
    for n, cases in (('conv_pred_allset', [f'4={f} 10={h}' for f in fv for h in hv]),
                     ('conv_pred_allset2', [f'3={k} 4={f} 10={h}' for k in ('0', '4', '100', '-1') for f in fv for h in hv[:3]])):
        st, got, metal, why = v5_compare(n, cases, allowed=('does not fold',))
        for c in why: assert 'air.convert.' in why[c] and ('-7.5' in c or '65504' in c), (n, c, why[c][:200])   # uint(-7.5), short(65504.0): poison
        tot['match'] += st['match']; tot['refused'] += st['refused']
    # the verify5 example: F = 0 -> Metal []; fix round 4 gave [0, 1, 3] (present if used)
    a, _ = v5_fixture('conv_pred_allset'); assert ours5(a, '4=0 10=0')[0] == [], ours5(a, '4=0 10=0')
    # Metal's conversion folding at the edges (NaN, inf, out of range: poison -> refused; -0.5 -> 0; bool(NaN) true)
    edge = [f'4={f} 10={h}' for f in ('nan', 'inf', '-inf', '1e10', '-7.5', '-0.5', '2.9', '0', '3e9', '300') for h in ('nan', '1e5', '0', '-0.5', '1.5')]
    st, got, metal, why = v5_compare('convprobe', edge, pixel=False, allowed=('does not fold',))
    assert st['match'] >= 5 and got['4=-0.5 10=-0.5'][0] != 'refused', (st, got['4=-0.5 10=-0.5'])
    tot['match'] += st['match']; tot['refused'] += st['refused']
    return (f"{tot['match']} all-set cases == Metal (present + pixel), {tot['refused']} refused (NaN / out-of-range conversion: poison in Metal)"), \
           (None, 'fix round 4: present if used, e.g. F = 0: ours [0, 1, 3], Metal []')

@test('pun_constants', 'verify5 item 3: a float constant loaded as an integer (isnan in a static initialiser) is reinterpreted, not converted')
def _():
    st, got, metal, why = v5_compare('pun_ctor_isnan', [f'1={b} 4={f}' for b in ('0', '1', 'u') for f in ('-7.5', '2', '0', '-0.5', '0.25', 'u')],
                                     allowed=('unset function constant',))
    assert got['1=0 4=-7.5'] == ([0], [1.0, 0.0, 0.0, 0.0]), got['1=0 4=-7.5']                 # verify5: ours [0, 2] px 5.0
    assert got['1=u 4=-7.5'][0] == 'refused', got['1=u 4=-7.5']                                 # B decides the body; bug 3 let it compile
    s2, got2, _, _ = v5_compare('pun_body_ok', [f'4={f} 10={h}' for f in ('-7.5', '2', '0', '0.25') for h in ('-2', '65504', '1.5', '0')])
    return f"pun_ctor_isnan {st['match']} == Metal + {st['refused']} refused (B or F unset); pun_body_ok {s2['match']}/16 == Metal", \
           (None, 'fix round 4: B = 0, F = -7.5: buffer(2) present and read, pixel 5.0 (Metal 1.0)')

@test('ctor_air_calls', 'verify5 minors: AIR conversions of set constants no longer force a refusal; [[color(0), index(1)]] named as such')
def _():
    cases = [f'0=u 3={k} 4={f} 10={h}' for k in ('4', '100') for f in ('2', '0.25') for h in ('1', '1.5', '-2')] + ['0=1 3=4 4=2 10=1', '0=0 3=100 4=0.25 10=1.5']
    st, got, metal, why = v5_compare('ctor_conv_set', cases, allowed=('unset function constant',))
    assert st['match'] >= 6, (st, why)                                                           # fix round 4 refused every A-unset case
    # Metal itself rejects a static initialiser that calls popcount / clamp / floor / abs / clz: so do we
    s2, _, m2, _ = v5_compare('ctor_helpers', ['0=1 3=7 4=2 10=1.5', '0=u 3=7 4=2 10=1.5'], allowed=('does not decide', 'does not fold'))
    assert s2['both_refuse'] == 2, (s2, m2)
    # a gated dual-source output: the warning names [[color(0), index(1)]]; an active one is refused (it collided with colour 0)
    a = air('v5_rna', os.path.join(V5, 'rna.metal'))
    rc, out, j = run(NEW, a, ['--entry', 'out_dual']); assert rc == 0, err(out)
    w = j['reflection']['warnings']; assert j['reflection']['requires_no_attachment'] == [0] and any('[[color(0), index(1)]]' in x for x in w), w
    rc, out, _ = run(NEW, a, ['--entry', 'out_dual', '--fc', '0=1']); assert rc != 0 and 'dual-source' in out, err(out)
    return (f"ctor_conv_set {st['match']} == Metal with A unset (+{st['refused']} refused on A); helpers refused as Metal does; dual-source output named / refused"), \
           (None, 'fix round 4: every A-unset case refused (call in the static initialiser); warning said [[color(0)]]; index(1) stored over colour 0')

# ------------------------------------------------------------- verify6 must-fix items (fix6) --
V6 = os.path.join(FIX, 'v6')
def v6_compare(n, cases, pixel=True, allowed=()):
    return v5_compare(n, cases, pixel, allowed, V6, 'v6_')
def v6_cases(n):
    return [l.strip() for l in open(os.path.join(V6, n + '.cases')) if l.strip()]

@test('sidecar_exact_values', 'verify6 item 2: function_constants exact in the declared type, valid JSON, the key recomputes (cache format 5)')
def _():
    a = air('v6_sidecar_values6', os.path.join(V6, 'sidecar_values6.metal'))
    # case -> {index: expected value list, expected bits (float / half) or None}
    exp = {
        '9=4294967295 3=-2147483648 4=nan 10=-inf 8=-128 5=65535 0=1 12=-0.0,0.1': {9: ([4294967295], None), 3: ([-2147483648], None),
            4: (['nan'], ['0x7fc00000']), 10: (['-inf'], ['0xfc00']), 8: ([-128], None), 5: ([65535], None), 0: ([1], None),
            12: ([-0.0, 0.1], ['0x80000000', '0x3dcccccd'])},
        '9=3000000001 3=2147483647 4=-0.0 10=65504 8=127 5=0 0=0 12=inf,1e-45': {9: ([3000000001], None), 3: ([2147483647], None),
            4: ([-0.0], ['0x80000000']), 10: ([65504.0], ['0x7bff']), 12: (['inf', 1e-45], ['0x7f800000', '0x00000001'])},
        '9=-1 3=4294967295 4=0.1 10=0.1 8=200 5=-1 0=2 12=3.4028234663852886e+38,-nan': {9: ([4294967295], None), 3: ([-1], None),
            4: ([0.1], ['0x3dcccccd']), 10: ([0.099975586], ['0x2e66']), 8: ([-56], None), 5: ([65535], None), 0: ([1], None),
            12: ([3.4028235e+38, '-nan'], ['0x7f7fffff', '0xffc00000'])},
    }
    def same(x, y):
        if isinstance(y, str): return x == y
        if type(x) is not type(y): return False
        return x == y and (not isinstance(y, float) or (x == 0) <= (str(x)[0] == str(y)[0]))   # -0.0 keeps its sign
    for c, want in exp.items():
        args = []
        for t in c.split(): args += ['--fc', t]
        rc, out, j = run(NEW, a, ['--entry', 'f'] + args); assert rc == 0, (c, err(out))
        t = open(os.path.join(SCR, 'regress.json')).read()
        json.loads(t, parse_constant=lambda x: (_ for _ in ()).throw(ValueError('not JSON: ' + x)))   # strict: no NaN / Infinity literals
        assert cachekey.key_of_sidecar(j) == j['key'], (c, 'key does not recompute from the sidecar')
        fcs = {f['index']: f for f in j['reflection']['function_constants']}
        for i, (v, b) in want.items():
            f = fcs[i]; got = f['value']
            assert len(got) == len(v) and all(same(x, y) for x, y in zip(got, v)), (c, i, got, v)
            assert f.get('bits') == b, (c, i, f.get('bits'), b)
            if b:   # the decimal reads back to the same bits
                fmt = '<f' if f['type'].startswith('float') else '<e'
                for x, bb in zip(got, b):
                    if isinstance(x, str) and 'nan' in x: continue
                    assert struct.pack(fmt, float(x)) == struct.pack('<I' if fmt == '<f' else '<H', int(bb, 16)), (c, i, x, bb)
    # the verify6 checker (7 cases, sidecar_values.metal)
    p = subprocess.run([sys.executable, os.path.join(V6, 'sidecar_check.py')], capture_output=True, text=True)
    assert p.returncode == 0 and 'sidecar_check: 0 bad of 7' in p.stdout, p.stdout[-600:] + p.stderr[-300:]
    return 'uint 2^32-1, int -2^31, NaN / -inf / -0 / 0.1 (bits), half, char, bool 2 -> 1, float2: exact, strict JSON, key recomputes; sidecar_check 7/7', \
           (None, 'format 4: %.9g, so 4.2949673e+09, -2.14748365e+09, bare nan / inf, -0 read as +0: 6 of 7 cases bad')

@test('poison_no_fallback', 'verify6 item 1: a predicate our evaluator could not decide is refused, never taken from the optimiser\'s leftovers')
def _():
    st, got, metal, why = v6_compare('poison_select', v6_cases('poison_select'), allowed=('does not fold', 'does not decide'))
    for c, w in why.items(): assert any(f'4={x} ' in c for x in ('nan', '1e10', '-7.5', 'inf')), (c, w[:200])   # only poison conversions
    assert got['0=1 1=0 4=nan 10=nan'][0] == 'refused', got['0=1 1=0 4=nan 10=nan']                         # fix5: [0,1,3,4,5,6,7,8,9], Metal [3]
    s2, got2, _, _ = v6_compare('poison_absorb', v6_cases('poison_absorb'), allowed=('does not fold', 'does not decide', 'unset function constant', 'set the constant'))
    return f"poison_select {st['match']} == Metal, {st['refused']} refused (NaN / inf / 1e10 / -7.5 through uint()); poison_absorb {s2['match']} == Metal, {s2['refused']} refused", \
           (None, 'fix round 5: A = 1, B = 0, F = NaN: ours [0,1,3,4,5,6,7,8,9], Metal [3] (the implicit-global fallback)')

@test('ctor_ieee_body', 'verify6 item 3: the static initialiser is IEEE; with every constant set the body reads the evaluator\'s values')
def _():
    FM = ("from finite operands under Metal's fast-math flags",)
    # N = 70000: half(N) = inf (an AIR conversion, IEEE in Metal) propagates through `fadd fast`: IEEE, == Metal (present)
    s1, g1, _, why1 = v6_compare('overflow_body', v6_cases('overflow_body'))
    assert s1['match'] == 4, (s1, why1)
    s2, g2, _, _ = v6_compare('absent_read', v6_cases('absent_read'))
    assert s2['match'] == 4, s2
    # the same poison class, measured: signbit(float(K) * F - 0) with K = -128 is false in Metal for F = FLT_MAX and
    # true for F = 1e38 (both products are -inf): refused; the finite cases == Metal
    s4, _, m4, why4 = v6_compare('fmf_poison', v6_cases('fmf_poison'), allowed=FM)
    assert s4['match'] == 3 and s4['refused'] == 2, (s4, why4)
    assert 0 not in m4['4=3.4028234663852886e+38 5=31744 8=-128'][0] and 0 in m4['4=1e38 5=0 8=-128'][0], m4
    # absent_read N = 70000: b0 and b1 absent (Metal) and no longer read by the code
    rc, out, j = run(NEW, air('v6_absent_read', os.path.join(V6, 'absent_read.metal')), ['--entry', 'f', '--fc', '3=70000']); assert rc == 0, err(out)
    used = sorted(b['metal_index'] for b in j['reflection']['bindings'] if b['kind'] == 'ubo' and b['used'])
    assert used == [2], used
    s3, _, _, why = v6_compare('pun_probe', v6_cases('pun_probe'))
    assert s3['match'] == 143 and s3['refused'] == 0, (s3, list(why.values())[:2])
    return f"overflow_body 4/4, absent_read 4/4 (N = 70000 reads UBO 2 only), pun_probe 143/143, fmf_poison 3 == Metal + 2 refused (an overflowing fast-math product: Metal's answer flips)", \
           (None, 'fix round 5: overflow_body pixel 0 (Metal 3), absent_read read UBO 0 and 1, 31 spurious internal refusals in pun_probe')

@test('cv_trunc_edges', 'verify6 item 4: float -> char / short of a constant truncates toward zero (char(-128.5) == -128)')
def _():
    tot = dict(match=0, refused=0)
    for n in ('cv_neg', 'cv_charm128', 'cv_shortm32768', 'cv_uneg'):
        st, got, metal, why = v6_compare(n, v6_cases(n), allowed=('does not fold',))
        for c, w in why.items(): assert '-128.99' in c or 'uneg' in n, (n, c, w[:200])   # half(-128.99) = -129: out of range, poison
        tot['match'] += st['match']; tot['refused'] += st['refused']
    return f"{tot['match']} == Metal (presence + pixel), {tot['refused']} refused (char(half(-128.99)) = char(-129): poison)", \
           (None, 'fix round 5: cv_neg pixel 48 (Metal 120), cv_charm128 0 (3), cv_shortm32768 2 (3): NIR f2i8 / f2i16 folding')

@test('int_clamp', 'fix round 6 (A16 run 2 UBO probes): air.clamp.s / .u are integer clamps, not max.f / min.f on the bits')
def _():
    st, got, metal, why = v6_compare('int_clamp', ['0=1', '0=0'])
    assert st['match'] == 2, (st, got, metal)
    probes = os.path.join(ROOT, 'tools', 'a16ref', 'probes.air')
    res = {}
    for fn, extra in (('probe_ubo_lo', []), ('probe_ubo_hi', ['--test-ubo-slots', '32'])):
        vb = os.path.join(SCR, fn + '.ir3v')
        subprocess.run([NEW, '--quiet', '--stage', 'fragment', '--entry', fn, '--rt-format', '0=80', '--variant', vb] + extra + [probes], check=True, capture_output=True)
        dis = subprocess.run([NEW, '--verify-variant', vb], capture_output=True, text=True).stdout
        assert 'max.s' in dis and 'min.s' in dis and 'max.f' not in dis and 'min.f' not in dis, (fn, re.findall(r'.*(?:max|min)\.\w.*', dis))
        ldc = sorted(int(x) for x in re.findall(r'ldc\.1\.k\.imm c\[a1\.x\], 0, (\d+)', dis))
        assert ldc == list(range(0, 16) if fn == 'probe_ubo_lo' else range(16, 31)), (fn, ldc)
        res[fn] = len(ldc)
    # the one corpus function with an integer clamp (QuartzCore variable_blur_copy_base_mip_compute) uses an
    # imageblock and is refused before translation: the fix changes no corpus variant
    rc, out, j = run(NEW, corpus('QuartzCore', 'variable_blur_copy_base_mip_compute')); assert rc != 0 and 'imageblock' in out, err(out)
    return f"int_clamp == Metal; probe_ubo_lo / _hi: max.s / min.s, one static ldc per UBO ({res['probe_ubo_lo']} / {res['probe_ubo_hi']})", \
           (None, 'fix round 5 (A16 run 2): max.f / min.f on 0..15 (fp32 denormals, flushed on Adreno): every band read the first slot')

@test('int_convert_ext', 'fix round 6: integer -> integer air.convert extends by the SOURCE signedness (uint4(short4(-1)) = 0xffffffff)')
def _():
    st, got, metal, why = v6_compare('int_convert', ['0=1', '0=0'])
    assert st['match'] == 2, (st, got, metal)
    return f"int_convert == Metal: {got['0=1'][1]}", (None, 'fix round 5: uint4(short4(-1)).x >> 16 = 0 (zero-extended), int4(ushort4(65535)) = -1')


def deriv_types(binary, src, args):
    vb = os.path.join(OUT, os.path.basename(src) + '.' + os.path.basename(binary) + '.ir3v')
    rc, out, _ = run(binary, src, ['--stage', 'fragment', '--variant', vb] + args, json_out=False)
    if rc: return None, err(out)
    dis = subprocess.run([binary, '--verify-variant', vb], capture_output=True, text=True).stdout
    return re.findall(r'\b(dsx|dsy)(?:pp\.\d)? \((f16|f32)\)', dis), ''

@test('deriv16 dsx/dsy at 32 bits', 'dsx/dsy on half registers (A16 v101: fwidth(half) tens of times too large)')
def _():
    res, old = [], []
    for src, args in ((air('deriv16_frag'), []), (corpus('QuartzCore', 'glass_background_sdf_cr_lph'), ['--rt-format', '0=80'])):
        ds, e = deriv_types(NEW, src, args)
        assert ds is not None, e
        assert ds and all(t == 'f32' for _, t in ds), f'{os.path.basename(src)}: {ds}'
        res.append(f'{len(ds)} f32')
        if os.path.exists(OLD_DERIV):
            d0, _ = deriv_types(OLD_DERIV, src, args)
            old.append(','.join(sorted({t for _, t in d0 or []})))
    return ', '.join(res), (None, ('before: ' + ' / '.join(old)) if old else 'before: dsx (f16) / dsy (f16) on half registers')
OLD_DERIV = os.environ.get('AIR2IR3_OLD', os.path.join(ROOT, 'build', 'air2ir3-old'))

IMAGEBLOCK_FN = None
def main():
    global IMAGEBLOCK_FN
    os.makedirs(OUT, exist_ok=True); os.makedirs(SCR, exist_ok=True); os.makedirs(os.path.join(ROOT, 'results'), exist_ok=True)
    IMAGEBLOCK_FN = 'blur_copy_compute'
    only = sys.argv[1:]
    fails = 0
    rows = []
    for name, bug, f in TESTS:
        if only and not any(o in name for o in only): continue
        try:
            res, v0 = f(); ok = 'PASS'
        except Skip as e:
            res, v0, ok = str(e), (None, ''), 'SKIP'
        except AssertionError as e:
            res, v0, ok = str(e)[:120], (None, ''), 'FAIL'; fails += 1
        v0s = '' if v0[0] is None else ('rc=%d ' % v0[0])
        rows.append((ok, name, bug, res, v0s + v0[1]))
        print(f'{ok}  {name:48s} | {res[:60]:60s} | v0: {v0s}{v0[1][:90]}', flush=True)
    json.dump(rows, open(os.path.join(ROOT, 'results', 'regress.json' if not only else 'regress-partial.json'), 'w'), indent=1)
    skips = sum(1 for r in rows if r[0] == 'SKIP')
    print(f'\n{len(rows) - fails - skips}/{len(rows)} passed' + (f', {skips} skipped' if skips else ''))
    sys.exit(1 if fails else 0)

if __name__ == '__main__':
    main()

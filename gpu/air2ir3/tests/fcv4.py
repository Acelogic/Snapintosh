#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""fcv4.py - verify4's randomized unset-function-constant test (verify4 work/fc/fcv4.py, ported into the
tree by fix round 4; the generator is unchanged, so its seeds reproduce verify4's shaders).
Constants: bool A,B,C (0..2), int N (3), float F (4), ushort U (5), short S (6).
Focus: conditions whose value the compiler's undef *sample set* cannot see (N == 4, N in (5,17),
F == 2.0, U == 7 ...), mixed with ordinary random shapes.  Same oracle as fix3's fcrand:
present set, read set (red channel = sum of 2^k), full pixel.  Our side: this tree's build/air2ir3 + build/nirexec.
ABI v5 must refuse or match: zero present/read/pixel mismatches among compiled cases.
usage: fcv4.py --shaders N --cases K --seed S [--mode hole|mixed|pred] [--out results/fcv4-<mode>-<seed>.json]
       exit status 1 on any mismatch or unexpected refusal
"""
import json, os, random, re, struct, subprocess, sys, time
from concurrent.futures import ThreadPoolExecutor
HERE = os.path.dirname(os.path.abspath(__file__))
TREE = os.path.dirname(HERE)
NEW = os.path.join(TREE, 'build', 'air2ir3'); NIREXEC = os.path.join(TREE, 'build', 'nirexec')
METAL = os.path.join(TREE, 'build', 'tests', 'fcv4metal')
SWIFT = os.path.join(HERE, 'fixtures', 'fcv4.swift')
NB = 12
VALS = {0: 'u01', 1: 'u01', 2: 'u01', 3: ['u', '0', '4', '7', '9', '100'], 4: ['u', '0', '2', '0.25', '7.5'],
        5: ['u', '0', '7', '300'], 6: ['u', '0', '-5', '12']}

def hole_cond(r):
    k = r.randrange(22)
    v = r.choice([4, 6, 7, 8, 9, 10, 11, 100, -5, 1000, 4096])
    return [f'(N == {v})', f'(N != {v})', f'(N >= 6 && N <= 16)', f'(N > 5 && N < 17)', '((N >> 1) == 4)',
            '((N % 7) == 4)', f'(F == 2.0)', f'(F != 2.0)', '(F == 0.25)', '(F > 3.5 && F < 100.0)', '(isnan(F))',
            '(F * F == 4.0)', f'(U == 7)', '(U > 256 && U < 65535)', f'(S == -5)', f'(S == 12)', '(uint(N) == 4u)',
            f'(A || N == {v})', f'(!B && N == {v})', f'((N == {v}) != C)', '(abs(N) == 4)', '(N * N == 16)'][k]

def plain_cond(r):
    return r.choice(['A', '!B', 'C', '(A && B)', '(A || C)', '(N > 1)', '(N == 2)', '(F > 0.5)', '(U < 3)', '(S >= 0)', 'is_function_constant_defined(N)'])

def gen_pred(seed):
    r = random.Random(seed); lines = []; body = []; args = []
    for k in range(NB):
        c = hole_cond(r) if r.random() < 0.7 else plain_cond(r)
        c = c.replace('isnan(F)', '(F != F)').replace('abs(N) == 4', '(N == 4 || N == -4)').replace('uint(N)', 'as_type<uint>(N)')
        if 'is_function_constant_defined' in c: c = '(A && C)'
        lines.append(f'constant bool Q{k} = {c};')
        args.append(f'constant float4 &b{k} [[buffer({k}), function_constant(Q{k})]]')
        body.append(f'  if (Q{k}) r.x += b{k}.x;' if r.random() < 0.7 else f'  r.x += Q{k} ? b{k}.x : 0.0;')
    return ('#include <metal_stdlib>\nusing namespace metal;\n'
            'constant bool A [[function_constant(0)]];\nconstant bool B [[function_constant(1)]];\n'
            'constant bool C [[function_constant(2)]];\nconstant int N [[function_constant(3)]];\n'
            'constant float F [[function_constant(4)]];\nconstant ushort U [[function_constant(5)]];\n'
            'constant short S [[function_constant(6)]];\n' + '\n'.join(lines) + '\n'
            'vertex float4 v(uint i [[vertex_id]]) { return float4(i == 1 ? 3.0 : -1.0, i == 2 ? 3.0 : -1.0, 0, 1); }\n'
            'fragment float4 f(' + ',\n  '.join(args) + ') {\n  float4 r = 0;\n' + '\n'.join(body) + '\n  return r;\n}\n')

def gen(seed, mode):
    if mode == 'pred': return gen_pred(seed)
    r = random.Random(seed)
    pool = list(range(NB)); r.shuffle(pool)
    body = []
    def cond(): return hole_cond(r) if (mode == 'hole' or r.random() < 0.6) else plain_cond(r)
    def b(k): return f'b{k}.x'
    while pool:
        s = r.random(); c = cond()
        if s < 0.3 and len(pool) >= 2: body.append(f'  r.x += {c} ? {b(pool.pop())} : {b(pool.pop())};')
        elif s < 0.5 and len(pool) >= 2: body.append(f'  if ({c}) r.x += {b(pool.pop())}; else r.x += {b(pool.pop())};')
        elif s < 0.6: body.append(f'  if ({c}) r.x += {b(pool.pop())};')
        elif s < 0.68: body.append(f'  r.x += {c} ? 0.0 : {b(pool.pop())};')
        elif s < 0.78 and len(pool) >= 2: body.append(f'  r.x += select(b{pool.pop()}, b{pool.pop()}, {c}).x;')
        elif s < 0.88:
            k = pool.pop(); body.append(f'  if ({c}) {{ for (int i = 0; i < int(b{k}.w); i++) r.x += {b(k)}; }}')
        else:
            k = pool.pop(); body.append(f'  r.x += {b(k)}; r.y += {c} ? 1.5 : 2.25;')
    if r.random() < 0.3: body.append(f'  r.z += float({cond()}) * 0.75;')
    args = [f'constant float4 &b{k} [[buffer({k})]]' for k in range(NB)]
    return ('#include <metal_stdlib>\nusing namespace metal;\n'
            'constant bool A [[function_constant(0)]];\nconstant bool B [[function_constant(1)]];\n'
            'constant bool C [[function_constant(2)]];\nconstant int N [[function_constant(3)]];\n'
            'constant float F [[function_constant(4)]];\nconstant ushort U [[function_constant(5)]];\n'
            'constant short S [[function_constant(6)]];\n'
            'vertex float4 v(uint i [[vertex_id]]) { return float4(i == 1 ? 3.0 : -1.0, i == 2 ? 3.0 : -1.0, 0, 1); }\n'
            'fragment float4 f(' + ',\n  '.join(args) + ') {\n  float4 r = 0;\n' + '\n'.join(body) + '\n  return r;\n}\n')

def main():
    a = sys.argv[1:]
    def opt(n, d): return type(d)(a[a.index(n) + 1]) if n in a else d
    NS, K, SEED, J, MODE = opt('--shaders', 100), opt('--cases', 8), opt('--seed', 41), opt('--jobs', 12), opt('--mode', 'hole')
    OUT = opt('--out', os.path.join(TREE, 'results', f'fcv4-{MODE}-{SEED}.json'))
    Wd = os.path.join(TREE, 'scratch', 'fcv4', f'w-{MODE}-{SEED}'); os.makedirs(Wd, exist_ok=True)
    if not os.path.exists(METAL) or os.path.getmtime(METAL) < os.path.getmtime(SWIFT):
        os.makedirs(os.path.dirname(METAL), exist_ok=True)
        subprocess.run(['swiftc', '-O', SWIFT, '-o', METAL], check=True, capture_output=True)
    def build(i):
        s = gen(SEED * 7919 + i, MODE); base = os.path.join(Wd, f's{i:04d}')
        open(base + '.metal', 'w').write(s)
        p = subprocess.run(['xcrun', '-sdk', 'macosx', 'metal', '-c', base + '.metal', '-o', base + '.air'], capture_output=True, text=True)
        if p.returncode: return i, p.stderr[-300:]
        subprocess.run(['xcrun', '-sdk', 'macosx', 'metallib', base + '.air', '-o', base + '.metallib'], check=True, capture_output=True)
        return i, None
    ok = []
    with ThreadPoolExecutor(J) as ex:
        for i, e in ex.map(build, range(NS)):
            if e: print('bad MSL', i, e)
            else: ok.append(i)
    rnd = random.Random(SEED)
    allu = ' '.join(f'{k}=u' for k in range(7))
    cases = []
    for i in ok:
        cs = {allu}
        while len(cs) < K: cs.add(' '.join(f'{k}={rnd.choice(VALS[k])}' for k in range(7)))
        cases += [(i, c) for c in sorted(cs)]
    p = subprocess.run([METAL], input='\n'.join(f"{os.path.join(Wd, f's{i:04d}.metallib')}\t{c}" for i, c in cases) + '\n', capture_output=True, text=True, check=True)
    metal = {}
    for l in p.stdout.splitlines():
        key, res = l.split(' -> ', 1); path, c = key.split('\t'); i = int(os.path.basename(path)[1:5])
        if res.startswith('ERR'): metal[(i, c)] = ('ERR', res); continue
        m = re.match(r'(\[.*?\]) px (\S+) (\S+) (\S+) (\S+)', res)
        px = [struct.unpack('<f', struct.pack('<I', int(h, 16)))[0] for h in m.groups()[1:]]
        metal[(i, c)] = (json.loads(m.group(1)), sorted(k for k in range(NB) if int(px[0]) >> k & 1), px)
    def ours(ic):
        i, c = ic; base = os.path.join(Wd, f's{i:04d}'); tag = c.replace(' ', '_').replace('=', '')
        jp = f'{base}_{tag}.json'
        fc = {t.split('=')[0]: t.split('=')[1] for t in c.split() if not t.endswith('=u')}
        args = [NEW, '--quiet', '--entry', 'f', '--json', jp]
        for k, v in fc.items(): args += ['--fc', f'{k}={v}']
        q = subprocess.run(args + [base + '.air'], capture_output=True, text=True)
        if q.returncode: return ic, ('REFUSED', ((q.stdout + q.stderr).strip().splitlines() or ['?'])[-1][:300])
        j = json.load(open(jp)); os.remove(jp)
        ub = [x for x in j['reflection']['bindings'] if x['kind'] == 'ubo']
        present = sorted(x['metal_index'] for x in ub if x['present']); used = sorted(x['metal_index'] for x in ub if x['used'])
        fcn = {k: float(v) for k, v in fc.items()}
        sc = dict(name=f's{i}', width=1, height=1, frames=1, format='rgba32f', clear=[0, 0, 0, 0],
                  vs=dict(bc=base + '.air', entry='v', function='v', fc=fcn), fs=dict(bc=base + '.air', entry='f', function='f', fc=fcn),
                  vertex=dict(stride=0, data=dict(floats=[]), count=3, primitive='triangle', attributes=[]),
                  buffers=dict(fragment=[dict(index=k, floats=[float(1 << k), 0, 0, 1]) for k in range(NB)]), rt=dict(format='rgba32f'))
        sp = f'{base}_{tag}.scene.json'; op = f'{base}_{tag}.f32'; json.dump(sc, open(sp, 'w'))
        q = subprocess.run([NIREXEC, sp, op, '--frames', '1'], capture_output=True, text=True)
        if q.returncode: return ic, ('NIREXEC-FAIL', (q.stdout + q.stderr).strip()[-300:])
        px = list(struct.unpack('<4f', open(op, 'rb').read()[:16])); os.remove(sp); os.remove(op)
        return ic, (present, used, px)
    with ThreadPoolExecutor(J) as ex: got = dict(ex.map(ours, cases))
    st = dict(cases=len(cases), match=0, refused=0, bad_refusal=0, present=0, read=0, pixel=0, metal_err=0, nirexec=0)
    bad = []
    for ic in cases:
        m, o = metal[ic], got[ic]
        if m[0] == 'ERR': st['metal_err'] += 1; bad.append((ic, 'metalERR', m[1])); continue
        if o[0] == 'REFUSED':
            if 'unset function constant' in o[1] and '=u' in ic[1]: st['refused'] += 1
            else: st['bad_refusal'] += 1; bad.append((ic, 'refused', o[1]))
            continue
        if o[0] == 'NIREXEC-FAIL': st['nirexec'] += 1; bad.append((ic, 'nirexec', o[1])); continue
        pr, us, px = o
        if pr != m[0]: st['present'] += 1; bad.append((ic, 'present', pr, m[0])); continue
        pxbad = any(abs(x - y) > 1e-5 * max(1, abs(y)) for x, y in zip(px, m[2]))
        if us != m[1]: st['read'] += 1; st['read_and_pixel'] = st.get('read_and_pixel', 0) + pxbad; bad.append((ic, 'read', us, m[1], 'px', px[:2], m[2][:2])); continue
        if any(abs(x - y) > 1e-5 * max(1, abs(y)) for x, y in zip(px, m[2])): st['pixel'] += 1; bad.append((ic, 'pixel', px, m[2])); continue
        st['match'] += 1
    json.dump(dict(stats=st, bad=[[str(x) for x in b] for b in bad]), open(OUT, 'w'), indent=1)
    print(st)
    for b in bad[:30]: print('  ', b)
    sys.exit(1 if bad else 0)

if __name__ == '__main__':
    main()

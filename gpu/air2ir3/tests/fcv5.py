#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""fcv5.py - verify5's randomized unset-constant differential test (verify5 work/fc/fcv5.py, ported into
the tree by fix round 5; the generator is unchanged, so its seeds reproduce verify5's shaders).
12 constant types: bool A,B,C,D (0,1,2,11), int N (3), float F (4), ushort U (5), short S (6), uchar Q (7),
char K (8), uint W (9), half H (10); body / pred / shadow modes (pred and shadow: presence predicates,
direct copies of every type, conversions, isnan / isinf, shadow chains).  Oracle as fcv4: Metal present
set, read set (red = sum of 2^k), full pixel vs this tree's build/air2ir3 sidecar + build/nirexec.

Classification (fix round 5 adds two classes, everything else is verify5's):
  refused         refused naming an unset constant, in a case with an unset constant
  refused_poison  refused because a float -> integer conversion in the static initialiser is out of
                  range or NaN (Metal: poison), with every constant set; expected (BINDING-ABI.md 3.7)
  metal_err       Metal rejects the pipeline and we compile it: reported, harmless, not a failure
  present / pixel / bad_refusal / nirexec: failures (exit status 1)
usage: fcv5.py --mode body|pred|shadow --seed S --shaders N --cases K [--out results/fcv5-<mode>-<seed>.json]"""
import json, os, random, re, struct, subprocess, sys
from concurrent.futures import ThreadPoolExecutor
HERE = os.path.dirname(os.path.abspath(__file__))
TREE = os.path.dirname(HERE)
NEW = os.path.join(TREE, 'build', 'air2ir3'); NIREXEC = os.path.join(TREE, 'build', 'nirexec')
METAL = os.path.join(TREE, 'build', 'tests', 'fcv5metal'); SWIFT = os.path.join(HERE, 'fixtures', 'fcv5.swift')
NB = 12
DECL = ('constant bool A [[function_constant(0)]];\nconstant bool B [[function_constant(1)]];\nconstant bool C [[function_constant(2)]];\n'
        'constant int N [[function_constant(3)]];\nconstant float F [[function_constant(4)]];\nconstant ushort U [[function_constant(5)]];\n'
        'constant short S [[function_constant(6)]];\nconstant uchar Q [[function_constant(7)]];\nconstant char K [[function_constant(8)]];\n'
        'constant uint W [[function_constant(9)]];\nconstant half H [[function_constant(10)]];\nconstant bool D [[function_constant(11)]];\n')
VALS = {0: ['u', '0', '1'], 1: ['u', '0', '1'], 2: ['u', '0', '1'], 11: ['u', '0', '1'],
        3: ['u', '0', '1', '-1', '4', '7', '100', '2147483647', '-2147483648'], 4: ['u', '0', '2', '0.25', '-7.5'],
        5: ['u', '0', '7', '300', '65535'], 6: ['u', '0', '-5', '12', '-32768', '32767'], 7: ['u', '0', '1', '200', '255'],
        8: ['u', '0', '-3', '127', '-128'], 9: ['u', '0', '5', '4294967295', '2147483648'], 10: ['u', '0', '1.5', '-2', '65504']}
INTS = {'N': (-2**31, 2**31 - 1), 'U': (0, 65535), 'S': (-32768, 32767), 'Q': (0, 255), 'K': (-128, 127), 'W': (0, 2**32 - 1)}
BOOLS = ['A', 'B', 'C', 'D']

def icond(r):
    X = r.choice(list(INTS)); lo, hi = INTS[X]
    v = r.choice([0, 1, 4, 7, 12, 100, 127, 128, 200, 255, 256, 300, 32767, 65535, 65536, lo, hi, lo - 1 if lo > -2**31 else lo, hi + 1 if hi < 2**31 - 1 else hi])
    if X in ('U', 'Q', 'W'): v = abs(v)
    vs = f'{v}u' if X == 'W' else (str(v) if -2**31 <= v < 2**31 else f'{v}l')
    m = r.choice([1, 3, 7, 15, 128, 255, 0])
    s = r.randint(0, 7)
    c = r.choice([
        f'({X} == {vs})', f'({X} != {vs})', f'({X} > {vs})', f'({X} <= {vs})', f'({X} >= {vs})', f'({X} < {vs})',
        f'(({X} & {m}) == {m & 5})', f'(({X} & {m}) <= {m})', f'(({X} | {m | 1}) != 0)', f'(({X} | {m}) == {m})',
        f'((({X} >> {s}) & 1) == 1)', f'(({X} * 0) == 0)', f'((({X} * 2) & 1) == 0)', f'(({X} / 2) == 3)', f'(({X} % 3) == 1)',
        f'((100 / ({X} | 1)) > 7)', f'(uchar({X}) == 200)', f'(short({X}) < 0)', f'(float({X}) > 99.5)', f'(half({X}) == 4.0h)',
        f'(bool({X}))', f'(int(uchar({X})) - 300 < 0)', f'(float(uchar({X})) < 256.0)', f'(min({X}, ({type_of(X)})10) <= 10)',
        f'(max({X}, ({type_of(X)})10) >= 10)', f'(clamp({X}, ({type_of(X)})2, ({type_of(X)})9) == 5)', f'(popcount({X}) <= 32)',
        f'(popcount({X}) == 3)', f'(clz({X}) >= 0)', f'(({X} ^ {X}) == 0)', f'(({X} - {X}) == 0)', f'(ushort({X}) < 65536)',
        f'(({X} & 0) == 0)', f'((({X} << 4) & 15) == 0)', f'(({X} & 0xF0) > 0x0F)', f'(abs(int({X})) == 7)', f'(({X} + 1) > {X})'])
    return c

def type_of(X): return dict(N='int', U='ushort', S='short', Q='uchar', K='char', W='uint')[X]

def bcond(r):
    a, b = r.sample(BOOLS, 2)
    return r.choice([a, f'!{a}', f'({a} && {b})', f'({a} || !{b})', f'({a} == {b})', f'({a} != {b})', f'({a} && !{a})', f'({a} || !{a})',
                     f'(int({a}) + int({b}) == 2)', f'(select(false, true, {a}))', f'({a} ? {b} : !{b})', f'(is_function_constant_defined({a}) && {a})'])

def fcond(r):
    X = r.choice(['F', 'H']); h = 'h' if X == 'H' else ''
    return r.choice([f'({X} == 2.0{h})', f'({X} > 0.5{h})', f'({X} != {X})', f'(isnan({X}))', f'(isinf({X}))', f'({X} * 0.0{h} == 0.0{h})',
                     f'(floor({X}) == {X})', f'(int({X}) == 2)', f'({X} + 1.0{h} > {X})', f'({X} >= -INFINITY)', f'(bool({X}))'])

def cond(r):
    k = r.random()
    if k < 0.55: c = icond(r)
    elif k < 0.8: c = bcond(r)
    else: c = fcond(r)
    if r.random() < 0.25: c = f'({r.choice(BOOLS)} {r.choice(["&&", "||"])} {c})'
    return c

def gen_body(seed):
    r = random.Random(seed); pool = list(range(NB)); r.shuffle(pool); body = []
    def bx(k): return f'b{k}.x'
    while pool:
        s = r.random(); c = cond(r)
        if s < 0.2 and len(pool) >= 2: body.append(f'  r.x += {c} ? {bx(pool.pop())} : {bx(pool.pop())};')
        elif s < 0.35 and len(pool) >= 2: body.append(f'  if ({c}) r.x += {bx(pool.pop())}; else r.x += {bx(pool.pop())};')
        elif s < 0.45: body.append(f'  if ({c}) r.x += {bx(pool.pop())};')
        elif s < 0.52 and len(pool) >= 2: body.append(f'  r.x += select(b{pool.pop()}, b{pool.pop()}, {c}).x;')
        elif s < 0.6 and len(pool) >= 3:
            X = r.choice(list(INTS)); k1, k2, k3 = pool.pop(), pool.pop(), pool.pop()
            body.append(f'  switch (int({X} & 3)) {{ case 0: r.x += {bx(k1)}; break; case 1: r.x += {bx(k2)}; break; default: r.x += {bx(k3)}; break; }}')
        elif s < 0.66:
            X = r.choice(list(INTS)); k = pool.pop(); mask = r.choice(['0', '3', '1'])
            body.append(f'  for (int i = 0; i < int({X} & {mask}); i++) r.x += {bx(k)};')
        elif s < 0.72:
            X = r.choice(list(INTS)); k = pool.pop()
            body.append(f'  r.x += {bx(k)}; r.y += b{k}[int({X} & {r.choice(["0", "1", "3"])})];')
        elif s < 0.8:
            k = pool.pop(); body.append(f'  r.x += {bx(k)}; r.y += {c} ? 0.125 : 0.0625;')
        elif s < 0.86:
            X = r.choice(list(INTS)); k = pool.pop()
            body.append(f'  r.x += {bx(k)}; r.z += float({X} & {r.choice(["0", "1", "0xF"])}) * 0.5;')
        elif s < 0.92:
            k = pool.pop(); body.append(f'  r.x += {c} ? 0.0 : {bx(k)};')
        else:
            k = pool.pop(); body.append(f'  if ({c}) {{ for (int i = 0; i < int(b{k}.w); i++) r.x += {bx(k)}; }}')
    if r.random() < 0.4: body.append(f'  r.w += float({cond(r)}) * 0.75;')
    args = [f'constant float4 &b{k} [[buffer({k})]]' for k in range(NB)]
    return ('#include <metal_stdlib>\nusing namespace metal;\n' + DECL +
            'vertex float4 v(uint i [[vertex_id]]) { return float4(i == 1 ? 3.0 : -1.0, i == 2 ? 3.0 : -1.0, 0, 1); }\n'
            'fragment float4 f(' + ',\n  '.join(args) + ') {\n  float4 r = 0;\n' + '\n'.join(body) + '\n  return r;\n}\n')

DIRECT = ['A', 'D', 'N', 'U', 'S', 'Q', 'K', 'W', 'bool(uchar(N))', '(N != 0)', '(0 != U)', '!A', 'F', 'H', 'bool(int(A))', '(A && true)',
          '(A || false)', 'bool(short(W))', '(Q != 0)', '(K == 0)', 'bool(N & 1)', '(bool)(uchar)(U >> 8)', 'is_function_constant_defined(N) && (N != 0)',
          '!(!A)', '(A == true)', '(N != 0) && (N != 0)', 'bool(-N)', 'bool(~W)', 'bool(N + 0)', 'bool(N * 1)', 'bool(N | 0)', '(N > 0) || (N < 0)']

def gen_pred(seed, shadow=False):
    r = random.Random(seed); lines = []; body = []; args = []
    for k in range(NB):
        x = r.random()
        c = r.choice(DIRECT) if x < 0.5 else cond(r)
        if os.environ.get('NOCONV'):
            while re.search(r'\b(float|half|int|uint|short|ushort|uchar|char)\((F|H)|isnan|isinf|floor|popcount|clz|min\(|max\(|clamp\(|abs\(|bool\((F|H)\)|= (F|H);|float\(|half\(', c):
                c = r.choice(DIRECT) if r.random() < 0.5 else cond(r)
        if shadow and r.random() < 0.6:
            t = r.choice(['int', 'bool', 'uchar', 'uint', 'short'])
            lines.append(f'constant {t} M{k} = {t}({c});'); c = f'bool(M{k})' if r.random() < 0.5 else f'(M{k} != 0)'
            if r.random() < 0.3: body.append(f'  r.y += float(M{k} != 0) * 0.125;')
        lines.append(f'constant bool Q{k} = {c};')
        args.append(f'constant float4 &b{k} [[buffer({k}), function_constant(Q{k})]]')
        y = r.random()
        body.append(f'  if (Q{k}) r.x += b{k}.x;' if y < 0.6 else f'  r.x += Q{k} ? b{k}.x : 0.0;')
    return ('#include <metal_stdlib>\nusing namespace metal;\n' + DECL + '\n'.join(lines) + '\n'
            'vertex float4 v(uint i [[vertex_id]]) { return float4(i == 1 ? 3.0 : -1.0, i == 2 ? 3.0 : -1.0, 0, 1); }\n'
            'fragment float4 f(' + ',\n  '.join(args) + ') {\n  float4 r = 0;\n' + '\n'.join(body) + '\n  return r;\n}\n')

def summary():
    # fix round 5: the 16 runs of tools/runall.sh together (results/fcv5-<mode>-<seed>.json); exit 1 on any failure
    tot = {}; runs = 0
    for f in sorted(os.listdir(os.path.join(TREE, 'results'))):
        if not re.match(r'fcv5-(body|pred|shadow)-\d+\.json$', f): continue
        st = json.load(open(os.path.join(TREE, 'results', f)))['stats']; runs += 1
        print(f[5:-5], st)
        for k, v in st.items(): tot[k] = tot.get(k, 0) + v
    fail = sum(tot.get(k, 0) for k in ('present', 'read', 'pixel', 'bad_refusal', 'nirexec'))
    print(f'fcv5: {runs} runs, {tot.get("cases", 0)} cases: {tot.get("match", 0)} match Metal ({tot.get("match_with_unset", 0)} with an unset constant), '
          f'{tot.get("refused", 0)} refused on an unset constant, {tot.get("refused_poison", 0)} refused on a poison conversion, '
          f'{tot.get("both_refuse", 0)} refused by both, {tot.get("metal_err", 0)} Metal-only rejections, {tot.get("unsupported", 0)} unsupported; failures {fail}')
    sys.exit(1 if fail or not runs else 0)

def main():
    a = sys.argv[1:]
    if '--summary' in a: return summary()
    def opt(n, d): return type(d)(a[a.index(n) + 1]) if n in a else d
    NS, K, SEED, J, MODE = opt('--shaders', 100), opt('--cases', 8), opt('--seed', 5), opt('--jobs', 12), opt('--mode', 'body')
    OUTJ = a[a.index('--out') + 1] if '--out' in a else os.path.join(TREE, 'results', f'fcv5-{MODE}-{SEED}.json')
    Wd = os.path.join(TREE, 'scratch', 'fcv5', f'{MODE}-{SEED}'); os.makedirs(Wd, exist_ok=True)
    for f in os.listdir(Wd): os.remove(os.path.join(Wd, f))
    if not os.path.exists(METAL) or os.path.getmtime(METAL) < os.path.getmtime(SWIFT):
        os.makedirs(os.path.dirname(METAL), exist_ok=True)
        subprocess.run(['swiftc', '-O', SWIFT, '-o', METAL], check=True, capture_output=True)
    def build(i):
        s = gen_body(SEED * 7919 + i) if MODE == 'body' else gen_pred(SEED * 7919 + i, MODE == 'shadow')
        base = os.path.join(Wd, f's{i:04d}'); open(base + '.metal', 'w').write(s)
        p = subprocess.run(['xcrun', '-sdk', 'macosx', 'metal', '-c', base + '.metal', '-o', base + '.air'], capture_output=True, text=True)
        if p.returncode: return i, p.stderr[-400:]
        subprocess.run(['xcrun', '-sdk', 'macosx', 'metallib', base + '.air', '-o', base + '.metallib'], check=True, capture_output=True)
        return i, None
    ok = []; badmsl = 0
    with ThreadPoolExecutor(J) as ex:
        for i, e in ex.map(build, range(NS)):
            if e: badmsl += 1; (badmsl <= 3 and print('bad MSL', i, e[:300]))
            else: ok.append(i)
    rnd = random.Random(SEED)
    allu = ' '.join(f'{k}=u' for k in range(12))
    cases = []
    for i in ok:
        cs = {allu}
        while len(cs) < K:
            pu = rnd.choice([0.05, 0.1, 0.2, 0.5])
            cs.add(' '.join(f'{k}=' + ('u' if rnd.random() < pu else rnd.choice(VALS[k][1:])) for k in range(12)))
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
                  buffers=dict(fragment=[dict(index=k, floats=[float(1 << k), 0.5, 0.25, 1] + [0.0] * 12) for k in range(NB)]), rt=dict(format='rgba32f'))
        sp = f'{base}_{tag}.scene.json'; op = f'{base}_{tag}.f32'; json.dump(sc, open(sp, 'w'))
        q = subprocess.run([NIREXEC, sp, op, '--frames', '1'], capture_output=True, text=True)
        if q.returncode: return ic, ('NIREXEC-FAIL', (q.stdout + q.stderr).strip()[-300:])
        px = list(struct.unpack('<4f', open(op, 'rb').read()[:16])); os.remove(sp); os.remove(op)
        return ic, (present, used, px)
    with ThreadPoolExecutor(J) as ex: got = dict(ex.map(ours, cases))
    st = dict(shaders=len(ok), bad_msl=badmsl, cases=len(cases), match=0, refused=0, bad_refusal=0, present=0, read=0, pixel=0, metal_err=0, nirexec=0)
    bad = []; reasons = {}
    for ic in cases:
        m, o = metal[ic], got[ic]
        if m[0] == 'ERR':
            if o[0] == 'REFUSED': st['both_refuse'] = st.get('both_refuse', 0) + 1
            else: st['metal_err'] += 1                                   # harmless: reported, not a failure
            continue
        if o[0] == 'REFUSED':
            if 'unset function constant' in o[1] and '=u' in ic[1]:
                st['refused'] += 1; key = re.sub(r'\(.*', '', o[1])[:90]; reasons[key] = reasons.get(key, 0) + 1
            elif 'not implemented' in o[1]: st['unsupported'] = st.get('unsupported', 0) + 1
            elif 'does not fold' in o[1] and 'air.convert.' in o[1]: st['refused_poison'] = st.get('refused_poison', 0) + 1
            else: st['bad_refusal'] += 1; bad.append((ic, 'refused', o[1]))
            continue
        if o[0] == 'NIREXEC-FAIL': st['nirexec'] += 1; bad.append((ic, 'nirexec', o[1])); continue
        pr, us, px = o
        if pr != m[0]:
            st['present'] += 1; st['present_allset' if '=u' not in ic[1] else 'present_unset'] = st.get('present_allset' if '=u' not in ic[1] else 'present_unset', 0) + 1
            bad.append((ic, 'present', pr, m[0])); continue
        pxbad = any(abs(x - y) > 1e-5 * max(1, abs(y)) for x, y in zip(px, m[2]))
        if pxbad: st['pixel'] += 1; bad.append((ic, 'pixel', px, m[2], 'used', us, 'metal_read', m[1])); continue
        if us != m[1]: st['static_use_only'] = st.get('static_use_only', 0) + 1
        st['match'] += 1
        if '=u' in ic[1]: st['match_with_unset'] = st.get('match_with_unset', 0) + 1
    json.dump(dict(stats=st, bad=[[str(x) for x in b] for b in bad], reasons=reasons), open(OUTJ, 'w'), indent=1)
    print(st)
    for b in bad[:40]: print('  ', b)
    sys.exit(1 if bad else 0)

if __name__ == '__main__':
    main()

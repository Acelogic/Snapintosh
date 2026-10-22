#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""fc6.py - verify6's randomized function-constant differential (independent of fcv5's generator).

Typed random expressions over the 12 fcv5 constants (bool A,B,C,D; int N; float F; ushort U; short S;
uchar Q; char K; uint W; half H) through every scalar conversion, as_type puns of every size (incl.
vector puns), isnan/isinf/isfinite/isnormal/signbit, and AIR helpers; values include NaN, +-inf, -0.0,
denormals, half overflow/underflow, int-range edges and IEEE special bit patterns.
Modes: pred (16 presence predicates), shadow (shadow globals of other types, read back by as_type /
classification: the punStored path), body (the same expressions deciding reads / values in the body).
Oracle: tests/fixtures/fcv5.swift (Metal present set + pixel); ours: tree build/air2ir3 sidecar +
llvmpipe (work/h/nirexec6, which accepts string constant values).
usage: fc6.py --mode pred|shadow|body --seed S --shaders N --cases K [--allset P]
"""
import json, os, random, re, struct, subprocess, sys
from concurrent.futures import ThreadPoolExecutor
# fix round 6: verify6's generator ported unchanged, pointed at this tree (build/nirexec reads string
# constant values since round 6, as verify6's nirexec6 did); results -> results/fc6-*.json
TREE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HERE = os.path.join(TREE, 'scratch', 'fc6'); os.makedirs(HERE, exist_ok=True)
NEW = os.path.join(TREE, 'build', 'air2ir3'); NIREXEC = os.path.join(TREE, 'build', 'nirexec')
METAL = os.path.join(TREE, 'build', 'tests', 'fcv5metal'); SWIFT = os.path.join(TREE, 'tests', 'fixtures', 'fcv5.swift')
NB = 16
DECL = ('constant bool A [[function_constant(0)]];\nconstant bool B [[function_constant(1)]];\nconstant bool C [[function_constant(2)]];\n'
        'constant int N [[function_constant(3)]];\nconstant float F [[function_constant(4)]];\nconstant ushort U [[function_constant(5)]];\n'
        'constant short S [[function_constant(6)]];\nconstant uchar Q [[function_constant(7)]];\nconstant char K [[function_constant(8)]];\n'
        'constant uint W [[function_constant(9)]];\nconstant half H [[function_constant(10)]];\nconstant bool D [[function_constant(11)]];\n')
ATOM = dict(A='bool', B='bool', C='bool', D='bool', N='int', F='float', U='ushort', S='short', Q='uchar', K='char', W='uint', H='half')
IDX = dict(A=0, B=1, C=2, N=3, F=4, U=5, S=6, Q=7, K=8, W=9, H=10, D=11)
VALS = {0: ['0', '1'], 1: ['0', '1'], 2: ['0', '1'], 11: ['0', '1'],
        3: ['0', '1', '-1', '2', '-7', '255', '256', '65504', '65505', '70000', '16777217', '-16777217', '2147483647', '-2147483648', '32768', '-129',
            '2139095040', '2143289344', '-8388608', '8388608'],
        4: ['0', '-0.0', '0.5', '-0.5', '2', '-7.5', '255.5', '256', '-128.5', '65504', '65520', '70000', '1e-08', '7.174648137343063e-43',
            '1.1754943508222875e-38', '2147483520', '2147483648', '4294967040', '4294967296', '-2147483648', '-2147483904', 'nan', 'inf', '-inf',
            '3.4028234663852886e+38', '1.5', '2.5', '-2.5', '0.1'],
        5: ['0', '1', '255', '256', '32768', '65535', '31744', '32256', '15360', '1'],
        6: ['0', '-1', '-32768', '32767', '-128', '255', '31744', '-512', '15360', '-1024'],
        7: ['0', '1', '127', '128', '255'],
        8: ['0', '-1', '-128', '127', '1'],
        9: ['0', '1', '2139095040', '2143289344', '2147483648', '1065353216', '4294967295', '16777217', '2147483647', '8388608'],
        10: ['0', '-0.0', '0.5', '-0.5', '1.5', '-2', '65504', '-65504', '255.5', '-128.5', '300', '5.9604644775390625e-08', '6.103515625e-05', 'nan', 'inf', '-inf', '2.5']}
if os.environ.get('SAFE'):   # finite values whose conversions stay in range for every destination type
    VALS = {0: ['0', '1'], 1: ['0', '1'], 2: ['0', '1'], 11: ['0', '1'],
            3: ['0', '1', '2', '7', '100', '127', '1065353216', '1073741824'], 4: ['0', '0.5', '1', '2', '7.5', '100.25', '126.5'],
            5: ['0', '1', '7', '127', '15360', '16384'], 6: ['0', '1', '7', '127', '15360', '16384'], 7: ['0', '1', '7', '127'], 8: ['0', '1', '7', '127'],
            9: ['0', '1', '7', '100', '1065353216', '1073741824'], 10: ['0', '0.5', '1', '2', '7.5', '100.25', '126.5']}
INTT = ['char', 'uchar', 'short', 'ushort', 'int', 'uint']
FLT = ['half', 'float']
SIZE = dict(bool=1, char=1, uchar=1, short=2, ushort=2, int=4, uint=4, half=2, float=4)
LIT = {'bool': ['true', 'false'],
       'char': ['0', '-1', '127', '-128', '1', '5'], 'uchar': ['0', '1', '127', '128', '255', '200'],
       'short': ['0', '-1', '32767', '-32768', '255', '-128', '15360'], 'ushort': ['0', '1', '65535', '32768', '255', '31744', '15360'],
       'int': ['0', '1', '-1', '2', '-7', '255', '2147483647', '(-2147483647 - 1)', '65504', '70000', '16777216', '2139095040'],
       'uint': ['0u', '1u', '7u', '4294967295u', '2147483648u', '2139095040u', '2143289344u', '1065353216u', '255u'],
       'half': ['0.0h', '-0.0h', '0.5h', '1.0h', '2.0h', '-2.0h', '65504.0h', 'INFINITY', '-INFINITY', '255.5h', '300.0h'],
       'float': ['0.0', '-0.0', '0.5', '2.0', '-7.5', '256.0', '65504.0', '65520.0', 'INFINITY', '-INFINITY', '4294967296.0', '2147483648.0', '1e-8']}
PUN = {4: ['int', 'uint', 'float', 'half2', 'ushort2', 'short2', 'uchar4', 'char4'], 2: ['short', 'ushort', 'half', 'uchar2', 'char2'], 1: ['char', 'uchar']}
NOCALL = bool(os.environ.get('NOCALL'))          # pred/shadow: no AIR helper calls (Metal rejects them in static initialisers)

def scalar_of(t):
    return re.sub(r'\d$', '', t)

def expr(r, depth, want=None):
    """(msl, type) of a scalar expression."""
    k = r.random()
    if depth <= 0 or k < 0.22:
        a = r.choice(list(ATOM)); e, t = a, ATOM[a]
    elif k < 0.50:                                   # conversion
        e0, t0 = expr(r, depth - 1, want)
        t = r.choice(['bool', 'char', 'uchar', 'short', 'ushort', 'int', 'uint', 'half', 'float'])
        e = f'{t}({e0})'
    elif k < 0.68:                                   # as_type pun (same size)
        e0, t0 = expr(r, depth - 1, want)
        if t0 == 'bool': e0, t0 = f'uchar({e0})', 'uchar'
        t = r.choice(PUN[SIZE[t0]])
        if t == t0: t = r.choice(PUN[SIZE[t0]])
        e = f'as_type<{t}>({e0})'
        if t[-1].isdigit():
            n = int(t[-1]); e = f'{e}.{"xyzw"[r.randrange(n)]}'; t = scalar_of(t)
    elif k < 0.80 and not (NOCALL and want == 'ctor'):   # helpers
        e0, t0 = expr(r, depth - 1, want)
        if t0 == 'bool': e0, t0 = f'int({e0})', 'int'
        if t0 in FLT:
            h = 'h' if t0 == 'half' else ''
            f = r.choice(['floor', 'ceil', 'trunc', 'round', 'rint', 'fabs', 'sign', 'saturate', 'fract', 'abs', 'copysign1', 'fmin', 'fmax', 'clamp', 'min', 'max', 'sqrt'])
            if f == 'copysign1': e = f'copysign({e0}, -1.0{h})'
            elif f in ('fmin', 'fmax', 'min', 'max'): e = f'{f}({e0}, {r.choice(["0.5", "-2.0", "300.0", "0.0"])}{h})'
            elif f == 'clamp': e = f'clamp({e0}, -1.0{h}, 2.0{h})'
            else: e = f'{f}({e0})'
            t = t0
        else:
            f = r.choice(['popcount', 'clz', 'ctz', 'abs', 'min', 'max', 'clamp', 'absdiff', 'addsat', 'subsat', 'rotate', 'reverse_bits', 'extract_bits', 'mulhi', 'hadd'])
            c = f'{t0}({r.choice(["3", "1", "0", "100"])})'
            if f in ('popcount', 'clz', 'ctz', 'reverse_bits'): e = f'{f}({e0})'
            elif f == 'abs': e = f'abs({e0})'
            elif f == 'clamp': e = f'clamp({e0}, {t0}(2), {t0}(9))'
            elif f == 'extract_bits': e = f'extract_bits({e0}, 1u, 3u)'
            elif f == 'rotate': e = f'rotate({e0}, {t0}(3))'
            else: e = f'{f}({e0}, {c})'
            t = 'u' + t0 if f in ('abs', 'absdiff') and not t0.startswith('u') else t0
            if f in ('abs', 'absdiff'): t = {'char': 'uchar', 'short': 'ushort', 'int': 'uint'}.get(t0, t0)
    elif k < 0.90:                                   # arithmetic
        e0, t0 = expr(r, depth - 1, want); e1, t1 = expr(r, depth - 1, want)
        if t0 in FLT or t1 in FLT:
            op = r.choice(['+', '-', '*'])
            t = 'float' if 'float' in (t0, t1) else 'half'
            e = f'({t}({e0}) {op} {t}({e1}))'
        else:
            op = r.choice(['+', '-', '*', '&', '|', '^', '>>', '<<'])
            if op in ('>>', '<<'): e = f'({e0} {op} {r.randint(0, 9)})'
            else: e = f'({e0} {op} {e1})'
            t = 'int'
            if 'uint' in (t0, t1): t = 'uint'
            if op in ('>>', '<<'): t = t0 if SIZE.get(t0, 4) == 4 else 'int'
    else:                                            # classification
        e0, t0 = expr(r, depth - 1, want)
        if t0 not in FLT: e0, t0 = f'{r.choice(FLT)}({e0})', 'float'
        e = f'{r.choice(["isnan", "isinf", "isfinite", "isnormal", "signbit"])}({e0})'; t = 'bool'
    return e, t

def boolify(r, e, t):
    if t == 'bool': return r.choice([e, f'!{e}'])
    k = r.random()
    if k < 0.2: return f'bool({e})'
    op = r.choice(['==', '!=', '<', '>', '<=', '>='])
    lit = r.choice(LIT[t])
    return f'({e} {op} {t}({lit}))' if t not in ('half', 'float') else f'({e} {op} {lit})'

def cond(r, want=None):
    e, t = expr(r, r.randint(1, 3), want)
    c = boolify(r, e, t)
    if r.random() < 0.3:
        bb = r.choice(["A", "B", "C", "D"]); op = r.choice(["&&", "||", "&", "|"])
        c = r.choice([f'({bb} {op} {c})', f'({c} {op} {bb})', f'({c} ? true : {bb})', f'({c} ? {bb} : false)', f'select({bb}, true, {c})'])
    return c

HEAD = '#include <metal_stdlib>\nusing namespace metal;\n' + DECL
VS = 'vertex float4 v(uint i [[vertex_id]]) { return float4(i == 1 ? 3.0 : -1.0, i == 2 ? 3.0 : -1.0, 0, 1); }\n'

def gen_pred(seed, shadow):
    r = random.Random(seed); lines = []; body = []; args = []
    for k in range(NB):
        c = cond(r, 'ctor')
        if shadow and r.random() < 0.7:
            e, t = expr(r, r.randint(1, 3), 'ctor')
            if t == 'bool': t = 'uchar'; e = f'uchar({e})'
            lines.append(f'constant {t} M{k} = {e};')
            # read the shadow back as a value and through its bytes
            if t in FLT:
                ut = 'ushort' if t == 'half' else 'uint'
                c = r.choice([f'signbit(M{k})', f'isnan(M{k})', f'isinf(M{k})', f'(as_type<{ut}>(M{k}) == {ut}({r.choice(LIT[ut])}))',
                              f'(as_type<{ut}>(M{k}) > {ut}({r.choice(LIT[ut])}))', f'(M{k} > {r.choice(LIT[t])})', f'bool(M{k})'])
            else:
                pt = r.choice([p for p in PUN[SIZE[t]] if p != t])
                pe = f'as_type<{pt}>(M{k})'
                if pt[-1].isdigit(): pe += '.' + 'xyzw'[r.randrange(int(pt[-1]))]; pt = scalar_of(pt)
                c = r.choice([f'bool(M{k})', f'(M{k} {r.choice(["==", ">", "<"])} {t}({r.choice(LIT[t])}))', boolify(r, pe, pt)])
            if r.random() < 0.3: body.append(f'  r.y += float(M{k}) * 0.0;')
        lines.append(f'constant bool Q{k} = {c};')
        args.append(f'constant float4 &b{k} [[buffer({k}), function_constant(Q{k})]]')
        body.append(f'  if (Q{k}) r.x += b{k}.x;' if r.random() < 0.6 else f'  r.x += Q{k} ? b{k}.x : 0.0;')
    return HEAD + '\n'.join(lines) + '\n' + VS + 'fragment float4 f(' + ',\n  '.join(args) + ') {\n  float4 r = 0;\n' + '\n'.join(body) + '\n  return r;\n}\n'

def gen_body(seed):
    r = random.Random(seed); body = []; args = [f'constant float4 &b{k} [[buffer({k})]]' for k in range(NB)]
    pool = list(range(NB)); r.shuffle(pool)
    while pool:
        s = r.random(); c = cond(r)
        if s < 0.3 and len(pool) >= 2: body.append(f'  r.x += {c} ? b{pool.pop()}.x : b{pool.pop()}.x;')
        elif s < 0.6: body.append(f'  if ({c}) r.x += b{pool.pop()}.x;')
        elif s < 0.8:
            e, t = expr(r, r.randint(1, 3)); k = pool.pop()
            # a value: its exact float image goes to .z (scaled so ints stay exact), .x marks the read
            body.append(f'  r.x += b{k}.x; r.z += float({e}) * 0.001;' if t != 'bool' else f'  r.x += b{k}.x; r.z += float({e});')
        else:
            k = pool.pop(); body.append(f'  r.x += b{k}.x; r.w += select(0.0, 0.5, {c});')
    return HEAD + VS + 'fragment float4 f(' + ',\n  '.join(args) + ') {\n  float4 r = 0;\n' + '\n'.join(body) + '\n  return r;\n}\n'

def sidecar(path):
    t = open(path).read()
    bad = bool(re.search(r'[:\[,](-?nan|-?inf)[,\]}]', t))
    t = re.sub(r'(?<=[:\[,])-?nan(?=[,\]}])', 'NaN', t)
    t = re.sub(r'(?<=[:\[,])inf(?=[,\]}])', 'Infinity', t)
    t = re.sub(r'(?<=[:\[,])-inf(?=[,\]}])', '-Infinity', t)
    return json.loads(t), bad

def main():
    a = sys.argv[1:]
    def opt(n, d): return type(d)(a[a.index(n) + 1]) if n in a else d
    NS, KC, SEED, J, MODE, PA = opt('--shaders', 100), opt('--cases', 10), opt('--seed', 1), opt('--jobs', 12), opt('--mode', 'pred'), opt('--allset', 0.7)
    OUTJ = os.path.join(TREE, 'results', f'fc6-{MODE}-{SEED}{"-nocall" if NOCALL else ""}{"-safe" if os.environ.get("SAFE") else ""}.json'); os.makedirs(os.path.dirname(OUTJ), exist_ok=True)
    Wd = os.path.join(HERE, 'scratch', f'{MODE}-{SEED}{"-nocall" if NOCALL else ""}{"-safe" if os.environ.get("SAFE") else ""}'); os.makedirs(Wd, exist_ok=True)
    for f in os.listdir(Wd): os.remove(os.path.join(Wd, f))
    if not os.path.exists(METAL):
        os.makedirs(os.path.dirname(METAL), exist_ok=True)
        subprocess.run(['swiftc', '-O', SWIFT, '-o', METAL], check=True, capture_output=True)
    def build(i):
        s = gen_body(SEED * 104729 + i) if MODE == 'body' else gen_pred(SEED * 104729 + i, MODE == 'shadow')
        base = os.path.join(Wd, f's{i:04d}'); open(base + '.metal', 'w').write(s)
        p = subprocess.run(['xcrun', '-sdk', 'macosx', 'metal', '-c', base + '.metal', '-o', base + '.air'], capture_output=True, text=True)
        if p.returncode: return i, p.stderr[-600:]
        subprocess.run(['xcrun', '-sdk', 'macosx', 'metallib', base + '.air', '-o', base + '.metallib'], check=True, capture_output=True)
        return i, None
    ok = []; badmsl = 0
    with ThreadPoolExecutor(J) as ex:
        for i, e in ex.map(build, range(NS)):
            if e: badmsl += 1; (badmsl <= 3 and print('bad MSL', i, e[:500]))
            else: ok.append(i)
    rnd = random.Random(SEED)
    cases = []
    for i in ok:
        cs = set()
        while len(cs) < KC:
            pu = 0.0 if rnd.random() < PA else rnd.choice([0.05, 0.15, 0.4])
            cs.add(' '.join(f'{k}=' + ('u' if rnd.random() < pu else rnd.choice(VALS[k])) for k in range(12)))
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
        i, c = ic; base = os.path.join(Wd, f's{i:04d}'); tag = re.sub(r'[^0-9a-zA-Z]', '', c.replace(' ', '_'))[:200] + str(abs(hash(c)))
        jp = f'{base}_{tag}.json'
        fc = {t.split('=')[0]: t.split('=')[1] for t in c.split() if not t.endswith('=u')}
        args = [NEW, '--quiet', '--entry', 'f', '--json', jp]
        for k, v in fc.items(): args += ['--fc', f'{k}={v}']
        q = subprocess.run(args + [base + '.air'], capture_output=True, text=True)
        if q.returncode: return ic, ('REFUSED', ((q.stdout + q.stderr).strip().splitlines() or ['?'])[-1][:400])
        try: j, badjson = sidecar(jp)
        except Exception as e: return ic, ('JSONFAIL', str(e)[:200])
        os.remove(jp)
        ub = [x for x in j['reflection']['bindings'] if x['kind'] == 'ubo']
        present = sorted(x['metal_index'] for x in ub if x['present']); used = sorted(x['metal_index'] for x in ub if x['used'])
        sc = dict(name=f's{i}', width=1, height=1, frames=1, format='rgba32f', clear=[0, 0, 0, 0],
                  vs=dict(bc=base + '.air', entry='v', function='v', fc=fc), fs=dict(bc=base + '.air', entry='f', function='f', fc=fc),
                  vertex=dict(stride=0, data=dict(floats=[]), count=3, primitive='triangle', attributes=[]),
                  buffers=dict(fragment=[dict(index=k, floats=[float(1 << k), 0.5, 0.25, 1] + [0.0] * 12) for k in range(NB)]), rt=dict(format='rgba32f'))
        sp = f'{base}_{tag}.scene.json'; op = f'{base}_{tag}.f32'; json.dump(sc, open(sp, 'w'))
        q = subprocess.run([NIREXEC, sp, op, '--frames', '1'], capture_output=True, text=True)
        if q.returncode: return ic, ('NIREXEC-FAIL', (q.stdout + q.stderr).strip()[-300:])
        px = list(struct.unpack('<4f', open(op, 'rb').read()[:16])); os.remove(sp); os.remove(op)
        return ic, (present, used, px, badjson)
    with ThreadPoolExecutor(J) as ex: got = dict(ex.map(ours, cases))
    st = dict(shaders=len(ok), bad_msl=badmsl, cases=len(cases), allset=sum(1 for _, c in cases if '=u' not in c), match=0, match_allset=0,
              refused_unset=0, refused_poison=0, refused_call=0, refused_other=0, both_refuse=0, metal_err=0, present=0, pixel=0, nirexec=0, jsonfail=0, invalid_json_sidecar=0)
    bad = []; other = []
    for ic in cases:
        m, o = metal[ic], got[ic]
        if m[0] == 'ERR':
            if o[0] == 'REFUSED': st['both_refuse'] += 1
            else: st['metal_err'] += 1
            continue
        if o[0] == 'REFUSED':
            if 'unset function constant' in o[1] and '=u' in ic[1]: st['refused_unset'] += 1
            elif 'does not fold' in o[1] and 'air.convert.' in o[1]: st['refused_poison'] += 1; other.append((ic, o[1]))
            elif 'static initialiser' in o[1]: st['refused_call'] += 1; other.append((ic, o[1]))
            else: st['refused_other'] += 1; other.append((ic, o[1]))
            continue
        if o[0] == 'JSONFAIL': st['jsonfail'] += 1; bad.append((ic, 'jsonfail', o[1])); continue
        if o[0] == 'NIREXEC-FAIL': st['nirexec'] += 1; bad.append((ic, 'nirexec', o[1])); continue
        pr, us, px, bj = o
        if bj: st['invalid_json_sidecar'] += 1
        if pr != m[0]: st['present'] += 1; bad.append((ic, 'present', pr, m[0], 'metalpx', m[2])); continue
        pxbad = any(not (x == y or (x != x and y != y) or abs(x - y) <= 1e-5 * max(1, abs(y))) for x, y in zip(px, m[2]))
        if pxbad: st['pixel'] += 1; bad.append((ic, 'pixel', px, m[2], 'used', us, 'metal_read', m[1])); continue
        st['match'] += 1
        if '=u' not in ic[1]: st['match_allset'] += 1
    json.dump(dict(stats=st, bad=[[str(x) for x in b] for b in bad], other=[[str(x) for x in b] for b in other]), open(OUTJ, 'w'), indent=1)
    print(MODE, SEED, st)
    for b in bad[:12]: print('  BAD', b)
    sys.exit(1 if bad else 0)

if __name__ == '__main__':
    main()

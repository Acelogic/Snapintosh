#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""fcrand.py - randomized differential test of UNSET function constants against Metal (verify3 item 1).

Generates random fragment functions over four function constants (bool A, B, C = indices 0..2, int N =
index 3) whose bodies branch, select, switch and combine them logically (if/else, `?:` with buffer or
constant arms, select(), switch with and without default and fallthrough, loop-guarded branches that
cannot become selects, nested ifs, is_function_constant_defined, presence predicates gating buffer
arguments, and a few statements that use a constant's VALUE).  Each shader is specialised with a
sample of the 135 set/unset combinations (0=u|0|1 1=.. 2=.. 3=u|0..3) and compared with Metal on
this Mac:
  - present set: Metal's reflection vs ours (bindings[].present);
  - read set:    buffer k holds float4(2^k, 0, 0, 1) and every statement adds bk.x, so the red channel
                 of Metal's render is the set of buffers Metal's specialised code reads; ours is the
                 set of ubo bindings with used = true;
  - pixel:       our NIR on llvmpipe (build/nirexec) must render the same pixel as Metal (red, and the
                 value statements in green/blue/alpha);
  - refusals:    ABI v4/v5 refuse a variant in which an unset constant decides anything in the body
                 ("the value of unset function constant X decides a branch / reaches ...") or a presence
                 predicate depends on an unset constant's value (ABI v5, "the presence predicate ..."); such a case
                 passes, any other refusal fails.  Every case that compiles must match Metal exactly.
  python3 tests/fcrand.py [--shaders N] [--cases K] [--seed S] [--jobs J] [--out results/fcrand.json]
"""
import json, os, random, re, struct, subprocess, sys, time
from concurrent.futures import ThreadPoolExecutor
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
NEW = os.path.join(ROOT, 'build', 'air2ir3'); NIREXEC = os.path.join(ROOT, 'build', 'nirexec')
NB = 12
ALL_CASES = [f'0={a} 1={b} 2={c} 3={n}' for a in 'u01' for b in 'u01' for c in 'u01' for n in 'u0123']

class Gen:
    def __init__(self, rnd): self.r = rnd
    def ie(self, glob=False):
        r = self.r
        opts = ['N', '(N + 1)', '(N * 2)', '(N - 1)', '(A ? N : 1)', '(B ? 2 : N)', '(N & 3)', '(N % 3)', '(N >> 1)', '(3 - N)']
        if not glob: opts += ['abs(N - 2)', 'min(N, 2)', 'max(N, 1)']
        e = r.choice(opts); return e, {'N'} | ({'A'} if 'A' in e else set()) | ({'B'} if 'B' in e else set())
    def atom(self, preds, glob=False):
        r = self.r; k = r.random()
        if k < 0.35:
            v = r.choice('ABC'); return (('!' if r.random() < 0.3 else '') + v), {v}
        if k < 0.7:
            e, d = self.ie(glob); op = r.choice(['==', '!=', '>', '<', '>=', '<=']); return f'({e} {op} {r.randint(-1, 4)})', d
        if k < 0.78:
            v = r.choice('ABCN'); return f'is_function_constant_defined({v})', set()
        if k < 0.85: return '((N & 1) != 0)', {'N'}
        if preds and k < 0.95:
            q = r.choice(preds); return q[0], q[1]
        return r.choice(['true', 'false']), set()
    def be(self, depth=2, preds=(), glob=False):
        r = self.r
        if depth == 0 or r.random() < 0.35: return self.atom(list(preds), glob)
        k = r.random()
        x, dx = self.be(depth - 1, preds, glob); y, dy = self.be(depth - 1, preds, glob)
        if k < 0.3: return f'({x} && {y})', dx | dy
        if k < 0.6: return f'({x} || {y})', dx | dy
        if k < 0.7: return f'({x} != {y})', dx | dy
        if k < 0.78: return f'({x} == {y})', dx | dy
        if k < 0.88: return f'!({x})', dx
        z, dz = self.be(depth - 1, preds, glob); return f'({x} ? {y} : {z})', dx | dy | dz

def gen_shader(seed):
    r = random.Random(seed); g = Gen(r)
    pool = list(range(NB)); r.shuffle(pool)
    npred = r.choice([0, 1, 1, 2, 3])
    preds, gated, lines = [], {}, []
    for j in range(npred):
        e, d = g.be(2, (), glob=True); preds.append((f'Q{j}', d)); lines.append(f'constant bool Q{j} = {e};')
    for j in range(npred):
        if pool and r.random() < 0.8: gated[pool.pop()] = j
    body, value_deps = [], set()
    def b(k): return f'b{k}.x'
    for k, j in gated.items():
        if r.random() < 0.5: body.append(f'  if (Q{j}) r.x += {b(k)};')
        else:
            e, d = g.be(1, preds); body.append(f'  if (Q{j} && {e}) r.x += {b(k)};')
    while pool:
        shape = r.random(); e, d = g.be(2, preds)
        if shape < 0.12: body.append(f'  if ({e}) r.x += {b(pool.pop())};')
        elif shape < 0.24 and len(pool) >= 2: body.append(f'  if ({e}) r.x += {b(pool.pop())}; else r.x += {b(pool.pop())};')
        elif shape < 0.34 and len(pool) >= 2: body.append(f'  r.x += {e} ? {b(pool.pop())} : {b(pool.pop())};')
        elif shape < 0.40: body.append(f'  r.x += {e} ? 0.0 : {b(pool.pop())};')
        elif shape < 0.46: body.append(f'  r.x += {e} ? {b(pool.pop())} : 0.0;')
        elif shape < 0.54 and len(pool) >= 2: body.append(f'  r.x += select(b{pool.pop()}, b{pool.pop()}, {e}).x;')
        elif shape < 0.66 and len(pool) >= 2:
            ie, _ = g.ie(); vals = r.sample(range(-1, 5), r.randint(1, 3)); arms = []
            for v in vals:
                if not pool: break
                arms.append(f'case {v}: r.x += {b(pool.pop())};' + ('' if r.random() < 0.2 else ' break;'))
            if pool and r.random() < 0.7: arms.append(f'default: r.x += {b(pool.pop())}; break;')
            body.append(f'  switch ({ie}) {{ ' + ' '.join(arms) + ' }')
        elif shape < 0.76:
            k = pool.pop()
            if pool and r.random() < 0.5:
                k2 = pool.pop()
                body.append(f'  if ({e}) {{ for (int i = 0; i < int(b{k}.w); i++) r.x += {b(k)}; }} else {{ for (int i = 0; i < int(b{k2}.w); i++) r.x += {b(k2)}; }}')
            else: body.append(f'  if ({e}) {{ for (int i = 0; i < int(b{k}.w); i++) r.x += {b(k)}; }}')
        elif shape < 0.84 and len(pool) >= 2:
            e2, _ = g.be(1, preds)
            body.append(f'  if ({e}) {{ if ({e2}) r.x += {b(pool.pop())}; else r.x += {b(pool.pop())}; }}')
        elif shape < 0.90: body.append(f'  r.x += ({e} ? b{pool.pop()} : float4(0)).x;')
        else: body.append(f'  if ({e}) r.x += {b(pool.pop())};')
    # value statements (green/blue/alpha): the constant's value reaches the output
    for _ in range(r.choice([0, 0, 1, 2])):
        k = r.random(); ch = r.choice('yzw')
        if k < 0.3: ie, d = g.ie(); body.append(f'  r.{ch} += float({ie}) * 0.5;'); value_deps |= d
        elif k < 0.6: e, d = g.be(1, preds); body.append(f'  r.{ch} += {e} ? 1.5 : 2.25;'); value_deps |= d
        else: e, d = g.be(1, preds); body.append(f'  r.{ch} += float({e}) * 0.75;'); value_deps |= d
    # predicates used in the value expressions depend on their constants
    for q, d in preds:
        if any(q in l for l in body if 'r.y' in l or 'r.z' in l or 'r.w' in l): value_deps |= d
    args = []
    for k in range(NB):
        args.append(f'constant float4 &b{k} [[buffer({k})' + (f', function_constant(Q{gated[k]})' if k in gated else '') + ']]')
    src = ('#include <metal_stdlib>\nusing namespace metal;\n'
           'constant bool A [[function_constant(0)]];\nconstant bool B [[function_constant(1)]];\n'
           'constant bool C [[function_constant(2)]];\nconstant int N [[function_constant(3)]];\n' + '\n'.join(lines) + '\n'
           'vertex float4 v(uint i [[vertex_id]]) { return float4(i == 1 ? 3.0 : -1.0, i == 2 ? 3.0 : -1.0, 0, 1); }\n'
           'fragment float4 f(' + ',\n                  '.join(args) + ') {\n  float4 r = 0;\n' + '\n'.join(body) + '\n  return r;\n}\n')
    return src, sorted(value_deps)

NAMES = {'A': 0, 'B': 1, 'C': 2, 'N': 3}
def unset_in(case, deps):
    toks = dict(t.split('=') for t in case.split())
    return [d for d in deps if toks[str(NAMES[d])] == 'u']

def main():
    a = sys.argv[1:]
    def opt(n, d): return type(d)(a[a.index(n) + 1]) if n in a else d
    NS, K, SEED, J = opt('--shaders', 400), opt('--cases', 24), opt('--seed', 1), opt('--jobs', 12)
    OUTJ = opt('--out', os.path.join(ROOT, 'results', 'fcrand.json'))
    global W
    W = os.path.join(ROOT, 'build', 'fcrand-' + os.path.splitext(os.path.basename(OUTJ))[0])
    os.makedirs(W, exist_ok=True)
    for f in os.listdir(W): os.remove(os.path.join(W, f))
    t0 = time.time()
    exe = os.path.join(ROOT, 'build', 'tests', 'fcrand')
    src = os.path.join(ROOT, 'tests', 'fixtures', 'fcrand.swift')
    if not os.path.exists(exe) or os.path.getmtime(exe) < os.path.getmtime(src):
        os.makedirs(os.path.dirname(exe), exist_ok=True)
        subprocess.run(['swiftc', '-O', src, '-o', exe], check=True, capture_output=True)
    shaders = {}
    def build(i):
        s, deps = gen_shader(SEED * 100003 + i)
        base = os.path.join(W, f's{i:04d}')
        open(base + '.metal', 'w').write(s)
        p = subprocess.run(['xcrun', '-sdk', 'macosx', 'metal', '-c', base + '.metal', '-o', base + '.air'], capture_output=True, text=True)
        if p.returncode: return i, None, p.stderr[-300:]
        subprocess.run(['xcrun', '-sdk', 'macosx', 'metallib', base + '.air', '-o', base + '.metallib'], check=True, capture_output=True)
        return i, deps, None
    with ThreadPoolExecutor(J) as ex:
        for i, deps, e in ex.map(build, range(NS)):
            if e is None: shaders[i] = deps
            else: print('generator produced invalid MSL', i, e)
    rnd = random.Random(SEED)
    cases = []
    for i in sorted(shaders):
        cs = [ALL_CASES[0]] + rnd.sample(ALL_CASES[1:], K - 1)
        cases += [(i, c) for c in cs]
    t1 = time.time()
    p = subprocess.run([exe], input='\n'.join(f"{os.path.join(W, f's{i:04d}.metallib')}\t{c}" for i, c in cases) + '\n',
                       capture_output=True, text=True, check=True)
    metal = {}
    for l in p.stdout.splitlines():
        key, res = l.split(' -> ', 1)
        path, c = key.split('\t')
        i = int(os.path.basename(path)[1:5])
        if res.startswith('ERR'): metal[(i, c)] = ('ERR', res); continue
        m = re.match(r'(\[.*?\]) px (\S+) (\S+) (\S+) (\S+)', res)
        px = [struct.unpack('<f', struct.pack('<I', int(h, 16)))[0] for h in m.groups()[1:]]
        rd = int(px[0]); metal[(i, c)] = (json.loads(m.group(1)), sorted(k for k in range(NB) if rd >> k & 1), px)
    t2 = time.time()
    def ours(ic):
        i, c = ic
        base = os.path.join(W, f's{i:04d}'); tag = c.replace(' ', '_').replace('=', '')
        jp = f'{base}_{tag}.json'
        fc = {t.split('=')[0]: int(t.split('=')[1]) for t in c.split() if not t.endswith('=u')}
        args = [NEW, '--quiet', '--entry', 'f', '--json', jp]
        for k, v in fc.items(): args += ['--fc', f'{k}={v}']
        q = subprocess.run(args + [base + '.air'], capture_output=True, text=True)
        if q.returncode:
            return ic, ('REFUSED', ((q.stdout + q.stderr).strip().splitlines() or [f'rc {q.returncode}'])[-1][:300])
        j = json.load(open(jp)); os.remove(jp)
        ub = [b for b in j['reflection']['bindings'] if b['kind'] == 'ubo']
        present = sorted(b['metal_index'] for b in ub if b['present']); used = sorted(b['metal_index'] for b in ub if b['used'])
        sc = dict(name=f's{i}', width=1, height=1, frames=1, format='rgba32f', clear=[0, 0, 0, 0],
                  vs=dict(bc=base + '.air', entry='v', function='v'), fs=dict(bc=base + '.air', entry='f', function='f', fc=fc),
                  vertex=dict(stride=0, data=dict(floats=[]), count=3, primitive='triangle', attributes=[]),
                  buffers=dict(fragment=[dict(index=k, floats=[float(1 << k), 0, 0, 1]) for k in range(NB)]), rt=dict(format='rgba32f'))
        sp = f'{base}_{tag}.scene.json'; op = f'{base}_{tag}.f32'
        json.dump(sc, open(sp, 'w'))
        q = subprocess.run([NIREXEC, sp, op, '--frames', '1'], capture_output=True, text=True)
        if q.returncode: return ic, ('NIREXEC-FAIL', (q.stdout + q.stderr).strip()[-300:])
        px = list(struct.unpack('<4f', open(op, 'rb').read()[:16])); os.remove(sp); os.remove(op)
        return ic, (present, used, px)
    with ThreadPoolExecutor(J) as ex: got = dict(ex.map(ours, cases))
    t3 = time.time()
    stats = dict(shaders=len(shaders), cases=len(cases), metal_err=0, match=0, refused=0, refused_why={}, refused_unexpected=0,
                 present_mismatch=0, read_mismatch=0, pixel_mismatch=0, nirexec_fail=0)
    bad = []
    for ic in cases:
        m, o = metal[ic], got[ic]
        i, c = ic; deps = shaders[i]
        if m[0] == 'ERR':
            stats['metal_err'] += 1; bad.append((ic, 'metal ERR', m[1][:200], o[0] if o[0] == 'REFUSED' else '')); continue
        if o[0] == 'REFUSED':
            if 'unset function constant' in o[1] and 'u' in c:
                stats['refused'] += 1; why = re.search(r'constant .*? (decides a \w+|reaches[\w ]*?) in the function body', o[1]) or re.search(r'(presence predicate)', o[1])
                stats['refused_why'][why.group(1) if why else '?'] = stats['refused_why'].get(why.group(1) if why else '?', 0) + 1
            else: stats['refused_unexpected'] += 1; bad.append((ic, 'refused', o[1]))
            continue
        if o[0] == 'NIREXEC-FAIL': stats['nirexec_fail'] += 1; bad.append((ic, 'nirexec', o[1])); continue
        present, used, px = o
        if present != m[0]: stats['present_mismatch'] += 1; bad.append((ic, 'present', present, m[0])); continue
        if used != m[1]: stats['read_mismatch'] += 1; bad.append((ic, 'read', used, m[1])); continue
        if any(abs(x - y) > 1e-5 * max(1, abs(y)) or (x != x) != (y != y) for x, y in zip(px, m[2])):
            stats['pixel_mismatch'] += 1; bad.append((ic, 'pixel', px, m[2])); continue
        stats['match'] += 1
    stats['seconds'] = dict(build=round(t1 - t0), metal=round(t2 - t1), ours=round(t3 - t2))
    compared = stats['cases'] - stats['metal_err']
    unset_cases = sum(1 for i, c in cases if 'u' in c)
    stats['summary'] = (f"{stats['match']}/{compared} cases match Metal (present + read + pixel) and {stats['refused']} are refused "
                        f"because an unset constant would decide something in the body ({stats['refused_why']}); "
                        f"{stats['refused_unexpected']} other refusals, {stats['present_mismatch']} present / {stats['read_mismatch']} read / "
                        f"{stats['pixel_mismatch']} pixel mismatches, {stats['metal_err']} Metal errors; {stats['shaders']} shaders, "
                        f"{unset_cases} cases with an unset constant, seed {SEED}")
    json.dump(dict(stats=stats, bad=[[str(x) for x in b] for b in bad]), open(OUTJ, 'w'), indent=1)
    print(stats['summary']); print(stats['seconds'])
    for b in bad[:25]: print('  ', b)
    ok = stats['match'] + stats['refused'] == compared and stats['metal_err'] == 0
    sys.exit(0 if ok else 1)

if __name__ == '__main__':
    main()

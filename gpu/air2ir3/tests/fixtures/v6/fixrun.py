# SPDX-License-Identifier: MIT
# fixrun.py <base (no ext; .air + .metallib exist)> <cases file: one "i=v ..." per line> [BIN=...]: Metal vs ours (presence, pixel)
import json, os, re, struct, subprocess, sys
from concurrent.futures import ThreadPoolExecutor
# fix round 6: verify6's runner, pointed at this tree (BIN / NX / MT override; nirexec accepts string values since round 6)
T = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..', '..'))
BIN = os.environ.get('BIN') or T + '/build/air2ir3'; NX = os.environ.get('NX') or T + '/build/nirexec'; MT = os.environ.get('MT') or T + '/build/tests/fcv5metal'
base, cf = sys.argv[1], sys.argv[2]
cases = [l.strip() for l in open(cf) if l.strip()]
out = subprocess.run([MT], input=''.join(f'{base}.metallib\t{c}\n' for c in cases), capture_output=True, text=True).stdout.splitlines()
metal = {}
for l in out:
    k, r = l.split(' -> ', 1); c = k.split('\t')[1]
    if r.startswith('ERR'): metal[c] = None; continue
    m = re.match(r'(\[.*?\]) px (\S+)', r); metal[c] = (json.loads(m.group(1)), struct.unpack('<f', struct.pack('<I', int(m.group(2), 16)))[0])
def ours(c):
    tag = str(abs(hash(c))); fc = {t.split('=')[0]: t.split('=')[1] for t in c.split() if not t.endswith('=u')}
    args = [BIN, '--quiet', '--entry', 'f', '--json', f'{base}_{tag}.json']
    for k, v in fc.items(): args += ['--fc', f'{k}={v}']
    q = subprocess.run(args + [base + '.air'], capture_output=True, text=True)
    if q.returncode: return c, ('REFUSED', (q.stdout + q.stderr).strip().splitlines()[-1][:200])
    t = open(f'{base}_{tag}.json').read(); os.remove(f'{base}_{tag}.json')
    t = re.sub(r'(?<=[:\[,])-?nan(?=[,\]}])', 'NaN', t); t = re.sub(r'(?<=[:\[,])(-?)inf(?=[,\]}])', r'\1Infinity', t)
    j = json.loads(t); pr = sorted(b['metal_index'] for b in j['reflection']['bindings'] if b['kind'] == 'ubo' and b['present'])
    sc = dict(name='r', width=1, height=1, frames=1, format='rgba32f', clear=[0, 0, 0, 0],
              vs=dict(bc=base + '.air', entry='v', function='v', fc=fc), fs=dict(bc=base + '.air', entry='f', function='f', fc=fc),
              vertex=dict(stride=0, data=dict(floats=[]), count=3, primitive='triangle', attributes=[]),
              buffers=dict(fragment=[dict(index=k, floats=[float(1 << k), 0.5, 0.25, 1] + [0.0] * 12) for k in range(16)]), rt=dict(format='rgba32f'))
    json.dump(sc, open(f'{base}_{tag}.scene.json', 'w'))
    subprocess.run([NX, f'{base}_{tag}.scene.json', f'{base}_{tag}.f32', '--frames', '1'], capture_output=True)
    px = struct.unpack('<f', open(f'{base}_{tag}.f32', 'rb').read()[:4])[0]; os.remove(f'{base}_{tag}.f32'); os.remove(f'{base}_{tag}.scene.json')
    return c, (pr, px)
with ThreadPoolExecutor(12) as ex: got = dict(ex.map(ours, cases))
n = dict(match=0, refused=0, metal_err=0, present=0, pixel=0)
for c in cases:
    m, o = metal[c], got[c]
    if m is None: n['metal_err'] += 1; continue
    if o[0] == 'REFUSED': n['refused'] += 1; print('REFUSED', c, o[1]); continue
    if o[0] != m[0]: n['present'] += 1; print('PRESENT', c, 'ours', o[0], 'metal', m[0]); continue
    if o[1] != m[1]: n['pixel'] += 1; print('PIXEL', c, 'ours', o[1], 'metal', m[1]); continue
    n['match'] += 1
print(os.path.basename(base), n)

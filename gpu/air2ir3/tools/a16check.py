#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""a16check.py - this compiler against the ir3 variants that ran on the A16 (fix round 6).

tools/a16ref/render-shaders.pinned.json is a copy of q1n1's tools/a16gpu-render/render-shaders.json
(sha256 8bb658df..., the set of A16 render run 2: fix4 + adreno-render-fix/air2ir3-abi6-final.patch,
compiler air2ir3-src-a51400fcd94cea44); tools/a16ref/probes.air is q1n1's pinned probe module.  q1n1 is
not touched: both are copies.  For every pipeline and stage the pinned record names the air2ir3
arguments; this compiles the same bitcode with the same arguments and compares the blob (ir3_store_variant)
with the pinned blob_sha256.  A difference is shown as a disassembly diff.

  python3 tools/a16check.py [--bin build/air2ir3] [--ref <the A16 run-2 compiler>]   -> results/a16check.json
With --ref (adreno-render-fix/work/fix4abi6/build/air2ir3, whose blobs are the pinned ones), a differing
stage gets the disassembly diff (ref -> this build).
"""
import difflib, hashlib, json, os, subprocess, sys
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REF = os.path.join(ROOT, 'tools', 'a16ref')
BIN = sys.argv[sys.argv.index('--bin') + 1] if '--bin' in sys.argv else os.path.join(ROOT, 'build', 'air2ir3')
REFBIN = sys.argv[sys.argv.index('--ref') + 1] if '--ref' in sys.argv else None
SCR = os.path.join(ROOT, 'scratch', 'a16check'); os.makedirs(SCR, exist_ok=True)
pinned = json.load(open(os.path.join(REF, 'render-shaders.pinned.json'))) if os.path.exists(os.path.join(REF, 'render-shaders.pinned.json')) else sys.exit('tools/a16ref/render-shaders.pinned.json is compiled from Apple shaders and not distributed: generate it locally ''(q1n1 tools/a16gpu-render) and copy it there; build probes.air with tools/a16ref/build-probes-air.sh')

def sha(p): return hashlib.sha256(open(p, 'rb').read()).hexdigest()

def dis(b, blob):
    return subprocess.run([b, '--verify-variant', blob], capture_output=True, text=True).stdout.splitlines()

rows, out = [], {}
for name in pinned['order']:
    p = pinned['pipelines'][name]
    for st in ('vs', 'fs'):
        rec = p['compile'][st]
        fn = p['vs_function' if st == 'vs' else 'fs_function']
        bc = os.path.join(REF, 'probes.air') if p['lib'] == 'Probe' else os.path.join(ROOT, 'corpus', p['lib'], fn + '.bc')
        tag = f'{name}.{st}'
        blob, side = os.path.join(SCR, tag + '.ir3v'), os.path.join(SCR, tag + '.json')
        r = subprocess.run([BIN] + rec['args'] + ['--json', side, '--variant', blob, bc], capture_output=True, text=True)
        if r.returncode:
            res = dict(status='refused', error=(r.stdout + r.stderr).strip().splitlines()[-1][:300])
        else:
            same = sha(blob) == rec['blob_sha256']
            res = dict(status='identical' if same else 'differs', blob_sha256=sha(blob), pinned=rec['blob_sha256'])
            if not same:
                res['instrs_new'] = json.load(open(side))['ir3']['stats']['instrs']
                if REFBIN:
                    rb = os.path.join(SCR, tag + '.ref.ir3v')
                    subprocess.run([REFBIN] + rec['args'] + ['--variant', rb, bc], capture_output=True, check=True)
                    res['ref_reproduces_pinned'] = sha(rb) == rec['blob_sha256']
                    res['disasm_diff'] = list(difflib.unified_diff(dis(REFBIN, rb), dis(BIN, blob), 'A16 run 2', 'this build', lineterm='', n=1))
        out[tag] = res
        rows.append((tag, res['status'], res.get('error', '')))
json.dump(dict(pinned_sha256=sha(os.path.join(REF, 'render-shaders.pinned.json')), compiler=subprocess.run([BIN, '--compiler-id'], capture_output=True, text=True).stdout.strip(),
               stages=out), open(os.path.join(ROOT, 'results', 'a16check.json'), 'w'), indent=1)
from collections import Counter
print(Counter(s for _, s, _ in rows))
for t, s, e in rows:
    if s != 'identical':
        print(f'  {t:40s} {s} {e}')
        for l in out[t].get('disasm_diff') or []: print('      ' + l)

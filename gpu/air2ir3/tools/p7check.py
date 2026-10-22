#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""p7check.py - does this compiler still produce the A16-verified P7 shaders?

The A16 Stage 3 P7 run (q1n1 docs/A16-ADRENO-STAGE3.md, run 3) drew SkyLight SimpleVertex +
SimpleTextureFragment, compiled by fix round 1; q1n1 pins that tools/a16gpu-p7/p7-shaders.json by
SHA-256 (88aab4e2...).  Fix round 2 changed one bit of the fragment code ((eq) on instruction 1,
JSON d0c5fe3d...).  This regenerates the JSON from THIS tree and compares it, per stage, with both:
code bytes, the fields the command stream programs, and the disassembly.

q1n1 itself is never touched: tools/p7ref/ holds a copy of its make-p7-shaders.sh +
export_p7_shaders.cpp and of the pinned JSON (taken read-only by the round-3 verifier into
../verify3/work/p7/tool/), plus the round-2 output (../fix2/scratch/p7/p7-shaders.json).
  python3 tools/p7check.py -> results/p7check.json"""
import hashlib, json, os, subprocess, sys
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REF = os.path.join(ROOT, 'tools', 'p7ref')
out = os.path.join(ROOT, 'scratch', 'p7'); os.makedirs(out, exist_ok=True)
p = subprocess.run(['zsh', os.path.join(REF, 'make-p7-shaders.sh')], env=dict(os.environ, AIR2IR3_TREE=ROOT, OUT=out),
                   capture_output=True, text=True)
if p.returncode: sys.exit(p.stdout[-800:] + p.stderr[-800:])
new = os.path.join(out, 'p7-shaders.json')
sha = lambda f: hashlib.sha256(open(f, 'rb').read()).hexdigest()
res = dict(new_sha256=sha(new), against={})
b = json.load(open(new))
for tag, f in [(t, f) for t, f in (('pinned (A16 run 3)', 'p7-shaders.pinned.json'), ('round 2', 'p7-shaders.round2.json')) if os.path.exists(os.path.join(REF, f)) or print(f'skip {t}: tools/p7ref/{f} is compiled from Apple shaders and not distributed; generate it locally with tools/p7ref/make-p7-shaders.sh')]:
    a = json.load(open(os.path.join(REF, f)))
    r = dict(sha256=sha(os.path.join(REF, f)), stages={})
    for st in ('vs', 'vs_binning', 'fs'):
        x, y = a[st], b[st]
        A, B = bytes.fromhex(x['code_hex']), bytes.fromhex(y['code_hex'])
        diffs = [dict(instr=i // 8, old=A[i:i + 8][::-1].hex(), new=B[i:i + 8][::-1].hex()) for i in range(0, max(len(A), len(B)), 8) if A[i:i + 8] != B[i:i + 8]]
        fields = {k: [x[k], y.get(k)] for k in x if k not in ('sidecar', 'code_hex', 'disasm') and x[k] != y.get(k)}
        r['stages'][st] = dict(code_identical=not diffs, code_bytes=len(B), code_diffs=diffs, field_changes=fields,
                               disasm_changes=[(l0, l1) for l0, l1 in zip(x['disasm'].splitlines(), y['disasm'].splitlines()) if l0 != l1])
    r['link_identical'] = a['link_vs_fs'] == b['link_vs_fs']
    res['against'][tag] = r
json.dump(res, open(os.path.join(ROOT, 'results', 'p7check.json'), 'w'), indent=1)
for tag, r in res['against'].items():
    print(f'-- vs {tag} ({r["sha256"][:8]})')
    for st, s in r['stages'].items():
        print(f"{st:10s} code {'identical' if s['code_identical'] else 'DIFFERS'} ({s['code_bytes']} bytes); fields {s['field_changes'] or 'same'}; "
              f"disasm {s['disasm_changes'] or 'same'}")
    print('link_vs_fs', 'identical' if r['link_identical'] else 'DIFFERS')
print('json sha256', res['new_sha256'][:8])

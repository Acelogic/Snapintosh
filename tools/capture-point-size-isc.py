#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Read the ISC at idle generation72 after the generation72 snapshot; no SSD writes.

Derived from capture-shader-cache-isc-gen69.py. `tools/cycle.py storage` read the
persistence (c0336e9d) and took the snapshot (9093b77b) at idle generation72,
after the generation71 run was retired on the regular stage pair (retirement
65741fbf). The last SSD apply was the shader-cache package (24d4c7ff, apply
846553ea, header after 5e6fa734), so its manifest supplies the disk layout.

Stage binding preflight (both --check and a real run, before any connection):
the native hash helper binds this checkout's own q1n1 stage build first, so the
stage the last retirement chainloaded must be q1n1/build/uefi's stage binary
for the slot.

Failure inventory: stale generation, changed snapshot/persistence evidence,
incorrect disk identity, partial read, copy/hash mismatch, SError, or a running
stage the native hash helper cannot bind to.
"""
from pathlib import Path
import hashlib
import json

ROOT = Path(__file__).resolve().parents[1]
Q1N1 = ROOT.parent / 'q1n1'
RETIREMENT = ROOT / 'build/installed-metal-integrated-guestes-2400s-20260928-retirement-v1.json'
RETIREMENT_SHA = '65741fbfc298cfce469ee2f8c4cef495d984da50688cc6fc0b431610e2b8ebf3'
sha = lambda p: hashlib.sha256(Path(p).read_bytes()).hexdigest()
retired = json.loads(RETIREMENT.read_text())
assert sha(RETIREMENT) == RETIREMENT_SHA
assert retired['status'] == 'GENERATION72_IDLE' and not retired['ssd_writes'] and retired['generation'] == 71
assert retired['after']['stage_generation'] == 72 and retired['after']['image_base'] == retired['target_base'] == 0xb0800000
local = Q1N1 / 'build/uefi/q1n1-stage-alt.bin'
if sha(local) != retired['chosen_stage']['sha256']:
    raise SystemExit(json.dumps(dict(status='REFUSED_STAGE_BINDING', hardware_access=False,
        running_stage=retired['chosen_stage'], native_hash_elf=str(Q1N1 / 'build/uefi/stage/hardware-alt.elf'),
        native_hash_stage=dict(path=str(local), sha256=sha(local)),
        reason='the A16 runs a stage whose text the q1n1 native hash helper cannot bind; '
               'NativeHash would refuse after the ISC read')))
base = ROOT / 'build/capture-metal-raw-sign-isc-20260927.py'
assert hashlib.sha256(base.read_bytes()).hexdigest() == 'b44ef6b0d439a2f2a6124b35fa6c2332e496c4125c04048860a5efd45454e9be'
source = base.read_text()
changes = {
    "base = Path(__file__).with_name('capture-installed-metal-isc-20260926.py')":
        "base = ROOT / 'build/capture-installed-metal-isc-20260926.py'",
    'installed-metal-raw-sign-3600s-20260927': 'installed-metal-integrated-guestes-2400s-20260928',
    '3eb863e803be5b9436156d025b88bfbc3a3d317620d2276fbd123b40a587ac9e': 'c0336e9d6eb9703a19926219ba2d350ea3e218e422c704109229fdb9501c71ce',
    'raw-sign-report-snapshot-v1': '../installed-metal-integrated-guestes-2400s-20260928-snapshot-v1',
    'raw-sign-isc-v1': 'isc-v1',
    "persistence['bootinfo']['stage_generation']==45": "persistence['bootinfo']['stage_generation']==72",
    "snapshot['generation']==45": "snapshot['generation']==72",
    "\"info['stage_generation']==45\"": "\"info['stage_generation']==72\"",
    'generation=45': 'generation=72',
    'Generation45 ISC': 'Generation72 ISC',
}
for old, new in changes.items():
    assert source.count(old) == (2 if old == 'raw-sign-report-snapshot-v1' else 1), old
    source = source.replace(old, new)
assert '==45' not in source
anchor = "code = compile(source, str(base), 'exec')"
assert source.count(anchor) == 1
extra = {
    "BASE=ROOT/'build/installed-metal-20260926'": "BASE=ROOT/'build/point-size-deploy-gen72-20260928'",
    "manifest=json.loads((BASE/'bootstrap-delta-v2/manifest.json').read_text())":
        "manifest=json.loads((ROOT.parent/'Snapintosh-shaders/build/shader-cache-deploy-20260928/delta-v1/manifest.json').read_text())",
    "assert status==0 and 'on AC' in battery['text']": "assert status==0 and battery['plausible'] and (battery['ac'] or battery['percent']>=30)",
}
injected = ''.join(f'assert source.count({old!r}) == 1, {old!r}\nsource = source.replace({old!r}, {new!r})\n' for old, new in extra.items())
source = source.replace(anchor, injected + anchor)
exec(compile(source, str(base), 'exec'), dict(__file__=__file__, __name__='__main__', ROOT=ROOT))

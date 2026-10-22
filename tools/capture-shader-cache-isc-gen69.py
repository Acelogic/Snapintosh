#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Read the ISC at idle generation69 after the generation69 snapshot; no SSD writes.

Derived from capture-shader-cache-isc.py (generation68). The A16 went idle
67 -> 68 (early-stop stage pair) -> 69 (regular stage pair) with no guest and no
SSD writes. The persistence was read at generation67 (ee3e8c5b); the snapshot
was taken at generation69 by tools/storage-gen69-idle.py and binds that
persistence and both idle retirements.

Stage binding preflight (both --check and a real run, before any connection):
q1n1/tools/nvme_hash.py places its helper in the running stage's slot only when
the running .text equals q1n1/build/uefi/stage/hardware[-alt].elf, so the stage
the last retirement chainloaded must be that checkout's stage binary for the slot.

Failure inventory: stale generation, changed snapshot/persistence evidence,
incorrect disk identity, partial read, copy/hash mismatch, SError, or a running
stage the native hash helper cannot bind to.
"""
from pathlib import Path
import hashlib
import json

ROOT = Path(__file__).resolve().parents[1]
Q1N1 = ROOT.parent / 'q1n1'
RETIREMENT = ROOT / 'build/idle-gen68-regular-stage-20260928-retirement-v1.json'
RETIREMENT_SHA = 'd7329b8dce68bfd1f651ed958313e50fe80e00003af97ef1053890e4b15c47b0'
sha = lambda p: hashlib.sha256(Path(p).read_bytes()).hexdigest()
retired = json.loads(RETIREMENT.read_text())
assert sha(RETIREMENT) == RETIREMENT_SHA
assert retired['status'] == 'GENERATION69_IDLE' and not retired['ssd_writes'] and retired['generation'] == 68
assert retired['after']['stage_generation'] == 69 and retired['after']['image_base'] == retired['target_base'] == 0xb0000000
local = Q1N1 / 'build/uefi/q1n1-stage.bin'
if sha(local) != retired['chosen_stage']['sha256']:
    raise SystemExit(json.dumps(dict(status='REFUSED_STAGE_BINDING', hardware_access=False,
        running_stage=retired['chosen_stage'], native_hash_elf=str(Q1N1 / 'build/uefi/stage/hardware.elf'),
        native_hash_stage=dict(path=str(local), sha256=sha(local)),
        reason='the A16 runs a stage whose text the q1n1 native hash helper cannot bind; '
               'NativeHash would refuse after the ISC read')))
base = ROOT / 'build/capture-metal-raw-sign-isc-20260927.py'
assert hashlib.sha256(base.read_bytes()).hexdigest() == 'b44ef6b0d439a2f2a6124b35fa6c2332e496c4125c04048860a5efd45454e9be'
source = base.read_text()
changes = {
    "base = Path(__file__).with_name('capture-installed-metal-isc-20260926.py')":
        "base = ROOT / 'build/capture-installed-metal-isc-20260926.py'",
    'installed-metal-raw-sign-3600s-20260927': 'installed-metal-ca-memo-2400s-20260928',
    '3eb863e803be5b9436156d025b88bfbc3a3d317620d2276fbd123b40a587ac9e': 'ee3e8c5bba606d43bf12d1c4b06071592becbcd167946dddd26add8dc5492863',
    'raw-sign-report-snapshot-v1': '../ca-memo-deploy-20260928/snapshot-gen69-v1',
    'raw-sign-isc-v1': 'isc-v1',
    "persistence['bootinfo']['stage_generation']==45": "persistence['bootinfo']['stage_generation']==67",
    "snapshot['generation']==45": "snapshot['generation']==69",
    "\"info['stage_generation']==45\"": "\"info['stage_generation']==69\"",
    'generation=45': 'generation=69',
    'Generation45 ISC': 'Generation69 ISC',
}
for old, new in changes.items():
    assert source.count(old) == (2 if old == 'raw-sign-report-snapshot-v1' else 1), old
    source = source.replace(old, new)
assert '==45' not in source
anchor = "code = compile(source, str(base), 'exec')"
assert source.count(anchor) == 1
extra = {
    "BASE=ROOT/'build/installed-metal-20260926'": "BASE=ROOT/'build/shader-cache-deploy-gen69-20260928'",
    "manifest=json.loads((BASE/'bootstrap-delta-v2/manifest.json').read_text())":
        "manifest=json.loads((ROOT.parent/'Snapintosh-adreno-composite/build/ca-composite-deploy-20260928/delta-v1/manifest.json').read_text())",
    "assert status==0 and 'on AC' in battery['text']": "assert status==0 and battery['plausible'] and (battery['ac'] or battery['percent']>=30)",
}
injected = ''.join(f'assert source.count({old!r}) == 1, {old!r}\nsource = source.replace({old!r}, {new!r})\n' for old, new in extra.items())
source = source.replace(anchor, injected + anchor)
exec(compile(source, str(base), 'exec'), dict(__file__=__file__, __name__='__main__', ROOT=ROOT))

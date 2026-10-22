#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Retire idle generation62 after its verified composite SSD update.

Derived from retire-gen58-ca.py (0xb0800000 -> 0xb0000000 alternating chainload).
Generation62 never initialized the GPU: generation61's retirement quiesced it
gracefully (record 95f37412...) before chainloading 61->62, and generation62's
only clients are storage reads and the native SSD writer. a16gpu quiesce on a
GMU already held in reset takes its 'already in reset' branch and never reports
'graceful', so this path binds the inherited graceful quiescence instead of
issuing a second GPU write sequence.

Failure inventory: live guest/other owner, wrong generation or image base,
incomplete SSD apply, changed package/ISC/stage binary, changed gen61
quiescence evidence, SError, or ambiguous chainload. No SSD or GPU writes.
Caller must own hardware exclusively and must never interrupt a native call.
"""
from pathlib import Path
import argparse
import hashlib
import json
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
COMPOSITE = ROOT.parent / 'Snapintosh-adreno-composite'
Q = ROOT.parent / 'q1n1'
OUT = ROOT / 'build/ca-composite-deploy-gen62-20260928'
PRIOR = 'installed-metal-ca-network-3600s-20260928'
sha = lambda p: hashlib.sha256(Path(p).read_bytes()).hexdigest()
ap = argparse.ArgumentParser(description=__doc__)
ap.add_argument('--check', action='store_true')
args = ap.parse_args()
prior_path = ROOT / 'build' / (PRIOR + '-retirement-v1.json')
assert sha(prior_path) == '7da980b761b1e20ca57b37d9368ef38822bee4701becd5e279f7170597394188'
prior = json.loads(prior_path.read_text())
assert prior['status'] == 'GENERATION62_IDLE' and not prior['ssd_writes']
assert prior['source_sha256'] == sha(ROOT / 'tools/retire-gen61-network.py')
assert prior['after']['stage_generation'] == 62 and prior['after']['image_base'] == 0xb0800000
assert not any(prior['after_serror'][k] for k in ['before', 'during', 'unconsumed'])
quiet_path = ROOT / 'build' / (PRIOR + '-quiesce-v1.json')
assert sha(quiet_path) == prior['quiesce_sha256'] == '95f374121f38f0e6c60b1cbbcdb4d72fed2cb18d9fc646e739d2561c2c94a3ba'
quiet = json.loads(quiet_path.read_text())
assert quiet.get('quiesce') == 'graceful' and not quiet.get('stopped') and 'gmu_reset' in quiet['gmu_steps']
assert not any(quiet['serror_guard']['after'][k] for k in ['before', 'during', 'unconsumed'])
isc_path = OUT / 'isc-v1/capture.json'
isc = json.loads(isc_path.read_text())
assert isc['result'] == 'PASS' and isc['generation'] == isc['bootinfo']['stage_generation'] == 62
assert not isc['ssd_writes'] and isc['source_sha256'] == sha(ROOT / 'build/capture-ca-composite-isc-20260928.py')
package_path = COMPOSITE / 'build/ca-composite-deploy-20260928/delta-v1/package.json'
package = json.loads(package_path.read_text())
assert package['binding_inputs_sha256'][str(isc_path.resolve())] == sha(isc_path)
applied_path = OUT / 'apply-v1.json'
applied = json.loads(applied_path.read_text())
assert applied['result'] == 'PASS' and applied['mode'] == 'apply'
assert applied['bootinfo']['stage_generation'] == 62
assert applied['package_sha256'] == sha(package_path)
assert applied['header_after'] == package['header_after_sha256']
assert applied['container_after'] == package['container_after_sha256']
assert applied['edges_unchanged'] and not any(applied['serror'].values())
stages = {'q1n1-stage.bin': '752b4ab711fcab5f7a4d4fc1b71dc70ae93ff98efd3212c15d918d2c1e279ea4',
          'q1n1-stage-alt.bin': 'e6276e5a032f97ee0f8f087f5f301da25e709f8b8deca2167eb1d4a4ce9c3c03'}
for name, digest in stages.items():
    assert sha(Q / 'build/uefi' / name) == digest
out = OUT / 'retirement-gen62-v1.json'
assert not out.exists()
record = dict(status='READY', started=time.time(), source_sha256=sha(__file__),
    prior_retirement_sha256=sha(prior_path), inherited_quiesce_sha256=sha(quiet_path),
    isc_sha256=sha(isc_path), package_sha256=sha(package_path), apply_sha256=sha(applied_path),
    stage_sha256=stages, ssd_writes=False, gpu_writes=False, previous_guest_generation=61)
if args.check:
    print(json.dumps(record))
    raise SystemExit(0)


def save():
    out.write_text(json.dumps(record, indent=2) + '\n')


with out.open('x') as stream:
    json.dump(record, stream, indent=2)
sys.path.insert(0, str(Q / 'tools'))
import q1n1proxy
try:
    proxy = q1n1proxy.connect('udp://en5')
    try:
        info = proxy.bootinfo()
        assert info['current_el'] == 2 and info['stage_generation'] == 62 and info['image_base'] == 0xb0800000
        guard = proxy.serror_state()
        assert not any(guard[k] for k in ['before', 'during', 'unconsumed'])
        record.update(before=info, before_serror=guard, status='GENERATION62_VERIFIED')
        save()
        chosen, data, link = proxy.pick_stage(Q / 'build/uefi/q1n1-stage.bin')
        assert sha(chosen) == stages[chosen.name] and link == 0xb0000000
        record['chainload'] = proxy.chainload(proxy.stage_configure(data, None, False))
    finally:
        proxy.link.close()
    record['status'] = 'CHAINLOAD_RETURNED'
    save()
    time.sleep(6)
    proxy = q1n1proxy.connect('udp://en5', wait=30)
    try:
        info = proxy.bootinfo()
        assert info['current_el'] == 2 and info['stage_generation'] == 63 and info['image_base'] == link
        guard = proxy.serror_state()
        assert not any(guard[k] for k in ['before', 'during', 'unconsumed'])
        record.update(after=info, after_serror=guard, status='GENERATION63_IDLE')
    finally:
        proxy.link.close()
except BaseException as error:
    record.update(status='FAILED', error=repr(error))
    raise
finally:
    record['finished'] = time.time()
    save()
print(json.dumps(dict(status=record['status'], output=str(out))))

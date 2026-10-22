#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Retire idle standalone CA generation58 after its verified SSD update.

Failure inventory: live guest/other owner, changed saved pixel evidence, wrong
generation, incomplete SSD apply, changed stage binary, failed quiescence or
ambiguous chainload. This path performs no SSD writes. Caller must own hardware
exclusively and must never interrupt a native call.
"""
from pathlib import Path
import argparse
import hashlib
import json
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
PIPE = ROOT.parent / 'Snapintosh-adreno-pipeline'
Q = ROOT.parent / 'q1n1'
OUT = ROOT / 'build/ca-metal-deploy-20260928'
sha = lambda p: hashlib.sha256(Path(p).read_bytes()).hexdigest()
ap = argparse.ArgumentParser(description=__doc__)
ap.add_argument('--check', action='store_true')
args = ap.parse_args()
proof_path = PIPE / 'build/ca-vpc-a16-verified-gen58-20260928-v1/verification.json'
assert sha(proof_path) == '8d95a910aedce77fb31710799e0882e0a1c8b0d32b1eacfbf709e0c5d0995c2e'
proof = json.loads(proof_path.read_text())
assert proof['status'] == 'A16_CA_FRAME_EXACT' and not proof['desktop_verified']
for name, digest in proof['artifact_sha256'].items():
    assert sha(proof_path.parent / name) == digest
run_path = PIPE / 'build/ca-vpc-a16-run-gen58-20260928-v1/run.json'
assert sha(run_path) == proof['run_sha256']
run = json.loads(run_path.read_text())
assert run['finished'] and run['generation'] == 58 and not run['guest_boot']
assert sha(run_path.parent / 'replay.json') == proof['replay_sha256']
package_path = PIPE / 'build/ca-metal-deploy-20260928/delta-v1/package.json'
package = json.loads(package_path.read_text())
applied_path = OUT / 'apply-v1.json'
applied = json.loads(applied_path.read_text())
assert applied['result'] == 'PASS' and applied['mode'] == 'apply'
assert applied['bootinfo']['stage_generation'] == 58
assert applied['package_sha256'] == sha(package_path)
assert applied['header_after'] == package['header_after_sha256']
assert applied['container_after'] == package['container_after_sha256']
assert applied['edges_unchanged'] and not any(applied['serror'].values())
stages = {'q1n1-stage.bin': '752b4ab711fcab5f7a4d4fc1b71dc70ae93ff98efd3212c15d918d2c1e279ea4',
          'q1n1-stage-alt.bin': 'e6276e5a032f97ee0f8f087f5f301da25e709f8b8deca2167eb1d4a4ce9c3c03'}
for name, digest in stages.items():
    assert sha(Q / 'build/uefi' / name) == digest
out, quiet_path = OUT / 'retirement-gen58-v1.json', OUT / 'quiesce-gen58-v1.json'
assert not out.exists() and not quiet_path.exists()
record = dict(status='READY', started=time.time(), source_sha256=sha(__file__),
    proof_sha256=sha(proof_path), apply_sha256=sha(applied_path),
    stage_sha256=stages, ssd_writes=False, previous_guest_generation=57)
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
        assert info['current_el'] == 2 and info['stage_generation'] == 58 and info['image_base'] == 0xb0800000
        guard = proxy.serror_state()
        assert not any(guard[k] for k in ['before', 'during', 'unconsumed'])
        record.update(before=info, before_serror=guard)
    finally:
        proxy.link.close()
    command = [sys.executable, str(Q / 'tools/a16gpu.py'), '--device', 'udp://en5',
               '--out', str(quiet_path), 'quiesce', '--write']
    with (OUT / 'quiesce-gen58-v1.log').open('x') as stream:
        result = subprocess.run(command, cwd=Q, stdout=stream, stderr=subprocess.STDOUT)
    assert result.returncode == 0, result.returncode
    quiet = json.loads(quiet_path.read_text())
    assert quiet.get('quiesce') == 'graceful' and not quiet.get('stopped')
    assert not any(quiet['serror_guard']['after'][k] for k in ['before', 'during', 'unconsumed'])
    record.update(status='GPU_QUIESCED', quiesce_sha256=sha(quiet_path))
    save()
    proxy = q1n1proxy.connect('udp://en5')
    try:
        assert proxy.bootinfo()['stage_generation'] == 58
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
        assert info['current_el'] == 2 and info['stage_generation'] == 59 and info['image_base'] == link
        guard = proxy.serror_state()
        assert not any(guard[k] for k in ['before', 'during', 'unconsumed'])
        record.update(after=info, after_serror=guard, status='GENERATION59_IDLE')
    finally:
        proxy.link.close()
except BaseException as error:
    record.update(status='FAILED', error=repr(error))
    raise
finally:
    record['finished'] = time.time()
    save()
print(json.dumps(dict(status=record['status'], output=str(out))))

#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Preserve the completed gradient result and retire generation60 for a guest.

Failure inventory: active replay, altered pixels/guards, wrong generation,
changed stage, failed quiescence or ambiguous chainload. The saved one-channel
precision mismatch is not an exact pass. No SSD write or running guest exists.
"""
from pathlib import Path
import argparse
import hashlib
import json
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
WORK = ROOT.parent/'Snapintosh-adreno-buffer-textures'
Q = ROOT.parent/'q1n1'
OUT = ROOT/'build/ca-network-boot-20260928'
sha = lambda p: hashlib.sha256(Path(p).read_bytes()).hexdigest()
ap = argparse.ArgumentParser(description=__doc__)
ap.add_argument('--check',action='store_true')
args = ap.parse_args()
proof_path = WORK/'build/ca-gradient-alias256-a16-verified-gen60-20260928-v1/verification.json'
assert sha(proof_path) == '236558830b64df4569f98ba028fb663ac238f28374d5284b236c6f83365b6d98'
proof = json.loads(proof_path.read_text())
assert proof['status'] == 'A16_CA_FRAME_MISMATCH' and proof['pixels']['max_channel_error'] == 1
assert proof['pixels']['mismatches'] == {'frame':975} and not proof['desktop_verified']
assert len(proof['copies']) == 4 and all(c['exact'] for c in proof['copies'])
assert len(proof['guards']) == 6 and all(g['before'] and g['after'] for g in proof['guards'])
for name,digest in proof['artifact_sha256'].items(): assert sha(proof_path.parent/name) == digest
run_path = WORK/'build/ca-gradient-alias256-a16-run-gen60-20260928-v1/run.json'
assert sha(run_path) == proof['run_sha256'] == '59eef186c044933ab81bc09defc3c6247c8a3cee5e0b04a268be746c4c7ec64e'
run = json.loads(run_path.read_text())
assert run['finished'] > run['started'] and run['generation'] == 60 and not run['guest_boot']
assert run['status'] == 'HARDWARE_REPLAY_RETURNED_PIXELS_PENDING' and run['replay_exit'] == 0
observed = subprocess.run(['ps','-p',str(run['pid']),'-o','command='],capture_output=True,text=True)
assert observed.returncode == 1 and not observed.stdout.strip(), 'replay PID exists; inspect before retirement'
assert sha(run_path.parent/'replay.json') == proof['replay_sha256']
for path,digest in run['q1n1_sources'].items(): assert sha(path) == digest
stages = {'q1n1-stage.bin':'752b4ab711fcab5f7a4d4fc1b71dc70ae93ff98efd3212c15d918d2c1e279ea4',
          'q1n1-stage-alt.bin':'e6276e5a032f97ee0f8f087f5f301da25e709f8b8deca2167eb1d4a4ce9c3c03'}
for name,digest in stages.items(): assert sha(Q/'build/uefi'/name) == digest
out,quiet_path = OUT/'retirement-gen60-v1.json',OUT/'quiesce-gen60-v1.json'
assert not out.exists() and not quiet_path.exists()
record = dict(status='READY',started=time.time(),source_sha256=sha(__file__),
              proof_sha256=sha(proof_path),run_sha256=sha(run_path),stage_sha256=stages,
              ssd_writes=False,previous_guest_generation=59,gradient_exact=False)
if args.check:
    print(json.dumps(record))
    raise SystemExit(0)
OUT.mkdir(exist_ok=True)
def save(): out.write_text(json.dumps(record,indent=2)+'\n')
with out.open('x') as stream: json.dump(record,stream,indent=2)
sys.path.insert(0,str(Q/'tools'))
import q1n1proxy
try:
    proxy = q1n1proxy.connect('udp://en5')
    try:
        info = proxy.bootinfo()
        assert info['current_el'] == 2 and info['stage_generation'] == 60 and info['image_base'] == 0xb0800000
        guard = proxy.serror_state()
        assert not any(guard[k] for k in ['before','during','unconsumed'])
        record.update(before=info,before_serror=guard)
    finally: proxy.link.close()
    with (OUT/'quiesce-gen60-v1.log').open('x') as stream:
        result = subprocess.run([sys.executable,str(Q/'tools/a16gpu.py'),'--device','udp://en5',
                                 '--out',str(quiet_path),'quiesce','--write'],cwd=Q,stdout=stream,stderr=subprocess.STDOUT)
    assert result.returncode == 0
    quiet = json.loads(quiet_path.read_text())
    assert quiet.get('quiesce') == 'graceful' and not quiet.get('stopped')
    assert not any(quiet['serror_guard']['after'][k] for k in ['before','during','unconsumed'])
    record.update(status='GPU_QUIESCED',quiesce_sha256=sha(quiet_path))
    save()
    proxy = q1n1proxy.connect('udp://en5')
    try:
        assert proxy.bootinfo()['stage_generation'] == 60
        chosen,data,link = proxy.pick_stage(Q/'build/uefi/q1n1-stage.bin')
        assert sha(chosen) == stages[chosen.name] and link == 0xb0000000
        record['chainload'] = proxy.chainload(proxy.stage_configure(data,None,False))
    finally: proxy.link.close()
    record['status'] = 'CHAINLOAD_RETURNED'
    save()
    time.sleep(6)
    proxy = q1n1proxy.connect('udp://en5',wait=30)
    try:
        info = proxy.bootinfo()
        assert info['current_el'] == 2 and info['stage_generation'] == 61 and info['image_base'] == link
        guard = proxy.serror_state()
        assert not any(guard[k] for k in ['before','during','unconsumed'])
        record.update(after=info,after_serror=guard,status='GENERATION61_IDLE')
    finally: proxy.link.close()
except BaseException as error:
    record.update(status='FAILED',error=repr(error))
    raise
finally:
    record['finished'] = time.time()
    save()
print(json.dumps(dict(status=record['status'],output=str(out))))

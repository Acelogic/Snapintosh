#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Submit a fresh qualified scene on the still-idle standalone CP, without reinitializing it.

Uses the existing q1n1 replay prologue to re-prove live arena, boot token, CP
state, bounded ring space, SMMU mappings and GPU fences. Failure inventory:
stale previous run/bundle, different generation, live owner, insufficient power,
faulted CP, output reuse, or confusing successful submission with correct pixels.
"""
from pathlib import Path
import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
Q = ROOT.parent/'q1n1'
sha = lambda p: hashlib.sha256(Path(p).read_bytes()).hexdigest()
ap = argparse.ArgumentParser(description=__doc__)
ap.add_argument('--previous-run',type=Path,required=True)
ap.add_argument('--bundle',type=Path,required=True)
ap.add_argument('--output',type=Path,required=True)
ap.add_argument('--check',action='store_true')
args = ap.parse_args()
prior_path,bundle,out = args.previous_run.resolve(),args.bundle.resolve(),args.output.resolve()
prior = json.loads(prior_path.read_text())
assert prior['status'] == 'HARDWARE_REPLAY_RETURNED_PIXELS_PENDING' and prior['replay_exit'] == 0
assert sha(prior_path.parent/'replay.json') == prior['replay_sha256']
assert prior['hardware_access'] and not prior['guest_boot']
prepared = json.loads((bundle/'preparation.json').read_text())
assert prepared['status'] == 'CA_HARDWARE_REPLAY_BUNDLE_PLANNED' and not prepared['a16_access']
for name,digest in prepared['artifact_sha256'].items(): assert sha(bundle/name) == digest, name
for name,digest in prepared['q1n1_sha256'].items(): assert sha(name) == digest, name
assert not out.exists()
record = dict(status='READY',pid=os.getpid(),started=time.time(),source_sha256=sha(__file__),
              previous_run=str(prior_path),previous_run_sha256=sha(prior_path),generation=prior['generation'],
              bundle=str(bundle),preparation_sha256=sha(bundle/'preparation.json'),hardware_access=False,
              ssd_writes=False,guest_boot=False)
if args.check:
    print(json.dumps(record))
    raise SystemExit(0)
out.mkdir()
shutil.copy2(__file__,out/'run-source.py')
def save(): (out/'run.json').write_text(json.dumps(record,indent=2)+'\n')
save()
try:
    sys.path.insert(0,str(Q/'tools'))
    import q1n1proxy
    proxy = q1n1proxy.connect('udp://en5',wait=10)
    record['hardware_access'] = True
    try:
        info = proxy.bootinfo()
        assert info['current_el'] == 2 and info['stage_generation'] == prior['generation']
        assert info['image_base'] == prior['bootinfo']['image_base']
        status,battery = proxy.live_battery()
        assert status == 0 and battery['plausible'] and (battery['ac'] or battery['percent'] >= 80)
        guard = proxy.serror_state()
        assert not any(guard[k] for k in ['before','during','unconsumed'])
        record.update(bootinfo=info,battery=battery,before_serror=guard,status='REPLAY_RUNNING')
        save()
    finally: proxy.link.close()
    command = [sys.executable,str(Q/'tools/a16gpu_replay.py'),'--bundle',str(bundle),'--write',
               '--device','udp://en5','--out',str(out/'replay.json')]
    record['command'] = command
    save()
    with (out/'replay.log').open('x') as stream:
        result = subprocess.run(command,cwd=Q,env=dict(os.environ,A16_GPU_FW_DIR=str(ROOT.parent/'Snapintosh/gpu/adreno/gpu-bringup-q1n1/fw')),
                                stdout=stream,stderr=subprocess.STDOUT)
    record.update(replay_exit=result.returncode,replay_sha256=sha(out/'replay.json') if (out/'replay.json').exists() else None)
    assert result.returncode == 0, ('replay',result.returncode)
    replay = json.loads((out/'replay.json').read_text())
    assert replay.get('stopped') is None and 'replay_read_back' in replay['order']
    record['status'] = 'HARDWARE_REPLAY_RETURNED_PIXELS_PENDING'
except BaseException as error:
    record.update(status='FAILED',error=repr(error))
    raise
finally:
    record['finished'] = time.time()
    save()
print(json.dumps(dict(status=record['status'],output=str(out/'run.json'))))

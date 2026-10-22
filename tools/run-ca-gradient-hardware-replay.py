#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Run the captured CoreAnimation gradient on generation60's standalone Adreno.

Failure inventory: stale bundle/retirement/source, wrong target/generation,
insufficient power, concurrent owner, failed GPU stage, reused outputs, GPU fault,
and confusing submission with correct pixels. One owner; no SSD or guest boot.
--check-inputs validates only offline inputs and does not authorize hardware use.
"""
from pathlib import Path
import argparse
import hashlib
import json
import os
import runpy
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
MAIN = ROOT.parent/'Snapintosh'
Q = ROOT.parent/'q1n1'
BUNDLE = ROOT/'build/ca-gradient-alias256-a16-plan-20260928-v1'
OUT = ROOT/'build/ca-gradient-alias256-a16-run-gen60-20260928-v1'
sha = lambda p: hashlib.sha256(Path(p).read_bytes()).hexdigest()
ap = argparse.ArgumentParser(description=__doc__)
mode = ap.add_mutually_exclusive_group()
mode.add_argument('--check',action='store_true')
mode.add_argument('--check-inputs',action='store_true')
ap.add_argument('--retirement-sha256')
args = ap.parse_args()
assert sha(BUNDLE/'preparation.json') == 'db055766caac8647a8a02b08e96f8f280c264506e84de60228ffdea8fd17cc19'
prepared = json.loads((BUNDLE/'preparation.json').read_text())
assert prepared['status'] == 'CA_HARDWARE_REPLAY_BUNDLE_PLANNED' and not prepared['a16_access']
for name,digest in prepared['artifact_sha256'].items(): assert sha(BUNDLE/name) == digest, name
for name,digest in prepared['q1n1_sha256'].items(): assert sha(name) == digest, name
STEPS = [('guard',['guard']),('cx',['cx-on','--write']),('arena',['arena','--write']),
         ('smmu',['gmu-smmu','--write']),('gmu',['gmu-boot','--write']),('hfi',['hfi','--write']),
         ('oob',['oob','--write']),('c3',['cp-fence','--write','--stop-after','C3']),
         ('c3s',['cp-fence','--write','--stop-after','C3S']),
         ('c5',['cp-fence','--write','--stop-after','C5']),('fence',['cp-fence','--write'])]
assert not OUT.exists()
if args.check_inputs:
    print(json.dumps(dict(status='GRADIENT_REPLAY_OFFLINE_INPUTS_VALID',steps=len(STEPS),
                          preparation_sha256=sha(BUNDLE/'preparation.json'),
                          source_sha256=sha(__file__),hardware_access=False)))
    raise SystemExit(0)
if not args.retirement_sha256:
    ap.error('--retirement-sha256 is required after generation59 capture, inspection and retirement')
retired_path = MAIN/'build/installed-metal-ca-3600s-20260928-retirement-v1.json'
assert sha(retired_path) == args.retirement_sha256
retired = json.loads(retired_path.read_text())
assert retired['status'] == 'GENERATION60_IDLE' and retired['finished'] > retired['started']
assert retired['before']['bootinfo']['stage_generation'] == 59
assert retired['after']['stage_generation'] == 60 and retired['after']['image_base'] == 0xb0800000
assert retired['after']['current_el'] == 2
assert not any(retired['after_serror'][k] for k in ['before','during','unconsumed'])
assert sha(MAIN/'tools/retire-gen59-metal.py') == retired['source_sha256']
preserved = MAIN/'build/metal-ca-gen59-preserved-20260928-v1/preservation.json'
assert sha(preserved) == retired['verification_sha256']
assert sha(MAIN/'tools/preserve-gen59-metal.py') == json.loads(preserved.read_text())['source_sha256']
# This rechecks the exact launcher identity/termination and saved stopped artifacts.
# It imports no transport and performs no A16 access.
runpy.run_path(str(MAIN/'tools/preserve-gen59-metal.py'))['validate']()
record = dict(status='READY',pid=os.getpid(),started=time.time(),source_sha256=sha(__file__),
              generation=60,bundle=str(BUNDLE),preparation_sha256=sha(BUNDLE/'preparation.json'),
              retirement_sha256=sha(retired_path),hardware_access=False,ssd_writes=False,guest_boot=False,steps=[])
record['q1n1_sources'] = {str(p):sha(p) for p in sorted((Q/'tools').glob('a16gpu*.py'))}
record['q1n1_sources'].update({str(Q/'tools'/n):sha(Q/'tools'/n) for n in ['adreno_x2.py','a8xx_regs.py','q1n1proxy.py']})
if args.check:
    print(json.dumps(dict(status=record['status'],steps=len(STEPS),bundle=str(BUNDLE),source_sha256=record['source_sha256'])))
    raise SystemExit(0)
OUT.mkdir()
def save(): (OUT/'run.json').write_text(json.dumps(record,indent=2)+'\n')
save()
try:
    sys.path.insert(0,str(Q/'tools'))
    import q1n1proxy
    proxy = q1n1proxy.connect('udp://en5',wait=10)
    record['hardware_access'] = True
    try:
        info = proxy.bootinfo()
        assert info['current_el'] == 2 and info['stage_generation'] == 60 and info['image_base'] == 0xb0800000
        status,battery = proxy.live_battery()
        assert status == 0 and battery['plausible'] and (battery['ac'] or battery['percent'] >= 80)
        guard = proxy.serror_state()
        assert not any(guard[k] for k in ['before','during','unconsumed'])
        record.update(bootinfo=info,battery=battery,before_serror=guard,status='GPU_PREPARATION')
        save()
    finally: proxy.link.close()
    environment = dict(os.environ,A16_GPU_FW_DIR=str(MAIN/'gpu/adreno/gpu-bringup-q1n1/fw'))
    for name,arguments in STEPS:
        output = OUT/(name+'.json')
        with (OUT/(name+'.log')).open('x') as stream:
            result = subprocess.run([sys.executable,str(Q/'tools/a16gpu.py'),'--device','udp://en5',
                                     '--out',str(output),*arguments],cwd=Q,env=environment,stdout=stream,stderr=subprocess.STDOUT)
        record['steps'].append(dict(name=name,exit_code=result.returncode,output=str(output),sha256=sha(output) if output.exists() else None))
        save()
        assert result.returncode == 0, (name,result.returncode)
        step = json.loads(output.read_text())
        assert step.get('stopped') is None, (name,step.get('stopped'))
        if name == 'guard': assert step['serror_guard']['present']
        print(json.dumps(dict(step=name,exit_code=0)),flush=True)
    record.update(status='REPLAY_RUNNING')
    save()
    output = OUT/'replay.json'
    with (OUT/'replay.log').open('x') as stream:
        result = subprocess.run([sys.executable,str(Q/'tools/a16gpu_replay.py'),'--bundle',str(BUNDLE),
                                 '--write','--device','udp://en5','--out',str(output)],
                                cwd=Q,env=environment,stdout=stream,stderr=subprocess.STDOUT)
    record.update(replay_exit=result.returncode,replay_sha256=sha(output) if output.exists() else None)
    assert result.returncode == 0, ('replay',result.returncode)
    replay = json.loads(output.read_text())
    assert replay.get('stopped') is None and 'replay_read_back' in replay['order']
    record['status'] = 'HARDWARE_REPLAY_RETURNED_PIXELS_PENDING'
except BaseException as error:
    record.update(status='FAILED',error=repr(error))
    raise
finally:
    record['finished'] = time.time()
    save()
print(json.dumps(dict(status=record['status'],output=str(OUT/'run.json'))))

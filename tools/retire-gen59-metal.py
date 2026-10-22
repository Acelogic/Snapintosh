#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Retire preserved generation59 through graceful GPU quiescence and chainload.

Failure inventory: changed evidence/stage, live launcher, different generation,
unparked guest, SError, failed GPU quiescence, ambiguous chainload, output reuse.
Reuses the established native-stop and alternating-stage sequence. No SSD write.
Run only after inspecting the stopped guest and preserving all needed evidence.
"""
from pathlib import Path
import argparse
import hashlib
import json
import runpy
import struct
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
Q = ROOT.parent/'q1n1'
RUNTIME = ROOT.parent/'Snapintosh-adreno-sks'
PREFIX = 'installed-metal-ca-3600s-20260928'
sha = lambda p: hashlib.sha256(Path(p).read_bytes()).hexdigest()
path = lambda suffix: ROOT/'build'/(PREFIX+suffix)
ap = argparse.ArgumentParser(description=__doc__)
ap.add_argument('--preservation-sha256',required=True)
ap.add_argument('--check',action='store_true')
args = ap.parse_args()
preservation = ROOT/'build/metal-ca-gen59-preserved-20260928-v1/preservation.json'
assert sha(preservation) == args.preservation_sha256 == sha(path('-pre-reset-verification.json'))
saved = json.loads(preservation.read_text())
assert saved['status'] == 'GEN59_STOPPED_EVIDENCE_PRESERVED' and saved['generation'] == 59
assert len(saved['runtime_sources']) == 303 and len(saved['artifacts']) >= 40
for group in ['runtime_sources','artifacts','binaries','diagnosis']:
    for name,entry in saved[group].items(): assert sha(name) == sha(entry['copy']) == entry['sha256'], name
preserver = ROOT/'tools/preserve-gen59-metal.py'
assert sha(preserver) == saved['source_sha256']
launch = runpy.run_path(str(preserver))['validate']()
stages = {'q1n1-stage.bin':'752b4ab711fcab5f7a4d4fc1b71dc70ae93ff98efd3212c15d918d2c1e279ea4',
          'q1n1-stage-alt.bin':'e6276e5a032f97ee0f8f087f5f301da25e709f8b8deca2167eb1d4a4ce9c3c03'}
for name,digest in stages.items(): assert sha(Q/'build/uefi'/name) == digest
out = path('-retirement-v1.json')
assert not out.exists() and not path('-quiesce-v1.json').exists()
record = dict(status='READY',started=time.time(),source_sha256=sha(__file__),
              verification_sha256=args.preservation_sha256,stage_sha256=stages,ssd_writes=False)
if args.check:
    print(json.dumps(record))
    raise SystemExit(0)


def stopped(proxy):
    info = proxy.bootinfo()
    assert info['current_el'] == 2 and info['stage_generation'] == 59 and info['image_base'] == 0xb0000000
    guard = proxy.serror_state()
    assert not any(guard[k] for k in ['before','during','unconsumed'])
    sys.path[:0] = [str(RUNTIME/'probes'),str(RUNTIME/'tools')]
    import run
    from monitor_layout import MonitorLayout
    layout = MonitorLayout()
    assert layout.size('context') == launch['context_bytes'] == 5124736
    work,size = run.resident_work(proxy,info)
    at = work+layout.offset('context','services')
    raw = proxy.readmem(at,64,live=True)
    assert struct.unpack('<8Q',raw) == (0,0x100000001,0x8000000000000003,0,0,0,0,0)
    assert proxy.readmem(at,64,live=True) == raw
    guard = proxy.serror_state()
    assert not any(guard[k] for k in ['before','during','unconsumed'])
    return dict(bootinfo=info,work=work,bytes=size,service_hex=raw.hex(),serror=guard)


def save(): out.write_text(json.dumps(record,indent=2)+'\n')


with out.open('x') as f: json.dump(record,f,indent=2)
sys.path.insert(0,str(Q/'tools'))
import q1n1proxy
try:
    proxy = q1n1proxy.connect('udp://en5')
    try: record['before'] = stopped(proxy)
    finally: proxy.link.close()
    record['status'] = 'NATIVE_STOP_VERIFIED'
    save()
    command = [sys.executable,str(Q/'tools/a16gpu.py'),'--device','udp://en5',
               '--out',str(path('-quiesce-v1.json')),'quiesce','--write']
    with path('-quiesce-v1.log').open('x') as stream:
        result = subprocess.run(command,cwd=Q,stdout=stream,stderr=subprocess.STDOUT)
    assert result.returncode == 0, result.returncode
    quiet = json.loads(path('-quiesce-v1.json').read_text())
    assert quiet.get('quiesce') == 'graceful' and not quiet.get('stopped')
    assert not any(quiet['serror_guard']['after'][k] for k in ['before','during','unconsumed'])
    record.update(status='GPU_QUIESCED',quiesce_sha256=sha(path('-quiesce-v1.json')))
    save()
    proxy = q1n1proxy.connect('udp://en5')
    try:
        assert proxy.bootinfo()['stage_generation'] == 59
        chosen,data,link = proxy.pick_stage(Q/'build/uefi/q1n1-stage.bin')
        assert sha(chosen) == stages[chosen.name] and link == 0xb0800000
        data = proxy.stage_configure(data,None,False)
        record['chainload'] = proxy.chainload(data)
    finally: proxy.link.close()
    record['status'] = 'CHAINLOAD_RETURNED'
    save()
    time.sleep(6)
    proxy = q1n1proxy.connect('udp://en5',wait=30)
    try:
        info = proxy.bootinfo()
        record['after'] = info
        assert info['current_el'] == 2 and info['stage_generation'] == 60 and info['image_base'] == link
        guard = proxy.serror_state()
        assert not any(guard[k] for k in ['before','during','unconsumed'])
        record['after_serror'] = guard
    finally: proxy.link.close()
    record['status'] = 'GENERATION60_IDLE'
except BaseException as error:
    record.update(status='FAILED',error=repr(error))
    raise
finally:
    record['finished'] = time.time()
    save()
print(json.dumps(dict(status=record['status'],output=str(out))))

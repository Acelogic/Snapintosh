#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Measure saved WindowServer startup timing without accessing the A16.

Failure inventory: mixing boots, altered raw evidence, mismatched reconstructed
archive, a failed decoder mistaken for no events, timestamp gaps mistaken for
proven waits, and changing the running guest to shorten an unmeasured delay.
The timeline establishes event timing only; a silent interval is not causality.
"""
from pathlib import Path
from datetime import datetime
import hashlib
import json
import subprocess
import time

ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT/'build/ca-metal-deploy-20260928'
DECODE = BASE/'unified-log-decoded-v2'
OUT = BASE/'gen57-startup-timing-v1'
LAUNCH = ROOT/'build/installed-metal-qc-pipeline-3600s-20260928-launch.json'
CAUSE = BASE/'gen57-windowserver-cause-v1.json'
sha = lambda p: hashlib.sha256(Path(p).read_bytes()).hexdigest()


def events(path, boot_uuid, start):
    result = []
    for line in path.open():
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        if event.get('bootUUID') != boot_uuid:
            continue
        stamp = datetime.strptime(event['timestamp'], '%Y-%m-%d %H:%M:%S.%f%z').timestamp()
        result.append(dict(seconds_after_launch=stamp-start,
                           timestamp=event['timestamp'], pid=event.get('processID'),
                           process=event.get('processImagePath'),
                           message=event.get('eventMessage','')))
    return sorted(result, key=lambda e: e['seconds_after_launch'])


launch = json.loads(LAUNCH.read_text())
cause = json.loads(CAUSE.read_text())
decoded = json.loads((DECODE/'decode.json').read_text())
assert sha(CAUSE) == '1bc41f327359137baa2d014449d662ac796d6f5aa50cf152c682a7d31ebff931'
assert sha(DECODE/'decode.json') == '226e1225010fa7e10333f1a63de8d65bab2e9775b2963c10ff20e2d7e6363507'
assert launch['exit_code'] == 9 and launch['adreno_record']['stage_generation'] == 57
assert decoded['status'] == 'SAVED_UNIFIED_LOG_DECODE_COMPLETE' and decoded['decoder_exit'] == 0
assert sha(DECODE/'windowserver.ndjson') == decoded['output_sha256']
archive = DECODE/'guest.logarchive'


def archive_intact():
    for entry in decoded['copied']:
        assert sha(archive/entry['target']) == entry['sha256'], entry['target']
    assert sha(archive/'Info.plist') == decoded['generated_info_sha256']


archive_intact()
OUT.mkdir(exist_ok=False)
record = dict(status='RUNNING',started=time.time(),source_sha256=sha(__file__),
              inputs_sha256={str(p):sha(p) for p in [LAUNCH,CAUSE,DECODE/'decode.json',DECODE/'windowserver.ndjson']},
              boot_uuid=cause['boot_uuid'],hardware_access=False,runtime_changes=False,
              boundary='Saved event timing; log gaps do not prove a blocked call or its cause')
try:
    command = ['/usr/bin/log','show','--archive',str(archive),'--style','ndjson','--info','--debug',
               '--predicate','process == "clocksyncd" OR process == "configd" OR subsystem CONTAINS[c] "TimeSync" OR eventMessage CONTAINS[c] "TimeSync" OR eventMessage CONTAINS[c] "timesync.expositor"']
    record['command'] = command
    raw = OUT/'clock-network.ndjson'
    with raw.open('x') as stdout, (OUT/'decoder.log').open('x') as stderr:
        result = subprocess.run(command,stdout=stdout,stderr=stderr,timeout=90)
    record['decoder_exit'] = result.returncode
    assert result.returncode == 0
    clock = events(raw,cause['boot_uuid'],launch['started'])
    window = events(DECODE/'windowserver.ndjson',cause['boot_uuid'],launch['started'])
    first_pid = cause['events'][0]['processID']
    first = [e for e in window if e['pid'] == first_pid]
    assert len(first) >= 2
    gaps = sorted((dict(seconds=b['seconds_after_launch']-a['seconds_after_launch'],before=a,after=b)
                   for a,b in zip(first,first[1:])),key=lambda e:e['seconds'],reverse=True)
    record.update(first_windowserver_pid=first_pid,windowserver_events=len(first),
                  largest_windowserver_gaps=gaps[:8],clock_network_events=len(clock),
                  clock_network_output_sha256=sha(raw))
    (OUT/'clock-network-current-boot.json').write_text(json.dumps(clock,indent=2)+'\n')
    record['artifact_sha256'] = {p.name:sha(p) for p in OUT.iterdir() if p.is_file()}
    archive_intact()
    record.update(status='GEN57_STARTUP_TIMING_EXTRACTED',archive_unchanged=True)
except BaseException as error:
    record.update(status='FAILED',error=repr(error))
    raise
finally:
    record['finished'] = time.time()
    (OUT/'timing.json').write_text(json.dumps(record,indent=2)+'\n')
print(json.dumps(dict(status=record['status'],output=str(OUT/'timing.json'),
                      largest_gap_seconds=record['largest_windowserver_gaps'][0]['seconds'])))

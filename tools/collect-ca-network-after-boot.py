#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Wait for the actual generation61 launcher exit, then collect once in order.

Failure inventory: connecting during P_CALL, a reused launcher PID, absent exit
metadata, drifted source pins, overwriting evidence, concurrent collectors, or
continuing after a failed stop audit. This coordinator never resets or boots.
"""
from pathlib import Path
from datetime import datetime, timezone
import hashlib
import json
import os
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
PREFIX = 'installed-metal-ca-network-3600s-20260928'
LAUNCH = ROOT/'build'/(PREFIX+'-launch.json')
OUTPUT = ROOT/'build'/(PREFIX+'-collection-sequence-v1.json')
STEPS = [
    ('primary','collect-ca-network-20260928.py','0d23809a6209ee3716d2d647d771c3d9dfc522bdeccaef4d21aae096cbde87d9',['--prefix',PREFIX]),
    ('native','capture-native-startup-gen61-20260928.py','c97d99938fad953b3df4c971d894edfeecc51076e1e163332ea392348e75e238',['--attempt','v1']),
    ('crashes','capture-crash-retention-gen61-20260928.py','1dba09749584c89ba93bbfbec77232be08baf471e6d88801ae2a86b2844b57d9',['--attempt','v1']),
]
sha = lambda p: hashlib.sha256(Path(p).read_bytes()).hexdigest()
read = lambda p: json.loads(Path(p).read_text())

def owner_live(launch):
    observed = subprocess.run(['ps','-p',str(launch['pid']),'-o','lstart=,command='],
        env=dict(os.environ,TZ='UTC',LC_ALL='C'),capture_output=True,text=True,check=False)
    if not observed.stdout.strip():
        assert observed.returncode == 1 and not observed.stderr.strip()
        return False
    row = observed.stdout.strip()
    born = datetime.strptime(row[:24],'%a %b %d %H:%M:%S %Y').replace(tzinfo=timezone.utc).timestamp()
    if launch.get('finished') and born > launch['finished']: return False
    assert 'tools/run-ca-network-candidate.py --boot' in row
    assert born <= launch['started'] and launch['started']-born < 120
    return True

def main():
    assert sys.argv[1:] == ['--wait']
    with OUTPUT.open('x') as stream: stream.write('{}\n')
    record = dict(status='WAITING_FOR_LAUNCHER',pid=os.getpid(),started=time.time(),
        source_sha256=sha(__file__),launch=str(LAUNCH),hardware_access=False,steps=[])
    def save():
        temporary = OUTPUT.with_suffix('.tmp')
        temporary.write_text(json.dumps(record,indent=2)+'\n');temporary.replace(OUTPUT)
    save()
    try:
        while True:
            launch = read(LAUNCH)
            assert launch['pid'] == 75660 and launch['adreno_record']['stage_generation'] == 61
            alive = owner_live(launch)
            if not alive:
                assert launch.get('finished') and 'exit_code' in launch, 'launcher ended without completed exit metadata'
                break
            assert time.time()-launch['started'] < 5400, 'launcher exceeded the bounded wait; no collection attempted'
            time.sleep(10)
        assert launch['finished'] > launch['started'] and launch['exit_code'] in (6,7,9)
        for name,digest in launch['source_sha256'].items(): assert sha(name) == digest,name
        record.update(status='COLLECTING',launch_sha256=sha(LAUNCH),stopped_exit=launch['exit_code'])
        save()
        for name,script,digest,arguments in STEPS:
            path = ROOT/'build'/script
            assert sha(path) == digest
            if name != 'primary':
                audit = read(ROOT/'build'/(PREFIX+'-audit.json'))
                assert audit['runtime_stop_qualified'] and audit['user_mapping_qualified']
            log_path = ROOT/'build'/(PREFIX+'-sequence-'+name+'-v1.log')
            step = dict(name=name,source_sha256=digest,started=time.time(),log=str(log_path))
            record['steps'].append(step);record['hardware_access']=True;save()
            with log_path.open('x') as log:
                child = subprocess.Popen([sys.executable,str(path),*arguments],cwd=ROOT,
                    env=dict(os.environ,SNAP_STOPPED_EXIT=str(launch['exit_code'])),
                    stdout=log,stderr=subprocess.STDOUT)
                step['pid']=child.pid;save()
                step['exit_code']=child.wait()
            step['finished']=time.time();step['log_sha256']=sha(log_path);save()
            assert step['exit_code'] == 0,(name,step['exit_code'])
        record.update(status='ALL_COLLECTORS_COMPLETED',finished=time.time())
        save()
    except BaseException as error:
        record.update(status='FAILED',error=repr(error),finished=time.time());save()
        raise

if __name__ == '__main__': main()

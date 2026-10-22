#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Read-only native stop recovery after the generation56 host launcher vanished.

Failure inventory: docs/GEN56-HOST-INTERRUPTION-20260928.md.
--check-inputs is offline. --capture never resumes, resets or writes target MMIO.
"""
from pathlib import Path
import argparse
import hashlib
import json
import os
import struct
import subprocess
import sys
import time
from datetime import datetime, timezone

ROOT = Path(__file__).resolve().parents[1]
RUNTIME = ROOT.parent / 'Snapintosh-adreno-sks'
PREFIX = 'installed-metal-panel-arguments-3600s-20260928'
LAUNCH = ROOT / 'build' / (PREFIX + '-launch.json')
RECOVERY = ROOT / 'build' / (PREFIX + '-host-recovery-v1.json')
EARLIEST = datetime(2026, 9, 28, 6, 31, tzinfo=timezone.utc).timestamp()
sha = lambda p: hashlib.sha256(Path(p).read_bytes()).hexdigest()


def host_absent(launch):
    observed = subprocess.run(['ps', '-p', str(launch['pid']), '-o', 'lstart='],
        env=dict(os.environ, TZ='UTC', LC_ALL='C'), capture_output=True, text=True)
    if observed.stdout.strip():
        started = datetime.strptime(observed.stdout.strip(), '%a %b %d %H:%M:%S %Y').replace(tzinfo=timezone.utc).timestamp()
        assert started > EARLIEST, 'original launcher or ambiguous reused PID remains'
    else:
        assert observed.returncode == 1 and not observed.stderr.strip(), observed.stderr


def validate():
    launch = json.loads(LAUNCH.read_text())
    assert launch['pid'] == 9271 and launch['started'] == 1790573382.064686
    assert 'finished' not in launch and 'exit_code' not in launch
    assert launch['runtime_root'] == launch['observer_root'] == str(RUNTIME)
    assert launch['context_bytes'] == 5124736 and launch['context_fields'] == 217
    assert launch['adreno_record']['stage_generation'] == 56
    assert launch['environment']['SNAP_WATCHDOG'] == '3600'
    assert len(launch['source_sha256']) == 243
    for name, digest in launch['source_sha256'].items():
        assert sha(name) == digest, name
    assert sha(launch['monitor_path']) == launch['monitor_sha256'] == sha(RUNTIME / 'build/xnuboot.bin')
    host_absent(launch)
    return launch


def capture():
    launch = validate()
    assert time.time() >= EARLIEST, 'wait until 06:31UTC; elapsed time is not stop proof'
    assert not RECOVERY.exists(), 'preserve previous recovery attempt'
    record = dict(status='STARTING', started=time.time(), launch_sha256=sha(LAUNCH),
        source_sha256=sha(Path(__file__)), host_exit_code=None, host_finished_time=None,
        generation=56, hardware_access=False, target_writes=False, guest_resumed=False,
        boundary='Recovered native stop preflight; full SMP/ownership audit pending. Original host result is unavailable.')
    def save():
        RECOVERY.write_text(json.dumps(record, indent=2) + '\n')
    with RECOVERY.open('x') as stream:
        json.dump(record, stream, indent=2)
    sys.path[:0] = [str(RUNTIME / 'probes'), str(RUNTIME / 'tools')]
    import run
    from monitor_layout import MonitorLayout
    layout = MonitorLayout()
    assert layout.size('context') == launch['context_bytes']
    proxy = None
    try:
        record['hardware_access'] = True
        save()
        proxy = run.connect('udp://en5', tries=1)
        info = proxy.bootinfo()
        record['bootinfo'] = info
        assert info['current_el'] == 2 and info['stage_generation'] == 56
        assert info['image_base'] == 0xb0800000
        guard = proxy.serror_state()
        record['serror_before'] = guard
        assert guard['mechanism'] and not any(guard[k] for k in ['before','during','unconsumed'])
        work, size = run.resident_work(proxy, info)
        record.update(work=work, work_bytes=size)
        def read(address, count):
            return b''.join(proxy.readmem(address + off, min(65536, count - off), live=True)
                for off in range(0, count, 65536))
        blob = Path(launch['monitor_path']).read_bytes()
        assert read(info['heap_base'] + run.CODE_AT, len(blob)) == blob
        record['monitor_sha256'] = hashlib.sha256(blob).hexdigest()
        service_pa = work + layout.offset('context', 'services')
        first = read(service_pa, 64)
        service = struct.unpack('<8Q', first)
        record['service'] = list(service)
        assert service[0] == 0 and service[2] == 0x8000000000000003 and not any(service[3:])
        assert service[1] >> 32 in (1, 2) and 1 <= service[1] & 0xffffffff <= 6
        report_pa = info['heap_base'] + run.OUT_AT
        report = read(report_pa, 80)
        record.update(report_address=report_pa, report_words=list(struct.unpack('<10Q', report)))
        assert struct.unpack_from('<Q', report, 8)[0] != 0, 'guest entry not witnessed'
        record['stop_owner'] = (service[1] & 0xffffffff) - 1
        record['native_last_event'] = run.read_last_event(proxy, report_pa)
        assert read(service_pa, 64) == first and read(report_pa, 80) == report, 'native stop observation changed'
        proxy.read64(guard['address'])
        final = proxy.serror_state()
        record['serror_after'] = final
        assert not any(final[k] for k in ['before','during','unconsumed'])
        record.update(status='NATIVE_STOP_PREFLIGHT_RECOVERED', observed_stopped_at=time.time())
    except BaseException as error:
        record.update(status='FAILED', error=repr(error))
        raise
    finally:
        if proxy is not None:
            proxy.link.close()
        record['finished'] = time.time()
        save()
    assert sha(LAUNCH) == record['launch_sha256'], 'incomplete host launch record changed'
    print(json.dumps(dict(status=record['status'], output=str(RECOVERY), service=record['service'], host_exit_code=None)))


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    group = ap.add_mutually_exclusive_group(required=True)
    group.add_argument('--check-inputs', action='store_true')
    group.add_argument('--capture', action='store_true')
    args = ap.parse_args()
    if args.check_inputs:
        validate()
        print(json.dumps(dict(status='RECOVERY_INPUTS_VERIFIED', hardware_access=False, earliest_observation_utc='2026-09-28T06:31:00Z')))
    else:
        capture()


if __name__ == '__main__':
    main()

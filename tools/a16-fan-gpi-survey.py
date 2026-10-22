#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Read-only, bounded IC10/GPI ownership survey. Never allocates or launches DMA."""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import runpy
import sys
import time
from a16_fan_gpi import survey_plan, decode_survey

ROOT = Path(__file__).resolve().parents[1]


def capture(proxy, record, save, generation, image_base, deadline, need, serror_clear):
    """The complete read phase, shared by the CLI and injected-transport replay."""
    info = proxy.bootinfo()
    record['bootinfo'] = info
    need(info['current_el'] == 2 and info['stage_generation'] == generation and
         info['image_base'] == image_base, 'resident target identity mismatch')
    record['serror_before'] = proxy.serror_state()
    need(serror_clear(record['serror_before']), 'preexisting SError')
    for name, address in survey_plan():
        need(time.monotonic() < deadline, 'survey deadline expired')
        row = dict(name=name, address=hex(address))
        record['reads'].append(row)
        save()
        row['value'] = proxy.read32(address)
        row['serror'] = proxy.serror_state()
        save()
        need(serror_clear(row['serror']), f'SError at {address:#x}; stop without clearing')
    record.update(status='READ_COMPLETE', decoded=decode_survey(record['reads']))
    save()


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--plan', action='store_true', help='offline register allowlist only')
    ap.add_argument('--replay', type=Path, help='offline decoding of a retained capture')
    ap.add_argument('--output', type=Path, required=True)
    ap.add_argument('--device')
    ap.add_argument('--generation', type=int)
    ap.add_argument('--image-base', type=lambda x: int(x, 0))
    ap.add_argument('--idle', action='store_true')
    ap.add_argument('--max-seconds', type=float, default=15)
    args = ap.parse_args()
    if args.output.exists():
        ap.error('output exists; use a new capture path')
    if not 0 < args.max_seconds <= 30:
        ap.error('max-seconds must be in (0,30]')
    if args.plan and args.replay:
        ap.error('choose plan or replay')
    args.output.parent.mkdir(parents=True, exist_ok=True)
    record = dict(status='STARTING', mmio_writes=False, target_memory_writes=False,
                  dma_launch_admitted=False, reads=[], source_sha256={
                      str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest()
                      for p in [Path(__file__), ROOT / 'tools/a16_fan_gpi.py',
                                ROOT / 'tools/a16-control-guard.py']})

    def save():
        temporary = args.output.with_suffix(args.output.suffix + '.tmp')
        with temporary.open('w') as stream:
            stream.write(json.dumps(record, indent=2) + '\n')
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, args.output)

    if args.plan:
        record.update(status='OFFLINE_PLAN', registers=[dict(name=n, address=hex(a)) for n, a in survey_plan()])
        save()
        print(json.dumps(dict(status=record['status'], reads=len(record['registers']), output=str(args.output))))
        return 0
    if args.replay:
        old = json.loads(args.replay.read_text())
        if old.get('status') != 'READ_COMPLETE' or old.get('mmio_writes') is not False:
            ap.error('replay requires complete read-only capture')
        record.update(status='OFFLINE_REPLAY', capture=str(args.replay),
                      capture_sha256=hashlib.sha256(args.replay.read_bytes()).hexdigest(),
                      decoded=decode_survey(old['reads']))
        save()
        print(json.dumps(dict(status=record['status'], decoded=record['decoded'])))
        return 0
    if not (args.idle and args.device and args.generation is not None and args.image_base is not None):
        ap.error('hardware survey requires --idle --device --generation --image-base')
    sys.path[:0] = [str(ROOT / 'tools'), str(ROOT / 'probes')]
    import run
    from cycle_lib.common import Workspace, require_exclusive, need, serror_clear
    ControlGuard = runpy.run_path(str(ROOT / 'tools/a16-control-guard.py'))['ControlGuard']
    require_exclusive(Workspace(ROOT))
    with open('/tmp/snapintosh-hardware.lock', 'a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        raw_proxy = guard = None
        deadline = time.monotonic() + args.max_seconds
        try:
            save()
            raw_proxy = run.connect(args.device, tries=1)
            raw_proxy.link.timeout = 0.5
            guard = ControlGuard(raw_proxy, record, save)
            raw_proxy = None
            capture(guard.proxy, record, save, args.generation, args.image_base,
                    deadline, need, serror_clear)
            print(json.dumps(dict(status=record['status'], output=str(args.output), decoded=record['decoded'])))
            return 0
        except BaseException as exc:
            if guard:
                guard.freeze(f'fan survey refused: {type(exc).__name__}: {exc}')
            record.update(status='REFUSED_OR_FAILED', error=repr(exc))
            save()
            raise
        finally:
            if guard:
                guard.close()
            elif raw_proxy:
                raw_proxy.link.close()


if __name__ == '__main__':
    sys.exit(main())

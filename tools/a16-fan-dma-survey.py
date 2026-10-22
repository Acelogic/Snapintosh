#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Guarded read-only GPI9/SMMUv2 survey; no mapping or allocation writes."""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import runpy
import sys
import time
from a16_fan_dma import (identity_plan, identity_decode, streams_plan, streams_decode,
                         context_plan, context_decode, linked_plan, linked_decode, linked_subject)
from a16_fan_gpi import require

ROOT = Path(__file__).resolve().parents[1]


def capture(proxy, record, save, generation, image_base, deadline, identity=None, streams=None,
            context_capture=None):
    info = proxy.bootinfo()
    record['bootinfo'] = info
    require(info['current_el'] == 2 and info['stage_generation'] == generation and
            info['image_base'] == image_base, 'resident identity mismatch')
    for previous_capture in (identity, streams, context_capture):
        if previous_capture is None:
            continue
        old = previous_capture['bootinfo']
        require(old['stage_generation'] == generation and old['image_base'] == image_base,
                'prior capture belongs to a different resident image')
    record['serror_before'] = proxy.serror_state()
    require(not any(record['serror_before'][k] for k in ('before', 'during', 'unconsumed')),
            'preexisting SError')
    plan = (linked_plan(identity, streams, context_capture) if context_capture else
            context_plan(identity, streams) if streams else
            streams_plan(identity) if identity else identity_plan())
    linked_bank = linked_subject(identity, streams, context_capture)[2] if context_capture else None
    prior = context_capture or streams or identity
    previous = {r['name']: r['value'] for r in prior['reads']} if prior else {}
    current = {}
    for name, address in plan:
        require(time.monotonic() < deadline, 'survey deadline')
        row = dict(name=name, address=hex(address))
        record['reads'].append(row)
        save()
        row['value'] = proxy.read32(address)
        row['serror'] = proxy.serror_state()
        save()
        require(not any(row['serror'][k] for k in ('before', 'during', 'unconsumed')),
                f'SError at {address:#x}')
        current[name] = row['value']
        if name in previous:
            require(row['value'] == previous[name], 'SMMU header/route changed; refuse dependent reads')
        if name.startswith('verify.'):
            require(row['value'] == current[name[7:]], 'translation controls changed during observation')
        if linked_bank is not None and name == f'bank{linked_bank}.cbar':
            require((row['value'] >> 16) & 3 == 0, 'linked bank is not stage2; refuse dependent reads')
    decoded = (linked_decode(record['reads'], identity, streams, context_capture) if context_capture else
               context_decode(record['reads'], identity, streams) if streams else
               streams_decode(record['reads'], identity) if identity else identity_decode(record['reads']))
    record.update(status='READ_COMPLETE', decoded=decoded)
    save()


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--phase', choices=('identity', 'streams', 'context', 'linked'), default='identity')
    ap.add_argument('--identity-capture', type=Path)
    ap.add_argument('--streams-capture', type=Path)
    ap.add_argument('--context-capture', type=Path)
    ap.add_argument('--plan', action='store_true')
    ap.add_argument('--output', type=Path, required=True)
    ap.add_argument('--device')
    ap.add_argument('--generation', type=int)
    ap.add_argument('--image-base', type=lambda s: int(s, 0))
    ap.add_argument('--idle', action='store_true')
    ap.add_argument('--max-seconds', type=float, default=15)
    args = ap.parse_args()
    if args.output.exists():
        ap.error('output exists; retain captures')
    if not 0 < args.max_seconds <= 30:
        ap.error('max-seconds must be in (0,30]')
    if bool(args.identity_capture) != (args.phase in ('streams', 'context', 'linked')):
        ap.error('streams/context/linked require --identity-capture; identity does not accept it')
    if bool(args.streams_capture) != (args.phase in ('context', 'linked')):
        ap.error('context/linked require --streams-capture; other phases do not accept it')
    if bool(args.context_capture) != (args.phase == 'linked'):
        ap.error('linked requires --context-capture; other phases do not accept it')
    identity = json.loads(args.identity_capture.read_text()) if args.identity_capture else None
    streams = json.loads(args.streams_capture.read_text()) if args.streams_capture else None
    context_capture = json.loads(args.context_capture.read_text()) if args.context_capture else None
    plan = (linked_plan(identity, streams, context_capture) if context_capture else
            context_plan(identity, streams) if streams else
            streams_plan(identity) if identity else identity_plan())
    record = dict(status='STARTING', phase=args.phase, reads=[], mmio_writes=False,
                  target_memory_writes=False, hardware_lease_admitted=False,
                  source_sha256={str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest()
                      for p in [Path(__file__), ROOT / 'tools/a16_fan_dma.py', ROOT / 'tools/a16_fan_gpi.py',
                                ROOT / 'tools/a16-control-guard.py']})
    if args.identity_capture:
        record['identity_capture'] = dict(path=str(args.identity_capture),
            sha256=hashlib.sha256(args.identity_capture.read_bytes()).hexdigest())
    if args.streams_capture:
        record['streams_capture'] = dict(path=str(args.streams_capture),
            sha256=hashlib.sha256(args.streams_capture.read_bytes()).hexdigest())
    if args.context_capture:
        record['context_capture'] = dict(path=str(args.context_capture),
            sha256=hashlib.sha256(args.context_capture.read_bytes()).hexdigest())
    args.output.parent.mkdir(parents=True, exist_ok=True)

    def save():
        temp = args.output.with_suffix(args.output.suffix + '.tmp')
        with temp.open('w') as stream:
            json.dump(record, stream, indent=2)
            stream.write('\n')
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp, args.output)

    if args.plan:
        record.update(status='OFFLINE_PLAN', registers=[dict(name=n, address=hex(a)) for n, a in plan])
        save()
        print(json.dumps(dict(status=record['status'], reads=len(plan), output=str(args.output))))
        return 0
    if not (args.idle and args.device and args.generation is not None and args.image_base is not None):
        ap.error('hardware requires --idle --device --generation --image-base')
    sys.path[:0] = [str(ROOT / 'tools'), str(ROOT / 'probes')]
    import run
    from cycle_lib.common import Workspace, require_exclusive
    Guard = runpy.run_path(str(ROOT / 'tools/a16-control-guard.py'))['ControlGuard']
    require_exclusive(Workspace(ROOT))
    with open('/tmp/snapintosh-hardware.lock', 'a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        raw = guard = None
        deadline = time.monotonic() + args.max_seconds
        try:
            save()
            raw = run.connect(args.device, tries=1)
            raw.link.timeout = 0.5
            guard = Guard(raw, record, save)
            raw = None
            capture(guard.proxy, record, save, args.generation, args.image_base, deadline,
                    identity, streams, context_capture)
            print(json.dumps(dict(status=record['status'], output=str(args.output), decoded=record['decoded'])))
            return 0
        except BaseException as exc:
            if guard:
                guard.freeze(f'fan DMA survey refused: {type(exc).__name__}: {exc}')
            record.update(status='REFUSED_OR_FAILED', error=repr(exc))
            save()
            raise
        finally:
            if guard:
                guard.close()
            elif raw:
                raw.link.close()


if __name__ == '__main__':
    sys.exit(main())

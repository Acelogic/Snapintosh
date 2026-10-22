#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Read the retained console ring from a source-bound, audited stopped run."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'probes'))
import run
from monitor_layout import MonitorLayout


def sha(data):
    return hashlib.sha256(data).hexdigest()

def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--device', required=True)
    ap.add_argument('--prefix', required=True)
    args = ap.parse_args()
    if not re.fullmatch(r'[a-z0-9-]+', args.prefix):
        raise ValueError('invalid artifact prefix')
    base = ROOT / 'build' / args.prefix
    outputs = [Path(f'{base}-console-tail{suffix}') for suffix in ('.bin', '.txt', '.json')]
    if any(p.exists() for p in outputs):
        raise ValueError('preserve existing console captures')
    launch = json.loads(Path(f'{base}-launch.json').read_text())
    audit = json.loads(Path(f'{base}-audit.json').read_text())
    if not launch.get('finished') or 'exit_code' not in launch or not audit['runtime_stop_qualified']:
        raise ValueError('capture requires a completed run and qualified stopped audit')
    try:
        os.kill(launch['pid'], 0)
    except ProcessLookupError:
        pass
    else:
        raise ValueError('launcher is still present')
    for name, digest in launch['source_sha256'].items():
        if sha((ROOT / name).read_bytes()) != digest:
            raise ValueError(f'{name} differs from the recorded build')
    layout = MonitorLayout()
    CAPACITY = layout.length('context', 'console_tail')
    blob = (ROOT / 'build/xnuboot.bin').read_bytes()
    digest = sha(blob)
    if digest != launch['monitor_sha256'] or digest != audit['monitor_sha256']:
        raise ValueError('build differs from launch or audit')
    proxy = run.connect(args.device, tries=1)
    try:
        def read(pa, size):
            return b''.join(proxy.readmem(pa+i, min(65536, size-i), live=True)
                            for i in range(0, size, 65536))
        info = proxy.bootinfo()
        work, work_size = run.resident_work(proxy, info)
        if read(info['heap_base'] + run.CODE_AT, len(blob)) != blob:
            raise ValueError('resident monitor differs from the audited build')
        def field(name, size):
            offset = layout.offset('context', name)
            if not 0 <= offset <= min(work_size, layout.size('context')) - size:
                raise ValueError('console field outside monitor context')
            return read(work + offset, size)
        def counters():
            return tuple(struct.unpack('<Q', field(n, 8))[0] for n in
                         ('console_tail_bytes', 'console_len', 'console_dropped'))
        stop = struct.pack('<8Q', *audit['service'])
        if field('services', 64) != stop:
            raise ValueError('resident stop token differs from audit')
        before = counters()
        total, prefix_bytes, dropped = before
        if prefix_bytes != min(total, 1024) or total != prefix_bytes + dropped:
            raise ValueError('ring and legacy console counters disagree')
        raw = field('console_tail', CAPACITY)
        prefix = field('console', 1024)[:prefix_bytes]
        if before != counters() or field('services', 64) != stop:
            raise ValueError('guest state changed during console capture')
        kept = min(total, CAPACITY)
        start = (total-kept) % CAPACITY
        data = (raw[start:] + raw[:start])[:kept]
        omitted = total-kept
        if omitted < prefix_bytes and data[:prefix_bytes-omitted] != prefix[omitted:]:
            raise ValueError('ring differs from overlapping legacy console prefix')
    finally:
        proxy.link.close()
    record = dict(monitor_sha256=digest, total_bytes=total, retained_bytes=kept,
                  omitted_prefix_bytes=omitted, complete=not omitted,
                  legacy_dropped_bytes=dropped, sha256=sha(data),
                  service=audit['service'], source_bound=True,
                  boundary='Stopped monitor console bytes, not proof of GUI or GPU execution.')
    outputs[0].write_bytes(data)
    outputs[1].write_text(data.decode('utf-8', errors='replace'))
    outputs[2].write_text(json.dumps(record, indent=2) + '\n')
    print(json.dumps(record))
    return 0

if __name__ == '__main__':
    raise SystemExit(main())

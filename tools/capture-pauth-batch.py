#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Capture batch-signing counters and public pointers at a qualified stop.

No derived keys or domain seed are read. Signing/restoration counters do not
prove that subsequent guest authentication instructions accepted the outputs.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'probes'))
import run
from monitor_layout import MonitorLayout


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--device', required=True)
    parser.add_argument('--prefix', required=True)
    args = parser.parse_args()
    if not re.fullmatch(r'[a-z0-9-]+', args.prefix):
        raise ValueError('invalid prefix')
    audit = json.loads((ROOT / 'build' / f'{args.prefix}-audit.json').read_text())
    blob = (ROOT / 'build/xnuboot.bin').read_bytes()
    if not audit['runtime_stop_qualified'] or audit['ownership']['mismatches']:
        raise ValueError('requires a qualified stop')
    if hashlib.sha256(blob).hexdigest() != audit['monitor_sha256']:
        raise ValueError('monitor changed')
    layout = MonitorLayout()
    stride = layout.size('pauth_batch_state')
    names = ('attempts', 'calls', 'records', 'failures', 'input_pa', 'count',
             'scratch_pa', 'result_va', 'tbi', 'tbid', 'input_type',
             'failed_index', 'sign_calls', 'restored_calls')
    proxy = run.connect(args.device, tries=1)
    try:
        def read(pa, size):
            return b''.join(proxy.readmem(pa+i, min(65536, size-i), live=True)
                            for i in range(0, size, 65536))

        info = proxy.bootinfo()
        code = info['heap_base'] + run.CODE_AT
        work, work_size = run.resident_work(proxy, info)
        if read(code, len(blob)) != blob:
            raise ValueError('resident monitor differs')
        service = list(struct.unpack('<8Q', read(
            work + layout.offset('context', 'services'), 64)))
        if service != audit['service'] or service[0] or not service[1]:
            raise ValueError('not at saved stop')
        rows = []
        for cpu in range(6):
            base = work + layout.offset('context', 'pauth_batch') + cpu * stride
            raw = read(base, stride)
            row = dict(cpu=cpu)
            row.update({name: struct.unpack_from('<Q', raw, layout.offset(
                'pauth_batch_state', name))[0] for name in names})
            count = min(row['count'], 64)
            entries = [struct.unpack_from('<QQII', raw, layout.offset(
                'pauth_batch_state', 'input') + i * 24) for i in range(count)]
            outputs = struct.unpack_from(f'<{count}Q', raw, layout.offset(
                'pauth_batch_state', 'output'))
            row['last_batch'] = [dict(pointer=hex(e[0]), modifier=hex(e[1]),
                key=e[2], padding=e[3], signed=hex(out))
                for e, out in zip(entries, outputs)]
            row['all_attempts_completed'] = (
                row['attempts'] == row['calls'] and row['failures'] == 0
                and (not row['attempts'] or
                     row['sign_calls'] == row['restored_calls'] == row['count']))
            pointer_base = work + layout.offset('context', 'pauth_pointer') + \
                cpu * layout.size('pauth_pointer_state')
            pointer_raw = read(pointer_base, layout.size('pauth_pointer_state'))
            pointer_names = ('attempts', 'calls', 'signs', 'auths', 'valid',
                'invalid', 'failures', 'pointer', 'modifier', 'key',
                'authenticate', 'tbi', 'tbid', 'stripped', 'computed', 'result',
                'native_calls', 'native_restores')
            row['pointer_service'] = {name: struct.unpack_from('<Q', pointer_raw,
                layout.offset('pauth_pointer_state', name))[0]
                for name in pointer_names}
            rows.append(row)
        report = dict(monitor_sha256=audit['monitor_sha256'], service=service,
            calls=sum(r['calls'] for r in rows), records=sum(r['records'] for r in rows),
            failures=sum(r['failures'] for r in rows), cpus=rows,
            pointer_auths=sum(r['pointer_service']['auths'] for r in rows),
            pointer_valid=sum(r['pointer_service']['valid'] for r in rows),
            pointer_invalid=sum(r['pointer_service']['invalid'] for r in rows),
            boundary='native signing and restoration; guest authentication of these outputs needs separate evidence')
        path = ROOT / 'build' / f'{args.prefix}-pauth-batch.json'
        path.write_text(json.dumps(report, indent=2) + '\n')
        print(json.dumps(dict(path=str(path), calls=report['calls'],
            records=report['records'], failures=report['failures'],
            cpus=[{k: v for k, v in r.items() if k != 'last_batch'}
                  for r in rows]), indent=2))
    finally:
        proxy.link.close()


if __name__ == '__main__':
    main()

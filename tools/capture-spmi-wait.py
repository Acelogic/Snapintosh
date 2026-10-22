#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Read RAM-only controller/clock targets for an audited CPU0 SPMI queue wait."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import runpy
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'probes'))
import run
import xnuboot as xb


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--device', required=True)
    ap.add_argument('--prefix', required=True)
    args = ap.parse_args()
    if not re.fullmatch(r'[a-z0-9-]+', args.prefix):
        raise ValueError('invalid prefix')
    base = ROOT / 'build' / args.prefix
    audit = json.loads(Path(f'{base}-audit.json').read_text())
    stop = json.loads(Path(f'{base}-cpu0-stop.json').read_text())
    if stop['pc'] != '0xfffffe0009a1439c' or stop['snapshot_kind'] != 1:
        raise ValueError('requires the exact native queuePop watchdog stop')
    proxy = run.connect(args.device, tries=1)
    try:
        info = proxy.bootinfo()
        work, work_size = run.resident_work(proxy, info)
        def read(pa, size):
            if not 0 < size <= 0x200000:
                raise ValueError('invalid read size')
            return b''.join(proxy.readmem(pa+i, min(65536, size-i), live=True)
                            for i in range(0, size, 65536))
        monitor = (ROOT / 'build/xnuboot.bin').read_bytes()
        if (hashlib.sha256(monitor).hexdigest() != audit['monitor_sha256'] or
                read(info['heap_base']+run.CODE_AT, len(monitor)) != monitor):
            raise ValueError('monitor differs from audited run')
        layout=runpy.run_path(str(ROOT/'tools/monitor_layout.py'))['MonitorLayout']()
        current = struct.unpack('<36Q', read(work+layout.offset('context','vcpus')+
                                            layout.offset('vcpu','async_regs'), 288))
        if current[33] != int(stop['pc'], 16) or any(
                current[i] != int(stop['registers'][str(i)], 16) for i in range(31)):
            raise ValueError('CPU0 registers differ from captured stop')
        g = audit['geometry']
        params_pa, = struct.unpack('<Q', read(work, 8))
        params = struct.unpack(f'<{xb.PARAMS_WORDS}Q', read(params_pa, xb.PARAMS_WORDS*8))
        if (params[0], params[30], params[31]) != (g['root'], g['ram_low'], g['ram_high']):
            raise ValueError('geometry differs from audited run')
        def ram(pa, size):
            if not g['ram_low'] <= pa < pa+size <= g['ram_high']:
                raise ValueError('read outside guest RAM')
            return read(pa, size)
        def va_read(va, size):
            if not 0 < size <= 0x4000-(va & 0x3fff):
                raise ValueError('read crosses guest page')
            table = g['root']
            for shift in (36, 25, 14):
                desc, = struct.unpack('<Q', ram(table+8*((va >> shift) & 2047), 8))
                if desc & 3 != 3:
                    raise ValueError('unmapped guest RAM')
                table = desc & 0x0000ffffffffc000
            return ram(table+(va & 0x3fff), size)
        def canonical(value):
            return (value & 0xffffffffffff) | 0xffff000000000000
        controller = current[22]
        raw = va_read(controller, 0x200)
        vtable = canonical(struct.unpack_from('<Q', raw)[0])
        targets = {}
        for label, address in [('waitForResponse', vtable+0x9c0),
                               ('runInterruptMode', vtable+0x9c8),
                               ('runPolledMode', vtable+0x9d0),
                               ('deadline_import', 0xfffffe00081fb058),
                               ('absolute_time_import', 0xfffffe00081fb068)]:
            value, = struct.unpack('<Q', va_read(address, 8))
            targets[label] = dict(slot=hex(address), target=hex(canonical(value)))
        fields = {name: struct.unpack_from(fmt, raw, off)[0] for name, fmt, off in
                  [('debug', '<I', 0x104), ('irq_vector', '<I', 0x188),
                   ('slave', '<I', 0x194), ('timeout', '<I', 0x198),
                   ('deadline', '<Q', 0x1a0), ('busy', '<B', 0x1a9)]}
        result = dict(controller=hex(controller), vtable=hex(vtable), fields=fields,
                      targets=targets, raw_hex=raw.hex(), monitor_sha256=audit['monitor_sha256'])
    finally:
        proxy.link.close()
    output = Path(f'{base}-spmi-wait.json')
    output.write_text(json.dumps(result, indent=2)+'\n')
    print(json.dumps(dict(controller=result['controller'], fields=fields, targets=targets)))


if __name__ == '__main__':
    main()

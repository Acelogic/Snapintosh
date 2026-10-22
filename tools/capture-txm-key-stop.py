#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Read a stopped primary TXM26 call without claiming a full SMP audit."""
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
    log = Path(f'{base}.log').read_text()
    match = re.search(r'  monitor stop PC (0x[0-9a-f]+), SP (0x[0-9a-f]+), '
                      r'PSTATE (0x[0-9a-f]+)(.*?)(?:  exception return|\Z)', log, re.S)
    if not match:
        raise ValueError('no saved primary monitor stop')
    expected = {int(k): int(v, 16) for k, v in
                re.findall(r'x(\d+)\s+(0x[0-9a-f]+)', match[4])}
    if len(expected) != 31 or expected[16] != 0x200000000001a:
        raise ValueError('saved stop is not TXM26')
    layout = runpy.run_path(str(ROOT / 'tools/monitor_layout.py'))['MonitorLayout']()
    blob = (ROOT / 'build/xnuboot.bin').read_bytes()
    proxy = run.connect(args.device, tries=1)
    try:
        def read(pa, size):
            if not 0 < size <= 0x40000:
                raise ValueError('capture bound')
            return b''.join(proxy.readmem(pa+i, min(65536, size-i), live=True)
                            for i in range(0, size, 65536))

        info = proxy.bootinfo()
        work, work_size = run.resident_work(proxy, info)
        if read(info['heap_base'] + run.CODE_AT, len(blob)) != blob:
            raise ValueError('resident monitor differs')
        cpu = work + layout.offset('context', 'vcpus')
        service_pa = work + layout.offset('context', 'services')
        service = read(service_pa, 64)
        if struct.unpack('<8Q', service)[1] != 0x100000001:
            raise ValueError('primary is not the stopped owner')
        regs_pa = cpu + layout.offset('vcpu', 'async_regs')
        snapshot = read(regs_pa, 288)
        regs = struct.unpack('<36Q', snapshot)
        if (any(regs[i] != expected[i] for i in range(31)) or
                tuple(int(match[i], 16) for i in (1, 2, 3)) !=
                (regs[33], regs[31], regs[32])):
            raise ValueError('resident registers differ from saved stop')
        params_pa, = struct.unpack('<Q', read(work, 8))
        if not params_pa or params_pa & 0x3fff or params_pa + xb.PARAMS_WORDS*8 >= 1 << 36:
            raise ValueError('invalid parameter placement')
        params = struct.unpack(f'<{xb.PARAMS_WORDS}Q', read(params_pa, xb.PARAMS_WORDS*8))
        root, tcr = struct.unpack('<2Q', read(cpu + layout.offset('vcpu', 'guest_ttbr1'), 16))
        if root != params[0] or (tcr >> 30) & 3 != 1 or (tcr >> 16) & 63 != 17:
            raise ValueError('unexpected kernel translation regime')
        low, high = params[30:32]
        if not low <= params_pa < params_pa + xb.PARAMS_WORDS*8 <= high < 1 << 36:
            raise ValueError('parameters outside declared guest RAM')

        def ram(pa, size):
            if not low <= pa < pa + size <= high:
                raise ValueError('outside guest RAM')
            return read(pa, size)

        def virtual(va, size):
            if va < 0xffff800000000000 or size > 0x4000 - (va & 0x3fff):
                raise ValueError('invalid bounded kernel read')
            table = root
            for shift in (36, 25, 14):
                desc, = struct.unpack('<Q', ram(table + 8*((va >> shift) & 2047), 8))
                if desc & 3 != 3 or desc & 0x3000:
                    raise ValueError('unexpected page-table descriptor')
                table = desc & 0x0000ffffffffc000
            return ram(table + (va & 0x3fff), size)

        public_key = virtual(regs[1], 97)
        frames, fp = [], regs[29]
        for _ in range(20):
            if fp & 15:
                break
            previous, lr = struct.unpack('<2Q', virtual(fp, 16))
            frames.append(dict(fp=hex(fp), lr=hex((lr & ((1 << 48)-1)) | 0xffff000000000000)))
            if previous <= fp or previous - fp > 0x4000:
                break
            fp = previous
        if read(service_pa, 64) != service or read(regs_pa, 288) != snapshot:
            raise ValueError('stop changed while reading')
        report = dict(monitor_sha256=hashlib.sha256(blob).hexdigest(),
                      pc=hex(regs[33]), selector=26, input_va=hex(regs[1]),
                      public_key_bytes=97, public_key_sha256=hashlib.sha256(public_key).hexdigest(),
                      first_byte=public_key[0], frames=frames,
                      boundary='read-only primary stop capture; no full SMP qualification')
        path = Path(f'{base}-txm-key.json')
        path.write_text(json.dumps(report, indent=2)+'\n')
        print(json.dumps(dict(path=str(path), **report)))
    finally:
        proxy.link.close()


if __name__ == '__main__':
    main()

#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Capture the PMGR descriptor from a stopped 26A428 OSArray growth frame."""
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
    if stop['monitor_sha256'] != audit['monitor_sha256']:
        raise ValueError('stop and audit monitor hashes differ')
    blob = xb.DEFAULT_KERNELCACHE.read_bytes()
    if hashlib.sha256(blob).hexdigest() != 'dc9019ae39187b36936c2c513b485e513f15cd966b5c887ac88ffd2925976c62':
        raise ValueError('frame contract requires J700 26A428')
    # The indexed OSArray::setObject prologue saves x25 at fp-0x38,
    # x21 at fp-0x18 and x20 at fp-0x10. PMGR's indirect call returns here.
    frames = [f for f in stop['frame_chain']
              if int(f['canonical_lr'], 16) == 0xfffffe0009796908]
    if len(frames) != 1:
        raise ValueError('missing unique PMGR array construction frame')
    fp = int(frames[0]['fp'], 16)
    sp = int(stop['sp'], 16)
    stack = bytes.fromhex(stop['stack_hex'])
    if not sp <= fp - 0x50 < fp + 16 <= sp + len(stack):
        raise ValueError('saved PMGR registers outside captured stack')
    descriptor, = struct.unpack_from('<Q', stack, fp - 0x10 - sp)
    array, = struct.unpack_from('<Q', stack, fp - 0x18 - sp)
    counter, = struct.unpack_from('<Q', stack, fp - 0x38 - sp)
    proxy = run.connect(args.device, tries=1)
    try:
        def read(pa, size):
            if not 0 < size <= 0x200000:
                raise ValueError('invalid read size')
            return b''.join(proxy.readmem(pa+i, min(65536, size-i), live=True)
                            for i in range(0, size, 65536))
        info = proxy.bootinfo()
        work, work_size = run.resident_work(proxy, info)
        monitor = (ROOT / 'build/xnuboot.bin').read_bytes()
        if (hashlib.sha256(monitor).hexdigest() != audit['monitor_sha256'] or
                read(info['heap_base'] + run.CODE_AT, len(monitor)) != monitor):
            raise ValueError('resident monitor differs from audit')
        param_pa, = struct.unpack('<Q', read(work, 8))
        params = struct.unpack(f'<{xb.PARAMS_WORDS}Q', read(param_pa, xb.PARAMS_WORDS*8))
        g = audit['geometry']
        if (params[0], params[30], params[31]) != (g['root'], g['ram_low'], g['ram_high']):
            raise ValueError('resident geometry differs from audit')
        def ram(pa, size):
            if not g['ram_low'] <= pa < pa + size <= g['ram_high']:
                raise ValueError('outside guest RAM')
            return read(pa, size)
        def virtual(va, size):
            if not 0 < size <= 0x4000:
                raise ValueError('invalid virtual read size')
            result = bytearray()
            while size:
                table = params[0]
                for shift in (36, 25, 14):
                    pte, = struct.unpack('<Q', ram(table+8*((va >> shift) & 2047), 8))
                    if pte & 3 != 3:
                        raise ValueError('unmapped guest VA')
                    table = pte & 0x0000ffffffffc000
                n = min(size, 0x4000-(va & 0x3fff))
                result.extend(ram(table+(va & 0x3fff), n))
                va += n
                size -= n
            return bytes(result)
        if virtual(sp, len(stack)) != stack:
            raise ValueError('resident stack differs from stopped capture')
        raw = virtual(descriptor, 0x118)
        array_raw = virtual(array, 0x30)
        count, = struct.unpack_from('<I', raw, 8)
        tables = {}
        for offset in (0x78, 0x98):
            va, = struct.unpack_from('<Q', raw, offset)
            if va and count:
                # +78 is the raw one-record DT table in this bound failure;
                # +98 is the derived array, sized by the native state count.
                data = virtual(va, (1 if offset == 0x78 else min(count, 16))*8)
                tables[hex(offset)] = dict(va=hex(va), first_entries=list(struct.iter_unpack('<2I', data)))
        if proxy.exceptions:
            raise ValueError('proxy exception during RAM capture')
        result = dict(monitor_sha256=audit['monitor_sha256'], frame=hex(fp),
                      descriptor_va=hex(descriptor), descriptor_hex=raw.hex(),
                      state_count=count, loop_counter=counter, tables=tables,
                      array_va=hex(array), array_hex=array_raw.hex(),
                      boundary='read-only mapped guest RAM; no MMIO reads or resume')
    finally:
        proxy.link.close()
    Path(f'{base}-pmgr-perf.json').write_text(json.dumps(result, indent=2)+'\n')
    print(json.dumps(result))


if __name__ == '__main__':
    main()

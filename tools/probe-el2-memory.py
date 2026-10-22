#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Read the boot CPU's EL2 translation/cache regime; no control-register writes.

Uses the read-only-query scratch at heap+480000/490000. Run only with a
stopped guest and one proxy client. Does not start any CPU or change GIC state.
"""
import argparse
import json
from pathlib import Path
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'probes'))
import run


def collect(proxy, blob):
    info = proxy.bootinfo()
    if info['current_el'] != 2 or info['heap_size'] < 0x490080 or len(blob) > 0x10000:
        raise ValueError('invalid EL2 inventory scratch')
    code, out = info['heap_base']+0x480000, info['heap_base']+0x490000
    proxy.writemem(code, blob)
    proxy.flush_code(code, len(blob))
    proxy.writemem(out, bytes(128))
    proxy.call(code, out, timeout=10)  # never retry an uncertain call
    words = struct.unpack('<16Q', proxy.readmem(out, 128, live=True))
    if words[0] != 8 or words[11] != code or words[12] != 1 or proxy.exceptions:
        raise ValueError('incomplete EL2 memory inventory')
    names = ('current_el_raw', 'mpidr', 'sctlr', 'tcr', 'ttbr0', 'mair', 'hcr',
             'cnthctl', 'cntfrq', 'vbar', 'sp', 'pc', 'done', 'reserved0', 'reserved1', 'reserved2')
    result = dict(zip(names, map(hex, words)))
    result.update(code=hex(code), report=hex(out),
                  mmu_enabled=bool(words[2]&1), data_cache_enabled=bool(words[2]&4),
                  instruction_cache_enabled=bool(words[2]&0x1000))
    proxy.nop()
    return result


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--device', required=True)
    ap.add_argument('--output', required=True, type=Path)
    args = ap.parse_args()
    blob = run.build('el2-memory', ROOT/'build/cpu-probe')
    proxy = run.connect(args.device, tries=1)
    try:
        result = collect(proxy, blob)
    finally:
        proxy.link.close()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2)+'\n')
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()

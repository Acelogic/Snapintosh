#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Read the boot CPU's MMFR3 without replacing the stopped monitor image."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'probes'))
from run import CODE_AT, OUT_AT, connect


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--device', required=True)
    ap.add_argument('--output', type=Path, required=True)
    args = ap.parse_args()
    blob = (ROOT / 'build/xnuboot.bin').read_bytes()
    probe_offset = OUT_AT - CODE_AT - 4096
    if len(blob) > probe_offset:
        raise ValueError('no reserved code padding for the register probe')
    proxy = connect(args.device, tries=2)
    try:
        info = proxy.bootinfo()
        code = info['heap_base'] + CODE_AT
        resident = proxy.readmem(code, len(blob))
        if resident != blob:
            raise ValueError('resident monitor differs from local build')
        address = code + probe_offset
        saved = proxy.readmem(address, 8)
        # MRS X0, ID_AA64MMFR3_EL1 (S3_0_C0_C7_3); RET.
        probe = struct.pack('<2I', 0xd5380760, 0xd65f03c0)
        try:
            proxy.writemem(address, probe)
            proxy.flush_code(address, len(probe))
            value = proxy.call(address, timeout=10)
        finally:
            proxy.writemem(address, saved)
            proxy.flush_code(address, len(saved))
        if proxy.readmem(address, 8) != saved:
            raise ValueError('probe padding was not restored')
        result = dict(monitor_sha256=hashlib.sha256(blob).hexdigest(),
                      boot_cpu_only=True, mmfr3=hex(value),
                      s1pie=(value >> 8) & 15, s1poe=(value >> 16) & 15,
                      padding_restored=True)
        args.output.write_text(json.dumps(result, indent=2) + '\n')
        print(json.dumps(result))
    finally:
        proxy.link.close()


if __name__ == '__main__':
    main()

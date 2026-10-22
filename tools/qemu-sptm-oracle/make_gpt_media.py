#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Assemble the same GPT RAM media Snapintosh boots (stock BaseSystem root +
auxiliary ISC/xART image) with Snapintosh's own probes/bootmedia.py, as one
file for qemu-sptm's -ramdisk. Neither APFS payload is modified."""
import sys, mmap
sys.path.insert(0, str(__import__('pathlib').Path(__file__).resolve().parents[2] / 'probes'))
import bootmedia
root_path, isc_path, out = sys.argv[1:4]
with open(root_path, 'rb') as r, open(isc_path, 'rb') as i:
    root = mmap.mmap(r.fileno(), 0, access=mmap.ACCESS_READ)
    isc = mmap.mmap(i.fileno(), 0, access=mmap.ACCESS_READ)
    chunks, desc = bootmedia.assemble(root, isc, 0, 1 << 36)
    with open(out, 'wb') as o:
        o.truncate(desc['bytes'])
        for off, data in sorted(chunks.items()):
            o.seek(off)
            for p in range(0, len(data), 64 << 20):
                o.write(data[p:p + (64 << 20)])
    print(desc)

#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""SHA-256 of every section's file bytes in a 64-bit Mach-O (zerofill sections by size only), and of the dyld fixup /
symbol tables' non-debug content is left out: what a kext runs, not where its objects were built.
Usage: macho-sections.py BINARY [BINARY2]  (two: print only the sections that differ)."""
import hashlib, struct, sys

def sections(path):
    data = open(path, 'rb').read()
    magic, _, _, _, ncmds, _, _, _ = struct.unpack_from('<IiiIIIII', data, 0)
    assert magic == 0xfeedfacf, 'not a 64-bit Mach-O'
    off, out = 32, {}
    for _ in range(ncmds):
        cmd, size = struct.unpack_from('<II', data, off)
        if cmd == 0x19:                                   # LC_SEGMENT_64
            nsects = struct.unpack_from('<I', data, off + 64)[0]
            s = off + 72
            for _ in range(nsects):
                sect, seg = (x.rstrip(b'\0').decode() for x in struct.unpack_from('<16s16s', data, s))
                addr, sz, fo = struct.unpack_from('<QQI', data, s + 32)
                flags = struct.unpack_from('<I', data, s + 64)[0]
                zerofill = (flags & 0xff) in (0x1, 0xc, 0x12)
                body = b'' if zerofill else data[fo:fo + sz]
                out[f'{seg},{sect}'] = f'{addr:#x} {sz:#x} ' + hashlib.sha256(body).hexdigest()[:16]
                s += 80
        off += size
    return out

a = sections(sys.argv[1])
if len(sys.argv) == 2:
    for k, v in a.items(): print(f'{k:28} {v}')
else:
    b = sections(sys.argv[2])
    diff = [k for k in sorted(set(a) | set(b)) if a.get(k) != b.get(k)]
    for k in diff: print(f'{k:28} {a.get(k)} | {b.get(k)}')
    print(f'{len(set(a) | set(b)) - len(diff)} of {len(set(a) | set(b))} sections identical')

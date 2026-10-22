#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Name kernel addresses from a run using the KDK's symbols.

The J700 26A428 kernelcache's com.apple.kernel and the KDK's
kernel.release.t8140 are the same binary (both LC_UUID
F9F468D7-1F50-354A-BECD-6BD6C1C834AD), but the kernelcache builder moved
every segment. So an address is translated by the segment it falls in,
then looked up in the KDK kernel's symbol table.

  tools/kc-symbolicate.py 0xfffffe000ba69c18 0xfffffe000ba6a2d0 ...
  tools/kc-symbolicate.py < addresses.txt      # one address per line
"""
import bisect
import runpy
import struct
import subprocess
import sys
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
KERNELCACHE = ROOT / 'downloads/extracted/j700ap/kernelcache.release.mac17p'
KDK_KERNEL = Path('/Library/Developer/KDKs/KDK_27.0_26A428.kdk/System/Library/Kernels/kernel.release.t8140')
# Full DWARF (static functions, inlined frames, file:line); the release
# kernel's own symbol table has only exported names.
KDK_DSYM = KDK_KERNEL.with_name(KDK_KERNEL.name + '.dSYM') / 'Contents/Resources/DWARF' / KDK_KERNEL.name
KERNEL_UUID = uuid.UUID('F9F468D7-1F50-354A-BECD-6BD6C1C834AD')
LC_SEGMENT_64, LC_UUID = 0x19, 0x1B


def macho_segments(data, off=0):
    """{segname: (vmaddr, vmsize)} and the LC_UUID of the Mach-O at off."""
    ncmds = struct.unpack_from('<I', data, off + 16)[0]
    p, segs, found = off + 32, {}, None
    for _ in range(ncmds):
        cmd, size = struct.unpack_from('<II', data, p)
        if cmd == LC_SEGMENT_64:
            name = bytes(data[p + 8:p + 24]).rstrip(b'\0').decode()
            segs[name] = struct.unpack_from('<QQ', data, p + 24)
        elif cmd == LC_UUID:
            found = uuid.UUID(bytes=bytes(data[p + 8:p + 24]))
        p += size
    return segs, found


class Symbolicator:
    def __init__(self):
        kc = runpy.run_path(str(ROOT / 'tools/kc-xref.py'))['Kernelcache'](KERNELCACHE)
        off = next(o for name, _, o in kc.entries if name == 'com.apple.kernel')
        self.kc_segs, kc_uuid = macho_segments(kc.data, off)
        kdk = KDK_KERNEL.read_bytes()
        self.kdk_segs, kdk_uuid = macho_segments(kdk)
        if kc_uuid != KERNEL_UUID or kdk_uuid != KERNEL_UUID:
            raise SystemExit(f'UUID mismatch: kernelcache {kc_uuid}, KDK {kdk_uuid}')
        out = subprocess.run(['nm', '-n', '-arch', 'arm64e', str(KDK_KERNEL)],
                             capture_output=True, text=True, check=True).stdout
        self.addrs, self.names = [], []
        for line in out.splitlines():
            parts = line.split()
            if len(parts) == 3 and parts[1] in 'tTdDsSbB':
                self.addrs.append(int(parts[0], 16))
                self.names.append(parts[2])

    def translate(self, va):
        """(segment, KDK address) for a kernelcache address, or (None, None)."""
        best = None
        for name, (vm, size) in self.kc_segs.items():
            if size and vm <= va < vm + size and name in self.kdk_segs:
                if best is None or vm > self.kc_segs[best][0]:
                    best = name
        if best is None:
            return None, None
        return best, self.kdk_segs[best][0] + (va - self.kc_segs[best][0])

    def name(self, va):
        seg, kva = self.translate(va)
        if kva is None:
            return f'{va:#x}  (not in com.apple.kernel; a kext or data)'
        i = bisect.bisect_right(self.addrs, kva) - 1
        if i < 0:
            return f'{va:#x}  {seg} (no symbol)'
        return f'{va:#x}  {self.names[i]}+{kva - self.addrs[i]:#x}  [{seg}]'


    def resolve(self, vas):
        """One atos pass over the dSYM for every translatable address; the
        nearest exported symbol is the fallback when there is no dSYM."""
        translated = [(va,) + self.translate(va) for va in vas]
        wanted = [kva for _va, _seg, kva in translated if kva is not None]
        dwarf = {}
        if wanted and KDK_DSYM.exists():
            out = subprocess.run(['atos', '-o', str(KDK_DSYM), '-arch', 'arm64e'] +
                                 [hex(k) for k in wanted], capture_output=True, text=True).stdout
            dwarf = dict(zip(wanted, out.splitlines()))
        lines = []
        for va, seg, kva in translated:
            if kva is None:
                lines.append(self.name(va))
            elif kva in dwarf and not dwarf[kva].startswith('0x'):
                lines.append(f'{va:#x}  {dwarf[kva].replace(" (in kernel.release.t8140)", "")}  [{seg}]')
            else:
                lines.append(self.name(va))
        return lines


def main(argv):
    s = Symbolicator()
    values = argv or [line.strip() for line in sys.stdin if line.strip()]
    for line in s.resolve([int(v, 16) for v in values]):
        print(line)


if __name__ == '__main__':
    main(sys.argv[1:])

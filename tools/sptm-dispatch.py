#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Print SPTM's own dispatch table: endpoint number -> Apple's name and handler.

Every endpoint this project implements was named by inference: watch what XNU
does with the answer, and give the call the name that behaviour deserves. That
works and it is slow, and two of the names it produced were wrong in ways no
single run would have shown.

Apple ships the answer. SPTM's `__DATA_CONST` holds one array per dispatch
table of

    struct { void *handler; uint64_t flags; const char *name; };      /* 0x18 */

indexed by endpoint, and the name is the `SPTM_FUNCTIONID_*` string. The
pointers are stored as chained fixups rather than as addresses, which is why a
plain search for a function's address inside the binary finds nothing: the low
30 bits of each slot are the target's offset from the Mach-O header and the top
bits are the link to the next fixup.

    tools/sptm-dispatch.py downloads/extracted/j700ap/sptm.t8140.release

The default table is the one XNU calls: domain 0, table 0, `XNU_BOOTSTRAP`. Pass
--at to read another array in the same format; --scan lists the ones it can
find, which is how the XNU table's address was found in the first place.

The layout is not asserted, it is checked: `--verify` re-derives it from the
endpoints whose numbers are already known from the kernelcache's own call stubs
(`tools/kc-analyze.py`), and refuses to print a table that disagrees with them.
"""
import argparse
import pathlib
import struct
import sys

LC_SEGMENT_64 = 0x19
MH_MAGIC_64 = 0xFEEDFACF
ENTRY_SIZE = 0x18

# The XNU_BOOTSTRAP table in sptm.t8140.release (macOS 27 build 26A428, j700ap).
# Its address is a fact about this build; --scan finds it in another one.
XNU_BOOTSTRAP_VA = 0xFFFFFFF027022350

# Endpoints whose numbers come from somewhere other than this table: the
# kernelcache's call stubs say which endpoint each monitor call site uses, and
# these are the ones whose behaviour is independently established (see
# docs/BOOT-CHAIN.md section 5 and probes/xnuboot.c). If the table does not
# agree with all of them, the layout has been read wrongly.
KNOWN = {
    0: 'SPTM_FUNCTIONID_LOCKDOWN',
    2: 'SPTM_FUNCTIONID_MAP_PAGE',
    14: 'SPTM_FUNCTIONID_REGISTER_CPU',
    15: 'SPTM_FUNCTIONID_FIXUPS_COMPLETE',
    18: 'SPTM_FUNCTIONID_REGISTER_EXC_RETURN',
    45: 'SPTM_FUNCTIONID_SPTM_SERIAL_PUTC',
    46: 'SPTM_FUNCTIONID_SPTM_SERIAL_DISABLE',
}


def segments(data):
    magic, _, _, _, ncmds = struct.unpack_from('<IiiII', data, 0)
    if magic != MH_MAGIC_64:
        raise SystemExit('not a 64-bit Mach-O')
    out, off = [], 32
    for _ in range(ncmds):
        cmd, size = struct.unpack_from('<II', data, off)
        if cmd == LC_SEGMENT_64:
            name = data[off + 8:off + 24].rstrip(b'\0').decode()
            out.append((name,) + struct.unpack_from('<QQQQ', data, off + 24))
        off += size
    return out


class Image:
    def __init__(self, path):
        self.data = pathlib.Path(path).read_bytes()
        self.segs = segments(self.data)
        self.base = min(vmaddr for _, vmaddr, _, _, _ in self.segs)

    def locate(self, va):
        """(segment name, file offset) for a virtual address."""
        for name, vmaddr, vmsize, fileoff, filesize in self.segs:
            if vmaddr <= va < vmaddr + vmsize:
                offset = va - vmaddr
                return name, (fileoff + offset if offset < filesize else None)
        return None, None

    def word(self, va):
        _, off = self.locate(va)
        return None if off is None else struct.unpack_from('<Q', self.data, off)[0]

    def pointer(self, va):
        """A chained-fixup slot, as the address it will hold once linked.

        DYLD_CHAINED_PTR_64_KERNEL_CACHE: the target is the low 30 bits, as an
        offset from the image base. The rest is signing and the chain link, and
        neither changes where it points."""
        raw = self.word(va)
        if not raw:
            return 0
        return self.base + (raw & 0x3FFFFFFF)

    def string(self, va, limit=200):
        name, off = self.locate(va)
        if off is None:
            return None
        end = self.data.find(b'\0', off, off + limit)
        if end < 0:
            return None
        try:
            text = self.data[off:end].decode('ascii')
        except UnicodeDecodeError:
            return None
        return text if text.isprintable() else None


def read_table(image, va, count):
    """[(endpoint, name, handler, flags)], stopping at `count` entries."""
    out = []
    for n in range(count):
        entry = va + n * ENTRY_SIZE
        handler = image.pointer(entry)
        flags = image.word(entry + 8)
        name = image.string(image.pointer(entry + 0x10))
        if flags is None:
            break
        out.append((n, name, handler, flags))
    return out


def verify(rows):
    """Does this table agree with the endpoints we already knew?"""
    named = {n: name for n, name, _, _ in rows if name}
    wrong = [(n, expected, named.get(n)) for n, expected in KNOWN.items()
             if named.get(n) != expected]
    return wrong


def scan(image):
    """Every address in the image that looks like the head of one of these."""
    found = []
    for name, vmaddr, vmsize, fileoff, filesize in image.segs:
        if 'DATA' not in name or not filesize:
            continue
        for offset in range(0, min(vmsize, filesize) - ENTRY_SIZE * 4, 8):
            va = vmaddr + offset
            rows = read_table(image, va, 4)
            if len(rows) < 4:
                continue
            # Four consecutive entries, each a handler in an executable segment,
            # a zero middle word, and a printable name.
            def ok(row):
                _, nm, handler, flags = row
                seg, _ = image.locate(handler) if handler else (None, None)
                return nm and handler and flags == 0 and seg and 'EXEC' in seg
            if all(ok(r) for r in rows):
                found.append((va, rows[0][1]))
    return found


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('image')
    ap.add_argument('--at', type=lambda v: int(v, 0), default=XNU_BOOTSTRAP_VA,
                    help='the table to read (default: XNU_BOOTSTRAP)')
    ap.add_argument('--count', type=int, default=51,
                    help='how many endpoints (default: 51, XNU_BOOTSTRAP 0x0..0x32)')
    ap.add_argument('--scan', action='store_true',
                    help='find tables in this format instead of printing one')
    ap.add_argument('--verify', action='store_true',
                    help='exit non-zero unless the known endpoints line up')
    args = ap.parse_args()

    image = Image(args.image)

    if args.scan:
        heads = scan(image)
        print(f'{len(heads)} candidate dispatch tables:')
        seen = set()
        for va, first in heads:
            if va - ENTRY_SIZE in seen:      # the same table, one entry in
                seen.add(va)
                continue
            seen.add(va)
            print(f'  {va:#018x}  starts {first}')
        return 0

    rows = read_table(image, args.at, args.count)
    if not rows:
        raise SystemExit(f'nothing readable at {args.at:#x}')

    wrong = verify(rows)
    if wrong:
        print('This table does not agree with the endpoints already established '
              'from the kernelcache:')
        for n, expected, got in wrong:
            print(f'  endpoint {n:#x}: expected {expected}, table says {got}')
        print('\nThe layout has been read wrongly; the names below would be '
              'off by however far the disagreement is.')
        if args.verify:
            return 1
    elif args.verify:
        print(f'{len(KNOWN)} independently known endpoints all match.')

    print(f'{args.image}: dispatch table at {args.at:#018x}, '
          f'{len(rows)} entries of {ENTRY_SIZE:#x}\n')
    for n, name, handler, flags in rows:
        note = f'  flags={flags:#x}' if flags else ''
        if not name and not handler:
            print(f'  {n:>3} {n:#04x}   --')
            continue
        print(f'  {n:>3} {n:#04x}   {name or "<unnamed>":<44} '
              f'{handler:#018x}{note}')

    live = sum(1 for _, name, handler, _ in rows if name or handler)
    print(f'\n{live} of {len(rows)} endpoints are implemented; the rest are holes '
          'in the numbering, not calls this monitor refuses.')
    return 0


if __name__ == '__main__':
    sys.exit(main())

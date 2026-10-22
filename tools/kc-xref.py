#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Who references a string, who calls a function, what a function calls, in order.

Settling "does X run before Y" in a stripped MH_FILESET kernelcache is three
questions asked over and over: which function owns this literal, who branches
to it, and what does it branch to between one literal and the next. This
answers them from one index over the selected image's `__TEXT_EXEC.__text`, so the
answer to R1 (docs/PLAN-HISTORY-20260922.md) took an afternoon instead of a week.

    tools/kc-xref.py <kernelcache> string 'initialize_screen: b='
    tools/kc-xref.py <kernelcache> callers 0xfffffe000bc0a34c
    tools/kc-xref.py <kernelcache> calls   0xfffffe000c3f7384
    tools/kc-xref.py <kernelcache> startup --min-subsystem 17
    tools/kc-xref.py <kernelcache> --scope com.apple.filesystems.apfs string system-volume-auth-blob

The default scope is com.apple.kernel; it excludes kext code. Select a kext
explicitly before interpreting missing references in that driver.

Facts this encodes, each of which cost a wrong answer before it was learned:

  * A fileset entry's `vmaddr` is that kext's Mach-O *header*. Attributing an
    address to a kext means parsing that entry's own LC_SEGMENT_64 list; the
    top-level segments only answer "file offset of this VA".
  * Release arm64e: functions that save LR use `pacibsp`, sometimes preceded
    by `bti c`. Include that landing instruction in the inferred start. Leaf
    functions without one are absorbed into their predecessor; `calls` is
    therefore exact for a callee address and approximate for a range.
  * A callee with no `bl` callers is not dead. Tail calls are plain `b`, and
    `PE_initialize_console` is reached only through pointers, so `callers`
    reports both kinds and says which.
  * `adrp`+`add`/`ldr` pairs are matched within eight instructions. The
    compiler keeps a page register alive far longer than that (36 insns in
    pe_arm_init_interrupts), so a missing reference is evidence, not proof;
    `--window` widens it when a specific slot matters.
  * `__BOOTDATA.__init_entry_set` is XNU's STARTUP() table: 24-byte entries of
    {u32 subsystem, u32 rank, func, arg}, the function pointer a chained fixup
    (auth: low 32 bits, plain: low 43 bits, both offsets from the fileset base).
    Everything in it with subsystem <= the value passed to
    kernel_startup_initialize_upto() at a given call site has run by then.
"""
import argparse
import bisect
import hashlib
import os
import pathlib
import pickle
import struct
import sys
import tempfile

LC_SEGMENT_64 = 0x19
LC_FILESET_ENTRY = 0x80000035
MH_MAGIC_64 = 0xFEEDFACF
PACIBSP = 0xD503237F
KERNEL = 'com.apple.kernel'


class Kernelcache:
    def __init__(self, path, *, scope=KERNEL, segment='__TEXT_EXEC'):
        self.path = pathlib.Path(path)
        self.data = self.path.read_bytes()
        _, self.top, self.entries = self._header(0)
        self.kext = {name: self._header(off)[1] for name, _, off in self.entries}
        if not self.entries:
            self.kext[KERNEL] = self.top  # standalone SPTM/TXM Mach-O
        if scope not in self.kext:
            raise ValueError(f'no fileset image {scope!r}')
        self.scope = scope
        self.segment = segment
        self._index = None

    def _header(self, off):
        magic, _, _, ftype, ncmds = struct.unpack_from('<IiiII', self.data, off)
        if magic != MH_MAGIC_64:
            raise SystemExit(f'{self.path.name}: not a 64-bit Mach-O at {off:#x}')
        segs, entries, p = [], [], off + 32
        for _ in range(ncmds):
            cmd, size = struct.unpack_from('<II', self.data, p)
            if cmd == LC_SEGMENT_64:
                name = self.data[p + 8:p + 24].rstrip(b'\0').decode()
                vmaddr, vmsize, fileoff, filesize = struct.unpack_from('<QQQQ', self.data, p + 24)
                nsects = struct.unpack_from('<I', self.data, p + 64)[0]
                sects = []
                for i in range(nsects):
                    q = p + 72 + i * 80
                    sname = self.data[q:q + 16].rstrip(b'\0').decode()
                    saddr, ssize = struct.unpack_from('<QQ', self.data, q + 32)
                    sects.append((sname, saddr, ssize))
                segs.append((name, vmaddr, vmsize, fileoff, filesize, sects))
            elif cmd == LC_FILESET_ENTRY:
                vmaddr, fileoff, strx = struct.unpack_from('<QQI', self.data, p + 8)
                name = self.data[p + strx:self.data.index(b'\0', p + strx)].decode()
                entries.append((name, vmaddr, fileoff))
            p += size
        return ftype, segs, entries

    # -- addresses -----------------------------------------------------------
    def va2off(self, va):
        for _, vmaddr, vmsize, fileoff, filesize, _ in self.top:
            if vmaddr <= va < vmaddr + min(vmsize, filesize):
                return fileoff + (va - vmaddr)
        return None

    def off2va(self, off):
        for _, vmaddr, _, fileoff, filesize, _ in self.top:
            if fileoff <= off < fileoff + filesize:
                return vmaddr + (off - fileoff)
        return None

    def u32(self, va):
        return struct.unpack_from('<I', self.data, self.va2off(va))[0]

    def cstr(self, va, limit=200):
        o = self.va2off(va)
        end = self.data.find(b'\0', o, o + limit)
        return self.data[o:end if end >= 0 else o + limit].decode('latin1')

    def section(self, seg, sec, kext=KERNEL):
        for segname, _, _, _, _, sects in self.kext[kext]:
            if segname == seg:
                for sname, saddr, ssize in sects:
                    if sname == sec:
                        return saddr, ssize
        raise KeyError((kext, seg, sec))

    def owner(self, va):
        """(kext, segment, section) whose own LC_SEGMENT_64 covers va."""
        for name, segs in self.kext.items():
            for segname, svm, svs, _, _, sects in segs:
                if svm <= va < svm + svs:
                    sec = next((s[0] for s in sects if s[1] <= va < s[1] + s[2]), None)
                    return name, segname, sec
        return None, None, None

    def string_va(self, needle):
        """VA of the literal that *starts* with needle, i.e. preceded by NUL."""
        nb, i = needle.encode(), 0
        while True:
            i = self.data.find(nb, i)
            if i < 0:
                return None
            if i == 0 or self.data[i - 1] == 0:
                return self.off2va(i)
            i += 1

    # -- the index -------------------------------------------------------------
    def index(self, window=8):
        if self._index is not None:
            return self._index
        st = self.path.stat()
        key = hashlib.sha1(f'scoped-v3:{self.path.resolve()}:{st.st_size}:{st.st_mtime_ns}:{window}:{self.scope}:{self.segment}'.encode()).hexdigest()[:16]
        cache = pathlib.Path(tempfile.gettempdir()) / f'kc-xref-{key}.pickle'
        if cache.exists():
            self._index = pickle.loads(cache.read_bytes())
            return self._index
        saddr, ssize = self.section(self.segment, '__text', kext=self.scope)
        n = ssize // 4
        words = struct.unpack_from(f'<{n}I', self.data, self.va2off(saddr))
        xrefs, bls, bs, funcs = {}, [], [], []
        for i, w in enumerate(words):
            va = saddr + i * 4
            if w == PACIBSP:
                funcs.append(va-4 if i and words[i-1] == 0xd503245f else va)
            top = w >> 26
            if top in (0x25, 0x05):                              # bl / b
                imm = w & 0x3FFFFFF
                if imm & (1 << 25):
                    imm -= 1 << 26
                (bls if top == 0x25 else bs).append((va, va + imm * 4))
            elif (w & 0x9F000000) == 0x90000000:                 # adrp
                rd = w & 0x1F
                imm = (((w >> 5) & 0x7FFFF) << 2) | ((w >> 29) & 3)
                if imm & (1 << 20):
                    imm -= 1 << 21
                page = (va & ~0xFFF) + (imm << 12)
                for j in range(1, window):
                    if i + j >= n:
                        break
                    w2 = words[i + j]
                    if (w2 & 0xFF800000) == 0x91000000 and ((w2 >> 5) & 0x1F) == rd:   # add
                        xrefs.setdefault(page + ((w2 >> 10) & 0xFFF), []).append((va, 'add'))
                        break
                    if (w2 & 0x3B000000) == 0x39000000 and ((w2 >> 5) & 0x1F) == rd:   # ldr/str
                        xrefs.setdefault(page + (((w2 >> 10) & 0xFFF) << (w2 >> 30)), []).append(
                            (va, 'ldr' if (w2 >> 22) & 1 else 'str'))
                        break
                    if (w2 & 0x1F) == rd and (w2 & 0xFF800000) != 0x91000000:
                        break                                    # page register clobbered
            elif (w & 0x9F000000) == 0x10000000:                 # adr
                imm = (((w >> 5) & 0x7FFFF) << 2) | ((w >> 29) & 3)
                if imm & (1 << 20):
                    imm -= 1 << 21
                xrefs.setdefault(va + imm, []).append((va, 'adr'))
        self._index = {'text': (saddr, ssize), 'xrefs': xrefs, 'bls': bls, 'bs': bs, 'funcs': funcs}
        try:
            cache.write_bytes(pickle.dumps(self._index))
        except OSError:
            pass
        return self._index

    def func_start(self, va):
        start, size = self.index()['text']
        if not start <= va < start + size:
            return None
        f = self.index()['funcs']
        i = bisect.bisect_right(f, va) - 1
        return f[i] if i >= 0 else None

    def func_end(self, start):
        f = self.index()['funcs']
        i = bisect.bisect_right(f, start)
        return f[i] if i < len(f) else self.index()['text'][0] + self.index()['text'][1]

    def calls_in(self, start, end=None):
        end = end or self.func_end(start)
        b = self.index()['bls']
        return b[bisect.bisect_left(b, (start, 0)):bisect.bisect_left(b, (end, 0))]

    def callers_of(self, target):
        idx = self.index()
        out = [(va, 'bl') for va, t in idx['bls'] if t == target]
        out += [(va, 'b') for va, t in idx['bs'] if t == target]
        out += [(va, kind) for va, kind in idx['xrefs'].get(target, [])]   # address taken
        return sorted(out)

    def strings_of(self, start, end=None):
        if start is None:
            return []
        end = end or self.func_end(start)
        ranges = [(addr, addr+size) for _, _, _, _, _, sections in self.kext[self.scope]
                  for name, addr, size in sections if name == '__cstring']
        out = []
        for tgt, refs in self.index()['xrefs'].items():
            if any(lo <= tgt < hi for lo, hi in ranges):
                out.extend((va, tgt) for va, _ in refs if start <= va < end)
        return sorted(out)

    def describe(self, f, nstr=3):
        if f is None:
            return '[function start not identified]'
        start, size = self.index()['text']
        if not start <= f < start + size:
            return f'{f:#x} [outside indexed {self.segment}]'
        strs = [repr(self.cstr(t, 40)) for _, t in self.strings_of(f)[:nstr]]
        return f'{f:#x}' + (' [' + ' | '.join(strs) + ']' if strs else ' [no literals]')

    def startup_entries(self):
        saddr, ssize = self.section('__BOOTDATA', '__init_entry_set')
        base = self.top[0][1]
        out = []
        for i in range(ssize // 24):
            sub, rank, fptr, _ = struct.unpack_from('<IIQQ', self.data, self.va2off(saddr + i * 24))
            fn = base + (fptr & 0xFFFFFFFF if fptr >> 63 else fptr & 0x7FFFFFFFFFF)
            out.append((sub, rank, fn))
        return out


def cmd_string(kc, args):
    va = kc.string_va(args.literal)
    if va is None:
        raise SystemExit(f'no literal starting with {args.literal!r}')
    refs = kc.index()['xrefs'].get(va, [])
    print(f'{args.literal!r} at {va:#x} ({kc.owner(va)[2]}), {len(refs)} reference(s) in {kc.scope}')
    for f in sorted({kc.func_start(r) for r, _ in refs},
                    key=lambda value: (-1 if value is None else value)):
        print(f'  in function {kc.describe(f, 4)}')
        if f is None:
            continue
        for site, kind in kc.callers_of(f):
            print(f'      <- {kind:3s} {site:#x} in {kc.describe(kc.func_start(site))}')


def cmd_callers(kc, args):
    for site, kind in kc.callers_of(args.address):
        print(f'  {kind:3s} {site:#x} in {kc.describe(kc.func_start(site), 4)}')


def cmd_calls(kc, args):
    start = args.address
    end = args.end or kc.func_end(start)
    events = [(a, 'bl', t) for a, t in kc.calls_in(start, end)]
    events += [(a, 'str', t) for a, t in kc.strings_of(start, end)]
    events += [(a, 'b', t) for a, t in kc.index()['bs'] if start <= a < end and not start <= t < end]
    print(f'{start:#x}..{end:#x}  ({kc.owner(start)[0]})')
    for a, kind, t in sorted(events):
        if kind == 'str':
            print(f'  {a:#x}  str  {kc.cstr(t, 60)!r}')
        else:
            print(f'  {a:#x}  {kind:3s}  {kc.describe(t)}')


def cmd_startup(kc, args):
    ents = kc.startup_entries()
    hist = {}
    for sub, _, _ in ents:
        hist[sub] = hist.get(sub, 0) + 1
    print(f'{len(ents)} entries; per subsystem: ' + ' '.join(f'{s}:{n}' for s, n in sorted(hist.items())))
    for sub, rank, fn in ents:
        if sub >= args.min_subsystem:
            print(f'  sub {sub:>10} rank {rank:>10} {kc.describe(fn)}')


def main():
    ap = argparse.ArgumentParser(description=__doc__.split('\n\n')[0])
    ap.add_argument('kernelcache')
    ap.add_argument('--scope', default=KERNEL, help='fileset image to index (default: com.apple.kernel)')
    ap.add_argument('--segment', default='__TEXT_EXEC',
                    help='segment containing __text (for example __KLD for bootstrap loader code)')
    sub = ap.add_subparsers(dest='cmd', required=True)
    s = sub.add_parser('string', help='function(s) referencing a literal, and their callers')
    s.add_argument('literal')
    s = sub.add_parser('callers', help='bl, b and address-takes of a function')
    s.add_argument('address', type=lambda v: int(v, 0))
    s = sub.add_parser('calls', help='calls and literals of a function, in order')
    s.add_argument('address', type=lambda v: int(v, 0))
    s.add_argument('--end', type=lambda v: int(v, 0), help='stop here instead of at the next pacibsp')
    s = sub.add_parser('startup', help='the STARTUP() table')
    s.add_argument('--min-subsystem', type=int, default=0)
    args = ap.parse_args()
    kc = Kernelcache(args.kernelcache, scope=args.scope, segment=args.segment)
    {'string': cmd_string, 'callers': cmd_callers, 'calls': cmd_calls, 'startup': cmd_startup}[args.cmd](kc, args)
    return 0


if __name__ == '__main__':
    sys.exit(main())

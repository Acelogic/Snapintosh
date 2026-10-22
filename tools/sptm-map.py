#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Read Apple's SPTM out of its own binary.

Everything this project builds for XNU -- the handoff table, the page tables XNU
is entered with, the frame table, the answer to every monitor call -- is
something SPTM produces. We have been deriving all of it from the consuming
side: run XNU, watch it fault, work backwards to what it must have wanted. That
works, and it is slow, and it produces structures that fit every observation so
far and can still be wrong. `handoff[+0x38]` was called a frame table for two
days on exactly that basis.

`sptm.t8140.release` is the producer, it ships in the IPSW, and its `__TEXT_EXEC`
is 0x64000 bytes. It is small enough to read. This turns that reading into
something repeatable:

    tools/sptm-map.py <image> --func 0xfffffff0270c02d4     # one function, whole
    tools/sptm-map.py <image> --strings handoff             # strings + who refs them
    tools/sptm-map.py <image> --xref 0xfffffff027006d51     # who points here
    tools/sptm-map.py <image> --survey                      # what hardware it needs

`--survey` is the one with a decision attached. SPTM assumes Apple silicon under
it. How *much* it assumes decides whether hosting the real binary is an option
or a fantasy, and counting is cheaper than arguing about it.
"""
import argparse
import collections
import importlib.util
import pathlib
import struct
import sys

HERE = pathlib.Path(__file__).resolve().parent

# kc-disas.py already resolves VA through the segment table and already works
# around llvm-mc dropping encodings it cannot decode. Both are load-bearing and
# neither is worth a second copy; the hyphen in the name is the only reason this
# is not a plain import.
_spec = importlib.util.spec_from_file_location('kcdisas', HERE / 'kc-disas.py')
if _spec is None or _spec.loader is None:              # only if the file is gone
    raise SystemExit('tools/kc-disas.py is missing; sptm-map builds on it')
kc = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(kc)

PACIBSP = 0xD503237F
RETS = (kc.RET, kc.RETAB)
BRK = 0xD4200000


# --------------------------------------------------------------------------
# instruction shapes we care about

def adrp_page(word, va):
    immlo, immhi = (word >> 29) & 3, (word >> 5) & 0x7FFFF
    imm = (immhi << 2) | immlo
    if imm & (1 << 20):
        imm -= 1 << 21
    return (va & ~0xFFF) + (imm << 12)


def is_adrp(word):
    return (word & 0x9F000000) == 0x90000000


def sysreg(word):
    """(op0, op1, CRn, CRm, op2, read) for an MRS/MSR, else None.

    MSR (immediate) shares the top ten bits and is excluded by its fixed Rt of
    31 and CRn of 4 -- it writes PSTATE, not a register, and is not part of the
    interface this is trying to size."""
    if (word >> 22) != 0x354:
        return None
    op0 = (word >> 19) & 3
    if op0 < 2:
        return None
    crn = (word >> 12) & 0xF
    if crn == 4 and (word & 0x1F) == 31 and not (word >> 21) & 1:
        return None
    return (op0, (word >> 16) & 7, crn, (word >> 8) & 0xF, (word >> 5) & 7,
            bool((word >> 21) & 1))


def sysreg_name(op0, op1, crn, crm, op2):
    return f'S{op0}_{op1}_C{crn}_C{crm}_{op2}'


def impdef(op0, crn):
    """Is this one of the encodings ARM reserves for the implementer?

    CRn 9, 10, 11 and 15 at op0 3 are the IMPLEMENTATION DEFINED space, which is
    the same set `HCR_EL2.TIDCP` traps -- so this is exactly the register set
    that would have to be emulated for anything running below us."""
    return op0 == 3 and crn in (9, 10, 11, 15)


def wide_constants(data, start, end, va_of):
    """Every 64-bit immediate built by a movz/movk run, with where it was built.

    SPTM's fixed addresses -- VA windows, MMIO bases -- are all materialised this
    way, and reading them off the immediates is exact where inferring them from
    behaviour is not."""
    out, pending = [], {}
    for off in range(start, end, 4):
        word = struct.unpack_from('<I', data, off)[0]
        wide = (word >> 31) & 1
        opc = (word >> 29) & 3
        if (word & 0x1F800000) == 0x12800000 and wide:
            rd, shift, imm16 = word & 0x1F, ((word >> 21) & 3) * 16, (word >> 5) & 0xFFFF
            if opc == 2:                                  # movz
                pending[rd] = (imm16 << shift, va_of(off))
            elif opc == 0:                                # movn
                pending[rd] = ((~(imm16 << shift)) & 0xFFFFFFFFFFFFFFFF, va_of(off))
            elif opc == 3 and rd in pending:              # movk
                value, first = pending[rd]
                value = (value & ~(0xFFFF << shift)) | (imm16 << shift)
                pending[rd] = (value, first)
            if rd in pending:
                out.append((pending[rd][1], rd, pending[rd][0]))
    return out


# --------------------------------------------------------------------------
# functions

def function_start(data, segs, va, limit=0x4000):
    """Walk back to the prologue.

    `pacibsp` first, because this binary is arm64e and nearly every function
    signs its return address. Falling back to "the instruction after the last
    `ret`" covers the leaf functions that do not."""
    _, off = kc.locate(segs, va)
    if off is None:
        return None
    for back in range(0, limit, 4):
        word = struct.unpack_from('<I', data, off - back)[0]
        if word == PACIBSP:
            return va - back
    for back in range(0, limit, 4):
        word = struct.unpack_from('<I', data, off - back)[0]
        if word in RETS or word == BRK:
            return va - back + 4
    return None


def function_words(data, segs, start, cap=4096):
    """Linear sweep that does not stop at the first `ret`.

    A function with an early return has a `ret` in the middle of it, and taking
    that as the end silently truncates the listing -- which for a boot path is
    the same failure mode as a misaligned disassembly: it reads as complete. So
    the sweep tracks the furthest local branch target seen and keeps going while
    there is still code the function itself points at."""
    _, off = kc.locate(segs, start)
    words, furthest = [], start
    for i in range(cap):
        va = start + i * 4
        word = struct.unpack_from('<I', data, off + i * 4)[0]
        words.append(word)
        target = None if word in kc.APPLE else kc.targets(word, va)
        if target is not None and not is_adrp(word) and start <= target < start + cap * 4:
            furthest = max(furthest, target)
        if word in RETS and va >= furthest:
            break
        if word == BRK and va >= furthest:
            break
    return words


def print_function(segs, start, words):
    lines = kc.decode(words)
    name, off = kc.locate(segs, start)
    print(f'{start:#018x}  ({name}, file {off:#x}, {len(words)} instructions)')
    for i, word in enumerate(words):
        va = start + i * 4
        text = kc.APPLE.get(word) or lines[i]
        tail = ''
        target = None if word in kc.APPLE else kc.targets(word, va)
        if target is not None:
            seg, _ = kc.locate(segs, target)
            tail = f'   ; {target:#x}' + (f' ({seg})' if seg else ' (unmapped)')
        sr = sysreg(word)
        if sr and impdef(sr[0], sr[2]):
            tail += '   <-- IMPDEF'
        print(f'  {va:#018x}  {word:08x}  {text:<40}{tail}')


# --------------------------------------------------------------------------
# cross references

def text_ranges(segs):
    for name, vmaddr, vmsize, fileoff, filesize in segs:
        if 'TEXT_EXEC' in name or name == '__TEXT':
            if filesize:
                yield name, vmaddr, fileoff, min(vmsize, filesize)


def xrefs(data, segs, wanted):
    """adrp+add and adrp+ldr pairs that resolve to any address in `wanted`.

    Two forms because a string is reached with `add` and a pointer with `ldr`,
    and SPTM's boot path uses both within a few instructions of each other."""
    found = collections.defaultdict(list)
    for name, vmaddr, fileoff, size in text_ranges(segs):
        if 'TEXT_EXEC' not in name:
            continue
        pages = {}
        for off in range(fileoff, fileoff + size - 4, 4):
            va = vmaddr + (off - fileoff)
            word = struct.unpack_from('<I', data, off)[0]
            if is_adrp(word):
                pages[word & 0x1F] = (adrp_page(word, va), va)
                continue
            rn = (word >> 5) & 0x1F
            if rn not in pages:
                continue
            page, site = pages[rn]
            if (word & 0xFF800000) == 0x91000000:                   # add xD, xN, #imm
                target = page + ((word >> 10) & 0xFFF)
            elif (word & 0xFFC00000) == 0xF9400000:                 # ldr xD, [xN, #imm]
                target = page + (((word >> 10) & 0xFFF) * 8)
            else:
                continue
            if target in wanted:
                found[target].append(site)
    return found


def strings(data, segs, needle=None, minlen=6):
    """Printable runs in the read-only segments, with their addresses."""
    out = []
    for name, vmaddr, vmsize, fileoff, filesize in segs:
        if name not in ('__TEXT', '__DATA_CONST', '__LATE_CONST') or not filesize:
            continue
        span = data[fileoff:fileoff + min(vmsize, filesize)]
        start = None
        for i, byte in enumerate(span + b'\0'):
            if 0x20 <= byte < 0x7F:
                start = i if start is None else start
                continue
            if start is not None and i - start >= minlen:
                text = span[start:i].decode('ascii')
                if needle is None or needle.lower() in text.lower():
                    out.append((vmaddr + start, name, text))
            start = None
    return out


# --------------------------------------------------------------------------
# the survey

def survey(data, segs):
    """What this binary needs from the silicon under it.

    The question behind this is whether Apple's real SPTM could be hosted here
    rather than reimplemented. Every IMPDEF register it touches and every fixed
    physical address it pokes is something this machine would have to answer
    for, so the counts are the estimate."""
    regs = collections.Counter()
    reads = collections.Counter()
    writes = collections.Counter()
    total_insns = 0
    for name, vmaddr, fileoff, size in text_ranges(segs):
        if 'TEXT_EXEC' not in name:
            continue
        total_insns += size // 4
        for off in range(fileoff, fileoff + size - 4, 4):
            word = struct.unpack_from('<I', data, off)[0]
            sr = sysreg(word)
            if not sr:
                continue
            op0, op1, crn, crm, op2, read = sr
            if not impdef(op0, crn):
                continue
            key = sysreg_name(op0, op1, crn, crm, op2)
            regs[key] += 1
            (reads if read else writes)[key] += 1

    print(f'{total_insns:,} instructions in __TEXT_EXEC\n')
    print(f'IMPDEF system registers: {len(regs)} distinct, '
          f'{sum(regs.values())} accesses')
    for key, count in regs.most_common():
        print(f'  {key:<22} {count:4}   read {reads[key]:3}  write {writes[key]:3}')

    # Fixed addresses. Apple's MMIO lives low; anything at or above the kernel
    # half is SPTM's own text or a VA window, which is a different question.
    mmio = collections.Counter()
    windows = collections.Counter()
    for name, vmaddr, fileoff, size in text_ranges(segs):
        if 'TEXT_EXEC' not in name:
            continue
        for site, _, value in wide_constants(data, fileoff, fileoff + size,
                                             lambda o, b=fileoff, v=vmaddr: v + (o - b)):
            if 0x10000000 <= value < 0x1000000000000:
                mmio[value & ~0xFFFFF] += 1
            elif value >= 0xFFFF000000000000:
                windows[value & 0xFFFFFFF000000000] += 1

    print(f'\nFixed low addresses (MMIO-shaped), by 1 MiB page: {len(mmio)} distinct')
    for base, count in mmio.most_common(24):
        print(f'  {base:#014x}  {count}')
    print(f'\nHigh VA windows, by 64 GiB: {len(windows)} distinct')
    for base, count in windows.most_common(24):
        print(f'  {base:#018x}  {count}')


# --------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('image')
    ap.add_argument('--func', type=lambda v: int(v, 0),
                    help='disassemble the whole function containing this address')
    ap.add_argument('--raw', action='store_true',
                    help='with --func, start exactly here instead of at the prologue')
    ap.add_argument('--xref', type=lambda v: int(v, 0),
                    help='find adrp+add / adrp+ldr sites that resolve here')
    ap.add_argument('--strings', nargs='?', const='', metavar='NEEDLE',
                    help='list strings, optionally filtered, with their xrefs')
    ap.add_argument('--survey', action='store_true',
                    help='what this binary needs from the hardware under it')
    ap.add_argument('--segments', action='store_true')
    args = ap.parse_args()

    data = pathlib.Path(args.image).read_bytes()
    segs = kc.segments(data)

    if args.segments:
        for name, vmaddr, vmsize, fileoff, filesize in segs:
            print(f'{name:<16} {vmaddr:#018x} +{vmsize:#x}  file {fileoff:#x} +{filesize:#x}')
        return 0

    if args.survey:
        survey(data, segs)
        return 0

    if args.strings is not None:
        found = strings(data, segs, args.strings or None)
        refs = xrefs(data, segs, {va for va, _, _ in found})
        for va, seg, text in found:
            sites = refs.get(va, [])
            where = '  <- ' + ' '.join(f'{s:#x}' for s in sites[:6]) if sites else ''
            print(f'{va:#018x} ({seg}) {text!r}{where}')
        return 0

    if args.xref is not None:
        found = xrefs(data, segs, {args.xref})
        for site in found.get(args.xref, []):
            print(f'{site:#018x}')
        if not found:
            print('no adrp-based references')
        return 0

    if args.func is not None:
        start = args.func if args.raw else function_start(data, segs, args.func)
        if start is None:
            raise SystemExit(f'no prologue found above {args.func:#x}')
        words = function_words(data, segs, start)
        print_function(segs, start, words)
        return 0

    ap.print_help()
    return 1


if __name__ == '__main__':
    sys.exit(main())

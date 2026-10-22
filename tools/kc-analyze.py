#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Where does a stock XNU kernelcache call its monitors, and can we catch it?

XNU on SPTM systems reaches SPTM and TXM with `genter`, an Apple instruction in
the reserved encoding space. On this project's silicon `genter` is simply an
undefined instruction, and an undefined instruction taken at EL1 is delivered to
EL1 -- there is no HCR_EL2 bit that routes it to the hypervisor. The only
mechanism that does route an instruction fetch to EL2 is a stage-2 execute
permission fault, which applies to whole pages.

So the question that decides whether the monitors can be intercepted without
touching a byte of the kernel is: how many pages hold the call sites? If the
answer is "a few", stage-2 execute-never on those pages costs nothing anywhere
else in the kernel. If the answer is "spread through the text", the approach is
dead and something else is needed.

    tools/kc-analyze.py downloads/extracted/kernelcache.release.mac17p

Accepts a raw Mach-O or an IM4P (decompressed with the lzfse CLI, cached next to
the input). Exits non-zero if the call sites do not fit the budget.
"""
import argparse
import pathlib
import struct
import subprocess
import sys
from collections import Counter

# Apple's guarded-execution instructions, both in the reserved encoding space.
GENTER = 0x00201420
GEXIT = 0x00201400
# The other half of every call stub in the 26A428 kernelcaches: a second
# undefined encoding, reached when a byte in __DATA_CONST is set. Its meaning is
# not established here -- what matters for interception is that it is undefined
# on this silicon too, and that it shares its pages with the genter it guards.
ALT_CALL = 0xD4E00000

MONITOR_OPS = {GENTER: 'genter', ALT_CALL: 'alt-call', GEXIT: 'gexit'}

LC_SEGMENT_64 = 0x19
LC_DYLD_CHAINED_FIXUPS = 0x80000034
MH_MAGIC_64 = 0xFEEDFACF

# How many pages of execute-never we are willing to spend. Each one costs a trap
# per call, which is the point; what it must not do is cover ordinary kernel
# text. Four 16K pages is under 0.1% of __TEXT_EXEC.
PAGE_BUDGET = 8


def decompress(path: pathlib.Path) -> pathlib.Path:
    """IM4P in, raw Mach-O out. Raw input is returned unchanged."""
    head = path.open('rb').read(4)
    if struct.unpack('<I', head)[0] == MH_MAGIC_64:
        return path

    raw = path.with_suffix(path.suffix + '.raw')
    if raw.exists() and struct.unpack('<I', raw.open('rb').read(4))[0] == MH_MAGIC_64:
        return raw

    data = path.read_bytes()
    start = data.find(b'bvx2')
    if start < 0:
        raise SystemExit(f'{path.name}: not a Mach-O and no lzfse payload in it')
    proc = subprocess.run(['lzfse', '-decode'], input=data[start:],
                          capture_output=True)
    if proc.returncode or not proc.stdout:
        raise SystemExit(f'{path.name}: lzfse failed: {proc.stderr.decode()[:200]}')
    raw.write_bytes(proc.stdout)
    print(f'  decompressed to {raw.name} ({len(proc.stdout):,} bytes)')
    return raw


def segments(data: bytes):
    magic, _, _, filetype, ncmds = struct.unpack_from('<IiiII', data, 0)
    if magic != MH_MAGIC_64:
        raise SystemExit('not a 64-bit Mach-O')
    out, off, fixups = [], 32, None
    for _ in range(ncmds):
        cmd, size = struct.unpack_from('<II', data, off)
        if cmd == LC_SEGMENT_64:
            name = data[off + 8:off + 24].rstrip(b'\0').decode()
            vmaddr, vmsize, fileoff, filesize = struct.unpack_from('<QQQQ', data, off + 24)
            out.append((name, vmaddr, vmsize, fileoff, filesize))
        elif cmd == LC_DYLD_CHAINED_FIXUPS:
            fixups = struct.unpack_from('<II', data, off + 8)
        off += size
    return filetype, out, fixups


def scan(data: bytes, vmaddr: int, fileoff: int, filesize: int):
    """Every monitor opcode in one segment, as (opcode, virtual address)."""
    body = data[fileoff:fileoff + filesize]
    found = []
    for i in range(0, len(body) - 3, 4):
        word = int.from_bytes(body[i:i + 4], 'little')
        if word in MONITOR_OPS:
            found.append((word, vmaddr + i))
    return found


def decode_stub(words, index):
    """What x16 holds when the call at `index` executes.

    The monitor ABI packs the routing into one register:

        domain   = x16[55:48]      table = x16[39:32]      endpoint = x16[31:0]

    Each stub builds it from immediates, so the kernelcache states its own
    interface. Walking back from the call to the function head and replaying
    every write to x16 recovers it. A `mov w16, w0` means the endpoint is the
    caller's first argument rather than a constant.
    """
    value, dynamic = 0, False
    start = max(0, index - 24)
    head = start
    for i in range(index - 1, start - 1, -1):
        if words[i] == 0xD503237F:              # pacibsp: the stub's first insn
            head = i
            break
    for word in words[head:index]:
        if (word & 0x1F) != 16:                 # not a write to x16
            continue
        imm16 = (word >> 5) & 0xFFFF
        shift = ((word >> 21) & 3) * 16
        if (word & 0xFF800000) == 0xD2800000:   # movz x16, #imm, lsl #shift
            value = imm16 << shift
        elif (word & 0xFF800000) == 0xF2800000:  # movk x16, #imm, lsl #shift
            value = (value & ~(0xFFFF << shift)) | (imm16 << shift)
        elif word in (0x2A0003F0, 0xAA0003F0):   # mov w16, w0 / mov x16, x0
            dynamic = True
    return value, dynamic


# Names from m1n1 (AsahiLinux) and the author's J700 research fork (sptm/private.h), which reverse-
# engineered them against this same SoC. They are that tree's names, not
# Apple's, and table 14 is called SPTM_TABLE_INVALID there while this
# kernelcache has 16 live stubs for it -- so the name is wrong for macOS 27 and
# is shown with a question mark rather than quietly dropped.
TABLES = {
    (0, 0): 'XNU_BOOTSTRAP', (0, 1): 'TXM_BOOTSTRAP', (0, 2): 'SK_BOOTSTRAP',
    (0, 3): 'T8110_DART_XNU', (0, 4): 'T8110_DART_SK', (0, 5): 'SART',
    (0, 6): 'NVME', (0, 7): 'UAT', (0, 8): 'SHART', (0, 9): 'CPUTRACE',
    (0, 10): 'HIB', (0, 11): 'GEN3_DART_XNU', (0, 12): 'GEN3_DART_SK',
    (0, 13): 'T6000_DART_XNU', (0, 14): 'INVALID?',
    (2, 0): 'TXM_XNU', (3, 0): 'cL4 ringgate',
}


def report_stubs(data, segs):
    """The monitor interface, as the kernelcache states it."""
    routes = Counter()
    endpoints = {}
    for name, _, _, fileoff, filesize in segs:
        if 'TEXT' not in name or filesize == 0:
            continue
        body = data[fileoff:fileoff + filesize]
        words = [int.from_bytes(body[i:i + 4], 'little') for i in range(0, len(body) - 3, 4)]
        for index, word in enumerate(words):
            if word != GENTER:
                continue
            value, dynamic = decode_stub(words, index)
            domain, table = (value >> 48) & 0xFF, (value >> 32) & 0xFF
            routes[(domain, table)] += 1
            slot = endpoints.setdefault((domain, table), set())
            slot.add('caller' if dynamic else hex(value & 0xFFFFFFFF))

    if not routes:
        return
    print('\nMonitor routes the kernelcache asks for '
          '(x16: domain[55:48] table[39:32] endpoint[31:0]):')
    for (domain, table), count in sorted(routes.items()):
        values = endpoints[(domain, table)]
        if 'caller' in values:
            shown = 'endpoint from x0'
        else:
            shown = ' '.join(sorted(values, key=lambda v: int(v, 16))[:8])
            if len(values) > 8:
                shown += f' ... ({len(values)} distinct)'
        label = TABLES.get((domain, table), '?')
        print(f'  domain {domain}  table {table:<3} {label:<15} {count:>3} stubs   {shown}')


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('kernelcache')
    ap.add_argument('--granule', type=int, default=16384,
                    help="the guest's page size, for the page report (default 16K)")
    args = ap.parse_args()

    path = decompress(pathlib.Path(args.kernelcache))
    data = path.read_bytes()
    filetype, segs, fixups = segments(data)
    print(f'{path.name}: Mach-O filetype {filetype}'
          f'{" (MH_FILESET)" if filetype == 12 else ""}, {len(segs)} segments')

    sptm = next((s for s in segs if s[0] == '__DATA_SPTM'), None)
    if sptm:
        print(f'  __DATA_SPTM      {sptm[1]:#018x} +{sptm[2]:#x}  '
              f'({sptm[2] // args.granule} pages) -- this kernel is SPTM-based')
    else:
        print('  __DATA_SPTM      absent -- not an SPTM kernel')
    if fixups:
        print(f'  chained fixups   dataoff {fixups[0]:#x} size {fixups[1]:#x}')

    hits = []
    for name, vmaddr, _, fileoff, filesize in segs:
        if 'TEXT' not in name or filesize == 0:
            continue
        found = scan(data, vmaddr, fileoff, filesize)
        if not found:
            continue
        counts = Counter(MONITOR_OPS[w] for w, _ in found)
        print(f'  {name:<18} ' + '  '.join(f'{k} {v}' for k, v in sorted(counts.items())))
        hits += found

    if not hits:
        print('\nNo monitor call sites. Nothing to intercept.')
        return 0

    pages = sorted({va // args.granule for _, va in hits})
    per_page = Counter(va // args.granule for _, va in hits)
    print(f'\n{len(hits)} call sites in {len(pages)} pages of {args.granule // 1024}K:')
    for page in pages:
        print(f'  {page * args.granule:#018x}  {per_page[page]:>4} sites')

    # The hypervisor works in 4K, whatever the guest's page size is, because the
    # shadow it emits is a 4K regime.
    quads = sorted({va // 4096 for _, va in hits})
    print(f'\nStage-2 execute-never would cover {len(quads)} pages of 4K:')
    for page in quads:
        print(f'  {page * 4096:#018x}')

    report_stubs(data, segs)

    text = sum(s[2] for s in segs if 'TEXT' in s[0])
    covered = len(quads) * 4096
    print(f'\n{covered:,} bytes of {text:,} in TEXT segments: '
          f'{100.0 * covered / text:.4f}%')

    if len(pages) > PAGE_BUDGET:
        print(f'\nFAILED: {len(pages)} pages is over the budget of {PAGE_BUDGET}. '
              'Execute-never on that many pages would trap ordinary kernel text.')
        return 1
    print(f'\nThe call sites are confined to {len(pages)} pages. Marking them '
          'execute-never at stage 2 routes every monitor call to EL2 and nothing '
          'else -- no byte of the kernel is modified.')
    return 0


if __name__ == '__main__':
    sys.exit(main())

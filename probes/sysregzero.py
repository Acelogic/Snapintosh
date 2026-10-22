# SPDX-License-Identifier: MIT
"""Opt-in removal of trapped, ignored Apple IMPDEF register accesses in the kernel.

SNAP_KERNEL_SYSREG_ZERO=1 (or xnuboot.build(..., sysreg_zero=True)) rewrites,
in the loader's copy of the stock image, every MRS/MSR of REGISTERS that the
instruction decoder finds in the kernelcache's executable segments:

    MRS Xt, <reg>  ->  MOVZ Xt, #0      (MRS XZR, <reg> -> NOP)
    MSR <reg>, Xt  ->  NOP

The source firmware file is never rewritten, and every other byte is unchanged.

Why this is exactly what the monitor does today, in both the control and the
fast build. HCR_EL2.TIDCP (probes/xnuboot.S) traps every EL1 access to these
IMPDEF encodings. The control build takes every one through
xnuboot_trap_locked, whose system-register section has no build conditional;
the fast build classifies first (compat/fast-trap.h) and sends declines and
first occurrences to the same locked code.
  - IGNORED: no handler claims them (pauth_user_reg, the IPI, clock and SPRR
    handlers and the switch cases all pass them to the default case;
    tools/test-fast-trap.py proves it for fast_trap_ignored, which holds all
    of them). The default and the lock-free FAST_TRAP_IGNORE class both put 0
    in Rt (nothing for XZR), drop a write and step ELR by 4.
  - ZERO_CASE: GXF_STATUS_EL1's locked case is exactly `if (is_read) value =
    0;` (no record; a write changes nothing), and its lock-free class
    FAST_TRAP_ZERO is the same.
MOVZ Xt, #0 writes 0 to Xt and, like MRS, leaves NZCV alone; NOP leaves
everything alone, like the dropped MSR. What the monitor also does -- trap
counters, the census and one EV_SYSREG record per vCPU -- is host bookkeeping
the guest cannot see; with the patch those counts are zero for these registers.
CONTEXTIDR_EL1 and the JAPIB key registers are also in the ignore list but are
deliberately left out.

Admission. The sites are found by decoding, never from an address list, so the
same finder serves any kernel. A kernel is admitted only when its digest is in
PINS and the decoded closure (per-register and per-bundle counts and the digest
of the site list) matches the reviewed one: an unknown or different kernel is
refused instead of patched unreviewed. tools/test-kernel-sysreg-zero.py
builds both images and checks the whole contract.
"""
import bisect
import collections
import hashlib
import re
import struct

# (op0, op1, CRn, CRm, op2) -> name. IGNORED: the monitor's ignore default
# (the 2026-10-16 census's lock-only registers, docs/SYSREG-CENSUS-20261016.md,
# plus the PMU registers PMC0, PMC1, PMCR0 and UPMSR). ZERO_CASE: a claimed
# register whose only handling is "reads zero".
IGNORED = {
    (3, 2, 15, 0, 0): 'PMC0', (3, 2, 15, 1, 0): 'PMC1',
    (3, 2, 15, 2, 0): 'PMC2', (3, 2, 15, 3, 0): 'PMC3', (3, 2, 15, 4, 0): 'PMC4',
    (3, 2, 15, 5, 0): 'PMC5', (3, 2, 15, 6, 0): 'PMC6', (3, 2, 15, 7, 0): 'PMC7',
    (3, 2, 15, 9, 0): 'PMC8', (3, 2, 15, 10, 0): 'PMC9',
    (3, 1, 15, 0, 0): 'PMCR0', (3, 7, 15, 6, 4): 'UPMSR',
    (3, 4, 15, 15, 6): 'S3_4_C15_C15_6', (3, 4, 15, 10, 4): 'S3_4_C15_C10_4',
    (3, 1, 15, 1, 5): 'S3_1_C15_C1_5', (3, 4, 15, 1, 4): 'S3_4_C15_C1_4',
    (3, 4, 15, 1, 3): 'AMX_STATE_T_EL1',
}
ZERO_CASE = {(3, 6, 15, 8, 0): 'GXF_STATUS_EL1'}
REGISTERS = {**IGNORED, **ZERO_CASE}
MOVZ_X0 = 0xd2800000   # MOVZ Xt, #0, LSL #0 (sf=1, opc=10, hw=0, imm16=0) | Rt
NOP = 0xd503201f
# J700 26A428 kernelcache.release.mac17p (probes/nativecalls.py KERNEL_SHA256).
J700_26A428 = 'dc9019ae39187b36936c2c513b485e513f15cd966b5c887ac88ffd2925976c62'
# The reviewed closure: sites by (register, direction), by fileset bundle, and
# the digest of the sorted "va word" site list (closure_digest below).
PINS = {
    J700_26A428: dict(
        sites=240,
        registers={
            'PMC0 MRS': 30, 'PMC0 MSR': 2, 'PMC1 MRS': 28, 'PMC1 MSR': 2,
            'PMC2 MRS': 3, 'PMC2 MSR': 4, 'PMC3 MRS': 3, 'PMC3 MSR': 4,
            'PMC4 MRS': 3, 'PMC4 MSR': 4, 'PMC5 MRS': 3, 'PMC5 MSR': 4,
            'PMC6 MRS': 3, 'PMC6 MSR': 4, 'PMC7 MRS': 3, 'PMC7 MSR': 4,
            'PMC8 MRS': 3, 'PMC8 MSR': 4, 'PMC9 MRS': 3, 'PMC9 MSR': 4,
            'PMCR0 MRS': 1, 'PMCR0 MSR': 8, 'UPMSR MRS': 1, 'UPMSR MSR': 2,
            'GXF_STATUS_EL1 MRS': 1,
            'S3_4_C15_C15_6 MRS': 2, 'S3_4_C15_C15_6 MSR': 1,
            'S3_4_C15_C10_4 MRS': 3, 'S3_4_C15_C10_4 MSR': 5,
            'S3_1_C15_C1_5 MRS': 2, 'S3_1_C15_C1_5 MSR': 4,
            'S3_4_C15_C1_4 MRS': 39, 'S3_4_C15_C1_4 MSR': 26,
            'AMX_STATE_T_EL1 MRS': 24, 'AMX_STATE_T_EL1 MSR': 3,
        },
        bundles={'com.apple.kernel': 222, 'com.apple.driver.AppleT8140CLPC': 18},
        closure_sha256='3c74c369892fd5f04315755ec01b579f33085a4723ab42e0d05bc81660d1ebeb',
    ),
}


def encoding(word):
    """(is_read, (op0, op1, CRn, CRm, op2), Rt) for MRS/MSR (register), else None."""
    if word & 0xffd00000 != 0xd5100000:     # 1101010100 L 1 o0: op0 is 2 or 3
        return None
    return ((word >> 21) & 1,
            ((word >> 19) & 3, (word >> 16) & 7, (word >> 12) & 15, (word >> 8) & 15, (word >> 5) & 7),
            word & 31)


def replacement(word):
    """The equivalent word for a REGISTERS access, or None for any other word."""
    decoded = encoding(word)
    if decoded is None or decoded[1] not in REGISTERS:
        return None
    is_read, _, rt = decoded
    return MOVZ_X0 | rt if is_read and rt != 31 else NOP


def _sections(image):
    """[(lo, hi, bundle, segment, section)] for every executable fileset section."""
    out = []
    for bundle, _, fileoff in image.kexts:
        ncmds = struct.unpack_from('<I', image.data, fileoff + 16)[0]
        p = fileoff + 32
        for _ in range(ncmds):
            cmd, size = struct.unpack_from('<II', image.data, p)
            if cmd == 0x19 and struct.unpack_from('<I', image.data, p + 60)[0] & 4:
                segment = bytes(image.data[p + 8:p + 24]).rstrip(b'\0').decode()
                for n in range(struct.unpack_from('<I', image.data, p + 64)[0]):
                    s = p + 72 + 80 * n
                    addr, length = struct.unpack_from('<QQ', image.data, s + 32)
                    out.append((addr, addr + length, bundle, segment,
                                bytes(image.data[s:s + 16]).rstrip(b'\0').decode()))
            p += size
    return sorted(out)


def find(image):
    """Every REGISTERS access in the image's executable segments, by decoding.

    Returns [dict(va, offset, word, replacement, register, read, rt, bundle,
    section)] sorted by address. A site must lie in an executable fileset
    __text section; anything else (data in text, a header) is refused."""
    sections = _sections(image)
    starts = [s[0] for s in sections]
    sites = []
    for _, va, _, off, size in image.executable_segments:
        if (va | off | size) & 3 or off + size > len(image.data):
            raise ValueError('unaligned or incomplete executable segment')
        body = image.data[off:off + size]
        # Byte 3 of every system instruction is 0xd5; decode only those words.
        for match in re.finditer(b'\xd5', body):
            pos = match.start() - 3
            if pos & 3:
                continue
            word = struct.unpack_from('<I', body, pos)[0]
            new = replacement(word)
            if new is None:
                continue
            address = va + pos
            i = bisect.bisect_right(starts, address) - 1
            if i < 0 or not address < sections[i][1] or sections[i][4] != '__text':
                raise ValueError(f'{address:#x}: register access outside an executable __text section')
            is_read, reg, rt = encoding(word)
            sites.append(dict(va=address, offset=off + pos, word=word, replacement=new,
                              register=REGISTERS[reg], read=bool(is_read), rt=rt,
                              bundle=sections[i][2], section=f'{sections[i][3]},{sections[i][4]}'))
    return sorted(sites, key=lambda s: s['va'])


def closure_digest(sites):
    return hashlib.sha256(''.join(f'{s["va"]:x} {s["word"]:08x}\n' for s in sites).encode()).hexdigest()


def closure(sites):
    return dict(
        sites=len(sites),
        registers=dict(sorted(collections.Counter(
            f'{s["register"]} {"MRS" if s["read"] else "MSR"}' for s in sites).items())),
        bundles=dict(sorted(collections.Counter(s['bundle'] for s in sites).items())),
        closure_sha256=closure_digest(sites))


def admit(image):
    """The decoded sites of a pinned kernel whose closure matches its pin."""
    kernel = hashlib.sha256(image.data).hexdigest()
    pin = PINS.get(kernel)
    if pin is None:
        raise ValueError(f'kernel {kernel[:16]}... has no reviewed sysreg-zero closure')
    sites = find(image)
    found = closure(sites)
    for key in ('sites', 'registers', 'bundles', 'closure_sha256'):
        if found[key] != pin[key]:
            raise ValueError(f'sysreg-zero closure differs from the reviewed one ({key})')
    return kernel, sites, found


def patch(image, data):
    """Rewrite the admitted sites in data, a stock-derived loaded image.

    data may already carry other admitted replacements (the SPTM HVC calls);
    each site must still hold its stock word, and afterwards the executable
    bytes differ from their state on entry at exactly the sites."""
    if len(data) != len(image.data):
        raise ValueError('sysreg-zero patch does not cover the selected kernel image')
    kernel, sites, found = admit(image)
    before = {off: bytes(data[off:off + size]) for _, _, _, off, size in image.executable_segments}
    for site in sites:
        if struct.unpack_from('<I', data, site['offset'])[0] != site['word']:
            raise ValueError(f'{site["va"]:#x}: sysreg site already modified')
        struct.pack_into('<I', data, site['offset'], site['replacement'])
    for _, _, _, off, size in image.executable_segments:
        expected = bytearray(before[off])
        for site in sites:
            if off <= site['offset'] < off + size:
                struct.pack_into('<I', expected, site['offset'] - off, site['replacement'])
        if data[off:off + size] != expected:
            raise ValueError('sysreg-zero changed executable bytes outside its sites')
    return dict(found, kernel_sha256=kernel,
                movz=sum(1 for s in sites if s['replacement'] != NOP),
                nop=sum(1 for s in sites if s['replacement'] == NOP),
                loaded_data_sha256=hashlib.sha256(data).hexdigest(),
                site_list=[(s['va'], s['word'], s['replacement']) for s in sites])

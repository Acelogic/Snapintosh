# SPDX-License-Identifier: MIT
"""Opt-in removal of XNU's NOFLUSH page-aging reference clears in the kernel.

SNAP_KERNEL_REFMOD_SKIP=1 (or xnuboot.build(..., refmod_skip=True)) rewrites,
in the loader's copy of the stock image, the call word of each
`pmap_clear_refmod_options(pn, VM_MEM_REFERENCED, PMAP_OPTIONS_NOFLUSH, NULL)`
that the instruction decoder finds in the kernel's __text:

    MOVZ W1, #0x40    ; bits  = PP_ATTR_REFERENCED      (unchanged)
    MOVZ W2, #0x20    ; options = PMAP_OPTIONS_NOFLUSH  (unchanged)
    MOVZ X3, #0       ; arg = NULL                      (unchanged)
    MOVZ X4, #0       ; flush_range = NULL              (unchanged)
    BL   phys_attribute_clear_with_flush_range  ->  NOP

The source firmware file is never rewritten, and every other byte is unchanged.

Why. Each such call runs arm_force_fast_fault_with_flush_range over the
page's mappings: one SPTM UPDATE_DISJOINT (endpoint 6, options 0x10a: clear
AF, defer the TLBI) per page, and the next access to the page takes an Access
flag fault that arm_fast_fault answers with a second UPDATE_DISJOINT (options
0xc0a). Under our monitor each call takes the global service lock (v39:
22.6 us held, 134 us waited on average). On 26A428 the pattern is exactly two
calls: vm_page_balance_inactive (vm_pageout.c, run on every active-queue
insertion and inactive-queue removal to keep inactive at half of pageable
memory) and vm_fault_deactivate_behind (vm_fault.c, sequential faults).
Apple's own comment on the first: the clear needs no TLB flush because a
missed reference "is just fine"; both are aging hints.

What the guest loses: these pages keep PP_ATTR_REFERENCED and their AF, so
vm_pageout_scan sees every once-referenced page as referenced and reactivates
it (bounded by VM_PAGE_REACTIVATE_LIMIT and the 1-in-1000 forced reclaim)
before reclaiming in queue order: second-chance aging becomes FIFO under
memory pressure. Nothing else changes: the deactivation itself still happens
(vm_page_deactivate_internal follows each call), and no modify-bit clear,
write protection, ledger update, unmap, COW, code-signing or TPRO path is
touched. The NOP leaves pmap state consistent: AF set, REFERENCED set, no
REFFAULT pending, i.e. "referenced again right after the clear".

Admission. The function is found by its two unique panic strings
("phys_attribute_clear(...): invalid options" and "...: should not clear
'modified' without flushing TLBs"): the function holding the only ADRP+ADD
reference to each. A site is a BL to it whose four preceding words are
exactly the four argument MOVZs above, inside com.apple.kernel's __text, with
no direct branch anywhere in the executable segments landing on the three
later MOVZs or the BL, and no indirect jump (BR family) in the containing
region between the surrounding BL targets, so every path to the BL carries
those arguments. A kernel is admitted only when its digest is in PINS and the
decoded closure (function, string references, every BL to the function, and
the site list digest) matches the reviewed one: an unknown or different
kernel is refused instead of patched unreviewed.
tools/test-kernel-refmod-skip.py builds both images and checks the contract.
"""
import bisect
import hashlib
import re
import struct

# 26A428 J700 kernelcache.release.mac17p (probes/nativecalls.py KERNEL_SHA256).
J700_26A428 = 'dc9019ae39187b36936c2c513b485e513f15cd966b5c887ac88ffd2925976c62'
KERNEL_BUNDLE = 'com.apple.kernel'
# phys_attribute_clear_with_flush_range's two panic format strings.
STRINGS = (
    b'phys_attribute_clear(%#010x,%#010x,%#010x,%p,%p): invalid options @%s:%d',
    b"phys_attribute_clear(%#010x,%#010x,%#010x,%p,%p): should not clear 'modified' "
    b'without flushing TLBs @%s:%d',
)
PP_ATTR_REFERENCED = 0x40
PMAP_OPTIONS_NOFLUSH = 0x20
MOVZ_W, MOVZ_X = 0x52800000, 0xd2800000     # MOVZ Wd/Xd, #imm16, LSL #0
ARGUMENTS = frozenset((MOVZ_W | PP_ATTR_REFERENCED << 5 | 1,     # MOVZ W1, #0x40
                       MOVZ_W | PMAP_OPTIONS_NOFLUSH << 5 | 2,   # MOVZ W2, #0x20
                       MOVZ_X | 3,                               # MOVZ X3, #0
                       MOVZ_X | 4))                              # MOVZ X4, #0
NOP = 0xd503201f
PACIBSP = 0xd503237f
# The reviewed closure: the function, its string references and every BL to
# it (offsets from the function), and the digest of the sorted "va word" site
# list (closure_digest below).
PINS = {
    J700_26A428: dict(
        function=0xfffffe000ba6d7d8,
        string_refs=(0x2c0, 0x2e8),
        calls=16,
        sites=2,
        closure_sha256='4af4e969e934147f7538e7e4979f64b9710521b348c1f9f02ea6954908c9c014',
    ),
}


def _signed(value, bits):
    return value - (1 << bits) if value >> (bits - 1) & 1 else value


def branch_target(word, pc):
    """(target, is_call) of a direct branch at pc, else None."""
    if word & 0x7c000000 == 0x14000000:                 # B, BL
        return pc + 4 * _signed(word & 0x3ffffff, 26), bool(word >> 31)
    if word & 0xff000000 == 0x54000000:                 # B.cond, BC.cond
        return pc + 4 * _signed(word >> 5 & 0x7ffff, 19), False
    if word & 0x7e000000 == 0x34000000:                 # CBZ, CBNZ
        return pc + 4 * _signed(word >> 5 & 0x7ffff, 19), False
    if word & 0x7e000000 == 0x36000000:                 # TBZ, TBNZ
        return pc + 4 * _signed(word >> 5 & 0x3fff, 14), False
    return None


def indirect_jump(word):
    """BR, BRAA, BRAB, BRAAZ, BRABZ: a jump through a register without link."""
    return word & 0xfeff0000 == 0xd61f0000


# Byte 3 of every direct branch: B 0x14-0x17, BL 0x94-0x97, B.cond 0x54,
# CBZ/CBNZ/TBZ/TBNZ 0x34-0x37 and 0xb4-0xb7.
_BRANCH_BYTE = re.compile(rb'[\x14-\x17\x94-\x97\x54\x34-\x37\xb4-\xb7]')
_ADRP_BYTE = re.compile(rb'[\x90\xb0\xd0\xf0]')


def _segments(image):
    for _, va, _, off, size in image.executable_segments:
        if (va | off | size) & 3 or off + size > len(image.data):
            raise ValueError('unaligned or incomplete executable segment')
        yield va, off, size


def branches(image):
    """[(pc, target, is_call)] for every direct branch in the executable segments."""
    out = []
    for va, off, size in _segments(image):
        body = image.data[off:off + size]
        for match in _BRANCH_BYTE.finditer(body):
            pos = match.start() - 3
            if pos & 3:
                continue
            found = branch_target(struct.unpack_from('<I', body, pos)[0], va + pos)
            if found is not None:
                out.append((va + pos, *found))
    return out


def sections(image, bundle):
    """[(segment, section, lo, hi, fileoff)] of one fileset entry."""
    off = next((o for name, _, o in image.kexts if name == bundle), None)
    if off is None:
        raise ValueError(f'no {bundle} in the kernelcache')
    out = []
    ncmds = struct.unpack_from('<I', image.data, off + 16)[0]
    p = off + 32
    for _ in range(ncmds):
        cmd, size = struct.unpack_from('<II', image.data, p)
        if cmd == 0x19:
            segment = bytes(image.data[p + 8:p + 24]).rstrip(b'\0').decode()
            for n in range(struct.unpack_from('<I', image.data, p + 64)[0]):
                s = p + 72 + 80 * n
                addr, length, fileoff = struct.unpack_from('<QQI', image.data, s + 32)
                out.append((segment, bytes(image.data[s:s + 16]).rstrip(b'\0').decode(),
                            addr, addr + length, fileoff))
        p += size
    return out


def _section(secs, segment, section):
    found = [s for s in secs if s[0] == segment and s[1] == section]
    if len(found) != 1:
        raise ValueError(f'{segment},{section}: {len(found)} sections')
    return found[0]


def string_address(image, cstring, text):
    """The address of the one NUL-terminated occurrence of text in cstring."""
    _, _, lo, hi, off = cstring
    blob = image.data[off:off + hi - lo]
    hits = [m.start() for m in re.finditer(re.escape(text + b'\0'), blob)
            if m.start() == 0 or blob[m.start() - 1] == 0]
    if len(hits) != 1:
        raise ValueError(f'{len(hits)} copies of a phys_attribute_clear panic string')
    return lo + hits[0]


def string_refs(image, text_section, address):
    """Every ADRP Xd + ADD Xn, Xd, #lo12 (within 8 words) that forms address."""
    _, _, lo, hi, off = text_section
    body = image.data[off:off + hi - lo]
    page, low = address & ~0xfff, address & 0xfff
    out = []
    for match in _ADRP_BYTE.finditer(body):
        pos = match.start() - 3
        if pos & 3:
            continue
        word = struct.unpack_from('<I', body, pos)[0]
        if word & 0x9f000000 != 0x90000000:
            continue
        imm = _signed((word >> 5 & 0x7ffff) << 2 | word >> 29 & 3, 21) << 12
        if ((lo + pos) & ~0xfff) + imm & 0xffffffffffffffff != page:
            continue
        rd = word & 31
        for d in range(4, 36, 4):
            if pos + d + 4 > len(body):
                break
            add = struct.unpack_from('<I', body, pos + d)[0]
            if add & 0xffc00000 == 0x91000000 and add >> 5 & 31 == rd and add >> 10 & 0xfff == low:
                out.append(lo + pos)
                break
    return out


def find(image):
    """The decoded function, its string references, every BL to it and the sites.

    Returns dict(function, string_refs, calls=[(pc, [4 preceding words])],
    sites=[dict(va, offset, word, replacement, region)]) for the image as
    given. Raises ValueError when the pattern is ambiguous or unsafe."""
    secs = sections(image, KERNEL_BUNDLE)
    cstring = _section(secs, '__TEXT', '__cstring')
    text = _section(secs, '__TEXT_EXEC', '__text')
    refs = []
    for s in STRINGS:
        found = string_refs(image, text, string_address(image, cstring, s))
        if len(found) != 1:
            raise ValueError(f'{len(found)} references to a phys_attribute_clear panic string')
        refs.append(found[0])
    every = branches(image)
    entries = sorted({t for _, t, call in every if call})
    owners = {entries[bisect.bisect_right(entries, r) - 1] for r in refs if entries[0] <= r}
    if len(owners) != 1:
        raise ValueError('the panic strings are not referenced from one called function')
    function = owners.pop()
    if any(function < e <= max(refs) for e in entries):
        raise ValueError('a called entry lies between the function and its panic strings')

    def word_at(va):
        for sva, off, size in _segments(image):
            if sva <= va < sva + size:
                return struct.unpack_from('<I', image.data, off + va - sva)[0], off + va - sva
        raise ValueError(f'{va:#x} is not executable')
    if word_at(function)[0] != PACIBSP:
        raise ValueError('the phys_attribute_clear function does not start with PACIBSP')

    calls = sorted((pc, [word_at(pc - 4 * k)[0] for k in (4, 3, 2, 1)])
                   for pc, t, call in every if call and t == function)
    candidates = [pc for pc, before in calls if set(before) == ARGUMENTS and len(set(before)) == 4]
    windows = {pc: range(pc - 12, pc + 4, 4) for pc in candidates}
    landing = {t for _, t, _ in every}
    sites = []
    for pc in candidates:
        if not (text[2] <= pc - 16 and pc < text[3]):
            raise ValueError(f'{pc:#x}: a reference-clear call outside {KERNEL_BUNDLE} __text')
        if any(a in landing for a in windows[pc]):
            raise ValueError(f'{pc:#x}: a branch lands inside the argument window')
        i = bisect.bisect_right(entries, pc)
        lo, hi = entries[i - 1], entries[i] if i < len(entries) else text[3]
        if any(indirect_jump(word_at(a)[0]) for a in range(lo, hi, 4)):
            raise ValueError(f'{pc:#x}: an indirect jump in the containing region')
        word, offset = word_at(pc)
        sites.append(dict(va=pc, offset=offset, word=word, replacement=NOP, region=(lo, hi)))
    return dict(function=function, string_refs=tuple(r - function for r in refs),
                calls=calls, sites=sites)


def closure_digest(sites):
    return hashlib.sha256(''.join(f'{s["va"]:x} {s["word"]:08x}\n' for s in sites).encode()).hexdigest()


def closure(found):
    return dict(function=found['function'], string_refs=found['string_refs'],
                calls=len(found['calls']), sites=len(found['sites']),
                closure_sha256=closure_digest(found['sites']))


def admit(image):
    """The decoded sites of a pinned kernel whose closure matches its pin."""
    kernel = hashlib.sha256(image.data).hexdigest()
    pin = PINS.get(kernel)
    if pin is None:
        raise ValueError(f'kernel {kernel[:16]}... has no reviewed refmod-skip closure')
    found = find(image)
    summary = closure(found)
    for key in ('function', 'string_refs', 'calls', 'sites', 'closure_sha256'):
        if summary[key] != pin[key]:
            raise ValueError(f'refmod-skip closure differs from the reviewed one ({key})')
    return kernel, found, summary


def patch(image, data):
    """Rewrite the admitted sites in data, a stock-derived loaded image.

    data may already carry other admitted replacements (the SPTM HVC calls,
    sysreg-zero); each site must still hold its stock BL, and afterwards the
    executable bytes differ from their state on entry at exactly the sites."""
    if len(data) != len(image.data):
        raise ValueError('refmod-skip patch does not cover the selected kernel image')
    kernel, found, summary = admit(image)
    sites = found['sites']
    before = {off: bytes(data[off:off + size]) for _, off, size in _segments(image)}
    for site in sites:
        if struct.unpack_from('<I', data, site['offset'])[0] != site['word']:
            raise ValueError(f'{site["va"]:#x}: refmod-skip site already modified')
        struct.pack_into('<I', data, site['offset'], site['replacement'])
    for _, off, size in _segments(image):
        expected = bytearray(before[off])
        for site in sites:
            if off <= site['offset'] < off + size:
                struct.pack_into('<I', expected, site['offset'] - off, site['replacement'])
        if data[off:off + size] != expected:
            raise ValueError('refmod-skip changed executable bytes outside its sites')
    return dict(summary, kernel_sha256=kernel,
                loaded_data_sha256=hashlib.sha256(data).hexdigest(),
                site_list=[(s['va'], s['word'], s['replacement']) for s in sites])

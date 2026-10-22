# SPDX-License-Identifier: MIT
"""Opt-in 4 KiB user page tables for every process in the kernel.

SNAP_KERNEL_USER_4K=1 (or xnuboot.build(..., user_4k=True)) rewrites, in the
loader's copy of the stock image, four branches that the instruction decoder
finds in the kernel's __text. Three make every process be created exactly as
one spawned with Apple's own 4K testing switch (posix_spawnattr psa_4k, or
_POSIX_SPAWN_FORCE_4K_PAGES = psa_flags bit 12); the fourth (G) keeps 4K maps
off VM guard objects, whose allocator assumes 16K pages:

  P1 load_machfile (mach_loader.c:781)
       LDR  X8, [X19, #0x2e0]     imgp->ip_px_sa
       CBZ  X8, skip              ->  B force
       LDRB W9, [X8, #0x69]       psa->psa_4k
       TBNZ W9, #0, force
       LDRH W8, [X8]              psa->psa_flags
       TBNZ W8, #12, force
     force: ORR W25, W25, #0x8    pmap_flags |= PMAP_CREATE_FORCE_4K_PAGES
  P2 exec_add_apple_strings (kern_exec.c:8165): the same test, whose force
     path adds the "vm_force_4k_pages=1" apple string userspace reads.
  Q  load_machfile (mach_loader.c:1006): the entitlement gate that a forced
     4K arm64 process must pass ("com.apple.private.4k-pages", then the two
     cross-architecture entitlements, else the exec fails):
       CBZ  W26, past_gate        ->  B past_gate
     W26 is set on P1's force path for every non-x86 binary.
  G  vm_guard_object_find_space_anywhere (vm_map_store.c:1958): the map's
     page shift, which sizes the slab bucket of the request:
       CBZ  X0, kernel            (no map: shift 14)
       LDRB W8, [X0, #0x2c]       map->hdr.page_shift
       B    mask                  ->  TBZ W8, #1, fallback
     kernel: MOV W8, #14
     mask:   MOV W9, #-1; LSL W8, W9, W8; MVN W8, W8; ORR X20, X6, X8
     fallback: MOV W8, #0x2e; B epilogue (returns 46, which its caller
     vm_map_locate_space_anywhere answers with the ordinary allocator).
     The bucket is bit_length(page-rounded size - 1) and the slab arrays
     (vgos_partial/vgos_full[28]) start at bucket 14: in a 4K map a request of
     at most 4K is bucket 12, index -2, so vmgo_chunk_alloc_anywhere stores
     its new chunk pointer 16 bytes before the map's vmgo_slab_pair, i.e. at
     +1008 of the preceding 1 KiB element of early.kalloc.1024 (896-byte
     KT_GO_SLAB rounded up). installed-fresh-20261018-v56 and -v58 panicked
     on exactly that ("[early.kalloc.1024]: element modified after free
     (off:1008, val:<64-byte-aligned chunk>)"). Page shifts with bit 1 set
     (14, the only other one macOS uses) take the stock path unchanged;
     every other (12) falls back before any guard-object state is touched.

The source firmware file is never rewritten, and every other byte is unchanged.
Neither force path reads the spawn attributes (P1's computes W26 from the CPU
type and the cambria flag; P2's only passes the string), so taking them with
no attributes is the attribute-less spawn the switch describes. The boot-arg
cambria_pagesize=4 is not needed: it only selects 4K for x86_64 (Rosetta)
processes (pmap_create_options_internal, load_machfile:792).

Why. The A16 has no 16K granule, so a 16K user tree can only ever be shadowed.
With every user pmap in SPTM format 1 (4K tables, L0 root, T0SZ 17) the
monitor can let the hardware walk XNU's own tables (SNAP_USER_HW_WALK,
compat/user-hw-walk.h). Without that monitor define the patch is legal but
slower (docs/KERNEL-PATCHES.md "Studied and rejected").

Admission. The sites are found by decoding, never from an address list: the
P pattern above (registers free, offsets 0x2e0/0x69 and bit 12 fixed),
classified by the instruction at force; Q is the CBZ Wn nearest before the
ADRP+ADD X2 of the gate's string whose target lies past the gate's calls. A
kernel is admitted only when its digest is in PINS and the decoded closure
(one site of each kind, and the digest of the site list) matches the
reviewed one. tools/test-kernel-user-4k.py builds both images and checks the
contract, alone and with the other kernel patches.
"""
import hashlib
import re
import struct

from refmodskip import _section, _segments, _signed, sections, string_refs

# 26A428 J700 kernelcache.release.mac17p (probes/nativecalls.py KERNEL_SHA256).
J700_26A428 = 'dc9019ae39187b36936c2c513b485e513f15cd966b5c887ac88ffd2925976c62'
KERNEL_BUNDLE = 'com.apple.kernel'
APPLE_STRING = b'vm_force_4k_pages=1'
ENTITLEMENT = b'com.apple.private.4k-pages'
IP_PX_SA = 0x2e0                 # struct image_params ip_px_sa
PSA_4K = 0x69                    # struct _posix_spawnattr psa_4k
FORCE_4K_BIT = 12                # _POSIX_SPAWN_FORCE_4K_PAGES in psa_flags
KINDS = ('load_machfile force', 'apple string', 'entitlement gate', 'guard objects fallback')
MAP_PAGE_SHIFT = 0x2c            # struct _vm_map hdr.page_shift
KERN_NOT_SUPPORTED = 0x2e        # vm_guard_object_find_space_anywhere: use the ordinary allocator
PINS = {
    J700_26A428: dict(
        sites=4,
        kinds={'apple string': 1, 'entitlement gate': 1, 'guard objects fallback': 1,
               'load_machfile force': 1},
        closure_sha256='c63aa83cd441cd8cfab761a9b4b5e8858950c9e3ac34e82aaa9152283b663bc4',
    ),
}


def b_to(pc, target):
    """B target, from pc."""
    offset = (target - pc) >> 2
    if (target - pc) & 3 or not -(1 << 25) <= offset < 1 << 25:
        raise ValueError(f'{pc:#x}: B target out of range')
    return 0x14000000 | (offset & 0x3ffffff)


def tbz_to(pc, target, reg, bit):
    """TBZ Wreg, #bit, target, from pc."""
    offset = (target - pc) >> 2
    if (target - pc) & 3 or not -(1 << 13) <= offset < 1 << 13 or not 0 <= bit < 32:
        raise ValueError(f'{pc:#x}: TBZ target out of range')
    return 0x36000000 | bit << 19 | (offset & 0x3fff) << 5 | reg


def _guard_objects(words, tva):
    """G: [(pc of the B, register, fallback target)]."""
    out = []
    for i in range(len(words) - 8):
        cbz, ldrb, b, mov14, m1, lsl, mvn, orr = words[i:i + 8]
        t = ldrb & 31
        if (cbz != 0xb4000060 or ldrb != 0x39400000 | MAP_PAGE_SHIFT << 10 | t or b != 0x14000002 or
                mov14 != 0x528001c0 | t or m1 & 0xffffffe0 != 0x12800000):
            continue
        s = m1 & 31
        if (lsl != 0x1ac02000 | t << 16 | s << 5 | t or mvn != 0x2a2003e0 | t << 16 | t or
                orr & 0xfffffc00 != 0xaa000000 | t << 16):
            continue
        # The fallback: the first MOV Wt, #46; B epilogue after it, where the
        # epilogue moves Wt to the result and returns (RETAB) within 12 words.
        for k in range(i + 8, min(i + 0x200, len(words) - 1)):
            if words[k] != 0x52800000 | KERN_NOT_SUPPORTED << 5 | t or words[k + 1] >> 26 != 0x5:
                continue
            epi = k + 1 + _signed(words[k + 1] & 0x3ffffff, 26)
            if (0 <= epi < len(words) - 12 and words[epi] == 0xaa0003e0 | t << 16 and
                    0xd65f0fff in words[epi:epi + 12]):
                out.append((tva + 4 * (i + 2), t, tva + 4 * k))
            break
    return out


def _string(image, cstring, text):
    _, _, lo, hi, off = cstring
    blob = image.data[off:off + hi - lo]
    hits = [m.start() for m in re.finditer(re.escape(text + b'\0'), blob)
            if m.start() == 0 or blob[m.start() - 1] == 0]
    if len(hits) != 1:
        raise ValueError(f'{len(hits)} copies of {text!r}')
    return lo + hits[0]


def _adrp_add(words, i, pc):
    """(address, Rd) formed by ADRP at word i and an ADD of its register at i+1."""
    w0, w1 = words[i], words[i + 1]
    if w0 & 0x9f000000 != 0x90000000 or w1 & 0xff800000 != 0x91000000 or (w1 >> 5) & 31 != w0 & 31:
        return None
    imm = _signed(((w0 >> 5) & 0x7ffff) << 2 | (w0 >> 29) & 3, 21) << 12
    return ((pc & ~0xfff) + imm + ((w1 >> 10) & 0xfff)) & 0xffffffffffffffff, w1 & 31


def find(image):
    """[dict(kind, va, offset, word, replacement, target)] sorted by address."""
    secs = sections(image, KERNEL_BUNDLE)
    text = _section(secs, '__TEXT_EXEC', '__text')
    cstring = _section(secs, '__TEXT', '__cstring')
    _, _, tva, tend, toff = text
    words = struct.unpack_from(f'<{(tend - tva) // 4}I', image.data, toff)
    apple = _string(image, cstring, APPLE_STRING)
    entitlement = _string(image, cstring, ENTITLEMENT)
    sites = []
    for i, w in enumerate(words[:-8]):
        # LDR Xa, [Xb, #0x2e0] (64-bit, unsigned offset).
        if w & 0xffc00000 != 0xf9400000 or (w >> 10) & 0xfff != IP_PX_SA // 8:
            continue
        a = w & 31
        j = next((k for k in range(i + 1, i + 5) if words[k] & 0xff00001f == 0xb4000000 | a), None)
        if j is None:
            continue
        ldrb, tbnz, ldrh, tb12 = words[j + 1:j + 5]
        c = ldrb & 31
        if (ldrb & 0xffc00000 != 0x39400000 or (ldrb >> 10) & 0xfff != PSA_4K or (ldrb >> 5) & 31 != a or
                tbnz & 0xfff8001f != 0x37000000 | c or
                ldrh & 0xffffffe0 != 0x79400000 | a << 5 or
                tb12 & 0x7ef8001f != 0x36000000 | FORCE_4K_BIT << 19 | (ldrh & 31)):
            continue
        pc = tva + 4 * j
        force = pc + 8 + 4 * _signed((tbnz >> 5) & 0x3fff, 14)
        if not tva <= force < tend:
            raise ValueError(f'{pc:#x}: force path outside __text')
        fw = words[(force - tva) // 4]
        kind = None
        # ORR Wn, Wn, #0x8 (32-bit logical immediate N=0 immr=29 imms=0).
        if fw & 0xfffffc00 == 0x321d0000 and (fw >> 5) & 31 == fw & 31:
            kind = 'load_machfile force'
        else:
            formed = _adrp_add(words, (force - tva) // 4, force)
            if formed and formed[0] == apple:
                kind = 'apple string'
        if kind is None:
            raise ValueError(f'{pc:#x}: a psa_4k test whose force path is not recognised')
        sites.append(dict(kind=kind, va=pc, offset=toff + 4 * j, word=words[j],
                          replacement=b_to(pc, force), target=force))
    for i in range(len(words) - 1):
        formed = _adrp_add(words, i, tva + 4 * i)
        if not formed or formed[0] != entitlement or formed[1] != 2:
            continue
        for k in range(i - 1, max(i - 8, -1), -1):
            c = words[k]
            if c & 0xff000000 == 0x34000000:                    # CBZ Wn
                pc = tva + 4 * k
                target = pc + 4 * _signed((c >> 5) & 0x7ffff, 19)
                if target <= tva + 4 * i + 8 or target >= tend:
                    raise ValueError(f'{pc:#x}: the gate branch does not skip the gate')
                sites.append(dict(kind='entitlement gate', va=pc, offset=toff + 4 * k, word=c,
                                  replacement=b_to(pc, target), target=target))
                break
        else:
            raise ValueError('no gate branch before the 4K entitlement check')
    for pc, reg, fallback in _guard_objects(words, tva):
        j = (pc - tva) // 4
        sites.append(dict(kind='guard objects fallback', va=pc, offset=toff + 4 * j, word=words[j],
                          replacement=tbz_to(pc, fallback, reg, 1), target=fallback))
    return sorted(sites, key=lambda s: s['va'])


def closure_digest(sites):
    return hashlib.sha256(''.join(f'{s["va"]:x} {s["word"]:08x} {s["replacement"]:08x}\n'
                                  for s in sites).encode()).hexdigest()


def closure(sites):
    kinds = {}
    for s in sites:
        kinds[s['kind']] = kinds.get(s['kind'], 0) + 1
    return dict(sites=len(sites), kinds=dict(sorted(kinds.items())), closure_sha256=closure_digest(sites))


def admit(image):
    """The decoded sites of a pinned kernel whose closure matches its pin."""
    kernel = hashlib.sha256(image.data).hexdigest()
    pin = PINS.get(kernel)
    if pin is None:
        raise ValueError(f'kernel {kernel[:16]}... has no reviewed user-4k closure')
    sites = find(image)
    found = closure(sites)
    for key in ('sites', 'kinds', 'closure_sha256'):
        if found[key] != pin[key]:
            raise ValueError(f'user-4k closure differs from the reviewed one ({key})')
    return kernel, sites, found


def patch(image, data):
    """Rewrite the admitted sites in data, a stock-derived loaded image.

    data may already carry other admitted replacements (the SPTM HVC calls,
    sysreg-zero, refmod-skip); each site must still hold its stock word, and
    afterwards the executable bytes differ from their state on entry at
    exactly the sites."""
    if len(data) != len(image.data):
        raise ValueError('user-4k patch does not cover the selected kernel image')
    kernel, sites, found = admit(image)
    before = {off: bytes(data[off:off + size]) for _, off, size in _segments(image)}
    for site in sites:
        if struct.unpack_from('<I', data, site['offset'])[0] != site['word']:
            raise ValueError(f'{site["va"]:#x}: user-4k site already modified')
        struct.pack_into('<I', data, site['offset'], site['replacement'])
    for _, off, size in _segments(image):
        expected = bytearray(before[off])
        for site in sites:
            if off <= site['offset'] < off + size:
                struct.pack_into('<I', expected, site['offset'] - off, site['replacement'])
        if data[off:off + size] != expected:
            raise ValueError('user-4k changed executable bytes outside its sites')
    return dict(found, kernel_sha256=kernel,
                loaded_data_sha256=hashlib.sha256(data).hexdigest(),
                site_list=[(s['va'], s['word'], s['replacement'], s['kind']) for s in sites])

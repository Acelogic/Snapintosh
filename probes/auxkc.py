# SPDX-License-Identifier: MIT
"""Admission and placement for a kmutil-built, code-bearing AuxKC.

The codeless path (bootfb.py) serializes its own 32 KiB collection. This one
takes Apple's linker output instead: `kmutil create -n aux` links our kexts
against the pinned BootKC and emits an MH_FILESET whose lowest vmaddr is 0,
whose RW segments sit below its mach header and whose pointers are still
raw chained-fixup words. XNU finishes the job at EL1:

  arm_vm_auxkc_init -> arm_auxkc_init(mh, base)
    slide = base                          (lowest vmaddr is 0)
    kernel_collection_slide(mh, bases)    walks the chains, PAC-signs
    kernel_collection_adjust_mh_addrs()   adds `base` to every vmaddr
  then asserts the RO/RX/LINKEDIT ordering checked by `layout_checks` here.

So the loader must map every segment at base + vmaddr with its bytes exactly
as kmutil wrote them, and must NOT apply the fixups (the primary image is
pre-flattened by xnuboot.build; this collection is not). There is one AuxKC
handoff (+0x2d8 base, +0x2e0 header, +0x2e8 end), so the codeless boot
framebuffer bundle travels inside this collection as an ordinary codeless kext.

Nothing here executes, signs or modifies an Apple binary.
"""
import hashlib
import json
from pathlib import Path
import plistlib
import struct

PAGE = 0x4000
MH_MAGIC_64 = 0xfeedfacf
CPU_ARM64 = 0x100000c
CPU_SUBTYPE_ARM64E = 2
MH_FILESET = 12
LC_SEGMENT_64 = 0x19
LC_UUID = 0x1b
LC_SYMTAB = 0x2
LC_DYLD_CHAINED_FIXUPS = 0x80000034
LC_FILESET_ENTRY = 0x80000035
VM_PROT_WRITE = 2
VM_PROT_EXECUTE = 4
# dyld_chained_ptr_64_kernel_cache_rebase; walk_chain rejects anything else.
DYLD_CHAINED_PTR_64_KERNEL_CACHE = 8
CHAINED_PTR_START_NONE = 0xffff
CHAINED_PTR_START_MULTI = 0x8000
# fixup64.cacheLevel indexes collection_base_pointers[] by kc index, not by
# kc_kind: pexpert/gen/kcformat.c primary=0, pageable=1, auxiliary=3. The
# pageable/system slots are null on this boot; a pointer through them makes
# fixup_value stop the whole walk and leaves the rest of the chains raw.
LEVEL_PRIMARY = 0
LEVEL_AUXILIARY = 3
MANIFEST_FORMAT = 'snapintosh-auxkc-v1'
BOOTFB_BUNDLE = 'org.snapintosh.bootframebuffer'
# kmutil records these on every personality it links; nothing else may change.
KMUTIL_PERSONALITY_KEYS = frozenset({'IOPersonalityPublisher'})
MAX_BYTES = 0x01000000


def _cstring(raw):
    return raw.split(b'\0', 1)[0].decode('ascii')


class Collection:
    """A strict reader: every length and offset is bounded before use."""

    def __init__(self, data):
        self.data = bytes(data)
        if len(self.data) < 32 or len(self.data) > MAX_BYTES:
            raise ValueError('AuxKC size outside supported bounds')
        magic, cpu, subtype, kind, count, size, _, _ = struct.unpack_from('<8I', self.data)
        if magic != MH_MAGIC_64 or cpu != CPU_ARM64 or (subtype & 0xff) != CPU_SUBTYPE_ARM64E:
            raise ValueError('AuxKC is not an arm64e Mach-O')
        if kind != MH_FILESET:
            raise ValueError('AuxKC is not an MH_FILESET')
        if not 0 < count <= 256 or 32 + size > min(len(self.data), PAGE):
            raise ValueError('AuxKC load commands outside the header page')
        self.segments = []   # (name, vmaddr, vmsize, fileoff, filesize, maxprot, initprot)
        self.sections = {}   # (segment, section) -> (addr, size, offset)
        self.entries = []    # (bundle id, vmaddr, fileoff)
        self.uuid = None
        self.fixups = None
        pos = 32
        for _ in range(count):
            if pos + 8 > 32 + size:
                raise ValueError('AuxKC command header outside bounds')
            cmd, length = struct.unpack_from('<II', self.data, pos)
            if length < 8 or length % 8 or pos + length > 32 + size:
                raise ValueError('AuxKC command outside bounds')
            if cmd == LC_SEGMENT_64:
                if length < 72:
                    raise ValueError('short AuxKC segment command')
                raw, va, vmsize, off, filesize, maxprot, initprot, nsects, _ = \
                    struct.unpack_from('<16sQQQQiiII', self.data, pos + 8)
                name = _cstring(raw)
                if length != 72 + 80 * nsects:
                    raise ValueError(f'AuxKC segment {name} section table size')
                self.segments.append((name, va, vmsize, off, filesize, maxprot, initprot))
                for n in range(nsects):
                    sraw, graw, addr, ssize, soff = struct.unpack_from(
                        '<16s16sQQI', self.data, pos + 72 + 80 * n)
                    self.sections[(_cstring(graw), _cstring(sraw))] = (addr, ssize, soff)
            elif cmd == LC_UUID:
                if length != 24 or self.uuid is not None:
                    raise ValueError('invalid AuxKC UUID command')
                self.uuid = self.data[pos + 8:pos + 24]
            elif cmd == LC_DYLD_CHAINED_FIXUPS:
                if length != 16 or self.fixups is not None:
                    raise ValueError('invalid AuxKC chained-fixups command')
                self.fixups = struct.unpack_from('<II', self.data, pos + 8)
            elif cmd == LC_FILESET_ENTRY:
                va, off, name_off = struct.unpack_from('<QQI', self.data, pos + 8)
                if not 32 <= name_off < length:
                    raise ValueError('invalid AuxKC fileset entry name')
                self.entries.append((_cstring(self.data[pos + name_off:pos + length]), va, off))
            pos += length
        if pos != 32 + size:
            raise ValueError('AuxKC command count/size mismatch')
        if self.uuid is None:
            raise ValueError('AuxKC has no LC_UUID')
        self._check_segments()

    def _check_segments(self):
        loaded = []
        for name, va, vmsize, off, filesize, maxprot, initprot in self.segments:
            if not vmsize:
                continue
            if (va | vmsize | off) % PAGE or filesize > vmsize or off + filesize > len(self.data):
                raise ValueError(f'AuxKC segment {name} is unaligned or truncated')
            if maxprot & ~7 or initprot & ~7 or initprot & ~maxprot:
                raise ValueError(f'AuxKC segment {name} has invalid protections')
            if initprot & VM_PROT_WRITE and initprot & VM_PROT_EXECUTE:
                raise ValueError(f'AuxKC segment {name} is writable and executable')
            loaded.append((va, va + vmsize, name))
        if not loaded:
            raise ValueError('AuxKC has no loaded segments')
        loaded.sort()
        for (_, end, a), (start, _, b) in zip(loaded, loaded[1:]):
            if end > start:
                raise ValueError(f'AuxKC segments {a} and {b} overlap')
        # arm_auxkc_init: "the lowest vmaddr in an AuxKC collection is 0".
        if loaded[0][0] != 0:
            raise ValueError('AuxKC lowest vmaddr is not 0; XNU slides by base')
        self.top = loaded[-1][1]
        headers = [s for s in self.segments if s[0] == '__TEXT' and s[3] == 0 and s[4]]
        if len(headers) != 1:
            raise ValueError('AuxKC needs exactly one __TEXT segment holding its header')
        self.mh_vmaddr = headers[0][1]

    def segment_at(self, va, size=1):
        for seg in self.segments:
            name, start, vmsize, off, filesize, _, _ = seg
            if start <= va and va + size <= start + filesize:
                return seg
        return None

    def file_offset(self, va, size=8):
        seg = self.segment_at(va, size)
        if seg is None:
            raise ValueError(f'AuxKC address {va:#x} is not file-backed')
        return seg[3] + va - seg[1]

    def prelink_info(self):
        sec = self.sections.get(('__PRELINK_INFO', '__info'))
        if sec is None:
            raise ValueError('AuxKC has no __PRELINK_INFO,__info')
        addr, size, off = sec
        if not size or off + size > len(self.data) or self.file_offset(addr, size) != off:
            raise ValueError('AuxKC prelink section outside its segment')
        info = plistlib.loads(self.data[off:off + size].split(b'\0', 1)[0])
        if not isinstance(info, dict) or not isinstance(info.get('_PrelinkInfoDictionary'), list):
            raise ValueError('AuxKC prelink metadata is not a kext list')
        return info


def symbols(coll):
    """Defined (N_SECT) symbols of every fileset entry, as unslid (vmaddr, name).

    kmutil keeps them only with `-s none` (build/build-auxkc.py passes it);
    a stripped collection yields none and readers fall back to address ranges.
    """
    result = []
    for bundle, _, off in coll.entries:
        if off + 32 > len(coll.data):
            raise ValueError(f'AuxKC entry {bundle} header outside the file')
        magic, _, _, _, count, size, _, _ = struct.unpack_from('<8I', coll.data, off)
        if magic != MH_MAGIC_64 or off + 32 + size > len(coll.data):
            raise ValueError(f'AuxKC entry {bundle} is not a Mach-O')
        pos = off + 32
        for _ in range(count):
            cmd, length = struct.unpack_from('<II', coll.data, pos)
            if length < 8 or pos + length > off + 32 + size:
                raise ValueError(f'AuxKC entry {bundle} command outside bounds')
            if cmd == LC_SYMTAB:
                symoff, nsyms, stroff, strsize = struct.unpack_from('<4I', coll.data, pos + 8)
                if symoff + 16 * nsyms > len(coll.data) or stroff + strsize > len(coll.data):
                    raise ValueError(f'AuxKC entry {bundle} symbol table outside the file')
                strings = coll.data[stroff:stroff + strsize]
                for n in range(nsyms):
                    strx, kind, _, _, value = struct.unpack_from('<IBBHQ', coll.data, symoff + 16 * n)
                    if kind & 0xe0 or kind & 0x0e != 0x0e or not 0 < strx < strsize:
                        continue
                    result.append((value, strings[strx:].split(b'\0', 1)[0].decode('ascii', 'replace')))
            pos += length
    return sorted(result)


def layout_checks(coll):
    """Emulate kernel_collection_adjust_mh_addrs and arm_vm_auxkc_init's asserts.

    The ranges are unslid (base 0); sliding adds the same constant to all of
    them, so the orderings hold or fail identically in the guest.
    """
    lowest = lowest_ro = lowest_rx = None
    highest = highest_nle = highest_ro = highest_rx = 0
    for name, va, vmsize, _, _, maxprot, _ in coll.segments:
        if not vmsize:
            continue
        lowest = va if lowest is None else min(lowest, va)
        linkedit = name == '__LINKEDIT'
        if va + vmsize > highest:
            highest = va + vmsize
            if not linkedit:
                highest_nle = highest
        if maxprot & VM_PROT_WRITE or linkedit:
            continue
        lowest_ro = va if lowest_ro is None else min(lowest_ro, va)
        highest_ro = max(highest_ro, va + vmsize)
        if not maxprot & VM_PROT_EXECUTE:
            continue
        if lowest_rx is None or (va < lowest_rx and lowest_rx <= va + vmsize):
            lowest_rx = va
        if va + vmsize > highest_rx and (highest_rx >= va or highest_rx == 0):
            highest_rx = va + vmsize
    if lowest_ro is None or lowest_rx is None:
        raise ValueError('AuxKC has no read-only executable range')
    checks = [
        ('segHIGHESTROAuxKC == segHIGHESTNLEAuxKC', highest_ro == highest_nle),
        ('segHIGHESTAuxKC >= segHIGHESTROAuxKC', highest >= highest_ro),
    ]
    highest_ro = max(highest_ro, highest)
    checks += [
        ('segHIGHESTRXAuxKC <= segHIGHESTROAuxKC', highest_rx <= highest_ro),
        ('segLOWESTRXAuxKC <= segHIGHESTRXAuxKC', lowest_rx <= highest_rx),
        ('segLOWESTROAuxKC <= segLOWESTRXAuxKC', lowest_ro <= lowest_rx),
        ('segLOWESTAuxKC <= segLOWESTROAuxKC', lowest <= lowest_ro),
    ]
    failed = [name for name, ok in checks if not ok]
    if failed:
        raise ValueError('AuxKC fails native arm_vm_auxkc_init asserts: ' + ', '.join(failed))
    return dict(lowest=lowest, highest=highest, lowest_ro=lowest_ro, highest_ro=highest_ro,
                lowest_rx=lowest_rx, highest_rx=highest_rx, highest_nle=highest_nle)


def chained_fixups(coll, primary):
    """Walk the chains exactly as kernel_collection_slide will, without writing.

    Yields (file offset, level, target VA if base were 0 for level 3, is_auth).
    Raises on anything XNU's walker would stop at, because a stopped walk
    leaves every later pointer as a raw chain word and faults much later.
    """
    if coll.fixups is None:
        return
    dataoff, datasize = coll.fixups
    if dataoff + datasize > len(coll.data) or datasize < 28:
        raise ValueError('AuxKC chained fixups outside the file')
    linkedit = [s for s in coll.segments if s[0] == '__LINKEDIT']
    if len(linkedit) != 1 or not linkedit[0][3] <= dataoff < dataoff + datasize <= linkedit[0][3] + linkedit[0][4]:
        raise ValueError('AuxKC chained fixups are not inside __LINKEDIT')
    blob = coll.data[dataoff:dataoff + datasize]
    version, starts = struct.unpack_from('<II', blob)
    if version != 0 or starts + 4 > datasize:
        raise ValueError('unsupported AuxKC chained-fixups header')
    seg_count, = struct.unpack_from('<I', blob, starts)
    if starts + 4 + 4 * seg_count > datasize:
        raise ValueError('AuxKC chained starts outside the table')
    for index in range(seg_count):
        seg_off, = struct.unpack_from('<I', blob, starts + 4 + 4 * index)
        if not seg_off:
            continue
        pos = starts + seg_off
        if pos + 22 > datasize:
            raise ValueError('AuxKC segment starts outside the table')
        _, page_size, fmt, seg_start, _, page_count = struct.unpack_from('<IHHQIH', blob, pos)
        if fmt != DYLD_CHAINED_PTR_64_KERNEL_CACHE:
            raise ValueError(f'AuxKC pointer format {fmt} is not the kernel-cache format')
        if page_size != PAGE or pos + 22 + 2 * page_count > datasize:
            raise ValueError('AuxKC chained page table is malformed')
        for page in range(page_count):
            start, = struct.unpack_from('<H', blob, pos + 22 + 2 * page)
            if start == CHAINED_PTR_START_NONE:
                continue
            if start & CHAINED_PTR_START_MULTI:
                raise ValueError('AuxKC uses multi-start pages; kernel_collection_slide aborts')
            # walk_chain: mh + segment_offset + page * page_size (modulo 2^64).
            va = (coll.mh_vmaddr + seg_start + page * page_size + start) & (2 ** 64 - 1)
            while True:
                off = coll.file_offset(va)
                seg = coll.segment_at(va, 8)
                if seg[0] == '__LINKEDIT' or seg[5] & VM_PROT_EXECUTE:
                    raise ValueError(f'AuxKC fixup at {va:#x} lands in {seg[0]}')
                raw, = struct.unpack_from('<Q', coll.data, off)
                target, level = raw & 0x3fffffff, (raw >> 30) & 3
                nxt, auth = (raw >> 51) & 0xfff, raw >> 63
                if level == LEVEL_PRIMARY:
                    if not primary.vmin + target < primary.vmax:
                        raise ValueError(f'AuxKC fixup at {va:#x} targets outside the BootKC')
                elif level == LEVEL_AUXILIARY:
                    if not target < coll.top:
                        raise ValueError(f'AuxKC fixup at {va:#x} targets outside the AuxKC')
                else:
                    raise ValueError(f'AuxKC fixup at {va:#x} uses absent cache level {level}')
                yield off, level, target, bool(auth)
                if not nxt:
                    break
                va += nxt * 4
                if va // PAGE != (va - nxt * 4) // PAGE:
                    raise ValueError('AuxKC fixup chain crosses a page')


def admit(coll, primary_image, primary_info, expected_bundles, bootfb_personality=None):
    """Everything the kernel will assume about this collection, checked offline."""
    info = coll.prelink_info()
    boot_id = primary_info.get('_PrelinkKCID')
    if not isinstance(boot_id, bytes) or info.get('_BootKCID') != boot_id:
        raise ValueError('AuxKC is not linked against the pinned BootKC')
    if info.get('_PrelinkKCID') != coll.uuid:
        raise ValueError('AuxKC prelink identity disagrees with its LC_UUID')
    kexts = info['_PrelinkInfoDictionary']
    bundles = sorted(k.get('CFBundleIdentifier') for k in kexts)
    if bundles != sorted(expected_bundles) or len(set(bundles)) != len(bundles):
        raise ValueError(f'AuxKC bundles {bundles} differ from the pinned list '
                         f'{sorted(expected_bundles)}')
    executables = {name for name, _, _ in coll.entries}
    coded = sorted(k['CFBundleIdentifier'] for k in kexts if 'CFBundleExecutable' in k)
    if sorted(executables) != coded:
        raise ValueError('AuxKC fileset entries disagree with its executable kexts')
    if bootfb_personality is not None:
        entry = next((k for k in kexts if k.get('CFBundleIdentifier') == BOOTFB_BUNDLE), None)
        if entry is None or 'CFBundleExecutable' in entry:
            raise ValueError('AuxKC lacks the codeless boot framebuffer bundle')
        personalities = entry.get('IOKitPersonalities', {})
        got = personalities.get('SnapintoshBootFramebuffer')
        if set(personalities) != {'SnapintoshBootFramebuffer'} or not isinstance(got, dict):
            raise ValueError('boot framebuffer bundle has unexpected personalities')
        extra = set(got) - set(bootfb_personality)
        if extra - KMUTIL_PERSONALITY_KEYS or {k: got[k] for k in bootfb_personality if k in got} != bootfb_personality:
            raise ValueError('boot framebuffer personality differs inside the AuxKC')
    ranges = layout_checks(coll)
    counts = {LEVEL_PRIMARY: 0, LEVEL_AUXILIARY: 0}
    auth = 0
    slots = set()
    for off, level, _, signed in chained_fixups(coll, primary_image):
        if off in slots:
            raise ValueError('AuxKC fixup chains revisit a slot')
        slots.add(off)
        counts[level] += 1
        auth += signed
    return dict(bundles=bundles, executables=coded, uuid=coll.uuid.hex(),
                fixups=dict(primary=counts[LEVEL_PRIMARY], auxiliary=counts[LEVEL_AUXILIARY],
                            authenticated=auth),
                ranges={k: hex(v) for k, v in ranges.items()}, top=hex(coll.top),
                mh_vmaddr=hex(coll.mh_vmaddr))


def handoff_values(coll, base_va, primary_end):
    """(auxkc_base, auxkc_mh, auxkc_end). auxkc_end also becomes end_kern and
    vm_kernelcache_top, so it covers both collections."""
    if base_va % PAGE or primary_end % PAGE:
        raise ValueError('AuxKC base and primary end must be page aligned')
    top = base_va + ((coll.top + PAGE - 1) & -PAGE)
    return base_va, base_va + coll.mh_vmaddr, max(top, primary_end)


def mappings(coll, base_va, base_pa):
    """Per-segment (va, pa, span, bytes, executable). Unfixed bytes, zero tail."""
    result = []
    for name, va, vmsize, off, filesize, maxprot, initprot in coll.segments:
        if not vmsize:
            continue
        body = coll.data[off:off + filesize].ljust(vmsize, b'\0')
        result.append((name, base_va + va, base_pa + va, vmsize, body,
                       bool(initprot & VM_PROT_EXECUTE)))
    return result


def manifest_path(path):
    path = Path(path)
    return path.with_name(path.name + '.json')


def load(path, kernel_sha256):
    """The collection plus its build manifest; the sha256 pin is mandatory."""
    path = Path(path)
    data = path.read_bytes()
    manifest = json.loads(manifest_path(path).read_text())
    if manifest.get('format') != MANIFEST_FORMAT:
        raise ValueError('AuxKC manifest has an unknown format')
    if hashlib.sha256(data).hexdigest() != manifest.get('sha256') or len(data) != manifest.get('bytes'):
        raise ValueError('AuxKC bytes do not match their pinned sha256')
    if manifest.get('kernel_sha256') != kernel_sha256:
        raise ValueError('AuxKC was linked against a different kernelcache')
    bundles = manifest.get('bundles')
    if not isinstance(bundles, list) or not bundles or not all(isinstance(b, str) for b in bundles):
        raise ValueError('AuxKC manifest has no bundle list')
    return data, manifest

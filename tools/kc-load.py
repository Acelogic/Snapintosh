#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Lay a stock kernelcache out the way a loader has to, and check the result.

An arm64e kernelcache is an MH_FILESET, and loading it is not a memcpy. Every
pointer in __DATA_CONST, __DATA and the kext data segments ships as a
`dyld_chained_ptr_64_kernel_cache_rebase` bitfield -- a 30-bit offset plus a
12-bit link to the next fixup in the same page -- so until the chains are walked
and each slot is overwritten, all of that data is garbage. m1n1's macho.py names
the load command and never processes it, which is exactly the trap this avoids.

    tools/kc-load.py downloads/extracted/j700ap/kernelcache.release.mac17p
    tools/kc-load.py ... --out build/xnu.img --slide 0

The checks are the point. Every rebased value must land inside a segment, and
which segment it lands in is reported, because a fixup pass that is subtly wrong
produces an image that loads and then dies somewhere unrelated.
"""
import argparse
import hashlib
import pathlib
import struct
import sys
from collections import Counter

MH_MAGIC_64 = 0xFEEDFACF
LC_SEGMENT_64 = 0x19
LC_UNIXTHREAD = 0x05
LC_DYLD_CHAINED_FIXUPS = 0x80000034
LC_FILESET_ENTRY = 0x80000035

# dyld_chained_ptr_64_kernel_cache_rebase. The only format a kernelcache uses.
DYLD_CHAINED_PTR_64_KERNEL_CACHE = 8
DYLD_CHAINED_PTR_ARM64E_KERNEL = 7
CHAINED_PTR_START_NONE = 0xFFFF


class Image:
    def __init__(self, data: bytes):
        self.data = data
        magic, _, _, self.filetype, ncmds = struct.unpack_from('<IiiII', data, 0)
        if magic != MH_MAGIC_64:
            raise SystemExit('not a 64-bit Mach-O')
        self.segments = []      # (name, vmaddr, vmsize, fileoff, filesize)
        self.executable_segments = []  # same tuples, selected by initprot
        self.segment_protections = []  # (name, vmaddr, vmsize, maxprot, initprot)
        self.kexts = []         # (name, vmaddr, fileoff)
        self.fixups = None      # (dataoff, datasize)
        self.entry = None

        off = 32
        for _ in range(ncmds):
            cmd, size = struct.unpack_from('<II', data, off)
            if cmd == LC_SEGMENT_64:
                name = data[off + 8:off + 24].rstrip(b'\0').decode()
                self.segments.append((name,) + struct.unpack_from('<QQQQ', data, off + 24))
                self.segment_protections.append((name, *struct.unpack_from('<QQ',data,off+24),
                                                 *struct.unpack_from('<II',data,off+56)))
                if struct.unpack_from('<I', data, off + 60)[0] & 4:
                    self.executable_segments.append(self.segments[-1])
            elif cmd == LC_DYLD_CHAINED_FIXUPS:
                self.fixups = struct.unpack_from('<II', data, off + 8)
            elif cmd == LC_FILESET_ENTRY:
                vmaddr, fileoff, nameoff = struct.unpack_from('<QQI', data, off + 8)
                end = data.index(b'\0', off + nameoff)
                self.kexts.append((data[off + nameoff:end].decode(), vmaddr, fileoff))
            elif cmd == LC_UNIXTHREAD:
                # ARM_THREAD_STATE64: x0..x28, fp, lr, sp, pc, cpsr.
                self.entry = struct.unpack_from('<34Q', data, off + 16)[32]
            off += size

        loaded = [s for s in self.segments if s[2]]
        self.vmin = min(s[1] for s in loaded)
        self.vmax = max(s[1] + s[2] for s in loaded)

    def segment_of_file(self, offset):
        for name, _, _, fileoff, filesize in self.segments:
            if fileoff <= offset < fileoff + filesize:
                return name
        return None

    def segment_of(self, va):
        for name, vmaddr, vmsize, _, _ in self.segments:
            if vmaddr <= va < vmaddr + vmsize:
                return name
        return None


def chained_fixups(image: Image, slide: int):
    """Walk every chain. Yields (file_offset, rebased_value)."""
    dataoff, datasize = image.fixups
    blob = image.data[dataoff:dataoff + datasize]
    version, starts_offset = struct.unpack_from('<II', blob, 0)
    if version != 0:
        raise SystemExit(f'unsupported chained-fixups version {version}')

    seg_count = struct.unpack_from('<I', blob, starts_offset)[0]
    offsets = struct.unpack_from(f'<{seg_count}I', blob, starts_offset + 4)

    base = image.vmin + slide
    for seg_index, seg_off in enumerate(offsets):
        if seg_off == 0:
            continue
        pos = starts_offset + seg_off
        _, page_size, pointer_format, segment_offset, _, page_count = \
            struct.unpack_from('<IHHQIH', blob, pos)
        if pointer_format not in (DYLD_CHAINED_PTR_64_KERNEL_CACHE,
                                  DYLD_CHAINED_PTR_ARM64E_KERNEL):
            raise SystemExit(f'segment {seg_index}: pointer format {pointer_format} '
                             'is not a kernel-cache format')
        starts = struct.unpack_from(f'<{page_count}H', blob, pos + 22)

        for page in range(page_count):
            start = starts[page]
            if start == CHAINED_PTR_START_NONE:
                continue
            cursor = segment_offset + page * page_size + start
            while True:
                raw = struct.unpack_from('<Q', image.data, cursor)[0]
                target = raw & 0x3FFFFFFF
                level = (raw >> 30) & 3
                nxt = (raw >> 51) & 0xFFF
                if level != 0:
                    raise SystemExit(f'cacheLevel {level} at {cursor:#x}: this is not '
                                     'a standalone kernelcache')
                # PAC diversity is dropped: the rebased slot is a plain VA. A
                # signed pointer would have to be re-signed with the boot-time
                # keys, which is the monitor's job, not the loader's.
                yield cursor, base + target
                if nxt == 0:
                    break
                cursor += nxt * 4


def hide_amx(image, data):
    """Clear the application AMX-version field in the loader's private copy.

    AMXIDR and XNU's internal AMX version remain unchanged. The publication
    sequence is found by instructions, then checked through its global,
    32-bit/64-bit commpage and optional x86 commpage stores. SME bits survive.
    """
    pinned = 'dc9019ae39187b36936c2c513b485e513f15cd966b5c887ac88ffd2925976c62'
    if hashlib.sha256(image.data).hexdigest() != pinned:
        raise ValueError('hide-amx requires the reviewed J700 26A428 kernelcache')
    if len(data) != len(image.data):
        raise ValueError('hide-amx loaded image size differs')
    before, after = 0xaa090108, 0x9261ed08

    def adrp(word, pc):
        immediate = ((word >> 29) & 3) | (((word >> 5) & 0x7ffff) << 2)
        if immediate & (1 << 20):
            immediate -= 1 << 21
        return (pc & ~4095) + (immediate << 12)

    def mapped_data(va, size):
        return any(base <= va and va + size <= base + backed and
                   not (initprot & 4)
                   for (_, base, _, _, backed), (_, _, _, _, initprot)
                   in zip(image.segments, image.segment_protections))

    sites = []
    for name, base, _, fileoff, filesize in image.executable_segments:
        end = fileoff + filesize
        if fileoff & 3 or filesize & 3 or end > len(image.data):
            raise ValueError('hide-amx executable segment bounds are invalid')
        cursor = fileoff
        while True:
            found = image.data.find(struct.pack('<I', 0x53051129), cursor, end)
            if found < 0:
                break
            cursor = found + 4
            start = found - 8
            if found & 3 or start < fileoff or start + 72 > end:
                continue
            words = struct.unpack_from('<18I', image.data, start)
            masks = {0: (0x9f00001f, 0x90000009), 1: (0xffc003ff, 0xb9400129),
                     4: (0x9f00001f, 0x9000000b), 5: (0xffc003ff, 0xb900016a),
                     8: (0x9f00001f, 0x90000008), 9: (0xffc003ff, 0xf9000109),
                     10: (0xffc003ff, 0xf94002ca), 12: (0xffc003ff, 0xf9400109),
                     13: (0xffc003ff, 0xf94002ca), 15: (0xffc003ff, 0xf94002aa),
                     16: (0xff00001f, 0xb400000a)}
            exact = {2: 0x53051129, 3: 0x5280002a, 6: before, 7: 0xb2750109,
                     11: 0xb9002149, 14: 0xf9000949, 17: 0xf907ed49}
            if (any(words[i] & mask != value for i, (mask, value) in masks.items()) or
                    any(words[i] != value for i, value in exact.items())):
                continue
            va = base + start - fileoff
            version = adrp(words[0], va) + ((words[1] >> 10) & 4095) * 4
            capability = adrp(words[8], va + 32) + ((words[9] >> 10) & 4095) * 8
            normal = adrp(words[4], va + 16) + ((words[5] >> 10) & 4095) * 4
            branch = (words[16] >> 5) & 0x7ffff
            if branch & (1 << 18):
                branch -= 1 << 19
            if (words[10] != words[13] or ((words[9] ^ words[12]) & 0x003ffc00) or
                    branch != 2 or len({version, capability, normal}) != 3 or
                    not mapped_data(version, 4) or not mapped_data(capability, 8) or
                    not mapped_data(normal, 4)):
                raise ValueError('hide-amx publication operands do not close')
            if bytes(data[start:start + 72]) != image.data[start:start + 72]:
                raise ValueError('hide-amx publication preimage changed or already patched')
            sites.append(dict(va=va + 24, file_offset=start + 24, before=before, after=after,
                              sequence_va=va, sequence_file_offset=start, sequence_bytes=72,
                              version_va=version, capabilities_va=capability,
                              commpage32_offset=0x20, commpage64_offset=0x10,
                              x86_commpage64_offset=0xfd8))
    if not sites or len(sites) > 8:
        raise ValueError('hide-amx publication sequence absent or exceeds bound')
    # Complete preflight precedes all writes, including when multiple sites exist.
    for site in sites:
        struct.pack_into('<I', data, site['file_offset'], after)
    closure = ''.join(f'{s["va"]:016x} {before:08x} {after:08x}\n' for s in sites)
    return dict(status='APPLICATION_AMX_CAPABILITY_MASKED', sites=sites, mask=0x78000000,
                kernel_sha256=pinned, closure_sha256=hashlib.sha256(closure.encode()).hexdigest(),
                native_sme_qualified=False)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('kernelcache')
    ap.add_argument('--slide', type=lambda v: int(v, 0), default=0,
                    help='KASLR slide to apply (default 0)')
    ap.add_argument('--out', help='write the fixed-up flat image here')
    ap.add_argument('--verbose', action='store_true')
    ap.add_argument('--hide-amx', action='store_true',
                    help='clear the application AMX-version capability field in the output image')
    args = ap.parse_args()

    path = pathlib.Path(args.kernelcache)
    image = Image(path.read_bytes())

    print(f'{path.name}: filetype {image.filetype}, {len(image.segments)} segments, '
          f'{len(image.kexts)} kexts')
    print(f'  entry            {image.entry:#018x}'
          f'  ({image.segment_of(image.entry)})')
    print(f'  span             {image.vmin:#018x} .. {image.vmax:#018x}'
          f'  ({(image.vmax - image.vmin) / (1 << 20):.1f} MiB)')
    if args.slide:
        print(f'  slide            {args.slide:#x} -> entry '
              f'{image.entry + args.slide:#018x}')

    for name, vmaddr, vmsize, fileoff, filesize in image.segments:
        gap = '' if vmsize == filesize else f'  (+{vmsize - filesize:#x} zero-fill)'
        print(f'  {name:<18} {vmaddr:#018x} +{vmsize:#011x}  file {fileoff:#010x}{gap}')

    if not image.fixups:
        print('\nNo LC_DYLD_CHAINED_FIXUPS. Nothing to rebase.')
        return 0

    buffer = bytearray(image.data)
    landed, source, stray, total = Counter(), Counter(), [], 0
    for offset, value in chained_fixups(image, args.slide):
        struct.pack_into('<Q', buffer, offset, value)
        total += 1
        source[image.segment_of_file(offset)] += 1
        segment = image.segment_of(value - args.slide)
        if segment is None:
            if len(stray) < 8:
                stray.append((offset, value))
        else:
            landed[segment] += 1

    if args.hide_amx:
        contract = hide_amx(image, buffer)
        print(f'  hide-amx: {len(contract["sites"])} application capability publication sites')

    print(f'\n{total:,} fixups applied')
    for segment, count in source.most_common():
        print(f'  in {segment:<18} {count:>10,}')
    for segment, count in landed.most_common():
        print(f'  -> {segment:<18} {count:>10,}')
    if not source['__DATA_SPTM']:
        print('  __DATA_SPTM carries no compile-time pointers: it is the window '
              'the monitor fills in at handoff, not static data.')
    if stray:
        print(f'\nFAILED: {len(stray)}+ rebased values land outside every segment. '
              'The chain walk or the base is wrong.')
        for offset, value in stray:
            print(f'  file {offset:#x} -> {value:#018x}')
        return 1
    print(f'  all {total:,} land inside a segment')

    # An independent check on the same data: a pointer slot that still holds a
    # raw chain field would have a `next` stride in it, and after a correct pass
    # none of the slots we touched can be read as one.
    if args.out:
        out = pathlib.Path(args.out)
        out.parent.mkdir(parents=True, exist_ok=True)
        blob = bytearray(image.vmax - image.vmin)
        for name, vmaddr, vmsize, fileoff, filesize in image.segments:
            if vmsize == 0:
                continue
            start = vmaddr - image.vmin
            blob[start:start + filesize] = buffer[fileoff:fileoff + filesize]
        out.write_bytes(bytes(blob))
        print(f'\nflat image  {out}  {len(blob):,} bytes, loads at '
              f'{image.vmin + args.slide:#x}')
    return 0


if __name__ == '__main__':
    sys.exit(main())

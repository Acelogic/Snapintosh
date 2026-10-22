#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Read Mach-O images and symbols from a selected split arm64e dyld cache.

All addresses are unslid. Never infer a guest slide from an image name;
match captured instruction bytes before resolving runtime addresses.
No extraction, rebasing, code modification, or target access is performed.
"""
import argparse
import json
import mmap
from pathlib import Path
import re
import struct


class Cache:
    def __init__(self, directory):
        self.directory = Path(directory)
        self.files = []
        self.maps = []
        self.images = {}
        self.parsed = {}
        try:
            for path in sorted(self.directory.glob('dyld_shared_cache_arm64e*')):
                if path.suffix in ('.map', '.atlas'):
                    continue
                stream = path.open('rb')
                header = stream.read(32)
                if not header.startswith(b'dyld_v1'):
                    stream.close()
                    continue
                view = mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_READ)
                self.files.append((path, stream, view))
                offset, count = struct.unpack_from('<II', header, 16)
                if not 0 < count <= 128 or offset+count*32 > len(view):
                    raise ValueError('invalid cache mapping table')
                for va, size, fileoff, maximum, initial in struct.iter_unpack(
                        '<QQQII', view[offset:offset+count*32]):
                    if size <= 0 or fileoff+size > len(view):
                        raise ValueError('cache mapping outside file')
                    self.maps.append((va, va+size, fileoff, path, view, initial))
            if not self.maps:
                raise ValueError('no arm64e cache mappings found')
            current = None
            for line in (self.directory/'dyld_shared_cache_arm64e.map').read_text().splitlines():
                if line.startswith('/'):
                    current = line
                    self.images[current] = []
                match = re.fullmatch(r'\s+(__\w+) 0x([0-9A-Fa-f]+) -> 0x([0-9A-Fa-f]+)', line)
                if match and current:
                    self.images[current].append((match[1], int(match[2], 16), int(match[3], 16)))
        except BaseException:
            self.close()
            raise

    def close(self):
        for _, stream, view in self.files:
            view.close()
            stream.close()
        self.files.clear()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

    def locate(self, address):
        matches = [m for m in self.maps if m[0] <= address < m[1]]
        if len(matches) != 1:
            raise ValueError(f'cache VA {address:#x} has {len(matches)} mappings')
        return matches[0]

    def read(self, address, size):
        if not 0 < size <= 32 << 20:
            raise ValueError('cache read outside bounded size')
        result = bytearray()
        while size:
            lo, hi, off, path, view, _ = self.locate(address)
            take = min(hi-address, size)
            start = off+address-lo
            result += view[start:start+take]
            address += take
            size -= take
        return bytes(result)

    def string(self, address):
        lo, hi, off, path, view, _ = self.locate(address)
        start = off+address-lo
        end = view.find(b'\0', start, start+min(hi-address, 8192))
        if end < 0:
            raise ValueError('cache symbol string not terminated within bound')
        return view[start:end].decode('utf-8', errors='replace')

    def image(self, path):
        if path in self.parsed:
            return self.parsed[path]
        texts = [r for r in self.images[path] if r[0] == '__TEXT']
        if len(texts) != 1:
            raise ValueError('image has no unique text header')
        base = texts[0][1]
        magic, cpu, subtype, kind, count, size, flags, reserved = struct.unpack('<8I', self.read(base, 32))
        # The cache includes /usr/lib/dyld as MH_DYLINKER, alongside MH_DYLIBs.
        if magic != 0xfeedfacf or cpu != 0x100000c or kind not in (6, 7) or not 0 < count <= 512 or not 0 < size <= 0x40000:
            raise ValueError('unsupported cached Mach-O header')
        raw = self.read(base+32, size)
        result = dict(path=path, base=base, segments=[], sections=[], uuid=None, symtab=None)
        pos = 0
        for _ in range(count):
            if pos+8 > size:
                raise ValueError('Mach-O command header outside bounds')
            cmd, length = struct.unpack_from('<II', raw, pos)
            if length < 8 or pos+length > size:
                raise ValueError('Mach-O command outside bounds')
            if cmd == 0x19:
                if length < 72:
                    raise ValueError('short Mach-O segment')
                name, va, span, off, filebytes, mp, ip, sections, _ = struct.unpack_from('<16sQQQQiiII', raw, pos+8)
                if 72+sections*80 != length:
                    raise ValueError('segment section count differs')
                result['segments'].append((name.rstrip(b'\0').decode(), va, span, off, filebytes))
                for i in range(sections):
                    sec, seg, addr, nbytes = struct.unpack_from('<16s16sQQ', raw, pos+72+i*80)
                    result['sections'].append((seg.rstrip(b'\0').decode(), sec.rstrip(b'\0').decode(), addr, nbytes))
            elif cmd == 2:
                if length != 24:
                    raise ValueError('invalid symbol command')
                result['symtab'] = struct.unpack_from('<4I', raw, pos+8)
            elif cmd == 0x1b:
                if length != 24:
                    raise ValueError('invalid UUID command')
                result['uuid'] = raw[pos+8:pos+24].hex()
            pos += length
        if pos != size:
            raise ValueError('Mach-O command count/size mismatch')
        self.parsed[path] = result
        return result

    def symbols(self, path):
        image = self.image(path)
        symoff, count, stroff, strsize = image['symtab']
        if not 0 < count <= 1 << 20 or not 0 < strsize <= 1 << 30:
            raise ValueError('symbol table outside bounds')
        links = [r for r in image['segments'] if r[0] == '__LINKEDIT']
        if len(links) != 1:
            raise ValueError('image has no unique linkedit segment')
        _, va, size, off, filebytes = links[0]
        if not off <= symoff < symoff+count*16 <= off+filebytes or not off <= stroff < stroff+strsize <= off+filebytes:
            raise ValueError('symbols outside linkedit')
        raw = self.read(va+symoff-off, count*16)
        result = []
        for index, kind, section, desc, value in struct.iter_unpack('<IBBHQ', raw):
            if index >= strsize:
                raise ValueError('symbol string outside table')
            if index:
                result.append((value, self.string(va+stroff-off+index), kind, section))
        return result

    def owner(self, address):
        # LINKEDIT is shared across all images and cannot establish ownership.
        return [(path, name) for path, rows in self.images.items()
                for name, lo, hi in rows if name != '__LINKEDIT' and lo <= address < hi]

    def match_code(self, runtime_pc, code):
        """Establish a slide from a unique full instruction-byte match.

        Only executable mappings qualify. A short or repeated sequence cannot
        identify a cache location; refuse it rather than guess from image names.
        """
        if runtime_pc < 0 or runtime_pc % 4 or not 64 <= len(code) <= 4096 or len(code) % 4:
            raise ValueError('need an aligned PC and 64..4096 instruction bytes')
        matches = []
        for lo, hi, off, path, view, prot in self.maps:
            if not prot & 4:
                continue
            end = off+hi-lo
            pos = view.find(code, off, end)
            while pos >= 0:
                address = lo+pos-off
                if address % 4 == 0:
                    matches.append(dict(unslid_pc=address, runtime_pc=runtime_pc,
                                        slide=runtime_pc-address, file=str(path),
                                        file_offset=pos, matched_bytes=len(code)))
                    if len(matches) > 1:
                        raise ValueError('instruction bytes match multiple executable locations')
                pos = view.find(code, pos+1, end)
        if not matches:
            raise ValueError('instruction bytes have no executable cache match')
        return matches[0]

    def pointer_target(self, address):
        """Decode an unslid v5 pointer only after verifying chain membership.

        This returns the target VA, without forging or reproducing a PAC.
        Format and chain stride: Apple dyld fd8d0c4d52320ebf64db34f3cb280310d905c5ae,
        include/mach-o/{dyld_cache_format.h,fixup-chains.h}, common/DyldSharedCache.cpp.
        """
        if address % 8:
            raise ValueError('unaligned cache pointer')
        lo, hi, off, path, view, _ = self.locate(address)
        if len(view) < 0x140:
            raise ValueError('missing mapping-with-slide header')
        table, count = struct.unpack_from('<II', view, 0x138)
        if not 0 < count <= 128 or table+count*56 > len(view):
            raise ValueError('invalid mapping-with-slide table')
        rows = [r for r in struct.iter_unpack('<6Q2I', view[table:table+count*56])
                if r[0] <= address < r[0]+r[1]]
        if len(rows) != 1:
            raise ValueError('no unique pointer slide mapping')
        base, size, fileoff, slideoff, slidesize, flags, maximum, initial = rows[0]
        if (base, base+size, fileoff) != (lo, hi, off) or slidesize < 24 or slideoff+slidesize > len(view):
            raise ValueError('pointer slide bounds differ from mapping')
        version, pagesize, pages, value_add = struct.unpack_from('<III4xQ', view, slideoff)
        if version != 5 or pagesize not in (4096, 16384):
            raise ValueError('only v5 cache pointer chains are supported')
        page = (address-base)//pagesize
        if page >= pages or 24+pages*2 > slidesize:
            raise ValueError('pointer page outside slide table')
        cursor = struct.unpack_from('<H', view, slideoff+24+page*2)[0]
        pagebase = base+page*pagesize
        while cursor != 0xffff:
            if cursor % 8 or cursor+8 > pagesize or pagebase+cursor+8 > hi:
                raise ValueError('pointer chain outside mapped page')
            raw = struct.unpack_from('<Q', view, off+page*pagesize+cursor)[0]
            if pagebase+cursor == address:
                target = value_add+(raw & ((1 << 34)-1))
                return target if raw >> 63 else target | (((raw >> 34) & 255) << 56)
            delta = (raw >> 52) & 0x7ff
            if not delta or pagebase+cursor > address:
                break
            cursor += delta*8
        raise ValueError('address is not a member of the pointer slide chain')


def main():
    parser = argparse.ArgumentParser(description=__doc__.split('\n\n')[0])
    parser.add_argument('directory', type=Path)
    parser.add_argument('--image', help='exact image path from the cache map')
    parser.add_argument('--symbols', help='regular expression for symbol names')
    parser.add_argument('--address', type=lambda value: int(value, 0), help='unslid VA; prints nearest symbol, not exact function proof')
    parser.add_argument('--snapshot', type=Path, help='CPU-stop JSON; establish a unique instruction-byte match and cache slide')
    args = parser.parse_args()
    if not args.image and not args.snapshot:
        parser.error('--image or --snapshot is required')
    if args.snapshot and args.address is not None:
        parser.error('--snapshot and --address are mutually exclusive')
    with Cache(args.directory) as cache:
        if args.snapshot:
            snapshot = json.loads(args.snapshot.read_text())
            match = cache.match_code(int(snapshot['pc'], 0), bytes.fromhex(snapshot['instruction']['data_hex']))
            args.address = match['unslid_pc']
            owners = cache.owner(args.address)
            if len(owners) != 1:
                raise ValueError('matched PC has no unique image owner')
            if args.image and args.image != owners[0][0]:
                raise ValueError('selected image differs from matched instruction owner')
            args.image = owners[0][0]
            print(json.dumps(dict(code_match=match)))
        meta = cache.image(args.image)
        print(json.dumps(dict(image=args.image, base=hex(meta['base']), uuid=meta['uuid'])))
        symbols = sorted(cache.symbols(args.image))
        if args.symbols:
            pattern = re.compile(args.symbols)
            for address, name, kind, section in symbols:
                if pattern.search(name):
                    print(f'{address:#x} {kind:#x} {section} {name}')
        if args.address is not None:
            candidates = [r for r in symbols if r[0] and r[0] <= args.address and (r[2] & 0xe) == 0xe]
            row = candidates[-1] if candidates else None
            print(json.dumps(dict(address=hex(args.address), owner=cache.owner(args.address),
                                  nearest_symbol=row, offset=hex(args.address-row[0]) if row else None)))


if __name__ == '__main__':
    main()

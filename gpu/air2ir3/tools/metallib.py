#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Minimal MTLB (.metallib) parser: lists functions and extracts each AIR bitcode blob.

Layout (reverse-engineered, matches files in macOS 27 26A428 BaseSystem):
  0x00 'MTLB'
  0x04 u16 target/platform flags, u16 fileVersionMajor, u16 fileVersionMinor
  0x0a u8 libraryType, u8 targetOS, u16 osMajor, u16 osMinor
  0x10 u64 fileSize
  0x18 u64 funcListOff, u64 funcListSize
  0x28 u64 publicMDOff, u64 publicMDSize
  0x38 u64 privateMDOff, u64 privateMDSize
  0x48 u64 bitcodeOff,  u64 bitcodeSize
  funcList: u32 count, then per function: u32 entrySize, tag records until 'ENDT'
  tag record: 4-byte tag, u16 len, payload (ENDT has no len)
"""
import struct, sys, os, json

def parse(path):
    d = open(path, 'rb').read()
    assert d[:4] == b'MTLB', 'not a metallib'
    plat, vmaj, vmin = struct.unpack_from('<HHH', d, 4)
    libtype, tos, osmaj, osmin = struct.unpack_from('<BBHH', d, 10)
    fsize, flo, fls, pmo, pms, pro, prs, bco, bcs = struct.unpack_from('<9Q', d, 0x10)
    hdr = dict(platform=hex(plat), file_version=f'{vmaj}.{vmin}', libtype=libtype,
               target_os=hex(tos), os_version=f'{osmaj}.{osmin}', file_size=fsize,
               funclist=(flo, fls), public_md=(pmo, pms), private_md=(pro, prs),
               bitcode=(bco, bcs))
    off = flo
    count, = struct.unpack_from('<I', d, off); off += 4
    funcs = []
    for i in range(count):
        esz, = struct.unpack_from('<I', d, off)
        p = off + 4
        f = {}
        while True:
            tag = d[p:p+4]; p += 4
            if tag == b'ENDT':
                break
            ln, = struct.unpack_from('<H', d, p); p += 2
            val = d[p:p+ln]; p += ln
            t = tag.decode('ascii', 'replace')
            if t == 'NAME':
                f['name'] = val.rstrip(b'\0').decode()
            elif t == 'TYPE':
                f['type'] = {0: 'vertex', 1: 'fragment', 2: 'kernel', 3: 'unqualified',
                             4: 'visible', 5: 'extern', 6: 'intersection', 7: 'mesh', 8: 'object'}.get(val[0], val[0])
            elif t == 'HASH':
                f['hash'] = val.hex()
            elif t == 'MDSZ':
                f['bc_size'], = struct.unpack('<Q', val)
            elif t == 'OFFT':
                f['pub_off'], f['priv_off'], f['bc_off'] = struct.unpack('<3Q', val)
            elif t == 'VERS':
                a = struct.unpack('<4H', val)
                f['air_version'] = f'{a[0]}.{a[1]}'; f['lang_version'] = f'{a[2]}.{a[3]}'
            else:
                f.setdefault('other', {})[t] = val.hex()
        off += esz
        funcs.append(f)
    return d, hdr, funcs

if __name__ == '__main__':
    path = sys.argv[1]
    outdir = sys.argv[2] if len(sys.argv) > 2 else None
    d, hdr, funcs = parse(path)
    print(json.dumps(hdr))
    for f in funcs:
        print(f"{f.get('type','?'):10} air={f.get('air_version')} msl={f.get('lang_version')} bc={f.get('bc_size',0):7d}  {f.get('name')}")
        if outdir:
            os.makedirs(outdir, exist_ok=True)
            s = hdr['bitcode'][0] + f['bc_off']
            open(os.path.join(outdir, f['name'] + '.bc'), 'wb').write(d[s:s+f['bc_size']])

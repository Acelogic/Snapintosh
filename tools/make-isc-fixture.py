#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Give a newly formatted, empty scratch APFS image the documented xART role.

This creates guest test media, not SEP-backed trusted storage. Apple's host
formatter restricts creation of this role to entitled callers. We instead
encode the public APFS field in a separate, unmounted image file and retain
the original. Never pass a physical device or an existing user filesystem.
See docs/ISC-BOOT-MEDIA-20260922.md for the fresh-image creation recipe.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct

MAX_SCRATCH_BYTES = 2 << 30  # permits native xART, Preboot and Hardware volumes


def checksum(block):
    if len(block) != 4096:
        raise ValueError('expected a 4 KiB APFS metadata block')
    a = b = 0
    mod = 0xffffffff
    for word, in struct.iter_unpack('<I', block[8:]):
        a = (a + word) % mod
        b = (b + a) % mod
    low = mod - (a + b) % mod
    high = mod - (a + low) % mod
    return struct.pack('<II', low, high)


def make_xart(source):
    if not 0x4000 <= len(source) <= MAX_SCRATCH_BYTES or len(source) % 0x4000:
        raise ValueError('scratch image size is outside the permitted bound')
    if source[32:36] != b'NXSB' or struct.unpack_from('<IQ', source, 36) != (4096, len(source) // 4096):
        raise ValueError('expected an unwrapped APFS scratch container')
    if source[:8] != checksum(source[:4096]):
        raise ValueError('invalid container superblock checksum')
    volumes = []
    for offset in range(0, len(source), 4096):
        if source[offset + 32:offset + 36] != b'APSB':
            continue
        block = source[offset:offset + 4096]
        if (block[:8] != checksum(block) or struct.unpack_from('<I', block, 24)[0] != 13 or
                struct.unpack_from('<H', block, 964)[0] != 0 or
                block[704:960].split(b'\0', 1)[0] != b'Snapintosh-xART' or
                any(struct.unpack_from('<5Q', block, 184)) or
                struct.unpack_from('<Q', block, 264)[0] != 1):
            raise ValueError('input is not the expected empty, unencrypted scratch volume')
        volumes.append(offset)
    if len(volumes) != 1:
        raise ValueError('expected exactly one freshly formatted volume superblock')
    result = bytearray(source)
    offset = volumes[0]
    struct.pack_into('<H', result, offset + 964, 0x100)
    result[offset:offset + 8] = checksum(result[offset:offset + 4096])
    return result, offset


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('source', type=Path)
    ap.add_argument('output', type=Path)
    ap.add_argument('--source-sha256', required=True)
    args = ap.parse_args()
    if not args.source.is_file() or args.source.is_symlink():
        ap.error('source must be a regular scratch image file')
    if args.source.stat().st_size > MAX_SCRATCH_BYTES:
        ap.error('source exceeds scratch image size limit')
    source = args.source.read_bytes()
    digest = hashlib.sha256(source).hexdigest()
    if digest != args.source_sha256:
        ap.error('fresh source image does not match the explicitly supplied SHA256')
    result, offset = make_xart(source)
    with args.output.open('xb') as stream:
        stream.write(result)
    print(json.dumps(dict(source=str(args.source), source_sha256=digest,
                          output=str(args.output), bytes=len(result),
                          sha256=hashlib.sha256(result).hexdigest(),
                          superblock_offset=offset, role=256,
                          sep_trusted_storage=False), indent=2))


if __name__ == '__main__':
    main()

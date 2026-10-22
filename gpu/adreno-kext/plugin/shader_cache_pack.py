#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Pack, verify and list AdrenoMetal compile-result cache records (host side).

The plug-in (AdrenoMetal/AdrenoShader.m) writes one record per air2ir3 cache key:
    <dir>/<namespace>/<key[:2]>/<key>.amse
and reads a read-only pack shipped in the bundle:
    Contents/Resources/AdrenoShaderCache.amsp

Record (little endian): b"AMSE" u32 version=1 u32 id_length u32 0 | key[64] (hex) |
u64 size[4] (sidecar, blob, code, program) | SHA-256 over bytes [0,112) + id + payloads |
id | payloads.
Pack: b"AMSP" u32 version=1 u32 count u32 id_length | id | pad to 8 |
count x (key[64] u64 offset u64 length), sorted by key | records (each 8-aligned).

    shader_cache_pack.py build --records DIR --output FILE.amsp [--compiler-id ID]
    shader_cache_pack.py verify FILE.amsp [--compiler-id ID]
Doc: docs/SHADER-COMPILE-PATH-20260928.md.
"""
import argparse
import hashlib
import json
import os
import re
import struct
import sys
from pathlib import Path

RECORD_HEADER, RECORD_DIGEST, PACK_HEADER, INDEX_ENTRY, MAX_ID = 144, 112, 16, 80, 1024
PAYLOAD_LIMIT = (8 << 20, 16 << 20, 16 << 20, 32 << 20)  # sidecar, blob, code, program
KEY = re.compile(rb'^[0-9a-f]{64}$')


def parse_record(data, key=None, compiler_id=None):
    """Return (key, compiler_id, sizes) of a valid record; raise ValueError otherwise."""
    if len(data) < RECORD_HEADER or data[:4] != b'AMSE':
        raise ValueError('not an AMSE record')
    version, id_length, reserved = struct.unpack_from('<III', data, 4)
    if version != 1 or reserved != 0 or not 0 < id_length <= MAX_ID:
        raise ValueError('unsupported record header')
    record_key = data[16:80]
    if not KEY.match(record_key) or (key is not None and record_key != key):
        raise ValueError('record key mismatch')
    sizes = struct.unpack_from('<4Q', data, 80)
    if any(not 0 < s <= limit for s, limit in zip(sizes, PAYLOAD_LIMIT)):
        raise ValueError('payload size outside its limit')
    if len(data) != RECORD_HEADER + id_length + sum(sizes):
        raise ValueError('record length mismatch')
    ident = data[RECORD_HEADER:RECORD_HEADER + id_length]
    if compiler_id is not None and ident != compiler_id:
        raise ValueError('record from a different compiler')
    digest = hashlib.sha256(data[:RECORD_DIGEST] + data[RECORD_HEADER:]).digest()
    if digest != data[RECORD_DIGEST:RECORD_HEADER]:
        raise ValueError('record digest mismatch')
    return record_key, ident, sizes


def build_pack(records, compiler_id):
    """records: {key(bytes): record bytes}. Returns the pack bytes."""
    head = b'AMSP' + struct.pack('<III', 1, len(records), len(compiler_id)) + compiler_id
    head += b'\0' * (-len(head) % 8)
    at = len(head) + INDEX_ENTRY * len(records)
    index, body = [], []
    for key in sorted(records):
        pad = -at % 8
        body.append(b'\0' * pad)
        at += pad
        index.append(key + struct.pack('<QQ', at, len(records[key])))
        body.append(records[key])
        at += len(records[key])
    return head + b''.join(index) + b''.join(body)


def read_pack(data, compiler_id=None):
    """Validate a whole pack; returns (compiler_id, {key: (offset, length)})."""
    if len(data) < PACK_HEADER or data[:4] != b'AMSP':
        raise ValueError('not an AMSP pack')
    version, count, id_length = struct.unpack_from('<III', data, 4)
    if version != 1 or not 0 < id_length <= MAX_ID or count > 1 << 20:
        raise ValueError('unsupported pack header')
    ident = data[PACK_HEADER:PACK_HEADER + id_length]
    if compiler_id is not None and ident != compiler_id:
        raise ValueError('pack from a different compiler')
    index = (PACK_HEADER + id_length + 7) & ~7
    end = index + count * INDEX_ENTRY
    if end > len(data):
        raise ValueError('index outside the pack')
    entries, previous = {}, None
    for i in range(count):
        e = index + i * INDEX_ENTRY
        key = data[e:e + 64]
        offset, length = struct.unpack_from('<QQ', data, e + 64)
        if previous is not None and key <= previous:
            raise ValueError('index not strictly sorted')
        if offset < end or offset + length > len(data):
            raise ValueError('record outside the pack')
        parse_record(data[offset:offset + length], key, ident)
        entries[key], previous = (offset, length), key
    return ident, entries


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest='command', required=True)
    b = sub.add_parser('build')
    b.add_argument('--records', type=Path, required=True, help='a namespace directory of .amse records')
    b.add_argument('--output', type=Path, required=True)
    b.add_argument('--compiler-id', help='require this compiler identity')
    v = sub.add_parser('verify')
    v.add_argument('pack', type=Path)
    v.add_argument('--compiler-id')
    args = ap.parse_args()
    want = args.compiler_id.encode() if args.compiler_id else None
    if args.command == 'build':
        if args.output.exists():
            sys.exit(f'{args.output} exists; refusing to overwrite')
        records, ident = {}, want
        for path in sorted(args.records.rglob('*.amse')):
            data = path.read_bytes()
            key, rid, _ = parse_record(data, path.stem.encode(), ident)
            if path.parent.name != path.stem[:2]:
                raise ValueError(f'{path}: not in its key directory')
            ident = rid
            records[key] = data
        if not records:
            sys.exit('no records')
        pack = build_pack(records, ident)
        read_pack(pack, ident)
        tmp = args.output.with_name(args.output.name + '.tmp')
        tmp.write_bytes(pack)
        os.replace(tmp, args.output)
        print(json.dumps(dict(status='PACKED', records=len(records), bytes=len(pack),
                              sha256=hashlib.sha256(pack).hexdigest(), compiler_id=ident.decode())))
    else:
        data = args.pack.read_bytes()
        ident, entries = read_pack(data, want)
        print(json.dumps(dict(status='VERIFIED', records=len(entries), bytes=len(data),
                              sha256=hashlib.sha256(data).hexdigest(), compiler_id=ident.decode())))


if __name__ == '__main__':
    main()

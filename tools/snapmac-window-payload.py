#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Full-install M5, Mac side: pack the main APFS container of the M1 image for the A16 window.

  python3 tools/snapmac-window-payload.py --image build/full-install/configured.img \\
      --manifest build/full-install/pristine-manifest.json --out /Volumes/EXTERNAL/snapintosh-m5

Reads the image's main container partition (GPT type 7C3457EF, from the M1 manifest) in 8 MiB
chunks. A chunk that is all zeros is not packed: the Windows writer (build/write-snapmac-window-
20260925.ps1) writes zeros for it, so the window gets every byte of the container, holes
included, while only non-zero data crosses the network. Non-zero chunks go into 2 GiB pack files
in order. manifest.json lists every packed chunk (index, pack, offset, SHA256) and the SHA256 of
the whole container byte range, which the writer checks on the SSD after writing.

Reads only the image; writes only --out (refuses a non-empty directory).
"""
import argparse
import hashlib
import json
import os
import sys

CHUNK = 8 << 20
PACK = 2 << 30
CONTAINER_TYPE = '7c3457ef-0000-11aa-aa11-00306543ecac'


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split('\n\n')[0])
    ap.add_argument('--image', required=True)
    ap.add_argument('--manifest', required=True, help='M1 manifest (gpt.partitions)')
    ap.add_argument('--out', required=True)
    args = ap.parse_args(argv)
    m1 = json.load(open(args.manifest))
    parts = [p for p in m1['gpt']['partitions'] if p['type'].lower() == CONTAINER_TYPE]
    if len(parts) != 1:
        raise SystemExit(f'expected one main container in the M1 manifest, found {len(parts)}')
    part = parts[0]
    base, size = part['offset'], part['bytes']
    if size % 4096 or base % 4096:
        raise SystemExit('container range is not 4 KiB aligned')
    if os.path.exists(args.out) and os.listdir(args.out):
        raise SystemExit(f'{args.out} is not empty; not mixing payloads')
    os.makedirs(args.out, exist_ok=True)
    whole = hashlib.sha256()
    chunks, packs = [], []
    pack = None
    zero = bytes(CHUNK)
    with open(args.image, 'rb') as img:
        img.seek(base)
        index = 0
        done = 0
        while done < size:
            n = min(CHUNK, size - done)
            data = img.read(n)
            if len(data) != n:
                raise SystemExit(f'short read at container byte {done}')
            whole.update(data)
            if data != zero[:n]:
                if pack is None or pack.tell() + n > PACK:
                    if pack:
                        pack.close()
                    name = f'pack{len(packs):03d}.bin'
                    packs.append(name)
                    pack = open(os.path.join(args.out, name), 'wb')
                chunks.append(dict(index=index, bytes=n, pack=packs[-1], offset=pack.tell(),
                                   sha256=hashlib.sha256(data).hexdigest()))
                pack.write(data)
            done += n
            index += 1
            if index % 512 == 0:
                print(f'{done >> 30} GiB scanned, {len(chunks)} chunks packed', file=sys.stderr, flush=True)
    if pack:
        pack.close()
    pack_info = []
    for name in packs:
        h = hashlib.sha256()
        with open(os.path.join(args.out, name), 'rb') as f:
            for block in iter(lambda: f.read(64 << 20), b''):
                h.update(block)
        pack_info.append(dict(name=name, bytes=os.path.getsize(os.path.join(args.out, name)), sha256=h.hexdigest()))
    manifest = dict(schema='snapintosh-window-container/1', image=os.path.abspath(args.image),
                    m1_manifest_sha256=m1.get('manifest_sha256_of_body_without_this_field'),
                    container=dict(guid=part['guid'], image_offset=base, bytes=size, sha256=whole.hexdigest()),
                    chunk_bytes=CHUNK, chunk_count=index, packed_chunks=len(chunks),
                    packed_bytes=sum(c['bytes'] for c in chunks), packs=pack_info, chunks=chunks)
    with open(os.path.join(args.out, 'manifest.json'), 'w') as f:
        json.dump(manifest, f, indent=0)
    print(json.dumps({k: manifest[k] for k in ('container', 'chunk_count', 'packed_chunks', 'packed_bytes')}, indent=1))


if __name__ == '__main__':
    main()

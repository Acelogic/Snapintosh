#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Full-install M5, Mac side: the window header and window.json for the Windows writer.

  python3 tools/snapmac-window-header.py --payload /Volumes/EXTERNAL/snapintosh-m5 \\
      --isc build/isc-xart-20260922.apfs --partition-guid ffea9120-5c2e-47ff-a459-3f645a59654e

The window is the partition M4 created (docs/FULL-INSTALL-DESIGN.md "The window"). Partition-
relative layout: the first MiB is the synthesized GPT's (served by the monitor, never read from
media) with this 4 KiB header at +512 KiB; the ISC region is 1 MiB..513 MiB; the container region
starts at 513 MiB; the last MiB is the synthesized backup GPT's.

Header (little-endian, 4096 bytes):
     0  magic "SNAPWIN1"            8  u32 version (1)          12  u32 header bytes (4096)
    16  partition unique GUID (16, GPT on-disk byte order)
    32  u64 first real LBA         40  u64 last real LBA (512-byte LBAs)
    48  u32 virtual block (4096)   52  u32 state (1 = provisioned, all data verified)
    56  u64 ISC offset             64  u64 ISC region bytes       72  u64 ISC image bytes
    80  u64 container offset       88  u64 container region bytes 96  u64 container image bytes
   104  ISC image SHA256          136  container image SHA256    168  payload manifest SHA256
   200  provisioned UTC (ASCII, NUL-padded, 32)
  4092  u32 CRC-32 of bytes 0..4091
Writes header.bin and window.json into --payload.
"""
import argparse
import datetime
import hashlib
import json
import os
import struct
import uuid
import zlib

MIB = 1 << 20
DISK = dict(unique_id='eui.002538F261C3C291', bytes=1024209543168, guid='{1c98f6ba-8bab-4cae-8c35-bf82870d8cf2}')
PART_TYPE = '{af494c0f-7849-4186-8d2c-9b05cf6ab8b8}'
PART_OFFSET, PART_SIZE = 599379673088, 422668402688
HEADER_OFF, ISC_OFF, ISC_REGION = 512 << 10, MIB, 512 * MIB
CON_OFF = ISC_OFF + ISC_REGION


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for block in iter(lambda: f.read(64 * MIB), b''):
            h.update(block)
    return h.hexdigest()


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split('\n\n')[0])
    ap.add_argument('--payload', required=True)
    ap.add_argument('--isc', required=True)
    ap.add_argument('--partition-guid', required=True)
    args = ap.parse_args(argv)
    manifest_path = os.path.join(args.payload, 'manifest.json')
    m = json.load(open(manifest_path))
    isc_bytes = os.path.getsize(args.isc)
    if isc_bytes > ISC_REGION or isc_bytes % 4096:
        raise SystemExit('ISC image does not fit its region')
    con_region = PART_SIZE - MIB - CON_OFF
    if m['container']['bytes'] > con_region:
        raise SystemExit('container does not fit its region')
    guid = uuid.UUID(args.partition_guid)
    isc_sha = sha256_file(args.isc)
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
    first = PART_OFFSET // 512
    last = (PART_OFFSET + PART_SIZE) // 512 - 1
    body = struct.pack('<8sII16sQQII6Q32s32s32s32s', b'SNAPWIN1', 1, 4096, guid.bytes_le, first, last, 4096, 1,
                       ISC_OFF, ISC_REGION, isc_bytes, CON_OFF, con_region, m['container']['bytes'],
                       bytes.fromhex(isc_sha), bytes.fromhex(m['container']['sha256']),
                       bytes.fromhex(sha256_file(manifest_path)), stamp.encode())
    header = body + bytes(4092 - len(body))
    header += struct.pack('<I', zlib.crc32(header))
    assert len(header) == 4096
    with open(os.path.join(args.payload, 'header.bin'), 'wb') as f:
        f.write(header)
    zero_tail = hashlib.sha256(bytes(ISC_REGION - isc_bytes)).hexdigest()
    window = dict(disk=DISK, partition=dict(guid='{' + str(guid) + '}', type=PART_TYPE, offset=PART_OFFSET, size=PART_SIZE),
                  layout=dict(header_offset=HEADER_OFF, isc_offset=ISC_OFF, isc_region=ISC_REGION, isc_image=isc_bytes,
                              container_offset=CON_OFF, container_region=con_region),
                  isc=dict(file=os.path.basename(args.isc), sha256=isc_sha, zero_tail_sha256=zero_tail),
                  header_sha256=hashlib.sha256(header).hexdigest(), provisioned_utc=stamp)
    with open(os.path.join(args.payload, 'window.json'), 'w') as f:
        json.dump(window, f, indent=1)
    print(json.dumps(window, indent=1))


if __name__ == '__main__':
    main()

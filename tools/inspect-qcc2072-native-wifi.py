#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Inventory native Wi-Fi dependencies offline; never access the A16.

Failure inventory and qualification limits: docs/GUEST-WIFI-20261019.md.
Only the new --output receipt is written. No build or runtime success is implied.
"""
import argparse
import hashlib
import json
from pathlib import Path
import plistlib
import re
import struct
import subprocess
import uuid


ROOT = Path(__file__).resolve().parents[1]
EXPECTED_KC = 'dc9019ae39187b36936c2c513b485e513f15cd966b5c887ac88ffd2925976c62'
EXPECTED_FIRMWARE = {
    'firmware-2.bin': '4c6a1be1f5bfad76319755ff76904abb21c4c7ece5293cc5f33a20b1f4c35254',
    'board-2.bin': '6880d8e6d51292f6bb5f855965b4c2d1bca3fa0d8a70e68bd693d1e73ff43bf1',
    'Notice.txt': '515bf4c9d620a87458e4447fe01a0e9bc384d1c3e0037cc4c3d2037b1ff25525',
}
CLASSES = ['IO80211Controller', 'IO80211InfraInterface', 'IO80211InfraProtocol',
           'IO80211SkywalkInterface', 'IO80211APIUserClient']


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def run(*args):
    return subprocess.run(args, check=True, capture_output=True, text=True).stdout


def commands(data, base=0):
    require(0 <= base <= len(data) - 32, 'truncated Mach-O header')
    magic, cpu, subtype, _, count, size, _, _ = struct.unpack_from('<8I', data, base)
    require(magic == 0xfeedfacf and cpu == 0x100000c and subtype & 255 == 2,
            'expected arm64e Mach-O')
    pos, end = base + 32, base + 32 + size
    require(end <= len(data) and count <= size // 8, 'invalid command table')
    for _ in range(count):
        require(pos + 8 <= end, 'truncated command')
        kind, length = struct.unpack_from('<II', data, pos)
        require(length >= 8 and length % 8 == 0 and pos + length <= end,
                'invalid command length')
        yield kind, data[pos:pos + length]
        pos += length
    require(pos == end, 'command count/size mismatch')


def guest_inventory(path):
    data = path.read_bytes()
    require(digest(data) == EXPECTED_KC, 'different guest KC: requalify this inspection')
    entries = {}
    for kind, command in commands(data):
        if kind != 0x80000035:
            continue
        require(len(command) >= 32, 'short fileset entry')
        _, offset, name_offset, _ = struct.unpack_from('<QQII', command, 8)
        require(32 <= name_offset < len(command), 'invalid fileset name offset')
        raw = command[name_offset:]
        require(b'\0' in raw, 'unterminated fileset name')
        name = raw.split(b'\0', 1)[0].decode('ascii')
        require(name not in entries, 'duplicate fileset entry')
        entries[name] = offset
    result = {}
    for name in ['IO80211Family', 'IOSkywalkFamily']:
        bundle = 'com.apple.iokit.' + name
        require(bundle in entries, 'missing guest dependency ' + bundle)
        values = []
        for kind, command in commands(data, entries[bundle]):
            if kind == 0x1b:
                require(len(command) == 24, 'invalid UUID command')
                values.append(str(uuid.UUID(bytes=command[8:24])).upper())
        require(len(values) == 1, 'missing or duplicate dependency UUID')
        result[name] = values[0]
    return {'path': str(path), 'sha256': digest(data), 'fileset_count': len(entries),
            'dependency_uuids': result}


def ies(data, magic=None):
    pos = 0
    if magic is not None:
        prefix = magic + b'\0'
        require(data.startswith(prefix), 'invalid firmware/board magic')
        pos = (len(prefix) + 3) & ~3
    require(pos <= len(data), 'truncated container')
    while pos < len(data):
        require(pos + 8 <= len(data), 'truncated IE header')
        kind, length = struct.unpack_from('<II', data, pos)
        start = pos + 8
        end = start + length
        next_pos = start + ((length + 3) & ~3)
        require(end <= len(data) and next_pos <= len(data), 'truncated IE payload/padding')
        yield kind, data[start:end]
        pos = next_pos


def firmware_inventory(directory):
    files, blobs = {}, {}
    for name, expected in EXPECTED_FIRMWARE.items():
        data = (directory / name).read_bytes()
        require(digest(data) == expected, 'different firmware input: ' + name)
        blobs[name] = data
        files[name] = {'bytes': len(data), 'sha256': digest(data)}
    parts = []
    for kind, body in ies(blobs['firmware-2.bin'], b'QCOM-ATH12K-FW'):
        parts.append({'id': kind, 'bytes': len(body), 'sha256': digest(body)})
    require(all(sum(p['id'] == n for p in parts) == 1 for n in [2, 3, 5]),
            'missing or duplicate AMSS/M3/AUX image')
    names = []
    for kind, body in ies(blobs['board-2.bin'], b'QCA-ATH12K-BOARD'):
        for subkind, payload in ies(body):
            if kind == 0 and subkind == 0:
                names.append(payload.rstrip(b'\0').decode('ascii'))
    require(bool(names), 'no board names found')
    exact_subsystem = [n for n in names if
        'subsystem-vendor=105b' in n.split(',') and 'subsystem-device=e14f' in n.split(',')]
    return {'directory': str(directory), 'files': files, 'firmware_ies': parts,
            'board_names': names, 'module_subsystem_matches': exact_subsystem,
            'board_qualified': False, 'live_qmi_identity_observed': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--kdk', type=Path,
                        default=Path('/Library/Developer/KDKs/KDK_27.0_26A428.kdk'))
    parser.add_argument('--firmware-dir', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    require(not args.output.exists(), 'receipt already exists')
    guest = guest_inventory(ROOT / 'downloads/extracted/j700ap/kernelcache.release.mac17p')
    families = {}
    for name, guest_uuid in guest['dependency_uuids'].items():
        bundle = args.kdk / 'System/Library/Extensions' / (name + '.kext')
        binary = bundle / 'Contents/MacOS' / name
        info = plistlib.loads((bundle / 'Contents/Info.plist').read_bytes())
        uuids = run('/usr/bin/xcrun', 'dwarfdump', '--uuid', str(binary))
        match = re.search(r'UUID: ([0-9A-F-]+) \(arm64e\)', uuids)
        require(match is not None and match[1] == guest_uuid, 'KDK/guest UUID mismatch')
        symbols = run('/usr/bin/xcrun', 'nm', '-arch', 'arm64e', str(binary)).splitlines()
        vtables = {c: [s.strip() for s in symbols if
                       s.endswith('__ZTV' + str(len(c)) + c) and ' U ' not in s]
                   for c in CLASSES} if name == 'IO80211Family' else {}
        require(not vtables or all(vtables.values()), 'missing native Wi-Fi class')
        families[name] = {'binary': str(binary), 'sha256': digest(binary.read_bytes()),
                          'bundle_id': info['CFBundleIdentifier'],
                          'version': info['CFBundleVersion'], 'arm64e_uuid': match[1],
                          'guest_uuid_matches': True, 'native_vtables': vtables}
    result = {'status': 'OFFLINE_INVENTORY_COMPLETE', 'hardware_access': False,
              'driver_built': False, 'native_wifi_runtime_qualified': False,
              'source_sha256': digest(Path(__file__).read_bytes()),
              'guest': guest, 'kdk': families,
              'firmware': firmware_inventory(args.firmware_dir.resolve()),
              'limitations': ['Private class layouts and PAC contracts not recovered.',
                              'MHI/QMI, DMA isolation and native Wi-Fi are not implemented.',
                              'No current device state was queried.']}
    with args.output.open('x') as stream:
        json.dump(result, stream, indent=2, sort_keys=True)
        stream.write('\n')
    print(json.dumps({'status': result['status'], 'receipt': str(args.output),
                      'sha256': digest(args.output.read_bytes()),
                      'exact_subsystem_board_entries': len(result['firmware']['module_subsystem_matches']),
                      'hardware_access': False}))


if __name__ == '__main__':
    main()

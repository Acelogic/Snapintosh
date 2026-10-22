#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Pull one board's firmware set out of a macOS restore IPSW.

A UniversalMac IPSW carries every Mac Apple ships, so "the kernelcache" is
ambiguous until a board is named. BuildManifest.plist is the authority on which
files belong together, and this reads it rather than guessing from filenames:
the board picks an identity, the identity names its kernelcache, SPTM, TXM,
device tree, iBoot and SEP, and those are what come out.

    tools/extract-firmware.py downloads/UniversalMac_27.0_26A428_Restore.ipsw j700ap

Each component is unwrapped from its IM4P container and decompressed if it was
compressed, so what lands on disk is the raw image a loader would place in DRAM.
"""
import argparse
import pathlib
import plistlib
import struct
import subprocess
import sys
import zipfile

# The parts a boot chain needs. Everything else in the identity is restore
# plumbing, cryptexes and trust caches.
WANTED = ['KernelCache', 'Ap,TrustedExecutionMonitor', 'DeviceTree', 'iBoot',
          'LLB', 'SEP', 'SepStage1', 'iBootData']

MH_MAGIC_64 = 0xFEEDFACF


def der(data: bytes, pos: int):
    """One DER element: returns (tag, body, next_position)."""
    tag = data[pos]
    length = data[pos + 1]
    pos += 2
    if length & 0x80:
        count = length & 0x7F
        length = int.from_bytes(data[pos:pos + count], 'big')
        pos += count
    return tag, data[pos:pos + length], pos + length


def im4p_payload(data: bytes) -> bytes:
    """The payload octet string out of an IM4P, or the input if it is not one.

    IM4P is SEQUENCE { IA5String "IM4P", IA5String type, IA5String description,
    OCTET STRING payload, ... }. Only the fourth element is wanted.
    """
    if len(data) < 2 or data[0] != 0x30:
        return data
    _, body, _ = der(data, 0)
    pos, elements = 0, []
    while pos < len(body) and len(elements) < 4:
        tag, value, pos = der(body, pos)
        elements.append((tag, value))
    if len(elements) < 4 or elements[0][1] != b'IM4P':
        return data
    return elements[3][1]


def decompress(payload: bytes, name: str) -> bytes:
    if payload[:4] == b'bvx2':
        proc = subprocess.run(['lzfse', '-decode'], input=payload, capture_output=True)
        if proc.returncode or not proc.stdout:
            raise SystemExit(f'{name}: lzfse failed: {proc.stderr.decode()[:200]}')
        return proc.stdout
    if payload[:8] == b'complzss':
        # Apple's LZSS header: magic, adler32, decompressed size, compressed size.
        _, _, size, _ = struct.unpack_from('>IIII', payload, 0)
        return lzss(payload[0x180:], size)
    return payload


def lzss(data: bytes, size: int) -> bytes:
    """Apple's variant of LZSS, as used by older kernelcaches."""
    window = bytearray(0x1000)
    out = bytearray()
    pos, cursor, flags = 0, 0xFEE, 0
    while len(out) < size and pos < len(data):
        flags >>= 1
        if not flags & 0x100:
            flags = data[pos] | 0xFF00
            pos += 1
        if flags & 1:
            byte = data[pos]
            pos += 1
            out.append(byte)
            window[cursor] = byte
            cursor = (cursor + 1) & 0xFFF
        else:
            low, high = data[pos], data[pos + 1]
            pos += 2
            offset = low | ((high & 0xF0) << 4)
            for n in range((high & 0x0F) + 3):
                byte = window[(offset + n) & 0xFFF]
                out.append(byte)
                window[cursor] = byte
                cursor = (cursor + 1) & 0xFFF
    return bytes(out)


def identify(blob: bytes) -> str:
    if len(blob) >= 4 and struct.unpack_from('<I', blob)[0] == MH_MAGIC_64:
        filetype = struct.unpack_from('<I', blob, 12)[0]
        return f'Mach-O (filetype {filetype})'
    if blob[:4] in (b'bvx2', b'bvx-'):
        return 'lzfse (undecompressed)'
    # An Apple device tree starts with a property count and a node count.
    if len(blob) >= 8 and struct.unpack_from('<I', blob)[1 if False else 0] < 64:
        return 'device tree (probably)'
    return 'raw'


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('ipsw')
    ap.add_argument('board', help='device class, e.g. j700ap')
    ap.add_argument('--out', default=None,
                    help='output directory (default downloads/extracted/<board>)')
    args = ap.parse_args()

    ipsw = pathlib.Path(args.ipsw)
    out = pathlib.Path(args.out) if args.out else \
        ipsw.parent / 'extracted' / args.board
    out.mkdir(parents=True, exist_ok=True)

    zf = zipfile.ZipFile(ipsw)
    manifest = plistlib.loads(zf.read('BuildManifest.plist'))
    identity = next((i for i in manifest['BuildIdentities']
                     if i.get('Info', {}).get('DeviceClass') == args.board
                     and i.get('Info', {}).get('RestoreBehavior') == 'Erase'), None)
    if identity is None:
        classes = sorted({i.get('Info', {}).get('DeviceClass', '?')
                          for i in manifest['BuildIdentities']})
        raise SystemExit(f'no Erase identity for {args.board}. Boards: {" ".join(classes)}')

    chip = identity.get('ApChipID', '?')
    print(f'{args.board}: ApChipID {chip}, ApBoardID {identity.get("ApBoardID", "?")}, '
          f'build {manifest.get("ProductBuildVersion", "?")}')

    # SPTM is named per SoC and is not always listed in the identity's manifest,
    # so it is resolved from the chip ID against what the IPSW actually carries.
    soc = f't{int(str(chip), 16):x}' if str(chip).startswith('0x') else None
    names = zf.namelist()
    extra = {}
    if soc:
        for entry in names:
            if entry.endswith(f'sptm.{soc}.release.im4p'):
                extra['SPTM'] = entry
            if entry.endswith(f'exclavecore_bundle.{soc}.RELEASE.im4p'):
                extra['ExclaveCore'] = entry

    todo = {}
    for key in WANTED:
        path = identity['Manifest'].get(key, {}).get('Info', {}).get('Path')
        if path:
            todo[key] = path
    todo.update(extra)

    for key, path in todo.items():
        if path not in names:
            print(f'  {key:<28} MISSING ({path})')
            continue
        raw = im4p_payload(zf.read(path))
        blob = decompress(raw, key)
        name = pathlib.Path(path).name
        if name.endswith('.im4p'):
            name = name[:-len('.im4p')]
        target = out / name
        target.write_bytes(blob)
        print(f'  {key:<28} {target.name:<34} {len(blob):>12,}  {identify(blob)}')

    print(f'\n{len(todo)} components in {out}')
    return 0


if __name__ == '__main__':
    sys.exit(main())

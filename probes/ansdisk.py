# SPDX-License-Identifier: MIT
"""The virtual ANS2 test disk: a 4096-byte-LBA GPT around one APFS container.

Apple's ANS namespaces use 4 KiB LBAs (the model's Identify says LBADS 12),
so the GPT is laid out in 4 KiB blocks: protective MBR in LBA 0, the header
in LBA 1, the 128 x 128-byte array in LBAs 2..5, the backup array and header
in the last five blocks. The container itself is built on the Mac with
Apple's own tools (build/build-ans-test-disk-20260925.py) and never edited
here. Every byte outside it is generated, so no earlier content survives.
"""
import hashlib
import struct
import uuid
import zlib

from bootmedia import APFS_TYPE

BLOCK = 4096
DISK_BYTES = 64 << 20
ALIGN = 1 << 20
ENTRIES = 128
ENTRY_BYTES = 128
TABLE_BLOCKS = ENTRIES * ENTRY_BYTES // BLOCK        # 4
FIRST_USABLE = 2 + TABLE_BLOCKS                      # 6
NAME = 'Snapintosh ANS2 test'


def _identity(name):
    return uuid.uuid5(uuid.NAMESPACE_URL, 'snapintosh://ans2-m2/' + name).bytes_le


def layout(disk_bytes=DISK_BYTES):
    if disk_bytes < 4 * ALIGN or disk_bytes % ALIGN or disk_bytes > 1 << 30:
        raise ValueError('ANS test disk must be 4 MiB..1 GiB and 1 MiB aligned')
    blocks = disk_bytes // BLOCK
    last_usable = blocks - 2 - TABLE_BLOCKS
    offset = ALIGN
    size = disk_bytes - 2 * ALIGN
    return dict(bytes=disk_bytes, blocks=blocks, last_usable=last_usable,
                container=(offset, size))


def _header(current, other, entries_lba, blocks, entries_crc):
    header = bytearray(BLOCK)
    struct.pack_into('<8sIIIIQQQQ16sQIII', header, 0, b'EFI PART', 0x10000, 92, 0, 0,
                     current, other, FIRST_USABLE, blocks - 2 - TABLE_BLOCKS,
                     _identity('disk'), entries_lba, ENTRIES, ENTRY_BYTES, entries_crc)
    struct.pack_into('<I', header, 16, zlib.crc32(header[:92]))
    return bytes(header)


def _mbr(blocks):
    mbr = bytearray(BLOCK)
    struct.pack_into('<B3sB3sII', mbr, 446, 0, b'\x00\x02\x00', 0xee, b'\xff\xff\xff',
                     1, min(blocks - 1, 0xffffffff))
    mbr[510:512] = b'\x55\xaa'
    return bytes(mbr)


def _entries(desc):
    offset, size = desc['container']
    entries = bytearray(ENTRIES * ENTRY_BYTES)
    struct.pack_into('<16s16sQQQ72s', entries, 0, APFS_TYPE.bytes_le, _identity('container'),
                     offset // BLOCK, (offset + size) // BLOCK - 1, 0, NAME.encode('utf-16le'))
    return bytes(entries)


def container_blocks(container):
    """APFS nx_superblock: magic 'NXSB' at +32, block size +36, block count +40."""
    if len(container) < BLOCK or container[32:36] != b'NXSB':
        raise ValueError('container does not start with an APFS superblock')
    block_size, count = struct.unpack_from('<IQ', container, 36)
    if block_size != BLOCK or count * BLOCK != len(container):
        raise ValueError('APFS container geometry differs from its partition')
    return count


def assemble(container, disk_bytes=DISK_BYTES):
    desc = layout(disk_bytes)
    offset, size = desc['container']
    if len(container) != size:
        raise ValueError(f'container is {len(container)} bytes, the partition {size}')
    container_blocks(container)
    blocks = desc['blocks']
    entries = _entries(desc)
    crc = zlib.crc32(entries)
    image = bytearray(disk_bytes)
    image[0:BLOCK] = _mbr(blocks)
    image[BLOCK:2 * BLOCK] = _header(1, blocks - 1, 2, blocks, crc)
    image[2 * BLOCK:2 * BLOCK + len(entries)] = entries
    image[offset:offset + size] = container
    backup = blocks - 1 - TABLE_BLOCKS
    image[backup * BLOCK:(backup + TABLE_BLOCKS) * BLOCK] = entries
    image[(blocks - 1) * BLOCK:] = _header(blocks - 1, 1, backup, blocks, crc)
    return bytes(image)


def inspect(image):
    """Validate the whole disk: both GPT copies, the one entry, the container.

    Returns the layout with the container's sha256. Geometry and metadata
    only; it does not certify the filesystem inside."""
    desc = layout(len(image))
    blocks = desc['blocks']
    expected = _entries(desc)
    crc = zlib.crc32(expected)
    backup = blocks - 1 - TABLE_BLOCKS
    offset, size = desc['container']
    if image[:BLOCK] != _mbr(blocks):
        raise ValueError('invalid protective MBR')
    for here, other, table in ((1, blocks - 1, 2), (blocks - 1, 1, backup)):
        if image[here * BLOCK:(here + 1) * BLOCK] != _header(here, other, table, blocks, crc):
            raise ValueError('GPT header or CRC mismatch')
        if image[table * BLOCK:(table + TABLE_BLOCKS) * BLOCK] != expected:
            raise ValueError('GPT partition array differs')
    for low, high in ((2 * BLOCK + len(expected), offset), (offset + size, backup * BLOCK)):
        if any(image[low:high]):
            raise ValueError('GPT gap is not zero')
    container_blocks(image[offset:offset + size])
    desc['container_sha256'] = hashlib.sha256(image[offset:offset + size]).hexdigest()
    desc['sha256'] = hashlib.sha256(image).hexdigest()
    return desc

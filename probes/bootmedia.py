# SPDX-License-Identifier: MIT
"""GPT transport for an unchanged authenticated root and a separate ISC image.

Only the surrounding disk layout is generated here. Neither APFS payload is
modified. XNU still discovers the partitions, validates the root and mounts
volumes using its own storage stack.
"""
import struct
import uuid
import zlib

SECTOR = 512
ALIGN = 1 << 20
TABLE_BYTES = 128 * 128
APFS_TYPE = uuid.UUID('7C3457EF-0000-11AA-AA11-00306543ECAC')
ISC_TYPE = uuid.UUID('69646961-6700-11AA-AA11-00306543ECAC')


def layout(root_size, isc_size):
    if any(n < 0x4000 or n % 0x4000 for n in (root_size, isc_size)):
        raise ValueError('GPT APFS payloads must be nonempty and 16 KiB aligned')
    root_offset = ALIGN
    isc_offset = (root_offset + root_size + ALIGN - 1) & -ALIGN
    size = (isc_offset + isc_size + TABLE_BYTES + SECTOR + ALIGN - 1) & -ALIGN
    return dict(bytes=size, root=(root_offset, root_size), isc=(isc_offset, isc_size))


def _identity(name):
    return uuid.uuid5(uuid.NAMESPACE_URL, 'snapintosh://ram-boot/' + name).bytes_le


def _header(current, other, entries_lba, sectors, entries_crc):
    header = bytearray(SECTOR)
    struct.pack_into('<8sIIIIQQQQ16sQIII', header, 0, b'EFI PART', 0x10000,
                     92, 0, 0, current, other, 34, sectors - 34,
                     _identity('disk'), entries_lba, 128, 128, entries_crc)
    struct.pack_into('<I', header, 16, zlib.crc32(header[:92]))
    return header


def assemble(root, isc, base, end):
    """Return contiguous initialized chunks and their media/subimage ranges.

    Separate payload chunks let the existing EFI preload copy the stock root
    locally even though it now begins at a partition offset in the RAM disk.
    Gaps are explicitly zeroed, never exposed from an earlier guest run.
    """
    desc = layout(len(root), len(isc))
    if base < 0 or base % 0x4000 or end > 1 << 36 or desc['bytes'] + (128 << 20) > end - base:
        raise ValueError('GPT RAM disk placement leaves insufficient allocator memory')
    entries = bytearray(TABLE_BYTES)
    for i, (name, kind) in enumerate((('root', APFS_TYPE), ('isc', ISC_TYPE))):
        offset, size = desc[name]
        struct.pack_into('<16s16sQQQ72s', entries, i * 128, kind.bytes_le,
                         _identity(name), offset // SECTOR,
                         (offset + size) // SECTOR - 1, 0,
                         ('Snapintosh ' + name).encode('utf-16le'))
    sectors = desc['bytes'] // SECTOR
    crc = zlib.crc32(entries)
    prefix = bytearray(ALIGN)
    struct.pack_into('<B3sB3sII', prefix, 446, 0, b'\x00\x02\x00',
                     0xee, b'\xff\xff\xff', 1, min(sectors - 1, 0xffffffff))
    prefix[510:512] = b'\x55\xaa'
    prefix[SECTOR:2 * SECTOR] = _header(1, sectors - 1, 2, sectors, crc)
    prefix[2 * SECTOR:2 * SECTOR + TABLE_BYTES] = entries
    root_offset, root_size = desc['root']
    isc_offset, isc_size = desc['isc']
    tail_offset = isc_offset + isc_size
    tail = bytearray(desc['bytes'] - tail_offset)
    tail[-SECTOR - TABLE_BYTES:-SECTOR] = entries
    tail[-SECTOR:] = _header(sectors - 1, 1, sectors - 33, sectors, crc)
    chunks = {base: prefix, base + root_offset: root,
              base + isc_offset: isc, base + tail_offset: tail}
    gap = isc_offset - root_offset - root_size
    if gap:
        chunks[base + root_offset + root_size] = bytes(gap)
    return chunks, desc


def inspect(read, size):
    """Validate both GPT copies through a bounded relative-offset reader.

    This audits geometry and metadata only; it does not certify filesystem
    contents, root authentication, or successful native volume discovery.
    """
    if size < 3 * ALIGN or size % 0x4000:
        raise ValueError('invalid GPT media size')
    sectors = size // SECTOR
    mbr = read(0, SECTOR)
    expected_mbr = bytearray(SECTOR)
    struct.pack_into('<B3sB3sII', expected_mbr, 446, 0, b'\x00\x02\x00',
                     0xee, b'\xff\xff\xff', 1, min(sectors - 1, 0xffffffff))
    expected_mbr[510:512] = b'\x55\xaa'
    if mbr != expected_mbr:
        raise ValueError('invalid protective MBR')
    entries = read(2 * SECTOR, TABLE_BYTES)
    if len(entries) != TABLE_BYTES or any(entries[256:]):
        raise ValueError('expected exactly two GPT entries')
    crc = zlib.crc32(entries)
    for here, other, table in ((1, sectors - 1, 2), (sectors - 1, 1, sectors - 33)):
        if read(here * SECTOR, SECTOR) != _header(here, other, table, sectors, crc):
            raise ValueError('GPT header or CRC mismatch')
        if read(table * SECTOR, TABLE_BYTES) != entries:
            raise ValueError('GPT partition arrays differ')
    desc = dict(bytes=size)
    for i, (name, kind) in enumerate((('root', APFS_TYPE), ('isc', ISC_TYPE))):
        typ, identity, first, last, flags, label = struct.unpack_from('<16s16sQQQ72s', entries, i * 128)
        if (typ != kind.bytes_le or identity != _identity(name) or flags or
                first > last or first < 34 or last > sectors - 34 or
                label != ('Snapintosh ' + name).encode('utf-16le').ljust(72, b'\0')):
            raise ValueError('GPT partition identity or bounds mismatch')
        desc[name] = (first * SECTOR, (last - first + 1) * SECTOR)
    if desc != layout(desc['root'][1], desc['isc'][1]):
        raise ValueError('GPT partitions overlap or differ from the reserved layout')
    return desc


def upload_auxiliary(proxy, base, payload):
    """Initialize sparse scratch media locally, then transfer nonzero blocks.

    Every byte is written: an old guest's bytes must not survive in free space.
    Bounded zero operations use the same proxy memory API as the EFI copy.
    """
    size = len(payload)
    if base < 0 or base % 0x4000 or size < 0x4000 or size % 0x4000 or base + size > 1 << 36:
        raise ValueError('invalid auxiliary upload range')
    for offset in range(0, size, 8 << 20):
        proxy.memset8(base + offset, 0, min(8 << 20, size - offset))
    sent = 0
    for offset in range(0, size, 64 << 10):
        block = payload[offset:offset + (64 << 10)]
        if block != bytes(len(block)):
            proxy.writemem(base + offset, block)
            sent += len(block)
    return sent

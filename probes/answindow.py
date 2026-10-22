# SPDX-License-Identifier: MIT
"""The virtual ANS2's window mode (full-install M6): what the guest sees instead of the RAM disk.

The disk is the M4 partition on the A16's SSD (the window, docs/FULL-INSTALL-DESIGN.md "The
window"), presented in 4096-byte blocks: virtual block v is real 512-byte LBA first + 8 * v. The
first and last MiB are the synthesized GPT, served from the reservation (compat/ans.h
ANS_WINDOW_HEAD/TAIL) and never read from media:

  block 0            protective MBR
  block 1            GPT header; blocks 2..5 the 128 x 128-byte array
  blocks 256..131327 the ISC (the qualified xART fixture M5 wrote at +1 MiB)
  131328..end - 257  the main APFS container (configured.img's, written at +513 MiB)
  the last 5 blocks  the backup array and header

Disk and partition GUIDs are configured.img's (the M1 manifest), so the installed system sees the
identities it was created with. The window header M5 wrote at +512 KiB is inside the head, so the
guest can never address it.

nvmeh_params() turns q1n1's adopt record (tools/nvme_m3.py --adopt-dma) into the monitor's
struct nvmeh_params (compat/nvme-host.h).
"""
import struct
import uuid
import zlib

BLOCK = 4096
ENTRIES, ENTRY_BYTES = 128, 128
TABLE_BLOCKS = ENTRIES * ENTRY_BYTES // BLOCK        # 4
FIRST_USABLE = 2 + TABLE_BLOCKS                      # 6
EDGE_BLOCKS = 256                                    # compat/ans.h ANS_WINDOW_EDGE_BLOCKS
ISC_TYPE = uuid.UUID('69646961-6700-11aa-aa11-00306543ecac')
CONTAINER_TYPE = uuid.UUID('7c3457ef-0000-11aa-aa11-00306543ecac')

# compat/ans.h window layout, relative to the reservation
WINDOW_MODE = 1
WINDOW_HEAD = 0x34000
WINDOW_TAIL = 0x134000
WINDOW_NVMEH = 0x234000
WINDOW_DMA = 0x300000
WINDOW_STAGE = 0x400000
WINDOW_BYTES = 0x500000
# compat/nvme-host.h
NVMEH_F_ENABLE = 1
NVMEH_F_WRITE = 2
NVMEH_PARAMS_WORDS = 16
NVMEH_STATE_FIELDS = ('status', 'prepare', 'tail', 'head', 'phase', 'next_cid',
    'reads', 'read_bytes', 'errors', 'timeouts', 'refused', 'last_status',
    'last_lba', 'max_ticks', 'total_ticks', 'csts', 'writes', 'write_bytes',
    'flushes', 'last_opcode')


def layout(window_bytes, isc_offset, isc_region, container_offset):
    if window_bytes % (1 << 20) or window_bytes < 1 << 30:
        raise ValueError('window must be a whole number of MiB and at least 1 GiB')
    if (isc_offset, container_offset) != (EDGE_BLOCKS * BLOCK, EDGE_BLOCKS * BLOCK + isc_region):
        raise ValueError('ISC and container regions are not where the design puts them')
    blocks = window_bytes // BLOCK
    return dict(bytes=window_bytes, blocks=blocks, last_usable=blocks - 2 - TABLE_BLOCKS,
                isc=(isc_offset // BLOCK, (isc_offset + isc_region) // BLOCK - 1),
                container=(container_offset // BLOCK, blocks - EDGE_BLOCKS - 1))


def _header(disk_guid, current, other, entries_lba, blocks, entries_crc):
    header = bytearray(BLOCK)
    struct.pack_into('<8sIIIIQQQQ16sQIII', header, 0, b'EFI PART', 0x10000, 92, 0, 0,
                     current, other, FIRST_USABLE, blocks - 2 - TABLE_BLOCKS,
                     disk_guid.bytes_le, entries_lba, ENTRIES, ENTRY_BYTES, entries_crc)
    struct.pack_into('<I', header, 16, zlib.crc32(header[:92]))
    return bytes(header)


def _mbr(blocks):
    mbr = bytearray(BLOCK)
    struct.pack_into('<B3sB3sII', mbr, 446, 0, b'\x00\x02\x00', 0xee, b'\xff\xff\xff',
                     1, min(blocks - 1, 0xffffffff))
    mbr[510:512] = b'\x55\xaa'
    return bytes(mbr)


def overlays(desc, disk_guid, isc_guid, container_guid):
    """(head, tail): the first and last EDGE_BLOCKS blocks of the virtual disk."""
    blocks = desc['blocks']
    entries = bytearray(ENTRIES * ENTRY_BYTES)
    for i, (t, g, (first, last), name) in enumerate((
            (ISC_TYPE, isc_guid, desc['isc'], 'iBootSystemContainer'),
            (CONTAINER_TYPE, container_guid, desc['container'], 'Container'))):
        struct.pack_into('<16s16sQQQ72s', entries, i * ENTRY_BYTES, t.bytes_le, g.bytes_le, first, last, 0,
                         name.encode('utf-16le'))
    crc = zlib.crc32(entries)
    head = bytearray(EDGE_BLOCKS * BLOCK)
    head[0:BLOCK] = _mbr(blocks)
    head[BLOCK:2 * BLOCK] = _header(disk_guid, 1, blocks - 1, 2, blocks, crc)
    head[2 * BLOCK:2 * BLOCK + len(entries)] = entries
    tail = bytearray(EDGE_BLOCKS * BLOCK)
    backup = blocks - 1 - TABLE_BLOCKS
    at = (backup - (blocks - EDGE_BLOCKS)) * BLOCK
    tail[at:at + len(entries)] = entries
    tail[-BLOCK:] = _header(disk_guid, blocks - 1, 1, backup, blocks, crc)
    if desc['container'][1] > desc['last_usable']:
        raise ValueError('container region runs into the backup GPT')
    return bytes(head), bytes(tail)


def nvmeh_params(record, reservation, timer_hz, timeout_s=5.0, *, writable=False):
    """struct nvmeh_params from q1n1's adopt record, checked against the reservation."""
    a = record['adopt']
    dma = int(a['dma_base'], 16)
    if dma != reservation + WINDOW_DMA:
        raise ValueError(f'the SSD queues are at {dma:#x}, not in this reservation ({reservation + WINDOW_DMA:#x})')
    lay = a['layout']
    want = dict(name='adopt', bytes=0x100000, asq=0, acq=0x1000, iosq=0x2000, iocq=0x3000, prp=0x8000,
                data=0x10000, admin_entries=32, io_entries=64)
    if any(lay.get(k) != v for k, v in want.items()):
        raise ValueError('the adopt record layout differs from compat/nvme-host.h')
    if not a.get('left_running') or record.get('stopped') or record.get('exit_code'):
        raise ValueError('the adopt record is not a clean hand-off')
    w = a['window']
    first, last = w['first_lba'], w['last_lba']
    edge_lbas = EDGE_BLOCKS * BLOCK // 512
    if a['lba_bytes'] != 512 or first < 0 or last <= first + 2 * edge_lbas:
        raise ValueError('invalid physical window or LBA size')
    words = [NVMEH_F_ENABLE | (NVMEH_F_WRITE if writable else 0), int(a['bar'], 16), a['stride'], dma,
             a['io']['tail'], a['io']['head'], a['io']['phase'], a['io']['next_cid'],
             a['lba_bytes'], first, last, min(a['max_transfer'], 128 << 10),
             int(timeout_s * timer_hz), first + edge_lbas if writable else 0,
             last - edge_lbas if writable else 0, 0]
    assert len(words) == NVMEH_PARAMS_WORDS
    return struct.pack(f'<{NVMEH_PARAMS_WORDS}Q', *words)


def decode_nvmeh(raw):
    """Live window parameters plus physical-controller state, separate from ANS I/O."""
    if len(raw) != 8 * (NVMEH_PARAMS_WORDS + len(NVMEH_STATE_FIELDS)):
        raise ValueError('wrong physical NVMe capture size')
    p = struct.unpack_from('<16Q', raw)
    s = dict(zip(NVMEH_STATE_FIELDS, struct.unpack_from('<20Q', raw, 0x80)))
    return dict(flags=p[0], writable=bool(p[0] & NVMEH_F_WRITE),
        first_lba=p[9], last_lba=p[10], write_first_lba=p[13], write_last_lba=p[14],
        dma_base=hex(p[3]), params_hex=raw[:0x80].hex(), state=s)

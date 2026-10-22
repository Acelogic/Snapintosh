# SPDX-License-Identifier: MIT
"""Bounded read-only copy of the pinned native kernel's circular message log."""
import struct

WITNESSES = (
    (0xfffffe000bf02f8c, 0xb0003eb9),  # msgbufp page
    (0xfffffe000bf02f90, 0xf9408b28),  # msgbufp slot
    (0xfffffe000bf02f94, 0xb9400518),  # size
    (0xfffffe000bf02fe0, 0xf940092b),  # character buffer
    (0xfffffe000bf02fe4, 0xb980092c),  # write position
)
SLOT = 0xfffffe000c6d7110


def collect(read, instruction):
    for address, word in WITNESSES:
        if instruction(address) != word:
            raise ValueError(f'kernel message witness differs at {address:#x}')
    obj, = struct.unpack('<Q', read(SLOT, 8))
    obj |= 0xffff000000000000
    raw_header = read(obj, 24)
    magic, size, write_pos, read_pos, storage = struct.unpack('<4IQ', raw_header)
    if magic != 0x063061 or not 1 <= size <= 1 << 20 or not 0 <= read_pos < size or not 0 <= write_pos < size:
        raise ValueError('invalid native message buffer geometry')
    storage |= 0xffff000000000000
    raw = b''.join(read(storage+i, min(0x4000, size-i)) for i in range(0, size, 0x4000))
    if read(obj, 24) != raw_header:
        raise ValueError('native message buffer changed during stopped capture')
    text = (raw[write_pos:] + raw[:write_pos]).replace(b'\0', b'').decode('utf-8', errors='replace')
    return dict(object=hex(obj), storage=hex(storage), size=size,
                write_pos=write_pos, read_pos=read_pos, text=text,
                boundary='Circular retained log; earlier messages may have been overwritten')

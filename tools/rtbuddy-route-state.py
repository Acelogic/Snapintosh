# SPDX-License-Identifier: MIT
"""Read a stopped, witnessed RTBuddy route wait from the 26A428 kernel.

The matching dictionary address is recorded, not decoded. The route bytes come
from the native OSData retained in the caller's saved x21, independently of DT.
"""
import struct


RETURN_PC = 0xfffffe000b32a7d0
WITNESSES = (
    # OSData cast result, data accessor, four-byte record and matching argument.
    (0xfffffe000b32a680, 0xaa0003f5),
    (0xfffffe000b32a770, 0x8b180808),
    (0xfffffe000b32a778, 0x52800081),
    (0xfffffe000b32a79c, 0xaa0003fc),
    (0xfffffe000b32a7c4, 0xaa1c03e0),
    (0xfffffe000b32a7c8, 0x92800001),
    (0xfffffe000b32a7cc, 0x94009f07),
    # waitForMatchingService tail-calls the helper whose saved registers we read.
    (0xfffffe000c0f119c, 0xd503245f),
    (0xfffffe000c0f11a0, 0xd2800002),
    (0xfffffe000c0f11a4, 0x17ffc1a0),
    (0xfffffe000c0e1828, 0xd10203ff),
    (0xfffffe000c0e182c, 0xa9026ffc),
    (0xfffffe000c0e1830, 0xa90367fa),
    (0xfffffe000c0e1834, 0xa9045ff8),
    (0xfffffe000c0e1838, 0xa90557f6),
    (0xfffffe000c0e183c, 0xa9064ff4),
    (0xfffffe000c0e1840, 0xa9077bfd),
    (0xfffffe000c0e1844, 0x9101c3fd),
    # Native OSData length and backing pointer fields.
    (0xfffffe000c04efa4, 0xb9400c08),
    (0xfffffe000c04efac, 0xf8418c10),
    (0xfffffe000c04f234, 0xb9400c00),
)


def collect(threads, va_read, native_word):
    for va, word in WITNESSES:
        if native_word(va) != word:
            raise ValueError(f'RTBuddy route witness differs at {va:x}')

    def pointer(value):
        return value | 0xffff000000000000 if value else 0

    result = []
    for thread in threads:
        for frame in thread.get('frames', []):
            if pointer(int(frame['raw_lr'], 16)) != RETURN_PC:
                continue
            fp = int(frame['fp'], 16)
            stack = pointer(int(thread['kernel_stack'], 16))
            if fp & 15 or not stack <= fp-0x50 < fp+16 <= stack+0x4000:
                raise ValueError('RTBuddy saved registers outside bounded stack')
            saved = struct.unpack('<10Q', va_read(fp-0x50, 0x50))
            matching, index, data, service = (
                pointer(saved[0]), saved[4], pointer(saved[7]), pointer(saved[9]))
            if not data or not matching or not service:
                raise ValueError('RTBuddy route wait has a null retained object')
            length, = struct.unpack('<I', va_read(data+0xc, 4))
            if not 4 <= length <= 256 or length % 4 or index >= length//4:
                raise ValueError('RTBuddy route array length or index outside bounds')
            storage, = struct.unpack('<Q', va_read(data+0x18, 8))
            storage = pointer(storage)
            if not storage:
                raise ValueError('RTBuddy route array has null backing storage')
            payload = va_read(storage+4*index, 4)
            route, = struct.unpack('<I', payload)
            result.append(dict(tid=thread['tid'], name=thread.get('name'),
                frame=hex(fp), service=hex(service), matching_dictionary=hex(matching),
                routes_object=hex(data), routes_length=length, route_index=index,
                route_storage=hex(storage+4*index), route_bytes=payload.hex(),
                route_value=route, deadline='infinite',
                boundary='Native saved route bytes; provider registration not inferred'))
    return result

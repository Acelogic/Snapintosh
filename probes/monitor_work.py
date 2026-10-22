# SPDX-License-Identifier: MIT
"""Bounded monitor storage outside the guest and q1n1's reserved allocations."""
import hashlib
import struct

WORK_PAGES = 61440
WORK_SIZE = WORK_PAGES << 12
LOCATOR_OFFSET = 0x500000
LOCATOR_MAGIC = 0x314b524f57504e53
LOCATOR_VERSION = 1
LOCATOR_SIZE = 80
IPA_LIMIT = 1 << 36
# gpu_arena_*: q1n1's Adreno arena (gpu-el2.h). The GPU and GMU may DMA into it
# at any time, so no guest or monitor placement may ever include it, whether or
# not the profile adopts the GPU (Stage 4, probes/adreno.py).
RESERVED_FIELDS = (('image_base', 'image_size'), ('heap_base', 'heap_size'),
                   ('dma_base', 'dma_size'), ('stage_base', 'stage_size'),
                   ('fb_base', 'fb_size'), ('gpu_arena_base', 'gpu_arena_size'))


def reserved(info):
    return [(info[b], info[b] + info[s]) for b, s in RESERVED_FIELDS
            if info.get(b) and info.get(s)]


def free_spans(blob, stride, info):
    if stride < 40 or len(blob) % stride:
        raise ValueError('invalid firmware memory-map geometry')
    spans = []
    for off in range(0, len(blob), stride):
        kind, _, base, _, pages, _ = struct.unpack_from('<IIQQQQ', blob, off)
        if kind == 7 and pages:
            end = base + pages * 4096
            if base & 4095 or end > 1 << 64:
                raise ValueError('invalid conventional-memory range')
            spans.append((base, end))
    for low, high in reserved(info):
        remaining = []
        for begin, end in spans:
            if high <= begin or low >= end:
                remaining.append((begin, end))
            else:
                if begin < low:
                    remaining.append((begin, low))
                if high < end:
                    remaining.append((high, end))
        spans = remaining
    return spans


def locator_address(info):
    if info['heap_base'] & 4095 or info['heap_size'] < LOCATOR_OFFSET + LOCATOR_SIZE:
        raise ValueError('q1n1 heap cannot hold the monitor work locator')
    return info['heap_base'] + LOCATOR_OFFSET


def validate_region(base, size, guest_low, guest_high, info, free):
    if (not 0 < base or base & 65535 or size != WORK_SIZE or
            not 0 < guest_low < guest_high <= IPA_LIMIT or
            (guest_low | guest_high) & 4095 or base + size > IPA_LIMIT):
        raise ValueError('invalid monitor work-region geometry')
    for low, high in reserved(info) + [(guest_low, guest_high)]:
        if base < high and low < base + size:
            raise ValueError('monitor work region overlaps guest or q1n1 storage')
    if not any(low <= base < base + size <= high for low, high in free):
        raise ValueError('monitor work region is not firmware-reported free memory')


def validate_ans(base, size, work, work_size, info, free):
    """The virtual ANS2 reservation (xnuboot.ans_reservation): directly above
    the work arena, in firmware-free memory, clear of q1n1's allocations.
    The guest and the arena are below it by construction; this checks it."""
    aligned = (work + work_size + (1 << 20) - 1) & ~((1 << 20) - 1)   # the SSD window's 1 MiB alignment
    if (work <= 0 or work_size != WORK_SIZE or base not in (work + work_size, aligned) or
            base & 65535 or not 0 < size <= (1 << 30) + (1 << 20) or size & 65535 or
            base + size > IPA_LIMIT):
        raise ValueError('invalid virtual ANS2 reservation geometry')
    for low, high in reserved(info):
        if base < high and low < base + size:
            raise ValueError('virtual ANS2 reservation overlaps q1n1 storage')
    if not any(low <= base < base + size <= high for low, high in free):
        raise ValueError('virtual ANS2 reservation is not firmware-reported free memory')


def validate_gpu_pool(base, size, previous_end, info, free):
    """The wide GPU table reservation (xnuboot.gpu_pool_reservation, agents/gpu-va-wide V5): the next 64 KiB
    boundary after the monitor's last reservation, exactly adreno.pool_reservation_bytes(), in firmware-free
    memory, clear of q1n1's allocations (the Adreno arena among them). The guest, the work arena and the ANS2
    reservation are below it by construction; this checks it."""
    import adreno
    if (previous_end <= 0 or base != (previous_end + 65535) & ~65535 or size != adreno.pool_reservation_bytes() or
            base + size > IPA_LIMIT):
        raise ValueError('invalid GPU table reservation geometry')
    for low, high in reserved(info):
        if base < high and low < base + size:
            raise ValueError('GPU table reservation overlaps q1n1 storage')
    if not any(low <= base < base + size <= high for low, high in free):
        raise ValueError('GPU table reservation is not firmware-reported free memory')


def encode_locator(base, size, guest_low, guest_high, info, free):
    locator_address(info)
    validate_region(base, size, guest_low, guest_high, info, free)
    payload = struct.pack('<9Q', LOCATOR_MAGIC, LOCATOR_VERSION, base, size,
                          info['heap_base'], info['image_base'],
                          info['stage_generation'], guest_low, guest_high)
    return payload + hashlib.sha256(payload).digest()[:8]


def decode_locator(data, info, free):
    if len(data) != LOCATOR_SIZE or hashlib.sha256(data[:72]).digest()[:8] != data[72:]:
        raise ValueError('monitor work locator missing or checksum mismatch')
    magic, version, base, size, heap, image, generation, low, high = struct.unpack('<9Q', data[:72])
    if (magic != LOCATOR_MAGIC or version != LOCATOR_VERSION or
            (heap, image, generation) != (info['heap_base'], info['image_base'], info['stage_generation'])):
        raise ValueError('monitor work locator differs from the resident q1n1 boot')
    validate_region(base, size, low, high, info, free)
    return base, size


def firmware_free(proxy, info):
    size = info['memory_map_size']
    if not info['memory_map'] or not 0 < size <= 1 << 20:
        raise ValueError('missing or oversized firmware memory map')
    return free_spans(proxy.readmem(info['memory_map'], size),
                      info['memory_map_stride'] or 48, info)


def resident_work(proxy, info):
    """Fail closed on a missing/stale locator; never guess a physical address."""
    data = proxy.readmem(locator_address(info), LOCATOR_SIZE, live=True)
    return decode_locator(data, info, firmware_free(proxy, info))


def publish_work(proxy, info, base, size, guest_low, guest_high):
    data = encode_locator(base, size, guest_low, guest_high, info, firmware_free(proxy, info))
    where = locator_address(info)
    proxy.writemem(where, data)
    if proxy.readmem(where, len(data)) != data:
        raise ValueError('monitor work locator upload did not verify')

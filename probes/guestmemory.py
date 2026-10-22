# SPDX-License-Identifier: MIT
"""Bounded postmortem reads through the current 16 KiB guest table format."""


def read_16k(read_physical, root, ram_low, ram_high, va, size):
    """Walk live L1..L3 tables; never issue a read outside owned RAM.

    Supports 47-bit TTBR1 VAs, 32 MiB L2 blocks, and 16 KiB L3 pages.
    Reject other formats explicitly. No cached tables: each call observes
    the current mappings, including stacks created after bootstrap.
    """
    if (root & 0x3fff or not 0 <= ram_low < ram_high <= 1 << 48
            or not 0xffff800000000000 <= va < 1 << 64
            or not 0 < size <= 0x10000 or va + size > 1 << 64):
        raise ValueError('unsupported guest read geometry')

    def physical(pa, count):
        if not ram_low <= pa <= ram_high - count:
            raise ValueError('guest read points outside owned RAM')
        raw = read_physical(pa, count)
        if len(raw) != count:
            raise ValueError('short physical read')
        return raw

    result = bytearray()
    while len(result) < size:
        current, table = va + len(result), root
        for shift in (36, 25, 14):
            entry = int.from_bytes(physical(table + ((current >> shift) & 2047) * 8, 8), 'little')
            kind = entry & 3
            address = entry & 0x0000ffffffffc000
            if (shift == 25 and kind == 1) or (shift == 14 and kind == 3):
                mask = (1 << shift) - 1
                if address & mask:
                    raise ValueError('misaligned guest leaf')
                count = min(size - len(result), (1 << shift) - (current & mask))
                result.extend(physical(address + (current & mask), count))
                break
            if kind != 3 or shift == 14:
                raise ValueError('unmapped or unsupported guest descriptor')
            table = address
    return bytes(result)

#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Read-only audit of whole boot-segment SLIDE_REGION moves in a stopped guest.

Consumes the 90-word loader ABI. Checks every 4K hardware leaf against the
16K guest walk, old VA removal, destination permissions and physical-to-virtual
metadata. Partial/resliding sequences require an explicit operation trace and
are intentionally outside this boot-sequence auditor's contract.
"""
import argparse
import json
from pathlib import Path
import struct
import sys


def audit(read, params, shadow_root, work_low, work_high):
    words = struct.unpack('<90Q', read(params, 90 * 8))
    root, ram_low, ram_high = words[0], words[30], words[31]
    table_low, table_high, region_pa, begin, end, count = words[60:66]
    if not (1 <= count <= 8 and ram_low <= table_low <= root < table_high <= ram_high
            and work_low <= shadow_root < work_high and begin < end):
        raise ValueError('invalid loader ABI or shadow bounds')
    cache = {}

    def table(pa, granule):
        size = 1 << granule
        low, high = (ram_low, ram_high) if granule == 14 else (work_low, work_high)
        if pa % size or not low <= pa < pa + size <= high:
            raise ValueError(f'table outside owned memory: {pa:#x}')
        key = pa, granule
        if key not in cache:
            cache[key] = struct.unpack(f'<{size // 8}Q', read(pa, size))
        return cache[key]

    def walk(va, granule):
        va &= (1 << 47) - 1
        pa = root if granule == 14 else shadow_root
        seen = set()
        for level in range(1 if granule == 14 else 0, 4):
            if pa in seen:
                raise ValueError('cyclic table')
            seen.add(pa)
            shift = granule + (3 - level) * (granule - 3)
            desc = table(pa, granule)[(va >> shift) & ((1 << (granule - 3)) - 1)]
            if not desc & 1:
                return None
            if level == 3:
                if desc & 3 != 3:
                    raise ValueError('invalid leaf')
                return (desc & 0x0000fffffffff000 & -(1 << granule)) + (va & ((1 << granule) - 1)), desc
            if desc & 3 != 3:
                raise ValueError('unexpected block in a slide range')
            pa = desc & 0x0000fffffffff000
        raise AssertionError('walk did not terminate')

    if not ram_low <= region_pa < region_pa + 0x1000 <= ram_high:
        raise ValueError('region metadata outside owned memory')
    blob = read(region_pa, 0x1000)
    entries = struct.unpack_from('<I', blob)[0]
    if not 1 <= entries <= 50:
        raise ValueError('bad region count')
    regions = [struct.unpack_from('<QQI', blob, 0x10 + i * 24) for i in range(entries)]
    merged = []
    for pa, va, pages in regions:
        stop = pa + pages * 0x4000
        if not pages or (pa | va) & 0x3fff or stop > 1 << 64 or va + pages * 0x4000 > 1 << 64:
            raise ValueError('invalid physical-to-virtual range')
        if merged and pa < merged[-1][1]:
            raise ValueError('physical-to-virtual regions overlap or are unsorted')
        if merged and pa == merged[-1][1]:
            merged[-1][1] = stop
        else:
            merged.append([pa, stop])
    expected = [[ram_low, ram_high]]
    if words[33]:
        expected.append([words[32], words[32] + words[33]])
    expected.sort()
    if merged != expected:
        raise ValueError('physical-to-virtual coverage differs from owned RAM and panel')
    moved = []
    shadow_pages = 0
    for i in range(count):
        va, pa, pages = words[66 + i * 3:69 + i * 3]
        matches = [(start, dest, n) for start, dest, n in regions
                   if start <= pa < pa + pages * 0x4000 <= start + n * 0x4000]
        if len(matches) != 1:
            raise ValueError('source is split or absent from published metadata')
        start, dest, _ = matches[0]
        dest += pa - start
        if not begin <= dest < dest + pages * 0x4000 <= end:
            raise ValueError('a boot segment has not been moved into the reserved window')
        for offset in range(0, pages * 0x4000, 0x1000):
            if walk(va + offset, 14) is not None or walk(va + offset, 12) is not None:
                raise ValueError(f'old alias remains at {va + offset:#x}')
            guest, shadow = walk(dest + offset, 14), walk(dest + offset, 12)
            if guest is None or shadow is None or guest[0] != pa + offset or shadow[0] != guest[0]:
                raise ValueError(f'destination mismatch at {dest + offset:#x}')
            mask = (3 << 53) | 0xffc
            # NX kernel RW (selector 3), or the aperture selector of a later
            # ROZONE (2) / USER_EXEC (11) retype: this alias is XNU's phystokv
            # address, the one Apple re-permissions (replay-papt-moved-alias.py).
            if guest[1] & mask != shadow[1] & mask or guest[1] & ((3 << 53) | 0xc0) not in (
                    3 << 53, 2 << 53, (3 << 53) | 0x80):
                raise ValueError(f'destination attributes differ or are not an aperture selector: {dest + offset:#x}')
            shadow_pages += 1
        moved.append(dict(source=hex(va), destination=hex(dest), physical=hex(pa), pages=pages))
    return dict(moved=moved, pages=sum(r['pages'] for r in moved),
                shadow_pages=shadow_pages, region_entries=entries, tables_read=len(cache), mismatches=[])


def main():
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'probes'))
    import run
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--device', default=run.DEFAULT_DEVICE)
    for name in ('params', 'shadow-root', 'work-low', 'work-high'):
        parser.add_argument('--' + name, required=True, type=lambda s: int(s, 0))
    args = vars(parser.parse_args())
    proxy = run.connect(args.pop('device'), tries=1)
    try:
        result = audit(proxy.readmem, **args)
    finally:
        proxy.link.close()
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()

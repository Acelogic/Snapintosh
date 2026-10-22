#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Read-only audit of the monitor's private 4 KiB, 36-bit stage-2 maps."""
import hashlib
import struct

OA = 0x0000fffffffff000
XN = 1 << 54


def audit_private_stage2(read, banks, ranges, work_low, work_high):
    """Prove ownership, permissions, coverage and disjoint descriptor storage.

    ranges contains (low, high, low_attributes, upper_attributes). Each bank
    supplies root, vttbr and guards (pa, slot, open_descriptor, mode). All guards
    must be closed. This audits memory, not TLB behavior or concurrent execution.
    """
    assert banks and ranges
    ranges = sorted(ranges)
    for i, (lo, hi, low, upper) in enumerate(ranges):
        assert 0 <= lo < hi <= 1 << 36 and not ((lo | hi) & 4095)
        assert not i or ranges[i-1][1] <= lo
        assert low & ~0xffc == 0 and upper & ~XN == 0
    normalized_ranges = []
    for lo, hi, low, upper in ranges:
        if (normalized_ranges and normalized_ranges[-1][1] == lo
                and normalized_ranges[-1][2:] == (low, upper)):
            normalized_ranges[-1] = (normalized_ranges[-1][0], hi, low, upper)
        else:
            normalized_ranges.append((lo, hi, low, upper))
    ranges = normalized_ranges
    owned, vmids, results, reference = set(), set(), [], None
    for bank in banks:
        root, vttbr = bank['root'], bank['vttbr']
        vmid = vttbr >> 48
        assert 1 <= vmid <= 255 and vmid not in vmids
        assert vttbr == root | (vmid << 48)
        vmids.add(vmid)
        guards = {}
        for pa, slot, descriptor, mode in bank['guards']:
            assert not pa & 4095 and mode in (0, 1)
            assert pa not in guards
            guards[pa] = (slot, descriptor, mode)
        tables, leaves, seen_guards = set(), [], set()

        def walk(table, level, base):
            assert work_low <= table < work_high and table + 4096 <= work_high
            assert not table & 4095 and table not in owned and table not in tables
            assert len(tables) < 4096
            tables.add(table)
            data = read(table, 4096)
            assert len(data) == 4096
            for index, desc in enumerate(struct.unpack('<512Q', data)):
                if level == 1 and index >= 64:
                    assert desc == 0
                    continue
                span = 1 << (12 + 9 * (3-level))
                ipa = base + index * span
                slot = table + 8 * index
                if desc & 1 and level < 3 and desc & 2:
                    assert desc == (desc & OA) | 3
                    walk(desc & OA, level+1, ipa)
                    continue
                guard = guards.get(ipa) if level == 3 else None
                if guard:
                    expected_slot, original, mode = guard
                    assert slot == expected_slot
                    assert original & 3 == 3
                    closed = original | XN if mode == 0 else original & ~1
                    assert desc == closed
                    desc = original
                    seen_guards.add(ipa)
                if not desc & 1:
                    assert desc == 0
                    continue
                assert bool(desc & 2) == (level == 3)
                match = [r for r in ranges if r[0] <= ipa and ipa+span <= r[1]]
                assert len(match) == 1
                _, _, low, upper = match[0]
                expected = ipa | low | upper | (3 if level == 3 else 1)
                assert desc == expected
                leaves.append((ipa, ipa+span, low, upper))

        walk(root, 1, 0)
        assert seen_guards == set(guards)
        leaves.sort()
        merged = []
        for lo, hi, low, upper in leaves:
            if merged and merged[-1][1] == lo and merged[-1][2:] == (low, upper):
                merged[-1] = (merged[-1][0], hi, low, upper)
            else:
                merged.append((lo, hi, low, upper))
        assert merged == ranges
        # Equivalent address/permission coverage may use a different table shape.
        normalized = [(pa, desc, mode) for pa, (_, desc, mode) in sorted(guards.items())]
        if reference is None:
            reference = normalized
        else:
            assert normalized == reference
        owned.update(tables)
        digest = hashlib.sha256(b''.join(struct.pack('<4Q', *r) for r in leaves)).hexdigest()
        results.append(dict(root=hex(root), vmid=vmid, tables=len(tables),
                            leaves=len(leaves), guards_closed=len(seen_guards),
                            mapping_sha256=digest))
    return dict(banks=results, disjoint_table_pages=len(owned),
                table_addresses=[hex(pa) for pa in sorted(owned)],
                complete_ranges=True, closed_guards=True)

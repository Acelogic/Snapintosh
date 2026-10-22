#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Check EL0 UPERM read witnesses against the qualified fixed SPRR contract."""
import struct

FIELDS = 'reads pc word value spsr sp root umprr'.split()


def audit(raw):
    assert len(raw) == 6 * 8 * 8
    rows = []
    for cpu, values in enumerate(struct.iter_unpack('<8Q', raw)):
        row = dict(zip(FIELDS, values), cpu=cpu)
        if row['reads']:
            assert 0 < row['pc'] < (1 << 47) - 4 and not row['pc'] & 3
            assert row['word'] & ~31 == 0xd53ef1a0
            assert row['value'] & ~(1 << 36) == 0x2010002030100000
            assert not row['value'] & (1 << 36) or row['umprr'] & 0xc0000 == 0x40000
            assert not row['spsr'] & 31 and not row['spsr'] >> 32
            assert not row['spsr'] & ((1 << 20) | (1 << 5))
            assert 0 < row['sp'] < (1 << 47)
            assert row['root'] and not row['root'] & 0x3fff
            assert not row['umprr'] & ~0x40800
        else:
            assert not any(values)
        rows.append(row)
    return dict(reads=sum(row['reads'] for row in rows), rows=rows)

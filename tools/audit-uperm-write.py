#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Validate historical UPERM transactions and their unchanged-mapping proofs."""
import struct

FIELDS = 'writes changes pc word before after spsr sp root shadow tables pages classes umprr'.split()


def audit(raw, *, translated_tpro=False):
    assert len(raw) == 6 * 14 * 8
    rows = []
    for cpu, values in enumerate(struct.iter_unpack('<14Q', raw)):
        row = dict(zip(FIELDS, values), cpu=cpu)
        if row['writes']:
            assert row['changes'] <= row['writes']
            assert row['pc'] and not row['pc'] & 3
            mode = row['spsr'] & 31
            # XNU also writes UPERM from EL1t, with its kernel stack in SP_EL0.
            assert mode in (0, 4, 5) and not row['spsr'] >> 32, (cpu, row['spsr'])
            assert not row['spsr'] & (1 << 5)
            if mode == 0:
                assert row['pc'] < (1 << 47) - 4
                assert not row['spsr'] & (1 << 20)
            else:
                assert row['pc'] >> 47 == (1 << 17) - 1
            assert row['word'] & ~31 == 0xd51ef1a0 and row['word'] & 31 != 31
            assert row['before'] & ~(1 << 36) == 0x2010002030100000
            assert row['after'] & ~(1 << 36) == 0x2010002030100000
            assert row['umprr'] in (0x40000, 0x40800)
            assert row['root'] and not row['root'] & 0x3fff
            assert row['shadow'] and not row['shadow'] & 0xfff
            assert 0 < row['tables'] <= 8192
            assert row['pages'] <= row['tables'] * 512
            assert bool(row['classes']) == bool(row['pages'])
            # The opt-in requires a separate audit of installed CPU views.
            # Default retains the historical unchanged-mapping proof contract.
            assert not row['classes'] & ~(0xae88 if translated_tpro else 0xac88)
        else:
            assert not any(values)
        rows.append(row)
    return dict(writes=sum(r['writes'] for r in rows),
                changes=sum(r['changes'] for r in rows), rows=rows)

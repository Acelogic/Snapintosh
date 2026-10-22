#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Check PPERM selector9 transactions and both unchanged-mapping proofs."""
import struct

FIELDS = ('transactions grants restores before after pc user_root user_shadow '
          'user_tables user_pages user_classes kernel_root kernel_tables kernel_pages kernel_classes').split()


def audit(raw, current_pperm=None, *, translated_tpro=False):
    assert len(raw) == 6 * 15 * 8
    assert current_pperm is None or len(current_pperm) == 6
    rows = []
    for cpu, values in enumerate(struct.iter_unpack('<15Q', raw)):
        r = dict(zip(FIELDS, values), cpu=cpu)
        if r['transactions']:
            assert r['transactions'] == r['grants'] + r['restores']
            assert r['grants'] - r['restores'] in (0, 1)
            assert r['pc'] >> 47 == (1 << 17) - 1 and not r['pc'] & 3
            for key in ('before', 'after'):
                assert r[key] & ~(0x100 | (1 << 36)) == 0x2020a52a302abae6
            assert (r['before'] ^ r['after']) & (1 << 36)
            assert bool(r['after'] & (1 << 36)) == bool(r['grants'] - r['restores'])
            assert r['user_root'] and not r['user_root'] & 0x3fff
            for key in ('user_shadow', 'kernel_root'):
                assert r[key] and not r[key] & 0xfff
            assert 0 < r['user_tables'] <= 8192 and 0 < r['kernel_tables'] <= 8192
            assert r['user_pages'] <= r['user_tables'] * 512
            assert r['kernel_pages'] <= 1 << 35
            assert not r['user_classes'] & ~(0xae88 if translated_tpro else 0xac88)
            assert not r['kernel_classes'] & ~0xfdff
            for prefix in ('user', 'kernel'):
                assert bool(r[prefix + '_classes']) == bool(r[prefix + '_pages'])
        else:
            assert not any(values)
        if current_pperm is not None:
            assert bool(current_pperm[cpu] & (1 << 36)) == bool(r['grants'] - r['restores'])
        rows.append(r)
    return dict(transactions=sum(r['transactions'] for r in rows),
                grants=sum(r['grants'] for r in rows),
                restores=sum(r['restores'] for r in rows), rows=rows)

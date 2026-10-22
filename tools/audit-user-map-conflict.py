#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Audit the historical MAP_PAGE conflict reply without assuming it persisted."""
import struct
FIELDS='count root va wanted options old pointer result'.split()
def audit(raw):
    assert len(raw)==384
    rows=[]
    for cpu,values in enumerate(struct.iter_unpack('<8Q',raw)):
        row=dict(zip(FIELDS,values),cpu=cpu)
        if row['count']:
            assert row['result']==6 and row['options'] in (0,1)
            assert row['root'] and not row['root']&16383
            assert 0<=row['va']<1<<47 and not row['va']&4095
            assert row['wanted']&3==3
            if row['options']:
                assert not row['old'] and not row['pointer']
            else:
                assert row['old']&3==3
                assert (row['wanted']^row['old'])&0x0000fffffffff000
                assert row['pointer']>=0xffff800000000000 and not row['pointer']&7
        else:assert not any(values)
        rows.append(row)
    return dict(count=sum(r['count'] for r in rows),rows=rows)

#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Independently check an emulated EL0 counter read against its hardware sample."""
import struct

FIELDS='reads pc word value spsr sp root cntkctl raw host_hz guest_hz'.split()

def audit(raw):
    assert len(raw)==6*11*8
    rows=[]
    for cpu,values in enumerate(struct.iter_unpack('<11Q',raw)):
        row=dict(zip(FIELDS,values),cpu=cpu)
        if row['reads']:
            assert 0<row['pc']<(1<<47)-4 and not row['pc']&3
            assert row['word']&~31==0xd53cfac0
            assert not row['spsr']&31 and not row['spsr']>>32
            assert not row['spsr']&((1<<20)|(1<<5))
            assert 0<row['sp']<(1<<47)
            assert row['root'] and not row['root']&0x3fff
            assert row['cntkctl']&2
            assert row['host_hz']==19200000 and row['guest_hz']==24000000
            assert row['value']==(row['raw']*row['guest_hz']//row['host_hz'])&((1<<64)-1)
        else:
            assert not any(values)
        rows.append(row)
    return dict(reads=sum(r['reads'] for r in rows),rows=rows)

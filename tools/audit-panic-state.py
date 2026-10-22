#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Validate the shared panic flag and private first-owner bookkeeping."""
import struct

def audit(page,state,pointer,expected_pointer):
    if len(page)!=16384 or len(state)!=88:raise ValueError('panic state geometry')
    triggered,owner,phase,entries,rejected,*cpus=struct.unpack('<11Q',state)
    assert pointer==expected_pointer
    assert triggered in (0,1) and page[0]==triggered and not any(page[1:])
    assert entries==sum(cpus)
    if triggered:
        assert owner<6 and phase==1 and entries and cpus[owner]
    else:
        assert owner==0x8000 and phase==0xff and not entries and not rejected
    return dict(triggered=triggered,owner=owner,phase=phase,entries=entries,
                rejected=rejected,cpu_entries=cpus,pointer=hex(pointer))

#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Bind populated/shared commpage attachment to the shipped SPTM."""
from pathlib import Path
import hashlib
import runpy
import struct

ROOT=Path(__file__).resolve().parents[1]
h=runpy.run_path(str(ROOT/'tools/sptm-dispatch.py'))
im=h['Image'](ROOT/'downloads/extracted/j700ap/sptm.t8140.release')
assert hashlib.sha256(im.data).hexdigest()=='bd5736d4bd98bceaed2b057ebc09094324bf5149491c2922b329f87db23b1bd0'
rows=h['read_table'](im,h['XNU_BOOTSTRAP_VA'],47)
assert not h['verify'](rows)
assert rows[3]==(3,'SPTM_FUNCTIONID_MAP_TABLE',0xfffffff0270fa604,0)
checks=3
for offset,word in (
    (0xfa780,0x71005f9f), # commpage gets separate placement validation
    (0xfa784,0x54002940),
    (0xfacfc,0x721b011f), # ARM64_32 window selector
    (0xfa824,0x71005d1f), # populated commpage bypasses ordinary restrictions
    (0xfa828,0x540035a0),
    (0xfa82c,0x79401309), # ordinary leaf count must be zero
    (0xfa830,0x35003649),
    (0xfa840,0x48e8fd2a), # ordinary child links must transition 0 -> 1
    (0xfa848,0x54003cc1),
    (0xfaedc,0xaa1703e0), # shared helper: parent metadata
    (0xfaee0,0xaa1803e1), # child metadata
    (0xfaee4,0x52800002), # add link, not remove
    (0xfaee8,0x97ffc69c), # shared accounting helper ec958
    (0xec9d4,0x91001809), # root parent+6
    (0xec9dc,0x782a012a), # increment root child refs
    (0xeca48,0x91002009), # ordinary parent+8
    (0xeca50,0x782a012a), # increment parent child refs
    (0xeca74,0x91001829), # child+6
    (0xeca7c,0x78280128), # increment shared link count
    (0xeca80,0x529fff2a), # old count below 0xfff9
    (0xeca84,0x6b0a011f),
    (0xeca88,0x54000522),
    (0xeca20,0x91001828), # remove decrements same child field
    (0xeca28,0x78290109),
    (0xed0e4,0x71005d1f), # generic detach selects shared helper for type23
    (0xed0e8,0x54000820),
):
    va=0xfffffff027000000+offset
    off=im.locate(va)[1]
    assert off is not None and struct.unpack_from('<I',im.data,off)[0]==word,hex(va)
    checks+=1
print(f'PASS: {checks} shipped shared commpage attachment contract checks')

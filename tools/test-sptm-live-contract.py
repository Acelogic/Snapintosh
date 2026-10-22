#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Pinned MAP_PAGE missing-table and ordinary user data policy witnesses."""
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
assert rows[2]==(2,'SPTM_FUNCTIONID_MAP_PAGE',0xfffffff0270f8f18,0)
checks=3
for va,word in (
    (0xfffffff0270f8fec,0x97ffcd3f), # table walker
    (0xfffffff0270f8ff0,0xb40003c0), # absent ->...9068
    (0xfffffff0270f9070,0x528000e0), # missing table returns7
    (0xfffffff0270f908c,0x7940092a), # type permission bitmap at+4
    (0xfffffff0270f90a0,0xa9452d6c), # leaf table's data-type bitmask at+50
    (0xfffffff0270f90d8,0x927e057c), # permission class from AP
    (0xfffffff0270f90dc,0xb375da9c), # and PXN/UXN
    (0xfffffff0270f9100,0x37580074), # ordinary table requires nG
    (0xfffffff0270f9130,0x3940c929), # data type's trust-hook flag at+32
):
    off=im.locate(va)[1];assert struct.unpack_from('<I',im.data,off)[0]==word;checks+=1
default=0xfffffff02709e230+11*0x90
assert im.word(default)&0xffff00000000==0x888800000000;checks+=1
assert im.word(0xfffffff02709e230+20*0x90+0x50)&(1<<11);checks+=1
assert not im.data[im.locate(default+0x32)[1]]&1;checks+=1
print(f'PASS: {checks} shipped active user-mapping contract checks')

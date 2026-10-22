#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Bind shared table identity and attachment rules to the shipped T8140 SPTM."""
from pathlib import Path
import hashlib
import runpy
import struct
ROOT=Path(__file__).resolve().parents[1]
h=runpy.run_path(str(ROOT/'tools/sptm-dispatch.py'))
im=h['Image'](ROOT/'downloads/extracted/j700ap/sptm.t8140.release')
assert hashlib.sha256(im.data).hexdigest()=='bd5736d4bd98bceaed2b057ebc09094324bf5149491c2922b329f87db23b1bd0'
checks=1
assert im.string(im.pointer(0xfffffff02701e6b8+21*8))=='XNU_PAGE_TABLE_SHARED';checks+=1
d=0xfffffff02709e230+21*0x90
assert im.data[im.locate(d)[1]+1]==2;checks+=1
assert struct.unpack_from('<H',im.data,im.locate(d+4)[1])[0]==0;checks+=1
for off,value in [(0x40,1<<11),(0x60,0)]:
    assert im.word(d+off)==value;checks+=1
for off,value in [(0x68,0xfffffff0270eb12c),(0x70,0xfffffff0270eb020)]:
    assert im.pointer(d+off)==value;checks+=1
assert im.word(0xfffffff02709e230+11*0x90+0x40)&(1<<21);checks+=1
for kind,mask in [(8,0x500000),(18,0x900000),(19,0x200000),(21,0x4204801)]:
    assert im.word(0xfffffff02709e230+kind*0x90+0x50)==mask;checks+=1
for off,word in [
    (0xeb130,0x12001c48),(0xeb134,0x7100111f),(0xeb138,0x54000062),(0xeb13c,0x39001002),
    (0xeb050,0x79401008),(0xeb054,0x79400c0a),(0xeb058,0x2a0a010b),(0xeb060,0x54000241),
    (0xfa7c4,0xa945354c),(0xfa7e8,0xb4002f8c),(0xfa7f8,0xa945318d),(0xfa808,0xb400312a),
    (0xfa80c,0x39401308),(0xfa814,0x6b29011f),(0xfa82c,0x79401309),(0xfa830,0x35003649),
    (0xfa840,0x48e8fd2a),(0xfa848,0x54003cc1), # child links 0 -> 1
    (0xfa878,0x78290109),(0xfa8a4,0x78290109), # parent root/table counts
    (0xfa8f8,0x9ac8096b),(0xfa900,0xc8ecfd55),(0xfa914,0x11000529), # grouped PTEs
    (0xfaa58,0x97ffc99a), # roll back references if destination was occupied
]:
    va=0xfffffff027000000+off
    assert struct.unpack_from('<I',im.data,im.locate(va)[1])[0]==word,hex(va)
    checks+=1
print(f'PASS: {checks} shipped shared-table contract checks')

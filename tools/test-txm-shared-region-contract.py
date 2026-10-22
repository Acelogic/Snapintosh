#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""TXM37's shared-region declaration and normal address-space teardown."""
from pathlib import Path
import hashlib
import runpy
import struct
ROOT=Path(__file__).resolve().parents[1]
im=runpy.run_path(str(ROOT/'tools/sptm-dispatch.py'))['Image'](
    ROOT/'downloads/extracted/j700ap/txm.macosx.release')
assert hashlib.sha256(im.data).hexdigest()=='b746aaba8d3c0874911a53bf51f9591854783aa6e7b02f25494c2d782eecd246'
checks=1
for offset,word in [
    (0x3f5a0,0x0000007c), # endpoint37 jump table entry
    (0x3f114,0xaa1403e0),(0x3f118,0x97fff3c1), # validated object handle
    (0x3f11c,0xaa1503e1),(0x3f120,0xaa1603e2),(0x3f124,0x97ffdd59), # start,size
    (0x3669c,0xf240343f),(0x366a0,0x54000341), # start alignment
    (0x366a4,0xf240345f),(0x366a8,0x54000301), # size alignment
    (0x366b0,0xb4000341),(0x366b4,0xb4000362), # nonzero bounds
    (0x366b8,0xab020295),(0x366bc,0x54000362), # checked start+size
    (0x366cc,0x9400125c), # exclusive object lock
    (0x366d0,0x79404a68),(0x366d4,0x7100051f),(0x366d8,0x540001c1), # shared class1
    (0x366dc,0xf9403268),(0x366e0,0xb5000188), # end must be unset
    (0x366e4,0xa905d674), # store start/end at+58/+60
    (0x366f0,0x9400128f),(0x366f4,0xd2800000), # unlock, success
    (0x3638c,0xb8422014),(0x36390,0xb90017f4), # teardown uses packed identity
    (0x363d0,0xb9406808),(0x363d4,0x35000b88), # rejects live refs at+68
    (0x36518,0x94001768), # normal destructor releases the object
]:
    va=0xfffffff017000000+offset
    assert struct.unpack_from('<I',im.data,im.locate(va)[1])[0]==word,hex(va)
    checks+=1
print(f'PASS: {checks} shipped TXM shared-region contract checks')

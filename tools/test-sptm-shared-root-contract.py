#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Bind root conversion and TXM identity transfer to the shipped firmware."""
from pathlib import Path
import hashlib
import runpy
import struct
ROOT=Path(__file__).resolve().parents[1]
h=runpy.run_path(str(ROOT/'tools/sptm-dispatch.py'))
checks=0
def image(name,digest):
    global checks
    im=h['Image'](ROOT/'downloads/extracted/j700ap'/name)
    assert hashlib.sha256(im.data).hexdigest()==digest
    checks+=1
    return im
def instructions(im,base,rows):
    global checks
    for offset,word in rows:
        va=base+offset
        assert struct.unpack_from('<I',im.data,im.locate(va)[1])[0]==word,hex(va)
        checks+=1
sptm=image('sptm.t8140.release','bd5736d4bd98bceaed2b057ebc09094324bf5149491c2922b329f87db23b1bd0')
txm=image('txm.macosx.release','b746aaba8d3c0874911a53bf51f9591854783aa6e7b02f25494c2d782eecd246')
for kind,transitions,preserve in [(18,0x80800,0x30),(19,0x800,0)]:
    desc=0xfffffff02709e230+kind*0x90
    assert sptm.word(desc+0x40)==transitions;checks+=1
    assert sptm.word(desc+0x60)==preserve;checks+=1
    assert sptm.pointer(desc+0x68)==0xfffffff0270ebb3c;checks+=1
    assert sptm.pointer(desc+0x70)==0xfffffff0270eb558;checks+=1
    assert struct.unpack_from('<H',sptm.data,sptm.locate(desc+4)[1])[0]==0;checks+=1
instructions(sptm,0xfffffff027000000,[
    (0xeb58c,0x79400c09),(0xeb590,0x35000a89), # zero root references
    (0xeb5b0,0x71004c3f),(0xeb5b4,0x540006c0), # user -> shared branch
    (0xeb68c,0x52800001),(0xeb690,0x52800002), # retain TXM object and ASID until ctor
    (0xeb8d0,0xd5089349),(0xeb8d4,0xd5033a3f),(0xeb8d8,0xd5033fdf), # TLBI/barriers
    (0xeb914,0xf829118a), # release ASID bitmap bit
    (0xebc48,0x7900167f),(0xebc80,0xf9000d93),(0xebc88,0x39000189), # flags/registry
    (0xebc8c,0x3900226a),(0xebc90,0x79400a61),(0xebcac,0x97ff2a9d), # slot and TXM transfer
    (0xebcb0,0x79000a7f),(0xebd04,0x39003274),(0xebd08,0x79000e7f), # zero count/format/refs
    (0xeb5cc,0x79400808),(0xeb5d0,0x35000b68), # shared teardown requires zero nesting
])
instructions(txm,0xfffffff017000000,[
    (0x3eed0,0x52a00021),(0x3eed4,0xb3403ee1), # endpoint4 packed shared identity
    (0x3eed8,0x92403ec0),(0x3eedc,0x97ffddad), # old ASID and transfer call
    (0x365e4,0xf9402408),(0x365e8,0xb5000368), # reject attached signing state
    (0x365ec,0xf9401408),(0x365f0,0xb5000368), # reject mappings
    (0x365f4,0xf9400c08),(0x365f8,0xb5000368), # reject flags
    (0x36604,0xc8a97d1f),(0x36618,0xb8022013),(0x3661c,0xc8a87d20), # move same object
    (0x360d4,0x7103fd1f),(0x360d8,0x540000c2), # shared id <255
])
print(f'PASS: {checks} shipped shared-root contract checks')

#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Pin Image4 digest registration to the selected Apple TXM and kernel."""
import hashlib
from pathlib import Path
import runpy
import struct

ROOT=Path(__file__).resolve().parents[1]
helpers=runpy.run_path(str(ROOT/'tools/kc-disas.py'))
checks=0
def image(name,digest):
    global checks
    raw=(ROOT/'downloads/extracted/j700ap'/name).read_bytes()
    assert hashlib.sha256(raw).hexdigest()==digest;checks+=1
    segs=helpers['segments'](raw)
    def number(va,fmt='<I'):
        off=helpers['locate'](segs,va)[1]
        assert off is not None
        return struct.unpack_from(fmt,raw,off)[0]
    return number

txm=image('txm.macosx.release','b746aaba8d3c0874911a53bf51f9591854783aa6e7b02f25494c2d782eecd246')
kernel=image('kernelcache.release.mac17p','dc9019ae39187b36936c2c513b485e513f15cd966b5c887ac88ffd2925976c62')
assert txm(0xfffffff01703f510+51*4,'<i')==0x44c;checks+=1
assert 0xfffffff01703f094+0x44c==0xfffffff01703f4e0;checks+=1
for va,word in (
    (0xfffffff01703f094,0x10000011), # ADR dispatch base, after delta load
    (0xfffffff01703f070,0xf9000e7f), # reply count starts zero
    (0xfffffff01703f4e4,0xaa1403e0), # domain
    (0xfffffff01703f4e8,0xaa1503e1), # input pointer
    (0xfffffff01703f4ec,0xaa1603e2), # length
    (0xfffffff01703f4f0,0x94000479), # bounded wrapper
    (0xfffffff01703f4f8,0xf9000fff), # successful status zero
    (0xfffffff01703f500,0xf9000660), # reply status store
    (0xfffffff0170406e0,0xb4000221), # non-null input
    (0xfffffff0170406e4,0xb4000242), # nonzero length
    (0xfffffff0170406e8,0xab02003f), # pointer/length overflow
    (0xfffffff0170406ec,0x54000242),
    (0xfffffff017040718,0x1400034a), # library trampoline
    (0xfffffff017041444,0x1400df1c), # trampoline -> bounded setter
    (0xfffffff0170790d0,0x7100441f), # domain is uint32_t, below 17
    (0xfffffff0170790d4,0x540002a2),
    (0xfffffff0170790dc,0xf100c45f), # length below 49
    (0xfffffff0170790e0,0x540002c2),
    (0xfffffff0170790e8,0xf9477a88), # registry base
    (0xfffffff0170790ec,0x2a0003f5), # zero-extend domain index
    (0xfffffff0170790f0,0x8b151908), # native 64-byte record
    (0xfffffff0170790f4,0xf9401d09), # committed length
    (0xfffffff0170790f8,0xb5000289), # duplicate is fatal, even identical
    (0xfffffff0170790fc,0x91002100), # payload starts at +8
    (0xfffffff017079100,0xaa1303e2), # requested copy length
    (0xfffffff017079104,0x97ff2d9a), # memcpy
    (0xfffffff017079110,0xf9001d13), # commit length after copy
    (0xfffffff017079134,0x97ff1136), # invalid domain fatal
    (0xfffffff017079144,0x97ff1132), # invalid length fatal
    (0xfffffff017079154,0x97ff112e), # duplicate fatal
):
    assert txm(va)==word,hex(va);checks+=1
for va,word in (
    (0xfffffe000befc7fc,0x52800689), # _image4_v2_set_nonce_digest selector52
    (0xfffffe000b2dc054,0x94004413), # Image4::start callsite
):
    assert kernel(va)==word,hex(va);checks+=1
print(f'PASS: {checks} shipped nonce-digest registration contract checks')

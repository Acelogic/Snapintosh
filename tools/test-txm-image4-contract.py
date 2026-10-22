#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Bind the Image4 UUID negative reply to the selected shipped binaries."""
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
assert txm(0xfffffff01703f510+44*4,'<i')==0xc8;checks+=1
assert txm(0xfffffff01701df18+6*8,'<Q')==16;checks+=1
assert txm(0xfffffff01702bea0+6*8,'<Q')!=0;checks+=1
for va,word in (
    (0xfffffff01703f16c,0x9400053f), # wrapper -> bounds checker
    (0xfffffff0170406ac,0x140002a6), # -> Image4 dispatcher
    (0xfffffff017041198,0x54001301), # reject wrong operation-specific size
    (0xfffffff01704119c,0xd2c009c8), # errno78 in high32
    (0xfffffff0170411a0,0x528000a9), # error domain5
    (0xfffffff0170411a4,0xf1000adf), # op6 takes >2 branch
    (0xfffffff0170411a8,0x5400012c),
    (0xfffffff0170411cc,0xf1000edf), # no operation6 implementation
    (0xfffffff0170411d0,0x54000a80),
    (0xfffffff0170411d4,0xf10012df),
    (0xfffffff0170411d8,0x54000ca0),
    (0xfffffff0170411dc,0xf10016df),
    (0xfffffff0170411e0,0x54000e81), # op!=5 -> return default error
    (0xfffffff0170413c8,0xaa080120), # combine errno/domain
    (0xfffffff01703f070,0xf9000e7f), # reply count=0
    (0xfffffff01703f500,0xf9000660), # reply status at offset8
):
    assert txm(va)==word,hex(va);checks+=1
for va,word in (
    (0xfffffe000befcbc8,0xf940073a), # read transport status
    (0xfffffe000befecf4,0x79408be8), # decode domain
    (0xfffffe000befecf8,0x7100151f), # require errno domain5
    (0xfffffe000befed00,0xb9404be0), # return errno
    (0xfffffe00094b7c78,0x34000dc0), # nonzero follows native fallback
):
    assert kernel(va)==word,hex(va);checks+=1
assert txm(0xfffffff01701df18+3*8,'<Q')==44;checks+=1
assert txm(0xfffffff01702bea0+3*8,'<Q')&0xffffffff==0x690b0;checks+=1
assert txm(0xfffffff01702d400,'<Q')&0xffffffff==0x6b460;checks+=1
for va,word in (
    (0xfffffff017041334,0xad400680), # copy first32
    (0xfffffff01704133c,0x3cc1c280), # copy last16 at offset28
    (0xfffffff01704134c,0x52800582), # handler length44
    (0xfffffff0170413a8,0x9a8803e9), # domain5 only on error
    (0xfffffff0170413ac,0xd3607e68), # errno in upper32
    (0xfffffff01706d140,0xd360fc28), # ID must fit32
    (0xfffffff01706d148,0x52800a94), # wide ID -> errno84
    (0xfffffff01706d158,0x97fff98d), # lookup in actual domain registry
    (0xfffffff01706b7f0,0x52800040), # absent domain -> errno2
    (0xfffffff01706d174,0xf9401509), # existing state marker
    (0xfffffff01706d178,0xb4000169), # only empty state reaches stores
    (0xfffffff01706d17c,0x528004b4), # already set -> errno37
    (0xfffffff01706d1a8,0x12001929), # flags &= 0x7f
    (0xfffffff01706d1b4,0xb8001149), # flags at state+1
    (0xfffffff01706d1bc,0x3c805140), # first16 at state+5
    (0xfffffff01706d1c8,0x3d800d00), # second16 at state+48
    (0xfffffff01706d1cc,0xf9001509), # set initialization marker
    (0xfffffff01706d1d8,0x52800014), # actual success after stores
    (0xfffffff01706e0a8,0xd0000102), # twelve-domain array at 170901f8
    (0xfffffff01706e0ac,0x9107e042),
    (0xfffffff01706e0b8,0x52800183),
    (0xfffffff01706e0c0,0xf9001ea0), # save registry at state+0x38
    (0xfffffff01706ae7c,0xa9010801), # registry array at +0x18
    (0xfffffff01706ae80,0xf9001403), # registry count at +0x28
    (0xfffffff01706f464,0xf9400808), # expert state
    (0xfffffff01706f468,0xf9401d00), # nonce registry getter
):
    assert txm(va)==word,hex(va);checks+=1
for i,domain in enumerate((0x70646d67,0x63707478,0x64766469,0x63316274,
        0x63316162,0x6331676e,0x6331736d,0x64316d61,0x63316765,0x63316572,
        0x63316169,0x6331616c)):
    obj=0xfffffff017004000+(txm(0xfffffff0170901f8+8*i,'<Q')&0xffffffff)
    descriptor=0xfffffff017004000+(txm(obj,'<Q')&0xffffffff)
    assert txm(descriptor+8)==domain;checks+=1
for va,word in (
    (0xfffffe00094b5978,0xb9400828), # domain ID from descriptor
    (0xfffffe00094b597c,0xf9002fe8), # zero-extended ID at input+0
    (0xfffffe00094b5980,0xb90063e2), # flags at input+8
):
    assert kernel(va)==word,hex(va);checks+=1
print(f'PASS: {checks} shipped TXM/Image4 contract checks (UUID negative reply, nonce storage and domains)')

#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Pin empty trust-cache query replies to the selected Apple TXM and kernel."""
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
assert txm(0xfffffff01703f510+13*4,'<i')==0xe0;checks+=1
for va,word in (
    (0xfffffff01703f178,0x12001e80), # query kind as u8
    (0xfffffff01703f184,0x94000213), # endpoint14 -> query wrapper
    (0xfffffff01703f9f8,0x52800288), # default hash length20
    (0xfffffff01703fa00,0x9a960103), # length0 -> 20
    (0xfffffff01703fa08,0xb4000574), # null input rejected
    (0xfffffff01703fa10,0x54000562), # span overflow rejected
    (0xfffffff01703fa4c,0x94001b07), # lib query
    (0xfffffff01703fa64,0x52800069), # domain3 for library errors
    (0xfffffff01703fa7c,0xf9000e6a), # two token words only on success
    (0xfffffff01703fa88,0xd348fd0a),
    (0xfffffff01703fa98,0xb3601d0b), # packed result high32
    (0xfffffff01703f070,0xf9000e7f), # initial reply count0
    (0xfffffff01703f500,0xf9000660), # reply status+8
    (0xfffffff0170463d4,0xf8bfc000), # read list head, not hash
    (0xfffffff017046524,0x52848233), # empty list 0x12411
    (0xfffffff017046528,0x72a00033),
    (0xfffffff017046530,0xb4000280), # empty -> return without hash read
    (0xfffffff017046580,0xaa1303e0),
    (0xfffffff017046624,0x52848240), # all empty -> 0x12412
    (0xfffffff017046628,0x72a00020),
    (0xfffffff0170466b8,0x97ffff92), # kind1 first static list
    (0xfffffff0170466c4,0x910062c0), # kind1 second static list
    (0xfffffff017046700,0xf94012c0), # kind2 dynamic list
    (0xfffffff0170466e0,0x91002100), # kind3 second dynamic list
):
    assert txm(va)==word,hex(va);checks+=1
for va,word in (
    (0xfffffe000befa70c,0x528001c9), # kernel selector14
    (0xfffffe000befa73c,0x79406be8), # error domain
    (0xfffffe000befa748,0x7100913f), # library error0x24
    (0xfffffe000befa74c,0x7a430900), # domain3
    (0xfffffe000befa750,0x52800708), # map miss to KERN_NOT_FOUND56
    (0xfffffe000971aa80,0x350000c0), # AMFI does not consume token on error
    (0xfffffe00097264b4,0xf90007ff), # next lookup output starts zero
    (0xfffffe00097264bc,0x52800040), # static miss -> kind2
    (0xfffffe00097264e0,0x52800060), # kind2 miss -> kind3
):
    assert kernel(va)==word,hex(va);checks+=1
assert txm(0xfffffff01703f510+29*4,'<i')==0x308;checks+=1
assert txm(0xfffffff017090da0,'<Q')==0;checks+=1 # no compilation hash initially
for va,word in (
    (0xfffffff01703f3a8,0x940003b8), # endpoint30 -> bounded wrapper
    (0xfffffff0170402d4,0xf100529f), # nonzero size >=20
    (0xfffffff0170402e4,0x52800294), # zero means20
    (0xfffffff0170402ec,0xf101029f), # size <=64
    (0xfffffff01704032c,0x94001112), # copy input before matching
    (0xfffffff017040338,0x97ffe555), # call compilation-hash matcher
    (0xfffffff0170398dc,0xf9449a62), # stored hash length
    (0xfffffff0170398f0,0x54000101), # nonmatching lengths -> false
    (0xfffffff017039910,0x52800000),
    (0xfffffff01704035c,0x52800100), # no match status8
    (0xfffffff01703982c,0xf9049909), # setter updates same stored length
):
    assert txm(va)==word,hex(va);checks+=1
for va,word in (
    (0xfffffe000befbd50,0x140007da), # named match_compilation_service wrapper
    (0xfffffe000befdcec,0x528003c8), # selector30
    (0xfffffe000befdd54,0x7100001f), # return true only for status0
    (0xfffffe000befdd58,0x1a9f17e0),
    (0xfffffe00097292d4,0x34000120), # AMFI no-match path
):
    assert kernel(va)==word,hex(va);checks+=1
print(f'PASS: {checks} shipped empty trust-query / compilation-match contract checks')

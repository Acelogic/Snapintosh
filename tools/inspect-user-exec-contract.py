#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Pin USER_EXEC descriptor, retype, aperture and cache witnesses in 26A428."""
import hashlib
import json
from pathlib import Path
import runpy
import struct
ROOT=Path(__file__).resolve().parents[1]
SHA='bd5736d4bd98bceaed2b057ebc09094324bf5149491c2922b329f87db23b1bd0'
BASE=0xfffffff000000000
WORDS=(
    (0x270ebf7c,0xd503245f),(0x270ebf80,0xd65f03c0),
    (0x270eb2cc,0xb9400808),(0x270eb2d0,0xb9400c0a),(0x270eb31c,0x3500054a),
    (0x270eb1cc,0xb9400c08),(0x270eb1d0,0x35000248),
    (0x270f86ac,0x37500068),(0x270f86b8,0x39402a88),
    (0x270f8768,0x39000a95),(0x270f8770,0x39401ae1),(0x270f8784,0x97ff9ce6),
    (0x270dfd38,0x2a1603e8),(0x270dfd3c,0xd37c7ec9),(0x270dfd40,0xaa08d528),
    (0x270f8790,0x79400908),(0x270f87a0,0x7203c11f),
    (0x270f8814,0x52880001),(0x270f8818,0x97fedc91),
    (0x270afa84,0xd50b7520),(0x270afa94,0xd5033f9f),(0x270afa98,0xd5033fdf),
)
def require_words(read):
    for low,wanted in WORDS:
        if read(BASE|low)!=wanted:raise ValueError(f'USER_EXEC instruction differs at {low:x}')
def inspect(path):
    im=runpy.run_path(str(ROOT/'tools/sptm-dispatch.py'))['Image'](path)
    if hashlib.sha256(im.data).hexdigest()!=SHA:raise ValueError('SPTM image differs from 26A428')
    def read(va):return struct.unpack_from('<I',im.data,im.locate(va)[1])[0]
    require_words(read)
    rows={}
    for kind in (11,14):
        va=BASE|0x2709e230;va+=kind*144;_,off=im.locate(va);d=im.data[off:off+144]
        policy=int.from_bytes(d[4:6],'little');allowed=int.from_bytes(d[64:80],'little')
        rows[kind]=dict(name=im.string(im.pointer((BASE|0x2701e6b8)+kind*8)),
            descriptor=hex(va),policy=hex(policy),selectors=[n for n in range(16) if policy>>n&1],
            aperture_selector=d[6],preserve_mask=hex(int.from_bytes(d[96:98],'little')),
            mixed_aliases=bool(d[0x33]),allowed_transitions=[n for n in range(68) if allowed>>n&1],
            constructor=hex(im.pointer(va+0x68)),destructor=hex(im.pointer(va+0x70)))
    assert rows[14]['name']=='XNU_USER_EXEC' and rows[14]['selectors']==[11,13,15]
    assert rows[14]['aperture_selector']==11 and rows[14]['preserve_mask']=='0xf00'
    assert rows[14]['allowed_transitions']==[11] and 14 in rows[11]['allowed_transitions']
    assert rows[14]['constructor']=='0xfffffff0270ebf7c' and rows[14]['mixed_aliases']
    return dict(sptm_sha256=SHA,types=rows,instruction_witnesses=len(WORDS),
                preserved_bytes=[8,9,10,11],cache_bytes=16384,
                native_cache_sequence=['DSB SY','IC IVAU per 64-byte line','DSB SY','ISB'],
                host_cache_sequence=['DC CIVAC per 64-byte line','DSB ISH','IC IALLUIS','DSB ISH','ISB'])
if __name__=='__main__':
    print(json.dumps(inspect(ROOT/'downloads/extracted/j700ap/sptm.t8140.release'),indent=2))

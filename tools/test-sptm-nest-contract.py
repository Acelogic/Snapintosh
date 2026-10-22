#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Pin NEST range geometry, identity, descriptor copying and reference ABI."""
from pathlib import Path
import hashlib
import runpy
import struct
ROOT=Path(__file__).resolve().parents[1]
h=runpy.run_path(str(ROOT/'tools/sptm-dispatch.py'))
im=h['Image'](ROOT/'downloads/extracted/j700ap/sptm.t8140.release')
assert hashlib.sha256(im.data).hexdigest()=='bd5736d4bd98bceaed2b057ebc09094324bf5149491c2922b329f87db23b1bd0'
checks=1
for off,word in [
    (0xff1a4,0x39402268),(0xff1a8,0x6b0802bf),(0xff1ac,0x54002a81),
    (0xff1e8,0x940001c2),(0xff208,0x97ffb4b8),(0xff210,0x7103febf),
    (0xff268,0xfa492142),(0xff26c,0x54002a48),(0xff28c,0x97ffb497),
    (0xff2d4,0xcb17030c),(0xff2d8,0x8b16018c),(0xff2e8,0x4b0b0108),
    (0xff2f8,0x11000515),(0xff328,0xf240051f),(0xff354,0x7100551f),
    (0xff36c,0x71000d1f),(0xff384,0x36280b28),(0xff390,0xc8a87f77),
    (0xff398,0x54001501),(0xff3a8,0x97ffb56c),(0xff3e4,0xd5033bbf),
    (0xff3e8,0xd5033fdf),(0xfcf98,0x2a0103e8),(0xfcfa4,0x54000663),
    (0xff95c,0xf94029ae),(0xff968,0x54000421),(0xff990,0x5100058b),
    (0xff994,0x0a0e016c),(0xff998,0x0a0a016a),(0xff9a0,0x350004ea),
]:
    va=0xfffffff027000000+off
    assert struct.unpack_from('<I',im.data,im.locate(va)[1])[0]==word,hex(va)
    checks+=1
for fmt,expected in [(0,(0x4000,14,0x7ff000000000,25,0xffe000000)),
                     (1,(0x1000,12,0x7fc0000000,21,0x3fe00000))]:
    g=im.pointer(0xfffffff027023bc0+fmt*8);sub=im.pointer(g)
    page,shift,upper,l2shift,l2mask=expected
    assert (im.word(g+0x48),im.word(g+0x50),im.word(sub+0x50),
            im.word(sub+0x80),im.word(sub+0x88))==expected;checks+=5
    # Page-aligned partial ends pass the binary's index test. Its inclusive
    # last-page calculation then copies one extra descriptor, not a full group.
    start=0x180000000+page;group=0x4000//page;end=start+group*(1<<l2shift)
    assert not (((start&l2mask)>>l2shift)|((end&l2mask)>>l2shift))&(group-1)
    assert not (start^(end-page))&upper
    assert ((end-page)>>l2shift)-(start>>l2shift)+1==group+1
    checks+=3
print(f'PASS: {checks} shipped NEST_REGION contract checks')

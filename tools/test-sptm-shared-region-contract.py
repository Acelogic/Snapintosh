#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Pin SPTM9 state, geometry and release behavior to Apple's shipped firmware."""
from pathlib import Path
import hashlib
import runpy
import struct
ROOT=Path(__file__).resolve().parents[1]
h=runpy.run_path(str(ROOT/'tools/sptm-dispatch.py'))
im=h['Image'](ROOT/'downloads/extracted/j700ap/sptm.t8140.release')
assert hashlib.sha256(im.data).hexdigest()=='bd5736d4bd98bceaed2b057ebc09094324bf5149491c2922b329f87db23b1bd0'
checks=1
row=h['read_table'](im,h['XNU_BOOTSTRAP_VA'],10)[9]
assert row[:3]==(9,'SPTM_FUNCTIONID_CONFIGURE_SHAREDREGION',0xfffffff0270fea14)
checks+=1
for off,word in [
    (0xfea30,0xaa0203f4),(0xfea34,0xaa0103f5),(0xfea38,0x97ffee8a), # count/start/root
    (0xfea48,0x48a97c08),(0xfea6c,0x7100051f), # serialized root, class1
    (0xfea74,0x39403268),(0xfea88,0xf9402ac8), # format and page shift
    (0xfea8c,0xd2c00209),(0xfea90,0x9ac82528),(0xfeaa8,0x97fff935), # 64GiB validator
    (0xfeac4,0x39402268),(0xfeac8,0x7103fd1f),(0xfead8,0x8b08152a), # slot*32
    (0xfeae8,0xf94026c9),(0xfeaf0,0x9b097d6b), # count to bytes
    (0xfeaf4,0x5280004c),(0xfeaf8,0x52800029),(0xfeafc,0x08e97d4c), # 1 -> 2
    (0xfeb08,0xa900ad40),(0xfeb0c,0x52800068),(0xfeb10,0x08acfd48), # start/size, 2 -> 3
    (0xfcf98,0x2a0103e8),(0xfcf9c,0x340006a1),(0xfcfa0,0xeb08005f), # uint32 count
    (0xfcfd8,0xf940256a),(0xfcfe0,0xea00019f), # start alignment
    (0xfcfe8,0x9bca7d0c),(0xfcff0,0x9b0a7d0c),(0xfcff4,0xcb0a018d),
    (0xfcff8,0xab0d0014),(0xfd000,0xf940316a),(0xfd004,0x7100213f), # last page, type8 exception
    (0xfd048,0x9100054a),(0xfd04c,0xeb0a029f),(0xfd054,0xf9000088), # VA limit, normalized count
    (0xeb608,0xa9017d1f),(0xeb60c,0x383f8109),(0xeb610,0x34000da9), # teardown clears slot
]:
    va=0xfffffff027000000+off
    assert struct.unpack_from('<I',im.data,im.locate(va)[1])[0]==word,hex(va)
    checks+=1
for fmt,base,page,shift in [(0,0xfffffff02701ec78,0x4000,14),(1,0xfffffff02701ece0,0x1000,12)]:
    assert im.pointer(0xfffffff027023bc0+8*fmt)==base;checks+=1
    for off,value in [(0x48,page),(0x50,shift),(0x60,(1<<47)-1)]:
        assert im.word(base+off)==value;checks+=1
print(f'PASS: {checks} shipped SPTM shared-region contract checks')

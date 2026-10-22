#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Pin the shipped MAP_PAGE accepted-leaf status and its XNU consumer.

After the CAS at ...f92b4 succeeds, ...f9490 tests the replaced descriptor
(x16 = old&3, set at ...f92cc): an empty slot returns 0 at ...f9574, a valid
page descriptor is invalidated and returns 1 at ...f95d4; an identical
request returns 1 at ...f9378 without a store. The code is common to kernel,
user and shared roots. XNU's pmap_enter consumer (ba61544) enters a PV entry
(bl ba77af8, pmap_enter_pv) only for status 0 and takes the existing-mapping
path at ba61600 for status 1. compat/sptm.h sptm_mac_map_page_status mirrors
this. A qemu-sptm run of the real SPTM with this kernelcache returned 1 for
all 254 observed same-PA replacements (251 kernel, 3 user)."""
from pathlib import Path
import hashlib
import json
import runpy
import struct
ROOT=Path(__file__).resolve().parents[1]
SPTM_SHA='bd5736d4bd98bceaed2b057ebc09094324bf5149491c2922b329f87db23b1bd0'
KERNEL_SHA='dc9019ae39187b36936c2c513b485e513f15cd966b5c887ac88ffd2925976c62'
SPTM_WORDS=((0x270f92b4,0xc8bafe3b),(0x270f92b8,0xeb15035f),(0x270f92bc,0x54000ea0),
    (0x270f92c0,0xeb14035f),(0x270f92c4,0x540005a0),(0x270f92cc,0x92400750),
    (0x270f9378,0x52800020),(0x270f9490,0xf1000e1f),(0x270f9498,0x540005e1),
    (0x270f9574,0x52800000),(0x270f95d4,0x52800020))
KERNEL_WORDS=((0xba61544,0x7100041f),(0xba61548,0x54000308),(0xba6154c,0x540005a0),
    (0xba61564,0x94005965),(0xba61600,0x5280001a),(0xba61608,0x5280001b))
def require_words(read,words,base):
    for offset,word in words:
        if read(base|offset)!=word:raise ValueError(f'MAP_PAGE status instruction differs at {offset:x}')
def inspect():
    helper=runpy.run_path(str(ROOT/'tools/sptm-dispatch.py'))
    im=helper['Image'](ROOT/'downloads/extracted/j700ap/sptm.t8140.release')
    kernel=runpy.run_path(str(ROOT/'tools/kc-xref.py'))['Kernelcache'](
        ROOT/'downloads/extracted/j700ap/kernelcache.release.mac17p')
    if hashlib.sha256(im.data).hexdigest()!=SPTM_SHA or hashlib.sha256(kernel.data).hexdigest()!=KERNEL_SHA:
        raise ValueError('requires the exact J700/T8140 26A428 images')
    row=helper['read_table'](im,helper['XNU_BOOTSTRAP_VA'],3)[2]
    assert row==(2,'SPTM_FUNCTIONID_MAP_PAGE',0xfffffff0270f8f18,0)
    require_words(lambda va:struct.unpack_from('<I',im.data,im.locate(va)[1])[0],SPTM_WORDS,0xfffffff000000000)
    require_words(kernel.u32,KERNEL_WORDS,0xfffffe0000000000)
    return dict(sptm_sha256=SPTM_SHA,kernel_sha256=KERNEL_SHA,endpoint=2,
        status={'identical':1,'empty_slot':0,'valid_leaf_replaced':1,'different_pa':6},
        kernel_consumer='ba61544: 0 -> pmap_enter_pv (ba77af8); 1 -> existing mapping (ba61600)',
        instruction_witnesses=len(SPTM_WORDS)+len(KERNEL_WORDS))
if __name__=='__main__':print(json.dumps(inspect(),indent=2))

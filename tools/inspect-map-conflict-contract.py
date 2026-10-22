#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Pin the shipped MAP_PAGE different-PA response and its XNU consumer."""
from pathlib import Path
import hashlib
import json
import runpy
import struct
ROOT=Path(__file__).resolve().parents[1]
SPTM_SHA='bd5736d4bd98bceaed2b057ebc09094324bf5149491c2922b329f87db23b1bd0'
KERNEL_SHA='dc9019ae39187b36936c2c513b485e513f15cd966b5c887ac88ffd2925976c62'
SPTM_WORDS=((0x270f9124,0xf940013a),(0x270f92c8,0xaa1a03f5),
    (0x270f92d0,0xf1000e1f),(0x270f92e8,0x92748eb1),
    (0x270f92ec,0xeb19023f),(0x270f92f0,0x54001761),
    (0x270f95dc,0x528000c0),(0x270f95e0,0x17ffff6a),
    (0x270f9514,0x3700011a),(0x270f952c,0xf85a83a9),(0x270f9530,0xa9002515))
KERNEL_WORDS=((0xba62e04,0x7100081f),(0xba62e08,0x54000922),
    (0xba61544,0x7100041f),(0xba61548,0x54000308),
    (0xba615e4,0x71001b3f),(0xba615e8,0x54003641),
    (0xba615ec,0x91401342),(0xba615f8,0x94000680),
    (0xba6343c,0x941f2035),(0xc22b520,0xd28000f0))
def require_words(read,words,base):
    for offset,word in words:
        if read(base|offset)!=word:raise ValueError(f'MAP_PAGE conflict instruction differs at {offset:x}')
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
        guest_result=6,pte_modified=False,reference_delta=False,
        output=['old_pte','old_pte_aperture_pointer'],suppress_output_option=1,
        kernel_consumer='ba615e4: status6 -> ba62ff8 over [VA,VA+16K)',
        instruction_witnesses=len(SPTM_WORDS)+len(KERNEL_WORDS))
if __name__=='__main__':print(json.dumps(inspect(),indent=2))

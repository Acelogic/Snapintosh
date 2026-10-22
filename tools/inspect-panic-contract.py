#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Pin the shipped kernel's panic pointer and SPTM's shared flag/latch."""
import hashlib
import json
from pathlib import Path
import runpy
import struct
ROOT=Path(__file__).resolve().parents[1]
KERNEL_SHA='dc9019ae39187b36936c2c513b485e513f15cd966b5c887ac88ffd2925976c62'
SPTM_SHA='bd5736d4bd98bceaed2b057ebc09094324bf5149491c2922b329f87db23b1bd0'
KERNEL_WORDS={0xfffffe000c244800:0xf940cea8,0xfffffe000c244808:0xf902e928,
    0xfffffe000b86f648:0xb0fe2984,0xfffffe000b86f64c:0xf942e884,
    0xfffffe000b86f650:0x39400084,0xfffffe000b86f654:0x35000344}
SPTM_WORDS={0xfffffff0270c053c:0x90000289,0xfffffff0270c0540:0x91029129,
    0xfffffff0270c0544:0xf900a109,0xfffffff0270f222c:0x39029148,
    0xfffffff0270f223c:0x48ab7d49,0xfffffff0270f225c:0x08aa7d28,
    0xfffffff0270f2310:0xf1000a9f,0xfffffff0270f2318:0x7100045f,
    0xfffffff0270f2524:0xd2800000,0xfffffff0270f2528:0xd2800001}
def require_words(read,witnesses):
    for va,wanted in witnesses.items():
        if read(va)!=wanted:raise ValueError(f'panic contract instruction mismatch at {va:x}')
def inspect():
    k=runpy.run_path(str(ROOT/'tools/kc-xref.py'))['Kernelcache'](ROOT/'downloads/extracted/j700ap/kernelcache.release.mac17p')
    s=runpy.run_path(str(ROOT/'tools/sptm-dispatch.py'))['Image'](ROOT/'downloads/extracted/j700ap/sptm.t8140.release')
    assert hashlib.sha256(k.data).hexdigest()==KERNEL_SHA
    assert hashlib.sha256(s.data).hexdigest()==SPTM_SHA
    require_words(k.u32,KERNEL_WORDS)
    require_words(lambda va:struct.unpack_from('<I',s.data,s.locate(va)[1])[0],SPTM_WORDS)
    def data(va,n):
        off=s.locate(va)[1];return s.data[off:off+n]
    assert data(0xfffffff02710c00c,3)==b'\x00\x80\xff'
    assert data(0xfffffff0271100a4,1)==b'\0'
    return dict(kernel_sha256=KERNEL_SHA,sptm_sha256=SPTM_SHA,handoff_offset='0x198',
                kernel_global='0xfffffe0007da05d0',native_flag='0xfffffff0271100a4',
                initial_flag=0,initial_owner=0x8000,initial_phase=0xff,
                panic_flag=1,panic_phase=1,owner_policy='first CPU wins',
                instruction_witnesses=len(KERNEL_WORDS)+len(SPTM_WORDS))
if __name__=='__main__':print(json.dumps(inspect(),indent=2))

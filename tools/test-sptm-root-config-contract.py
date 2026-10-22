#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Pin saved root flags and the separate activation modifier to shipped SPTM."""
from pathlib import Path
import hashlib
import runpy
import capstone

ROOT=Path(__file__).resolve().parents[1]
h=runpy.run_path(str(ROOT/'tools/sptm-dispatch.py'))
im=h['Image'](ROOT/'downloads/extracted/j700ap/sptm.t8140.release')
assert hashlib.sha256(im.data).hexdigest()=='bd5736d4bd98bceaed2b057ebc09094324bf5149491c2922b329f87db23b1bd0'
cs=capstone.Cs(capstone.CS_ARCH_ARM64,capstone.CS_MODE_ARM)
witnesses=[
    (0x27100200,'mov','x19, x2'),(0x27100204,'mov','x20, x1'),
    (0x27100208,'bl','#0xfffffff0270f9fe0'),
    (0x2710020c,'mov','w8, #0xfea4'),(0x27100210,'tst','w20, w8'),
    (0x27100218,'tst','w19, w8'),(0x27100220,'mvn','w11, w19'),
    (0x27100224,'and','w12, w19, w20'),(0x27100248,'add','x9, x0, #0xa'),
    (0x2710024c,'ldrh','w14, [x0, #0xa]'),(0x27100250,'and','w15, w14, w11'),
    (0x27100254,'orr','w15, w15, w12'),(0x2710025c,'cash','w16, w15, [x9]'),
    (0x27100264,'b.ne','#0xfffffff02710023c'),
    (0x27100688,'mov','w8, #9'),(0x2710068c,'tst','w28, w8'),
    (0x27100694,'lsl','w8, w28, #0xf'),(0x27100698,'and','w8, w8, #0x40000'),
    (0x2710069c,'bfi','w8, w28, #0xb, #1'),
    (0x271006a0,'msr','s3_6_c15_c3_0, x8'),(0x271006a8,'msr','s3_6_c15_c3_0, xzr'),
]
for low,mnemonic,operands in witnesses:
    va=0xfffffff000000000|low;off=im.locate(va)[1]
    instruction=next(cs.disasm(im.data[off:off+4],va))
    assert (instruction.mnemonic,instruction.op_str)==(mnemonic,operands),hex(va)
print(f'PASS: {len(witnesses)+1} shipped root-configuration contract checks')

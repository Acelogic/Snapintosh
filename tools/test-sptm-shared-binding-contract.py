#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Pin binding, mapping-tree shape and both release lifetimes to 26A428."""
from pathlib import Path
import hashlib
import runpy
import capstone
ROOT=Path(__file__).resolve().parents[1]
h=runpy.run_path(str(ROOT/'tools/sptm-dispatch.py'))
cs=capstone.Cs(capstone.CS_ARCH_ARM64,capstone.CS_MODE_ARM)
checks=0
contracts=[('sptm.t8140.release','bd5736d4bd98bceaed2b057ebc09094324bf5149491c2922b329f87db23b1bd0',[
    (0x270fecd4,'ldrb','w10, [x19, #0xc]'),
    (0x270fecd8,'ldrb','w11, [x20, #0xc]'),
    (0x270fecdc,'cmp','w10, w11'),
    (0x270fece4,'ldrb','w2, [x20, #8]'),
    (0x270fed00,'cmp','w11, #3'),
    (0x270fed10,'casb','w11, w2, [x12]'),
    (0x270fed14,'cmp','w11, #0xff'),
    (0x270fed28,'ldrh','w1, [x19, #4]'),
    (0x270fed44,'ldp','x3, x4, [x8, #8]'),
    (0x270fed48,'bl','#0xfffffff0270b6738'),
    (0x270fed68,'ldaddh','w8, w8, [x9]'),
    (0x270fed6c,'mov','w10, #0xfff9'),
    (0x270eb5c0,'mov','w1, #1'),
    (0x270eb5c4,'mov','w2, #1'),
    (0x270eb924,'cmp','w8, #0xff'),
    (0x270eb938,'ldr','x8, [x8, #0x18]'),
    (0x270eb95c,'ldaddh','w9, w9, [x8]'),
    (0x270eb960,'cbz','w9, #0xfffffff0270ebaa8'),
]),('txm.macosx.release','b746aaba8d3c0874911a53bf51f9591854783aa6e7b02f25494c2d782eecd246',[
    (0x1703674c,'tst','x2, #0x3fff'),
    (0x17036754,'tst','x3, #0x3fff'),
    (0x17036760,'cbz','x2, #0xfffffff017036880'),
    (0x17036764,'cbz','x3, #0xfffffff017036888'),
    (0x17036768,'adds','x24, x21, x3'),
    (0x17036784,'ldr','x22, [x0, #0x58]'),
    (0x17036794,'ldr','x23, [x0, #0x60]'),
    (0x170367a8,'ldadd','w9, w8, [x8]'),
    (0x170367ec,'ldr','x8, [x0, #0x48]'),
    (0x170367fc,'ldr','x21, [x0, #0x38]'),
    (0x1703680c,'strb','w9, [x21, #0x12]'),
    (0x17036810,'stp','x22, x23, [x21, #0x28]'),
    (0x17036814,'str','x20, [x21, #0x18]'),
    (0x17036834,'bl','#0xfffffff017035e0c'),
    (0x1703683c,'str','x21, [x19, #0x48]'),
    (0x17036840,'str','xzr, [x19, #0x38]'),
    (0x17035428,'and','x9, x9, #0xfffffffffffffffe'),
    (0x17035444,'str','x9, [x8, #0x48]'),
    (0x170363d0,'ldr','w8, [x0, #0x68]'),
    (0x170363e0,'ldr','x19, [x8, #0x18]'),
    (0x170363fc,'ldaddal','w9, w8, [x8]'),
    (0x1703643c,'ldr','x19, [x0, #0x28]!'),
])]
for name,digest,witnesses in contracts:
    im=h['Image'](ROOT/'downloads/extracted/j700ap'/name)
    assert hashlib.sha256(im.data).hexdigest()==digest;checks+=1
    for low,mnemonic,operands in witnesses:
        va=0xfffffff000000000|low;off=im.locate(va)[1]
        i=next(cs.disasm(im.data[off:off+4],va))
        assert (i.mnemonic,i.op_str)==(mnemonic,operands),hex(va)
        checks+=1
print(f'PASS: {checks} shipped shared-binding contract checks')

#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Replay unmodified 26A428 SPTM stream geometry fragments in Unicorn.

This checks stream flags, root level and table indexing, not hardware DMA.
The stream record and register inputs are explicit fixtures from the pinned DT.
"""
from pathlib import Path
import hashlib
import json
import runpy
import struct
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'build/test-python-deps'))
from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM
import unicorn.arm64_const as reg

SHA='bd5736d4bd98bceaed2b057ebc09094324bf5149491c2922b329f87db23b1bd0'


def main():
    image=runpy.run_path(str(ROOT/'tools/kc-xref.py'))['Kernelcache'](
        ROOT/'downloads/extracted/j700ap/sptm.t8140.release')
    assert hashlib.sha256(image.data).hexdigest()==SHA
    u=Uc(UC_ARCH_ARM64,UC_MODE_ARM)
    for base in (0xfffffff0270dd000,0xfffffff0270d7000,0xfffffff02701a000):
        u.mem_map(base,0x1000)
        o=image.va2off(base);u.mem_write(base,image.data[o:o+0x1000])
    data=0x1000000;u.mem_map(data,0x4000)
    rows=[]
    for name,low,size,tcr,level in (
        ('SEP SID0',0x10000004000,0xffff0000,1,1),
        ('SEP SID1',0x10000000000,0x50000000,1,1),
        ('SEP SID2',0x20000004000,0xffff0000,9,0),
        ('SIO',1<<40,3<<40,9,0),
        ('Adreno',0x40000000,0xc0000000,1,1),
        ('Adreno wide',0x40000000,0x3c0000000,1,1),   # agents/gpu-va-wide: ADRENO_VA_WIDE's [1 GiB, 16 GiB)
        ('threshold',0,(0x4400000<<14),1,1),
        ('above-threshold',0,(0x4400001<<14),9,0)):
        for initial in (1,9):
            u.mem_write(data+0x10,struct.pack('<Q',(low+size)>>14))
            u.reg_write(reg.UC_ARM64_REG_X8,data)
            u.reg_write(reg.UC_ARM64_REG_W9,initial)
            u.emu_start(0xfffffff0270dd668,0xfffffff0270dd68c,count=9)
            actual=struct.unpack('<I',u.mem_read(data+0x20,4))[0]
            assert actual==tcr,(name,actual,tcr)
            u.mem_write(data+0x100,struct.pack('<Q',data))
            u.reg_write(reg.UC_ARM64_REG_X26,data+0x100)
            u.reg_write(reg.UC_ARM64_REG_X25,0)
            u.reg_write(reg.UC_ARM64_REG_X29,data+0x1000)
            u.emu_start(0xfffffff0270d7d18,0xfffffff0270d7d2c,count=5)
            actual_level=struct.unpack('<I',u.mem_read(data+0x1000-0x5c,4))[0]
            assert actual_level==level,(name,actual_level,level)
        # Native index selection takes page numbers; the root's descriptor
        # lives in stream slot0 and each subsequent level masks its own bits.
        for address in (low,low+size-0x4000):
            for current in range(level,3):
                u.reg_write(reg.UC_ARM64_REG_W8,tcr)
                u.reg_write(reg.UC_ARM64_REG_X19,current)
                u.reg_write(reg.UC_ARM64_REG_W22,address>>14)
                u.emu_start(0xfffffff0270d7d90,0xfffffff0270d7dcc,count=20)
                index=u.reg_read(reg.UC_ARM64_REG_W28)
                expected=0 if current==level else (address>>(47-11*current))&2047
                assert index==expected,(name,current,index,expected)
        rows.append(dict(stream=name,base=hex(low),end=hex(low+size),tcr=tcr,root_level=level))
    print(json.dumps(dict(sptm_sha256=SHA,cases=rows,passed=True,
        boundary='original instruction fragments with fixture stream records; no hardware DMA'),indent=2))


if __name__=='__main__':main()

#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
import runpy
import struct
from pathlib import Path

audit=runpy.run_path(str(Path(__file__).with_name('audit-txm-release-type.py')))['audit']
checks=0
def run(raw):
    global checks
    checks+=1
    return audit(raw,stacks_pa=0x100000,stack_count=2)

assert not run(bytes(184))['initialized']
for length in range(65):
    original=b'X'*length+(bytes(64-length) if length<64 else b'')
    value=original[:62].split(b'\0',1)[0]
    for calls in (1,2,20):
        raw=struct.pack('<7Q',calls,1,calls-1,0 if calls==1 else (37<<32)|5,
                        0xfffffe0100100000,0x104000,len(value))+original+value.ljust(64,b'\0')
        assert run(raw)['value']==value.decode()

good=bytearray(struct.pack('<7Q',1,1,0,0,0xfffffe0100100000,0x100000,4)+
               b'User'.ljust(64,b'\0')*2)
for index,value in [(0,0),(1,2),(2,1),(3,37<<32|5),(4,0),(5,0x108000),(6,63)]:
    bad=bytearray(good);struct.pack_into('<Q',bad,index*8,value)
    try:run(bad)
    except ValueError:pass
    else:raise AssertionError(index)
for at in (56,120,125,183):
    bad=bytearray(good);bad[at]^=1
    try:run(bad)
    except ValueError:pass
    else:raise AssertionError(at)
print(f'TXM release-type auditor: {checks} cases passed')

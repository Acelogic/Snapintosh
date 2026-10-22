#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
import pathlib
import sys
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / 'probes'))
from guestmemory import read_16k

memory = bytearray(0x18000)
low, high, va = 0x80000000, 0x80018000, 0xfffffea9b4094000
reads = []
checks = 0


def read(pa, n):
    assert low <= pa <= high-n
    reads.append((pa, n))
    return memory[pa-low:pa-low+n]


def put(pa, value):
    memory[pa-low:pa-low+8] = value.to_bytes(8, 'little')


def check(condition):
    global checks
    checks += 1
    assert condition


def refused(*args):
    try:
        read_16k(read, *args)
    except ValueError:
        check(True)
    else:
        check(False)


put(low + ((va >> 36) & 2047)*8, (low+0x4000)|3)
put(low+0x4000 + ((va >> 25) & 2047)*8, (low+0x8000)|3)
leaf = low+0x8000 + ((va >> 14) & 2047)*8
put(leaf, (low+0xc000)|3)
put(leaf+8, (low+0x10000)|3)
memory[0xfffc:0x10004] = b'abcdefgh'
check(read_16k(read,low,low,high,va+0x3ffc,8) == b'abcdefgh')
# A changed mapping must be observed without rebuilding the reader.
put(leaf, (low+0x14000)|3)
memory[0x14000:0x14004]=b'live'
check(read_16k(read,low,low,high,va,4) == b'live')
for entry in (0,2,1,high|3,0x301000003):
    put(leaf,entry)
    refused(low,low,high,va,4)
for root,address,size in ((low+1,va,4),(high,va,4),(low,0,4),(low,va,0),
                          (low,va,0x10001),(low,(1<<64)-2,4)):
    refused(root,low,high,address,size)
# L2 block offset and alignment, with its physical read still RAM bounded.
l2 = low+0x4000 + ((va >> 25) & 2047)*8
put(l2,low|1)
block_va = va & ~((1<<25)-1)
check(read_16k(read,low,low,high,block_va+0x14000,4)==b'live')
refused(low,low,high,block_va+0x18000,4)
put(l2,(low+0x4000)|1)
refused(low,low,high,block_va,4)
try:
    read_16k(lambda pa,n: b'',low,low,high,va,4)
except ValueError:
    check(True)
else:
    check(False)
print(f'PASS: {checks} bounded live guest-memory checks')

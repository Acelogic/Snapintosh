#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""wsfmtscan.py - every direct call in SkyLight to a function that takes a WSPixelFormat, with the
immediate moves into w0..w7 in the 12 instructions before it (FORMATS.md 2.4: no call site passes
9, 10 or 11).  Runs in adreno/windowserver-metal-usage (wsm_lib, this Mac's dyld cache)."""
import os, re, struct, sys, bisect
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'tools'))
import scrdir
W = os.path.join(scrdir.scratchpad(), 'adreno', 'windowserver-metal-usage'); sys.path.insert(0, W); os.chdir(W)
from wsm_lib import *
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
s, addrs = syms('SkyLight')
names = {a: demangle(n) for a, n in s}
targets = {a: nm for a, nm in names.items() if 'WSPixelFormat' in nm and '(' in nm}
print(len(targets), 'SkyLight functions with a WSPixelFormat parameter')
md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
for sg, sc, base, n in sections('SkyLight'):
    if sc != '__text': continue
    data = cache.read(base, n)
    for off in range(0, n, 4):
        w = struct.unpack_from('<I', data, off)[0]
        if (w & 0xfc000000) != 0x94000000: continue
        pc = base + off; t = pc + sxt(w & 0x3ffffff, 26) * 4
        if t not in targets: continue
        ins = list(md.disasm(data[max(0, off - 48):off], pc - min(off, 48)))
        movs = [i.op_str for i in ins if i.mnemonic in ('mov', 'movz', 'orr') and re.match(r'w[0-7], #(0x[0-9a-f]+|\d+)$', i.op_str)]
        i = bisect.bisect_right(addrs, pc) - 1
        print(hex(pc), names[addrs[i]][:90], '->', targets[t][:80], '|', movs)

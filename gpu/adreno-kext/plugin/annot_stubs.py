# SPDX-License-Identifier: MIT
# Annotate `bl 0x...` lines of ipsw-style .s dumps with the objc selector the stub sends.
import sys,re
import os; sys.path.insert(0, os.environ.get('MACOS_GPU_ABI_DIR') or sys.exit('set MACOS_GPU_ABI_DIR to the directory holding dsc.py'))
from dsc import *
d=DSC(); cache={}
for line in open(sys.argv[1]):
    line=line.rstrip('\n')
    m=re.search(r'\s(bl|b)\s+(0x[0-9a-f]+)$',line)
    if m:
        t=int(m.group(2),16)
        if t not in cache: cache[t]=decode_stub(d,t)
        if cache[t]: line+=f'   ; [{cache[t]}]'
    print(line[:170])

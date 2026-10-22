#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Feed the C virtual boot frontend replies through the unchanged ROM client."""
import json
from pathlib import Path
import runpy
import subprocess
ROOT=Path(__file__).resolve().parents[1]
r=runpy.run_path(str(ROOT/'tools/replay-sep-rom-boot.py'))
k=runpy.run_path(str(ROOT/'tools/kc-xref.py'))['Kernelcache'](
    ROOT/'downloads/extracted/j700ap/kernelcache.release.mac17p')
p=subprocess.run([str(ROOT/'build/test-sep-rom-boot'),'--trace'],capture_output=True,text=True,check=True)
words=[int(v,16) for v in p.stdout.split()]
assert words==[0x1006601ff,0x6901ff,0x2006601ff,0x6a01ff]
answers=[((v>>16)&255,v>>32) for v in words]
boot=r['ROM'](k);boot.receiver=r['ROM'](k)
out=boot.boot(answers,firmware=0x10000004000,shared_address=0x10001000000,shared_size=0x28000,
              slot_selection=True,selected_slot=2)
assert out['stop']=='return' and out['return_value']==0 and out['phase']==101
assert [int(m['word'],16)>>16&255 for m in out['messages'][:-1]]==[2,5,2,6]
assert out['messages'][-1]==dict(endpoint=254,word='1000100000280000')
assert out['messages'][-2]['word']=='1000000420060100'
print(json.dumps(dict(kernel_sha256=r['s']['KERNEL_SHA'],responses=[hex(v) for v in words],
    native=out,boundary='original ROM client and parser; C producer; explicit IOKit/wait/DMA fixtures; no firmware execution or authentication')))

#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Feed the portable producer's replies to the original SEP ROM parser."""
import json
from pathlib import Path
import runpy
import subprocess
ROOT=Path(__file__).resolve().parents[1]
r=runpy.run_path(str(ROOT/'tools/replay-sep-rom-boot.py'))
k=runpy.run_path(str(ROOT/'tools/kc-xref.py'))['Kernelcache'](
    ROOT/'downloads/extracted/j700ap/kernelcache.release.mac17p')
receiver=r['ROM'](k)
for tag in range(256):
    p=subprocess.run([str(ROOT/'build/test-sep-rom-status'),'--reply',str(tag)],
                     text=True,capture_output=True,check=True)
    word=int(p.stdout,16)
    assert word==0x1006600ff|(tag<<8)
    result=receiver.reply((word>>16)&255,word>>32,word&255,tag=(word>>8)&255,phase=201)
    assert result==dict(stop='wake',phase=1,waiting=False,last=0),(tag,result)
print(json.dumps(dict(kernel_sha256=r['s']['KERNEL_SHA'],cases=256,
    status_phase=1,waiting=False,
    boundary='original reply parser accepts C producer output; no native IRQ, TZ0 or firmware execution proof')))

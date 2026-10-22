#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Bind RoRgn bounds to shipped instruction bytes and KC segment protections."""
from pathlib import Path
import hashlib
import runpy
import sys
from types import SimpleNamespace

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'probes'))
import xnuboot as xb
k=runpy.run_path(str(ROOT/'tools/kc-xref.py'))['Kernelcache'](xb.DEFAULT_KERNELCACHE)
assert hashlib.sha256(k.data).hexdigest()=='dc9019ae39187b36936c2c513b485e513f15cd966b5c887ac88ffd2925976c62'
checks=1
for va,word in (
    (0xfffffe000ba87c08,0xd538b148), # lower MRS
    (0xfffffe000ba87c10,0xf9001128), # save at ...7e2c020
    (0xfffffe000ba87c14,0xd538b168), # upper page-base MRS
    (0xfffffe000ba87c18,0x913ffd08), # expand upper by 4095
    (0xfffffe000ba87c20,0xf9001548), # save at ...7e2c028
    (0xfffffe000b981938,0xf940128a), # validation uses the saved lower
    (0xfffffe000b981954,0xf9401668), # validation uses the saved upper
    (0xfffffe000b981958,0x91000508), # inclusive -> exclusive before comparison
):
    assert k.u32(va)==word,hex(va);checks+=1
image=xb.kc_load.Image(k.data)
lo,hi=xb.const_region_contract(image,0x8c0080000)
assert (lo,hi)==(0x8c0080000,0x8c52e8000);checks+=1
for name,va,size,maxprot,initprot in image.segment_protections:
    if not size:continue
    pa=lo+va-image.vmin
    if pa<hi:assert pa+size<=hi and not (maxprot|initprot)&2
    if (maxprot|initprot)&2 or name=='__LINKEDIT':assert pa>=hi
    checks+=1
assert lo<=0x8c00c1fb0<hi;checks+=1 # native rejected const source
seed=[('__TEXT',0x10000,0x4000,1,1),('__TEXT_EXEC',0x14000,0x8000,5,5),
      ('__DATA',0x1c000,0x4000,3,3),('__LINKEDIT',0x20000,0x4000,1,1)]
def model(rows):return SimpleNamespace(vmin=0x10000,vmax=0x24000,segment_protections=rows)
assert xb.const_region_contract(model(seed),0x80000000)==(0x80000000,0x8000c000);checks+=1
for rows,pa in (([seed[0],('__TEXT_EXEC',0x18000,0x4000,5,5),*seed[2:]],0x80000000),
                ([('__TEXT',0x10000,0x2000,1,1),*seed[1:]],0x80000000),
                ([('__TEXT',0x10000,0x4000,1,0),*seed[1:]],0x80000000),
                ([('__TEXT',0x10000,0x4000,3,1),*seed[1:]],0x80000000),
                (seed,0x80001000)):
    try:xb.const_region_contract(model(rows),pa)
    except ValueError:checks+=1
    else:raise AssertionError('malformed const prefix admitted')
print(f'PASS: {checks} shipped RoRgn and loader contract checks')

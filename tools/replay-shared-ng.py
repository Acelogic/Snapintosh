#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Run the pinned UPDATE_REGION descriptor helper for shared nG conversion.

Unmodified Apple instructions; stop before the helper epilogue or its explicit
bad-template branch. This proves selection only, not publication/ref/TLBI.
"""
import hashlib
import json
from pathlib import Path
import runpy
import subprocess
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'build/test-python-deps'))
from unicorn import Uc,UC_ARCH_ARM64,UC_MODE_ARM,UC_HOOK_CODE
import unicorn.arm64_const as reg
BASE=0xfffffff027000000
SHA='bd5736d4bd98bceaed2b057ebc09094324bf5149491c2922b329f87db23b1bd0'

def replay(binary):
    im=runpy.run_path(str(ROOT/'tools/sptm-dispatch.py'))['Image'](
        ROOT/'downloads/extracted/j700ap/sptm.t8140.release')
    assert hashlib.sha256(im.data).hexdigest()==SHA
    u=Uc(UC_ARCH_ARM64,UC_MODE_ARM);u.mem_map(BASE,0x200000)
    for _,va,_,off,size in im.segs:u.mem_write(va,im.data[off:off+size])
    u.mem_map(0x1000000,0x100000)
    context,data,table,out=0x1010000,0x1011000,0x1012000,0x1013000
    u.mem_write(context,data.to_bytes(8,'little')+table.to_bytes(8,'little'))
    def stop(uc,address,size,user):
        if address in (BASE+0xfd8f0,BASE+0xfd724):uc.emu_stop()
    u.hook_add(UC_HOOK_CODE,stop);rows=[]
    leaves=[(11,0),(11,0x400000000000000),(11,0x94280c006)]
    for dtype,attrs in [(11,0x0060000000000643),(11,0x00600000000006c3),
                        (11,0x08600000000006c3),(14,0x00200000000006c3),
                        (14,0x00600000000006c3)]:
        for ng in (0,0x800):
            for wired in (0,1<<58):
                for af in (0,0x400):
                    leaves.append((dtype,0x94280c000|(attrs&~0x400)|ng|wired|af))
    for dtype,old in leaves:
        for requested in (0x800,0,0x0060000123400843):
            for options in (4,0x104):
                u.mem_write(data+2,bytes([dtype]));u.mem_write(table+2,bytes([21]))
                u.mem_write(context+0x20,b'\0')
                for n,value in enumerate((context,old,requested,options,out)):
                    u.reg_write(getattr(reg,f'UC_ARM64_REG_X{n}'),value)
                u.reg_write(reg.UC_ARM64_REG_SP,0x1080000)
                u.emu_start(BASE+0xfd544,BASE+0xfd900,count=1000)
                pc=u.reg_read(reg.UC_ARM64_REG_PC)
                assert pc in (BASE+0xfd8f0,BASE+0xfd724),hex(pc)
                rejected=pc==BASE+0xfd724
                new=int.from_bytes(u.mem_read(out,8),'little')
                run=subprocess.run([binary,'--pte',f'{old:x}',f'{requested:x}',f'{options:x}'],
                                   check=True,capture_output=True,text=True)
                status,value=run.stdout.split()
                assert bool(int(status))==rejected and (rejected or int(value,16)==new),run.stdout
                if not rejected:
                    assert u.reg_read(reg.UC_ARM64_REG_X0)==int(old!=new)
                    assert u.mem_read(context+0x20,1)[0]==int(old!=new)
                rows.append(dict(data_type=dtype,old=hex(old),requested=hex(requested),
                                 options=hex(options),new=hex(new),rejected=rejected))
    return dict(sptm_sha256=SHA,helper='fffffff0270fd544',c_cases_matched=len(rows),cases=rows,
                boundary='descriptor selection only; no source publication, references or TLBI')

if __name__=='__main__':
    print(json.dumps(replay(sys.argv[1]),indent=2))

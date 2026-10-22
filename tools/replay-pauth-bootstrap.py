#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Compare virtual PA register defaults against unmodified T8140 bootstrap.

System-register operations are captured, not executed. No hardware key
transformation or PAC cryptography is emulated by this check.
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

def main():
    im=runpy.run_path(str(ROOT/'tools/sptm-dispatch.py'))['Image'](
        ROOT/'downloads/extracted/j700ap/sptm.t8140.release')
    assert hashlib.sha256(im.data).hexdigest()==SHA
    output=subprocess.check_output([str(ROOT/'build/test-pauth-user'),'--boot'],text=True)
    expected={int(a,16):int(b,16) for a,b in (line.split() for line in output.splitlines())}
    rows=[]
    for begin,end in [(BASE+0xa40c8,BASE+0xa414c),(BASE+0xaf5e4,BASE+0xaf668)]:
        uc=Uc(UC_ARCH_ARM64,UC_MODE_ARM);uc.mem_map(BASE,0x200000)
        for _,va,_,off,size in im.segs:uc.mem_write(va,im.data[off:off+size])
        values={}
        def hook(u,address,size,_):
            word=int.from_bytes(u.mem_read(address,4),'little')
            if word&0xffe00000 not in (0xd5000000,0xd5200000):return
            op0=(word>>19)&3
            if op0!=3:return
            op1=(word>>16)&7;crn=(word>>12)&15;crm=(word>>8)&15;op2=(word>>5)&7
            encoded=(op0<<20)|(op2<<17)|(op1<<14)|(crn<<10)|(crm<<1)
            rt=word&31
            if word&(1<<21):
                if rt!=31:u.reg_write(getattr(reg,f'UC_ARM64_REG_X{rt}'),values.get(encoded,0))
            else:
                values[encoded]=0 if rt==31 else u.reg_read(getattr(reg,f'UC_ARM64_REG_X{rt}'))
            u.reg_write(reg.UC_ARM64_REG_PC,address+4)
        uc.hook_add(UC_HOOK_CODE,hook)
        uc.emu_start(begin,end,count=200)
        assert uc.reg_read(reg.UC_ARM64_REG_PC)==end
        got={k:values[k] for k in expected}
        assert got==expected,(got,expected)
        rows.append(dict(begin=hex(begin),end=hex(end),registers_matched=len(expected)))
    print(json.dumps(dict(sptm_sha256=SHA,boot_sequences=rows,
                         boundary='guest operator defaults only; no Apple key transformation'),indent=2))

if __name__=='__main__':main()

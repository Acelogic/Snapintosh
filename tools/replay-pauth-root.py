#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Compare root PAC-enable policy with the pinned unmodified SPTM instructions."""
from pathlib import Path
import hashlib,json,runpy,subprocess,sys
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'build/test-python-deps'))
from unicorn import Uc,UC_ARCH_ARM64,UC_MODE_ARM,UC_HOOK_CODE
import unicorn.arm64_const as reg

def main():
    im=runpy.run_path(str(ROOT/'tools/sptm-dispatch.py'))['Image'](
        ROOT/'downloads/extracted/j700ap/sptm.t8140.release')
    sha=hashlib.sha256(im.data).hexdigest()
    assert sha=='bd5736d4bd98bceaed2b057ebc09094324bf5149491c2922b329f87db23b1bd0'
    base=0xfffffff027000000;begin=base+0x1006ec;end=base+0x100724
    rows=subprocess.check_output([str(ROOT/'build/test-pauth-domain'),'--root'],text=True).splitlines()
    for line in rows:
        old,flags,want=[int(v,16) for v in line.split()]
        u=Uc(UC_ARCH_ARM64,UC_MODE_ARM);u.mem_map(base,0x200000)
        for _,va,_,off,size in im.segs:u.mem_write(va,im.data[off:off+size])
        state=[old]
        def hook(u,a,size,_):
            if a==begin:
                u.reg_write(reg.UC_ARM64_REG_X9,state[0]);u.reg_write(reg.UC_ARM64_REG_PC,a+4)
            elif a==base+0x100720:
                state[0]=u.reg_read(reg.UC_ARM64_REG_X8);u.reg_write(reg.UC_ARM64_REG_PC,a+4)
        u.hook_add(UC_HOOK_CODE,hook);u.reg_write(reg.UC_ARM64_REG_X28,flags)
        u.emu_start(begin,end,count=100)
        assert u.reg_read(reg.UC_ARM64_REG_PC)==end and state[0]==want,(line,hex(state[0]))
    print(json.dumps(dict(sptm_sha256=sha,cases=len(rows),
                         boundary='pinned control-flow replay with modeled SCTLR_EL1')))

if __name__=='__main__':main()

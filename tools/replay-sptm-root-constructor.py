#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Replay shipped USER_ROOT construction through metadata publication.

Models LDSET and boot-initialized format/ASID limits. This is not a hardware
execution proof or a replay of the later TXM address-space registration.
"""
from pathlib import Path
import hashlib,json,runpy,struct,sys
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'build/test-python-deps'))
from unicorn import Uc,UC_ARCH_ARM64,UC_MODE_ARM,UC_HOOK_CODE
import unicorn.arm64_const as reg

def main():
    im=runpy.run_path(str(ROOT/'tools/sptm-dispatch.py'))['Image'](
        ROOT/'downloads/extracted/j700ap/sptm.t8140.release')
    sha=hashlib.sha256(im.data).hexdigest()
    assert sha=='bd5736d4bd98bceaed2b057ebc09094324bf5149491c2922b329f87db23b1bd0'
    base=0xfffffff027000000;start=base+0xebb50;end=base+0xebc28
    meta=0x1000000;bitmap=base+0x10e080;cases=0
    rows=[(fmt,geometry|controls,asid,None)
          for fmt,geometry in ((0,0),(0,0x20),(1,0),(1,4),(1,0x20))
          for controls in (0,1,2,3,8,9,10,11) for asid in (1,23,65535)]
    rows += [(0,0,0,base+0xebdd4),(0,0x200,23,base+0xebe1c),
             (1,0x24,23,base+0xebe6c),(0,0x80,23,base+0xebe80)]
    for fmt,flags,asid,rejected in rows:
        u=Uc(UC_ARCH_ARM64,UC_MODE_ARM);u.mem_map(base,0x200000);u.mem_map(meta,4096)
        for _,va,_,off,size in im.segs:u.mem_write(va,im.data[off:off+size])
        u.mem_write(base+0x9e218,b'\1');u.mem_write(base+0x9e21c,struct.pack('<I',65536))
        u.mem_write(bitmap,bytes(8192))
        stopped=[]
        def hook(u,pc,size,_):
            if not start<=pc<end:
                stopped.append(pc);u.emu_stop();return
            if pc==base+0xebc04:  # LDSET x11,x12,[x12]
                addr=u.reg_read(reg.UC_ARM64_REG_X12)
                assert bitmap<=addr<bitmap+8192 and not addr&7
                old=struct.unpack('<Q',u.mem_read(addr,8))[0]
                u.mem_write(addr,struct.pack('<Q',old|u.reg_read(reg.UC_ARM64_REG_X11)))
                u.reg_write(reg.UC_ARM64_REG_X12,old);u.reg_write(reg.UC_ARM64_REG_PC,pc+4)
        u.hook_add(UC_HOOK_CODE,hook)
        def call(address):
            stopped.clear();u.reg_write(reg.UC_ARM64_REG_X0,address)
            u.reg_write(reg.UC_ARM64_REG_X1,18)
            u.reg_write(reg.UC_ARM64_REG_X2,(asid<<32)|(flags<<16)|fmt)
            u.emu_start(start,end,count=200)
            return u.reg_read(reg.UC_ARM64_REG_PC)
        want=bytearray(16);struct.pack_into('<H',want,4,asid)
        struct.pack_into('<H',want,10,flags);want[8]=255;want[12]=fmt
        assert call(meta)==(rejected or end),(fmt,flags,asid,stopped)
        assert bytes(u.mem_read(meta,16))==(bytes(16) if rejected else bytes(want))
        cases+=1
        if not rejected:
            assert call(meta+32)==base+0xebebc  # duplicate ASID
            assert bytes(u.mem_read(meta+32,16))==bytes(16)
            cases+=1
    print(json.dumps(dict(sptm_sha256=sha,calls=cases,
        boundary='native constructor control flow and metadata; modeled LDSET and boot globals')))

if __name__=='__main__':main()

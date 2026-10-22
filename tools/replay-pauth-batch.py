#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Replay the pinned batch handler with modeled copy, sysregs and PAC.

This compares actual validation/order/output instructions with C-model results.
It does not validate the cryptographic algorithm or execute the copy subroutine.
"""
from pathlib import Path
import hashlib,json,runpy,struct,subprocess,sys
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'build/test-python-deps'))
from unicorn import Uc,UC_ARCH_ARM64,UC_MODE_ARM,UC_HOOK_CODE
import unicorn.arm64_const as reg
BASE=0xfffffff027000000
RAM=0x80000000;SCRATCH=RAM+0x10000;CPU=RAM+0x20000;STACK=RAM+0x30000
RETURN=RAM+0x3f000

def main():
    im=runpy.run_path(str(ROOT/'tools/sptm-dispatch.py'))['Image'](
        ROOT/'downloads/extracted/j700ap/sptm.t8140.release')
    sha=hashlib.sha256(im.data).hexdigest()
    assert sha=='bd5736d4bd98bceaed2b057ebc09094324bf5149491c2922b329f87db23b1bd0'
    off=im.locate(BASE+0x9e230)[1]
    assert [i for i in range(68) if im.data[off+i*144+0x34]&1]==[11,35]
    vectors={}
    for line in subprocess.check_output([str(ROOT/'build/test-pauth-batch'),'--replay'],text=True).splitlines():
        parts=line.split();vectors[int(parts[0])]=[int(v,16) for v in parts[1:]]
    cases=0
    for count,bad in [(n,None) for n in range(1,65)]+[(64,i) for i in range(64)]+[(0,None),(65,None)]:
        u=Uc(UC_ARCH_ARM64,UC_MODE_ARM);u.mem_map(BASE,0x200000);u.mem_map(RAM,0x40000)
        for _,va,_,off,size in im.segs:u.mem_write(va,im.data[off:off+size])
        u.mem_write(BASE+0x9e1f8,struct.pack('<2Q',RAM,RAM+0x10000))
        u.mem_write(CPU+0x1680,struct.pack('<Q',SCRATCH))
        u.mem_write(SCRATCH,b'\xa5'*4096)
        inputs=b''.join(struct.pack('<QQII',0x100000000+16*i,0x9876000000000000+i,
                                    1 if i==bad else (i&1)*2,0x55aa55aa) for i in range(min(count,64)))
        u.mem_write(RAM+16,inputs)
        state=dict(apctl=0x11,signs=0,copied=False,rejected=False)
        def get(i):return u.reg_read(getattr(reg,'UC_ARM64_REG_X'+str(i)))
        def put(i,v):u.reg_write(getattr(reg,'UC_ARM64_REG_X'+str(i)),v)
        def advance(a):u.reg_write(reg.UC_ARM64_REG_PC,a+4)
        def hook(u,a,size,_):
            if a in (BASE+0x101bf0,BASE+0x101bfc,BASE+0x101c4c,BASE+0x101c94,BASE+0x101b8c):
                state['rejected']=True;u.emu_stop();return
            if a==BASE+0x101a70:advance(a) # PACIBSP prologue modeled as no-op
            elif a==BASE+0x101a94:put(8,1);advance(a)
            elif a==BASE+0x101a9c:put(8,CPU);advance(a)
            elif a==BASE+0x101ae0:
                assert (get(0),get(1),get(2),get(3))==(RAM+16,24,count,512)
                u.mem_write(SCRATCH+512,bytes(u.mem_read(RAM+16,24*count)))
                state['copied']=True;put(0,SCRATCH+512);put(30,a+4);advance(a)
            elif a==BASE+0x101b10:put(9,0x3c0);advance(a)
            elif a in (BASE+0x101b20,BASE+0x101b68):put(9 if a==BASE+0x101b20 else 8,state['apctl']);advance(a)
            elif a in (BASE+0x101b28,BASE+0x101b70):state['apctl']=get(9 if a==BASE+0x101b28 else 8);advance(a)
            elif a in (BASE+0x101b38,BASE+0x101b60):
                assert state['copied'] and state['apctl']==0x13 and bad is None
                key=2 if a==BASE+0x101b38 else 0
                put(17,get(17)^get(16)^0x1234000000000000^key);state['signs']+=1;advance(a)
            elif a==BASE+0x101b88:u.reg_write(reg.UC_ARM64_REG_PC,get(30)) # RETAB epilogue
        u.hook_add(UC_HOOK_CODE,hook);u.reg_write(reg.UC_ARM64_REG_SP,STACK)
        put(0,RAM+16);put(1,count);put(2,0xfeedfacefeedfad3);put(30,RETURN)
        u.emu_start(BASE+0x101a70,RETURN,count=5000)
        reject=bad is not None or count not in range(1,65)
        assert state['rejected']==reject
        if reject:
            assert state['signs']==0 and bytes(u.mem_read(SCRATCH,512))==b'\xa5'*512
        else:
            assert u.reg_read(reg.UC_ARM64_REG_PC)==RETURN and get(0)==SCRATCH+512
            assert state['signs']==count and state['apctl']==0x11
            assert list(struct.unpack('<'+str(count)+'Q',u.mem_read(SCRATCH,count*8)))==vectors[count]
            assert bytes(u.mem_read(SCRATCH+512,count*24))==inputs
        cases+=1
    print(json.dumps(dict(sptm_sha256=sha,cases=cases,copy_frame_types=[11,35],
                         boundary='pinned control flow with modeled copy and PAC; no hardware crypto proof')))

if __name__=='__main__':main()

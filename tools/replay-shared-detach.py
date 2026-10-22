#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Replay the selected SPTM UNMAP_TABLE reference helper without code patches."""
import hashlib,json,runpy,struct,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'build/test-python-deps'))
from unicorn import Uc,UC_ARCH_ARM64,UC_MODE_ARM,UC_HOOK_CODE
import unicorn.arm64_const as reg
BASE=0xfffffff027000000
SHA='bd5736d4bd98bceaed2b057ebc09094324bf5149491c2922b329f87db23b1bd0'
def replay():
    im=runpy.run_path(str(ROOT/'tools/sptm-dispatch.py'))['Image'](
        ROOT/'downloads/extracted/j700ap/sptm.t8140.release')
    assert hashlib.sha256(im.data).hexdigest()==SHA
    u=Uc(UC_ARCH_ARM64,UC_MODE_ARM);u.ctl_set_cpu_model(reg.UC_CPU_ARM64_MAX)
    u.mem_map(BASE,0x200000)
    for _,va,_,off,size in im.segs:u.mem_write(va,im.data[off:off+size])
    parent,child=0x1010000,0x1011000;u.mem_map(0x1000000,0x100000)
    ends={0xed174,0xed180,0xed1b8,0xed1ec,0xed200,0xed22c,0xed27c,0xed2b4,0xed2c0,0xed2d4}
    def hook(uc,address,size,user):
        if address-BASE in ends:uc.emu_stop()
    u.hook_add(UC_HOOK_CODE,hook);rows=[]
    for typ in (18,19,20,21):
        for links in (0,1,2):
            for leaves in (0,1):
                for count in (0,1,1824):
                    a=bytearray(16);a[0]=1;a[2]=typ;field=6 if typ in (18,19) else 8
                    if typ==19:struct.pack_into('<H',a,4,2)
                    struct.pack_into('<H',a,field,count)
                    b=bytearray(16);b[0]=1;b[2]=21;b[4]=3
                    struct.pack_into('<HH',b,6,links,leaves)
                    u.mem_write(parent,bytes(a));u.mem_write(child,bytes(b))
                    u.reg_write(reg.UC_ARM64_REG_X0,parent);u.reg_write(reg.UC_ARM64_REG_X1,child)
                    u.emu_start(BASE+0xed0d0,BASE+0xed300,count=200)
                    pc=u.reg_read(reg.UC_ARM64_REG_PC)-BASE
                    assert pc in ends
                    ok=pc==0xed174;assert ok==(links==1 and leaves==0 and count>0)
                    if ok:
                        struct.pack_into('<H',a,field,count-1);struct.pack_into('<H',b,6,0)
                        assert bytes(u.mem_read(parent,16))==a and bytes(u.mem_read(child,16))==b
                    rows.append(dict(parent_type=typ,links=links,leaves=leaves,parent_children=count,
                        admitted=ok,stop=hex(pc)))
    return dict(sptm_sha256=SHA,cases=rows,
        boundary='unchanged locked reference helper only; descriptor removal, locking and hardware TLBI excluded')
if __name__=='__main__':print(json.dumps(replay(),indent=2))

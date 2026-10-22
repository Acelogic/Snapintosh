#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Execute selected SPTM UNNEST slices unchanged; stop before hardware TLBI."""
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
    u.mem_map(0x1000000,0x100000)
    parent,child,slot,scratch,sp=0x1010000,0x1011000,0x1012000,0x1013000,0x1080000
    def setregs(values):
        for n,value in values.items():u.reg_write(getattr(reg,f'UC_ARM64_REG_X{n}'),value)
        u.reg_write(reg.UC_ARM64_REG_SP,sp)
    stops=set()
    def hook(uc,address,size,user):
        if address-BASE in stops:uc.emu_stop()
    u.hook_add(UC_HOOK_CODE,hook)
    def run(start,ends):
        nonlocal stops
        stops=set(ends);u.emu_start(BASE+start,BASE+0x102cc8,count=1000)
        pc=u.reg_read(reg.UC_ARM64_REG_PC)-BASE
        if pc not in stops:raise ValueError(f'unexpected slice end {pc:x}')
        return pc
    rows=[]
    for typ in (20,21,23):
        for pte in (0,1,2,0x1020003):
            u.mem_write(slot,struct.pack('<Q',pte));u.mem_write(child,bytes(16));u.mem_write(child+2,bytes([typ]))
            u.mem_write(scratch,bytes(32));setregs({19:1,20:slot,27:scratch,28:0,29:sp+0xc0})
            pc=run(0xffc7c,(0xffc94,0xffcd8))
            if pc==0xffc94:
                # ec314 resolves and locks the already supplied typed frame;
                # resume after that helper, with the actual type-policy/CAS.
                setregs({0:child})
                pc=run(0xffc98,(0xffcd0,0xffcd8,0xffd34))
            after=struct.unpack('<Q',u.mem_read(slot,8))[0]
            removed=typ==21 and pte&3==3
            assert after==(0 if removed else pte) and pc!=0xffd34
            assert u.reg_read(reg.UC_ARM64_REG_X28)==int(removed)
            if removed:assert struct.unpack('<Q',u.mem_read(scratch,8))[0]==pte&0xfffffffff000
            rows.append(dict(type=typ,before=hex(pte),after=hex(after),removed=removed))
    refs=[]
    for parent_type in (18,20):
        for links in (2,5,100):
            a=bytearray(16);a[2]=parent_type;field=6 if parent_type==18 else 8
            struct.pack_into('<H',a,field,10)
            b=bytearray(16);b[2]=21;struct.pack_into('<H',b,6,links);struct.pack_into('<H',b,8,7)
            u.mem_write(parent,bytes(a));u.mem_write(child,bytes(b));setregs({0:parent,1:child,2:1})
            run(0xec968,(0xeca8c,0xeca98,0xecab0,0xecae8))
            aa=bytes(u.mem_read(parent,16));bb=bytes(u.mem_read(child,16))
            struct.pack_into('<H',a,field,9);struct.pack_into('<H',b,6,links-1)
            assert aa==a and bb==b
            refs.append(dict(parent_type=parent_type,links_before=links,links_after=links-1,source_leaves_unchanged=7))
    ranges=[]
    for fmt in (0,1):
        shift=12 if fmt else 14;page=1<<shift;span=1<<(2*shift-3);group=0x4000//page
        g=im.pointer(BASE+0x23bc0+8*fmt);sub=im.pointer(g)
        # Materialize the two static data fixups used by the range slice.
        u.mem_write(BASE+0x23bc0+8*fmt,struct.pack('<Q',g))
        u.mem_write(g,struct.pack('<Q',sub))
        maximum=im.word(sub+0x38)>>im.word(g+0x50)
        for va,pages in [(0x180000000,1),(0x180000000+page,1),
            (0x180000000+page,group*span//page),(0x180000000+span,1),
            (0x180000000,0),(0x180000000+1,1),
            (0x180000000,(1<<32)|1),(0x180000000,(1<<(3*shift-6))//page+1)]:
            m=bytearray(16);m[2]=19;m[12]=fmt;u.mem_write(parent,bytes(m))
            setregs({0:va,1:pages,2:maximum,3:parent,4:slot})
            pc=run(0xfcf98,(0xfd054,0xfd070,0xfd0b4,0xfd0ec,0xfd130,0xfd178,0xfd1d0))
            ok=pc==0xfd054;normalized=pages&0xffffffff
            if ok:
                u.mem_write(slot,struct.pack('<Q',normalized));setregs({0:va,19:parent,20:slot})
                pc=run(0xff934,(0xff9a4,0xff9ec,0xffa3c));ok=pc==0xff9a4
            end=va+normalized*page
            expected=bool(normalized and va%page==0 and
                va//(1<<(3*shift-6))==(end-page)//(1<<(3*shift-6)) and
                not ((va//span)|(end//span))&(group-1))
            assert ok==expected,(fmt,va,pages,hex(pc))
            ranges.append(dict(format=fmt,va=hex(va),raw_pages=pages,admitted=ok,
                descriptor_count=((end-page)//span-va//span+1) if ok else None))
    return dict(sptm_sha256=SHA,descriptor_cases=rows,reference_cases=refs,range_cases=ranges,
        boundary='unchanged range, descriptor CAS and reference slices; excludes locks, TLBI and full endpoint execution')
if __name__=='__main__':print(json.dumps(replay(),indent=2))

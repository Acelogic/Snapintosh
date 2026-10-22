#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Run shipped MAP_PAGE policy/selection slices for shared and ordinary roots.

No instructions are replaced. Stops before TXM validation, source CAS and
reference atomics. Typed executable pages still need their TXM lifecycle;
this replay proves admission and descriptor selection, not authentication.
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

def replay(binary=None):
    im=runpy.run_path(str(ROOT/'tools/sptm-dispatch.py'))['Image'](
        ROOT/'downloads/extracted/j700ap/sptm.t8140.release')
    if hashlib.sha256(im.data).hexdigest()!=SHA:raise ValueError('wrong SPTM image')
    u=Uc(UC_ARCH_ARM64,UC_MODE_ARM);u.mem_map(BASE,0x200000)
    for _,va,_,off,size in im.segs:u.mem_write(va,im.data[off:off+size])
    u.mem_map(0x1000000,0x100000)
    root,table,data,slot,fp,sp=0x1010000,0x1011000,0x1012000,0x1013000,0x10800c0,0x1080000
    def setregs(values):
        for n,value in values.items():u.reg_write(getattr(reg,f'UC_ARM64_REG_X{n}'),value)
        u.reg_write(reg.UC_ARM64_REG_SP,sp)
    u.mem_write(fp-0x58,slot.to_bytes(8,'little'))
    stops={0xf9134,0xf973c,0xf979c,0xf9890,0xf9984,0xf98dc,
           0xf92ac,0xf9378,0xf95dc,0xf9374}
    def stop(uc,address,size,user):
        if address-BASE in stops:uc.emu_stop()
    u.hook_add(UC_HOOK_CODE,stop)
    def run(start):
        u.emu_start(BASE+start,BASE+0x102d08,count=1000)
        pc=u.reg_read(reg.UC_ARM64_REG_PC)-BASE
        if pc not in stops:raise ValueError(f'unexpected slice end {pc:x}')
        return pc
    def policy(root_type,table_type,data_type,pte):
        u.mem_write(root+2,bytes([root_type]));u.mem_write(table+2,bytes([table_type]))
        u.mem_write(data+2,bytes([data_type]));u.mem_write(slot,bytes(8))
        setregs({9:data_type,19:root,20:pte,21:BASE+0x9e230,24:table,26:0,27:data,29:fp})
        pc=run(0xf9080)
        return pc==0xf9134,pc
    admission=[]
    for root_type,table_type in ((19,21),(18,20)):
        for data_type in (11,14,17,25,35):
            for cls in (3,7,11,13,15):
                for ng in (0,1):
                    pte=0x94663c000|0x603|((cls&12)<<4)|((cls&3)<<53)|(ng<<11)
                    ok,pc=policy(root_type,table_type,data_type,pte)
                    admission.append(dict(root=root_type,table=table_type,data=data_type,
                        selector=cls,ng=ng,admitted=ok,stop=hex(BASE+pc)))
    captured=next(r for r in admission if (r['root'],r['table'],r['data'],r['selector'],r['ng'])==(19,21,11,15,0))
    assert captured['admitted']
    assert not next(r for r in admission if (r['root'],r['table'],r['data'],r['selector'],r['ng'])==(18,20,11,15,0))['admitted']
    assert not any(r['admitted'] for r in admission if r['table']==21 and r['data'] not in (11,14))
    rows=[]
    for data_type,classes in ((11,(7,15)),(14,(13,15))):
        for new_class in classes:
            for ng in (0,1):
                for history in ((0,1) if data_type==11 else (0,)):
                    wanted=0x94663c000|0x603|((new_class&12)<<4)|((new_class&3)<<53)|(ng<<11)|(history<<59)
                    for old_class in (0,)+classes:
                        for old_flags in (0,1<<58,1<<59) if data_type==11 else (0,1<<58):
                            old=(wanted&~(0xc0|(3<<53)|(3<<58)))|((old_class&12)<<4)|((old_class&3)<<53)|old_flags if old_class else 0
                            # Include differing AF/nG in the template: same-PA
                            # MAP preserves the old unselected attributes.
                            for toggle in (0,0xc00):
                                requested=wanted^toggle
                                setregs({20:requested,21:BASE+0x9e230,22:0x1d2b3c000,
                                    23:19,25:requested&0x0000fffffffff000,26:old,28:new_class,29:fp})
                                u.mem_write(sp+0x60,data.to_bytes(8,'little'))
                                pc=run(0xf9230)
                                status=1 if pc==0xf9378 else 6 if pc==0xf95dc else 0
                                selected=old if status else u.reg_read(reg.UC_ARM64_REG_X27)
                                row=dict(data=data_type,old=f'{old:016x}',requested=f'{requested:016x}',
                                    next=f'{selected:016x}',result=status,rejected=pc==0xf9374)
                                if binary:
                                    p=subprocess.run([binary,'--pte',row['old'],row['requested']],capture_output=True,text=True,check=True)
                                    c_status,c_result,c_next=p.stdout.split()
                                    if bool(int(c_status))!=row['rejected'] or (not row['rejected'] and (int(c_result)!=status or c_next!=row['next'])):
                                        raise ValueError(f'C/binary selection mismatch {row}: {p.stdout}')
                                rows.append(row)
    deltas=[]
    for data_type,selector in ((11,7),(11,15),(14,13),(14,15)):
        u.mem_write(table+2,bytes([21]));u.mem_write(data+2,bytes([data_type]))
        pte=0x94663c603|((selector&12)<<4)|((selector&3)<<53)
        for old,new in ((0,pte),(pte,0),(pte,pte)):
            setregs({0:table,1:data,2:old,3:new})
            u.emu_start(BASE+0xecb9c,BASE+0xecd00,count=1000)
            assert u.reg_read(reg.UC_ARM64_REG_PC)==BASE+0xecd00
            def signed(n):
                v=u.reg_read(getattr(reg,f'UC_ARM64_REG_W{n}'));return v if v<1<<31 else v-(1<<32)
            ro,other=signed(15),signed(16)
            sign=1 if not old else -1 if not new else 0
            assert [ro,other]==([sign,0] if selector==15 else [0,sign])
            deltas.append(dict(table_type=21,data_type=data_type,selector=selector,
                old=hex(old),new=hex(new),ro_delta=ro,other_delta=other))
    return dict(sptm_sha256=SHA,policy_cases=admission,captured=captured,selection_cases=rows,
        shared_reference_deltas=deltas,
        c_cases_matched=len(rows) if binary else None,
        boundary='policy/selection only; before TXM validation, CAS, references and TLBI')

if __name__=='__main__':
    print(json.dumps(replay(sys.argv[1] if len(sys.argv)==2 else None),indent=2))

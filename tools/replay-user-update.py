#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Bounded replay of Apple's selected UPDATE_DISJOINT descriptor helper.

The real shipped helper runs against DEFAULT11/table20 scratch metadata. Stop
before its epilogue or deferred-revocation bookkeeping call; no instructions
are replaced. This proves descriptor selection, not TLBI/atomic execution.
"""
import hashlib
import json
from pathlib import Path
import runpy
import sys
import subprocess

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'build/test-python-deps'))
from unicorn import Uc,UC_ARCH_ARM64,UC_MODE_ARM,UC_HOOK_CODE
import unicorn.arm64_const as reg
BASE=0xfffffff027000000
SHA='bd5736d4bd98bceaed2b057ebc09094324bf5149491c2922b329f87db23b1bd0'

def replay(kernel=False,templates_only=False):
    im=runpy.run_path(str(ROOT/'tools/sptm-dispatch.py'))['Image'](
        ROOT/'downloads/extracted/j700ap/sptm.t8140.release')
    if hashlib.sha256(im.data).hexdigest()!=SHA:raise ValueError('wrong SPTM image')
    u=Uc(UC_ARCH_ARM64,UC_MODE_ARM);u.mem_map(BASE,0x200000)
    for _,va,_,off,size in im.segs:u.mem_write(va,im.data[off:off+size])
    u.mem_map(0x1000000,0x100000)
    context,data,table,out=0x1010000,0x1011000,0x1012000,0x1013000
    u.mem_write(context,data.to_bytes(8,'little')+table.to_bytes(8,'little'))
    u.mem_write(data+2,bytes([11]));u.mem_write(table+2,bytes([20]))
    def stop(uc,address,size,user):
        if address in (BASE+0xfd8f0,BASE+0xfda34,BASE+0xfd904,BASE+0xfd94c):uc.emu_stop()
    u.hook_add(UC_HOOK_CODE,stop)
    rows=[]
    classes=(3,11,19,27) if kernel else (7,15,23,31)
    for old_class in classes:
        for requested_class in classes:
            for options in ((0xa,2,0x802,0xc0a,0x40a) if kernel else (2,0x802,0xc0a,0x40a)):
                for old_af,new_af in ((1,1),(0,1),(1,0)):
                    def pte(cls,af):
                        return (0x94280c000|3|(0 if kernel else 0x800)|0x200|(af<<10)|
                                ((cls&12)<<4)|((cls&3)<<53)|((cls>>4)<<59))
                    old,requested=pte(old_class,old_af),pte(requested_class,new_af)
                    if templates_only:requested&=~0x0000fffffffff000
                    for n,value in enumerate((context,old,requested,options,out)):
                        u.reg_write(getattr(reg,f'UC_ARM64_REG_X{n}'),value)
                    u.reg_write(reg.UC_ARM64_REG_SP,0x1080000)
                    try:
                        u.emu_start(BASE+0xfd544,BASE+0xfd900,count=1000)
                    except Exception as exc:
                        raise ValueError(f'classes {old_class}->{requested_class}, options {options:x}, '
                                         f'PC {u.reg_read(reg.UC_ARM64_REG_PC):x}: {exc}') from exc
                    pc=u.reg_read(reg.UC_ARM64_REG_PC)
                    if pc not in (BASE+0xfd8f0,BASE+0xfda34,BASE+0xfd904,BASE+0xfd94c):
                        raise ValueError(f'unexpected helper end {pc:x}')
                    new=int.from_bytes(u.mem_read(out,8),'little')
                    rows.append(dict(old_class=old_class,requested_class=requested_class,
                        options=options,old_af=old_af,requested_af=new_af,
                        old=f'{old:016x}',requested=f'{requested:016x}',new=f'{new:016x}',
                        deferred_revocation=pc==BASE+0xfda34,
                        rejected=pc in (BASE+0xfd904,BASE+0xfd94c)))
    if kernel:
        captured=next(r for r in rows if (r['old_class'],r['requested_class'],r['options'],
                                        r['old_af'],r['requested_af'])==(3,27,0xa,1,1))
        assert captured['new']=='086000094280c683'
        control=next(r for r in rows if (r['old_class'],r['requested_class'],r['options'],
                                        r['old_af'],r['requested_af'])==(27,3,0x40a,1,1))
        assert control['new']==control['old']
    else:
        captured=next(r for r in rows if (r['old_class'],r['requested_class'],r['options'],
                                    r['old_af'],r['requested_af'])==(31,7,0xc0a,1,1))
        assert captured['new']=='006000094280ce43' and not captured['deferred_revocation']
        control=next(r for r in rows if (r['old_class'],r['requested_class'],r['options'],
                                   r['old_af'],r['requested_af'])==(31,7,0x40a,1,1))
        assert control['new']==control['old']
    # Unchanged non-NX-domain classes (page aging on TPRO class9 in type17 and
    # executable class13/15 in type14; A16 live request options 0x10a).
    if not kernel and not templates_only:
        for dtype,cls in ((17,9),(14,13),(14,15)):
            u.mem_write(data+2,bytes([dtype]))
            for options in (2,8,0xa,0x10a,0x90a,0x802,0x40a):
                for old_af,new_af in ((1,1),(0,1),(1,0),(0,0)):
                    old=(0x94280c000|3|0x800|0x200|(old_af<<10)|((cls&12)<<4)|((cls&3)<<53))
                    requested=(old&~0x400)|(new_af<<10)
                    for n,value in enumerate((context,old,requested,options,out)):
                        u.reg_write(getattr(reg,f'UC_ARM64_REG_X{n}'),value)
                    u.reg_write(reg.UC_ARM64_REG_SP,0x1080000)
                    u.emu_start(BASE+0xfd544,BASE+0xfd900,count=1000)
                    pc=u.reg_read(reg.UC_ARM64_REG_PC)
                    if pc not in (BASE+0xfd8f0,BASE+0xfda34,BASE+0xfd904,BASE+0xfd94c):
                        raise ValueError(f'unexpected helper end {pc:x}')
                    new=int.from_bytes(u.mem_read(out,8),'little')
                    rows.append(dict(old_class=cls,requested_class=cls,data_type=dtype,
                        options=options,old_af=old_af,requested_af=new_af,
                        old=f'{old:016x}',requested=f'{requested:016x}',new=f'{new:016x}',
                        deferred_revocation=pc==BASE+0xfda34,
                        rejected=pc in (BASE+0xfd904,BASE+0xfd94c)))
        u.mem_write(data+2,bytes([11]))
        live=next(r for r in rows if r.get('data_type')==17 and r['options']==0x10a and
                  (r['old_af'],r['requested_af'])==(1,0))
        assert not live['rejected'] and int(live['new'],16)==int(live['old'],16)&~0x400
    # Match another original-helper execution whose input is the selected
    # output. This checks repeated descriptor selection, not batch ordering.
    lookup={(r['old'],r['requested'],r['options']):r for r in rows}
    repeats=[]
    for row in rows:
        if row['rejected']:continue
        again=lookup.get((row['new'],row['requested'],row['options']))
        if again is None:continue
        assert not again['rejected'] and again['new']==row['new'],(row,again)
        repeats.append((row,again))
    return dict(sptm_sha256=SHA,helper='fffffff0270fd544',cases=rows,
                idempotent_repeat_comparisons=len(repeats),
                captured=captured,without_fault_option=control,
                boundary='descriptor helper only; no source CAS, ref atomics, TLBI or deferred bookkeeping')

if __name__=='__main__':
    result=replay(kernel='--check-kernel-c' in sys.argv,templates_only='--region-templates' in sys.argv)
    if len(sys.argv)>=3 and sys.argv[1] in ('--check-c','--check-kernel-c'):
        for row in result['cases']:
            run=subprocess.run([sys.argv[2],'--pte',row['old'],row['requested'],f"{row['options']:x}"],
                               check=True,capture_output=True,text=True)
            status,value=run.stdout.split()
            if bool(int(status))!=row['rejected'] or (not row['rejected'] and value!=row['new']):
                raise ValueError(f'C/binary disagreement: {row}; C={run.stdout.strip()}')
        result['c_cases_matched']=len(result['cases'])
    print(json.dumps(result,indent=2))

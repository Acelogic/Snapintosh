#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Run key-bank assembly with modeled privileged registers; no hardware proof."""
from pathlib import Path
import json,struct,subprocess,sys
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'build/test-python-deps')]
from capstone import Cs,CS_ARCH_ARM64,CS_MODE_ARM
from unicorn import Uc,UC_ARCH_ARM64,UC_MODE_ARM,UC_HOOK_CODE
import unicorn.arm64_const as reg
LLVM=Path('/opt/homebrew/opt/llvm/bin')
BASE=0x1000000;BUFFER=BASE+0x10000;RETURN=BASE+0x1f000
KEYS=[k+'key'+half+'_el1' for k in ('apia','apib','apda','apdb','apga') for half in ('lo','hi')]

def main():
    obj=ROOT/'build/pauth-switch-test.o';out=ROOT/'build/pauth-switch-test.bin'
    subprocess.run([str(LLVM/'clang'),'--target=aarch64-none-elf','-c',str(ROOT/'compat/pauth-switch.S'),'-o',str(obj)],check=True)
    subprocess.run([str(LLVM/'llvm-objcopy'),'-O','binary','--only-section=.text',str(obj),str(out)],check=True)
    symbols={n:int(a,16) for a,_,n in (l.split() for l in subprocess.check_output([str(LLVM/'llvm-nm'),'--defined-only',str(obj)],text=True).splitlines())}
    blob=out.read_bytes();ins={i.address:i for i in Cs(CS_ARCH_ARM64,CS_MODE_ARM).disasm(blob,BASE)}
    cases=0
    overrides=[{},dict(currentel=4),dict(daif=0),dict(hcr_el2=1<<34),dict(hcr_el2=1<<41),dict(sctlr_el1=0x2000)]
    enables=[sum((1<<bit) for i,bit in enumerate((13,27,30,31)) if mask&(1<<i)) for mask in range(16)]+[1]
    for enable in enables:
      for override in overrides:
       for corrupt in (None,*KEYS,'hcr_el2','sctlr_el1') if not override and enable==0xc8002000 else (None,):
        uc=Uc(UC_ARCH_ARM64,UC_MODE_ARM);uc.mem_map(BASE,0x20000);uc.mem_write(BASE,blob)
        initial=dict(currentel=8,daif=0x3c0,hcr_el2=0x88000019,sctlr_el1=0x30501805)
        initial.update({k:0xfef0000+i for i,k in enumerate(KEYS)});initial.update(override)
        regs=initial.copy();writes=[];phase='enter'
        guest=tuple(0x1234000+i for i in range(10));state=bytearray(256)
        state[:80]=struct.pack('<10Q',*guest);struct.pack_into('<Q',state,176,enable)
        uc.mem_write(BUFFER-16,b'\xa5'*16+state+b'\xa5'*16)
        def get(n):return 0 if n=='xzr' else uc.reg_read(getattr(reg,'UC_ARM64_REG_'+n.upper()))
        def put(n,v):uc.reg_write(getattr(reg,'UC_ARM64_REG_'+n.upper()),v)
        def hook(u,address,size,_):
            a=ins[address];parts=a.op_str.split(', ')
            if a.mnemonic=='mrs':
                dest,name=parts;value=regs[name]
                if phase=='leave' and name==corrupt:value^=1
                put(dest,value)
            elif a.mnemonic=='msr':
                name,src=parts;regs[name]=get(src);writes.append((name,regs[name]))
            else:return
            put('pc',address+size)
        uc.hook_add(UC_HOOK_CODE,hook)
        def call(name):
            put('sp',BASE+0x18000);put('x30',RETURN);put('x0',BUFFER)
            for i in range(19,30):put('x'+str(i),0xabc000+i)
            uc.emu_start(BASE+symbols[name],RETURN,count=1000)
            assert get('pc')==RETURN and get('sp')==BASE+0x18000
            assert all(get('x'+str(i))==0xabc000+i for i in range(19,30))
            return get('x0')
        rejected=bool(override) or enable==1
        assert call('pauth_switch_enter')==int(rejected)
        if rejected:assert regs==initial and not writes
        else:
            assert tuple(regs[k] for k in KEYS)==guest
            assert regs['hcr_el2']==initial['hcr_el2']|(1<<41)
            assert regs['sctlr_el1']==initial['sctlr_el1']|enable
            phase='leave';assert call('pauth_switch_leave')==int(bool(corrupt))
            assert regs==initial
            state=bytes(uc.mem_read(BUFFER,256))
            assert struct.unpack_from('<Q',state,184)[0]==int(bool(corrupt))
            assert state[80:160]==(struct.pack('<10Q',*(initial[k] for k in KEYS)) if corrupt else bytes(80))
            assert struct.unpack_from('<2Q',state,192)==(1,int(not corrupt))
            expected=7 if not corrupt else 7^({'hcr_el2':2,'sctlr_el1':4}.get(corrupt,1))
            assert struct.unpack_from('<2Q',state,208)==(int(bool(corrupt)),expected)
            if corrupt:
                corrupt=None;assert call('pauth_switch_leave')==0
                state=bytes(uc.mem_read(BUFFER,256))
                assert state[80:160]==bytes(80) and struct.unpack_from('<Q',state,184)[0]==0
                assert struct.unpack_from('<2Q',state,192)==(1,1)
            writes.clear();assert call('pauth_switch_leave')==0 and not writes
        assert bytes(uc.mem_read(BUFFER-16,16))==bytes([0xa5])*16
        assert bytes(uc.mem_read(BUFFER+256,16))==bytes([0xa5])*16
        cases+=1
    print(json.dumps(dict(cases=cases,boundary='assembly control flow and restoration with modeled registers')))

if __name__=='__main__':main()

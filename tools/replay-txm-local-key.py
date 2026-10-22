#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Compare the pinned TXM26 dispatcher/setter with the portable service."""
import hashlib
import json
from pathlib import Path
import runpy
import struct
import subprocess
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'build/test-python-deps'))
from unicorn import Uc,UC_ARCH_ARM64,UC_MODE_ARM,UC_HOOK_CODE
import unicorn.arm64_const as reg


def replay(binary):
    raw=(ROOT/'downloads/extracted/j700ap/txm.macosx.release').read_bytes()
    digest=hashlib.sha256(raw).hexdigest()
    assert digest=='b746aaba8d3c0874911a53bf51f9591854783aa6e7b02f25494c2d782eecd246'
    h=runpy.run_path(str(ROOT/'tools/kc-disas.py'))
    segments=h['segments'](raw)
    u=Uc(UC_ARCH_ARM64,UC_MODE_ARM);u.ctl_set_cpu_model(reg.UC_CPU_ARM64_MAX)
    u.mem_map(0xfffffff017000000,0x200000)
    for _,va,_,off,size in segments:u.mem_write(va,raw[off:off+size])
    u.mem_map(0x1000000,0x100000)
    source,reply,stack=0x1040000,0x1050000,0x10e0000
    state=0xfffffff017090cac
    outcome=None
    def put(n,v):u.reg_write(getattr(reg,f'UC_ARM64_REG_X{n}'),v)
    def get(n):return u.reg_read(getattr(reg,f'UC_ARM64_REG_X{n}'))
    def hook(uc,address,size,user):
        nonlocal outcome
        if address==0xfffffff01703ed54:
            outcome=('return',get(0));uc.emu_stop();return
        if address==0xfffffff01703d818:
            outcome=('panic',get(0));uc.emu_stop();return
        word,=struct.unpack('<I',uc.mem_read(address,4))
        if word==0xd503237f:uc.reg_write(reg.UC_ARM64_REG_PC,address+4)
        elif word==0xd65f0fff:uc.reg_write(reg.UC_ARM64_REG_PC,get(30))
    u.hook_add(UC_HOOK_CODE,hook)
    u.reg_write(reg.UC_ARM64_REG_CPACR_EL1,3<<20)
    def invoke(value):
        nonlocal outcome
        outcome=None
        u.mem_write(source,value);u.mem_write(reply,b'\xa5'*80)
        u.reg_write(reg.UC_ARM64_REG_SP,stack)
        put(19,reply);put(20,source);put(26,26)
        u.emu_start(0xfffffff01703f070,0,count=1000)
        assert outcome is not None,'dispatcher did not finish'
        return outcome
    records=[bytes(97),b'\xff'*97,bytes(range(97))]
    records += [bytes((i+seed)&255 for i in range(97)) for seed in (1,31,127,255)]
    for value in records:
        u.mem_write(state,bytes(99))
        assert invoke(value)==('return',0)
        assert bytes(u.mem_read(state,99))==b'\x01\x01'+value
        assert struct.unpack('<Q',u.mem_read(reply+8,8))[0]==0
        assert struct.unpack('<Q',u.mem_read(reply+24,8))[0]==0
        assert invoke(b'Z'*97)==('panic',0x55)
        assert bytes(u.mem_read(state+2,97))==value
        p=subprocess.run([binary,'--record',value.hex()],capture_output=True,text=True,check=True)
        c_value,duplicate=p.stdout.split()
        assert bytes.fromhex(c_value)==value and duplicate=='duplicate-stopped'
    return dict(txm_sha256=digest,records=len(records),native_calls=2*len(records),
                boundary='original dispatch/copy/one-time CAS run; PAC returns modeled; native duplicate panic becomes monitor stop')


if __name__=='__main__':
    print(json.dumps(replay(sys.argv[1] if len(sys.argv)>1 else str(ROOT/'build/test-txm-local-key'))))

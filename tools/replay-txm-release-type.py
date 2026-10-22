#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Execute the shipped release-type wrapper/setter and compare the C service.

PAC call/return mechanics and the error logger are modeled. The real copy,
truncation, type checks, uncontended locks, set-once state and return code run
from the pinned TXM image. This is not native hardware/PAC qualification.
"""
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
    if digest!='b746aaba8d3c0874911a53bf51f9591854783aa6e7b02f25494c2d782eecd246':
        raise ValueError('wrong TXM image')
    h=runpy.run_path(str(ROOT/'tools/kc-disas.py'))
    segments=h['segments'](raw)
    q=lambda va:struct.unpack_from('<Q',raw,h['locate'](segments,va)[1])[0]
    assert q(0xfffffff01702bea0)&0xffffffff==0x68f88
    assert q(0xfffffff01701df18)==64
    u=Uc(UC_ARCH_ARM64,UC_MODE_ARM);u.ctl_set_cpu_model(reg.UC_CPU_ARM64_MAX)
    u.mem_map(0xfffffff017000000,0x200000)
    for _,va,_,off,size in segments:u.mem_write(va,raw[off:off+size])
    u.mem_map(0x1000000,0x100000)
    expert,state,subsystem,source,stack,stop=0x1010000,0x1020000,0x1030000,0x1040000,0x10e0000,0x10f0000
    def put(n,v):u.reg_write(getattr(reg,f'UC_ARM64_REG_X{n}'),v)
    def get(n):return u.reg_read(getattr(reg,f'UC_ARM64_REG_X{n}'))
    def memq(at,value):u.mem_write(at,struct.pack('<Q',value))
    memq(0xfffffff017091c00,expert)
    u.mem_write(expert+8,struct.pack('<I',0x7472786d))
    memq(expert+0x10,subsystem);memq(expert+0x18,state)
    memq(expert+0xf0,0xfffffff01706f460)
    pac=logs=0
    def hook(uc,address,size,user):
        nonlocal pac,logs
        word,=struct.unpack('<I',uc.mem_read(address,4))
        if word==0xd503237f: # PACIBSP: model signing of our own return address.
            pac+=1;uc.reg_write(reg.UC_ARM64_REG_PC,address+4)
        elif word==0xd65f0fff: # RETAB: modeled matched authenticated return.
            pac+=1;uc.reg_write(reg.UC_ARM64_REG_PC,get(30))
        elif address==0xfffffff017072390: # BRAA x16,x17: installed fixture callback.
            assert get(16)==0xfffffff01706f460
            pac+=1;uc.reg_write(reg.UC_ARM64_REG_PC,get(16))
        elif address==0xfffffff0170718e8:
            logs+=1;uc.reg_write(reg.UC_ARM64_REG_PC,get(30))
    u.hook_add(UC_HOOK_CODE,hook)
    u.reg_write(reg.UC_ARM64_REG_CPACR_EL1,3<<20)
    def invoke(data):
        u.mem_write(source,data)
        u.reg_write(reg.UC_ARM64_REG_SP,stack)
        put(0,0);put(1,source);put(2,64);put(30,stop)
        try:u.emu_start(0xfffffff01706cf88,stop,count=20000)
        except Exception as error:
            raise ValueError(f'replay failed at {u.reg_read(reg.UC_ARM64_REG_PC):x}: {error}') from error
        if u.reg_read(reg.UC_ARM64_REG_PC)!=stop:raise ValueError('handler did not return')
        result=get(0)
        assert bytes(u.mem_read(state+0x31,2))==b'\0\0'
        value=bytes(u.mem_read(state+0x160,64))
        marker,=struct.unpack('<Q',u.mem_read(state+0x158,8))
        assert marker==state+0x160
        # Execute the actual dispatcher errno/domain packing slice.
        put(0,result)
        u.emu_start(0xfffffff01704139c,0xfffffff0170413b0,count=20)
        status=get(8)|get(9)
        return status,value
    records=[b'User'+bytes(60),bytes(64),b'A'*64]
    for end in range(65):
        row=bytearray((0x80+i for i in range(64)))
        if end<64:row[end]=0
        records.append(bytes(row))
    calls=0
    for data in records:
        u.mem_write(state,bytes(0x300))
        status,value=invoke(data);calls+=1
        assert status==0
        duplicate,again=invoke(b'Z'*64);calls+=1
        assert duplicate==(37<<32)|5 and again==value
        p=subprocess.run([binary,'--record',data.hex()],capture_output=True,text=True,check=True)
        c_status,c_value,c_duplicate=p.stdout.split()
        assert (int(c_status),bytes.fromhex(c_value),int(c_duplicate))==(status,value,duplicate)
    return dict(txm_sha256=digest,records=len(records),handler_calls=calls,
                modeled_pac_steps=pac,modeled_error_logs=logs,
                boundary='pinned wrapper, copying, locks and set-once state; PAC and error logger modeled')


if __name__=='__main__':
    print(json.dumps(replay(sys.argv[1] if len(sys.argv)>1 else str(ROOT/'build/test-txm-release-type'))))

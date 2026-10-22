#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Replay the native EP0 notification route, then the original manager gate.

Thread-call scheduling and IOKit are explicit fixtures. No notification is
sent to hardware and no SEP firmware, discovery or service is executed.
"""
from pathlib import Path
import json
import runpy
import struct
import subprocess
import sys
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'build/test-python-deps'))
from capstone import Cs,CS_ARCH_ARM64,CS_MODE_ARM
from unicorn import UC_PROT_READ,UC_PROT_EXEC
import unicorn.arm64_const as reg
s=runpy.run_path(str(ROOT/'tools/replay-sep-startup.py'))
START=0xfffffe00099d1270
ASYNC=0xfffffe00099d15b0
NOTIFY=0xfffffe00099b8e78
DATA,OBJECT,ARG,RETURN=(s[k] for k in ('DATA','OBJECT','ARG','RETURN'))


class Control(s['Startup']):
    def __init__(self,image):
        super().__init__(image)
        base=START&~0xfff;size=0x2000;off=image.va2off(base)
        code=image.data[off:off+size]
        self.u.mem_map(base,size,UC_PROT_READ|UC_PROT_EXEC);self.u.mem_write(base,code)
        self.instructions.update({i.address:i for i in Cs(CS_ARCH_ARM64,CS_MODE_ARM).disasm(code,base)})
        # Map the actual tail-call destination so the hook can stop before
        # executing the thread-call scheduling API.
        base=0xfffffe00099de000;off=image.va2off(base)
        self.u.mem_map(base,0x1000,UC_PROT_READ|UC_PROT_EXEC)
        self.u.mem_write(base,image.data[off:off+0x1000])

    def hook(self,u,pc,size,unused):
        if pc==NOTIFY:
            assert u.reg_read(reg.UC_ARM64_REG_X0)==OBJECT
            self.finish('notify-active');return
        if pc==0xfffffe00099b935c:
            self.finish('notify-other-state');return
        if pc==0xfffffe00099de36c:
            assert u.reg_read(reg.UC_ARM64_REG_X0)==OBJECT+0x2000
            assert u.reg_read(reg.UC_ARM64_REG_X1)==0
            self.finish('scheduled-active');return
        ins=self.instructions.get(pc)
        if ins is None:raise AssertionError(f'unmodeled native control exit {pc:x}')
        if ins.mnemonic in ('pacibsp','autibsp','autda','xpacd','pacia'):
            u.reg_write(reg.UC_ARM64_REG_PC,pc+4);return
        if ins.mnemonic=='retab':self.finish('return');return
        if pc==0xfffffe00099d12f8:
            self.call(pc,'unknown-tag',0);return
        if pc==0xfffffe00099d14fc:
            word=struct.unpack('<Q',u.mem_read(u.reg_read(reg.UC_ARM64_REG_X1),8))[0]
            self.sent.append(hex(word));self.call(pc,'send-control-fixture');return
        if ins.mnemonic=='bl' and ins.op_str=='#0xfffffe00099ddbac':
            self.call(pc,'log');return
        if ins.mnemonic=='bl' and ins.op_str=='#0xfffffe00099de1ec':
            self.call(pc,'time-fixture',1234);return
        if ins.mnemonic in ('bl','blr','blraa','braa','brk'):
            raise AssertionError(f'unmodeled control call {pc:x}: {ins.mnemonic} {ins.op_str}')

    def execute(self,start,x0):
        for n in range(31):self.u.reg_write(getattr(reg,f'UC_ARM64_REG_X{n}'),0)
        self.u.reg_write(reg.UC_ARM64_REG_X0,x0)
        self.u.reg_write(reg.UC_ARM64_REG_X2,ARG)
        self.u.reg_write(reg.UC_ARM64_REG_X30,RETURN)
        self.u.reg_write(reg.UC_ARM64_REG_SP,DATA+0x1f000)
        self.stop=None
        self.u.emu_start(start,RETURN,count=5000)
        assert self.stop is not None,'control replay budget exhausted'

    def message(self,word):
        self.u.mem_write(DATA,bytes(0x20000));self.events=[];self.sent=[]
        self.put(DATA+0x70,'<Q',OBJECT);self.put(DATA+0xb0,'<Q',OBJECT+0x2000)
        self.put(DATA+0x78,'<Q',OBJECT+0x3000)
        self.put(DATA,'<Q',s['VTABLE'])
        self.put(OBJECT+0x3000,'<Q',s['VTABLE'])
        self.put(ARG,'<Q',word)
        self.execute(START,DATA)
        route=self.stop
        if route=='scheduled-active':self.execute(ASYNC,OBJECT)
        return dict(route=route,stop=self.stop,sent=self.sent,
                    info_present=self.u.mem_read(DATA+0xc2,1)[0],
                    info=struct.unpack('<I',self.u.mem_read(DATA+0xc4,4))[0])


def main():
    image=runpy.run_path(str(ROOT/'tools/kc-xref.py'))['Kernelcache'](
        ROOT/'downloads/extracted/j700ap/kernelcache.release.mac17p')
    control=Control(image);manager=s['Startup'](image);checks=0;traces=[]
    for opcode in range(256):
        out=control.message(opcode<<16)
        expected=('notify-active' if opcode in (0xd,0x15) else
                  'notify-other-state' if opcode==0x10 else 'return')
        assert out['stop']==expected,(opcode,out)
        if opcode in (0xd,0x15):
            active=manager.run('active',state=5,power=2)
            assert active['state']==8 and 'cancel-startup-timer' in active['events']
            assert 'notify-active' in active['events']
            traces.append(dict(word=hex(opcode<<16),dispatch=out,manager=active))
        if opcode==0x11:assert out['sent']==['0x120000']
        checks+=1
    for endpoint in (1,31,0xfd,0xff):
        assert control.message(0xd0000|endpoint)['stop']=='return';checks+=1
    for tag in (1,2,255):
        out=control.message(0xd0000|tag<<8)
        assert out['stop']=='return' and not out['info_present'];checks+=1
    for info in (0,1,0xffffffff):
        out=control.message(info<<32|0x290000)
        assert out['info_present']==1 and out['info']==info;checks+=1
    producer=subprocess.run([str(ROOT/'build/test-sep-service'),'--notification',
        str(ROOT/'build/sep-rom-slot-live-20260922-sep-shared.bin')],capture_output=True,text=True,check=True)
    word=int(producer.stdout,16);assert word==0xd0000
    out=control.message(word);assert out['route']=='scheduled-active' and out['stop']=='notify-active'
    active=manager.run('active',state=5,power=2)
    assert active['state']==8 and 'cancel-startup-timer' in active['events'];checks+=1
    traces.append(dict(producer='C resource-backed frontend',word=hex(word),dispatch=out,manager=active))
    print(json.dumps(dict(kernel_sha256=s['KERNEL_SHA'],checks=checks,traces=traces,
        boundary='original EP0 dispatch, asynchronous callback and separate manager action; scheduling/IOKit fixtures; no live notification or SEP service execution'),indent=2))


if __name__=='__main__':main()

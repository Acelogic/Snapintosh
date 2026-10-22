#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Run native SEP OOL setters with explicit memory-object/transaction fixtures.

This proves message construction and native early returns only. No buffer
admission, endpoint publication, DMA, reply backend or physical OOL qualification.
"""
from pathlib import Path
import json
import runpy
import struct

ROOT=Path(__file__).resolve().parents[1]
c=runpy.run_path(str(ROOT/'tools/replay-sep-control-startup.py'))
s=c['s'];reg=c['reg'];DATA=c['DATA'];OBJECT=c['OBJECT'];RETURN=c['RETURN']
SEND=0xfffffe00099d1c34
RECV=0xfffffe00099d1d90
BUFFER=DATA+0xc000


class OOL(c['Control']):
    def hook(self,u,pc,size,unused):
        ins=self.instructions.get(pc)
        if ins is None:raise AssertionError(f'unmodeled OOL exit {pc:x}')
        if ins.mnemonic in ('pacibsp','autibsp','autda','xpacd','pacia'):
            u.reg_write(reg.UC_ARM64_REG_PC,pc+4);return
        if ins.mnemonic=='retab':
            self.finish('return');return
        descriptors=(0xfffffe00099d1c8c,0xfffffe00099d1de8)
        lengths=(0xfffffe00099d1cbc,0xfffffe00099d1e18)
        addresses=(0xfffffe00099d1cf8,0xfffffe00099d1e54)
        if pc in descriptors:
            assert u.reg_read(reg.UC_ARM64_REG_X0)==BUFFER
            self.call(pc,'buffer-descriptor-fixture',BUFFER+0x100);return
        if pc in lengths:
            assert u.reg_read(reg.UC_ARM64_REG_X0)==BUFFER+0x100
            self.call(pc,'descriptor-length-fixture',self.length);return
        if pc in addresses:
            assert u.reg_read(reg.UC_ARM64_REG_X0)==BUFFER
            self.call(pc,'buffer-iova-fixture',self.iova);return
        if pc in (0xfffffe00099d1d20,0xfffffe00099d1d4c,
                  0xfffffe00099d1e7c,0xfffffe00099d1ea8):
            address=u.reg_read(reg.UC_ARM64_REG_X1)
            assert u.reg_read(reg.UC_ARM64_REG_X0)==DATA
            assert u.reg_read(reg.UC_ARM64_REG_X3)==0
            timeout=u.reg_read(reg.UC_ARM64_REG_X2)
            assert struct.unpack('<I',u.mem_read(timeout,4))[0]==15000
            self.sent.append(struct.unpack('<Q',u.mem_read(address,8))[0])
            self.call(pc,'transaction-status-fixture',self.failure if len(self.sent)==self.fail_at else 0);return
        if pc in (0xfffffe00099d1d68,0xfffffe00099d1ec4):
            self.call(pc,'null-memory-log-fixture');return
        if ins.mnemonic in ('bl','blr','blraa','braa','brk'):
            raise AssertionError(f'unmodeled OOL call {pc:x}: {ins.mnemonic} {ins.op_str}')

    def run(self,receive,endpoint,length,iova,fail_at=0,null=False):
        self.length=length;self.iova=iova;self.fail_at=fail_at;self.failure=0xe00002d6
        self.sent=[];self.events=[];self.stop=None
        self.u.mem_write(DATA,bytes(0x20000))
        for address in (DATA,BUFFER,BUFFER+0x100):self.put(address,'<Q',s['VTABLE'])
        for n in range(31):self.u.reg_write(getattr(reg,f'UC_ARM64_REG_X{n}'),0)
        for r,value in [(reg.UC_ARM64_REG_X0,DATA),(reg.UC_ARM64_REG_X1,endpoint),
                        (reg.UC_ARM64_REG_X2,0 if null else BUFFER),(reg.UC_ARM64_REG_X3,15000),
                        (reg.UC_ARM64_REG_X30,RETURN),(reg.UC_ARM64_REG_SP,DATA+0x1f000)]:
            self.u.reg_write(r,value)
        self.u.emu_start(RECV if receive else SEND,RETURN,count=5000)
        assert self.stop=='return'
        return self.u.reg_read(reg.UC_ARM64_REG_X0)


def main():
    image=runpy.run_path(str(ROOT/'tools/kc-xref.py'))['Kernelcache'](
        ROOT/'downloads/extracted/j700ap/kernelcache.release.mac17p')
    replay=OOL(image);checks=0;samples=[]
    for receive in (False,True):
        for endpoint in range(1,32):
            for length,iova in [(0x4000,0x10000004000),(0x14000,0x10001000000),(0x1c000,0x10001014000)]:
                assert replay.run(receive,endpoint,length,iova)==0
                expected=[length<<32|endpoint<<24|(5 if receive else 4)<<16,
                          (iova>>12)<<32|endpoint<<24|(3 if receive else 2)<<16]
                assert replay.sent==expected;checks+=1
                if endpoint==1 and length==(0x14000 if receive else 0x1c000):
                    samples.append(dict(direction='receive' if receive else 'send',length=hex(length),
                                        iova=hex(iova),requests=[hex(w) for w in replay.sent]))
        for step in (1,2):
            assert replay.run(receive,1,0x4000,0x10000004000,fail_at=step)==replay.failure
            assert len(replay.sent)==step;checks+=1
        assert replay.run(receive,1,0x4000,0x10000004000,null=True)==0xe00002c2
        assert not replay.sent;checks+=1
    print(json.dumps(dict(kernel_sha256=s['KERNEL_SHA'],checks=checks,samples=samples,
                         boundary=__doc__.strip()),indent=2))


if __name__=='__main__':main()

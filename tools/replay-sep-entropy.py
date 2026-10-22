#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Pinned native tagged reply, entropy getter and 48-byte batch replay.

C producer inputs use public test words. Request-table lookup, transaction
completion, IOKit gates, zeroization API and entropy sink are explicit fixtures.
No hardware entropy quality, full scheduling or FIPS claim follows from this.
"""
from pathlib import Path
import json
import runpy
import struct
import subprocess

ROOT=Path(__file__).resolve().parents[1]
c=runpy.run_path(str(ROOT/'tools/replay-sep-control-startup.py'))
s=c['s'];reg=c['reg'];DATA=c['DATA'];OBJECT=c['OBJECT'];ARG=c['ARG'];RETURN=c['RETURN']
GETTER=0xfffffe00099d1674
BATCH=0xfffffe00099b9424
SLOT=DATA+0xe000
OUTPUT=DATA+0xf000


class Entropy(c['Control']):
    def __init__(self,image):
        super().__init__(image)
        self.u.mem_map(0xfffffe00081e6000,0x1000)

    def hook(self,u,pc,size,unused):
        if self.kind=='dispatch':
            if pc==0xfffffe00099d12f8:
                assert u.reg_read(reg.UC_ARM64_REG_X1)==self.tag
                self.call(pc,'tag-lookup-fixture',SLOT);return
            if pc==0xfffffe00099d1460:
                self.finish('reply-copied-before-wakeup');return
            return super().hook(u,pc,size,unused)
        ins=self.instructions.get(pc)
        if ins is None:raise AssertionError(f'unmodeled entropy exit {pc:x}')
        if ins.mnemonic in ('pacibsp','autibsp','autda','xpacd','pacia'):
            u.reg_write(reg.UC_ARM64_REG_PC,pc+4);return
        if ins.mnemonic=='retab':
            u.reg_write(reg.UC_ARM64_REG_PC,u.reg_read(reg.UC_ARM64_REG_X30));return
        if pc==0xfffffe00099d16b8:
            address=u.reg_read(reg.UC_ARM64_REG_X1)
            assert struct.unpack('<Q',u.mem_read(address,8))[0]==0x360000
            assert u.reg_read(reg.UC_ARM64_REG_X3)==0
            assert self.used<len(self.words),'native requested more words than fixture'
            self.put(address,'<Q',self.words[self.used]);self.used+=1
            self.reply_addresses.append(address)
            self.call(pc,'transaction-completion-fixture',0);return
        if pc in (0xfffffe00099d16fc,0xfffffe00099b954c,0xfffffe00099b9580):
            address=u.reg_read(reg.UC_ARM64_REG_X0);n=u.reg_read(reg.UC_ARM64_REG_X1)
            assert u.reg_read(reg.UC_ARM64_REG_X2)==0 and u.reg_read(reg.UC_ARM64_REG_X3)==n
            assert n in (4,5,48)
            u.mem_write(address,bytes(n));self.clears.append(n)
            self.call(pc,'zeroization-api-fixture');return
        if pc==0xfffffe00099b9568:
            assert u.reg_read(reg.UC_ARM64_REG_X1)==48
            self.sink=bytes(u.mem_read(u.reg_read(reg.UC_ARM64_REG_X0),48))
            self.call(pc,'48-byte-entropy-sink-fixture');return
        fixtures={0xfffffe00099b947c:OBJECT,0xfffffe00099b94b4:0,
                  0xfffffe00099b94c0:1,0xfffffe00099b94d4:OBJECT,
                  0xfffffe00099b94e4:OBJECT,0xfffffe00099b9598:0}
        if pc in fixtures:self.call(pc,'batch-environment-fixture',fixtures[pc]);return
        if pc in (0xfffffe00099d172c,0xfffffe00099d1724,0xfffffe00099b95e4):
            self.finish('native-failure');return
        if ins.mnemonic in ('bl','blr','blraa','braa','brk'):
            if pc==0xfffffe00099b9524:return # Execute original getter.
            raise AssertionError(f'unmodeled entropy call {pc:x}: {ins.mnemonic} {ins.op_str}')

    def prepare(self,kind,words):
        self.kind=kind;self.words=words;self.used=0;self.sink=None
        self.reply_addresses=[];self.clears=[];self.events=[];self.stop=None
        self.u.mem_write(DATA,bytes(0x20000))
        self.put(DATA,'<Q',s['VTABLE']);self.put(OBJECT,'<Q',s['VTABLE'])
        self.put(DATA+0x78,'<Q',OBJECT);self.put(DATA+0xb98,'<B',1)
        self.put(DATA+0xc0,'<I',1)
        self.put(s['GLOBALS']+0x9c8,'<Q',DATA+0xd000)
        self.put(DATA+0xd000,'<Q',0x12345678)
        self.put(0xfffffe00081e6f48,'<Q',0)

    def execute_native(self,start):
        for n in range(31):self.u.reg_write(getattr(reg,f'UC_ARM64_REG_X{n}'),0)
        self.u.reg_write(reg.UC_ARM64_REG_X0,DATA)
        self.u.reg_write(reg.UC_ARM64_REG_X1,OUTPUT)
        self.u.reg_write(reg.UC_ARM64_REG_X2,15000)
        self.u.reg_write(reg.UC_ARM64_REG_X30,RETURN)
        self.u.reg_write(reg.UC_ARM64_REG_SP,DATA+0x1f000)
        self.u.reg_write(reg.UC_ARM64_REG_CPACR_EL1,3<<20)
        self.u.emu_start(start,RETURN,count=10000)
        if self.u.reg_read(reg.UC_ARM64_REG_PC)==RETURN:self.stop='return'
        assert self.stop is not None,'native entropy replay budget exhausted'
        return self.u.reg_read(reg.UC_ARM64_REG_X0)

    def dispatch(self,word):
        self.prepare('dispatch',[]);self.tag=word>>8&255
        self.put(SLOT+0x20,'<B',1);self.put(SLOT+0x28,'<Q',OUTPUT)
        self.put(ARG,'<Q',word)
        self.execute(c['START'],DATA)
        assert self.stop=='reply-copied-before-wakeup'
        assert self.u.mem_read(SLOT+0x20,1)==b'\0'
        assert struct.unpack('<Q',self.u.mem_read(OUTPUT,8))[0]==word

    def getter(self,word):
        self.prepare('getter',[word]);self.put(OUTPUT,'<I',0xaabbccdd)
        result=self.execute_native(GETTER)
        return result,struct.unpack('<I',self.u.mem_read(OUTPUT,4))[0]


def main():
    image=runpy.run_path(str(ROOT/'tools/kc-xref.py'))['Kernelcache'](
        ROOT/'downloads/extracted/j700ap/kernelcache.release.mac17p')
    replay=Entropy(image);checks=0
    producer=subprocess.run([str(ROOT/'build/test-sep-service'),'--entropy',
        str(ROOT/'build/sep-rom-slot-live-20260922-sep-shared.bin')],
        capture_output=True,text=True,check=True)
    words=[int(line,16) for line in producer.stdout.splitlines()]
    assert len(words)==255
    for tag,word in enumerate(words,1):
        assert word==((tag*0x01010101)<<32|0x360000|tag<<8)
        replay.dispatch(word);checks+=1
        assert replay.getter(word)==(0,word>>32)
        assert replay.clears==[5]
        assert replay.u.mem_read(replay.reply_addresses[0]+3,5)==bytes(5);checks+=1
    for data in (0,1,0x80000000,0xffffffff):
        assert replay.getter(data<<32|0x360100)==(0,data);checks+=1
    assert replay.getter(0x2360100)==(0xe00002bc,0xaabbccdd);checks+=1
    replay.getter(0x1360100);assert replay.stop=='native-failure';checks+=1
    replay.prepare('batch',words[:12])
    assert replay.execute_native(BATCH)==1 and replay.used==12
    assert replay.sink==struct.pack('<12I',*[w>>32 for w in words[:12]])
    assert replay.clears==[5,4]*12+[48];checks+=1
    replay.prepare('batch',[0x2360100])
    assert replay.execute_native(BATCH)==0 and replay.used==1 and replay.sink is None;checks+=1
    replay.prepare('batch',[words[0],0x2360200]);replay.execute_native(BATCH)
    assert replay.stop=='native-failure' and replay.used==2 and replay.sink is None;checks+=1
    print(json.dumps(dict(kernel_sha256=s['KERNEL_SHA'],checks=checks,
        native_tagged_replies=255,native_getters=261,native_batches=3,
        boundary=__doc__.strip()),indent=2))


if __name__=='__main__':main()

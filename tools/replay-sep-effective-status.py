#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Original tagged dispatch, effective-status getter and native bit consumers.

C producer words report neither production nor secure SEP execution. Other
byte values are explicit consumer test fixtures only. IOKit lookup/property
setters, transaction completion and thread lifecycle are fixtures; PAC is
omitted. This is not live property publication or SEP firmware execution.
"""
from pathlib import Path
import json,runpy,struct,subprocess
ROOT=Path(__file__).resolve().parents[1]
e=runpy.run_path(str(ROOT/'tools/replay-sep-entropy.py'))
reg=e['reg'];DATA=e['DATA'];OBJECT=e['OBJECT'];ARG=e['ARG'];RETURN=e['RETURN']
s=e['s'];OUTPUT=DATA+0xf000
GETTER=0xfffffe00099d20b0
UPDATE=0xfffffe00099bae7c
CLIENT=0xfffffe00099cdf90


class Status(e['Entropy']):
    def __init__(self,image):
        super().__init__(image)
        from capstone import Cs,CS_ARCH_ARM64,CS_MODE_ARM
        for base in (0xfffffe00099cd000,0xfffffe000768b000):
            code=image.data[image.va2off(base):image.va2off(base)+0x1000]
            self.u.mem_map(base,0x1000);self.u.mem_write(base,code)
            if base==0xfffffe00099cd000:
                self.instructions.update({i.address:i for i in Cs(CS_ARCH_ARM64,CS_MODE_ARM).disasm(code,base)})

    def hook(self,u,pc,size,unused):
        if self.kind=='dispatch':return super().hook(u,pc,size,unused)
        ins=self.instructions.get(pc)
        assert ins is not None,f'unmodeled status exit {pc:x}'
        if ins.mnemonic in ('pacibsp','autibsp','autda','xpacd','pacia'):
            u.reg_write(reg.UC_ARM64_REG_PC,pc+4);return
        if ins.mnemonic=='retab':
            u.reg_write(reg.UC_ARM64_REG_PC,u.reg_read(reg.UC_ARM64_REG_X30));return
        if pc==0xfffffe00099d20e8:
            address=u.reg_read(reg.UC_ARM64_REG_X1)
            assert struct.unpack('<Q',u.mem_read(address,8))[0]==0x140000
            assert struct.unpack('<I',u.mem_read(u.reg_read(reg.UC_ARM64_REG_X2),4))[0]==500
            assert u.reg_read(reg.UC_ARM64_REG_X3)==0
            self.transactions+=1
            if not self.failure:self.put(address,'<Q',self.word)
            self.call(pc,'transaction-completion-fixture',self.failure);return
        fixtures={0xfffffe00099baec8:OBJECT,0xfffffe00099baed8:DATA,
                  0xfffffe00099baee8:DATA,0xfffffe00099cdfb4:DATA,
                  0xfffffe00099d2104:0,0xfffffe00099bafa0:0,
                  0xfffffe00099bafd0:0,0xfffffe00099bafd4:DATA+0x1000,
                  0xfffffe00099bafdc:0}
        if pc in fixtures:self.call(pc,'IOKit-or-log-fixture',fixtures[pc]);return
        if pc in (0xfffffe00099baf34,0xfffffe00099baf78):
            assert u.reg_read(reg.UC_ARM64_REG_X0)==OBJECT
            address=u.reg_read(reg.UC_ARM64_REG_X1)
            name=bytes(u.mem_read(address,64)).split(b'\0')[0].decode()
            expected='effective-production-status-sep' if pc==0xfffffe00099baf34 else 'effective-security-mode-sep'
            assert name==expected and u.reg_read(reg.UC_ARM64_REG_X3)==1
            value=u.reg_read(reg.UC_ARM64_REG_X2);assert value in (0,1)
            self.properties.append((name,value))
            self.call(pc,'property-set-fixture',int(self.property_failure!=len(self.properties)));return
        if pc==0xfffffe00099bafe4:self.finish('thread-termination');return
        if ins.mnemonic in ('bl','blr','blraa','braa','brk'):
            assert pc in (0xfffffe00099baef4,0xfffffe00099cdfc0),f'unmodeled status call {pc:x}: {ins.mnemonic}'

    def native(self,start,word,failure=0,null=False,property_failure=0):
        self.prepare('status',[]);self.word=word;self.failure=failure
        self.properties=[];self.transactions=0;self.property_failure=property_failure
        self.put(OBJECT,'<Q',s['VTABLE'])
        self.put(s['GLOBALS']+0x9d0,'<Q',DATA+0xd010);self.put(DATA+0xd010,'<Q',OBJECT)
        self.put(DATA+0xd8,'<Q',OBJECT);self.put(ARG+0x48,'<Q',OUTPUT)
        self.put(OUTPUT,'<Q',0xaabbccddeeff1234)
        for n in range(31):self.u.reg_write(getattr(reg,f'UC_ARM64_REG_X{n}'),0)
        self.u.reg_write(reg.UC_ARM64_REG_X0,DATA)
        self.u.reg_write(reg.UC_ARM64_REG_X1,0 if null else OUTPUT)
        self.u.reg_write(reg.UC_ARM64_REG_X2,ARG if start==CLIENT else 500)
        self.u.reg_write(reg.UC_ARM64_REG_X30,RETURN)
        self.u.reg_write(reg.UC_ARM64_REG_SP,DATA+0x1f000)
        self.u.emu_start(start,RETURN,count=10000)
        if self.u.reg_read(reg.UC_ARM64_REG_PC)==RETURN:self.stop='return'
        assert self.stop is not None,'status replay exhausted instruction budget'
        return self.u.reg_read(reg.UC_ARM64_REG_W0),struct.unpack('<Q',self.u.mem_read(OUTPUT,8))[0]


def main():
    image=runpy.run_path(str(ROOT/'tools/kc-xref.py'))['Kernelcache'](
        ROOT/'downloads/extracted/j700ap/kernelcache.release.mac17p')
    replay=Status(image);checks=0
    producer=subprocess.run([str(ROOT/'build/test-sep-effective-status'),'--wire',
        str(ROOT/'build/sep-rom-slot-live-20260922-sep-shared.bin')],capture_output=True,text=True,check=True)
    words=[int(l,16) for l in producer.stdout.splitlines()];assert len(words)==255
    names=['effective-production-status-sep','effective-security-mode-sep']
    for tag,word in enumerate(words,1):
        assert word==0x140000|tag<<8
        replay.dispatch(word);checks+=1
        assert replay.native(GETTER,word)==(0,0) and replay.transactions==1;checks+=1
        assert replay.native(CLIENT,word)==(0,0) and replay.transactions==1;checks+=1
        replay.native(UPDATE,word)
        assert replay.stop=='thread-termination' and replay.properties==[(n,0) for n in names]
        assert replay.u.mem_read(DATA+0xcf,1)==b'\1';checks+=1
    for value in range(256):
        word=value<<32|0x140800
        assert replay.native(GETTER,word)==(0,value);checks+=1
        assert replay.native(CLIENT,word)==(0,value);checks+=1
        replay.native(UPDATE,word)
        assert replay.properties==[(names[0],value&1),(names[1],value>>1&1)]
        assert replay.u.mem_read(DATA+0xcf,1)==b'\1';checks+=1
    assert replay.native(GETTER,words[0],null=True)==(0xe00002bc,0xaabbccddeeff1234)
    assert not replay.transactions;checks+=1
    for failure in (1,0xe00002bc,0xffffffff):
        assert replay.native(GETTER,words[0],failure)==(failure,0xaabbccddeeff1234);checks+=1
        assert replay.native(CLIENT,words[0],failure)==(failure,0);checks+=1
        replay.native(UPDATE,words[0],failure)
        assert not replay.properties and replay.u.mem_read(DATA+0xcf,1)==b'\0';checks+=1
    for failure in (1,2):
        replay.native(UPDATE,words[0],property_failure=failure)
        assert len(replay.properties)==failure and replay.u.mem_read(DATA+0xcf,1)==b'\0';checks+=1
    print(json.dumps(dict(kernel_sha256=s['KERNEL_SHA'],checks=checks,
        c_producer_replies=len(words),virtual_effective_status=0,
        production=False,secure_execution=False,boundary=__doc__.strip()),indent=2))


if __name__=='__main__':main()

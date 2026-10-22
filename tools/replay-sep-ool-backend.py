#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Original OOL setter -> _cmsgSend -> tagged dispatcher -> status decoder.

Uses actual C producer replies after its resource admission fixtures. IOKit
objects, descriptor metadata, slot allocation/release, deadline creation and
delivery scheduling are fixtures; PAC is omitted. The original transaction
code allocates the tag, the original dispatcher copies the reply and clears
the active slot, and the original decoder returns status to each setter.
This proves their combined contract, not live DMA or scheduling.
"""
from pathlib import Path
import json,runpy,struct,subprocess
ROOT=Path(__file__).resolve().parents[1]
e=runpy.run_path(str(ROOT/'tools/replay-sep-entropy.py'))
reg=e['reg'];s=e['s'];DATA=e['DATA'];OBJECT=e['OBJECT'];ARG=e['ARG'];RETURN=e['RETURN']
SLOT=e['SLOT'];BUFFER=DATA+0xc000
SEND=0xfffffe00099d1c34
RECEIVE=0xfffffe00099d1d90


class OOLBackend(e['Entropy']):
    def __init__(self,kernel,backend):
        super().__init__(kernel);self.backend=backend;self.dispatching=False
        base=0xfffffe0007693000;self.u.mem_map(base,0x1000)
        self.u.mem_write(base,kernel.data[kernel.va2off(base):kernel.va2off(base)+0x1000])

    def hook(self,u,pc,size,unused):
        if self.dispatching:
            if pc==0xfffffe00099d1460:
                assert u.mem_read(SLOT+0x20,1)==b'\0'
                assert struct.unpack('<Q',u.mem_read(self.message,8))[0]==self.reply
                for n,value in enumerate(self.saved):u.reg_write(getattr(reg,f'UC_ARM64_REG_X{n}'),value)
                u.reg_write(reg.UC_ARM64_REG_SP,self.saved_sp)
                self.kind='ool-cmsg';self.dispatching=False
                self.call(0xfffffe00099d1944,'delivered-reply',0);return
            return super().hook(u,pc,size,unused)
        ins=self.instructions.get(pc);assert ins is not None,f'unmodeled OOL backend exit {pc:x}'
        if ins.mnemonic in ('pacibsp','autibsp','autda','xpacd','pacia'):
            u.reg_write(reg.UC_ARM64_REG_PC,pc+4);return
        if ins.mnemonic=='retab':
            u.reg_write(reg.UC_ARM64_REG_PC,u.reg_read(reg.UC_ARM64_REG_X30));return
        if pc in (0xfffffe00099d1c8c,0xfffffe00099d1de8):
            assert u.reg_read(reg.UC_ARM64_REG_X0)==BUFFER
            self.call(pc,'descriptor-fixture',BUFFER+0x100);return
        if pc in (0xfffffe00099d1cbc,0xfffffe00099d1e18):
            assert u.reg_read(reg.UC_ARM64_REG_X0)==BUFFER+0x100
            self.call(pc,'length-fixture',self.length);return
        if pc in (0xfffffe00099d1cf8,0xfffffe00099d1e54):
            assert u.reg_read(reg.UC_ARM64_REG_X0)==BUFFER
            self.call(pc,'iova-fixture',self.iova);return
        fixtures={0xfffffe00099d17a8:OBJECT,0xfffffe00099d17d8:OBJECT,
                  0xfffffe00099d17fc:0,0xfffffe00099d1820:OBJECT,
                  0xfffffe00099d1844:1,0xfffffe00099d1880:OBJECT,
                  0xfffffe00099d18a4:1,0xfffffe00099d1968:15000,
                  0xfffffe00099d1b68:0}
        if pc in fixtures:self.call(pc,'workloop-or-log-fixture',fixtures[pc]);return
        if pc==0xfffffe00099d18dc:
            assert u.reg_read(reg.UC_ARM64_REG_X0)==OBJECT and u.reg_read(reg.UC_ARM64_REG_X2)==1
            self.put(u.reg_read(reg.UC_ARM64_REG_X1),'<Q',SLOT)
            self.put(SLOT+0x40,'<B',self.tag-1)
            self.call(pc,'slot-allocation-fixture',0);return
        if pc==0xfffffe00099d1944:
            self.message=u.reg_read(reg.UC_ARM64_REG_X1)
            request=struct.unpack('<Q',u.mem_read(self.message,8))[0]
            assert request>>8&255==self.tag and u.mem_read(SLOT+0x20,1)==b'\1'
            assert struct.unpack('<Q',u.mem_read(SLOT+0x28,8))[0]==self.message
            self.sent.append(request);self.reply=self.backend[request]
            if len(self.sent)==self.corrupt_at:self.reply|=self.status<<24
            self.saved=[u.reg_read(getattr(reg,f'UC_ARM64_REG_X{n}')) for n in range(31)]
            self.saved_sp=u.reg_read(reg.UC_ARM64_REG_SP)
            self.put(ARG,'<Q',self.reply);self.kind='dispatch';self.dispatching=True
            u.reg_write(reg.UC_ARM64_REG_X0,DATA);u.reg_write(reg.UC_ARM64_REG_X2,ARG)
            u.reg_write(reg.UC_ARM64_REG_X30,RETURN);u.reg_write(reg.UC_ARM64_REG_SP,DATA+0x1b000)
            u.reg_write(reg.UC_ARM64_REG_PC,e['c']['START']);return
        if pc==0xfffffe00099d1978:
            self.put(u.reg_read(reg.UC_ARM64_REG_X2),'<Q',1)
            self.call(pc,'deadline-fixture');return
        if pc==0xfffffe00099d1bc4:
            assert u.reg_read(reg.UC_ARM64_REG_X0)==OBJECT and u.reg_read(reg.UC_ARM64_REG_X1)==SLOT
            assert u.mem_read(SLOT+0x20,1)==b'\0'
            self.releases+=1;self.call(pc,'slot-release-fixture');return
        if ins.mnemonic in ('bl','blr','blraa','braa','brk'):
            assert pc in (0xfffffe00099d1d20,0xfffffe00099d1d4c,
                          0xfffffe00099d1e7c,0xfffffe00099d1ea8),f'unmodeled call {pc:x}: {ins.mnemonic}'

    def run(self,receive,tag,corrupt_at=0,status=1):
        self.prepare('ool-cmsg',[]);self.tag=tag;self.corrupt_at=corrupt_at;self.status=status
        self.sent=[];self.releases=0;self.dispatching=False
        self.length=0x14000 if receive else 0x1c000
        self.iova=0x10002000000+(0x200000 if receive else 0)
        self.put(DATA+0x78,'<Q',OBJECT)
        for address in (DATA,OBJECT,BUFFER,BUFFER+0x100):self.put(address,'<Q',s['VTABLE'])
        for n in range(31):self.u.reg_write(getattr(reg,f'UC_ARM64_REG_X{n}'),0)
        for r,value in [(reg.UC_ARM64_REG_X0,DATA),(reg.UC_ARM64_REG_X1,1),
                        (reg.UC_ARM64_REG_X2,BUFFER),(reg.UC_ARM64_REG_X3,15000),
                        (reg.UC_ARM64_REG_X30,RETURN),(reg.UC_ARM64_REG_SP,DATA+0x1f000)]:
            self.u.reg_write(r,value)
        self.u.emu_start(RECEIVE if receive else SEND,RETURN,count=10000)
        assert self.u.reg_read(reg.UC_ARM64_REG_PC)==RETURN and not self.dispatching
        assert self.releases==len(self.sent)
        return self.u.reg_read(reg.UC_ARM64_REG_W0)


def main():
    image=runpy.run_path(str(ROOT/'tools/kc-xref.py'))['Kernelcache'](
        ROOT/'downloads/extracted/j700ap/kernelcache.release.mac17p')
    producer=subprocess.run([str(ROOT/'build/test-sep-pnon'),'--ool',
        str(ROOT/'build/sep-rom-slot-live-20260922-sep-shared.bin')],capture_output=True,text=True,check=True)
    backend=dict(tuple(int(v,16) for v in line.split()) for line in producer.stdout.splitlines())
    assert len(backend)==4*255
    replay=OOLBackend(image,backend);checks=0
    for receive in (False,True):
        for tag in range(1,256):
            assert replay.run(receive,tag)==0 and len(replay.sent)==2
            assert [v>>16&255 for v in replay.sent]==([5,3] if receive else [4,2]);checks+=1
        for tag in (1,8,255):
            for step in (1,2):
                assert replay.run(receive,tag,corrupt_at=step)==0xe00002c2
                assert len(replay.sent)==step;checks+=1
        for status in range(256):
            expected=0 if status==0 else 0xe00002c2 if status==1 else 0xe00002eb if status==2 else 0xe00002e9
            assert replay.run(receive,8,corrupt_at=1,status=status)==expected
            assert len(replay.sent)==(1 if status else 2);checks+=1
    print(json.dumps(dict(kernel_sha256=s['KERNEL_SHA'],checks=checks,c_producer_replies=len(backend),
        original_cmsg_send=True,original_tagged_dispatch=True,original_status_decoder=True,
        echoed_endpoint_regression=hex(0xe00002c2),boundary=__doc__.strip()),indent=2))


if __name__=='__main__':main()

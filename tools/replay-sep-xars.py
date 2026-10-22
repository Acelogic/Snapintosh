#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Replay pinned xars client gates, buffer sizing and reply status handling.

Original Apple instructions execute offline. IOKit objects, allocation, gates,
transport and PAC are fixtures. No endpoint is published on hardware and no
credential, SEP firmware execution or GUI result is claimed.
"""
from pathlib import Path
import argparse
import hashlib
import json
import runpy
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'build/test-python-deps'))
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_CODE
import unicorn.arm64_const as reg

SHA = 'dc9019ae39187b36936c2c513b485e513f15cd966b5c887ac88ffd2925976c62'
DATA = 0x1000000
VT = DATA + 0x2000
MANAGER = DATA + 0x4000
ARGS = DATA + 0x6000
OUTPUT = DATA + 0x8000
LENGTH = DATA + 0x9000
OBJECT = DATA + 0xa000
RETURN = DATA + 0xb000
ITEM = DATA + 0xc000
MESSAGE = DATA + 0xd000
CONFIG = DATA + 0xe000
STACK = DATA + 0x3f000
GLOBAL = 0xfffffe00081e8000


class Replay:
    def __init__(self, image):
        assert hashlib.sha256(image.data).hexdigest() == SHA
        self.u = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
        base, size = 0xfffffe00099b0000, 0x2f000
        raw = image.data[image.va2off(base):image.va2off(base) + size]
        self.u.mem_map(base, size)
        self.u.mem_write(base, raw)
        decoder = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
        decoder.skipdata = True
        self.instructions = {i.address:i for i in decoder.disasm(raw, base)}
        self.u.mem_map(DATA, 0x40000)
        self.u.mem_map(GLOBAL, 0x1000)
        self.u.hook_add(UC_HOOK_CODE, self.hook)

    def put(self, address, fmt, *values):
        self.u.mem_write(address, struct.pack(fmt, *values))

    def x(self, number):
        return self.u.reg_read(getattr(reg, f'UC_ARM64_REG_X{number}'))

    def call(self, pc, name, value=0):
        self.events.append(name)
        self.u.reg_write(reg.UC_ARM64_REG_X0, value)
        self.u.reg_write(reg.UC_ARM64_REG_PC, pc + 4)

    def finish(self, name):
        self.stop = name
        self.u.emu_stop()

    def reset(self):
        self.u.mem_write(DATA, bytes(0x40000))
        self.u.mem_write(GLOBAL, bytes(0x1000))
        for address in (DATA, MANAGER, OBJECT, ITEM):
            self.put(address, '<Q', VT)
        self.events, self.stop = [], None
        for n in range(31):
            self.u.reg_write(getattr(reg, f'UC_ARM64_REG_X{n}'), 0)
        self.u.reg_write(reg.UC_ARM64_REG_SP, STACK)
        self.u.reg_write(reg.UC_ARM64_REG_X30, RETURN)

    def execute(self, start, *arguments):
        for n, value in enumerate(arguments):
            self.u.reg_write(getattr(reg, f'UC_ARM64_REG_X{n}'), value)
        self.u.emu_start(start, RETURN, count=20000)
        assert self.stop is not None, f'no qualified exit at {self.u.reg_read(reg.UC_ARM64_REG_PC):#x}'
        return self.x(0) & 0xffffffff

    def common(self, pc):
        ins = self.instructions.get(pc)
        assert ins is not None, f'outside pinned instructions {pc:#x}'
        if ins.mnemonic in ('pacibsp', 'autibsp', 'autda', 'xpacd', 'pacia', 'pacda'):
            self.u.reg_write(reg.UC_ARM64_REG_PC, pc + 4)
            return True
        if ins.mnemonic == 'retab':
            self.finish('return')
            return True
        return False

    def unknown_call(self, pc):
        ins = self.instructions[pc]
        assert ins.mnemonic not in ('bl', 'blr', 'blraa', 'braa', 'brk'), (
            f'unmodeled call {pc:#x}: {ins.mnemonic} {ins.op_str}')


class Client(Replay):
    def run(self, *, booted=True, endpoint=True, status=1, output_length=0, available=True):
        self.reset()
        self.endpoint, self.status, self.output_length, self.available = endpoint, status, output_length, available
        self.property = DATA + (0x1100 if booted else 0x1200)
        self.put(DATA + 0xd8, '<Q', MANAGER)
        self.put(GLOBAL + 0x9f8, '<Q', DATA + 0x1000)
        self.put(DATA + 0x1000, '<Q', DATA + 0x1080)
        self.put(DATA + 0x1080, '<Q', DATA + 0x1100)
        self.put(LENGTH, '<Q', 0x8000)
        self.u.mem_write(OUTPUT, b'untouched-output')
        value = self.execute(0xfffffe00099cf3e0, DATA, 0, ARGS)
        return dict(stop=self.stop, status=value, length=self.x(0),
                    output=bytes(self.u.mem_read(OUTPUT, 16)).hex(), events=self.events)

    def hook(self, u, pc, size, _):
        if self.common(pc):
            return
        if pc in (0xfffffe00099cf594, 0xfffffe00099cf598):
            self.finish('panic:!booted' if pc == 0xfffffe00099cf594 else 'panic:length')
            return
        if pc == 0xfffffe00099cf42c:
            assert self.x(1) == self.x(3) == 24 and self.x(2) == 0
            u.mem_write(self.x(0), bytes(24))
            self.call(pc, 'zero-local-buffer')
        elif pc == 0xfffffe00099cf434:
            self.call(pc, 'manager-available-fixture', int(self.available))
        elif pc == 0xfffffe00099cf470:
            self.call(pc, 'sep-booted-property-fixture', self.property)
        elif pc == 0xfffffe00099cf490:
            assert self.x(0) == MANAGER and self.x(1) == 15000
            self.call(pc, 'xars-lookup-fixture', OBJECT if self.endpoint else 0)
        elif pc == 0xfffffe00099cf534:
            assert self.x(0) == ARGS and self.x(2) == 0
            self.put(self.x(1), '<3Q', OUTPUT, LENGTH, 0)
            self.call(pc, 'output-descriptor-fixture')
        elif pc == 0xfffffe00099cf560:
            assert self.x(0) == OBJECT and self.x(1) == OUTPUT
            self.put(self.x(2), '<Q', self.output_length)
            self.call(pc, 'lynx-status-fixture', self.status)
        else:
            self.unknown_call(pc)


class ReplyStatus(Replay):
    """Execute native post-wakeup status handling, including output-copy gate."""
    def run(self, status, *, length=0):
        self.reset()
        self.copies = []
        sp = STACK - 0x70
        self.u.reg_write(reg.UC_ARM64_REG_SP, sp)
        self.put(sp + 0x18, '<Q', ITEM)
        self.put(OBJECT + 0x78, '<Q', DATA)
        self.put(OBJECT + 0xd0, '<Q', DATA + 0x10000)
        self.put(CONFIG, '<4Q', 0, 0, OUTPUT, LENGTH)
        self.put(MESSAGE, '<Q', 2 | (7 << 8) | (status << 16) | (length << 24))
        self.put(LENGTH, '<Q', 0xaaaaaaaaaaaaaaaa)
        for n, value in ((19,OBJECT),(20,CONFIG),(21,MESSAGE),(24,OBJECT),(25,0x0a)):
            self.u.reg_write(getattr(reg, f'UC_ARM64_REG_X{n}'), value)
        value = self.execute(0xfffffe00099cb388)
        return dict(status=value, copies=self.copies,
                    length=struct.unpack('<Q', self.u.mem_read(LENGTH,8))[0], events=self.events)

    def hook(self, u, pc, size, _):
        if self.common(pc):
            return
        if pc == 0xfffffe00099cb3c0:
            assert self.x(1) == ITEM
            self.call(pc, 'release-transaction-fixture')
        elif pc == 0xfffffe00099cb41c:
            assert self.x(0) == OUTPUT and self.x(1) == DATA + 0x10000
            self.copies.append(self.x(2))
            self.call(pc, 'bounded-output-copy-fixture')
        elif pc == 0xfffffe00099cb4c0:
            self.call(pc, 'command-gate-fixture', MANAGER)
        elif pc == 0xfffffe00099cb500:
            assert self.x(1) == OBJECT + 0xc2 and self.x(2) == 0
            self.call(pc, 'wake-buffer-waiter-fixture')
        else:
            self.unknown_call(pc)


class ServiceBounds(Replay):
    def run(self, sizes):
        self.reset()
        self.sizes = sizes
        for n, value in ((19,DATA),(20,MANAGER),(21,OBJECT),(22,ITEM),(23,0)):
            self.u.reg_write(getattr(reg, f'UC_ARM64_REG_X{n}'), value)
        self.execute(0xfffffe00099cbbe4)
        return self.stop

    def hook(self, u, pc, size, _):
        if pc == 0xfffffe00099cbc84:
            self.finish('bounds-accepted')
            return
        if pc in (0xfffffe00099cbd6c,0xfffffe00099cbd70,0xfffffe00099cbd74,
                  0xfffffe00099cbd78,0xfffffe00099cbd7c):
            self.finish('bounds-refused')
            return
        if self.common(pc):
            return
        if pc == 0xfffffe00099cbbe8:
            self.call(pc,'manager-fixture',MANAGER)
        elif pc in (0xfffffe00099cbbf8,0xfffffe00099cbc1c,0xfffffe00099cbc40,0xfffffe00099cbc64):
            self.call(pc,'16k-page-size-fixture',0x4000)
        elif pc in (0xfffffe00099cbc04,0xfffffe00099cbc28,0xfffffe00099cbc4c,0xfffffe00099cbc70):
            index=(0xfffffe00099cbc04,0xfffffe00099cbc28,0xfffffe00099cbc4c,0xfffffe00099cbc70).index(pc)
            self.call(pc,'advertised-size-fixture',self.sizes[index])
        else:
            self.unknown_call(pc)


class Receiver(Replay):
    def run(self, message, *, tag=7, pending=True):
        self.reset()
        self.tag, self.wakes = tag, 0
        self.put(OBJECT+0x60,'<I',2)
        self.put(OBJECT+0x78,'<Q',DATA)
        self.put(ITEM+0x20,'<B',int(pending))
        self.put(ITEM+0x28,'<Q',OUTPUT)
        self.put(OUTPUT,'<Q',0x8877665544332211)
        self.put(MESSAGE,'<Q',message)
        self.execute(0xfffffe00099cacc4,OBJECT,0,MESSAGE)
        return dict(stop=self.stop,wakes=self.wakes,pending=self.u.mem_read(ITEM+0x20,1)[0],
                    reply=struct.unpack('<Q',self.u.mem_read(OUTPUT,8))[0])

    def hook(self, u, pc, size, _):
        if self.common(pc):
            return
        if pc in (0xfffffe00099cad0c,0xfffffe00099cadd0):
            self.call(pc,'workloop-or-gate-fixture',MANAGER)
        elif pc == 0xfffffe00099cad44:
            self.call(pc,'in-gate-fixture',1)
        elif pc == 0xfffffe00099cad8c:
            self.call(pc,'tag-table-fixture',ITEM if self.x(1)==self.tag else 0)
        elif pc == 0xfffffe00099cae30:
            assert self.x(1)==ITEM and self.x(2)==0
            self.wakes+=1
            self.finish('wake')
        elif pc == 0xfffffe00099cae44:
            self.call(pc,'rejected-reply-log-fixture')
        else:
            self.unknown_call(pc)


class APSlotInfo(Replay):
    """Pinned native builder and output gates; transport response is a fixture."""
    def run(self, *, slot=0, status=1, length=56, payload=bytes(range(56)), state=0x7e):
        self.reset()
        self.status,self.length,self.payload,self.state=status,length,payload,state
        self.message=None
        self.put(GLOBAL+0x9c8,'<Q',DATA+0x1100)
        self.put(DATA+0x1100,'<Q',0x12345678)
        self.put(ARGS+0x20,'<4Q',OBJECT,OUTPUT,OUTPUT+16,OUTPUT+32)
        self.put(ARGS+0x40,'<B',slot)
        self.u.mem_write(OUTPUT,b'\xa5'*80)
        value=self.execute(0xfffffe00099be588,ARGS)
        return dict(stop=self.stop,status=value,request=self.message,
                    output=bytes(self.u.mem_read(OUTPUT,80)).hex())

    def hook(self,u,pc,size,_):
        if pc in (0xfffffe00099be688,0xfffffe00099be68c):
            self.finish('assert:transport-status' if pc==0xfffffe00099be688 else 'assert:payload-length')
            return
        if self.common(pc):return
        if pc==0xfffffe00099be5f4:
            self.call(pc,'timeout-policy-fixture',0)
        elif pc==0xfffffe00099be614:
            assert self.x(0)==OBJECT
            self.message=struct.unpack('<Q',u.mem_read(self.x(1),8))[0]
            source,size,destination,count=struct.unpack('<4Q',u.mem_read(self.x(2),32))
            assert source==size==0 and struct.unpack('<Q',u.mem_read(count,8))[0]==56
            if not self.status:
                u.mem_write(destination,self.payload)
                self.put(count,'<Q',self.length)
                self.put(self.x(1)+6,'<B',self.state)
            self.call(pc,'mailbox-response-fixture',self.status)
        else:self.unknown_call(pc)


class FullEpochs(Replay):
    """Pinned AppleSEPXART::getFullEpochs block (fffffe00099be464): opcode 0x17,
    EPOCH_COUNT 8 x 4-byte slots, panic unless out_len == 32. The transport is a
    fixture with the native post-wakeup semantics replayed by ReplyStatus:
    success copies min(length, 0x8000) bytes and stores that length; a failure
    status leaves the preset length untouched."""
    def run(self, *, status=0, length=32, payload=bytes(32)):
        self.reset()
        self.status,self.length,self.payload,self.message=status,length,payload,None
        self.put(ARGS+0x20,'<3Q',OBJECT,8,OUTPUT)
        self.u.mem_write(OUTPUT,b'\xa5'*40)
        value=self.execute(0xfffffe00099be464,ARGS)
        return dict(stop=self.stop,status=value,request=self.message,
                    output=bytes(self.u.mem_read(OUTPUT,40)).hex())

    def hook(self,u,pc,size,_):
        if pc==0xfffffe00099be4e0:
            self.finish('assert:out-length');return
        if self.common(pc):return
        if pc==0xfffffe00099be4a0:
            self.call(pc,'timeout-policy-fixture',0)
        elif pc==0xfffffe00099be4c0:
            assert self.x(0)==OBJECT
            self.message=struct.unpack('<Q',u.mem_read(self.x(1),8))[0]
            source,size,destination,count=struct.unpack('<4Q',u.mem_read(self.x(2),32))
            assert source==size==0 and destination==OUTPUT
            assert struct.unpack('<Q',u.mem_read(count,8))[0]==32
            if not self.status:
                copied=min(self.length,0x8000)
                u.mem_write(destination,self.payload[:copied])
                self.put(count,'<Q',copied)
            self.call(pc,'mailbox-response-fixture',self.status)
        else:self.unknown_call(pc)


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--producer',type=Path,help='JSON emitted by the C endpoint model test')
    args=ap.parse_args()
    image = runpy.run_path(str(ROOT/'tools/kc-xref.py'))['Kernelcache'](
        ROOT/'downloads/extracted/j700ap/kernelcache.release.mac17p')
    client, reply = Client(image), ReplyStatus(image)
    checks = 0
    assert client.run(booted=True,endpoint=False)['stop'] == 'panic:!booted'; checks += 1
    assert client.run(booted=False,endpoint=False)['status'] == 0xe00002c2; checks += 1
    assert client.run(available=False)['status'] == 0xe00002c2; checks += 1
    for status in range(1,256):
        result = reply.run(status, length=0xffff)
        assert result['status'] == status and not result['copies']
        assert result['length'] == 0xaaaaaaaaaaaaaaaa
        out = client.run(status=result['status'])
        assert out['stop'] == 'return' and out['status'] == status
        assert out['output'] == b'untouched-output'.hex()
        checks += 1
    for length in (0,1,31,0x7fff,0x8000,0x8001,0xffff):
        result = reply.run(0,length=length)
        assert result['status'] == 0 and result['length'] == min(length,0x8000)
        assert result['copies'] == [min(length,0x8000)]
        checks += 1
    assert client.run(status=0,output_length=1<<32)['stop'] == 'panic:length'; checks += 1
    slot_info=APSlotInfo(image)
    for status in range(1,256):
        out=slot_info.run(status=status)
        assert out['stop']=='assert:transport-status' and out['output']==(b'\xa5'*80).hex()
        assert out['request']==0x180000;checks+=1
    for slot in range(256):
        out=slot_info.run(slot=slot,status=0)
        assert out['stop']=='return' and out['status']==0
        assert out['request']==0x180000|(slot<<48)
        raw=bytes.fromhex(out['output'])
        assert raw[0]==0x7e and raw[16:24]==bytes(range(8)) and raw[32:]==bytes(range(8,56))
        assert raw[1:16]==b'\xa5'*15 and raw[24:32]==b'\xa5'*8;checks+=1
    for length in (0,1,55,57,0x8000,0xffff):
        out=slot_info.run(status=0,length=length)
        assert out['stop']=='assert:payload-length' and out['output']==(b'\xa5'*80).hex();checks+=1
    epochs=FullEpochs(image)
    out=epochs.run(status=0,length=32,payload=bytes(range(32)))
    assert out['stop']=='return' and out['request']==0x170000
    assert bytes.fromhex(out['output'])==bytes(range(32))+b'\xa5'*8;checks+=1
    for length in (0,1,31,33,56,0x8000,0xffff):
        out=epochs.run(status=0,length=length,payload=bytes(0x8000))
        assert out['stop']=='assert:out-length',(length,out);checks+=1
    epoch_refusal=epochs.run(status=1)
    bounds=ServiceBounds(image)
    for field in range(4):
        for value in range(256):
            sizes=[2,2,2,2];sizes[field]=value
            expected='bounds-accepted' if (value<=2 if field in (0,2) else value>=2) else 'bounds-refused'
            assert bounds.run(sizes)==expected,(sizes,bounds.stop)
            checks+=1
    producer=None
    if args.producer:
        raw=args.producer.read_bytes();producer=json.loads(raw)
        parser=runpy.run_path(str(ROOT/'tools/replay-sep-discovery.py'))['Parser'](image)
        for word in producer['advertisements']:
            parser.send(struct.pack('<Q',word))
        records=parser.records()
        assert records==struct.pack('<BIB4B',1,0x78617273,2,2,2,2,2)
        assert len(parser.publications)==1
        assert bounds.run(list(records[6:]))=='bounds-accepted';checks+=1
        receiver=Receiver(image)
        for word in producer['refusals']:
            out=receiver.run(word)
            assert out==dict(stop='wake',wakes=1,pending=0,reply=word)
            status=reply.run((out['reply']>>16)&255)
            assert status['status']==1 and not status['copies']
            assert client.run(status=status['status'])['status']==1
            checks+=1
            for bad in (word^1,word^0x100,word&~0xff00):
                out=receiver.run(bad)
                assert out['stop']=='return' and out['wakes']==0 and out['pending']==1
                assert out['reply']==0x8877665544332211;checks+=1
            out=receiver.run(word,pending=False)
            assert out['stop']=='return' and out['wakes']==0 and out['reply']==0x8877665544332211
            checks+=1
        for request,word in producer.get('empty_slots',()):
            # C-produced empty-slot reply through native receive, status/copy
            # and get_ap_slot_info gates; payload is the monitor's 56 zeros.
            slot=request>>48&255
            assert slot in (0,1) and request&~0xff00==0x180002|slot<<48
            out=receiver.run(word,tag=request>>8&255)
            assert out==dict(stop='wake',wakes=1,pending=0,reply=word);checks+=1
            status=reply.run(word>>16&255,length=word>>24&0xffff)
            assert status['status']==0 and status['copies']==[56] and status['length']==56;checks+=1
            out=slot_info.run(slot=slot,status=0,length=56,payload=bytes(56),state=word>>48&255)
            assert out['stop']=='return' and out['status']==0
            assert out['request']==request&~0xffff
            raw_out=bytes.fromhex(out['output'])
            assert raw_out[0]==0 and raw_out[16:24]==bytes(8) and raw_out[32:80]==bytes(48);checks+=1
        for request,word in producer.get('full_epochs',()):
            # C-produced getFullEpochs reply through native receive, status/copy
            # and the pinned builder's length assert: eight empty slots.
            assert request&~0xff00==0x170002
            out=receiver.run(word,tag=request>>8&255)
            assert out==dict(stop='wake',wakes=1,pending=0,reply=word);checks+=1
            status=reply.run(word>>16&255,length=word>>24&0xffff)
            assert status['status']==0 and status['copies']==[32] and status['length']==32;checks+=1
            out=epochs.run(status=0,length=32,payload=bytes(32))
            assert out['stop']=='return' and out['request']==request&~0xffff
            assert bytes.fromhex(out['output'])==bytes(32)+b'\xa5'*8;checks+=1
        producer['artifact_sha256']=hashlib.sha256(raw).hexdigest()
    print(json.dumps(dict(kernel_sha256=SHA, checks=checks,
                         missing_endpoint=client.run(endpoint=False),
                         refused_reply=reply.run(1),
                         client_refusal=client.run(status=1),
                         ap_slot_refusal=slot_info.run(),
                         full_epochs_refusal=epoch_refusal,
                         full_epochs_contract='Opcode0x17, no payload; EPOCH_COUNT 8 x 4 bytes; the builder panics unless out_len==32. Producer replay: eight empty slots (32 zero bytes, status0); no epoch is claimed.',
                         ap_slot_contract='Opcode0x18; slot in byte6; nonzero transport status asserts; success requires56 bytes and returns byte6 plus8-byte/48-byte outputs. Producer replay: empty slots0/1 are state0 with zero BNCN/commit hash; no nonce or manifest commitment is claimed.',
                         producer=producer,
                         boundary=__doc__.strip()),indent=2))


if __name__ == '__main__':
    main()

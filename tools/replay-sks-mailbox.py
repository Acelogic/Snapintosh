#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Native SEP discovery and mailbox transport replay for the SKS candidate."""
from pathlib import Path
import argparse
import hashlib
import importlib.util
import json
import re
import runpy
import struct
import subprocess

ROOT=Path(__file__).resolve().parents[1]
PRIOR=ROOT/'build/sks-startup-model-20260928-v1/qualification.json'
assert hashlib.sha256(PRIOR.read_bytes()).hexdigest()=='3557a6e9a62731dda42ad0455aa386a580028b9f8260ee883dea737ba57fd59c'
for path,want in json.loads(PRIOR.read_text())['source_sha256'].items():
    assert hashlib.sha256(Path(path).read_bytes()).hexdigest()==want,path
spec=importlib.util.spec_from_file_location('sks_startup',ROOT/'tools/replay-sks-startup-model.py')
startup=importlib.util.module_from_spec(spec);spec.loader.exec_module(startup)
base=startup.b
IMAGE=Path('/Library/Developer/KDKs/KDK_27.0_26A428.kdk/System/Library/Extensions/AppleSEPManager.kext/Contents/MacOS/AppleSEPManager')
IMAGE_SHA='f264f92a4397c0d0591e7434d7aa4bd33b9e37cd20dc0d9e04951ca9184e2aaa'
UUID='d4c978c0c95430a3ae950f0f25aa5aac'
GUEST_SHA='dc9019ae39187b36936c2c513b485e513f15cd966b5c887ac88ffd2925976c62'
GUEST=ROOT/'downloads/extracted/j700ap/kernelcache.release.mac17p'
OBJECT=base.DATA+0x60000
PROVIDER=base.DATA+0x62000
INFO=base.DATA+0x64000
MESSAGE=base.DATA+0x65000
VTABLE=base.DATA+0x66000
FIXTURES=base.DATA+0x68000


def commands(raw):
    assert struct.unpack_from('<I',raw)[0]==0xfeedfacf
    pos=32
    for _ in range(struct.unpack_from('<I',raw,16)[0]):
        cmd,length=struct.unpack_from('<II',raw,pos)
        assert length>=8 and pos+length<=len(raw)
        yield cmd,raw[pos:pos+length]
        pos+=length


class Manager(base.Native):
    def __init__(self):
        assert base.sha(IMAGE)==IMAGE_SHA
        fat=IMAGE.read_bytes()
        assert struct.unpack_from('>I',fat)[0]==0xcafebabe
        arches=[struct.unpack_from('>IIIII',fat,8+i*20) for i in range(struct.unpack_from('>I',fat,4)[0])]
        matches=[a for a in arches if a[:2]==(0x100000c,0xc0000002)]
        assert len(matches)==1
        _,_,offset,size,_=matches[0];raw=fat[offset:offset+size]
        self.u=base.Uc(base.UC_ARCH_ARM64,base.UC_MODE_ARM)
        self.pages,self.instructions,self.segments=set(),{},{}
        md=base.Cs(base.CS_ARCH_ARM64,base.CS_MODE_ARM);md.skipdata=True
        found=None
        for cmd,data in commands(raw):
            if cmd==0x1b:found=data[8:24].hex()
            if cmd==0x19:
                name=data[8:24].rstrip(b'\0').decode()
                va,vmbytes,fo,fs=struct.unpack_from('<QQQQ',data,24)
                self.segments[name]=(va,vmbytes,fo,fs)
                if name!='__LINKEDIT':
                    self.map(va,vmbytes)
                    if fs:self.u.mem_write(va,raw[fo:fo+fs])
                    if name=='__TEXT_EXEC':
                        self.instructions.update((i.address,i) for i in md.disasm(raw[fo:fo+fs],va))
        assert found==UUID
        assembly=subprocess.check_output([str(base.LLVM/'llvm-objdump'),'--macho','--arch=arm64e','-d',str(IMAGE)],text=True)
        self.imports={}
        for line in assembly.splitlines():
            match=re.search(r'\b(?:bl|b)\s+0x([0-9a-f]+)\s*; symbol stub for: (\S+)',line)
            if match:self.imports[int(match[1],16)]=match[2]
        self.map(base.DATA,base.AREA)
        self.put(0x53d90,'<Q',base.GUARD)
        self.put(base.GUARD,'<Q',0xa183ea7155cc9922)
        self.events,self.callbacks,self.executed,self.digests=[],[],set(),{}
        self.fixtures={}
        self.u.hook_add(base.UC_HOOK_CODE,self.hook)
        self.u.hook_add(base.UC_HOOK_MEM_INVALID,self.invalid)
        self.u.hook_add(base.UC_HOOK_MEM_READ,self.memory_read)

    def fixture(self,name,callback):
        address=FIXTURES+len(self.fixtures)*16
        self.fixtures[address]=(name,callback)
        self.imports[address]='fixture:'+name
        return address

    def hook(self,u,pc,size,unused):
        if pc in self.fixtures:
            name,callback=self.fixtures[pc]
            self.events.append(dict(name=name,args=[hex(self.x(n)) for n in range(6)]))
            result=callback(self)
            self.result(0 if result is None else result);return
        super().hook(u,pc,size,unused)

    def guest_binding(self,sites):
        assert base.sha(GUEST)==GUEST_SHA
        scope='com.apple.driver.AppleSEPManager'
        helper=runpy.run_path(str(ROOT/'tools/kc-xref.py'))
        guest=helper['Kernelcache'](GUEST,scope=scope)
        entry=next(e for e in guest.entries if e[0]==scope)
        header=guest.data[entry[2]:entry[2]+0x1000]
        assert next(data[8:24].hex() for cmd,data in commands(header) if cmd==0x1b)==UUID
        native_text=self.segments['__TEXT_EXEC'][0]
        guest_text=next(s[1] for s in guest.kext[scope] if s[0]=='__TEXT_EXEC')
        result=[]
        for address in sites:
            counterpart=guest_text+address-native_text
            word=bytes(self.u.mem_read(address,4))
            actual=guest.data[guest.va2off(counterpart):guest.va2off(counterpart)+4]
            assert actual==word,(hex(address),actual.hex(),word.hex())
            result.append(dict(native=hex(address),guest=hex(counterpart),word=word.hex()))
        return dict(uuid=UUID,guest_sha256=GUEST_SHA,sites=result)


def discovery(pages):
    native=Manager();published=[]
    native.put(OBJECT,'<Q',VTABLE);native.put(PROVIDER,'<Q',VTABLE+0x1000)
    target=native.fixture('discovery-workloop',lambda n:PROVIDER)
    native.put(VTABLE+0x188,'<Q',target)
    target=native.fixture('discovery-in-gate',lambda n:1)
    native.put(VTABLE+0x1000+0x158,'<Q',target)
    def publish(n):
        assert n.x(0)==OBJECT
        published.append(bytes(n.u.mem_read(n.x(1),9)))
    native.fixtures[0x13b94]=('publication-boundary',publish)
    name=0x736b7320030000fd
    advertisement=int.from_bytes(bytes([0xfd,0,1,3,*pages]),'little')
    for word in [name,advertisement]:
        native.put(MESSAGE,'<Q',word);native.invoke(0x137e0,OBJECT,0,MESSAGE)
    assert len(published)==1
    assert published[0]==struct.pack('<IB4B',0x736b7320,3,*pages)
    native.u.mem_write(INFO,published[0])
    native.put(OBJECT+0x88,'<Q',INFO);native.put(OBJECT+0x90,'<Q',PROVIDER)
    decoded=[native.invoke(entry,OBJECT) for entry in [0x2a798,0x2a7a8,0x2a7b8,0x2a7c8]]
    assert decoded==list(pages)
    page_sizes=[]
    for flag,want in [(0,0x1000),(1,0x4000)]:
        native.put(PROVIDER+0x1b4,'<I',flag)
        value=native.invoke(0x2a778,OBJECT);assert value==want;page_sizes.append(value)
    native.invoke(0x2a5e4,MESSAGE,18,0x736b7320)
    formatted=bytes(native.u.mem_read(MESSAGE,18)).split(b'\0')[0].decode()
    assert formatted=='sep-endpoint,sks'
    return native,dict(name_advertisement=hex(name),ool_advertisement=hex(advertisement),
        published_info_hex=published[0].hex(),name=formatted,pages=decoded,page_size_by_format=page_sizes,
        fixture_calls=native.events,executed_pcs=[hex(x) for x in sorted(native.executed)])


def negotiate(direction,first_status=0):
    native=Manager();requests=[]
    length=0x8000;iova=0x2040000+direction*0x40000
    native.put(OBJECT,'<Q',VTABLE);native.put(PROVIDER,'<Q',VTABLE+0x1000)
    for table,offset,name,value in [(VTABLE,0x138,'memory-descriptor',PROVIDER),
            (VTABLE+0x1000,0x300,'descriptor-length',length),
            (VTABLE,0x140,'device-address',iova)]:
        target=native.fixture(name,lambda n,value=value:value)
        native.put(table+offset,'<Q',target)
    def control(n):
        assert n.x(0)==INFO and n.x(3)==0
        word=struct.unpack('<Q',n.u.mem_read(n.x(1),8))[0]
        timeout=struct.unpack('<I',n.u.mem_read(n.x(2),4))[0]
        requests.append(dict(native_word=hex(word),timeout=timeout,
            tagged_word=hex(word|5<<8),tag_boundary='control-transport fixture assigns tag 5'))
        return first_status if len(requests)==1 else 0
    native.fixtures[0x34030]=('control-transport',control)
    result=native.invoke(0x34534 if direction==0 else 0x34690,INFO,3,OBJECT,12345)
    expected=[(length<<32)|(3<<24)|((4+direction)<<16)]
    if not first_status:expected.append((iova>>12)<<32|3<<24|(2+direction)<<16)
    assert [int(x['native_word'],16) for x in requests]==expected
    assert result==first_status
    return native,dict(direction=direction,bytes=length,iova=hex(iova),result=hex(result),
        requests=requests,fixture_calls=native.events,executed_pcs=[hex(x) for x in sorted(native.executed)])


class KeyStoreReceiver(base.Native):
    SELF=base.DATA+0x60000
    WORKLOOP=base.DATA+0x80000
    VT=base.DATA+0x81000
    EVENT=base.DATA+0x82000
    MSG=base.DATA+0x84000
    DEBUG=base.DATA+0x85000
    WAKE=base.DATA+0x90000

    def __init__(self):
        super().__init__()
        self.phase=None;self.wakes=0;self.decision=None
        self.put(0x5a460,'<Q',self.DEBUG)
        self.put(self.SELF+0x81c0,'<QQ',self.WORKLOOP,self.EVENT)
        self.put(self.WORKLOOP,'<Q',self.VT)
        self.put(self.VT+0x208,'<Q',self.WAKE)
        self.imports[self.WAKE]='fixture:command-wakeup'

    def finish(self,value=0):
        self.u.reg_write(base.reg.UC_ARM64_REG_X0,value&0xffffffff)
        self.u.reg_write(base.reg.UC_ARM64_REG_PC,base.RETURN)

    def hook(self,u,pc,size,unused):
        if pc==self.WAKE:
            assert [self.x(i) for i in range(3)]==[self.WORKLOOP,self.EVENT,0]
            self.events.append(dict(name='command-wakeup',event=hex(self.EVENT)))
            self.wakes+=1;self.result();return
        if pc==0xb2c4 and self.phase=='action':
            self.events.append(dict(name='unexpected-async-log-boundary'))
            self.result();return
        if self.phase=='gate':
            if pc==0x12b60:
                self.u.reg_write(base.reg.UC_ARM64_REG_X19,self.SELF)
                self.u.reg_write(base.reg.UC_ARM64_REG_X26,self.DEBUG+16)
                fp=base.STACK-0x300
                self.u.reg_write(base.reg.UC_ARM64_REG_X29,fp)
                self.put(fp-0x68,'<Q',self.expected_command)
            if pc in [0x12910,0x12cdc,0x13134]:
                self.decision={0x12910:'continue-wait',0x12cdc:'decode-payload',0x13134:'return-status'}[pc]
                status=self.x(25)&0xffffffff if pc==0x13134 else 0
                self.events.append(dict(name='native-gated-decision-boundary',pc=hex(pc),
                    decision=self.decision,status=hex(status),bytes=self.x(21)&0xffff))
                self.finish(status);return
        super().hook(u,pc,size,unused)

    def run(self,word,expected_command=0x19):
        self.phase='action';self.wakes=0
        self.put(self.MSG,'<Q',word);self.put(self.SELF+0x188,'<Q',0)
        self.invoke(0x133d8,self.SELF,self.SELF+0x188,self.MSG)
        captured=struct.unpack('<Q',self.u.mem_read(self.SELF+0x188,8))[0]
        self.phase='gate';self.expected_command=expected_command
        result=self.invoke(0x12b60)
        return dict(word=hex(word),captured=hex(captured),wakes=self.wakes,
            expected_command=hex(expected_command),decision=self.decision,result=hex(result),
            fixture_calls=self.events,executed_pcs=[hex(x) for x in sorted(self.executed)])


def keystore_binding(native,sites):
    fat=base.IMAGE.read_bytes()
    arches=[struct.unpack_from('>IIIII',fat,8+i*20) for i in range(struct.unpack_from('>I',fat,4)[0])]
    a=next(a for a in arches if a[:2]==(0x100000c,0xc0000002));raw=fat[a[2]:a[2]+a[3]]
    native_text=next(struct.unpack_from('<Q',data,24)[0] for cmd,data in commands(raw)
        if cmd==0x19 and data[8:24].rstrip(b'\0')==b'__TEXT_EXEC')
    scope='com.apple.driver.AppleSEPKeyStore'
    guest=runpy.run_path(str(ROOT/'tools/kc-xref.py'))['Kernelcache'](GUEST,scope=scope)
    assert hashlib.sha256(guest.data).hexdigest()==GUEST_SHA
    entry=next(e for e in guest.entries if e[0]==scope)
    assert next(data[8:24].hex() for cmd,data in commands(guest.data[entry[2]:entry[2]+0x1000])
        if cmd==0x1b)==base.IMAGE_UUID
    guest_text=next(s[1] for s in guest.kext[scope] if s[0]=='__TEXT_EXEC')
    result=[]
    for address in sites:
        va=guest_text+address-native_text;word=bytes(native.u.mem_read(address,4))
        assert guest.data[guest.va2off(va):guest.va2off(va)+4]==word,hex(address)
        result.append(dict(native=hex(address),guest=hex(va),word=word.hex()))
    return dict(uuid=base.IMAGE_UUID,image_sha256=base.IMAGE_SHA,sites=result)


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args();assert not args.output.exists()
    record=dict(status='RUNNING',hardware_access=False,image_sha256=IMAGE_SHA,image_uuid=UUID,
        sources_sha256={str(p):base.sha(p) for p in [Path(__file__),ROOT/'docs/SKS-MAILBOX-20260928.md',ROOT/'tools/kc-xref.py']},
        discovery=[],negotiation=[],reception=[])
    try:
        for pages in [(1,2,3,4),(2,2,2,2)]:
            native,case=discovery(pages);record['discovery'].append(case)
        for direction in [0,1]:
            for status in [0,0xe00002bd]:
                native,case=negotiate(direction,status);record['negotiation'].append(case)
        record['manager_guest_binding']=native.guest_binding([
            0x1393c,0x13968,0x13a40,0x13a44,0x13a50,0x13a54,0x13ab0,0x13ab4,
            0x2a780,0x2a784,0x2a79c,0x2a7a0,0x2a7b0,0x2a7c0,0x2a7d0,
            0x34600,0x34604,0x34608,0x3460c,0x34628,0x3462c,0x34630,0x34634,0x34638])
        for name,tag,command,status,length,want in [
            ('success',0x85,0x19,0,88,'decode-payload'),
            ('refusal',0x85,0x19,1,0,'return-status'),
            ('signed-refusal',0x85,0x19,0xff,0,'return-status'),
            ('wrong-command',0x85,0x18,0,88,'continue-wait'),
            ('missing-reply-flag',5,0x19,0,88,'continue-wait'),
            ('different-low-tag',0x86,0x19,1,0,'return-status')]:
            receiver=KeyStoreReceiver()
            word=int.from_bytes(struct.pack('<BBBBHH',3,tag,command,status,0,length),'little')
            case=receiver.run(word);assert case['decision']==want,(name,case)
            assert case['wakes']==int(bool(tag&0x80))
            if want=='return-status':assert int(case['result'],16)==(status if status<128 else status-256)&0xffffffff
            case['name']=name;record['reception'].append(case)
        record['keystore_guest_binding']=keystore_binding(receiver,[
            0x1343c,0x13440,0x1348c,0x13490,0x13494,0x12b60,0x12b64,0x12b68,
            0x12b6c,0x12b70,0x12b74,0x12b78,0x12b7c,0x12b80,0x12cd8,0x13130])
        record.update(status='NATIVE_SKS_DISCOVERY_OOL_AND_REPLY_CONTRACT_QUALIFIED',
            boundary='Native discovery/getters/name formatter and OOL builders; publication and control transport/tag assignment are fixtures. Native SKS callback and gated reply decision execute, stopping before payload decoding or cleanup. Low tag is not checked at these native gates. No hardware or integrated endpoint proof.')
    except Exception as error:
        record.update(status='FAILED',error=repr(error));raise
    finally:
        args.output.write_text(json.dumps(record,indent=2)+'\n')
    print(json.dumps(dict(status=record['status'],output=str(args.output),sha256=base.sha(args.output))))


if __name__=='__main__':main()

#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Replay 26A428 BootPolicy discovery and original OS-type library code.

The C backend supplies the advertisements and reply payload. Allocator, logging,
transport and free are explicit fixtures; PAC is omitted. This validates the
native consumer contract offline, not physical transport or SEP firmware.
"""
from pathlib import Path
import hashlib,json,runpy,struct,subprocess,sys

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'build/test-python-deps'))
from unicorn import Uc,UC_ARCH_ARM64,UC_MODE_ARM,UC_HOOK_CODE
import unicorn.arm64_const as reg
from capstone import Cs,CS_ARCH_ARM64,CS_MODE_ARM

LIB_SHA='c1c2a3e7d7626a1edf76c91336b7f550f52f71ba8a84a4c5cd391f7cdc125232'
START=0x19dfb7564
DATA=0x1000000
REQ=DATA+0x1000
RESPONSE=DATA+0x2000
OUT=DATA+0x3000
RETURN=DATA+0x4000
LOGGER=0x1c3da0690
REQUEST=struct.pack('<8I',0x42506368,0x3e,0,0,0,0,0,0)
BS_SHA='b51910d2fbe06afac6aa05d0ac4e463087a142029eaf37a0849e42aef58fd739'


def early_task(os_type):
    """Run the exact post-getter branch, stopping before the ACM call."""
    data=Path('/Volumes/macOS Base System/usr/libexec/bs-early-tasks').read_bytes()
    assert hashlib.sha256(data).hexdigest()==BS_SHA
    u=Uc(UC_ARCH_ARM64,UC_MODE_ARM);u.mem_map(0x100000000,0x4000)
    # The pinned Mach-O __TEXT maps file offset zero at this address.
    assert data[:4]==b'\xcf\xfa\xed\xfe'
    offset=32;found=False
    for _ in range(struct.unpack_from('<I',data,16)[0]):
        cmd,size=struct.unpack_from('<II',data,offset)
        if cmd==0x19 and data[offset+8:offset+24].rstrip(b'\0')==b'__TEXT':
            va,vmsize,fo,fs=struct.unpack_from('<4Q',data,offset+24)
            assert va==0x100000000 and fo==0 and fs==0x4000
            found=True
        offset+=size
    assert found
    u.mem_write(0x100000000,data[:0x4000]);u.mem_map(DATA,0x1000)
    u.reg_write(reg.UC_ARM64_REG_SP,DATA)
    u.mem_write(DATA+0x20,struct.pack('<I',os_type))
    stop=[]
    def hook(u,pc,size,unused):
        if pc==0x1000008ec:
            assert [u.reg_read(getattr(reg,f'UC_ARM64_REG_X{n}')) for n in range(4)]==[0x1f,0,0,0]
            stop.append('ACM-recovery-selector');u.emu_stop()
        elif pc==0x100000900:stop.append('not-recovery');u.emu_stop()
    u.hook_add(UC_HOOK_CODE,hook);u.emu_start(0x1000008cc,0x100000910,count=32)
    assert len(stop)==1
    return stop[0]


class Library:
    def __init__(self,path):
        data=path.read_bytes();assert hashlib.sha256(data).hexdigest()==LIB_SHA
        self.u=Uc(UC_ARCH_ARM64,UC_MODE_ARM);self.instructions={};mapped=set()
        md=Cs(CS_ARCH_ARM64,CS_MODE_ARM)
        def map_range(va,size):
            for page in range(va&~0xfff,(va+size+0xfff)&~0xfff,0x1000):
                if page not in mapped:self.u.mem_map(page,0x1000);mapped.add(page)
        offset=32
        for _ in range(struct.unpack_from('<I',data,16)[0]):
            cmd,size=struct.unpack_from('<II',data,offset)
            if cmd==0x19:
                va,vmsize,fo,fs=struct.unpack_from('<4Q',data,offset+24)
                assert vmsize<0x1000000
                if vmsize:map_range(va,vmsize)
                if fs:self.u.mem_write(va,data[fo:fo+fs])
                if data[offset+8:offset+24].rstrip(b'\0')==b'__TEXT':
                    nsects=struct.unpack_from('<I',data,offset+64)[0]
                    for n in range(nsects):
                        section=offset+72+n*80
                        if data[section:section+16].rstrip(b'\0')==b'__text':
                            address,length=struct.unpack_from('<QQ',data,section+32)
                            raw=data[fo+address-va:fo+address-va+length]
                            self.instructions={i.address:i for i in md.disasm(raw,address)}
            offset+=size
        map_range(DATA,0x20000);map_range(LOGGER,8)
        self.u.hook_add(UC_HOOK_CODE,self.hook)

    def put(self,pa,fmt,*args):self.u.mem_write(pa,struct.pack(fmt,*args))
    def call(self,pc,result=0):
        self.u.reg_write(reg.UC_ARM64_REG_X0,result)
        self.u.reg_write(reg.UC_ARM64_REG_PC,pc+4)
    def finish(self,reason):self.stop=reason;self.u.emu_stop()

    def hook(self,u,pc,size,_):
        ins=self.instructions.get(pc)
        assert ins is not None,f'unmodeled library exit {pc:x}'
        if ins.mnemonic in ('pacibsp','autibsp','autda','xpacd','pacia'):
            u.reg_write(reg.UC_ARM64_REG_PC,pc+4);return
        if ins.mnemonic=='retab':
            u.reg_write(reg.UC_ARM64_REG_PC,u.reg_read(reg.UC_ARM64_REG_X30));return
        if pc in (0x19dfb7640,0x19dfb7664):
            length=32 if pc==0x19dfb7640 else 36
            assert u.reg_read(reg.UC_ARM64_REG_X0)==1 and u.reg_read(reg.UC_ARM64_REG_X1)==length
            address=REQ if length==32 else RESPONSE
            u.mem_write(address,bytes(length));self.call(pc,address);return
        if pc==0x19dfc4108:
            assert u.reg_read(reg.UC_ARM64_REG_X1)==32
            self.request=bytes(u.mem_read(u.reg_read(reg.UC_ARM64_REG_X0),32))
            assert self.request==REQUEST
            length_at=u.reg_read(reg.UC_ARM64_REG_X3)
            assert struct.unpack('<Q',u.mem_read(length_at,8))[0]==36
            u.mem_write(u.reg_read(reg.UC_ARM64_REG_X2),self.payload)
            self.put(length_at,'<Q',self.length)
            self.call(pc,self.transport_status);return
        if pc in (0x19dfb75a8,0x19dfb7780,0x19dfb78bc,0x19dfc41c4,
                  0x19dfb77d4,0x19dfb77dc):
            self.call(pc);return
        failures={0x19dfc43e0:'transport',0x19dfc43ec:'short-header',
                  0x19dfc43f8:'magic',0x19dfc4404:'oversized',
                  0x19dfb79b0:'status',0x19dfb79bc:'fixed-length'}
        if pc in failures:self.finish(failures[pc]);return
        if ins.mnemonic in ('bl','blr','blraa','blraaz','braa','brk'):
            assert pc in (0x19dfb7684,0x19dfb7988),f'unmodeled call {pc:x}: {ins.mnemonic} {ins.op_str}'

    def run(self,payload,length=None,transport_status=0):
        self.payload=payload;self.length=len(payload) if length is None else length
        self.transport_status=transport_status;self.stop=None;self.request=None
        self.u.mem_write(DATA,bytes(0x20000));self.put(LOGGER,'<Q',1)
        self.put(OUT,'<I',0xaabbccdd)
        for n in range(31):self.u.reg_write(getattr(reg,f'UC_ARM64_REG_X{n}'),0)
        self.u.reg_write(reg.UC_ARM64_REG_X0,OUT)
        self.u.reg_write(reg.UC_ARM64_REG_X30,RETURN)
        self.u.reg_write(reg.UC_ARM64_REG_SP,DATA+0x1f000)
        self.u.reg_write(reg.UC_ARM64_REG_CPACR_EL1,3<<20)
        self.u.emu_start(START,RETURN,count=10000)
        if self.u.reg_read(reg.UC_ARM64_REG_PC)==RETURN:self.stop='return'
        assert self.stop is not None,'library instruction budget exhausted'
        return self.stop,self.u.reg_read(reg.UC_ARM64_REG_W0),struct.unpack('<I',self.u.mem_read(OUT,4))[0]


class KernelWire:
    """Original send builder and receive callback with explicit IOKit fixtures."""
    CONTEXT=DATA+0x10000
    MESSAGE=DATA+0x30000
    GATE=DATA+0x1000
    VTABLE=DATA+0x2000
    def __init__(self,kernel):
        self.u=Uc(UC_ARCH_ARM64,UC_MODE_ARM)
        base=0xfffffe0009ef5000
        self.u.mem_map(base,0x2000)
        raw=kernel.data[kernel.va2off(base):kernel.va2off(base)+0x2000]
        self.u.mem_write(base,raw);self.u.mem_map(DATA,0x100000)
        self.instructions={i.address:i for i in Cs(CS_ARCH_ARM64,CS_MODE_ARM).disasm(raw,base)}
        self.u.hook_add(UC_HOOK_CODE,self.hook)
    def put(self,pa,fmt,*values):self.u.mem_write(pa,struct.pack(fmt,*values))
    def call(self,pc,value=0):
        self.u.reg_write(reg.UC_ARM64_REG_X0,value);self.u.reg_write(reg.UC_ARM64_REG_PC,pc+4)
    def hook(self,u,pc,size,_):
        ins=self.instructions.get(pc);assert ins is not None,f'unmodeled kernel exit {pc:x}'
        if ins.mnemonic in ('pacibsp','autibsp','autda'):
            u.reg_write(reg.UC_ARM64_REG_PC,pc+4);return
        if ins.mnemonic=='retab':u.reg_write(reg.UC_ARM64_REG_PC,u.reg_read(reg.UC_ARM64_REG_X30));return
        if pc==0xfffffe0009ef5fe8:self.call(pc,self.GATE);return
        if pc==0xfffffe0009ef6020:
            assert u.reg_read(reg.UC_ARM64_REG_X0)==self.GATE
            assert u.reg_read(reg.UC_ARM64_REG_X2)==self.CONTEXT and u.reg_read(reg.UC_ARM64_REG_X3)==1
            self.sent=struct.unpack('<Q',u.mem_read(u.reg_read(reg.UC_ARM64_REG_X1),8))[0]
            self.call(pc);return
        if pc==0xfffffe0009ef5c14:
            assert u.reg_read(reg.UC_ARM64_REG_X0)==DATA
            assert u.reg_read(reg.UC_ARM64_REG_X1)==self.CONTEXT+5
            n=u.reg_read(reg.UC_ARM64_REG_X2);assert n<=0x14000
            assert n==len(self.body)
            u.mem_write(self.CONTEXT+5,self.body);self.copies+=1
            self.call(pc,n if self.copy_ok else n-1);return
        if pc in (0xfffffe0009ef5cc4,0xfffffe0009ef5cf8):self.call(pc);return
        if pc==0xfffffe0009ef5c80:
            assert u.reg_read(reg.UC_ARM64_REG_X0)==self.GATE
            assert u.reg_read(reg.UC_ARM64_REG_X1)==self.CONTEXT and u.reg_read(reg.UC_ARM64_REG_X2)==0
            self.wake=True;u.emu_stop();return
        if ins.mnemonic in ('bl','blr','blraa','braa','brk'):
            raise AssertionError(f'unmodeled kernel call {pc:x}: {ins.mnemonic}')
    def prepare(self):
        self.u.mem_write(DATA,bytes(0x100000));self.sent=None;self.wake=False;self.copies=0
        self.put(DATA+0x88,'<Q',self.GATE);self.put(self.GATE,'<Q',self.VTABLE)
        for n in range(31):self.u.reg_write(getattr(reg,f'UC_ARM64_REG_X{n}'),0)
        self.u.reg_write(reg.UC_ARM64_REG_SP,DATA+0xf0000)
        self.u.reg_write(reg.UC_ARM64_REG_X30,RETURN)
        self.u.reg_write(reg.UC_ARM64_REG_X0,DATA)
        self.u.reg_write(reg.UC_ARM64_REG_X1,self.CONTEXT)
    def send(self,n):
        self.prepare();self.u.reg_write(reg.UC_ARM64_REG_X2,n)
        self.u.emu_start(0xfffffe0009ef5fc0,RETURN,count=1000)
        assert self.u.reg_read(reg.UC_ARM64_REG_PC)==RETURN
        return self.sent
    def receive(self,word,body,copy_ok=True):
        self.prepare();self.body=body;self.copy_ok=copy_ok
        self.put(self.MESSAGE,'<Q',word);self.u.reg_write(reg.UC_ARM64_REG_X2,self.MESSAGE)
        self.u.emu_start(0xfffffe0009ef5bb0,RETURN,count=1000)
        assert self.wake
        return (struct.unpack('<I',self.u.mem_read(self.CONTEXT,4))[0],
                struct.unpack('<I',self.u.mem_read(self.CONTEXT+0x14008,4))[0])


def main():
    producer=subprocess.run([str(ROOT/'build/test-sep-pnon'),'--wire',
        str(ROOT/'build/sep-rom-slot-live-20260922-sep-shared.bin')],
        capture_output=True,text=True,check=True).stdout.splitlines()
    name,ool,reply=map(lambda line:int(line,16),producer[:3]);payload=bytes.fromhex(producer[3])
    assert reply==36<<32|0x201 and len(payload)==36
    discovery=runpy.run_path(str(ROOT/'tools/replay-sep-discovery.py'))
    kernel=runpy.run_path(str(ROOT/'tools/kc-xref.py'))['Kernelcache'](
        ROOT/'downloads/extracted/j700ap/kernelcache.release.mac17p')
    assert hashlib.sha256(kernel.data).hexdigest()==discovery['KERNEL_SHA']
    parser=discovery['Parser'](kernel)
    assert parser.send(struct.pack('<Q',name))=='return'
    assert parser.send(struct.pack('<Q',ool))=='publish'
    assert parser.publications==[struct.pack('<IB4B',0x706e6f6e,1,7,7,5,5).hex()]
    checks=2
    lib=Library(ROOT/'build/research/bootpolicy-26A428/libbootpolicy.dylib')
    assert lib.run(payload)==('return',0,2);checks+=1
    for os_type in range(256):
        altered=bytearray(payload);altered[32]=os_type
        assert lib.run(bytes(altered))==('return',0,os_type if os_type<6 else 255);checks+=1
    for length in range(40):
        if length==36:continue
        expected='short-header' if length<32 else 'oversized' if length>36 else 'fixed-length'
        outcome,_,value=lib.run(payload,length)
        assert outcome==expected and value==0xaabbccdd;checks+=1
    for byte in range(4):
        for bit in range(8):
            altered=bytearray(payload);altered[byte]^=1<<bit
            outcome,_,value=lib.run(bytes(altered))
            assert outcome=='magic' and value==0xaabbccdd;checks+=1
    for status in (1,2,0xffffffff):
        altered=bytearray(payload);struct.pack_into('<I',altered,4,status)
        outcome,_,value=lib.run(bytes(altered))
        assert outcome=='status' and value==0xaabbccdd;checks+=1
        outcome,_,value=lib.run(payload,transport_status=status)
        assert outcome=='transport' and value==0xaabbccdd;checks+=1
    for os_type in (*range(6),255):
        assert early_task(os_type)==('ACM-recovery-selector' if os_type in (1,2) else 'not-recovery')
        checks+=1
    wire=KernelWire(kernel)
    assert wire.send(32)==32<<32|0x200;checks+=1
    assert wire.receive(reply,payload)==(0,36) and wire.copies==1
    assert wire.u.mem_read(wire.CONTEXT+5,36)==payload;checks+=1
    for status in range(256):
        assert wire.receive(reply|status<<16,payload)==(status,36);checks+=1
    for kind in range(256):
        if kind==2:continue
        assert wire.receive(36<<32|kind<<8|1,payload)==(0xe00002c2,0)
        assert not wire.copies;checks+=1
    for length in (0x14001,0xffffffff):
        assert wire.receive(length<<32|0x201,b'')==(0xe00002c2,0) and not wire.copies;checks+=1
    assert wire.receive(reply,payload,copy_ok=False)==(0xe00002c9,0);checks+=1
    print(json.dumps(dict(checks=checks,library_sha256=LIB_SHA,
        kernel_sha256=discovery['KERNEL_SHA'],early_tasks_sha256=BS_SHA,os_type=2,request=REQUEST.hex(),
        response=payload.hex(),boundary=__doc__.strip()),indent=2))


if __name__=='__main__':main()

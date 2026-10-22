#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Replay original 26A428 code against the pnon not-supported reply.

mobileassetd's bootpolicy_get_blessed_recoveryos_policy_nonce_digest sends
BootPolicy command 0x10 and expects an 80-byte reply; the virtual SEP has no
policy nonce storage, so it answers with a 32-byte header carrying status 0xff.
This runs the C producer's actual request/reply bytes through the original
kernel receive callback and the original libbootpolicy nonce-digest path
(__get_policy_nonce_digest -> __sep_command_with_fixed_output -> __sep_command)
and checks the caller gets error 255 ("not supported") with its output
untouched. Allocator, free, logging and the transport call are explicit
fixtures; PAC is omitted. Offline evidence, not physical delivery.
"""
from pathlib import Path
import hashlib,json,runpy,struct,subprocess,sys

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'build/test-python-deps'))
from unicorn import Uc,UC_ARCH_ARM64,UC_MODE_ARM,UC_HOOK_CODE,UC_HOOK_MEM_READ_UNMAPPED
import unicorn.arm64_const as reg
from capstone import Cs,CS_ARCH_ARM64,CS_MODE_ARM

os_type=runpy.run_path(str(ROOT/'tools/replay-bootpolicy-os-type.py'),run_name='replay_os_type')
LIB_SHA=os_type['LIB_SHA']
DIGEST=0x19dfc28a8          # __get_policy_nonce_digest(command, out)
SEP_SEND=0x19dfc4108        # bl __sep_send inside __sep_command
CALLOC=0x1a00b4980
FREE=0x1a00b47b0
DATA=0x1000000
OUT=DATA+0x3000
RETURN=DATA+0x4000
HEAP=DATA+0x8000
LOGGER=0x1c3da0690


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
                if vmsize:map_range(va,vmsize)
                if fs:self.u.mem_write(va,data[fo:fo+fs])
                if data[offset+8:offset+24].rstrip(b'\0')==b'__TEXT':
                    for n in range(struct.unpack_from('<I',data,offset+64)[0]):
                        section=offset+72+n*80
                        if data[section:section+16].rstrip(b'\0')==b'__text':
                            address,length=struct.unpack_from('<QQ',data,section+32)
                            raw=data[fo+address-va:fo+address-va+length]
                            self.instructions={i.address:i for i in md.disasm(raw,address)}
            offset+=size
        map_range(DATA,0x20000);map_range(LOGGER,8);self.mapped=mapped;self.external=set()
        self.u.hook_add(UC_HOOK_CODE,self.hook)
        self.u.hook_add(UC_HOOK_MEM_READ_UNMAPPED,self.unmapped)

    def unmapped(self,u,access,address,size,value,_):
        # Globals in other dyld-cache images (os_log's default object): zero.
        page=address&~0xfff
        assert 0x180000000<=address<0x200000000,f'wild read {address:x}'
        u.mem_map(page,0x1000);self.mapped.add(page);self.external.add(page)
        return True

    def ret(self,pc,value=0):
        self.u.reg_write(reg.UC_ARM64_REG_X0,value);self.u.reg_write(reg.UC_ARM64_REG_PC,pc+4)

    def hook(self,u,pc,_size,_):
        ins=self.instructions.get(pc)
        assert ins is not None,f'unmodeled library exit {pc:x}'
        if ins.mnemonic in ('pacibsp','autibsp','autda','xpacd','pacia'):
            u.reg_write(reg.UC_ARM64_REG_PC,pc+4);return
        if ins.mnemonic=='retab':
            u.reg_write(reg.UC_ARM64_REG_PC,u.reg_read(reg.UC_ARM64_REG_X30));return
        if pc==SEP_SEND:
            assert u.reg_read(reg.UC_ARM64_REG_X1)==32
            self.request=bytes(u.mem_read(u.reg_read(reg.UC_ARM64_REG_X0),32))
            length_at=u.reg_read(reg.UC_ARM64_REG_X3)
            self.capacity=struct.unpack('<Q',u.mem_read(length_at,8))[0]
            u.mem_write(u.reg_read(reg.UC_ARM64_REG_X2),self.payload)
            u.mem_write(length_at,struct.pack('<Q',len(self.payload)))
            self.ret(pc,0);return
        if ins.mnemonic=='bl' and ins.op_str=='#0x%x'%CALLOC:
            count,unit=u.reg_read(reg.UC_ARM64_REG_X0),u.reg_read(reg.UC_ARM64_REG_X1)
            self.allocations.append(count*unit);address=HEAP+0x1000*len(self.allocations)
            u.mem_write(address,bytes(count*unit));self.ret(pc,address);return
        if ins.mnemonic=='bl' and ins.op_str=='#0x%x'%FREE:
            self.frees+=1;self.ret(pc);return
        if ins.mnemonic in ('bl','blr','blraa','blraaz','braa','braaz','b'):
            target=ins.op_str
            if target.startswith('#'):
                address=int(target[1:],16)
                if address in self.instructions:return   # original library code runs
            # os_log and friends outside the image: report "disabled". A plain
            # branch there is a tail call, so return to the caller's caller.
            if ins.mnemonic.startswith('bl'):self.ret(pc);return
            if ins.mnemonic=='b' and target.startswith('#'):
                u.reg_write(reg.UC_ARM64_REG_X0,0)
                u.reg_write(reg.UC_ARM64_REG_PC,u.reg_read(reg.UC_ARM64_REG_X30));return
            raise AssertionError(f'unmodeled branch {pc:x}: {ins.mnemonic} {ins.op_str}')
        if ins.mnemonic=='brk':raise AssertionError(f'trap at {pc:x}')

    def digest(self,command,payload):
        self.payload=payload;self.request=None;self.capacity=None
        self.allocations=[];self.frees=0
        self.u.mem_write(DATA,bytes(0x20000));self.u.mem_write(LOGGER,bytes(8))
        self.u.mem_write(OUT,b'\xdd'*48)
        for n in range(31):self.u.reg_write(getattr(reg,f'UC_ARM64_REG_X{n}'),0)
        self.u.reg_write(reg.UC_ARM64_REG_X0,command)
        self.u.reg_write(reg.UC_ARM64_REG_X1,OUT)
        self.u.reg_write(reg.UC_ARM64_REG_X30,RETURN)
        self.u.reg_write(reg.UC_ARM64_REG_SP,DATA+0x1f000)
        self.u.reg_write(reg.UC_ARM64_REG_CPACR_EL1,3<<20)
        self.u.emu_start(DIGEST,RETURN,count=20000)
        assert self.u.reg_read(reg.UC_ARM64_REG_PC)==RETURN,'did not return'
        return (self.u.reg_read(reg.UC_ARM64_REG_W0),bytes(self.u.mem_read(OUT,48)),
                self.request,self.capacity)


def main():
    producer=subprocess.run([str(ROOT/'build/test-sep-pnon'),'--wire-unsupported',
        str(ROOT/'build/sep-rom-slot-live-20260922-sep-shared.bin')],
        capture_output=True,text=True,check=True).stdout.splitlines()
    word=int(producer[0],16);request=bytes.fromhex(producer[1]);reply=bytes.fromhex(producer[2])
    assert word==32<<32|0x201 and len(request)==32 and len(reply)==32
    checks=0
    lib=Library(ROOT/'build/research/bootpolicy-26A428/libbootpolicy.dylib')
    status,out,sent,capacity=lib.digest(0x10,reply)
    assert sent==request,'library request differs from the one the model answered'
    assert capacity==0x50,'blessed digest expects an 80-byte reply'
    assert status==0xff and out==b'\xdd'*48,'not-supported must reach the caller, output untouched'
    assert lib.allocations==[0x20,0x50] and lib.frees==2;checks+=1
    # Every nonce-digest command the library has takes the same path.
    for command in (0x0b,0x0c,0x0d,0x0e,0x0f,0x10):
        altered=bytearray(request);altered[4]=command
        status,out,sent,_=lib.digest(command,reply)
        assert sent==bytes(altered) and status==0xff and out==b'\xdd'*48;checks+=1
    # Control: a real 80-byte success reply fills the 48-byte digest.
    good=struct.pack('<8I',0x42507268,0,0,0,0,0,0,0)+bytes(range(48))
    status,out,_,_=lib.digest(0x10,good)
    assert status==0 and out==bytes(range(48));checks+=1
    for s in (1,2,3,0x12):
        bad=bytearray(reply);bad[4]=s
        assert lib.digest(0x10,bytes(bad))[0]==s;checks+=1
    # Kernel side: the original receive callback copies 32 bytes, status zero.
    kernel=runpy.run_path(str(ROOT/'tools/kc-xref.py'))['Kernelcache'](
        ROOT/'downloads/extracted/j700ap/kernelcache.release.mac17p')
    discovery=runpy.run_path(str(ROOT/'tools/replay-sep-discovery.py'))
    assert hashlib.sha256(kernel.data).hexdigest()==discovery['KERNEL_SHA']
    wire=os_type['KernelWire'](kernel)
    assert wire.receive(word,reply)==(0,32) and wire.copies==1
    assert bytes(wire.u.mem_read(wire.CONTEXT+5,32))==reply;checks+=1
    print(json.dumps(dict(checks=checks,library_sha256=LIB_SHA,kernel_sha256=discovery['KERNEL_SHA'],
        command='0x10 blessed recoveryOS policy nonce digest',reply_word=hex(word),
        request=request.hex(),reply=reply.hex(),caller_status=255,
        external_zero_pages=sorted(hex(p) for p in lib.external)),indent=2))


if __name__=='__main__':main()

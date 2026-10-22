#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Replay original 26A428 code for BootPolicy commands that carry a body.

Most libbootpolicy commands send more than the 32-byte header: security
mode, SIP flags, policy tags, pairing status, MDM state and every policy
create/update. __sep_command always writes the same header (magic, command
word, 24 zero bytes) at the start of the request and the caller's body after
it. The virtual SEP now answers any such command with the 32-byte
not-supported header (status 0xff), reading only the header.

Checks, all on original Apple instructions:
  * the kext's send builder turns every request length into the word the C
    model accepts (kind 0x201 after the endpoint byte, DATA = length);
  * for each distinct fixed-output (command, length, capacity) with a body
    (29 tuples from the 26A428 call sites, lengths 0x124..0x8168) and for
    the policy commands issued through __sep_command, the library writes
    the header the model reads, and the C producer's
    reply makes the library return 255 ("not supported") with the caller's
    output untouched;
  * the kext's receive callback copies the 32-byte reply with transport
    status 0, as for the existing 32-byte refusal.
Allocator, logging, the transport and IOKit are fixtures; PAC is omitted.
Offline evidence, not physical delivery.
"""
from pathlib import Path
import hashlib,json,runpy,struct,subprocess,sys

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'build/test-python-deps'))
import unicorn.arm64_const as reg

unsupported=runpy.run_path(str(ROOT/'tools/replay-bootpolicy-unsupported.py'),run_name='replay_unsupported')
os_type=runpy.run_path(str(ROOT/'tools/replay-bootpolicy-os-type.py'),run_name='replay_os_type')
LIB_SHA=os_type['LIB_SHA']
FIXED=0x19dfb7968          # __sep_command_with_fixed_output(cmd, req, len, resp, cap)
COMMAND=0x19dfc40b4        # __sep_command(cmd, req, len, resp, cap, &resp_len)
SEP_SEND=0x19dfc4108       # bl __sep_send inside __sep_command
DATA=unsupported['DATA']
BUFFERS=0x2000000          # separately mapped; the base harness maps DATA..+0x20000
REQUEST=BUFFERS            # room for the largest 0x1c000-byte request
RESPONSE=BUFFERS+0x20000
RESPONSE_LENGTH=BUFFERS+0x30000
RETURN=DATA+0x4000
BODY=0xb5

# (command, request length, response capacity) at each 26A428 fixed-output
# call site whose request carries a body, read from the call-site arguments.
FIXED_SITES=[(0x43,0x4028,0x24),(0x16,0x124,0x20),(0x19,0x124,0x20),(0x1d,0x1124,0x20),
    (0x35,0x4130,0x4054),(0x11,0x4028,0x24),(0x3d,0x4030,0x50),(0x18,0x4058,0x24),
    (0x3c,0x4030,0x28),(0x4c,0x4030,0x30),(0x3b,0x4030,0x24),(0x45,0x8138,0x4054),
    (0x17,0x8168,0x4054),(0x1a,0x8138,0x4054),(0x1f,0x8140,0x4054),(0x42,0x4130,0x4054),
    (0x32,0x4130,0x20),(0x25,0x124,0x20),(0x3a,0x4028,0x24),(0x47,0x4028,0x24),
    (0x39,0x4130,0x4054),(0x30,0x4130,0x4054),(0x31,0x4130,0x4054),(0x44,0x8030,0x24),
    (0x15,0x130,0x20),(0x40,0x4028,0x20),(0x1b,0x4130,0x4024),(0x13,0x4130,0x4024),
    (0x4d,0x124,0x20)]
# Commands issued straight through __sep_command by the policy builders
# (_bootpolicy_create_local_policy_ex2 and friends); their lengths are built
# at run time, so representative lengths up to the whole send buffer are used.
POLICY_COMMANDS=[0x4e,0x4f,0x51,0x52,0x53,0x54,0x55,0x56,0x58,0x59,0x5a,0x5b,0x5c,0x5d]
POLICY_LENGTHS=[0x21,0x1000,0x8000,0x1bfe0,0x1c000]


class Library(unsupported['Library']):
    def __init__(self,path):
        super().__init__(path)
        self.u.mem_map(BUFFERS,0x40000)

    def hook(self,u,pc,size,user):
        if pc==SEP_SEND:
            length=u.reg_read(reg.UC_ARM64_REG_X1)
            base=u.reg_read(reg.UC_ARM64_REG_X0)
            self.sent=(length,bytes(u.mem_read(base,32)),bytes(u.mem_read(base+32,min(length-32,64))))
            length_at=u.reg_read(reg.UC_ARM64_REG_X3)
            self.capacity=struct.unpack('<Q',u.mem_read(length_at,8))[0]
            u.mem_write(u.reg_read(reg.UC_ARM64_REG_X2),self.payload)
            u.mem_write(length_at,struct.pack('<Q',len(self.payload)))
            self.ret(pc,0);return
        return super().hook(u,pc,size,user)

    def run(self,entry,args,payload,length,capacity):
        self.payload=payload;self.sent=None;self.capacity=None
        self.allocations=[];self.frees=0
        self.u.mem_write(DATA,bytes(0x20000))
        self.u.mem_write(REQUEST,bytes([BODY])*length)   # caller's body; header area too
        self.u.mem_write(RESPONSE,b'\xdd'*capacity)
        self.u.mem_write(RESPONSE_LENGTH,b'\xee'*8)
        for n in range(31):self.u.reg_write(getattr(reg,f'UC_ARM64_REG_X{n}'),0)
        for n,value in enumerate(args):self.u.reg_write(getattr(reg,f'UC_ARM64_REG_X{n}'),value)
        self.u.reg_write(reg.UC_ARM64_REG_X30,RETURN)
        self.u.reg_write(reg.UC_ARM64_REG_SP,DATA+0x1f000)
        self.u.reg_write(reg.UC_ARM64_REG_CPACR_EL1,3<<20)
        self.u.emu_start(entry,RETURN,count=20000)
        assert self.u.reg_read(reg.UC_ARM64_REG_PC)==RETURN,'did not return'
        return self.u.reg_read(reg.UC_ARM64_REG_W0)


def header(command):return struct.pack('<2I24x',0x42506368,command)


def main():
    shared=str(ROOT/'build/sep-rom-slot-live-20260922-sep-shared.bin')
    lines=subprocess.run([str(ROOT/'build/test-sep-pnon'),'--wire-long',shared],
        capture_output=True,text=True,check=True).stdout.splitlines()
    word=int(lines[0],16);request=bytes.fromhex(lines[1]);reply=bytes.fromhex(lines[2])
    assert word==0x4028<<32|0x201 and request==header(0x11) and len(reply)==32
    assert reply==struct.pack('<8I',0x42507268,0xff,0,0,0,0,0,0)
    checks=0
    lib=Library(ROOT/'build/research/bootpolicy-26A428/libbootpolicy.dylib')

    # Fixed-output commands with a body.
    for command,length,capacity in FIXED_SITES:
        status=lib.run(FIXED,(command,REQUEST,length,RESPONSE,capacity),reply,length,capacity)
        sent_length,sent_header,sent_body=lib.sent
        assert sent_length==length and sent_header==header(command),hex(command)
        assert sent_body==bytes([BODY])*len(sent_body),'body must follow the 32-byte header'
        assert lib.capacity==capacity
        assert status==0xff,f'{command:#x}: library status {status:#x}'
        # The transport fixture wrote the 32-byte reply; the rest of the
        # caller's response buffer is untouched.
        tail=bytes(lib.u.mem_read(RESPONSE+32,capacity-32))
        assert tail==b'\xdd'*(capacity-32);checks+=1
    status=lib.run(FIXED,(0x11,REQUEST,0x4028,RESPONSE,0x24),reply,0x4028,0x24)
    assert lib.sent[1]==request and status==0xff;checks+=1   # byte-exact vs the producer

    # Policy commands issued straight through __sep_command.
    for command in POLICY_COMMANDS:
        for length in POLICY_LENGTHS:
            status=lib.run(COMMAND,(command,REQUEST,length,RESPONSE,0x4000,RESPONSE_LENGTH),
                           reply,length,0x4000)
            assert lib.sent[0]==length and lib.sent[1]==header(command)
            assert status==0xff and struct.unpack('<Q',lib.u.mem_read(RESPONSE_LENGTH,8))[0]==32;checks+=1

    # Control: a real success header still returns zero through the same path.
    ok=struct.pack('<8I',0x42507268,0,0,0,0,0,0,0)+bytes(4)
    assert lib.run(FIXED,(0x11,REQUEST,0x4028,RESPONSE,0x24),ok,0x4028,0x24)==0;checks+=1

    # Kernel side: the original send builder emits kind 2 and DATA = length for
    # every length (the endpoint adds byte0 = 1); the receive callback copies
    # the 32-byte refusal with transport status 0.
    kernel=runpy.run_path(str(ROOT/'tools/kc-xref.py'))['Kernelcache'](
        ROOT/'downloads/extracted/j700ap/kernelcache.release.mac17p')
    discovery=runpy.run_path(str(ROOT/'tools/replay-sep-discovery.py'))
    assert hashlib.sha256(kernel.data).hexdigest()==discovery['KERNEL_SHA']
    wire=os_type['KernelWire'](kernel)
    lengths=sorted({l for _,l,_ in FIXED_SITES}|set(POLICY_LENGTHS)|{0x20})
    for length in lengths:
        assert wire.send(length)|1==length<<32|0x201;checks+=1
    assert wire.send(0x4028)|1==word;checks+=1
    assert wire.receive(0x20<<32|0x201,reply)==(0,32) and wire.copies==1
    assert bytes(wire.u.mem_read(wire.CONTEXT+5,32))==reply;checks+=1
    print(json.dumps(dict(checks=checks,library_sha256=LIB_SHA,kernel_sha256=discovery['KERNEL_SHA'],
        fixed_output_sites=len(FIXED_SITES),policy_commands=[hex(c) for c in POLICY_COMMANDS],
        producer_word=hex(word),producer_request=request.hex(),producer_reply=reply.hex(),
        caller_status=255),indent=2))


if __name__=='__main__':main()

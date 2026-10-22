#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Replay native SKS startup through the compiled volatile wire model."""
from pathlib import Path
import argparse
import ctypes as C
import hashlib
import importlib.util
import json
import struct
import subprocess

ROOT=Path(__file__).resolve().parents[1]
sha=lambda p:hashlib.sha256(Path(p).read_bytes()).hexdigest()
REPLIES=ROOT/'build/sks-native-replies-20260928-v2.json'
REPLIES_SHA='565213fc1538423ca618f86b7f6a43302bb07337e015032ce455b7019a9c4913'
assert sha(REPLIES)==REPLIES_SHA
for path,digest in json.loads(REPLIES.read_text())['inputs_sha256'].items():
    assert sha(path)==digest,path
spec=importlib.util.spec_from_file_location('sks_reply',ROOT/'tools/replay-sks-replies.py')
replay=importlib.util.module_from_spec(spec);spec.loader.exec_module(replay)
b=replay.base
CODE={0x4d:0x33310,0x2a:0x2e730,0x19:b.CODE}


class State(C.Structure):
    _fields_=[('updates',C.c_uint64),('environment_valid',C.c_uint32),
              ('environment',C.c_ubyte*1036)]


class Model:
    def __init__(self,library):
        self.state=State()
        self.library=C.CDLL(str(library))
        self.call=self.library.sep_sks_wire
        self.call.argtypes=[C.POINTER(State),C.c_uint32,C.c_void_p,C.c_uint32,
                           C.c_void_p,C.c_uint32,C.POINTER(C.c_uint32)]
        self.call.restype=C.c_int

    def exchange(self,command,request,capacity=4096):
        src=C.create_string_buffer(request)
        dest=C.create_string_buffer(b'\xcc'*(capacity+32))
        size=C.c_uint32(0xdeadbeef)
        before=bytes(self.state)
        result=self.call(C.byref(self.state),command,src,len(request),dest,capacity,C.byref(size))
        assert dest.raw[capacity:capacity+32]==b'\xcc'*32
        if result:
            assert size.value==0 and dest.raw[:capacity]==b'\xcc'*capacity
            assert bytes(self.state)==before
            response=b''
        else:
            assert 0<size.value<=capacity
            assert dest.raw[size.value:capacity]==b'\xcc'*(capacity-size.value)
            response=dest.raw[:size.value]
        return result,response


class Startup(replay.ReplyNative):
    def __init__(self,model,refuse_all=False):
        self.model=model;self.refuse_all=refuse_all;self.exchanges=[]
        self.transport=replay.ReplyNative()
        super().__init__()
        singleton=b.DATA+0x61000
        self.put(0x504d0,'<Q',singleton)
        self.put(singleton+0x150,'<Q',b.CALLBACK)

    def hook(self,u,pc,size,unused):
        if pc==0x8e74:
            self.events.append(dict(name='device-tree-property-absent',result=1))
            self.result(1);return
        if self.imports.get(pc)=='_proc_selfpid':
            self.events.append(dict(name='_proc_selfpid',result=1234))
            self.result(1234);return
        if pc==b.CALLBACK:
            command,pointer=self.x(1),self.x(2)
            assert command in CODE
            args=bytes(u.mem_read(pointer,0xf8))
            entry=dict(command=hex(command),context=hex(self.x(0)),args_hex=args.hex())
            self.exchanges.append(entry)
            if self.refuse_all:
                entry['status']=1;self.result(1);return
            transport=self.transport
            transport.u.mem_write(b.ARGS,args)
            if command in [0x4d,0x2a]:
                data_pointer,count=struct.unpack_from('<QI',args,0x60)
                assert count<=0x4000
                if count:
                    payload=bytes(u.mem_read(data_pointer,count))
                    transport.u.mem_write(b.PAYLOAD,payload)
                    transport.put(b.ARGS+0x60,'<Q',b.PAYLOAD)
                    entry['payload_hex']=payload.hex()
            length=transport.invoke(CODE[command],1,0,b.BUF,0x4000,b.ARGS)
            assert 0<length<=0x4000
            request=bytes(transport.u.mem_read(b.BUF,length))
            status,response=self.model.exchange(command,request)
            entry.update(request_hex=request.hex(),response_hex=response.hex(),status=status)
            if status==0:
                transport.u.mem_write(b.REPLY,response)
                transport.u.mem_write(b.DECODE,bytes(0xf8))
                decoded=transport.invoke(CODE[command],0,0,b.REPLY,len(response),b.DECODE)
                assert decoded==len(response)
                output=bytes(transport.u.mem_read(b.DECODE,0xf8))
                if command==0x4d:
                    assert struct.unpack_from('<Q',output,0x70)[0]==2
                    assert output[0x78:0x84]==bytes(12)
                u.mem_write(pointer,output)
                entry['decoded_hex']=output.hex()
            self.result(status);return
        super().hook(u,pc,size,unused)


def resign(message):
    message=bytearray(message)
    message[4:20]=hashlib.sha256(message[20:]).digest()[:16]
    return bytes(message)


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--output-dir',type=Path,required=True)
    args=parser.parse_args();out=args.output_dir.resolve();out.mkdir(exist_ok=False)
    crypto=ROOT.parent/'q1n1/platform/uefi'
    sources=[Path(__file__),ROOT/'docs/SKS-STARTUP-MODEL-20260928.md',
             ROOT/'compat/sep-sks.c',ROOT/'compat/sep-sks.h',crypto/'sha256.c',crypto/'sha256.h']
    record=dict(status='RUNNING',hardware_access=False,replies_sha256=REPLIES_SHA,
                source_sha256={str(p):sha(p) for p in sources},image_sha256=b.IMAGE_SHA,
                image_uuid=b.IMAGE_UUID,boundary='Native startup through compiled C wire model; explicit context and transport fixtures. No endpoint publication, mailbox, OOL, hardware, lock cleanup or GUI proof.')
    try:
        command=['clang','-std=c11','-O2','-Wall','-Wextra','-Werror','-dynamiclib',
                 '-I'+str(crypto),str(ROOT/'compat/sep-sks.c'),str(crypto/'sha256.c'),
                 '-o',str(out/'model.dylib')]
        build=subprocess.run(command,text=True,capture_output=True)
        (out/'build.log').write_text(build.stdout+build.stderr)
        record['build']=dict(command=command,exit=build.returncode)
        assert build.returncode==0,build.stderr
        model=Model(out/'model.dylib');native=Startup(model)
        result=native.invoke(0x1359c)
        version=struct.unpack('<I',native.u.mem_read(0x50418,4))[0]
        assert version==2 and [x['command'] for x in native.exchanges]==['0x4d','0x2a']
        assert [x['status'] for x in native.exchanges]==[0,0]
        environment=bytes.fromhex(native.exchanges[1]['payload_hex'])
        assert model.state.environment_valid==1 and model.state.updates==1
        assert bytes(model.state.environment)==environment
        native.put(b.OUTPTR,'<Q',0x123456789abcdef0);native.put(b.OUTLEN,'<I',0x87654321)
        refused=native.invoke(b.ENTRY,b.CALLBACK,0,0x1122334455667788,0x99aabbcc,
                              0x10203040,b.OUTPTR,b.OUTLEN)
        assert refused==1
        assert bytes(native.u.mem_read(b.OUTPTR,8))==struct.pack('<Q',0x123456789abcdef0)
        assert bytes(native.u.mem_read(b.OUTLEN,4))==struct.pack('<I',0x87654321)
        record['startup']=dict(return_value=result,negotiated_version=version,
            exchanges=native.exchanges,environment_hex=environment.hex(),updates=model.state.updates,
            device_state_refusal=refused,output_sentinels_intact=True,
            fixture_calls=native.events,executed_pcs=[hex(x) for x in sorted(native.executed)],
            transport_fixture_calls=native.transport.events,
            transport_executed_pcs=[hex(x) for x in sorted(native.transport.executed)])
        control=Startup(model,refuse_all=True)
        try:
            control.invoke(0x1359c)
        except AssertionError as error:
            assert 'unmodeled native import _panic' in str(error),str(error)
            panic=bytes(control.u.mem_read(control.x(0),160)).split(b'\0')[0].decode()
            assert 'set_env failed' in panic
            record['all_refusal_control']=dict(expected_panic=panic,commands=[e['command'] for e in control.exchanges],
                pc=hex(control.u.reg_read(b.reg.UC_ARM64_REG_PC)))
        else:
            raise AssertionError('all-refusal startup did not panic')
        negative=[]
        for e in native.exchanges[:2]:
            command=int(e['command'],16);request=bytes.fromhex(e['request_hex'])
            frame=struct.unpack_from('<I',request)[0]+4
            candidates=[('truncated',request[:n]) for n in range(len(request))]
            candidates.append(('trailing-byte',request+b'\x00'))
            corrupt=bytearray(request);corrupt[4]^=1;candidates.append(('bad-digest',bytes(corrupt)))
            for name,offset,value in [('variant',frame,2),('protected',32,1),('blob-size',frame+12,0xffffffff)]:
                corrupt=bytearray(request);struct.pack_into('<I',corrupt,offset,value)
                candidates.append((name,resign(corrupt)))
            for name,payload in candidates:
                status,response=model.exchange(command,payload)
                assert status!=0 and not response,(command,name,len(payload))
                negative.append(dict(command=hex(command),case=name,input_bytes=len(payload),status=status))
            for capacity in [0,len(bytes.fromhex(e['response_hex']))-1]:
                status,response=model.exchange(command,request,capacity)
                assert status!=0 and not response
                negative.append(dict(command=hex(command),case='short-output',capacity=capacity,status=status))
            corrupt=bytearray(request);struct.pack_into('<Q',corrupt,frame+4,0x7777)
            status,response=model.exchange(command,resign(corrupt));assert status==1 and not response
            negative.append(dict(command=hex(command),case='unknown-id',status=status))
        record['negative']=negative
        record['model_sha256']=sha(out/'model.dylib')
        record['status']='NATIVE_SKS_STARTUP_WIRE_MODEL_QUALIFIED'
    except Exception as error:
        record.update(status='FAILED',error=repr(error))
        if 'native' in locals():
            record['last_exchanges']=native.exchanges
            record['last_fixture_calls']=native.events[-10:]
            record['last_pc']=hex(native.u.reg_read(b.reg.UC_ARM64_REG_PC))
        raise
    finally:
        (out/'qualification.json').write_text(json.dumps(record,indent=2)+'\n')
    print(json.dumps(dict(status=record['status'],output=str(out/'qualification.json'),
                          sha256=sha(out/'qualification.json'))))


if __name__=='__main__':main()

#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Native startup through the compiled SKS endpoint and staged DMA fixtures."""
from pathlib import Path
import argparse
import ctypes as C
import hashlib
import importlib.util
import json
import subprocess

ROOT=Path(__file__).resolve().parents[1]
sha=lambda p:hashlib.sha256(Path(p).read_bytes()).hexdigest()
PROOF=ROOT/'build/sks-mailbox-native-20260928-v1.json'
assert sha(PROOF)=='770c937c4d09900af26029d6954e18f97fd084ef357bff335460ab6a56da4263'
for p,digest in json.loads(PROOF.read_text())['sources_sha256'].items():assert sha(p)==digest,p
spec=importlib.util.spec_from_file_location('mailbox',ROOT/'tools/replay-sks-mailbox.py')
mailbox=importlib.util.module_from_spec(spec);spec.loader.exec_module(mailbox)
startup=mailbox.startup


class Endpoint(C.Structure):
    _fields_=[(name,C.c_uint64) for name in ['ready','advertisements','negotiations','queries','last_request','last_reply']]+[
        ('stage',C.c_uint64*2),('size',C.c_uint64*2),('iova',C.c_uint64*2),
        ('physical',(C.c_uint64*2)*2),('wire',startup.State)]


BIND=C.CFUNCTYPE(C.c_int,C.c_void_p,C.POINTER(Endpoint),C.c_uint32,C.c_uint64,C.c_uint64,C.POINTER(C.c_uint64))
PREPARE=C.CFUNCTYPE(C.c_int,C.c_void_p,C.POINTER(Endpoint),C.c_uint32,C.c_uint32,
    C.POINTER(startup.State),C.c_void_p,C.POINTER(C.c_uint16),C.POINTER(C.c_uint8))
PUBLISH=C.CFUNCTYPE(C.c_int,C.c_void_p,C.POINTER(Endpoint),C.c_void_p,C.c_uint16)


class IO(C.Structure):
    _fields_=[('context',C.c_void_p),('bind',BIND),('prepare',PREPARE),('publish',PUBLISH)]


class EndpointModel:
    def __init__(self,library):
        self.library=C.CDLL(str(library));self.state=Endpoint()
        self.state.ready=1;self.state.advertisements=2
        self.tx=C.create_string_buffer(0x8000);self.rx=C.create_string_buffer(b'\xa5'*0x8000)
        self.fail_prepare=False;self.fail_publish=False;self.alias_pages=False
        self.callback_errors=[];self.events=[];self.tag=0
        self.step=self.library.sep_sks_endpoint_step
        self.step.argtypes=[C.POINTER(Endpoint),C.POINTER(IO),C.c_uint64,C.POINTER(C.c_uint64)]
        self.step.restype=C.c_int
        self.wire=self.library.sep_sks_wire
        self.wire.argtypes=[C.POINTER(startup.State),C.c_uint32,C.c_void_p,C.c_uint32,C.c_void_p,C.c_uint32,C.POINTER(C.c_uint32)]
        self.wire.restype=C.c_int
        def guarded(callback):
            def run(*args):
                try:return callback(*args)
                except Exception as error:
                    self.callback_errors.append(repr(error));return 0
            return run
        self.bind_cb=BIND(guarded(self.bind));self.prepare_cb=PREPARE(guarded(self.prepare));self.publish_cb=PUBLISH(guarded(self.publish))
        self.io=IO(None,self.bind_cb,self.prepare_cb,self.publish_cb)

    def bind(self,context,state,direction,iova,size,pages):
        assert direction<2 and size==0x8000
        for page in range(2):pages[page]=(0x800000 if self.alias_pages else 0x800000+direction*0x100000)+page*0x4000
        self.events.append(dict(operation='bind',direction=direction,iova=hex(iova)))
        return 1

    def prepare(self,context,state,command,length,wire,reply,reply_bytes,status):
        self.events.append(dict(operation='prepare',command=command,bytes=length))
        if self.fail_prepare:return 0
        size=C.c_uint32()
        status[0]=self.wire(wire,command,self.tx,length,reply,100,C.byref(size))
        assert size.value<=100
        reply_bytes[0]=size.value
        return 1

    def publish(self,context,state,reply,length):
        self.events.append(dict(operation='publish',bytes=length))
        if self.fail_publish:return 0
        assert length<=100
        C.memmove(self.rx,reply,length)
        return 1

    def submit(self,word):
        before=bytes(self.state);old_receive=self.rx.raw
        response=C.c_uint64(0xfeedfacecafebeef)
        result=self.step(C.byref(self.state),C.byref(self.io),word,C.byref(response))
        assert not self.callback_errors,self.callback_errors
        if result:
            assert bytes(self.state)==before and self.rx.raw==old_receive
            assert response.value==0xfeedfacecafebeef
        return result,response.value

    def negotiate(self):
        proof=json.loads(PROOF.read_text())
        for case in proof['negotiation']:
            if int(case['result'],16):continue
            for request in case['requests']:
                word=int(request['tagged_word'],16);result,response=self.submit(word)
                assert result==0 and response==word&~0xff000000
        assert list(self.state.stage)==[2,2] and self.state.negotiations==4

    def exchange(self,command,request):
        assert len(request)<=0x8000
        C.memset(self.tx,0x6d,0x8000);C.memmove(self.tx,request,len(request))
        word=3|self.tag<<8|command<<16|len(request)<<48
        self.tag=(self.tag+1)&127
        result,response=self.submit(word);assert result==0,(result,hex(word))
        consumer=mailbox.KeyStoreReceiver();observed=consumer.run(response,command)
        status=response>>24&255;length=response>>48
        assert response&0xffffff==(word&0xffffff)|0x8000
        assert observed['wakes']==1
        assert observed['decision']==('return-status' if status else 'decode-payload')
        assert observed['result']==hex(status)
        self.events.append(dict(operation='native-reception',request=hex(word),reply=hex(response),decision=observed['decision']))
        return status,self.rx.raw[:length]


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--output-dir',type=Path,required=True)
    args=parser.parse_args();out=args.output_dir.resolve();out.mkdir(exist_ok=False)
    crypto=ROOT.parent/'q1n1/platform/uefi'
    inputs=[Path(__file__),ROOT/'docs/SKS-ENDPOINT-MODEL-20260928.md',ROOT/'compat/sep-sks-endpoint.h',
        ROOT/'compat/sep-sks-endpoint.c',ROOT/'compat/sep-sks.c',ROOT/'compat/sep-sks.h',crypto/'sha256.c',crypto/'sha256.h']
    record=dict(status='RUNNING',hardware_access=False,inputs_sha256={str(p):sha(p) for p in inputs})
    try:
        command=['clang','-std=c11','-O2','-Wall','-Wextra','-Werror','-dynamiclib','-I'+str(crypto),
            str(ROOT/'compat/sep-sks-endpoint.c'),str(ROOT/'compat/sep-sks.c'),str(crypto/'sha256.c'),'-o',str(out/'model.dylib')]
        compiled=subprocess.run(command,text=True,capture_output=True);(out/'build.log').write_text(compiled.stdout+compiled.stderr)
        record['build']=dict(command=command,exit=compiled.returncode);assert compiled.returncode==0,compiled.stderr
        model=EndpointModel(out/'model.dylib');model.negotiate()
        native=startup.Startup(model);result=native.invoke(0x1359c)
        assert result==0 and model.state.wire.environment_valid==1 and model.state.wire.updates==1
        assert model.state.queries==2
        environment=bytes.fromhex(native.exchanges[1]['payload_hex'])
        assert bytes(model.state.wire.environment)==environment
        record['startup']=dict(result=result,exchanges=native.exchanges,queries=model.state.queries,
            environment_updates=model.state.wire.updates,environment_hex=environment.hex())
        request=bytes.fromhex(native.exchanges[1]['request_hex'])
        failures=[]
        C.memmove(model.tx,request,len(request));word=3|7<<8|0x2a<<16|len(request)<<48
        for flag in ['fail_prepare','fail_publish']:
            setattr(model,flag,True);status,_=model.submit(word);assert status==4
            failures.append(dict(case=flag,result=status,live_state_and_receive_unchanged=True));setattr(model,flag,False)
        status,_=model.submit(word|0x8000);assert status==1
        failures.append(dict(case='reply-bit-request',result=status))
        status,_=model.submit((word&0x0000ffffffffffff)|(0x8001<<48));assert status==3
        failures.append(dict(case='oversized-request',result=status))
        fresh=EndpointModel(out/'model.dylib');status,_=fresh.submit(word);assert status==3
        failures.append(dict(case='before-bindings',result=status))
        # A changed physical identity must fail before publishing or retaining it.
        model.alias_pages=True
        query=next(c for c in json.loads(PROOF.read_text())['negotiation'] if c['direction']==1 and c['result']=='0x0')['requests'][1]
        status,_=model.submit(int(query['tagged_word'],16));assert status==4
        failures.append(dict(case='aliased-or-changed-physical-binding',result=status))
        model.alias_pages=False
        model.state.queries=0xffffffffffffffff
        status,_=model.submit(word);assert status==3
        failures.append(dict(case='query-counter-overflow',result=status))
        record.update(status='NATIVE_SKS_ENDPOINT_STARTUP_QUALIFIED',failures=failures,
            events=model.events,model_sha256=sha(out/'model.dylib'),
            boundary='Native startup serialization and reply reception through compiled endpoint/wire models. DMA ownership, control tag assignment and publication are host fixtures. No device dispatcher, cache/interrupt delivery, hardware cleanup or GUI proof.')
    except Exception as error:
        record.update(status='FAILED',error=repr(error))
        if 'model' in locals():record['events']=model.events;record['callback_errors']=model.callback_errors
        raise
    finally:(out/'qualification.json').write_text(json.dumps(record,indent=2)+'\n')
    print(json.dumps(dict(status=record['status'],output=str(out/'qualification.json'),sha256=sha(out/'qualification.json'))))


if __name__=='__main__':main()

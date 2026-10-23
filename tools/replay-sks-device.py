#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Native SKS startup through the real ASC dispatcher, queues and endpoint."""
from pathlib import Path
import argparse
import ctypes as C
import hashlib
import importlib.util
import json
import subprocess
from source_text import source_files

ROOT=Path(__file__).resolve().parents[1]
sha=lambda p:hashlib.sha256(Path(p).read_bytes()).hexdigest()
PROOF=ROOT/'build/sks-endpoint-model-20260928-v1/qualification.json'
assert sha(PROOF)=='c096ac6856a31ab67c040078f5c8c212ba2117d3171c07028d75f2749404157d'
for path,digest in json.loads(PROOF.read_text())['inputs_sha256'].items():assert sha(path)==digest,path
spec=importlib.util.spec_from_file_location('endpoint',ROOT/'tools/replay-sks-endpoint.py')
endpoint=importlib.util.module_from_spec(spec);spec.loader.exec_module(endpoint)


class Device(endpoint.EndpointModel):
    def __init__(self,library):
        super().__init__(library)
        self.library.sks_device_start.argtypes=[C.POINTER(endpoint.IO),C.c_void_p,C.c_void_p]
        self.library.sks_device_endpoint.restype=C.POINTER(endpoint.Endpoint)
        self.library.sks_device_state.restype=C.c_void_p
        self.library.sks_device_advertisements.restype=C.POINTER(C.c_uint64)
        self.library.sks_device_counters.argtypes=[C.POINTER(C.c_uint64)]
        self.library.sks_device_submit.argtypes=[C.c_uint64]
        self.library.sks_device_receive.argtypes=[C.POINTER(C.c_uint64)]
        assert self.library.sks_device_start(C.byref(self.io),None,None)==0
        self.state=self.library.sks_device_endpoint().contents
        self.advertisements=[self.library.sks_device_advertisements()[i] for i in range(7)]
        assert self.advertisements==[0xd0000,0x706e6f6e010000fd,0x05050707010100fd,
            0x78617273020000fd,0x02020202020100fd,0x736b7320030000fd,0x02020202030100fd]

    def snapshot(self):
        return C.string_at(self.library.sks_device_state(),self.library.sks_device_state_size())

    def counters(self):
        values=(C.c_uint64*8)();self.library.sks_device_counters(values)
        return dict(zip(['submitted','consumed','published','delivered','pending','replies','sks_queries','environment_updates'],values))

    def receive(self):
        response=C.c_uint64();assert self.library.sks_device_receive(C.byref(response))==0
        return response.value

    def submit(self,word):
        assert self.library.sks_device_submit(word)==0
        before=self.snapshot();old_receive=self.rx.raw
        status=self.library.sks_device_step()
        assert not self.callback_errors,self.callback_errors
        if status:
            assert self.snapshot()==before and self.rx.raw==old_receive
            return status,0xfeedfacecafebeef
        return 0,self.receive()


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--output-dir',type=Path,required=True)
    args=parser.parse_args();out=args.output_dir.resolve();out.mkdir(exist_ok=False)
    crypto=ROOT.parent/'q1n1/platform/uefi'
    names=['device','aic','watchdog','clock','dart','aes-engine','aes','mmio','sep-bootstrap',
           'sep-pnon','sep-xars','sep-sks','sep-sks-endpoint','ans','ans-window','nvme-host']
    sources=[ROOT/'tools/sks-device-e2e-bridge.c']+[ROOT/'compat'/f'{name}.c' for name in names]+[crypto/'sha256.c']
    pins=sources+[ROOT/'compat/device.h',ROOT/'compat/sep-sks-endpoint.h',ROOT/'compat/sep-sks.h',
        Path(__file__),ROOT/'docs/SKS-MONITOR-INTEGRATION-20260928.md',ROOT/'probes/xnuboot.c',
        ROOT/'compat/sptm-dart.c',ROOT/'compat/sptm-dart.h',ROOT/'probes/run.py',ROOT/'probes/devicemodel.py']
    pins+=[q for p in pins if p.suffix=='.c' for q in source_files(p)[1:]]
    record=dict(status='RUNNING',hardware_access=False,inputs_sha256={str(p):sha(p) for p in pins})
    try:
        command=['clang','-std=c11','-O2','-Wall','-Wextra','-Werror','-dynamiclib',
            '-I'+str(ROOT/'compat'),'-I'+str(crypto),*[str(p) for p in sources],'-o',str(out/'device.dylib')]
        compiled=subprocess.run(command,text=True,capture_output=True);(out/'build.log').write_text(compiled.stdout+compiled.stderr)
        record['build']=dict(command=command,exit=compiled.returncode);assert compiled.returncode==0,compiled.stderr
        model=Device(out/'device.dylib');model.negotiate()
        native=endpoint.startup.Startup(model);result=native.invoke(0x1359c)
        assert result==0 and model.state.wire.updates==1 and model.state.queries==2
        record['startup']=dict(result=result,exchanges=native.exchanges,counters=model.counters(),
            advertisements=[hex(x) for x in model.advertisements],environment_hex=bytes(model.state.wire.environment).hex())
        # Effective-status replies fill the actual queue without touching SKS.
        for i in range(8):
            assert model.library.sks_device_submit(0x140100+i*0x100)==0
            assert model.library.sks_device_step()==0
        assert model.counters()['replies']==8
        request=bytes.fromhex(native.exchanges[1]['request_hex'])
        C.memmove(model.tx,request,len(request))
        word=3|9<<8|0x2a<<16|len(request)<<48
        assert model.library.sks_device_submit(word)==0
        before=model.snapshot();rx=model.rx.raw;events=len(model.events)
        status=model.library.sks_device_step()
        assert status!=0 and model.snapshot()==before and model.rx.raw==rx and len(model.events)==events
        blocked=model.counters()
        assert model.receive()==0x140100
        assert model.library.sks_device_step()==0
        replies=[model.receive() for _ in range(8)]
        assert replies[:7]==[0x140100+i*0x100 for i in range(1,8)]
        assert replies[-1]==(88<<48)|0x2a8903
        assert model.state.wire.updates==2
        final=model.counters();assert final['pending']==final['replies']==0
        assert final['submitted']==final['consumed'] and final['published']==final['delivered']
        assert model.library.sks_device_step()==0
        record['queue_pressure']=dict(refused_result=status,blocked=blocked,final=final,
            no_callback_or_write_while_full=True,recovered_reply=hex(replies[-1]))
        record.update(status='NATIVE_SKS_DEVICE_DISPATCH_QUALIFIED',events=model.events,
            library_sha256=sha(out/'device.dylib'),device_state_bytes=model.library.sks_device_state_size(),
            boundary='Cold ROM and service discovery through real MMIO queues and device dispatcher, native SKS startup/reception and compiled endpoint/wire. Bootstrap and DMA are explicit fixtures. Monitor DMA callbacks only source-pinned, not executed; pnon/xars publication verified but their data callbacks not exercised here. No hardware proof.')
    except Exception as error:
        record.update(status='FAILED',error=repr(error))
        if 'model' in locals():record['events']=model.events;record['callback_errors']=model.callback_errors
        raise
    finally:(out/'qualification.json').write_text(json.dumps(record,indent=2)+'\n')
    print(json.dumps(dict(status=record['status'],output=str(out/'qualification.json'),sha256=sha(out/'qualification.json'))))


if __name__=='__main__':main()

#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Native SKS startup through actual device, monitor DMA and SPTM/DART code."""
from pathlib import Path
import argparse
import ctypes as C
import hashlib
import importlib.util
import json
import struct
import subprocess
from source_text import read_source, source_files

ROOT=Path(__file__).resolve().parents[1]
sha=lambda p:hashlib.sha256(Path(p).read_bytes()).hexdigest()
spec=importlib.util.spec_from_file_location('device',ROOT/'tools/replay-sks-device.py')
device=importlib.util.module_from_spec(spec);spec.loader.exec_module(device)
endpoint=device.endpoint
mailbox=endpoint.mailbox


class Monitor(device.Device):
    def __init__(self,library):
        super().__init__(library)
        lib=self.library
        for name in ['buffer','ram','dart']:
            getattr(lib,'sks_monitor_'+name).restype=C.c_void_p
        lib.sks_monitor_translations.restype=C.c_uint64
        assert lib.sks_monitor_start()==0
        self.tx=(C.c_char*0x8000).from_address(lib.sks_monitor_buffer(0))
        self.rx=(C.c_char*0x8000).from_address(lib.sks_monitor_buffer(1))
        self.negotiations=[]

    def negotiate(self):
        for direction in range(2):
            n=mailbox.Manager();requests=[]
            iova=0x10001100000+direction*0x40000
            n.put(mailbox.OBJECT,'<Q',mailbox.VTABLE)
            n.put(mailbox.PROVIDER,'<Q',mailbox.VTABLE+0x1000)
            for table,offset,name,value in [(mailbox.VTABLE,0x138,'memory-descriptor',mailbox.PROVIDER),
                    (mailbox.VTABLE+0x1000,0x300,'descriptor-length',0x8000),
                    (mailbox.VTABLE,0x140,'device-address',iova)]:
                target=n.fixture(name,lambda native,value=value:value)
                n.put(table+offset,'<Q',target)
            def control(native):
                word=struct.unpack('<Q',native.u.mem_read(native.x(1),8))[0]|0x500
                result,reply=self.submit(word)
                assert result==0 and reply==word&~0xff000000,(result,hex(word),hex(reply),self.library.sks_monitor_refusal())
                requests.append(dict(request=hex(word),reply=hex(reply)))
                return 0
            n.fixtures[0x34030]=('control-transport',control)
            result=n.invoke(0x34534 if direction==0 else 0x34690,mailbox.INFO,3,mailbox.OBJECT,12345)
            assert result==0 and len(requests)==2
            self.negotiations.append(dict(direction=direction,iova=hex(iova),requests=requests))
        assert list(self.state.stage)==[2,2]

    def memory_snapshot(self):
        lib=self.library
        return (C.string_at(lib.sks_monitor_ram(),lib.sks_monitor_ram_size()),
                C.string_at(lib.sks_monitor_dart(),lib.sks_monitor_dart_size()),
                lib.sks_monitor_publications())


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--output-dir',type=Path,required=True)
    args=parser.parse_args();out=args.output_dir.resolve();out.mkdir(exist_ok=False)
    crypto=ROOT.parent/'q1n1/platform/uefi'
    names=['device','aic','watchdog','clock','dart','aes-engine','aes','mmio','sep-bootstrap',
           'sep-pnon','sep-xars','sep-sks','sep-sks-endpoint','ans','ans-window','nvme-host',
           'sptm-dart','sptm','sptm-refs']
    sources=[ROOT/'tools/sks-monitor-e2e-bridge.c']+[ROOT/'compat'/f'{n}.c' for n in names]+[crypto/'sha256.c']
    pins=sources+[ROOT/'tools/sks-device-e2e-bridge.c',ROOT/'tools/test-sptm-dart-sep.c',
        ROOT/'tools/replay-sks-device.py',Path(__file__),ROOT/'probes/xnuboot.c',
        ROOT/'docs/SKS-DMA-E2E-20260928.md']+list((ROOT/'compat').glob('*.h'))
    pins+=[q for p in pins if p.suffix=='.c' for q in source_files(p)[1:]]
    record=dict(status='RUNNING',hardware_access=False,inputs_sha256={str(p):sha(p) for p in pins})
    try:
        source=read_source(ROOT/'probes/xnuboot.c')
        begin=source.index('struct sep_rom_dma_context {');end=source.index('\n};',begin)+3
        callback_begin=source.index('static int sep_service_admit(')
        callback_end=source.index('static int sep_entropy32(',callback_begin)
        header=out/'sks-monitor-callbacks.h'
        header.write_text(source[begin:end]+'\n'+source[callback_begin:callback_end])
        record['extracted_callbacks']=dict(sha256=sha(header),source_start_line=source[:callback_begin].count('\n')+1)
        command=['clang','-std=c11','-O1','-g','-Wall','-Wextra','-Werror','-Wno-unused-function','-dynamiclib',
            '-I'+str(ROOT/'compat'),'-I'+str(ROOT/'shadow'),'-I'+str(ROOT/'tools'),'-I'+str(crypto),
            '-I'+str(out),*[str(p) for p in sources],'-o',str(out/'monitor.dylib')]
        compiled=subprocess.run(command,text=True,capture_output=True)
        (out/'build.log').write_text(compiled.stdout+compiled.stderr)
        record['build']=dict(command=command,exit=compiled.returncode)
        assert compiled.returncode==0,compiled.stderr
        model=Monitor(out/'monitor.dylib');model.negotiate()
        native=endpoint.startup.Startup(model);result=native.invoke(0x1359c)
        assert result==0 and model.state.wire.updates==1 and model.state.queries==2
        assert model.library.sks_monitor_scratch_clear()==1
        assert model.library.sks_monitor_publications()==2
        record['startup']=dict(result=result,exchanges=native.exchanges,counters=model.counters(),
            negotiation=model.negotiations,seven_spans=True,pages=25,
            translations=model.library.sks_monitor_translations(),cache_publications=2,scratch_cleared=True)
        request=bytes.fromhex(native.exchanges[1]['request_hex'])
        failures=[]
        for fault,label in enumerate(['request-map','reply-map','last-page-write-permission',
                'bootstrap-physical-alias','prepare-counter-overflow','changed-xars-identity',
                'publication-ownership-walk','publish-counter-overflow'],1):
            C.memmove(model.tx,request,len(request))
            model.library.sks_monitor_fault(fault)
            word=3|9<<8|0x2a<<16|len(request)<<48
            assert model.library.sks_device_submit(word)==0
            before=model.snapshot();memory=model.memory_snapshot();updates=model.state.wire.updates
            result=model.library.sks_device_step()
            refusal=model.library.sks_monitor_refusal()
            assert result!=0 and refusal!=0,(label,result,refusal)
            assert model.snapshot()==before,label
            assert model.memory_snapshot()==memory,label
            model.library.sks_monitor_fault(0)
            assert model.library.sks_device_step()==0,label
            reply=model.receive();assert reply==(88<<48)|0x2a8903,(label,hex(reply))
            assert model.state.wire.updates==updates+1 and model.library.sks_monitor_scratch_clear()==1
            failures.append(dict(case=label,result=result,refusal=refusal,
                state_ram_dma_accounting_unchanged=True,same_request_retry_succeeded=True))
        final=model.counters();assert final['pending']==final['replies']==0
        assert final['submitted']==final['consumed'] and final['published']==final['delivered']
        record.update(status='NATIVE_SKS_MONITOR_DMA_QUALIFIED',failures=failures,final=final,
            library_sha256=sha(out/'monitor.dylib'),events=model.events,
            boundary='Native SKS startup and OOL builders through real device queue, endpoint, wire, verbatim monitor callbacks and SPTM/DART memory ownership code with all seven spans. Host RAM, initial ROM bootstrap, control tags and cache publication observation are fixtures. No hardware cache, interrupt, lock-cleanup or GUI proof.')
    except Exception as error:
        record.update(status='FAILED',error=repr(error))
        raise
    finally:(out/'qualification.json').write_text(json.dumps(record,indent=2)+'\n')
    print(json.dumps(dict(status=record['status'],output=str(out/'qualification.json'),sha256=sha(out/'qualification.json'))))


if __name__=='__main__':main()

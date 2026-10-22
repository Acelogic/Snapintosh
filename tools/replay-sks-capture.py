#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Qualify the hardware capture decoder against native-driven C runtime state."""
from pathlib import Path
import argparse
import copy
import ctypes as C
import hashlib
import importlib.util
import json
import re
import struct
import subprocess
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'tools'))
import audit_sep_rom
import audit_sep_sks
import audit_sep_xars
sha=lambda p:hashlib.sha256(Path(p).read_bytes()).hexdigest()
spec=importlib.util.spec_from_file_location('monitor',ROOT/'tools/replay-sks-monitor.py')
monitor=importlib.util.module_from_spec(spec);spec.loader.exec_module(monitor)


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--output-dir',type=Path,required=True)
    args=parser.parse_args();out=args.output_dir.resolve();out.mkdir(exist_ok=False)
    proof=ROOT/'build/sks-monitor-dma-20260928-v1/qualification.json'
    assert sha(proof)=='75d1d528be4bb983b11fdce0a82c4105b813ab692fc352b35c5e3526f9abe780'
    qualified=json.loads(proof.read_text())
    for p,h in qualified['inputs_sha256'].items():assert sha(p)==h,p
    library=proof.parent/'monitor.dylib';assert sha(library)==qualified['library_sha256']
    inputs=[Path(__file__),ROOT/'docs/SKS-CAPTURE-E2E-20260928.md',ROOT/'tools/audit-secondary-runtime.py',
        ROOT/'tools/audit_sep_rom.py',ROOT/'tools/audit_sep_sks.py',ROOT/'tools/audit_sep_xars.py',ROOT/'tools/audit_sep_pnon.py']
    record=dict(status='RUNNING',hardware_access=False,inputs_sha256={str(p):sha(p) for p in inputs},
        dma_qualification_sha256=sha(proof),library_sha256=sha(library))
    try:
        command=['clang','--target=aarch64-unknown-none-elf','-ffreestanding','-mgeneral-regs-only',
            '-Ishadow','-Icompat','-Xclang','-fdump-record-layouts','-fsyntax-only','probes/xnuboot.c']
        result=subprocess.run(command,cwd=ROOT,capture_output=True,text=True)
        (out/'layout.txt').write_text(result.stdout);(out/'layout-errors.txt').write_text(result.stderr)
        assert result.returncode==0,result.stderr
        def offset(kind,field):
            block=next(b for b in result.stdout.split('*** Dumping AST Record Layout')
                if re.search(r'^\s*0 \| struct '+kind+r'\n',b))
            values=re.findall(r'^\s*(\d+) \|   \S.* '+field+r'$',block,re.M)
            assert len(values)==1,(kind,field,values)
            return int(values[0])
        assert offset('sep_sks_endpoint','wire')==128 and offset('sep_sks_wire_state','environment')==12
        model=monitor.Monitor(library)
        def capture():
            data=model.snapshot()
            def field(name,fmt):return struct.unpack_from(fmt,data,offset('device_sep_asc',name))
            asc={k:field(k,'<Q')[0] for k in ['submitted','consumed','published','delivered',
                'rom_status_replies','rom_last_request','rom_last_reply','rom_stage','rom_firmware_iova',
                'rom_firmware_size','rom_shared_iova','rom_shared_size','service_ready','service_notifications',
                'entropy_words','entropy_last_request','status_queries','status_last_request']}
            asc.update(rom_status_producer=True,service_bootstrap=True,pnon_recovery=False,
                pnon_refusal=True,xars_refusal=True,sks_startup=True,virtual_effective_status=0)
            asc['service_resources']=list(field('bootstrap','<8I'))
            count=field('reply_count','<I')[0];words=field('reply','<16Q')
            asc['replies']=[list(words[i*2:i*2+2]) for i in range(count)]
            for name,pages in [('pnon',7),('xars',2)]:
                words=field(name,'<'+str(12+2*pages)+'Q')
                state=dict(zip(['ready','advertisements','negotiations','queries','last_request','last_reply'],words[:6]))
                state.update(stage=list(words[6:8]),size=list(words[8:10]),iova=list(words[10:12]),
                    physical=[list(words[12:12+pages]),list(words[12+pages:])]);asc[name]=state
            start=offset('device_sep_asc','sks')
            raw=data[start:start+audit_sep_sks.STATE_BYTES]
            assert raw==bytes(model.state),'host/target SKS ABI mismatch'
            asc['sks']=audit_sep_sks.decode(raw)
            audit_sep_rom.audit_history(asc)
            return asc
        captures={'before_sks_negotiation':capture()}
        model.negotiate();native=monitor.endpoint.startup.Startup(model)
        assert native.invoke(0x1359c)==0
        captures['after_native_startup']=capture()
        request=bytes.fromhex(native.exchanges[0]['request_hex'])
        C.memmove(model.tx,request,len(request))
        word=3|0x4d<<16|len(request)<<48
        assert model.library.sks_device_submit(word)==model.library.sks_device_step()==0
        captures['reply_pending']=capture();assert len(captures['reply_pending']['replies'])==1
        model.receive();captures['reply_consumed']=capture()
        asc=captures['reply_consumed'];base=0x8c0000000
        geometry=dict(frame_map=base+0x4000,frame_low=base,frame_high=base+0x200000,
            alloc_low=base+0x140000,alloc_high=base+0x200000,boot_ranges=[],boot_aliases=[])
        ram=model.memory_snapshot()[0];leaves=[]
        for slot in range(2048):
            value=struct.unpack_from('<Q',ram,0x144000+slot*8)[0]
            if value&1:
                leaves.append(dict(device_id=20,sid=0,iova=0x10000000000+slot*0x4000,
                    pa=(value&0xfffffffc00)<<4,readonly=bool(value&8),no_read=bool(value&4),begin=0,end=0x4000))
        buffers=audit_sep_xars.audit_buffers(asc,leaves,geometry)
        assert len(buffers['bindings'])==7
        rejects=[]
        for label in ['environment-counter','reply-shape','cross-peer-identity']:
            changed=copy.deepcopy(asc)
            if label=='environment-counter':changed['sks']['wire']['updates']=changed['sks']['queries']+1
            if label=='reply-shape':changed['sks']['last_reply']^=1<<16
            if label=='cross-peer-identity':changed['sks']['physical'][1][1]=changed['xars']['physical'][0][0]
            try:
                audit_sep_rom.audit_history(changed)
                audit_sep_xars.audit_buffers(changed,leaves,geometry)
            except AssertionError as error:rejects.append(dict(case=label,error=str(error)))
            else:raise AssertionError('invalid capture accepted: '+label)
        primary=ROOT/'build/installed-metal-virtual-ethernet-2100s-20260927-pre-reset-verification.json'
        old=[]
        for name,digest in json.loads(primary.read_text())['artifacts_sha256'].items():
            path=primary.with_name(primary.name.removesuffix('-pre-reset-verification.json')+name) if name.startswith('-') else Path(name)
            if path.suffix!='.json':continue
            if not path.is_absolute():path=ROOT/name
            if not path.is_file():continue
            data=json.loads(path.read_text())
            if not isinstance(data,dict) or not data.get('sep_asc'):continue
            assert sha(path)==digest
            for state in data['sep_asc']:audit_sep_rom.audit_history(state)
            old.append(dict(path=str(path),sha256=digest))
        assert old,'generation52 saved SEP capture not located'
        record.update(status='NATIVE_SKS_CAPTURE_AUDIT_QUALIFIED',captures=captures,
            buffers=buffers,negative_capture_cases=rejects,generation52_compatibility=old,
            layout_command=command,layout_sha256=sha(out/'layout.txt'),
            boundary='Actual native-driven C state decoded at AArch64 layout offsets and independently audited. Old saved generation52 captures remain valid. No hardware action.')
    except Exception as error:
        record.update(status='FAILED',error=repr(error));raise
    finally:(out/'qualification.json').write_text(json.dumps(record,indent=2)+'\n')
    print(json.dumps(dict(status=record['status'],output=str(out/'qualification.json'),sha256=sha(out/'qualification.json'))))


if __name__=='__main__':main()

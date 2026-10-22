#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Replay original SIGN_USER_POINTER control flow for the observed raw input.

PAC is an opaque callback: this proves operand forwarding and service control
flow, not cryptographic outputs. Compare the current C model and preserve the
actual stopped-state arguments without modifying the guest or runtime source.
"""
from pathlib import Path
import argparse
import ctypes as C
import hashlib
import json
import runpy
import subprocess
import sys

ROOT=Path(__file__).resolve().parents[1]
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
sys.path.insert(0,str(ROOT/'build/test-python-deps'))
from unicorn import Uc,UC_ARCH_ARM64,UC_MODE_ARM,UC_HOOK_CODE
import unicorn.arm64_const as reg

def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--prefix',required=True)
    ap.add_argument('--output',type=Path,required=True)
    args=ap.parse_args();out=args.output.resolve();out.mkdir(parents=True,exist_ok=False)
    capture=ROOT/'build'/(args.prefix+'-pauth-batch.json')
    stop=ROOT/'build'/(args.prefix+'-cpu5-stop.json')
    a=json.loads(capture.read_text());s=json.loads(stop.read_text())
    pointer=a['cpus'][5]['pointer_service']
    assert a['stop_identity_rechecked'] and s['snapshot_kind']==2
    assert int(s['registers']['16'],16)==0x10 and not pointer['authenticate']
    assert [int(s['registers'][str(i)],16) for i in range(3)]==[pointer[k] for k in ['pointer','key','modifier']]
    sources=[Path(__file__).resolve(),ROOT/'tools/sptm-dispatch.py',ROOT/'compat/pauth-pointer.c',
             ROOT/'compat/pauth-pointer.h',ROOT/'compat/pauth-batch.h',ROOT/'compat/sptm.h']
    source_hashes={str(p.relative_to(ROOT)):sha(p) for p in sources}
    firmware=ROOT/'downloads/extracted/j700ap/sptm.t8140.release'
    image=runpy.run_path(str(ROOT/'tools/sptm-dispatch.py'))['Image'](firmware)
    image_hash=hashlib.sha256(image.data).hexdigest()
    assert image_hash=='bd5736d4bd98bceaed2b057ebc09094324bf5149491c2922b329f87db23b1bd0'
    base=0xfffffff027000000;ram=0x80000000
    u=Uc(UC_ARCH_ARM64,UC_MODE_ARM);u.mem_map(base,0x200000);u.mem_map(ram,0x10000)
    for _,va,_,offset,size in image.segs:u.mem_write(va,image.data[offset:offset+size])
    state={};opaque=0x2468ace013579bdf
    get=lambda n:u.reg_read(getattr(reg,'UC_ARM64_REG_X'+str(n)))
    put=lambda n,v:u.reg_write(getattr(reg,'UC_ARM64_REG_X'+str(n)),v)
    def hook(engine,address,size,unused):
        off=address-base
        advance=lambda:u.reg_write(reg.UC_ARM64_REG_PC,address+4)
        if off==0x101a00:state['rejected']=True;u.emu_stop()
        elif off==0x1019a0:put(8,state['daif']);advance()
        elif off==0x1019b0:state['daif']|=0x1c0;advance()
        elif off==0x1019f8:state['daif']=get(8);advance()
        elif off in (0x1019b4,0x1019e0):put(9,state['apctl']);advance()
        elif off in (0x1019bc,0x1019e8):state['apctl']=get(9);advance()
        elif off in (0x1019d0,0x1019d8):
            assert state['apctl']==0x13
            state['pac_operands'].append([get(17),get(1)&0xffffffff,get(16)])
            put(17,opaque);advance()
    u.hook_add(UC_HOOK_CODE,hook)
    command=['clang','-shared','-fPIC','-O1','-g','-Wall','-Wextra','-Werror',
             str(ROOT/'compat/pauth-pointer.c'),'-o',str(out/'current-model.dylib')]
    with (out/'build.log').open('x') as log:subprocess.run(command,stdout=log,stderr=subprocess.STDOUT,check=True)
    class Entry(C.Structure):_fields_=[('pointer',C.c_uint64),('modifier',C.c_uint64),('key',C.c_uint32),('padding',C.c_uint32)]
    callback=C.CFUNCTYPE(C.c_int,C.c_void_p,C.POINTER(Entry),C.c_uint64,C.c_uint64,C.POINTER(C.c_uint64))
    calls=[]
    @callback
    def sign(context,entry,tbi,tbid,result):
        calls.append([entry.contents.pointer,entry.contents.key,entry.contents.modifier]);result[0]=opaque;return 1
    library=C.CDLL(str(out/'current-model.dylib'));model=library.pauth_pointer
    model.argtypes=[C.c_uint64]*6+[callback,C.c_void_p,C.c_void_p];model.restype=C.c_int
    cases=[]
    inputs=[pointer['pointer'],0,1,0x100000000,(1<<47)-1,1<<47,1<<55,1<<56,0xffffffffffffffff]
    for value in inputs:
        for key in (0,2,1,0x100000002):
            for daif in (0,0x1c0,0x3c0):
                state.clear();state.update(daif=daif,apctl=0x11,rejected=False,pac_operands=[])
                for i in range(31):put(i,0)
                put(0,value);put(1,key);put(2,pointer['modifier']);put(30,ram)
                u.reg_write(reg.UC_ARM64_REG_SP,ram+0x8000)
                u.emu_start(base+0x101994,ram,count=100)
                accepted=(key&0xffffffff) in (0,2)
                assert state['rejected']!=accepted
                assert state['apctl']==0x11 and state['daif']==daif
                expected=[[value,key&0xffffffff,pointer['modifier']]] if accepted else []
                assert state['pac_operands']==expected
                if accepted:assert get(0)==opaque
                storage=(C.c_uint64*18)();calls.clear()
                status=model(value,key,pointer['modifier'],0,pointer['tbi'],pointer['tbid'],sign,None,storage)
                cases.append(dict(pointer=hex(value),key=hex(key),daif=hex(daif),
                    native_accepts=accepted,native_pac_operands=state['pac_operands'],
                    current_model_status=status,current_model_pac_operands=list(calls)))
    reached=[c for c in cases if c['pointer']==hex(pointer['pointer']) and c['key']=='0x2']
    assert len(reached)==3 and all(c['native_accepts'] and c['current_model_status']==2 and
                                not c['current_model_pac_operands'] for c in reached)
    for name,digest in source_hashes.items():assert sha(ROOT/name)==digest,name
    result=dict(status='ORIGINAL_SIGN_ACCEPTS_CAPTURED_RAW_INPUT_CURRENT_MODEL_REJECTS',
        capture_sha256=sha(capture),stop_sha256=sha(stop),sources_sha256=source_hashes,
        firmware_sha256=sha(firmware),sptm_image_sha256=image_hash,commands=[command],cases=cases,
        original_sign_code_hex=bytes(u.mem_read(base+0x101994,0x6c)).hex(),
        artifacts_sha256={p.name:sha(p) for p in sorted(out.iterdir()) if p.is_file()},boundary=__doc__)
    report=out/'contract.json';report.write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(dict(status=result['status'],cases=len(cases),captured_cases=len(reached),report=str(report))))

if __name__=='__main__':main()

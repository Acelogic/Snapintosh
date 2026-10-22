#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Replay pinned DEFAULT-to-DEFAULT RETYPE before its C implementation.

Executes address/type/matrix/destructor/reset/constructor/post instructions.
Models PAC, per-CPU register, CAS lock, byte atomic and aperture publication;
those models are explicit boundaries, not physical qualification.
"""
from pathlib import Path
import argparse
import hashlib
import json
import runpy
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'build/test-python-deps'))
from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_CODE
import unicorn.arm64_const as reg

BASE, RAM, TARGET = 0xfffffff027000000, 0x1000000, 0x90008000
META, CPU, STACK = RAM+0x2000, RAM+0x4000, RAM+0xf000
SHA = 'bd5736d4bd98bceaed2b057ebc09094324bf5149491c2922b329f87db23b1bd0'


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--output', type=Path, required=True)
    ap.add_argument('--page-output', type=Path, required=True)
    args = ap.parse_args()
    assert not args.output.exists() and not args.page_output.exists()
    capture = ROOT / 'build/installed-kernel-unmap-300s-20260925-transfer-retype.json'
    data = json.loads(capture.read_text())
    page = bytes.fromhex(data['reads'][data['target']+':16384'])
    assert len(page) == 16384 and hashlib.sha256(page).hexdigest() == data['page_sha256']
    assert data['target_metadata'] == '00000b00000000000000000000000000'
    im = runpy.run_path(str(ROOT / 'tools/sptm-dispatch.py'))['Image'](
        ROOT / 'downloads/extracted/j700ap/sptm.t8140.release')
    assert hashlib.sha256(im.data).hexdigest() == SHA
    descriptor = BASE+0x9e230+11*144
    assert im.pointer(descriptor+0x70) == BASE+0xeb29c
    assert im.pointer(descriptor+0x68) == BASE+0xeb4f4
    assert im.pointer(descriptor+0x38) == BASE+0xebf84
    cases = [('captured', bytes.fromhex(data['target_metadata']), TARGET, 11, 11)]
    flags = bytearray(cases[0][1]); flags[3:8] = bytes.fromhex('a080aabbcc')
    cases += [('clear-private-bytes', bytes(flags), TARGET, 11, 11)]
    for n in (0,1,8,9,10,11,12,13,14,15):
        m = bytearray(cases[0][1]); m[n] = 1
        cases.append((f'busy-{n}', bytes(m), TARGET, 11, 11))
    cases += [('unaligned',cases[0][1],TARGET+1,11,11),
              ('wrong-old',cases[0][1],TARGET,14,11),
              ('invalid-type',cases[0][1],TARGET,11,68)]
    rows = []
    for name, metadata, target, old, new in cases:
        u = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
        u.mem_map(BASE,0x200000);u.mem_map(RAM,0x10000);u.mem_map(TARGET,0x4000)
        for _, va, _, off, size in im.segs:u.mem_write(va,im.data[off:off+size])
        u.mem_write(TARGET,page);u.mem_write(META,metadata)
        for at, value in ((BASE+0x9e1f8,TARGET),(BASE+0x9e200,TARGET+0x4000),
                          (BASE+0x9d520,META),(BASE+0x112140,(1<<22)|(1<<8)),
                          (BASE+0x9e1e8,0)):
            u.mem_write(at,struct.pack('<Q',value))
        u.mem_write(CPU+0xb00,b'\x01')
        u.reg_write(reg.UC_ARM64_REG_SP,STACK)
        def get(n):return u.reg_read(getattr(reg,'UC_ARM64_REG_X'+str(n)))
        def put(n,v):u.reg_write(getattr(reg,'UC_ARM64_REG_X'+str(n)),v)
        for i,v in enumerate((target,old,new,0)):put(i,v)
        state = dict(calls=[])
        def hook(u,a,size,_):
            off=a-BASE
            def jump(at):u.reg_write(reg.UC_ARM64_REG_PC,at)
            if off in (0xf83ec,0xeb29c):jump(a+4)
            elif off==0xf8460:put(25,CPU);jump(a+4)
            elif off==0xf848c:
                lock=struct.unpack('<H',u.mem_read(META,2))[0]
                put(10,lock)
                if not lock:u.mem_write(META,b'\x01\x00')
                jump(a+4)
            elif off in (0xf84dc,0xf892c):
                put(9 if off==0xf84dc else 8,(1<<22)|(1<<8));jump(a+4)
            elif off in (0xf85b8,0xf8764,0xf89a8):
                dest={0xf85b8:0xeb29c,0xf8764:0xeb4f4,0xf89a8:0xebf84}[off]
                state['calls'].append(hex(BASE+dest));put(30,a+4);jump(BASE+dest)
            elif off==0xeb32c:
                at=get(8);v=u.mem_read(at,1)[0]
                u.mem_write(at,bytes([v&~3]));put(8,v);jump(a+4)
            elif off==0xeb338:jump(get(30))
            elif off==0xf8784:
                state['aperture']=[get(i) for i in range(4)];jump(a+4)
            elif off==0xf8994:put(0,TARGET);jump(a+4)
            elif off==0xf89cc:state['stop']='success';u.emu_stop()
            elif (0xf89d0<=off<0xf8f18) or (0xeb33c<=off<0xeb4f4):
                state['stop']=hex(a);u.emu_stop()
        u.hook_add(UC_HOOK_CODE,hook)
        u.emu_start(BASE+0xf83ec,BASE+0x200000,count=1500)
        assert 'stop' in state,(name,state)
        success=name in ('captured','clear-private-bytes')
        assert (state['stop']=='success')==success,(name,state)
        after=bytes(u.mem_read(META,16))
        assert bytes(u.mem_read(TARGET,len(page)))==page
        if success:
            expected=bytearray(metadata);expected[4:]=b'\0'*12
            assert after==bytes(expected),(name,after.hex())
            assert len(state['calls'])==3 and state['aperture']==[TARGET,3,0,3],state
        rows.append(dict(name=name,before=metadata.hex(),after=after.hex(),**state))
    result=dict(result='PASS',sptm_sha256=SHA,capture_sha256=hashlib.sha256(capture.read_bytes()).hexdigest(),
                page_sha256=data['page_sha256'],cases=rows,
                boundary='Native lifecycle instructions; PAC, CPU register, lock atomics and aperture work modeled. No hardware qualification.')
    with args.page_output.open('xb') as f:f.write(page)
    with args.output.open('x') as f:f.write(json.dumps(result,indent=2)+'\n')
    print(json.dumps(dict(result='PASS',cases=len(rows),page_sha256=result['page_sha256'],output=str(args.output))))


if __name__ == '__main__':main()

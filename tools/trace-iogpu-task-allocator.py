#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Retain UUID-bound native IOGPUTask allocator lifecycle and call-site bytes.

Offline source evidence only. This does not allocate guest GPU memory or prove
that a kext, mapping, submission or rendered frame ran on the A16.
"""
import argparse
import hashlib
import json
from pathlib import Path
import runpy
import struct
import subprocess
import capstone

ROOT=Path(__file__).resolve().parents[1]
KDK=Path('/Library/Developer/KDKs/KDK_27.0_26A428.kdk/System/Library/Extensions/IOGPUFamily.kext/Contents/MacOS/IOGPUFamily')

def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--output',type=Path,required=True);args=ap.parse_args()
    assert not args.output.exists()
    metadata=runpy.run_path(str(ROOT/'tools/kc-symbolicate.py'))['macho_segments']
    raw=KDK.read_bytes()
    slices=[struct.unpack_from('>5I',raw,8+i*20) for i in range(struct.unpack_from('>I',raw,4)[0])]
    _,_,offset,length,_=next(v for v in slices if v[0]==0x100000c and v[1]&0xffffff==2)
    thin=raw[offset:offset+length];ks,uid=metadata(thin)
    kc=runpy.run_path(str(ROOT/'tools/kc-xref.py'))['Kernelcache'](
        ROOT/'downloads/extracted/j700ap/kernelcache.release.mac17p',scope='com.apple.iokit.IOGPUFamily')
    _,_,entry=next(v for v in kc.entries if v[0]==kc.scope);cs,cuid=metadata(kc.data,entry)
    assert uid==cuid and str(uid)=='6172533f-b127-35e2-90b8-f7b3b1f2c5b7'
    def translate(va):
        name,start=next((n,b) for n,(b,size) in ks.items() if b<=va<b+size)
        return cs[name][0]+va-start
    symbols=[]
    for line in subprocess.check_output(['nm','-arch','arm64e','-n',str(KDK)],text=True).splitlines():
        fields=line.split()
        if len(fields)==3:
            try:symbols.append((int(fields[0],16),fields[2]))
            except ValueError:pass
    md=capstone.Cs(capstone.CS_ARCH_ARM64,capstone.CS_MODE_ARM);functions=[]
    for part in ('IOGPUTask4init','IOGPUTask4free','IOGPUTask8allocate','IOGPUTask10deallocate'):
        matches=[(va,name) for va,name in symbols if part in name and '.cold.' not in name]
        assert len(matches)==1,(part,matches)
        start,name=matches[0];end=min(va for va,_ in symbols if va>start)
        va=translate(start);at=kc.va2off(va);code=kc.data[at:at+end-start]
        # The prologue and non-PC-relative arithmetic establish the same native
        # implementation without mistaking relocated branches for mismatches.
        witnesses=[]
        for insn in md.disasm(code,va):
            # ADD immediate can be the relocated low half of ADRP+ADD.
            if insn.mnemonic in ('paciasp','pacibsp','stp','ldp','mov','sub','cmp','ret','retab'):
                kdk_va=start+insn.address-va
                assert struct.unpack_from('<I',thin,kdk_va)[0]==kc.u32(insn.address), (
                    name,hex(kdk_va),hex(insn.address),insn.mnemonic,insn.op_str,
                    hex(struct.unpack_from('<I',thin,kdk_va)[0]),hex(kc.u32(insn.address)))
                witnesses.append(hex(insn.address))
        assert len(witnesses)>=4
        functions.append(dict(symbol=name,kdk=hex(start),kc=hex(va),bytes_hex=code.hex(),
            witnesses=witnesses,instructions=[f'{i.address:#x} {i.mnemonic} {i.op_str}' for i in md.disasm(code,va)]))
    sha=lambda value:hashlib.sha256(value).hexdigest()
    out=dict(kext_uuid=str(uid),kernel_sha256=sha(kc.data),kdk_sha256=sha(thin),
             functions=functions,boundary=__doc__)
    args.output.write_text(json.dumps(out,indent=2)+'\n')
    print(json.dumps(dict(output=str(args.output),uuid=str(uid),functions=len(functions))))

if __name__=='__main__':main()

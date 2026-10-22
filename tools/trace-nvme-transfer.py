#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Retain the exact native embedded transfer-size/PRP allocation witnesses.

Failure inventory: do not choose the wrong fat slice, confuse file/segment
addresses, or present static instructions as executed guest calls. Require
the KC/KDK UUID and compare the non-relocated field/branch instructions.
"""
import argparse
import hashlib
import json
from pathlib import Path
import runpy
import struct
import capstone

ROOT=Path(__file__).resolve().parents[1]
KDK=Path('/Library/Developer/KDKs/KDK_27.0_26A428.kdk/System/Library/Extensions/IONVMeFamily.kext/Contents/MacOS/IONVMeFamily')


def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--output',type=Path,required=True)
    args=ap.parse_args();assert not args.output.exists()
    metadata=runpy.run_path(str(ROOT/'tools/kc-symbolicate.py'))['macho_segments']
    raw=KDK.read_bytes()
    slices=[struct.unpack_from('>5I',raw,8+i*20) for i in range(struct.unpack_from('>I',raw,4)[0])]
    _,_,off,size,_=next(v for v in slices if v[0]==0x100000c and v[1]&0xffffff==2)
    thin=raw[off:off+size];ks,uid=metadata(thin)
    kc=runpy.run_path(str(ROOT/'tools/kc-xref.py'))['Kernelcache'](
        ROOT/'downloads/extracted/j700ap/kernelcache.release.mac17p',scope='com.apple.iokit.IONVMeFamily')
    _,_,entry=next(v for v in kc.entries if v[0]==kc.scope);cs,cuid=metadata(kc.data,entry)
    assert str(uid)=='c24bd447-be4c-30ed-b7b8-f601ea1b1a7e' and uid==cuid
    def translate(a):
        name,base=next((n,b) for n,(b,s) in ks.items() if b<=a<b+s)
        return cs[name][0]+a-base
    md=capstone.Cs(capstone.CS_ARCH_ARM64,capstone.CS_MODE_ARM)
    ranges=[('namespace_type_store',0x298d0,0x29954),('published_limits',0x2a9a8,0x2ad98),
            ('prp_allocation',0x39680,0x39764),('prp_count_and_capacity',0x4f34c,0x4f3c8),
            ('tunnel_sqe',0x50ba0,0x50be0),('sanitize_counter_caller',0x26bc4,0x26e68)]
    out=dict(kext_uuid=str(uid),kdk_sha256=hashlib.sha256(thin).hexdigest(),
             kernel_sha256=hashlib.sha256(kc.data).hexdigest(),functions=[])
    for name,start,end in ranges:
        va=translate(start);off=kc.va2off(va);code=kc.data[off:off+end-start]
        out['functions'].append(dict(name=name,kdk=hex(start),kc=hex(va),bytes_hex=code.hex(),
            instructions=[f'{i.address:#x} {i.mnemonic} {i.op_str}' for i in md.disasm(code,va)]))
    out['stable_witnesses']=[]
    for a in (0x29930,0x2a9cc,0x2a9d0,0x2a9d4,0x2ab74,0x2abc0,
              0x396e4,0x396e8,0x4f34c,0x4f38c,0x4f390,0x4f394,0x4f398,
              0x50bcc,0x50bd0,0x50bd4,0x50bd8,0x26d1c,0x26d3c,0x26d40):
        word=struct.unpack_from('<I',thin,a)[0];assert word==kc.u32(translate(a))
        out['stable_witnesses'].append(dict(kdk=hex(a),kc=hex(translate(a)),word=hex(word)))
    table=translate(0x78188);off=kc.va2off(table)
    out['type_limits']=list(struct.unpack_from('<12I',kc.data,off))
    assert out['type_limits'][1]==1<<20
    out['properties']=[dict(kc=hex(a),name=kc.cstr(t,100))
        for a,t in kc.strings_of(translate(0x2a9a8),translate(0x2ad97)+1)]
    out['boundary']='Static UUID-bound native contract; guest failure/request sizes require separate runtime evidence.'
    args.output.write_text(json.dumps(out,indent=2)+'\n')
    print(json.dumps(dict(output=str(args.output),namespace_type1_bytes=out['type_limits'][1],witnesses=len(out['stable_witnesses']))))


if __name__=='__main__':main()

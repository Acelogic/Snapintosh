#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Save UUID-bound IOGPU memory and IODART mapping contracts without execution.

Captures original kernelcache code, KDK names and disassembly. This artifact is
static evidence; it does not qualify descriptor lifetime, DMA or GPU execution.
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
KDK=Path('/Library/Developer/KDKs/KDK_27.0_26A428.kdk/System/Library/Extensions')
TARGETS={
    'kernel': ('com.apple.kernel', (
        '__ZN12IODMACommand7prepareEyybb',
        '__ZN12IODMACommand8completeEbb',
        '__ZN12IODMACommand26getPreparedOffsetAndLengthEPyS0_',)),
    'IOGPUFamily': ('com.apple.iokit.IOGPUFamily', (
        '__ZN14IOGPUMemoryMap4initEP5IOGPUP9IOGPUTaskP11IOGPUMemoryyj',
        '__ZN14IOGPUMemoryMap8finalizeEv',
        '__ZN14IOGPUMemoryMap10commit_pteEy',
        '__ZN14IOGPUMemoryMap24reserveGPUVirtualAddressEyy',
        '__ZN14IOGPUMemoryMap22allocGPUVirtualAddressEv',
        '__ZN14IOGPUMemoryMap21freeGPUVirtualAddressEv',
        '__ZNK14IOGPUMemoryMap9getLengthEv',
        '__ZN11IOGPUMemory11add_mappingEP14IOGPUMemoryMap',
        '__ZNK11IOGPUMemory12get_iomd_ptrEv',
        '__ZNK14IOGPUSysMemory12get_iomd_ptrEv',
        '__ZN11IOGPUMemory14remove_mappingEP14IOGPUMemoryMap',
        '__ZN11IOGPUMemory15commit_mappingsEy',
        '__ZN14IOGPUMemoryMap4freeEv',
        '__ZN14IOGPUMemoryMap11release_pteEy',
        '__ZN14IOGPUMemoryMap18updateGPUPageTableEv',
        '__ZN14IOGPUMemoryMap18updateGPUPageTableEjP18IOMemoryDescriptorS1_',
        '__ZN14IOGPUSysMemory4wireEv',
        '__ZN14IOGPUSysMemory6unwireEv')),
    'IODARTFamily': ('com.apple.driver.IODARTFamily', (
        '__ZN12IODARTMapper13iovmMapMemoryEP18IOMemoryDescriptoryyjPK21IODMAMapSpecificationP12IODMACommandPK16IODMAMapPageListPySA_',
        '__ZN12IODARTMapper20_iovmAllocDMACommandEP12IODMACommandP18IOMemoryDescriptorjyyPyj',
        '__ZN12IODARTMapper21_iovmInsertDMACommandEP13IODARTVMSpaceP12IODMACommandP18IOMemoryDescriptoryyjPy',
        '__ZN12IODARTMapper15iovmUnmapMemoryEP18IOMemoryDescriptorP12IODMACommandyy',
        '__ZN12IODARTMapper19_iovmFreeDMACommandEP12IODMACommandjj',
        '__ZN6IODART13allowPteRemapEv',
        '__ZN12IODARTMapper9_iovmFreeEP13IODARTVMSpaceb',
        '__ZN12IODARTMapper10_iovmAllocEjP12IODMACommandjP16iomdHistoryEntryPKy',
        '__ZN12IODARTMapper9_iovmFreeEjj19IODARTHistoryAction',
        '__ZN12IODARTMapper11_iovmInsertEP13IODARTVMSpacejjjj',
        '__ZN12IODARTMapper10iovmInsertEjyyyy',
        '__ZN12IODARTMapper16_iovmInsertBatchEyyyj',
        '__ZN13IODARTVMSpace14setTranslationEjjjjb',
        '__ZN13IODARTVMSpace14setTranslationEjjjjjjb')),
    'AppleT8110DART': ('com.apple.driver.AppleT8110DART', (
        '__ZN14AppleT8110DART13allowPteRemapEv',)),
}
EXPECTED_UUIDS={
    'kernel': 'f9f468d7-1f50-354a-becd-6bd6c1c834ad',
    'IOGPUFamily': '6172533f-b127-35e2-90b8-f7b3b1f2c5b7',
    'IODARTFamily': 'e3a7454c-7b0a-3e41-8a5f-ae53e02329e0',
    'AppleT8110DART': 'cba75fcf-ddfe-341b-9332-aa18d0ef8434',
}
# Original KC instructions, not relocated KDK words. These witness the fixed
# path's capability gate, reservation lookup and failure on a missing range.
FIXED_PATH_WITNESSES={
    0xfffffe000a7e13a8: ('tbz', 'w27, #9, #0xfffffe000a7e1400'),
    0xfffffe000a7e13c0: ('mov', 'x17, #0x940'),
    0xfffffe000a7e13d4: ('cbz', 'w0, #0xfffffe000a7e1400'),
    0xfffffe000a7e1b50: ('cbz', 'x25, #0xfffffe000a7e1be0'),
    0xfffffe000a7e1b7c: ('mov', 'x17, #0x168'),
    0xfffffe000a7e1b98: ('cbz', 'x0, #0xfffffe000a7e1d94'),
    0xfffffe000a7e1bc0: ('cbnz', 'w8, #0xfffffe000a7e1f3c'),
    0xfffffe000a7e1bc8: ('cmp', 'w28, w8'),
    0xfffffe000a7e1bd0: ('b.ls', '#0xfffffe000a7e1c88'),
}

def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--output',type=Path,required=True);args=ap.parse_args()
    assert not args.output.exists()
    metadata=runpy.run_path(str(ROOT/'tools/kc-symbolicate.py'))['macho_segments']
    Cache=runpy.run_path(str(ROOT/'tools/kc-xref.py'))['Kernelcache']
    md=capstone.Cs(capstone.CS_ARCH_ARM64,capstone.CS_MODE_ARM)
    sha=lambda raw:hashlib.sha256(raw).hexdigest()
    images=[]
    for image,(scope,wanted) in TARGETS.items():
        path=(KDK.parent/'Kernels/kernel.release.t8140' if image=='kernel'
              else KDK/f'{image}.kext/Contents/MacOS/{image}')
        raw=path.read_bytes()
        if raw[:4]==b'\xcf\xfa\xed\xfe':
            thin=raw
        else:
            slices=[struct.unpack_from('>5I',raw,8+i*20) for i in range(struct.unpack_from('>I',raw,4)[0])]
            _,_,offset,length,_=next(v for v in slices if v[0]==0x100000c and v[1]&0xffffff==2)
            thin=raw[offset:offset+length]
        ks,uid=metadata(thin)
        kc=Cache(ROOT/'downloads/extracted/j700ap/kernelcache.release.mac17p',scope=scope)
        _,_,entry=next(v for v in kc.entries if v[0]==scope);cs,cuid=metadata(kc.data,entry)
        assert uid==cuid and str(uid)==EXPECTED_UUIDS[image], (image,uid,cuid)
        def translate(va):
            name,start=next((n,b) for n,(b,size) in ks.items() if b<=va<b+size)
            return cs[name][0]+va-start
        symbols=[]
        for line in subprocess.check_output(['nm','-arch','arm64e','-n',str(path)],text=True).splitlines():
            parts=line.split()
            if len(parts)==3:
                try:symbols.append((int(parts[0],16),parts[2]))
                except ValueError:pass
        functions=[]
        translated={}
        for address,name in symbols:
            try:
                translated.setdefault(translate(address),[]).append(name)
            except StopIteration:
                pass
        for name in wanted:
            start,=tuple(va for va,s in symbols if s==name)
            end=min(va for va,_ in symbols if va>start)
            va=translate(start);at=kc.va2off(va);code=kc.data[at:at+end-start]
            functions.append(dict(symbol=name,kdk=hex(start),kc=hex(va),bytes_hex=code.hex(),
                instructions=[dict(address=hex(i.address),mnemonic=i.mnemonic,operands=i.op_str,
                    target_names=translated.get(int(i.op_str[1:],16),[])
                        if i.mnemonic in ('b','bl') and i.op_str.startswith('#0x') else [])
                              for i in md.disasm(code,va)]))
        images.append(dict(image=image,uuid=str(uid),kdk_sha256=sha(thin),
                           kernel_sha256=sha(kc.data),functions=functions))
    actual={int(i['address'],16):(i['mnemonic'],i['operands'])
            for image in images for f in image['functions'] for i in f['instructions']}
    for address, expected in FIXED_PATH_WITNESSES.items():
        assert actual.get(address)==expected, (hex(address),actual.get(address),expected)
    result=dict(images=images,boundary=__doc__,
                fixed_path_witnesses={hex(a):v for a,v in FIXED_PATH_WITNESSES.items()},
                tracer_sha256=sha(Path(__file__).read_bytes()))
    args.output.write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(dict(output=str(args.output),images=[dict(name=i['image'],uuid=i['uuid'],
        functions=len(i['functions'])) for i in images])))

if __name__=='__main__':main()

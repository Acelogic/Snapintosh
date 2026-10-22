#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Bind cache transport, compiled target instructions and host integration evidence.

Host/static evidence only. --submission also binds the kext ownership interval.
Native execution, GPU internal caches, real buffer commands and GUI are open.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import runpy
import struct
import subprocess
import sys

ROOT=Path(__file__).resolve().parents[1]
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()


def submission_evidence(out,kext):
    native=json.loads((out/'native-v4.json').read_text());im=native['images'][0]
    assert im['uuid']=='6172533f-b127-35e2-90b8-f7b3b1f2c5b7' and len(im['functions'])==20
    assert native['completion_tracer_sha256']==sha(ROOT/'tools/trace-adreno-completion.py')
    assert native['tracer_sha256']==sha(ROOT/'tools/trace-adreno-memory-map.py')
    Cache=runpy.run_path(str(ROOT/'tools/kc-xref.py'))['Kernelcache']
    kc=Cache(ROOT/'downloads/extracted/j700ap/kernelcache.release.mac17p',scope='com.apple.iokit.IOGPUFamily')
    instructions={}
    for f in im['functions']:
        code=bytes.fromhex(f['bytes_hex']);at=kc.va2off(int(f['kc'],16))
        assert kc.data[at:at+len(code)]==code
        instructions.update({i['address']:i for i in f['instructions']})
    native_witnesses={
        '0xfffffe000a88abbc':('blraa','x9, x17'),
        '0xfffffe000a88b8a4':('blraa','x8, x16'),
        '0xfffffe000a88b1b0':('blraa','x8, x16'),
        '0xfffffe000a88de04':('str','w1, [x8, #0xc8]'),
        '0xfffffe000a861a7c':('ldr','w4, [x19, #0xc8]'),
        '0xfffffe000a861a84':('bl','#0xfffffe000a861b6c'),
        '0xfffffe000a8635a4':('bl','#0xfffffe000a88dc54'),
        '0xfffffe000a8635d0':('blraa','x8, x16')}
    for address,(mnemonic,operands) in native_witnesses.items():
        assert (instructions[address]['mnemonic'],instructions[address]['operands'])==(mnemonic,operands)
    spec=importlib.util.spec_from_file_location('abi',ROOT/'tools/qualify-adreno-resource-kext.py')
    abi=importlib.util.module_from_spec(spec);spec.loader.exec_module(abi)
    raw,ns,segs,word=abi.macho(abi.KDK/'Extensions/IOGPUFamily.kext/Contents/MacOS/IOGPUFamily')
    assert hashlib.sha256(raw).hexdigest()==im['kdk_sha256']
    base=next(s[0] for s in segs if s[3]==b'__TEXT')
    virtual=[]
    for cls,offset,disc,method in [
        ('17IOGPUCommandQueue',0x150,0xf69,'14processSegment'),
        ('17IOGPUCommandQueue',0x158,0xd32a,'28processSegmentKernelCommands'),
        ('17IOGPUCommandQueue',0x160,0x967b,'27processSegmentKernelCommand'),
        ('17IOGPUCommandQueue',0x1b0,0xe135,'18setSubmissionError'),
        ('17IOGPUCommandQueue',0x1d8,0x9dcc,'19submitCommandBuffer'),
        ('15IOGPUBlockFence',0x140,0x2667,'12notifyClient')]:
        symbol=next(f['symbol'] for f in im['functions'] if f['symbol'].startswith('__ZN'+cls+method))
        w=word(ns['__ZTV'+cls]+16+offset)
        assert (w>>32)&0xffff==disc and base+(w&0xffffffff)==ns[symbol]
        virtual.append(dict(symbol=symbol,offset=hex(offset),discriminator=hex(disc)))
    text=(out/'kext-v1-disassembly.txt').read_text()
    assert sha(out/'kext-v1-disassembly.txt')==kext['disassembly_sha256'] and kext['cache_hvc']
    def body(symbol):return text[text.index(symbol+':'):].split('\n__')[0]
    submit=body('__ZN19AdrenoAcceleratorX211submitFenceEP17AdrenoSegmentList')
    assert submit.index('symbol stub for: _IOLockLock')<submit.index('bl\t__ZN17AdrenoSegmentList6submit')<submit.index('symbol stub for: _IOLockUnlock')
    assert '#0x76' in submit and '#0x5c' in submit and '#-0x5d' in submit
    assert 'bl\t_adreno_resource_list_submit' in body('__ZN17AdrenoSegmentList6submitEPFiPvES0_')
    assert 'bl\t_adreno_resource_cache' in body('__ZN15AdrenoMemoryMap15cacheSubmissionEj')
    queue=body('__ZN18AdrenoCommandQueue27processSegmentKernelCommandEP24IOGPUSegmentResourceListPK18IOGPUKernelCommandS4_PKhS6_PK34IOGPUCommandQueueCommandBufferArgs')
    assert '#0xe135, lsl #48' in queue and re.search(r'mov\s+w1, #0xa',queue)
    binary=out/'kext-v1/AdrenoX2.kext/Contents/MacOS/AdrenoX2'
    assert b'snapintosh,guest-cache-abi\0' in binary.read_bytes()
    _,syms,_,kword=abi.macho(binary);v=syms['__ZTV17AdrenoSegmentList']+16
    init='__ZN17AdrenoSegmentList26initWithSharedResourceListEP11IOGPUDevicePK30IOGPUSegmentResourceListHeaderP16IOGPUDeviceShmem'
    for slot,disc,symbol in [(22,0xedc5,'__ZN17AdrenoSegmentList4freeEv'),(39,0x4320,init)]:
        w=kword(v+slot*8);assert (w>>32)&0xffff==disc and w&0xffffffff==syms[symbol]
    layout=(out/'kext-layout.log').read_text().split('0 | class AdrenoSegmentList\n')[1].split('*** Dumping')[0]
    assert '[sizeof=64,' in layout
    for offset,field in [(16,'fDevice'),(24,'fEntries'),(32,'fEntryBytes'),(40,'fResources')]:
        assert re.search(r'\n\s*'+str(offset)+r' \|.*\b'+field+r'\b',layout)
    return dict(native_functions=20,native_witnesses=native_witnesses,native_virtual_calls=virtual,
                segment_size=64,submission_lock_covers_cache_and_gpu=True)


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--artifacts',type=Path,required=True)
    ap.add_argument('--output',type=Path,required=True)
    ap.add_argument('--submission',action='store_true')
    ap.add_argument('--build-subdir',type=Path,default=Path('current'))
    ap.add_argument('--image-log',type=Path,default=Path('image-regression.log'))
    ap.add_argument('--monitor-disassembly',type=Path,default=Path('monitor-disassembly.txt'))
    args=ap.parse_args();out=args.artifacts.resolve()
    build=(out/args.build_subdir).resolve();build.relative_to(out)
    image_log_path=(out/args.image_log).resolve();image_log_path.relative_to(out)
    monitor_disassembly=(out/args.monitor_disassembly).resolve();monitor_disassembly.relative_to(out)
    assert not args.output.exists()
    read=lambda name:json.loads((out/name).read_text())
    monitor=json.loads((build/'monitor/build.json').read_text())
    profile=json.loads((build/'profile/qualification-v1.json').read_text())
    kext=read('resource-abi-v1.json' if args.submission else 'resource-abi-v2.json')
    sources={}
    for record in (monitor,profile,kext):
        for name,digest in record.get('source_sha256',record.get('sources_sha256',{})).items():
            assert sha(ROOT/name)==digest,name
            sources[name]=digest
    runtime='tools/secondary-runtime.py'
    assert sha(ROOT/runtime)==monitor['secondary_runtime_sha256']
    sources[runtime]=monitor['secondary_runtime_sha256']
    sys.path.insert(0,str(ROOT/'probes'))
    runpy.run_path(str(ROOT/runtime))['validate_guest_profile'](monitor['guest_profile'])
    expected={'replay-v1.log':143,'adreno-regression.log':1969,
              'dart-regression.log':715,'retention-regression.log':491}
    if args.submission:
        expected={'replay-v1.log':960,'cache-regression.log':143,
                  'adreno-regression.log':1969,'dart-regression.log':715}
    for name,count in expected.items():
        log=(out/name).read_text()
        assert re.search(r'^PASS: '+str(count)+r' ',log,re.M),name
        assert 'FAIL' not in log and 'runtime error:' not in log and 'Sanitizer' not in log,name
    assert (out/'replay-v1-build.log').read_text()==''
    assert 'error:' in (out/('before-v2-build.log' if args.submission else 'before-build.log')).read_text()
    assert 'warning:' not in (out/'kext-v1-build.log').read_text()
    image_log=image_log_path.read_text()
    assert re.search(r'Ran 17 tests',image_log) and re.search(r'^OK$',image_log,re.M)
    from appledt import DeviceTree
    import adreno
    tree=DeviceTree((build/'profile/combined-device-tree.bin').read_bytes())
    gpu=tree.nodes[adreno.GPU_NODE]
    for capability in ('fence','unmap','cache'):
        assert gpu['snapintosh,guest-'+capability+'-abi'].value==struct.pack('<I',1)
    assert profile['preserved_model_count']==122
    assert profile['images']['combined']['gpu_params'][0]==0x17
    assert sha(build/'monitor/xnuboot.bin')==monitor['monitor_sha256']
    assert monitor['bytes']<monitor['budget'] and '-DSNAP_CLASS_LEAF_MEMO=0' in monitor['build_defines']
    llvm='/opt/homebrew/opt/llvm/bin/llvm-objdump'
    dis=subprocess.check_output([llvm,'-d',str(build/'monitor/xnuboot.elf')],text=True)
    assert dis.splitlines()[2:]==monitor_disassembly.read_text().splitlines()[2:]
    body=dis[dis.index('<adreno_guest_cache>:'):].split('\n\n')[0]
    witnesses={name:[l.strip() for l in body.splitlines() if re.search(pattern,l)] for name,pattern in {
        'line_size_register':r'\bmrs\s+x\d+, CTR_EL0',
        'line_size_mask':r'\band\s+x\d+, x\d+, #0xf0000',
        'line_size_64':r'\bcmp\s+x\d+, #0x40, lsl #12',
        'clean_invalidate':r'\bdc\s+civac,',
        'invalidate':r'\bdc\s+ivac,',
        'completion_barrier':r'\bdsb\s+sy'}.items()}
    assert all(witnesses.values())
    assert re.search(r'\bbl\s+[^\n]*<adreno_guest_cache>',dis)
    bundle=out/'kext-v1/AdrenoX2.kext'
    subprocess.run(['codesign','--verify','--strict',str(bundle)],check=True,capture_output=True)
    assert sha(bundle/'Contents/MacOS/AdrenoX2')==kext['kext_sha256']
    assert len(kext['virtual_calls'])==22 and len(kext['callbacks'])==7
    submission={};external={}
    if args.submission:
        submission=submission_evidence(out,kext)
        for name in ['tools/trace-adreno-completion.py','tools/trace-adreno-memory-map.py','tools/kc-xref.py']:
            sources[name]=sha(ROOT/name)
    else:
        old=ROOT/'build/adreno-submit-wiring-20260926'
        old_binding=json.loads((old/'wiring-qualification-v2.json').read_text())
        old_dis=old/'kext-v2-disassembly.txt'
        assert sha(old_dis)==old_binding['artifacts_sha256']['kext-v2-disassembly.txt']
        new_dis=out/'kext-v2-disassembly.txt'
        assert sha(new_dis)==kext['disassembly_sha256']
        assert old_dis.read_text().splitlines()[1:]==new_dis.read_text().splitlines()[1:]
        external={str(p.relative_to(ROOT)):sha(p) for p in (old/'wiring-qualification-v2.json',old_dis)}
    for name in ['compat/adreno.c','compat/adreno.h','compat/adreno-guest.h',
                 'tools/replay-adreno-cache.c','tools/test-adreno.c','tools/test-sptm-dart-adreno.c',
                 'tools/replay-adreno-resource-retention.c','tools/test-adreno-image.py',
                 'tools/qualify-adreno-cache.py','build/build-adreno-kext-resource-20260926.py']:
        sources[name]=sha(ROOT/name)
    for directory in ('gpu/adreno-kext/kext','gpu/adreno-kext/include'):
        for path in (ROOT/directory).rglob('*'):
            if path.is_file() and 'out' not in path.parts and path.suffix in ('.c','.cpp','.h','.sh','.plist'):
                sources[str(path.relative_to(ROOT))]=sha(path)
    result=dict(status=('HOST_SUBMISSION_CACHE_QUALIFIED_NATIVE_PENDING' if args.submission else
                       'HOST_CACHE_TRANSPORT_QUALIFIED_KEXT_INTEGRATION_PENDING'),boundary=__doc__,
        integration_checks=expected,image_tests=17,compiled_witnesses=witnesses,
        submission=submission,build_subdir=str(build.relative_to(out)),
        image_log=str(image_log_path.relative_to(out)),
        monitor_disassembly=str(monitor_disassembly.relative_to(out)),
        monitor_sha256=monitor['monitor_sha256'],monitor_bytes=monitor['bytes'],
        kext_sha256=kext['kext_sha256'],kext_instructions_unchanged=not args.submission,
        sources_sha256=sources,
        external_artifacts_sha256=external,
        artifacts_sha256={str(p.relative_to(out)):sha(p) for p in sorted(out.rglob('*'))
            if p.is_file() and p.name!='.DS_Store' and p!=args.output.resolve()
            and not p.name.endswith('-qualification.log')})
    args.output.write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps({k:v for k,v in result.items() if k not in ('boundary','compiled_witnesses','submission',
        'sources_sha256','external_artifacts_sha256','artifacts_sha256')}))


if __name__=='__main__':main()

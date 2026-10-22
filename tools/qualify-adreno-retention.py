#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Bind retained resource-list code to native contracts and host replay artifacts.

This is host/static qualification. Native segment execution, resource wiring,
cache maintenance, resource-bearing GPU commands and GUI remain unqualified.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import runpy
import subprocess

ROOT=Path(__file__).resolve().parents[1]
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--artifacts',type=Path,required=True)
    ap.add_argument('--output',type=Path,required=True)
    ap.add_argument('--wiring',action='store_true',help='Qualify preparation ownership as well as retention')
    args=ap.parse_args();out=args.artifacts.resolve()
    assert not args.output.exists()
    read=lambda name:json.loads((out/name).read_text())
    retained=ROOT/'build/adreno-submit-resources-20260926' if args.wiring else out
    native=json.loads((retained/'native-v3.json').read_text())
    replay=json.loads((retained/'native-parser-replay-v4.json').read_text())
    version='v2' if args.wiring else 'v3'
    prefix='wiring' if args.wiring else 'retention'
    checks=491 if args.wiring else 359
    resource=read('resource-abi-'+version+'.json');monitor=read('current/monitor/build.json')
    profile=read('current/profile/qualification-v1.json')
    sources={}
    for record in (resource,monitor,profile):
        for name,digest in record.get('source_sha256',record.get('sources_sha256',{})).items():
            assert sha(ROOT/name)==digest,name
            sources[name]=digest
    for field,name in [('tracer_sha256','tools/trace-adreno-memory-map.py'),
                       ('resource_list_tracer_sha256','tools/trace-adreno-resource-list.py')]:
        assert native[field]==sha(ROOT/name)
    assert replay['native_sha256']==sha(retained/'native-v3.json')
    assert replay['source_sha256']==sha(ROOT/'tools/replay-adreno-resource-list.py')
    assert replay['checks']==5032
    assert f'PASS: {checks} ' in (out/(prefix+'-v2.log')).read_text()
    assert ('error:' if args.wiring else 'file not found') in (out/(prefix+'-before-build.log')).read_text()
    assert 'warning:' not in (out/('kext-'+version+'-build.log')).read_text()
    assert (out/(prefix+'-v2-build.log')).read_text()==''
    spec=importlib.util.spec_from_file_location('abi',ROOT/'tools/qualify-adreno-resource-kext.py')
    abi=importlib.util.module_from_spec(spec);spec.loader.exec_module(abi)
    image=next(i for i in native['images'] if i['image']=='IOGPUFamily')
    assert image['uuid']=='6172533f-b127-35e2-90b8-f7b3b1f2c5b7'
    raw,ns,nseg,nword=abi.macho(abi.KDK/'Extensions/IOGPUFamily.kext/Contents/MacOS/IOGPUFamily')
    assert hashlib.sha256(raw).hexdigest()==image['kdk_sha256']
    nbase=next(s[0] for s in nseg if s[3]==b'__TEXT')
    bundle=out/('kext-'+version)/'AdrenoX2.kext';binary=bundle/'Contents/MacOS/AdrenoX2'
    subprocess.run(['codesign','--verify','--strict',str(bundle)],check=True,capture_output=True)
    assert sha(binary)==resource['kext_sha256']
    dis=out/('kext-'+version+'-disassembly.txt')
    assert sha(dis)==resource['disassembly_sha256']
    text=dis.read_text()
    def body(symbol): return text[text.index(symbol+':'):].split('\n__')[0]
    initname='__ZN17AdrenoSegmentList26initWithSharedResourceListEP11IOGPUDevicePK30IOGPUSegmentResourceListHeaderP16IOGPUDeviceShmem'
    init=body(initname)
    release=body('__ZN17AdrenoSegmentList15releaseResourceEPvS0_')
    direct=['__ZN23IOGPUKernelMappedMemory13getKernelDataEv',
        '__ZN23IOGPUKernelMappedMemory17releaseKernelDataEv',
        '__ZNK16IOGPUDeviceShmem9getLengthEv','__ZN11IOGPUDevice14retainResourceEj']
    functions={f['symbol']:f for f in image['functions']}
    for symbol in direct:
        assert symbol in ns and symbol in functions
        assert 'symbol stub for: '+symbol in text
    assert re.search(r'ldr\s+x\d+, \[x\d+, #0x50\]',init)
    # The compiled null-acquisition branch must return without releasing a
    # lease. Walk that short unconditional path, rather than count call sites.
    rows=init.splitlines()[1:]
    index=next(i for i,l in enumerate(rows) if 'symbol stub for: '+direct[0] in l)
    branch=re.search(r'cbz\s+x0, (0x[0-9a-f]+)',rows[index+1]);assert branch
    byaddr={int(re.match(r'\s*([0-9a-f]+):',l)[1],16):l for l in rows if re.match(r'\s*([0-9a-f]+):',l)}
    pc=int(branch[1],16);null_path=[]
    for _ in range(24):
        row=byaddr[pc];null_path.append(row.strip())
        assert 'bl\t' not in row and 'blraa' not in row
        if re.search(r'\tret(?:ab)?(?:\s|$)',row): break
        jump=re.search(r'\tb\s+(0x[0-9a-f]+)',row)
        pc=int(jump[1],16) if jump else pc+4
    else: raise AssertionError('null acquisition did not return')
    assert init.count('symbol stub for: '+direct[1])==2
    assert 'bl\t_adreno_resource_list_acquire' in init
    assert re.search(r'#0x3a87, lsl #48',release)
    release_word=nword(ns['__ZTV13IOGPUResource']+16+5*8)
    assert (release_word>>32)&0xffff==0x3a87
    assert nbase+(release_word&0xffffffff)==ns['__ZNK11IOGPUObject7releaseEv']
    _,syms,_,word=abi.macho(binary);v=syms['__ZTV17AdrenoSegmentList']+16
    callbacks=[]
    for slot,disc,name in [(22,0xedc5,'__ZN17AdrenoSegmentList4freeEv'),(39,0x4320,initname)]:
        w=word(v+slot*8)
        assert (w>>32)&0xffff==disc and w&0xffffffff==syms[name]
        callbacks.append(dict(slot=slot,discriminator=hex(disc),symbol=name))
    layout=(out/('kext-layout.log' if args.wiring else 'kext-layout-v2.log')).read_text().split('0 | class AdrenoSegmentList\n')[1].split('*** Dumping')[0]
    for offset,field in [(16,'fDevice'),(24,'fEntries'),(32,'fEntryBytes'),(40,'fResources')]:
        assert re.search(r'\n\s*'+str(offset)+r' \|.*\b'+field+r'\b',layout)
    assert '[sizeof=64,' in layout
    assert len(resource['virtual_calls'])==22 and len(resource['callbacks'])==7
    assert profile['preserved_model_count']==122 and profile['images']['combined']['gpu_params'][0]==0x17
    assert '-DSNAP_CLASS_LEAF_MEMO=0' in monitor['build_defines']
    assert sha(out/'current/monitor/xnuboot.bin')==monitor['monitor_sha256']
    wiring={}
    external={}
    if args.wiring:
        trace=read('native-v2.json');wi=trace['images'][0]
        assert wi['uuid']==image['uuid'] and wi['kdk_sha256']==image['kdk_sha256']
        assert trace['wiring_tracer_sha256']==sha(ROOT/'tools/trace-adreno-wiring.py')
        assert trace['tracer_sha256']==sha(ROOT/'tools/trace-adreno-memory-map.py')
        assert len(wi['functions'])==23
        Cache=runpy.run_path(str(ROOT/'tools/kc-xref.py'))['Kernelcache']
        kc=Cache(ROOT/'downloads/extracted/j700ap/kernelcache.release.mac17p',scope='com.apple.iokit.IOGPUFamily')
        for f in wi['functions']:
            code=bytes.fromhex(f['bytes_hex'])
            offset=kc.va2off(int(f['kc'],16))
            assert kc.data[offset:offset+len(code)]==code,f['symbol']
        prep='__ZN11IOGPUMemory13prepareMemoryEv'
        done='__ZN11IOGPUMemory14completeMemoryEv'
        wf={f['symbol']:f for f in wi['functions']}
        assert any(i['mnemonic']=='ldadda' for i in wf[prep]['instructions'])
        assert any(i['mnemonic']=='ldaddl' for i in wf[done]['instructions'])
        slow=wf['__ZN11IOGPUMemory19prepare_memory_slowEjby']['instructions']
        assert any(i['address']=='0xfffffe000a8513c4' and i['mnemonic'].startswith('ldadd') for i in slow)
        prepare=body('__ZN15AdrenoMemoryMap20prepareForSubmissionEv')
        assert prepare.index('symbol stub for: '+prep)<prepare.index('symbol stub for: _IORecursiveLockLock')
        assert 'symbol stub for: '+done in prepare
        assert 'symbol stub for: '+done in body('__ZN15AdrenoMemoryMap18completeSubmissionEv')
        additional=[]
        for vtable,slot,disc,target,pattern in [
            ('__ZTV11IOGPUMemory',52,0x5223,'__ZNK11IOGPUMemory12get_iomd_ptrEv',r'mov\s+x17, #0x1a0'),
            ('__ZTV14IOGPUMemoryMap',43,0x31a9,'__ZN14IOGPUMemoryMap20getGPUVirtualAddressEv',r'ldr\s+x8, \[x8, #0x168\]')]:
            w=nword(ns[vtable]+16+slot*8)
            assert (w>>32)&0xffff==disc and nbase+(w&0xffffffff)==ns[target]
            assert re.search(pattern,prepare) and re.search('#'+hex(disc)+r', lsl #48',prepare)
            additional.append(dict(vtable=vtable,slot=slot,discriminator=hex(disc),symbol=target))
        assert 'bl\t_adreno_resource_list_prepare' in init
        submit=body('__ZN19AdrenoAcceleratorX211submitFenceEv')
        assert '#-0x5c' in submit and '#-0x5d' in submit
        queue=next(s for s in syms if s.startswith('__ZN18AdrenoCommandQueue27processSegmentKernelCommand'))
        assert re.search(r'cmn\s+w0, #0x5c',body(queue))
        assert 'bl\t__ZN17AdrenoSegmentList18retainAfterTimeoutEv' in body(queue)
        wiring=dict(native_functions=23,additional_virtual_calls=additional,
            prepare_symbol=prep,complete_symbol=done,
            limitation='Native preparation execution, cache maintenance, resource-bearing GPU commands and GUI remain unqualified')
        external={str(p.relative_to(ROOT)):sha(p) for p in (retained/'native-v3.json',retained/'native-parser-replay-v4.json')}
        sources['tools/trace-adreno-wiring.py']=sha(ROOT/'tools/trace-adreno-wiring.py')
    for name in ['compat/adreno-resource-list.c','compat/adreno-resource-list.h',
        'gpu/adreno-kext/kext/src/AdrenoSegmentList.cpp','tools/replay-adreno-resource-retention.c',
        'tools/test-adreno.c','tools/trace-adreno-resource-list.py','tools/replay-adreno-resource-list.py',
        'tools/qualify-adreno-retention.py','tools/kc-xref.py','build/build-adreno-kext-resource-20260926.py']:
        sources[name]=sha(ROOT/name)
    for directory in ('gpu/adreno-kext/kext','gpu/adreno-kext/include'):
        for path in (ROOT/directory).rglob('*'):
            if path.is_file() and 'out' not in path.parts and path.suffix in ('.c','.cpp','.h','.sh','.plist'):
                sources[str(path.relative_to(ROOT))]=sha(path)
    result=dict(status='HOST_RESOURCE_'+('WIRING' if args.wiring else 'RETENTION')+'_QUALIFIED_NATIVE_PENDING',boundary=__doc__,
        integration_checks=checks,native_parser_cases=5032,direct_native_calls=direct,
        wiring=wiring,external_artifacts_sha256=external,
        segment_callbacks=callbacks,null_acquisition_path=null_path,segment_size=64,
        kext_sha256=sha(binary),monitor_sha256=monitor['monitor_sha256'],sources_sha256=sources,
        artifacts_sha256={str(p.relative_to(out)):sha(p) for p in sorted(out.rglob('*')) if p.is_file()
            and p!=args.output.resolve() and not p.name.endswith('-qualification.log')})
    args.output.write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps({k:v for k,v in result.items() if k not in ('boundary','direct_native_calls',
        'segment_callbacks','null_acquisition_path','sources_sha256','artifacts_sha256')}))


if __name__=='__main__': main()

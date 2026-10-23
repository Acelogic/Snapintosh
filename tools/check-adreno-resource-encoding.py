#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Reproduce native resource encoding without creating a host GPU device.

Failure inventory and scope: docs/ADRENO-FIRST-METAL-IMAGE-20260926.md.
The harness uses synthetic IOGPUMetalResource objects and substitutes their
native deallocator with NSObject's path. Packing, Metal object-list retention,
Adreno metadata recording and the Adreno kernel-list parser are actual code.
No native kernel allocation, guest execution or rendering is claimed.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import runpy
import subprocess

ROOT=Path(__file__).resolve().parents[1]
PLUGIN=ROOT/'gpu/adreno-kext/plugin'

def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--output',type=Path,required=True)
    args=ap.parse_args()
    out=args.output.resolve()
    out.mkdir(parents=True,exist_ok=False)
    build=subprocess.check_output(['sw_vers','-buildVersion'],text=True).strip()
    if build!='26A428': raise RuntimeError('Unqualified host build: '+build)
    Cache=runpy.run_path(str(ROOT/'tools/dyld-cache.py'))['Cache']
    cache=Cache(Path('/System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld'))
    native={}
    for path,uuid,names in [
        ('/System/Library/PrivateFrameworks/IOGPU.framework/Versions/A/IOGPU',
         '3959324fd63d33878e97238f27a76b74',[
             '_IOGPUResourceListInit','_IOGPUResourceListReset','_IOGPUResourceListAddResource',
             '__ioGPUResourceListAddResourceEntry','_ioGPUResourceListAddHashValue',
             '_IOGPUMetalCommandBufferStorageBeginSegment','_IOGPUMetalCommandBufferStorageEndSegment',
             '-[IOGPUMetalResource resourceID]','-[IOGPUMetalResource resourceSize]']),
        ('/System/Library/Frameworks/Metal.framework/Versions/A/Metal',
         'b0bc74fe7080347d92ee38195058ccce',[
             '_MTLResourceListAddResource','-[MTLResourceList releaseAllObjectsAndReset]'])]:
        image=cache.image(path)
        if image['uuid']!=uuid: raise RuntimeError('Unqualified native image '+path)
        symbols=sorted((a,n) for a,n,_,_ in cache.symbols(path) if a)
        functions={}
        for name in names:
            matches=[a for a,n in symbols if n==name]
            if len(matches)!=1: raise RuntimeError('Ambiguous native function '+name)
            start=matches[0];end=next(a for a,n in symbols if a>start)
            data=cache.read(start,end-start)
            functions[name]={'offset':start-image['base'],'code_hex':data.hex(),
                             'sha256':hashlib.sha256(data).hexdigest()}
        native[path]={'uuid':uuid,'functions':functions}
    cache.close()
    (out/'native.json').write_text(json.dumps(native,indent=2)+'\n')
    sources=[Path(__file__).resolve(),ROOT/'tools/dyld-cache.py',
             ROOT/'compat/adreno-resource-list.c',ROOT/'compat/adreno-resource-list.h',
             ROOT/'compat/adreno-submit.h',PLUGIN/'build.sh',
             PLUGIN/'harness/resource-encoding.m',PLUGIN/'harness/regtest.m',PLUGIN/'harness/ws_selectors.h']
    sources+=list((PLUGIN/'AdrenoMetal').rglob('*'))   # split sources keep their parts in subdirectories
    sources+=list((PLUGIN.parent/'include').glob('*.h'))
    source_hashes={str(p.relative_to(ROOT)):sha(p) for p in sorted(sources) if p.is_file()}
    commands=[]
    def run(argv,log,env=None):
        commands.append(argv)
        with (out/log).open('x') as output:
            subprocess.run(argv,cwd=ROOT,env=env,stdout=output,stderr=subprocess.STDOUT,check=True)
    run(['xcrun','clang','-arch','arm64e','-mmacosx-version-min=27.0',
         '-fobjc-arc','-fobjc-arc-exceptions','-O1','-g','-Wall','-Werror',
         str(PLUGIN/'harness/resource-encoding.m'),str(PLUGIN/'AdrenoMetal/AdrenoResourceUsage.m'),
         str(ROOT/'compat/adreno-resource-list.c'),'-framework','Foundation','-framework','Metal',
         str(PLUGIN/'AdrenoMetal/IOGPU.tbd'),'-o',str(out/'resource-encoding')],'compile.log')
    run([str(out/'resource-encoding'),str(out/'payload.bin')],'run.json')
    result=json.loads((out/'run.json').read_text())
    if result.get('status')!='ADRENO_NATIVE_RESOURCE_ENCODING_PASS':
        raise RuntimeError('Native harness did not pass')
    env=dict(os.environ,OUT=str(out/'plugin'))
    run(['sh',str(PLUGIN/'build.sh')],'plugin-build.log',env)
    binary=out/'plugin/AdrenoMetal.bundle/Contents/MacOS/AdrenoMetal'
    run(['codesign','--verify','--strict',str(binary.parent.parent.parent)],'signature.log')
    for name,digest in source_hashes.items():
        if sha(ROOT/name)!=digest: raise RuntimeError('Source changed during qualification: '+name)
    artifacts={str(p.relative_to(out)):sha(p) for p in sorted(out.rglob('*')) if p.is_file()}
    record={'status':'ADRENO_RESOURCE_ENCODING_HOST_QUALIFIED','host_build':build,
            'sources':source_hashes,'artifacts':artifacts,'commands':commands,
            'result':result,'boundary':__doc__}
    (out/'qualification.json').write_text(json.dumps(record,indent=2)+'\n')
    print(json.dumps({'status':record['status'],'output':str(out/'qualification.json'),
                      'resources':result['resources'],'sources':len(source_hashes)}))

if __name__=='__main__': main()

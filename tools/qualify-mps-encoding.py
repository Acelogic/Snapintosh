#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Artifact-producing real MPS -> Adreno ordered encoding E2E, without GPU submission.

--verify verifies exact retained source/input/artifact hashes and reruns the wire
oracle. The rebuilt compiler runtime is an explicit hashed input, not rebuilt here.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
sys.dont_write_bytecode=True

ROOT=Path(__file__).resolve().parents[1]
PLUGIN=ROOT/'gpu/adreno-kext/plugin'
LIBRARY=Path('/System/Library/Frameworks/MetalPerformanceShaders.framework/Versions/A/Frameworks/MPSImage.framework/Versions/A/Resources/default.metallib')

def sha(p):
    h=hashlib.sha256()
    with Path(p).open('rb') as f:
        for chunk in iter(lambda:f.read(1<<20),b''): h.update(chunk)
    return h.hexdigest()

def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--out',type=Path)
    ap.add_argument('--runtime',type=Path);ap.add_argument('--verify',type=Path)
    ap.add_argument('--reference-capture',type=Path,default=ROOT/'build/compute-recovery-20261018/sealed/capture/capture.json')
    ap.add_argument('--lifecycle-only',action='store_true');ap.add_argument('--strict',action='store_true');args=ap.parse_args()
    if args.verify:
        receipt=args.verify.resolve();r=json.loads(receipt.read_text())
        for name,h in r['sources'].items():
            source=Path(name)
            copy_path=r.get('source_copies',{}).get(name)
            if copy_path: source=receipt.parent/copy_path
            elif source.is_relative_to(ROOT) and (receipt.parent/'source'/source.relative_to(ROOT)).is_file():
                source=receipt.parent/'source'/source.relative_to(ROOT)
            if sha(source)!=h: raise SystemExit('RETAINED SOURCE OR SYSTEM INPUT CHANGED: '+str(source))
        for name,h in r['artifacts'].items():
            if sha(receipt.parent/name)!=h: raise SystemExit('ARTIFACT CHANGED: '+name)
        spec=importlib.util.spec_from_file_location('mps_encoding_decoder',receipt.parent/'source/tools/decode-mps-encoding.py')
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        capture=receipt.parent/'capture/capture.json'
        if r.get('lifecycle_only'):
            c=json.loads(capture.read_text());check_lifecycle(c);cases=c['controls']
        else:
            reference=json.loads((receipt.parent/r['reference_capture_copy']).read_text())
            cases=module.check_capture(json.loads(capture.read_text()),capture.parent,reference=reference)
        print(f"VERIFIED {r['status']}: {len(cases)} encoded cases; {len(r['sources'])} sources/inputs and {len(r['artifacts'])} artifacts")
        return
    if args.out is None or (args.runtime is None and not args.lifecycle_only): ap.error('--out and --runtime or --verify required')
    out=args.out.resolve();out.mkdir(parents=True,exist_ok=False);runtime=args.runtime.resolve() if args.runtime else None
    if runtime and not (runtime/'libAdrenoCompiler.dylib').is_file(): raise SystemExit('Missing compiler runtime')
    report={'status':'RUNNING','target_access':False,'gpu_submission':False,
            'boundary':'Real host MPS and Adreno compiler/encoder, final command bytes intercepted before native submission. No Adreno execution, numeric shader result, A16, guest, display or performance proof.',
            'compiler_runtime':str(runtime) if runtime else None,'lifecycle_only':args.lifecycle_only,'strict':args.strict,'commands':[],'sources':{},'source_copies':{},'artifacts':{},
            'historical_verification':'Retained local sources and runtime binaries; current host system MPS library identity remains required.'}
    sources=[Path(__file__),ROOT/'tools/decode-mps-encoding.py',PLUGIN/'harness/mps-integral-encoding.m',PLUGIN/'build.sh',LIBRARY,
             ROOT/'docs/ADRENO-MPS-ENCODING-E2E-20261019.md']
    sources += [p for p in (PLUGIN/'AdrenoMetal').rglob('*') if p.is_file() and p.suffix in ('.m','.h','.tbd','.plist')]
    sources += list((ROOT/'gpu/adreno-kext/include').glob('*.h'))
    sources += list((ROOT/'compat').glob('adreno-*.h'))
    if runtime: sources += list(runtime.glob('*.dylib'))
    if not args.lifecycle_only: sources.append(args.reference_capture.resolve())
    report['sources']={str(p):sha(p) for p in sorted(set(sources))}
    for p in sources:
        if p.is_relative_to(ROOT) and not p.is_relative_to(ROOT/'build'):
            dst=out/'source'/p.relative_to(ROOT);dst.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(p,dst)
            report['source_copies'][str(p)]=str(dst.relative_to(out))
        elif runtime and p.parent==runtime:
            dst=out/'inputs/compiler-runtime'/p.name;dst.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(p,dst)
            report['source_copies'][str(p)]=str(dst.relative_to(out))
        elif p==args.reference_capture.resolve():
            dst=out/'inputs/reference-capture.json';dst.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(p,dst)
            report['source_copies'][str(p)]=str(dst.relative_to(out));report['reference_capture_copy']=str(dst.relative_to(out))
    def save(): (out/'qualification.json').write_text(json.dumps(report,indent=2)+'\n')
    def run(argv,label,env=None,timeout=60):
        row={'argv':[str(a) for a in argv],'env':env or {},'log':label+'.log'};report['commands'].append(row);save()
        with (out/row['log']).open('w') as log:
            process=subprocess.run(argv,cwd=ROOT,env=dict(os.environ,**(env or {})),stdout=log,stderr=subprocess.STDOUT,timeout=timeout)
        row['returncode']=process.returncode
        if process.returncode: raise RuntimeError('Command failed: '+str(out/row['log']))
    try:
        report['host_version']=subprocess.check_output(['sw_vers'],text=True).strip()
        env={'OUT':str(out/'plugin'),'ADRENO_LENIENT':'' if args.strict else '1','ADRENO_COMPILER_RUNTIME':str(runtime) if runtime else ''}
        run(['sh',PLUGIN/'build.sh'],'plugin-build',env)
        executable=out/'mps-integral-encoding'
        run(['xcrun','clang','-arch','arm64e','-fobjc-arc','-O1',PLUGIN/'harness/mps-integral-encoding.m','-o',executable,
             '-framework','Foundation','-framework','Metal','-framework','MetalPerformanceShaders','-framework','IOKit'],'harness-build')
        run(['codesign','-f','-s','-',executable],'harness-sign')
        run([executable,out/'plugin/AdrenoMetal.bundle',out/'capture']+(['--lifecycle-only'] if args.lifecycle_only else []),'mps-encoding',timeout=45)
        if args.lifecycle_only:
            capture=json.loads((out/'capture/capture.json').read_text());check_lifecycle(capture)
            report['status']='PASS_NATIVE_ENCODER_LIFECYCLE';report['cases']=len(capture['controls'])
            report['api_refusal_controls']=len(capture['controls']);report['artifact_refusal_controls']=0
        else:
            run([sys.executable,ROOT/'tools/decode-mps-encoding.py','--capture',out/'capture/capture.json','--out',out/'decoded',
                 '--reference-capture',out/report['reference_capture_copy']],'decode')
            decoded=json.loads((out/'decoded/decoded.json').read_text())
            if decoded['status']!='PASS_MPS_ORDERED_ENCODING': raise RuntimeError('Encoding oracle did not pass')
            report['status']='PASS_MPS_ORDERED_ENCODING';report['cases']=len(decoded['cases'])
            report['api_refusal_controls']=len(decoded['api_negative_controls']);report['artifact_refusal_controls']=len(decoded['mutation_negative_controls'])
        changed=[p for p,h in report['sources'].items() if sha(p)!=h]
        if changed: raise RuntimeError('Sources changed during qualification: '+', '.join(changed))
    except BaseException as error:
        report['status']='FAILED';report['error']=str(error);raise
    finally:
        report['artifacts']={str(p.relative_to(out)):sha(p) for p in out.rglob('*') if p.is_file() and p!=out/'qualification.json'};save()
    print(report['status']+f": {report['cases']} cases; no GPU submission or target I/O")

def check_lifecycle(capture):
    if capture['status']!='LIFECYCLE_CAPTURE_ONLY' or capture['intercepted_commits']!=0:
        raise ValueError('Lifecycle capture submitted or did not finish')
    required={'compute-blit-overlap','blit-compute-overlap','blit-render-overlap','commit-open-blit'}
    if {r['name'] for r in capture['controls']}!=required: raise ValueError('Lifecycle control coverage')
    for row in capture['controls']:
        encoders=row['work']['encoders']
        if not (row['refused'] and row['original_encoder_ended'] and row['native_commits']==0 and
                row['work']['encoding_failed'] and len(encoders)==1 and all(e['ended'] for e in encoders.values())):
            raise ValueError('Lifecycle ledger/balance proof: '+row['name'])

if __name__=='__main__': main()

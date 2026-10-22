#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Build/run real queued blit API -> final command bytes; no GPU submission/A16.
Historical --verify uses retained source/runtime copies, current system MPS identity.
"""
import argparse,hashlib,importlib.util,json,os,shutil,subprocess,sys
from pathlib import Path
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[1];PLUGIN=ROOT/'gpu/adreno-kext/plugin'
LIBRARY=Path('/System/Library/Frameworks/MetalPerformanceShaders.framework/Versions/A/Frameworks/MPSImage.framework/Versions/A/Resources/default.metallib')
def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--out',type=Path);ap.add_argument('--runtime',type=Path)
    ap.add_argument('--strict',action='store_true');ap.add_argument('--verify',type=Path)
    ap.add_argument('--reference-capture',type=Path,default=ROOT/'build/compute-recovery-20261018/sealed/capture/capture.json');args=ap.parse_args()
    if args.verify:
        receipt=args.verify.resolve();r=json.loads(receipt.read_text())
        for name,h in r['sources'].items():
            source=receipt.parent/r['source_copies'][name] if name in r['source_copies'] else Path(name)
            if sha(source)!=h:raise SystemExit('RETAINED SOURCE/SYSTEM INPUT CHANGED '+str(source))
        for name,h in r['artifacts'].items():
            if sha(receipt.parent/name)!=h:raise SystemExit('ARTIFACT CHANGED '+name)
        spec=importlib.util.spec_from_file_location('blit_decoder',receipt.parent/'source/tools/decode-blit-encoding.py')
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        capture=receipt.parent/'capture/capture.json';cases=module.check(json.loads(capture.read_text()),capture.parent)
        baseline=capture.parent/'mps-baseline-capture.json';reference=json.loads((receipt.parent/r['reference_capture_copy']).read_text())
        module.m.check_capture(json.loads(baseline.read_text()),baseline.parent,reference=reference)
        decoded=json.loads((receipt.parent/'decoded/decoded.json').read_text())
        for control in decoded['mutation_negative_controls']:
            folder=receipt.parent/'decoded/negative'/control['name']
            bad=json.loads((folder/'capture.json').read_text());overrides={}
            for name,h in control['overrides'].items():
                data=(folder/name).read_bytes()
                if hashlib.sha256(data).hexdigest()!=h:raise SystemExit('MUTATION BYTES CHANGED '+name)
                overrides[name]=data
            try:module.check(bad,capture.parent,overrides)
            except ValueError as error:
                if str(error)!=control['reason']:raise SystemExit('MUTATION REFUSAL CHANGED '+control['name'])
            else:raise SystemExit('MUTATION ACCEPTED '+control['name'])
        print(f"VERIFIED {r['status']}: {len(cases)} cases, {len(decoded['mutation_negative_controls'])} corruption replays, {len(r['sources'])} inputs and {len(r['artifacts'])} artifacts")
        return
    if not args.out or not args.runtime:ap.error('--out and --runtime or --verify required')
    out=args.out.resolve();out.mkdir(parents=True,exist_ok=False);runtime=args.runtime.resolve();reference=args.reference_capture.resolve()
    if not (runtime/'libAdrenoCompiler.dylib').is_file():raise SystemExit('Missing compiler runtime')
    report={'status':'RUNNING','target_access':False,'gpu_submission':False,'strict':args.strict,
        'boundary':'Real host Metal/MPS API and queued command encoding; native commit intercepted. Expected byte fixtures are API reference data, not GPU execution or performance proof.',
        'commands':[],'sources':{},'source_copies':{},'artifacts':{},'reference_capture_copy':'inputs/reference-capture.json'}
    sources=[Path(__file__),ROOT/'tools/decode-blit-encoding.py',ROOT/'tools/decode-mps-encoding.py',
        PLUGIN/'harness/blit-encoding.m',PLUGIN/'harness/mps-integral-encoding.m',PLUGIN/'build.sh',LIBRARY,reference,
        ROOT/'docs/ADRENO-BLIT-ENCODING-E2E-20261019.md']
    sources += [p for p in (PLUGIN/'AdrenoMetal').rglob('*') if p.is_file() and p.suffix in ('.m','.h','.tbd','.plist')]
    sources += list((ROOT/'gpu/adreno-kext/include').glob('*.h'))+list((ROOT/'compat').glob('adreno-*.h'))+list(runtime.glob('*.dylib'))
    for p in sorted(set(sources)):
        report['sources'][str(p)]=sha(p);dst=None
        if p.is_relative_to(ROOT) and not p.is_relative_to(ROOT/'build'):dst=out/'source'/p.relative_to(ROOT)
        elif p.parent==runtime:dst=out/'inputs/compiler-runtime'/p.name
        elif p==reference:dst=out/report['reference_capture_copy']
        if dst:
            dst.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(p,dst);report['source_copies'][str(p)]=str(dst.relative_to(out))
    def save():(out/'qualification.json').write_text(json.dumps(report,indent=2)+'\n')
    def run(argv,label,env=None,timeout=60):
        row={'argv':[str(a) for a in argv],'env':env or {},'log':label+'.log'};report['commands'].append(row);save()
        with (out/row['log']).open('w') as f:p=subprocess.run(argv,cwd=ROOT,env=dict(os.environ,**(env or {})),stdout=f,stderr=subprocess.STDOUT,timeout=timeout)
        row['returncode']=p.returncode
        if p.returncode:raise RuntimeError('Command failed: '+str(out/row['log']))
    try:
        run(['sh',PLUGIN/'build.sh'],'plugin-build',{'OUT':str(out/'plugin'),'ADRENO_LENIENT':'' if args.strict else '1','ADRENO_COMPILER_RUNTIME':str(runtime)})
        executable=out/'blit-encoding'
        run(['xcrun','clang','-arch','arm64e','-fobjc-arc','-O1',PLUGIN/'harness/blit-encoding.m','-o',executable,
             '-framework','Foundation','-framework','Metal','-framework','MetalPerformanceShaders','-framework','IOKit'],'harness-build')
        run(['codesign','-f','-s','-',executable],'harness-sign')
        run([executable,out/'plugin/AdrenoMetal.bundle',out/'capture'],'blit-encoding',timeout=60)
        run([sys.executable,ROOT/'tools/decode-blit-encoding.py','--capture',out/'capture/capture.json','--out',out/'decoded',
             '--reference-capture',out/report['reference_capture_copy']],'decode')
        decoded=json.loads((out/'decoded/decoded.json').read_text())
        if decoded['status']!='PASS_QUEUED_BLIT_ENCODING':raise RuntimeError('Blit oracle did not pass')
        changed=[p for p,h in report['sources'].items() if sha(p)!=h]
        if changed:raise RuntimeError('Inputs changed during qualification: '+', '.join(changed))
        report.update(status=decoded['status'],cases=len(decoded['cases']),api_refusal_controls=len(decoded['api_negative_controls']),artifact_refusal_controls=len(decoded['mutation_negative_controls']))
    except BaseException as error:report.update(status='FAILED',error=str(error));raise
    finally:
        report['artifacts']={str(p.relative_to(out)):sha(p) for p in out.rglob('*') if p.is_file() and p!=out/'qualification.json'};save()
    print(report['status']+f": {report['cases']} cases; no GPU submission or target I/O")
if __name__=='__main__':main()

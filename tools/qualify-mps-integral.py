#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Reproduce MPS -> Adreno capture and CPU execution of its exact AIR; no GPU submission.

The retained compiler runtime is an explicit, hashed input, not rebuilt here.
--verify checks every retained artifact and source/input hash without hardware I/O.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
PLUGIN = ROOT/'gpu/adreno-kext/plugin'
LIBRARY = Path('/System/Library/Frameworks/MetalPerformanceShaders.framework/Versions/A/Frameworks/MPSImage.framework/Versions/A/Resources/default.metallib')
ENTRIES = ('sum_rgba_columns', 'sum_rgba_rows')

def sha(p):
    h = hashlib.sha256()
    with Path(p).open('rb') as f:
        for b in iter(lambda:f.read(1<<20), b''):
            h.update(b)
    return h.hexdigest()

def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--out', type=Path)
    ap.add_argument('--runtime', type=Path, default=ROOT/'build/current-assets/metal-stage/AdrenoMetal.bundle/Contents/Frameworks')
    ap.add_argument('--verify', type=Path)
    args = ap.parse_args()
    if args.verify:
        receipt = args.verify.resolve()
        r = json.loads(receipt.read_text())
        for p,h in r['sources'].items():
            if sha(p) != h:
                raise SystemExit('SOURCE CHANGED: '+p)
        for p,h in r['artifacts'].items():
            if sha(receipt.parent/p) != h:
                raise SystemExit('ARTIFACT CHANGED: '+p)
        print(f"VERIFIED {r['status']}: {len(r['sources'])} sources/inputs, {len(r['artifacts'])} artifacts")
        return
    if args.out is None:
        ap.error('--out or --verify required')
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=False)
    runtime = args.runtime.resolve()
    if not (runtime/'libAdrenoCompiler.dylib').is_file():
        raise SystemExit('Missing compiler runtime')
    report = {'status':'RUNNING', 'target_access':False, 'gpu_submission':False,
              'boundary':'Real host MPS and Adreno compiler callbacks; captured AIR on CPU. No NIR/ir3 execution, Adreno packet execution, guest or display qualification.',
              'compiler_runtime':'Retained binary input, not rebuilt by this workflow',
              'commands':[], 'sources':{}, 'artifacts':{}}
    sources = [Path(__file__),ROOT/'tools/replay-mps-integral.py',ROOT/'tools/replay-mps-integral.c',
               PLUGIN/'build.sh', PLUGIN/'harness/mps-integral-capture.m',
               ROOT/'gpu/air2ir3/tools/metallib.py', LIBRARY]
    sources += [p for p in (PLUGIN/'AdrenoMetal').rglob('*') if p.is_file() and p.suffix in ('.m','.h','.tbd','.plist')]
    sources += list(runtime.glob('*.dylib'))
    report['sources'] = {str(p):sha(p) for p in sources}
    (out/'source').mkdir()
    for p in sources:
        if p.is_relative_to(ROOT) and not p.is_relative_to(ROOT/'build'):
            dst = out/'source'/p.relative_to(ROOT)
            dst.parent.mkdir(parents=True,exist_ok=True)
            shutil.copy2(p,dst)
    def save():
        (out/'qualification.json').write_text(json.dumps(report,indent=2)+'\n')
    def run(argv, label, env=None, timeout=60):
        row = {'argv':[str(a) for a in argv], 'env':env or {},'log':label+'.log'}
        report['commands'].append(row)
        save()
        with (out/row['log']).open('w') as f:
            p = subprocess.run(argv,cwd=ROOT,env=dict(os.environ,**(env or {})),stdout=f,stderr=subprocess.STDOUT,timeout=timeout)
        row['returncode'] = p.returncode
        if p.returncode:
            raise RuntimeError('Command failed: '+str(out/row['log']))
    try:
        report['host_version'] = subprocess.check_output(['sw_vers'],text=True).strip()
        run(['sh',PLUGIN/'build.sh'],'plugin-build',{'OUT':str(out/'plugin'),'ADRENO_LENIENT':'1','ADRENO_COMPILER_RUNTIME':str(runtime)})
        executable = out/'mps-integral-capture'
        run(['xcrun','clang','-arch','arm64e','-fobjc-arc','-O1',PLUGIN/'harness/mps-integral-capture.m','-o',executable,
             '-framework','Foundation','-framework','Metal','-framework','MetalPerformanceShaders','-framework','IOKit'],'harness-build')
        run(['codesign','-f','-s','-',executable],'harness-sign')
        run([executable,out/'plugin/AdrenoMetal.bundle',out/'capture'],'mps-capture',timeout=45)
        run([sys.executable,ROOT/'tools/replay-mps-integral.py','--capture',out/'capture/capture.json','--out',out/'cpu-replay'],'cpu-replay')
        # The file library and runtime MPS callback select different AIR modules.
        # Keep both identities; do not silently substitute one for the other.
        sys.path.insert(0,str(ROOT/'gpu/air2ir3/tools'))
        import metallib
        d,h,functions = metallib.parse(str(LIBRARY))
        directory = out/'file-library-air';directory.mkdir()
        extracted = []
        for entry in ENTRIES:
            rows = [f for f in functions if f['name'] == entry]
            if len(rows) != 1:
                raise RuntimeError('Ambiguous library function '+entry)
            f = rows[0];start = h['bitcode'][0]+f['bc_off']
            raw = d[start:start+f['bc_size']]
            if hashlib.sha256(raw).hexdigest() != f['hash']:
                raise RuntimeError('Library function HASH mismatch')
            (directory/(entry+'.bc')).write_bytes(raw)
            extracted.append(f)
        (directory/'origin.json').write_text(json.dumps({'library':str(LIBRARY),'library_sha256':sha(LIBRARY),'header':h,'functions':extracted},indent=2)+'\n')
        replay = json.loads((out/'cpu-replay/qualification.json').read_text())
        report['cases'] = replay['cases']
        report['status'] = 'PASS_MPS_CAPTURE_AND_AIR_CPU_REPLAY'
    except BaseException as e:
        report['status'] = 'FAILED'
        report['error'] = str(e)
        raise
    finally:
        report['artifacts'] = {str(p.relative_to(out)):sha(p) for p in out.rglob('*') if p.is_file() and p != out/'qualification.json'}
        save()
    print(report['status']+f": {len(report['cases'])} cases; no GPU submission or target I/O")

if __name__ == '__main__':
    main()

#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Link and pin the qualified fill driver using the original Mac build tools.

Opens one native administrator prompt for kmutil's root-owned staging. Does not
install anything or connect to the A16. All outputs require a fresh directory.
"""
from pathlib import Path
import argparse
import hashlib
import json
import plistlib
import shlex
import subprocess
import sys

ROOT=Path(__file__).resolve().parents[1]
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()

def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--qualification',type=Path,required=True)
    ap.add_argument('--original',type=Path,required=True)
    ap.add_argument('--output',type=Path,required=True)
    args=ap.parse_args()
    qualification=args.qualification.resolve();record=json.loads(qualification.read_text())
    kind = record['status']
    assert kind in ('METAL_FILL_NATIVE_PRODUCER_DRIVER_MODEL_QUALIFIED_NOT_INSTALLED',
                    'FILL_COMMAND_MONITOR_KEXT_HOST_QUALIFIED_NOT_INSTALLED')
    original=args.original.resolve();out=args.output.resolve()
    kext=qualification.parent/('integration/kext/AdrenoX2.kext'
        if kind=='METAL_FILL_NATIVE_PRODUCER_DRIVER_MODEL_QUALIFIED_NOT_INSTALLED'
        else 'kext/AdrenoX2.kext')
    binary=kext/'Contents/MacOS/AdrenoX2'
    bundle=plistlib.loads((kext/'Contents/Info.plist').read_bytes())['CFBundleIdentifier']
    assert bundle=='org.snapintosh.driver.AdrenoX2'
    def verify():
        for name,digest in record['sources_sha256'].items():assert sha(ROOT/name)==digest,name
        for name,digest in record['artifacts_sha256'].items():assert sha(qualification.parent/name)==digest,name
        assert sha(binary)==record['kext_sha256']
    verify()
    scripts=['build/kmutil-auxkc.sh','tools/auxkc-bundles.py','tools/auxkc-autoload.py',
             'build/build-auxkc.py','probes/auxkc.py','probes/xnuboot.py','probes/bootfb.py',
             'probes/guestprofile.py']
    original_sources={name:sha(original/name) for name in scripts}
    out.mkdir(parents=True,exist_ok=False)
    commands=[]
    def run(name,argv):
        commands.append(argv)
        with (out/(name+'.log')).open('x') as log:
            subprocess.run(argv,cwd=original,stdout=log,stderr=subprocess.STDOUT,check=True)
    run('signature',['codesign','--verify','--strict',str(kext)])
    raw=out/'AdrenoX2-explicit.kc';kc=out/'AdrenoX2.kc'
    shell=shlex.join(['/bin/sh',str(original/'build/kmutil-auxkc.sh'),str(raw),str(kext)])
    shell+=' > '+shlex.quote(str(out/'kmutil.log'))+' 2>&1'
    applescript=out/'link.applescript'
    applescript.write_text('do shell script '+json.dumps(shell)+' with administrator privileges\n')
    plan=dict(qualification=str(qualification),qualification_sha256=sha(qualification),
        qualification_kind=kind,
        kext_sha256=sha(binary),original_sources_sha256=original_sources,
        tool_sha256=sha(Path(__file__)),command=shell,applescript_sha256=sha(applescript))
    (out/'plan.json').write_text(json.dumps(plan,indent=2)+'\n')
    run('administrator',['osascript',str(applescript)])
    verify()
    run('autoload',[sys.executable,str(original/'tools/auxkc-autoload.py'),str(raw),str(kc),
        '--expected-sha256',sha(raw),'--bundle',bundle,'--record',str(out/'packaging.json')])
    run('pin',[sys.executable,str(original/'build/build-auxkc.py'),'pin','--kc',str(kc),
        '--bundle',bundle,'--sha256',sha(kc),
        '--guest-profile','j700ap-26A428-xars-uniform-auxkc-installed-adreno'])
    verify()
    for name,digest in original_sources.items():assert sha(original/name)==digest,name
    result=dict(status='FILL_AUXKC_LINKED_PINNED_NOT_INSTALLED',plan=plan,commands=commands,
        collection_sha256=sha(kc),sources_sha256={str(Path(__file__).relative_to(ROOT)):sha(Path(__file__))},
        artifacts_sha256={str(p.relative_to(out)):sha(p) for p in sorted(out.rglob('*')) if p.is_file()},
        boundary=__doc__)
    report=out/'link.json';report.write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(dict(status=result['status'],collection_sha256=sha(kc),report=str(report))))

if __name__=='__main__':main()

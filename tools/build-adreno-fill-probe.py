#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Build/sign the public Metal fill/readback guest probe, without executing it.

Bind the plug-in identity to a verified native-producer/driver-model record.
This is preparation only; A16 command completion and display remain unproven.
"""
from pathlib import Path
import argparse
import hashlib
import json
import re
import subprocess

ROOT=Path(__file__).resolve().parents[1]
SOURCE=ROOT/'gpu/adreno-kext/plugin/harness/guest-fill-probe.m'
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--qualification',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    qualification=args.qualification.resolve();record=json.loads(qualification.read_text())
    assert record['status']=='METAL_FILL_NATIVE_PRODUCER_DRIVER_MODEL_QUALIFIED_NOT_INSTALLED'
    for name,digest in record['sources_sha256'].items():assert sha(ROOT/name)==digest,name
    for name,digest in record['artifacts_sha256'].items():assert sha(qualification.parent/name)==digest,name
    plugin=qualification.parent/'native-resource/plugin/AdrenoMetal.bundle/Contents/MacOS/AdrenoMetal'
    expected=record['plugin_sha256'];assert sha(plugin)==expected
    assert re.fullmatch('[0-9a-f]{64}',expected)
    output=args.output.resolve();output.mkdir(parents=True,exist_ok=False)
    binary=output/'metal-fill-probe';commands=[]
    sources={str(p.relative_to(ROOT)):sha(p) for p in (SOURCE,Path(__file__).resolve())}
    def run(name,argv):
        commands.append(argv)
        result=subprocess.run(argv,cwd=ROOT,text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
        (output/(name+'.log')).write_text(result.stdout)
        assert result.returncode==0,(name,result.returncode,str(output/(name+'.log')))
        return result.stdout
    run('compiler',['xcrun','clang','--version'])
    run('build',['xcrun','clang','-arch','arm64e','-mmacosx-version-min=27.0',
        '-fobjc-arc','-fobjc-arc-exceptions','-O2','-Wall','-Wextra','-Werror',
        '-Wno-deprecated-declarations','-DSNAP_FILL_PLUGIN_SHA="'+expected+'"',str(SOURCE),
        '-o',str(binary),'-framework','Foundation','-framework','Metal','-framework','IOKit'])
    run('sign',['codesign','-s','-',str(binary)])
    run('verify-signature',['codesign','--verify','--strict','--verbose=2',str(binary)])
    architecture=run('architecture',['lipo','-archs',str(binary)]).strip()
    assert architecture=='arm64e',architecture
    signing=run('signature',['codesign','-dvvv',str(binary)])
    cdhash,=re.findall(r'^CDHash=([0-9a-f]+)$',signing,re.M)
    assert expected.encode() in binary.read_bytes()
    for name,digest in sources.items():assert sha(ROOT/name)==digest,name
    result=dict(status='GUEST_METAL_FILL_PROBE_BUILT_NOT_EXECUTED',
        qualification=str(qualification),qualification_sha256=sha(qualification),
        plugin=str(plugin),plugin_sha256=expected,binary_sha256=sha(binary),
        architecture=architecture,cdhash=cdhash,commands=commands,sources_sha256=sources,
        artifacts_sha256={p.name:sha(p) for p in sorted(output.iterdir()) if p.is_file()},
        boundary=__doc__)
    report=output/'build.json';report.write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(dict(status=result['status'],report=str(report),binary_sha256=sha(binary),cdhash=cdhash)))

if __name__=='__main__':main()

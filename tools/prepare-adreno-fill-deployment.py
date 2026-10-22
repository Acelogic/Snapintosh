#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Stage the exact fill plug-in/probe, trust entries and existing job replacement.

Produces host files only. No disk attachment, SSD write or A16 connection.
"""
from pathlib import Path
import argparse
import hashlib
import json
import plistlib
import re
import shutil
import subprocess
import sys

ROOT=Path(__file__).resolve().parents[1]
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()

def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--qualification',type=Path,required=True)
    ap.add_argument('--probe-build',type=Path,required=True)
    ap.add_argument('--firmware',type=Path,required=True)
    ap.add_argument('--output',type=Path,required=True)
    args=ap.parse_args()
    qualification=args.qualification.resolve();qualified=json.loads(qualification.read_text())
    probe_build=args.probe_build.resolve();probe=json.loads(probe_build.read_text())
    assert probe['qualification_sha256']==sha(qualification)
    assert qualified['status']=='METAL_FILL_NATIVE_PRODUCER_DRIVER_MODEL_QUALIFIED_NOT_INSTALLED'
    assert probe['status']=='GUEST_METAL_FILL_PROBE_BUILT_NOT_EXECUTED'
    for record,base in [(qualified,qualification.parent),(probe,probe_build.parent)]:
        for name,digest in record['sources_sha256'].items():assert sha(ROOT/name)==digest,name
        for name,digest in record['artifacts_sha256'].items():assert sha(base/name)==digest,name
    out=args.output.resolve();out.mkdir(parents=True,exist_ok=False)
    sources=[Path(__file__).resolve(),ROOT/'probes/trustcache.py',ROOT/'probes/guestprofile.py']
    source_hashes={str(p.relative_to(ROOT)):sha(p) for p in sources}
    bundle=qualification.parent/'native-resource/plugin/AdrenoMetal.bundle'
    executable=probe_build.parent/'metal-fill-probe'
    assert sha(bundle/'Contents/MacOS/AdrenoMetal')==probe['plugin_sha256']==qualified['plugin_sha256']
    assert sha(executable)==probe['binary_sha256']
    shutil.copytree(bundle,out/'AdrenoMetal.bundle')
    shutil.copy2(executable,out/'metal-fill-probe')
    rows=[];commands=[]
    for name,path in [('AdrenoMetal',out/'AdrenoMetal.bundle'),('metal-fill-probe',out/'metal-fill-probe')]:
        for kind,argv in [('verify',['codesign','--verify','--strict',str(path)]),
                          ('identity',['codesign','-dvvv',str(path)])]:
            commands.append(argv)
            result=subprocess.run(argv,text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
            (out/(name+'-'+kind+'.log')).write_text(result.stdout)
            assert result.returncode==0,(name,kind)
        cdhash,=re.findall(r'^CDHash=([0-9a-f]{40})$',result.stdout,re.M)
        if name=='metal-fill-probe':assert cdhash==probe['cdhash']
        rows.append(dict(name=name,cdhash=cdhash,category=2,flags=0))
    additions=out/'trust-additions.json';additions.write_text(json.dumps(rows,indent=2)+'\n')
    sys.path.insert(0,str(ROOT/'probes'))
    import xnuboot as xb
    from trustcache import parse_v2
    firmware=args.firmware.resolve()
    xb.configure_guest('j700ap-26A428-xars-uniform-auxkc-installed-adreno-metal',directory=firmware)
    spec=xb.trust_cache_spec(additions);payload=spec.load(firmware)
    assert spec.verify(payload)==payload
    (out/'trustcache.payload').write_bytes(payload)
    job=dict(Label='org.snapintosh.metal-probe',
        ProgramArguments=['/Library/Snapintosh/metal-fill-probe','--report-base','/var/db/Snapintosh/metal-fill-probe','--wait','600'],
        RunAtLoad=True,StandardOutPath='/var/log/snapintosh-metal-fill-probe.log',
        StandardErrorPath='/var/log/snapintosh-metal-fill-probe.log')
    job_path=out/'org.snapintosh.metal-probe.plist'
    with job_path.open('xb') as stream:plistlib.dump(job,stream,sort_keys=True)
    installs=[]
    for file in sorted((out/'AdrenoMetal.bundle').rglob('*')):
        if file.is_file():
            destination='/Library/GPUBundles/AdrenoMetal.bundle/'+str(file.relative_to(out/'AdrenoMetal.bundle'))
            installs.append(dict(source=str(file.relative_to(out)),destination=destination,sha256=sha(file)))
    installs.extend([
        dict(source='metal-fill-probe',destination='/Library/Snapintosh/metal-fill-probe',sha256=sha(out/'metal-fill-probe')),
        dict(source=job_path.name,destination='/private/var/db/ManagedConfigurationFiles/BackgroundTaskServices/LaunchDaemons/'+job_path.name,sha256=sha(job_path))])
    for record,base in [(qualified,qualification.parent),(probe,probe_build.parent)]:
        for name,digest in record['sources_sha256'].items():assert sha(ROOT/name)==digest,name
    for name,digest in source_hashes.items():assert sha(ROOT/name)==digest,name
    result=dict(status='FILL_DEPLOYMENT_STAGED_NOT_INSTALLED',qualification=str(qualification),
        qualification_sha256=sha(qualification),probe_build=str(probe_build),probe_build_sha256=sha(probe_build),
        sources_sha256=source_hashes,commands=commands,installs=installs,trust_rows=rows,
        trust_cache_sha256=sha(out/'trustcache.payload'),trust_entries=parse_v2(payload)['count'],
        firmware_base_trust_sha256=sha(firmware/spec.filename),
        artifacts_sha256={str(p.relative_to(out)):sha(p) for p in sorted(out.rglob('*')) if p.is_file()},
        boundary=__doc__+' Exact installed plug-in destination must be verified against current bundle registration before applying.')
    report=out/'deployment.json';report.write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(dict(status=result['status'],report=str(report),files=len(installs),trust_entries=result['trust_entries'])))

if __name__=='__main__':main()

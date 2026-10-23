#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Build SKS on the retained GPU baseline without modifying its frozen sources."""
from pathlib import Path
import argparse
import hashlib
import json
import re
import runpy
import subprocess
import sys
from source_text import read_source

ORIGINAL=Path(__file__).resolve().parents[1]
sha=lambda p:hashlib.sha256(Path(p).read_bytes()).hexdigest()


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--runtime-root',type=Path,required=True)
    parser.add_argument('--output-dir',type=Path,required=True)
    args=parser.parse_args();root=args.runtime_root.resolve();out=args.output_dir.resolve()
    assert not out.exists();out.mkdir()
    manifest=ORIGINAL/'build/installed-metal-virtual-ethernet-2100s-20260927-launch.json'
    retained=json.loads(manifest.read_text());baseline=Path(retained['runtime_root'])
    assert root!=baseline and root!=ORIGINAL
    for path,digest in retained['source_sha256'].items():assert sha(path)==digest,path
    dma=ORIGINAL/'build/sks-monitor-dma-20260928-v1/qualification.json'
    capture=ORIGINAL/'build/sks-capture-audit-20260928-v2/qualification.json'
    assert sha(dma)=='75d1d528be4bb983b11fdce0a82c4105b813ab692fc352b35c5e3526f9abe780'
    assert sha(capture)=='c026316e986801d20ee4d19c5fa3d39f2f79c64559b2715c5f5d2c58ef70b849'
    for proof in [dma,capture]:
        for path,digest in json.loads(proof.read_text())['inputs_sha256'].items():assert sha(path)==digest,path
    # The DMA qualification executed the same callback source used by this build.
    def callbacks(path):
        source=read_source(path);a=source.index('static int sep_service_admit(')
        return source[a:source.index('static int sep_entropy32(',a)]
    assert callbacks(root/'probes/xnuboot.c')==callbacks(ORIGINAL/'probes/xnuboot.c')
    permitted={'compat/device.c','compat/device.h','compat/sptm-dart.c','compat/sptm-dart.h',
        'probes/devicemodel.py','probes/run.py','probes/xnuboot.c','probes/guestprofile.py',
        'tools/audit-secondary-runtime.py','tools/audit_sep_rom.py','tools/audit_sep_xars.py',
        'tools/secondary-runtime.py'}
    changed=[]
    for path,digest in retained['source_sha256'].items():
        path=Path(path)
        if not path.is_relative_to(baseline):continue
        relative=str(path.relative_to(baseline));candidate=root/relative
        assert candidate.is_file(),relative
        if sha(candidate)!=digest:
            assert relative in permitted,relative
            changed.append(relative)
    for relative in ['compat/sep-sks.c','compat/sep-sks.h','compat/sep-sks-endpoint.c',
            'compat/sep-sks-endpoint.h','tools/audit_sep_sks.py']:
        assert sha(root/relative)==sha(ORIGINAL/relative),relative
    runner=runpy.run_path(str(root/'probes/run.py'));runner['FLAGS'][:]=retained['build_defines']
    sys.path.insert(0,str(root/'probes'))
    from guestprofile import get_profile
    from dataclasses import replace
    old=get_profile(retained['guest_profile']);profile=get_profile(retained['guest_profile']+'-sks')
    assert replace(profile,name=old.name,sep_asc=old.sep_asc)==old
    assert replace(profile.sep_asc,sks_startup=False)==old.sep_asc and profile.sep_asc.sks_startup
    runpy.run_path(str(root/'tools/secondary-runtime.py'))['validate_guest_profile'](profile.name)
    sources={root/p for p in runner['MULTI']['xnuboot']}
    sources.update(p for p in root.rglob('*.h') if '/build/' not in str(p) and '/downloads/' not in str(p))
    sources.update([Path(__file__),root/'probes/run.py',root/'probes/guestprofile.py',root/'probes/probe.ld',
        root/'tools/secondary-runtime.py',
        root.parent/'q1n1/platform/uefi/sha256.h',manifest,dma,capture])
    record=dict(status='RUNNING',hardware_access=False,runtime_root=str(root),guest_profile=profile.name,
        flags=runner['FLAGS'],baseline_changed_sources=changed,
        inputs_sha256={str(p):sha(p) for p in sorted(sources)},retained_sources_verified=len(retained['source_sha256']))
    try:
        payload=runner['build']('xnuboot',out/'monitor')
        record['monitor']=dict(path=str(out/'monitor/xnuboot.bin'),bytes=len(payload),sha256=sha(out/'monitor/xnuboot.bin'))
        command=[str(runner['LLVM']/'clang'),*runner['FLAGS'],'-I'+str(root/'shadow'),
            '-I'+str(root.parent/'q1n1/platform/uefi'),'-Xclang','-fdump-record-layouts',
            '-fsyntax-only',str(root/'probes/xnuboot.c')]
        result=subprocess.run(command,text=True,capture_output=True)
        (out/'layout.txt').write_text(result.stdout+result.stderr);assert result.returncode==0,result.stderr
        context=next(b for b in result.stdout.split('*** Dumping AST Record Layout')
            if re.search(r'^\s*0 \| struct context\s*$',b,re.M))
        size=int(re.search(r'\[sizeof=(\d+),',context)[1])
        offset=int(re.search(r'^\s*(\d+) \|\s+uint8_t\[16384\] sep_sks_request$',context,re.M)[1])
        record.update(status='GPU_BASELINE_SKS_CANDIDATE_BUILT',context_bytes=size,request_scratch_offset=offset,
            layout_sha256=sha(out/'layout.txt'),
            boundary='Current GPU baseline plus qualified SKS source and explicit opt-in board profile. Existing GPU sources unchanged. Compiles within current reservation. No hardware upload or execution.')
        for path,digest in record['inputs_sha256'].items():assert sha(path)==digest,path
    except Exception as error:
        record.update(status='FAILED',error=repr(error));raise
    finally:(out/'qualification.json').write_text(json.dumps(record,indent=2)+'\n')
    print(json.dumps(dict(status=record['status'],output=str(out/'qualification.json'),sha256=sha(out/'qualification.json'))))


if __name__=='__main__':main()

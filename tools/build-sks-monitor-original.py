#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Build original-checkout SKS integration with the retained runtime's flags.

This is an offline integration build, not the frozen pipeline GPU candidate.
"""
from pathlib import Path
import argparse
import hashlib
import json
import re
import runpy
import subprocess

ROOT=Path(__file__).resolve().parents[1]
sha=lambda p:hashlib.sha256(Path(p).read_bytes()).hexdigest()


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--output-dir',type=Path,required=True)
    args=parser.parse_args();out=args.output_dir.resolve();assert not out.exists();out.mkdir()
    manifest=ROOT/'build/installed-metal-virtual-ethernet-2100s-20260927-launch.json'
    retained=json.loads(manifest.read_text())
    for path,digest in retained['source_sha256'].items():assert sha(path)==digest,path
    runner=runpy.run_path(str(ROOT/'probes/run.py'))
    runner['FLAGS'][:]=retained['build_defines']
    sources={ROOT/p for p in runner['MULTI']['xnuboot']}
    sources.update(ROOT.rglob('*.h'))
    sources={p for p in sources if '/build/' not in str(p) and '/downloads/' not in str(p)}
    sources.update([Path(__file__),ROOT/'probes/run.py',ROOT/'probes/probe.ld',manifest,
        ROOT.parent/'q1n1/platform/uefi/sha256.h'])
    record=dict(status='RUNNING',hardware_access=False,flags=runner['FLAGS'],
        inputs_sha256={str(p):sha(p) for p in sorted(sources)},retained_runtime_sources_verified=198)
    try:
        payload=runner['build']('xnuboot',out/'monitor')
        record['monitor']=dict(bytes=len(payload),sha256=sha(out/'monitor/xnuboot.bin'))
        command=[str(runner['LLVM']/'clang'),*runner['FLAGS'],'-I'+str(ROOT/'shadow'),
            '-I'+str(ROOT.parent/'q1n1/platform/uefi'),'-Xclang','-fdump-record-layouts',
            '-fsyntax-only',str(ROOT/'probes/xnuboot.c')]
        layout=subprocess.run(command,text=True,capture_output=True)
        (out/'layout.txt').write_text(layout.stdout+layout.stderr)
        assert layout.returncode==0,layout.stderr
        blocks=layout.stdout.split('*** Dumping AST Record Layout')
        context=next(x for x in blocks if re.search(r'^\s*0 \| struct context\s*$',x,re.M))
        size=int(re.search(r'\[sizeof=(\d+),',context)[1])
        offset=int(re.search(r'^\s*(\d+) \|\s+uint8_t\[16384\] sep_sks_request$',context,re.M)[1])
        record.update(context_bytes=size,request_scratch_offset=offset,
            layout_sha256=sha(out/'layout.txt'),status='ORIGINAL_SKS_MONITOR_BUILD_QUALIFIED',
            boundary='Original checkout compiles/links within existing probe reservation using generation52 flags. All frozen pipeline sources rehash. Not the pipeline GPU runtime, not uploaded or hardware-qualified.')
        for p,digest in record['inputs_sha256'].items():assert sha(p)==digest,p
    except Exception as error:
        record.update(status='FAILED',error=repr(error));raise
    finally:(out/'qualification.json').write_text(json.dumps(record,indent=2)+'\n')
    print(json.dumps(dict(status=record['status'],output=str(out/'qualification.json'),sha256=sha(out/'qualification.json'))))


if __name__=='__main__':main()

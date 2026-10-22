#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Preserve generation52 source and captured evidence before the SKS boot."""
from pathlib import Path
import argparse
import hashlib
import json
import shutil

ROOT=Path(__file__).resolve().parents[1]
PREFIX='installed-metal-virtual-ethernet-2100s-20260927'
sha=lambda p:hashlib.sha256(Path(p).read_bytes()).hexdigest()


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--output-dir',type=Path,required=True)
    args=parser.parse_args();out=args.output_dir.resolve()
    primary=ROOT/'build'/(PREFIX+'-pre-reset-verification.json')
    assert sha(primary)=='94cabcf00b596f9bcfa802c3b74cdebfd13122b9a8287ad1bb88e18862dac81a'
    verified=json.loads(primary.read_text())
    assert verified['status']=='VIRTUAL_ETHERNET_STOPPED_CAPTURES_VERIFIED' and verified['generation']==52
    assert len(verified['artifacts_sha256'])==41
    for suffix,digest in verified['artifacts_sha256'].items():assert sha(ROOT/'build'/(PREFIX+suffix))==digest,suffix
    launch_path=ROOT/'build'/(PREFIX+'-launch.json');launch=json.loads(launch_path.read_text())
    assert launch['exit_code']==9 and launch['finished'] and len(launch['source_sha256'])==198
    for path,digest in launch['source_sha256'].items():assert sha(path)==digest,path
    paths={p for pattern in [PREFIX+'*','*gen52*','sks-resource-wait-gen52-*']
        for p in (ROOT/'build').glob(pattern) if p.is_file()}
    paths.update([Path(__file__),Path(launch['monitor_path']),Path(launch['monitor_path']).with_suffix('.elf')])
    assert all(p.stat().st_size<1024**3 for p in paths),'unexpected large preservation input'
    out.mkdir(exist_ok=False);blobs=out/'blobs';blobs.mkdir()
    def preserve(path):
        path=Path(path);digest=sha(path);target=blobs/digest
        if not target.exists():
            with path.open('rb') as source,target.open('xb') as dest:shutil.copyfileobj(source,dest)
        assert sha(target)==digest
        return dict(sha256=digest,copy=str(target),bytes=path.stat().st_size)
    sources={path:preserve(path) for path in launch['source_sha256']}
    artifacts={str(p):preserve(p) for p in sorted(paths)}
    record=dict(status='GEN52_SOURCES_AND_STOPPED_EVIDENCE_PRESERVED',generation=52,hardware_access=False,
        verification_sha256=sha(primary),launch_sha256=sha(launch_path),runtime_source_count=len(sources),
        runtime_sources=sources,artifacts=artifacts,source_sha256=sha(Path(__file__)),
        boundary='198 runtime sources, monitor binary/ELF and captured generation52 evidence preserved, including unsuccessful capture attempts. Full guest RAM and a fresh filesystem image are not copied. Original WindowServer crash cause remains unknown.')
    result=out/'preservation.json';result.write_text(json.dumps(record,indent=2)+'\n')
    print(json.dumps(dict(status=record['status'],path=str(result),sha256=sha(result),
        runtime_sources=len(sources),artifacts=len(artifacts))))


if __name__=='__main__':main()

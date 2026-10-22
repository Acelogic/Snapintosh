#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Preserve stopped writer-bank failures without accepting a failed runtime audit."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import runpy
import struct
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'probes'))
import run

def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--device',required=True)
    ap.add_argument('--prefix',required=True)
    args=ap.parse_args()
    if not re.fullmatch('[a-z0-9-]+',args.prefix):raise ValueError('invalid prefix')
    base=ROOT/'build'/args.prefix
    launch=json.loads(Path(f'{base}-launch.json').read_text())
    if launch.get('exit_code') not in (8,9) or not launch.get('finished'):
        raise ValueError('requires a terminal guest panic or watchdog return')
    try:os.kill(launch['pid'],0)
    except ProcessLookupError:pass
    else:raise ValueError('launcher PID still present')
    for name,digest in launch['source_sha256'].items():
        if hashlib.sha256((ROOT/name).read_bytes()).hexdigest()!=digest:
            raise ValueError(f'runtime source binding changed: {name}')
    blob=(ROOT/'build/xnuboot.bin').read_bytes()
    if hashlib.sha256(blob).hexdigest()!=launch['monitor_sha256']:
        raise ValueError('canonical monitor binding changed')
    layout=runpy.run_path(str(ROOT/'tools/monitor_layout.py'))['MonitorLayout']()
    api=runpy.run_path(str(ROOT/'tools/audit-native-writers.py'))
    proxy=run.connect(args.device,tries=1)
    try:
        def read(address,size):
            return b''.join(proxy.readmem(address+i,min(4096,size-i),live=True)
                            for i in range(0,size,4096))
        info=proxy.bootinfo();work,size=run.resident_work(proxy,info)
        if read(info['heap_base']+run.CODE_AT,len(blob))!=blob:
            raise ValueError('resident monitor binding changed')
        def context(field,length):
            address=work+layout.offset('context',field)
            if not work<=address<=work+size-length:raise ValueError('outside work arena')
            return read(address,length)
        service=context('services',64)
        enabled,=struct.unpack('<Q',context('writer_breakpoints_enabled',8))
        if enabled not in (0,1):raise ValueError('invalid enabled flag')
        banks=context('writer_debug',6*api['SIZE'])
        rows=[]
        for slot in range(6):
            address=work+layout.offset('context','vcpus')+slot*layout.size('vcpu')
            vcpu=read(address,layout.size('vcpu'))
            prepared,=struct.unpack_from('<Q',vcpu,layout.offset('vcpu','prepared'))
            if prepared not in (0,1):raise ValueError('invalid prepared flag')
            raw=banks[slot*api['SIZE']:(slot+1)*api['SIZE']]
            words=struct.unpack('<35Q',raw)
            row=dict(slot=slot,prepared=bool(prepared),raw_hex=raw.hex(),
                     fields=dict(zip(api['FIELDS'],words[24:])),
                     saved_values=list(words[:6]),saved_controls=list(words[6:12]),
                     observed_values=list(words[12:18]),observed_controls=list(words[18:24]))
            try:row['audit']=api['audit'](raw,enabled=bool(enabled),prepared=bool(prepared))
            except ValueError as error:row['audit_error']=str(error)
            if read(address,len(vcpu))!=vcpu:raise ValueError('CPU state changed during capture')
            rows.append(row)
        if context('services',64)!=service or context('writer_debug',len(banks))!=banks:
            raise ValueError('stopped state changed during capture')
        result=dict(monitor_sha256=launch['monitor_sha256'],service=list(struct.unpack('<8Q',service)),
                    enabled=bool(enabled),cpus=rows,
                    boundary='Raw stopped diagnostic; individual lifecycle audit results do not qualify the complete guest run.')
        output=Path(f'{base}-native-writer-state.json')
        with output.open('x') as stream:json.dump(result,stream,indent=2);stream.write('\n')
        print(json.dumps(dict(output=str(output),cpus=[dict(slot=r['slot'],fields=r['fields'],error=r.get('audit_error')) for r in rows])))
    finally:proxy.link.close()
    return 0

if __name__=='__main__':raise SystemExit(main())

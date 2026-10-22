#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Read ALU batching counters from a byte-verified, audited stopped monitor."""
import argparse
import hashlib
import json
from pathlib import Path
import runpy
import struct
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'probes'))
import run


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--device',default='udp://en5')
    parser.add_argument('--prefix',required=True)
    args=parser.parse_args()
    raw=(ROOT/'build'/f'{args.prefix}-audit.json').read_bytes()
    audit=json.loads(raw)
    if not (audit['runtime_stop_qualified'] and audit['user_mapping_qualified']):
        raise SystemExit('Capture requires qualified stopped CPUs and mapping audit')
    blob=(ROOT/'build/xnuboot.bin').read_bytes()
    if hashlib.sha256(blob).hexdigest()!=audit['monitor_sha256']:
        raise SystemExit('Built monitor does not match stopped audit')
    launch=json.loads((ROOT/'build'/f'{args.prefix}-launch.json').read_text())
    for name,wanted in launch['source_sha256'].items():
        if hashlib.sha256((ROOT/name).read_bytes()).hexdigest()!=wanted:
            raise SystemExit(f'Layout source changed after launch: {name}')
    layout=runpy.run_path(str(ROOT/'tools/monitor_layout.py'))['MonitorLayout']()
    fields=('resume_pc','resume_generation','armed','prior_native','batches','instructions','max_batch')
    if layout.size('step_alu_state')!=8*len(fields):
        raise SystemExit('Unexpected batching state layout')
    p=run.connect(args.device,tries=1)
    try:
        info=p.bootinfo();work,_=run.resident_work(p,info)
        if p.readmem(info['heap_base']+run.CODE_AT,len(blob),live=True)!=blob:
            raise SystemExit('Resident monitor bytes differ')
        services=work+layout.offset('context','services')
        expected=struct.pack('<8Q',*audit['service'])
        if p.readmem(services,len(expected),live=True)!=expected:
            raise SystemExit('Resident stop ownership differs')
        address=work+layout.offset('context','step_alu')
        data=p.readmem(address,6*8*len(fields),live=True)
        if data!=p.readmem(address,len(data),live=True):
            raise SystemExit('Batch counters changed while reading')
        rows=[]
        for cpu in range(6):
            values=struct.unpack_from('<7Q',data,cpu*56)
            row=dict(cpu=cpu,**dict(zip(fields,values)))
            if row['max_batch']>16 or row['batches']>row['instructions']:
                raise SystemExit('Invalid batch accounting')
            rows.append(row)
        if p.readmem(services,len(expected),live=True)!=expected:
            raise SystemExit('Resident stop ownership changed')
        result=dict(monitor_sha256=audit['monitor_sha256'],audit_sha256=hashlib.sha256(raw).hexdigest(),
                    cpus=rows,total_instructions=sum(r['instructions'] for r in rows),
                    total_batches=sum(r['batches'] for r in rows),max_batch=max(r['max_batch'] for r in rows))
        out=ROOT/'build'/f'{args.prefix}-step-alu.json'
        if out.exists():raise SystemExit('Refusing to overwrite an existing capture')
        out.write_text(json.dumps(result,indent=2)+'\n')
        print(json.dumps({k:v for k,v in result.items() if k!='cpus'}))
    finally:p.link.close()


if __name__=='__main__':main()

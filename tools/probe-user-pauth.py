#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Inspect or exercise physical PA, preserving the stopped monitor image.

Requires the recorded clean six-CPU stop. Only the short probe code and its
512-byte buffer overlap monitor storage; both are backed up and restored with
readback before returning. The work area and guest RAM are untouched. Exercise
mode uses public synthetic keys; host keys never leave the native helper.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import struct
import subprocess
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'probes'))
import run

BUFFER_SIZE=0x200
FIELDS='current_el isar1 isar2 sctlr_el2 tcr_el2 hcr_el2 sctlr_el1 tcr_el1 mmfr0 isar0'.split()
SYNTHETIC_KEYS=((0x0123456789abcdef,0xfedcba9876543210),
                (0x13579bdf2468ace0,0x0eca8642fdb97531))

def validate_rows(rows):
    # Compare sets, not individual signatures: truncated PACs can collide.
    for key in range(4):
        for tbi in range(2):
            for tbid in range(2):
                selected=[r for r in rows if (r['key'],r['tbi'],r['tbid'])==(key,tbi,tbid)]
                if not selected or not any(r['signed_pointer']!=r['pointer'] for r in selected):
                    raise ValueError(f'signing absent or NOP: key={key}, tbi={tbi}, tbid={tbid}')
                for field in ('synthetic_key_index','modifier'):
                    groups={}
                    for row in selected:
                        other=tuple((k,row[k]) for k in ('pointer','modifier','synthetic_key_index')
                                    if k!=field)
                        groups.setdefault(other,set()).add(row['signed_pointer'])
                    if not any(len(values)>1 for values in groups.values()):
                        raise ValueError(f'no {field} dependence: key={key}, tbi={tbi}, tbid={tbid}')

def exercise(proxy,code,out,read):
    rows=[]
    for key in range(4):
        for tbi in range(2):
            for tbid in range(2):
                pointers=[0x1cf5382f0,(1<<47)-1]
                if tbi and (key>=2 or not tbid):pointers.append(0xab000001cf5382f0)
                for pointer in pointers:
                    for key_index,(lo,hi) in enumerate(SYNTHETIC_KEYS):
                        for modifier in (0x9abf0001cf5382a8,0x9abf0001cf5382a9):
                            request=struct.pack('<7Q',pointer,modifier,lo,hi,key,tbi,tbid)
                            proxy.writemem(out+0x100,request)
                            proxy.writemem(out+0x180,b'\xa5'*24)
                            status=proxy.call(code,out,1)
                            signed,authenticated,restored=struct.unpack('<3Q',read(out+0x180,24))
                            if status or authenticated!=pointer or restored!=15:
                                raise ValueError(f'PA round trip failed: key={key}, tbi={tbi}, '
                                                 f'tbid={tbid}, status={status}, restore={restored}, '
                                                 f'pointer={pointer:x}, authenticated={authenticated:x}')
                            if read(out+0x100,56)!=request:raise ValueError('PA request modified')
                            rows.append(dict(key=key,tbi=tbi,tbid=tbid,pointer=hex(pointer),
                                             modifier=hex(modifier),synthetic_key_index=key_index,
                                             signed_pointer=hex(signed),authenticated=hex(authenticated),
                                             restored=restored))
    validate_rows(rows)
    return dict(cases=len(rows),all_authenticated=True,all_restored=True,rows=rows,
                boundary='native synthetic-key primitive only; guest key policy and consumer PA not integrated')

def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--device',required=True);ap.add_argument('--prefix',required=True)
    ap.add_argument('--exercise',action='store_true',help='test address signing with synthetic keys')
    args=ap.parse_args()
    if not re.fullmatch(r'[a-z0-9-]+',args.prefix):raise ValueError('invalid prefix')
    audit=json.loads((ROOT/'build'/f'{args.prefix}-audit.json').read_text())
    if not audit['runtime_stop_qualified'] or audit['ownership']['mismatches']:
        raise ValueError('requires qualified stopped run')
    blob=(ROOT/'build/xnuboot.bin').read_bytes()
    if hashlib.sha256(blob).hexdigest()!=audit['monitor_sha256']:raise ValueError('monitor changed')
    probe=run.build('pauth-address',ROOT/'build/pauth-address-probe')
    if len(probe)>len(blob):raise ValueError('probe overlaps saved monitor extent')
    layout=subprocess.check_output(['clang','--target=aarch64-unknown-none-elf','-ffreestanding',
        '-mgeneral-regs-only','-Ishadow','-Icompat','-Xclang','-fdump-record-layouts',
        '-fsyntax-only','probes/xnuboot.c'],cwd=ROOT,text=True)
    block=next(b for b in layout.split('*** Dumping AST Record Layout') if re.search(r'^\s*0 \| struct context\n',b))
    offset=int(re.search(r'^\s*(\d+) \|   .+ services$',block,re.M)[1])
    proxy=run.connect(args.device,tries=1)
    try:
        def read(pa,n):return b''.join(proxy.readmem(pa+i,min(65536,n-i),live=True) for i in range(0,n,65536))
        info=proxy.bootinfo();code=info['heap_base']+run.CODE_AT;out=info['heap_base']+run.OUT_AT
        work, work_size = run.resident_work(proxy, info)
        if read(code,len(blob))!=blob:raise ValueError('resident monitor differs')
        service=list(struct.unpack('<8Q',read(work+offset,64)))
        if service!=audit['service'] or service[0] or not service[1]:raise ValueError('monitor not at saved stop')
        original=read(out,BUFFER_SIZE)
        trials=None
        try:
            proxy.writemem(code,probe);proxy.flush_code(code,len(probe))
            if proxy.call(code,out,0):raise ValueError('configuration probe failed')
            values=struct.unpack('<10Q',read(out,80))
            if args.exercise:
                trials=exercise(proxy,code,out,read)
                if proxy.call(code,out,0):raise ValueError('final configuration probe failed')
                if struct.unpack('<10Q',read(out,80))!=values:
                    raise ValueError('physical configuration changed after exercise')
        finally:
            proxy.writemem(code,blob[:len(probe)]);proxy.flush_code(code,len(probe))
            proxy.writemem(out,original)
            if read(code,len(blob))!=blob or read(out,BUFFER_SIZE)!=original:
                raise ValueError('stopped monitor restoration failed')
        report=dict(monitor_sha256=audit['monitor_sha256'],monitor_restored=True,
                    probe_sha256=hashlib.sha256(probe).hexdigest(),
                    registers={k:hex(v) for k,v in zip(FIELDS,values)})
        if trials:report['exercise']=trials
        suffix='pauth-native' if args.exercise else 'pauth-config'
        p=ROOT/'build'/f'{args.prefix}-{suffix}.json';p.write_text(json.dumps(report,indent=2)+'\n')
        summary=dict(report)
        if trials:summary['exercise']={k:v for k,v in trials.items() if k!='rows'}
        print(json.dumps(summary,indent=2))
    finally:proxy.link.close()

if __name__=='__main__':main()

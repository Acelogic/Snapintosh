#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Capture modeled guest PA operands from a qualified stopped monitor.

Register operands and switching counters only: no native key material is exported.
Switching counters alone do not prove successful authenticated pointer consumers.
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

def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--device',required=True);ap.add_argument('--prefix',required=True)
    args=ap.parse_args()
    if not re.fullmatch(r'[a-z0-9-]+',args.prefix):raise ValueError('invalid prefix')
    audit=json.loads((ROOT/'build'/f'{args.prefix}-audit.json').read_text())
    blob=(ROOT/'build/xnuboot.bin').read_bytes()
    if not audit['runtime_stop_qualified'] or audit['ownership']['mismatches']:
        raise ValueError('requires a qualified stop')
    if hashlib.sha256(blob).hexdigest()!=audit['monitor_sha256']:raise ValueError('monitor changed')
    layouts=subprocess.check_output(['clang','--target=aarch64-unknown-none-elf','-ffreestanding',
        '-mgeneral-regs-only','-Ishadow','-Icompat','-Xclang','-fdump-record-layouts',
        '-fsyntax-only','probes/xnuboot.c'],cwd=ROOT,text=True)
    def layout(name):
        block=next(b for b in layouts.split('*** Dumping AST Record Layout')
                   if re.search(r'^\s*0 \| struct '+name+r'\n',b))
        fields={m[1]:int(m[0]) for m in re.findall(r'^\s*(\d+) \|   [^\n]*? (\w+)$',block,re.M)}
        return fields,int(re.search(r'\[sizeof=(\d+)',block)[1])
    ctx,_=layout('context');vcpu,vsize=layout('vcpu');_,psize=layout('pauth_user_state')
    bank,bsize=layout('pauth_switch')
    if psize!=19*8:raise ValueError('PA state layout changed')
    proxy=run.connect(args.device,tries=1)
    try:
        def read(pa,n):return b''.join(proxy.readmem(pa+i,min(65536,n-i),live=True) for i in range(0,n,65536))
        info=proxy.bootinfo();code=info['heap_base']+run.CODE_AT
        work, work_size = run.resident_work(proxy, info)
        if read(code,len(blob))!=blob:raise ValueError('resident monitor differs')
        service=list(struct.unpack('<8Q',read(work+ctx['services'],64)))
        if service!=audit['service'] or service[0] or not service[1]:raise ValueError('not at saved stop')
        rows=[]
        for cpu in range(6):
            words=struct.unpack('<19Q',read(work+ctx['user_pauth']+cpu*psize,psize))
            base=work+ctx['vcpus']+cpu*vsize
            scalar=lambda f:struct.unpack('<Q',read(base+vcpu[f],8))[0]
            if (scalar('guest_apga_lo'),scalar('guest_apga_hi'))!=words[8:10]:
                raise ValueError('PACGA backend is not using tracked operands')
            if words[15]&~0x1fff:raise ValueError('unknown PA register marked written')
            names=('IA','IB','DA','DB','GA')
            row=dict(cpu=cpu,operators={n:[hex(words[i*2]),hex(words[i*2+1])]
                                       for i,n in enumerate(names)},
                     extra=[hex(words[10]),hex(words[11])],apctl=hex(words[12]),
                     reads=words[13],writes=words[14],written_mask=hex(words[15]),
                     extra_writes=words[16],last_reg=hex(words[17]),last_read=bool(words[18]),
                     guest_sctlr=hex(scalar('guest_sctlr')),guest_tcr=hex(scalar('guest_tcr')))
            bank_pa=work+ctx['pauth_bank']+cpu*bsize
            row['switching']={name:struct.unpack('<Q',read(bank_pa+bank[name],8))[0]
                              for name in ('enables','active','entries','exits','failures','restored')}
            switch=row['switching']
            if switch['active'] or switch['failures'] or switch['entries']!=switch['exits']:
                raise ValueError('guest bank not cleanly restored at stop')
            if switch['restored']!=(7 if switch['entries'] else 0):
                raise ValueError('restoration readback did not pass')
            # Read only the host-save area after proving it inactive; never emit its bytes.
            if read(bank_pa+bank['host'],80)!=bytes(80):
                raise ValueError('host-save area was not cleared')
            rows.append(row)
        report=dict(monitor_sha256=audit['monitor_sha256'],cpus=rows,
                    boundary='guest operands and native bank switching; consumer authentication requires separate witnesses')
        path=ROOT/'build'/f'{args.prefix}-pauth-state.json'
        path.write_text(json.dumps(report,indent=2)+'\n')
        print(json.dumps(dict(path=str(path),cpus=[{k:r[k] for k in
              ('cpu','extra','apctl','reads','writes','written_mask','extra_writes','switching')} for r in rows]),indent=2))
    finally:proxy.link.close()

if __name__=='__main__':main()

#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Inspect physical DC ZVA geometry while preserving a captured stopped monitor.

Only the probe code and 512-byte scratch/output region are touched, then restored
and checked byte for byte. Guest memory, page tables and register policy remain
unchanged. The zeroing exercise runs at EL2; it does not qualify EL0 permissions.
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

FIELDS='current_el dczid_el0 ctr_el0 hcr_el2 sctlr_el1 sctlr_el2'.split()


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--device',required=True)
    ap.add_argument('--prefix',required=True)
    args=ap.parse_args()
    if not re.fullmatch(r'[a-z0-9-]+',args.prefix):raise ValueError('invalid prefix')
    audit=json.loads((ROOT/'build'/f'{args.prefix}-audit.json').read_text())
    if not audit['runtime_stop_qualified'] or audit['ownership']['mismatches']:
        raise ValueError('requires qualified stopped run')
    blob=(ROOT/'build/xnuboot.bin').read_bytes()
    if hashlib.sha256(blob).hexdigest()!=audit['monitor_sha256']:
        raise ValueError('monitor changed')
    probe=run.build('cache-geometry',ROOT/'build/cache-geometry-probe')
    if not probe or len(probe)>len(blob):raise ValueError('invalid probe size')
    layout=subprocess.check_output(['clang','--target=aarch64-unknown-none-elf',
        '-ffreestanding','-mgeneral-regs-only','-Ishadow','-Icompat','-Xclang',
        '-fdump-record-layouts','-fsyntax-only','probes/xnuboot.c'],cwd=ROOT,text=True)
    block=next(b for b in layout.split('*** Dumping AST Record Layout')
               if re.search(r'^\s*0 \| struct context\n',b))
    offset=int(re.search(r'^\s*(\d+) \|   \S.* services$',block,re.M)[1])
    proxy=run.connect(args.device,tries=1)
    proxy.resume_skip=False
    try:
        def read(pa,n):
            return b''.join(proxy.readmem(pa+i,min(65536,n-i),live=True)
                            for i in range(0,n,65536))
        info=proxy.bootinfo()
        code=info['heap_base']+run.CODE_AT
        out=info['heap_base']+run.OUT_AT
        work, work_size = run.resident_work(proxy, info)
        if out&63:raise ValueError('unaligned scratch')
        if read(code,len(blob))!=blob:raise ValueError('resident monitor differs')
        service=list(struct.unpack('<8Q',read(work+offset,64)))
        if service!=audit['service'] or service[0] or not service[1]:
            raise ValueError('monitor not at captured stop')
        original=read(out,512)
        (ROOT/'build'/f'{args.prefix}-cache-geometry-output-before.bin').write_bytes(original)
        try:
            proxy.writemem(out,bytes([0xa5])*512)
            proxy.writemem(code,probe)
            proxy.flush_code(code,len(probe))
            result=proxy.call(code,out,0)
            observed=read(out,512)
        finally:
            proxy.writemem(code,blob[:len(probe)])
            proxy.flush_code(code,len(probe))
            proxy.writemem(out,original)
            if read(code,len(blob))!=blob or read(out,512)!=original:
                raise ValueError('stopped monitor restoration failed')
        if read(work+offset,64)!=struct.pack('<8Q',*service):
            raise ValueError('service state changed')
        registers=dict(zip(FIELDS,struct.unpack('<6Q',observed[:48])))
        if result or registers['current_el']!=8 or registers['dczid_el0']!=4:
            raise ValueError(f'unsupported geometry: {registers}, result={result}')
        expected=observed[:48]+bytes([0xa5])*(256-48)+bytes(64)+bytes([0xa5])*(512-320)
        if observed!=expected:raise ValueError('zeroing footprint mismatch')
        report=dict(monitor_sha256=audit['monitor_sha256'],monitor_restored=True,
                    service_state_unchanged=True,probe_sha256=hashlib.sha256(probe).hexdigest(),
                    registers={k:hex(v) for k,v in registers.items()},zero_block_bytes=64,
                    footprint_verified=True,exercise_el=2,el0_execution_qualified=False)
        path=ROOT/'build'/f'{args.prefix}-cache-geometry.json'
        path.write_text(json.dumps(report,indent=2)+'\n')
        print(json.dumps(report,indent=2))
    finally:proxy.link.close()


if __name__=='__main__':main()

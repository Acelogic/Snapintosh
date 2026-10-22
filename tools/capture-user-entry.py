#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Read-only source/shadow proof for the stopped first EL0 return."""
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
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--device',required=True);ap.add_argument('--prefix',required=True)
    args=ap.parse_args()
    if not args.prefix or any(c not in 'abcdefghijklmnopqrstuvwxyz0123456789-' for c in args.prefix):
        raise ValueError('invalid artifact prefix')
    base=ROOT/'build'/args.prefix
    audit=json.loads(Path(f'{base}-audit.json').read_text())
    stop=json.loads(Path(f'{base}-cpu3-stop.json').read_text())
    runtime=json.loads(Path(f'{base}-result.json').read_text())
    if (stop['cpu'],stop['pc'],stop['esr'])!=(3,'0xfffffe000b870048','0x6a000000'):
        raise ValueError('not the reached first-user-return stop')
    target=int(stop['far'],16);sp=int(stop['sp'],16)
    if not 0<target<1<<47 or target&3 or not 0<sp<1<<47:raise ValueError('invalid user entry geometry')
    root=next(row for row in audit['root_switch']['roots'] if 3 in row['active_cpus'])
    g=audit['geometry'];proxy=run.connect(args.device,tries=1)
    try:
        def read(pa,size):
            if not size or size>0x40000:raise ValueError('unbounded capture read')
            return b''.join(proxy.readmem(pa+i,min(65536,size-i),live=True) for i in range(0,size,65536))
        info=proxy.bootinfo();work, work_size = run.resident_work(proxy, info)
        blob=(ROOT/'build/xnuboot.bin').read_bytes()
        if hashlib.sha256(blob).hexdigest()!=audit['monitor_sha256'] or read(info['heap_base']+run.CODE_AT,len(blob))!=blob:
            raise ValueError('resident monitor differs')
        layout=runpy.run_path(str(ROOT/'tools/secondary-runtime.py'))
        service=struct.unpack('<8Q',read(work+layout['SERVICES_OFFSET'],64))
        if list(service)!=audit['service'] or service[1]!=0x100000004:raise ValueError('stop owner changed')
        cpu=work+layout['VCPUS_OFFSET']+3*layout['VCPU_SIZE']
        output=struct.unpack('<Q',read(cpu+8,8))[0]
        if output&4095 or not work<=output<=work + work_size-4096:raise ValueError('invalid CPU output')
        words=next(row['output_words'] for row in runtime['cpus'] if row['slot']==3)
        if read(output,352)!=struct.pack('<44Q',*words):raise ValueError('stopped registers changed')
        def walk(va,shift,table):
            lo,hi=(g['ram_low'],g['ram_high']) if shift==14 else (work,work + work_size)
            size=1<<shift;path=[]
            for level in range(1 if shift==14 else 0,4):
                if table&(size-1) or not lo<=table<=hi-size or table in path:
                    raise ValueError('invalid entry table')
                path.append(table);slot=(va>>(shift+(3-level)*(shift-3)))&((size//8)-1)
                d=struct.unpack_from('<Q',read(table,size),slot*8)[0]
                if d&3!=3:raise ValueError('entry is not a page mapping')
                table=d&((1<<48)-size)
            return table+(va&(size-1)),d
        mappings={}
        for name,va in [('entry',target),('stack',sp)]:
            pa,d=walk(va,14,int(root['root'],16));host,h=walk(va,12,int(root['shadow'],16))
            if pa!=host or (d&(0xfff|(3<<53)))!=(h&(0xfff|(3<<53))):
                raise ValueError('user source and hardware mappings differ')
            selector=((d>>4)&12)|((d>>53)&3)
            if selector!=(13 if name=='entry' else 7):raise ValueError('unexpected entry or stack rights')
            meta_pa=g['frame_map']+(((pa&~16383)-g['frame_low'])>>14)*16
            meta=read(meta_pa,16)
            if meta[2]!=(14 if name=='entry' else 11):raise ValueError('entry or stack type mismatch')
            payload=read(pa&~16383,16384)
            mappings[name]=dict(va=hex(va),pa=hex(pa),source_pte=hex(d),shadow_pte=hex(h),
                selector=selector,metadata_hex=meta.hex(),frame_sha256=hashlib.sha256(payload).hexdigest(),
                bytes_at_address=payload[pa&16383:(pa&16383)+64].hex())
        result=dict(monitor_sha256=audit['monitor_sha256'],stop_pc=stop['pc'],
            target=hex(target),stack=hex(sp),root=root,mappings=mappings,
            el0_execution_proven=False)
    finally:proxy.link.close()
    out=Path(f'{base}-user-entry.json');out.write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(result));print(out)
if __name__=='__main__':main()

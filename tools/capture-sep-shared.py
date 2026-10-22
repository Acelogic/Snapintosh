#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Read an audited, stopped SEP shared buffer through freshly walked DART tables."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import runpy
import struct
import subprocess
import sys
ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT/'probes'), str(ROOT/'tools')]
import run
import xnuboot as xb
from audit_sep_rom import audit_buffers


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--device',required=True); ap.add_argument('--prefix',required=True)
    args=ap.parse_args()
    if not re.fullmatch(r'[a-z0-9-]+',args.prefix):raise ValueError('invalid prefix')
    base=ROOT/'build'/args.prefix
    audit=json.loads(Path(f'{base}-audit.json').read_text())
    if not audit['runtime_stop_qualified']:raise ValueError('unqualified resident stop')
    xb.configure_guest(audit['guest_profile'])
    asc=next(s for s in audit['sep_asc'] if s['rom_stage']==3)
    layout=subprocess.run(['clang','--target=aarch64-unknown-none-elf','-ffreestanding',
        '-mgeneral-regs-only','-Ishadow','-Icompat','-Xclang','-fdump-record-layouts',
        '-fsyntax-only','probes/xnuboot.c'],cwd=ROOT,capture_output=True,text=True,check=True).stdout
    def offset(kind,field):
        block=next(b for b in layout.split('*** Dumping AST Record Layout')
                   if re.search(r'^\s*0 \| struct '+kind+r'\n',b))
        return int(re.findall(r'^\s*(\d+) \|   .+ '+field+r'$',block,re.M)[0])
    secondary=runpy.run_path(str(ROOT/'tools/secondary-runtime.py'))
    dart=runpy.run_path(str(ROOT/'tools/audit-dart-tables.py'))
    proxy=run.connect(args.device,tries=1)
    try:
        def read(pa,n):
            if not 0<n<=0x4000000:raise ValueError('invalid read size')
            return b''.join(proxy.readmem(pa+i,min(65536,n-i),live=True) for i in range(0,n,65536))
        info=proxy.bootinfo(); work, work_size = run.resident_work(proxy, info)
        blob=(ROOT/'build/xnuboot.bin').read_bytes()
        assert hashlib.sha256(blob).hexdigest()==audit['monitor_sha256']
        assert read(info['heap_base']+run.CODE_AT,len(blob))==blob
        def stable():
            assert struct.unpack('<8Q',read(work+secondary['SERVICES_OFFSET'],64))==tuple(audit['service'])
            address=work+offset('context','model_state')+asc['index']*13000
            for key in ('rom_stage','rom_firmware_iova','rom_firmware_size','rom_shared_iova','rom_shared_size'):
                assert struct.unpack('<Q',read(address+offset('device_sep_asc',key),8))[0]==asc[key]
        stable()
        param_pa,=struct.unpack('<Q',read(work,8))
        params=struct.unpack(f'<{xb.PARAMS_WORDS}Q',read(param_pa,xb.PARAMS_WORDS*8))
        geometry=audit['geometry']
        assert [params[i] for i in (0,43,44,45,46,47)]==[geometry[k] for k in
            ('root','frame_map','frame_low','frame_high','alloc_low','alloc_high')]
        roots=[]
        for model in audit['dart_runtime']:
            if model['policy'] not in (300,556):continue
            address=work+offset('context','model_state')+model['index']*13000
            initialized,powered=struct.unpack('<2I',read(address,8))
            if not initialized and not powered:continue
            assert initialized==powered and initialized.bit_count()==1
            device=initialized.bit_length()-1
            tcr=struct.unpack('<256I',read(address+offset('dart_state','tcr'),1024))
            ttbr=struct.unpack('<256I',read(address+offset('dart_state','ttbr'),1024))
            roots.extend((device,sid,t,tcr[sid]) for sid,t in enumerate(ttbr) if t)
        walked=dart['audit'](read,roots=roots,**{k:geometry[k] for k in
            ('frame_map','frame_low','frame_high','alloc_low','alloc_high','boot_ranges','boot_aliases','sep_firmware')})
        assert not walked['mismatches'],walked['mismatches']
        buffers=audit_buffers(asc,walked['leaves'],geometry)
        leaves={int(l['iova'],0):l for l in walked['leaves'] if l['device_id']==20 and l['sid']==0}
        payload=b''.join(read(int(leaves[asc['rom_shared_iova']+off]['pa'],0),0x4000)
                         for off in range(0,asc['rom_shared_size'],0x4000))
        stable()
    finally:
        proxy.link.close()
    directory=[]
    for off in range(0,0x4000,16):
        name,size,start,reserved=struct.unpack_from('<4sIII',payload,off)
        if name==b'llun':
            directory.append(dict(name='null',directory_offset=off));break
        if not any(payload[off:off+16]):break
        entry=dict(name_bytes=name.hex(),directory_offset=off,size=size,offset=start,reserved=reserved)
        if all(32<=c<127 for c in name):entry['name']=name[::-1].decode('ascii')
        if 0<start<=len(payload)-size and size>=4:
            entry.update(first_word=struct.unpack_from('<I',payload,start)[0],
                         sha256=hashlib.sha256(payload[start:start+size]).hexdigest())
        directory.append(entry)
    Path(f'{base}-sep-shared.bin').write_bytes(payload)
    report=dict(monitor_sha256=audit['monitor_sha256'],iova=hex(asc['rom_shared_iova']),
                bytes=len(payload),sha256=hashlib.sha256(payload).hexdigest(),
                buffers=buffers,directory=directory,
                boundary='read-only resident capture; directory interpretation pending native layout verification')
    Path(f'{base}-sep-shared.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(report))


if __name__=='__main__':main()

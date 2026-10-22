#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Read the stopped USER_EXEC request's frame, bound to its audited monitor."""
import argparse
import hashlib
import json
import runpy
from pathlib import Path
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
    registers={int(k):int(v,16) for k,v in stop['registers'].items()}
    if (stop['cpu'],stop['pc'],registers[1],registers[2],registers[3])!=(
            3,'0xfffffe000c22b3c8',11,14,0):raise ValueError('not the reached USER_EXEC request')
    pa=registers[0];g=audit['geometry']
    if pa&16383 or not g['alloc_low']<=pa<g['alloc_high']:raise ValueError('frame outside allocation')
    proxy=run.connect(args.device,tries=1)
    try:
        info=proxy.bootinfo();blob=(ROOT/'build/xnuboot.bin').read_bytes()
        def read(pa,size):
            return b''.join(proxy.readmem(pa+i,min(65536,size-i),live=True)
                            for i in range(0,size,65536))
        if hashlib.sha256(blob).hexdigest()!=audit['monitor_sha256'] or read(info['heap_base']+run.CODE_AT,len(blob))!=blob:
            raise ValueError('resident monitor differs')
        layout=runpy.run_path(str(ROOT/'tools/secondary-runtime.py'))
        work, work_size = run.resident_work(proxy, info)
        service=struct.unpack('<8Q',read(work+layout['SERVICES_OFFSET'],64))
        if list(service)!=audit['service'] or service[1]!=0x100000004:
            raise ValueError('CPU3 no longer owns the audited stop')
        cpu=work+layout['VCPUS_OFFSET']+3*layout['VCPU_SIZE']
        output=struct.unpack('<Q',read(cpu+8,8))[0]
        if output&4095 or not work<=output<=work + work_size-4096:
            raise ValueError('CPU3 output outside work area')
        words=next(row['output_words'] for row in runtime['cpus'] if row['slot']==3)
        if read(output,352)!=struct.pack('<44Q',*words):
            raise ValueError('CPU3 stopped register snapshot changed')
        metadata_pa=g['frame_map']+((pa-g['frame_low'])>>14)*16
        metadata=read(metadata_pa,16);payload=read(pa,16384)
        if metadata[2]!=11:raise ValueError('frame changed since refused request')
        result=dict(cpu=3,pc=stop['pc'],pa=hex(pa),old_type=11,new_type=14,options=0,
                    monitor_sha256=audit['monitor_sha256'],metadata_pa=hex(metadata_pa),
                    metadata_hex=metadata.hex(),ro_refs=struct.unpack_from('<I',metadata,8)[0],
                    other_refs=struct.unpack_from('<I',metadata,12)[0],
                    payload_sha256=hashlib.sha256(payload).hexdigest(),prefix_hex=payload[:64].hex(),
                    intended_user_va=hex(registers[24]),candidate_pte=hex(registers[21]))
    finally:proxy.link.close()
    out=Path(f'{base}-exec-frame.json');out.write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(result));print(out)
if __name__=='__main__':main()

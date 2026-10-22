#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Match captured user instruction bytes to shared-cache mappings, without guessing ASLR.

This resolves lookup candidates, not authenticated return addresses. It neither
reads nor changes the live target. Unmatched sites may belong to the executable,
optimized frames, or a different image; they remain unresolved.
"""
import argparse
import json
import mmap
from pathlib import Path
import struct


def sites(snapshot):
    out=[]
    for row in snapshot.get('user_frame_candidates',{}).get('frames',[]):
        if 'return_site_hex' in row:
            out.append(dict(live_va=int(row['return_site_va'],16),
                            lookup_pc=int(row['lookup_pc'],16),
                            code=bytes.fromhex(row['return_site_hex'])))
    pc=int(snapshot['pc'],16)
    if 0<pc<1<<47 and 'instruction' in snapshot:
        out.append(dict(live_va=pc,lookup_pc=pc,
                        code=bytes.fromhex(snapshot['instruction']['data_hex'])))
    return out


def resolve(items,cache):
    rows=[dict(live_va=hex(x['live_va']),lookup_pc=hex(x['lookup_pc']),
               instruction_hex=x['code'].hex(),matches=[]) for x in items]
    for path in sorted(cache.parent.glob(cache.name+'*')):
        if not path.is_file() or not path.stat().st_size:continue
        with path.open('rb') as source,mmap.mmap(source.fileno(),0,access=mmap.ACCESS_READ) as data:
            if data[:7]!=b'dyld_v1':continue
            start,count=struct.unpack_from('<II',data,16)
            if not 0<count<=256 or start+count*32>len(data):
                raise ValueError(f'invalid mapping table: {path}')
            mappings=[struct.unpack_from('<QQQII',data,start+i*32) for i in range(count)]
            for item,row in zip(items,rows):
                pattern=item['code']
                if len(pattern)<16 or not any(pattern):continue
                offset=data.find(pattern);hits=0
                while offset>=0:
                    hits+=1
                    if hits>4096:raise ValueError('instruction pattern is too ambiguous')
                    for va,size,fileoff,_,_ in mappings:
                        if fileoff<=offset and offset+len(pattern)<=fileoff+size:
                            unslid=va+offset-fileoff
                            slide=item['live_va']-unslid
                            if 0<=slide<1<<32 and not slide&0x3fff:
                                row['matches'].append(dict(cache_file=path.name,file_offset=hex(offset),
                                    unslid_site=hex(unslid),slide=hex(slide),
                                    unslid_lookup_pc=hex(item['lookup_pc']-slide)))
                    offset=data.find(pattern,offset+1)
    candidates=[set(m['slide'] for m in row['matches']) for row in rows if row['matches']]
    common=set.intersection(*candidates) if candidates else set()
    return dict(sites=rows,matching_sites=len(candidates),
                common_slide=next(iter(common)) if len(common)==1 else None,
                boundary='Exact captured instruction matches with 16 KiB slide alignment; frame addresses are not authenticated')


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('snapshot',type=Path)
    ap.add_argument('--cache',type=Path,required=True)
    ap.add_argument('--output',type=Path)
    args=ap.parse_args()
    result=resolve(sites(json.loads(args.snapshot.read_text())),args.cache)
    payload=json.dumps(result,indent=2)+'\n'
    if args.output:args.output.write_text(payload)
    print(payload,end='')


if __name__=='__main__':main()

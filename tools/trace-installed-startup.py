#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Resolve stopped loader/display frames against exact shared-cache code.

Read-only/offline. The cache slide comes from a unique captured 64-byte
kernelmanagerd return-site witness. Every other supplied code fragment must
match before its symbols are attributed. Executable frames remain unresolved;
PAC-stripped frame candidates are not authenticated backtraces.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import runpy

ROOT=Path(__file__).resolve().parents[1]

def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--prefix',required=True)
    ap.add_argument('--cache',type=Path,required=True)
    ap.add_argument('--output',type=Path,required=True)
    args=ap.parse_args()
    assert re.fullmatch('[a-z0-9-]+',args.prefix) and not args.output.exists()
    base=ROOT/'build'/args.prefix
    raw=Path(str(base)+'-kernel-waits.json').read_bytes();capture=json.loads(raw)
    audit_raw=Path(str(base)+'-audit.json').read_bytes();audit=json.loads(audit_raw)
    assert audit['runtime_stop_qualified'] and audit['user_mapping_qualified']
    assert capture['monitor_sha256']==audit['monitor_sha256']
    processes=capture['user_processes']['processes']
    loader=next(p for p in processes if p['name']=='kernelmanagerd')
    frame=loader['threads'][0]['user_frame_chain']['frames'][0]
    code=bytes.fromhex(frame['return_site_hex']);assert len(code)==64
    Cache=runpy.run_path(str(ROOT/'tools/dyld-cache.py'))['Cache']
    rows=[]
    with Cache(args.cache) as cache:
        witness=cache.match_code(int(frame['return_site_va'],16),code)
        slide=witness['slide'];assert 0<=slide<1<<32 and not slide&0x3fff
        symbol_cache={}
        for process in processes:
            if process['name'] not in ('kernelmanagerd','WindowServer','corerepaird'):continue
            for thread in process['threads']:
                state=thread.get('saved_user_state') or {}
                sites=[('pc',state.get('pc','0x0'),state.get('instruction_hex')),
                       ('lr',state.get('lr','0x0'),None)]
                sites += [('return-site',f['return_site_va'],f['return_site_hex'])
                          for f in (thread.get('user_frame_chain') or {}).get('frames',[])
                          if 'return_site_hex' in f]
                resolved=[]
                for kind,address,fragment in sites:
                    va=int(address,16)-slide;owners=cache.owner(va)
                    row=dict(kind=kind,runtime_va=address)
                    if len(owners)!=1:
                        row['resolution']='outside a unique cache image';resolved.append(row);continue
                    if fragment:
                        expected=bytes.fromhex(fragment)
                        assert cache.read(va,len(expected))==expected,(process['name'],address)
                        row['matched_bytes']=len(expected)
                    image=owners[0][0]
                    if image not in symbol_cache:symbol_cache[image]=cache.symbols(image)
                    preceding=[s for s in symbol_cache[image] if s[3] and s[0]<=va]
                    nearest=max(preceding,default=None)
                    row.update(unslid_va=hex(va),image=image,
                               uuid=cache.image(image).get('uuid'),
                               nearest_symbol=nearest[1] if nearest else None,
                               offset=hex(va-nearest[0]) if nearest else None)
                    resolved.append(row)
                rows.append(dict(pid=process['pid'],name=process['name'],tid=thread['tid'],
                    scheduler=thread.get('scheduler_state'),on_cpu=thread['on_cpu'],
                    wait_event=thread['wait_event'],sites=resolved))
    sha=lambda value:hashlib.sha256(value).hexdigest()
    result=dict(prefix=args.prefix,monitor_sha256=audit['monitor_sha256'],
        capture_sha256=sha(raw),audit_sha256=sha(audit_raw),cache=str(args.cache),
        slide=hex(slide),witness=witness,threads=rows,boundary=__doc__)
    args.output.write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(dict(output=str(args.output),slide=hex(slide),threads=len(rows))))

if __name__=='__main__':main()

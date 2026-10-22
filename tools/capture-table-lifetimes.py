#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Read bound monitor history when a lifecycle auditor needs investigation."""
import argparse,hashlib,json,re,struct,subprocess,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'probes'),str(ROOT/'tools')]
import run
import xnuboot as xb
def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--device',required=True)
    ap.add_argument('--prefix',required=True);args=ap.parse_args()
    if not re.fullmatch(r'[a-z0-9-]+',args.prefix):raise ValueError('invalid prefix')
    layout=subprocess.check_output(['clang','--target=aarch64-unknown-none-elf','-ffreestanding',
        '-mgeneral-regs-only','-Ishadow','-Icompat','-Xclang','-fdump-record-layouts',
        '-fsyntax-only','probes/xnuboot.c'],cwd=ROOT,text=True)
    block=next(b for b in layout.split('*** Dumping AST Record Layout') if re.search(r'^\s*0 \| struct context\n',b))
    def offset(field):return int(re.search(r'^\s*(\d+) \|   .+ '+field+r'$',block,re.M)[1])
    proxy=run.connect(args.device,tries=1)
    try:
        def read(pa,n):return b''.join(proxy.readmem(pa+i,min(65536,n-i),live=True) for i in range(0,n,65536))
        info=proxy.bootinfo();work, work_size = run.resident_work(proxy, info)
        blob=(ROOT/'build/xnuboot.bin').read_bytes();assert read(info['heap_base']+run.CODE_AT,len(blob))==blob
        params=struct.unpack('<Q',read(work,8))[0]
        words=struct.unpack(f'<{xb.PARAMS_WORDS}Q',read(params,xb.PARAMS_WORDS*8))
        def meta(pa):return read(words[43]+((pa-words[44])>>14)*16,16).hex()
        nest=struct.unpack('<8Q',read(work+offset('nest_state'),64))
        unnest=struct.unpack('<46Q',read(work+offset('unnest_calls'),368))
        detach=read(work+offset('shared_detaches'),8+4096*64);calls=struct.unpack_from('<Q',detach)[0]
        record=struct.unpack_from('<8Q',detach,8+((calls-1)%4096)*64) if calls else ()
        roots={hex(pa):meta(pa) for pa in (nest[2],nest[3],unnest[3],unnest[4]) if pa}
        out=dict(monitor_sha256=hashlib.sha256(blob).hexdigest(),root_metadata=roots,
            nesting=[hex(x) for x in nest],unnesting=[hex(x) for x in unnest[:14]],
            detach_calls=calls,last_detach=[hex(x) for x in record])
        if unnest[0]:
            shift=12 if unnest[8] else 14;mask=(1<<48)-(1<<shift)
            def l2(root,va):
                table=root
                for level in range(0 if shift==12 else 1,3):
                    at=table+8*((va>>(shift+(3-level)*(shift-3)))&((1<<(shift-3))-1))
                    pte=struct.unpack('<Q',read(at,8))[0]
                    if level==2 or pte&3!=3:return at,pte
                    table=pte&mask
            edges=[]
            for i in range(unnest[11]):
                if not (unnest[14+i//64]>>(i%64)&1):continue
                va=unnest[9]+i*unnest[10];edge=dict(va=hex(va))
                for name,root in [('consumer',unnest[3]),('shared',unnest[4])]:
                    at,pte=l2(root,va);edge[name]=dict(slot=hex(at),descriptor=hex(pte),
                        child_metadata=meta(pte&~0x3fff) if pte&3==3 else None)
                edges.append(edge)
            out['last_unnest_current_edges']=edges
        fields='calls entries changed options result target count root va slot old next shift flags last_changed requested'.split()
        raw=read(work+offset('shared_regions_updates'),1536)
        out['shared_region_witnesses']=[dict(cpu=i//2,kind='changed' if i%2 else 'latest',
            **{k:hex(v) for k,v in zip(fields,values)})
            for i,values in enumerate(struct.iter_unpack('<16Q',raw)) if values[0]]
        if record:
            out['last_detach_readback']=dict(root_metadata=meta(record[0]),child_metadata=meta(record[3]),
                parent_metadata=meta(record[2]&~0x3fff),slot=read(record[2],8).hex(),
                child_nonzero_bytes=sum(bool(x) for x in read(record[3],0x4000)))
        path=ROOT/'build'/f'{args.prefix}-lifetimes.json';path.write_text(json.dumps(out,indent=2)+'\n')
        print(path);print(json.dumps(out))
    finally:
        proxy.link.close()
if __name__=='__main__':main()

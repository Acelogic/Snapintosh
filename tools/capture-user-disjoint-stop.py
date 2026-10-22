#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Read a qualified stopped UPDATE_DISJOINT list and its source PTE walks."""
from pathlib import Path
import argparse,hashlib,json,re,struct,subprocess,sys
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'probes'))
import run

def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--device',required=True);ap.add_argument('--prefix',required=True)
    args=ap.parse_args()
    if not re.fullmatch(r'[a-z0-9-]+',args.prefix):raise ValueError('invalid prefix')
    prefix=ROOT/'build'/args.prefix
    audit=json.loads(Path(f'{prefix}-audit.json').read_text())
    service=audit['service'];cpu=(service[1]&0xffffffff)-1
    if not audit['runtime_stop_qualified'] or audit['ownership']['mismatches'] or service[1]>>32!=1:
        raise ValueError('requires a qualified normal stop')
    if not 0<=cpu<6:raise ValueError('invalid owner')
    stop=json.loads(Path(f'{prefix}-cpu{cpu}-stop.json').read_text())
    regs=[int(stop['registers'][str(i)],16) for i in range(31)]
    if regs[16]!=6 or int(stop['pc'],16)!=0xfffffe000c22b4f4 or stop['snapshot_kind']!=2:
        raise ValueError('requires UPDATE_DISJOINT terminal snapshot')
    blob=(ROOT/'build/xnuboot.bin').read_bytes()
    if hashlib.sha256(blob).hexdigest()!=audit['monitor_sha256']:raise ValueError('build changed')
    layouts=subprocess.check_output(['clang','--target=aarch64-unknown-none-elf','-ffreestanding',
        '-mgeneral-regs-only','-Ishadow','-Icompat','-Xclang','-fdump-record-layouts',
        '-fsyntax-only','probes/xnuboot.c'],cwd=ROOT,text=True)
    def layout(name):
        block=next(b for b in layouts.split('*** Dumping AST Record Layout')
                   if re.search(r'^\s*0 \| struct '+name+r'\n',b))
        return {m[1]:int(m[0]) for m in re.findall(r'^\s*(\d+) \|   [^\n]*? (\w+)$',block,re.M)},int(re.search(r'\[sizeof=(\d+)',block)[1])
    ctx,_=layout('context');vcpu,stride=layout('vcpu');g=audit['geometry']
    proxy=run.connect(args.device,tries=1)
    try:
        def read(pa,n):
            if not 0<n<=0x40000:raise ValueError('read size')
            return b''.join(proxy.readmem(pa+i,min(65536,n-i),live=True) for i in range(0,n,65536))
        def ram(pa,n):
            if not g['ram_low']<=pa<pa+n<=g['ram_high']:raise ValueError('outside guest RAM')
            return read(pa,n)
        def metadata(pa):
            if pa&0x3fff or not g['frame_low']<=pa<g['frame_high']:raise ValueError('invalid frame')
            return ram(g['frame_map']+((pa-g['frame_low'])>>14)*16,16)
        info=proxy.bootinfo();work, work_size = run.resident_work(proxy, info)
        if read(info['heap_base']+run.CODE_AT,len(blob))!=blob:raise ValueError('resident differs')
        if list(struct.unpack('<8Q',read(work+ctx['services'],64)))!=service:raise ValueError('stop changed')
        live=struct.unpack('<36Q',read(work+ctx['vcpus']+cpu*stride+vcpu['async_regs'],288))
        if list(live[:31])!=regs or live[33]!=int(stop['pc'],16):raise ValueError('registers changed')
        target,source,count,options=regs[:4]
        if not 0<count<=64 or source&7:raise ValueError('invalid request list')
        raw=ram(source,count*24);rows=[]
        for root,va,requested in struct.iter_unpack('<3Q',raw):
            if root not in g['user_roots']+[g['root']]:raise ValueError('unknown root')
            meta=metadata(root);fmt=meta[12] if root!=g['root'] else 0
            if fmt not in (0,1):raise ValueError('unknown format')
            shift=12 if fmt else 14;table=root;walk=[]
            for level in range(0 if fmt else 1,4):
                slot=table+((va>>(shift+(3-level)*(shift-3)))&((1<<(shift-3))-1))*8
                pte=struct.unpack('<Q',ram(slot,8))[0]
                walk.append(dict(level=level,slot=hex(slot),pte=hex(pte),metadata=metadata(table&~0x3fff).hex()))
                if not pte&1 or level==3 or pte&3!=3:break
                table=pte&((1<<48)-(1<<shift))
            rows.append(dict(root=hex(root),kernel=root==g['root'],va=hex(va),requested=hex(requested),
                             root_metadata=meta.hex(),walk=walk))
        if proxy.exceptions:raise ValueError('proxy read exception')
        result=dict(monitor_sha256=audit['monitor_sha256'],cpu=cpu,target=hex(target),
                    target_metadata=metadata(target).hex(),source=hex(source),count=count,
                    options=hex(options),records=rows)
        path=Path(f'{prefix}-disjoint.json');path.write_text(json.dumps(result,indent=2)+'\n')
        print(json.dumps(result))
    finally:proxy.link.close()

if __name__=='__main__':main()

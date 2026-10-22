#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Read a stopped, audited guest's native I2C2 object from mapped RAM only."""
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
import xnuboot as xb

def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--device',required=True)
    ap.add_argument('--prefix',required=True)
    args=ap.parse_args()
    if not re.fullmatch(r'[a-z0-9-]+',args.prefix):raise ValueError('invalid prefix')
    base=ROOT/'build'/args.prefix
    audit=json.loads(Path(f'{base}-audit.json').read_text())
    kernel=ROOT/'downloads/extracted/j700ap/kernelcache.release.mac17p'
    if hashlib.sha256(kernel.read_bytes()).hexdigest()!=('dc9019ae39187b36936c2c513b485e513f15cd966b5c887ac88ffd2925976c62'):
        raise ValueError('native object layout is bound to J700 26A428')
    names=subprocess.run(['nm','-n',str(kernel)],capture_output=True,text=True,check=True).stdout
    symbols=[int(s.split()[0],16)+16 for s in names.splitlines()
             if '__ZTV' in s and s.endswith('AppleS5L8940XI2CController')]
    if len(symbols)!=1:raise ValueError('ambiguous I2C controller vtable')
    expected=symbols[0]
    proxy=run.connect(args.device,tries=1)
    try:
        def read(pa,n):
            if not 0<n<=0x200000:raise ValueError('invalid read size')
            return b''.join(proxy.readmem(pa+i,min(65536,n-i),live=True) for i in range(0,n,65536))
        info=proxy.bootinfo();work, work_size = run.resident_work(proxy, info)
        blob=(ROOT/'build/xnuboot.bin').read_bytes()
        if (hashlib.sha256(blob).hexdigest()!=audit['monitor_sha256'] or
            read(info['heap_base']+run.CODE_AT,len(blob))!=blob):
            raise ValueError('resident monitor differs from audit')
        param_pa,=struct.unpack('<Q',read(work,8))
        params=struct.unpack(f'<{xb.PARAMS_WORDS}Q',read(param_pa,xb.PARAMS_WORDS*8))
        g=audit['geometry']
        if (params[0],params[30],params[31])!=(g['root'],g['ram_low'],g['ram_high']):
            raise ValueError('resident guest geometry differs from audit')
        def ram(pa,n):
            if not g['ram_low']<=pa<pa+n<=g['ram_high']:raise ValueError('not guest RAM')
            return read(pa,n)
        def translate(va):
            table=params[0]
            for shift in (36,25,14):
                desc,=struct.unpack('<Q',ram(table+8*((va>>shift)&2047),8))
                if desc&3!=3:return None
                table=desc&0x0000ffffffffc000
            return table+(va&0x3fff)
        aperture=params[48]&((1<<47)-1)
        aperture_end=aperture+params[47]-params[30]
        seen=set();pages={}
        def walk(pa,shift,prefix):
            if pa in seen or len(seen)>=2048:raise ValueError('unexpected table graph')
            seen.add(pa)
            for i,(desc,) in enumerate(struct.iter_unpack('<Q',ram(pa,0x4000))):
                if desc&3!=3:continue
                va=prefix+(i<<shift)
                if aperture<=va and va+(1<<shift)<=aperture_end:continue
                target=desc&0x0000ffffffffc000
                if shift>14:walk(target,shift-11,va)
                elif params[46]<=target<params[47]:
                    pages.setdefault(target,[]).append(va|0xffff800000000000)
        walk(params[0],36,0)
        if len(pages)>10000:raise ValueError('mapped object scan exceeds bound')
        matches=[];needle=struct.pack('<Q',expected)
        for pa,vas in sorted(pages.items()):
            page=ram(pa,0x4000);pos=0
            while (pos:=page.find(needle,pos))>=0:
                off=pos;pos+=8
                if off%8 or off+0x1b8>0x4000:continue
                raw=page[off:off+0x1b8]
                refs,=struct.unpack_from('<Q',raw,8)
                registers,=struct.unpack_from('<Q',raw,0x118)
                if not 0<(refs&0xffff)<1000 or translate(registers)!=0x385018000:continue
                fields={name:hex(struct.unpack_from(fmt,raw,offset)[0]) for name,fmt,offset in
                    [('revision','<I',0x13c),('command','<Q',0x188),('address','<I',0x190),
                     ('read_length','<I',0x19c),('error','<I',0x1a8),
                     ('last_status','<I',0x1ac),('initial_status','<I',0x1b0)]}
                matches.append(dict(pa=hex(pa+off),vas=[hex(v+off) for v in vas],
                    vtable=hex(expected),reference_word=hex(refs),registers_va=hex(registers),
                    fields=fields,raw_hex=raw.hex()))
        if proxy.exceptions:raise ValueError('proxy exceptions during read-only scan')
        result=dict(monitor_sha256=audit['monitor_sha256'],scanned_tables=len(seen),
            scanned_pages=len(pages),matches=matches,
            boundary='read-only mapped guest RAM; no MMIO reads, resume or guest execution')
    finally:proxy.link.close()
    Path(f'{base}-i2c-completion.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(dict(scanned_pages=len(pages),matches=len(matches),
                         fields=[m['fields'] for m in matches])))
    if len(matches)!=1:raise ValueError('expected one bound native I2C2 controller object')

if __name__=='__main__':main()

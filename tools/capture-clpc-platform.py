#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Read native CLPC platform state and temporary PTEs from an audited stopped guest."""
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

def read_cstring(reader,va,limit=128):
    """Read through NUL without crossing an unread mapped-page boundary."""
    if not 0<limit<=0x4000:raise ValueError('invalid native string limit')
    data=bytearray()
    while len(data)<limit:
        size=min(64,limit-len(data),0x4000-(va&0x3fff))
        part=reader(va,size)
        if len(part)!=size:raise ValueError('short native string read')
        end=part.find(b'\0')
        if end>=0:return (data+part[:end]).decode('ascii')
        data.extend(part);va+=size
    raise ValueError('unterminated native string')

def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--device',required=True)
    ap.add_argument('--prefix',required=True)
    ap.add_argument('--fault-state',type=lambda v:int(v,0),
                    help='optional native saved-state VA from the bound panic arguments')
    ap.add_argument('--fane',action='store_true',
                    help='capture the native CLPC FANE table identified in the bound rate-loop trace')
    ap.add_argument('--cpu-sampler',action='store_true',
                    help='capture the two native ClusterPerfSampler descriptors from guest RAM')
    args=ap.parse_args()
    if not re.fullmatch(r'[a-z0-9-]+',args.prefix):raise ValueError('invalid prefix')
    base=ROOT/'build'/args.prefix
    audit=json.loads(Path(f'{base}-audit.json').read_text())
    kernel=xb.DEFAULT_KERNELCACHE
    blob=kernel.read_bytes()
    if hashlib.sha256(blob).hexdigest()!='dc9019ae39187b36936c2c513b485e513f15cd966b5c887ac88ffd2925976c62':
        raise ValueError('native CLPC contract is bound to J700 26A428')
    symbols={}
    for row in subprocess.run(['nm','-n',str(kernel)],capture_output=True,text=True,check=True).stdout.splitlines():
        words=row.split()
        if len(words)==3 and words[2] in ('__ZN4clpc18running_on_siliconE','__ZN4clpc18clpc_assert_energyE'):
            if words[2] in symbols:raise ValueError('duplicate CLPC symbol')
            symbols[words[2]]=int(words[0],16)
    if len(symbols)!=2:raise ValueError('missing CLPC platform symbols')
    image=xb.kc_load.Image(blob)
    def original(va,width):
        seg=next(s for s in image.segments if s[1]<=va<va+width<=s[1]+s[4])
        off=seg[3]+va-seg[1]
        return int.from_bytes(blob[off:off+width],'little')
    proxy=run.connect(args.device,tries=1)
    try:
        def read(pa,n):
            if not 0<n<=0x200000:raise ValueError('invalid read size')
            return b''.join(proxy.readmem(pa+i,min(65536,n-i),live=True) for i in range(0,n,65536))
        info=proxy.bootinfo();work, work_size = run.resident_work(proxy, info)
        monitor=(ROOT/'build/xnuboot.bin').read_bytes()
        if (hashlib.sha256(monitor).hexdigest()!=audit['monitor_sha256'] or
            read(info['heap_base']+run.CODE_AT,len(monitor))!=monitor):
            raise ValueError('resident monitor differs from audit')
        param_pa,=struct.unpack('<Q',read(work,8))
        params=struct.unpack(f'<{xb.PARAMS_WORDS}Q',read(param_pa,xb.PARAMS_WORDS*8))
        g=audit['geometry']
        if (params[0],params[30],params[31])!=(g['root'],g['ram_low'],g['ram_high']):
            raise ValueError('resident geometry differs from audit')
        def ram(pa,n):
            if not g['ram_low']<=pa<pa+n<=g['ram_high']:raise ValueError('not guest RAM')
            return read(pa,n)
        def leaf(va):
            table=params[0]
            for shift in (36,25,14):
                at=table+8*((va>>shift)&2047)
                desc,=struct.unpack('<Q',ram(at,8))
                if shift==14:return at,desc
                if desc&3!=3:raise ValueError('missing table level')
                table=desc&0x0000ffffffffc000
        def virtual(va,n):
            if not 0<n<=0x4000:raise ValueError('invalid mapped object size')
            result=bytearray()
            while n:
                _,pte=leaf(va)
                if pte&3!=3:raise ValueError('object is unmapped')
                size=min(n,0x4000-(va&0x3fff))
                result.extend(ram((pte&0x0000ffffffffc000)+(va&0x3fff),size))
                va+=size;n-=size
            return bytes(result)
        def cstring(va,limit=128):
            return read_cstring(virtual,va,limit)
        fields={}
        for name,va in symbols.items():
            width=1 if 'running_on_silicon' in name else 4
            _,pte=leaf(va)
            if pte&3!=3:raise ValueError('CLPC global is unmapped')
            pa=(pte&0x0000ffffffffc000)+(va&0x3fff)
            fields[name]=dict(va=hex(va),pa=hex(pa),file_value=original(va,width),
                             value=int.from_bytes(ram(pa,width),'little'))
        windows=[]
        for cpu in range(6):
            for index in range(4):
                va=0xfffffecfffd00000+cpu*0x10000+index*0x4000
                at,pte=leaf(va)
                windows.append(dict(cpu=cpu,index=index,va=hex(va),pte_pa=hex(at),pte=hex(pte)))
        if proxy.exceptions:raise ValueError('proxy exceptions during RAM readback')
        result=dict(monitor_sha256=audit['monitor_sha256'],fields=fields,windows=windows,
                    boundary='read-only mapped guest RAM and PTEs; no MMIO reads or resume')
        if args.cpu_sampler:
            rows=[]
            # Bound enableCluster uses object+8+cluster*0x78; the saved
            # camera-deferred CPU1 x8 identifies this exact native object.
            for cluster in range(2):
                va=0xfffffe000c914a38+cluster*0x78
                raw=virtual(va,0x78)
                rows.append(dict(cluster=cluster,va=hex(va),raw_hex=raw.hex(),
                    register_base=hex(struct.unpack_from('<Q',raw,8)[0]),
                    enable_register=hex(struct.unpack_from('<Q',raw,0x10)[0]),
                    selector_offsets=list(struct.unpack_from('<10I',raw,0x4c))))
            result['cpu_sampler']=rows
        if args.fault_state is not None:
            va=args.fault_state
            if va&15 or (va&0x3fff)+0x180>0x4000:raise ValueError('invalid saved-state span')
            _,pte=leaf(va)
            if pte&3!=3:raise ValueError('saved state is unmapped')
            pa=(pte&0x0000ffffffffc000)+(va&0x3fff)
            raw=ram(pa,0x180)
            if struct.unpack_from('<2I',raw)!=(21,74):raise ValueError('unexpected ARM saved-state header')
            words=struct.unpack_from('<37Q',raw,8)
            result['fault_state']=dict(va=hex(va),pa=hex(pa),raw_hex=raw.hex(),
                registers={str(i):hex(words[i]) for i in range(29)},
                fp=hex(words[29]),lr=hex(words[30]),sp=hex(words[31]),pc=hex(words[32]),
                pstate=hex(words[33]&0xffffffff),far=hex(words[34]),esr=hex(words[35]))
        fane_available=True
        if args.fane:
            clpc=0xfffffe000c911600
            header=virtual(clpc,0x20)
            nub,=struct.unpack_from('<Q',header,0x10)
            providers=[]
            try:
                # Only the nub and its cached PMGR parent are validated.
                # A concurrent stop may precede publication of either.
                for _ in range(2):
                    obj=virtual(nub,0x80)
                    providers.append(dict(va=hex(nub),raw_hex=obj.hex()))
                    nub,=struct.unpack_from('<Q',obj,0x30)
                if struct.unpack_from('<Q',obj)[0]!=0xfffffe0008274088:
                    raise ValueError('CLPC provider is not bound AppleT8140PMGR')
            except ValueError as error:
                if args.fault_state is not None:raise
                fane_available=False
                result['fane']=dict(available=False,clpc=hex(clpc),
                    clpc_header=header.hex(),provider_cache_chain=providers,
                    error=str(error),boundary='provider publication not available at this concurrent stop')
            result['clpc_dvmr_types']=[dict(cluster=cluster,
                va=hex(clpc+0xf68+cluster*0x278+0x130),
                entries=[hex(value) for value in struct.unpack('<32Q',
                    virtual(clpc+0xf68+cluster*0x278+0x130,32*8))])
                for cluster in range(2)]
        if args.fane and fane_available:
            if args.fault_state is not None and words[32]!=0xfffffe0009b847a8:
                raise ValueError('unexpected original fault for FANE capture')
            def object_at(va,n):return dict(va=hex(va),raw_hex=virtual(va,n).hex())
            # Native init stores its ApplePMGRNub argument at CLPC+10.
            # x24 retains the dictionary pointer array (loop owner+8).
            # Its count is at owner+12c, hence x24+124. x22 has been reused
            # after the loop and must not be used as the owner at the fault.
            clpc=0xfffffe000c911600
            table_va=words[24] if args.fault_state is not None else clpc+0x11e8
            header=virtual(clpc,0x20)
            nub,=struct.unpack_from('<Q',header,0x10)
            count,=struct.unpack('<I',virtual(table_va+0x124,4))
            if count>32 or (not count and args.fault_state is not None):
                raise ValueError('unexpected CLPC FANE table count')
            dictionaries=struct.unpack(f'<{count}Q',virtual(table_va,count*8)) if count else ()
            objects=[object_at(p,0x40) for p in dictionaries]
            for obj in objects:
                data=bytes.fromhex(obj['raw_hex'])
                n,=struct.unpack_from('<I',data,0x14)
                table,=struct.unpack_from('<Q',data,0x20)
                if not 0<n<=32:raise ValueError('unexpected native dictionary size')
                entries=[]
                for key,value in struct.iter_unpack('<2Q',virtual(table,n*16)):
                    key_data=virtual(key,0x18);value_data=virtual(value,0x18)
                    string,=struct.unpack_from('<Q',key_data,0x10)
                    name=cstring(string)
                    entries.append(dict(key=hex(key),name=name,value=hex(value),
                        key_hex=key_data.hex(),value_hex=value_data.hex()))
                obj['entries']=entries
            result['fane']=dict(available=True,clpc=hex(clpc),clpc_header=header.hex(),
                loop_count=count,table_va=hex(table_va),dictionaries=objects,
                provider_cache_chain=providers)
            driver,=struct.unpack_from('<Q',header,0x18)
            try:
                driver_data=virtual(driver,0xa0)
            except ValueError as error:
                # A concurrent start may not yet have a live driver object.
                # Preserve that absence and the other observations; do not
                # manufacture a callback value or discard the entire capture.
                result['fane']['apple_clpc']=dict(va=hex(driver),available=False,error=str(error))
            else:
                result['fane']['apple_clpc']=dict(va=hex(driver),available=True,raw_hex=driver_data.hex(),
                    post_init_callback=hex(struct.unpack_from('<Q',driver_data,0x98)[0]))
            # The first provider's cached parent is the exact native
            # AppleT8140PMGR instance; validate its vtable before offsets.
            pmgr=int(providers[1]['va'],16)
            if struct.unpack_from('<Q',bytes.fromhex(providers[1]['raw_hex']))[0]!=0xfffffe0008274088:
                raise ValueError('CLPC provider is not bound AppleT8140PMGR')
            # Unlike CLPC's temporary array, the retained domain DVFMStates
            # dictionary survives the driver's initialization/cleanup. Decode only
            # bounded, native-vtable-bound collections; unknown objects stay
            # references, and no methods or MMIO are invoked.
            budget=[256]
            def collection(va,depth=0):
                if depth>5 or budget[0]<=0:return dict(va=hex(va),truncated=True)
                budget[0]-=1
                data=virtual(va,0x28);vt,=struct.unpack_from('<Q',data)
                obj=dict(va=hex(va),vtable=hex(vt))
                if vt==0xfffffe0007e66900:
                    obj.update(number=struct.unpack_from('<Q',data,0x10)[0],
                               number_bits=struct.unpack_from('<I',data,0xc)[0])
                elif vt in (0xfffffe0007e650f0,0xfffffe0007e64398):
                    n,=struct.unpack_from('<I',data,0x14)
                    if n>64:raise ValueError('oversized native collection')
                    storage,=struct.unpack_from('<Q',data,0x20)
                    storage=(storage&0x0000ffffffffffff)|0xffff000000000000
                    obj['count']=n
                    if vt==0xfffffe0007e650f0:
                        entries=[]
                        for key,value in struct.iter_unpack('<2Q',virtual(storage,n*16) if n else b''):
                            key_data=virtual(key,0x18)
                            if struct.unpack_from('<Q',key_data)[0] not in (0xfffffe0007e67c38,0xfffffe0007e67fa8):
                                raise ValueError('unexpected native dictionary key type')
                            string,=struct.unpack_from('<Q',key_data,0x10)
                            try:
                                name=cstring(string)
                            except ValueError as error:
                                raise ValueError(f'key {key:#x} raw={key_data.hex()} string={string:#x}: {error}') from error
                            item=dict(name=name,value=hex(value))
                            item['object']=collection(value,depth+1)
                            entries.append(item)
                        obj['entries']=entries
                    else:
                        values=struct.unpack(f'<{n}Q',virtual(storage,n*8)) if n else ()
                        obj['items']=[collection(value,depth+1) for value in values]
                return obj
            descriptors,=struct.unpack('<Q',virtual(pmgr+0x6328,8))
            domains=[]
            for domain in (2,5,8):
                index,=struct.unpack('<H',virtual(pmgr+0x6338+2*domain,2))
                if index>=7:raise ValueError('invalid PMGR domain index')
                address=descriptors+index*0x118
                data=virtual(address,0x118)
                record,=struct.unpack_from('<Q',data)
                definition=virtual(record,28)
                if definition[3]!=domain:raise ValueError('PMGR requested type differs from native record')
                n,=struct.unpack_from('<I',data,8)
                raw_n,=struct.unpack_from('<I',data,0x70)
                raw_table,=struct.unpack_from('<Q',data,0x78)
                rates,=struct.unpack_from('<Q',data,0x98)
                # _initPerfDomainInfo stores its retained dictionary at +f8
                # (9796a8c), before populating DVFMStates and FANE indices.
                info_dictionary,=struct.unpack_from('<Q',data,0xf8)
                if not 0<n<=32 or not 0<raw_n<=32:raise ValueError('invalid PMGR table bound')
                domains.append(dict(requested_type=domain,index=index,va=hex(address),
                    state_count=n,raw_count=raw_n,descriptor_hex=data.hex(),
                    definition_hex=definition.hex(),
                    raw_entries=list(struct.iter_unpack('<2I',virtual(raw_table,raw_n*8))),
                    metadata=list(struct.unpack(f'<{n}Q',virtual(rates,n*8))),
                    info_dictionary=collection(info_dictionary) if info_dictionary else None))
            result['fane']['pmgr_domains']=domains
            if args.fault_state is not None:
                # This exact CLPC fault retains init's stack frame. Stack
                # slots can be reused: +140 no longer points to DVMR types
                # after 9b83acc. Read those from persistent cluster info+130.
                sp=words[31]
                local_offsets=dict(cluster=0x88,ane_frequencies=0xb0,
                    zero_number=0xb8,cluster_info=0xc0,reused_f0=0xf0,
                    reused_140=0x140)
                locals_={name:struct.unpack('<Q',virtual(sp+offset,8))[0]
                         for name,offset in local_offsets.items()}
                if (locals_['cluster']>1 or locals_['cluster_info']!=
                    clpc+0xf68+locals_['cluster']*0x278):
                    raise ValueError('unexpected retained CLPC cluster info')
                dvmr_types=locals_['cluster_info']+0x130
                packed,=struct.unpack('<Q',virtual(dvmr_types,8))
                symbol_ptrs=struct.unpack('<3Q',virtual(0xfffffe000c911590,24))
                symbols_=[]
                for pointer in symbol_ptrs:
                    item=dict(va=hex(pointer))
                    if pointer:
                        raw=virtual(pointer,0x18)
                        if struct.unpack_from('<Q',raw)[0]!=0xfffffe0007e67c38:
                            raise ValueError('unexpected CLPC FANE symbol type')
                        item['name']=cstring(struct.unpack_from('<Q',raw,0x10)[0])
                    symbols_.append(item)
                result['fane']['conversion_inputs']=dict(sp=hex(sp),
                    locals={name:hex(value) for name,value in locals_.items()},
                    dvmr_types=hex(dvmr_types),
                    dvmr_entry_zero=hex(packed),
                    dvmr_entry_zero_bytes=list(packed.to_bytes(8,'little')),
                    symbols=symbols_,
                    ane_frequencies=collection(locals_['ane_frequencies']),
                    zero_number=collection(locals_['zero_number']),
                    boundary='retained objects and DVMR entry zero; f0/140 stack slots are reused; not a branch execution trace')
    finally:proxy.link.close()
    Path(f'{base}-clpc-platform.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(dict(fields=fields,occupied_windows=[w for w in windows if int(w['pte'],16)&3])))

if __name__=='__main__':main()

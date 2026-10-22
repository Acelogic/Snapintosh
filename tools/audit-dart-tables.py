#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Independent read-only audit of mac-v1 class-5 SIO/normal SEP/Adreno tables.

Roots are (logical device ID, SID, raw TTBR register, raw TCR) tuples captured from
the stopped model. Ordinary DEFAULT-frame leaves contribute to the same
reference counters as CPU mappings; return their independently counted
references for audit-sptm-refs.py to combine with its CPU walk.
The read callback must enforce physical bounds and transport chunk limits.
"""
import struct
import collections
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parent))
from audit_memory import ManagedFrames, SEPFirmwareFrames


def audit(read, *, frame_map, frame_low, frame_high, alloc_low, alloc_high, roots,
          boot_ranges=(), boot_aliases=(), sep_firmware=(0,0), sep_released=False):
    if (not frame_low <= alloc_low < alloc_high <= frame_high or
            (frame_low | frame_high | alloc_low | alloc_high) & 0x3fff or
            frame_map & 15 or alloc_high > 1 << 36):
        raise ValueError('invalid frame geometry')
    managed=ManagedFrames(frame_map,frame_low,frame_high,alloc_low,alloc_high,
                          boot_ranges,boot_aliases,sep_firmware if sep_released else (0,0))
    firmware=SEPFirmwareFrames(managed,frame_map,frame_low,frame_high,alloc_low,
                               (0,0) if sep_released else sep_firmware)
    size=((frame_high-frame_low)>>14)*16
    fm=read(frame_map,size)
    if len(fm)!=size:raise ValueError('short frame map')
    seen=set();tables=[];mismatches=[];owners=set();leaves=[];refs=collections.Counter()

    def meta(pa):
        offset=((pa-frame_low)>>14)*16
        return fm[offset:offset+16]

    def issue(pa,field,expected,actual):
        mismatches.append(dict(pa=hex(pa),field=field,expected=expected,actual=actual))

    def visit(pa,device,sid,level,prefix):
        if pa & 0x3fff or not managed.contains(pa):
            issue(pa,'table address','aligned allocator frame',hex(pa));return
        if pa in seen:
            issue(pa,'attachment','one parent, acyclic','shared or cyclic');return
        seen.add(pa);e=meta(pa)
        expected=bytes([0,0,24,0,e[4],e[5],5,0,device,sid,level,0,0,0,0,0])
        if e!=expected:
            issue(pa,'ownership',expected.hex(),e.hex());return
        page=read(pa,0x4000)
        if len(page)!=0x4000:raise ValueError('short table page')
        children=0
        for slot,(pte,) in enumerate(struct.iter_unpack('<Q',page)):
            if not pte:continue
            children+=1
            if level==2:
                target=(pte&0x3ffffffc00)<<4
                begin=(pte>>52)*4;end=(((pte>>40)&0xfff)+1)*4
                if (not pte&1 or pte&~0xffffff3ffffffc0d or begin>=end
                        or not (managed.contains(target) or
                                device==20 and sid==0 and firmware.contains(target))):
                    issue(pa,'leaf descriptor','owned DEFAULT frame and supported bounds/flags',hex(pte));continue
                data=meta(target)
                if data[:8]!=bytes([0,0,11,0,0,0,0,0]):
                    issue(target,'DMA frame','idle ordinary DEFAULT data',data.hex());continue
                readonly=bool(pte&4)
                refs[target,int(not readonly)]+=1
                iova=prefix|slot<<14
                if device==20:
                    low=0x10000000000 if sid else 0x10000004000
                    high=0x10050000000 if sid else 0x100ffff4000
                    if not low<=iova+begin<iova+end<=high:
                        issue(pa,'leaf window','declared SEP stream window',hex(iova))
                if device==31 and not 0x40000000<=iova+begin<iova+end<=0x100000000:
                    issue(pa,'leaf window','Adreno 1..4 GiB window',hex(iova))
                leaves.append(dict(iova=hex(iova),pa=hex(target),
                    device_id=device,sid=sid,readonly=readonly,no_read=bool(pte&8),
                    begin=begin,end=end))
                continue
            if not pte&1 or pte&~0x3ffffffc01:
                issue(pa,'table descriptor','valid address-only table descriptor',hex(pte));continue
            if level==0 and not 16<=slot<64:
                issue(pa,'root slot','SIO 1..4 TiB window',slot)
            if device==20 and level==1 and slot>=(40 if sid else 128):
                issue(pa,'root slot','declared SEP stream window',slot)
            if device==31 and level==1 and not 32<=slot<128:
                issue(pa,'root slot','Adreno 1..4 GiB window',slot)
            visit((pte&0x3ffffffc00)<<4,device,sid,level+1,prefix|slot<<(36-11*level))
        count=int.from_bytes(e[4:6],'little')
        if count!=1+children:issue(pa,'references',1+children,count)
        tables.append(dict(pa=hex(pa),device_id=device,sid=sid,level=level,
                           children=children,references=count))

    for root in roots:
        # Legacy three-field SIO snapshots predate explicit TCR capture.
        device,sid,ttbr,tcr=(*root,9) if len(root)==3 else root
        if not 0<=device<32 or not 0<=sid<2 or (device,sid) in owners:
            raise ValueError('invalid or duplicate stream owner')
        owners.add((device,sid))
        if device==31 and sid!=0:raise ValueError('unexpected Adreno stream')
        if tcr!=(1 if device in (20,31) else 9):raise ValueError('unexpected stream geometry')
        if not ttbr:continue
        if not ttbr&1 or ttbr&~0x3ffffffd:raise ValueError('malformed TTBR')
        visit((ttbr&0x3ffffffc)<<12,device,sid,1 if device in (20,31) else 0,
              1<<40 if device==20 else 0)
    unattached=[]
    for pa in managed.frames():
        e=meta(pa)
        if e[2]!=24 or pa in seen:continue
        count=int.from_bytes(e[4:6],'little')
        if count:issue(pa,'unattached references',0,count)
        if e[6]!=5 or e[9]>1 or e[10]>3:
            issue(pa,'unattached owner','class 5, SID 0/1, level 0..3',e.hex())
        unattached.append(hex(pa))
    return dict(attached_tables=len(seen),tables=tables,unattached_frames=unattached,
                leaves=leaves,dma_mappings=len(leaves),
                data_references=[dict(pa=hex(pa),readonly=refs[pa,0],other=refs[pa,1])
                                 for pa in sorted({pa for pa,_ in refs})],mismatches=mismatches)

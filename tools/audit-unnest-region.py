#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Read back an UNNEST witness independently of the C removal implementation."""
import struct
FIELDS='calls descriptors leaves root shared va pages cpu format base span count last_descriptors last_leaves'.split()
def audit_unnesting(read,blob,*,frame_map,frame_low,detachments=()):
    if len(blob)!=368:raise ValueError('invalid unnest telemetry size')
    words=struct.unpack('<46Q',blob);v=dict(zip(FIELDS,words[:14]));bits=words[14:]
    if not v['calls']:
        if any(words):raise ValueError('uninitialized unnest witness')
        return dict(calls=0,descriptors=0,leaves=0)
    if v['format'] not in (0,1) or v['cpu']>=6:raise ValueError('invalid unnest CPU or format')
    shift=12 if v['format'] else 14;page=1<<shift;span=1<<(2*shift-3);mask=(1<<48)-page
    va,pages=v['va'],v['pages'];end=va+pages*page;group=0x4000//page
    if (not 0<pages<=0xffffffff or va%page or end>1<<47 or
        va//(1<<(3*shift-6))!=(end-page)//(1<<(3*shift-6)) or
        ((va//span)|(end//span))&(group-1) or v['span']!=span or
        v['base']!=va//span*span or v['count']!=(end-page)//span-va//span+1 or
        not 0<v['count']<=2048):raise ValueError('invalid unnest range')
    selected=[i for i in range(2048) if bits[i//64]>>(i%64)&1]
    if (any(i>=v['count'] for i in selected) or len(selected)!=v['last_descriptors'] or
        len(selected)>v['descriptors'] or v['last_leaves']>v['leaves'] or
        v['last_leaves']>len(selected)*page//8):raise ValueError('invalid unnest counters')
    def meta(pa):
        if pa%0x4000 or pa<frame_low:raise ValueError('invalid unnest frame')
        out=read(frame_map+((pa-frame_low)>>14)*16,16)
        if len(out)!=16 or any(out[:2]):raise ValueError('invalid unnest metadata')
        return out
    u,p=meta(v['root']),meta(v['shared'])
    retired_root=u==bytes([0,0,11])+bytes(13)
    if retired_root and any(read(v['root'],0x4000)):
        raise ValueError('retired unnest root retains descriptors')
    if ((not retired_root and (u[2]!=18 or u[8]==255 or u[8]!=p[8] or u[12]!=v['format'])) or
        p[2]!=19 or p[12]!=v['format'] or
        not int.from_bytes(p[4:6],'little')):raise ValueError('invalid unnest identity')
    def descriptor(root,addr,retired=False):
        table=root
        for level in range(0 if shift==12 else 1,3):
            idx=(addr>>(shift+(3-level)*(shift-3)))&((1<<(shift-3))-1)
            slot=table+idx*8;pte=struct.unpack('<Q',read(slot,8))[0]
            if level==2:return slot,pte
            if not pte and retired:return slot,0
            if pte&~mask!=3:raise ValueError('missing unnest parent')
            table=pte&mask
    rows=[]
    for i in selected:
        addr=v['base']+i*span
        retired=any(r['root']==v['shared'] and r['base']<=addr<r['base']+r['size'] for r in detachments)
        dst,a=(None,0) if retired_root else descriptor(v['root'],addr)
        src,b=descriptor(v['shared'],addr,retired)
        dst_text=hex(dst) if dst is not None else None
        replacement=None
        if a:
            # XNU can replace a removed shared L3 with a private L3 before
            # the next stop. The old shared edge must still be absent: a
            # different, ordinary type20 child with one parent is required.
            # The complete ownership/canonical audit validates its contents.
            f=meta(a&~0x3fff)
            if (a&~mask!=3 or (a&~0x3fff)==(b&~0x3fff) or f[2]!=20 or f[4]!=3 or
                int.from_bytes(f[6:8],'little')!=1 or int.from_bytes(f[8:10],'little')>2048):
                raise ValueError('unnested consumer retains a shared or invalid replacement descriptor')
            replacement=hex(a)
        if not b and retired:
            rows.append(dict(va=hex(addr),user_slot=dst_text,shared_slot=hex(src),
                source_descriptor='0x0',source_detached=True,remaining_links=0,
                consumer_replacement=replacement))
            continue
        if b&~mask!=3:raise ValueError('shared source descriptor was lost')
        f=meta(b&~0x3fff);links=int.from_bytes(f[6:8],'little')
        if f[2]!=21 or f[4]!=3 or not 1<=links<=0xfff9:
            raise ValueError('shared source child was released')
        rows.append(dict(va=hex(addr),user_slot=dst_text,shared_slot=hex(src),
            source_descriptor=hex(b),remaining_links=links,consumer_replacement=replacement))
    return dict(**v,retired_root=retired_root,mask=[hex(b) for b in bits],current_removed_descriptors=rows)

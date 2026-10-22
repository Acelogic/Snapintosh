#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Independently verify the last NEST_REGION against live source descriptors."""
import struct


def audit_nesting(read, blob, *, frame_map, frame_low, ownership, removed=0,detachments=()):
    if len(blob)!=64:raise ValueError('invalid nesting telemetry size')
    calls,total,root,shared,va,pages,first,last=struct.unpack('<8Q',blob)
    if not calls:
        if any(blob) or ownership['nested_descriptors'] or removed:
            raise ValueError('unexplained nested descriptors')
        return dict(calls=0,descriptors=0)
    if calls>total or not 0<=removed<=total or total-removed!=ownership['nested_descriptors']:
        raise ValueError('nesting totals disagree with independently traversed roots')
    def meta(pa):
        if pa&0x3fff or pa<frame_low:raise ValueError('invalid nesting frame')
        data=read(frame_map+((pa-frame_low)>>14)*16,16)
        if len(data)!=16 or any(data[:2]):raise ValueError('invalid nesting metadata')
        return data
    u,p=meta(root),meta(shared)
    retired_root=u==bytes([0,0,11])+bytes(13)
    if retired_root:
        contents=read(root,0x4000)
        if len(contents)!=0x4000 or any(contents):
            raise ValueError('retired nesting root retains descriptors')
    if (root==shared or p[2]!=19 or p[12] not in (0,1) or
            (not retired_root and (u[2]!=18 or u[8]==255 or u[8]!=p[8] or u[12]!=p[12])) or
            not int.from_bytes(p[4:6],'little')):
        raise ValueError('invalid nesting identity')
    shift=12 if p[12] else 14
    page,span,mask=1<<shift,1<<(2*shift-3),(1<<48)-(1<<shift)
    limit=1<<(32 if not retired_root and u[10]&0x20 else 47)
    if (not 0<pages<=0xffffffff or va%page or va>=limit or pages>(limit-va)//page or
            first!=va//span*span or last!=(va+(pages-1)*page)//span*span+span):
        raise ValueError('invalid nesting range')
    count=(last-first)//span
    if count>total:raise ValueError('last nesting exceeds cumulative total')
    def descriptor(root,addr,allow_empty=False):
        table=root
        for level in range(0 if shift==12 else 1,3):
            idx=(addr>>(shift+(3-level)*(shift-3)))&((1<<(shift-3))-1)
            pte=struct.unpack('<Q',read(table+idx*8,8))[0]
            if not pte and allow_empty:return 0
            if pte&~mask!=3:raise ValueError('invalid nesting table descriptor')
            table=pte&mask
        return pte
    children=set();retired=0
    for addr in range(first,last,span):
        detached=any(r['root']==shared and r['base']<=addr<r['base']+r['size'] for r in detachments)
        a=0 if retired_root else descriptor(root,addr,removed>0)
        b=descriptor(shared,addr,detached)
        if a!=b or not b:
            if not removed or (a and meta(a&~0x3fff)[2] not in (20,23)):
                raise ValueError('nested descriptor differs from source')
            retired+=1;continue
        child=a&~0x3fff;f=meta(child)
        if f[2]!=21 or f[4]!=3 or not 2<=int.from_bytes(f[6:8],'little')<=0xfff9:
            raise ValueError('nested child ownership mismatch')
        children.add(child)
    if retired>removed:raise ValueError('unexplained retired nesting descriptors')
    return dict(calls=calls,descriptors=total,removed_descriptors=removed,
                current_descriptors=total-removed,last_descriptors=count,
                last_retired_descriptors=retired,last_tables=len(children),
                root=hex(root),shared=hex(shared),va=hex(va),pages=pages,
                first=hex(first),last=hex(last),format=p[12],retired_root=retired_root)

#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Independently inspect the last committed shared MAP_PAGE and cached aliases."""
import hashlib
from pathlib import Path
import runpy
import struct

ROOT=Path(__file__).resolve().parents[1]
FIELDS='calls inserts updates alias_updates root va old next shift mask unmaps removed requested options result cpu'.split()

def select(old,requested):
    im=runpy.run_path(str(ROOT/'tools/sptm-dispatch.py'))['Image'](
        ROOT/'downloads/extracted/j700ap/sptm.t8140.release')
    if hashlib.sha256(im.data).hexdigest()!='bd5736d4bd98bceaed2b057ebc09094324bf5149491c2922b329f87db23b1bd0':
        raise ValueError('wrong SPTM image')
    selector=lambda p:((p>>4)&12)|((p>>53)&3)
    before,after=selector(old),selector(requested)
    if old==requested:return old,1
    if old:
        if old&3!=3:raise ValueError('unsupported old shared descriptor')
        if (old^requested)&0x0000fffffffff000:return old,6
        if before!=after:
            rows=[]
            for base in (0xfffffff02701a878,0xfffffff02701a898):
                rows.append(struct.unpack_from('<H',im.data,im.locate(base+2*before)[1])[0])
            if not (rows[0]|rows[1])&(1<<after):raise ValueError('shared MAP permission transition refused')
    # Shipped f9288..f92a8 preserves unselected old attributes for same PA.
    base=old or requested
    value=(base&~((3<<58)|(3<<53)|0xc0))|(requested&((3<<58)|(3<<53)|0xc0))
    if after in (3,5,7,9):value&=~(1<<59)
    return value,0

def audit(read,*,state,cache,regions,ram_low,ram_high,work_low,work_high):
    s=state
    if s['calls']!=s['inserts']+s['updates'] or s['alias_updates']>64*s['calls'] or s['removed']>64*s['unmaps']:
        raise ValueError('shared-page counters disagree')
    if not s['calls']:
        if any(s[k] for k in FIELDS if k not in ('unmaps','removed')):
            raise ValueError('unused shared-page witness is not empty')
        return dict(s,rows=[])
    if s['shift'] not in (12,14) or s['options']&~1 or s['cpu']>=6 or s['result'] not in (0,1):
        raise ValueError('invalid shared-page witness')
    expected,status=select(s['old'],s['requested'])
    # Status follows the old leaf, not the selection: valid same-PA -> 1.
    status=1 if s['old']&3==3 else 0
    if expected!=s['next'] or status!=s['result'] or s['old']==s['next']:
        raise ValueError('shared-page selection differs from shipped policy')
    size=1<<s['shift'];va=s['va'];root=s['root']
    region=next((r for r in regions if int(r['root'],16)==root),None)
    if not region or region['page_size']!=size or not int(region['start'],16)<=va<int(region['end'],16) or va&(size-1):
        raise ValueError('shared-page geometry disagrees with shared registry')
    def walk(root,shift,va,hardware=False):
        table=root;lo,hi=(work_low,work_high) if hardware else (ram_low,ram_high)
        size=1<<shift;seen=set()
        for level in range(1 if shift==14 else 0,4):
            if table&(size-1) or not lo<=table<table+size<=hi or table in seen:
                raise ValueError('shared-page walk leaves admitted memory')
            seen.add(table);slot=table+8*((va>>(shift+(3-level)*(shift-3)))&((1<<(shift-3))-1))
            pte,=struct.unpack('<Q',read(slot,8))
            if level==3:return slot,pte
            if not pte:return None,0
            if pte&3!=3:raise ValueError('shared-page walk encounters unsupported descriptor')
            table=pte&((1<<48)-size)
        raise ValueError('incomplete shared-page walk')
    slot,pte=walk(root,s['shift'],va)
    aliases=[]
    for i,c in enumerate(cache):
        if not c['valid'] or c['format']!=(s['shift']==12):continue
        candidate,source=walk(c['root'],s['shift'],va)
        if slot is None or candidate!=slot:continue
        if source!=pte:raise ValueError('shared source differs at the same physical slot')
        parts=[]
        for off in range(0,size,4096):
            _,leaf=walk(c['shadow'],12,va+off,True)
            expected=((pte&((1<<48)-size))+off)|(pte&(0xfff|(3<<53))) if pte else 0
            if leaf!=expected:raise ValueError('shared alias canonical leaf differs from source')
            parts.append(hex(leaf))
        aliases.append(dict(cache_index=i,root=hex(c['root']),canonical=hex(c['shadow']),leaves=parts))
    return dict(s,descriptor_policy_verified=True,current_source_slot=None if slot is None else hex(slot),
        current_source_pte=None if slot is None else hex(pte),current_source_matches=slot is not None and pte==s['next'],
        current_aliases=aliases,historical_alias_mask=hex(s['mask']))

#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Check native user-update witnesses against the selected SPTM policy tables."""
import hashlib
from pathlib import Path
import runpy
import struct

ROOT=Path(__file__).resolve().parents[1]
FIELDS='calls entries changed options result target count root va slot old next shift flags last_changed requested'.split()
MASK=0x08680000000000c0

def policy():
    im=runpy.run_path(str(ROOT/'tools/sptm-dispatch.py'))['Image'](
        ROOT/'downloads/extracted/j700ap/sptm.t8140.release')
    if hashlib.sha256(im.data).hexdigest()!='bd5736d4bd98bceaed2b057ebc09094324bf5149491c2922b329f87db23b1bd0':
        raise ValueError('wrong SPTM policy image')
    return [struct.unpack('<32I',im.data[im.locate(base)[1]:im.locate(base)[1]+128])
            for base in (0xfffffff02701a8b8,0xfffffff02701a938,0xfffffff02701a9b8)]

def selected(old,requested,options,tables):
    new=old
    if options&1:new=(new&~(1<<58))|(requested&(1<<58))
    if options&8:
        new&=~0x400
        if old&0x400 or options&0x800:new|=requested&0x400
    if options&2:
        index=lambda p:((p>>4)&12)|((p>>53)&3)|((p>>55)&16)
        before,after=index(old),index(requested)
        if before!=after:
            allow,ignore,fault=(table[before]&(1<<after) for table in tables)
            if not ignore and (not fault or options&0x800):
                if not (allow or fault):raise ValueError('native witness contains rejected permission transition')
                new=(new&~MASK)|(requested&MASK)
    return new

def audit(read,*,states,cache,ram_low,ram_high,region=False):
    if len(states)!=6:raise ValueError('user update CPU count')
    tables=policy();rows=[]
    for cpu,s in enumerate(states):
        if not s['calls']:
            if any(s.values()):raise ValueError('unused user update witness is not empty')
            continue
        if (not 1<=s['count']<=64 or s['entries']<s['calls'] or
            s['changed']>s['entries'] or s['count']>s['entries'] or
            not s['options']&0xb or s['options']&~0xd0b or s['shift'] not in (12,14) or
            s['target']&0x3fff or
            (not ram_low<=s['target']<ram_high and not (region and s['target']==0 and s['old']&3!=3))):
            raise ValueError('invalid user update counters or geometry')
        if region and s['target']!=((s['old']&0x0000ffffffffc000) if s['old']&3==3 else 0):
            raise ValueError('region target differs from old descriptor')
        matches=(s['old']&3)==3 and (s['old']&0x0000ffffffffc000)==s['target']
        expected=selected(s['old'],s['requested'],s['options'],tables) if matches else s['old']
        if expected!=s['next'] or s['last_changed']!=int(s['old']!=expected):
            raise ValueError('native update differs from shipped descriptor policy')
        if s['result'] not in (0,5) or (s['result']==5 and not s['options']&0x100):
            raise ValueError('invalid user update status')
        if s['count']==1:
            hardware_changed=bool((s['old']^s['next'])&~(3<<58))
            if s['result']!=(5 if hardware_changed and s['options']&0x100 else 0):
                raise ValueError('single-record deferred status differs')
        current=None
        roots=[c for c in cache if c['valid'] and c['root']==s['root']]
        if roots:
            c=roots[0];shift=s['shift'];size=1<<shift;table=s['root']
            if c['format']!=(shift==12) or c['flags']!=s['flags']:
                raise ValueError('update witness geometry differs from cached root')
            for level in range(1 if shift==14 else 0,4):
                at=table+8*((s['va']>>(shift+(3-level)*(shift-3)))&((1<<(shift-3))-1))
                if not ram_low<=at<at+8<=ram_high:raise ValueError('update table outside RAM')
                pte,=struct.unpack('<Q',read(at,8))
                if pte&3!=3:break
                if level==3:
                    current=pte
                    if at!=s['slot']:raise ValueError('update source slot differs from current root walk')
                table=pte&((1<<48)-size)
        row=dict(s,cpu=cpu,descriptor_policy_verified=True,
                 current_source_pte=None if current is None else hex(current),
                 current_source_matches=current==s['next'])
        for field in ('target','root','va','slot','old','next','requested','options','flags'):
            row[field]=hex(row[field])
        rows.append(row)
    return dict(calls=sum(s['calls'] for s in states),entries=sum(s['entries'] for s in states),
                changed=sum(s['changed'] for s in states),rows=rows)

def audit_kernel(read,*,states,root,canonical,ram_low,ram_high):
    result=audit(read,states=states,
        cache=[dict(valid=1,root=root,format=0,flags=0)],ram_low=ram_low,ram_high=ram_high)
    for row in result['rows']:
        if int(row['root'],16)!=root or row['shift']!=14 or int(row['flags'],16):
            raise ValueError('kernel update witness has non-kernel geometry')
        if row['current_source_pte'] is None:continue
        source=int(row['current_source_pte'],16);va=int(row['va'],16)
        if source&3!=3:continue
        parts=[]
        for part in range(4):
            at=(va&((1<<47)-1))+part*4096;table=canonical
            for level in range(4):
                slot=table+8*((at>>(12+9*(3-level)))&511)
                pte,=struct.unpack('<Q',read(slot,8))
                if pte&3!=3:raise ValueError('kernel update canonical leaf missing')
                table=pte&0x0000fffffffff000
            expected=(source&0x0000ffffffffc000)+part*4096
            expected|=source&(0xfff|(3<<53))
            if pte!=expected:raise ValueError('kernel update source/canonical permissions differ')
            parts.append(hex(pte))
        row['canonical_4k_ptes']=parts
    return result

#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Independently check shared UPDATE_REGION witnesses and current source walks.

nG selection follows the pinned helper fd544, independently binary-replayed
by replay-shared-ng.py. The full runtime audit separately checks ownership,
all nested canonical shadows and all six private views.
"""
import struct
FIELDS='calls entries changed options result target count root va slot old next shift flags last_changed requested'.split()
PA=0x0000ffffffffc000

def audit(read,*,states,ram_low,ram_high,frame_map,frame_low):
    if len(states)!=6:raise ValueError('shared update CPU count')
    rows=[];total=[0,0,0]
    for cpu,pair in enumerate(states):
        if len(pair)!=2:raise ValueError('shared update witness pair')
        latest,changed=pair
        if (changed['calls']>latest['calls'] or changed['entries']>latest['entries'] or
            changed['changed']!=latest['changed'] or bool(changed['calls'])!=bool(latest['changed'])):
            raise ValueError('shared changed witness counters differ')
        total=[a+latest[k] for a,k in zip(total,('calls','entries','changed'))]
        for kind,s in zip(('latest','changed'),pair):
            if not s['calls']:
                if any(s.values()):raise ValueError('unused shared witness not empty')
                continue
            shift=s['shift'];valid=s['old']&3==3
            if (shift not in (12,14) or s['flags'] or not 1<=s['count']<=64 or
                s['entries']<s['calls'] or s['entries']<s['count'] or
                s['changed']>s['entries'] or s['options'] not in (4,0x104) or
                s['root']&0x3fff or not ram_low<=s['root']<s['root']+0x4000<=ram_high or
                s['va']&((1<<shift)-1) or s['va']>=1<<47 or
                s['target']!=((s['old']&PA) if valid else 0) or
                (valid and (not ram_low<=s['target']<ram_high or not s['requested']&0x800))):
                raise ValueError('invalid shared update counters or geometry')
            expected=s['old']|0x800 if valid else s['old']
            if (s['next']!=expected or s['last_changed']!=int(expected!=s['old']) or
                (kind=='changed' and not s['last_changed'])):
                raise ValueError('shared nG descriptor policy differs')
            if s['result'] not in (0,5) or (s['result']==5 and s['options']!=0x104):
                raise ValueError('shared result invalid')
            if kind=='changed' and s['result']!=(5 if s['options']==0x104 else 0):
                raise ValueError('changed shared result differs')
            if s['count']==1 and s['result']!=(5 if s['last_changed'] and s['options']==0x104 else 0):
                raise ValueError('single shared result differs')
            meta=read(frame_map+((s['root']-frame_low)>>14)*16,16)
            current=None;slot=None;live=meta[2]==19
            if live:
                if meta[12]!=(shift==12):raise ValueError('shared root format differs')
                table=s['root']
                for level in range(1 if shift==14 else 0,4):
                    at=table+8*((s['va']>>(shift+(3-level)*(shift-3)))&((1<<(shift-3))-1))
                    if not ram_low<=at<at+8<=ram_high:raise ValueError('shared walk outside RAM')
                    pte,=struct.unpack('<Q',read(at,8))
                    if level==3:
                        slot=at;current=pte
                        if at!=s['slot']:raise ValueError('shared witness slot differs from walk')
                    if pte&3!=3:break
                    table=pte&((1<<48)-(1<<shift))
            row=dict(s,cpu=cpu,witness=kind,descriptor_policy_verified=True,root_still_shared=live,
                     current_source_pte=None if current is None else hex(current),
                     current_source_matches=current==s['next'])
            for key in ('root','va','slot','old','next','target','requested','options'):
                row[key]=hex(row[key])
            rows.append(row)
    return dict(zip(('calls','entries','changed'),total),rows=rows)

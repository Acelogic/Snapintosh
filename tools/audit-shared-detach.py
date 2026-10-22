#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Validate bounded source retirement history and the last live empty detach."""
import struct
CAPACITY=4096
FIELDS='root va slot child format level parent_count bindings'.split()
def audit_shared_detaches(read,blob,*,frame_map,frame_low):
    if len(blob)!=8+CAPACITY*64:raise ValueError('invalid shared detach telemetry size')
    calls=struct.unpack_from('<Q',blob)[0];rows=[]
    for i in range(max(0,calls-CAPACITY),calls):
        row=dict(zip(FIELDS,struct.unpack_from('<8Q',blob,8+(i%CAPACITY)*64)))
        if (row['format'] not in (0,1) or row['root']%0x4000 or row['child']%0x4000 or
            row['root']<frame_low or row['child']<frame_low or row['slot']%8 or
            row['slot']<frame_low or row['bindings']>0xfff9):raise ValueError('invalid shared detach record')
        shift=12 if row['format'] else 14;group=0x4000>>shift
        start=0 if row['format'] else 1;level=row['level']
        if not start<=level<=2:raise ValueError('invalid shared detach level')
        span=1<<(shift+(3-level)*(shift-3));capacity=(2048 if shift==14 else 64)
        if level!=start:capacity=2048//group
        if (row['va']%(1<<shift) or row['va']>=1<<47 or
            row['va']//span&(group-1) or not 0<row['parent_count']<=capacity):
            raise ValueError('invalid shared detach geometry or count')
        row['base']=row['va']//span*span;row['size']=span*group
        rows.append(row)
    if calls<CAPACITY and any(blob[8+calls*64:]):raise ValueError('uninitialized shared detach history')
    retired_root=False
    if rows:
        v=rows[-1];group=4 if v['format'] else 1
        if any(read(v['slot'],group*8)):raise ValueError('last detached source still present')
        def meta(pa):return read(frame_map+((pa-frame_low)>>14)*16,16)
        root,child=meta(v['root']),meta(v['child'])
        # The kernel may unbind a consumer after cleanup. Historical bindings
        # are not current bindings; the full shared-region audit reconstructs
        # the latter from live roots independently.
        # The final empty root can itself be released after the last detach.
        # Qualify only the captured empty/default case, not arbitrary reuse.
        default=bytes([0,0,11])+bytes(13)
        retired_root=root==default
        if retired_root:
            root_page,child_page=read(v['root'],0x4000),read(v['child'],0x4000)
            if (v['root']!=(v['slot']&~0x3fff) or v['level']!=(0 if v['format'] else 1) or
                v['parent_count']!=1 or v['bindings'] or child!=default or
                len(root_page)!=0x4000 or any(root_page) or
                len(child_page)!=0x4000 or any(child_page)):
                raise ValueError('invalid retired shared detach root')
        elif (len(root)!=16 or any(root[:2]) or root[2]!=19 or root[12]!=v['format'] or
              int.from_bytes(root[4:6],'little')>0xfff9):
            raise ValueError('invalid current shared detach root')
        # sptm_mac_unmap_user_table refuses a detach unless all 16 KiB are
        # zero, so emptiness at detach time is the monitor's own invariant.
        # XNU may then RETYPE the frame and reuse it for anything, so later
        # contents prove nothing; only a frame that is still an unowned
        # shared table of the detached level must still be empty.
        if len(child)!=16 or any(child[:2]):
            raise ValueError('last detached child has in-flight state')
        if (child[2]==21 and not any(child[6:8]) and
            (child[4]!=v['level']+1 or any(child[8:16]) or any(read(v['child'],0x4000)))):
            raise ValueError('last detached child is not empty and unowned')
        parent=meta(v['slot']&~0x3fff);off=6 if (v['slot']&~0x3fff)==v['root'] else 8
        if int.from_bytes(parent[off:off+2],'little')!=v['parent_count']-1:
            raise ValueError('shared detach parent count mismatch')
    return dict(calls=calls,retained_records=len(rows),records=rows,
        current_bindings=int.from_bytes(root[4:6],'little') if rows else 0,
        retired_root=retired_root)
def covers(report,root,va):
    return any(r['root']==root and r['base']<=va<r['base']+r['size'] for r in report.get('records',[]))

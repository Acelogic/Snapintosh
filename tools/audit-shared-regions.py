#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Independently reconcile private SPTM range records with guest frame metadata."""
import struct

LIMIT=255

def audit_shared_regions(blob, configurations, metadata):
    """metadata contains every managed type19 frame as {physical_address: bytes}."""
    def require(ok, why):
        if not ok:
            raise ValueError('SPTM shared regions: '+why)
    require(len(blob)==LIMIT*32, 'registry size')
    require(0<=configurations<=0xffffffffffffffff, 'configuration counter')
    expected={}
    for root, f in metadata.items():
        require(root>0 and root%0x4000==0, 'unaligned root')
        require(len(f)==16 and f[2]==19, 'root type')
        require(f[0:2]==b'\0\0' and not any(f[i] for i in [9,10,11,13,14,15]),
                'root metadata state')
        require(f[8]<LIMIT and f[12] in (0,1), 'root slot/format')
        require(f[8] not in expected, 'duplicate root slot')
        expected[f[8]]=(root,f[12])
    entries=[];seen=set()
    for slot in range(LIMIT):
        state,start,size,root=struct.unpack_from('<4Q',blob,slot*32)
        if state==0:
            require(start==size==root==0, 'dirty free slot')
            require(slot not in expected, 'missing allocated slot')
            continue
        require(state in (1,3), 'invalid or transitional slot state')
        require(slot in expected and expected[slot][0]==root, 'slot owner')
        require(root not in seen, 'duplicate owner')
        seen.add(root)
        fmt=expected[slot][1];page=0x1000 if fmt else 0x4000
        if state==1:
            require(start==size==0, 'unconfigured range is not empty')
        else:
            require(0<size<=1<<36 and start%page==size%page==0, 'range geometry')
            require(start<1<<47 and start+size<=1<<47, 'range virtual bounds')
        entries.append(dict(slot=slot,state=state,root=hex(root),format=fmt,
                            page_size=page,start=hex(start),size=hex(size),end=hex(start+size)))
    require(seen==set(metadata), 'root inventory')
    configured=sum(e['state']==3 for e in entries)
    require(configured<=configurations, 'counter below live configuration count')
    return dict(configurations=configurations,configured=configured,entries=entries)

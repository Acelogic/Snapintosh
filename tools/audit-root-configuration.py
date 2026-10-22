#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Validate configuration history separately from its current root metadata."""
import struct

def audit_root_configuration(blob,metadata):
    if len(blob)!=64:raise ValueError('root configuration size')
    calls,changes,root,value,mask,before,after,reserved=struct.unpack('<8Q',blob)
    if reserved or changes>calls:raise ValueError('root configuration counters')
    if not calls:
        if any((changes,root,value,mask,before,after)):raise ValueError('dirty unused configuration record')
    else:
        if not root or root&0x3fff or (value|mask)>0xffff or (value|mask)&0xfea4 or mask&~11:
            raise ValueError('root configuration arguments')
        if (before|2)&~9 not in (2,6,0x22) or after!=((before&~mask)|(value&mask)):
            raise ValueError('root configuration transition')
        if before!=after and not changes:raise ValueError('missing configuration change')
    f=metadata.get(root)
    # A retained history record need not still name a live root: it may have
    # been retired/reused. Report agreement explicitly rather than confusing
    # the last operation with current ownership.
    matches=bool(f and len(f)==16 and f[2]==18 and int.from_bytes(f[10:12],'little')==after)
    return dict(calls=calls,changes=changes,root=hex(root),value=hex(value),mask=hex(mask),
                before=hex(before),after=hex(after),last_matches_current=matches,
                current_metadata=f.hex() if f else None)

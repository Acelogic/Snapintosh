#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Bounded read-only AArch64 user frame candidates from an audited active root.

The caller supplies the current root's reader. Stripping a return-address PAC
is for symbol lookup only; this does not authenticate it or prove a call chain.
Optimized/frameless code may make the chain incomplete.
"""
import struct

USER_LIMIT=1<<47


def collect(read,fp,limit=32):
    if not 1<=limit<=32:raise ValueError('invalid user frame bound')
    rows=[];reason='frame limit'
    for _ in range(limit):
        if not 0<fp<USER_LIMIT-16 or fp&15:
            reason='non-user or unaligned frame pointer';break
        try:raw=read(fp,16)
        except ValueError as error:reason=str(error);break
        if len(raw)!=16:raise ValueError('short user frame read')
        previous,lr=struct.unpack('<2Q',raw)
        # T0SZ=17 is independently checked by the stopped CPU/root capture.
        pc=lr&(USER_LIMIT-1)
        row=dict(fp=hex(fp),previous_fp=hex(previous),raw_lr=hex(lr),
                 lookup_pc=hex(pc),return_address_authenticated=False)
        if 4<=pc<USER_LIMIT and not pc&3:
            try:
                size=min(64,0x4000-((pc-4)&0x3fff))
                code=read(pc-4,size)
                if len(code)!=size:raise ValueError('short user code read')
                row['return_site_va']=hex(pc-4)
                row['return_site_hex']=code.hex()
            except ValueError as error:row['return_site_error']=str(error)
        else:row['return_site_error']='unaligned or null return address'
        rows.append(row)
        if not previous:
            reason='null parent';break
        if previous<=fp or previous-fp>0x4000:
            reason='non-monotonic or distant parent';break
        fp=previous
    return dict(frames=rows,end=reason,
                boundary='ABI frame candidates; PAC stripped for lookup, not authenticated')

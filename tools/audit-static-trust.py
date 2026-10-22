#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Independently decode the boot cache, token view and matched-entry bitmap."""
import hashlib
import struct


def audit_static_trust(read, cache, state_blob, spec, dynamic_expected=None):
    pa,va,size=cache
    if not pa:
        if va or size or any(state_blob):
            raise ValueError('unexpected trust state without a boot cache')
        return dict(loaded=False)
    if not spec or len(state_blob)!=616:
        raise ValueError('missing trust profile or wrong state layout')
    initialized,entries,queries,hits,misses,kind,length,status,cdhash,module,entry=struct.unpack(
        '<8Q24s2Q',state_blob[:104])
    if initialized!=1 or entries!=spec.entries or queries!=hits+misses:
        raise ValueError('invalid static trust counters')
    payload=read(pa+0x4000,size)
    spec.verify(payload)
    runtime=read(pa,0x4000)
    expected=bytearray(0x4000)
    struct.pack_into('<Q',expected,0x10,va+0x100)
    struct.pack_into('<Q',expected,0x20,va+0x80)
    struct.pack_into('<QQ',expected,0x110,size,va+0x4000)
    dynamic=dict(loaded=False)
    copies=[] if dynamic_expected is None else ([(13,dynamic_expected)] if isinstance(dynamic_expected,bytes) else dynamic_expected)
    if len(copies)>3:raise ValueError('too many dynamic copies')
    dynamic_rows=[];dynamic_tokens={};at=0x2000;previous=0
    for i,(typ,d) in enumerate(copies):
        if not 24<=len(d)<=8192 or struct.unpack_from('<I',d)[0]!=2:
            raise ValueError('invalid independently authenticated dynamic cache')
        if typ not in (13,14,27) or at+len(d)>0x4000:raise ValueError('invalid dynamic type/storage')
        count=struct.unpack_from('<I',d,20)[0]
        if 24+24*count>len(d):raise ValueError('truncated dynamic entries')
        mod=0x200+32*i
        struct.pack_into('<Q',expected,0x80,va+mod)
        struct.pack_into('<4Q',expected,mod,previous,typ,len(d),va+at)
        expected[at:at+len(d)]=d
        dynamic_tokens[va+mod]=(d,count,at)
        dynamic_rows.append(dict(type=typ,entries=count,bytes=len(d),uuid=d[4:20].hex(),
            payload_sha256=hashlib.sha256(d).hexdigest(),module=hex(va+mod),payload=hex(va+at)))
        previous=va+mod;at=(at+len(d)+15)&~15
    if copies:
        dynamic=dict(loaded=True,count=len(copies),caches=dynamic_rows,
            entries=sum(c['entries'] for c in dynamic_rows),bytes=sum(c['bytes'] for c in dynamic_rows))
    if runtime!=expected:
        raise ValueError('guest-visible trust runtime/module disagrees with boot cache')
    bits=int.from_bytes(state_blob[104:],'little')
    if bits>>entries or bits.bit_count()>hits:
        raise ValueError('invalid matched trust-cache entry bitmap')
    bitmap_entries=min(entries,8*len(state_blob[104:]))
    matched=[]
    for i in range(bitmap_entries):
        if bits&(1<<i):
            row=payload[24+24*i:48+24*i]
            matched.append(dict(index=i,cdhash=row[:20].hex(),hash_type=row[20],
                                flags=row[21],category=struct.unpack_from('<H',row,22)[0]))
    if queries:
        if kind>3 or not length or any(cdhash[20:]):
            raise ValueError('malformed last trust query')
        if status==0x1000000000:
            is_dynamic=module in dynamic_tokens
            queried,limit,begin=dynamic_tokens[module] if is_dynamic else (payload,entries,0x4000)
            index=(entry-va-begin-24)//24
            if (not hits or (not is_dynamic and module!=va+0x100) or
                    kind not in ((0,2) if is_dynamic else (0,1)) or not 0<=index<limit or
                    entry!=va+begin+24+24*index or
                    (not is_dynamic and index<bitmap_entries and not bits&(1<<index)) or
                    queried[24+24*index:44+24*index]!=cdhash[:20]):
                raise ValueError('successful trust token does not identify the queried entry')
        elif status!=(0x1241100000003 if kind else 0x1241200000003) or module or entry:
            raise ValueError('unexpected trust miss/status token')
    return dict(loaded=True,entries=entries,payload_sha256=hashlib.sha256(payload).hexdigest(),
                queries=queries,hits=hits,misses=misses,matched=matched,
                matched_bitmap_entries=bitmap_entries,
                matched_bitmap_complete=bitmap_entries==entries,
                last_kind=kind,last_length=length,last_status=hex(status),
                last_cdhash=cdhash[:20].hex(),last_module=hex(module),last_entry=hex(entry),
                pa=hex(pa),va=hex(va),size=size,dynamic=dynamic)

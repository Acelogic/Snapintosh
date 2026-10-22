#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Independently compare guest user tables with their hardware4K shadows."""
import struct

def audit(read,*,cache,active,ram_low,ram_high,work_low,work_high,sprr=None,translated_tpro=False,
          diagnose_mismatches=False,loaded=None,shared_pages=frozenset()):
    """shared_pages: shared-region group tables (SNAP_NATIVE_SHARED), which every
    nesting root's shadow reaches; every other shadow table belongs to one root."""
    all_shadow_pages=set()
    def walk(root,shift,limit,low,high,hardware=False):
        pages=set();leaves={};history={}
        def visit(pa,level,base):
            size=1<<shift
            if pa&(size-1) or not low<=pa<pa+size<=high or pa in pages or len(pages)>=8192:
                raise ValueError('invalid or aliased table in user-shadow audit')
            pages.add(pa)
            data=read(pa,size)
            if len(data)!=size:raise ValueError('short table read')
            span=1<<(shift+(3-level)*(shift-3))
            for i,pte in enumerate(struct.unpack(f'<{size//8}Q',data)):
                if not pte&1:continue
                va=base+i*span
                if level<3 and pte&2:
                    visit(pte&((1<<48)-size),level+1,va)
                else:
                    if level!=3 or not pte&2 or va+span>limit:
                        raise ValueError('unexpected block or out-of-range user leaf')
                    target=pte&((1<<48)-size)
                    attrs=pte&(0xfff|(3<<53))
                    if hardware and pte&(1<<59):
                        raise ValueError('software WAS_WRITABLE leaked into hardware shadow')
                    for off in range(0,span,4096):
                        leaves[va+off]=(target+off,attrs)
                        if pte&(1<<59):history[va+off]=(target+off,attrs)
        visit(root,1 if shift==14 else 0,0)
        return pages,leaves,history
    rows=[];roots=set();asids=set()
    for c in cache:
        if not c['valid']:continue
        root=c['root'];asid=c['asid'];shadow=c['shadow'];fmt=c['format'];flags=c['flags']
        if (root in roots or asid in asids or not asid or fmt not in (0,1) or
                (flags|2)&~9 not in (2,6,0x22) or (flags&4 and fmt!=1)):
            raise ValueError('invalid cached root identity')
        roots.add(root);asids.add(asid)
        limit=1<<(32 if flags&0x20 else 47)
        source_pages,expected,history=walk(root,12 if fmt else 14,limit,ram_low,ram_high)
        if any((((attrs>>4)&12)|((attrs>>53)&3)) not in (7,15) for _,attrs in history.values()):
            raise ValueError('WAS_WRITABLE source is not an ordinary NX user class')
        for _,attrs in expected.values():
            selector=((attrs>>4)&12)|((attrs>>53)&3)
            if selector not in (3,7,10,11,13,15) and not (
                    translated_tpro and flags&8 and selector==9):
                raise ValueError('source requires SPRR permission translation')
        shadow_pages,actual,_=walk(shadow,12,1<<47,work_low,work_high,hardware=True)
        differing = sorted(va for va in expected.keys() | actual.keys()
                           if expected.get(va) != actual.get(va))
        if differing and not diagnose_mismatches:
            raise ValueError('user shadow differs from source mappings or exposes extra leaves')
        guest_pages=len(expected)//(4 if fmt==0 else 1)
        if c['leaves']!=guest_pages and not diagnose_mismatches:
            raise ValueError('cached user leaf count differs from source mappings')
        own_pages=shadow_pages-set(shared_pages)
        if own_pages&all_shadow_pages:raise ValueError('user caches share private table storage')
        all_shadow_pages.update(own_pages)
        rows.append(dict(root=hex(root),shadow=hex(shadow),asid=asid,format=fmt,flags=hex(flags),
            source_tables=len(source_pages),shadow_tables=len(shadow_pages),mapped_4k_pages=len(actual),
            mapped_guest_pages=guest_pages,
            mappings_equal=not differing, mismatch_count=len(differing),
            first_mismatches=[dict(va=hex(va), expected=expected.get(va), actual=actual.get(va))
                              for va in differing[:16]],
            cached_leaf_count=c['leaves'], cached_leaf_count_equal=c['leaves']==guest_pages,
            was_writable_4k_pages=len(history),
            was_writable_sample=[dict(va=hex(va),pa=hex(pa)) for va,(pa,_) in sorted(history.items())[:16]],
            hardware_history_bits_absent=True,
            active_cpus=[i for i,v in enumerate(active) if v==root]))
    if any(root and root not in roots for root in active):raise ValueError('active root has no valid shadow')
    result=dict(roots=rows,private_table_pages=len(all_shadow_pages),
                mappings_equal=all(r['mappings_equal'] for r in rows),
                cached_leaf_counts_equal=all(r['cached_leaf_count_equal'] for r in rows),
                active=[hex(v) for v in active])
    if sprr is None:
        if any(c['valid'] and c['root'] in active and c['flags']&9 for c in cache):
            raise ValueError('active modified root is missing SPRR readback')
        return result
    if len(sprr)!=len(active) or len(active)!=6:raise ValueError('SPRR CPU count differs')
    if loaded is not None and len(loaded)!=len(active):raise ValueError('loaded policy CPU count differs')
    for cpu,state in enumerate(sprr):
        flags=next((c['flags'] for c in cache if c['valid'] and c['root']==active[cpu]),0)
        if loaded is not None:
            row=loaded[cpu]
            if (row['root']!=active[cpu] or row['resets']!=state['resets'] or
                    (row['flags']^flags)&~1 or (not active[cpu] and row['flags'])):
                raise ValueError('loaded policy identity or sequence differs')
            flags=row['flags']
        wanted=((flags&8)<<15)|((flags&1)<<11)
        # Selector2 A/B affects the kernel aperture, audited independently by
        # audit-kernel-permissions.py against each CPU's installed TTBR1 view.
        if (state['uperm']&~(1<<36),state['pperm']&~(0x100|(1<<36)),state['umprr'],state['pmprr']) != (
                0x2010002030100000,0x2020a52a302abae6,wanted,0x40010):
            raise ValueError('SPRR register state disagrees with active root')
        if state['uperm']&(1<<36) and wanted&0xc0000!=0x40000:
            raise ValueError('TPRO writable state lacks the enabled root policy')
        if not state['resets'] or state['rejected']>state['writes']:
            raise ValueError('SPRR lifecycle counters are invalid')
    result['sprr']=sprr
    if loaded is not None:result['loaded']=loaded
    return result

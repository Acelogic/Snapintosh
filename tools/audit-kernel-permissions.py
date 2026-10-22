#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Independently validate the resident sparse kernel permission views.

Walks canonical tables, verifies every private table entry and rejects any
selector2 reachable through a shared table. Does not execute monitor helpers.
"""
import struct

OA=0x0000fffffffff000
NX=3<<53
AP=3<<6
PPERM=0x2020a52a302abae6
MASK47=(1<<47)-1

def audit(read, *, state, installed, prepared, canonical, pperm, work_low, work_high):
    def require(ok, why):
        if not ok:raise ValueError(why)
    require(len(state)==8256 and all(len(x)==6 for x in (installed,prepared,canonical,pperm)),
            'kernel permission state geometry')
    root,count,*syncs=struct.unpack_from('<8Q',state)
    require(1<=count<=128 and all(s>0 for s in syncs),'private view count or syncs')
    rows=[struct.unpack_from('<8Q',state,64+n*64) for n in range(count)]
    require(not any(state[64+count*64:]),'unused private records are not zero')
    records={r[0]:r for r in rows}
    copies=[pa for r in rows for pa in r[1:7]]
    require(len(records)==count and len(set(copies))==6*count,'aliased private storage')
    require(not set(records)&set(copies),'private storage aliases canonical tables')
    require(rows[0][0]==root and rows[0][7]==0 and all(r==root for r in canonical),
            'canonical root differs')
    require(all((v&~(0x100|(1<<36)))==PPERM for v in pperm),'unsupported PPERM')
    require(all(installed[i]==(rows[0][1+i] if prepared[i] else 0) for i in range(6)),
            'installed TTBR1 differs from private root')
    cache={}
    def page(pa):
        require(pa and not pa&4095 and work_low<=pa and pa+4096<=work_high,
                'kernel table outside allocated arena')
        if pa not in cache:
            data=read(pa,4096);require(len(data)==4096,'short table read')
            cache[pa]=struct.unpack('<512Q',data)
        return cache[pa]
    seen={};protected={};readonly={};txm_apertures={};private_paths=set();selector_pages={}
    def walk(pa,level,prefix,private):
        require(pa not in seen,'canonical table reused or cyclic')
        require(pa not in copies,'canonical tree points into private storage')
        seen[pa]=level
        row=records.get(pa)
        if row:require(row[7]==level,'private table level differs')
        # Every ancestor of a protected table must be private too.
        private=private and row is not None
        if private:private_paths.add(pa)
        for index,d in enumerate(page(pa)):
            if not d&1:continue
            require(level or index<256,'valid entry beyond T1SZ')
            va=prefix|(index<<(12+9*(3-level)))
            if level<3 and d&3==3:
                require(d&~OA==3,'unsupported table attributes')
                walk(d&OA,level+1,va,private)
                continue
            require(level>0 and d&3==(3 if level==3 else 1),'invalid leaf descriptor')
            size=1<<(12+9*(3-level))
            require(not (d&OA)&(size-1),'unaligned leaf')
            selector=((d>>4)&12)|((d>>53)&3)
            require(selector!=9,'untranslated selector9 in kernel view')
            key=str(selector);selector_pages[key]=selector_pages.get(key,0)+size//4096
            if selector==11:readonly[va|(~MASK47&((1<<64)-1))]=d&OA
            if selector in (2,4):
                require(level==3 and private,'protected selector exposed through shared table')
                target=protected if selector==2 else txm_apertures
                target[va|(~MASK47&((1<<64)-1))]=d&OA
    walk(root,0,0,True)
    for source,row in records.items():
        # Retained copies may become unreachable after a canonical unmap.
        # They must still match their canonical source for safe later reuse.
        level=row[7];require(level<=3,'private record level')
        for cpu in range(6):
            actual=page(row[1+cpu])
            for index,d in enumerate(page(source)):
                wanted=d
                if d&1:
                    if level<3 and d&3==3 and d&OA in records:
                        child=records[d&OA]
                        require(child[7]==level+1,'private child level')
                        wanted=child[1+cpu]|3
                    elif ((d>>4)&12)|((d>>53)&3) in (2,4):
                        require(level==3,'protected block unsupported')
                        selector=((d>>4)&12)|((d>>53)&3)
                        writable=selector==2 and pperm[cpu]&0x100
                        wanted=(d&~(AP|NX))|NX|(0 if writable else 2<<6)
                require(actual[index]==wanted,
                        f'CPU{cpu} private descriptor mismatch at {source:#x}+{index*8:#x}')
    return dict(canonical_root=hex(root),canonical_tables=len(seen),
                canonical_table_pages=[hex(pa) for pa in sorted(seen)],
                private_table_pages=[hex(pa) for pa in sorted(copies)],
                private_source_tables=count,private_copy_pages=len(copies),syncs=syncs,
                installed=[hex(p) for p in installed],pperm=[hex(p) for p in pperm],
                protected_4k_pages=len(protected),protected=protected,readonly=readonly,
                txm_aperture_4k_pages=len(txm_apertures),txm_apertures=txm_apertures,
                selector_4k_pages=selector_pages,
                private_descriptors_verified=True,shared_selector2_absent=True)

def audit_aperture(read, *, protected, root, frame_map, frame_low, aperture_low,
                   aperture_va, aperture_size,readonly=None,moved=(),txm_apertures=None):
    """Cross-check protection against independent 16K source PTEs and types.

    moved lists SLIDE_REGION's (va, pa, pages) ranges inside the slide window.
    A frame in one also has that alias, XNU's phystokv address and the only
    one Apple keeps; it must carry the same selector as the linear alias."""
    pages={}
    def descriptor(va):
        table=root
        for level in (1,2,3):
            if table not in pages:
                data=read(table,16384)
                if len(data)!=16384:raise ValueError('short source aperture table')
                pages[table]=struct.unpack('<2048Q',data)
            d=pages[table][(va>>(14+11*(3-level)))&2047]
            if d&3!=3:raise ValueError('source aperture is not a 16K page')
            if level==3:return d
            table=d&0x0000ffffffffc000
    expected={};executable={};txm={};frames={25:0,14:0,42:0};moved_aliases=0
    for off in range(0,len(frame_map),16):
        kind=frame_map[off+2]
        if kind not in (14,25,42):continue
        pa=frame_low+(off//16)*16384
        if not aperture_low<=pa<aperture_low+aperture_size:
            raise ValueError('ROZONE frame outside aperture')
        aliases=[aperture_va+pa-aperture_low]+[
            mva+pa-mpa for mva,mpa,npages in moved if mpa<=pa<mpa+npages*16384]
        frames[kind]+=1;moved_aliases+=len(aliases)-1
        for va in aliases:
            d=descriptor(va)
            selector={25:2,14:11,42:4}[kind]
            if d&0x0000ffffffffc000!=pa or ((d>>4)&12)|((d>>53)&3)!=selector:
                raise ValueError('protected source aperture descriptor differs')
            target=expected if kind==25 else txm if kind==42 else executable
            for n in range(4):target[va+4096*n]=pa+4096*n
    if protected!=expected:raise ValueError('protected views differ from ROZONE frame types')
    if any((readonly or {}).get(va)!=pa for va,pa in executable.items()):
        raise ValueError('USER_EXEC privileged alias is not read-only')
    if (txm_apertures or {})!=txm:
        raise ValueError('TXM_DEFAULT private apertures differ from typed frames')
    return dict(rozone_frames=frames[25],source_tables=len(pages),
                user_exec_frames=frames[14],txm_default_frames=frames[42],moved_aliases=moved_aliases,
                frame_types_and_source_pte_verified=True)

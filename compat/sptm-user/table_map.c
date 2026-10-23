/* SPDX-License-Identifier: MIT */
/* User table map, unmap and condemn, the leaf policy and MAP_PAGE.
 * Part of compat/sptm-user.c's translation unit, included in order; not compiled on its own. */
enum sptm_result sptm_mac_map_user_table(const struct sptm_memory *m,uint64_t root,
                                       uint64_t va,uint64_t level,uint64_t tte)
{
    const struct sptm_user_backend inactive={.ttbr0=0,.ttbr1=0};
    return sptm_mac_map_user_table_live(m,&inactive,root,va,level,tte);
}
enum sptm_result sptm_mac_map_user_table_live(const struct sptm_memory *m,
    const struct sptm_user_backend *b,uint64_t root,uint64_t va,uint64_t level,uint64_t tte)
{
    struct sptm_user_geometry g;volatile uint8_t *root_meta;
    enum sptm_result r=config(m,b,root,va,&g,&root_meta,1);if(r) return r;
    if(root_meta[2]==SPTM_MAC_SHARED_ROOT_TABLE)level=(uint8_t)level;
    if(level<g.start || level>2) return SPTM_BAD_TABLE;
    if(sptm_mac_user_index(&g,(unsigned)level,va)&(g.group-1)) return SPTM_BAD_ADDRESS;
    uint64_t child=tte&PA_MASK;
    if((tte&~PA_MASK)!=3 || child==root) return SPTM_BAD_TABLE;
    volatile uint8_t *child_meta;
    r=metadata(m,child,&child_meta);if(r) return r;
    unsigned table_type=root_meta[2]==SPTM_MAC_SHARED_ROOT_TABLE ? SPTM_MAC_PAGE_TABLE_SHARED : SPTM_MAC_PAGE_TABLE;
    int comm=table_type==SPTM_MAC_PAGE_TABLE && child_meta[2]==SPTM_MAC_PAGE_TABLE_COMMPAGE && level==2;
    if((child_meta[2]!=table_type && !comm) || child_meta[4]!=level+1)
        return SPTM_TYPE_MISMATCH;
    if(comm && !sptm_mac_commpage_table_va(root_meta[10],va)) return SPTM_BAD_ADDRESS;
    uint64_t links=get(child_meta+6,2),leaves=get(child_meta+8,2);
    if(!comm && (links || leaves)) return SPTM_FRAME_BUSY;
    if(comm && links>=0xfff9)return SPTM_BAD_REFERENCE;
    volatile uint8_t *page=m->map(m->ctx,child,PAGE_SIZE);
    if(!page) return SPTM_MEMORY_UNAVAILABLE;
    if(!comm) {
        for(unsigned i=0;i<PAGE_SIZE;i++) if(page[i]) return SPTM_BAD_TABLE;
    } else {
        if(!m->refs || (!!b->prepare_attach!=!!b->commit_attach) ||
           (leaves && b->active_refs && !b->prepare_attach))return SPTM_BAD_CONFIG;
        uint64_t base=va&~((2048*g.page_size)-1);unsigned valid=0;
        sptm_refs_begin(m->refs);
        for(unsigned i=0;i<2048;i++) {
            uint64_t pte=get(page+8*i,8),addr=base+i*g.page_size;
            if(!pte)continue;
            if((pte&3)!=3 || addr>=g.va_limit)return SPTM_BAD_TABLE;
            volatile uint8_t *data;
            r=metadata(m,pte&PA_MASK,&data);if(r)return r;
            r=sptm_mac_user_leaf_policy(root_meta[10],child_meta[2],data[2],addr,pte,&g);
            if(r)return r;
            if(!m->map(m->ctx,pte&g.pa_mask,g.page_size))return SPTM_MEMORY_UNAVAILABLE;
            /* A hypothetical removal validates all retained references,
             * including repeated aliases. Never commit these deltas. */
            r=sptm_refs_leaf(m,child,addr,pte,0);if(r)return r;
            valid++;
        }
        if(valid!=leaves)return SPTM_BAD_REFERENCE;
        r=sptm_refs_validate(m);if(r)return r;
    }
    volatile uint8_t *slot,*parent_meta;uint64_t slot_pa;
    r=walk(m,root,&g,va,(unsigned)level,0,&slot,&slot_pa,&parent_meta);if(r) return r;
    if(child==(slot_pa&PA_MASK)) return SPTM_BAD_TABLE;
    for(unsigned n=0;n<g.group;n++) {
        uint64_t old=get(slot+n*8,8);
        if(old&1) return SPTM_TABLE_EXISTS;
        if(old) return SPTM_BAD_TABLE;
    }
    unsigned parent_offset=level==g.start ? 6 : 8;
    uint64_t count=get(parent_meta+parent_offset,2);
    unsigned capacity=level==2 && table_type==SPTM_MAC_PAGE_TABLE ? 2048 : 2048/g.group;
    if(count>=(level==g.start ? g.root_groups+b->active_refs : capacity))
        return SPTM_BAD_REFERENCE;
    if(comm && b->prepare_attach &&
       !b->prepare_attach(b->ctx,root,va,g.shift,child))return SPTM_SHADOW_FAILED;
    put(child_meta+6,links+1,2);put(parent_meta+parent_offset,count+1,2);
    m->publish(m->ctx,m->frame_map_pa+((child-m->frame_low)>>14)*16,16);
    m->publish(m->ctx,m->frame_map_pa+(((slot_pa&PA_MASK)-m->frame_low)>>14)*16,16);
    for(unsigned n=0;n<g.group;n++) put(slot+n*8,(child+n*g.page_size)|3,8);
    m->publish(m->ctx,slot_pa,g.group*8);
    if(comm && b->commit_attach &&
       !b->commit_attach(b->ctx,root,va,g.shift,child))return SPTM_SHADOW_FAILED;
    return SPTM_OK;
}
enum sptm_result sptm_mac_unmap_user_table(const struct sptm_memory *m,
    const struct sptm_user_backend *b,uint64_t root,uint64_t va,uint64_t level)
{
    if(b && b->active_refs && (!b->prepare_detach || !b->commit_detach))return SPTM_FRAME_BUSY;
    struct sptm_user_geometry g;volatile uint8_t *root_meta;
    enum sptm_result r=config(m,b,root,va,&g,&root_meta,3);if(r) return r;
    if(root_meta[2]==SPTM_MAC_SHARED_ROOT_TABLE)level=(uint8_t)level;
    if(!!b->prepare_detach!=!!b->commit_detach)return SPTM_BAD_CONFIG;
    if(root_meta[2]==SPTM_MAC_SHARED_ROOT_TABLE && get(root_meta+4,2) &&
       !b->prepare_detach)return SPTM_BAD_CONFIG;
    if(level<g.start || level>2) return SPTM_UNSUPPORTED_OPTIONS;
    if(sptm_mac_user_index(&g,(unsigned)level,va)&(g.group-1)) return SPTM_BAD_ADDRESS;
    volatile uint8_t *slot,*parent_meta,*child_meta;uint64_t slot_pa;
    r=walk(m,root,&g,va,(unsigned)level,1,&slot,&slot_pa,&parent_meta);if(r) return r;
    uint64_t tte=get(slot,8),child=tte&PA_MASK;
    if(!tte) return SPTM_TABLE_MISSING;
    uint64_t attrs=tte&~PA_MASK;
    if((attrs!=3 && !(level==2 && attrs==7)) || child==root || child==(slot_pa&PA_MASK))
        return SPTM_BAD_TABLE;
    for(unsigned n=1;n<g.group;n++)
        if(get(slot+n*8,8)!=((child+n*g.page_size)|attrs)) return SPTM_BAD_TABLE;
    r=metadata(m,child,&child_meta);if(r) return r;
    unsigned table_type=root_meta[2]==SPTM_MAC_SHARED_ROOT_TABLE ? SPTM_MAC_PAGE_TABLE_SHARED : SPTM_MAC_PAGE_TABLE;
    int comm=table_type==SPTM_MAC_PAGE_TABLE && child_meta[2]==SPTM_MAC_PAGE_TABLE_COMMPAGE && level==2;
    if((comm || table_type==SPTM_MAC_PAGE_TABLE_SHARED) && attrs==7)return SPTM_BAD_TABLE;
    if((child_meta[2]!=table_type && !comm) || child_meta[4]!=level+1)
        return SPTM_TYPE_MISMATCH;
    uint64_t links=get(child_meta+6,2);
    if(comm ? (!links || links>0xfff9) : links!=1) return SPTM_BAD_REFERENCE;
    unsigned parent_offset=level==g.start ? 6 : 8;
    uint64_t count=get(parent_meta+parent_offset,2);
    unsigned cpu_refs=level==g.start ? b->active_refs:0;
    unsigned capacity=level==2 && table_type==SPTM_MAC_PAGE_TABLE ? 2048 : 2048/g.group;
    if(count<=cpu_refs || count>(level==g.start ? g.root_groups+cpu_refs : capacity))
        return SPTM_BAD_REFERENCE;
    volatile uint8_t *page=m->map(m->ctx,child,PAGE_SIZE);
    if(!page) return SPTM_MEMORY_UNAVAILABLE;
    unsigned valid=0;
    if(!comm) {
        /* Ordinary/shared tables must be empty before detachment (SPTM ...ed11c).
         * Type-23 instead takes ...ec958 and retains its populated leaves. */
        if(get(child_meta+8,2)) return SPTM_FRAME_BUSY;
#if SNAP_DETACH_FAST
        /* The same bytes, eight at a time (the page is 16K aligned). */
        for(unsigned i=0;i<PAGE_SIZE;i+=8) if(*(volatile uint64_t *)(void *)(page+i)) return SPTM_FRAME_BUSY;
#else
        for(unsigned i=0;i<PAGE_SIZE;i++) if(page[i]) return SPTM_FRAME_BUSY;
#endif
    } else {
        for(unsigned i=0;i<PAGE_SIZE;i+=8) {
            uint64_t pte=get(page+i,8);
            if(pte && (pte&3)!=3) return SPTM_BAD_TABLE;
            valid+=(pte&3)==3;
        }
        if(valid!=get(child_meta+8,2)) return SPTM_BAD_REFERENCE;
    }
    if(b->prepare_detach && !b->prepare_detach(b->ctx,root,va,g.shift,(unsigned)level,valid))
        return SPTM_SHADOW_FAILED;
    for(unsigned n=0;n<g.group;n++) put(slot+n*8,0,8);
    m->publish(m->ctx,slot_pa,g.group*8);
    if(b->commit_detach && !b->commit_detach(b->ctx,root,va,g.shift,(unsigned)level,valid))
        return SPTM_SHADOW_FAILED;
    put(child_meta+6,links-1,2);
    put(parent_meta+parent_offset,count-1,2);
    m->publish(m->ctx,m->frame_map_pa+((child-m->frame_low)>>14)*16,16);
    m->publish(m->ctx,m->frame_map_pa+(((slot_pa&PA_MASK)-m->frame_low)>>14)*16,16);
    if(table_type==SPTM_MAC_PAGE_TABLE_SHARED && b->shared_detaches) {
        struct sptm_shared_detach_state *s=b->shared_detaches;
        struct sptm_shared_detach_record *v=&s->records[s->calls%SPTM_SHARED_DETACH_HISTORY];
        v->root=root;v->va=va;v->slot=slot_pa;v->child=child;v->format=root_meta[12];
        v->level=level;v->parent_count=count;v->bindings=get(root_meta+4,2);
        s->calls++;
    }
    return SPTM_OK;
}
enum sptm_result sptm_mac_condemn_user_table(const struct sptm_memory *m,
    const struct sptm_user_backend *b,uint64_t root,uint64_t va,unsigned condemn,
    uint64_t *guest_result)
{
    struct sptm_user_geometry g;volatile uint8_t *root_meta;
    enum sptm_result r=config(m,b,root,va,&g,&root_meta,0);if(r)return r;
    if(!guest_result)return SPTM_BAD_CONFIG;
    if(condemn>1)return SPTM_UNSUPPORTED_OPTIONS;
    if(sptm_mac_user_index(&g,2,va)&(g.group-1))return SPTM_BAD_ADDRESS;
    volatile uint8_t *slot,*parent_meta,*child_meta;uint64_t slot_pa;
    r=walk(m,root,&g,va,2,1,&slot,&slot_pa,&parent_meta);if(r)return r;
    uint64_t tte=get(slot,8),attrs=tte&~PA_MASK,child=tte&PA_MASK;
    if(!tte || attrs==7) {
        if(condemn) {*guest_result=7;return SPTM_OK;}
        if(!tte)return SPTM_BAD_TABLE;
    }
    if(attrs!=(condemn ? 3u:7u) || child==root || child==(slot_pa&PA_MASK))return SPTM_BAD_TABLE;
    r=metadata(m,child,&child_meta);if(r)return r;
    if(child_meta[2]!=SPTM_MAC_PAGE_TABLE || child_meta[4]!=3)return SPTM_TYPE_MISMATCH;
    if(get(child_meta+6,2)!=1 || get(child_meta+8,2)>2048)return SPTM_BAD_REFERENCE;
    /* Global service serialization replaces Apple's grouped CAS/rollback.
     * Preflight every member before any lifetime bit is changed. */
    for(unsigned n=1;n<g.group;n++) {
        uint64_t old=get(slot+n*8,8),expected=(child+n*g.page_size)|attrs;
        if(old!=expected) {
            if(condemn && old==(expected|4)) {*guest_result=7;return SPTM_OK;}
            return SPTM_BAD_TABLE;
        }
    }
    for(unsigned n=0;n<g.group;n++)put(slot+n*8,(child+n*g.page_size)|(condemn ? 7:3),8);
    m->publish(m->ctx,slot_pa,g.group*8);
    *guest_result=0;return SPTM_OK;
}
enum sptm_result sptm_mac_user_leaf_policy(unsigned flags,unsigned table_type,
    unsigned data_type,uint64_t va,uint64_t pte,const struct sptm_user_geometry *g)
{
    uint64_t attrs=pte&~g->pa_mask;
    if(table_type==SPTM_MAC_PAGE_TABLE_SHARED) {
        /* Shipped type21 admits DEFAULT11 and USER_EXEC14 data. Shared
         * roots allow global mappings; executable policy still requires14. */
        if(data_type==SPTM_MAC_DEFAULT) {
            if((attrs&~(0x80UL|0x300UL|0x400UL|0x800UL|(3UL<<58)))!=0x0060000000000043UL ||
               ((attrs>>8)&3)<2)return SPTM_UNSUPPORTED_OPTIONS;
        } else if(data_type==SPTM_MAC_USER_EXEC) {
            if((attrs&~(0x300UL|0x400UL|0x800UL|(1UL<<58)|(1UL<<54)))!=0x00200000000000c3UL ||
               ((attrs>>8)&3)<2)return SPTM_UNSUPPORTED_OPTIONS;
        } else return SPTM_TYPE_MISMATCH;
        return SPTM_OK;
    }
    if(table_type==SPTM_MAC_PAGE_TABLE &&
       (data_type==SPTM_MAC_DEFAULT || data_type==SPTM_MAC_IO)) {
        /* DEFAULT and XNU_IO share policy +4 =0x8888 (NX classes3/7/11/15).
         * Apple's MAP_PAGE (...270f8f18..f9120) refuses kernel-only
         * classes3/11 and non-nG leaves in user roots, but never inspects
         * AttrIndx (bits4:2) or SH (bits9:8): IOKit user mappings carry
         * write-combined/device attributes (panel VRAM, WC surfaces). Both
         * are copied unchanged into the hardware view. AF, WIRED and history
         * remain source bookkeeping; MAP_PAGE normalizes writable history,
         * whereas UPDATE_DISJOINT can explicitly retain it. */
        if((attrs&~(0x1cUL|0x80UL|0x300UL|0x400UL|(3UL<<58)))!=0x0060000000000843UL)
            return SPTM_UNSUPPORTED_OPTIONS;
        return SPTM_OK;
    }
    if(table_type==SPTM_MAC_PAGE_TABLE && data_type==SPTM_MAC_USER_EXEC) {
        /* Type14's policy bitmap 0xa800 permits classes11/13/15. In user
         * space admit RO+X class13 and RO+NX class15, with nG/AF/normal0
         * and shareability matching the ordinary user mapping contract.
         * WIRED (bit58) is software state Apple admits on every type
         * (pmap_change_wiring sends UPDATE_REGION option1 for mlock). */
        if(((attrs&~(0x300UL|(1UL<<54)|(1UL<<58)))|0x400UL)!=0x0020000000000cc3UL ||
           ((attrs>>8)&3)<2)return SPTM_UNSUPPORTED_OPTIONS;
        return SPTM_OK;
    }
    if(table_type==SPTM_MAC_PAGE_TABLE && data_type==SPTM_MAC_USER_TPRO) {
        /* Type17's 0x8a88 policy includes ordinary user NX classes7/15
         * and dynamic TPRO class9. Raw class9 needs a private hardware view;
         * nG/normal0/shareability match the other user data policies. AF is
         * free here as for type 11 and 14: page aging clears it through
         * UPDATE_DISJOINT (A16: options 0x10a, ...e83 -> ...a83), which only
         * makes the next access fault; the class9 view keeps the bit.
         * WIRED and WAS_WRITABLE are software bits outside the hardware
         * view: Apple's rows 7->23/31, 9->25 and 23/25/31 back apply to
         * type17 exactly as to DEFAULT (policy checks the 4-bit class). */
        uint64_t fixed=(attrs&~(0x300UL|(3UL<<58)))|0x400UL;
        if(fixed!=0x0060000000000c43UL && fixed!=0x0060000000000cc3UL &&
           fixed!=0x0020000000000c83UL)return SPTM_UNSUPPORTED_OPTIONS;
        if(((attrs>>8)&3)<2)return SPTM_UNSUPPORTED_OPTIONS;
        if(fixed==0x0020000000000c83UL && !(flags&SPTM_MAC_ROOT_FLAG_UMPRR18))
            return SPTM_UNSUPPORTED_OPTIONS;
        return SPTM_OK;
    }
    if(table_type!=SPTM_MAC_PAGE_TABLE_COMMPAGE || data_type<29 || data_type>31)
        return SPTM_TYPE_MISMATCH;
    if(!sptm_mac_commpage_va(flags,va))return SPTM_BAD_ADDRESS;
    if(attrs!=0x00600000000007c3UL &&
       !(data_type==31 && attrs==0x00200000000007c3UL))return SPTM_UNSUPPORTED_OPTIONS;
    return SPTM_OK;
}
enum sptm_result sptm_mac_map_user_page(const struct sptm_memory *m,
    const struct sptm_user_backend *b,uint64_t root,uint64_t va,uint64_t pte,
    uint64_t options,uint64_t scratch,uint64_t *guest_result)
{
    struct sptm_user_geometry g;volatile uint8_t *root_meta;
    enum sptm_result r=config(m,b,root,va,&g,&root_meta,2);if(r) return r;
    int shared=root_meta[2]==SPTM_MAC_SHARED_ROOT_TABLE;
    if(shared && (!b->prepare_shared_leaf || !b->commit_shared_leaf))return SPTM_BAD_CONFIG;
    if(!guest_result || !m->refs) return SPTM_BAD_CONFIG;
    if(options&~1UL) return SPTM_UNSUPPORTED_OPTIONS;
    volatile uint8_t *slot,*table_meta;uint64_t slot_pa;unsigned type;
    r=walk(m,root,&g,va,3,0,&slot,&slot_pa,&table_meta);if(r) return r;
    if((table_meta[2]==SPTM_MAC_PAGE_TABLE_SHARED)!=shared)return SPTM_TYPE_MISMATCH;
    r=data_type(m,pte,&g,&type);if(r) return r;
    if(type==SPTM_MAC_USER_TPRO && !m->retype_user_tpro)return SPTM_BAD_CONFIG;
    r=sptm_mac_user_leaf_policy(root_meta[10],table_meta[2],type,va,pte,&g);
    if(r)return r;
    /* Device-window leaves are never dereferenced by the monitor. */
    if(type!=SPTM_MAC_IO && !m->map(m->ctx,pte&g.pa_mask,g.page_size))
        return SPTM_MEMORY_UNAVAILABLE;
    uint64_t old=get(slot,8),requested=pte,response=0;
    if((shared || table_meta[2]==SPTM_MAC_PAGE_TABLE) &&
       old && (old&3)==3 && !((old^pte)&g.pa_mask)) {
        r=sptm_mac_user_leaf_policy(root_meta[10],table_meta[2],type,va,old,&g);
        if(r)return r;
    }
    /* The shipped helper returns identical before normalization; otherwise
     * ...f9240..f92a8 clears WAS_WRITABLE when the new class is writable
     * (0x2a8: classes3/5/7/9), for every data type. */
    if(shared || (table_meta[2]==SPTM_MAC_PAGE_TABLE &&
       (old&3)==3 && !((old^pte)&g.pa_mask))) {
        r=sptm_mac_shared_map_pte(old,pte,&pte,&response);if(r)return r;
    } else if(old!=pte && (0x2a8u&(1u<<(((pte>>4)&12)|((pte>>53)&3)))))pte&=~(1UL<<59);
    int conflict=(old&3)==3 && ((old^pte)&g.pa_mask);
    int replace=!shared && table_meta[2]==SPTM_MAC_PAGE_TABLE &&
        (old&3)==3 && old!=pte && !conflict;
    /* An invalid descriptor without the bit7 in-flight marker (XNU's
     * compressed-page marker, bits63:62) is installed over exactly like an
     * empty slot: ...f92cc/f9290 build the leaf from the request alone and
     * ...f9490/f9574 return 0 after the CAS. XNU's pmap_enter then adds the
     * PV entry the marker never had. Bit7 would be FLUSH_PENDING (2); this
     * monitor never stores it, so it stays refused. */
    int fresh=(old&3)!=3 && !(old&0x80);
    if(!shared && old && old!=pte && !conflict && !replace && !fresh)return SPTM_TABLE_EXISTS;
    if(replace && (table_meta[2]!=SPTM_MAC_PAGE_TABLE ||
       !!b->prepare_update!=!!b->commit_update || (b->active_refs && !b->prepare_update)))
        return SPTM_BAD_CONFIG;
    /* User leaves never use the uncounted kernel physical-aperture shortcut. */
    if(m->aperture_size && va>=m->aperture_va && va-m->aperture_va<m->aperture_size)
        return SPTM_BAD_CONFIG;
    if(conflict || (shared && response==SPTM_USER_MAP_CONFLICT)) {
        unsigned old_type;
        r=data_type(m,old,&g,&old_type);if(r)return r;
        r=sptm_mac_user_leaf_policy(root_meta[10],table_meta[2],old_type,va,old,&g);
        if(r)return r;
    }
    /* A new leaf in a shared commpage needs publication to every cached root.
     * Retained attachment is supported; shared leaf mutation is a separate
     * contract and must not silently leave another root's shadow stale. */
    if(fresh && table_meta[2]==SPTM_MAC_PAGE_TABLE_COMMPAGE && get(table_meta+6,2)>1)
        return SPTM_FRAME_BUSY;
    volatile uint8_t *out=0;uint64_t pointer=0;
    if(!(options&1)) {
        uint64_t map_size=((m->frame_high-m->frame_low)>>14)*16;
        if((scratch&7) || scratch>UINT64_MAX-16 ||
           sptm_managed_frame(m,scratch&PA_MASK) ||
           (scratch<m->frame_map_pa+map_size && scratch+16>m->frame_map_pa))
            return SPTM_BAD_ADDRESS;
        pointer=sptm_published_pointer(&b->aperture,&b->moved,slot_pa,8);
        if(!pointer) return SPTM_BAD_ADDRESS;
        out=m->map(m->ctx,scratch,16);if(!out) return SPTM_MEMORY_UNAVAILABLE;
        /* Published below on both the conflict and the accepted path. */
        if(m->audit && pointer!=sptm_aperture_pointer(&b->aperture,slot_pa,8))
            m->audit->moved_pointers++;
    }
    if(conflict || (shared && response==SPTM_USER_MAP_CONFLICT)) {
        /* ...270f92e8/92ec compares the old/new PA; ...95dc returns6.
         * ...9530 still reports the old PTE and its aperture pointer. No CAS,
         * reference delta, shadow mutation or TLB invalidation happens here. */
        if(out) {put(out,old,8);put(out+8,pointer,8);m->publish(m->ctx,scratch,16);}
        *guest_result=SPTM_USER_MAP_CONFLICT;
        return SPTM_OK;
    }
    sptm_refs_begin(m->refs);
    r=sptm_refs_leaf(m,slot_pa&PA_MASK,va,old,pte);if(r) return r;
    r=sptm_refs_validate(m);if(r) return r;
    if(replace) {
        if(b->prepare_update && !b->prepare_update(b->ctx,root,va,g.shift,old,pte))
            return SPTM_SHADOW_FAILED;
        put(slot,pte,8);m->publish(m->ctx,slot_pa,8);
        if(b->commit_update && !b->commit_update(b->ctx,root,va,g.shift,old,pte))
            return SPTM_SHADOW_FAILED;
        /* Hold the old permission reference until cached/private views and
         * broadcast invalidation have completed, including inactive roots. */
        sptm_refs_commit(m);
        if(b->map_updates) {
            struct sptm_user_update_state *s=b->map_updates;
            *s=(struct sptm_user_update_state){.calls=s->calls+1,
                .entries=s->entries+1,.changed=s->changed+1,.options=options,
                .result=sptm_mac_map_page_status(old,requested),
                .target=pte&PA_MASK,.count=1,.root=root,.va=va,
                .slot=slot_pa,.old=old,.next=pte,.shift=g.shift,.flags=root_meta[10],
                .last_changed=1,.requested=requested};
        }
    } else if(shared && old!=pte) {
        /* The backends' old is the prior leaf: a compressed marker had none, so
         * every cached alias inserts (prepare/commit_leaf), as for an empty slot. */
        uint64_t prior=(old&3)==3 ? old:0;
        if(!b->prepare_shared_leaf(b->ctx,root,va,g.shift,prior,pte))return SPTM_SHADOW_FAILED;
        put(slot,pte,8);m->publish(m->ctx,slot_pa,8);sptm_refs_commit(m);
        if(!b->commit_shared_leaf(b->ctx,root,va,g.shift,prior,pte))return SPTM_SHADOW_FAILED;
    } else if(fresh) {
        /* An inactive root's kept cached shadow takes the same pair. */
        unsigned cached=b->active_refs || b->mirror;
        if(cached && !b->prepare_leaf(b->ctx,root,va,g.shift,pte))
            return SPTM_MEMORY_UNAVAILABLE;
        put(slot,pte,8);m->publish(m->ctx,slot_pa,8);sptm_refs_commit(m);
        if(cached && !b->commit_leaf(b->ctx,root,va,g.shift,pte))
            return SPTM_MEMORY_UNAVAILABLE;
    }
    if(out) {put(out,old,8);put(out+8,pointer,8);m->publish(m->ctx,scratch,16);}
    /* Conflicts returned 6 above; every accepted leaf reports whether a
     * valid descriptor was already present (see sptm_mac_map_page_status). */
    *guest_result=sptm_mac_map_page_status(old,requested);
    return SPTM_OK;
}


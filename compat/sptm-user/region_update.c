/* SPDX-License-Identifier: MIT */
/* PTE and region updates, shared-region updates, the mixed and user disjoint
 * updates and the disjoint and region unmaps.
 * Part of compat/sptm-user.c's translation unit, included in order; not compiled on its own. */
enum sptm_result sptm_mac_shared_map_pte(uint64_t old,uint64_t requested,
    uint64_t *next,uint64_t *result)
{
    if(!next || !result)return SPTM_BAD_CONFIG;
    *next=old;*result=0;
    if(old==requested){*result=1;return SPTM_OK;}
    /* An invalid descriptor without bit7 (XNU's compressed marker, bits63:61,
     * which UNMAP_DISJOINT leaves on shared-region roots as on ordinary ones)
     * is installed over exactly like an empty slot: Apple's ...f92cc builds the
     * leaf from the request alone and ...f9574 returns 0 for root type 19 too
     * (tools/replay-map-page-status.py, its "compressed" rows). Refusing it
     * stopped installed-fresh-20261018-v69 when a compressed shared-region page
     * was faulted back in. Bit7 is FLUSH_PENDING (status 2), which this monitor
     * never stores, and stays refused. */
    if(old && (old&3)!=3) {
        if(old&0x80)return SPTM_TABLE_EXISTS;
        old=0;
    }
    if(old && ((old^requested)&0x0000fffffffff000UL)) {
        *result=SPTM_USER_MAP_CONFLICT;return SPTM_OK;
    }
    unsigned from=(unsigned)(((old>>4)&12)|((old>>53)&3));
    unsigned to=(unsigned)(((requested>>4)&12)|((requested>>53)&3));
    if(old && from!=to) {
        /* OR of shipped MAP_PAGE allow rows at ...1a878 and ...1a898.
         * This selection slice is common to ordinary and shared user roots;
         * the caller separately enforces its typed leaf policy. */
        static const uint16_t allowed_rows[16]={
            0,0,0,0x800,0,0xa000,0,0x8020,0,0x8000,0,8,0,0x8020,0,0x22a0};
        unsigned allowed=allowed_rows[from];
        if(!(allowed&(1u<<to)))return SPTM_UNSUPPORTED_OPTIONS;
    }
    uint64_t base=old ? old:requested;
    uint64_t mask=0x0c600000000000c0UL;
    *next=(base&~mask)|(requested&mask);
    if((0x2a8u&(1u<<to)) && (*next&(1UL<<59)))
        *next&=~((1UL<<59)|(1UL<<51));
    return SPTM_OK;
}

enum sptm_result sptm_mac_user_update_pte(uint64_t old,uint64_t requested,
    uint64_t options,uint64_t *next)
{
    return sptm_nx_update_pte(old,requested,options,next,1);
}
enum sptm_result sptm_mac_user_update_typed(uint64_t old,uint64_t requested,
    uint64_t options,unsigned type,uint64_t *next)
{
    unsigned policy=sptm_mac_type_policy(type);
    if(!policy)return SPTM_TYPE_MISMATCH;
    return sptm_update_select(old,requested,options,policy,next);
}

enum sptm_result sptm_mac_update_user_region(const struct sptm_memory *m,
    const struct sptm_user_backend *b,uint64_t root,uint64_t va,uint64_t count,
    uint64_t templates,uint64_t options,uint64_t scratch,
    uint64_t *guest_result,struct sptm_user_update_state *state)
{
    struct sptm_user_geometry g;volatile uint8_t *root_meta;
    enum sptm_result r=config(m,b,root,va,&g,&root_meta,0);if(r)return r;
    if(!m->refs || !guest_result || !!b->prepare_update!=!!b->commit_update ||
       (b->active_refs && !b->prepare_update))return SPTM_BAD_CONFIG;
    count=(uint32_t)count;options=(uint32_t)options;
    if(!count || count>64 || count>(g.va_limit-va)/g.page_size ||
       (va>>(2*g.shift-3))!=((va+(count-1)*g.page_size)>>(2*g.shift-3)))
        return SPTM_BAD_ADDRESS;
    if(!sptm_update_options_valid(options))return SPTM_UNSUPPORTED_OPTIONS;
    uint64_t bytes=count*8,map_size=((m->frame_high-m->frame_low)>>14)*16;
    if((templates&7) || (scratch&7) || templates>UINT64_MAX-bytes || scratch>UINT64_MAX-bytes ||
       (templates<scratch+bytes && scratch<templates+bytes) ||
       (scratch<m->frame_map_pa+map_size && scratch+bytes>m->frame_map_pa))return SPTM_BAD_ADDRESS;
    for(uint64_t p=scratch&PA_MASK;;p+=PAGE_SIZE) {
        if(sptm_managed_frame(m,p))return SPTM_BAD_ADDRESS;
        if(p==((scratch+bytes-1)&PA_MASK))break;
    }
    volatile uint8_t *input=m->map(m->ctx,templates,bytes),*out=m->map(m->ctx,scratch,bytes);
    if(!input || !out)return SPTM_MEMORY_UNAVAILABLE;
    struct {volatile uint8_t *slot;uint64_t pa,old,next,requested;} plan[64];
    /* Copy all templates before any publication; the input may be in owned
     * guest memory. Scratch is excluded from every owned frame above. */
    for(uint64_t i=0;i<count;i++) {
        plan[i].slot=0;plan[i].pa=plan[i].old=plan[i].next=0;
        plan[i].requested=get(input+i*8,8);
    }
    uint64_t changed=0,hardware_changed=0,posted=0,attributes=0;sptm_refs_begin(m->refs);
    for(uint64_t i=0;i<count;i++) {
        uint64_t addr=va+i*g.page_size;volatile uint8_t *table_meta;unsigned type;
        r=walk(m,root,&g,addr,3,0,&plan[i].slot,&plan[i].pa,&table_meta);
        if(r==SPTM_TABLE_MISSING)continue;
        if(r)return r;
        if(table_meta[2]!=SPTM_MAC_PAGE_TABLE)return SPTM_TYPE_MISMATCH;
        plan[i].old=plan[i].next=get(plan[i].slot,8);
        if((plan[i].old&3)!=3)continue;
        r=data_type(m,plan[i].old,&g,&type);if(r)return r;
        if(type!=SPTM_MAC_DEFAULT && type!=SPTM_MAC_USER_EXEC &&
           type!=SPTM_MAC_USER_TPRO && type!=SPTM_MAC_IO)return SPTM_TYPE_MISMATCH;
        if(type==SPTM_MAC_USER_TPRO && !m->retype_user_tpro)return SPTM_BAD_CONFIG;
        r=sptm_mac_user_leaf_policy(root_meta[10],table_meta[2],type,addr,plan[i].old,&g);
        if(r)return r;
        r=sptm_mac_user_update_typed(plan[i].old,plan[i].requested,options,type,&plan[i].next);
        if(r)return r;
        r=sptm_mac_user_leaf_policy(root_meta[10],table_meta[2],type,addr,plan[i].next,&g);
        if(r)return r;
        /* A new SH/AttrIndx needs its frame cleaned below; EL2 has no alias
         * of the device window to maintain, so that keeps its attributes. */
        if((plan[i].old^plan[i].next)&SPTM_UPDATE_ATTRS) {
            if(!m->clean_frame || type==SPTM_MAC_IO)return SPTM_UNSUPPORTED_OPTIONS;
            attributes=1;
        }
        r=sptm_refs_leaf(m,plan[i].pa&PA_MASK,addr,plan[i].old,plan[i].next);if(r)return r;
        if(plan[i].old!=plan[i].next) {
            if(b->prepare_update && !b->prepare_update(b->ctx,root,addr,g.shift,plan[i].old,plan[i].next))
                return SPTM_SHADOW_FAILED;
            changed++;hardware_changed|=!!((plan[i].old^plan[i].next)&~(3UL<<58));
            posted|=sptm_update_leaves_posted(plan[i].old,plan[i].next);
        }
    }
    r=sptm_refs_validate(m);if(r)return r;
    /* Each distinct data frame once, before any source or shadow store. */
    for(uint64_t i=0;attributes && i<count;i++) {
        if(!((plan[i].old^plan[i].next)&SPTM_UPDATE_ATTRS))continue;
        uint64_t frame=plan[i].old&PA_MASK;int seen=0;
        for(uint64_t j=0;j<i && !seen;j++)
            seen=((plan[j].old^plan[j].next)&SPTM_UPDATE_ATTRS) && (plan[j].old&PA_MASK)==frame;
        if(!seen && !m->clean_frame(m->ctx,frame,PAGE_SIZE))return SPTM_MEMORY_UNAVAILABLE;
    }
    for(uint64_t i=0;i<count;i++)if(plan[i].old!=plan[i].next) {
        put(plan[i].slot,plan[i].next,8);m->publish(m->ctx,plan[i].pa,8);
        if(b->commit_update && !b->commit_update(b->ctx,root,va+i*g.page_size,g.shift,
                                                plan[i].old,plan[i].next))return SPTM_SHADOW_FAILED;
    }
    sptm_refs_commit(m);
    for(uint64_t i=0;i<count;i++)put(out+i*8,plan[i].old,8);
    m->publish(m->ctx,scratch,bytes);
    *guest_result=hardware_changed && !posted && (options&0x100) ? 5:0;
    if(state) {
        uint64_t i=count-1;state->calls++;state->entries+=count;state->changed+=changed;
        state->options=options;state->result=*guest_result;state->count=count;
        state->target=(plan[i].old&3)==3 ? plan[i].old&PA_MASK:0;
        state->root=root;state->va=va+i*g.page_size;state->slot=plan[i].pa;
        state->old=plan[i].old;state->next=plan[i].next;state->shift=g.shift;
        state->flags=get(root_meta+10,2);state->last_changed=plan[i].old!=plan[i].next;
        state->requested=plan[i].requested;
    }
    return SPTM_OK;
}

enum sptm_result sptm_mac_shared_ng_pte(uint64_t old,uint64_t requested,
    uint64_t options,uint64_t *next)
{
    if(!next)return SPTM_BAD_CONFIG;
    if((options&~0x100UL)!=4)return SPTM_UNSUPPORTED_OPTIONS;
    /* ...fd560 stores old first; invalid entries skip template validation.
     * ...fd5f4 requires nG in the template; ...fd600 only sets that bit. */
    *next=old;
    if((old&3)!=3)return SPTM_OK;
    if(!(requested&0x800UL))return SPTM_UNSUPPORTED_OPTIONS;
    *next=old|0x800UL;return SPTM_OK;
}
static void shared_update_witness(struct sptm_user_update_state *s,uint64_t count,
    uint64_t changed,uint64_t options,uint64_t result,uint64_t root,uint64_t va,
    unsigned shift,uint64_t slot,uint64_t requested,struct sptm_shared_update_entry e)
{
    s->calls++;s->entries+=count;s->changed+=changed;s->options=options;s->result=result;
    s->count=count;s->root=root;s->va=va;s->shift=shift;s->flags=0;s->slot=slot;
    s->target=(e.old&3)==3 ? e.old&PA_MASK:0;s->old=e.old;s->next=e.next;
    s->last_changed=e.old!=e.next;s->requested=requested;
}
enum sptm_result sptm_mac_update_shared_region(const struct sptm_memory *m,
    const struct sptm_user_backend *b,uint64_t root,uint64_t va,uint64_t count,
    uint64_t templates,uint64_t options,uint64_t scratch,
    uint64_t *guest_result,struct sptm_shared_update_state *state)
{
    struct sptm_user_geometry g;volatile uint8_t *root_meta;
    enum sptm_result r=config(m,b,root,va,&g,&root_meta,2);if(r)return r;
    if(root_meta[2]!=SPTM_MAC_SHARED_ROOT_TABLE)return SPTM_TYPE_MISMATCH;
    if(!m->refs || !guest_result || !b->prepare_shared_update || !b->commit_shared_update)
        return SPTM_BAD_CONFIG;
    count=(uint32_t)count;options=(uint32_t)options;
    const struct sptm_shared_slot *region=&m->shared_regions->slots[root_meta[8]];
    if(!count || count>64 || count>(g.va_limit-va)/g.page_size ||
       count>(region->start+region->size-va)/g.page_size ||
       (va>>(2*g.shift-3))!=((va+(count-1)*g.page_size)>>(2*g.shift-3)))
        return SPTM_BAD_ADDRESS;
    if((options&~0x100UL)!=4)return SPTM_UNSUPPORTED_OPTIONS;
    uint64_t bytes=count*8,map_size=((m->frame_high-m->frame_low)>>14)*16;
    if((templates&7) || (scratch&7) || templates>UINT64_MAX-bytes || scratch>UINT64_MAX-bytes ||
       (templates<scratch+bytes && scratch<templates+bytes) ||
       (scratch<m->frame_map_pa+map_size && scratch+bytes>m->frame_map_pa))return SPTM_BAD_ADDRESS;
    for(uint64_t p=scratch&PA_MASK;;p+=PAGE_SIZE) {
        if(sptm_managed_frame(m,p))return SPTM_BAD_ADDRESS;
        if(p==((scratch+bytes-1)&PA_MASK))break;
    }
    volatile uint8_t *input=m->map(m->ctx,templates,bytes),*out=m->map(m->ctx,scratch,bytes);
    if(!input || !out)return SPTM_MEMORY_UNAVAILABLE;
    struct {volatile uint8_t *slot;uint64_t pa,requested;} plan[64];
    struct sptm_shared_update_entry entries[64];
    for(uint64_t i=0;i<count;i++) {
        plan[i].slot=0;plan[i].pa=0;plan[i].requested=get(input+i*8,8);
        entries[i]=(struct sptm_shared_update_entry){0};
    }
    uint64_t changed=0,last_changed=0;sptm_refs_begin(m->refs);
    for(uint64_t i=0;i<count;i++) {
        uint64_t addr=va+i*g.page_size;volatile uint8_t *table_meta,*data_meta;
        r=walk(m,root,&g,addr,3,0,&plan[i].slot,&plan[i].pa,&table_meta);
        if(r==SPTM_TABLE_MISSING)continue;
        if(r)return r;
        if(table_meta[2]!=SPTM_MAC_PAGE_TABLE_SHARED)return SPTM_TYPE_MISMATCH;
        entries[i].old=entries[i].next=get(plan[i].slot,8);
        r=sptm_mac_shared_ng_pte(entries[i].old,plan[i].requested,options,&entries[i].next);
        if(r)return r;
        if((entries[i].old&3)!=3)continue;
        r=metadata(m,entries[i].old&PA_MASK,&data_meta);if(r)return r;
        r=sptm_mac_user_leaf_policy(0,table_meta[2],data_meta[2],addr,entries[i].old,&g);if(r)return r;
        r=sptm_mac_user_leaf_policy(0,table_meta[2],data_meta[2],addr,entries[i].next,&g);if(r)return r;
        r=sptm_refs_leaf(m,plan[i].pa&PA_MASK,addr,entries[i].old,entries[i].next);if(r)return r;
        if(entries[i].old!=entries[i].next){changed++;last_changed=i;}
    }
    r=sptm_refs_validate(m);if(r)return r;
    if(changed) {
        if(!b->prepare_shared_update(b->ctx,root,va,g.shift,count))return SPTM_SHADOW_FAILED;
        for(uint64_t i=0;i<count;i++)if(entries[i].old!=entries[i].next) {
            put(plan[i].slot,entries[i].next,8);m->publish(m->ctx,plan[i].pa,8);
        }
        if(!b->commit_shared_update(b->ctx,root,va,g.shift,count,entries))return SPTM_SHADOW_FAILED;
    }
    sptm_refs_commit(m);
    for(uint64_t i=0;i<count;i++)put(out+i*8,entries[i].old,8);
    m->publish(m->ctx,scratch,bytes);*guest_result=changed && (options&0x100) ? 5:0;
    if(state) {
        uint64_t i=count-1;
        shared_update_witness(&state->latest,count,changed,options,*guest_result,root,
            va+i*g.page_size,g.shift,plan[i].pa,plan[i].requested,entries[i]);
        if(changed) {
            i=last_changed;
            shared_update_witness(&state->changed,count,changed,options,*guest_result,root,
                va+i*g.page_size,g.shift,plan[i].pa,plan[i].requested,entries[i]);
        }
    }
    return SPTM_OK;
}

enum sptm_result sptm_mac_update_mixed_disjoint(const struct sptm_memory *m,
    int (*resolve)(void *,uint64_t,struct sptm_user_backend *),void *ctx,
    const struct sptm_mixed_kernel_backend *kernel,
    uint64_t target,uint64_t list,uint64_t count,uint64_t options,uint64_t scratch,
    uint64_t *guest_result,struct sptm_user_update_state *state)
{
    if(!m || !m->map || !m->publish || !m->refs || !resolve || !guest_result ||
       !sptm_boot_memory_valid(m))return SPTM_BAD_CONFIG;
    if(kernel && (!kernel->workspace || !kernel->prepare || !kernel->commit ||
                  (kernel->root&0x3fff)))return SPTM_BAD_CONFIG;
    if(((m->frame_low|m->frame_high|m->alloc_low|m->alloc_high)&0x3fff) ||
       (m->frame_map_pa&15) || m->frame_low>=m->frame_high ||
       m->alloc_low>=m->alloc_high || m->alloc_low<m->frame_low ||
       m->alloc_high>m->frame_high)return SPTM_BAD_CONFIG;
    uint64_t map_size=((m->frame_high-m->frame_low)>>14)*16;
    if(map_size>UINT64_MAX-m->frame_map_pa ||
       (m->frame_map_pa<m->alloc_high && m->frame_map_pa+map_size>m->alloc_low))return SPTM_BAD_CONFIG;
    if(!count || count>64 || (target&0x3fff) || (list&7) || (scratch&7) ||
       list>UINT64_MAX-count*24 || scratch>UINT64_MAX-count*8 ||
       (list<scratch+count*8 && scratch<list+count*24))return SPTM_BAD_ADDRESS;
    if(!sptm_update_options_valid(options))return SPTM_UNSUPPORTED_OPTIONS;
    volatile uint8_t *data;enum sptm_result r=metadata(m,target,&data);if(r)return r;
    /* Every user data type; the leaf policy below checks old and new PTEs
     * against the frame's own type, as UNMAP_DISJOINT's target check does. */
    if(data[2]!=SPTM_MAC_DEFAULT && data[2]!=SPTM_MAC_USER_EXEC &&
       data[2]!=SPTM_MAC_USER_TPRO)return SPTM_TYPE_MISMATCH;
    if(data[2]==SPTM_MAC_USER_TPRO && !m->retype_user_tpro)return SPTM_BAD_CONFIG;
    if(scratch<m->frame_map_pa+map_size && scratch+count*8>m->frame_map_pa)return SPTM_BAD_ADDRESS;
    for(uint64_t p=scratch&PA_MASK;;p+=PAGE_SIZE) {
        if(sptm_managed_frame(m,p))return SPTM_BAD_ADDRESS;
        if(p==((scratch+count*8-1)&PA_MASK))break;
    }
    volatile uint8_t *input=m->map(m->ctx,list,count*24),*out=m->map(m->ctx,scratch,count*8);
    if(!input || !out)return SPTM_MEMORY_UNAVAILABLE;
    struct {uint64_t root,va,pa,old,next,shift,flags,requested;volatile uint8_t *slot;int shared;} plan[64];
    uint64_t changed=0,hardware_changed=0,posted=0,attributes=0;
    sptm_refs_begin(m->refs);
    for(uint64_t i=0;i<count;i++) {
        plan[i].root=get(input+i*24,8);plan[i].va=get(input+i*24+8,8);
        plan[i].pa=plan[i].old=plan[i].next=0;plan[i].slot=0;
        plan[i].shift=plan[i].flags=0;plan[i].shared=0;
        uint64_t requested=plan[i].requested=get(input+i*24+16,8);
        for(uint64_t j=0;j<i;j++)if(plan[j].root==plan[i].root && plan[j].va==plan[i].va) {
            sptm_audit_duplicate(m->audit,plan[i].root,plan[i].va);break;
        }
        if(kernel && plan[i].root==kernel->root) {
            struct sptm_update_entry *e=&kernel->workspace->entries[i];
            r=kernel->prepare(kernel->ctx,target,plan[i].va,requested,options,
                              scratch,count*8,e);if(r)return r;
            plan[i].slot=e->guest;plan[i].pa=e->slot_pa;
            plan[i].old=e->old;plan[i].next=e->next;plan[i].shift=14;
            for(uint64_t j=0;j<i;j++) {
                if(e->guest && e->guest==plan[j].slot)return SPTM_BAD_ADDRESS;
                if(plan[j].root!=kernel->root)continue;
                struct sptm_update_entry *prior=&kernel->workspace->entries[j];
                for(unsigned a=0;a<4;a++)for(unsigned z=0;z<4;z++)
                    if(e->shadow[a] && e->shadow[a]==prior->shadow[z])return SPTM_SHADOW_FAILED;
            }
            changed+=e->old!=e->next;
            hardware_changed|=!!((e->old^e->next)&~(3UL<<58));
            posted|=sptm_update_leaves_posted(e->old,e->next);
            attributes|=!!((e->old^e->next)&SPTM_UPDATE_ATTRS);
            continue;
        }
        struct sptm_user_backend b={0};struct sptm_user_geometry g;
        volatile uint8_t *root_meta,*table_meta;
        if(!resolve(ctx,plan[i].root,&b))return SPTM_BAD_CONFIG;
        /* A configured shared-region root (mode 2: inside its slot) is aged
         * like any user root: XNU's pmap_clear_refmod sends its shared-cache
         * leaves here (A16 installed-fresh-20261017-v11: options 0x10a, a
         * type19 root, type21 tables, DEFAULT target, ...6c3 -> ...2c3).
         * Its leaves change through the shared-update backend, which
         * propagates to every aliasing root as UPDATE_REGION's shared form. */
        r=config(m,&b,plan[i].root,plan[i].va,&g,&root_meta,2);if(r)return r;
        int shared=plan[i].shared=root_meta[2]==SPTM_MAC_SHARED_ROOT_TABLE;
        plan[i].shift=g.shift;plan[i].flags=get(root_meta+10,2);
        if(shared ? (!b.prepare_shared_update || !b.commit_shared_update) :
           (!!b.prepare_update!=!!b.commit_update || (b.active_refs && !b.prepare_update)))
            return SPTM_BAD_CONFIG;
        r=walk(m,plan[i].root,&g,plan[i].va,3,0,&plan[i].slot,&plan[i].pa,&table_meta);
        if(r==SPTM_TABLE_MISSING)continue;
        if(r)return r;
        if(table_meta[2]!=(shared ? SPTM_MAC_PAGE_TABLE_SHARED:SPTM_MAC_PAGE_TABLE))
            return SPTM_TYPE_MISMATCH;
        plan[i].old=plan[i].next=get(plan[i].slot,8);
        int duplicate=0;
        for(uint64_t j=0;j<i;j++)if(plan[i].slot==plan[j].slot) {
            /* Repeated identical aliases observe the first record's selected
             * descriptor. Publish that one transition once; return its old
             * value for the first record and the selected value thereafter.
             * Require an idempotent selection, not conflicting updates. */
            if(plan[i].root!=plan[j].root || plan[i].va!=plan[j].va ||
               requested!=plan[j].requested ||
               plan[i].old!=plan[j].old)return SPTM_BAD_ADDRESS;
            if((plan[j].old&3)==3 && (plan[j].old&PA_MASK)==target) {
                uint64_t repeated;
                r=sptm_mac_user_update_typed(plan[j].next,requested,options,data[2],&repeated);
                if(r)return r;
                if(repeated!=plan[j].next)return SPTM_BAD_ADDRESS;
            }
            plan[i].old=plan[i].next=plan[j].next;
            duplicate=1;break;
        }
        if(duplicate)continue;
        /* Like the shipped operation, a stale list reports old descriptors
         * without changing absent, compressed or different-frame mappings. */
        if((plan[i].old&3)!=3 || (plan[i].old&PA_MASK)!=target)continue;
        r=sptm_mac_user_leaf_policy((unsigned)plan[i].flags,table_meta[2],data[2],
                                    plan[i].va,plan[i].old,&g);if(r)return r;
        r=sptm_mac_user_update_typed(plan[i].old,requested,options,data[2],&plan[i].next);
        if(r)return r;
        r=sptm_mac_user_leaf_policy((unsigned)plan[i].flags,table_meta[2],data[2],
                                    plan[i].va,plan[i].next,&g);if(r)return r;
        if((plan[i].old^plan[i].next)&SPTM_UPDATE_ATTRS) {
            if(!m->clean_frame)return SPTM_UNSUPPORTED_OPTIONS;
            attributes=1;
        }
        r=sptm_refs_leaf(m,plan[i].pa&PA_MASK,plan[i].va,plan[i].old,plan[i].next);if(r)return r;
        if(plan[i].old!=plan[i].next) {
            if(shared ? !b.prepare_shared_update(b.ctx,plan[i].root,plan[i].va,g.shift,1) :
               b.prepare_update && !b.prepare_update(b.ctx,plan[i].root,plan[i].va,g.shift,
                                                     plan[i].old,plan[i].next))return SPTM_SHADOW_FAILED;
            changed++;
            hardware_changed|=!!((plan[i].old^plan[i].next)&~(3UL<<58));
            posted|=sptm_update_leaves_posted(plan[i].old,plan[i].next);
        }
    }
    r=sptm_refs_validate(m);if(r)return r;
    /* Every changed leaf maps target: clean it once before the first store. */
    if(attributes && !m->clean_frame(m->ctx,target,PAGE_SIZE))return SPTM_MEMORY_UNAVAILABLE;
    /* Input records are copied above. Scratch cannot alias source/metadata.
     * Preflight has checked every changed source and cached shadow. Keep data
     * references until all private views and TLBs have been synchronized. */
    for(uint64_t i=0;i<count;i++)if(plan[i].old!=plan[i].next) {
        if(kernel && plan[i].root==kernel->root) {
            kernel->commit(kernel->ctx,&kernel->workspace->entries[i]);continue;
        }
        struct sptm_user_backend b={0};
        if(!resolve(ctx,plan[i].root,&b))return SPTM_SHADOW_FAILED;
        if(plan[i].shared) {
            /* The shared backend holds one prepared alias set: restore this
             * record's while source and shadows still agree (preflight above
             * prepared every record), then store, publish and commit it. */
            const struct sptm_shared_update_entry e={plan[i].old,plan[i].next};
            if(!b.prepare_shared_update || !b.commit_shared_update ||
               !b.prepare_shared_update(b.ctx,plan[i].root,plan[i].va,(unsigned)plan[i].shift,1))
                return SPTM_SHADOW_FAILED;
            put(plan[i].slot,plan[i].next,8);m->publish(m->ctx,plan[i].pa,8);
            if(!b.commit_shared_update(b.ctx,plan[i].root,plan[i].va,(unsigned)plan[i].shift,1,&e))
                return SPTM_SHADOW_FAILED;
            continue;
        }
        put(plan[i].slot,plan[i].next,8);m->publish(m->ctx,plan[i].pa,8);
        if(b.commit_update &&
           !b.commit_update(b.ctx,plan[i].root,plan[i].va,(unsigned)plan[i].shift,
                            plan[i].old,plan[i].next))return SPTM_SHADOW_FAILED;
    }
    sptm_refs_commit(m);
    for(uint64_t i=0;i<count;i++)put(out+i*8,plan[i].old,8);
    m->publish(m->ctx,scratch,count*8);
    *guest_result=(hardware_changed && !posted && (options&0x100)) ? 5:0;
    if(state) {
        uint64_t i=count-1;state->calls++;state->entries+=count;state->changed+=changed;
        state->options=options;state->result=*guest_result;state->target=target;state->count=count;
        state->root=plan[i].root;state->va=plan[i].va;state->slot=plan[i].pa;
        state->old=plan[i].old;state->next=plan[i].next;state->shift=plan[i].shift;
        state->flags=plan[i].flags;state->last_changed=plan[i].old!=plan[i].next;
        state->requested=plan[i].requested;
    }
    return SPTM_OK;
}

enum sptm_result sptm_mac_update_user_disjoint(const struct sptm_memory *m,
    int (*resolve)(void *,uint64_t,struct sptm_user_backend *),void *ctx,
    uint64_t target,uint64_t list,uint64_t count,uint64_t options,uint64_t scratch,
    uint64_t *guest_result,struct sptm_user_update_state *state)
{
    return sptm_mac_update_mixed_disjoint(m,resolve,ctx,0,target,list,count,
                                         options,scratch,guest_result,state);
}

#if SNAP_UNMAP_MIXED
enum sptm_result sptm_mac_unmap_mixed_disjoint(const struct sptm_memory *m,
    int (*resolve)(void *,uint64_t,struct sptm_user_backend *),void *ctx,
    const struct sptm_unmap_kernel *kernel,
    uint64_t target,uint64_t list,uint64_t count,uint64_t scratch,
    struct sptm_shared_update_state *state)
#else
enum sptm_result sptm_mac_unmap_user_disjoint(const struct sptm_memory *m,
    int (*resolve)(void *,uint64_t,struct sptm_user_backend *),void *ctx,
    uint64_t target,uint64_t list,uint64_t count,uint64_t scratch,
    struct sptm_shared_update_state *state)
#endif
{
    if(!m || !m->map || !m->publish || !m->refs || !resolve ||
       !sptm_boot_memory_valid(m))return SPTM_BAD_CONFIG;
#if SNAP_UNMAP_MIXED
    /* The kernel engine's configuration checks (sptm_mac_unmap_kernel_disjoint). */
    if(kernel && (!kernel->shadow || !kernel->shadow->read || !kernel->shadow->write ||
       kernel->shadow->txsz!=17 || (kernel->shadow->root&0xfff) || (kernel->root&0x3fff)))
        return SPTM_BAD_CONFIG;
#endif
    if(((m->frame_low|m->frame_high|m->alloc_low|m->alloc_high)&0x3fff) ||
       (m->frame_map_pa&15) || m->frame_low>=m->frame_high ||
       m->alloc_low>=m->alloc_high || m->alloc_low<m->frame_low ||
       m->alloc_high>m->frame_high)return SPTM_BAD_CONFIG;
    uint64_t map_size=((m->frame_high-m->frame_low)>>14)*16;
    if(map_size>UINT64_MAX-m->frame_map_pa ||
       (m->frame_map_pa<m->alloc_high && m->frame_map_pa+map_size>m->alloc_low))return SPTM_BAD_CONFIG;
    count=(uint32_t)count;
    if(!count || count>64 || (target&16383) || (scratch&16383) ||
       list<m->frame_low || list>=m->frame_high || count*24>m->frame_high-list ||
       (list&16383)+count*24>16384 || scratch>UINT64_MAX-2048)
        return SPTM_BAD_ADDRESS;
#if SNAP_UNMAP_MIXED
    if(kernel && ((list&7) || scratch==(list&~UINT64_C(0x3fff))))return SPTM_BAD_ADDRESS;
#endif
    uint64_t bytes=512+count*24;
    if((scratch<m->frame_map_pa+map_size && scratch+bytes>m->frame_map_pa) ||
       sptm_managed_frame(m,scratch))return SPTM_BAD_ADDRESS;
    volatile uint8_t *data;enum sptm_result r=metadata(m,target,&data);if(r)return r;
    if(data[2]!=SPTM_MAC_DEFAULT && data[2]!=SPTM_MAC_USER_EXEC &&
       data[2]!=SPTM_MAC_USER_TPRO)return SPTM_TYPE_MISMATCH;
    volatile uint8_t *input_meta=m->map(m->ctx,
        m->frame_map_pa+((list-m->frame_low)>>14)*16,16);
    if(!input_meta)return SPTM_MEMORY_UNAVAILABLE;
    unsigned lock=(unsigned)get(input_meta,2);
    if((lock&1) || lock>0xfff1)return SPTM_FRAME_BUSY;
    if(input_meta[2]!=SPTM_MAC_DEFAULT && input_meta[2]!=SPTM_MAC_KERNEL_RESTRICTED)
        return SPTM_TYPE_MISMATCH;
    volatile uint8_t *input=m->map(m->ctx,list,count*24),*out=m->map(m->ctx,scratch,bytes);
    if(!input || !out)return SPTM_MEMORY_UNAVAILABLE;
    struct {uint64_t root,va,requested,pa,old,next,shift,flags,shared,remove;
            volatile uint8_t *slot;} plan[64];
#if SNAP_UNMAP_MIXED
    unsigned char kernel_record[64];
#endif
    /* Copy all caller records before resolving any table or invoking a backend. */
    for(uint64_t i=0;i<count;i++) {
        plan[i].root=get(input+i*24,8);plan[i].va=get(input+i*24+8,8);
        plan[i].requested=get(input+i*24+16,8);
        plan[i].pa=plan[i].old=plan[i].next=plan[i].shift=plan[i].flags=0;
        plan[i].shared=plan[i].remove=0;plan[i].slot=0;
        for(uint64_t j=0;j<i;j++)if(plan[j].root==plan[i].root && plan[j].va==plan[i].va) {
            sptm_audit_duplicate(m->audit,plan[i].root,plan[i].va);break;
        }
#if SNAP_UNMAP_MIXED
        /* The kernel engine refuses these before its reference batch. */
        kernel_record[i]=kernel && plan[i].root==kernel->root;
        if(kernel_record[i] && (plan[i].va<0xffff800000000000UL || (plan[i].va&0x3fff)))
            return SPTM_BAD_ADDRESS;
#endif
    }
    uint64_t changed=0,last_changed=0;sptm_refs_begin(m->refs);
    for(uint64_t i=0;i<count;i++) {
        struct sptm_user_backend b={0};struct sptm_user_geometry g;
        volatile uint8_t *root_meta,*table_meta;
#if SNAP_UNMAP_MIXED
        if(kernel_record[i]) {
            /* The kernel engine's record, step for step, inside this batch. */
            plan[i].shift=14;
            r=sptm_kernel_unmap_slot(m,kernel->root,plan[i].va,scratch,
                                     &plan[i].slot,&plan[i].pa,&plan[i].old);if(r)return r;
            for(uint64_t j=0;j<i;j++)if(kernel_record[j] && plan[i].slot && plan[i].slot==plan[j].slot) {
                if(plan[i].va!=plan[j].va)return SPTM_BAD_TABLE;
                if(plan[j].remove)plan[i].old=plan[j].next|0x80;
            }
            plan[i].next=plan[i].old;
            if((plan[i].old&3)!=3 || (plan[i].old&PA_MASK)!=target)continue;
            plan[i].next=plan[i].requested&0xe000000000000000UL;
            r=sptm_kernel_unmap_check(kernel->shadow,plan[i].va,target,plan[i].old);if(r)return r;
            r=sptm_refs_leaf(m,plan[i].pa&PA_MASK,plan[i].va,plan[i].old,plan[i].next);if(r)return r;
            plan[i].remove=1;changed++;last_changed=i;continue;
        }
#endif
        if(!resolve(ctx,plan[i].root,&b))return SPTM_BAD_CONFIG;
        r=config(m,&b,plan[i].root,plan[i].va,&g,&root_meta,2);if(r)return r;
        int shared=plan[i].shared=root_meta[2]==SPTM_MAC_SHARED_ROOT_TABLE;
        plan[i].shift=g.shift;plan[i].flags=shared ? 0:get(root_meta+10,2);
        if(shared ? (!b.prepare_shared_unmap || !b.commit_shared_unmap) :
           (!!b.prepare_unmap!=!!b.commit_unmap || (b.active_refs && !b.prepare_unmap)))
            return SPTM_BAD_CONFIG;
        r=walk(m,plan[i].root,&g,plan[i].va,3,1,&plan[i].slot,&plan[i].pa,&table_meta);
        if(r==SPTM_TABLE_MISSING)continue;
        if(r)return r;
        if(table_meta[2]!=(shared ? SPTM_MAC_PAGE_TABLE_SHARED:SPTM_MAC_PAGE_TABLE))
            return SPTM_TYPE_MISMATCH;
        plan[i].old=get(plan[i].slot,8);
        /* A duplicate observes the first pass's invalid transient descriptor
         * in Apple's helper. Preserve that returned value, but release only
         * one reference and publish only the final software bits. */
        for(uint64_t j=0;j<i;j++)if(plan[j].remove && plan[i].slot==plan[j].slot)
            plan[i].old=plan[j].next|0x80;
        plan[i].next=plan[i].old;
        if((plan[i].old&3)!=3 || (plan[i].old&PA_MASK)!=target)continue;
        r=sptm_mac_user_leaf_policy((unsigned)plan[i].flags,table_meta[2],data[2],
                                    plan[i].va,plan[i].old,&g);if(r)return r;
        plan[i].next=plan[i].requested&0xe000000000000000UL;
        r=sptm_refs_leaf(m,plan[i].pa&PA_MASK,plan[i].va,plan[i].old,plan[i].next);if(r)return r;
        if(shared ? !b.prepare_shared_unmap(b.ctx,plan[i].root,plan[i].va,g.shift,1) :
           b.prepare_unmap && !b.prepare_unmap(b.ctx,plan[i].root,plan[i].va,g.shift,1))
            return SPTM_SHADOW_FAILED;
        plan[i].remove=1;changed++;last_changed=i;
    }
    r=sptm_refs_validate(m);if(r)return r;
    for(uint64_t i=0;i<count;i++)if(plan[i].remove) {
#if SNAP_UNMAP_MIXED
        if(kernel_record[i]) {
            if(!sptm_kernel_unmap_commit(kernel->shadow,plan[i].va))return SPTM_SHADOW_FAILED;
            put(plan[i].slot,plan[i].next,8);m->publish(m->ctx,plan[i].pa,8);
            continue;
        }
#endif
        struct sptm_user_backend b={0};
        if(!resolve(ctx,plan[i].root,&b))return SPTM_SHADOW_FAILED;
        /* Shared backends retain one prepared alias set. Every entry passed
         * full-batch preflight above; restore this entry's cookie while its
         * source and shadows still agree, before publishing its removal. */
        if(plan[i].shared && (!b.prepare_shared_unmap ||
           !b.prepare_shared_unmap(b.ctx,plan[i].root,plan[i].va,
                                   (unsigned)plan[i].shift,1)))return SPTM_SHADOW_FAILED;
        put(plan[i].slot,plan[i].next,8);m->publish(m->ctx,plan[i].pa,8);
        if(plan[i].shared ? !b.commit_shared_unmap ||
           !b.commit_shared_unmap(b.ctx,plan[i].root,plan[i].va,(unsigned)plan[i].shift,1,1) :
           b.commit_unmap && !b.commit_unmap(b.ctx,plan[i].root,plan[i].va,
                                           (unsigned)plan[i].shift,1,1))
            return SPTM_SHADOW_FAILED;
    }
    sptm_refs_commit(m);
    for(uint64_t i=0;i<count;i++) {
        put(out+i*8,plan[i].old,8);
        put(out+512+i*24,plan[i].root,8);put(out+520+i*24,plan[i].va,8);
        put(out+528+i*24,plan[i].requested,8);
    }
    m->publish(m->ctx,scratch,bytes);
#if SNAP_UNMAP_MIXED
    /* One witness per domain over that domain's records only, so each stays
     * what tools/audit-unmap-disjoint.py admits (user: options 0 and user VAs;
     * kernel: the kernel root's VAs). kernel 0: exactly the user witness below. */
    for(unsigned domain=0;domain<2;domain++) {
        struct sptm_shared_update_state *w=domain ? (kernel ? kernel->state:0) : state;
        uint64_t n=0,done=0,last=0,last_done=0;
        for(uint64_t i=0;i<count;i++)if(kernel_record[i]==domain) {
            n++;last=i;if(plan[i].remove){done++;last_done=i;}
        }
        if(!w || !n)continue;
        uint64_t i=last;
        shared_update_witness(&w->latest,n,done,0,0,plan[i].root,
            plan[i].va,(unsigned)plan[i].shift,plan[i].pa,plan[i].requested,
            (struct sptm_shared_update_entry){plan[i].old,plan[i].next});
        w->latest.target=target;w->latest.flags=plan[i].flags;
        w->latest.last_changed=plan[i].remove;
        if(done) {
            i=last_done;
            shared_update_witness(&w->changed,n,done,0,0,plan[i].root,
                plan[i].va,(unsigned)plan[i].shift,plan[i].pa,plan[i].requested,
                (struct sptm_shared_update_entry){plan[i].old,plan[i].next});
            w->changed.target=target;w->changed.flags=plan[i].flags;
        }
    }
    (void)changed;(void)last_changed;
#else
    if(state) {
        uint64_t i=count-1;
        shared_update_witness(&state->latest,count,changed,0,0,plan[i].root,
            plan[i].va,(unsigned)plan[i].shift,plan[i].pa,plan[i].requested,
            (struct sptm_shared_update_entry){plan[i].old,plan[i].next});
        state->latest.target=target;state->latest.flags=plan[i].flags;
        state->latest.last_changed=plan[i].remove;
        if(changed) {
            i=last_changed;
            shared_update_witness(&state->changed,count,changed,0,0,plan[i].root,
                plan[i].va,(unsigned)plan[i].shift,plan[i].pa,plan[i].requested,
                (struct sptm_shared_update_entry){plan[i].old,plan[i].next});
            state->changed.target=target;state->changed.flags=plan[i].flags;
        }
    }
#endif
    return SPTM_OK;
}
#if SNAP_UNMAP_MIXED
enum sptm_result sptm_mac_unmap_user_disjoint(const struct sptm_memory *m,
    int (*resolve)(void *,uint64_t,struct sptm_user_backend *),void *ctx,
    uint64_t target,uint64_t list,uint64_t count,uint64_t scratch,
    struct sptm_shared_update_state *state)
{return sptm_mac_unmap_mixed_disjoint(m,resolve,ctx,0,target,list,count,scratch,state);}
#endif

enum sptm_result sptm_mac_unmap_user_region(const struct sptm_memory *m,
    const struct sptm_user_backend *b,uint64_t root,uint64_t va,uint64_t count,
    uint64_t options,uint64_t scratch)
{
    struct sptm_user_geometry g;volatile uint8_t *root_meta;
    enum sptm_result r=config(m,b,root,va,&g,&root_meta,2);if(r)return r;
    int shared=root_meta[2]==SPTM_MAC_SHARED_ROOT_TABLE;
    if(shared && (!b->prepare_shared_unmap || !b->commit_shared_unmap))return SPTM_BAD_CONFIG;
    if(!m->refs || (!!b->prepare_unmap!=!!b->commit_unmap) ||
       (b->active_refs && !b->prepare_unmap))return SPTM_BAD_CONFIG;
    if(options&~1UL)return SPTM_UNSUPPORTED_OPTIONS;
    if(!count || count>64 || count>(g.va_limit-va)/g.page_size)
        return SPTM_BAD_ADDRESS;
    uint64_t end=va+count*g.page_size;
    if(shared) {
        const struct sptm_shared_slot *s=&m->shared_regions->slots[root_meta[8]];
        if(end-s->start>s->size)return SPTM_BAD_ADDRESS;
    }
    /* Shipped ...fc8a4 rejects a span crossing its source L3 table. */
    if((va>>(2*g.shift-3))!=((end-1)>>(2*g.shift-3)))return SPTM_BAD_ADDRESS;
    if(m->aperture_size && end>m->aperture_va &&
       (va<m->aperture_va || va-m->aperture_va<m->aperture_size))return SPTM_BAD_CONFIG;
    uint64_t bytes=count*8,map_size=((m->frame_high-m->frame_low)>>14)*16;
    if((scratch&7) || scratch>UINT64_MAX-bytes ||
       (scratch<m->frame_map_pa+map_size && scratch+bytes>m->frame_map_pa))
        return SPTM_BAD_ADDRESS;
    /* Output must not alias any owned table/data frame, even across a frame
     * boundary or inside a boot-disposable ownership range. */
    for(uint64_t p=scratch&~0x3fffUL;;p+=PAGE_SIZE) {
        if(sptm_managed_frame(m,p))return SPTM_BAD_ADDRESS;
        if(p==((scratch+bytes-1)&~0x3fffUL))break;
    }
    volatile uint8_t *out=m->map(m->ctx,scratch,bytes);
    if(!out)return SPTM_MEMORY_UNAVAILABLE;
    struct {volatile uint8_t *slot;uint64_t pa,old;int clear;} entries[64];
    uint64_t removed=0;
    sptm_refs_begin(m->refs);
    for(uint64_t n=0;n<count;n++) {
        uint64_t addr=va+n*g.page_size;volatile uint8_t *table_meta;
        entries[n].slot=0;entries[n].pa=entries[n].old=0;entries[n].clear=0;
        r=walk(m,root,&g,addr,3,1,&entries[n].slot,&entries[n].pa,&table_meta);
        if(r==SPTM_TABLE_MISSING)continue;
        if(r)return r;
        if(table_meta[2]!=(shared ? SPTM_MAC_PAGE_TABLE_SHARED:SPTM_MAC_PAGE_TABLE))
            return SPTM_TYPE_MISMATCH;
        uint64_t old=entries[n].old=get(entries[n].slot,8);
        if(!old)continue;
        if((old&3)!=3) {
            /* Invalid software state (XNU's compressed marker). Apple's
             * callback ...fd2f8..fd32c leaves it for option0 and clears it
             * for option1 (XNU: PMAP_OPTIONS_REMOVE); the prior PTE is
             * reported either way. It holds only a table count (...ecbe8). */
            if(!(old>>61) || !(options&1))continue;
            r=sptm_refs_leaf(m,entries[n].pa&PA_MASK,addr,old,0);if(r)return r;
            entries[n].clear=1;continue;
        }
        entries[n].clear=1;
        unsigned type;
        r=data_type(m,old,&g,&type);if(r)return r;
        r=sptm_mac_user_leaf_policy(root_meta[10],table_meta[2],type,addr,old,&g);
        if(r)return r;
        r=sptm_refs_leaf(m,entries[n].pa&PA_MASK,addr,old,0);if(r)return r;
        removed++;
    }
    r=sptm_refs_validate(m);if(r)return r;
    if(shared ? !b->prepare_shared_unmap(b->ctx,root,va,g.shift,count) :
       b->prepare_unmap && !b->prepare_unmap(b->ctx,root,va,g.shift,count))
        return SPTM_SHADOW_FAILED;
    /* The service token excludes concurrent guest mutations. Hardware walks
     * private tables, so source leaves can become zero directly; the shipped
     * monitor's transient 0x80 marker is unnecessary. References remain held
     * until the private removal and broadcast invalidation have completed. */
    for(uint64_t n=0;n<count;n++)if(entries[n].clear) {
        put(entries[n].slot,0,8);m->publish(m->ctx,entries[n].pa,8);
    }
    if(shared ? !b->commit_shared_unmap(b->ctx,root,va,g.shift,count,removed) :
       b->commit_unmap && !b->commit_unmap(b->ctx,root,va,g.shift,count,removed))
        return SPTM_SHADOW_FAILED; /* fatal: caller must not resume the guest */
    sptm_refs_commit(m);
    for(uint64_t n=0;n<count;n++)put(out+n*8,entries[n].old,8);
    m->publish(m->ctx,scratch,bytes);
    return SPTM_OK;
}

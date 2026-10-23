/* SPDX-License-Identifier: MIT */
/* Field access, configuration, the user table walk and the shared-region
 * nest/unnest calls.
 * Part of compat/sptm-user.c's translation unit, included in order; not compiled on its own. */
/* 8-byte fields: one single-copy-atomic access (compat/sptm-access.h, v67). */
static uint64_t get(volatile uint8_t *p,unsigned n)
{
    if(n==8)return sptm_get64(p);
    uint64_t v=0;for(unsigned i=0;i<n;i++) v|=(uint64_t)p[i]<<(8*i);return v;
}
static void put(volatile uint8_t *p,uint64_t v,unsigned n)
{
    if(n==8) {sptm_put64(p,v);return;}
    for(unsigned i=0;i<n;i++) p[i]=(uint8_t)(v>>(8*i));
}
static enum sptm_result metadata(const struct sptm_memory *m,uint64_t pa,
                                volatile uint8_t **out);
static enum sptm_result config(const struct sptm_memory *m,
    const struct sptm_user_backend *b,uint64_t root,uint64_t va,
    struct sptm_user_geometry *g,volatile uint8_t **root_meta,int allow_shared)
{
    if(!m || !b || !m->map || !m->publish || !sptm_boot_memory_valid(m) ||
       ((m->frame_low|m->frame_high|m->alloc_low|m->alloc_high)&0x3fff) ||
       (m->frame_map_pa&15) || m->frame_low>=m->frame_high ||
       m->alloc_low>=m->alloc_high || m->alloc_low<m->frame_low ||
       m->alloc_high>m->frame_high) return SPTM_BAD_CONFIG;
    uint64_t size=((m->frame_high-m->frame_low)>>14)*16;
    if(size>UINT64_MAX-m->frame_map_pa ||
       (m->frame_map_pa<m->alloc_high && m->frame_map_pa+size>m->alloc_low))
        return SPTM_BAD_CONFIG;
    if(root&0x3fff) return SPTM_BAD_ADDRESS;
    if(b->active_refs>6 || ((b->active_refs || b->mirror) && (!b->prepare_leaf || !b->commit_leaf)))
        return SPTM_BAD_CONFIG;
    if(((b->ttbr0&PA_MASK)==root && !b->active_refs) || (b->ttbr1&PA_MASK)==root)
        return SPTM_FRAME_BUSY;
    enum sptm_result r=metadata(m,root,root_meta);if(r) return r;
    volatile uint8_t *meta=*root_meta;
    if(allow_shared && meta[2]==SPTM_MAC_SHARED_ROOT_TABLE) {
        if(!m->shared_regions)return SPTM_BAD_CONFIG;
        /* Mode2 propagates leaf changes through bound roots. Mode3 removes
         * only empty tables with exactly one remaining source link; UNNEST
         * must already have removed all consumer aliases. Attachment (mode1)
         * remains unbound-only. */
        if((allow_shared==1 && get(meta+4,2)) || b->active_refs)return SPTM_FRAME_BUSY;
        if(get(meta+4,2)>0xfff9)return SPTM_BAD_REFERENCE;
        if(meta[8]>=SPTM_MAC_SHARED_ROOT_LIMIT || meta[9] || get(meta+10,2) ||
           meta[13] || meta[14] || meta[15] ||
           !sptm_mac_user_geometry(meta[12],SPTM_MAC_ROOT_FLAGS_USER,g))return SPTM_BAD_TABLE;
        const struct sptm_shared_slot *s=&m->shared_regions->slots[meta[8]];
        if(s->root!=root || !sptm_mac_shared_slot_valid(s,meta[12]))return SPTM_BAD_TABLE;
        if(allow_shared==2 && (s->state!=3 || va<s->start || va-s->start>=s->size))
            return SPTM_BAD_ADDRESS;
    } else if(meta[2]!=SPTM_MAC_USER_ROOT_TABLE || !get(meta+4,2) ||
       get(meta+6,2)>2054 || !sptm_mac_user_binding_valid(m,meta) || meta[13] || meta[14] || meta[15] ||
       !sptm_mac_user_geometry(meta[12],(unsigned)get(meta+10,2),g)) return SPTM_BAD_TABLE;
    if(get(meta+6,2)<b->active_refs || get(meta+6,2)>g->root_groups+b->active_refs)
        return SPTM_BAD_REFERENCE;
    if((va&(g->page_size-1)) || va>=g->va_limit) return SPTM_BAD_ADDRESS;
    return SPTM_OK;
}
static enum sptm_result metadata(const struct sptm_memory *m,uint64_t pa,
                                volatile uint8_t **out)
{
    if((pa&0x3fff) || !sptm_managed_frame(m,pa))
        return SPTM_BAD_ADDRESS;
    *out=m->map(m->ctx,m->frame_map_pa+((pa-m->frame_low)>>14)*16,16);
    if(!*out) return SPTM_MEMORY_UNAVAILABLE;
    if((*out)[0] || (*out)[1]) return SPTM_FRAME_BUSY;
    return SPTM_OK;
}
/* A leaf's data frame type, as Apple's ...270ec314 resolves it: managed DRAM
 * uses its frame-table entry (lock bytes must be clear); the declared device
 * window resolves to the static XNU_IO type with no lock or counts. Anything
 * else is refused; Apple's untyped fallback is a policy we do not grant. */
static enum sptm_result data_type(const struct sptm_memory *m,uint64_t pte,
    const struct sptm_user_geometry *g,unsigned *type)
{
    uint64_t pa=pte&g->pa_mask;
    if(sptm_managed_frame(m,pa&PA_MASK)) {
        volatile uint8_t *meta;
        enum sptm_result r=metadata(m,pa&PA_MASK,&meta);if(r)return r;
        *type=meta[2];return SPTM_OK;
    }
    if(sptm_user_io_frame(m,pa,g->page_size)) {*type=SPTM_MAC_IO;return SPTM_OK;}
    return SPTM_BAD_ADDRESS;
}
static enum sptm_result walk(const struct sptm_memory *m,uint64_t root,
    const struct sptm_user_geometry *g,uint64_t va,unsigned final,int allow_condemned,
    volatile uint8_t **slot,uint64_t *slot_pa,
    volatile uint8_t **last_meta)
{
    uint64_t table=root,seen[4];unsigned table_type=SPTM_MAC_PAGE_TABLE;
    for(unsigned level=g->start;level<=final;level++) {
        uint64_t frame=table&PA_MASK;
        for(unsigned i=g->start;i<level;i++) if(seen[i]==frame) return SPTM_BAD_TABLE;
        seen[level]=frame;
        volatile uint8_t *meta;
        enum sptm_result r=metadata(m,frame,&meta);if(r) return r;
        if(level==g->start && meta[2]==SPTM_MAC_SHARED_ROOT_TABLE)
            table_type=SPTM_MAC_PAGE_TABLE_SHARED;
        int aliased=level==3 && (meta[2]==SPTM_MAC_PAGE_TABLE_COMMPAGE ||
                                meta[2]==SPTM_MAC_PAGE_TABLE_SHARED);
        if(level!=g->start && ((meta[2]!=table_type &&
                   !(table_type==SPTM_MAC_PAGE_TABLE && aliased)) ||
                  meta[4]!=level || !get(meta+6,2) ||
                  (aliased ?
                   get(meta+6,2)>0xfff9 : get(meta+6,2)!=1)))
            return SPTM_BAD_TABLE;
        volatile uint8_t *page=m->map(m->ctx,table,g->page_size);
        if(!page) return SPTM_MEMORY_UNAVAILABLE;
        unsigned index=sptm_mac_user_index(g,level,va);
        uint64_t off=index*8UL;
        if(level==final) {
            *slot=page+off;*slot_pa=table+off;*last_meta=meta;return SPTM_OK;
        }
        /* NEST increments and publishes individual descriptors. Unlike an
         * ordinary grouped attachment, a 4K nested L3 need not have all four
         * sibling descriptors present in the destination. */
        uint64_t direct=get(page+off,8);
        if(table_type==SPTM_MAC_PAGE_TABLE && level==2 && (direct&3)==3) {
            volatile uint8_t *candidate;
            r=metadata(m,direct&PA_MASK,&candidate);if(r)return r;
            if(candidate[2]==SPTM_MAC_PAGE_TABLE_SHARED) {
                if(!sptm_mac_nested_table(m,root,va,direct))return SPTM_BAD_TABLE;
                table=direct&g->pa_mask;continue;
            }
        }
        unsigned first=index&~(g->group-1);
        uint64_t tte=get(page+first*8,8),child=tte&PA_MASK;
        if(!tte) {
            for(unsigned n=1;n<g->group;n++)
                if(get(page+(first+n)*8,8)) return SPTM_BAD_TABLE;
            return SPTM_TABLE_MISSING;
        }
        uint64_t attrs=tte&~PA_MASK;
        if(attrs!=3 && !(level==2 && attrs==7)) return SPTM_BAD_TABLE;
        for(unsigned n=1;n<g->group;n++)
            if(get(page+(first+n)*8,8)!=((child+n*g->page_size)|attrs)) return SPTM_BAD_TABLE;
        if(attrs==7) {
            volatile uint8_t *child_meta;
            r=metadata(m,child,&child_meta);if(r)return r;
            if(child_meta[2]!=SPTM_MAC_PAGE_TABLE || child_meta[4]!=3 ||
               get(child_meta+6,2)!=1)return SPTM_BAD_TABLE;
            if(!allow_condemned)return SPTM_TABLE_MISSING;
        }
        table=child+(index-first)*g->page_size;
    }
    return SPTM_BAD_TABLE;
}
int sptm_mac_root_shared_slot(const struct sptm_memory *m,uint64_t root)
{
    volatile uint8_t *u;
    if(!m || !m->map || metadata(m,root,&u) || u[2]!=SPTM_MAC_USER_ROOT_TABLE)return -1;
    return u[8];
}

int sptm_mac_nested_table(const struct sptm_memory *m,uint64_t root,uint64_t va,uint64_t pte)
{
    volatile uint8_t *u,*child;struct sptm_user_geometry g;
    if(!m || !m->map || !m->shared_regions || metadata(m,root,&u) ||
       u[2]!=SPTM_MAC_USER_ROOT_TABLE || u[8]==255 ||
       !sptm_mac_user_binding_valid(m,u) ||
       !sptm_mac_user_geometry(u[12],(unsigned)get(u+10,2),&g) || va>=g.va_limit ||
       (pte&~g.pa_mask)!=3 || metadata(m,pte&PA_MASK,&child) ||
       child[2]!=SPTM_MAC_PAGE_TABLE_SHARED || child[4]!=3 ||
       !get(child+6,2) || get(child+6,2)>0xfff9)return 0;
    const struct sptm_shared_slot *s=&m->shared_regions->slots[u[8]];
    /* The request is bounded by the configured range, but the native
     * operation aliases whole containing L3 tables, even at partial ends. */
    uint64_t span=1UL<<(2*g.shift-3),base=va&~(span-1);
    if(base+span<=s->start || base>=s->start+s->size)return 0;
    volatile uint8_t *slot,*parent;uint64_t slot_pa;
    return !walk(m,s->root,&g,va,2,0,&slot,&slot_pa,&parent) && get(slot,8)==pte;
}

enum sptm_result sptm_mac_shared_alias(const struct sptm_memory *m,uint64_t root,
    uint64_t shared,uint64_t va,unsigned shift,int *aliased)
{
    volatile uint8_t *u;struct sptm_user_geometry g;
    if(!aliased || !m || !m->shared_regions)return SPTM_BAD_CONFIG;
    *aliased=0;
    enum sptm_result r=metadata(m,root,&u);if(r)return r;
    if(u[2]!=SPTM_MAC_USER_ROOT_TABLE || !sptm_mac_user_binding_valid(m,u) ||
       !sptm_mac_user_geometry(u[12],(unsigned)get(u+10,2),&g))return SPTM_BAD_TABLE;
    if(u[8]==255 || m->shared_regions->slots[u[8]].root!=shared)return SPTM_OK;
    if(g.shift!=shift || va>=g.va_limit || (va&(g.page_size-1)))return SPTM_BAD_ADDRESS;
    volatile uint8_t *slot,*parent;uint64_t slot_pa;
    r=walk(m,root,&g,va,2,0,&slot,&slot_pa,&parent);
    if(r==SPTM_TABLE_MISSING)return SPTM_OK;
    if(r)return r;
    uint64_t pte=get(slot,8);
    if(!pte)return SPTM_OK;
    volatile uint8_t *child;
    r=metadata(m,pte&PA_MASK,&child);if(r)return r;
    if(child[2]==SPTM_MAC_PAGE_TABLE)return SPTM_OK;
    if(child[2]!=SPTM_MAC_PAGE_TABLE_SHARED || !sptm_mac_nested_table(m,root,va,pte))
        return SPTM_BAD_TABLE;
    *aliased=1;return SPTM_OK;
}

enum sptm_result sptm_mac_nest_region(const struct sptm_memory *m,
    const struct sptm_user_backend *b,uint64_t root,uint64_t shared,uint64_t va,uint64_t pages)
{
    struct sptm_user_geometry g;volatile uint8_t *u,*p;
    enum sptm_result r=config(m,b,root,va,&g,&u,0);if(r)return r;
    if(!m->shared_regions || (!!b->prepare_nest!=!!b->commit_nest) ||
       (b->active_refs && !b->prepare_nest))return SPTM_BAD_CONFIG;
    if(root==shared || u[8]==255)return SPTM_BAD_TABLE;
    r=metadata(m,shared,&p);if(r)return r;
    const struct sptm_shared_slot *region=&m->shared_regions->slots[u[8]];
    if(p[2]!=SPTM_MAC_SHARED_ROOT_TABLE || p[8]!=u[8] || p[12]!=u[12] ||
       region->root!=shared || region->state!=3 || !sptm_mac_user_binding_valid(m,u))
        return SPTM_BAD_TABLE;
    /* ...fcf98 normalizes the page count to u32. ...ff958 forbids crossing
     * one L2 parent; ...ff990 checks first and exclusive-end L2 indices. */
    pages=(uint32_t)pages;
    if(!pages || pages>(g.va_limit-va)/g.page_size)return SPTM_BAD_ADDRESS;
    uint64_t end=va+pages*g.page_size,last=end-g.page_size;
    uint64_t parent_span=1UL<<(3*g.shift-6),leaf_span=1UL<<(2*g.shift-3);
    if((va/parent_span)!=(last/parent_span) ||
       (sptm_mac_user_index(&g,2,va)&(g.group-1)) ||
       (sptm_mac_user_index(&g,2,end)&(g.group-1)) ||
       va<region->start || end>region->start+region->size)return SPTM_BAD_ADDRESS;
    unsigned count=(unsigned)(last/leaf_span-va/leaf_span+1);
    volatile uint8_t *src,*dst,*source_meta,*parent;uint64_t src_pa,dst_pa;
    r=walk(m,shared,&g,va,2,0,&src,&src_pa,&source_meta);if(r)return r;
    r=walk(m,root,&g,va,2,0,&dst,&dst_pa,&parent);if(r)return r;
    if(parent[2]!=SPTM_MAC_PAGE_TABLE || parent[4]!=2 ||
       source_meta[2]!=SPTM_MAC_PAGE_TABLE_SHARED || source_meta[4]!=2 ||
       (src_pa&PA_MASK)==(dst_pa&PA_MASK))return SPTM_BAD_TABLE;
    uint64_t children=get(parent+8,2);
    if(children+count>2048)return SPTM_BAD_REFERENCE;
    src=m->map(m->ctx,src_pa,count*8UL);dst=m->map(m->ctx,dst_pa,count*8UL);
    uint64_t map_size=((m->frame_high-m->frame_low)>>14)*16;
    volatile uint8_t *fm=m->map(m->ctx,m->frame_map_pa,map_size);
    if(!src || !dst || !fm)return SPTM_MEMORY_UNAVAILABLE;
    /* Map all metadata once so commit contains no fallible mappings. The
     * global service token keeps both descriptor arrays stable throughout. */
    for(unsigned i=0;i<count;i++) {
        uint64_t tte=get(src+i*8,8),child=tte&PA_MASK;
        if(get(dst+i*8,8))return SPTM_TABLE_EXISTS;
        if((tte&~g.pa_mask)!=3 || !sptm_managed_frame(m,child))return SPTM_BAD_TABLE;
        volatile uint8_t *meta=fm+((child-m->frame_low)>>14)*16;
        if(get(meta,2))return SPTM_FRAME_BUSY;
        if(meta[2]!=SPTM_MAC_PAGE_TABLE_SHARED || meta[4]!=3)return SPTM_TYPE_MISMATCH;
        uint64_t links=get(meta+6,2);unsigned added=1;
        for(unsigned j=0;j<i;j++)added+=(get(src+j*8,8)&PA_MASK)==child;
        if(!links || links+added>0xfff9 || get(meta+8,2)>2048)return SPTM_BAD_REFERENCE;
        if(!m->map(m->ctx,tte&g.pa_mask,g.page_size))return SPTM_MEMORY_UNAVAILABLE;
    }
    if(b->prepare_nest && !b->prepare_nest(b->ctx,root,shared,va,g.shift,pages))
        return SPTM_SHADOW_FAILED;
    for(unsigned i=0;i<count;i++) {
        uint64_t tte=get(src+i*8,8),child=tte&PA_MASK;
        volatile uint8_t *meta=fm+((child-m->frame_low)>>14)*16;
        put(meta+6,get(meta+6,2)+1,2);
        m->publish(m->ctx,m->frame_map_pa+((child-m->frame_low)>>14)*16+6,2);
        put(dst+i*8,tte,8);
    }
    put(parent+8,children+count,2);
    m->publish(m->ctx,m->frame_map_pa+(((dst_pa&PA_MASK)-m->frame_low)>>14)*16+8,2);
    m->publish(m->ctx,dst_pa,count*8UL);
    if(b->commit_nest && !b->commit_nest(b->ctx,root,shared,va,g.shift,pages))
        return SPTM_SHADOW_FAILED; /* fatal after publication; never resume */
    return SPTM_OK;
}
enum sptm_result sptm_mac_unnest_region(const struct sptm_memory *m,
    const struct sptm_user_backend *b,uint64_t root,uint64_t shared,uint64_t va,uint64_t pages)
{
    struct sptm_user_geometry g;volatile uint8_t *u,*p;
    enum sptm_result r=config(m,b,root,va,&g,&u,0);if(r)return r;
    if(!m->shared_regions || (!!b->prepare_unnest!=!!b->commit_unnest) ||
       (b->active_refs && !b->prepare_unnest))return SPTM_BAD_CONFIG;
    if(root==shared || u[8]==255)return SPTM_BAD_TABLE;
    r=metadata(m,shared,&p);if(r)return r;
    const struct sptm_shared_slot *region=&m->shared_regions->slots[u[8]];
    if(p[2]!=SPTM_MAC_SHARED_ROOT_TABLE || p[8]!=u[8] || p[12]!=u[12] ||
       region->root!=shared || region->state!=3 || !sptm_mac_user_binding_valid(m,u))
        return SPTM_BAD_TABLE;
    /* UNNEST shares NEST's ff8f0 range validator, including u32 page count
     * and partial-end rounding to individual L3 descriptors. */
    pages=(uint32_t)pages;
    if(!pages || pages>(g.va_limit-va)/g.page_size)return SPTM_BAD_ADDRESS;
    uint64_t end=va+pages*g.page_size,last=end-g.page_size;
    uint64_t parent_span=1UL<<(3*g.shift-6),span=1UL<<(2*g.shift-3);
    if(va/parent_span!=last/parent_span ||
       (sptm_mac_user_index(&g,2,va)&(g.group-1)) ||
       (sptm_mac_user_index(&g,2,end)&(g.group-1)) ||
       va<region->start || end>region->start+region->size)return SPTM_BAD_ADDRESS;
    struct sptm_unnest_plan plan;
    volatile uint64_t *clear=(volatile uint64_t *)&plan;
    for(unsigned i=0;i<sizeof(plan)/8;i++)clear[i]=0;
    plan.base=va&~(span-1);plan.span=span;plan.count=last/span-va/span+1;
    if(plan.count>2048)return SPTM_BAD_ADDRESS;
    volatile uint8_t *src,*dst,*source_meta,*parent;uint64_t src_pa,dst_pa;
    r=walk(m,shared,&g,va,2,0,&src,&src_pa,&source_meta);if(r)return r;
    r=walk(m,root,&g,va,2,0,&dst,&dst_pa,&parent);if(r)return r;
    if(parent[2]!=SPTM_MAC_PAGE_TABLE || parent[4]!=2 ||
       source_meta[2]!=SPTM_MAC_PAGE_TABLE_SHARED || source_meta[4]!=2 ||
       (src_pa&PA_MASK)==(dst_pa&PA_MASK))return SPTM_BAD_TABLE;
    src=m->map(m->ctx,src_pa,plan.count*8);dst=m->map(m->ctx,dst_pa,plan.count*8);
    uint64_t map_size=((m->frame_high-m->frame_low)>>14)*16;
    volatile uint8_t *fm=m->map(m->ctx,m->frame_map_pa,map_size);
    if(!src || !dst || !fm)return SPTM_MEMORY_UNAVAILABLE;
    for(unsigned i=0;i<plan.count;i++) {
        uint64_t tte=get(dst+i*8,8),child=tte&PA_MASK;
        if((tte&3)!=3)continue; /* Apple's ffc80 skips absent/invalid entries. */
        if(!sptm_managed_frame(m,child))return SPTM_BAD_ADDRESS;
        volatile uint8_t *meta=fm+((child-m->frame_low)>>14)*16;
        if(get(meta,2))return SPTM_FRAME_BUSY;
        if(meta[2]!=SPTM_MAC_PAGE_TABLE_SHARED)continue; /* Preserve ordinary tables. */
        if(meta[4]!=3 || (tte&~g.pa_mask)!=3 || tte!=get(src+i*8,8))return SPTM_BAD_TABLE;
        unsigned removed=1;
        for(unsigned j=0;j<i;j++)if(plan.mask[j/64]&(1UL<<(j%64)))
            removed+=(get(dst+j*8,8)&PA_MASK)==child;
        uint64_t links=get(meta+6,2);
        if(links<=removed || links>0xfff9 || get(meta+8,2)>2048)return SPTM_BAD_REFERENCE;
        volatile uint8_t *page=m->map(m->ctx,tte&g.pa_mask,g.page_size);
        if(!page)return SPTM_MEMORY_UNAVAILABLE;
#if SNAP_NEST_FAST
        /* compat/nest-fast.h 2: count only mapped leaves in a proved table.
         * Compressed markers occupy software slots, not hardware mappings;
         * other invalid descriptors still take the checked loop below. */
#if SNAP_UNNEST_4K_FAST
        /* compat/nest-fast.h 3: a 4K table too; its verdict may also carry
         * the count this scan makes (known), and then the scan is skipped. */
        uint64_t known=UINT64_MAX;
        int proved=g.shift==14 ?
            sptm_root_shared_proof(m,tte&g.pa_mask,plan.base+i*span,u[12],(unsigned)get(u+10,2)) :
            sptm_root_shared_proof_4k(m,tte&g.pa_mask,plan.base+i*span,u[12],(unsigned)get(u+10,2),&known);
#else
        int proved=g.shift==14 ?
            sptm_root_shared_proof(m,tte&g.pa_mask,plan.base+i*span,u[12],(unsigned)get(u+10,2)) : 0;
#endif
        if(proved<0)return SPTM_SHADOW_FAILED;
        if(m->nest_fast)m->nest_fast->unnest_tables++;
        uint64_t nonzero=0;
#if SNAP_UNNEST_4K_FAST
        if(proved && known!=UINT64_MAX)nonzero=known;
        else {
#endif
        for(unsigned n=0;proved && n<g.page_size/8;n++) {
            uint64_t pte=*(volatile uint64_t *)(void *)(page+n*8);
            if(!(pte&~0xe000000000000000UL))continue;
            if((pte&3)!=3)proved=0;
            nonzero++;
        }
#if SNAP_UNNEST_4K_FAST
        if(proved && g.shift==12 &&
           sptm_root_shared_count_4k(m,tte&g.pa_mask,plan.base+i*span,u[12],(unsigned)get(u+10,2),nonzero)<0)
            return SPTM_SHADOW_FAILED;
        }
#endif
        if(proved)plan.leaves+=nonzero;
        else {
        if(m->nest_fast)m->nest_fast->unnest_walked++;
#endif
        for(unsigned n=0;n<g.page_size/8;n++) {
            uint64_t pte=get(page+n*8,8);
            /* XNU's compressed markers hold only software bits 63:61.
             * Like zero, they have no physical frame or shadow leaf. Keep
             * the shared slot and its occupied count intact when unnesting. */
            if(!(pte&~0xe000000000000000UL))continue;
            volatile uint8_t *data;
            r=metadata(m,pte&PA_MASK,&data);if(r)return r;
            r=sptm_mac_user_leaf_policy(u[10],21,data[2],plan.base+i*span+n*g.page_size,pte,&g);
            if(r)return r;
            plan.leaves++;
        }
#if SNAP_NEST_FAST
        }
#endif
        plan.mask[i/64]|=1UL<<(i%64);plan.descriptors++;
    }
    uint64_t children=get(parent+8,2);
    if(children>2048 || children<plan.descriptors)return SPTM_BAD_REFERENCE;
    if(b->prepare_unnest && !b->prepare_unnest(b->ctx,root,shared,g.shift,&plan))
        return SPTM_SHADOW_FAILED;
    for(unsigned i=0;i<plan.count;i++)if(plan.mask[i/64]&(1UL<<(i%64)))put(dst+i*8,0,8);
    m->publish(m->ctx,dst_pa,plan.count*8);
    /* Like the shipped monitor, clear aliases and finish TLBI before
     * releasing their table references. Shared source/data refs never move. */
    if(b->commit_unnest && !b->commit_unnest(b->ctx,root,shared,g.shift,&plan))
        return SPTM_SHADOW_FAILED; /* fatal after publication */
    for(unsigned i=0;i<plan.count;i++)if(plan.mask[i/64]&(1UL<<(i%64))) {
        uint64_t child=get(src+i*8,8)&PA_MASK;
        volatile uint8_t *meta=fm+((child-m->frame_low)>>14)*16;
        put(meta+6,get(meta+6,2)-1,2);
        m->publish(m->ctx,m->frame_map_pa+((child-m->frame_low)>>14)*16+6,2);
    }
    put(parent+8,children-plan.descriptors,2);
    m->publish(m->ctx,m->frame_map_pa+(((dst_pa&PA_MASK)-m->frame_low)>>14)*16+8,2);
    return SPTM_OK;
}

/* SPDX-License-Identifier: MIT */
#include "sptm-user.h"
#include "sptm-access.h"
#include "sptm-nx-update.h"
#include "sptm-refs.h"
#if SNAP_UNMAP_MIXED
#include "../shadow/shadow.h"
#endif
#if SNAP_NEST_FAST || SNAP_DETACH_FAST
#include "nest-fast.h"
#endif
#define PA_MASK 0x0000ffffffffc000UL
#define PAGE_SIZE 0x4000UL

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

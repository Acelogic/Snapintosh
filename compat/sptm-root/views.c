/* SPDX-License-Identifier: MIT */
/* Root header access, table validation, shared aliases and the fixed, canonical
 * and mapped views.
 * Part of compat/sptm-root.c's translation unit, included in order; not compiled on its own. */
/* 8-byte fields: one single-copy-atomic access (compat/sptm-access.h, v67). */
static uint64_t get(volatile uint8_t *p,unsigned n)
{if(n==8)return sptm_get64(p);uint64_t v=0;for(unsigned i=0;i<n;i++)v|=(uint64_t)p[i]<<(8*i);return v;}
static void put16(volatile uint8_t *p,unsigned v)
{p[0]=(uint8_t)v;p[1]=(uint8_t)(v>>8);}
static volatile uint8_t *metadata(const struct sptm_memory *m,uint64_t pa)
{
    if(!sptm_managed_frame(m,pa))return 0;
    return m->map(m->ctx,m->frame_map_pa+((pa-m->frame_low)>>14)*16,16);
}
static unsigned active_count(const struct sptm_root_state *s,uint64_t root)
{unsigned n=0;for(unsigned i=0;i<SPTM_ROOT_CPUS;i++)n+=s->active[i]==root;return n;}
static int root_header(const struct sptm_memory *m,volatile uint8_t *meta,struct sptm_user_geometry *g)
{
    return meta && !get(meta,2) && meta[2]==SPTM_MAC_USER_ROOT_TABLE &&
        get(meta+4,2) && sptm_mac_user_binding_valid(m,meta) && !meta[13] && !meta[14] && !meta[15] &&
        sptm_mac_user_geometry(meta[12],(unsigned)get(meta+10,2),g);
}
/* 1 in (mask+1) word-load validations repeats the byte walk. Host tests may
 * set 0 to compare every validation; the monitor uses the default. */
#ifndef SPTM_ROOT_VALIDATE_SAMPLE
#define SPTM_ROOT_VALIDATE_SAMPLE 63u
#endif
struct validation {
    const struct sptm_memory *m;
    const struct sptm_user_geometry *g;
    unsigned flags, tables, root_children;
    uint64_t root;
    int words;
    /* Cache-hit switches only (sptm-root-memo.h); NULL walks everything. */
    struct sptm_root_memo *memo;
#if SNAP_ROOT_MISS_FAST
    /* A miss or a linked build: memo answers SHARED level-3 tables only. */
    int shared_only;
#endif
};
/* One descriptor of a validated table page. The page is page-size aligned and
 * each descriptor offset is a multiple of 8, so the 64-bit load is aligned and
 * single-copy atomic; on this little-endian target it yields exactly the value
 * the eight byte loads assemble whenever the word is stable (and one value a
 * byte schedule could also observe if it were not). */
static uint64_t descriptor(const struct validation *v,volatile uint8_t *page,unsigned i)
{
    if(v->words)return *(volatile uint64_t *)(void *)(page+8UL*i);
    return get(page+8UL*i,8);
}
/* Raw selector9 may exist only in the canonical shadow, behind the backend's
 * TPRO contract. It must be translated into a private CPU view for execution.
 * Ordinary fixed leaves retain the existing policy and hardware encoding. */
static int canonical_leaf(const struct sptm_memory *m,unsigned flags,
    const struct sptm_user_geometry *g,uint64_t va,uint64_t pte)
{
    if(sprr_fixed_native_leaf(pte))return 1;
    if(sprr_pte_class(pte)!=9 || !m->retype_user_tpro)return 0;
    volatile uint8_t *data=metadata(m,pte&MASK);
    return data && !get(data,2) && data[2]==SPTM_MAC_USER_TPRO &&
        sptm_mac_user_leaf_policy(flags,SPTM_MAC_PAGE_TABLE,data[2],va,pte,g)==SPTM_OK;
}
/* Validate owned tables and the currently admitted user-leaf policy before
 * allocating a hardware shadow. Unknown future leaf classes stop explicitly. */
static int validate_table(struct validation *v,uint64_t table,unsigned level,uint64_t base)
{
    const struct sptm_user_geometry *g=v->g;
    uint64_t frame=table&MASK;
    if(++v->tables>4096 || (table&(g->page_size-1)))return 0;
    volatile uint8_t *meta=metadata(v->m,frame);
    if(!meta || get(meta,2))return 0;
    int aliased=level==3 && (meta[2]==SPTM_MAC_PAGE_TABLE_COMMPAGE ||
                            meta[2]==SPTM_MAC_PAGE_TABLE_SHARED);
    if(level!=g->start && ((meta[2]!=SPTM_MAC_PAGE_TABLE && !aliased) ||
          meta[4]!=level || !get(meta+6,2) ||
          (aliased ?
           get(meta+6,2)>0xfff9 : get(meta+6,2)!=1)))return 0;
    volatile uint8_t *page=v->m->map(v->m->ctx,table,g->page_size);
    if(!page)return 0;
    /* Everything above was checked for this table on this walk. Only the
     * level-3 descriptor scan below may be answered by a retained verdict. */
    uint64_t record=0;
#if SNAP_ROOT_MISS_FAST
    int memo=level==3 && v->memo && root_miss_memo_table(v->shared_only,meta[2]);
    if(memo) {
#else
    if(level==3 && v->memo) {
#endif
        record=sptm_root_memo_record_bytes(meta);
        if(sptm_root_memo_find(v->memo,table,base,v->flags,g->shift,record))return 1;
    }
    uint64_t span=mmu_level_size(g->shift,level);
    for(unsigned i=0;i<g->page_size/8;i++) {
        uint64_t pte=descriptor(v,page,i),va=base+i*span;
        if(!pte)continue;
        /* A leaf holding only software bits63:61 is XNU's compressed marker
         * (UNMAP_DISJOINT template). Hardware never sees it: shadow_build
         * skips invalid leaves. Apple does not walk tables on switch. */
        if(level==3 && !(pte&~0xe000000000000000UL))continue;
        if((pte&3)!=3)return 0;
        if(level<3) {
            uint64_t attrs=pte&~g->pa_mask;
            if(attrs!=3 && !(level==2 && attrs==7))return 0;
            volatile uint8_t *candidate=metadata(v->m,pte&MASK);
            if(candidate && candidate[2]==SPTM_MAC_PAGE_TABLE_SHARED) {
                if(level!=2 || attrs!=3 || !sptm_mac_nested_table(v->m,v->root,va,pte))return 0;
                if(!validate_table(v,pte&g->pa_mask,3,va))return 0;
                continue;
            }
            unsigned first=i&~(g->group-1);
            uint64_t first_pte=descriptor(v,page,first),child=first_pte&MASK;
            if(attrs==7) {
                volatile uint8_t *child_meta=metadata(v->m,child);
                if(!child_meta || child_meta[2]!=SPTM_MAC_PAGE_TABLE)return 0;
            }
            if(pte!=((child+(i-first)*g->page_size)|attrs))return 0;
            if(i==first)for(unsigned n=1;n<g->group;n++)
                if(descriptor(v,page,i+n)!=((child+n*g->page_size)|attrs))return 0;
            if(level==g->start && i==first)v->root_children++;
            if(!validate_table(v,pte&g->pa_mask,level+1,va))return 0;
        } else {
            if(va>=g->va_limit)return 0;
            if(!canonical_leaf(v->m,v->flags,g,va,pte))return 0;
            /* The declared device window has no frame state (Apple XNU_IO);
             * its leaves are never dereferenced here. */
            if(!sptm_managed_frame(v->m,pte&MASK) &&
               sptm_user_io_frame(v->m,pte&g->pa_mask,g->page_size)) {
                if(sptm_mac_user_leaf_policy(v->flags,meta[2],SPTM_MAC_IO,va,pte,g))return 0;
                continue;
            }
            volatile uint8_t *data=metadata(v->m,pte&MASK);
            if(!data || get(data,2))return 0;
            /* A nested descriptor was matched to the immutable, bound source
             * above. Its existing leaves keep the source's permissions and
             * references; nesting neither creates nor authenticates code. */
            if(sptm_mac_user_leaf_policy(v->flags,meta[2],data[2],va,pte,g))return 0;
            if(!v->m->map(v->m->ctx,pte&g->pa_mask,g->page_size))return 0;
        }
    }
#if SNAP_ROOT_MISS_FAST
    if(memo)sptm_root_memo_store(v->memo,table,base,v->flags,g->shift,record);
#else
    if(level==3 && v->memo)sptm_root_memo_store(v->memo,table,base,v->flags,g->shift,record);
#endif
    return 1;
}
static int checked_read(void *ctx,uint64_t pa,uint64_t *word)
{
    const struct sptm_memory *m=ctx;
    volatile uint8_t *p=m->map(m->ctx,pa,8);
    if(!p || (pa&7))return -1;
    *word=get(p,8);return 0;
}
int sptm_root_shared_aliases(const struct sptm_memory *m,const struct sptm_root_state *s,
    uint64_t shared,uint64_t va,unsigned shift,sptm_root_mask_t *mask)
{
    if(!m || !s || !mask)return 0;
    *mask=SPTM_ROOT_MASK_NONE;
    for(unsigned cpu=0;cpu<SPTM_ROOT_CPUS;cpu++)if(s->active[cpu]) {
        unsigned found=0;
        for(unsigned i=0;i<SPTM_ROOT_CACHE;i++)
            found+=s->cache[i].valid && s->cache[i].root==s->active[cpu];
        if(found!=1)return 0;
    }
    for(unsigned i=0;i<SPTM_ROOT_CACHE;i++) {
        const struct sptm_root_cached *e=&s->cache[i];if(!e->valid)continue;
        struct sptm_user_geometry g;volatile uint8_t *meta=metadata(m,e->root);
        if(!root_header(m,meta,&g) || get(meta+4,2)!=e->asid ||
           get(meta+10,2)!=e->flags || meta[12]!=e->format ||
           get(meta+6,2)<active_count(s,e->root) ||
           get(meta+6,2)>g.root_groups+active_count(s,e->root))return 0;
        for(unsigned j=0;j<i;j++)if(s->cache[j].valid && s->cache[j].root==e->root)return 0;
        int aliased;
        if(sptm_mac_shared_alias(m,e->root,shared,va,shift,&aliased))return 0;
        if(aliased)SPTM_ROOT_MASK_SET(*mask,i);
    }
    return 1;
}
#if SNAP_USER_HW_WALK
int sptm_root_shared_aliases_hw(const struct sptm_memory *m,const struct sptm_root_state *s,
    uint64_t shared,uint64_t va,unsigned shift,sptm_root_mask_t *mask,
    int (*walked)(void *ctx,uint64_t root),void *ctx)
{
    if(!m || !s || !mask || !walked)return 0;
    *mask=SPTM_ROOT_MASK_NONE;
    for(unsigned cpu=0;cpu<SPTM_ROOT_CPUS;cpu++)if(s->active[cpu]) {
        unsigned found=0;
        for(unsigned i=0;i<SPTM_ROOT_CACHE;i++)
            found+=s->cache[i].valid && s->cache[i].root==s->active[cpu];
        if(found!=1 && !(found==0 && walked(ctx,s->active[cpu])))return 0;
    }
    for(unsigned i=0;i<SPTM_ROOT_CACHE;i++) {
        const struct sptm_root_cached *e=&s->cache[i];if(!e->valid)continue;
        struct sptm_user_geometry g;volatile uint8_t *meta=metadata(m,e->root);
        if(!root_header(m,meta,&g) || get(meta+4,2)!=e->asid ||
           get(meta+10,2)!=e->flags || meta[12]!=e->format ||
           get(meta+6,2)<active_count(s,e->root) ||
           get(meta+6,2)>g.root_groups+active_count(s,e->root))return 0;
        for(unsigned j=0;j<i;j++)if(s->cache[j].valid && s->cache[j].root==e->root)return 0;
        int aliased;
        if(sptm_mac_shared_alias(m,e->root,shared,va,shift,&aliased))return 0;
        if(aliased)SPTM_ROOT_MASK_SET(*mask,i);
    }
    return 1;
}
#endif
int sptm_root_prepare_leaf(struct sptm_root_cached *e,struct shadow *s,uint64_t va,unsigned shift)
{
    struct sptm_user_geometry g;
    if(!e || !e->valid || !s || s->txsz!=17 || s->root!=e->shadow ||
       !sptm_mac_user_geometry((unsigned)e->format,(unsigned)e->flags,&g) ||
       shift!=g.shift || (va&(g.page_size-1)) || va>=g.va_limit)return 0;
    return shadow_reserve(s,va,g.page_size)==0;
}
static uint64_t no_alloc(void *ctx) {(void)ctx;return 0;}
static int fixed_view_table(const struct sptm_root_cached *e,const struct shadow *s,
    const struct sptm_memory *m,const struct sptm_user_geometry *g,
    uint64_t table,unsigned level,uint64_t base,struct sptm_fixed_view *v,int tpro)
{
    if(!table || (table&4095) || ++v->tables>8192)return 0;
    struct mmu_config source={g->shift,17,e->root};
    uint64_t span=mmu_level_size(12,level);
    for(unsigned i=0;i<512;i++) {
        uint64_t pte,va=base+i*span;
        if(s->read(s->ctx,table+8UL*i,&pte))return 0;
        if(!pte)continue;
        if((pte&3)!=3 || va>=g->va_limit)return 0;
        if(level<3) {
            if((pte&~PT_OA_MASK)!=3 ||
               !fixed_view_table(e,s,m,g,pte&PT_OA_MASK,level+1,va,v,tpro))return 0;
        } else {
            struct mmu_leaf actual;
            if(mmu_walk(&source,va,checked_read,(void *)m,&actual) ||
               !actual.valid || actual.level!=3 || actual.size!=g->page_size ||
               !(tpro ? canonical_leaf(m,(unsigned)e->flags,g,va&~(g->page_size-1),
                                      actual.descriptor) : sprr_fixed_native_leaf(pte)) ||
               actual.pa!=(pte&PT_OA_MASK) ||
               ((actual.descriptor^pte)&(PT_LEAF_ATTRS|PT_LEAF_UPPER)))return 0;
            v->pages++;v->classes|=1UL<<sprr_pte_class(pte);
        }
    }
    return 1;
}
static int check_view(const struct sptm_root_cached *e,const struct shadow *s,
    const struct sptm_memory *m,struct sptm_fixed_view *out,int tpro)
{
    struct sptm_user_geometry g;struct sptm_fixed_view v={0};
    if(!e || !e->valid || !s || !s->read || s->txsz!=17 || s->root!=e->shadow ||
       !m || !m->map || !out ||
       !sptm_mac_user_geometry((unsigned)e->format,(unsigned)e->flags,&g) ||
       e->leaves>g.va_limit/g.page_size)return 0;
    volatile uint8_t *meta=metadata(m,e->root);struct sptm_user_geometry actual;
    if(!root_header(m,meta,&actual) || get(meta+4,2)!=e->asid ||
       get(meta+10,2)!=e->flags || meta[12]!=e->format ||
       !fixed_view_table(e,s,m,&g,e->shadow,0,0,&v,tpro) ||
       v.pages!=e->leaves*(g.page_size/4096))return 0;
    *out=v;return 1;
}
int sptm_root_fixed_view(const struct sptm_root_cached *e,const struct shadow *s,
    const struct sptm_memory *m,struct sptm_fixed_view *out)
{return check_view(e,s,m,out,0);}
int sptm_root_canonical_view(const struct sptm_root_cached *e,const struct shadow *s,
    const struct sptm_memory *m,struct sptm_fixed_view *out)
{return check_view(e,s,m,out,1);}
/* check_view with the same decisions in the same order and cheaper reads.
 * Per leaf, the reference re-walks the whole source tree with eight byte loads
 * per descriptor, and reads every canonical word through s->read. Here:
 *   - a canonical table is taken whole from `table`, whose contract is that it
 *     returns non-NULL exactly when all 512 s->read calls for that page would
 *     succeed, and then yields the same words; all-zero eight-word groups are
 *     skipped, as the reference skips each zero word;
 *   - the source leaf and its policy verdict are computed once per source page
 *     (a 16K page backs four consecutive 4K leaves) and reused only for leaves
 *     inside that page; the physical address is re-derived per leaf with
 *     mmu_walk's own formula;
 *   - the source tables above level 3 are walked once per level-3 span and
 *     reused only for VAs inside it: those VAs use the same upper descriptors;
 *   - source descriptors are single aligned 64-bit loads through the same
 *     m->map and alignment check as checked_read, equal to the byte assembly
 *     whenever the word is stable (the service token excludes monitor writers;
 *     XNU never stores SPTM page tables). Any failing read, invalid or block
 *     descriptor fails the proof, as it fails the reference leaf check. */
struct view_mapped_walk {
    const struct sptm_root_cached *e;const struct shadow *s;const struct sptm_memory *m;
    const struct sptm_user_geometry *g;struct sptm_fixed_view *v;int tpro,start;
    const volatile uint64_t *(*table)(void *,uint64_t);struct sptm_view_mapped_stats *st;
    uint64_t span_key,l3,leaf_va,leaf_desc;int span_valid,leaf_valid,leaf_ok,leaf_policy;
};
static int word_read(const struct sptm_memory *m,uint64_t pa,uint64_t *word)
{
    volatile uint8_t *p=m->map(m->ctx,pa,8);
    if(!p || (pa&7))return -1;
    *word=*(volatile uint64_t *)(void *)p;return 0;
}
static int view_source_leaf(struct view_mapped_walk *w,uint64_t va,uint64_t *out)
{
    unsigned shift=w->g->shift,l3_span=shift+shift-3;
    uint64_t key=va>>l3_span,d;
    if(w->start<0)return 0;
    if(!w->span_valid || w->span_key!=key) {
        uint64_t table=w->e->root&PT_OA_MASK;
        w->span_valid=0;w->st->span_walks++;
        for(int level=w->start;level<3;level++) {
            if(word_read(w->m,table+8UL*mmu_index(shift,(uint32_t)level,va),&d) ||
               !(d&PT_VALID) || !(d&PT_TABLE))return 0;
            table=d&PT_OA_MASK;
        }
        w->span_valid=1;w->span_key=key;w->l3=table;
    }
    if(word_read(w->m,w->l3+8UL*mmu_index(shift,3,va),&d) || !(d&PT_VALID) || !(d&PT_TABLE))
        return 0;
    *out=d;return 1;
}
static int view_mapped_leaf(struct view_mapped_walk *w,uint64_t va,uint64_t pte)
{
    const struct sptm_user_geometry *g=w->g;
    uint64_t page=va&~(g->page_size-1);
    if(!w->leaf_valid || w->leaf_va!=page) {
        w->leaf_valid=1;w->leaf_va=page;w->st->walks++;
        w->leaf_ok=view_source_leaf(w,page,&w->leaf_desc);
        w->leaf_policy=w->leaf_ok && w->tpro &&
            canonical_leaf(w->m,(unsigned)w->e->flags,g,page,w->leaf_desc);
    }
    if(!w->leaf_ok || !(w->tpro ? w->leaf_policy : sprr_fixed_native_leaf(pte)))return 0;
    uint64_t pa=(w->leaf_desc&PT_OA_MASK&~(g->page_size-1))|(va&(g->page_size-1));
    if(pa!=(pte&PT_OA_MASK) || ((w->leaf_desc^pte)&(PT_LEAF_ATTRS|PT_LEAF_UPPER)))return 0;
    w->v->pages++;w->v->classes|=1UL<<sprr_pte_class(pte);w->st->leaves++;
    return 1;
}
static int view_mapped_table(struct view_mapped_walk *w,uint64_t table,unsigned level,uint64_t base)
{
    if(!table || (table&4095) || ++w->v->tables>8192)return 0;
    const volatile uint64_t *words=w->table(w->s->ctx,table);
    if(!words)return 0;
    uint64_t span=mmu_level_size(12,level);
    for(unsigned group=0;group<512;group+=8) {
        uint64_t any=0;
        for(unsigned i=group;i<group+8;i++)any|=words[i];
        if(!any)continue;
        for(unsigned i=group;i<group+8;i++) {
            uint64_t pte=words[i],va=base+i*span;
            if(!pte)continue;
            if((pte&3)!=3 || va>=w->g->va_limit)return 0;
            if(level<3) {
                if((pte&~PT_OA_MASK)!=3 ||
                   !view_mapped_table(w,pte&PT_OA_MASK,level+1,va))return 0;
            } else if(!view_mapped_leaf(w,va,pte))return 0;
        }
    }
    return 1;
}
int sptm_root_view_mapped(const struct sptm_root_cached *e,const struct shadow *s,
    const struct sptm_memory *m,struct sptm_fixed_view *out,int tpro,
    const volatile uint64_t *(*table)(void *,uint64_t),struct sptm_view_mapped_stats *st)
{
    struct sptm_user_geometry g;struct sptm_fixed_view v={0};
    if(!table || !st)return 0;
    st->calls++;
    if(!e || !e->valid || !s || !s->read || s->txsz!=17 || s->root!=e->shadow ||
       !m || !m->map || !out ||
       !sptm_mac_user_geometry((unsigned)e->format,(unsigned)e->flags,&g) ||
       e->leaves>g.va_limit/g.page_size)return 0;
    /* A start level the walker refuses fails the reference at its first
     * leaf (mmu_walk returns -1); view_source_leaf does the same. */
    int start=mmu_start_level(g.shift,17);
    volatile uint8_t *meta=metadata(m,e->root);struct sptm_user_geometry actual;
    struct view_mapped_walk w={.e=e,.s=s,.m=m,.g=&g,.v=&v,.tpro=!!tpro,.start=start,
                               .table=table,.st=st};
    if(!root_header(m,meta,&actual) || get(meta+4,2)!=e->asid ||
       get(meta+10,2)!=e->flags || meta[12]!=e->format ||
       !view_mapped_table(&w,e->shadow,0,0) ||
       v.pages!=e->leaves*(g.page_size/4096))return 0;
    st->passed++;*out=v;return 1;
}

/* SPDX-License-Identifier: MIT */
#include "sptm-root.h"
#include "sptm-access.h"
#include "sptm-user.h"
#include "sptm-root-memo.h"
#if SNAP_ROOT_MISS_FAST
#include "root-miss.h"
#endif
#if SNAP_NEST_FAST || SNAP_DETACH_FAST
#include "nest-fast.h"
#endif
#define MASK 0x0000ffffffffc000UL
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
static int commit_leaf(struct sptm_root_cached *e,struct shadow *s,
    const struct sptm_memory *m,uint64_t va,unsigned shift,uint64_t expected,int inserted)
{
    struct sptm_user_geometry g;
    if(!e || !e->valid || !s || s->txsz!=17 || s->root!=e->shadow || !m || !m->map ||
       !sptm_mac_user_geometry((unsigned)e->format,(unsigned)e->flags,&g) ||
       shift!=g.shift || (va&(g.page_size-1)) || va>=g.va_limit)return 0;
    struct mmu_config cfg={shift,17,e->root};struct mmu_leaf leaf;
    if(mmu_walk(&cfg,va,checked_read,(void *)m,&leaf) || !leaf.valid ||
       leaf.level!=3 || leaf.descriptor!=expected || leaf.size!=g.page_size ||
       !canonical_leaf(m,(unsigned)e->flags,&g,va,leaf.descriptor))return 0;
    struct shadow commit=*s;commit.alloc=no_alloc;
    if(shadow_insert(&commit,&leaf,va,va+g.page_size))return 0;
    e->leaves+=(unsigned)inserted;return 1;
}
int sptm_root_commit_leaf(struct sptm_root_cached *e,struct shadow *s,
    const struct sptm_memory *m,uint64_t va,unsigned shift,uint64_t expected)
{return commit_leaf(e,s,m,va,shift,expected,1);}
int sptm_root_commit_update(struct sptm_root_cached *e,struct shadow *s,
    const struct sptm_memory *m,uint64_t va,unsigned shift,uint64_t old,uint64_t next)
{
    if((shift!=12 && shift!=14) || (old&3)!=3 || (next&3)!=3 ||
       ((old^next)&(PT_OA_MASK&~((1UL<<shift)-1))) || !e || !e->leaves || !s)return 0;
    struct mmu_config cfg={12,17,e->shadow};
    for(uint64_t off=0;off<(1UL<<shift);off+=4096) {
        struct mmu_leaf leaf;
        if(mmu_walk(&cfg,va+off,s->read,s->ctx,&leaf) || !leaf.valid || leaf.level!=3 ||
           leaf.pa!=(old&(PT_OA_MASK&~((1UL<<shift)-1)))+off ||
           ((leaf.descriptor^old)&(PT_LEAF_ATTRS|PT_LEAF_UPPER)))return 0;
    }
    return commit_leaf(e,s,m,va,shift,next,0);
}
static int unmap_geometry(struct sptm_root_cached *e,struct shadow *s,
    uint64_t va,unsigned shift,uint64_t count,struct sptm_user_geometry *g)
{
    return e && e->valid && s && s->read && s->write && s->txsz==17 &&
        s->root==e->shadow && sptm_mac_user_geometry((unsigned)e->format,(unsigned)e->flags,g) &&
        shift==g->shift && !(va&(g->page_size-1)) && va<g->va_limit &&
        count && count<=64 && count<=(g->va_limit-va)/g->page_size &&
        (va>>(2*shift-3))==((va+count*g->page_size-1)>>(2*shift-3));
}
int sptm_root_prepare_unmap(struct sptm_root_cached *e,struct shadow *s,
    const struct sptm_memory *m,uint64_t va,unsigned shift,uint64_t count)
{
    struct sptm_user_geometry g;
    if(!m || !m->map || !unmap_geometry(e,s,va,shift,count,&g))return 0;
    volatile uint8_t *meta=metadata(m,e->root);struct sptm_user_geometry root_g;
    if(!root_header(m,meta,&root_g) || get(meta+4,2)!=e->asid ||
       get(meta+10,2)!=e->flags || meta[12]!=e->format)return 0;
    struct mmu_config source={shift,17,e->root},hw={12,17,e->shadow};
    uint64_t removed=0;
    for(uint64_t n=0;n<count;n++) {
        uint64_t addr=va+n*g.page_size;struct mmu_leaf leaf;
        if(mmu_walk(&source,addr,checked_read,(void *)m,&leaf))return 0;
        if(leaf.valid && (leaf.level!=3 || leaf.size!=g.page_size))return 0;
        removed+=leaf.valid;
        for(uint64_t off=0;off<g.page_size;off+=4096) {
            struct mmu_leaf actual;
            if(mmu_walk(&hw,addr+off,s->read,s->ctx,&actual) || actual.valid!=leaf.valid)return 0;
            if(actual.valid && (actual.level!=3 || actual.pa!=leaf.pa+off ||
                ((actual.descriptor^leaf.descriptor)&(PT_LEAF_ATTRS|PT_LEAF_UPPER))))return 0;
        }
    }
    return removed<=e->leaves && !shadow_unmap(s,va,count*g.page_size,1);
}
int sptm_root_commit_unmap(struct sptm_root_cached *e,struct shadow *s,
    uint64_t va,unsigned shift,uint64_t count,uint64_t removed)
{
    struct sptm_user_geometry g;
    if(!unmap_geometry(e,s,va,shift,count,&g) || removed>count || removed>e->leaves)return 0;
    struct shadow commit=*s;commit.alloc=no_alloc;
    if(shadow_unmap(&commit,va,count*g.page_size,0))return 0;
    e->leaves-=removed;return 1;
}
static int detach_range(struct sptm_root_cached *e,struct shadow *s,uint64_t va,
    unsigned shift,unsigned level,struct sptm_user_geometry *g,uint64_t *base,uint64_t *end)
{
    if(!e || !e->valid || !s || !s->read || !s->write || s->txsz!=17 || s->root!=e->shadow ||
       !sptm_mac_user_geometry((unsigned)e->format,(unsigned)e->flags,g) ||
       shift!=g->shift || level<g->start || level>2 || (va&(g->page_size-1)) ||
       va>=g->va_limit || (sptm_mac_user_index(g,level,va)&(g->group-1)))return 0;
    uint64_t span=mmu_level_size(shift,level)*g->group;
    *base=va&~(span-1);*end=*base+span;
    if(*end>g->va_limit)*end=g->va_limit;
    return 1;
}
#if SNAP_DETACH_FAST
static int guest_level2(const struct sptm_memory *,const struct sptm_user_geometry *,
                        uint64_t,uint64_t,uint64_t *);
/* compat/nest-fast.h: 1 when neither the 16K guest tree nor the 4K shadow
 * maps a page in the 32 MiB [base,end) of one level-2 entry: the guest entry
 * is absent or names a table without a valid leaf, and shadow_range_empty
 * holds. 0: something is mapped, unusual or unreadable (the caller walks). */
static int detach_empty(const struct sptm_root_cached *e,const struct shadow *s,
    const struct sptm_memory *m,const struct sptm_user_geometry *g,uint64_t base,uint64_t end)
{
    uint64_t entry;
    if(guest_level2(m,g,e->root,base,&entry))return 0;
    if(entry&PT_VALID) {
        uint64_t table=entry&PT_OA_MASK;
        if(!(entry&PT_TABLE) || table!=(entry&g->pa_mask))return 0;
        volatile uint8_t *page=m->map(m->ctx,table,g->page_size);
        if(!page)return 0;
        for(unsigned i=0;i<g->page_size/8;i++)
            if((*(volatile uint64_t *)(void *)(page+8UL*i)&3)==3)return 0;
    }
    return shadow_range_empty(s,base,end-base)==1;
}
#endif
int sptm_root_prepare_detach(struct sptm_root_cached *e,struct shadow *s,
    const struct sptm_memory *m,uint64_t va,unsigned shift,unsigned level,uint64_t removed)
{
    struct sptm_user_geometry g;uint64_t base,end;
    if(!m || !m->map || !detach_range(e,s,va,shift,level,&g,&base,&end) || removed>e->leaves)return 0;
    volatile uint8_t *meta=metadata(m,e->root);struct sptm_user_geometry root_g;
    if(!root_header(m,meta,&root_g) || get(meta+4,2)!=e->asid ||
       get(meta+10,2)!=e->flags || meta[12]!=e->format)return 0;
#if SNAP_DETACH_FAST
    /* An empty level-3 table: the walks below find nothing and shadow_unmap
     * (check only) refuses nothing that shadow_range_empty accepted. */
    if(level==2 && !removed && shift==14 && g.shift==14 && end-base==mmu_level_size(14,2)) {
        if(detach_empty(e,s,m,&g,base,end)) {
            if(m->nest_fast)m->nest_fast->detach_fast++;
            return 1;
        }
        if(m->nest_fast)m->nest_fast->detach_slow++;
    }
#endif
    struct mmu_config source={shift,17,e->root},hw={12,17,e->shadow};uint64_t found=0;
    /* Skip absent subtrees using both walkers' returned levels. Higher-level
     * empty detachment must not iterate through terabytes one4K page at a time. */
    for(uint64_t addr=base;addr<end;) {
        struct mmu_leaf leaf,actual;
        if(mmu_walk(&source,addr,checked_read,(void *)m,&leaf) ||
           mmu_walk(&hw,addr,s->read,s->ctx,&actual) || leaf.valid!=actual.valid)return 0;
        if(leaf.valid) {
            if(leaf.level!=3 || actual.level!=3 || leaf.pa!=actual.pa ||
               ((leaf.descriptor^actual.descriptor)&(PT_LEAF_ATTRS|PT_LEAF_UPPER)))return 0;
            found+=!(addr&(g.page_size-1));addr+=4096;
        } else {
            uint64_t a=mmu_level_size(shift,leaf.level),b=mmu_level_size(12,actual.level);
            a=(addr&~(a-1))+a;b=(addr&~(b-1))+b;
            uint64_t next=a<b ? a:b;if(next<=addr)return 0;addr=next;
        }
    }
    return found==removed && !shadow_unmap(s,base,end-base,1);
}
int sptm_root_commit_detach(struct sptm_root_cached *e,struct shadow *s,
    uint64_t va,unsigned shift,unsigned level,uint64_t removed)
{
    struct sptm_user_geometry g;uint64_t base,end;
    if(!detach_range(e,s,va,shift,level,&g,&base,&end) || removed>e->leaves)return 0;
    struct shadow commit=*s;commit.alloc=no_alloc;
#if SNAP_DETACH_FAST
    /* Nothing to remove: shadow_unmap would validate, then store nothing. */
    if(level==2 && !removed && shift==14 && g.shift==14 && end-base==mmu_level_size(14,2) &&
       shadow_range_empty(&commit,base,end-base)==1)return 1;
#endif
    if(shadow_unmap(&commit,base,end-base,0))return 0;
    e->leaves-=removed;return 1;
}
static int attach_geometry(struct sptm_root_cached *e,struct shadow *s,
    const struct sptm_memory *m,uint64_t va,unsigned shift,uint64_t child,
    struct sptm_user_geometry *g,uint64_t *base,uint64_t *end)
{
    if(!m || !m->map || (child&0x3fff) ||
       !detach_range(e,s,va,shift,2,g,base,end))return 0;
    volatile uint8_t *root=metadata(m,e->root),*table=metadata(m,child);
    struct sptm_user_geometry root_g;
    return root_header(m,root,&root_g) && get(root+4,2)==e->asid &&
        get(root+10,2)==e->flags && root[12]==e->format &&
        sptm_mac_commpage_table_va((unsigned)e->flags,va) &&
        table && !get(table,2) && table[2]==SPTM_MAC_PAGE_TABLE_COMMPAGE && table[4]==3;
}
int sptm_root_prepare_attach(struct sptm_root_cached *e,struct shadow *s,
    const struct sptm_memory *m,uint64_t va,unsigned shift,uint64_t child)
{
    struct sptm_user_geometry g;uint64_t base,end;
    if(!attach_geometry(e,s,m,va,shift,child,&g,&base,&end))return 0;
    struct mmu_config source={shift,17,e->root},hw={12,17,e->shadow};
    for(uint64_t addr=base;addr<end;) {
        struct mmu_leaf a,b;
        if(mmu_walk(&source,addr,checked_read,(void *)m,&a) ||
           mmu_walk(&hw,addr,s->read,s->ctx,&b) || a.valid || b.valid)return 0;
        uint64_t x=mmu_level_size(shift,a.level),y=mmu_level_size(12,b.level);
        x=(addr&~(x-1))+x;y=(addr&~(y-1))+y;
        uint64_t next=x<y ? x:y;if(next<=addr)return 0;addr=next;
    }
    volatile uint8_t *page=m->map(m->ctx,child,0x4000);
    if(!page)return 0;
    for(unsigned i=0;i<2048;i++) {
        uint64_t pte=get(page+i*8,8),addr=base+i*g.page_size;
        if(!pte)continue;
        if((pte&3)!=3 || addr>=end || shadow_reserve(s,addr,g.page_size))return 0;
    }
    return 1;
}
int sptm_root_commit_attach(struct sptm_root_cached *e,struct shadow *s,
    const struct sptm_memory *m,uint64_t va,unsigned shift,uint64_t child)
{
    struct sptm_user_geometry g;uint64_t base,end;
    if(!attach_geometry(e,s,m,va,shift,child,&g,&base,&end))return 0;
    volatile uint8_t *page=m->map(m->ctx,child,0x4000);
    if(!page)return 0;
    for(unsigned i=0;i<2048;i++) {
        uint64_t pte=get(page+i*8,8),addr=base+i*g.page_size;
        if(!pte)continue;
        if((pte&3)!=3 || addr>=end ||
           !sptm_root_commit_leaf(e,s,m,addr,shift,pte))return 0;
    }
    return 1;
}
static int nest_geometry(struct sptm_root_cached *e,struct shadow *s,
    const struct sptm_memory *m,uint64_t shared,uint64_t va,unsigned shift,uint64_t pages,
    struct sptm_user_geometry *g,uint64_t *base,uint64_t *end)
{
    if(!m || !m->map || !s || !s->read || !s->write || !e || !e->valid ||
       s->root!=e->shadow || s->txsz!=17 ||
       !sptm_mac_user_geometry((unsigned)e->format,(unsigned)e->flags,g) ||
       shift!=g->shift || (va&(g->page_size-1)) || va>=g->va_limit ||
       !pages || pages>(g->va_limit-va)/g->page_size)return 0;
    volatile uint8_t *u=metadata(m,e->root);struct sptm_user_geometry actual;
    if(!root_header(m,u,&actual) || get(u+4,2)!=e->asid || u[12]!=e->format ||
       get(u+10,2)!=e->flags || u[8]==255 ||
       m->shared_regions->slots[u[8]].root!=shared)return 0;
    uint64_t span=mmu_level_size(shift,2);
    *base=va&~(span-1);*end=(va+(pages-1)*g->page_size+span)&~(span-1);
    return *end<=g->va_limit && *end>*base;
}
static uint64_t next_boundary(uint64_t addr,unsigned shift,unsigned level)
{
    uint64_t span=mmu_level_size(shift,level);
    return (addr&~(span-1))+span;
}
int sptm_root_prepare_nest(struct sptm_root_cached *e,struct shadow *s,
    const struct sptm_memory *m,uint64_t shared,uint64_t va,unsigned shift,uint64_t pages)
{
    struct sptm_user_geometry g;uint64_t base,end;
    if(!nest_geometry(e,s,m,shared,va,shift,pages,&g,&base,&end))return 0;
    struct mmu_config source={shift,17,shared},target={shift,17,e->root},hw={12,17,e->shadow};
    for(uint64_t addr=base;addr<end;) {
        struct mmu_leaf b,h;
        if(mmu_walk(&target,addr,checked_read,(void *)m,&b) ||
           mmu_walk(&hw,addr,s->read,s->ctx,&h) || b.valid || h.valid)return 0;
        uint64_t next=end;
        uint64_t x=next_boundary(addr,shift,b.level),y=next_boundary(addr,12,h.level);
        if(x<next)next=x;if(y<next)next=y;
        if(next<=addr)return 0;addr=next;
    }
    for(uint64_t addr=base;addr<end;) {
        struct mmu_leaf a;
        if(mmu_walk(&source,addr,checked_read,(void *)m,&a))return 0;
        if(a.valid) {
            volatile uint8_t *data=metadata(m,a.pa&MASK);
            if(a.level!=3 || a.size!=g.page_size || !sprr_fixed_native_leaf(a.descriptor) ||
               !data || get(data,2) ||
               sptm_mac_user_leaf_policy(e->flags,21,data[2],addr,a.descriptor,&g) ||
               !m->map(m->ctx,a.pa,g.page_size) || shadow_reserve(s,addr,g.page_size))return 0;
        }
        uint64_t next=next_boundary(addr,shift,a.level);
        if(next<=addr)return 0;addr=next;
    }
    return 1;
}
int sptm_root_commit_nest(struct sptm_root_cached *e,struct shadow *s,
    const struct sptm_memory *m,uint64_t shared,uint64_t va,unsigned shift,uint64_t pages)
{
    struct sptm_user_geometry g;uint64_t base,end;
    if(!nest_geometry(e,s,m,shared,va,shift,pages,&g,&base,&end))return 0;
    struct mmu_config source={shift,17,shared},target={shift,17,e->root};
    struct shadow commit=*s;commit.alloc=no_alloc;
    uint64_t added=0;
    for(uint64_t addr=base;addr<end;) {
        struct mmu_leaf a,b;
        if(mmu_walk(&source,addr,checked_read,(void *)m,&a) ||
           mmu_walk(&target,addr,checked_read,(void *)m,&b) ||
           a.valid!=b.valid || a.level!=b.level || a.descriptor!=b.descriptor)return 0;
        if(a.valid) {
            if(a.level!=3 || a.size!=g.page_size || !sprr_fixed_native_leaf(a.descriptor) ||
               shadow_insert(&commit,&a,addr,addr+g.page_size))return 0;
            added++;
        }
        uint64_t next=next_boundary(addr,shift,a.level);
        if(next<=addr)return 0;addr=next;
    }
    e->leaves+=added;return 1;
}
static int unnest_view(struct sptm_root_cached *e,struct shadow *s,
    const struct sptm_memory *m,uint64_t shared,unsigned shift,
    const struct sptm_unnest_plan *p,int commit)
{
    struct sptm_user_geometry g;uint64_t base,end;
    if(!p || !p->count || p->count>2048 || p->span!=mmu_level_size(shift,2) ||
       !nest_geometry(e,s,m,shared,p->base,shift,p->count*p->span/(1UL<<shift),&g,&base,&end) ||
       base!=p->base || p->leaves>e->leaves)return 0;
    struct mmu_config source={shift,17,e->root},hw={12,17,e->shadow};
    uint64_t found=0,descriptors=0;
    for(unsigned i=0;i<2048;i++)if(p->mask[i/64]&(1UL<<(i%64))) {
        if(i>=p->count)return 0;descriptors++;
        uint64_t start=p->base+i*p->span,stop=start+p->span;
        for(uint64_t addr=start;addr<stop;) {
            struct mmu_leaf a,b;
            if(mmu_walk(&source,addr,checked_read,(void *)m,&a) ||
               mmu_walk(&hw,addr,s->read,s->ctx,&b))return 0;
            if(commit) {if(a.valid || a.level>2)return 0;}
            else if(a.valid!=b.valid)return 0;
            if(b.valid) {
                if(b.level!=3 || (!commit && (a.level!=3 || a.pa!=b.pa ||
                    ((a.descriptor^b.descriptor)&(PT_LEAF_ATTRS|PT_LEAF_UPPER)))))return 0;
                found+=!(addr&(g.page_size-1));addr+=4096;
            } else {
                uint64_t next=next_boundary(addr,12,b.level);
                if(!commit) {uint64_t x=next_boundary(addr,shift,a.level);if(x<next)next=x;}
                if(next<=addr)return 0;addr=next;
            }
        }
        if(shadow_unmap(s,start,p->span,1))return 0;
    }
    if(found!=p->leaves || descriptors!=p->descriptors)return 0;
    if(commit) {
        struct shadow noalloc=*s;noalloc.alloc=no_alloc;
        for(unsigned i=0;i<p->count;i++)if(p->mask[i/64]&(1UL<<(i%64)))
            if(shadow_unmap(&noalloc,p->base+i*p->span,p->span,0))return 0;
        e->leaves-=found;
    }
    return 1;
}
int sptm_root_prepare_unnest(struct sptm_root_cached *e,struct shadow *s,
    const struct sptm_memory *m,uint64_t shared,unsigned shift,const struct sptm_unnest_plan *p)
{return unnest_view(e,s,m,shared,shift,p,0);}
int sptm_root_commit_unnest(struct sptm_root_cached *e,struct shadow *s,
    const struct sptm_memory *m,uint64_t shared,unsigned shift,const struct sptm_unnest_plan *p)
{return unnest_view(e,s,m,shared,shift,p,1);}
int sptm_root_build_shadow(const struct sptm_memory *m,struct shadow *s,
    uint64_t root,unsigned format,unsigned flags,uint64_t *leaves)
{
    struct sptm_user_geometry g;
    if(!m || !m->map || !s || !leaves || s->txsz!=17 || !s->root ||
       !sptm_mac_user_geometry(format,flags,&g))return 0;
    /* A build decides the shadow's content: never retained verdicts. */
#if SNAP_ROOT_MISS_FAST
    struct validation v={m,&g,flags,0,0,root,0,0,0};
#else
    struct validation v={m,&g,flags,0,0,root,0,0};
#endif
    if(!validate_table(&v,root,g.start,0))return 0;
    /* Existing root is inactive. Clear through the full shadow width even
     * when its new owner has a32-bit limit. Preserve empty table allocations. */
    if(shadow_unmap(s,0,1UL<<47,0))return 0;
    struct mmu_config cfg={g.shift,17,root};
    long n=shadow_build(s,&cfg,0,g.va_limit,checked_read,(void *)m);
    if(n<0)return 0;
    *leaves=(uint64_t)n;
    return 1;
}
/* SNAP_NATIVE_SHARED: nested guest level-2 entries are linked to shared
 * 4K groups (sptm-root.h, struct sptm_root_links) instead of copied. */
static int links_valid(const struct sptm_root_links *l)
{return l && l->group && l->link && l->linked && l->unlink;}
/* The guest level-2 entry of 16K root `root` at va, or 0 when a level above
 * is absent; -1 when unreadable or malformed. */
static int guest_level2(const struct sptm_memory *m,const struct sptm_user_geometry *g,
    uint64_t root,uint64_t va,uint64_t *entry)
{
    uint64_t l1;
    if(g->shift!=14 || g->start!=1 ||
       checked_read((void *)m,root+8UL*sptm_mac_user_index(g,1,va),&l1))return -1;
    if(!(l1&1)) {*entry=0;return 0;}
    if((l1&~g->pa_mask)!=3 || !(l1&g->pa_mask))return -1;
    return checked_read((void *)m,(l1&g->pa_mask)+8UL*sptm_mac_user_index(g,2,va),entry) ? -1 : 0;
}
/* A table entry naming a shared level-3 table: its PA, else 0. */
static uint64_t shared_child(const struct sptm_memory *m,const struct sptm_user_geometry *g,
    uint64_t entry)
{
    if((entry&3)!=3 || (entry&~g->pa_mask)!=3)return 0;
    volatile uint8_t *child=metadata(m,entry&g->pa_mask);
    return child && child[2]==SPTM_MAC_PAGE_TABLE_SHARED && child[4]==3 ? entry&g->pa_mask : 0;
}
uint64_t sptm_root_shared_child(const struct sptm_memory *m,uint64_t root,uint64_t va)
{
    struct sptm_user_geometry g;uint64_t entry;
    if(!m || !m->map || !sptm_mac_user_geometry(0,SPTM_MAC_ROOT_FLAGS_USER,&g) ||
       va>=(UINT64_C(1)<<47) || guest_level2(m,&g,root,va,&entry))return 0;
    return shared_child(m,&g,entry);
}
#if SNAP_ROOT_MISS_FAST
static int build_linked(const struct sptm_memory *m,struct shadow *s,uint64_t root,
    unsigned format,unsigned flags,uint64_t *leaves,const struct sptm_root_links *l,
    struct sptm_root_memo *memo,int (*grouped)(void *,uint64_t,uint64_t));
int sptm_root_build_linked(const struct sptm_memory *m,struct shadow *s,
    uint64_t root,unsigned format,unsigned flags,uint64_t *leaves,const struct sptm_root_links *l)
{return build_linked(m,s,root,format,flags,leaves,l,0,0);}
int sptm_root_build_linked_memo(const struct sptm_memory *m,struct shadow *s,uint64_t root,
    unsigned format,unsigned flags,uint64_t *leaves,const struct sptm_root_links *l,
    struct sptm_root_memo *memo,int (*grouped)(void *,uint64_t,uint64_t))
{return memo && !grouped ? 0 : build_linked(m,s,root,format,flags,leaves,l,memo,grouped);}
/* Only the shared children this build links to an existing group
 * (shared_child below: attrs 3, type SHARED, level 3 -- exactly
 * validate_table's shared branch) may be answered by a verdict: a child
 * whose group the build creates is copied into it, so it is scanned in full
 * first, like every table the build copies into the root's own tree. */
static int build_linked(const struct sptm_memory *m,struct shadow *s,uint64_t root,
    unsigned format,unsigned flags,uint64_t *leaves,const struct sptm_root_links *l,
    struct sptm_root_memo *memo,int (*grouped)(void *,uint64_t,uint64_t))
#else
int sptm_root_build_linked(const struct sptm_memory *m,struct shadow *s,
    uint64_t root,unsigned format,unsigned flags,uint64_t *leaves,const struct sptm_root_links *l)
#endif
{
    struct sptm_user_geometry g;
    if(!links_valid(l) || format || !m || !m->map || !s || !s->read || !leaves ||
       s->txsz!=17 || !s->root || !sptm_mac_user_geometry(format,flags,&g))return 0;
#if SNAP_ROOT_MISS_FAST
    struct validation v={m,&g,flags,0,0,root,0,memo,1};
#else
    struct validation v={m,&g,flags,0,0,root,0,0};
#endif
    if(!validate_table(&v,root,g.start,0))return 0;
    /* A fresh tree only: clearing through a linked group would clear leaves
     * every nesting address space shares. */
    for(unsigned i=0;i<512;i++) {
        uint64_t d;
        if(s->read(s->ctx,s->root+8UL*i,&d) || d)return 0;
    }
    struct mmu_config cfg={g.shift,17,root};
    uint64_t total=0,span=mmu_level_size(14,2);
    for(uint64_t va=0;va<g.va_limit;) {
        uint64_t l1;
        if(checked_read((void *)m,root+8UL*sptm_mac_user_index(&g,1,va),&l1))return 0;
        uint64_t next=next_boundary(va,14,1);
        if(!(l1&1)) {va=next;continue;}
        if(next>g.va_limit)next=g.va_limit;
        for(;va<next;va+=span) {
            uint64_t entry,child,n=0;
            if(guest_level2(m,&g,root,va,&entry))return 0;
            if(!(entry&1))continue;
            if((child=shared_child(m,&g,entry))) {
#if SNAP_ROOT_MISS_FAST
                if(memo && !root_miss_linked_only(grouped(l->ctx,child,va))) {
                    struct validation full={m,&g,flags,0,0,root,0,0,0};
                    if(!validate_table(&full,child,3,va))return 0;
                }
#endif
                if(va+span>g.va_limit || l->group(l->ctx,child,va)<0 ||
                   !l->link(l->ctx,child,va,&n))return 0;
            } else {
                long built=shadow_build(s,&cfg,va,va+span<next ? va+span : next,checked_read,(void *)m);
                if(built<0)return 0;
                n=(uint64_t)built;
            }
            total+=n;
        }
    }
    *leaves=total;return 1;
}
#if SNAP_NEST_FAST
/* compat/nest-fast.h. validate_table's level-3 scan of shared table `table`
 * reached at `base` under root `flags`, without the memo: what a retained
 * verdict means. */
static int shared_validates(const struct sptm_memory *m,const struct sptm_user_geometry *g,
    uint64_t table,uint64_t base,unsigned flags)
{
#if SNAP_ROOT_MISS_FAST
    struct validation v={m,g,flags,0,0,0,1,0,0};
#else
    struct validation v={m,g,flags,0,0,0,1,0};
#endif
    return validate_table(&v,table,3,base);
}
/* 1: the table's level-3 scan is proved, by a retained verdict or by
 * shared_validates (recorded at once); 0: not proved; -1: a sampled rescan
 * of a retained verdict failed (fatal, a mismatch). */
static int shared_proof(const struct sptm_memory *m,const struct sptm_user_geometry *g,
    uint64_t table,uint64_t base,unsigned flags,int unnest)
{
    struct sptm_nest_fast_stats *st=m->nest_fast;
    struct sptm_root_memo *memo=m->root_memo;
    volatile uint8_t *meta=metadata(m,table&MASK);
#if SNAP_UNNEST_4K_FAST
    /* compat/nest-fast.h 3: also a 4K table, 4K aligned in its frame. */
    if(!memo || !meta || (g->shift!=14 && g->shift!=12) || (table&g->pa_mask)!=table)return 0;
#else
    if(!memo || !meta || g->shift!=14 || (table&MASK)!=table)return 0;
#endif
    uint64_t record=sptm_root_memo_record_bytes(meta);
    if(sptm_root_memo_peek(memo,table,base,flags,g->shift,record)) {
        memo->stats.hits++;
        uint64_t n=st ? (unnest ? ++st->unnest_hits : ++st->nest_hits) : 0;
        if(!(n&SPTM_NEST_FAST_SAMPLE)) {
            if(st)st->sampled++;
            if(!shared_validates(m,g,table,base,flags)) {if(st)st->mismatches++;return -1;}
        }
        return 1;
    }
    if(st) {if(unnest)st->unnest_scans++;else st->nest_scans++;}
    if(!shared_validates(m,g,table,base,flags))return 0;
    memo->stats.misses++;
    sptm_root_memo_store(memo,table,base,flags,g->shift,record);
    if(st) {if(unnest)st->unnest_records++;else st->nest_records++;}
    return 1;
}
int sptm_root_shared_proof(const struct sptm_memory *m,uint64_t table,uint64_t base,
                           unsigned format,unsigned flags)
{
    struct sptm_user_geometry g;
    if(!m || !m->map || !sptm_mac_user_geometry(format,flags,&g))return 0;
    return shared_proof(m,&g,table,base,flags,1);
}
#if SNAP_UNNEST_4K_FAST
/* compat/nest-fast.h 3: shared_proof itself for a 4K table at shift 12 (the
 * same verdicts, sampling and accounting). A hit that was not sampled also
 * hands back the leaf count its verdict carries; a sampled hit (rescanned by
 * shared_proof), a recorded miss or no counters leave *known UINT64_MAX, so
 * the caller counts and sptm_root_shared_count_4k records or compares. */
int sptm_root_shared_proof_4k(const struct sptm_memory *m,uint64_t table,uint64_t base,
                              unsigned format,unsigned flags,uint64_t *known)
{
    struct sptm_user_geometry g;
    if(!known)return 0;
    *known=UINT64_MAX;
    if(!m || !m->map || !sptm_mac_user_geometry(format,flags,&g) || g.shift!=12)return 0;
    struct sptm_nest_fast_stats *st=m->nest_fast;
    uint64_t hits=st ? st->unnest_hits : 0,sampled=st ? st->sampled : 0;
    int r=shared_proof(m,&g,table,base,flags,1);
    if(r==1 && st && st->unnest_hits!=hits && st->sampled==sampled) {
        volatile uint8_t *meta=metadata(m,table&MASK);
        struct sptm_root_memo_entry *e=!meta ? 0 :
            sptm_root_memo_entry_of(m->root_memo,table,base,flags,g.shift,sptm_root_memo_record_bytes(meta));
        if(e)*known=sptm_root_memo_leaves(e);
        if(*known!=UINT64_MAX)st->unnest_counted++;
    }
    return r;
}
int sptm_root_shared_count_4k(const struct sptm_memory *m,uint64_t table,uint64_t base,
                              unsigned format,unsigned flags,uint64_t leaves)
{
    struct sptm_user_geometry g;
    if(!m || !m->map || !sptm_mac_user_geometry(format,flags,&g) || g.shift!=12 ||
       leaves>g.page_size/8)return 0;
    struct sptm_root_memo *memo=m->root_memo;
    volatile uint8_t *meta=metadata(m,table&MASK);
    if(!memo || !meta)return 0;
    struct sptm_root_memo_entry *e=
        sptm_root_memo_entry_of(memo,table,base,flags,g.shift,sptm_root_memo_record_bytes(meta));
    if(!e)return 0;
    uint64_t had=sptm_root_memo_leaves(e);
    if(had!=UINT64_MAX && had!=leaves) {if(m->nest_fast)m->nest_fast->mismatches++;return -1;}
    sptm_root_memo_set_leaves(e,leaves);
    return 1;
}
#endif
/* The per-address source check of sptm_root_prepare_nest_linked over the
 * 32 MiB of a level-2 entry naming shared table `table`, reading the table
 * once with word loads: every valid leaf (bits1:0 = 3, what mmu_walk reports
 * as a level-3 leaf) is a fixed native class over an unlocked managed frame
 * the root's policy admits, mappable. -1: the page cannot be mapped (the
 * caller walks per address, as before). */
static int nest_table_scan(const struct sptm_memory *m,const struct sptm_user_geometry *g,
    uint64_t table,uint64_t base,unsigned flags)
{
    volatile uint8_t *page=m->map(m->ctx,table,g->page_size);
    if(!page)return -1;
    for(unsigned i=0;i<g->page_size/8;i++) {
        uint64_t pte=*(volatile uint64_t *)(void *)(page+8UL*i);
        if((pte&3)!=3)continue;
        uint64_t addr=base+i*g->page_size;
        volatile uint8_t *data=metadata(m,pte&MASK);
        if(!sprr_fixed_native_leaf(pte) || !data || get(data,2) ||
           sptm_mac_user_leaf_policy(flags,21,data[2],addr,pte,g) ||
           !m->map(m->ctx,pte&MASK,g->page_size))return 0;
    }
    return 1;
}
#endif
int sptm_root_prepare_nest_linked(struct sptm_root_cached *e,struct shadow *s,
    const struct sptm_memory *m,uint64_t shared,uint64_t va,unsigned shift,uint64_t pages,
    const struct sptm_root_links *l)
{
    struct sptm_user_geometry g;uint64_t base,end;
    if(!links_valid(l) || shift!=14 || !nest_geometry(e,s,m,shared,va,shift,pages,&g,&base,&end))
        return 0;
    struct mmu_config source={shift,17,shared},target={shift,17,e->root},hw={12,17,e->shadow};
    for(uint64_t addr=base;addr<end;) {
        struct mmu_leaf b,h;
        if(mmu_walk(&target,addr,checked_read,(void *)m,&b) ||
           mmu_walk(&hw,addr,s->read,s->ctx,&h) || b.valid || h.valid)return 0;
        uint64_t next=end;
        uint64_t x=next_boundary(addr,shift,b.level),y=next_boundary(addr,12,h.level);
        if(x<next)next=x;if(y<next)next=y;
        if(next<=addr)return 0;addr=next;
    }
    /* Every source leaf must suit this root's policy, exactly as for a copy. */
#if SNAP_NEST_FAST
    /* Per level-2 entry (compat/nest-fast.h 1); any entry not naming a
     * shared level-3 table, or whose page cannot be mapped, is walked per
     * address over its 32 MiB exactly as before. */
    uint64_t lspan=mmu_level_size(14,2);
    for(uint64_t at=base;at<end;at+=lspan) {
        uint64_t entry,child;int r=0;
        if(!guest_level2(m,&g,shared,at,&entry) && (child=shared_child(m,&g,entry))) {
            if(m->nest_fast)m->nest_fast->nest_tables++;
            r=shared_proof(m,&g,child,at,(unsigned)e->flags,0);
            if(r<0)return 0;
            if(!r)r=nest_table_scan(m,&g,child,at,(unsigned)e->flags);
            if(!r)return 0;
        }
        if(r==1)continue;
        if(m->nest_fast)m->nest_fast->nest_walked++;
        for(uint64_t addr=at;addr<at+lspan;) {
#else
    for(uint64_t addr=base;addr<end;) {
#endif
        struct mmu_leaf a;
        if(mmu_walk(&source,addr,checked_read,(void *)m,&a))return 0;
        if(a.valid) {
            volatile uint8_t *data=metadata(m,a.pa&MASK);
            if(a.level!=3 || a.size!=g.page_size || !sprr_fixed_native_leaf(a.descriptor) ||
               !data || get(data,2) ||
               sptm_mac_user_leaf_policy(e->flags,21,data[2],addr,a.descriptor,&g) ||
               !m->map(m->ctx,a.pa,g.page_size))return 0;
        }
        uint64_t next=next_boundary(addr,shift,a.level);
        if(next<=addr)return 0;addr=next;
    }
#if SNAP_NEST_FAST
    }
#endif
    /* Groups exist and the level-2 path is allocated before publication. */
    uint64_t span=mmu_level_size(14,2);
    for(uint64_t addr=base;addr<end;addr+=span) {
        uint64_t entry,child,table;
        if(guest_level2(m,&g,shared,addr,&entry) || !(child=shared_child(m,&g,entry)) ||
           l->group(l->ctx,child,addr)<0 || shadow_table(s,2,addr,&table))return 0;
    }
    return 1;
}
int sptm_root_commit_nest_linked(struct sptm_root_cached *e,struct shadow *s,
    const struct sptm_memory *m,uint64_t shared,uint64_t va,unsigned shift,uint64_t pages,
    const struct sptm_root_links *l)
{
    struct sptm_user_geometry g;uint64_t base,end,added=0;
    if(!links_valid(l) || shift!=14 || !nest_geometry(e,s,m,shared,va,shift,pages,&g,&base,&end))
        return 0;
    uint64_t span=mmu_level_size(14,2);
    for(uint64_t addr=base;addr<end;addr+=span) {
        uint64_t a,b,child,n;
        if(guest_level2(m,&g,shared,addr,&a) || guest_level2(m,&g,e->root,addr,&b) ||
           a!=b || !(child=shared_child(m,&g,a)) || !l->link(l->ctx,child,addr,&n))return 0;
        added+=n;
    }
    e->leaves+=added;return 1;
}
static int unnest_linked(struct sptm_root_cached *e,struct shadow *s,
    const struct sptm_memory *m,uint64_t shared,unsigned shift,
    const struct sptm_unnest_plan *p,const struct sptm_root_links *l,int commit)
{
    struct sptm_user_geometry g;uint64_t base,end;
    if(!links_valid(l) || shift!=14 || !p || !p->count || p->count>2048 ||
       p->span!=mmu_level_size(shift,2) ||
       !nest_geometry(e,s,m,shared,p->base,shift,p->count*p->span/(1UL<<shift),&g,&base,&end) ||
       base!=p->base || p->leaves>e->leaves)return 0;
    uint64_t found=0,descriptors=0;
    for(unsigned i=0;i<2048;i++)if(p->mask[i/64]&(1UL<<(i%64))) {
        if(i>=p->count)return 0;descriptors++;
        uint64_t addr=p->base+i*p->span,a,b,child,n;
        /* Before publication the root still names the shared table; after
         * it, nothing. The group is always found through the shared root. */
        if(guest_level2(m,&g,shared,addr,&a) || guest_level2(m,&g,e->root,addr,&b) ||
           !(child=shared_child(m,&g,a)) || (commit ? b!=0 : b!=a))return 0;
        if(!(commit ? l->unlink(l->ctx,child,addr,&n) : l->linked(l->ctx,child,addr,&n)))return 0;
        found+=n;
    }
    if(found!=p->leaves || descriptors!=p->descriptors)return 0;
    if(commit)e->leaves-=found;
    return 1;
}
int sptm_root_prepare_unnest_linked(struct sptm_root_cached *e,struct shadow *s,
    const struct sptm_memory *m,uint64_t shared,unsigned shift,const struct sptm_unnest_plan *p,
    const struct sptm_root_links *l)
{return unnest_linked(e,s,m,shared,shift,p,l,0);}
int sptm_root_commit_unnest_linked(struct sptm_root_cached *e,struct shadow *s,
    const struct sptm_memory *m,uint64_t shared,unsigned shift,const struct sptm_unnest_plan *p,
    const struct sptm_root_links *l)
{return unnest_linked(e,s,m,shared,shift,p,l,1);}
int sptm_root_invalidate(struct sptm_root_state *s,uint64_t root,int retire)
{
    if(!s || !root || active_count(s,root))return 0;
    for(unsigned i=0;i<SPTM_ROOT_CACHE;i++)if(s->cache[i].root==root) {
        s->cache[i].valid=0;
        if(retire)s->cache[i].root=0;
        s->invalidations++;
    }
    return 1;
}
unsigned sptm_root_reclaim_pick(const struct sptm_root_state *s,
    const uint64_t stamp[SPTM_ROOT_CACHE],sptm_root_mask_t exclude)
{
    unsigned best=SPTM_ROOT_CACHE,best_rank=4;uint64_t best_age=UINT64_MAX;
    if(!s)return best;
    for(unsigned n=0;n<SPTM_ROOT_CACHE;n++) {
        unsigned i=(unsigned)((s->builds+n)%SPTM_ROOT_CACHE);
        const struct sptm_root_cached *e=&s->cache[i];
        if(SPTM_ROOT_MASK_HAS(exclude,i))continue;
        unsigned rank;
        if(!e->root) {
            if(!e->shadow)continue;
            rank=1;
        } else {
            if(active_count(s,e->root))continue;
            rank=e->valid ? 3 : 2;
        }
        uint64_t age=rank==3 && stamp ? stamp[i] : 0;
        if(rank<best_rank || (rank==best_rank && age<best_age)) {
            best=i;best_rank=rank;best_age=age;
        }
    }
    return best;
}
int sptm_root_reclaim_forget(struct sptm_root_state *s,unsigned slot)
{
    if(!s || slot>=SPTM_ROOT_CACHE)return 0;
    struct sptm_root_cached *e=&s->cache[slot];
    if(e->root && active_count(s,e->root))return 0;
    if(e->valid)s->invalidations++;
    e->root=0;e->shadow=0;e->leaves=0;e->asid=0;e->format=0;e->flags=0;e->valid=0;
    return 1;
}
/* Read-only: the cache entry sptm_mac_switch_root selects for root (the last
 * slot naming it) is valid for this identity, so no build follows. */
static int cache_hit(const struct sptm_root_state *s,uint64_t root,unsigned asid,
                     unsigned format,unsigned flags)
{
    const struct sptm_root_cached *entry=0;
    for(unsigned i=0;i<SPTM_ROOT_CACHE;i++)if(s->cache[i].root==root)entry=&s->cache[i];
    return entry && entry->valid && entry->asid==asid && entry->format==format && entry->flags==flags;
}
enum sptm_result sptm_mac_switch_root(const struct sptm_memory *m,
    struct sptm_root_state *s,const struct sptm_root_backend *b,unsigned cpu,
    uint64_t root,uint64_t set_flags,uint64_t clear_flags)
{
    if(!m || !m->map || !m->publish || !s || !b || !b->build || !b->install ||
       cpu>=SPTM_ROOT_CPUS || !b->kernel_root || !b->kernel_shadow ||
       (b->kernel_root&0x3fff) || (b->kernel_shadow&0xfff) ||
       !sptm_boot_memory_valid(m) ||
       ((m->frame_low|m->frame_high|m->alloc_low|m->alloc_high)&0x3fff) ||
       (m->frame_map_pa&15) || m->frame_low>=m->frame_high ||
       m->alloc_low>=m->alloc_high || m->alloc_low<m->frame_low ||
       m->alloc_high>m->frame_high ||
       m->frame_map_pa>UINT64_MAX-((m->frame_high-m->frame_low)>>14)*16)
        return SPTM_BAD_CONFIG;
    /* The observed native call uses no overrides. APRR/domain overrides have
     * additional semantics; do not accept them as harmless flag changes. */
    if(set_flags || clear_flags)return SPTM_UNSUPPORTED_OPTIONS;
    if(!root || (root&0x3fff))return SPTM_BAD_ADDRESS;
    uint64_t old=s->active[cpu];
    volatile uint8_t *old_meta=old ? metadata(m,old) : 0;
    struct sptm_user_geometry g;
    if(old && (!root_header(m,old_meta,&g) || get(old_meta+6,2)<active_count(s,old)))
        return SPTM_BAD_REFERENCE;
    if(root==b->kernel_root) {
        b->install(b->ctx,b->kernel_shadow,b->kernel_root,0,0);
        sprr_root_reset(&s->sprr[cpu],0);
        if(old) {put16(old_meta+6,(unsigned)get(old_meta+6,2)-1);
            m->publish(m->ctx,m->frame_map_pa+((old-m->frame_low)>>14)*16,16);}
        s->active[cpu]=0;s->switches++;s->kernel_switches++;
        return SPTM_OK;
    }
    volatile uint8_t *meta=metadata(m,root);
    if(!root_header(m,meta,&g))return SPTM_BAD_TABLE;
    unsigned flags=(unsigned)get(meta+10,2),asid=(unsigned)get(meta+4,2),format=meta[12];
#if SNAP_USER_HW_WALK
    if(b->hw_eligible) {
        int hw=b->hw_eligible(b->ctx,m,root,asid,format,flags);
        if(hw<0)return SPTM_BAD_TABLE;
        if(hw) {
            /* No walk counts the root's children: keep the bounds config()
             * applies to every user call (children plus CPU references). */
            unsigned cpus=active_count(s,root);
            if(get(meta+6,2)<cpus || get(meta+6,2)>g.root_groups+cpus)return SPTM_BAD_REFERENCE;
            b->install(b->ctx,0,root,asid,format);
            goto installed;
        }
    }
#endif
    /* Keep the actual activation state, including UMPRR field9. The explicit
     * TPRO backend contract admits typed raw selector9 only in canonical
     * storage; install must translate it before guest resumption. */
    struct sptm_root_validate_stats *vs=b->validate;
    int hit=cache_hit(s,root,asid,format,flags);
    /* Audit mode: an exact-by-construction cached shadow is not walked on
     * every hit; the owner samples which hits still are. */
    int walk=!hit || !b->skip_hit_validation || !b->skip_hit_validation(b->ctx);
    /* Retained level-3 verdicts only when this switch installs the cached
     * shadow (the entry selected below is already valid for this identity),
     * and only with the sampled reference walk that checks them. */
#if SNAP_ROOT_MISS_FAST
    /* A miss of a 16K root whose build links its shared tables: the walk may
     * answer those tables, and only those, from memo (compat/root-miss.h).
     * calls still counts cache-hit validations only. */
    int shared_only=!hit && b->linked_builds && !format;
    struct sptm_root_memo *memo=vs && b->memo && (hit || shared_only) ? b->memo : 0;
    struct validation v={m,&g,flags,0,0,root,vs!=0,memo,shared_only};
    if(walk && memo && hit)memo->stats.calls++;
#else
    struct sptm_root_memo *memo=vs && b->memo && hit ? b->memo : 0;
    struct validation v={m,&g,flags,0,0,root,vs!=0,memo};
    if(walk && memo)memo->stats.calls++;
#endif
    int valid=!walk || validate_table(&v,root,g.start,0);
    if(walk && vs) {
        /* Every 64th word-load validation repeats the original byte-load walk
         * and must reach the same verdict, table count and root-group count.
         * A difference is terminal; the byte result is never substituted.
         * The reference walk never uses retained verdicts. */
        if(!(++vs->validations&SPTM_ROOT_VALIDATE_SAMPLE)) {
#if SNAP_ROOT_MISS_FAST
            struct validation bytes={m,&g,flags,0,0,root,0,0,0};
#else
            struct validation bytes={m,&g,flags,0,0,root,0,0};
#endif
            int again=validate_table(&bytes,root,g.start,0);
            vs->sampled++;if(memo)memo->stats.sampled++;
            if(again!=valid || bytes.tables!=v.tables || bytes.root_children!=v.root_children) {
                vs->mismatches++;if(memo)memo->stats.mismatches++;return SPTM_BAD_TABLE;
            }
        }
        vs->tables+=v.tables;
    }
    if(!valid)return SPTM_BAD_TABLE;
    if((walk && get(meta+6,2)!=v.root_children+active_count(s,root)) ||
       get(meta+6,2)>=0x80b)return SPTM_BAD_REFERENCE;
    struct sptm_root_cached *entry=0,*empty=0;
    for(unsigned i=0;i<SPTM_ROOT_CACHE;i++) {
        struct sptm_root_cached *e=&s->cache[i];
        if(e->root==root)entry=e;
        if(!e->root && !empty)empty=e;
        if(e->root && e->root!=root && e->asid==asid)return SPTM_FRAME_BUSY;
    }
    if(!entry)entry=empty;
#if SNAP_ROOT_MISS_FAST
    /* Full cache with stamps: the least recently installed inactive root
     * gives up its slot (compat/root-miss.h), accounted as below. */
    if(!entry && b->stamp) {
        if(!(entry=root_miss_victim(s,b->stamp,root)))return SPTM_MEMORY_UNAVAILABLE;
        entry->valid=0;entry->root=0;s->invalidations++;
        if(b->evictions)(*b->evictions)++;
    }
#endif
    if(!entry) {
        /* Every slot names a root: more address spaces are live than slots.
         * A fast boot reaches that (61 processes plus an exec'ing xpcproxy
         * filled all 64). A cached shadow is derived state, so take the slot
         * of a root no CPU has installed -- an already invalidated one first,
         * then round robin. It loses nothing: user updates to an uncached
         * inactive root go to its guest tables, and its next switch rebuilds
         * the shadow from them. build() flushes all-VMID translations and
         * resets the slot's views before reuse, as for a retired root. */
        for(unsigned pass=0;pass<2 && !entry;pass++)
            for(unsigned n=0;n<SPTM_ROOT_CACHE && !entry;n++) {
                struct sptm_root_cached *e=&s->cache[(s->builds+n)%SPTM_ROOT_CACHE];
                if(e->root && e->root!=root && e->valid==pass && !active_count(s,e->root))entry=e;
            }
        if(!entry)return SPTM_MEMORY_UNAVAILABLE;
        entry->valid=0;entry->root=0;s->invalidations++;
        if(b->evictions)(*b->evictions)++;
    }
    if(entry->valid && (entry->asid!=asid || entry->format!=format || entry->flags!=flags))
        return SPTM_BAD_TABLE;
    uint64_t shadow=entry->shadow,leaves=entry->leaves;
    if(!entry->valid) {
        if(active_count(s,root))return SPTM_FRAME_BUSY;
        if(!b->build(b->ctx,m,root,format,flags,shadow,&shadow,&leaves) ||
           !shadow || (shadow&0xfff))return SPTM_MEMORY_UNAVAILABLE;
        entry->root=root;entry->shadow=shadow;entry->leaves=leaves;
        entry->asid=asid;entry->format=format;entry->flags=flags;entry->valid=1;
        s->builds++;
    }
    b->install(b->ctx,shadow,root,asid,format);
#if SNAP_USER_HW_WALK
installed:
#endif
    sprr_root_reset(&s->sprr[cpu],flags);
    if(old!=root) {
        put16(meta+6,(unsigned)get(meta+6,2)+1);
        m->publish(m->ctx,m->frame_map_pa+((root-m->frame_low)>>14)*16,16);
        if(old) {put16(old_meta+6,(unsigned)get(old_meta+6,2)-1);
            m->publish(m->ctx,m->frame_map_pa+((old-m->frame_low)>>14)*16,16);}
    }
    s->active[cpu]=root;s->switches++;s->user_switches++;
    return SPTM_OK;
}
#if SNAP_FINE_SWITCH
#include "fine-lock.h"
#if SNAP_FINE_SWITCH_HW && !SNAP_USER_HW_WALK
#error "SNAP_FINE_SWITCH_HW requires SNAP_USER_HW_WALK (the backend's hw_eligible hook)"
#endif
static unsigned active_count_fine(const struct sptm_root_state *s,uint64_t root)
{
    unsigned n=0;
    for(unsigned i=0;i<SPTM_ROOT_CPUS;i++)n+=__atomic_load_n(&s->active[i],__ATOMIC_RELAXED)==root;
    return n;
}
int sptm_mac_switch_root_hit(const struct sptm_memory *m,
    struct sptm_root_state *s,const struct sptm_root_backend *b,unsigned cpu,
    uint64_t root,uint64_t set_flags,uint64_t clear_flags)
{
    if(!m || !m->map || !m->publish || !s || !b || !b->build || !b->install ||
       cpu>=SPTM_ROOT_CPUS || !b->kernel_root || !b->kernel_shadow ||
       (b->kernel_root&0x3fff) || (b->kernel_shadow&0xfff) ||
       !sptm_boot_memory_valid(m) ||
       ((m->frame_low|m->frame_high|m->alloc_low|m->alloc_high)&0x3fff) ||
       (m->frame_map_pa&15) || m->frame_low>=m->frame_high ||
       m->alloc_low>=m->alloc_high || m->alloc_low<m->frame_low ||
       m->alloc_high>m->frame_high ||
       m->frame_map_pa>UINT64_MAX-((m->frame_high-m->frame_low)>>14)*16)
        return 0;
    if(set_flags || clear_flags)return 0;
    if(!root || (root&0x3fff))return 0;
    uint64_t old=s->active[cpu];
    volatile uint8_t *old_meta=old ? metadata(m,old) : 0;
    struct sptm_user_geometry g;
    if(old && (!root_header(m,old_meta,&g) || get(old_meta+6,2)<active_count_fine(s,old)))
        return 0;
    if(root==b->kernel_root) {
        b->install(b->ctx,b->kernel_shadow,b->kernel_root,0,0);
        sprr_root_reset(&s->sprr[cpu],0);
        if(old) {put16(old_meta+6,(unsigned)get(old_meta+6,2)-1);
            m->publish(m->ctx,m->frame_map_pa+((old-m->frame_low)>>14)*16,16);}
        __atomic_store_n(&s->active[cpu],0,__ATOMIC_RELEASE);
        __atomic_fetch_add(&s->switches,1,__ATOMIC_RELAXED);
        __atomic_fetch_add(&s->kernel_switches,1,__ATOMIC_RELAXED);
        return 1;
    }
    volatile uint8_t *meta=metadata(m,root);
    if(!root_header(m,meta,&g))return 0;
    unsigned flags=(unsigned)get(meta+10,2),asid=(unsigned)get(meta+4,2),format=meta[12];
#if SNAP_FINE_SWITCH_HW
    /* SNAP_FINE_SWITCH_HW: sptm_mac_switch_root's hardware-walk branch, for
     * a root whose record already exists. The owner's hook answers as
     * hw_eligible does but never attaches: 1 for a record of this identity,
     * -1 for a record of another (the token path refuses it: decline, and it
     * repeats and reports the call), 0 for no record (the token path's
     * shadow path or attach: the cache-hit test below, which then declines
     * a root with no cache entry). The reference bounds are the token path's,
     * with the activity words loaded atomically; the caller holds this
     * root's stripe, so no other CPU switches to or from it meanwhile. */
    if(b->hw_eligible) {
        int hw=b->hw_eligible(b->ctx,m,root,asid,format,flags);
        if(hw<0)return 0;
        if(hw) {
            unsigned cpus=active_count_fine(s,root);
            if(get(meta+6,2)<cpus || get(meta+6,2)>g.root_groups+cpus)return 0;
            b->install(b->ctx,0,root,asid,format);goto installed;
        }
    }
#endif
    if(!cache_hit(s,root,asid,format,flags) || !b->skip_hit_validation ||
       !b->skip_hit_validation(b->ctx))return 0;
    if(get(meta+6,2)>=0x80b)return 0;
    struct sptm_root_cached *entry=0;
    for(unsigned i=0;i<SPTM_ROOT_CACHE;i++) {
        struct sptm_root_cached *e=&s->cache[i];
        if(e->root==root)entry=e;
        if(e->root && e->root!=root && e->asid==asid)return 0;
    }
    if(!entry || !entry->valid || entry->asid!=asid || entry->format!=format || entry->flags!=flags)
        return 0;
    b->install(b->ctx,entry->shadow,root,asid,format);
#if SNAP_FINE_SWITCH_HW
installed:
#endif
    sprr_root_reset(&s->sprr[cpu],flags);
    if(old!=root) {
        put16(meta+6,(unsigned)get(meta+6,2)+1);
        m->publish(m->ctx,m->frame_map_pa+((root-m->frame_low)>>14)*16,16);
        if(old) {put16(old_meta+6,(unsigned)get(old_meta+6,2)-1);
            m->publish(m->ctx,m->frame_map_pa+((old-m->frame_low)>>14)*16,16);}
    }
    __atomic_store_n(&s->active[cpu],root,__ATOMIC_RELEASE);
    __atomic_fetch_add(&s->switches,1,__ATOMIC_RELAXED);
    __atomic_fetch_add(&s->user_switches,1,__ATOMIC_RELAXED);
    return 1;
}
#endif

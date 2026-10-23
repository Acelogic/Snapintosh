/* SPDX-License-Identifier: MIT */
/* User views and shadows, native user tables and shared groups, and user TLB
 * maintenance.
 * Part of probes/xnuboot.c's translation unit, included in order; not compiled on its own. */
static struct sptm_root_cached *user_cached(struct context *c,uint64_t root)
{
    for(unsigned i=0;i<SPTM_ROOT_CACHE;i++)
        if(c->user_roots.cache[i].root==root && c->user_roots.cache[i].valid)
            return &c->user_roots.cache[i];
    return 0;
}
static struct sprr_views *user_views(struct context *c,struct sptm_root_cached *e)
{return &UVIEWS(c)[e-c->user_roots.cache];}
static int user_private_write(void *ctx,uint64_t pa,uint64_t value)
{
    struct context *c=ctx;uint64_t old;
    if(kernel_table_read(c,pa,&old))return -1;
    if(old==value)return 0;
    /* A shared table path may become private while another CPU executes.
     * Break a valid output-address change before making its replacement. */
    if((old&1) && (value&1) && ((old^value)&PT_OA_MASK)) {
        if(kernel_table_write(c,pa,0))return -1;
        publish(pa,pa+8);
        __asm__ volatile("dsb ishst; tlbi alle1is; dsb ish; isb" ::: "memory");
        c->shadow_tlb_syncs++;
    }
    return kernel_table_write(c,pa,value);
}
static struct shadow user_shadow(struct context *c,struct sptm_root_cached *e)
{
    return (struct shadow){.txsz=17,.root=e->shadow,.alloc=user_table_alloc,
        .read=kernel_table_read,.write=user_private_write,.ctx=c,
        .alloc_ctx=&UOWNERS(c)[e-c->user_roots.cache],
        .admit=SNAP_NATIVE_WRITER_ADMISSION ? native_writer_admit_user:0};
}
/* Keep user_shadow's allocator canonical for shared and unnest commits. Only
 * sprr_views operations allocate permission copies through this constructor. */
static struct shadow user_view_shadow(struct context *c,struct sptm_root_cached *e)
{
    struct shadow s=user_shadow(c,e);s.alloc=private_user_alloc;return s;
}
#if SNAP_NATIVE_TABLES
/* UMPRR of a cached root, exactly as sprr_root_reset derives it. */
static uint64_t native_umprr(const struct sptm_root_cached *e)
{return ((uint64_t)(e->flags&8)<<15)|((uint64_t)(e->flags&1)<<11);}
/* Monitor-owned hardware ASIDs, never XNU's: one per (slot, w, k). The
 * kernel root keeps ASID 0. A slot's are flushed when it is released
 * (root_slot_release's all-VMID invalidation). */
static uint64_t native_asid(unsigned slot,unsigned w,unsigned k)
{return 0x100UL+4UL*slot+2UL*w+k;}
/* 1 in 2^SNAP_NATIVE_AUDIT_SHIFT calls, counted in *asks. */
static int native_due(uint64_t *asks)
{return !((*asks)++&((UINT64_C(1)<<SNAP_NATIVE_AUDIT_SHIFT)-1));}
static int native_page(const struct context *c,uint64_t pa,uint64_t *index)
{
    if(pa<c->work_base || pa>=c->next_table)return 0;
    *index=(pa-c->work_base)/4096;return *index<MONITOR_ARENA_PAGES;
}
static int native_source(const struct context *c,uint64_t index)
{return !!(c->native_sources[index/64]&(UINT64_C(1)<<(index%64)));}
/* Mark or clear every table of v whose stores reach variant copies. */
static void native_mark(struct context *c,const struct sprr_views *v,int set)
{
    for(unsigned n=0;n<v->count && n<SPRR_VIEW_TABLES;n++) {
        uint64_t i;
        if(!native_page(c,v->tables[n].source,&i))continue;
        if(set)c->native_sources[i/64]|=UINT64_C(1)<<(i%64);
        else c->native_sources[i/64]&=~(UINT64_C(1)<<(i%64));
    }
}
/* mem_write, before the store. Nonzero refuses it (terminal). Kernel
 * tables, and a user root whose variants do not exist yet (built, never
 * installed; its first install derives them), take raw TPRO as before. */
static int native_store_admit(struct context *c,uint64_t pa,uint64_t value)
{
    uint64_t i;
    if(!native_page(c,pa,&i))return 0;
    /* A shared group is reachable from every nesting root and variant. */
    if(c->table_pool.owner[i]==NATIVE_SHARED_OWNER && (value&1) && sprr_pte_class(value)==9) {
        c->native_stats.refused++;c->user_view_failed=1;return 1;
    }
    int source=native_source(c,i);
    if(!source && (!(value&1) || sprr_pte_class(value)!=9))return 0;
    unsigned owner=c->table_pool.owner[i];
    const struct sprr_views *v=owner && owner<=SPTM_ROOT_CACHE ? &UVIEWS(c)[owner-1] : 0;
    if(!source && (!v || !v->count))return 0;
    /* A source always belongs to a root with variants (native_mark). */
    if(source && v && v->count &&
       native_views_admit(v,pa,value,native_umprr(&c->user_roots.cache[owner-1])))return 0;
    c->native_stats.refused++;c->user_view_failed=1;return 1;
}
/* Variant copies are hardware-walked while other CPUs run: each store is
 * cleaned at once, as user_live_write does for canonical stores, so the
 * TLBI that completes the call finds both in memory. The zeroing of a new
 * copy is cleaned before anything can link it. */
static int native_copy_write(void *ctx,uint64_t pa,uint64_t value)
{
    int result=user_private_write(ctx,pa,value);
    if(!result)publish(pa,pa+8);
    return result;
}
static uint64_t native_live_alloc(void *ctx)
{
    uint64_t pa=private_user_alloc(ctx);
    if(pa)publish(pa,pa+4096);
    return pa;
}
static struct shadow native_live_shadow(struct context *c,struct sptm_root_cached *e)
{
    struct shadow s=user_view_shadow(c,e);
    s.alloc=native_live_alloc;s.write=native_copy_write;return s;
}
/* mem_write, after the store: the same entry of both variant copies. */
static int native_store_propagate(struct context *c,uint64_t pa,uint64_t value)
{
    uint64_t i;
    if(!native_page(c,pa,&i) || !native_source(c,i))return 0;
    unsigned owner=c->table_pool.owner[i];
    if(!owner || owner>SPTM_ROOT_CACHE) {c->user_view_failed=1;return 1;}
    struct sptm_root_cached *e=&c->user_roots.cache[owner-1];
    struct shadow s=native_live_shadow(c,e);
    if(!native_views_store(&UVIEWS(c)[owner-1],&s,pa,value,native_umprr(e))) {
        c->user_view_failed=1;return 1;
    }
    c->native_stats.propagated++;return 0;
}
/* Invalidate [va, va+size) of the EL1&0 regime by VA for every ASID (every
 * variant, every address space) in every guest CPU's VMID: stage 2 is per
 * CPU, and a stage-1 TLBI names only the current VMID. Larger ranges drop
 * each VMID's stage-1 entries instead. */
#define NATIVE_TLBI_PAGES 64u
static void native_tlbi_range(struct context *c,uint64_t va,uint64_t size)
{
    uint64_t first=va>>12,pages=(size+4095)>>12,saved;
    int all=!pages || pages>NATIVE_TLBI_PAGES;
    __asm__ volatile("mrs %0, vttbr_el2; dsb ishst" : "=r"(saved) :: "memory");
    for(unsigned cpu=0;cpu<GUEST_CPU_COUNT;cpu++) {
        __asm__ volatile("msr vttbr_el2, %0; isb" :: "r"(vcpu_vttbr(&c->vcpus[cpu])) : "memory");
        if(all)__asm__ volatile("tlbi vmalle1is" ::: "memory");
        else for(uint64_t n=0;n<pages;n++)
            __asm__ volatile("tlbi vaae1is, %0" :: "r"((first+n)&((UINT64_C(1)<<44)-1)) : "memory");
    }
    __asm__ volatile("dsb ish; msr vttbr_el2, %0; isb" :: "r"(saved) : "memory");
    c->native_stats.tlbi_calls++;
    if(all)c->native_stats.tlbi_full++;else c->native_stats.tlbi_pages+=pages;
    c->shadow_tlb_syncs++;
}
/* The kernel PPERM snapshot in audit mode. Its identity -- valid, root,
 * count, the six PPERMs and every copy identity -- is checked on every
 * transaction, and the exact re-read of every source word runs 1 in
 * 2^SNAP_NATIVE_AUDIT_SHIFT times. Every canonical kernel change refreshes the
 * copies and re-saves the snapshot (shadow_tlb_sync) before another PPERM
 * transaction can run, so identity without equal words is a broken
 * invariant: terminal. 1 means current (proved or sampled away). */
static int native_reuse_current(struct context *c,const struct shadow *ks,const uint64_t *pp)
{
    const struct sprr_reuse_state *r=&c->kernel_reuse_state;
    const struct sprr_views *v=&c->kernel_views;
    if(!sprr_reuse_configured(v,ks,pp) || !r->valid || r->root!=ks->root || r->count!=v->count)
        return 0;
    for(unsigned cpu=0;cpu<SPRR_VIEW_CPUS;cpu++)if(r->pperm[cpu]!=pp[cpu])return 0;
    for(unsigned n=0;n<v->count;n++) {
        const struct sprr_view_table *a=&r->tables[n],*b=&v->tables[n];
        if(a->source!=b->source || a->level!=b->level)return 0;
        for(unsigned cpu=0;cpu<SPRR_VIEW_CPUS;cpu++)if(a->copy[cpu]!=b->copy[cpu])return 0;
    }
    if(!native_due(&c->native_stats.reuse_asks))return 1;
    c->native_stats.reuse_checks++;
    if(sprr_reuse_current(r,v,ks,pp)==1)return 1;
    c->native_stats.reuse_failures++;c->kernel_view_failed=1;return 0;
}
/* SWITCH_ROOT audit mode: walk 1 in 2^SNAP_NATIVE_AUDIT_SHIFT cache hits. */
static int native_skip_hit(void *ctx)
{
    struct context *c=ctx;
    if(native_due(&c->native_stats.hit_asks))return 0;
    c->native_stats.hit_skips++;return 1;
}
#define NATIVE_SKIP_HIT native_skip_hit
#else
#define NATIVE_SKIP_HIT 0
#endif
#if SNAP_NATIVE_TABLES
/* Copy the paths of a TPRO leaf's 4K parts before its raw canonical store.
 * Every copy store is cleaned in program order (native_live_shadow): a new
 * copy is zeroed and filled in memory before the one store that links it,
 * and that link (a table-address change, so user_private_write breaks it
 * first) is in memory before the range is invalidated. After that no walk,
 * cached or new, reaches the shared table the path replaced, and the raw
 * leaf can be stored. No variants exist before a root's first install; its
 * sync derives them. */
static int native_prepare_tpro(struct context *c,struct sptm_root_cached *e,
                               uint64_t va,unsigned shift)
{
    struct sprr_views *v=&UVIEWS(c)[e-c->user_roots.cache];
    if(!v->count)return 1;
    struct shadow live=native_live_shadow(c,e);
    int linked=0;
    for(uint64_t off=0;off<(UINT64_C(1)<<shift);off+=4096) {
        int r=native_views_prepare_leaf(v,&live,va+off,native_umprr(e));
        if(!r) {c->user_view_failed=1;return 0;}
        linked|=r==2;
    }
    native_mark(c,v,1);
    if(linked) {c->native_stats.paths++;native_tlbi_range(c,va,UINT64_C(1)<<shift);}
    return 1;
}
#endif
#if SNAP_NATIVE_SHARED
static int user_source_read(void *,uint64_t,uint64_t *);
_Static_assert(NATIVE_SHARED_OWNER>SPTM_ROOT_CACHE && NATIVE_SHARED_OWNER<TABLE_POOL_FREE,
               "shared group allocation domain");
/* Group pages are walked by every nesting root: cleaned when allocated and on
 * every store, as user_live_alloc/user_live_write do for a live root. */
static uint64_t native_group_alloc(void *ctx)
{
    uint64_t pa=table_alloc_owned(ctx,NATIVE_SHARED_OWNER);
    if(pa)publish(pa,pa+4096);
    return pa;
}
static int native_group_write(void *ctx,uint64_t pa,uint64_t value)
{
    int result=mem_write(ctx,pa,value);
    if(!result)publish(pa,pa+8);
    return result;
}
static struct shadow native_group_shadow(struct context *c)
{
    return (struct shadow){.txsz=17,.alloc=native_group_alloc,.read=kernel_table_read,
        .write=native_group_write,.ctx=c};
}
/* No root links a freed group, and each unlink already invalidated. */
static void native_group_release(void *ctx,uint64_t pa)
{
    struct context *c=ctx;
    uint32_t used=(uint32_t)((c->next_table-c->work_base)/4096);
    if(pa<c->work_base || table_pool_release_one(&c->table_pool,used,
            (uint32_t)((pa-c->work_base)/4096),NATIVE_SHARED_OWNER))
        c->user_view_failed=1;
}
_Static_assert(SPTM_ROOT_CACHE<=NATIVE_SHARED_SLOTS,"a link bit per cached slot");
/* Before group g is freed with its guest table: a cached slot that is no
 * longer valid (invalidated, evicted or retired; its tree is kept until the
 * slot is reused) may still link it, since UNNEST of an uncached root leaves
 * that stale tree alone. Such a tree is derived state: the slot goes now. A
 * valid slot still linking g would name a table the guest is detaching. */
static int native_group_unlinked(struct context *c,int g)
{
    struct native_shared *ns=&UNS(c);
    for(unsigned s=0;s<SPTM_ROOT_CACHE;s++)if(NATIVE_SHARED_SLOT_HAS(ns->group[g].slots,s)) {
        struct sptm_root_cached *e=&c->user_roots.cache[s];
        if(e->valid || (e->root && vcpu_root_busy(c,e->root)) ||
           !sptm_root_reclaim_forget(&c->user_roots,s) || root_slot_release(c,s,1)<0)return 0;
        ns->stale++;
    }
    return !NATIVE_SHARED_SLOTS_ANY(ns->group[g].slots);
}
static uint64_t native_no_alloc(void *ctx) {(void)ctx;return 0;}
/* A linking slot's canonical tree for native_shared_grow: allocation-free,
 * each store cleaned (user_live_write), as the NEST commit writes links. */
static int nl_tree(void *ctx,unsigned slot,struct shadow *out)
{
    struct context *c=ctx;
    if(slot>=SPTM_ROOT_CACHE || !c->user_roots.cache[slot].shadow)return -1;
    struct sptm_root_cached *e=&c->user_roots.cache[slot];
    *out=(struct shadow){.txsz=17,.root=e->shadow,.alloc=native_no_alloc,.read=mem_read,
        .write=user_live_write,.ctx=c,.alloc_ctx=&UOWNERS(c)[slot],
        .admit=SNAP_NATIVE_WRITER_ADMISSION ? native_writer_admit_user:0};
    return 0;
}
/* The shared root a user root is bound to (its nested tables' owner), or 0. */
static uint64_t native_shared_root_of(struct context *c,uint64_t root)
{
    struct sptm_memory m=sptm_context_memory(c);
    if(!sptm_managed_frame(&m,root) || !m.shared_regions)return 0;
    volatile uint8_t *u=m.map(m.ctx,m.frame_map_pa+((root-m.frame_low)>>14)*16,16);
    return u && u[8]<SPTM_MAC_SHARED_ROOT_LIMIT ? m.shared_regions->slots[u[8]].root : 0;
}
static int nl_group(void *ctx,uint64_t child,uint64_t va)
{
    struct native_links *l=ctx;struct native_shared *ns=&UNS(l->c);
    int g=native_shared_find(ns,child);
    if(g>=0)return ns->group[g].va==va && ns->group[g].shared==l->shared ? g : -1;
    if(!l->shared)return -1;
    struct shadow w=native_group_shadow(l->c);
    return native_shared_create(ns,&w,l->shared,child,va,user_source_read,l->c,native_group_release,l->c);
}
#if SNAP_ROOT_MISS_FAST
/* Read-only: nl_group will find child's group rather than create (and fill)
 * one, so a linked build copies none of child's leaves (compat/root-miss.h). */
static int nl_grouped(void *ctx,uint64_t child,uint64_t va)
{
    struct native_links *l=ctx;(void)va;
    return native_shared_find(&UNS(l->c),child)>=0;
}
#endif
static int nl_find(struct native_links *l,uint64_t child,uint64_t va)
{
    int g=native_shared_find(&UNS(l->c),child);
    return g>=0 && UNS(l->c).group[g].va==va ? g : -1;
}
static int nl_link(void *ctx,uint64_t child,uint64_t va,uint64_t *leaves)
{
    struct native_links *l=ctx;int g=nl_find(l,child,va);
    if(g<0 || !native_shared_link(&UNS(l->c),l->s,l->slot,g))return 0;
    *leaves=UNS(l->c).group[g].leaves;return 1;
}
static int nl_linked(void *ctx,uint64_t child,uint64_t va,uint64_t *leaves)
{
    struct native_links *l=ctx;int g=nl_find(l,child,va);
    if(g<0 || !native_shared_slot_links(&UNS(l->c),l->slot,g) ||
       !native_shared_linked(&UNS(l->c),l->s,g))return 0;
    *leaves=UNS(l->c).group[g].leaves;return 1;
}
static int nl_unlink(void *ctx,uint64_t child,uint64_t va,uint64_t *leaves)
{
    struct native_links *l=ctx;int g=nl_find(l,child,va);
    if(g<0)return 0;
    *leaves=UNS(l->c).group[g].leaves;
    return native_shared_unlink(&UNS(l->c),l->s,l->slot,g);
}
static struct sptm_root_links native_links_for(struct native_links *l)
{return (struct sptm_root_links){nl_group,nl_link,nl_linked,nl_unlink,l};}
/* The group mirroring the shared table under va of 16K shared root `shared`
 * (-1 when none exists yet) and that table's PA; 0 when no table is there. */
static int native_group_at(struct context *c,uint64_t shared,uint64_t va,int *g,uint64_t *child)
{
    struct sptm_memory m=sptm_context_memory(c);
    *child=sptm_root_shared_child(&m,shared,va);
    *g=*child ? native_shared_find(&UNS(c),*child) : -1;
    return *child!=0;
}
/* Every cached root aliasing the range links group g (so needs no write). */
static int native_aliases_link(struct context *c,sptm_root_mask_t mask,int g)
{
    for(unsigned i=0;i<SPTM_ROOT_CACHE;i++)if(SPTM_ROOT_MASK_HAS(mask,i)) {
        struct shadow s=user_shadow(c,&c->user_roots.cache[i]);
        if(g<0 || !native_shared_slot_links(&UNS(c),i,g) ||
           !native_shared_linked(&UNS(c),&s,g))return 0;
    }
    return 1;
}
/* Before a shared-root leaf change of count pages from va: every aliasing
 * root links its group and each group holds the current guest leaves. */
static int native_shared_prepare(struct context *c,uint64_t shared,uint64_t va,unsigned shift,
                                 uint64_t count,sptm_root_mask_t mask,uint64_t next)
{
    struct shadow w=native_group_shadow(c);
    const struct native_shared_roots roots={nl_tree,c};
    for(uint64_t n=0;n<count;n++) {
        uint64_t addr=va+(n<<shift),child,guest;int g;
        /* No shared table there (an UNMAP the SPTM skips as TABLE_MISSING): no
         * guest leaf and no group, so no root may alias it. */
        if(!native_group_at(c,shared,addr,&g,&child)) {
            if(SPTM_ROOT_MASK_ANY(mask))return 0;
            continue;
        }
        if(user_source_read(c,child+8*((addr>>14)&2047),&guest) || !native_aliases_link(c,mask,g) ||
           (g>=0 && !native_shared_holds(&UNS(c),&w,g,addr,guest)))return 0;
        /* A new leaf's 2 MiB gets its page, linked into every linking tree,
         * before the guest store (nothing is mapped there yet). */
        if(g>=0 && (next&1) && !native_shared_grow(&UNS(c),&w,g,addr,&roots))return 0;
    }
    return 1;
}
/* After it: write each group once (next[n], or 0 without next). */
static int native_shared_commit(struct context *c,uint64_t shared,uint64_t va,unsigned shift,
                                uint64_t count,const struct sptm_shared_update_entry *entries,
                                uint64_t next)
{
    struct shadow w=native_group_shadow(c);
    for(uint64_t n=0;n<count;n++) {
        uint64_t addr=va+(n<<shift),child;int g;
        if(entries && entries[n].old==entries[n].next)continue;
        /* Without a shared table nothing is mirrored (prepare: no alias). */
        if(!native_group_at(c,shared,addr,&g,&child)) {
            if(next || entries)return 0;
            continue;
        }
        if(g>=0 && !native_shared_store(&UNS(c),&w,g,addr,entries ? entries[n].next : next))
            return 0;
    }
    return 1;
}
#endif
/* The table this CPU's hardware walks for cached root e. */
static uint64_t user_hw_root(struct context *c,struct sptm_root_cached *e,unsigned cpu)
{
#if SNAP_USER_HW_WALK
    /* A hardware-walk root's identity entry: the installed variant's table
     * (the guest root or a copy of it). */
    if(hw_walk_of_entry(c->hw_walk,e)) {
        const struct native_cpu *n=&c->native_cpu[cpu];
        return n->installed && n->w<2 ? n->ttbr0[n->w][n->k&1]&PT_OA_MASK : 0;
    }
#endif
#if SNAP_NATIVE_TABLES
    const struct native_cpu *n=&c->native_cpu[cpu];
    return n->installed && n->w<2 ? native_views_root(&UVIEWS(c)[e-c->user_roots.cache],n->w) : 0;
#else
    return sprr_views_root(&UVIEWS(c)[e-c->user_roots.cache],cpu);
#endif
}
static void user_tlb_sync(struct context *c)
{
    __asm__ volatile("dsb ishst; tlbi alle1is; dsb ish; isb" ::: "memory");
    c->shadow_tlb_syncs++;
}
/* These four commits touch only a user shadow and its private views. Their
 * prepare/commit callbacks cannot change a kernel mapping or PPERM. Retyping
 * and kernel transactions finish their own kernel refresh before returning.
 * Keep the same all-VMID hardware invalidation, including inactive roots and
 * before reference release, without rebuilding unchanged kernel copies. */
#if !SNAP_NATIVE_TABLES
static int user_commit_tlb_sync(struct context *c,unsigned kind)
{
    if(kind>=4 || c->kernel_view_failed || c->user_view_failed)return 0;
#if SNAP_USER_ONLY_TLBI
    user_tlb_sync(c);sprr_count(&c->user_only_tlbi[kind]);
#else
    shadow_tlb_sync(c);
#endif
    return !c->kernel_view_failed && !c->user_view_failed;
}
#endif
/* The same completion for a known VA range. Native tables invalidate exactly
 * that range (size 0: everything) in every VMID; the counters are kept. */
static int user_commit_tlb_range(struct context *c,unsigned kind,uint64_t va,uint64_t size)
{
#if SNAP_NATIVE_TABLES
    if(kind>=4 || c->kernel_view_failed || c->user_view_failed)return 0;
    native_tlbi_range(c,va,size);
#if SNAP_USER_ONLY_TLBI
    sprr_count(&c->user_only_tlbi[kind]);
#endif
    return !c->kernel_view_failed && !c->user_view_failed;
#else
    (void)va;(void)size;return user_commit_tlb_sync(c,kind);
#endif
}
static void user_tlb_range(struct context *c,uint64_t va,uint64_t size)
{
#if SNAP_NATIVE_TABLES
    native_tlbi_range(c,va,size);
#else
    (void)va;(void)size;user_tlb_sync(c);
#endif
}

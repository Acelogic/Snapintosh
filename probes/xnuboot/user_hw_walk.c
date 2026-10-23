/* SPDX-License-Identifier: MIT */
/* SNAP_USER_HW_WALK glue (compat/user-hw-walk.h).
 * Part of probes/xnuboot.c's translation unit, included in order; not compiled on its own. */
#if SNAP_USER_HW_WALK
/* --- SNAP_USER_HW_WALK glue (compat/user-hw-walk.h) ----------------------
 * Copies live in arena pages of their own pool domain; guest tables are read
 * where the SPTM wrote them. Every store into a copy is cleaned before the
 * walker can need it; invalidation is native_tlbi_range (every VMID). */
static int hw_copy_write(void *ctx,uint64_t pa,uint64_t value)
{
    struct context *c=ctx;
    if((pa&7) || pa<c->work_base || pa>=c->next_table)return -1;
    int result=mem_write(ctx,pa,value);
    if(!result)publish(pa,pa+8);
    return result;
}
static uint64_t hw_copy_alloc(void *ctx)
{
    uint64_t pa=table_alloc_owned(ctx,HW_WALK_OWNER);
    if(pa)publish(pa,pa+4096);
    return pa;
}
static void hw_copy_release(void *ctx,uint64_t pa)
{
    struct context *c=ctx;
    /* A page that cannot be given back is a broken invariant: terminal. */
    if(pa<c->work_base || pa>=c->next_table || (pa&4095) ||
       table_pool_release_one(&c->table_pool,(uint32_t)((c->next_table-c->work_base)/4096),
                              (uint32_t)((pa-c->work_base)/4096),HW_WALK_OWNER))
        c->user_view_failed=1;
}
static int hw_table_read(void *ctx,uint64_t pa,uint64_t *out)
{
    struct context *c=ctx;
    if(pa&7)return -1;
    if(pa>=c->work_base && pa<c->next_table)return mem_read(ctx,pa,out);
    volatile uint8_t *p=sptm_map(ctx,pa,8);
    if(!p)return -1;
    *out=*(volatile uint64_t *)p;return 0;
}
static int hw_table_type(void *ctx,uint64_t table)
{
    struct context *c=ctx;struct sptm_memory m=sptm_context_memory(c);
    uint64_t frame=table&~UINT64_C(0x3fff);
    if(!sptm_managed_frame(&m,frame))return -1;
    volatile uint8_t *meta=m.map(m.ctx,m.frame_map_pa+((frame-m.frame_low)>>14)*16,16);
    return meta ? meta[2] : -1;
}
static struct hw_walk_ops hw_ops(struct context *c)
{return (struct hw_walk_ops){hw_table_read,hw_copy_write,hw_copy_alloc,hw_copy_release,hw_table_type,c};}
static void hw_tlb_range(void *ctx,uint64_t va,uint64_t size){native_tlbi_range(ctx,va,size);}
static struct hw_walk_root *hw_root(struct context *c,uint64_t root){return hw_walk_find(c->hw_walk,root);}
/* The identity runtime paths read for an active root that has no cache
 * entry: its hardware-walk record's, or 0. */
static struct sptm_root_cached *hw_record_entry(struct context *c,uint64_t root)
{
    struct hw_walk_root *r=hw_root(c,root);
    return r ? &r->entry : 0;
}
static int hw_fail(struct context *c){c->user_view_failed=1;return 0;}
static int hw_prepare_leaf(void *ctx,uint64_t root,uint64_t va,unsigned shift,uint64_t pte)
{
    struct context *c=ctx;struct hw_walk_root *r=hw_root(c,root);
    if(!r || shift!=12)return 0;
    if(sprr_pte_class(pte)!=9)return 1;
    struct hw_walk_ops o=hw_ops(c);struct hw_walk_tlb t={hw_tlb_range,c};
    return hw_walk_before_tpro(&o,r,va,UINT64_C(1)<<shift,&t,&c->hw_walk->stats);
}
static int hw_commit_leaf(void *ctx,uint64_t root,uint64_t va,unsigned shift,uint64_t pte)
{
    struct context *c=ctx;struct hw_walk_root *r=hw_root(c,root);struct hw_walk_ops o=hw_ops(c);
    (void)pte;
    if(!r || !hw_walk_after_add(&o,r,va,UINT64_C(1)<<shift,&c->hw_walk->stats))return hw_fail(c);
    c->user_live_pages++;return 1;
}
static int hw_prepare_unmap(void *ctx,uint64_t root,uint64_t va,unsigned shift,uint64_t count)
{(void)va;(void)count;return hw_root(ctx,root) && shift==12;}
static int hw_commit_unmap(void *ctx,uint64_t root,uint64_t va,unsigned shift,uint64_t count,uint64_t removed)
{
    struct context *c=ctx;struct hw_walk_root *r=hw_root(c,root);struct hw_walk_ops o=hw_ops(c);
    struct hw_walk_tlb t={hw_tlb_range,c};
    if(!r || !hw_walk_after_change(&o,r,va,count<<shift,&t,&c->hw_walk->stats))return hw_fail(c);
    c->user_unmap_calls++;c->user_unmap_pages+=removed;return 1;
}
static int hw_prepare_update(void *ctx,uint64_t root,uint64_t va,unsigned shift,uint64_t old,uint64_t next)
{
    struct context *c=ctx;struct hw_walk_root *r=hw_root(c,root);
    if(!r || shift!=12)return 0;
    if(sprr_pte_class(next)!=9 || sprr_pte_class(old)==9)return 1;
    struct hw_walk_ops o=hw_ops(c);struct hw_walk_tlb t={hw_tlb_range,c};
    return hw_walk_before_tpro(&o,r,va,UINT64_C(1)<<shift,&t,&c->hw_walk->stats);
}
static int hw_prepare_detach(void *ctx,uint64_t root,uint64_t va,unsigned shift,unsigned level,uint64_t removed)
{(void)va;(void)level;(void)removed;return hw_root(ctx,root) && shift==12;}
static int hw_commit_detach(void *ctx,uint64_t root,uint64_t va,unsigned shift,unsigned level,uint64_t removed)
{
    struct context *c=ctx;struct hw_walk_root *r=hw_root(c,root);struct hw_walk_ops o=hw_ops(c);
    struct hw_walk_tlb t={hw_tlb_range,c};(void)shift;(void)removed;
    if(!r || level>2 || !hw_walk_after_unlink(&o,r,va,4*hw_walk_span(level),&t,&c->hw_walk->stats))
        return hw_fail(c);
    c->user_detach_calls++;return !c->user_view_failed;
}
static int hw_prepare_attach(void *ctx,uint64_t root,uint64_t va,unsigned shift,uint64_t child)
{(void)va;(void)child;return hw_root(ctx,root) && shift==12;}
static int hw_commit_attach(void *ctx,uint64_t root,uint64_t va,unsigned shift,uint64_t child)
{
    struct context *c=ctx;struct hw_walk_root *r=hw_root(c,root);struct hw_walk_ops o=hw_ops(c);
    struct hw_walk_tlb t={hw_tlb_range,c};(void)shift;(void)child;
    uint64_t span=4*hw_walk_span(2);
    if(!r || !hw_walk_after_change(&o,r,va&~(span-1),span,&t,&c->hw_walk->stats))return hw_fail(c);
    c->user_comm_attach_calls++;return 1;
}
static int hw_prepare_nest(void *ctx,uint64_t root,uint64_t shared,uint64_t va,unsigned shift,uint64_t pages)
{(void)shared;(void)va;(void)pages;return hw_root(ctx,root) && shift==12;}
/* NEST links empty level-2 slots: nothing to invalidate (compat/user-hw-walk.h). */
static int hw_commit_nest(void *ctx,uint64_t root,uint64_t shared,uint64_t va,unsigned shift,uint64_t pages)
{
    struct context *c=ctx;struct hw_walk_root *r=hw_root(c,root);struct hw_walk_ops o=hw_ops(c);
    if(!r || !hw_walk_after_add(&o,r,va,pages<<shift,&c->hw_walk->stats))return hw_fail(c);
    uint64_t span=UINT64_C(1)<<(2*shift-3),last=va+((pages-1)<<shift);
    struct sptm_nest_state *n=&c->nest_state;
    n->calls++;n->descriptors+=last/span-va/span+1;
    n->root=root;n->shared=shared;n->va=va;n->pages=pages;
    n->first=va&~(span-1);n->last=(last&~(span-1))+span;
    return 1;
}
static int hw_prepare_unnest(void *ctx,uint64_t root,uint64_t shared,unsigned shift,
                             const struct sptm_unnest_plan *plan)
{(void)shared;(void)plan;return hw_root(ctx,root) && shift==12;}
static int hw_commit_unnest(void *ctx,uint64_t root,uint64_t shared,unsigned shift,
                            const struct sptm_unnest_plan *plan)
{
    struct context *c=ctx;struct hw_walk_root *r=hw_root(c,root);struct hw_walk_ops o=hw_ops(c);
    struct hw_walk_tlb t={hw_tlb_range,c};
    if(!r || !hw_walk_after_unlink(&o,r,plan->base,plan->span*plan->count,&t,&c->hw_walk->stats))
        return hw_fail(c);
    c->unnest_calls++;c->unnest_descriptors+=plan->descriptors;c->unnest_leaves+=plan->leaves;
    c->unnest_root=root;c->unnest_shared=shared;c->unnest_format=shift==12;
    return !c->user_view_failed;
}
/* MAP_TABLE and (UN)CONDEMN store table descriptors without a callback. */
static int hw_after_table(struct context *c,uint64_t root,uint64_t va,unsigned level)
{
    struct hw_walk_root *r=hw_root(c,root);
    if(!r)return 1;
    struct hw_walk_ops o=hw_ops(c);uint64_t span=4*hw_walk_span(level>2 ? 2 : level);
    return hw_walk_after_add(&o,r,va&~(span-1),span,&c->hw_walk->stats) || hw_fail(c);
}
/* Before a UPERM write or TPRO PPERM change, in place of the canonical-view
 * proof: the copies are exact, and 1 in 4096 also the whole private tree. */
static int hw_entry_proof(struct context *c,const struct sptm_root_cached *e,struct sptm_fixed_view *out)
{
    struct hw_walk_root *r=hw_walk_of_entry(c->hw_walk,e);
    if(!r)return 0;
    struct hw_walk_ops o=hw_ops(c);unsigned tables=0;
    int deep=!(c->hw_walk->stats.proofs++&4095);
    c->hw_walk->stats.verifies++;
    if(!hw_walk_verify(&o,r,deep,&tables)) {c->hw_walk->stats.verify_failures++;return 0;}
    out->tables=deep ? tables : r->count;out->pages=r->count;out->classes=0;
    return 1;
}
/* SWITCH_ROOT (compat/sptm-root.c hw_eligible; user_root_install then gets
 * shadow 0). A format-1 root with a record, or one that has no cached shadow
 * and gets a record now. */
static int hw_switch_eligible(void *ctx,const struct sptm_memory *m,uint64_t root,unsigned asid,
                              unsigned format,unsigned flags)
{
    struct context *c=ctx;(void)m;
    if(format!=1)return 0;
    struct hw_walk_root *r=hw_root(c,root);
    if(r)return r->entry.asid==asid && r->entry.flags==flags ? 1 : -1;
    if(user_cached(c,root))return 0;          /* a shadow keeps this root for its lifetime */
    struct hw_walk_ops o=hw_ops(c);
    if(!hw_walk_attach(c->hw_walk,&o,root,asid,flags)) {c->hw_walk->stats.fallbacks++;return 0;}
    return 1;
}
/* user_root_install's user-root transaction for a record's TTBR0 values,
 * after its PPERM reset: the native variant selection (w from UPERM), the
 * same register sequence, shared-region flush and installed-state records. */
static void hw_install_user(struct context *c,uint64_t root,uint64_t asid,unsigned format)
{
    struct vcpu *v=vcpu_of(c);
    struct hw_walk_root *r=hw_root(c,root);
    if(!r || format!=1 || r->entry.asid!=asid) {c->root_install_failures++;return;}
    unsigned flags=(unsigned)r->entry.flags;
    struct sprr_state initial={0};sprr_root_reset(&initial,flags);
    struct native_cpu *n=&c->native_cpu[v->slot];
    uint64_t ttbr0[2][2];
    for(unsigned w=0;w<2;w++)for(unsigned k=0;k<2;k++)ttbr0[w][k]=hw_walk_ttbr0(r,w);
    uint64_t ttbr=native_install(n,(const uint64_t (*)[2])ttbr0,0,initial.uperm,initial.pperm,0);
    if(!ttbr) {c->user_view_failed=1;c->root_install_failures++;return;}
    c->native_stats.installs++;c->hw_walk->stats.installs++;
    struct user_view_state *u=&c->user_view_state[v->slot];
    u->root=root;u->shadow=ttbr&PT_OA_MASK;u->el0=0;
    u->uperm=initial.uperm;u->pperm=initial.pperm;u->umprr=initial.umprr;u->syncs++;
    v->guest_tcr=SPTM_ROOT_TCR_4K|(1UL<<36);
    v->guest_sctlr=pauth_root_enables(v->guest_sctlr,flags);
    uint64_t tcr=shadow_tcr(v->guest_tcr);
    /* Copies were cleaned as written; other noted arena pages as for every
     * installation (requires SNAP_ROOT_DIRTY_PUBLISH, asserted above). */
#if SNAP_ROOT_PUBLISH_BATCH_DSB
    int (*page)(void *,uint64_t)=publish_page_lines;
#else
    int (*page)(void *,uint64_t)=root_publish_page;
#endif
#if SNAP_INCREMENTAL_PUBLISH
    if(!root_index_flush(&c->root_publish,&c->perf.root_index,c->work_base,c->next_table,page,c)) {
#else
    if(!root_publish_flush(&c->root_publish,c->work_base,c->next_table,page,c)) {
#endif
        __asm__ volatile("dsb ish" ::: "memory");
        install_failed(c,0);return;
    }
    uint64_t live_tcr,live_ttbr;
    __asm__ volatile("mrs %0, tcr_el1; mrs %1, ttbr0_el1":"=r"(live_tcr),"=r"(live_ttbr));
    struct sptm_memory memory=sptm_context_memory(c);
    int region=sptm_mac_root_shared_slot(&memory,root);
    if(live_tcr==tcr) {
        /* Kernel root (ASID 0, global low entries) to a user root, or a
         * different shared region's global entries: drop them locally. */
        int crossing=!(live_ttbr>>48)!=!(ttbr>>48);
        uint16_t incoming=region<0 ? UINT16_MAX : region==255 ? 0 : (uint16_t)(region+1);
        uint16_t last=c->user_shared_slot[v->slot];
        int shared_flush=incoming==UINT16_MAX || (last && last!=incoming);
        __asm__ volatile("dsb ish; msr ttbr0_el1, %0; isb" :: "r"(ttbr) : "memory");
        if(crossing || shared_flush) {
            __asm__ volatile("tlbi vmalle1; dsb nsh; isb" ::: "memory");
            c->native_stats.local_flushes++;
            if(shared_flush)c->shared_switch_flushes[v->slot]++;
            c->user_shared_slot[v->slot]=0;
        }
    } else
        __asm__ volatile("dsb ish; msr tcr_el1, %2; isb; tlbi alle1is; dsb ish; "
                         "msr ttbr0_el1, %0; isb; msr tcr_el1, %1; isb"
                         :: "r"(ttbr),"r"(tcr),"r"(tcr|(1UL<<7)):"memory");
    uint64_t actual_ttbr,actual_tcr;
    __asm__ volatile("mrs %0, ttbr0_el1; mrs %1, tcr_el1":"=r"(actual_ttbr),"=r"(actual_tcr));
    c->root_installed[v->slot][0]=actual_ttbr;
    c->root_installed[v->slot][1]=actual_tcr;
    c->user_shared_slot[v->slot]=region<0 || region==255 ? 0 : (uint16_t)(region+1);
    if(actual_ttbr!=ttbr || actual_tcr!=tcr)c->root_install_failures++;
    v->guest_ttbr0=root|(asid<<48);
    c->shadow_tlb_syncs++;
}
/* Stage 2: a retyped page-table frame read-only (ro) or RW again in every
 * vCPU's tree, then every VMID forgets it: stage 2 by IPA, then the frame's
 * aperture aliases (the only stage-1 mappings a typed frame keeps). */
#if SNAP_USER_HW_WALK_S2RO
static struct sptm_aperture xnu_aperture(const struct context *);
static int hw_s2_write(void *ctx,uint64_t pa,uint64_t value)
{
    int result=mem_write(ctx,pa,value);
    if(!result)publish(pa,pa+8);
    return result;
}
/* xnuboot_prepare, after every vCPU's tree: guest RAM [mem_low, mem_high) in
 * level-3 leaves, every store published, then every VMID forgets stage 2. */
static int hw_s2_presplit_all(struct context *c)
{
    const struct params *p=c->params;
    struct shadow trees[HW_S2_TREES];
    for(unsigned cpu=0;cpu<GUEST_CPU_COUNT;cpu++)
        trees[cpu]=(struct shadow){.txsz=S2_TXSZ,.root=c->vcpus[cpu].stage2_root,.alloc=prepare_table_alloc,
                                   .read=mem_read,.write=hw_s2_write,.ctx=c};
    int created=hw_s2_presplit(trees,GUEST_CPU_COUNT,p->mem_low&~((UINT64_C(1)<<21)-1),p->mem_high);
    if(created<0)return -1;
    c->hw_walk->stats.s2_tables=(unsigned)created;     /* RETYPE adds none: no splits after this */
    __asm__ volatile("dsb ish; tlbi alle1is; dsb ish; isb" ::: "memory");
    return 0;
}
static int hw_s2_frame(struct context *c,uint64_t frame,int ro)
{
    struct shadow trees[HW_S2_TREES];
    _Static_assert(GUEST_CPU_COUNT==HW_S2_TREES,"one stage-2 tree per vCPU");
    for(unsigned cpu=0;cpu<GUEST_CPU_COUNT;cpu++)
        trees[cpu]=(struct shadow){.txsz=S2_TXSZ,.root=c->vcpus[cpu].stage2_root,.alloc=table_alloc,
                                   .read=mem_read,.write=hw_s2_write,.ctx=c};
    /* Leaves only: the trees were pre-split at setup (hw_s2_presplit_all). */
    if(hw_s2_set(trees,GUEST_CPU_COUNT,frame,ro)<0) {c->hw_walk->stats.s2_failures++;return 0;}
    if(ro)c->hw_walk->stats.s2_protects++;else c->hw_walk->stats.s2_unprotects++;
    struct sptm_aperture ap=xnu_aperture(c);struct sptm_moved mv=xnu_moved(c);
    uint64_t linear=sptm_aperture_pointer(&ap,frame,0x4000);
    uint64_t moved=sptm_published_pointer(&ap,&mv,frame,0x4000);
    uint64_t saved,mask=(UINT64_C(1)<<44)-1;
    __asm__ volatile("mrs %0, vttbr_el2; dsb ishst" : "=r"(saved) :: "memory");
    for(unsigned cpu=0;cpu<GUEST_CPU_COUNT;cpu++) {
        __asm__ volatile("msr vttbr_el2, %0; isb" :: "r"(vcpu_vttbr(&c->vcpus[cpu])) : "memory");
        for(unsigned p=0;p<4;p++)
            __asm__ volatile("tlbi ipas2e1is, %0" :: "r"(((frame+4096UL*p)>>12)&mask) : "memory");
        __asm__ volatile("dsb ish" ::: "memory");
        for(unsigned p=0;p<4;p++) {
            if(linear)__asm__ volatile("tlbi vaae1is, %0" :: "r"(((linear+4096UL*p)>>12)&mask) : "memory");
            if(moved && moved!=linear)
                __asm__ volatile("tlbi vaae1is, %0" :: "r"(((moved+4096UL*p)>>12)&mask) : "memory");
        }
    }
    __asm__ volatile("dsb ish; msr vttbr_el2, %0; isb" :: "r"(saved) : "memory");
    c->shadow_tlb_syncs++;
    return 1;
}
#endif
#endif

/* SPDX-License-Identifier: MIT */
/* User view publication, sync and refresh, EL0 mode and memo, user instruction
 * reads, the crash ring and canonical views.
 * Part of probes/xnuboot.c's translation unit, included in order; not compiled on its own. */
static int user_publish_view(struct context *c,struct sptm_root_cached *e,unsigned cpu,
                              const struct sprr_state *state,int el0)
{
    struct sprr_views *views=user_views(c,e);
#if SNAP_USER_DIRTY_PUBLISH
    _Static_assert(SPRR_VIEW_TABLES==USER_PUBLISH_MAX,"user publication selection ABI");
    uint64_t pages[USER_PUBLISH_MAX];
    if(cpu>=GUEST_CPU_COUNT || !views->count || views->count>USER_PUBLISH_MAX) {
        c->user_publish.errors++;c->user_view_failed=1;return 0;
    }
    for(unsigned n=0;n<views->count;n++)pages[n]=views->tables[n].copy[cpu];
    if(!user_publish_flush(&c->root_publish,&c->private_pages,&c->user_publish,
        c->work_base,c->next_table,pages,(unsigned)views->count,root_publish_page,c)) {
        c->user_view_failed=1;return 0;
    }
#else
    for(unsigned n=0;n<views->count;n++) {
        uint64_t pa=views->tables[n].copy[cpu];publish(pa,pa+4096);
    }
#endif
    if(c->user_roots.active[cpu]==e->root) {
        struct user_view_state *u=&c->user_view_state[cpu];
        u->root=e->root;u->shadow=sprr_views_root(views,cpu);u->el0=el0;
        u->uperm=state->uperm;u->pperm=state->pperm;u->umprr=state->umprr;u->syncs++;
    }
    return 1;
}
static int user_sync_view_impl(struct context *c,struct sptm_root_cached *e,unsigned cpu,
                          const struct sprr_state *state,int el0)
{
    struct shadow s=user_view_shadow(c,e);struct sprr_views *views=user_views(c,e);
#if SNAP_USER_VIEW_CACHE
#if SNAP_VIEW_TABLE_READ
    struct view_table_read_stats *st=&c->view_table_reads[1];
    if(st->errors) {c->user_view_failed=1;return 0;}
    sprr_count(&st->calls);st->tables+=views->count;
#if SNAP_USER_TREE_MEMO
    int ok=sprr_views_sync_user_cached_memo(views,&s,cpu,state,el0,&c->user_view_epoch,
        &UPROOFS(c)[e-c->user_roots.cache],&c->user_view_proof_stats[cpu],
        SNAP_USER_VIEW_VERIFY,user_view_table_read,private_copy_table_read,&c->view_store_compare[1],
        &c->table_memo,&UMEMOS(c)[e-c->user_roots.cache]);
#elif SNAP_VIEW_STORE_COMPARE
    int ok=sprr_views_sync_user_cached_compared(views,&s,cpu,state,el0,&c->user_view_epoch,
        &UPROOFS(c)[e-c->user_roots.cache],&c->user_view_proof_stats[cpu],
        SNAP_USER_VIEW_VERIFY,user_view_table_read,private_copy_table_read,&c->view_store_compare[1]);
#else
    int ok=sprr_views_sync_user_cached_mapped(views,&s,cpu,state,el0,&c->user_view_epoch,
        &UPROOFS(c)[e-c->user_roots.cache],&c->user_view_proof_stats[cpu],
        SNAP_USER_VIEW_VERIFY,user_view_table_read);
#endif
    if(!ok) {
        sprr_count(&st->errors);c->user_view_failed=1;return 0;
    }
    sprr_count(&st->complete);
#else
    if(!sprr_views_sync_user_cached(views,&s,cpu,state,el0,&c->user_view_epoch,
        &UPROOFS(c)[e-c->user_roots.cache],&c->user_view_proof_stats[cpu],
        SNAP_USER_VIEW_VERIFY)) {
        c->user_view_failed=1;return 0;
    }
#endif
#else
    if(!sprr_views_sync_user_cpu(views,&s,cpu,state,el0)) {
        c->user_view_failed=1;return 0;
    }
#endif
    return user_publish_view(c,e,cpu,state,el0);
}
static int user_sync_view(struct context *c,struct sptm_root_cached *e,unsigned cpu,
                          const struct sprr_state *state,int el0)
{
    int started=detail_begin(c,DETAIL_USER_SYNC);
    int result=user_sync_view_impl(c,e,cpu,state,el0);
    detail_end(c,DETAIL_USER_SYNC,started,result);return result;
}
#if SNAP_USER_TABLE_READ && !SNAP_NATIVE_TABLES
static const volatile uint64_t *user_table_read(void *ctx,uint64_t pa)
{
    struct context *c=ctx;
    if(c->user_table_reads[2])return 0;
    sprr_count(&c->user_table_reads[0]);
    if((pa&4095) || pa<c->work_base || pa>=c->next_table || c->next_table-pa<4096) {
        sprr_count(&c->user_table_reads[2]);return 0;
    }
    /* Canonical user tables are monitor-owned and stable under the service
     * token. Check the complete allocation span once; the walker still loads
     * and validates all512 descriptors. No mapping or proof is reused. */
    sprr_count(&c->user_table_reads[1]);
    return (const volatile uint64_t *)pa;
}
#endif
#if SNAP_USER_FUSED_COMPARE && !SNAP_NATIVE_TABLES
static const volatile uint64_t *user_fused_source_read(void *ctx,uint64_t pa)
{
    struct context *c=ctx;
    if(c->private_pages.errors || (pa&4095) || pa<c->work_base ||
       pa>=c->next_table || c->next_table-pa<4096)return 0;
    uint64_t index=(pa-c->work_base)/4096;
    if(index>=SPRR_PRIVATE_PAGES ||
       (c->private_pages.bitmap[index/64]&(UINT64_C(1)<<(index%64))))return 0;
    /* Separate from the full-tree reader counters: this is the private-path
     * preflight/commit mapping, after full source and coverage validation. */
    return (const volatile uint64_t *)pa;
}
#endif
#if !SNAP_NATIVE_TABLES
static int user_refresh_all_impl(struct context *c,struct sptm_root_cached *e)
{
    struct shadow s=user_view_shadow(c,e);struct sprr_views *views=user_views(c,e);
#if SNAP_USER_VIEW_CACHE
    struct sprr_view_proof *proof=&UPROOFS(c)[e-c->user_roots.cache];
    proof->valid=0;
#endif
    if(!views->count && !sprr_views_init(views,&s)) {c->user_view_failed=1;return 0;}
#if !SNAP_USER_PREPARE_FUSED
    if(!sprr_views_prepare_user(views,&s)) {c->user_view_failed=1;return 0;}
#endif
#if SNAP_USER_VIEW_BATCH
    struct sprr_state states[GUEST_CPU_COUNT];int modes[GUEST_CPU_COUNT];
    _Static_assert(GUEST_CPU_COUNT==SPRR_VIEW_CPUS,"batch view CPU count");
    for(unsigned cpu=0;cpu<GUEST_CPU_COUNT;cpu++) {
        struct sprr_state initial={0};sprr_root_reset(&initial,(unsigned)e->flags);
        int active=c->user_roots.active[cpu]==e->root;
        states[cpu]=active ? c->user_roots.sprr[cpu]:initial;
        modes[cpu]=active ? (int)c->user_view_state[cpu].el0:0;
    }
#if SNAP_USER_VIEW_FUSED
#if SNAP_USER_PREPARE_FUSED
#if SNAP_USER_ZERO_GROUP
#if SNAP_USER_TREE_MEMO
    if(!sprr_views_prepare_sync_user_memo(views,&s,states,modes,
            &c->user_prepare_plan,&c->user_prepare_stats,user_table_read,
            &c->user_zero_groups,user_fused_source_read,private_copy_table_read,
            &c->user_fused_compare,&c->table_memo,
            &UMEMOS(c)[e-c->user_roots.cache])) {c->user_view_failed=1;return 0;}
#elif SNAP_USER_FUSED_COMPARE
    if(!sprr_views_prepare_sync_user_compared(views,&s,states,modes,
            &c->user_prepare_plan,&c->user_prepare_stats,user_table_read,
            &c->user_zero_groups,user_fused_source_read,private_copy_table_read,
            &c->user_fused_compare)) {c->user_view_failed=1;return 0;}
#else
    if(!sprr_views_prepare_sync_user_grouped(views,&s,states,modes,
            &c->user_prepare_plan,&c->user_prepare_stats,user_table_read,
            &c->user_zero_groups)) {c->user_view_failed=1;return 0;}
#endif
#else
#if SNAP_USER_TABLE_READ
    if(!sprr_views_prepare_sync_user_mapped(views,&s,states,modes,
            &c->user_prepare_plan,&c->user_prepare_stats,user_table_read)) {c->user_view_failed=1;return 0;}
#else
    if(!sprr_views_prepare_sync_user_fused(views,&s,states,modes,
            &c->user_prepare_plan,&c->user_prepare_stats)) {c->user_view_failed=1;return 0;}
#endif
#endif
#else
    if(!sprr_views_sync_user_fused(views,&s,states,modes)) {c->user_view_failed=1;return 0;}
#endif
    sprr_count(&c->user_fused_syncs);
#else
    if(!sprr_views_sync_user_all(views,&s,states,modes)) {c->user_view_failed=1;return 0;}
#endif
    for(unsigned cpu=0;cpu<GUEST_CPU_COUNT;cpu++)
        if(!user_publish_view(c,e,cpu,&states[cpu],modes[cpu]))return 0;
#else
    for(unsigned cpu=0;cpu<GUEST_CPU_COUNT;cpu++) {
        struct sprr_state initial={0};sprr_root_reset(&initial,(unsigned)e->flags);
        int active=c->user_roots.active[cpu]==e->root;
        const struct sprr_state *state=active ? &c->user_roots.sprr[cpu]:&initial;
        int el0=active ? (int)c->user_view_state[cpu].el0:0;
        if(!user_sync_view(c,e,cpu,state,el0))return 0;
    }
#endif
#if SNAP_USER_VIEW_CACHE
    proof->root=s.root;proof->count=views->count;proof->epoch=c->user_view_epoch;
    proof->valid=c->user_view_epoch!=UINT64_MAX;
#endif
    user_tlb_sync(c);return 1;
}
#endif
static int user_refresh_all(struct context *c,struct sptm_root_cached *e)
{
#if SNAP_NATIVE_TABLES
    /* The variant copies follow every canonical store; before the first
     * install they do not exist yet. A sampled audit re-derives them all. */
    struct sprr_views *v=user_views(c,e);
    if(!v->count || !native_due(&c->native_stats.audit_asks))return !c->user_view_failed;
    int started=detail_begin(c,DETAIL_USER_REFRESH);
    struct shadow s=user_view_shadow(c,e);
    /* Every sampled audit re-derives every copy; every 64th of them also
     * walks the whole canonical tree for coverage. */
    int full=!(c->native_stats.audits&63);
    int result=full ? native_views_verify(v,&s,native_umprr(e)) : native_views_exact(v,&s,native_umprr(e));
    c->native_stats.audits++;c->native_stats.coverages+=full;
    if(!result) {c->native_stats.audit_failures++;c->user_view_failed=1;}
    detail_end(c,DETAIL_USER_REFRESH,started,result);return result;
#else
    int started=detail_begin(c,DETAIL_USER_REFRESH);
    int result=user_refresh_all_impl(c,e);
    detail_end(c,DETAIL_USER_REFRESH,started,result);return result;
#endif
}
static uint64_t user_install_view(struct context *c,uint64_t root,uint64_t canonical,
                                  int invalidate)
{
    unsigned cpu=(unsigned)vcpu_of(c)->slot;
    struct sptm_root_cached *e=user_cached(c,root);
#if SNAP_NATIVE_TABLES
    (void)invalidate;
    if(!e || e->shadow!=canonical)return 0;
    unsigned slot=(unsigned)(e-c->user_roots.cache);
    struct sprr_views *v=user_views(c,e);
    /* First install after a build: derive both variants once. From then on
     * every canonical store keeps them exact. */
    if(!v->count) {
        struct shadow s=user_view_shadow(c,e);
        if(!native_views_sync(v,&s,native_umprr(e))) {c->user_view_failed=1;return 0;}
        native_mark(c,v,1);c->native_stats.syncs++;
        /* No CPU could reach these copies before now: clean them whole. */
        for(unsigned t=0;t<v->count;t++)
            for(unsigned w=0;w<NATIVE_VARIANTS;w++)
                publish(v->tables[t].copy[w],v->tables[t].copy[w]+4096);
    }
#if SNAP_INACTIVE_MIRROR
    UBUDGETS(c)[slot]=0;
#endif
    /* The reset state: UPERM and PPERM initial, EL1 about to run. Phase 1
     * has no kernel variants, so k selects the same TTBR0 and TTBR1 stays. */
    struct sprr_state initial={0};sprr_root_reset(&initial,(unsigned)e->flags);
    struct native_cpu *n=&c->native_cpu[cpu];
    uint64_t ttbr0[2][2];
    for(unsigned w=0;w<2;w++)for(unsigned k=0;k<2;k++)
        ttbr0[w][k]=native_views_root(v,w)|(native_asid(slot,w,0)<<48);
    if(!native_install(n,(const uint64_t (*)[2])ttbr0,0,initial.uperm,initial.pperm,0)) {
        c->user_view_failed=1;return 0;
    }
    c->native_stats.installs++;
    struct user_view_state *u=&c->user_view_state[cpu];
    u->root=root;u->shadow=native_views_root(v,n->w);u->el0=0;
    u->uperm=initial.uperm;u->pperm=initial.pperm;u->umprr=initial.umprr;u->syncs++;
    return u->shadow;
#else
    if(!e || e->shadow!=canonical || !user_refresh_all(c,e))return 0;
#if SNAP_INACTIVE_MIRROR
    UBUDGETS(c)[e-c->user_roots.cache]=0;
#endif
    /* SWITCH_ROOT commits its logical reset after this callback. Install the
     * incoming root's reset state, not the previous address space's state. */
    struct sprr_state initial={0};sprr_root_reset(&initial,(unsigned)e->flags);
    if(!user_sync_view(c,e,cpu,&initial,0))return 0;
    /* Only this CPU's copy was written after the refresh's own TLBI. */
    if(invalidate)user_tlb_sync(c);
    struct user_view_state *u=&c->user_view_state[cpu];
    u->root=root;u->shadow=sprr_views_root(user_views(c,e),cpu);u->el0=0;
    u->uperm=initial.uperm;u->pperm=initial.pperm;u->umprr=initial.umprr;
    return u->shadow;
#endif
}
static int user_refresh_pperm(struct context *c,uint64_t value)
{
    unsigned cpu=(unsigned)vcpu_of(c)->slot;
    if(!c->user_roots.active[cpu])return 1;
    struct sptm_root_cached *e=user_cached(c,c->user_roots.active[cpu]);
#if SNAP_USER_HW_WALK
    if(!e)e=hw_record_entry(c,c->user_roots.active[cpu]);
#endif
    if(!e) {c->user_view_failed=1;return 0;}
#if SNAP_NATIVE_TABLES
    /* PPERM governs EL1: its TPRO bit selects the variant while EL1 runs.
     * The regime is the tracked one, as user_sync_view's was. */
    struct user_view_state *u=&c->user_view_state[cpu];
    struct native_cpu *n=&c->native_cpu[cpu];unsigned w=n->w;
    if(!native_set_pperm(n,value,(int)u->el0)) {c->user_view_failed=1;return 0;}
    c->native_stats.flips+=n->w!=w;
    u->pperm=value;u->shadow=user_hw_root(c,e,cpu);
    return !c->user_view_failed;
#else
    struct sprr_state next=c->user_roots.sprr[cpu];next.pperm=value;
    return user_sync_view(c,e,cpu,&next,(int)c->user_view_state[cpu].el0);
#endif
}
#if SNAP_USER_MODE_SKIP
/* The only mode-dependent input to a user view is a class9 leaf's write bit:
 * entry_decode takes it from UPERM at EL0 and PPERM at EL1. Everything else
 * (fixed native leaves, UMPRR validity, child copies) is mode-independent. */
static int user_mode_write(const struct sprr_state *s,unsigned el0)
{return !!((el0 ? s->uperm : s->pperm)&SPRR_UPERM_TPRO_WRITE);}
#endif
#if SNAP_NATIVE_TABLES
/* An EL0<->EL1 crossing, safe without the service lock: it touches only this
 * CPU's native_cpu, user_view_state and user_roots.active entries, which no
 * other CPU writes, and reads the latched failure flag. 1: the variant of
 * the regime about to run (el0) is live and u->el0/shadow/entries/returns
 * are updated exactly as user_enter_mode does. 0: declined with nothing
 * changed (a failure latched, no native address space installed, state that
 * disagrees with the active root, a missing variant); the caller takes the
 * locked path, user_enter_mode, which decides and reports. Per-CPU counters
 * only: native_cpu.selects/flips count every crossing, native_stats.flips
 * the locked ones. */
static int native_cross(struct context *c,unsigned cpu,int el0)
{
    if(cpu>=GUEST_CPU_COUNT || c->user_view_failed)return 0;
    struct native_cpu *n=&c->native_cpu[cpu];
    struct user_view_state *u=&c->user_view_state[cpu];
    uint64_t root=c->user_roots.active[cpu];
    el0=!!el0;
    if(!n->installed || !root || u->root!=root || n->el0!=u->el0)return 0;
    if(u->el0==(unsigned)el0)return 1;
    if(!n->ttbr0[native_variant_w(n->uperm,n->pperm,el0)][native_variant_k(n->pperm)])return 0;
    if(!native_select(n,el0))return 0;
    u->el0=(unsigned)el0;u->shadow=n->ttbr0[n->w][n->k]&PT_OA_MASK;
    if(el0)u->returns++;else u->entries++;
    return 1;
}
#endif
static int user_enter_mode(struct context *c,int el0)
{
    unsigned cpu=(unsigned)vcpu_of(c)->slot;
    struct sptm_root_cached *e=user_cached(c,c->user_roots.active[cpu]);
#if SNAP_USER_HW_WALK
    if(!e)e=hw_record_entry(c,c->user_roots.active[cpu]);
#endif
    if(!e) {c->user_view_failed=1;return 0;}
    struct user_view_state *u=&c->user_view_state[cpu];
    if(u->el0==(unsigned)el0)return !c->user_view_failed;
#if SNAP_NATIVE_TABLES
    /* The governing register changes with the regime: select its variant.
     * Under the lock a declined crossing is a failure. */
    unsigned w=c->native_cpu[cpu].w;
    if(!native_cross(c,cpu,el0) || u->shadow!=user_hw_root(c,e,cpu)) {c->user_view_failed=1;return 0;}
    c->native_stats.flips+=c->native_cpu[cpu].w!=w;
    return 1;
#endif
#if SNAP_USER_MODE_SKIP
    /* This CPU's copies were last written (sync, refresh or install) for
     * exactly this root, view and SPRR state in mode u->el0. If the mode's
     * TPRO write bit is the same, a sync for the new mode would store
     * nothing, so there is nothing to publish or invalidate. Every 256th
     * skip runs the real sync instead and counts any store as a mismatch. */
    const struct sprr_state *now=&c->user_roots.sprr[cpu];
    struct user_mode_skip_stats *k=&c->user_mode_skip[cpu];
    if(!c->user_view_failed && u->root==e->root &&
       u->shadow==sprr_views_root(user_views(c,e),cpu) &&
       u->uperm==now->uperm && u->pperm==now->pperm && u->umprr==now->umprr &&
       user_mode_write(now,(unsigned)u->el0)==user_mode_write(now,(unsigned)el0)) {
        if((k->skips++&255)!=255) {
            u->el0=(unsigned)el0;
            if(el0)u->returns++;else u->entries++;
            return 1;
        }
        uint64_t changed=c->view_store_compare[1].changed;
#if SNAP_USER_TREE_MEMO
        /* Keep this check independent of memo claims: the sync recomputes
         * and compares every private word, and also verifies every claim. */
        c->table_memo.force=1;
#endif
        int synced=user_sync_view(c,e,cpu,now,el0);
#if SNAP_USER_TREE_MEMO
        c->table_memo.force=0;
#endif
        if(!synced)return 0;
        k->checks++;
        if(c->view_store_compare[1].changed!=changed)k->mismatches++;
        user_tlb_sync(c);
        if(el0)u->returns++;else u->entries++;
        return 1;
    }
    k->differs++;
#endif
    if(!user_sync_view(c,e,cpu,&c->user_roots.sprr[cpu],el0))return 0;
    user_tlb_sync(c);
    if(el0)u->returns++;else u->entries++;
    return 1;
}
#if SNAP_EL0_MEMO
/* The lookup, then every other check (user_return_check, which a memo hit
 * runs on the entry it remembers). */
static struct sptm_root_cached *user_return_check(struct context *c,struct sptm_root_cached *e);
static struct sptm_root_cached *user_return_root(struct context *c)
{
    struct vcpu *v=vcpu_of(c);
    struct sptm_root_cached *e=user_cached(c,c->user_roots.active[v->slot]);
#if SNAP_USER_HW_WALK
    if(!e)e=hw_record_entry(c,c->user_roots.active[v->slot]);
#endif
    return user_return_check(c,e);
}
static struct sptm_root_cached *user_return_check(struct context *c,struct sptm_root_cached *e)
{
    struct vcpu *v=vcpu_of(c);
#else
static struct sptm_root_cached *user_return_root(struct context *c)
{
    struct vcpu *v=vcpu_of(c);
    struct sptm_root_cached *e=user_cached(c,c->user_roots.active[v->slot]);
#if SNAP_USER_HW_WALK
    if(!e)e=hw_record_entry(c,c->user_roots.active[v->slot]);
#endif
#endif
    if(!e || !e->asid || e->asid>0xffff || e->format>1 ||
       c->root_install_failures || c->kernel_view_failed || c->user_view_failed)return 0;
    struct sptm_memory m=sptm_context_memory(c);
    if(!sptm_managed_frame(&m,e->root))return 0;
    volatile uint8_t *meta=m.map(m.ctx,m.frame_map_pa+((e->root-m.frame_low)>>14)*16,16);
    if(!meta || meta[0] || meta[1] || meta[2]!=SPTM_MAC_USER_ROOT_TABLE ||
       ((unsigned)meta[4]|((unsigned)meta[5]<<8))!=e->asid ||
       ((unsigned)meta[10]|((unsigned)meta[11]<<8))!=e->flags ||
       meta[12]!=e->format || meta[13] || meta[14] || meta[15] ||
       !sptm_mac_user_binding_valid(&m,meta))return 0;
    uint64_t ttbr,tcr;
    __asm__ volatile("mrs %0, ttbr0_el1; mrs %1, tcr_el1":"=r"(ttbr),"=r"(tcr));
    if(v->guest_ttbr0!=(e->root|(e->asid<<48)) ||
#if SNAP_NATIVE_TABLES
       ttbr!=c->native_cpu[v->slot].ttbr0[c->native_cpu[v->slot].w&1][c->native_cpu[v->slot].k&1] ||
       !c->native_cpu[v->slot].installed ||
#else
       ttbr!=(sprr_views_root(user_views(c,e),(unsigned)v->slot)|(e->asid<<48)) ||
#endif
       tcr!=shadow_tcr(v->guest_tcr) ||
       (tcr&((1UL<<7)|(3UL<<14))) || (tcr&63)!=17)return 0;
    return e;
}
static int user_source_read(void *ctx,uint64_t pa,uint64_t *out)
{
    volatile uint8_t *p=sptm_map(ctx,pa,8);
    if(!p || (pa&7))return -1;
    *out=*(volatile uint64_t *)p;return 0;
}
#if SNAP_EL0_MEMO
/* user_instruction_read's code frame and word at pa (also a memo hit's
 * re-read): a managed USER_EXEC frame. */
static int user_code_word(struct context *c,uint64_t pa,uint32_t *word)
{
    struct sptm_memory m=sptm_context_memory(c);uint64_t frame=pa&~16383UL;
    if(!sptm_managed_frame(&m,frame))return 0;
    volatile uint8_t *meta=m.map(m.ctx,m.frame_map_pa+((frame-m.frame_low)>>14)*16,16);
    volatile uint8_t *code=m.map(m.ctx,pa,4);
    if(!meta || meta[0] || meta[1] || meta[2]!=SPTM_MAC_USER_EXEC || !code)return 0;
    *word=*(volatile uint32_t *)code;
    return 1;
}
/* This vCPU's memo while its fast_el0_word's full read records, else 0. */
static struct el0_memo_cpu *el0_memo_recording(struct context *c)
{
    struct el0_memo_cpu *m=&EL0M(c)[vcpu_of(c)->slot];
    return m->recording ? m : 0;
}
#endif
/* Capture a bounded, independently walkable witness for the initial dyld-like
 * entry. Later ERETs may target demand-paged addresses: a missing instruction
 * is XNU's fault to resolve, not a reason to fabricate a mapping here. */
static int user_instruction_read(struct context *c,struct sptm_root_cached *e,
    uint64_t target,struct mmu_leaf *source_leaf,struct mmu_leaf *hardware_leaf,
    uint32_t *word)
{
    struct mmu_config source={e->format ? 12 : 14,17,e->root},
        hardware={12,17,user_hw_root(c,e,(unsigned)vcpu_of(c)->slot)};
    struct mmu_leaf a,b;
#if SNAP_EL0_MEMO
    /* fast_el0_word's full read records every descriptor both walks read
     * (compat/el0-memo.h); every other caller reads exactly as below. */
    struct el0_memo_cpu *memo=el0_memo_recording(c);
#if SNAP_USER_HW_WALK
    unsigned hardware_kind=hw_walk_of_entry(c->hw_walk,e)!=0;
    mmu_read_fn hardware_read=hardware_kind ? hw_table_read : kernel_table_read;
#else
    unsigned hardware_kind=0;
    mmu_read_fn hardware_read=kernel_table_read;
#endif
    struct el0_memo_reader rs={user_source_read,c,memo ? &memo->pending.walk[0] : 0},
        rh={hardware_read,c,memo ? &memo->pending.walk[1] : 0};
    if(mmu_walk(&source,target,memo ? el0_memo_read : user_source_read,memo ? (void *)&rs : c,&a) ||
       !a.valid || a.level!=3 ||
       mmu_walk(&hardware,target,memo ? el0_memo_read : hardware_read,memo ? (void *)&rh : c,&b) ||
       !b.valid || b.level!=3 ||
#else
#if SNAP_USER_HW_WALK
    /* A hardware-walk root's tables are guest RAM (or copies in the arena). */
    mmu_read_fn hardware_read=hw_walk_of_entry(c->hw_walk,e) ? hw_table_read : kernel_table_read;
    if(mmu_walk(&source,target,user_source_read,c,&a) || !a.valid || a.level!=3 ||
       mmu_walk(&hardware,target,hardware_read,c,&b) || !b.valid || b.level!=3 ||
#else
    if(mmu_walk(&source,target,user_source_read,c,&a) || !a.valid || a.level!=3 ||
       mmu_walk(&hardware,target,kernel_table_read,c,&b) || !b.valid || b.level!=3 ||
#endif
#endif
       a.pa!=b.pa || (a.descriptor&(PT_LEAF_ATTRS|PT_LEAF_UPPER))!=
                       (b.descriptor&(PT_LEAF_ATTRS|PT_LEAF_UPPER)) ||
       (a.descriptor&PT_AP)!=PT_AP || !(a.descriptor&PT_AF) ||
       !(a.descriptor&PT_PXN) || (a.descriptor&PT_UXN))return 0;
#if SNAP_EL0_MEMO
    uint32_t code_word;
    if(!user_code_word(c,a.pa,&code_word))return 0;
    *source_leaf=a;*hardware_leaf=b;*word=code_word;
    if(memo)el0_memo_recorded(memo,e,source.root,source.granule_shift,hardware.root,hardware_kind,
                              a.descriptor,b.descriptor,a.pa);
    return 1;
#else
    struct sptm_memory m=sptm_context_memory(c);uint64_t frame=a.pa&~16383UL;
    if(!sptm_managed_frame(&m,frame))return 0;
    volatile uint8_t *meta=m.map(m.ctx,m.frame_map_pa+((frame-m.frame_low)>>14)*16,16);
    volatile uint8_t *code=m.map(m.ctx,a.pa,4);
    if(!meta || meta[0] || meta[1] || meta[2]!=SPTM_MAC_USER_EXEC || !code)return 0;
    *source_leaf=a;*hardware_leaf=b;*word=*(volatile uint32_t *)code;
    return 1;
#endif
}
#if SNAP_USER_CRASH_RING
/* One aligned user word through the guest's own tables for the active root:
 * a software walk (no AT, no shadow view), accepted only when the leaf is a
 * valid accessed page of SPTM-managed RAM, so a stray frame pointer can
 * never reach device memory or anything outside the declared DRAM. */
static int user_crash_read(void *ctx,uint64_t va,uint64_t *out)
{
    struct context *c=ctx;
    struct sptm_root_cached *e=user_cached(c,c->user_roots.active[vcpu_of(c)->slot]);
#if SNAP_USER_HW_WALK
    if(!e)e=hw_record_entry(c,c->user_roots.active[vcpu_of(c)->slot]);
#endif
    struct mmu_leaf a;
    if(!e || !e->root || e->format>1 || (va&7) || va>=(UINT64_C(1)<<47))return 0;
    struct mmu_config source={e->format ? 12 : 14,17,e->root};
    if(mmu_walk(&source,va,user_source_read,c,&a) || !a.valid || a.level!=3 ||
       !(a.descriptor&PT_AF))return 0;
    struct sptm_memory m=sptm_context_memory(c);
    if(!sptm_managed_frame(&m,a.pa&~16383UL))return 0;
    volatile uint8_t *word=sptm_map(c,a.pa,8);
    if(!word)return 0;
    *out=*(volatile uint64_t *)word;
    return 1;
}
static void user_crash_note(struct context *c,unsigned kind,const uint64_t *frame,
                            uint64_t esr,uint64_t elr,uint64_t far)
{
    struct vcpu *v=vcpu_of(c);
    uint64_t raw,sp,thread,tsd;
    __asm__ volatile("isb; mrs %0, cntvct_el0; mrs %1, sp_el0; mrs %2, tpidr_el1; "
                     "mrs %3, tpidrro_el0":"=r"(raw),"=r"(sp),"=r"(thread),"=r"(tsd)::"memory");
    uint64_t guest=v->clock_rate.host_hz && v->clock_rate.guest_hz ?
                   clock_rate_sample(&v->clock_rate,raw) : 0;
    user_crash_record(&c->user_crashes[v->slot],kind,(unsigned)v->slot,guest,raw,esr,elr,
                      far,frame,sp,v->guest_ttbr0,thread,tsd,user_crash_read,c);
}
#endif
static int user_entry_snapshot(struct context *c,struct sptm_root_cached *e,
    struct user_execution *u,uint64_t target,uint64_t spsr,uint64_t x0)
{
    struct mmu_leaf a,b;uint32_t word;
    if(!user_instruction_read(c,e,target,&a,&b,&word))return 0;
    __asm__ volatile("mrs %0, sp_el0":"=r"(u->stack));
    __asm__ volatile("mrs %0, ttbr0_el1; mrs %1, tcr_el1":"=r"(u->ttbr),"=r"(u->tcr));
    u->entry=target;u->initial_spsr=spsr;u->root=e->root;
    u->shadow=user_hw_root(c,e,(unsigned)vcpu_of(c)->slot);
    u->entry_pa=a.pa;u->source_pte=a.descriptor;u->shadow_pte=b.descriptor;
    u->instruction=word;u->initial_x0=x0;
    return u->instruction==0x910003e0 && !(spsr&(1UL<<21));
}
#if SNAP_CANONICAL_VIEW_FAST
/* kernel_table_read accepts all 512 words of pa..pa+4095 exactly when pa is
 * 4K aligned inside the allocated arena with a whole page before next_table. */
static const volatile uint64_t *canonical_table_read(void *ctx,uint64_t pa)
{
    struct context *c=ctx;
    if((pa&4095) || pa<c->work_base || pa>=c->next_table || c->next_table-pa<4096)return 0;
    return (const volatile uint64_t *)pa;
}
/* sptm_root_canonical_view's proof through sptm_root_view_mapped. Every 64th
 * call also runs the reference walk: a different verdict or result is terminal
 * and nothing is repaired. */
static int canonical_view(struct context *c,const struct sptm_root_cached *e,
    const struct shadow *s,const struct sptm_memory *m,struct sptm_fixed_view *out)
{
    struct canonical_view_perf *p=&c->perf.canonical;
    int ok=sptm_root_view_mapped(e,s,m,out,1,canonical_table_read,&p->mapped);
    if(!(p->mapped.calls&63)) {
        struct sptm_fixed_view reference={0};
        int again=sptm_root_canonical_view(e,s,m,&reference);
        p->sampled++;
        if(again!=ok || (ok && (reference.tables!=out->tables ||
            reference.pages!=out->pages || reference.classes!=out->classes))) {
            p->mismatches++;return 0;
        }
    }
    return ok;
}
#endif
/* The canonical user-view proof taken before every UPERM write and TPRO PPERM
 * change: all of the active root's 4K leaves against its source tables. Its
 * own detail bucket; UPERM writes are otherwise outside every bucket. */
static int user_canonical_proof(struct context *c,const struct sptm_root_cached *e,
    const struct shadow *s,const struct sptm_memory *m,struct sptm_fixed_view *out)
{
    int started=detail_begin(c,DETAIL_USER_VIEW_PROOF);
#if SNAP_CANONICAL_VIEW_FAST
    int result=canonical_view(c,e,s,m,out);
#else
    int result=sptm_root_canonical_view(e,s,m,out);
#endif
    detail_end(c,DETAIL_USER_VIEW_PROOF,started,result);return result;
}

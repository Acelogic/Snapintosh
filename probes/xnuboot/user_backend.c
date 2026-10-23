/* SPDX-License-Identifier: MIT */
/* User permission and TPRO checks, the sptm_user_backend callbacks, mixed
 * kernel updates and UPDATE_DISJOINT.
 * Part of probes/xnuboot.c's translation unit, included in order; not compiled on its own. */
/* user_proof=0 (native audit mode, sampled away): keep proof's user fields,
 * which the caller copied from this CPU's last proof. */
static int pperm_tpro_preflight(struct context *c,struct sprr_pperm_update_state *proof,
                                int user_proof)
{
    struct sptm_root_cached *e=user_return_root(c);
    if(!e)return 0;
    struct shadow s={.txsz=17,.root=e->shadow,.read=kernel_table_read,.ctx=c};
    struct sptm_memory m=sptm_context_memory(c);struct sptm_fixed_view user={0};
    struct shadow k=kernel_shadow(c);struct sprr_view_classes kernel;
#if SNAP_USER_HW_WALK
    if(user_proof && (hw_walk_of_entry(c->hw_walk,e) ? !hw_entry_proof(c,e,&user) :
                      !user_canonical_proof(c,e,&s,&m,&user)))return 0;
#else
    if(user_proof && !user_canonical_proof(c,e,&s,&m,&user))return 0;
#endif
#if SNAP_KERNEL_CLASS_PROOF && SNAP_CLASS_PROOF_MAPPED
    struct class_proof_mapped_stats *cm=&c->class_proof_mapped;
    struct sprr_class_walk_stats walk={0};
    uint64_t walks=c->kernel_class_proof.walks,verified=c->kernel_class_proof.verified;
#if SNAP_CLASS_LEAF_MEMO
    int proved=sprr_class_proof_check_leaf(&c->kernel_class_proof,&k,1UL<<9,
        c->work_base,c->work_end,&kernel,class_table_read,c,&walk,
        &c->class_leaf,&c->table_memo);
#elif SNAP_KERNEL_PPERM_FAST
    /* Walks run only here, at the top of a PPERM write or a root install,
     * never inside an SPTM transaction between a mapped page's write note
     * and its stores, so an unchanged generation means unchanged bytes. */
    int proved=sprr_class_proof_check_fast(&c->kernel_class_proof,&k,1UL<<9,
        c->work_base,c->work_end,&kernel,class_table_read,c,&walk,
        &c->class_leaf,&c->table_memo);
#else
    int proved=sprr_class_proof_check_with(&c->kernel_class_proof,&k,1UL<<9,
        c->work_base,c->work_end,&kernel,class_table_read,c,&walk);
#endif
    /* A full walk used the mapped traversal; a verifying hit re-walked through
     * the original word reader and matched that walk's saved result. */
    cm->walks+=c->kernel_class_proof.walks-walks;
    cm->compared+=c->kernel_class_proof.verified-verified;
    cm->tables+=walk.tables;cm->groups+=walk.groups;cm->empty_groups+=walk.empty_groups;
    if(!proved) {cm->errors++;return 0;}
#elif SNAP_KERNEL_CLASS_PROOF
    if(!sprr_class_proof_check(&c->kernel_class_proof,&k,1UL<<9,
                              c->work_base,c->work_end,&kernel))return 0;
#else
    if(!sprr_views_check_classes(&k,1UL<<9,&kernel))return 0;
#endif
    if(user_proof) {
        proof->user_root=e->root;proof->user_shadow=e->shadow;
        proof->user_tables=user.tables;proof->user_pages=user.pages;proof->user_classes=user.classes;
    }
    proof->kernel_root=k.root;proof->kernel_tables=kernel.tables;
    proof->kernel_pages=kernel.pages;proof->kernel_classes=kernel.classes;
    return 1;
}
static int user_change_uperm(void *ctx,uint64_t value)
{
    struct context *c=ctx;struct vcpu *v=vcpu_of(c);
    struct sptm_root_cached *e=user_return_root(c);
    if(!e)return 0;
    struct shadow s={.txsz=17,.root=e->shadow,.read=kernel_table_read,.ctx=c};
    struct sptm_memory m=sptm_context_memory(c);struct sptm_fixed_view view;
#if SNAP_NATIVE_TABLES
    /* Audit mode: the proof runs on a CPU's first write and then sampled; its
     * record keeps the last proof. The flip itself is a TTBR0 write. */
    struct sprr_uperm_update_state *u=&c->sprr_uperm_update[v->slot];
    if(!u->root || native_due(&c->native_stats.proof_asks)) {
#if SNAP_USER_HW_WALK
        if(hw_walk_of_entry(c->hw_walk,e) ? !hw_entry_proof(c,e,&view) :
           !user_canonical_proof(c,e,&s,&m,&view))return 0;
#else
        if(!user_canonical_proof(c,e,&s,&m,&view))return 0;
#endif
        u->root=e->root;u->shadow=e->shadow;u->tables=view.tables;
        u->pages=view.pages;u->classes=view.classes;
    } else c->native_stats.proof_skips++;
    struct user_view_state *state=&c->user_view_state[v->slot];
    struct native_cpu *n=&c->native_cpu[v->slot];unsigned w=n->w;
    if(!native_set_uperm(n,value,(int)state->el0)) {c->user_view_failed=1;return 0;}
    c->native_stats.flips+=n->w!=w;
    state->uperm=value;state->shadow=user_hw_root(c,e,(unsigned)v->slot);
    return !c->user_view_failed;
#else
    if(!user_canonical_proof(c,e,&s,&m,&view))return 0;
    struct sprr_state next=c->user_roots.sprr[v->slot];next.uperm=value;
    if(!user_sync_view(c,e,(unsigned)v->slot,&next,
                      (int)c->user_view_state[v->slot].el0))return 0;
    user_tlb_sync(c);
    struct sprr_uperm_update_state *u=&c->sprr_uperm_update[v->slot];
    u->root=e->root;u->shadow=e->shadow;u->tables=view.tables;
    u->pages=view.pages;u->classes=view.classes;return 1;
#endif
}
static enum sprr_result user_write_uperm(struct context *c,uint64_t *frame,
    uint64_t pc,uint64_t saved,uint32_t word)
{
    struct vcpu *v=vcpu_of(c);struct sprr_state *s=&c->user_roots.sprr[v->slot];
    uint64_t before=s->uperm,value=(word&31)==31 ? 0 : frame[word&31];
    enum sprr_result result=sprr_user_write(s,word,frame,user_change_uperm,c);
    if(result!=SPRR_OK)return result;
    struct sprr_uperm_update_state *u=&c->sprr_uperm_update[v->slot];
    u->writes++;u->changes+=before!=value;u->pc=pc;u->word=word;
    u->before=before;u->after=value;u->spsr=saved;u->umprr=s->umprr;
    __asm__ volatile("mrs %0, sp_el0":"=r"(u->sp));
    return SPRR_OK;
}
static int user_sysreg_access(struct context *c,uint64_t *frame,uint64_t pc,
                          uint64_t saved,uint64_t esr,uint64_t vector,uint64_t *elr)
{
    if(vector!=0x400 || esr!=0x02000000 || pc>=(1UL<<47)-4)return 0;
    struct vcpu *v=vcpu_of(c);
    uint64_t vhcr=v->vncr_va ? *(volatile uint64_t *)(v->vncr_va+0x78) : 0,translated;
    if(!exception_user_return(0xd69f03e0,vhcr,pc+4,saved,&translated))return 0;
    struct sptm_root_cached *root=user_return_root(c);
    struct mmu_leaf source,hardware;uint32_t word;
    if(!root || !user_instruction_read(c,root,pc,&source,&hardware,&word))return 0;
    struct clock_backend backend={c,clock_counter,clock_control};
    struct sprr_state *sprr=&c->user_roots.sprr[v->slot];
    enum clock_result clock_result=guest_clock_user_read(&v->clock,&backend,word,frame);
    if(clock_result==CLOCK_OK) {
        struct user_clock_state *u=&c->user_clock[v->slot];
        u->reads++;u->pc=pc;u->word=word;u->value=v->clock.last;u->spsr=saved;
        __asm__ volatile("mrs %0, sp_el0":"=r"(u->sp));
        u->root=root->root;u->cntkctl=v->clock.cntkctl;u->raw=v->clock_raw_last;
        u->host_hz=v->clock_rate.host_hz;u->guest_hz=v->clock_rate.guest_hz;
        SERVICE_SUB_TAG(c,SERVICE_SUB_EL0_CLOCK);
    } else if(clock_result==CLOCK_UNHANDLED && (word&~31U)==0xd51ef1a0U) {
        if(user_write_uperm(c,frame,pc,saved,word)!=SPRR_OK)return 0;
        SERVICE_SUB_TAG(c,SERVICE_SUB_EL0_UPERM_WRITE);
    } else if(clock_result==CLOCK_UNHANDLED && sprr_user_read(sprr,word,frame)==SPRR_OK) {
        struct user_sprr_state *u=&c->user_sprr[v->slot];
        u->reads++;u->pc=pc;u->word=word;u->value=sprr->uperm;u->spsr=saved;
        __asm__ volatile("mrs %0, sp_el0":"=r"(u->sp));
        u->root=root->root;u->umprr=sprr->umprr;
        SERVICE_SUB_TAG(c,SERVICE_SUB_EL0_UPERM);
    } else return 0;
    /* The vector page has executed no instruction: restore the original user
     * PSTATE and keep SP_EL0/registers intact except the MRS destination. */
    step_arm(c,0);guards_close(c);
    __asm__ volatile("msr spsr_el2, %0"::"r"(translated));
    *elr=pc+4;
    return 1;
}
static uint64_t user_live_alloc(void *ctx)
{
    uint64_t pa=user_table_alloc(ctx);
    /* Publish zeroed child storage before descend links it into a live root. */
    if(pa)publish(pa,pa+4096);
    return pa;
}
static int user_live_write(void *ctx,uint64_t pa,uint64_t value)
{
    int result=mem_write(ctx,pa,value);
    if(!result)publish(pa,pa+8);
    return result;
}
static int user_prepare_leaf(void *ctx,uint64_t root,uint64_t va,unsigned shift,uint64_t pte)
{
    struct context *c=ctx;struct sptm_root_cached *e=user_cached(c,root);
    if(!e)return 0;
    struct shadow s={.txsz=17,.root=e->shadow,.alloc=user_live_alloc,
        .read=mem_read,.write=user_live_write,.ctx=c,
        .alloc_ctx=&UOWNERS(c)[e-c->user_roots.cache],
        .admit=SNAP_NATIVE_WRITER_ADMISSION ? native_writer_admit_user:0};
    if(!sptm_root_prepare_leaf(e,&s,va,shift))return 0;
    if(sprr_pte_class(pte)==9) {
        /* Detach every active CPU's path while all future leaves are still
         * absent. No running CPU may observe raw Apple class9 as Arm RX. */
#if SNAP_NATIVE_TABLES
        if(!native_prepare_tpro(c,e,va,shift))return 0;
#else
        struct shadow private=user_view_shadow(c,e);
        for(uint64_t off=0;off<(1UL<<shift);off+=4096)
            if(!sprr_views_prepare_user_leaf(user_views(c,e),&private,va+off))return 0;
        if(!user_refresh_all(c,e))return 0;
#endif
    }
    return 1;
}
static int user_commit_leaf(void *ctx,uint64_t root,uint64_t va,unsigned shift,uint64_t pte)
{
    struct context *c=ctx;struct sptm_root_cached *e=user_cached(c,root);
    if(!e)return 0;
    struct shadow s={.txsz=17,.root=e->shadow,.alloc=user_live_alloc,
        .read=mem_read,.write=user_live_write,.ctx=c,
        .alloc_ctx=&UOWNERS(c)[e-c->user_roots.cache],
        .admit=SNAP_NATIVE_WRITER_ADMISSION ? native_writer_admit_user:0};
    struct sptm_memory m=sptm_context_memory(c);
    if(!sptm_root_commit_leaf(e,&s,&m,va,shift,pte) || !user_refresh_all(c,e))return 0;
    if(!user_commit_tlb_range(c,0,va,UINT64_C(1)<<shift))return 0;
    c->user_live_pages++;return 1;
}
#if SNAP_INACTIVE_MIRROR
/* After an accepted, non-conflicting MAP_PAGE on a root no CPU has installed
 * (e: its valid cached entry, or 0): nonzero keeps a shadow that still equals
 * the guest tree (compat/inactive-mirror.h). A fresh leaf counts as committed
 * only if user_commit_leaf finished for this call. Zero: invalidate. */
static int inactive_map_keep(struct context *c,struct sptm_root_cached *e,
    const struct sptm_user_backend *b,uint64_t pte,uint64_t status,uint64_t live)
{
    struct inactive_mirror_state *m=&c->inactive_mirror;
    if(!e)return 0;
    int committed=b->mirror && c->user_live_pages==live+1;
    if(!inactive_mirror_keep(e->valid!=0,status,committed)) {
        /* Not admitted: the same reasons, in inactive_mirror_admit's order
         * (with SNAP_NATIVE_LIVE only arena room is asked). */
        if(!SNAP_NATIVE_LIVE && sprr_pte_class(pte)==9)m->stats.tpro++;
        else if(!SNAP_NATIVE_LIVE && UBUDGETS(c)[e-c->user_roots.cache]>=INACTIVE_MIRROR_BUDGET)m->stats.budget++;
        else m->stats.arena++;
        return 0;
    }
    if(committed) {m->stats.leaves++;UBUDGETS(c)[e-c->user_roots.cache]++;}
    else m->stats.present++;
    return 1;
}
#endif
static int user_prepare_unmap(void *ctx,uint64_t root,uint64_t va,unsigned shift,uint64_t count)
{
    struct context *c=ctx;struct sptm_root_cached *e=user_cached(c,root);
    /* user_backend has already rejected active roots without a valid cache. */
    if(!e)return 1;
    struct shadow s={.txsz=17,.root=e->shadow,.alloc=user_live_alloc,
        .read=mem_read,.write=user_live_write,.ctx=c,
        .alloc_ctx=&UOWNERS(c)[e-c->user_roots.cache],
        .admit=SNAP_NATIVE_WRITER_ADMISSION ? native_writer_admit_user:0};
    struct sptm_memory m=sptm_context_memory(c);
    return sptm_root_prepare_unmap(e,&s,&m,va,shift,count);
}
static int user_prepare_update(void *ctx,uint64_t root,uint64_t va,unsigned shift,uint64_t old,uint64_t next)
{
    if(!user_prepare_unmap(ctx,root,va,shift,1))return 0;
    struct context *c=ctx;struct sptm_root_cached *e=user_cached(c,root);
    if(e && sprr_pte_class(next)==9 && sprr_pte_class(old)!=9) {
        /* Prepare private paths before an existing fixed leaf becomes TPRO.
         * The source still contains its old permissions while copies detach. */
#if SNAP_NATIVE_TABLES
        if(!native_prepare_tpro(c,e,va,shift))return 0;
#else
        struct shadow private=user_view_shadow(c,e);
        for(uint64_t off=0;off<(1UL<<shift);off+=4096)
            if(!sprr_views_prepare_user_leaf(user_views(c,e),&private,va+off))return 0;
        if(!user_refresh_all(c,e))return 0;
#endif
    }
    return 1;
}
static int user_commit_update(void *ctx,uint64_t root,uint64_t va,unsigned shift,uint64_t old,uint64_t next)
{
    struct context *c=ctx;struct sptm_root_cached *e=user_cached(c,root);
#if SNAP_USER_HW_WALK
    /* A hardware-walk root (never cached): its copies follow the store, then
     * the same skip and invalidation as below (hardware never caches an
     * AF-clear leaf, and the copies keep AF). */
    struct hw_walk_root *hr=hw_root(c,root);
    if(hr) {
        struct hw_walk_ops o=hw_ops(c);
        if(e || !hw_walk_after_add(&o,hr,va,UINT64_C(1)<<shift,&c->hw_walk->stats))return hw_fail(c);
    }
#endif
    if(e) {
        struct shadow s={.txsz=17,.root=e->shadow,.alloc=user_live_alloc,
            .read=mem_read,.write=user_live_write,.ctx=c,
            .alloc_ctx=&UOWNERS(c)[e-c->user_roots.cache],
            .admit=SNAP_NATIVE_WRITER_ADMISSION ? native_writer_admit_user:0};
        struct sptm_memory m=sptm_context_memory(c);
        if(!sptm_root_commit_update(e,&s,&m,va,shift,old,next) || !user_refresh_all(c,e))return 0;
    }
#if SNAP_UPDATE_DISJOINT_FAST
    /* An old leaf with AF clear raised an Access flag fault on every walk, so
     * no TLB holds it, and prepare proved the cached copies equal it
     * (compat/update-fast.h): nothing to revoke. */
    if(update_fast_uncached(old))return !c->user_view_failed;
#endif
    /* Option400 permits a weaker final synchronization in Apple's monitor.
     * Finish it here, including every VMID, so no deferred revocation remains. */
    user_tlb_range(c,va,UINT64_C(1)<<shift);return !c->user_view_failed;
}
static int user_commit_unmap(void *ctx,uint64_t root,uint64_t va,unsigned shift,
                             uint64_t count,uint64_t removed)
{
    struct context *c=ctx;struct sptm_root_cached *e=user_cached(c,root);
    if(e) {
        struct shadow s={.txsz=17,.root=e->shadow,.alloc=user_live_alloc,
            .read=mem_read,.write=user_live_write,.ctx=c,
            .alloc_ctx=&UOWNERS(c)[e-c->user_roots.cache],
            .admit=SNAP_NATIVE_WRITER_ADMISSION ? native_writer_admit_user:0};
        if(!sptm_root_commit_unmap(e,&s,va,shift,count,removed) || !user_refresh_all(c,e))return 0;
    }
    /* Flush even an inactive root: its previous translations must not outlive
     * the references about to be released by sptm_mac_unmap_user_region. */
    if(!user_commit_tlb_range(c,1,va,count<<shift))return 0;
    c->user_unmap_calls++;c->user_unmap_pages+=removed;return 1;
}
static int user_prepare_detach(void *ctx,uint64_t root,uint64_t va,unsigned shift,
                               unsigned level,uint64_t removed)
{
    struct context *c=ctx;struct sptm_root_cached *e=user_cached(c,root);
#if SNAP_NATIVE_SHARED
    /* A shared root detaching an (empty, un-nested) level-3 table: its group
     * is derived state no root links; drop it so the PA can be reused. */
    if(!e && level==2 && shift==14) {
        uint64_t child;int g;
        if(native_group_at(c,root,va,&g,&child) && g>=0) {
            if(UNS(c).group[g].leaves || UNS(c).group[g].shared!=root ||
               !native_group_unlinked(c,g))return 0;
            if(!native_shared_free(&UNS(c),g,native_group_release,c) || c->user_view_failed)return 0;
        }
    }
#endif
    if(!e)return 1;
    struct shadow s={.txsz=17,.root=e->shadow,.alloc=user_live_alloc,
        .read=mem_read,.write=user_live_write,.ctx=c,
        .alloc_ctx=&UOWNERS(c)[e-c->user_roots.cache],
        .admit=SNAP_NATIVE_WRITER_ADMISSION ? native_writer_admit_user:0};
    struct sptm_memory m=sptm_context_memory(c);
    return sptm_root_prepare_detach(e,&s,&m,va,shift,level,removed);
}
static int user_commit_detach(void *ctx,uint64_t root,uint64_t va,unsigned shift,
                              unsigned level,uint64_t removed)
{
    struct context *c=ctx;struct sptm_root_cached *e=user_cached(c,root);
    if(e) {
        struct shadow s={.txsz=17,.root=e->shadow,.alloc=user_live_alloc,
            .read=mem_read,.write=user_live_write,.ctx=c,
            .alloc_ctx=&UOWNERS(c)[e-c->user_roots.cache],
            .admit=SNAP_NATIVE_WRITER_ADMISSION ? native_writer_admit_user:0};
        if(!sptm_root_commit_detach(e,&s,va,shift,level,removed) || !user_refresh_all(c,e))return 0;
    }
    /* No kernel mapping changed. Always invalidate every guest VMID before
     * source-table lifetime references can be released. */
    user_tlb_range(c,0,0);c->user_detach_calls++;return !c->user_view_failed;
}
static int user_prepare_attach(void *ctx,uint64_t root,uint64_t va,unsigned shift,uint64_t child)
{
    struct context *c=ctx;struct sptm_root_cached *e=user_cached(c,root);
    if(!e)return 1;
    struct shadow s={.txsz=17,.root=e->shadow,.alloc=user_live_alloc,
        .read=mem_read,.write=user_live_write,.ctx=c,
        .alloc_ctx=&UOWNERS(c)[e-c->user_roots.cache],
        .admit=SNAP_NATIVE_WRITER_ADMISSION ? native_writer_admit_user:0};
    struct sptm_memory m=sptm_context_memory(c);
    return sptm_root_prepare_attach(e,&s,&m,va,shift,child);
}
static int user_commit_attach(void *ctx,uint64_t root,uint64_t va,unsigned shift,uint64_t child)
{
    struct context *c=ctx;struct sptm_root_cached *e=user_cached(c,root);
    struct sptm_memory m=sptm_context_memory(c);
    if(e) {
        struct shadow s={.txsz=17,.root=e->shadow,.alloc=user_live_alloc,
            .read=mem_read,.write=user_live_write,.ctx=c,
            .alloc_ctx=&UOWNERS(c)[e-c->user_roots.cache],
            .admit=SNAP_NATIVE_WRITER_ADMISSION ? native_writer_admit_user:0};
        if(!sptm_root_commit_attach(e,&s,&m,va,shift,child) || !user_refresh_all(c,e))return 0;
    }
    volatile uint8_t *meta=m.map(m.ctx,m.frame_map_pa+((child-m.frame_low)>>14)*16,16);
    if(!meta)return 0;
    uint64_t leaves=meta[8]|((uint64_t)meta[9]<<8);
    if(!user_commit_tlb_range(c,2,0,0))return 0;
    if(leaves){c->user_comm_attach_calls++;c->user_comm_attach_leaves+=leaves;}
    return 1;
}
static int user_prepare_nest(void *ctx,uint64_t root,uint64_t shared,uint64_t va,
                             unsigned shift,uint64_t pages)
{
    struct context *c=ctx;struct sptm_root_cached *e=user_cached(c,root);
    if(!e)return 1;
    struct shadow s={.txsz=17,.root=e->shadow,.alloc=user_live_alloc,
        .read=mem_read,.write=user_live_write,.ctx=c,
        .alloc_ctx=&UOWNERS(c)[e-c->user_roots.cache],
        .admit=SNAP_NATIVE_WRITER_ADMISSION ? native_writer_admit_user:0};
    struct sptm_memory m=sptm_context_memory(c);
#if SNAP_NATIVE_SHARED
    if(!e->format && shift==14) {
        struct native_links nl={c,&s,(unsigned)(e-c->user_roots.cache),shared};
        struct sptm_root_links links=native_links_for(&nl);
        return sptm_root_prepare_nest_linked(e,&s,&m,shared,va,shift,pages,&links);
    }
#endif
    return sptm_root_prepare_nest(e,&s,&m,shared,va,shift,pages);
}
static int user_commit_nest(void *ctx,uint64_t root,uint64_t shared,uint64_t va,
                            unsigned shift,uint64_t pages)
{
    struct context *c=ctx;struct sptm_root_cached *e=user_cached(c,root);
    if(e) {
        struct shadow s={.txsz=17,.root=e->shadow,.alloc=user_live_alloc,
            .read=mem_read,.write=user_live_write,.ctx=c,
            .alloc_ctx=&UOWNERS(c)[e-c->user_roots.cache],
            .admit=SNAP_NATIVE_WRITER_ADMISSION ? native_writer_admit_user:0};
        struct sptm_memory m=sptm_context_memory(c);
#if SNAP_NATIVE_SHARED
        if(!e->format && shift==14) {
            /* Prepare made every table; commit links only. */
            s.alloc=native_no_alloc;
            struct native_links nl={c,&s,(unsigned)(e-c->user_roots.cache),shared};
            struct sptm_root_links links=native_links_for(&nl);
            if(!sptm_root_commit_nest_linked(e,&s,&m,shared,va,shift,pages,&links) ||
               !user_refresh_all(c,e))return 0;
        } else
#endif
        if(!sptm_root_commit_nest(e,&s,&m,shared,va,shift,pages) || !user_refresh_all(c,e))return 0;
    }
    if(!user_commit_tlb_range(c,3,va,pages<<shift))return 0;
    uint64_t span=1UL<<(2*shift-3),last=va+((pages-1)<<shift);
    struct sptm_nest_state *n=&c->nest_state;
    n->calls++;n->descriptors+=last/span-va/span+1;
    n->root=root;n->shared=shared;n->va=va;n->pages=pages;
    n->first=va&~(span-1);n->last=(last&~(span-1))+span;
    return 1;
}
static int user_prepare_unnest(void *ctx,uint64_t root,uint64_t shared,unsigned shift,
                               const struct sptm_unnest_plan *plan)
{
    struct context *c=ctx;struct sptm_root_cached *e=user_cached(c,root);
    if(!e)return 1;
    struct shadow s=user_shadow(c,e);struct sptm_memory m=sptm_context_memory(c);
#if SNAP_NATIVE_SHARED
    if(!e->format && shift==14) {
        struct native_links nl={c,&s,(unsigned)(e-c->user_roots.cache),shared};
        struct sptm_root_links links=native_links_for(&nl);
        return sptm_root_prepare_unnest_linked(e,&s,&m,shared,shift,plan,&links);
    }
#endif
    return sptm_root_prepare_unnest(e,&s,&m,shared,shift,plan);
}
static int user_commit_unnest(void *ctx,uint64_t root,uint64_t shared,unsigned shift,
                              const struct sptm_unnest_plan *plan)
{
    struct context *c=ctx;struct sptm_root_cached *e=user_cached(c,root);
    if(e) {
        struct shadow s=user_shadow(c,e);struct sptm_memory m=sptm_context_memory(c);
#if SNAP_NATIVE_SHARED
        if(!e->format && shift==14) {
            /* The cleared links are in memory before the invalidation below. */
            s.alloc=native_no_alloc;s.read=mem_read;s.write=user_live_write;
            struct native_links nl={c,&s,(unsigned)(e-c->user_roots.cache),shared};
            struct sptm_root_links links=native_links_for(&nl);
            if(!sptm_root_commit_unnest_linked(e,&s,&m,shared,shift,plan,&links) ||
               !user_refresh_all(c,e))return 0;
        } else
#endif
        if(!sptm_root_commit_unnest(e,&s,&m,shared,shift,plan) || !user_refresh_all(c,e))return 0;
    }
    user_tlb_range(c,0,0);
    if(c->user_view_failed)return 0;
    c->unnest_calls++;c->unnest_descriptors+=plan->descriptors;c->unnest_leaves+=plan->leaves;
    c->unnest_root=root;c->unnest_shared=shared;c->unnest_format=shift==12;
    volatile uint64_t *dst=(volatile uint64_t *)&c->unnest_plan;
    const uint64_t *src=(const uint64_t *)plan;
    for(unsigned i=0;i<sizeof(*plan)/8;i++)dst[i]=src[i];
    return 1;
}
static int user_shared_mask(struct context *c,uint64_t root,uint64_t va,unsigned shift,
                            sptm_root_mask_t *mask)
{
    for(unsigned cpu=0;cpu<GUEST_CPU_COUNT;cpu++)
        if(!sptm_root_recorded_matches(&c->user_roots,cpu,
            c->vcpus[cpu].guest_ttbr0,c->params->ttbr1_root))return 0;
    struct sptm_memory m=sptm_context_memory(c);
#if SNAP_USER_HW_WALK
    return sptm_root_shared_aliases_hw(&m,&c->user_roots,root,va,shift,mask,hw_walk_recorded,c->hw_walk);
#else
    return sptm_root_shared_aliases(&m,&c->user_roots,root,va,shift,mask);
#endif
}
static int user_prepare_shared_leaf(void *ctx,uint64_t root,uint64_t va,unsigned shift,
                                    uint64_t old,uint64_t next)
{
    struct context *c=ctx;sptm_root_mask_t mask;
    if(!user_shared_mask(c,root,va,shift,&mask))return 0;
#if SNAP_NATIVE_SHARED
    if(shift==14) {
        /* Every aliasing root links the group: one write, no per-root work. */
        if(!native_shared_storable(next) || !native_shared_prepare(c,root,va,shift,1,mask,next))return 0;
        ROOT_PLAN_SET(c,mask);c->shared_plan_root=root;c->shared_plan_va=va;c->shared_plan_count=1;
        return 1;
    }
#endif
    for(unsigned i=0;i<SPTM_ROOT_CACHE;i++)if(SPTM_ROOT_MASK_HAS(mask,i)) {
        uint64_t user=c->user_roots.cache[i].root;
        if(!user_prepare_unmap(c,user,va,shift,1) ||
           (!old && !user_prepare_leaf(c,user,va,shift,next)))return 0;
    }
    ROOT_PLAN_SET(c,mask);c->shared_plan_root=root;c->shared_plan_va=va;c->shared_plan_count=1;
    return 1;
}
static int user_commit_shared_leaf(void *ctx,uint64_t root,uint64_t va,unsigned shift,
                                   uint64_t old,uint64_t next)
{
    struct context *c=ctx;sptm_root_mask_t mask;
    if(!user_shared_mask(c,root,va,shift,&mask) || SPTM_ROOT_MASK_NE(mask,ROOT_PLAN_MASK(c)) ||
       root!=c->shared_plan_root || va!=c->shared_plan_va || c->shared_plan_count!=1)return 0;
#if SNAP_NATIVE_SHARED
    if(shift==14) {
        if(!native_shared_commit(c,root,va,shift,1,0,next))return 0;
        uint64_t aliases=0;
        for(unsigned i=0;i<SPTM_ROOT_CACHE;i++)if(SPTM_ROOT_MASK_HAS(mask,i)) {
            c->user_roots.cache[i].leaves+=!old;aliases++;
        }
        user_tlb_range(c,va,UINT64_C(1)<<shift);
        c->shared_map_calls++;c->shared_map_inserts+=!old;c->shared_map_updates+=!!old;
        c->shared_map_aliases+=aliases;c->shared_map_root=root;c->shared_map_va=va;
        c->shared_map_old=old;c->shared_map_next=next;c->shared_map_shift=shift;c->shared_map_mask=SPTM_ROOT_MASK_LOW(mask);
        return !c->user_view_failed;
    }
#endif
    struct sptm_memory m=sptm_context_memory(c);uint64_t aliases=0;
    for(unsigned i=0;i<SPTM_ROOT_CACHE;i++)if(SPTM_ROOT_MASK_HAS(mask,i)) {
        struct sptm_root_cached *e=&c->user_roots.cache[i];struct shadow s=user_shadow(c,e);
        if(!(old ? sptm_root_commit_update(e,&s,&m,va,shift,old,next) :
                   sptm_root_commit_leaf(e,&s,&m,va,shift,next)) || !user_refresh_all(c,e))return 0;
        aliases++;
    }
    user_tlb_range(c,va,UINT64_C(1)<<shift);
    c->shared_map_calls++;c->shared_map_inserts+=!old;c->shared_map_updates+=!!old;
    c->shared_map_aliases+=aliases;c->shared_map_root=root;c->shared_map_va=va;
    c->shared_map_old=old;c->shared_map_next=next;c->shared_map_shift=shift;c->shared_map_mask=SPTM_ROOT_MASK_LOW(mask);
    return !c->user_view_failed;
}
static int user_prepare_shared_unmap(void *ctx,uint64_t root,uint64_t va,unsigned shift,uint64_t count)
{
    struct context *c=ctx;sptm_root_mask_t mask;
    if(!user_shared_mask(c,root,va,shift,&mask))return 0;
#if SNAP_NATIVE_SHARED
    if(shift==14) {
        if(!native_shared_prepare(c,root,va,shift,count,mask,0))return 0;
        ROOT_PLAN_SET(c,mask);c->shared_plan_root=root;c->shared_plan_va=va;c->shared_plan_count=count;
        return 1;
    }
#endif
    for(unsigned i=0;i<SPTM_ROOT_CACHE;i++)if(SPTM_ROOT_MASK_HAS(mask,i))
        if(!user_prepare_unmap(c,c->user_roots.cache[i].root,va,shift,count))return 0;
    ROOT_PLAN_SET(c,mask);c->shared_plan_root=root;c->shared_plan_va=va;c->shared_plan_count=count;
    return 1;
}
static int user_commit_shared_unmap(void *ctx,uint64_t root,uint64_t va,unsigned shift,
                                    uint64_t count,uint64_t removed)
{
    struct context *c=ctx;sptm_root_mask_t mask;
    if(!user_shared_mask(c,root,va,shift,&mask) || SPTM_ROOT_MASK_NE(mask,ROOT_PLAN_MASK(c)) ||
       root!=c->shared_plan_root || va!=c->shared_plan_va || count!=c->shared_plan_count)return 0;
#if SNAP_NATIVE_SHARED
    if(shift==14) {
        if(!native_shared_commit(c,root,va,shift,count,0,0))return 0;
        for(unsigned i=0;i<SPTM_ROOT_CACHE;i++)if(SPTM_ROOT_MASK_HAS(mask,i)) {
            struct sptm_root_cached *e=&c->user_roots.cache[i];
            if(e->leaves<removed)return 0;
            e->leaves-=removed;
        }
    } else
#endif
    for(unsigned i=0;i<SPTM_ROOT_CACHE;i++)if(SPTM_ROOT_MASK_HAS(mask,i)) {
        struct sptm_root_cached *e=&c->user_roots.cache[i];struct shadow s=user_shadow(c,e);
        if(!sptm_root_commit_unmap(e,&s,va,shift,count,removed) || !user_refresh_all(c,e))return 0;
    }
    user_tlb_range(c,va,count<<shift);c->shared_unmap_calls++;c->shared_unmap_pages+=removed;
    return !c->user_view_failed;
}
static int user_commit_shared_update(void *ctx,uint64_t root,uint64_t va,unsigned shift,
                                     uint64_t count,const struct sptm_shared_update_entry *entries)
{
    struct context *c=ctx;sptm_root_mask_t mask;
    if(!user_shared_mask(c,root,va,shift,&mask) || SPTM_ROOT_MASK_NE(mask,ROOT_PLAN_MASK(c)) ||
       root!=c->shared_plan_root || va!=c->shared_plan_va || count!=c->shared_plan_count)return 0;
#if SNAP_NATIVE_SHARED
    if(shift==14) {
        if(!native_shared_commit(c,root,va,shift,count,entries,0))return 0;
        user_tlb_range(c,va,count<<shift);return !c->user_view_failed;
    }
#endif
    struct sptm_memory m=sptm_context_memory(c);
    for(unsigned i=0;i<SPTM_ROOT_CACHE;i++)if(SPTM_ROOT_MASK_HAS(mask,i)) {
        struct sptm_root_cached *e=&c->user_roots.cache[i];struct shadow s=user_shadow(c,e);
        for(uint64_t n=0;n<count;n++)if(entries[n].old!=entries[n].next)
            if(!sptm_root_commit_update(e,&s,&m,va+(n<<shift),shift,entries[n].old,entries[n].next))return 0;
        if(!user_refresh_all(c,e))return 0;
    }
    user_tlb_range(c,va,count<<shift);return !c->user_view_failed;
}
/* XNU's phystokv is linear except for frames SLIDE_REGION moved; every PTE
 * pointer returned to XNU goes through both (see sptm.h). */
static struct sptm_aperture xnu_aperture(const struct context *c)
{
    const struct params *p=c->params;
    return (struct sptm_aperture){p->mem_low,p->ram_aperture_va,p->alloc_high-p->mem_low};
}
static struct sptm_moved xnu_moved(const struct context *c)
{
    return sptm_slide_moved(&c->slide,&c->params->slide);
}
static int user_backend(struct context *c,uint64_t root,struct sptm_user_backend *b)
{
    b->ttbr0=vcpu_of(c)->guest_ttbr0;b->ttbr1=vcpu_of(c)->guest_ttbr1;
    b->aperture=xnu_aperture(c);b->moved=xnu_moved(c);
    b->active_refs=0;b->mirror=0;b->prepare_leaf=user_prepare_leaf;b->commit_leaf=user_commit_leaf;b->ctx=c;
    b->prepare_unmap=user_prepare_unmap;b->commit_unmap=user_commit_unmap;
    b->prepare_detach=user_prepare_detach;b->commit_detach=user_commit_detach;
    b->shared_detaches=&c->shared_detaches;
    b->prepare_attach=user_prepare_attach;b->commit_attach=user_commit_attach;
    b->prepare_nest=user_prepare_nest;b->commit_nest=user_commit_nest;
    b->prepare_unnest=user_prepare_unnest;b->commit_unnest=user_commit_unnest;
    b->prepare_update=user_prepare_update;b->commit_update=user_commit_update;
    b->prepare_shared_leaf=user_prepare_shared_leaf;b->commit_shared_leaf=user_commit_shared_leaf;
    b->prepare_shared_unmap=user_prepare_shared_unmap;b->commit_shared_unmap=user_commit_shared_unmap;
    b->prepare_shared_update=user_prepare_shared_unmap;b->commit_shared_update=user_commit_shared_update;
    for(unsigned cpu=0;cpu<GUEST_CPU_COUNT;cpu++) {
        int active=c->user_roots.active[cpu]==root;
        int recorded=(c->vcpus[cpu].guest_ttbr0&0x0000ffffffffc000UL)==root;
        if(active!=recorded || (c->vcpus[cpu].guest_ttbr1&0x0000ffffffffc000UL)==root)return 0;
        b->active_refs+=active;
    }
#if SNAP_USER_HW_WALK
    /* A hardware-walk root: its own events, for an inactive root too (stale
     * TLB entries under its ASIDs, and copies the next install walks).
     * Shared-root calls keep the cached-alias callbacks above. */
    if(hw_root(c,root)) {
        b->prepare_leaf=hw_prepare_leaf;b->commit_leaf=hw_commit_leaf;
        b->prepare_unmap=hw_prepare_unmap;b->commit_unmap=hw_commit_unmap;
        b->prepare_detach=hw_prepare_detach;b->commit_detach=hw_commit_detach;
        b->prepare_attach=hw_prepare_attach;b->commit_attach=hw_commit_attach;
        b->prepare_nest=hw_prepare_nest;b->commit_nest=hw_commit_nest;
        b->prepare_unnest=hw_prepare_unnest;b->commit_unnest=hw_commit_unnest;
        b->prepare_update=hw_prepare_update;   /* commit: user_commit_update's hw prelude */
        b->mirror=!b->active_refs;
        return 1;
    }
#endif
    return !b->active_refs || user_cached(c,root)!=0;
}
static int user_update_backend(void *ctx,uint64_t root,struct sptm_user_backend *b)
{return user_backend(ctx,root,b);}
/* One UPDATE_DISJOINT engine call (Apple ...270fdc44): endpoint 6 and each
 * endpoint 0x15 group. A frame can have both user and kernel aliases; every
 * record must preflight before either domain publishes any changes. */
struct mixed_kernel_context {
    const struct sptm_memory *memory;
    const struct sptm_update_backend *backend;
};
static enum sptm_result mixed_kernel_prepare(void *ctx,uint64_t target,uint64_t va,
    uint64_t requested,uint64_t options,uint64_t scratch,uint64_t bytes,
    struct sptm_update_entry *entry)
{
    const struct mixed_kernel_context *k=ctx;
    return sptm_kernel_update_prepare(k->memory,k->backend,target,va,requested,
                                      options,scratch,bytes,entry);
}
static void mixed_kernel_commit(void *ctx,struct sptm_update_entry *entry)
{
    const struct mixed_kernel_context *k=ctx;sptm_kernel_update_commit(k->memory,entry);
}
/* Linked-AuxKC observation (compat/auxkc-observe.h): count, log the first
 * few execute transitions, never refuse. */
static void auxkc_note_leaf(struct context *c,unsigned kind,uint64_t elr,
                            uint64_t va,uint64_t old,uint64_t next)
{
    if(auxkc_observe_leaf(&c->auxkc_exec,&c->params->auxkc,kind,elr,va,old,next))
        record(c,EV_AUXKC_EXEC,elr,va,old,next);
}

static int update_disjoint_call(struct context *c,uint64_t target,uint64_t list,
    uint64_t count,uint64_t options,uint64_t scratch,uint64_t elr,uint64_t *out)
{
    const struct params *p=c->params;
    struct sptm_memory memory=sptm_context_memory(c);
    struct sptm_update_backend backend={.kernel_root=p->ttbr1_root,
        .shadow_root=vcpu_of(c)->shadow_root,.map_shadow=sptm_shadow_map,.ctx=c,
        .admit=SNAP_NATIVE_WRITER_ADMISSION ? native_writer_admit_high:0};
    enum sptm_result result=SPTM_BAD_CONFIG;
    uint64_t response=SPTM_SUCCESS;
    volatile uint8_t *records=count && count<=64 && !(list&7) && list<=UINT64_MAX-count*24 ?
        memory.map(memory.ctx,list,count*24):0;
    int user=0,kernel=0;
    if(records)for(uint64_t n=0;n<count;n++) {
        if(((volatile uint64_t *)records)[n*3]==p->ttbr1_root)kernel=1;
        else user=1;
    }
    if(kernel)kernel_class_proof_forget(c);
    c->attr_updates.pending=0;
    if(user && kernel && ((p->tcr>>16)&63)==17) {
        struct mixed_kernel_context kctx={&memory,&backend};
        struct sptm_mixed_kernel_backend k={.root=p->ttbr1_root,
            .workspace=&c->update_workspace,.ctx=&kctx,
            .prepare=mixed_kernel_prepare,.commit=mixed_kernel_commit};
        result=sptm_mac_update_mixed_disjoint(&memory,user_update_backend,c,&k,
            target,list,count,options,scratch,&response,
            &c->user_updates[vcpu_of(c)->slot]);
    } else if(user && !kernel)
        result=sptm_mac_update_user_disjoint(&memory,user_update_backend,c,
            target,list,count,options,scratch,&response,
            &c->user_updates[vcpu_of(c)->slot]);
    else if (((p->tcr>>16)&63)==17) {
        kernel_class_proof_forget(c);
        result=sptm_mac_update_disjoint(&memory,&backend,&c->update_workspace,
            target,list,count,options,scratch);
    }
    if (result!=SPTM_OK) {
        record(c,EV_UPDATE_FAILED,elr,result,target,options);
        return 0;
    }
    if(!user) {
        response=sptm_update_result(&c->update_workspace,count,options);
        struct sptm_user_update_state *s=&c->kernel_updates[vcpu_of(c)->slot];
        struct sptm_update_entry *e=&c->update_workspace.entries[0];
        s->calls++;s->entries+=count;
        for(uint64_t n=0;n<count;n++) {
            s->changed+=c->update_workspace.entries[n].old!=c->update_workspace.entries[n].next;
            if(p->auxkc.va_end)
                auxkc_note_leaf(c,AUXKC_KIND_UPDATE,elr,((volatile uint64_t *)records)[3*n+1],
                    c->update_workspace.entries[n].old,c->update_workspace.entries[n].next);
        }
        s->options=options;s->result=response;s->target=target;s->count=count;
        s->root=p->ttbr1_root;s->va=((volatile uint64_t *)records)[1];
        s->requested=((volatile uint64_t *)records)[2];
        s->slot=e->slot_pa;s->old=e->old;s->next=e->next;s->shift=14;s->flags=0;
        s->last_changed=e->old!=e->next;
    }
    if(user && kernel && p->auxkc.va_end)for(uint64_t n=0;n<count;n++)
        if(((volatile uint64_t *)records)[3*n]==p->ttbr1_root)
            auxkc_note_leaf(c,AUXKC_KIND_UPDATE,elr,((volatile uint64_t *)records)[3*n+1],
                c->update_workspace.entries[n].old,c->update_workspace.entries[n].next);
    if(!transaction_publish(c)) {
        record(c,EV_UPDATE_FAILED,elr,SPTM_SHADOW_FAILED,target,options);return 0;
    }
#if SNAP_USER_UPDATE_KERNEL_SKIP
    if(user && !kernel)user_update_kernel_skip(c);
    else
#endif
    shadow_tlb_sync(c);
    attr_clean_finish(c);
    c->update_calls++; c->update_entries+=count;
    *out=response;
    if(user) {
        volatile uint64_t *rec=(volatile uint64_t *)records;
        volatile uint64_t *old=(volatile uint64_t *)memory.map(memory.ctx,scratch,count*8);
        for(uint64_t n=0;n<count;n++) {
            uint64_t root=rec[3*n];
            if(root==p->ttbr1_root || (root&0x3fff) || root<memory.frame_low || root>=memory.frame_high)continue;
            volatile uint8_t *meta=memory.map(memory.ctx,
                memory.frame_map_pa+((root-memory.frame_low)>>14)*16,16);
            if(!meta || meta[2]!=SPTM_MAC_SHARED_ROOT_TABLE)continue;
            unsigned slot=vcpu_of(c)->slot;
            struct sptm_user_update_state *s=&c->shared_disjoint[slot];
            c->shared_disjoint_records[slot]++;
            s->calls++;s->entries+=count;s->options=options;s->result=response;s->target=target;
            s->count=count;s->root=root;s->va=rec[3*n+1];s->requested=rec[3*n+2];
            s->old=old ? old[n]:0;s->slot=elr;
        }
    }
    return 1;
}

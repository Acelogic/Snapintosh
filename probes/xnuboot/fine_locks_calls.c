/* SPDX-License-Identifier: MIT */
/* SNAP_FINE_LOCKS, second block: the converted map, unmap, update,
 * retype, kernel and switch endpoints.
 * Part of probes/xnuboot.c's translation unit, included in order; not compiled on its own. */
#if SNAP_FINE_LOCKS
/* ---- the converted endpoints ------------------------------------------
 * Each returns FINE_DONE with frame[0] set, FINE_DECLINE with nothing
 * changed (*reason says why), or FINE_FATAL after a commit failure (stores
 * were made: terminal, reported under the token as the locked path does). */
enum {FINE_DECLINE,FINE_DONE,FINE_FATAL};
struct fine_call_state {
    uint64_t x16,a0,a1,a2,a3,elr;   /* arguments, and the guest ELR the call reports */
    unsigned kind,reason;
    uint64_t fail_kind,fail_a,fail_b;  /* the locked path's failure record */
    enum sptm_result result;
#if SNAP_TOKEN_TRIM || SNAP_DART_CONVERTED
    uint64_t fail_value;               /* with fail_raw: the record's a, in place of result */
    int fail_raw;
#endif
#if SNAP_SPTM_FINE_KERNEL
    uint64_t aux_va,aux_old,aux_new;   /* a converted kernel MAP_PAGE's auxkc_note_leaf, made under aux */
    int aux_note;
#endif
};
static int fine_engine_end(struct context *c,struct fine_call_state *s,enum sptm_result r,
                           uint64_t kind,uint64_t a,uint64_t b)
{
    struct fine_cpu *f=fine_cpu(c);
    if(r==SPTM_OK)return FINE_DONE;
    s->result=r;s->fail_kind=kind;s->fail_a=a;s->fail_b=b;
    if(!f->stores) {s->reason=f->alloc_refused ? FINE_NO_ALLOC : FINE_NO_ENGINE;return FINE_DECLINE;}
    return FINE_FATAL;
}
/* MAP_PAGE's user branch (monitor_call_impl case SPTM_FN_MAP_PAGE). */
static int fine_map_page(struct context *c,uint64_t *frame,uint64_t scratch,struct fine_call_state *s)
{
    uint64_t root_pa=frame[0],va=frame[1],new_pte=frame[2];
    struct sptm_memory memory=fine_memory(c);
    struct sptm_user_backend backend={0};
    uint64_t result=0;
    if(!fine_user_backend(c,root_pa,&backend)) {s->reason=FINE_NO_ROOT;return FINE_DECLINE;}
    /* A cached root no CPU runs: inactive_map_keep's mirror/invalidation
     * decision rewrites the cache, a token-path structure. */
    if(!backend.active_refs && user_cached(c,root_pa)) {s->reason=FINE_NO_INACTIVE;return FINE_DECLINE;}
    if((new_pte&1) && sprr_pte_class(new_pte)==9) {s->reason=FINE_NO_SHAPE;return FINE_DECLINE;}
    backend.map_updates=&c->user_map_replacements[vcpu_of(c)->slot];
    enum sptm_result r=sptm_mac_map_user_page(&memory,&backend,root_pa,va,new_pte,frame[3],scratch,&result);
    if(r==SPTM_TABLE_MISSING && !fine_cpu(c)->stores) {
        fine_add(&c->user_missing_tables,1);frame[0]=7;return FINE_DONE;
    }
    int end=fine_engine_end(c,s,r,EV_REFERENCE_FAILED,va,new_pte);
    if(end!=FINE_DONE)return end;
    if(result==SPTM_USER_MAP_CONFLICT) {
        struct user_map_conflict_state *w=&c->user_map_conflict[vcpu_of(c)->slot];
        w->count++;w->root=root_pa;w->va=va;w->wanted=new_pte;
        w->options=frame[3];w->old=w->pointer=0;w->result=result;
        if(!(frame[3]&1) && (mem_read(c,scratch,&w->old) || mem_read(c,scratch+8,&w->pointer)))
            w->old=w->pointer=0;
    }
    /* Otherwise an inactive root here is uncached: inactive_map_keep(c,0,..)
     * is 0 and sptm_root_invalidate finds no entry, so nothing changes. */
    fine_add(&c->map_pages,1);frame[0]=result;return FINE_DONE;
}
/* UNMAP_REGION's user branch. */
static int fine_unmap_region(struct context *c,uint64_t *frame,uint64_t scratch,struct fine_call_state *s)
{
    struct sptm_memory memory=fine_memory(c);
    struct sptm_user_backend user={0};
    if(!fine_user_backend(c,frame[0],&user)) {s->reason=FINE_NO_ROOT;return FINE_DECLINE;}
    enum sptm_result r=sptm_mac_unmap_user_region(&memory,&user,frame[0],frame[1],
                                                 frame[2],frame[3],scratch);
    int end=fine_engine_end(c,s,r,EV_UNMAP_FAILED,frame[1],frame[2]);
    if(end!=FINE_DONE)return end;
    frame[0]=SPTM_SUCCESS;return FINE_DONE;
}
/* UPDATE_DISJOINT with user records only (update_disjoint_call's
 * sptm_mac_update_user_disjoint branch). transaction_publish is not run:
 * every store this call made was published at the store. The 1-in-1024
 * kernel-view verification of user_update_kernel_skip stays on the token
 * path (no kernel view can change while the gate is shared); the skip is
 * counted. attr_updates.pending is zero between token transactions. */
static int fine_update_disjoint(struct context *c,uint64_t *frame,uint64_t scratch,struct fine_call_state *s)
{
    const struct params *p=c->params;
    struct sptm_memory memory=fine_memory(c);
    uint64_t target=frame[0],list=frame[1],count=frame[2],options=frame[3],response=SPTM_SUCCESS;
    unsigned type=fine_frame_type(c,target);
    if((options&(UINT64_C(0x10)|UINT64_C(0x20))) || (type!=SPTM_MAC_DEFAULT && type!=SPTM_MAC_USER_EXEC)) {
        s->reason=FINE_NO_SHAPE;return FINE_DECLINE;
    }
    enum sptm_result r=sptm_mac_update_user_disjoint(&memory,fine_update_backend,c,
        target,list,count,options,scratch,&response,&c->user_updates[vcpu_of(c)->slot]);
    int end=fine_engine_end(c,s,r,EV_UPDATE_FAILED,target,options);
    if(end!=FINE_DONE)return end;
    (void)p;
    fine_add(&c->user_update_skip.skipped,1);
    fine_add(&c->update_calls,1);fine_add(&c->update_entries,count);
    frame[0]=response;return FINE_DONE;
}
#if SNAP_SPTM_FINE
/* ---- SNAP_SPTM_FINE (agents/sptm-locks/FAILURE-MODES.md) -------------------
 * UNMAP_DISJOINT with user records only: case SPTM_FN_UNMAP_DISJOINT's branch
 * for a list with no kernel record (sptm_mac_unmap_user_disjoint and nothing
 * else: each removed leaf's commit_unmap completed its TLBI in every VMID
 * before the references drop). fine_lockset_for admitted every record's root
 * and holds its stripe; the backend refuses any other root. */
static int fine_unmap_disjoint(struct context *c,uint64_t *frame,uint64_t scratch,struct fine_call_state *s)
{
    struct sptm_memory memory=fine_memory(c);
    uint64_t count=(uint32_t)frame[2];
    enum sptm_result r=sptm_mac_unmap_user_disjoint(&memory,fine_update_backend,c,
        frame[0],frame[1],count,scratch,&c->user_disjoint_unmaps[vcpu_of(c)->slot]);
    int end=fine_engine_end(c,s,r,EV_UNMAP_FAILED,frame[0],frame[2]);
    if(end!=FINE_DONE)return end;
    frame[0]=SPTM_SUCCESS;return FINE_DONE;
}
/* UPDATE_REGION on a user root that is not a shared root: case
 * SPTM_FN_UPDATE_REGION's sptm_mac_update_user_region branch. No clean_frame
 * (fine_memory): a leaf whose SH/AttrIndx would change is refused in preflight
 * (SPTM_UNSUPPORTED_OPTIONS before any store), so attr_updates stays empty and
 * the token path's attr_clean_finish has nothing to do. */
static int fine_update_region(struct context *c,uint64_t *frame,uint64_t scratch,struct fine_call_state *s)
{
    struct sptm_memory memory=fine_memory(c);
    struct sptm_user_backend user={0};uint64_t result=0;
    if(!fine_user_backend(c,frame[0],&user)) {s->reason=FINE_NO_ROOT;return FINE_DECLINE;}
    enum sptm_result r=sptm_mac_update_user_region(&memory,&user,frame[0],frame[1],frame[2],
        frame[3],frame[4],scratch,&result,&c->user_regions[vcpu_of(c)->slot]);
    int end=fine_engine_end(c,s,r,EV_REGION_FAILED,frame[1],frame[4]);
    if(end!=FINE_DONE)return end;
    frame[0]=result;return FINE_DONE;
}
#endif
#if SNAP_SPTM_FINE_RETYPE
/* RETYPE for the page-table frame lifecycle (11->20, 20->11) and the data
 * reset (11->11): case SPTM_FN_RETYPE with none of its host callbacks, which
 * these transitions never call (no root, IOMMU, exec, TPRO, TXM, ROZONE or
 * shared transition; sptm_mac_retype's own guards keep it that way). The frame
 * is held exclusive (compat/sptm-frame-lock.h): no converted call holds a
 * reference touch, an input frame or a retype on it, and none can start one
 * until this call has published the new record. Every refusal of
 * sptm_mac_retype precedes its first store: a decline, and the token path
 * repeats and reports it (EV_RETYPE_FAILED). An AuxKC-range frame stays on the
 * token path (auxkc_observe_retype counts it there). sptm_root_memo_retype is
 * a read-only no-op here (the record's counts are zero, checked before, and
 * held still by the lock); the root index notes nothing (no root key). */
#if SNAP_USER_HW_WALK_S2RO
/* hw_s2_frame for a converted RETYPE: the same leaf-only S2AP change of the
 * frame's four pages in every vCPU's tree (pre-split at setup: nothing is
 * allocated; distinct frames are distinct words, so two converted retypes
 * never write one word), stored through fine_mem_write and cleaned at the
 * store, counters added atomically, then the same stage-2-by-IPA and aperture
 * invalidation in every VMID (this CPU's VTTBR, restored). */
static int fine_hw_s2_write(void *ctx,uint64_t pa,uint64_t value)
{return fine_user_live_write(ctx,pa,value);}     /* hw_s2_write: fine_mem_write, then publish */
static int fine_hw_s2_frame(struct context *c,uint64_t frame,int ro)
{
    struct shadow trees[HW_S2_TREES];
    for(unsigned cpu=0;cpu<GUEST_CPU_COUNT;cpu++)
        trees[cpu]=(struct shadow){.txsz=S2_TXSZ,.root=c->vcpus[cpu].stage2_root,.alloc=fine_hw_refuse_alloc,
                                   .read=mem_read,.write=fine_hw_s2_write,.ctx=c};
    if(hw_s2_set(trees,GUEST_CPU_COUNT,frame,ro)<0) {fine_add(&c->hw_walk->stats.s2_failures,1);return 0;}
    if(ro)fine_add(&c->hw_walk->stats.s2_protects,1);else fine_add(&c->hw_walk->stats.s2_unprotects,1);
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
    fine_add(&c->shadow_tlb_syncs,1);
    return 1;
}
#endif
static int fine_retype(struct context *c,uint64_t *frame,struct fine_call_state *s)
{
    const struct params *p=c->params;
    uint64_t pa=frame[0],old=frame[1],next=frame[2],options=frame[3];
    if(!((old==SPTM_MAC_DEFAULT && (next==SPTM_MAC_PAGE_TABLE || next==SPTM_MAC_DEFAULT)) ||
         (old==SPTM_MAC_PAGE_TABLE && next==SPTM_MAC_DEFAULT)) ||
       (p->auxkc.pa_end && pa>=p->auxkc.pa_base && pa<p->auxkc.pa_end)) {
        s->reason=FINE_NO_SHAPE;return FINE_DECLINE;
    }
    if(!sptm_frame_exclusive(&fine_cpu(c)->frames,pa&~UINT64_C(0x3fff))) {s->reason=FINE_NO_FRAME;return FINE_DECLINE;}
    struct sptm_memory memory=fine_memory(c);
    memory.retype_user_tpro=0;
    enum sptm_result r=sptm_mac_retype(&memory,pa,old,next,options);
    int end=fine_engine_end(c,s,r,EV_RETYPE_FAILED,pa,next);
    if(end!=FINE_DONE)return end;
#if SNAP_USER_HW_WALK_S2RO
    /* As case SPTM_FN_RETYPE: a frame that became (or stopped being) a table is
     * read-only (or RW again) at stage 2 before XNU sees the result; a refusal
     * after the type store is terminal there too. */
    int s2=hw_s2_retype_action((unsigned)old,(unsigned)next);
    if(s2>=0 && !fine_hw_s2_frame(c,pa,s2)) {
        s->result=SPTM_SHADOW_FAILED;s->fail_kind=EV_RETYPE_FAILED;s->fail_a=pa;s->fail_b=next;
        return FINE_FATAL;
    }
#endif
    frame[0]=SPTM_SUCCESS;return FINE_DONE;
}
/* The input frames a converted call reads besides its references: an
 * UPDATE_DISJOINT or UNMAP_DISJOINT record list, a pointer batch's input. Held
 * shared before the first read (S3, S18); 0: one is held exclusive. */
static int fine_input_frames(struct context *c,const struct fine_call_state *s)
{
    struct sptm_frame_held *h=&fine_cpu(c)->frames;
    uint64_t input=0;
    if(s->kind==FINE_CALL_UPDATE_DISJOINT || s->kind==FINE_CALL_UNMAP_DISJOINT)input=s->a1;
#if SNAP_FAST_PAUTH_CALLS
    if(s->kind==FINE_CALL_PAUTH_BATCH)input=s->a0;
#endif
    const struct params *p=c->params;
    if(!input || input<p->frame_low || input>=p->frame_high)return 1;
    return sptm_frame_share(h,input&~UINT64_C(0x3fff));
}
#endif
#if SNAP_SPTM_FINE_KERNEL
/* ---- SNAP_SPTM_FINE_KERNEL: kernel-root MAP_PAGE and UNMAP_REGION ----------
 * compat/sptm-fine.h has the converted bodies and why no kernel_refresh is
 * needed. Here: the token path's logged refusals and reports stay there
 * (classes 2/4/9, a root outside guest RAM, a PTE outside it: map_range_note
 * and the EV_MAP_OUTSIDE/EV_MAP_DEVICE records; a missing table, a conflict, a
 * copied or unbuilt shadow path); everything else runs under KL, the one lock
 * of every converted kernel-root call (the token path takes none: the gate). */
static int fine_kernel_copied(void *ctx,uint64_t table)
{
    const struct sprr_views *v=&((struct context *)ctx)->kernel_views;
    if(v->count>SPRR_VIEW_TABLES)return 1;
    for(uint64_t n=0;n<v->count;n++)if(v->tables[n].source==table)return 1;
    return 0;
}
static void fine_kernel_tlbi(void *ctx,uint64_t va,uint64_t size){fine_native_tlbi_range(ctx,va,size);}
static void fine_kernel_clean_out(void *ctx,volatile uint64_t *out)
{
    (void)ctx;
    __asm__ volatile("dc cvau, %0\n\tdc cvau, %1\n\tdsb ish" :: "r"(&out[0]), "r"(&out[1]) : "memory");
}
/* The canonical kernel shadow MAP_PAGE and UNMAP_REGION use (vcpu_of(c)->
 * shadow_root, shared by every vCPU), with the converted allocator (refuses:
 * the path was checked) and writer (fine_mem_write, cleaned at the store). */
static struct sptm_fine_kernel fine_kernel_of(struct context *c,struct sptm_memory *m,struct shadow *s,
    struct user_table_owner *owner,struct sptm_aperture *a,struct sptm_moved *moved,uint32_t txsz)
{
    *owner=(struct user_table_owner){c,0};
    *s=(struct shadow){.txsz=txsz,.root=vcpu_of(c)->shadow_root,.alloc=fine_refuse_alloc,
        .write=fine_user_live_write,.read=mem_read,.ctx=c,.alloc_ctx=owner,
        .admit=SNAP_NATIVE_WRITER_ADMISSION ? native_writer_admit_high:0};
    *a=xnu_aperture(c);*moved=xnu_moved(c);
    return (struct sptm_fine_kernel){.m=m,.shadow=s,.guest_read=mem_read,.guest_write=fine_mem_write,
        .copied=fine_kernel_copied,.tlbi=fine_kernel_tlbi,.clean_out=fine_kernel_clean_out,.ctx=c,
        .aperture=a,.moved=moved,.t1sz=(uint32_t)((c->params->tcr>>16)&0x3f)};
}
static int fine_kernel_map(struct context *c,uint64_t *frame,uint64_t scratch,struct fine_call_state *s)
{
    const struct params *p=c->params;
    uint64_t root=frame[0],va=frame[1],new_pte=frame[2],pte_pa=new_pte&PT_OA_MASK;
    unsigned cls=sprr_pte_class(new_pte);
    if(((new_pte&1) && (cls==2 || cls==4 || cls==9)) ||
       (p->mem_low && (root<p->mem_low || root+0x4000>p->mem_high)) ||
       (p->mem_low && (new_pte&1) && (pte_pa<p->mem_low || pte_pa>=p->mem_high) &&
        !(p->fb_span && pte_pa>=p->fb_pa && pte_pa-p->fb_pa<p->fb_span))) {
        s->reason=FINE_NO_SHAPE;return FINE_DECLINE;
    }
    struct sptm_memory memory=fine_memory(c);
    struct shadow shadow;struct user_table_owner owner;struct sptm_aperture aperture;struct sptm_moved moved;
    struct sptm_fine_kernel k=fine_kernel_of(c,&memory,&shadow,&owner,&aperture,&moved,
                                             (uint32_t)((p->tcr>>16)&0x3f));
    volatile uint64_t *out=scratch ? (volatile uint64_t *)scratch : 0;
    enum sptm_fine_kernel_end e=sptm_fine_kernel_map(&k,root,va,new_pte,out);
    if(e==SPTM_FINE_K_COPIED) {s->reason=FINE_NO_COPIED;return FINE_DECLINE;}
    if(e==SPTM_FINE_K_DECLINE) {s->reason=fine_cpu(c)->alloc_refused ? FINE_NO_ALLOC : FINE_NO_ENGINE;return FINE_DECLINE;}
    if(e==SPTM_FINE_K_FATAL) {
        /* map_page_failed's record, made under the token by fine_fatal. */
        s->fail_kind=EV_MAP_FAILED;s->result=(enum sptm_result)k.fail;s->fail_a=k.fail_va;s->fail_b=k.fail_detail;
        return FINE_FATAL;
    }
    if(out)fine_cpu(c)->audit.moved_pointers+=(uint64_t)k.moved_pointer;
    s->aux_note=1;s->aux_va=va;s->aux_old=k.old;s->aux_new=new_pte;
    fine_add(&c->map_pages,1);
    frame[0]=k.status;return FINE_DONE;
}
static int fine_kernel_unmap(struct context *c,uint64_t *frame,uint64_t scratch,struct fine_call_state *s)
{
    const struct params *p=c->params;
    if(((p->tcr>>16)&63)!=17) {s->reason=FINE_NO_SHAPE;return FINE_DECLINE;}
    struct sptm_memory memory=fine_memory(c);
    struct shadow shadow;struct user_table_owner owner;struct sptm_aperture aperture;struct sptm_moved moved;
    struct sptm_fine_kernel k=fine_kernel_of(c,&memory,&shadow,&owner,&aperture,&moved,17);
    enum sptm_result r=SPTM_OK;
    enum sptm_fine_kernel_end e=sptm_fine_kernel_unmap(&k,frame[0],frame[1],frame[2],frame[3],scratch,&r);
    if(e==SPTM_FINE_K_COPIED) {s->reason=FINE_NO_COPIED;return FINE_DECLINE;}
    if(e==SPTM_FINE_K_DECLINE) {
        if(r)return fine_engine_end(c,s,r,EV_UNMAP_FAILED,frame[1],frame[2]);
        s->reason=FINE_NO_SHAPE;return FINE_DECLINE;
    }
    frame[0]=SPTM_SUCCESS;return FINE_DONE;
}
#define FINE_KERNEL_CALL(kind) ((kind)==FINE_CALL_KERNEL_MAP || (kind)==FINE_CALL_KERNEL_UNMAP)
#endif
#if SNAP_FINE_SWITCH
/* ---- SNAP_FINE_SWITCH: SWITCH_ROOT cache hits (phase 1b) ----------------
 * The case SPTM_FN_SWITCH_ROOT body and user_root_install's NATIVE_TABLES
 * branch for a switch that changes no cache state (compat/sptm-root.h
 * sptm_mac_switch_root_hit). The stripes of this CPU's current root and of
 * the target are held, so no converted call on either root runs while their
 * activity, records and (for the target) view selection change, and every
 * other CPU's activity words are its own. Declined before any change: a
 * PPERM that is not the reset value (the install's kernel PPERM transaction
 * rewrites kernel copies, token-path state), a target whose variants do not
 * exist yet (the first install derives them: allocation), a sampled tree walk
 * (the memo is token-path state), and every case sptm_mac_switch_root_hit
 * declines. */
/* The owner's sampled walk, read without counting: the token path's
 * native_skip_hit counts and walks this switch if it is due. A converted
 * hit counts its skip afterwards. */
static int fine_skip_hit(void *ctx)
{
    struct context *c=ctx;
    return !!(__atomic_load_n(&c->native_stats.hit_asks,__ATOMIC_RELAXED)&
              ((UINT64_C(1)<<SNAP_NATIVE_AUDIT_SHIFT)-1));
}
static int fine_no_build(void *ctx,const struct sptm_memory *m,uint64_t root,unsigned format,
                         unsigned flags,uint64_t previous,uint64_t *result,uint64_t *leaves)
{(void)ctx;(void)m;(void)root;(void)format;(void)flags;(void)previous;(void)result;(void)leaves;return 0;}
static void fine_install_failed(struct context *c,int deferred)
{
    fine_add(&c->root_install_failures,1);
    if(deferred) {
        fine_add(&c->install_tlbi.failure_flushes,1);
        __asm__ volatile("dsb ishst; tlbi alle1is; dsb ish; isb" ::: "memory");
        fine_add(&c->shadow_tlb_syncs,1);
    }
}
/* user_install_view once the variants exist: this CPU's selection, its view
 * state and the slot's budget (the target's stripe is held). */
static uint64_t fine_user_install_view(struct context *c,uint64_t root,uint64_t canonical)
{
    unsigned cpu=(unsigned)vcpu_of(c)->slot;
    struct sptm_root_cached *e=user_cached(c,root);
    if(!e || e->shadow!=canonical)return 0;
    unsigned slot=(unsigned)(e-c->user_roots.cache);
    struct sprr_views *v=user_views(c,e);
    if(!v->count)return 0;
    UBUDGETS(c)[slot]=0;
    struct sprr_state initial={0};sprr_root_reset(&initial,(unsigned)e->flags);
    struct native_cpu *n=&c->native_cpu[cpu];
    uint64_t ttbr0[2][2];
    for(unsigned w=0;w<2;w++)for(unsigned k=0;k<2;k++)
        ttbr0[w][k]=native_views_root(v,w)|(native_asid(slot,w,0)<<48);
    if(!native_install(n,(const uint64_t (*)[2])ttbr0,0,initial.uperm,initial.pperm,0)) {
        fine_view_failed(c);return 0;
    }
    fine_add(&c->native_stats.installs,1);
    struct user_view_state *u=&c->user_view_state[cpu];
    u->root=root;u->shadow=native_views_root(v,n->w);u->el0=0;
    u->uperm=initial.uperm;u->pperm=initial.pperm;u->umprr=initial.umprr;u->syncs++;
    return u->shadow;
}
/* root_publish_flush for a converted install, under aux: every dirty page
 * this CPU's walkers can reach after the switch -- the target slot's
 * canonical and variant pages (owner slot+1), the shared groups it links and
 * every monitor and kernel page (owner 0, which includes the kernel root's
 * low shadow) -- is cleaned and its bit cleared; other roots' bits stay for
 * the next token-path flush (their converted writers clean at the store, so
 * those bits are already clean). Aux orders this against other converted
 * installs, and the dsb completes the cleaning before aux is released. The
 * 97 runtime pages are not cleaned: no walker reads them, no converted call
 * writes them, secondary_launch publishes the whole work area before CPU_ON,
 * and every token-path transaction and install still cleans them. */
static int fine_install_publish(struct context *c,unsigned owner)
{
    struct root_publish_state *s=&c->root_publish;
    fine_aux_lock(c);
    int ok=!__atomic_load_n(&s->errors,__ATOMIC_RELAXED) &&
           root_publish_geometry(c->work_base,c->next_table);
    unsigned pages=ok ? (unsigned)((c->next_table-c->work_base)/4096) : 0,dirty=0;
    for(unsigned w=0;w<(pages+63)/64;w++) {
        uint64_t bits=__atomic_load_n(&s->bitmap[w],__ATOMIC_RELAXED),mine=0;
        while(bits) {
            unsigned bit=(unsigned)__builtin_ctzll(bits),index=w*64+bit;
            unsigned who=c->table_pool.owner[index];
            bits&=bits-1;
            if(who && who!=owner && who!=NATIVE_SHARED_OWNER)continue;
            publish_page_lines(c,c->work_base+(uint64_t)index*4096);
            mine|=UINT64_C(1)<<bit;dirty++;
        }
        if(mine)__atomic_fetch_and(&s->bitmap[w],~mine,__ATOMIC_RELAXED);
    }
    __asm__ volatile("dsb ish" ::: "memory");
    if(ok) {s->calls++;s->complete++;s->considered+=pages;s->published+=dirty;s->skipped+=pages-dirty;}
    fine_aux_unlock(c);
    return ok;
}
#if SNAP_FINE_SWITCH_HW && SNAP_USER_HW_WALK
/* ---- SNAP_FINE_SWITCH_HW: SWITCH_ROOT to a hardware-walk root with a record
 * (batch8 switch FAILURES-AND-DESIGN.md S1-S14). The record, its index slot,
 * copies' addresses and identity are token-path state (attach, detach, path
 * preparation, prune): constants while the gate is shared. */
/* hw_switch_eligible without the attach: a record answers 1 or -1 exactly
 * as there; no record answers 0, the cache-hit test then declines a root
 * with no cache entry, and the token path attaches it (S3, S4). */
static int fine_hw_switch_eligible(void *ctx,const struct sptm_memory *m,uint64_t root,unsigned asid,
                                   unsigned format,unsigned flags)
{
    struct context *c=ctx;(void)m;
    if(format!=1)return 0;
    struct hw_walk_root *r=hw_root(c,root);
    if(r)return r->entry.asid==asid && r->entry.flags==flags ? 1 : -1;
    return 0;     /* no record: the token path attaches (or keeps the shadow) */
}
/* hw_install_user for a converted switch: the same native selection, view
 * state, register sequence, shared-region flush and installed-state records
 * (this CPU's words), shared counters added atomically (S6), guest_ttbr0
 * stored with release like fine_user_root_install's, and the converted
 * publication in place of root_publish_flush: every dirty page of owner 0,
 * of the native shared groups and of the copy domain this CPU's TTBR0 can
 * now reach, under aux (S7). */
static void fine_hw_install_user(struct context *c,uint64_t root,uint64_t asid,unsigned format)
{
    struct vcpu *v=vcpu_of(c);
    struct hw_walk_root *r=hw_root(c,root);
    if(!r || format!=1 || r->entry.asid!=asid) {fine_add(&c->root_install_failures,1);return;}
    unsigned flags=(unsigned)r->entry.flags;
    struct sprr_state initial={0};sprr_root_reset(&initial,flags);
    struct native_cpu *n=&c->native_cpu[v->slot];
    uint64_t ttbr0[2][2];
    for(unsigned w=0;w<2;w++)for(unsigned k=0;k<2;k++)ttbr0[w][k]=hw_walk_ttbr0(r,w);
    uint64_t ttbr=native_install(n,(const uint64_t (*)[2])ttbr0,0,initial.uperm,initial.pperm,0);
    if(!ttbr) {fine_view_failed(c);fine_add(&c->root_install_failures,1);return;}
    fine_add(&c->native_stats.installs,1);fine_add(&c->hw_walk->stats.installs,1);
    struct user_view_state *u=&c->user_view_state[v->slot];
    u->root=root;u->shadow=ttbr&PT_OA_MASK;u->el0=0;
    u->uperm=initial.uperm;u->pperm=initial.pperm;u->umprr=initial.umprr;u->syncs++;
    v->guest_tcr=SPTM_ROOT_TCR_4K|(1UL<<36);
    v->guest_sctlr=pauth_root_enables(v->guest_sctlr,flags);
    uint64_t tcr=shadow_tcr(v->guest_tcr);
    if(!fine_install_publish(c,HW_WALK_OWNER)) {
        fine_install_failed(c,0);return;
    }
    uint64_t live_tcr,live_ttbr;
    __asm__ volatile("mrs %0, tcr_el1; mrs %1, ttbr0_el1":"=r"(live_tcr),"=r"(live_ttbr));
    struct sptm_memory memory=sptm_context_memory(c);
    int region=sptm_mac_root_shared_slot(&memory,root);
    if(live_tcr==tcr) {
        int crossing=!(live_ttbr>>48)!=!(ttbr>>48);
        uint16_t incoming=region<0 ? UINT16_MAX : region==255 ? 0 : (uint16_t)(region+1);
        uint16_t last=c->user_shared_slot[v->slot];
        int shared_flush=incoming==UINT16_MAX || (last && last!=incoming);
        __asm__ volatile("dsb ish; msr ttbr0_el1, %0; isb" :: "r"(ttbr) : "memory");
        if(crossing || shared_flush) {
            __asm__ volatile("tlbi vmalle1; dsb nsh; isb" ::: "memory");
            fine_add(&c->native_stats.local_flushes,1);
            if(shared_flush)fine_add(&c->shared_switch_flushes[v->slot],1);
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
    if(actual_ttbr!=ttbr || actual_tcr!=tcr)fine_add(&c->root_install_failures,1);
    __atomic_store_n(&v->guest_ttbr0,root|(asid<<48),__ATOMIC_RELEASE);
    fine_add(&c->shadow_tlb_syncs,1);
}
#endif
/* user_root_install, NATIVE_TABLES branch, PPERM already the reset value. */
static void fine_user_root_install(void *ctx,uint64_t shadow,uint64_t guest_root,
                                   uint64_t asid,unsigned format)
{
    struct context *c=ctx;struct vcpu *v=vcpu_of(c);
#if SNAP_EL0_MEMO
    /* Before anything changes: this vCPU's EL0 fetch memo is stale. */
    el0_memo_installed(&EL0M(c)[v->slot]);
#endif
    const int defer=SNAP_INSTALL_TLBI_DEFER;int deferred=0;
    if(defer)fine_add(&c->install_tlbi.installs,1);
    fine_add(&c->native_stats.pperm_skips,1);
    deferred=defer;
    unsigned owner=0;
#if SNAP_FINE_SWITCH_HW && SNAP_USER_HW_WALK
    /* As user_root_install: a hardware-walk root comes with shadow 0, after
     * the same EL0-memo, TLBI-defer and PPERM-skip accounting. */
    if(asid && !shadow) {fine_hw_install_user(c,guest_root,asid,format);return;}
#endif
    if(asid) {
        shadow=fine_user_install_view(c,guest_root,shadow);
        if(!shadow) {fine_install_failed(c,deferred);return;}
    } else {
        struct user_view_state *u=&c->user_view_state[v->slot];
        u->root=u->shadow=u->el0=u->uperm=u->pperm=u->umprr=0;
        native_uninstall(&c->native_cpu[v->slot]);
    }
    if(asid) {
        v->guest_tcr=(format ? SPTM_ROOT_TCR_4K : SPTM_ROOT_TCR_16K)|(1UL<<36);
        struct sptm_root_cached *entry=user_cached(c,guest_root);
        if(!entry) {fine_install_failed(c,deferred);return;}
        owner=(unsigned)(entry-c->user_roots.cache)+1;
        USTAMPS(c)[entry-c->user_roots.cache]=__atomic_add_fetch(&c->arena_reclaim.clock,1,__ATOMIC_RELAXED);
        v->guest_sctlr=pauth_root_enables(v->guest_sctlr,(unsigned)entry->flags);
    }
    const struct native_cpu *nc=&c->native_cpu[v->slot];
    uint64_t ttbr=asid ? nc->ttbr0[nc->w&1][nc->k&1] : shadow;
    uint64_t tcr=shadow_tcr(v->guest_tcr);
    if(asid && (ttbr&PT_OA_MASK)!=shadow) {fine_install_failed(c,deferred);return;}
    if(!fine_install_publish(c,owner)) {fine_install_failed(c,deferred);return;}
    uint64_t live_tcr,live_ttbr;
    __asm__ volatile("mrs %0, tcr_el1; mrs %1, ttbr0_el1":"=r"(live_tcr),"=r"(live_ttbr));
    if(live_tcr==tcr) {
        int crossing=!(live_ttbr>>48)!=!(ttbr>>48);
        int shared_flush=0;
        if(asid) {
            struct sptm_memory memory=sptm_context_memory(c);
            int region=sptm_mac_root_shared_slot(&memory,guest_root);
            uint16_t incoming=region<0 ? UINT16_MAX : region==255 ? 0 : (uint16_t)(region+1);
            uint16_t last=c->user_shared_slot[v->slot];
            shared_flush=incoming==UINT16_MAX || (last && last!=incoming);
        }
        __asm__ volatile("dsb ish; msr ttbr0_el1, %0; isb" :: "r"(ttbr) : "memory");
        if(crossing || shared_flush) {
            __asm__ volatile("tlbi vmalle1; dsb nsh; isb" ::: "memory");
            fine_add(&c->native_stats.local_flushes,1);
            if(shared_flush)c->shared_switch_flushes[v->slot]++;
            c->user_shared_slot[v->slot]=0;
        }
    } else
    __asm__ volatile("dsb ish; msr tcr_el1, %2; isb; tlbi alle1is; dsb ish; "
                     "msr ttbr0_el1, %0; isb; msr tcr_el1, %1; isb"
                     :: "r"(ttbr),"r"(tcr),"r"(tcr|(1UL<<7)):"memory");
    uint64_t actual_ttbr,actual_tcr;
    __asm__ volatile("mrs %0, ttbr0_el1; mrs %1, tcr_el1"
                     :"=r"(actual_ttbr),"=r"(actual_tcr));
    c->root_installed[v->slot][0]=actual_ttbr;
    c->root_installed[v->slot][1]=actual_tcr;
    if(asid) {
        struct sptm_memory memory=sptm_context_memory(c);
        int region=sptm_mac_root_shared_slot(&memory,guest_root);
        c->user_shared_slot[v->slot]=region<0 || region==255 ? 0 : (uint16_t)(region+1);
    }
    if(actual_ttbr!=ttbr || actual_tcr!=tcr)fine_add(&c->root_install_failures,1);
    __atomic_store_n(&v->guest_ttbr0,guest_root|(asid<<48),__ATOMIC_RELEASE);
    fine_add(&c->shadow_tlb_syncs,1);
}
/* case SPTM_FN_SWITCH_ROOT for a converted hit or kernel switch. */
static int fine_switch_root(struct context *c,uint64_t *frame,struct fine_call_state *s)
{
    struct vcpu *v=vcpu_of(c);
    uint64_t root=frame[0];
    int kernel=root==c->params->ttbr1_root;
    if(frame[1] || frame[2]) {s->reason=FINE_NO_SHAPE;return FINE_DECLINE;}
    if(c->user_roots.sprr[v->slot].pperm!=SPRR_PPERM_INITIAL) {s->reason=FINE_NO_SWITCH;return FINE_DECLINE;}
#if SNAP_FINE_SWITCH_HW && SNAP_USER_HW_WALK
    /* SNAP_FINE_SWITCH_HW: a target with a hardware-walk record has no cache
     * entry and no views (its install selects among the record's TTBR0
     * values); the record cannot change while the gate is shared. */
    int hw=!kernel && hw_root(c,root)!=0;
    if(!kernel && !hw) {
#else
    if(!kernel) {
#endif
        struct sptm_root_cached *e=user_cached(c,root);
        if(!e || !UVIEWS(c)[e-c->user_roots.cache].count) {s->reason=FINE_NO_SWITCH;return FINE_DECLINE;}
    }
    struct sptm_memory memory=fine_memory(c);
    /* No validation, memo, eviction or stamps: a converted switch never
     * walks, builds or evicts (sptm_mac_switch_root_hit declines those). */
    struct sptm_root_backend backend={.kernel_root=c->params->ttbr1_root,
        .kernel_shadow=v->low_root,.build=fine_no_build,
        .install=fine_user_root_install,.ctx=c,.skip_hit_validation=fine_skip_hit};
#if SNAP_FINE_SWITCH_HW && SNAP_USER_HW_WALK
    /* The token path's hook without its attach (S3). */
    backend.hw_eligible=fine_hw_switch_eligible;
#endif
    if(!sptm_mac_switch_root_hit(&memory,&c->user_roots,&backend,(unsigned)v->slot,
                                 root,frame[1],frame[2])) {
        s->reason=FINE_NO_SWITCH;return FINE_DECLINE;
    }
    s->fail_kind=EV_REFERENCE_FAILED;s->fail_a=s->a0;s->fail_b=s->a1;
    if(__atomic_load_n(&c->root_install_failures,__ATOMIC_RELAXED)) {s->result=SPTM_OK;return FINE_FATAL;}
#if SNAP_FINE_SWITCH_HW && SNAP_USER_HW_WALK
    /* As the token path's case with SNAP_USER_HW_WALK (S9): a hardware-walk
     * root's identity is its record's entry; without a record this is
     * sptm_root_note_loaded. */
    if(!hw_walk_note_loaded(&c->user_roots,c->hw_walk,c->root_loaded,(unsigned)v->slot)) {
#else
    if(!sptm_root_note_loaded(&c->user_roots,c->root_loaded,(unsigned)v->slot)) {
#endif
        s->result=SPTM_BAD_CONFIG;return FINE_FATAL;
    }
#if SNAP_FINE_SWITCH_HW && SNAP_USER_HW_WALK
    /* The token path asks skip_hit_validation for cached roots only (S8). */
    if(!kernel && !hw) {fine_add(&c->native_stats.hit_asks,1);fine_add(&c->native_stats.hit_skips,1);}
#else
    if(!kernel) {fine_add(&c->native_stats.hit_asks,1);fine_add(&c->native_stats.hit_skips,1);}
#endif
    frame[0]=SPTM_SUCCESS;return FINE_DONE;
}
#endif
#endif

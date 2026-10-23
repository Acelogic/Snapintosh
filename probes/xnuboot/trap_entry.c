/* SPDX-License-Identifier: MIT */
/* The PAuth EL0 live hook, the xnuboot_trap entry and the root/TXM extension
 * mirrors.
 * Part of probes/xnuboot.c's translation unit, included in order; not compiled on its own. */
#if SNAP_PAUTH_EL0_LIVE
/* SNAP_PAUTH_EL0_LIVE. sync_lower's pauth_switch_live left this CPU's EL0 PAC
 * bank installed (the process keys, SCTLR_EL1's address-key enables,
 * HCR_EL2.API): the entry may be an EL0 read that fast_el0_sysreg answers, and
 * only that class runs before the bank is restored. The slot is exactly the
 * lower-EL synchronous one, ESR_EL1 the undefined-instruction syndrome and
 * SPSR_EL1 EL0t: fast_cross_entry sends exactly those to its EL0 branch, which
 * returns whatever it decides (compat/fast-vector.h), so no class that resumes
 * EL1 runs here. Nothing on this path executes a PAC instruction, touches a key
 * register or writes SCTLR_EL1 or HCR_EL2 (tools/test-pauth-el0-live.py audits
 * the built monitor). 1: answered; EL0 resumes with the bank still live
 * (xnuboot_pauth_resume). 0: the bank is restored and the trap continues as
 * before, *crossed set when fast_crossing already declined it, so it is
 * neither counted nor tried twice. -1: the restore failed. */
static __attribute__((noinline)) int el0_live_trap(struct context *c,uint64_t *frame,uint64_t esr,
                                                   uint64_t *elr,int *crossed)
{
    struct vcpu *v=vcpu_of(c);
    struct pauth_switch *bank=&c->pauth_bank[v->slot];
    if(bank->active!=1)return 0;
    const struct params *p=c->params;
    uint64_t esr1,spsr1;
    __asm__ volatile("mrs %0, esr_el1; mrs %1, spsr_el1":"=r"(esr1),"=r"(spsr1));
    if((esr>>26)==0x20 && p->vbar && *elr-p->vbar_va==0x400 &&
       esr1==FAST_EL0_SYSREG_ESR && !(spsr1&31) && !(spsr1>>32)) {
        if(fast_crossing(c,frame,esr,elr)) {
            /* fast_cross_entry read SCTLR_EL1 with the process's enables; record
             * EL1's, which the restore would have installed before it ran. */
            c->pan_entry[v->slot].entry_sctlr=bank->saved_sctlr;
            return 1;
        }
        *crossed=1;
    }
    return pauth_switch_leave(bank) ? -1 : 0;
}
#endif
int xnuboot_trap(uint64_t *frame, uint64_t esr, uint64_t *elr);
int xnuboot_trap(uint64_t *frame, uint64_t esr, uint64_t *elr)
{
    struct context *c = context_of();
#if SNAP_PAUTH_EL0_LIVE
    int crossed = 0;
    if ((esr >> 26) == 0x20 && c->pauth_bank[vcpu_of(c)->slot].active == 1) {
        int live = el0_live_trap(c, frame, esr, elr, &crossed);
        if (live > 0) return 0;
        if (live < 0) return xnuboot_pauth_failed(frame);
    }
#endif
#if SNAP_SYSREG_CENSUS
    sysreg_census_note(&c->perf.census[vcpu_of(c)->slot],esr);
#endif
#if SNAP_FAST_VCPU_TRAPS
    if (fast_vcpu_trap(c, frame, esr, elr)) return 0;
#endif
#if SNAP_FAST_CROSSINGS
#if SNAP_PAUTH_EL0_LIVE
    if (!crossed && fast_crossing(c, frame, esr, elr)) return 0;
#else
    if (fast_crossing(c, frame, esr, elr)) return 0;
#endif
#endif
#if SNAP_FAST_IDLE_POLL
    if (fast_idle_poll(c, frame, esr, elr)) return 0;
#endif
#if SNAP_FINE_LOCKS
    {
        int stop = 0;
        if (fine_sptm_call(c, frame, esr, elr, &stop)) return stop;
#if SNAP_ANS_CONVERTED
        if (fine_ans_mmio(c, frame, esr, elr, &stop)) return stop;
#endif
    }
#endif
#if SNAP_MULTIPAGE_FAST
    /* agents/sptm-locks/multipage P1/P2: MULTIPAGE's first cleans, off the token; armed for this trap only. */
    multipage_preclean(c, frame, esr);
    if (!runtime_enter(c, frame, *elr, (esr >> 26) & 63)) {multipage_preclean_clear(c);return 1;}
#else
    if (!runtime_enter(c, frame, *elr, (esr >> 26) & 63)) return 1;
#endif
    struct native_call_state *native=&c->native_calls[vcpu_of(c)->slot];
    uint64_t native_before=SNAP_NATIVE_CALLS ? native->calls : 0;
    int stop=xnuboot_trap_locked(frame,esr,elr);
    if(c->kernel_view_failed && !stop) {
        record(c,EV_SPRR_FAILED,*elr,SPRR_VIEW_FAILED,0,0);
        fill_regs(&vcpu_of(c)->async_regs,frame,esr,*elr,0);
        vcpu_of(c)->async_captured=2;stop=1;
    }
    /* SNAP_ERET_SNAPSHOT: an ERET refreshes the snapshot that the unarmed
     * exception_return breakpoint no longer does (writer site 5). */
    if (SNAP_NATIVE_CALLS && !stop &&
        (native_call_snapshot_required(esr,native->calls!=native_before) ||
         (SNAP_ERET_SNAPSHOT && (esr>>26)==0x1a)))
        native_exception_snapshot(c);
    stop=runtime_leave(c,stop);
#if SNAP_ATTR_CLEAN_DEFER
    attr_clean_flush(c);   /* D1: off the token, before this vCPU resumes, stop or not */
#endif
#if SNAP_MULTIPAGE_FAST
    multipage_preclean_clear(c);   /* P2: no pre-clean outlives its trap */
#endif
    /* The new CPU needs this lock to install its register state. Wait only
     * after release, and bound the wait without discarding its reservation. */
    stop = stop || secondary_wait_entry(c);
    /* A peer can request stop while this CPU owns the service lock. Preserve
     * its final return frame instead of falling back to an older last_exc.
     * For emulated instructions *elr is the prospective resume PC. Existing
     * terminal/panic snapshots remain authoritative and are not overwritten. */
    if (stop && !vcpu_of(c)->async_captured) {
        fill_regs(&vcpu_of(c)->async_regs, frame, esr, *elr, 0);
        vcpu_of(c)->async_captured = 1;
    }
    return stop;
}

#if SNAP_ROOT_CACHE_WIDE
/* Every executor has quiesced: refresh struct context's define-free root
 * cache fields from the live state for host readers (slots 0-63 only; slot
 * 64 and above are visible nowhere else). compat/root-wide.h W8. */
static void root_ext_mirror(struct context *c)
{
    const struct sptm_root_state *s=&c->user_roots;
    struct sptm_root_state_compat *h=&c->user_roots_host;
    for(unsigned n=0;n<SPTM_ROOT_CPUS;n++) {h->active[n]=s->active[n];h->sprr[n]=s->sprr[n];}
    for(unsigned i=0;i<SPTM_ROOT_CACHE_COMPAT;i++)h->cache[i]=s->cache[i];
    h->switches=s->switches;h->user_switches=s->user_switches;h->kernel_switches=s->kernel_switches;
    h->builds=s->builds;h->invalidations=s->invalidations;
    const struct native_shared *ns=&UNS(c);struct native_shared_compat *nh=&c->native_shared_host;
    nh->live=ns->live;nh->created=ns->created;nh->freed=ns->freed;nh->stores=ns->stores;
    nh->linked=ns->linked;nh->unlinked=ns->unlinked;nh->errors=ns->errors;nh->full=ns->full;nh->stale=ns->stale;
    for(unsigned g=0;g<NATIVE_SHARED_GROUPS;g++) {
        const struct native_shared_group *a=&ns->group[g];struct native_shared_group_compat *b=&nh->group[g];
        b->guest=a->guest;b->shared=a->shared;b->va=a->va;b->leaves=a->leaves;b->slots=a->slots.w[0];
        for(unsigned q=0;q<NATIVE_SHARED_PAGES;q++)b->pages[q]=a->pages[q];
    }
    for(unsigned i=0;i<NATIVE_SHARED_INDEX;i++)nh->index[i]=ns->index[i];
    for(unsigned i=0;i<SPTM_ROOT_CACHE_COMPAT;i++) {
        c->user_views[i]=UVIEWS(c)[i];c->root_stamp[i]=USTAMPS(c)[i];
        c->inactive_mirror.budget[i]=UBUDGETS(c)[i];
    }
}
#endif
#if SNAP_TXM_ASPACE_WIDE
/* Every executor has quiesced: refresh the define-free 512-slot TXM registry
 * for host readers. Slots 512 and above are only in the live pages; count is
 * the live high-water mark and may exceed 512 (compat/txm.h A3). */
static void txm_ext_mirror(struct context *c)
{
    const struct txm_registry *r=TXM_REG(c);
    struct txm_registry_compat *h=&c->txm_registry_host;
    for(unsigned i=0;i<TXM_ASPACE_LIMIT_COMPAT;i++) {
        h->root[i]=r->root[i];h->asid[i]=r->asid[i];h->shared[i]=r->shared[i];
        h->region_start[i]=r->region_start[i];h->region_end[i]=r->region_end[i];
        h->bound_shared[i]=r->bound_shared[i];
    }
    h->count=r->count;h->region_sets=r->region_sets;
    h->bindings=r->bindings;h->unbindings=r->unbindings;
}
#endif

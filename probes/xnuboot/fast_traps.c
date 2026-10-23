/* SPDX-License-Identifier: MIT */
/* Fast paths: vCPU traps, timer IRQ, EL0/EL1 crossings and the idle poll.
 * Part of probes/xnuboot.c's translation unit, included in order; not compiled on its own. */
#if SNAP_FAST_VCPU_TRAPS
/* This CPU's operations for compat/fast-trap.h, identical to the reads the
 * locked handlers make. */
static uint64_t fast_guest_pa(void *ctx,uint64_t va) {(void)ctx;return guest_pa(va);}
static uint32_t fast_fetch(void *ctx,uint64_t pa) {(void)ctx;return *(volatile uint32_t *)pa;}
static uint64_t fast_stack(void *ctx,uint64_t spsr)
{
    uint64_t sp;(void)ctx;
    if(spsr&1)__asm__ volatile("mrs %0, sp_el1":"=r"(sp));
    else __asm__ volatile("mrs %0, sp_el0":"=r"(sp));
    return sp;
}
static uint64_t fast_esr(void *ctx) {uint64_t v;(void)ctx;__asm__ volatile("mrs %0, esr_el1":"=r"(v));return v;}
static uint64_t fast_far(void *ctx) {uint64_t v;(void)ctx;__asm__ volatile("mrs %0, far_el1":"=r"(v));return v;}
/* secondary_wait_entry's condition: CPU0 must keep taking the locked path,
 * which waits for a launched secondary after release, until it has entered. */
static int fast_secondary_pending(struct context *c)
{
    if(!c->secondary_base)return 0;
    for(unsigned i=1;i<6;i++) {
        if(!(c->host_cpus->mask&(1U<<i)))continue;
        struct secondary *s=secondary_of(c,i);
        if(!s->on_result && __atomic_load_n(&s->phase,__ATOMIC_ACQUIRE)<3)return 1;
    }
    return 0;
}
/* 1: emulated without the service lock, resume the guest. 0: take the locked
 * path, which repeats the classification and handles the trap unchanged. */
/* What every lock-free trap path requires: the service admits this CPU, no
 * view or install failure is latched, and no step, guard, user-entry probe,
 * pending secondary launch or native-call snapshot needs the locked path. */
static int fast_admitted(struct context *c,const struct vcpu *v,uint64_t esr)
{
    return guest_service_admitted(&c->services,(unsigned)v->slot) &&
       !__atomic_load_n(&c->kernel_view_failed,__ATOMIC_RELAXED) &&
       !__atomic_load_n(&c->user_view_failed,__ATOMIC_RELAXED) &&
       !__atomic_load_n(&c->root_install_failures,__ATOMIC_RELAXED) &&
       !v->stepping.active && !v->open_guards && !c->user_execution[v->slot].pending &&
       !(!v->slot && fast_secondary_pending(c)) && !native_call_snapshot_required(esr,0);
}
static int fast_reset_latched(struct context *c)
{
    return (__atomic_load_n(&c->device_reset_mask[0],__ATOMIC_RELAXED) |
            __atomic_load_n(&c->device_reset_mask[1],__ATOMIC_RELAXED))!=0;
}
/* The guest's virtual FIQ/IRQ lines agree with their sources. A path that
 * would leave a disagreement (an IPI another CPU posted, a changed timer or
 * model line) declines, so guest_interrupt_sync on the locked path raises it. */
static int fast_lines_current(const struct vcpu *v)
{
    uint64_t hcr;__asm__ volatile("mrs %0, hcr_el2":"=r"(hcr));
    int fiq=v->timer_pending || __atomic_load_n(&v->ipi.pending,__ATOMIC_RELAXED);
    return !(hcr&(1UL<<6))==!fiq && !(hcr&(1UL<<7))==!v->model_irq_pending;
}
/* A CNTV_TVAL write may skip timer_sync only while the watchdog is live, no
 * device deadline has passed since this CPU's last sync and nothing else is
 * waiting for the locked path. */
static int fast_timer_write_ready(struct context *c,const struct vcpu *v)
{
    if(!SNAP_FAST_TIMER_WRITE || !v->watchdog_live)return 0;
    uint64_t physical;__asm__ volatile("isb; mrs %0, cntpct_el0":"=r"(physical));
    return physical<c->fast_timer_due[v->slot].physical && fast_lines_current(v) &&
           !fast_reset_latched(c);
}
#if SNAP_FAST_IPI
/* The locked handler's IPI case (xnuboot_trap_locked: c->traps, guest_ipi_route,
 * the request/ack PC, guest_interrupt_sync, Rt and ELR) for an admitted CPU,
 * without the token: compat/fast-ipi.h decides, with the same runnable mask.
 * guest_interrupt_sync touches only this vCPU (no step is active once
 * admitted). 1: handled; 0: the locked path repeats it unchanged. */
static int fast_ipi_trap(struct context *c,struct vcpu *v,uint64_t *frame,uint64_t esr,uint64_t *elr)
{
    uint64_t start;__asm__ volatile("isb; mrs %0, cntpct_el0":"=r"(start)::"memory");
    uint64_t iss=esr&0x1ffffff,reg=ISS_REG(iss),rt=ISS_RT(iss);
    int is_read=(int)ISS_READ(iss);
    struct fast_ipi_cpu *f=&c->root_ext->fast_ipi[v->slot];
    if(!fast_admitted(c,v,esr)) {f->result[FAST_IPI_DECLINE_STATE]++;return 0;}
    struct guest_ipi *states[GUEST_CPU_COUNT];
    uint64_t affinities[GUEST_CPU_COUNT],runnable=0,life=guest_service_lifecycle(&c->services);
    for(unsigned i=0;i<GUEST_CPU_COUNT;i++) {
        states[i]=&c->vcpus[i].ipi;affinities[i]=c->vcpus[i].vmpidr;
        if(!(life&SERVICE_ADMISSION_CLOSED) && c->vcpus[i].prepared &&
           ((life>>(i*3))&7)==EXECUTOR_RUNNING) runnable|=UINT64_C(1)<<i;
    }
    uint64_t value=(rt==31) ? 0 : frame[rt];
    unsigned r=fast_ipi_access(states,affinities,GUEST_CPU_COUNT,runnable,(unsigned)v->slot,
                               reg,is_read,&value);
    f->result[r]++;
    if(r>=FAST_IPI_DECLINES)return 0;
    if(!is_read) {
        if(reg==IPI_SR && value) v->ipi_ack_pc=*elr;
        else if(reg!=IPI_SR) v->ipi_request_pc=*elr;
    }
    guest_interrupt_sync(c);
    if(is_read && rt!=31) frame[rt]=value;
    *elr+=4;
    /* c->traps' share (report word 2 adds every CPU's fast sysreg count), and
     * runtime_enter's per-vCPU bookkeeping for the category. */
    c->perf.fast[v->slot].sysreg++;
    if(SNAP_STEP_ALU)step_alu_enter(&c->step_alu[v->slot],0x18);
    step_translation_clear(&c->step_translation[v->slot]);
    uint64_t end;__asm__ volatile("isb; mrs %0, cntpct_el0":"=r"(end)::"memory");
    f->ticks+=end-start;
    if(end-start>f->max)f->max=end-start;
    return 1;
}
#endif
#if SNAP_LEAN_TRAPS
/* After a lock-free ESR/FAR/PMC read at EL1 (lean_run_start), the next
 * instructions while each is an MRS the lock-free path answers: read from the
 * const-sealed kernel image through the current stage-1 translation, emulated
 * by fast_trap_emulate with the syndrome a trap would report, at most
 * LEAN_RUN_MAX. The first trap's admission covers them (no stop, step, guard
 * or probe can begin without a trap or tick); an ignored register not yet
 * logged ends the run, so it traps and takes the locked path's record. Not
 * traps: neither the census nor handled[] counts them (lean->steps does). */
static inline __attribute__((always_inline)) void lean_run_ahead(struct context *c,
    struct fast_trap_cpu *f,struct lean_trap_cpu *l,
    const struct fast_trap_hw *hw,const struct fast_trap_vcpu *state,uint64_t spsr,
    uint64_t *frame,uint64_t *elr)
{
    const struct params *p=c->params;
    uint64_t page=UINT64_MAX,base=0;
    l->runs++;
    for(unsigned n=0;n<LEAN_RUN_MAX;n++) {
        uint64_t va=*elr;
        if((va>>12)!=page) {
            uint64_t pa=guest_pa(va);
            if(!pa) {l->ends++;return;}
            page=va>>12;base=pa&~UINT64_C(0xfff);
        }
        uint64_t pa=base|(va&0xfff);
        if(pa<p->const_begin || pa>p->const_end-4) {l->ends++;return;}
        uint64_t reg;unsigned rt;
        if(!lean_mrs(*(const volatile uint32_t *)pa,&reg,&rt))return;
        unsigned cls=fast_trap_sysreg_class(reg,1);
        uint64_t bit=fast_trap_log_bit(cls,reg);
        if(!lean_run_class(cls) || (bit && !(f->logged&bit)))return;
        if(fast_trap_emulate(hw,state,lean_mrs_esr(reg,rt),spsr,frame,elr)!=cls)return;
        l->steps++;
    }
}
#endif
static int fast_vcpu_trap(struct context *c,uint64_t *frame,uint64_t esr,uint64_t *elr)
{
    uint64_t ec=esr>>26,reg=0;
    if(ec!=0x09 && ec!=0x18)return 0;
    struct vcpu *v=vcpu_of(c);
    struct fast_trap_cpu *f=&c->perf.fast[v->slot];
    unsigned cls=FAST_TRAP_PACGA;
    if(ec==0x18) {
        uint64_t iss=esr&0x1ffffff;reg=ISS_REG(iss);
#if SNAP_FAST_IPI
        if(reg==IPI_RR_LOCAL || reg==IPI_RR_GLOBAL || reg==IPI_SR)return fast_ipi_trap(c,v,frame,esr,elr);
#endif
        cls=fast_trap_sysreg_class(reg,(int)ISS_READ(iss));
        if(cls==FAST_TRAP_NONE)return 0;
    }
    /* The first trap of each recording class/register per vCPU keeps its
     * shared-log record by taking the locked path. */
    uint64_t bit=fast_trap_log_bit(cls,reg);
    if(bit && !(f->logged&bit)) {f->logged|=bit;f->first++;f->declined++;return 0;}
    if(!fast_admitted(c,v,esr) ||
       /* A latched device reset stops the guest at its next locked timer access. */
       (cls==FAST_TRAP_TIMER && fast_reset_latched(c)) ||
       (cls==FAST_TRAP_TIMER_WRITE && !fast_timer_write_ready(c,v))) {
        f->declined++;return 0;
    }
    uint64_t spsr;
    __asm__ volatile("mrs %0, spsr_el2":"=r"(spsr));
    const struct clock_backend clock={c,clock_counter,clock_control};
    const struct fast_trap_hw hw={.ctx=c,.mem_low=c->params->mem_low,
#if SNAP_LEAN_TRAPS
        /* Only PACGA asks; the ID registers are not read for the others. */
        .mem_high=c->params->mem_high,.pac_supported=ec==0x09 && generic_pauth_supported(),
#else
        .mem_high=c->params->mem_high,.pac_supported=generic_pauth_supported(),
#endif
        .guest_pa=fast_guest_pa,.fetch=fast_fetch,.stack=fast_stack,.sign=generic_sign,
        .esr=fast_esr,.far=fast_far,.clock=&clock};
    const struct fast_trap_vcpu state={&c->user_pauth[v->slot],&v->guest_apga_lo,
        &v->guest_apga_hi,&v->pacga_calls,&v->clock,&v->arch_counter_reads,&v->timer,
        &c->user_roots.sprr[v->slot],&v->timer_pending};
#if SNAP_NATIVE_PACGA
    uint64_t apga_lo=v->guest_apga_lo,apga_hi=v->guest_apga_hi;
#endif
    unsigned done=fast_trap_emulate(&hw,&state,esr,spsr,frame,elr);
    if(done==FAST_TRAP_NONE) {f->declined++;return 0;}
#if SNAP_NATIVE_PACGA
    if(done==FAST_TRAP_KEY)native_pacga_sync(c,v,apga_lo,apga_hi);
#endif
    if(done==FAST_TRAP_TIMER_WRITE) {
        /* The line is unchanged (fast_trap_emulate checked it), so only this
         * CPU's EL2 timer moves, exactly as timer_sync would arm it. */
        uint64_t physical;__asm__ volatile("mrs %0, cntpct_el0":"=r"(physical));
        timer_arm(c,physical,c->fast_timer_due[v->slot].guest);
    }
    /* runtime_enter's per-vCPU bookkeeping for every non-step category. */
    if(SNAP_STEP_ALU)step_alu_enter(&c->step_alu[v->slot],(unsigned)ec);
    step_translation_clear(&c->step_translation[v->slot]);
    f->handled[done]++;
    if(ec==0x18)f->sysreg++;
    FAST_EXIT_MARK(frame,FAST_EXIT_TRAP_SLOT(done));
#if SNAP_LEAN_TRAPS
    if(ec==0x18 && lean_run_start(done,reg,(int)ISS_READ(esr&0x1ffffff)))
        lean_run_ahead(c,f,&c->root_ext->lean[v->slot],&hw,&state,spsr,frame,elr);
#endif
    return 1;
}
#endif

#if SNAP_FAST_TIMER_IRQ
/* This CPU's operations for compat/fast-timer-irq.h: the reads, writes and
 * calls of xnuboot_async_locked's tick and timer_sync. */
_Static_assert(FAST_IRQ_ISTATUS==CNTHP_ISTATUS && ASYNC_IRQ_OTHER!=ASYNC_IRQ &&
               ASYNC_IRQ_OTHER!=ASYNC_FIQ && ASYNC_IRQ_OTHER!=ASYNC_SERROR,
               "the gate's ISTATUS; the hand-over kind is no vector's");
static uint64_t fast_irq_acknowledge(void *ctx)
{
    uint64_t intid;(void)ctx;
    __asm__ volatile("mrs %0, icc_iar1_el1; dsb sy":"=r"(intid)::"memory");
    return intid;
}
static void fast_irq_complete(void *ctx,uint64_t intid) {(void)ctx;timer_eoi(intid);}
static uint64_t fast_irq_physical(void *ctx) {uint64_t v;(void)ctx;__asm__ volatile("mrs %0, cntpct_el0":"=r"(v));return v;}
static uint64_t fast_irq_hcr(void *ctx) {uint64_t v;(void)ctx;__asm__ volatile("mrs %0, hcr_el2":"=r"(v));return v;}
static void fast_irq_set_hcr(void *ctx,uint64_t v) {(void)ctx;__asm__ volatile("msr hcr_el2, %0; isb"::"r"(v));}
static void fast_irq_arm(void *ctx,uint64_t physical,uint64_t due) {timer_arm(ctx,physical,due);}
/* 0, or 1 when the run stopped meanwhile: the tick ran here. FAST_IRQ_LOCKED:
 * nothing but this CPU's counter changed, take the locked path.
 * FAST_IRQ_LOCKED_OTHER: the acknowledged INTID was completed, take the
 * locked path's stop for it. */
#if SNAP_FAST_TIMER_IRQ_CPU0
/* vCPU 0 only: 1 when none of the duties its locked tick adds is due, by the
 * same tests those duties make, without their bookkeeping: the host poll
 * (early_stop_host_due), the thermal sample (a16_thermal_wait is 0 when due)
 * and the GPU tick (adopted, not quiesced, run_at reached), and a locked tick
 * within FAST_IRQ_CPU0_LOCKED_MS. Each schedule is written only by vCPU 0, in
 * its locked tick, so this CPU reads its own last values. Counts the first
 * duty found due. */
static int fast_cpu0_quiet(struct context *c,uint64_t physical)
{
    const struct params *p=c->params;
    struct fast_irq_cpu0 *z=&c->root_ext->cpu0_tick;
    const struct early_stop_params *e=&p->early_stop;
    const struct early_stop_state *s=&c->early_stop;
    if(!z->locked || physical-z->locked>=p->clock_host_hz/1000*FAST_IRQ_CPU0_LOCKED_MS) {z->backstop++;return 0;}
    if((e->flags&EARLY_STOP_F_HOST) && e->host_call && e->session &&
       e->host_poll_ms>=EARLY_STOP_POLL_FLOOR(e) && e->host_poll_ms<=EARLY_STOP_POLL_MAX_MS &&
       (!s->host_polls || (int64_t)(physical-s->host_next_poll)>=0)) {z->host++;return 0;}
    if(c->thermal && !a16_thermal_wait(c->thermal,physical,p->clock_host_hz,1)) {z->thermal++;return 0;}
    if(p->gpu.flags && (c->gpu.status&ADRENO_S_ADOPTED) && !(c->gpu.status&ADRENO_S_QUIESCED) &&
       physical>=c->gpu.run_at) {z->gpu++;return 0;}
    z->quiet++;
    return 1;
}
#endif
static int fast_timer_irq(struct context *c,uint64_t elr,uint64_t *frame)
{
    struct vcpu *v=vcpu_of(c);
    struct fast_irq_cpu *f=&c->root_ext->fast_irq[v->slot];
    struct fast_irq_gate g={.slot=v->slot};
    if(v->slot) {
        /* xnuboot_async_locked's reads, then fast_timer_write_ready's gate:
         * this CPU's last synced device deadline, no reset latched. */
        __asm__ volatile("mrs %0, cnthp_ctl_el2; mrs %1, icc_hppir1_el1; mrs %2, cntpct_el0"
                         :"=r"(g.ctl),"=r"(g.hppir),"=r"(g.physical));
        g.admitted=(uint64_t)fast_admitted(c,v,0);
        g.watchdog_live=v->watchdog_live;
        g.device_due=c->fast_timer_due[v->slot].physical;
        g.reset_latched=(uint64_t)fast_reset_latched(c);
        g.deadline=run_deadline(c);
    }
#if SNAP_FAST_TIMER_IRQ_CPU0
    else {
        /* vCPU 0: the same inputs, and whether any of its own duties is due. */
        __asm__ volatile("mrs %0, cnthp_ctl_el2; mrs %1, icc_hppir1_el1; mrs %2, cntpct_el0"
                         :"=r"(g.ctl),"=r"(g.hppir),"=r"(g.physical));
        g.admitted=(uint64_t)fast_admitted(c,v,0);
        g.watchdog_live=v->watchdog_live;
        g.device_due=c->fast_timer_due[0].physical;
        g.reset_latched=(uint64_t)fast_reset_latched(c);
        g.deadline=run_deadline(c);
        g.cpu0_quiet=(uint64_t)fast_cpu0_quiet(c,g.physical);
    }
#endif
#if SNAP_ANS_ASYNC
    /* agents/nvme-async N11, N19: at this vCPU's SSD deadline, peek at the completion (read-only). Ready, or
     * work queued with nothing in flight, or the backstop: the deadline counts as a passed device deadline, so
     * the gate declines and the locked tick polls. Not ready: push this vCPU's deadline and stay here. */
    {
        struct ans_state *as=c->root_ext->ans;
        uint64_t due;
        if(as && ans_async_due_of(c,v->slot,&due) && (int64_t)(g.physical-due)>=0) {
            struct ans_async *a=&as->async;
            __atomic_fetch_add(&a->sched[2],1,__ATOMIC_RELAXED);
            struct ans_window_backend b=ans_window_backend(c);
            if(!__atomic_load_n(&a->phys,__ATOMIC_RELAXED) || ans_window_ready(&b) ||
               (int64_t)(g.physical-a->start-ans_async_us(c,ANS_ASYNC_BACKSTOP_US))>=0) {
                if(due<g.device_due)g.device_due=due;     /* 0 (unsynced) already declines */
                __atomic_fetch_add(&a->sched[3],1,__ATOMIC_RELAXED);
            } else {
                uint64_t next=ans_async_next(c,g.physical,a->start);
                __atomic_compare_exchange_n(&a->due,&due,next,0,__ATOMIC_RELAXED,__ATOMIC_RELAXED);
            }
        }
    }
#endif
    unsigned r=fast_timer_irq_gate(&g);
    if(r==FAST_IRQ_HANDLED) {
        const struct fast_irq_hw hw={c,fast_irq_acknowledge,fast_irq_complete,clock_counter,
                                     fast_irq_physical,fast_irq_hcr,fast_irq_set_hcr,fast_irq_arm};
        const struct fast_irq_vcpu state={&v->timer,&v->timer_pending,&v->ipi.pending,
            &v->model_irq_pending,&v->timer_irqs,&v->timer_irq_pc,&v->timer_asserts,&v->timer_clears,
            &v->model_irq_asserts,&v->model_irq_clears,c->fast_timer_due[v->slot].guest};
        r=fast_timer_irq_tick(&hw,&state,elr);
    }
    f->result[r]++;
    if(r==FAST_IRQ_OTHER)return FAST_IRQ_LOCKED_OTHER;
    if(r!=FAST_IRQ_HANDLED)return FAST_IRQ_LOCKED;
    /* runtime_enter's per-vCPU bookkeeping for the IRQ category. */
    if(SNAP_STEP_ALU)step_alu_enter(&c->step_alu[v->slot],SERVICE_PROFILE_ASYNC+ASYNC_IRQ);
    step_translation_clear(&c->step_translation[v->slot]);
#if SNAP_WFI_RESUME
    /* The locked tick's last step, after the same ones; a reset latched since
     * the gate declines it, as device_reset_stop's stop does there. */
    wfi_resume(c,elr,frame,fast_reset_latched(c));
    if(frame[32]!=elr)f->resumed++;
#else
    (void)frame;
#endif
    uint64_t end;__asm__ volatile("isb; mrs %0, cntpct_el0":"=r"(end)::"memory");
    f->ticks+=end-g.physical;
    if(end-g.physical>f->max)f->max=end-g.physical;
    return guest_service_stopped(&c->services)!=0;
}
#endif

#if SNAP_FAST_CROSSINGS
/* This CPU's operations for compat/fast-vector.h, identical to the reads the
 * locked vector and ERET branches make. */
static void fast_el1(void *ctx,struct fast_cross_el1 *r)
{
    (void)ctx;
    __asm__ volatile("mrs %0, esr_el1; mrs %1, far_el1; mrs %2, elr_el1; "
                     "mrs %3, spsr_el1; mrs %4, sctlr_el1"
                     :"=r"(r->esr),"=r"(r->far),"=r"(r->elr),"=r"(r->spsr),"=r"(r->sctlr));
}
static uint64_t fast_hcr(void *ctx) {uint64_t v;(void)ctx;__asm__ volatile("mrs %0, hcr_el2":"=r"(v));return v;}
static uint64_t fast_vhcr(void *ctx)
{
    const struct vcpu *v=vcpu_of(ctx);
    return v->vncr_va ? *(volatile uint64_t *)(v->vncr_va+0x78) : 0;
}
/* EL0 crossings select through native tables (native_cross, per-CPU by its
 * contract). Without them a crossing rewrites this CPU's shared view copies
 * under the lock: no selection, so every EL0 entry and user return declines.
 * user_enter_mode's own check stays: the variant selected must be the active
 * root's (the active root's cache entry and views cannot change while it is
 * installed, and roots are unique in the cache, so the read-only lookup needs
 * no lock). A mismatch latches the failure as it does under the lock, and the
 * declined exit's locked path stops the run. */
#if SNAP_NATIVE_TABLES
static int fast_select(void *ctx,int el0)
{
    struct context *c=ctx;
    unsigned cpu=(unsigned)vcpu_of(c)->slot;
    struct sptm_root_cached *e=user_cached(c,c->user_roots.active[cpu]);
#if SNAP_USER_HW_WALK
    if(!e)e=hw_record_entry(c,c->user_roots.active[cpu]);
#endif
    if(!e || !native_cross(c,cpu,el0))return 0;
    if(c->user_view_state[cpu].shadow==user_hw_root(c,e,cpu))return 1;
    __atomic_store_n(&c->user_view_failed,1,__ATOMIC_RELAXED);
    return 0;
}
#define FAST_SELECT fast_select
#else
#define FAST_SELECT 0
#endif
static int fast_user_root(void *ctx) {return user_return_root(ctx)!=0;}
static void fast_capture(void *ctx,const uint64_t *frame,uint64_t esr,uint64_t elr,uint64_t far)
{capture_regs(ctx,frame,esr,elr,far);}
#if SNAP_FAST_EL0_SYSREG
#if SNAP_EL0_MEMO
/* SNAP_EL0_MEMO: fast_el0_word's answer from this vCPU's memo
 * (compat/el0-memo.h), or 0 and the full read follows. The root: no install
 * on this vCPU since the way was read and the same active root, so
 * user_return_root's lookup still names the way's entry (an installed root's
 * cache slot is never evicted, invalidated or retired, its hardware-walk
 * record never detached, and a root has one identity), which is re-checked
 * here before user_return_root's own checks (user_return_check). The walks:
 * their configuration recomputed and every recorded descriptor re-read,
 * unchanged, through user_instruction_read's readers. The code frame and the
 * word: re-read by user_code_word. A stale or changed way is dropped. */
static int el0_memo_answer(struct context *c,uint64_t pc,struct fast_el0_fetch *out)
{
    unsigned cpu=(unsigned)vcpu_of(c)->slot;
    struct el0_memo_cpu *m=&EL0M(c)[cpu];
    struct el0_memo_entry *w=el0_memo_find(m,pc);
    if(!w)return 0;
    uint64_t active=c->user_roots.active[cpu];
    struct sptm_root_cached *e=(struct sptm_root_cached *)w->entry;
    if(!el0_memo_current(m,w,active) || !e->valid || e->root!=active || user_return_check(c,e)!=e) {
        el0_memo_drop(w);m->stats.stale++;return 0;
    }
#if SNAP_USER_HW_WALK
    unsigned hardware_kind=hw_walk_of_entry(c->hw_walk,e)!=0;
    mmu_read_fn hardware_read=hardware_kind ? hw_table_read : kernel_table_read;
#else
    unsigned hardware_kind=0;
    mmu_read_fn hardware_read=kernel_table_read;
#endif
    uint64_t pa=w->page_pa|(pc&0xfff);uint32_t word;
    if(!el0_memo_check(w,e,e->root,e->format ? 12u : 14u,user_hw_root(c,e,cpu),hardware_kind,
                       user_source_read,c,hardware_read,c) || !user_code_word(c,pa,&word)) {
        el0_memo_drop(w);m->stats.changed++;return 0;
    }
    *out=(struct fast_el0_fetch){w->source_leaf,w->hardware_leaf,pa,e->root,word};
    m->stats.hits++;
    return 1;
}
#endif
/* user_sysreg_access's root and word, by the same two functions. */
static int fast_el0_word(void *ctx,uint64_t pc,struct fast_el0_fetch *out)
{
    struct context *c=ctx;
#if SNAP_EL0_MEMO
    /* A memo hit is already the second read of a pair (FAST_EL0_FETCH_PROVEN);
     * otherwise this full read records itself for fast_el0_note to keep. */
    if(el0_memo_answer(c,pc,out))return FAST_EL0_FETCH_PROVEN;
    unsigned cpu=(unsigned)vcpu_of(c)->slot;
    el0_memo_begin(&EL0M(c)[cpu],pc,c->user_roots.active[cpu]);
#endif
    struct sptm_root_cached *root=user_return_root(c);
    struct mmu_leaf source,hardware;uint32_t word;
#if SNAP_EL0_MEMO
    int read=root && user_instruction_read(c,root,pc,&source,&hardware,&word);
    el0_memo_end(&EL0M(c)[cpu],read);
    if(!read)return 0;
#else
    if(!root || !user_instruction_read(c,root,pc,&source,&hardware,&word))return 0;
#endif
    *out=(struct fast_el0_fetch){source.descriptor,hardware.descriptor,source.pa,root->root,word};
    return 1;
}
/* user_sysreg_access's records, statement for statement
 * (tools/test-fast-el0-sysreg.py compares them). */
static void fast_el0_note(void *ctx,unsigned kind,uint64_t pc,uint32_t word,uint64_t saved,uint64_t root)
{
    struct context *c=ctx;struct vcpu *v=vcpu_of(c);
    if(kind==FAST_EL0_CLOCK) {
        struct user_clock_state *u=&c->user_clock[v->slot];
        u->reads++;u->pc=pc;u->word=word;u->value=v->clock.last;u->spsr=saved;
        __asm__ volatile("mrs %0, sp_el0":"=r"(u->sp));
        u->root=root;u->cntkctl=v->clock.cntkctl;u->raw=v->clock_raw_last;
        u->host_hz=v->clock_rate.host_hz;u->guest_hz=v->clock_rate.guest_hz;
    } else {
        struct sprr_state *sprr=&c->user_roots.sprr[v->slot];
        struct user_sprr_state *u=&c->user_sprr[v->slot];
        u->reads++;u->pc=pc;u->word=word;u->value=sprr->uperm;u->spsr=saved;
        __asm__ volatile("mrs %0, sp_el0":"=r"(u->sp));
        u->root=root;u->umprr=sprr->umprr;
    }
#if SNAP_EL0_MEMO
    /* Both reads agreed and the word was emulated: keep that read's record. */
    el0_memo_keep(&EL0M(c)[v->slot],pc,root);
#endif
}
#endif
/* 1: the vector entry or ERET was handled without the service lock. 0: take
 * the locked path, which repeats the classification and handles it unchanged. */
static int fast_crossing(struct context *c,uint64_t *frame,uint64_t esr,uint64_t *elr)
{
    uint64_t ec=esr>>26;
    if(ec!=0x20 && ec!=0x1a)return 0;
    struct vcpu *v=vcpu_of(c);
    struct fast_trap_cpu *f=&c->perf.fast[v->slot];
    const struct params *p=c->params;
    uint64_t spsr,far,hcr;
    __asm__ volatile("mrs %0, spsr_el2; mrs %1, far_el2; mrs %2, hcr_el2"
                     :"=r"(spsr),"=r"(far),"=r"(hcr));
    /* Only the vector fetch of an exception entry: its IPA is the vector page. */
    if(ec==0x20 && (!p->vbar || far!=*elr || (esr&(1UL<<7)) ||
                    (guest_pa(far)&~0xfffUL)!=p->vbar))return 0;
    /* The locked boundary re-derives the virtual FIQ/IRQ lines (step_arm ->
     * guest_interrupt_sync), which is where an IPI another CPU posted is first
     * raised: take the locked path while a line disagrees with its sources. */
    int fiq=v->timer_pending || __atomic_load_n(&v->ipi.pending,__ATOMIC_RELAXED);
    if(((spsr&31)!=4 && (spsr&31)!=5) ||
       !guest_service_admitted(&c->services,(unsigned)v->slot) ||
       __atomic_load_n(&c->kernel_view_failed,__ATOMIC_RELAXED) ||
       __atomic_load_n(&c->user_view_failed,__ATOMIC_RELAXED) ||
       __atomic_load_n(&c->root_install_failures,__ATOMIC_RELAXED) ||
       v->stepping.active || v->open_guards || c->user_execution[v->slot].pending ||
       (!v->slot && fast_secondary_pending(c)) ||
       !(hcr&(1UL<<6))!=!fiq || !(hcr&(1UL<<7))!=!v->model_irq_pending) {
        f->declined++;return 0;
    }
#if SNAP_FAST_EL0_SYSREG
    const struct clock_backend clock={c,clock_counter,clock_control};
    const struct fast_el0_hw el0_hw={.ctx=c,.fetch=fast_el0_word,.clock=&clock,.note=fast_el0_note};
    uint64_t el0_spsr=0;
    const struct fast_el0_vcpu el0_state={&v->clock,&c->user_roots.sprr[v->slot],frame,
        c->exit_profile.cpu[v->slot].el0,&el0_spsr};
#endif
    const struct fast_cross_hw hw={.ctx=c,.vbar_va=p->vbar_va,.vbar_pa=p->vbar,
        .mem_low=p->mem_low,.mem_high=p->mem_high,.crash_ring=SNAP_USER_CRASH_RING,
        .guest_pa=fast_guest_pa,.fetch=fast_fetch,.el1=fast_el1,.hcr=fast_hcr,
        .vhcr=fast_vhcr,.cross=FAST_SELECT,.user_root=fast_user_root,.capture=fast_capture,
#if SNAP_FAST_EL0_SYSREG
        .el0=&el0_hw,
#endif
    };
    struct pan_entry_state *pan=&c->pan_entry[v->slot];
    struct user_execution *user=&c->user_execution[v->slot];
    const struct fast_cross_vcpu state={&pan->user_vectors,&pan->protected_vectors,
        &pan->vector,&pan->saved_spsr,&pan->entry_spsr,&pan->entry_sctlr,
        &v->timer_vectors,&v->model_irq_vectors,&v->fault_esr,&v->fault_far,
        &v->kernel_returns,&v->last_kernel_return,&user->returns,&user->svcs,&user->faults,
        &f->logged,&f->first,
#if SNAP_FAST_EL0_SYSREG
        &el0_state,
#endif
    };
    uint64_t next=0;
    unsigned done=ec==0x20 ? fast_cross_entry(&hw,&state,spsr,frame,elr) :
                             fast_cross_return(&hw,&state,spsr,elr,&next);
    if(done==FAST_CROSS_NONE) {f->declined++;return 0;}
    if(ec==0x1a)__asm__ volatile("msr spsr_el2, %0"::"r"(next));
#if SNAP_FAST_EL0_SYSREG
    /* The emulated EL0 read: back to EL0 with user_sysreg_access's PSTATE
     * (xnuboot_pauth_resume reloads the EL0 keys from SPSR_EL2's mode), the
     * vector slot not taken. */
    else if(done==FAST_CROSS_EL0_SYSREG_CLASS)__asm__ volatile("msr spsr_el2, %0"::"r"(el0_spsr));
#endif
    else f->branches++;
    /* The common exit's native-call snapshot: a vector entry always, an ERET
     * under SNAP_ERET_SNAPSHOT. */
    if(SNAP_NATIVE_CALLS && (ec==0x20 || SNAP_ERET_SNAPSHOT))native_exception_snapshot(c);
    /* runtime_enter's per-vCPU bookkeeping for every non-step category. */
    if(SNAP_STEP_ALU)step_alu_enter(&c->step_alu[v->slot],(unsigned)ec);
    step_translation_clear(&c->step_translation[v->slot]);
    if(ec==0x20)f->entries++;else f->returns++;
    FAST_EXIT_MARK(frame,FAST_EXIT_CROSS_SLOT(done));
    return 1;
}
#endif

#if SNAP_FAST_IDLE_POLL
/* The ACC idle poll (compat/fast-mmio.h): routed exactly as the locked data
 * abort is (stage-1 IPA, device windows, then device_model_find), answered
 * with the locked access's value, clock sample and read count. The locked
 * path's interrupt rerouting, model rescans and timer_sync follow an access
 * that changed nothing; the next locked trap or EL2 timer redoes them. */
static int fast_idle_poll(struct context *c,uint64_t *frame,uint64_t esr,uint64_t *elr)
{
    if((esr>>26)!=0x24 || (esr&(1UL<<7)))return 0;      /* data abort, not a stage-1 walk */
    struct dc_access a=dc_decode(esr);
    if(!a.valid || a.write || a.size!=8)return 0;
    struct vcpu *v=vcpu_of(c);
    const struct params *p=c->params;
    uint64_t spsr,far,hpfar;
    __asm__ volatile("mrs %0, spsr_el2; mrs %1, far_el2; mrs %2, hpfar_el2"
                     :"=r"(spsr),"=r"(far),"=r"(hpfar));
    if((spsr&31)!=4 && (spsr&31)!=5)return 0;
    uint64_t ipa=guest_pa(far),off=0;
    if(!ipa && (hpfar&0x0000fffffffffff0UL))ipa=((hpfar>>4)<<12)|(far&0xfff);
    if(!ipa || dc_window(p->device_pa,p->device_span,p->device_count,ipa,&off)>=0)return 0;
    int index=device_model_find(p->models,p->model_count,ipa,&off);
    if(index<0 || !fast_idle_poll_model(&p->models[index],off,a.size,a.write))return 0;
    struct fast_trap_cpu *f=&c->perf.fast[v->slot];
    if(!fast_admitted(c,v,esr) || !fast_lines_current(v) || fast_reset_latched(c)) {
        f->declined++;return 0;
    }
    (void)clock_counter(c);
    if(a.reg!=31)frame[a.reg]=dc_extend(&a,0);
    __atomic_fetch_add(&c->model_reads[index],1,__ATOMIC_RELAXED);
    if(SNAP_STEP_ALU)step_alu_enter(&c->step_alu[v->slot],0x24);
    step_translation_clear(&c->step_translation[v->slot]);
    f->handled[FAST_TRAP_IDLE_POLL]++;
    FAST_EXIT_MARK(frame,FAST_EXIT_TRAP_SLOT(FAST_TRAP_IDLE_POLL));
    *elr+=4;return 1;
}
#endif


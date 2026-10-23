/* SPDX-License-Identifier: MIT */
/* WFI resume and the asynchronous entry (xnuboot_async_locked, xnuboot_async).
 * Part of probes/xnuboot.c's translation unit, included in order; not compiled on its own. */
#if SNAP_WFI_RESUME
static uint64_t wfi_resume_pa(void *ctx, uint64_t va) {(void)ctx; return guest_pa(va);}
static uint32_t wfi_resume_fetch(void *ctx, uint64_t pa) {(void)ctx; return *(const volatile uint32_t *)pa;}
_Static_assert(sizeof(((struct fast_trap_cpu *)0)->wfi) == WFI_RESULTS * sizeof(uint32_t),
               "one perf.fast[cpu].wfi counter per wfi_resume_result");
/* The EL2 timer tick's last step, under the service lock after timer_sync, the
 * EOI, the GPU tick, the host-stop poll and the device-reset check: rewind the
 * saved ELR_EL2 (frame[32], xnuboot.S async_lower/resume_lower) from WFI+4 to
 * the WFI when compat/wfi-resume.h says nothing is due. An IPI another CPU
 * posts after the release is picked up by the next tick, which timer_arm has
 * armed no later than the 1 ms poll, as for a vCPU that never woke.
 * SNAP_FAST_TIMER_IRQ's lock-free tick (fast_timer_irq) makes the same call
 * after the same steps: WFI_SHARED then reads the words other CPUs write under
 * the token atomically. The models' lines stay plain reads there: a line
 * another CPU changes during the scan can only make the decision resume once
 * more (the guest sleeps at most one more poll, as for a line raised after the
 * locked tick's release) or decline once more (XNU runs its idle exit). */
static void wfi_resume(struct context *c, uint64_t elr, uint64_t *frame, int stop)
{
    struct vcpu *v = vcpu_of(c);
    const struct params *p = c->params;
    uint64_t models = 0;
    for (unsigned i = 0; i < p->model_count; i++)
        models |= (uint64_t)device_irq_pending(&p->models[i], &c->model_state[i]);
    struct wfi_resume_state s = {
        .elr = elr,
        .stop = (uint64_t)(stop || guest_service_stopped(&c->services) != 0 ||
                           WFI_SHARED(c->user_view_failed) || WFI_SHARED(c->root_install_failures) ||
                           WFI_SHARED(c->kernel_view_failed)),
        .monitor = (uint64_t)(v->stepping.active || v->open_guards || c->user_execution[v->slot].pending),
        .last_return = v->last_kernel_return,
        .ipi_pending = WFI_SHARED(v->ipi.pending), .timer_pending = v->timer_pending,
        .timer_ctl = v->timer.ctl, .timer_cval = v->timer.cval, .guest_now = v->clock_guest_last,
        .model_irq_pending = v->model_irq_pending, .models_pending = models,
        .device_due = c->fast_timer_due[v->slot].physical,
        .wake_bound = v->watchdog_live ? guest_ipi_poll_delay(v->clock_rate.host_hz, UINT64_MAX) : 0,
    };
    __asm__ volatile("mrs %0, spsr_el2; mrs %1, hcr_el2; mrs %2, cnthp_ctl_el2; mrs %3, cnthp_cval_el2"
                     : "=r"(s.spsr), "=r"(s.hcr), "=r"(s.el2_ctl), "=r"(s.el2_cval));
    __asm__ volatile("isb; mrs %0, cntpct_el0" : "=r"(s.physical) :: "memory");
    const struct wfi_resume_mem m = {c, p->mem_low, p->mem_high, p->const_begin, p->const_end,
                                     wfi_resume_pa, wfi_resume_fetch};
    unsigned r = wfi_resume_decide(&s, &m);
    c->perf.fast[v->slot].wfi[r]++;
    if (r == WFI_RESUME) frame[32] = elr - 4;
}
#endif

/* Something asynchronous arrived while the guest was running. Either way the
 * guest is not coming back on its own, and what it was doing is the whole point
 * of catching it -- so EL1's fault state comes back with it. A guest spinning in
 * its own exception vectors leaves the reason in ESR_EL1.
 *
 * Three different findings used to share one name. IRQ, FIQ and SError all
 * landed here and all recorded EV_WATCHDOG, so "the guest was still running
 * when its time ran out" was printed for a bus error -- the guest touching a
 * Qualcomm peripheral that does not answer -- which is the opposite reading: a
 * kernel that needed longer against a kernel that touched something that is not
 * there. `which` comes from the vector, because IRQ and FIQ do not write
 * ESR_EL2 and reading it after one of them yields an earlier trap's syndrome.
 *
 * The timer is the only interrupt this probe routes to EL2, so an IRQ with
 * ISTATUS clear is a fact about the machine that was not known, and it is
 * recorded as that rather than folded into the watchdog. */
static int xnuboot_async_locked(uint64_t elr, uint64_t which, const uint64_t *frame)
{
    struct context *c = context_of();
    uint64_t esr, far, el1, ctl, physical;
    __asm__ volatile("mrs %0, esr_el1" : "=r"(esr));
    __asm__ volatile("mrs %0, far_el1" : "=r"(far));
    __asm__ volatile("mrs %0, elr_el1" : "=r"(el1));
    /* Read before watchdog_off(), which clears the enable bit and with it
     * ISTATUS -- the only evidence that the timer is what brought us here. */
    __asm__ volatile("mrs %0, cnthp_ctl_el2" : "=r"(ctl));
    __asm__ volatile("mrs %0, cntpct_el0" : "=r"(physical));
    if (which == ASYNC_IRQ && (c->params->gpu.flags & ADRENO_F_ENABLE)) {
        uint64_t pending;
        __asm__ volatile("mrs %0, icc_hppir1_el1" : "=r"(pending));
        if (pending == ADRENO_INTID) {
            gpu_irq(c);
            return device_reset_stop(c, elr, frame);
        }
    }
    if (which == ASYNC_IRQ && (ctl & CNTHP_ISTATUS) &&
        (int64_t)(run_deadline(c) - physical) > 0) {
        uint64_t pending;
        __asm__ volatile("mrs %0, icc_hppir1_el1" : "=r"(pending));
        if (pending == 26) {
            uint64_t intid;
            __asm__ volatile("mrs %0, icc_iar1_el1; dsb sy" : "=r"(intid) :: "memory");
            if (intid == 26) {
                vcpu_of(c)->timer_irqs++;
                vcpu_of(c)->timer_irq_pc = elr;
#if SNAP_FAST_TIMER_IRQ_CPU0
                /* vCPU 0's quiet ticks count from here (fast_cpu0_quiet). */
                if (!vcpu_of(c)->slot) c->root_ext->cpu0_tick.locked = physical;
#endif
#if SNAP_ANS_ASYNC
                /* Before timer_sync, so the re-arm sees the next deadline (N19). */
                int ans_stop = ans_async_tick(c, elr, frame);
#endif
                timer_sync(c); /* rearm/deassert physical level before EOI */
                timer_eoi(intid);
#if SNAP_ANS_ASYNC
                if (ans_stop) return 1;
#endif
                int thermal_stop=thermal_tick(c,physical);
                if (!thermal_stop && !vcpu_of(c)->slot && c->params->gpu.flags) gpu_tick(c, elr);
#if SNAP_CPU_DVFS || SNAP_GPU_DVFS
                if (!thermal_stop) dvfs_tick(c,physical);
#endif
                int host_stop=thermal_stop ? 0 : early_stop_host_tick(c,physical);
                /* Thermal trip exits this handler immediately, before any new
                 * GPU/host service. runtime_leave publishes the service stop. */
                if(thermal_stop) {
#if SNAP_CPU_DVFS || SNAP_GPU_DVFS
                    dvfs_cpu_restore(c);   /* C5: the CPU's at once; the GPU's at the stop, before quiesce */
#endif
                    uint64_t now=service_profile_clock();
                    if(early_stop_fire(&c->early_stop,now,vcpu_of(c)->watchdog_deadline,(unsigned)vcpu_of(c)->slot))
                        record(c,EV_EARLY_STOP,elr,c->early_stop.source<<32|(uint32_t)c->early_stop.reason,
                               c->early_stop.detail,c->early_stop.accepted_delay);
                    fill_regs(&vcpu_of(c)->async_regs,frame,0,elr,0);
                    vcpu_of(c)->async_captured=1;watchdog_off(c);return 1;
                }
                if(host_stop)timer_sync(c);
                int stop=device_reset_stop(c,elr,frame);
#if SNAP_WFI_RESUME
                wfi_resume(c,elr,(uint64_t *)frame,stop || host_stop);
#endif
                return stop;
            }
            if (intid < 1020) timer_eoi(intid);
        }
    }
    /* IRQ/FIQ do not supply a new syndrome or fault address. Keep those zero
     * in the snapshot rather than attributing stale EL1 state to this stop. */
    fill_regs(&vcpu_of(c)->async_regs, frame, 0, elr, 0);
    vcpu_of(c)->async_captured = 1;

    if (which == ASYNC_SERROR) {
        /* The one asynchronous vector that does write ESR_EL2: EC 0x2f, with
         * the syndrome valid only when IDS is clear. ELR_EL2 is the guest
         * instruction the error was taken against.
         *
         * FAR is deliberately not carried here. An SError has no faulting
         * address -- that is what asynchronous means -- so printing FAR_EL1
         * beside it would label the guest's last unrelated abort as this
         * error's address, which is the same class of lie this fix exists to
         * remove. ESR_EL1/ELR_EL1 go in instead: they say where the guest was
         * in its own terms. */
        uint64_t hyp_esr;
        __asm__ volatile("mrs %0, esr_el2" : "=r"(hyp_esr));
        record(c, EV_SERROR, elr, hyp_esr, esr, el1);
    } else if ((ctl & CNTHP_ISTATUS) &&
               early_stop_fire(&c->early_stop, physical, vcpu_of(c)->watchdog_deadline,
                               (unsigned)vcpu_of(c)->slot)) {
        /* An accepted early stop's deadline, strictly before the budget. */
        const struct early_stop_state *s = &c->early_stop;
        record(c, EV_EARLY_STOP, elr, s->source << 32 | (uint32_t)s->reason, s->detail,
               s->accepted_delay);
    } else if ((ctl & CNTHP_ISTATUS) &&
               (int64_t)(vcpu_of(c)->watchdog_deadline - physical) <= 0) {
        record(c, EV_WATCHDOG, elr, esr, far, el1);
    } else {
        record(c, EV_ASYNC, elr, which, esr, el1);
    }
    watchdog_off(c);
    return 1;
}

#if SNAP_FAST_TIMER_IRQ
#define FAST_IRQ_LOCKED (-1)        /* fast_timer_irq: take the locked path */
#define FAST_IRQ_LOCKED_OTHER (-2)  /* ...as ASYNC_IRQ_OTHER: IAR returned another INTID */
static int fast_timer_irq(struct context *c, uint64_t elr, uint64_t *frame);
#endif
int xnuboot_async(uint64_t elr, uint64_t which, const uint64_t *frame);
int xnuboot_async(uint64_t elr, uint64_t which, const uint64_t *frame)
{
    struct context *c = context_of();
#if SNAP_FAST_TIMER_IRQ
    /* A secondary's timer tick without the token (compat/fast-timer-irq.h):
     * 0 or 1 is its stop. Otherwise the locked path, profiled as this vector;
     * an acknowledge of another INTID reaches it as ASYNC_IRQ_OTHER, a stop. */
    int stop = which == ASYNC_IRQ ? fast_timer_irq(c, elr, (uint64_t *)frame) : FAST_IRQ_LOCKED;
    if (stop < 0) {
        uint64_t kind = stop == FAST_IRQ_LOCKED_OTHER ? ASYNC_IRQ_OTHER : which;
        if (!runtime_enter(c, frame, elr, SERVICE_PROFILE_ASYNC + which)) return 1;
        stop = runtime_leave(c, xnuboot_async_locked(elr, kind, frame));
    }
#else
    if (!runtime_enter(c, frame, elr, SERVICE_PROFILE_ASYNC + which)) return 1;
    int stop = runtime_leave(c, xnuboot_async_locked(elr, which, frame));
#endif
    if (stop && !vcpu_of(c)->async_captured) {
        fill_regs(&vcpu_of(c)->async_regs, frame, 0, elr, 0);
        vcpu_of(c)->async_captured = 1;
    }
    return stop;
}

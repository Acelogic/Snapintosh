/* SPDX-License-Identifier: MIT */
/* SNAP_WFI_RESUME (probes/xnuboot.c): a monitor-only EL2 timer tick that
 * interrupted the guest in an idle WFI puts it straight back into that WFI.
 *
 * Guest WFI runs natively (HCR_EL2.TWI is never set). timer_arm caps every
 * vCPU's EL2 deadline at the 1 ms IPI poll (guest_ipi_poll_delay), so an idle
 * vCPU takes ~1000 host-only ticks a second. An interrupt that wakes WFI
 * returns at ELR_EL2 = WFI+4, so each tick that delivers nothing still runs
 * XNU's whole idle exit and re-entry (about 12 trapped system-register
 * accesses with SNAP_KERNEL_SYSREG_ZERO, about 22 without). Setting ELR_EL2
 * back to the WFI instead is indistinguishable, for the guest, from a WFI that
 * had not woken yet, provided nothing is pending for it: WFI completes on a
 * pending interrupt whether or not PSTATE masks it, and the monitor raises the
 * guest's lines (HCR_EL2.VI/VF/VSE) only at an EL2 entry, which the next tick
 * (no more than wake_bound host ticks away) still is.
 *
 * Nothing here touches hardware: the monitor collects the state after the
 * tick's timer_sync, EOI, GPU tick, host-stop poll and device-reset check,
 * under the runtime service lock (so an IPI another CPU posts is either seen
 * here or found by the next tick, exactly as for a vCPU already asleep), and
 * supplies AT S1E1R and the word fetch. tools/test-wfi-resume.c runs the same
 * decision natively over every decline reason.
 *
 * Failure inventory: rewinding onto anything but a WFI word (WFE, WFIT, NOP,
 * data), onto a WFI outside const-sealed kernel text or outside guest RAM, onto
 * a WFI-valued word on the page before the PC's (possibly not executable), from
 * EL0, AArch32 or a non-EL1 mode, while single-stepping (SPSR.SS, the monitor's
 * step, an open guard, a user-entry probe), after a PC alignment or illegal
 * state (IL), after an indirect branch (BTYPE: ELR is then a branch target, not
 * a WFI's successor) or an emulated ERET to WFI+4 (an EL1 exception taken
 * after the WFI completed, now returning), while an IPI, the guest timer, a virtual line, a model
 * IRQ or a device deadline is due, while the run stops, or with no bounded
 * next tick (watchdog off, EL2 timer disabled or masked, or due later than the
 * poll). Each declines with a reason the monitor counts. */
#pragma once
#include <stdint.h>

#define WFI_RESUME_WORD UINT32_C(0xd503207f)     /* WFI; WFE is 0xd503205f */
#define WFI_SPSR_BTYPE (UINT64_C(3) << 10)
#define WFI_SPSR_IL (UINT64_C(1) << 20)
#define WFI_SPSR_SS (UINT64_C(1) << 21)
#define WFI_HCR_LINES ((UINT64_C(1) << 6) | (UINT64_C(1) << 7) | (UINT64_C(1) << 8)) /* VF VI VSE */

/* Index into struct fast_trap_cpu.wfi (compat/fast-trap.h). */
enum wfi_resume_result {
    WFI_RESUME,         /* re-enter the WFI: the caller sets ELR_EL2 to PC-4 */
    WFI_DECLINE_STATE,  /* stop, monitor step/guard/user probe; not AArch64 EL1t/EL1h;
                         * SS, IL or BTYPE set; misaligned PC */
    WFI_DECLINE_BUSY,   /* EL0, the PC is the last kernel ERET's target, or the word at
                         * PC-4 is not WFI: the guest was running */
    WFI_DECLINE_TEXT,   /* PC-4 untranslated or outside guest RAM, or a WFI outside
                         * const-sealed kernel text or on another 4 KiB page than PC */
    WFI_DECLINE_IPI,    /* a posted IPI */
    WFI_DECLINE_TIMER,  /* the guest's virtual timer is pending or its deadline passed */
    WFI_DECLINE_LINE,   /* HCR_EL2 VF/VI/VSE, a model IRQ (this vCPU's line or any
                         * model's) or a passed device deadline */
    WFI_DECLINE_WAKE,   /* no bounded next tick: watchdog off, EL2 timer disabled or
                         * masked, or due later than wake_bound */
    WFI_RESULTS
};

/* Everything read after the tick's bookkeeping, under the service lock. */
struct wfi_resume_state {
    uint64_t elr, spsr, hcr;         /* ELR_EL2 (the interrupted PC), SPSR_EL2, HCR_EL2 */
    uint64_t stop;                   /* this exit stops the run (or a peer already stopped it) */
    uint64_t monitor;                /* monitor single-step, open guard or user-entry probe */
    uint64_t last_return;            /* target of this vCPU's last kernel ERET (last_kernel_return) */
    uint64_t ipi_pending;            /* struct guest_ipi.pending */
    uint64_t timer_pending;          /* the synced virtual timer line */
    uint64_t timer_ctl, timer_cval;  /* the guest's CNTV_CTL/CVAL (struct guest_timer) */
    uint64_t guest_now;              /* the guest count timer_sync sampled */
    uint64_t model_irq_pending;      /* this vCPU's synced model IRQ line */
    uint64_t models_pending;         /* any model has an IRQ pending now */
    uint64_t physical;               /* CNTPCT_EL0 at the decision */
    uint64_t device_due;             /* next device deadline, host ticks; UINT64_MAX none */
    uint64_t el2_ctl, el2_cval;      /* CNTHP_CTL/CVAL as timer_sync left them */
    uint64_t wake_bound;             /* longest sleep accepted, host ticks; 0 = never resume */
};

/* Guest memory, supplied by the monitor (AT S1E1R; the stage-2 identity map). */
struct wfi_resume_mem {
    void *ctx;
    uint64_t mem_low, mem_high;      /* owned guest RAM, end exclusive */
    uint64_t text_begin, text_end;   /* const-sealed kernel text (params const_begin/end) */
    uint64_t (*guest_pa)(void *ctx, uint64_t va);   /* 0 = the walk faulted */
    uint32_t (*fetch)(void *ctx, uint64_t pa);
};

/* WFI_RESUME or the first decline reason, in the order of the enum's checks
 * below. Changes nothing; guest memory is read only for an aligned AArch64
 * EL1t/EL1h PC with no stop, step, guard, probe, SS, IL or BTYPE that is not
 * the last kernel ERET's target. */
static inline unsigned wfi_resume_decide(const struct wfi_resume_state *s,
                                         const struct wfi_resume_mem *m)
{
    unsigned mode = (unsigned)(s->spsr & 31);
    if (s->stop || s->monitor) return WFI_DECLINE_STATE;
    if (mode == 0) return WFI_DECLINE_BUSY;                         /* EL0t: running user code */
    if ((mode != 4 && mode != 5) ||                                 /* AArch64 EL1t/EL1h only */
        (s->spsr & (WFI_SPSR_BTYPE | WFI_SPSR_IL | WFI_SPSR_SS)) || (s->elr & 3) || s->elr < 4)
        return WFI_DECLINE_STATE;
    /* An emulated ERET (HCR_EL2.NV) resumed the guest exactly here: it is
     * returning from an EL1 exception taken at WFI+4 and must run on. */
    if (s->elr == s->last_return) return WFI_DECLINE_BUSY;
    uint64_t pa = m->guest_pa(m->ctx, s->elr - 4);
    if (!pa || (pa & 3) || pa < m->mem_low || m->mem_high < 4 || pa > m->mem_high - 4)
        return WFI_DECLINE_TEXT;
    if (m->fetch(m->ctx, pa) != WFI_RESUME_WORD) return WFI_DECLINE_BUSY;
    /* Same 4 KiB page as the PC: the WFI then shares the PC's stage-1 and
     * stage-2 execute permission, so a WFI-valued data word in a read-only,
     * non-executable const page just before an executable one is never
     * resumed onto (ELR at that page's first word is a branch target). */
    if (((s->elr - 4) ^ s->elr) >> 12 || pa < m->text_begin || m->text_end < 4 ||
        pa > m->text_end - 4)
        return WFI_DECLINE_TEXT;
    if (s->ipi_pending) return WFI_DECLINE_IPI;
    if (s->timer_pending || ((s->timer_ctl & 1) && (int64_t)(s->timer_cval - s->guest_now) <= 0))
        return WFI_DECLINE_TIMER;
    if ((s->hcr & WFI_HCR_LINES) || s->model_irq_pending || s->models_pending ||
        (s->device_due != UINT64_MAX && (int64_t)(s->device_due - s->physical) <= 0))
        return WFI_DECLINE_LINE;
    if (!s->wake_bound || s->wake_bound > (uint64_t)INT64_MAX || (s->el2_ctl & 3) != 1 ||
        (int64_t)(s->el2_cval - s->physical) > (int64_t)s->wake_bound)
        return WFI_DECLINE_WAKE;
    return WFI_RESUME;
}

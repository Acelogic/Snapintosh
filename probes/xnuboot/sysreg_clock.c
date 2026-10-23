/* SPDX-License-Identifier: MIT */
/* System-register encodings, the guest counter/timer/WFE registers and the
 * trapped EL1 register names.
 * Part of probes/xnuboot.c's translation unit, included in order; not compiled on its own. */

/* ISS layout for a trapped MSR/MRS: Op0[21:20] Op2[19:17] Op1[16:14]
 * CRn[13:10] Rt[9:5] CRm[4:1] Direction[0]. */
#define SYSREG(op0, op1, crn, crm, op2) \
    (((op0) << 20) | ((op2) << 17) | ((op1) << 14) | ((crn) << 10) | ((crm) << 1))
#define ISS_REG(iss)  ((iss) & ~((0x1fUL << 5) | 1UL))
#define ISS_RT(iss)   (((iss) >> 5) & 0x1f)
#define ISS_READ(iss) ((iss) & 1)

static uint64_t clock_counter(void *ctx)
{
    struct context *c = ctx;
    if (!vcpu_of(c)->clock_rate.host_hz || !vcpu_of(c)->clock_rate.guest_hz) return 0;
    uint64_t value;
    /* ISB supplies the ordered read required by the speculative-safe alias.
     * The converted count and all guest deadlines use the declared guest Hz. */
    __asm__ volatile("isb; mrs %0, cntvct_el0" : "=r"(value) :: "memory");
#if SNAP_LEAN_TRAPS
    uint64_t guest = lean_rate_sample(&vcpu_of(c)->clock_rate, value);
#else
    uint64_t guest = clock_rate_sample(&vcpu_of(c)->clock_rate, value);
#endif
    if (!vcpu_of(c)->clock_backend_reads++) {
        vcpu_of(c)->clock_raw_first = value;
        vcpu_of(c)->clock_guest_first = guest;
    }
    vcpu_of(c)->clock_raw_last = value;
    vcpu_of(c)->clock_guest_last = guest;
    return guest;
}

static int clock_control(void *ctx, uint64_t value)
{
    struct context *c = ctx;
    guest_event_configure(&vcpu_of(c)->clock_event, value, clock_counter(c));
#if SNAP_NATIVE_WFE
    /* WFE runs natively (TWE clear): the hardware event stream wakes it, its
     * period moved to the host counter rate by the nearest power of two. */
    uint64_t native = clock_event_host_control(value, vcpu_of(c)->clock_rate.host_hz,
                                               vcpu_of(c)->clock_rate.guest_hz);
#else
    /* WFE traps consume coalesced virtual events. Keep native access bits,
     * but never generate an event stream at the unscaled physical rate. */
    uint64_t native = value & ~4UL;
#endif
    __asm__ volatile("msr cntkctl_el1, %0; isb" :: "r"(native) : "memory");
    return 0;
}

static void clock_wfe(struct context *c)
{
    uint64_t now = clock_counter(c), physical;
    __asm__ volatile("mrs %0, cntpct_el0" : "=r"(physical));
    /* WFE may wake spuriously. Bound an EL2 polling slice to 1 ms so even
     * disabled event streams cannot mask host service for a whole run. */
    uint64_t budget = vcpu_of(c)->clock_rate.host_hz/1000 + 1;
    if (vcpu_of(c)->watchdog_live) {
        uint64_t left = (int64_t)(vcpu_of(c)->watchdog_deadline-physical)>0 ?
                        vcpu_of(c)->watchdog_deadline-physical : 0;
        if (left < budget) budget = left;
    }
    uint64_t ticks = guest_event_wait(&vcpu_of(c)->clock_event, now, UINT64_MAX);
    for (unsigned i=0; i<c->params->model_count; i++)
        ticks = device_model_wait(&c->params->models[i], &c->model_state[i], now, ticks);
    if (ticks != UINT64_MAX)
        budget = clock_rate_wait(&vcpu_of(c)->clock_rate, vcpu_of(c)->clock_raw_last, now+ticks, budget);
    if (guest_ipi_fiq(&vcpu_of(c)->ipi,guest_timer_pending(&vcpu_of(c)->timer, now)) || vcpu_of(c)->model_irq_pending) budget = 0;
    else if (vcpu_of(c)->timer.ctl == 1)
        budget = clock_rate_wait(&vcpu_of(c)->clock_rate, vcpu_of(c)->clock_raw_last, vcpu_of(c)->timer.cval, budget);
    uint64_t until = physical+budget, sample=physical;
    while ((int64_t)(until-sample)>0)
        __asm__ volatile("isb; mrs %0, cntpct_el0" : "=r"(sample));
    vcpu_of(c)->wfe_traps++;
    if (guest_event_consume(&vcpu_of(c)->clock_event, clock_counter(c))) vcpu_of(c)->event_wakes++;
    else vcpu_of(c)->wfe_early++;
    timer_sync(c);
}

#define SR_SCTLR_EL1 SYSREG(3, 0, 1, 0, 0)
#define SR_TTBR0_EL1 SYSREG(3, 0, 2, 0, 0)
#define SR_TTBR1_EL1 SYSREG(3, 0, 2, 0, 1)
#define SR_TCR_EL1   SYSREG(3, 0, 2, 0, 2)
#define SR_MAIR_EL1  SYSREG(3, 0, 10, 2, 0)
#define SR_ESR_EL1   SYSREG(3, 0, 5, 2, 0)
#define SR_FAR_EL1   SYSREG(3, 0, 6, 0, 0)
#define SR_APGAKEYLO_EL1 SYSREG(3, 0, 2, 3, 0)
#define SR_APGAKEYHI_EL1 SYSREG(3, 0, 2, 3, 1)


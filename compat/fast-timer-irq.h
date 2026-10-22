/* SPDX-License-Identifier: MIT */
/* SNAP_FAST_TIMER_IRQ (probes/xnuboot.c): the EL2 timer tick (PPI 26) of
 * vCPUs 1-5 without the service token.
 *
 * IPIs have no physical kick, so timer_arm caps every vCPU's EL2 deadline at
 * the 1 ms poll (guest_ipi_poll_delay) and each vCPU takes about 1000 ticks a
 * second; each took the token. In installed-fresh-20261019-v89 (509 s, six
 * vCPUs) the secondaries' 2.07M ticks waited 87.1 s for it and held it 3.95 s.
 *
 * Why a secondary's tick needs no token. Off vCPU 0, xnuboot_async_locked's
 * tick is timer_irqs/timer_irq_pc, timer_sync, the EOI, device_reset_stop and
 * wfi_resume: thermal_tick, gpu_tick and early_stop_host_tick return at once.
 * Of timer_sync only the model poll (device_model_wait: the watchdog model's
 * counter, the only model with a deadline) and device_latch_resets
 * (device_reset_mask) are shared, and both still run at least once a poll:
 * in vCPU 0's tick, which always takes the locked path and is armed no later
 * than the same 1 ms, and in the timer_sync after every device-model access
 * (the watchdog's register writes included, which re-arm that CPU at the new
 * bite). The rest reads or writes only this vCPU: its clock samples, guest
 * timer, timer_pending and lines (HCR_EL2 VF/VI and their assert/clear
 * counts), CNTHP_*_EL2 and its GIC CPU interface. The fast tick repeats that
 * part, except fast_timer_due, which keeps this vCPU's last synced deadline,
 * and declines (the locked path then runs the unchanged tick) whenever the
 * shared part could matter to this vCPU:
 *   - vCPU 0;
 *   - not the timer: CNTHP_CTL_EL2.ISTATUS clear, or ICC_HPPIR1_EL1 other
 *     than 26 (the Adreno INTID, an SGI, nothing);
 *   - fast_admitted fails (a stop or closed admission, a latched view or
 *     install failure, a monitor step, an open guard, a user-entry probe), or
 *     the watchdog is off (timer_arm would leave the level asserted);
 *   - the device deadline this vCPU last synced has passed or none was synced
 *     (0), or a device reset is latched: the locked timer_sync polls the model,
 *     device_reset_stop stops;
 *   - the run budget or an accepted early stop is due: the locked tail records
 *     and stops.
 * Taken, the tick acknowledges (IAR). Another INTID than 26 is completed
 * (below 1020) and returned as FAST_IRQ_OTHER: the monitor's locked tail then
 * records and stops exactly as the locked tick does after the same
 * acknowledge, so no interrupt is swallowed and none stays active. Then
 * timer_irqs, a fresh guest count, timer_pending, the lines (ipi.pending,
 * which other CPUs post under the token, read with an atomic load: a post
 * after the read is raised by the next tick, as one after the locked tick's
 * release is), the re-arm with this vCPU's last device deadline (timer_arm:
 * the guest timer, the run budget, the 1 ms poll) and only then the EOI: the
 * level must be low when the interrupt deactivates.
 *
 * Nothing here touches hardware: the monitor supplies the acknowledge, EOI,
 * counter, HCR and re-arm (fast_irq_hw), so tools/test-fast-timer-irq.c runs
 * the same gate and tick natively against a level-triggered PPI model.
 * root_ext->fast_irq[cpu] (probes/xnuboot.c, reported as OUT_FAST_IRQ) counts
 * every outcome. */
#pragma once
#include <stdint.h>
#include "clock.h"

#define FAST_IRQ_TIMER_INTID UINT64_C(26)           /* the EL2 physical timer PPI */
#define FAST_IRQ_INTID_LIMIT UINT64_C(1020)         /* IAR values from 1020 are not interrupts */
#define FAST_IRQ_ISTATUS (UINT64_C(1) << 2)         /* CNTHP_CTL_EL2.ISTATUS */
#define FAST_IRQ_HCR_VF (UINT64_C(1) << 6)
#define FAST_IRQ_HCR_VI (UINT64_C(1) << 7)

/* Index into struct fast_irq_cpu.result: what each IRQ entry became. */
enum fast_irq_result {
    FAST_IRQ_HANDLED,           /* the tick finished without the token */
    FAST_IRQ_DECLINE_CPU0,      /* vCPU 0: every IRQ */
    FAST_IRQ_DECLINE_TIMER,     /* ISTATUS clear or HPPIR not 26 */
    FAST_IRQ_DECLINE_STATE,     /* fast_admitted failed or the watchdog is off */
    FAST_IRQ_DECLINE_DEVICE,    /* device deadline passed or unsynced, or a reset latched */
    FAST_IRQ_DECLINE_DEADLINE,  /* the run budget or an accepted early stop is due */
    FAST_IRQ_OTHER,             /* IAR returned another INTID: completed, the locked tail stops */
    FAST_IRQ_RESULTS
};

/* Per-vCPU counters (root_ext->fast_irq), written by that CPU only. */
struct fast_irq_cpu {
    uint64_t result[FAST_IRQ_RESULTS];  /* IRQ entries by enum fast_irq_result */
    uint64_t resumed;   /* handled ticks that re-entered the guest's WFI (SNAP_WFI_RESUME) */
    uint64_t ticks;     /* CNTPCT ticks of the handled ticks, from the gate's sample to the return */
    uint64_t max;       /* ...the longest */
    uint64_t reserved[6];   /* zero */
} __attribute__((aligned(64)));
_Static_assert(sizeof(struct fast_irq_cpu) == 128, "two cache lines per CPU");

/* FAST_IRQ_CPU0 (probes/xnuboot.c sets it from SNAP_FAST_TIMER_IRQ_CPU0,
 * docs/SPEED-BATCH4-20261020.md): vCPU 0 also takes this tick while none of
 * its own duties is due. Its locked tick adds the thermal sample, the GPU
 * tick and the host poll to the secondaries' tick; the monitor computes
 * cpu0_quiet from their schedules (each written only by vCPU 0, under the
 * token, in that locked tick) and from a backstop that forces a locked tick
 * at least every FAST_IRQ_CPU0_LOCKED_MS, and the rest of this gate applies
 * unchanged. A quiet vCPU 0 tick is the secondaries' tick to the letter. */
#ifndef FAST_IRQ_CPU0
#define FAST_IRQ_CPU0 0
#endif
#if FAST_IRQ_CPU0
#define FAST_IRQ_CPU0_LOCKED_MS 8u
/* vCPU 0's quiet-gate state (root_ext, written by vCPU 0 only). */
struct fast_irq_cpu0 {
    uint64_t locked;            /* CNTPCT of vCPU 0's last locked tick (0: none yet) */
    uint64_t quiet;             /* gates that found nothing of vCPU 0's due */
    uint64_t host, thermal, gpu, backstop;   /* declines by the first duty found due */
    uint64_t reserved[2];
} __attribute__((aligned(64)));
_Static_assert(sizeof(struct fast_irq_cpu0) == 64, "one cache line");
#endif

/* The gate's inputs, sampled at the IRQ entry; only slot is read for vCPU 0
 * (without FAST_IRQ_CPU0, or while it is not quiet). */
struct fast_irq_gate {
    uint64_t slot;              /* vCPU */
    uint64_t ctl, hppir;        /* CNTHP_CTL_EL2, ICC_HPPIR1_EL1 */
    uint64_t physical;          /* CNTPCT_EL0 */
    uint64_t admitted;          /* fast_admitted */
    uint64_t watchdog_live;
    uint64_t device_due;        /* fast_timer_due[slot].physical: 0 unsynced, UINT64_MAX none */
    uint64_t reset_latched;     /* device_reset_mask nonzero */
    uint64_t deadline;          /* run_deadline: the budget or an accepted early stop */
#if FAST_IRQ_CPU0
    uint64_t cpu0_quiet;        /* vCPU 0: none of its own duties is due */
#endif
};

/* FAST_IRQ_HANDLED when the tick may run here, else the first decline reason
 * in the enum's order. Changes nothing. */
static inline unsigned fast_timer_irq_gate(const struct fast_irq_gate *g)
{
#if FAST_IRQ_CPU0
    if (!g->slot && !g->cpu0_quiet) return FAST_IRQ_DECLINE_CPU0;
#else
    if (!g->slot) return FAST_IRQ_DECLINE_CPU0;
#endif
    if (!(g->ctl & FAST_IRQ_ISTATUS) || g->hppir != FAST_IRQ_TIMER_INTID) return FAST_IRQ_DECLINE_TIMER;
    if (!g->admitted || !g->watchdog_live) return FAST_IRQ_DECLINE_STATE;
    if (g->reset_latched || g->physical >= g->device_due) return FAST_IRQ_DECLINE_DEVICE;
    if ((int64_t)(g->deadline - g->physical) <= 0) return FAST_IRQ_DECLINE_DEADLINE;
    return FAST_IRQ_HANDLED;
}

/* This CPU's operations, the locked tick's own. */
struct fast_irq_hw {
    void *ctx;
    uint64_t (*acknowledge)(void *ctx);             /* ICC_IAR1_EL1 */
    void (*complete)(void *ctx, uint64_t intid);    /* EOI, and DIR under EOImode */
    uint64_t (*counter)(void *ctx);                 /* clock_counter: the guest count, samples kept */
    uint64_t (*physical)(void *ctx);                /* CNTPCT_EL0 */
    uint64_t (*hcr)(void *ctx);
    void (*set_hcr)(void *ctx, uint64_t hcr);
    void (*arm)(void *ctx, uint64_t physical, uint64_t device_due);   /* timer_arm */
};
/* The ticking vCPU's fields that the locked tick reads or writes. */
struct fast_irq_vcpu {
    const struct guest_timer *timer;
    uint64_t *timer_pending;            /* the synced virtual timer line */
    const uint64_t *ipi_pending;        /* struct guest_ipi.pending: other CPUs post it */
    const uint64_t *model_irq_pending;  /* this vCPU's model line, synced by its own exits */
    uint64_t *timer_irqs, *timer_irq_pc;
    uint64_t *timer_asserts, *timer_clears, *model_irq_asserts, *model_irq_clears;
    uint64_t device_due;                /* fast_timer_due[slot].guest: guest ticks, UINT64_MAX none */
};

/* After the gate: the tick, in the locked tick's order. FAST_IRQ_HANDLED, or
 * FAST_IRQ_OTHER with that INTID completed and nothing else changed. */
static inline unsigned fast_timer_irq_tick(const struct fast_irq_hw *hw, const struct fast_irq_vcpu *v,
                                           uint64_t elr)
{
    uint64_t intid = hw->acknowledge(hw->ctx);
    if (intid != FAST_IRQ_TIMER_INTID) {
        if (intid < FAST_IRQ_INTID_LIMIT) hw->complete(hw->ctx, intid);
        return FAST_IRQ_OTHER;
    }
    (*v->timer_irqs)++;
    *v->timer_irq_pc = elr;
    /* timer_sync's per-vCPU statements; the model poll and reset latch stay
     * with the locked ticks (the gate declined if either is due here). */
    uint64_t now = hw->counter(hw->ctx), physical = hw->physical(hw->ctx);
    *v->timer_pending = (uint64_t)guest_timer_pending(v->timer, now);
    /* guest_interrupt_sync with no monitor step active (the gate's admission):
     * exception_step_fiq passes both lines through. */
    uint64_t hcr = hw->hcr(hw->ctx);
    int fiq = *v->timer_pending || __atomic_load_n(v->ipi_pending, __ATOMIC_RELAXED);
    int irq = *v->model_irq_pending != 0;
    if (fiq != !!(hcr & FAST_IRQ_HCR_VF)) {
        if (fiq) (*v->timer_asserts)++; else (*v->timer_clears)++;
    }
    if (irq != !!(hcr & FAST_IRQ_HCR_VI)) {
        if (irq) (*v->model_irq_asserts)++; else (*v->model_irq_clears)++;
    }
    uint64_t next = (hcr & ~(FAST_IRQ_HCR_VF | FAST_IRQ_HCR_VI)) |
                    (fiq ? FAST_IRQ_HCR_VF : 0) | (irq ? FAST_IRQ_HCR_VI : 0);
    if (next != hcr) hw->set_hcr(hw->ctx, next);
    /* Re-arm (deassert the level) before the EOI, as timer_sync then timer_eoi. */
    hw->arm(hw->ctx, physical, v->device_due);
    hw->complete(hw->ctx, intid);
    return FAST_IRQ_HANDLED;
}

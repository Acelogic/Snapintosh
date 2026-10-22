/* SPDX-License-Identifier: MIT */
/* SNAP_FAST_TIMER_IRQ (compat/fast-timer-irq.h): the gate and the lock-free
 * EL2 timer tick of vCPUs 1-5.
 *
 * Failure inventory this covers, each as checks with the expected result:
 *   - the gate: vCPU 0 taken; ISTATUS or HPPIR ignored (the Adreno INTID,
 *     SGIs, the neighbouring PPIs, the spurious 1023); a failed admission or
 *     an off watchdog taken; the device deadline at, before and after the
 *     sample, unsynced (0) or none (UINT64_MAX); a latched reset; the run
 *     deadline at, before and after the sample and across counter wrap; the
 *     reason order; an exhaustive differential against a restated oracle;
 *   - another INTID from IAR: every SGI and PPI and the Adreno INTID completed
 *     once with nothing else touched; 1020..1023 never completed;
 *   - the order: the EOI before the re-arm (a level-triggered PPI model counts
 *     each re-pend at deactivation), the re-arm with a sample taken before the
 *     guest count or another device deadline, timer_irqs/timer_irq_pc lost;
 *   - the lines: VF from the timer line or a posted IPI, VI from the model
 *     line, HCR_EL2's other bits kept, assert/clear counts per transition, no
 *     HCR write without a change;
 *   - a differential against a transcription of the locked tick's per-vCPU
 *     statements (xnuboot_async_locked's IAR, timer_irqs/timer_irq_pc,
 *     timer_sync's count, line and timer_arm, guest_interrupt_sync with no
 *     step, timer_eoi; compat/ipi.c and compat/exception.c linked), call order
 *     included, over random timer, IPI, model and HCR states;
 *   - a timeline: a secondary ticking at the 1 ms poll for 20 simulated
 *     seconds, its guest timer re-programmed whenever it fires, IPIs posted
 *     between ticks and acknowledged once raised, model lines toggling, until
 *     the run deadline. The fast copy (gate, then tick or the locked fall-back)
 *     and the locked copy stay identical, each IPI is raised by the first tick
 *     after its post, no PPI re-pends at EOI and the interface is idle after
 *     every tick; an INTID arriving between HPPIR and IAR is completed and
 *     handed back.
 * tools/test-fast-timer-irq.py binds the transcription to probes/xnuboot.c
 * and requires weakened headers to fail this test.
 *
 * cc -std=gnu11 -O1 -g -Wall -Wextra -Werror -fsanitize=address,undefined \
 *    -fno-sanitize-recover=all -Icompat tools/test-fast-timer-irq.c compat/clock.c \
 *    compat/ipi.c compat/exception.c -o build/test-fast-timer-irq && build/test-fast-timer-irq */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "fast-timer-irq.h"
#include "ipi.h"
#include "exception.h"

static unsigned long checks;
#define CHECK(x) do { checks++; if (!(x)) { \
    fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #x); exit(1); } } while (0)

#define ADRENO_INTID 0x14cu
#define POLL 1000u              /* host ticks per 1 ms poll; the guest count runs at the same rate */

/* One CPU: CNTPCT, HCR_EL2, CNTHP_CVAL/CTL and a GIC CPU interface with
 * PPI 26 level-triggered from CNTHP's condition, plus at most one other
 * INTID that arrived after HPPIR was read (IAR returns it first). */
struct cpu {
    uint64_t physical, hcr, cval, ctl, deadline;
    uint64_t other;             /* with has_other */
    int has_other, active26, active_other;
    unsigned acks, completes, repends, bad, hcr_writes, counts, arms;
    uint64_t arm_physical, arm_due;
    const struct guest_timer *timer;    /* what timer_arm reads of the vCPU */
    const uint64_t *timer_pending;
    char trace[24];
    unsigned steps;
};
/* The vCPU fields the tick reads or writes. */
struct vstate {
    struct guest_timer timer;
    uint64_t timer_pending;
    struct guest_ipi ipi;
    uint64_t model_irq_pending;
    uint64_t timer_irqs, timer_irq_pc, timer_asserts, timer_clears, model_irq_asserts, model_irq_clears;
    uint64_t device_due;
    struct exception_step stepping;     /* never active: the gate's admission */
};

static int level(const struct cpu *h) { return (h->ctl & 3) == 1 && h->physical >= h->cval; }
static void note(struct cpu *h, char c)
{
    if (h->steps < sizeof h->trace - 1) h->trace[h->steps++] = c;
    h->trace[h->steps] = 0;
}
static uint64_t hw_acknowledge(void *ctx)
{
    struct cpu *h = ctx;
    note(h, 'A'); h->acks++;
    if (h->has_other) {
        uint64_t intid = h->other;
        h->has_other = 0;
        if (intid < 1020) h->active_other = (int)intid;
        return intid;
    }
    if (level(h) && !h->active26) { h->active26 = 1; return 26; }
    return 1023;
}
static void hw_complete(void *ctx, uint64_t intid)
{
    struct cpu *h = ctx;
    note(h, 'E'); h->completes++;
    if (intid == 26) {
        if (!h->active26) h->bad++;
        h->active26 = 0;
        if (level(h)) h->repends++;     /* still asserted at deactivation: pends again */
    } else if (intid < 1020 && (int)intid == h->active_other) h->active_other = 0;
    else h->bad++;
}
static uint64_t hw_counter(void *ctx)
{
    struct cpu *h = ctx;
    note(h, 'C'); h->counts++;
    h->physical += 3;                   /* time passes; the guest count is CNTPCT */
    return h->physical;
}
static uint64_t hw_physical(void *ctx) { struct cpu *h = ctx; note(h, 'P'); return h->physical; }
static uint64_t hw_hcr(void *ctx) { struct cpu *h = ctx; note(h, 'H'); return h->hcr; }
static void hw_set_hcr(void *ctx, uint64_t v) { struct cpu *h = ctx; note(h, 'W'); h->hcr_writes++; h->hcr = v; }
/* timer_arm's shape: the earliest of the run deadline, the guest timer (when
 * enabled and not pending), the device deadline and the poll. */
static void hw_arm(void *ctx, uint64_t physical, uint64_t due)
{
    struct cpu *h = ctx;
    note(h, 'R'); h->arms++;
    h->arm_physical = physical; h->arm_due = due;
    uint64_t delay = (int64_t)(h->deadline - physical) > 0 ? h->deadline - physical : 0;
    if (h->timer->ctl == 1 && !*h->timer_pending) {
        uint64_t left = (int64_t)(h->timer->cval - physical) > 0 ? h->timer->cval - physical : 0;
        if (left < delay) delay = left;
    }
    if (due != UINT64_MAX) {
        uint64_t left = (int64_t)(due - physical) > 0 ? due - physical : 0;
        if (left < delay) delay = left;
    }
    if (POLL < delay) delay = POLL;
    h->cval = physical + delay;
    h->ctl = 1;
}

static unsigned fast(struct cpu *h, struct vstate *v, uint64_t elr)
{
    const struct fast_irq_hw hw = {h, hw_acknowledge, hw_complete, hw_counter, hw_physical,
                                   hw_hcr, hw_set_hcr, hw_arm};
    const struct fast_irq_vcpu s = {&v->timer, &v->timer_pending, &v->ipi.pending, &v->model_irq_pending,
        &v->timer_irqs, &v->timer_irq_pc, &v->timer_asserts, &v->timer_clears,
        &v->model_irq_asserts, &v->model_irq_clears, v->device_due};
    return fast_timer_irq_tick(&hw, &s, elr);
}

/* xnuboot_async_locked's tick on a vCPU 1-5, where thermal_tick, gpu_tick and
 * early_stop_host_tick return at once, less timer_sync's shared statements
 * (the model poll, the reset latch, the fast_timer_due update) and
 * device_reset_stop. tools/test-fast-timer-irq.py binds every line to
 * probes/xnuboot.c (xnuboot_async_locked, timer_sync, guest_interrupt_sync). */
static unsigned locked(struct cpu *h, struct vstate *v, uint64_t elr)
{
    uint64_t intid = hw_acknowledge(h);
    if (intid == 26) {
        v->timer_irqs++;
        v->timer_irq_pc = elr;
        uint64_t now = hw_counter(h);
        uint64_t physical = hw_physical(h);
        v->timer_pending = guest_timer_pending(&v->timer, now);
        uint64_t hcr = hw_hcr(h);
        int fiq = exception_step_fiq(&v->stepping, guest_ipi_fiq(&v->ipi, (int)v->timer_pending));
        int irq = exception_step_fiq(&v->stepping, (int)v->model_irq_pending);
        if (fiq != !!(hcr & (1UL << 6))) {
            if (fiq) v->timer_asserts++; else v->timer_clears++;
        }
        if (irq != !!(hcr & (1UL << 7))) {
            if (irq) v->model_irq_asserts++; else v->model_irq_clears++;
        }
        uint64_t next = (hcr & ~((1UL << 6) | (1UL << 7))) |
                        (fiq ? 1UL << 6 : 0) | (irq ? 1UL << 7 : 0);
        if (next != hcr) hw_set_hcr(h, next);
        hw_arm(h, physical, v->device_due);
        hw_complete(h, intid);
        return FAST_IRQ_HANDLED;
    }
    if (intid < 1020) hw_complete(h, intid);
    return FAST_IRQ_OTHER;
}

static uint64_t rng = 0x9e3779b97f4a7c15u;
static uint64_t next_random(void)
{
    rng ^= rng << 13; rng ^= rng >> 7; rng ^= rng << 17;
    return rng;
}

static unsigned oracle(const struct fast_irq_gate *g)
{
    int cpu0 = g->slot == 0;
    int timer = ((g->ctl >> 2) & 1) && g->hppir == 26;
    int state = g->admitted && g->watchdog_live;
    int device = !g->reset_latched && g->device_due > g->physical;
    int deadline = (int64_t)(g->deadline - g->physical) > 0;
    if (!cpu0 && timer && state && device && deadline) return FAST_IRQ_HANDLED;
    return cpu0 ? FAST_IRQ_DECLINE_CPU0 : !timer ? FAST_IRQ_DECLINE_TIMER : !state ? FAST_IRQ_DECLINE_STATE :
           !device ? FAST_IRQ_DECLINE_DEVICE : FAST_IRQ_DECLINE_DEADLINE;
}

static struct fast_irq_gate good(uint64_t physical)
{
    return (struct fast_irq_gate){.slot = 3, .ctl = 5, .hppir = 26, .physical = physical, .admitted = 1,
                                  .watchdog_live = 1, .device_due = UINT64_MAX, .deadline = physical + 1};
}

static void gate_table(void)
{
    const uint64_t p = UINT64_C(1) << 40;
    struct fast_irq_gate g = good(p);
    CHECK(fast_timer_irq_gate(&g) == FAST_IRQ_HANDLED);
    for (uint64_t slot = 1; slot < 6; slot++) { g = good(p); g.slot = slot; CHECK(fast_timer_irq_gate(&g) == FAST_IRQ_HANDLED); }
    g = good(p); g.slot = 0; CHECK(fast_timer_irq_gate(&g) == FAST_IRQ_DECLINE_CPU0);
    /* vCPU 0 is decided before anything else is looked at. */
    g = (struct fast_irq_gate){0}; CHECK(fast_timer_irq_gate(&g) == FAST_IRQ_DECLINE_CPU0);
    const uint64_t ctls[] = {0, 1, 3, 4, 6};            /* ISTATUS clear, or ISTATUS without the bit 2 */
    for (unsigned i = 0; i < sizeof ctls / sizeof *ctls; i++) {
        g = good(p); g.ctl = ctls[i];
        CHECK(fast_timer_irq_gate(&g) == ((ctls[i] & 4) ? FAST_IRQ_HANDLED : FAST_IRQ_DECLINE_TIMER));
    }
    g = good(p); g.ctl = 7; CHECK(fast_timer_irq_gate(&g) == FAST_IRQ_HANDLED);  /* masked yet pending: still the timer */
    for (uint64_t intid = 0; intid < 1024; intid++) {
        g = good(p); g.hppir = intid;
        CHECK(fast_timer_irq_gate(&g) == (intid == 26 ? FAST_IRQ_HANDLED : FAST_IRQ_DECLINE_TIMER));
    }
    g = good(p); g.hppir = ADRENO_INTID; CHECK(fast_timer_irq_gate(&g) == FAST_IRQ_DECLINE_TIMER);
    g = good(p); g.hppir = 26 | (UINT64_C(1) << 32); CHECK(fast_timer_irq_gate(&g) == FAST_IRQ_DECLINE_TIMER);
    g = good(p); g.admitted = 0; CHECK(fast_timer_irq_gate(&g) == FAST_IRQ_DECLINE_STATE);
    g = good(p); g.watchdog_live = 0; CHECK(fast_timer_irq_gate(&g) == FAST_IRQ_DECLINE_STATE);
    g = good(p); g.reset_latched = 1; CHECK(fast_timer_irq_gate(&g) == FAST_IRQ_DECLINE_DEVICE);
    g = good(p); g.device_due = 0; CHECK(fast_timer_irq_gate(&g) == FAST_IRQ_DECLINE_DEVICE);   /* never synced */
    g = good(p); g.device_due = p; CHECK(fast_timer_irq_gate(&g) == FAST_IRQ_DECLINE_DEVICE);   /* due now */
    g = good(p); g.device_due = p - 1; CHECK(fast_timer_irq_gate(&g) == FAST_IRQ_DECLINE_DEVICE);
    g = good(p); g.device_due = p + 1; CHECK(fast_timer_irq_gate(&g) == FAST_IRQ_HANDLED);
    g = good(p); g.deadline = p; CHECK(fast_timer_irq_gate(&g) == FAST_IRQ_DECLINE_DEADLINE);
    g = good(p); g.deadline = p - 1; CHECK(fast_timer_irq_gate(&g) == FAST_IRQ_DECLINE_DEADLINE);
    g = good(p); g.deadline = p + INT64_MAX; CHECK(fast_timer_irq_gate(&g) == FAST_IRQ_HANDLED);
    /* Across the counter's wrap the deadline compare is modular, as run_deadline's users' are. */
    g = good(UINT64_MAX - 10); g.deadline = 5; CHECK(fast_timer_irq_gate(&g) == FAST_IRQ_HANDLED);
    g = good(5); g.deadline = UINT64_MAX - 10; CHECK(fast_timer_irq_gate(&g) == FAST_IRQ_DECLINE_DEADLINE);
    /* The first failing reason, in the enum's order. */
    g = good(p); g.ctl = 0; g.admitted = 0; g.reset_latched = 1; g.deadline = 0;
    CHECK(fast_timer_irq_gate(&g) == FAST_IRQ_DECLINE_TIMER);
    g.ctl = 5; CHECK(fast_timer_irq_gate(&g) == FAST_IRQ_DECLINE_STATE);
    g.admitted = 1; CHECK(fast_timer_irq_gate(&g) == FAST_IRQ_DECLINE_DEVICE);
    g.reset_latched = 0; CHECK(fast_timer_irq_gate(&g) == FAST_IRQ_DECLINE_DEADLINE);
}

static void gate_exhaustive(void)
{
    const uint64_t slots[] = {0, 1, 5}, ctls[] = {0, 1, 4, 5, 7}, hppirs[] = {26, 25, 27, 0, 15, ADRENO_INTID, 1023};
    const uint64_t bases[] = {1000, UINT64_C(1) << 40, UINT64_MAX - 3};
    const int64_t due_at[] = {-1, 0, 1, 2};             /* relative; plus 0 and UINT64_MAX below */
    const int64_t deadline_at[] = {-2, -1, 0, 1, 2, INT64_MAX};
    unsigned long n = 0;
    for (unsigned a = 0; a < 3; a++) for (unsigned b = 0; b < 5; b++) for (unsigned c = 0; c < 7; c++)
    for (unsigned d = 0; d < 3; d++) for (unsigned e = 0; e < 4; e++) for (unsigned f = 0; f < 6; f++)
    for (unsigned flags = 0; flags < 8; flags++) for (unsigned special = 0; special < 3; special++) {
        struct fast_irq_gate g = {.slot = slots[a], .ctl = ctls[b], .hppir = hppirs[c], .physical = bases[d],
                                  .admitted = flags & 1, .watchdog_live = (flags >> 1) & 1,
                                  .reset_latched = (flags >> 2) & 1,
                                  .deadline = bases[d] + (uint64_t)deadline_at[f]};
        g.device_due = special == 0 ? bases[d] + (uint64_t)due_at[e] : special == 1 ? 0 : UINT64_MAX;
        if (special == 0 && bases[d] > UINT64_MAX - 4) g.device_due = UINT64_MAX - (uint64_t)(2 - due_at[e]);
        struct fast_irq_gate copy = g;
        CHECK(fast_timer_irq_gate(&g) == oracle(&g));
        CHECK(!memcmp(&copy, &g, sizeof g));
        n++;
    }
    printf("gate: %lu input combinations agree with the oracle\n", n);
}

static void reset_cpu(struct cpu *h, const struct vstate *v, uint64_t physical)
{
    *h = (struct cpu){.physical = physical, .ctl = 1, .cval = physical, .deadline = physical + 100 * POLL,
                      .timer = &v->timer, .timer_pending = &v->timer_pending};
}

static void other_intids(void)
{
    const uint64_t intids[] = {0, 1, 7, 15, 16, 25, 27, 30, ADRENO_INTID, 1019, 1020, 1021, 1022, 1023};
    for (unsigned i = 0; i < sizeof intids / sizeof *intids; i++) {
        struct vstate v = {.timer = {.cval = 50, .ctl = 1}, .device_due = UINT64_MAX};
        v.ipi.pending = 1;
        struct cpu h;
        reset_cpu(&h, &v, 1000);
        h.hcr = 0x80000000u;
        h.other = intids[i];
        h.has_other = 1;
        struct vstate before = v;
        CHECK(fast(&h, &v, 0x4000) == FAST_IRQ_OTHER);
        CHECK(!memcmp(&before, &v, sizeof v));                   /* nothing of the vCPU changed */
        CHECK(h.acks == 1 && !h.counts && !h.arms && !h.hcr_writes && h.hcr == 0x80000000u);
        CHECK(h.completes == (intids[i] < 1020) && !h.bad && !h.active_other);
        CHECK(h.active26 == 0 && level(&h));                     /* the timer is still pending for the locked tick */
        CHECK(!strcmp(h.trace, intids[i] < 1020 ? "AE" : "A"));
    }
    /* No interrupt at all (it went away between HPPIR and IAR): nothing completed. */
    struct vstate v = {.device_due = UINT64_MAX};
    struct cpu h;
    reset_cpu(&h, &v, 1000);
    h.ctl = 0;
    CHECK(fast(&h, &v, 0) == FAST_IRQ_OTHER && !h.completes && !h.counts && !h.arms);
}

static void same(const struct cpu *a, const struct vstate *va, const struct cpu *b, const struct vstate *vb)
{
    CHECK(!memcmp(va, vb, sizeof *va));
    CHECK(a->physical == b->physical && a->hcr == b->hcr && a->cval == b->cval && a->ctl == b->ctl);
    CHECK(a->active26 == b->active26 && a->active_other == b->active_other && a->has_other == b->has_other);
    CHECK(a->acks == b->acks && a->completes == b->completes && a->repends == b->repends &&
          a->hcr_writes == b->hcr_writes && a->counts == b->counts && a->arms == b->arms);
    CHECK(a->arm_physical == b->arm_physical && a->arm_due == b->arm_due);
    CHECK(!strcmp(a->trace, b->trace));
}

static void lines_table(void)
{
    /* fiq = timer line or IPI, irq = model line; counts move only on a change. */
    for (unsigned bits = 0; bits < 64; bits++) {
        int timer_due = bits & 1, ipi = (bits >> 1) & 1, model = (bits >> 2) & 1;
        int vf = (bits >> 3) & 1, vi = (bits >> 4) & 1, masked = (bits >> 5) & 1;
        struct vstate v = {.timer = {.cval = timer_due ? 900 : 5000, .ctl = masked ? 3 : 1},
                           .model_irq_pending = (uint64_t)model, .device_due = UINT64_MAX};
        v.ipi.pending = ipi ? 4 : 0;
        struct cpu h;
        reset_cpu(&h, &v, 1000);
        h.hcr = UINT64_C(0x8000000080000039) | (vf ? 1u << 6 : 0) | (vi ? 1u << 7 : 0);
        uint64_t other = h.hcr & ~UINT64_C(0xc0);
        CHECK(fast(&h, &v, 0x1234) == FAST_IRQ_HANDLED);
        int line = timer_due && !masked;
        CHECK(v.timer_pending == (uint64_t)line);
        CHECK(!!(h.hcr & (1u << 6)) == (line || ipi) && !!(h.hcr & (1u << 7)) == model);
        CHECK((h.hcr & ~UINT64_C(0xc0)) == other);
        CHECK(v.timer_asserts == (uint64_t)((line || ipi) && !vf) && v.timer_clears == (uint64_t)(!(line || ipi) && vf));
        CHECK(v.model_irq_asserts == (uint64_t)(model && !vi) && v.model_irq_clears == (uint64_t)(!model && vi));
        CHECK(h.hcr_writes == (unsigned)(((line || ipi) != vf) || (model != vi)));
        CHECK(v.timer_irqs == 1 && v.timer_irq_pc == 0x1234 && h.counts == 1 && h.arms == 1);
        CHECK(h.arm_physical == h.physical && h.arm_due == UINT64_MAX);   /* sampled after the count */
        CHECK(h.completes == 1 && !h.repends && !h.bad && !h.active26 && !level(&h));
        CHECK(!strcmp(h.trace, h.hcr_writes ? "ACPHWRE" : "ACPHRE"));
    }
    /* The device deadline the re-arm gets is this vCPU's last synced one. */
    struct vstate v = {.timer = {.ctl = 0}, .device_due = 1300};
    struct cpu h;
    reset_cpu(&h, &v, 1000);
    CHECK(fast(&h, &v, 0) == FAST_IRQ_HANDLED && h.arm_due == 1300 && h.cval == 1300);
}

static void differential(void)
{
    unsigned long handled = 0, other = 0;
    for (unsigned n = 0; n < 200000; n++) {
        struct vstate v = {0};
        uint64_t base = next_random() >> (next_random() & 1 ? 1 : 20);
        v.timer.ctl = next_random() & 3;
        v.timer.cval = base + (next_random() % 4000) - 2000;
        v.timer_pending = next_random() & 1;
        v.ipi.pending = (next_random() & 3) ? 0 : next_random() & 0xff;
        v.model_irq_pending = next_random() & 1;
        v.timer_irqs = next_random() & 0xffff;
        v.device_due = (next_random() & 1) ? UINT64_MAX : base + (next_random() % 3000);
        struct cpu a;
        reset_cpu(&a, &v, base);
        a.hcr = next_random();
        a.cval = base - (next_random() % 50);
        a.ctl = (next_random() & 7) ? 1 : 5;
        a.deadline = base + (next_random() % 5000);
        if (!(next_random() & 15)) {                     /* an INTID that is not the timer's */
            a.other = next_random() % 1023;
            a.other += a.other >= 26;
            a.has_other = 1;
        }
        struct vstate w = v;
        struct cpu b = a;
        b.timer = &w.timer;
        b.timer_pending = &w.timer_pending;
        uint64_t elr = next_random();
        unsigned rf = fast(&a, &v, elr), rl = locked(&b, &w, elr);
        CHECK(rf == rl);
        same(&a, &v, &b, &w);
        CHECK(!a.bad && !a.active_other);
        /* Within the gate's bounds the re-arm lies ahead, so the EOI never re-pends. */
        if (rf == FAST_IRQ_HANDLED && (int64_t)(a.deadline - a.arm_physical) > 0 &&
            (v.device_due == UINT64_MAX || (int64_t)(v.device_due - a.arm_physical) > 0))
            CHECK(!a.repends);
        if (rf == FAST_IRQ_HANDLED) { handled++; CHECK(!a.active26); }
        else other++;
    }
    printf("differential: 200000 random states, %lu ticks and %lu other INTIDs identical to the locked tick\n",
           handled, other);
}

/* One vCPU for 20 simulated seconds: the EL2 timer fires, the gate decides,
 * the tick (or the locked fall-back) runs, then the guest runs until the next
 * expiry: it re-programs a fired guest timer, acknowledges a raised IPI, and
 * other CPUs post IPIs and toggle the model line between ticks. */
static void timeline(void)
{
    struct vstate vf = {.timer = {.cval = 5500, .ctl = 1}, .device_due = UINT64_MAX}, vl = vf;
    struct cpu hf, hl;
    reset_cpu(&hf, &vf, 1000);
    reset_cpu(&hl, &vl, 1000);
    hf.deadline = hl.deadline = 20000u * POLL;
    hf.cval = hl.cval = 1000 + POLL;
    unsigned long ticks = 0, ipis = 0, guest_timers = 0, latency_max = 0;
    uint64_t posted_at = 0;
    unsigned results[FAST_IRQ_RESULTS] = {0};
    for (;;) {
        /* Between ticks: perhaps an IPI post (another CPU, under the token) and a model line change. */
        uint64_t now = hf.physical;
        if (!vf.ipi.pending && !(next_random() % 7)) {
            uint64_t at = now + 1 + next_random() % (hf.cval - now);
            vf.ipi.pending = vl.ipi.pending = 1;
            posted_at = at;
            ipis++;
        }
        if (!(next_random() % 97)) vf.model_irq_pending = vl.model_irq_pending = !vf.model_irq_pending;
        /* The EL2 timer fires. */
        CHECK(hf.cval == hl.cval && hf.ctl == 1);
        uint64_t fire = hf.physical = hl.physical = hf.cval;
        CHECK(level(&hf));
        struct fast_irq_gate g = {.slot = 1, .ctl = hf.ctl | 4, .hppir = 26, .physical = hf.physical, .admitted = 1,
                                  .watchdog_live = 1, .device_due = UINT64_MAX, .deadline = hf.deadline};
        unsigned r = fast_timer_irq_gate(&g);
        results[r]++;
        if (r == FAST_IRQ_DECLINE_DEADLINE) break;          /* the locked tail records and stops */
        CHECK(r == FAST_IRQ_HANDLED);
        hf.steps = hl.steps = 0;
        CHECK(fast(&hf, &vf, 0x5000 + ticks) == FAST_IRQ_HANDLED);
        CHECK(locked(&hl, &vl, 0x5000 + ticks) == FAST_IRQ_HANDLED);
        same(&hf, &vf, &hl, &vl);
        CHECK(!hf.repends && !hf.bad && !hf.active26 && !hf.active_other && !level(&hf));
        CHECK((int64_t)(hf.cval - hf.physical) > 0 && hf.cval - hf.physical <= POLL);
        if (vf.ipi.pending) {
            CHECK(hf.hcr & (1u << 6));                      /* raised by the first tick after the post */
            if (fire - posted_at > latency_max) latency_max = fire - posted_at;
        }
        ticks++;
        /* The guest runs: it takes a raised FIQ, re-programs its timer and acknowledges the IPI. */
        if (hf.hcr & (1u << 6)) {
            if (vf.timer_pending) {
                vf.timer.cval = vl.timer.cval = hf.physical + 200 + next_random() % 3000;
                guest_timers++;
            }
            vf.ipi.pending = vl.ipi.pending = 0;
        }
    }
    CHECK(ticks > 20000 && ipis > 1000 && guest_timers > 1000 && latency_max < POLL);
    /* A different INTID between HPPIR and IAR at the last tick: completed and handed back. */
    hf.cval = hl.cval = hf.physical;
    hf.other = hl.other = ADRENO_INTID;
    hf.has_other = hl.has_other = 1;
    hf.steps = hl.steps = 0;
    CHECK(fast(&hf, &vf, 0x6000) == FAST_IRQ_OTHER && locked(&hl, &vl, 0x6000) == FAST_IRQ_OTHER);
    same(&hf, &vf, &hl, &vl);
    CHECK(!hf.active_other && !hf.bad && level(&hf));
    printf("timeline: %lu lock-free ticks, %lu IPIs each raised within %lu host ticks of its post, "
           "%lu guest timer expiries, stop at the run deadline\n", ticks, ipis, latency_max, guest_timers);
}

/* The device deadline (the watchdog model's bite) on a secondary that syncs it
 * only at locked ticks, while the guest pets the watchdog from another CPU and
 * moves the bite later: the fast tick never runs at or past the deadline it
 * last synced, which is never later than the true one, so after the last pet
 * the locked fall-back finds the bite at the true deadline itself. */
static void timeline_device(void)
{
    struct vstate v = {.timer = {.ctl = 0}, .device_due = 0};  /* unsynced until a locked tick */
    struct cpu h;
    reset_cpu(&h, &v, 1000);
    h.deadline = UINT64_MAX / 2;
    h.cval = 1000 + POLL;
    uint64_t bite = 1000 + 400 * POLL + 123;
    unsigned long fast_ticks = 0, fallbacks = 0, pets = 0;
    for (;;) {
        h.physical = h.cval;
        struct fast_irq_gate g = {.slot = 2, .ctl = 5, .hppir = 26, .physical = h.physical, .admitted = 1,
                                  .watchdog_live = 1, .device_due = v.device_due, .deadline = h.deadline};
        unsigned r = fast_timer_irq_gate(&g);
        h.steps = 0;
        if (r == FAST_IRQ_HANDLED) {
            CHECK(h.physical < v.device_due && v.device_due <= bite);
            CHECK(fast(&h, &v, 0) == FAST_IRQ_HANDLED);
            fast_ticks++;
        } else {
            CHECK(r == FAST_IRQ_DECLINE_DEVICE);
            /* The locked tick: timer_sync polls the model. A reached bite
             * latches the reset and device_reset_stop stops the run. */
            if ((int64_t)(h.physical - bite) >= 0) break;
            v.device_due = bite;
            CHECK(locked(&h, &v, 0) == FAST_IRQ_HANDLED);
            fallbacks++;
        }
        CHECK(!h.repends && !h.bad && !level(&h));
        if (fast_ticks + fallbacks < 20000 && !(next_random() % 13)) {
            bite = h.physical + 400 * POLL + next_random() % POLL;
            pets++;
        }
    }
    CHECK(h.physical == bite && fast_ticks > 19000 && fallbacks > 10 && pets > 1000);
    printf("device deadline: %lu lock-free ticks, %lu locked re-syncs after %lu pets, the bite found at "
           "its deadline\n", fast_ticks, fallbacks, pets);
}

int main(void)
{
    gate_table();
    gate_exhaustive();
    other_intids();
    lines_table();
    differential();
    timeline();
    timeline_device();
    printf("%lu checks\nPASS\n", checks);
    return 0;
}

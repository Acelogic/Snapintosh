/* SPDX-License-Identifier: MIT */
/* compat/irq-forward.c: a level GIC SPI forwarded to a virtual AIC source.
 *
 * cc -std=gnu11 -O1 -g -fsanitize=address,undefined -Wall -Wextra -Werror -Icompat \
 *    tools/test-irq-forward.c compat/irq-forward.c compat/aic.c -o build/test-irq-forward \
 *    && build/test-irq-forward
 *
 * Part 1 is the draft's model (gpu-bringup-q1n1/test-irq-forward.c): a level
 * device line feeds a GIC SPI (enable/pending/active), which feeds the virtual
 * AIC level. The guest ISR acks the AIC event, clears the device and writes
 * MASK_CLR. Checks: no interrupt is lost, no storm occurs while the guest holds
 * the source masked, and the SPI is never left masked with the device idle.
 *
 * Part 2 runs the same line through the monitor's own AIC model (compat/aic.c)
 * as XNU drives it: EVENT auto-masks, MASK_CLR (bank 3) is where the monitor
 * calls irqfwd_unmasked, and the level is re-checked there. */
#include <stdlib.h>
#include <stdio.h>
#include "irq-forward.h"
#include "aic.h"
#include <string.h>
/* Always evaluated, unlike CHECK(): several checks carry the access they check. */
#define CHECK(x) do { if (!(x)) { fprintf(stderr, "FAIL %d: %s\n", __LINE__, #x); exit(1); } } while (0)

struct hw {
    int device, enabled, active, aic_level, completes, disables, enables;
    int bad_aic;
};
static void dis(void *c, uint32_t i) { struct hw *h = c; (void)i; h->enabled = 0; h->disables++; }
static void en(void *c, uint32_t i) { struct hw *h = c; (void)i; h->enabled = 1; h->enables++; }
static int pend(void *c, uint32_t i) { struct hw *h = c; (void)i; return h->device; }
static void done(void *c, uint32_t i) { struct hw *h = c; (void)i; h->active = 0; h->completes++; }
static int aic(void *c, uint32_t irq, int level)
{
    struct hw *h = c;
    if (h->bad_aic || irq != 975) return 1;
    h->aic_level = level;
    return 0;
}
/* The GIC delivers when enabled, pending (device high) and not active. */
static int gic_would_fire(const struct hw *h) { return h->enabled && h->device && !h->active; }

static void part2(void);
int main(void)
{
    struct hw h = {.enabled = 1};
    struct irqfwd_ops ops = {&h, dis, en, pend, done, aic};
    struct irqfwd f = {0};
    CHECK(irqfwd_add(&f, 332, 975) == IRQFWD_OK);
    CHECK(irqfwd_add(&f, 332, 976) == IRQFWD_BAD);       /* duplicate INTID */
    CHECK(irqfwd_add(&f, 710, 975) == IRQFWD_BAD);       /* duplicate AIC source */
    CHECK(irqfwd_add(&f, 27, 977) == IRQFWD_BAD);        /* PPI, not an SPI */
    CHECK(irqfwd_physical(&f, &ops, 26) == IRQFWD_NOT_OURS);

    /* 1. Device asserts; EL2 takes it; guest sees a level. */
    h.device = 1;
    CHECK(gic_would_fire(&h));
    h.active = 1;
    CHECK(irqfwd_physical(&f, &ops, 332) == IRQFWD_OK);
    CHECK(h.aic_level == 1 && !h.enabled && !h.active);
    CHECK(!gic_would_fire(&h));                          /* no storm while guest works */

    /* 2. Guest clears the device then unmasks: level drops, SPI re-armed. */
    h.device = 0;
    irqfwd_unmasked(&f, &ops, 975 / 32, 1u << (975 % 32));
    CHECK(h.aic_level == 0 && h.enabled && f.line[0].resampled == 1);

    /* 3. Device re-asserts before the guest unmasks: level kept, no extra trip. */
    h.device = 1; h.active = 1;
    CHECK(irqfwd_physical(&f, &ops, 332) == IRQFWD_OK);
    irqfwd_unmasked(&f, &ops, 975 / 32, 1u << (975 % 32)); /* ISR saw new work */
    CHECK(h.aic_level == 1 && !h.enabled && f.line[0].kept == 1);
    h.device = 0;
    irqfwd_unmasked(&f, &ops, 975 / 32, 1u << (975 % 32));
    CHECK(h.aic_level == 0 && h.enabled);

    /* 4. Unrelated unmask bits and idle unmasks change nothing. */
    int before = h.enables;
    irqfwd_unmasked(&f, &ops, 975 / 32, 1u << ((975 + 1) % 32));
    irqfwd_unmasked(&f, &ops, 975 / 32, 1u << (975 % 32));
    CHECK(h.enables == before);

    /* 5. A stale delivery while asserted is completed and counted, not doubled. */
    h.device = 1; h.active = 1;
    irqfwd_physical(&f, &ops, 332);
    h.active = 1;
    CHECK(irqfwd_physical(&f, &ops, 332) == IRQFWD_OK && f.line[0].spurious == 1);
    CHECK(!h.active && f.line[0].fired == 3);

    /* 6. No virtual source: stays masked, reports BAD. */
    irqfwd_quiesce(&f, &ops);
    CHECK(!h.enabled && h.aic_level == 0 && f.line[0].state == IRQFWD_IDLE);
    h.bad_aic = 1; h.enabled = 1; h.active = 1;
    CHECK(irqfwd_physical(&f, &ops, 332) == IRQFWD_BAD && !h.enabled && !h.active);

    part2();
    printf("PASS: irq-forward (fired %llu, kept %llu, resampled %llu, spurious %llu) and the AIC loop\n",
           (unsigned long long)f.line[0].fired, (unsigned long long)f.line[0].kept,
           (unsigned long long)f.line[0].resampled, (unsigned long long)f.line[0].spurious);
    return 0;
}

/* --- Part 2: through compat/aic.c ------------------------------------------ */
static struct aic_config cfg = {1024, 0xa, 0x14a00};   /* flat die, event register */
static struct aic_state st;
static struct hw h2;
static int aic2(void *c, uint32_t irq, int level)
{
    (void)c;
    return aic_set_level(&cfg, &st, irq, level) != AIC_OK;
}
static uint64_t mmio(uint64_t off, int write, uint64_t v)
{
    CHECK(aic_access(&cfg, &st, off, 4, write, &v) == AIC_OK);
    return v;
}
#define WORD (975 / 32)
#define BIT (1u << (975 % 32))
/* What the monitor does after a MASK_CLR write reached the AIC model. */
static void mask_clr(struct irqfwd *f, const struct irqfwd_ops *o, uint32_t bits)
{
    mmio(0x14600 + 4 * WORD, 1, bits);
    irqfwd_unmasked(f, o, WORD, bits);
}
/* EL2 took the SPI: EOI/DIR and forward, as gpu_irq does. */
static void take(struct irqfwd *f, const struct irqfwd_ops *o)
{
    CHECK(h2.enabled && h2.device && !h2.active);
    h2.active = 1;
    CHECK(irqfwd_physical(f, o, 0x14c) == IRQFWD_OK);
    CHECK(!h2.active && !h2.enabled);
}
static void part2(void)
{
    struct irqfwd f = {0};
    struct irqfwd_ops o = {&h2, dis, en, pend, done, aic2};
    memset(&st, 0, sizeof(st));
    h2 = (struct hw){.enabled = 1};
    CHECK(irqfwd_add(&f, 0x14c, 975) == IRQFWD_OK);
    mmio(0x14, 1, 1);                                   /* AIC enabled */

    /* Stage 4 without a driver: the source stays masked in the guest. A
     * self-test (or a real interrupt) raises the level; nothing is delivered,
     * nothing storms, and quiesce drops it. */
    h2.device = 1;
    take(&f, &o);
    CHECK(!aic_pending(&cfg, &st) && (st.level[WORD] & BIT));
    CHECK(!h2.enabled);                                /* SPI held masked */
    irqfwd_quiesce(&f, &o);
    CHECK(!(st.level[WORD] & BIT) && f.line[0].state == IRQFWD_IDLE);
    h2.device = 0; h2.enabled = 1;

    /* A driver: unmask 975; nothing pending yet, so the unmask is a no-op. */
    unsigned enables = (unsigned)h2.enables;
    mask_clr(&f, &o, BIT);
    CHECK((unsigned)h2.enables == enables && !aic_pending(&cfg, &st));
    /* The GPU asserts; the guest takes the AIC event (auto-masks 975). */
    h2.device = 1;
    take(&f, &o);
    CHECK(aic_pending(&cfg, &st));
    CHECK(mmio(0x14a00, 0, 0) == (0x10000u | 975));
    CHECK(!aic_pending(&cfg, &st));                    /* EVENT masked it */
    /* The ISR clears RBBM_INT_0_STATUS, then unmasks: level drops, SPI armed. */
    h2.device = 0;
    mask_clr(&f, &o, BIT);
    CHECK(!(st.level[WORD] & BIT) && h2.enabled && !aic_pending(&cfg, &st));
    CHECK(f.line[0].resampled == 1);
    /* The GPU asserts again while the ISR still runs: the unmask sees the line
     * still pending, keeps the level, and the guest gets the next event with no
     * physical round trip; the SPI stays masked until the line is quiet. */
    h2.device = 1;
    take(&f, &o);
    CHECK(mmio(0x14a00, 0, 0) == (0x10000u | 975));
    mask_clr(&f, &o, BIT);                              /* device still high */
    CHECK((st.level[WORD] & BIT) && !h2.enabled && f.line[0].kept == 1);
    CHECK(aic_pending(&cfg, &st));
    CHECK(mmio(0x14a00, 0, 0) == (0x10000u | 975));
    h2.device = 0;
    mask_clr(&f, &o, BIT);
    CHECK(!(st.level[WORD] & BIT) && h2.enabled && !aic_pending(&cfg, &st));
    /* Unmasking another source in the same word leaves the GPU line alone. */
    h2.device = 1;
    take(&f, &o);
    mask_clr(&f, &o, BIT >> 1);
    CHECK((st.level[WORD] & BIT) && !h2.enabled);
    /* A level raised while the AIC is globally off is delivered once enabled. */
    mmio(0x14, 1, 0);
    CHECK(!aic_pending(&cfg, &st));
    mmio(0x14, 1, 1);
    mask_clr(&f, &o, BIT);                              /* device still high: kept */
    CHECK(aic_pending(&cfg, &st));
}

/* SPDX-License-Identifier: MIT */
/* Level-triggered GIC SPI -> virtual AIC source forwarding.
 *
 * The guest never sees the GIC. A forwarded SPI is taken at EL2 (HCR_EL2.IMO),
 * masked at the distributor, completed (EOI+DIR) and turned into a virtual AIC
 * level. The AIC's EVENT read auto-masks the source; the guest's driver clears
 * the device and writes MASK_CLR. That unmask is the resample point: if the
 * GIC still shows the line pending the level stays up and the SPI stays masked
 * (the guest gets the next event without another physical round trip);
 * otherwise the level drops and the SPI is re-enabled, so a device that
 * re-asserts later fires again.
 *
 * Pure model: all hardware effects go through ops, so it runs natively under
 * sanitizers (tools/test-irq-forward.c). Callers serialize with the AIC model
 * lock (the monitor's guest service lock). Stage 4 forwards one line: the
 * Adreno's INTID 0x14C (glymur.dtsi GIC_SPI 300, level high) to AIC 975, the
 * source the withdrawn /arm-io/sgx node held (compat/adreno.h). */
#pragma once
#include <stdint.h>

#define IRQFWD_MAX 8

struct irqfwd_ops {
    void *ctx;
    void (*gic_disable)(void *ctx, uint32_t intid);   /* GICD_ICENABLER + RWP wait */
    void (*gic_enable)(void *ctx, uint32_t intid);    /* GICD_ISENABLER */
    int (*gic_pending)(void *ctx, uint32_t intid);    /* GICD_ISPENDR bit */
    void (*gic_complete)(void *ctx, uint32_t intid);  /* ICC_EOIR1 (+ ICC_DIR if EOImode) */
    int (*aic_level)(void *ctx, uint32_t aic_irq, int level); /* device_irq_set_level */
};

enum irqfwd_state { IRQFWD_IDLE, IRQFWD_ASSERTED };

struct irqfwd_line {
    uint32_t intid, aic_irq;
    enum irqfwd_state state;
    uint64_t fired, kept, resampled, spurious;
};

struct irqfwd {
    struct irqfwd_line line[IRQFWD_MAX];
    unsigned count;
};

enum irqfwd_result { IRQFWD_OK, IRQFWD_NOT_OURS, IRQFWD_BAD };

/* Validate and record one mapping: SPI INTIDs 32..1019, distinct on both sides. */
enum irqfwd_result irqfwd_add(struct irqfwd *f, uint32_t intid, uint32_t aic_irq);
/* EL2 IRQ path, after ICC_IAR1 returned `intid`. NOT_OURS leaves it untouched. */
enum irqfwd_result irqfwd_physical(struct irqfwd *f, const struct irqfwd_ops *ops,
                                   uint32_t intid);
/* After the AIC model accepted a MASK_CLR write: `bits` of word `word` unmasked. */
void irqfwd_unmasked(struct irqfwd *f, const struct irqfwd_ops *ops,
                     unsigned word, uint32_t bits);
/* Guest reset / monitor exit: disable every SPI and drop every level. */
void irqfwd_quiesce(struct irqfwd *f, const struct irqfwd_ops *ops);

/* SPDX-License-Identifier: MIT */
/* SNAP_FAST_IPI (probes/xnuboot.c, docs/FAST-IPI-20261019.md): the Apple IPI
 * registers (IPI_RR_LOCAL, IPI_RR_GLOBAL, IPI_SR) without the service token.
 *
 * guest_ipi_route (compat/ipi.c) is the locked handler's whole decision. Its
 * inputs are every vCPU's struct guest_ipi, the affinities (fixed once
 * prepared), the runnable mask (from the lifecycle word, read atomically) and
 * the trapping vCPU's slot; its effects are on the trapping vCPU's own reads
 * and acks, and on one target's pending, coalesced, requests and last_request.
 * fast_ipi_access repeats it decision for decision. The words other CPUs write
 * change atomically here and, under the define, in compat/ipi.c too, so a
 * lock-free access and a locked one on another CPU never tear them:
 *   - a post exchanges the target's pending to 1 (release) and adds the old
 *     value to coalesced: a fresh request is never lost, and every request is
 *     counted once, fresh or coalesced;
 *   - an acknowledgement (IPI_SR write of 1) exchanges pending to 0 and counts
 *     an ack only when it cleared one;
 *   - reads and acks are written only by their own vCPU.
 * So requests == coalesced + acks + pending at every quiescent point.
 * Wherever guest_ipi_route would refuse (a configuration check, an RR read, a
 * value outside the register's bits, an unknown or non-runnable target) the
 * access declines with nothing changed, and the locked path repeats it, records
 * EV_IPI_FAILED and stops as before. Nothing here touches hardware, so
 * tools/test-fast-ipi.c runs it natively against guest_ipi_route. */
#pragma once
#include <stdint.h>
#include "ipi.h"

/* Index into struct fast_ipi_cpu.result. */
enum fast_ipi_result {
    FAST_IPI_SR_READ,           /* IPI_SR read: this vCPU's pending */
    FAST_IPI_SR_WRITE,          /* IPI_SR write of 0, or of 1 acknowledging */
    FAST_IPI_REQUEST_LOCAL,     /* IPI_RR_LOCAL posted */
    FAST_IPI_REQUEST_GLOBAL,    /* IPI_RR_GLOBAL posted */
    FAST_IPI_DECLINE_STATE,     /* the monitor's fast-trap admission failed */
    FAST_IPI_DECLINE_REFUSED,   /* guest_ipi_route refuses: the locked path records and stops */
    FAST_IPI_DECLINE_TARGET,    /* no runnable vCPU has the target affinity */
    FAST_IPI_RESULTS
};
#define FAST_IPI_DECLINES FAST_IPI_DECLINE_STATE   /* results from here on decline */

/* Per-vCPU counters (root_ext->fast_ipi), written by that CPU only. */
struct fast_ipi_cpu {
    uint64_t result[FAST_IPI_RESULTS];  /* IPI register traps by enum fast_ipi_result */
    uint64_t ticks;         /* CNTPCT ticks of the handled ones, admission to return */
    uint64_t max;           /* ...the longest */
    uint64_t reserved[7];   /* zero */
} __attribute__((aligned(64)));
_Static_assert(sizeof(struct fast_ipi_cpu) == 128, "two cache lines per CPU");

/* compat/ipi.c request(), with the shared words changed atomically. */
static inline void fast_ipi_post(struct guest_ipi *ipi, uint64_t value)
{
    uint64_t old = __atomic_exchange_n(&ipi->pending, 1, __ATOMIC_ACQ_REL);
    __atomic_fetch_add(&ipi->coalesced, old, __ATOMIC_RELAXED);
    __atomic_fetch_add(&ipi->requests, 1, __ATOMIC_RELAXED);
    __atomic_store_n(&ipi->last_request, value, __ATOMIC_RELAXED);
}
/* An IPI_SR write of 1: clears pending, and counts an ack when it did. */
static inline void fast_ipi_acknowledge(struct guest_ipi *ipi)
{
    if (__atomic_exchange_n(&ipi->pending, 0, __ATOMIC_ACQ_REL)) ipi->acks++;
}

/* guest_ipi_route(states, affinities, count, runnable, source, reg, read,
 * value) without the token: a result below FAST_IPI_DECLINES with the same
 * effects and *value, or a decline with nothing changed. */
static inline unsigned fast_ipi_access(struct guest_ipi *const states[], const uint64_t affinities[],
                                       unsigned count, uint64_t runnable, unsigned source,
                                       uint64_t reg, int read, uint64_t *value)
{
    if (reg != IPI_RR_LOCAL && reg != IPI_RR_GLOBAL && reg != IPI_SR) return FAST_IPI_DECLINE_REFUSED;
    if (!states || !affinities || !value || !count || count > 64 || source >= count ||
        (count < 64 && runnable >> count) || !(runnable & (UINT64_C(1) << source)) ||
        (read != 0 && read != 1)) return FAST_IPI_DECLINE_REFUSED;
    for (unsigned i = 0; i < count; i++) {
        if (!states[i] || __atomic_load_n(&states[i]->pending, __ATOMIC_RELAXED) > 1 ||
            (affinities[i] & UINT64_C(0xff00ff0000))) return FAST_IPI_DECLINE_REFUSED;
        for (unsigned j = 0; j < i; j++)
            if (states[i] == states[j] || (affinities[i] & 0xffff) == (affinities[j] & 0xffff))
                return FAST_IPI_DECLINE_REFUSED;
    }
    if (reg == IPI_SR) {
        struct guest_ipi *self = states[source];
        if (read) {
            *value = __atomic_load_n(&self->pending, __ATOMIC_ACQUIRE);
            self->reads++;
            return FAST_IPI_SR_READ;
        }
        if (*value & ~UINT64_C(1)) return FAST_IPI_DECLINE_REFUSED;
        if (*value) fast_ipi_acknowledge(self);
        return FAST_IPI_SR_WRITE;
    }
    if (read) return FAST_IPI_DECLINE_REFUSED;
    uint64_t allowed = reg == IPI_RR_LOCAL ? 0xff : 0xff00ff;
    if (*value & ~allowed) return FAST_IPI_DECLINE_REFUSED;
    uint64_t target = (*value & 0xff) |
                      (reg == IPI_RR_LOCAL ? (affinities[source] & 0xff00) : ((*value >> 8) & 0xff00));
    for (unsigned i = 0; i < count; i++)
        if ((affinities[i] & 0xffff) == target) {
            if (!(runnable & (UINT64_C(1) << i))) return FAST_IPI_DECLINE_TARGET;
            fast_ipi_post(states[i], *value);
            return reg == IPI_RR_LOCAL ? FAST_IPI_REQUEST_LOCAL : FAST_IPI_REQUEST_GLOBAL;
        }
    return FAST_IPI_DECLINE_TARGET;
}

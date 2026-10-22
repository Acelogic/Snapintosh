/* SPDX-License-Identifier: MIT */
/* The kext's side of GPU hang recovery (-DADRENO_GPU_RECOVER=1; ABI compat/adreno-guest.h ADRENO_GUEST_RECOVER; the
 * monitor's side is compat/adreno-ib.c SNAP_ADRENO_RECOVER; failure modes agents/gpu-recovery/FAILURE-MODES.md R14,
 * R19, R26-R29). Header-only and libc-free: AdrenoX2.cpp (under fSubmitLock) and the host tests
 * (tools/test-adreno-recover-e2e.c, against the monitor model) run the same code.
 *  - discovery: QUERY once at start; a monitor without RECOVER refuses it and everything stays as before;
 *  - the async bound: the monitor's hard limit + 2 s while it answers PENDING (R19);
 *  - un-latching (R27, R28): with the fail-fast latch set by a GPU result, at most one SETTLE per 100 ms; when the
 *    monitor answers 0 (the CP proven idle, after a reset if it needed one) the latch and the UNCERTAIN state of the
 *    package slots are cleared and submissions resume. Lists frozen by the uncertain submission stay frozen.
 *  - the IOGPU status word a failed kernel command completes with (R26; IOGPUFamily/IOGPU.framework 26A428). */
#ifndef SNAP_ADRENO_RECOVER_GUEST_H
#define SNAP_ADRENO_RECOVER_GUEST_H
#include <stdint.h>
#include "adreno-guest.h"
#include "adreno-submit.h"
#include "adreno-ib-async.h"
#include "adreno-ib-command.h"

#if !ADRENO_GPU_RECOVER
#error "adreno-recover-guest.h needs -DADRENO_GPU_RECOVER=1"
#endif

#define ADRENO_RECOVER_SETTLE_INTERVAL_US 100000u
#define ADRENO_RECOVER_MARGIN_US 2000000u          /* past the hard limit: the tick's 1 s grace + 1 s */
/* IOGPU 26A428 command buffer status words (IOGPUCommandQueue::setSubmissionError / the fence's +0xc8 status;
 * IOGPU.framework initWithIOGPUError: maps them to MTLCommandBufferError; FAILURE-MODES.md "IOGPU status codes"). */
#define ADRENO_IOGPU_STATUS_TIMEOUT 2u             /* "Caused GPU Timeout Error": Timeout, one strike */
#define ADRENO_IOGPU_STATUS_HANG 3u                /* "Caused GPU Hang Error": Timeout, one strike */
#define ADRENO_IOGPU_STATUS_VICTIM 5u              /* "Discarded (victim of GPU error/recovery)": Internal, no strike */
#define ADRENO_IOGPU_STATUS_INVALID 0xau           /* "Invalid Input": Internal (what the kext always set before) */
#define ADRENO_IOGPU_STATUS_PAGE_FAULT 0xbu        /* PageFault, one strike */

struct adreno_recover_guest {
    uint32_t abi, level, hard_s, dead;              /* QUERY's answer; abi 0: no RECOVER (an older monitor) */
    uint64_t epoch;                                 /* resets the monitor reported */
    uint64_t last_settle_us;
    uint64_t queries, settles, settled, unlatched, settle_resets, refused;
};
struct adreno_recover_ops {
    void *ctx;
    void (*hvc)(void *ctx, uint64_t regs[4]);       /* HVC #ADRENO_GUEST_HVC: x0..x3 in, x0..x3 out */
};

/* Discovery (R29): 1 when the monitor answers QUERY with this ABI and sane fields; 0 otherwise (g stays zero but for
 * the query count, so every other function here is a no-op). */
static inline int adreno_recover_guest_probe(const struct adreno_recover_ops *ops, struct adreno_recover_guest *g)
{
    uint8_t *b = (uint8_t *)g;
    for (unsigned long i = 0; i < sizeof *g; i++) b[i] = 0;
    uint64_t r[4];
    r[0] = ADRENO_GUEST_RECOVER; r[1] = ADRENO_RECOVER_QUERY; r[2] = 0; r[3] = 0;
    ops->hvc(ops->ctx, r);
    g->queries = 1;
    const uint32_t level = (uint32_t)(r[1] >> 8) & 0xff, hard = (uint32_t)(r[1] >> 16) & 0xff;
    if ((int64_t)r[0] != 0 || (r[1] & 0xff) != ADRENO_RECOVER_ABI || r[1] >> 24 || level < 1 || level > 2 || !hard ||
        hard > ADRENO_IB_HARD_SECONDS_MAX || r[3] > ADRENO_RECOVER_STATE_DEAD) return 0;
    g->abi = ADRENO_RECOVER_ABI;
    g->level = level;
    g->hard_s = hard;
    g->epoch = r[2];
    g->dead = r[3] == ADRENO_RECOVER_STATE_DEAD;
    return 1;
}

/* The kext's async bound (R19): the monitor's hard limit + ADRENO_RECOVER_MARGIN_US, or 0 (ADRENO_IB_ASYNC_LIMIT_US). */
static inline uint64_t adreno_recover_guest_limit_us(const struct adreno_recover_guest *g)
{
    return g->abi ? (uint64_t)g->hard_s * 1000000u + ADRENO_RECOVER_MARGIN_US : 0;
}

/* Un-latch (R27, R28), caller-serialized, with *latch set. dma_ok: the stamp DMA (and the IB arena's, when there is
 * one) is still prepared, i.e. the latch came from a GPU result, not from a failed DMA completion at teardown. One
 * SETTLE per ADRENO_RECOVER_SETTLE_INTERVAL_US; a 0 answer clears *latch and UNCERTAIN on every work in w[0..n).
 * Returns 1 when the latch was cleared. */
static inline int adreno_recover_guest_unlatch(const struct adreno_recover_ops *ops, struct adreno_recover_guest *g,
                                               uint64_t now_us, uint8_t *latch, struct adreno_ib_work *const *w,
                                               unsigned n, int dma_ok)
{
    if (!latch || !*latch || !g->abi || g->dead || !dma_ok) return 0;
    if (g->settles && now_us - g->last_settle_us < ADRENO_RECOVER_SETTLE_INTERVAL_US) return 0;
    g->last_settle_us = now_us;
    g->settles++;
    uint64_t r[4];
    r[0] = ADRENO_GUEST_RECOVER; r[1] = ADRENO_RECOVER_SETTLE; r[2] = 0; r[3] = 0;
    ops->hvc(ops->ctx, r);
    const int64_t s = (int64_t)r[0];
    if (s == ADRENO_RECOVER_E_DEAD) { g->dead = 1; return 0; }
    if (s || r[1] < g->epoch || r[2] > 1) { g->refused++; return 0; }   /* BUSY, UNCERTAIN, PARAMS, inconsistent */
    g->settle_resets += r[2];
    g->epoch = r[1];
    g->settled++;
    for (unsigned i = 0; i < n; i++) if (w[i]) w[i]->state &= ~(uint32_t)ADRENO_IB_STATE_UNCERTAIN;
    *latch = 0;
    g->unlatched++;
    return 1;
}

/* The IOGPU status word for a kernel command that failed with `result` (R26). latched: the fail-fast latch is set or
 * the monitor gave up, so a refusal is not this command buffer's doing. */
static inline uint32_t adreno_recover_guest_status(int result, int latched)
{
    switch (result) {
    case ADRENO_IB_E_RESET: return ADRENO_IOGPU_STATUS_HANG;
    case ADRENO_IB_E_RESET_FAULT: return ADRENO_IOGPU_STATUS_PAGE_FAULT;
    case ADRENO_SUBMIT_E_UNCERTAIN: return ADRENO_IOGPU_STATUS_TIMEOUT;
    case ADRENO_SUBMIT_E_INACTIVE: return latched ? ADRENO_IOGPU_STATUS_VICTIM : ADRENO_IOGPU_STATUS_INVALID;
    }
    return ADRENO_IOGPU_STATUS_INVALID;
}
#endif

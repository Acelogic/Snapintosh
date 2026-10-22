/* SPDX-License-Identifier: MIT */
/* The kext's side of ADRENO_GUEST_IB_START / ADRENO_GUEST_IB_POLL (ABI compat/adreno-guest.h; the monitor's side is
 * compat/adreno-ib.h SNAP_ADRENO_IB_ASYNC): discovery and the wait loop. Header-only and libc-free, so the kext
 * (AdrenoX2.cpp ibRing, built with ADRENO_IB_ASYNC: the HVC and IODelay) and the host tests (the monitor model)
 * compile the same code. Failure modes: agents/async-ib/FAILURE-MODES.md A9-A11, A17, A21, A22.
 *
 * The loop runs inside the kext's ring callback, under fSubmitLock, and returns only a final reply shaped like
 * ADRENO_GUEST_IB's (status, marker, ticks, WPTR), so adreno_ib_classify and the resource list's TO_DEVICE / ring /
 * FROM_DEVICE order are unchanged (A17). The waiting is the guest's: IODelay from 10 us doubling to 200 us, while the
 * monitor's service token is free for every other vCPU. */
#ifndef SNAP_ADRENO_IB_ASYNC_H
#define SNAP_ADRENO_IB_ASYNC_H
#include <stdint.h>
#include "adreno-guest.h"

#define ADRENO_IB_ASYNC_DELAY_FIRST_US 10u
#define ADRENO_IB_ASYNC_DELAY_MAX_US 200u
/* The kext's own bound, only while the monitor keeps answering PENDING: past the monitor's largest budget (1 s,
 * --ib-budget-1s) plus its tick's grace (1 s), so it fires only on a monitor fault (A10). */
#define ADRENO_IB_ASYNC_LIMIT_US 4000000u
#ifndef ADRENO_GPU_RECOVER
#define ADRENO_GPU_RECOVER 0
#endif

struct adreno_ib_async_ops {
    void *ctx;
    void (*hvc)(void *ctx, uint64_t regs[4]);      /* HVC #ADRENO_GUEST_HVC: x0..x3 in, x0..x3 out */
    void (*delay_us)(void *ctx, uint32_t us);      /* IODelay */
#if ADRENO_GPU_RECOVER
    /* agents/gpu-recovery R19: the kext's own bound while the monitor answers PENDING (compat/adreno-recover-guest.h
     * adreno_recover_guest_limit_us: the monitor's hard limit + 2 s); 0 keeps ADRENO_IB_ASYNC_LIMIT_US. */
    uint64_t limit_us;
#endif
};
#if ADRENO_GPU_RECOVER
/* A final reply after PENDING (A9), and with recovery also the monitor's reset answers (R14). */
#define ADRENO_IB_ASYNC_FINAL_FAILURE(s) ((s) == ADRENO_IB_E_GPU_ERROR || (s) == ADRENO_IB_E_UNCERTAIN || \
                                          (s) == ADRENO_IB_E_RESET || (s) == ADRENO_IB_E_RESET_FAULT)
#define ADRENO_IB_ASYNC_LIMIT(ops) ((ops)->limit_us ? (ops)->limit_us : (uint64_t)ADRENO_IB_ASYNC_LIMIT_US)
#else
#define ADRENO_IB_ASYNC_FINAL_FAILURE(s) ((s) == ADRENO_IB_E_GPU_ERROR || (s) == ADRENO_IB_E_UNCERTAIN)
#define ADRENO_IB_ASYNC_LIMIT(ops) ADRENO_IB_ASYNC_LIMIT_US
#endif
struct adreno_ib_async_stats { uint64_t ibs, pending, polls, waited_us, max_polls; };

/* Discovery (A11): 1 when the monitor answers IB_POLL(0) with IDLE, so START/POLL are used; 0 for any other reply
 * (an older or define-off monitor refuses the request word with ADRENO_E_PARAMS): keep ADRENO_GUEST_IB. */
static inline int adreno_ib_async_probe(const struct adreno_ib_async_ops *ops)
{
    uint64_t r[4];
    r[0] = ADRENO_GUEST_IB_POLL; r[1] = 0; r[2] = 0; r[3] = 0;
    ops->hvc(ops->ctx, r);
    return (int64_t)r[0] == ADRENO_IB_IDLE && !r[1];
}

/* One IB: START, then POLLs with backoff until a final status. out = {status, marker, ticks, WPTR}. START's own
 * final reply is passed through as is (it is ADRENO_GUEST_IB's). After PENDING the doorbell has been rung, so only
 * 0 with this marker, or GPU_ERROR / UNCERTAIN without one, are final; every other reply, an inconsistent marker
 * or the kext's own bound becomes ADRENO_IB_E_UNCERTAIN with marker 0 (A9, A10). */
static inline void adreno_ib_async_run(const struct adreno_ib_async_ops *ops, uint64_t package, uint64_t dwords,
                                       uint64_t bytes, uint64_t out[4], struct adreno_ib_async_stats *stats)
{
    uint64_t r[4];
    r[0] = ADRENO_GUEST_IB_START; r[1] = package; r[2] = dwords; r[3] = bytes;
    ops->hvc(ops->ctx, r);
    if (stats) stats->ibs++;
    if ((int64_t)r[0] != ADRENO_IB_PENDING) {
        out[0] = r[0]; out[1] = r[1]; out[2] = r[2]; out[3] = r[3];
        return;
    }
    const uint64_t marker = r[1];
    uint64_t ticks = r[2], wptr = r[3], waited = 0, polls = 0;
    uint32_t delay = ADRENO_IB_ASYNC_DELAY_FIRST_US;
    int64_t status = ADRENO_IB_E_UNCERTAIN;
    if (stats) stats->pending++;
    if (marker && !(marker >> 32)) {
        for (;;) {
            ops->delay_us(ops->ctx, delay);
            waited += delay;
            polls++;
            r[0] = ADRENO_GUEST_IB_POLL; r[1] = marker; r[2] = 0; r[3] = 0;
            ops->hvc(ops->ctx, r);
            const int64_t s = (int64_t)r[0];
            ticks = r[2];
            wptr = r[3];
            if (s == ADRENO_IB_PENDING && r[1] == marker) {
                if (waited >= ADRENO_IB_ASYNC_LIMIT(ops)) break;
                delay = delay >= ADRENO_IB_ASYNC_DELAY_MAX_US / 2 ? ADRENO_IB_ASYNC_DELAY_MAX_US : 2 * delay;
                continue;
            }
            if ((s == 0 && r[1] == marker) || (ADRENO_IB_ASYNC_FINAL_FAILURE(s) && !r[1])) status = s;
            break;
        }
    }
    if (stats) {
        stats->polls += polls;
        stats->waited_us += waited;
        if (polls > stats->max_polls) stats->max_polls = polls;
    }
    out[0] = (uint64_t)status;
    out[1] = status ? 0 : marker;
    out[2] = ticks;
    out[3] = wptr;
}
#endif

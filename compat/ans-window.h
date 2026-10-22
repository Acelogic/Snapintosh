/* SPDX-License-Identifier: MIT */
#ifndef SNAP_COMPAT_ANS_WINDOW_H
#define SNAP_COMPAT_ANS_WINDOW_H
#include "ans.h"
#include "nvme-host.h"

#if SNAP_ANS_ASYNC
/* SNAP_ANS_ASYNC (agents/nvme-async/FAILURE-MODES.md N5, N6, N10, N17): the read, write and flush below as a flight
 * that one physical command at a time advances. ans_window_start does what the synchronous call does up to the
 * first physical command and submits it (edge runs are copied at once); ans_window_poll reaps it without waiting
 * and, when it completed, does the synchronous call's next step (the chunk's copy, the next edge runs, the next
 * physical command). Same validity and policy checks, same chunking, same failures (1). The flight lives in the
 * virtual ANS2's async block (ans_state.async.backend); callers hold ANS exclusion. */
#define ANS_WINDOW_PENDING ANS_ASYNC_PENDING
struct ans_window_flight {
    uint64_t op, lba, n, i, run, phys;
    struct nvmeh_flight f;
};
_Static_assert(sizeof(struct ans_window_flight) <= 8 * ANS_ASYNC_BACKEND_WORDS, "window flight fits its slot");
#endif

/* Monitor-private whole-transfer staging is separate from the qualified
 *128KiB physical DMA bounce. The existing service lock serializes callers. */
struct ans_window_backend {
    uint64_t blocks;
    const volatile uint8_t *head, *tail;
    volatile uint8_t *stage, *bounce;
    const struct nvmeh_ops *ops;
    const struct nvmeh_params *params;
    struct nvmeh_state *state;
#if SNAP_ANS_ASYNC
    struct ans_window_flight *flight;
#endif
};
int ans_window_read_blocks(const struct ans_window_backend *, uint64_t, uint64_t, volatile uint8_t **);
int ans_window_prepare_write(const struct ans_window_backend *, uint64_t, uint64_t, volatile uint8_t **);
int ans_window_write_blocks(const struct ans_window_backend *, uint64_t, uint64_t);
#if SNAP_ANS_ASYNC
/* op 2 read, 1 write (the stage already holds the data: ans_window_prepare_write's buffer), 0 flush. 0: done
 * already (a read served wholly from the edges); ANS_WINDOW_PENDING: a physical command is in flight; 1: failed
 * (the synchronous call's failure). */
int ans_window_start(const struct ans_window_backend *, unsigned op, uint64_t lba, uint64_t n);
/* ANS_WINDOW_PENDING, 0 done (a read's blocks are in the stage: *data), or 1 failed. */
int ans_window_poll(const struct ans_window_backend *, volatile uint8_t **data);
/* Read-only: 1 when the physical command in flight has completed (nvmeh_ready). */
int ans_window_ready(const struct ans_window_backend *);
/* The stop (N6): reap the physical command in flight, bounded by its timeout, and end the flight. 1 if one was in
 * flight. */
int ans_window_quiesce(const struct ans_window_backend *);
#endif
#endif

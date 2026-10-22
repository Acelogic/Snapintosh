/* SPDX-License-Identifier: MIT */
/* The kext's IB pipeline (-DADRENO_PIPELINE=1; agents/gpu-pipeline FAILURE-MODES.md Q1-Q5, C1, C4-C6, R1, R2).
 * Header-only and libc-free: AdrenoX2.cpp (under fSubmitLock) and tools/test-adreno-ib-pipeline.c (against async-ib's
 * monitor model) run the same code.
 *
 * One IB at most is on the GPU after its submission returned: the flight. A pipelined submission stages, relocates,
 * validates and cleans (TO_DEVICE) its IB into the package slot the flight does not hold, then waits for the flight's
 * final reply, STARTs its own IB (IB_START: PENDING makes it the new flight), and only then finishes the old flight
 * (FROM_DEVICE, then the kext's `retired` callback). Every other ring user (FILL32, a synchronous client's IB,
 * teardown) first finishes the flight with adreno_pipe_complete; a FENCE with a flight active folds into it
 * (adreno_pipe_fold). A flight nobody waits for is finished by the kext's timer through adreno_pipe_poll.
 *
 * The caller serializes every function here (fSubmitLock). The callbacks run under that serialization: `stamp`
 * (a flight started: the value its retirement writes) and `retired` (after FROM_DEVICE, in retirement order). Anything
 * that can block or call into IOGPU belongs after the caller's unlock (C6). */
#ifndef SNAP_ADRENO_IB_PIPELINE_H
#define SNAP_ADRENO_IB_PIPELINE_H
#include <stdint.h>
#include "adreno-guest.h"
#include "adreno-ib-async.h"
#include "adreno-ib-command.h"

#if !ADRENO_PIPELINE
#error "adreno-ib-pipeline.h needs -DADRENO_PIPELINE=1 (the split adreno_ib_submit_begin/ring/finish)"
#endif

#define ADRENO_PIPE_SLOTS 2u
/* An arena holding ADRENO_PIPE_SLOTS slots, each [zero page][package] (adreno-ib-command.h's layout), 16 KiB aligned */
#define ADRENO_PIPE_SLOT_BYTES ((uint64_t)ADRENO_IB_PACKAGE_AT + ADRENO_IB_MAX_PACKAGE)
#define ADRENO_PIPE_ARENA_BYTES ((ADRENO_PIPE_SLOT_BYTES * ADRENO_PIPE_SLOTS + 0x3fffu) & ~(uint64_t)0x3fffu)

struct adreno_pipe_ops {
    void *ctx;
    void (*hvc)(void *ctx, uint64_t regs[4]);       /* HVC #ADRENO_GUEST_HVC: x0..x3 in, x0..x3 out */
    void (*delay_us)(void *ctx, uint32_t us);       /* IODelay */
    uint64_t (*now_us)(void *ctx);                  /* a monotonic clock in microseconds */
    /* A pipelined IB is in flight: the stamp value its retirement completes (IOGPU's event machine). */
    uint32_t (*stamp)(void *ctx, void *owner);
    /* The flight finished, FROM_DEVICE done: result as adreno_ib_submit's (0, ADRENO_IB_E_GPU_ERROR, a refusal,
     * ADRENO_SUBMIT_E_UNCERTAIN, ADRENO_LIST_E_VISIBILITY), the final reply, the flight's stamp. */
    void (*retired)(void *ctx, void *owner, int result, const struct adreno_ib_reply *final, uint32_t stamp);
#if ADRENO_GPU_RECOVER
    uint64_t limit_us;                              /* as adreno_ib_async_ops.limit_us (agents/gpu-recovery R19) */
#endif
};

struct adreno_pipe_stats {
    uint64_t flights, overlapped, immediate, sync_ibs, folded, drains, timer_finishes, waited_finishes;
    uint64_t polls, spin_us, gap_us, gap_max_us, gap_n, flight_max_us, failures, refused_in_flight;
};

struct adreno_pipe_flight {
    struct adreno_ib_pending pending;
    struct adreno_resource_list *list;
    struct adreno_resource_list_ops list_ops;       /* a copy: the caller's ops live on its stack */
    void *owner;
    uint64_t started_us;
    uint32_t active, slot, stamp, polls;
};

struct adreno_pipe {
    struct adreno_ib_work *slot[ADRENO_PIPE_SLOTS];
    struct adreno_pipe_flight flight;
    struct adreno_pipe_stats stats;
    uint64_t last_finish_us;                         /* when the last flight's final reply was seen (gap) */
    uint32_t gap_armed, last_slot;                   /* the slot the last submission staged into (logs) */
};

static inline void adreno_pipe_init(struct adreno_pipe *p, struct adreno_ib_work *slot0, struct adreno_ib_work *slot1)
{
    uint8_t *b = (uint8_t *)p;
    for (unsigned long i = 0; i < sizeof *p; i++) b[i] = 0;
    p->slot[0] = slot0;
    p->slot[1] = slot1;
}

/* DISABLED and UNCERTAIN apply to the GPU, not to one slot: copy them to every slot (FAILURE-MODES.md C4). */
static inline void adreno_pipe_sync_states(struct adreno_pipe *p)
{
    uint32_t bad = 0;
    for (unsigned s = 0; s < ADRENO_PIPE_SLOTS; s++)
        if (p->slot[s]) bad |= p->slot[s]->state & (ADRENO_IB_STATE_DISABLED | ADRENO_IB_STATE_UNCERTAIN);
    for (unsigned s = 0; s < ADRENO_PIPE_SLOTS; s++)
        if (p->slot[s]) p->slot[s]->state |= bad;
}

/* One IB_POLL of the flight: 1 and *final when final, 0 while PENDING. async-ib A9: after PENDING only 0 with this
 * marker, or GPU_ERROR/UNCERTAIN without one, are final as such; anything else, or PENDING past the kext's own bound
 * (A10, timed from START), is UNCERTAIN with marker 0. */
static inline int adreno_pipe_poll_once(struct adreno_pipe *p, const struct adreno_pipe_ops *ops,
                                        struct adreno_ib_reply *final)
{
    const uint64_t marker = p->flight.pending.marker;
    uint64_t r[4];
    r[0] = ADRENO_GUEST_IB_POLL; r[1] = marker; r[2] = 0; r[3] = 0;
    ops->hvc(ops->ctx, r);
    p->flight.polls++;
    p->stats.polls++;
    const int64_t s = (int64_t)r[0];
    if (s == ADRENO_IB_PENDING && r[1] == marker) {
        const uint64_t now = ops->now_us(ops->ctx);
        if (now - p->flight.started_us < ADRENO_IB_ASYNC_LIMIT(ops)) return 0;
        final->status = ADRENO_IB_E_UNCERTAIN; final->marker = 0; final->ticks = r[2]; final->wptr = r[3];
        return 1;
    }
    int64_t status = ADRENO_IB_E_UNCERTAIN;
    if ((s == 0 && r[1] == marker) || (ADRENO_IB_ASYNC_FINAL_FAILURE(s) && !r[1])) status = s;
    final->status = status;
    final->marker = status ? 0 : marker;
    final->ticks = r[2];
    final->wptr = r[3];
    return 1;
}

/* Finish a flight (the active one, or one detached from it) with its final reply: FROM_DEVICE and the work's state
 * (adreno_ib_submit_finish), DISABLED or UNCERTAIN spread to every slot, then `retired`. Returns the result. */
static inline int adreno_pipe_finish_flight(struct adreno_pipe *p, const struct adreno_pipe_ops *ops,
                                            struct adreno_pipe_flight *f, const struct adreno_ib_reply *final)
{
    struct adreno_ib_work *w = p->slot[f->slot];
    const int result = adreno_ib_submit_finish(w, f->list, &f->list_ops, &f->pending, final, 0);
    adreno_pipe_sync_states(p);
    const uint64_t took = ops->now_us(ops->ctx) - f->started_us;
    if (took > p->stats.flight_max_us) p->stats.flight_max_us = took;
    if (result) p->stats.failures++;
    void *owner = f->owner;
    const uint32_t stamp = f->stamp;
    f->active = 0; f->list = 0; f->owner = 0; f->polls = 0;
    ops->retired(ops->ctx, owner, result, final, stamp);
    return result;
}
static inline int adreno_pipe_finish(struct adreno_pipe *p, const struct adreno_pipe_ops *ops,
                                     const struct adreno_ib_reply *final)
{
    p->last_finish_us = ops->now_us(ops->ctx);
    p->gap_armed = 1;
    return adreno_pipe_finish_flight(p, ops, &p->flight, final);
}

/* POLL the flight until its final reply, IODelay 10 us doubling to 200 us between POLLs (async-ib's loop). */
static inline void adreno_pipe_wait(struct adreno_pipe *p, const struct adreno_pipe_ops *ops, struct adreno_ib_reply *final)
{
    uint32_t delay = ADRENO_IB_ASYNC_DELAY_FIRST_US;
    while (!adreno_pipe_poll_once(p, ops, final)) {
        ops->delay_us(ops->ctx, delay);
        p->stats.spin_us += delay;
        delay = delay >= ADRENO_IB_ASYNC_DELAY_MAX_US / 2 ? ADRENO_IB_ASYNC_DELAY_MAX_US : 2 * delay;
    }
    p->last_finish_us = ops->now_us(ops->ctx);
    p->gap_armed = 1;
}

/* Wait for the flight's final reply and finish it. 0 when there was no flight, 1 when one was finished. */
static inline int adreno_pipe_complete(struct adreno_pipe *p, const struct adreno_pipe_ops *ops)
{
    if (!p->flight.active) return 0;
    struct adreno_ib_reply final;
    adreno_pipe_wait(p, ops, &final);
    p->stats.waited_finishes++;
    adreno_pipe_finish_flight(p, ops, &p->flight, &final);
    return 1;
}

/* The kext's timer: one POLL; finish the flight if it is final. 1 when a flight remains in flight. */
static inline int adreno_pipe_poll(struct adreno_pipe *p, const struct adreno_pipe_ops *ops)
{
    if (!p->flight.active) return 0;
    struct adreno_ib_reply final;
    if (!adreno_pipe_poll_once(p, ops, &final)) return 1;
    p->stats.timer_finishes++;
    adreno_pipe_finish(p, ops, &final);
    return 0;
}

#ifndef ADRENO_PRESENT_RELATCH
#define ADRENO_PRESENT_RELATCH 0
#endif
#if ADRENO_PRESENT_RELATCH
/* agents/present-pacing FAILURE-MODES.md EP2 EP3: a flight that is already final is finished before a submitter's
 * TO_DEVICE, and the TO_DEVICE of a submitter that found a flight polls it between entries, at most every assist_us,
 * and finishes it when final, so its marks are not held for the rest of another list's maintenance. The caller's
 * switches and totals (the caller serializes, as every function here). */
struct adreno_pipe_early {
    uint32_t on;                                    /* adreno_pipe_early: 0 = today's order */
    uint64_t assist_us;                             /* adreno_pipe_assist_us: 0 = no assist */
    uint64_t pre, assisted, assist_polls, unmarks;  /* EP2 finishes, EP3 finishes, EP3 POLLs, EP1 early unmarks */
};
/* EP2: one POLL; a final flight is finished (FROM_DEVICE, `retired`) as the timer would. 1 when it was finished. */
static inline int adreno_pipe_try_finish(struct adreno_pipe *p, const struct adreno_pipe_ops *ops)
{
    if (!p->flight.active) return 0;
    struct adreno_ib_reply final;
    if (!adreno_pipe_poll_once(p, ops, &final)) return 0;
    adreno_pipe_finish(p, ops, &final);
    return 1;
}
#if !ADRENO_CACHE_SPARSE
/* EP3: the begin's sync, wrapped on the submitter's stack. adreno_ib_submit_begin reaches only `sync` (the nosparse
 * adreno_resource_list_begin: the checks, then TO_DEVICE per entry); the flight keeps the caller's own ops. */
struct adreno_pipe_assist {
    struct adreno_resource_list_ops ops;
    const struct adreno_resource_list_ops *inner;
    struct adreno_pipe *p;
    const struct adreno_pipe_ops *pops;
    struct adreno_pipe_early *early;
    uint64_t last_us;
};
static inline int adreno_pipe_assist_sync(void *c, void *preparation, unsigned direction)
{
    struct adreno_pipe_assist *a = (struct adreno_pipe_assist *)c;
    const int r = a->inner->sync(a->inner->context, preparation, direction);
    if (r || direction != ADRENO_CACHE_TO_DEVICE || !a->p->flight.active) return r;
    const uint64_t now = a->pops->now_us(a->pops->ctx);
    if (now - a->last_us < a->early->assist_us) return r;
    a->last_us = now;
    a->early->assist_polls++;
    if (adreno_pipe_try_finish(a->p, a->pops)) a->early->assisted++;
    return r;
}
#endif
#endif

/* A FENCE kernel command: 1 when it folds into the flight (FAILURE-MODES.md Q3; the caller validates its list). */
static inline int adreno_pipe_fold(struct adreno_pipe *p)
{
    if (!p->flight.active) return 0;
    p->stats.folded++;
    return 1;
}

/* Ring callbacks (context: the pipe ops). START only, for a pipelined IB; START then POLLs to the end, otherwise. */
static inline int adreno_pipe_ring_start(void *c, uint64_t package, uint64_t dwords, uint64_t bytes,
                                         struct adreno_ib_reply *reply)
{
    const struct adreno_pipe_ops *ops = (const struct adreno_pipe_ops *)c;
    uint64_t r[4];
    r[0] = ADRENO_GUEST_IB_START; r[1] = package; r[2] = dwords; r[3] = bytes;
    ops->hvc(ops->ctx, r);
    reply->status = (int64_t)r[0]; reply->marker = r[1]; reply->ticks = r[2]; reply->wptr = r[3];
    return 0;
}
static inline int adreno_pipe_ring_sync(void *c, uint64_t package, uint64_t dwords, uint64_t bytes,
                                        struct adreno_ib_reply *reply)
{
    const struct adreno_pipe_ops *ops = (const struct adreno_pipe_ops *)c;
#if ADRENO_GPU_RECOVER
    const struct adreno_ib_async_ops async = {ops->ctx, ops->hvc, ops->delay_us, ops->limit_us};
#else
    const struct adreno_ib_async_ops async = {ops->ctx, ops->hvc, ops->delay_us};
#endif
    uint64_t out[4];
    adreno_ib_async_run(&async, package, dwords, bytes, out, 0);
    reply->status = (int64_t)out[0]; reply->marker = out[1]; reply->ticks = out[2]; reply->wptr = out[3];
    return 0;
}

/* One IB (an ADRENO_KCMD_IB against `list`). pipelined: return once it is in flight (*in_flight = 1; the flight now
 * holds `owner` and `list`, which the caller keeps alive until `retired`); otherwise, or when START's reply is already
 * final, return its final result as adreno_ib_submit would. A refusal before the doorbell leaves any older flight in
 * flight. With an older flight: stage and clean first (it still runs), wait for its final reply, START this IB, and
 * only then finish the older one (its FROM_DEVICE overlaps this IB). An older flight that failed is finished first
 * and this IB is not rung. A synchronous IB finishes the older flight before it runs. */
static inline int adreno_pipe_submit(struct adreno_pipe *p, const struct adreno_pipe_ops *ops,
                                     struct adreno_resource_list *list, const struct adreno_resource_list_ops *list_ops,
                                     const void *command, uint64_t available,
                                     int (*resolve)(void *, void *, void *, uint64_t, uint64_t, uint64_t *),
                                     void *resolve_context, void *owner, int pipelined, int *in_flight
#if ADRENO_PRESENT_RELATCH
                                     , struct adreno_pipe_early *early
#endif
                                     )
{
    *in_flight = 0;
    const unsigned s = p->flight.active ? 1u - p->flight.slot : 0u;   /* never the slot the CP may fetch (Q2) */
    struct adreno_ib_work *w = p->slot[s];
    if (!w) return ADRENO_SUBMIT_E_INACTIVE;
    p->last_slot = s;
    struct adreno_ib_pending pending;
#if ADRENO_PRESENT_RELATCH && !ADRENO_CACHE_SPARSE
    /* EP3: with a flight active, the TO_DEVICE below polls it (slot s is the one the flight does not hold, so finishing
     * it there touches nothing staged here; a failed flight spreads its state and this IB is refused below, C4) */
    struct adreno_pipe_assist assist;
    const struct adreno_resource_list_ops *begin_ops = list_ops;
    if (early && early->on && early->assist_us && p->flight.active) {
        assist.ops.context = &assist; assist.ops.retain = 0; assist.ops.release = 0; assist.ops.prepare = 0;
        assist.ops.complete = 0; assist.ops.sync = adreno_pipe_assist_sync;
        assist.inner = list_ops; assist.p = p; assist.pops = ops; assist.early = early;
        assist.last_us = ops->now_us(ops->ctx);
        begin_ops = &assist.ops;
    }
    int e = adreno_ib_submit_begin(w, list, begin_ops, command, available, resolve, resolve_context, &pending);
#else
#if ADRENO_PRESENT_RELATCH
    (void)early;
#endif
    int e = adreno_ib_submit_begin(w, list, list_ops, command, available, resolve, resolve_context, &pending);
#endif
    if (e) return e;                                                  /* nothing rung; an older flight goes on */
    struct adreno_pipe_flight older;
    struct adreno_ib_reply older_final;
    int have_older = 0;
    if (p->flight.active) {                                           /* Q1: one IB on the ring */
        p->stats.overlapped++;
        adreno_pipe_wait(p, ops, &older_final);
        p->stats.waited_finishes++;
        if (!pipelined || older_final.status) {
            adreno_pipe_finish_flight(p, ops, &p->flight, &older_final);   /* states first (C4), or before a sync IB */
        } else {
            older = p->flight;                                        /* retired: detached, finished after START */
            p->flight.active = 0;
            have_older = 1;
        }
    }
    if (w->state & (ADRENO_IB_STATE_DISABLED | ADRENO_IB_STATE_UNCERTAIN)) {
        adreno_resource_list_end(list, list_ops, &pending.list, ADRENO_SUBMIT_E_INACTIVE);   /* begun, never rung */
        pending.armed = 0;
        return ADRENO_SUBMIT_E_INACTIVE;
    }
    if (p->gap_armed) {                                               /* from the last final reply to this doorbell */
        const uint64_t gap = ops->now_us(ops->ctx) - p->last_finish_us;
        p->stats.gap_us += gap; p->stats.gap_n++;
        if (gap > p->stats.gap_max_us) p->stats.gap_max_us = gap;
        p->gap_armed = 0;
    }
    if (!pipelined) {
        p->stats.sync_ibs++;
        e = adreno_ib_submit_ring(w, list, list_ops, &pending, adreno_pipe_ring_sync, (void *)ops);
        adreno_pipe_sync_states(p);
        return e == ADRENO_IB_IN_FLIGHT ? ADRENO_SUBMIT_E_UNCERTAIN : e;   /* the sync ring is always final */
    }
    const uint64_t started = ops->now_us(ops->ctx);
    e = adreno_ib_submit_ring(w, list, list_ops, &pending, adreno_pipe_ring_start, (void *)ops);
    if (e == ADRENO_IB_IN_FLIGHT) {
        struct adreno_pipe_flight *f = &p->flight;
        f->pending = pending;
        f->list = list;
        f->list_ops = *list_ops;
        f->owner = owner;
        f->started_us = started;
        f->slot = s;
        f->polls = 0;
        f->active = 1;
        f->stamp = ops->stamp(ops->ctx, owner);
        p->stats.flights++;
        *in_flight = 1;
        e = 0;
    } else {                                                          /* final at START: done, as a synchronous IB */
        p->stats.immediate++;
        adreno_pipe_sync_states(p);
    }
    if (have_older) adreno_pipe_finish_flight(p, ops, &older, &older_final);
    return e;
}
#endif

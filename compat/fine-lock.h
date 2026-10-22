/* SPDX-License-Identifier: MIT */
#ifndef SNAP_FINE_LOCK_H
#define SNAP_FINE_LOCK_H
#include <stdint.h>

/* SNAP_FINE_LOCKS (opt-in, default 0; docs/FINE-LOCKS-20261017.md): user
 * address-space SPTM calls run beside each other instead of behind the one
 * service token. Three levels, always taken in this order:
 *
 *   L0  the gate: struct guest_service_lock's token word (exclusive, every
 *       unconverted path, unchanged) and its reader mask (shared, a converted
 *       call; compat/service-lock.h guest_service_enter_shared). The token
 *       holder waits for the mask to drain, so an exclusive section never
 *       overlaps a converted call.
 *   L1  root stripes: FINE_STRIPES FIFO ticket locks, one per hash class of a
 *       root PA. A converted call takes the stripe of every root it names,
 *       in ascending stripe order, duplicates merged (struct fine_lockset).
 *   L2  aux: one FIFO ticket lock for the global trackers, logs and counters
 *       a converted call updates. A leaf: nothing is acquired while it is
 *       held, and it is never held across a TLBI wait.
 *
 * No CPU waits for L0 while it holds L1 or L2, and the token holder takes
 * neither, so waits form the order L0 < L1(stripe index) < L2: no cycle.
 *
 * Failure modes this file answers (the F numbers of the design note):
 *  F4  one root mutated by two CPUs: every root a call names is in its
 *      lockset; two roots of one stripe are one lock (merged, never taken
 *      twice, which would self-deadlock a ticket lock).
 *  F5  deadlock: fine_lockset_acquire takes stripes strictly ascending;
 *      fine_lockset_release drops them in reverse; aux is a leaf.
 *  F14 starvation: ticket locks serve in arrival order, so no CPU (or
 *      cluster) re-acquiring at once can pass a waiter; the token itself is
 *      FIFO with SNAP_FAIR_TOKEN (compat/service-lock.h).
 * SNAP_FINE_SWITCH (phase 1b) converts SWITCH_ROOT cache hits and requires
 * SNAP_FINE_LOCKS. */
#ifndef SNAP_FINE_LOCKS
#define SNAP_FINE_LOCKS 0
#endif
#ifndef SNAP_FINE_SWITCH
#define SNAP_FINE_SWITCH 0
#endif
#if SNAP_FINE_SWITCH && !SNAP_FINE_LOCKS
#error "SNAP_FINE_SWITCH requires SNAP_FINE_LOCKS"
#endif
/* SNAP_FINE_HW (docs/FINE-HW-WALK-20261019.md) converts MAP_PAGE and
 * UNMAP_REGION on hardware-walk roots (SNAP_USER_HW_WALK) and requires
 * SNAP_FINE_LOCKS; probes/xnuboot.c also asserts SNAP_USER_HW_WALK. */
#ifndef SNAP_FINE_HW
#define SNAP_FINE_HW 0
#endif
#if SNAP_FINE_HW && !SNAP_FINE_LOCKS
#error "SNAP_FINE_HW requires SNAP_FINE_LOCKS"
#endif
/* SNAP_FINE_SWITCH_HW (batch 8, opt-in) converts a SWITCH_ROOT to a
 * hardware-walk root whose record already exists (SNAP_USER_HW_WALK: no
 * cache entry, so SNAP_FINE_SWITCH's cache-hit conversion never sees it):
 * compat/sptm-root.c sptm_mac_switch_root_hit's hardware-walk branch and
 * probes/xnuboot.c fine_hw_install_user. Requires SNAP_FINE_SWITCH; its
 * users also assert SNAP_USER_HW_WALK. */
#ifndef SNAP_FINE_SWITCH_HW
#define SNAP_FINE_SWITCH_HW 0
#endif
#if SNAP_FINE_SWITCH_HW && !SNAP_FINE_SWITCH
#error "SNAP_FINE_SWITCH_HW requires SNAP_FINE_SWITCH"
#endif
/* SNAP_FAST_PAUTH_CALLS converts SIGN_USER_POINTER, AUTH_USER_POINTER and
 * BATCH_SIGN_USER_POINTER (FINE_CALL_PAUTH, FINE_CALL_PAUTH_BATCH): this
 * CPU's signing state only, the gate shared and no stripe (they name no
 * root; probes/xnuboot.c fine_pauth_pointer). Requires SNAP_FINE_LOCKS, whose
 * dispatcher, gate and profile it uses. */
#ifndef SNAP_FAST_PAUTH_CALLS
#define SNAP_FAST_PAUTH_CALLS 0
#endif
#if SNAP_FAST_PAUTH_CALLS && !SNAP_FINE_LOCKS
#error "SNAP_FAST_PAUTH_CALLS requires SNAP_FINE_LOCKS"
#endif
/* SNAP_TOKEN_TRIM (compat/token-trim.h) converts the Adreno DART's MAP and
 * UNMAP (FINE_CALL_DART_MAP, FINE_CALL_DART_UNMAP): the gate shared, no
 * stripe, the device lock. Requires SNAP_FINE_LOCKS and SNAP_FAST_PAUTH_CALLS
 * (the profile's bucket count then names its layout: 5, 7 or 9). */
#ifndef SNAP_TOKEN_TRIM
#define SNAP_TOKEN_TRIM 0
#endif
#if SNAP_TOKEN_TRIM && (!SNAP_FINE_LOCKS || !SNAP_FAST_PAUTH_CALLS)
#error "SNAP_TOKEN_TRIM requires SNAP_FINE_LOCKS and SNAP_FAST_PAUTH_CALLS"
#endif
/* SNAP_DART_CONVERTED (compat/dart-converted.h, batch 9) converts the same two calls
 * on its own: SNAP_TOKEN_TRIM's part B without its kernel-view witness. Requires
 * SNAP_FINE_LOCKS and SNAP_FAST_PAUTH_CALLS (the profile's bucket count still names
 * its layout) and excludes SNAP_TOKEN_TRIM (one conversion, one device lock). */
#ifndef SNAP_DART_CONVERTED
#define SNAP_DART_CONVERTED 0
#endif
#if SNAP_DART_CONVERTED && (!SNAP_FINE_LOCKS || !SNAP_FAST_PAUTH_CALLS)
#error "SNAP_DART_CONVERTED requires SNAP_FINE_LOCKS and SNAP_FAST_PAUTH_CALLS"
#endif
#if SNAP_DART_CONVERTED && SNAP_TOKEN_TRIM
#error "SNAP_TOKEN_TRIM's part B already converts the Adreno DART calls: give SNAP_DART_CONVERTED or SNAP_TOKEN_TRIM"
#endif
/* SNAP_PHASE_FAIR_GATE (compat/service-lock.h, batch6 FAILURES-AND-DESIGN.md)
 * makes L0 phase-fair: a converted call that finds a token holder waits for
 * that holder only, not for the token's whole queue, and a holder waits only
 * for the converted calls that arrived before it. Writers keep the token's
 * FIFO, so it requires SNAP_FAIR_TOKEN; probes/xnuboot.c also requires
 * SNAP_GATE_WAIT (the bounded wait that withdraws an arrival). */
#ifndef SNAP_PHASE_FAIR_GATE
#define SNAP_PHASE_FAIR_GATE 0
#endif
#if SNAP_PHASE_FAIR_GATE && (!SNAP_FINE_LOCKS || !SNAP_FAIR_TOKEN)
#error "SNAP_PHASE_FAIR_GATE requires SNAP_FINE_LOCKS and SNAP_FAIR_TOKEN"
#endif
/* SNAP_SPTM_FINE (opt-in, default 0; agents/sptm-locks/FAILURE-MODES.md) adds
 * converted calls in three stages, each requiring the previous one:
 *   SNAP_SPTM_FINE         user UNMAP_DISJOINT and UPDATE_REGION, and the
 *                          hardware-walk update events (a replacing MAP_PAGE,
 *                          UPDATE_DISJOINT records on hardware-walk roots); the
 *                          converted hardware-walk copy writes use the
 *                          converted trackers (fine_hw_ops);
 *   SNAP_SPTM_FINE_RETYPE  private per-frame locks (compat/sptm-fine.h) and
 *                          RETYPE 11->20, 20->11 and 11->11;
 *   SNAP_SPTM_FINE_KERNEL  kernel-root MAP_PAGE and UNMAP_REGION under one
 *                          kernel lock, outside every kernel-view copy source.
 * Each adds its fine-profile buckets and decline reasons at the end (header
 * bit 3, tools/perf_counters.py). */
#ifndef SNAP_SPTM_FINE
#define SNAP_SPTM_FINE 0
#endif
#ifndef SNAP_SPTM_FINE_RETYPE
#define SNAP_SPTM_FINE_RETYPE 0
#endif
#ifndef SNAP_SPTM_FINE_KERNEL
#define SNAP_SPTM_FINE_KERNEL 0
#endif
#if SNAP_SPTM_FINE && (!SNAP_FINE_LOCKS || !SNAP_FINE_HW)
#error "SNAP_SPTM_FINE requires SNAP_FINE_LOCKS and SNAP_FINE_HW"
#endif
#if (SNAP_SPTM_FINE_RETYPE || SNAP_SPTM_FINE_KERNEL) && !SNAP_SPTM_FINE
#error "SNAP_SPTM_FINE_RETYPE and SNAP_SPTM_FINE_KERNEL require SNAP_SPTM_FINE"
#endif

/* SNAP_ANS_CONVERTED (opt-in, default 0; agents/nvme-async/FAILURE-MODES.md, compat/ans.h): the virtual ANS2's
 * I/O doorbells (a converted MMIO call) and table-6 MAP/UNMAP_PAGES (a converted SPTM call) under the ANS device
 * lock: two buckets and one decline reason after every earlier one, header bit 4 (tools/perf_counters.py). */
#ifndef SNAP_ANS_CONVERTED
#define SNAP_ANS_CONVERTED 0
#endif
#if SNAP_ANS_CONVERTED && !SNAP_FINE_LOCKS
#error "SNAP_ANS_CONVERTED requires SNAP_FINE_LOCKS"
#endif

#ifndef FINE_STRIPES
#define FINE_STRIPES 64u
#endif
_Static_assert(FINE_STRIPES && FINE_STRIPES <= 256 && !(FINE_STRIPES & (FINE_STRIPES - 1)),
               "stripe index is a power-of-two mask that fits a byte");
/* The most distinct roots one converted call may name (UPDATE_DISJOINT's 64
 * records); more stripes than this cannot be named either. */
#define FINE_LOCKSET_MAX 64u

#ifndef FINE_RELAX
#define FINE_RELAX() __asm__ volatile("yield" ::: "memory")
#endif

struct fine_ticket { uint32_t next, serving; } __attribute__((aligned(64)));

/* A converted call's counter update: atomic, saturating at limit like the
 * token path's `if(x!=limit)x++` forms (sprr_count, the memo clocks). */
static inline uint64_t fine_sat_add(uint64_t *x, uint64_t n, uint64_t limit)
{
    uint64_t old = __atomic_load_n(x, __ATOMIC_RELAXED), next;
    do next = old >= limit || limit - old < n ? (old > limit ? old : limit) : old + n;
    while (!__atomic_compare_exchange_n(x, &old, next, 1, __ATOMIC_RELAXED, __ATOMIC_RELAXED));
    return next;
}
static inline void fine_add(uint64_t *x, uint64_t n) { __atomic_fetch_add(x, n, __ATOMIC_RELAXED); }

/* FIFO: a lock is granted in the order fine_ticket_draw was called, so a
 * CPU that releases and asks again at once queues behind every waiter
 * (fairness across clusters; tools/test-fine-locks.c "fair"). */
static inline uint32_t fine_ticket_draw(struct fine_ticket *t)
{
    return __atomic_fetch_add(&t->next, 1, __ATOMIC_RELAXED);
}
/* Returns 1 when this caller had to wait behind another holder. */
static inline int fine_ticket_wait(struct fine_ticket *t, uint32_t me)
{
    int waited = 0;
    while (__atomic_load_n(&t->serving, __ATOMIC_ACQUIRE) != me) { waited = 1; FINE_RELAX(); }
    return waited;
}
static inline int fine_ticket_lock(struct fine_ticket *t)
{
    return fine_ticket_wait(t, fine_ticket_draw(t));
}
static inline void fine_ticket_unlock(struct fine_ticket *t)
{
    /* Only the holder writes serving. */
    uint32_t now = __atomic_load_n(&t->serving, __ATOMIC_RELAXED);
    __atomic_store_n(&t->serving, now + 1, __ATOMIC_RELEASE);
}
static inline int fine_ticket_held(struct fine_ticket *t)
{
    return __atomic_load_n(&t->next, __ATOMIC_RELAXED) !=
           __atomic_load_n(&t->serving, __ATOMIC_RELAXED);
}

/* The stripe of a root page: 16K frame number, Fibonacci-hashed. */
static inline unsigned fine_stripe(uint64_t root)
{
    return (unsigned)(((root >> 14) * UINT64_C(0x9e3779b97f4a7c15)) >> 56) & (FINE_STRIPES - 1);
}

/* An ascending set of distinct stripes. */
struct fine_lockset { unsigned count; uint8_t stripe[FINE_LOCKSET_MAX]; };
static inline void fine_lockset_init(struct fine_lockset *s) { s->count = 0; }
/* 0 only when the set is full (never for a call naming at most
 * FINE_LOCKSET_MAX roots). */
static inline int fine_lockset_add(struct fine_lockset *s, uint64_t root)
{
    unsigned k = fine_stripe(root), i = 0;
    while (i < s->count && s->stripe[i] < k) i++;
    if (i < s->count && s->stripe[i] == k) return 1;
    if (s->count >= FINE_LOCKSET_MAX) return 0;
    for (unsigned j = s->count; j > i; j--) s->stripe[j] = s->stripe[j - 1];
    s->stripe[i] = (uint8_t)k;
    s->count++;
    return 1;
}
static inline int fine_lockset_has(const struct fine_lockset *s, uint64_t root)
{
    unsigned k = fine_stripe(root);
    for (unsigned i = 0; i < s->count; i++) if (s->stripe[i] == k) return 1;
    return 0;
}
/* Returns how many stripes were found held by another CPU. */
static inline unsigned fine_lockset_acquire(struct fine_ticket *stripes, const struct fine_lockset *s)
{
    unsigned waited = 0;
    for (unsigned i = 0; i < s->count; i++) waited += (unsigned)fine_ticket_lock(&stripes[s->stripe[i]]);
    return waited;
}
static inline void fine_lockset_release(struct fine_ticket *stripes, const struct fine_lockset *s)
{
    for (unsigned i = s->count; i--;) fine_ticket_unlock(&stripes[s->stripe[i]]);
}

/* Converted calls, decline reasons and the per-CPU profile (copied into
 * report.bin behind FINE_PROFILE_MAGIC, tools/perf_counters.py). Wait is
 * charged separately for the gate (a token holder present), the stripes and
 * aux; hold is the call from gate entry to gate release less those waits.
 * The pointer kinds exist only with SNAP_FAST_PAUTH_CALLS (a define-free or
 * FINE_LOCKS-only profile keeps its five buckets; the record header's bit 1
 * says which layout follows). */
enum fine_call {
    FINE_CALL_UPDATE_DISJOINT, FINE_CALL_MAP_PAGE, FINE_CALL_UNMAP_REGION,
    FINE_CALL_SWITCH_HIT, FINE_CALL_SWITCH_KERNEL,
#if SNAP_FAST_PAUTH_CALLS
    FINE_CALL_PAUTH, FINE_CALL_PAUTH_BATCH,
#endif
#if SNAP_TOKEN_TRIM || SNAP_DART_CONVERTED
    FINE_CALL_DART_MAP, FINE_CALL_DART_UNMAP,
#endif
#if SNAP_SPTM_FINE
    /* Always all five with SNAP_SPTM_FINE (a stage that is off leaves its
     * buckets zero): one layout per header bit 3. */
    FINE_CALL_UNMAP_DISJOINT, FINE_CALL_UPDATE_REGION, FINE_CALL_RETYPE,
    FINE_CALL_KERNEL_MAP, FINE_CALL_KERNEL_UNMAP,
#endif
#if SNAP_ANS_CONVERTED
    FINE_CALL_ANS_MMIO, FINE_CALL_ANS_SPTM,
#endif
    FINE_CALLS
};
enum fine_decline {
    FINE_NO_GATE,        /* token held or admission closed while trying */
    FINE_NO_STATE,       /* a latched failure, stop, panic, probe or pending launch */
    FINE_NO_SHAPE,       /* arguments outside the converted envelope */
    FINE_NO_ROOT,        /* a root that is not an admitted user root */
    FINE_NO_ARENA,       /* below the arena reserve: the locked path reclaims */
    FINE_NO_ENGINE,      /* preflight refused: the locked path repeats and reports */
    FINE_NO_ALLOC,       /* a shadow table would have to be allocated */
    FINE_NO_INACTIVE,    /* a cached root no CPU runs (mirror/invalidate decisions) */
    FINE_NO_SWITCH,      /* SWITCH_ROOT that is not a plain cache hit */
#if SNAP_SPTM_FINE
    FINE_NO_FRAME,       /* a frame lock held by another converted call (try-only) */
    FINE_NO_COPIED,      /* a kernel shadow table that a kernel view copies, or no path */
#endif
#if SNAP_ANS_CONVERTED
    FINE_NO_BUSY,        /* UNMAP_PAGES of a queued or in-service command id: the token path drains first */
#endif
    FINE_DECLINES
};
#define FINE_PROFILE_MAGIC UINT64_C(0x314b434c454e4946)   /* "FINELCK1" */
struct fine_bucket {
    uint64_t entries, gate_wait, stripe_wait, aux_wait, hold, contended;
};
struct fine_profile {
    struct fine_bucket call[FINE_CALLS];
    uint64_t declined[FINE_DECLINES];
    uint64_t aux_entries, aux_contended, failures;
} __attribute__((aligned(64)));
_Static_assert(sizeof(struct fine_bucket) == 48, "fine bucket stride (perf_counters.py)");
#endif

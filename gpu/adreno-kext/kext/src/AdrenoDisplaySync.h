/* SPDX-License-Identifier: MIT */
/* AdrenoDisplaySync.h - the present-sync gate (-DADRENO_PRESENT_SYNC=1; agents/present-sync FAILURE-MODES.md K1-K11).
 * Header-only C shared by AdrenoX2.cpp (the write table), AdrenoDisplay.cpp (the gate and the perf sync line) and
 * tools/replay-adreno-latency.c. No clock and no lock here: callers serialize the table and pass times (mach ticks in the
 * kext).
 *
 * Why: AdrenoDisplay copies WindowServer's layer-0 IOSurface at a beam tick. A copy that starts while the GPU still
 * writes that surface shows part of the old and part of the new frame (Adreno resolves bin by bin): the stale blocks
 * and flicker of b12v8-b12v11. The kext marks every IOSurface an IB or FILL32 writes, from before the submit-lock wait
 * until the submission returns (the IB has retired then). The display does not copy a marked surface: the swap waits
 * for a later tick, at most max_wait per swap (K2), then is copied anyway and counted. */
#pragma once
#include <stdint.h>
#include <string.h>
#ifdef KERNEL
#include <libkern/libkern.h>     /* snprintf */
#else
#include <stdio.h>
#endif

/* ---- the write table (K1 K5 K7): surface ID -> writers in the kext ---- */
#define ADRENO_SYNC_SLOTS 32u
#define ADRENO_SYNC_IDS_PER_SUBMIT 16u            /* distinct written surfaces one submission marks; more: wildcard */
#define ADRENO_SYNC_WILDCARD 0u                   /* IOSurface IDs start at 1; 0 marks "some surface, unknown" */
struct adreno_sync_slot { uint32_t id, writers; uint64_t since; };
struct adreno_sync_table {
    struct adreno_sync_slot slot[ADRENO_SYNC_SLOTS];
    uint32_t wild;                                /* wildcard and overflowed marks: every surface looks written (K5) */
    uint64_t wild_since;
    uint64_t marks, overflows, unmatched;         /* totals (the perf line takes window deltas) */
};
static inline void adreno_sync_mark(struct adreno_sync_table *t, uint32_t id, uint64_t now)
{
    t->marks++;
    if (id != ADRENO_SYNC_WILDCARD) {
        struct adreno_sync_slot *free_slot = 0;
        for (unsigned i = 0; i < ADRENO_SYNC_SLOTS; i++) {
            struct adreno_sync_slot *s = &t->slot[i];
            if (s->writers && s->id == id) { s->writers++; return; }
            if (!s->writers && !free_slot) free_slot = s;
        }
        if (free_slot) { free_slot->id = id; free_slot->writers = 1; free_slot->since = now; return; }
        t->overflows++;
    }
    if (!t->wild++) t->wild_since = now;
}
/* Unmark exactly what adreno_sync_mark marked: an id that found no slot was counted as a wildcard. The caller passes
 * the same id; `overflowed` is not known to it, so a missing slot falls back to the wildcard count (K5). */
static inline void adreno_sync_unmark(struct adreno_sync_table *t, uint32_t id)
{
    if (id != ADRENO_SYNC_WILDCARD) {
        for (unsigned i = 0; i < ADRENO_SYNC_SLOTS; i++) {
            struct adreno_sync_slot *s = &t->slot[i];
            if (s->writers && s->id == id) { s->writers--; return; }
        }
    }
    if (t->wild) t->wild--; else t->unmatched++;
}
/* Writers on id (wildcards included) and the oldest mark among them; 0 when none. */
static inline uint32_t adreno_sync_query(const struct adreno_sync_table *t, uint32_t id, uint64_t *since)
{
    uint32_t n = 0; uint64_t oldest = 0;
    if (t->wild) { n += t->wild; oldest = t->wild_since; }
    for (unsigned i = 0; id && i < ADRENO_SYNC_SLOTS; i++) {
        const struct adreno_sync_slot *s = &t->slot[i];
        if (s->writers && s->id == id) { n += s->writers; if (!oldest || s->since < oldest) oldest = s->since; }
    }
    if (since) *since = oldest;
    return n;
}

/* ---- the gate (K1-K4 K11): one decision per attempt to copy a layer-0 head ---- */
enum { ADRENO_SYNC_GO = 0, ADRENO_SYNC_WAIT = 1, ADRENO_SYNC_FORCED = 2 };
struct adreno_sync_gate {
    uint64_t max_wait, stale;                     /* ticks; max_wait 0 = the gate is off */
    const void *head; uint32_t head_id; uint64_t since;   /* the waiting head: identity only, never dereferenced (K11) */
    /* this window */
    uint64_t defer, swaps, forced, max_waited, busy, stale_seen;
};
static inline void adreno_sync_gate_init(struct adreno_sync_gate *g, uint64_t max_wait, uint64_t stale)
{
    memset(g, 0, sizeof *g);
    g->max_wait = max_wait; g->stale = stale;
}
static inline void adreno_sync_forget(struct adreno_sync_gate *g) { g->head = 0; g->head_id = 0; g->since = 0; }
/* writers/oldest: the head's surface in the table; now: the caller's clock (only needed when writers or a waiting head).
 * GO: copy it. WAIT: leave it queued for a later tick. FORCED: the bound passed; copy it (counted). */
static inline int adreno_sync_decide(struct adreno_sync_gate *g, const void *head, uint32_t swap_id, uint32_t writers,
                                     uint64_t oldest, uint64_t now)
{
    const int mine = g->head && g->head == head && g->head_id == swap_id;
    if (!g->max_wait) return ADRENO_SYNC_GO;
    if (writers && g->stale && oldest && now > oldest && now - oldest >= g->stale) {
        g->stale_seen++;                          /* K2: a mark this old is lost, not a write */
        writers = 0;
    }
    if (!writers) {
        if (mine && now >= g->since && now - g->since > g->max_waited) g->max_waited = now - g->since;
        adreno_sync_forget(g);                    /* this head is done, or the one that waited is no longer the head */
        return ADRENO_SYNC_GO;
    }
    g->busy++;
    if (!mine) { g->head = head; g->head_id = swap_id; g->since = now; g->swaps++; }
    const uint64_t waited = now >= g->since ? now - g->since : 0;
    if (waited >= g->max_wait) {
        if (waited > g->max_waited) g->max_waited = waited;
        g->forced++;
        adreno_sync_forget(g);
        return ADRENO_SYNC_FORCED;
    }
    g->defer++;
    return ADRENO_SYNC_WAIT;
}
static inline void adreno_sync_next_window(struct adreno_sync_gate *g)
{
    g->defer = g->swaps = g->forced = g->max_waited = g->busy = g->stale_seen = 0;
}

/* ---- the perf sync line (K9) ----
 * defer=decisions that left a head queued, swaps=heads that waited at least once, forced=copied at the bound,
 * max_us=longest wait of a head, marks=surface writes marked by IB/FILL32, busy=decisions that found a write,
 * ovf=marks that found no slot (wildcards), stale=marks ignored as lost, unm=unmarks without a mark. */
struct adreno_sync_summary { uint64_t defer, swaps, forced, max_us, marks, busy, overflows, stale, unmatched; };
#ifndef ADRENO_PERF_LINE_MAX
#define ADRENO_PERF_LINE_MAX 250
#endif
#ifndef ADRENO_PERF_CAP
#define ADRENO_PERF_CAP 999999999ull
#endif
static inline unsigned long long adreno_sync_cap(uint64_t v) { return (unsigned long long)(v < ADRENO_PERF_CAP ? v : ADRENO_PERF_CAP); }
static inline int adreno_perf_line_sync(char *buf, size_t size, uint64_t seq, const struct adreno_sync_summary *s)
{
    return snprintf(buf, size, "AdrenoDisplay: perf sync s=%llu defer=%llu swaps=%llu forced=%llu max_us=%llu marks=%llu "
                    "busy=%llu ovf=%llu stale=%llu unm=%llu", adreno_sync_cap(seq), adreno_sync_cap(s->defer),
                    adreno_sync_cap(s->swaps), adreno_sync_cap(s->forced), adreno_sync_cap(s->max_us),
                    adreno_sync_cap(s->marks), adreno_sync_cap(s->busy), adreno_sync_cap(s->overflows),
                    adreno_sync_cap(s->stale), adreno_sync_cap(s->unmatched));
}

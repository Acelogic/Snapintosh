/* SPDX-License-Identifier: MIT */
/* AdrenoDisplayPacing.h - frame pacing counters and the bounded "AdrenoDisplay: perf" console lines
 * (kext batch 8, FAILURES-AND-DESIGN.md 2026-10-20, F1-F11). Header-only C, shared by AdrenoDisplay.cpp
 * (-DADRENO_PERF_FRAMES=1) and tools/replay-adreno-presentation.c.
 *
 * Times are nanoseconds. One record per layer-0 copy (adreno_pacing_copy) and one per frame-timer tick
 * (adreno_pacing_tick); adreno_pacing_summarize reduces a window, adreno_pacing_next_window starts the next
 * one and keeps what spans windows (the previous copy time, the IB count seen). No clock is read here.
 *
 * The console kept 255 bytes of a line in v8 (the old perf line lost cached=, conv=, errors=), so every
 * line is formatted here, every value capped at ADRENO_PERF_CAP, and the worst case stays within
 * ADRENO_PERF_LINE_MAX bytes (the replay checks it). All lines of one window carry the same s=<seq>. */
#pragma once
#include <stdint.h>
#include <string.h>              /* memset: libkern in the kext, libc on the host */
#ifdef KERNEL
#include <libkern/libkern.h>     /* snprintf */
#else
#include <stdio.h>
#endif

#define ADRENO_PACING_BINS 101u              /* 1 ms bins: [b, b+1) ms for b < 100; [100] is 100 ms and more */
#define ADRENO_PERF_LINE_MAX 250
#define ADRENO_PERF_CAP 999999999ull

struct adreno_pacing {
    uint64_t prev_copy;                      /* the previous layer-0 copy, 0 before the first (spans windows) */
    uint64_t seen_ib;                        /* completed IBs at the previous copy (spans windows) */
    uint64_t bins[ADRENO_PACING_BINS];
    uint64_t buckets[5];                     /* intervals <= 17, <= 20, <= 34, <= 50, > 50 ms */
    uint64_t intervals, interval_ns;
    uint64_t copies, on_tick, off_tick;
    uint64_t ticks, ready, missed, idle;
    uint64_t late_n, late_ns;
    uint64_t gpu_n, gpu_ns;
    uint64_t q_n, q_ns;
};
struct adreno_pacing_summary {
    uint64_t pps_x10;                        /* copies per second x 10 over the window's intervals */
    uint64_t buckets[5];
    uint64_t mean_us, p95_ms;                /* p95: upper bound of the 1 ms bin; 101 = beyond 100 ms; 0 empty */
    uint64_t ticks, ready, missed, idle;     /* ready + missed + idle == ticks */
    uint64_t late_us, off, gpu_n, gpu_us, q_us;
};

static inline void adreno_pacing_init(struct adreno_pacing *p) { memset(p, 0, sizeof *p); }

/* A layer-0 copy started at now: from a frame tick (on_tick) or from the submission path; queued is when
 * its swap was first seen pending (0 unknown); ib_count/ib_last are the completed draw submissions and the
 * last one's completion time. */
static inline void adreno_pacing_copy(struct adreno_pacing *p, uint64_t now, int on_tick, uint64_t queued,
                                      uint64_t ib_count, uint64_t ib_last)
{
    p->copies++;
    if (on_tick) p->on_tick++; else p->off_tick++;
    if (p->prev_copy && now >= p->prev_copy) {
        uint64_t d = now - p->prev_copy, ms = d / 1000000u;
        p->intervals++;
        p->interval_ns += d;
        p->bins[ms < ADRENO_PACING_BINS - 1 ? ms : ADRENO_PACING_BINS - 1]++;
        p->buckets[d <= 17000000u ? 0 : d <= 20000000u ? 1 : d <= 34000000u ? 2 : d <= 50000000u ? 3 : 4]++;
    }
    p->prev_copy = now;
    if (ib_count > p->seen_ib && ib_last && ib_last <= now) {   /* F8: never negative */
        p->gpu_n++;
        p->gpu_ns += now - ib_last;
    }
    p->seen_ib = ib_count;
    if (queued && queued <= now) {
        p->q_n++;
        p->q_ns += now - queued;
    }
}

/* A frame tick at now, armed at armed (0 unknown) for period ns. completed: it completed a copied swap;
 * ready: a layer-0 copy started in the same tick. */
static inline void adreno_pacing_tick(struct adreno_pacing *p, uint64_t now, uint64_t armed, uint64_t period,
                                      int completed, int ready)
{
    p->ticks++;
    if (ready) p->ready++; else if (completed) p->missed++; else p->idle++;
    if (armed && armed <= now) {
        p->late_n++;
        if (now - armed > period) p->late_ns += now - armed - period;
    }
}

static inline void adreno_pacing_summarize(const struct adreno_pacing *p, struct adreno_pacing_summary *s)
{
    memset(s, 0, sizeof *s);
    for (unsigned i = 0; i < 5; i++) s->buckets[i] = p->buckets[i];
    if (p->intervals) {
        s->mean_us = p->interval_ns / p->intervals / 1000u;
        s->pps_x10 = p->interval_ns ? p->intervals * 10000000000ull / p->interval_ns : 0;
        uint64_t need = (p->intervals * 95 + 99) / 100, cum = 0;
        for (unsigned b = 0; b < ADRENO_PACING_BINS; b++) {
            cum += p->bins[b];
            if (cum >= need) { s->p95_ms = b + 1; break; }
        }
    }
    s->ticks = p->ticks; s->ready = p->ready; s->missed = p->missed; s->idle = p->idle;
    s->late_us = p->late_n ? p->late_ns / p->late_n / 1000u : 0;
    s->off = p->off_tick;
    s->gpu_n = p->gpu_n;
    s->gpu_us = p->gpu_n ? p->gpu_ns / p->gpu_n / 1000u : 0;
    s->q_us = p->q_n ? p->q_ns / p->q_n / 1000u : 0;
}

static inline void adreno_pacing_next_window(struct adreno_pacing *p)
{
    uint64_t prev = p->prev_copy, seen = p->seen_ib;
    memset(p, 0, sizeof *p);
    p->prev_copy = prev; p->seen_ib = seen;
}

/* ---- the perf lines ---- */
static inline unsigned long long adreno_perf_cap(uint64_t v) { return (unsigned long long)(v < ADRENO_PERF_CAP ? v : ADRENO_PERF_CAP); }
#define ADRENO_PERF_HEAD_FIELDS 7u           /* presents copies win mean_us max_us all_mean_us all_max_us */
#define ADRENO_PERF_SPLIT_FIELDS 9u          /* maint barrier read hash write (us), rows written/compared, skipped, refreshed */
/* GPU-map counters of one window (AdrenoGPUMapCounters, AdrenoMemoryMap.cpp); POOL_LIVE is a level. */
enum {
    ADRENO_MAP_INSERTS, ADRENO_MAP_PAGES_BIND, ADRENO_MAP_PAGES_WIRE, ADRENO_MAP_PAGES_FREE, ADRENO_MAP_CLEARS,
    ADRENO_MAP_STRICT, ADRENO_MAP_POOL_PUT, ADRENO_MAP_POOL_TAKE, ADRENO_MAP_POOL_REFUSED, ADRENO_MAP_POOL_LIVE,
    ADRENO_MAP_VA_BUSY, ADRENO_MAP_VA_COMMIT, ADRENO_MAP_VA_RETRIED, ADRENO_MAP_VA_FAILED, ADRENO_MAP_IBS,
    ADRENO_PERF_MAP_FIELDS
};

/* Each returns the length snprintf reports, which the replay keeps <= ADRENO_PERF_LINE_MAX. */
static inline int adreno_perf_line_head(char *b, size_t n, const char *why, uint64_t seq, const uint64_t *v)
{
    return snprintf(b, n, "AdrenoDisplay: perf why=%.8s s=%llu presents=%llu copies=%llu win=%llu mean_us=%llu "
                    "max_us=%llu all_mean_us=%llu all_max_us=%llu", why, adreno_perf_cap(seq), adreno_perf_cap(v[0]),
                    adreno_perf_cap(v[1]), adreno_perf_cap(v[2]), adreno_perf_cap(v[3]), adreno_perf_cap(v[4]),
                    adreno_perf_cap(v[5]), adreno_perf_cap(v[6]));
}
static inline int adreno_perf_line_split(char *b, size_t n, uint64_t seq, const uint64_t *v)
{
    return snprintf(b, n, "AdrenoDisplay: perf split s=%llu maint_us=%llu barrier_us=%llu read_us=%llu hash_us=%llu "
                    "write_us=%llu rows=%llu/%llu skipped=%llu refreshed=%llu", adreno_perf_cap(seq),
                    adreno_perf_cap(v[0]), adreno_perf_cap(v[1]), adreno_perf_cap(v[2]), adreno_perf_cap(v[3]),
                    adreno_perf_cap(v[4]), adreno_perf_cap(v[5]), adreno_perf_cap(v[6]), adreno_perf_cap(v[7]),
                    adreno_perf_cap(v[8]));
}
static inline int adreno_perf_line_src(char *b, size_t n, uint64_t seq, uint32_t mode, uint64_t attr, unsigned build,
                                       unsigned cached, const uint64_t *conv, uint64_t errors, int last_error)
{
    return snprintf(b, n, "AdrenoDisplay: perf src s=%llu mode=0x%x attr=0x%llx cached=%u/%u conv=%llu/%llu/%llu/%llu/%llu "
                    "errors=%llu last_error=%d", adreno_perf_cap(seq), mode, (unsigned long long)attr, build & 1, cached & 1,
                    adreno_perf_cap(conv[0]), adreno_perf_cap(conv[1]), adreno_perf_cap(conv[2]), adreno_perf_cap(conv[3]),
                    adreno_perf_cap(conv[4]), adreno_perf_cap(errors), last_error);
}
static inline int adreno_perf_line_pace(char *b, size_t n, uint64_t seq, const struct adreno_pacing_summary *s)
{
    unsigned long long pps = adreno_perf_cap(s->pps_x10);
    return snprintf(b, n, "AdrenoDisplay: perf pace s=%llu pps=%llu.%llu pp=%llu/%llu/%llu/%llu/%llu mean=%llu p95=%llu "
                    "tk=%llu/%llu/%llu/%llu late=%llu off=%llu gpu=%llu/%llu q=%llu", adreno_perf_cap(seq), pps / 10, pps % 10,
                    adreno_perf_cap(s->buckets[0]), adreno_perf_cap(s->buckets[1]), adreno_perf_cap(s->buckets[2]),
                    adreno_perf_cap(s->buckets[3]), adreno_perf_cap(s->buckets[4]), adreno_perf_cap(s->mean_us),
                    adreno_perf_cap(s->p95_ms), adreno_perf_cap(s->ticks), adreno_perf_cap(s->ready),
                    adreno_perf_cap(s->missed), adreno_perf_cap(s->idle), adreno_perf_cap(s->late_us),
                    adreno_perf_cap(s->off), adreno_perf_cap(s->gpu_n), adreno_perf_cap(s->gpu_us),
                    adreno_perf_cap(s->q_us));
}
static inline int adreno_perf_line_map(char *b, size_t n, uint64_t seq, const uint64_t *v)
{
    return snprintf(b, n, "AdrenoDisplay: perf map s=%llu ins=%llu pg=%llu/%llu/%llu clr=%llu sfree=%llu "
                    "pool=%llu/%llu/%llu/%llu va=%llu/%llu/%llu/%llu ib=%llu", adreno_perf_cap(seq),
                    adreno_perf_cap(v[ADRENO_MAP_INSERTS]), adreno_perf_cap(v[ADRENO_MAP_PAGES_BIND]),
                    adreno_perf_cap(v[ADRENO_MAP_PAGES_WIRE]), adreno_perf_cap(v[ADRENO_MAP_PAGES_FREE]),
                    adreno_perf_cap(v[ADRENO_MAP_CLEARS]), adreno_perf_cap(v[ADRENO_MAP_STRICT]),
                    adreno_perf_cap(v[ADRENO_MAP_POOL_PUT]), adreno_perf_cap(v[ADRENO_MAP_POOL_TAKE]),
                    adreno_perf_cap(v[ADRENO_MAP_POOL_REFUSED]), adreno_perf_cap(v[ADRENO_MAP_POOL_LIVE]),
                    adreno_perf_cap(v[ADRENO_MAP_VA_BUSY]), adreno_perf_cap(v[ADRENO_MAP_VA_COMMIT]),
                    adreno_perf_cap(v[ADRENO_MAP_VA_RETRIED]), adreno_perf_cap(v[ADRENO_MAP_VA_FAILED]),
                    adreno_perf_cap(v[ADRENO_MAP_IBS]));
}

#if ADRENO_VA_RECLAIM
/* ---- the perf va line (agents/gpu-va, FAILURE-MODES.md G10, G16) ----
 * The GPU VA window's occupancy by the kext's maps and pool: levels (held, peak since the last line, pooled, frozen:
 * MiB; frozen count) and this window's counts (exhausted reserves, reclaims ok/failed, drained entries and MiB, filled
 * strict frees, pressure-refused puts, lost reservations). AdrenoMemoryMap.cpp's AdrenoGPUVACounters fills totals and
 * byte levels; AdrenoDisplay.cpp passes window deltas and MiB. */
enum {
    ADRENO_VA_HELD, ADRENO_VA_PEAK, ADRENO_VA_POOLED, ADRENO_VA_FROZEN, ADRENO_VA_FROZEN_N, ADRENO_VA_EXHAUSTED,
    ADRENO_VA_RECLAIMED, ADRENO_VA_RECLAIM_FAILED, ADRENO_VA_DRAINED, ADRENO_VA_DRAINED_BYTES, ADRENO_VA_FILLED,
    ADRENO_VA_PRESSURE, ADRENO_VA_LOST,
    ADRENO_PERF_VA_FIELDS
};
static inline int adreno_perf_va_level(unsigned i)
{
    return i == ADRENO_VA_HELD || i == ADRENO_VA_PEAK || i == ADRENO_VA_POOLED || i == ADRENO_VA_FROZEN ||
           i == ADRENO_VA_FROZEN_N;
}
static inline int adreno_perf_line_va(char *b, size_t n, uint64_t seq, const uint64_t *v)
{
    return snprintf(b, n, "AdrenoDisplay: perf va s=%llu mib=%llu/%llu pool=%llu frozen=%llu/%llu exh=%llu rcl=%llu/%llu "
                    "drain=%llu/%llu fill=%llu press=%llu lost=%llu", adreno_perf_cap(seq),
                    adreno_perf_cap(v[ADRENO_VA_HELD]), adreno_perf_cap(v[ADRENO_VA_PEAK]),
                    adreno_perf_cap(v[ADRENO_VA_POOLED]), adreno_perf_cap(v[ADRENO_VA_FROZEN]),
                    adreno_perf_cap(v[ADRENO_VA_FROZEN_N]), adreno_perf_cap(v[ADRENO_VA_EXHAUSTED]),
                    adreno_perf_cap(v[ADRENO_VA_RECLAIMED]), adreno_perf_cap(v[ADRENO_VA_RECLAIM_FAILED]),
                    adreno_perf_cap(v[ADRENO_VA_DRAINED]), adreno_perf_cap(v[ADRENO_VA_DRAINED_BYTES]),
                    adreno_perf_cap(v[ADRENO_VA_FILLED]), adreno_perf_cap(v[ADRENO_VA_PRESSURE]),
                    adreno_perf_cap(v[ADRENO_VA_LOST]));
}
#endif

/* ---- the perf gpu line (ADRENO_PERF_GPU, pacing work 2026-10-21, P1-P7) ----
 * Where a window's GPU-side time went: the monitor's CP poll ticks of the IBs (GPU execution; host counter units,
 * converted offline with the run's host_hz) and their maximum; time inside submitIB holding / waiting for its lock;
 * resource preparations (native wire + our rewire + DART inserts) and unwires (clears) with their time; ADRENO_GUEST_CACHE
 * HVCs, bytes and time; residency events and level. Inputs are totals except the max (taken by exchange) and the two
 * levels (RES_BYTES, RES_BUDGET); AdrenoDisplay.cpp passes window deltas, times already in us, bytes in MiB. */
enum {
    ADRENO_GPU_PREPARES, ADRENO_GPU_PREPARE_TICKS, ADRENO_GPU_UNWIRES, ADRENO_GPU_UNWIRE_TICKS, ADRENO_GPU_CACHE_CALLS,
    ADRENO_GPU_CACHE_BYTES, ADRENO_GPU_CACHE_TICKS, ADRENO_GPU_RES_RETAINED, ADRENO_GPU_RES_REUSED, ADRENO_GPU_RES_EVICTED,
    ADRENO_GPU_RES_REFUSED, ADRENO_GPU_RES_BYTES, ADRENO_GPU_RES_BUDGET,
    ADRENO_GPU_IB_TICKS, ADRENO_GPU_IB_TICKS_MAX, ADRENO_GPU_SUBMIT_TICKS, ADRENO_GPU_LOCK_TICKS,
    ADRENO_PERF_GPU_FIELDS
};
static inline int adreno_perf_line_gpu(char *b, size_t n, uint64_t seq, const uint64_t *v)
{
    return snprintf(b, n, "AdrenoDisplay: perf gpu s=%llu gtk=%llu/%llu sub_us=%llu/%llu prep=%llu/%llu unw=%llu/%llu "
                    "cache=%llu/%llu/%llu res=%llu/%llu/%llu/%llu mib=%llu/%llu", adreno_perf_cap(seq),
                    adreno_perf_cap(v[ADRENO_GPU_IB_TICKS]), adreno_perf_cap(v[ADRENO_GPU_IB_TICKS_MAX]),
                    adreno_perf_cap(v[ADRENO_GPU_SUBMIT_TICKS]), adreno_perf_cap(v[ADRENO_GPU_LOCK_TICKS]),
                    adreno_perf_cap(v[ADRENO_GPU_PREPARES]), adreno_perf_cap(v[ADRENO_GPU_PREPARE_TICKS]),
                    adreno_perf_cap(v[ADRENO_GPU_UNWIRES]), adreno_perf_cap(v[ADRENO_GPU_UNWIRE_TICKS]),
                    adreno_perf_cap(v[ADRENO_GPU_CACHE_CALLS]), adreno_perf_cap(v[ADRENO_GPU_CACHE_BYTES]),
                    adreno_perf_cap(v[ADRENO_GPU_CACHE_TICKS]), adreno_perf_cap(v[ADRENO_GPU_RES_RETAINED]),
                    adreno_perf_cap(v[ADRENO_GPU_RES_REUSED]), adreno_perf_cap(v[ADRENO_GPU_RES_EVICTED]),
                    adreno_perf_cap(v[ADRENO_GPU_RES_REFUSED]), adreno_perf_cap(v[ADRENO_GPU_RES_BYTES]),
                    adreno_perf_cap(v[ADRENO_GPU_RES_BUDGET]));
}

/* ---- the phase-locked frame tick (--present-vsync60, FAILURES-AND-DESIGN-VSYNC.md 2026-10-20, S1-S11) ----
 * Unit-agnostic: the kext feeds mach abstime, the replay nanoseconds or a 24 MHz clock. The grid is
 * last + k * period; the timer is armed for one grid point at a time (deadline) and `last` is the grid point of the
 * last tick. Targets are never in the past (S1): from a tick at least period/4 ahead, after idle period/2; missed
 * points are skipped by division and the phase is kept. After an idle longer than idle_limit, or with no grid (first
 * arm, reset), the grid restarts at now + period (S2). adreno_vsync_arm_time arms early by the slop 26A428's
 * thread-call timer adds to a SYS_NORMAL timer, min((x - now) >> 3, lead_max) (S6), so the tick lands on the point. */
struct adreno_vsync {
    uint64_t period, lead_max, idle_limit;
    uint64_t deadline;                       /* the grid point the timer is armed for; 0 = not armed */
    uint64_t last;                           /* the grid point of the last tick; 0 = no grid */
    /* this window */
    uint64_t ticks, late_n, late_sum, late_max, early_n, early_sum, unarmed;
    uint64_t arms, arm_failed, skipped, resync_first, resync_idle, lead_sum;
};
struct adreno_vsync_summary {
    uint64_t period_ns, late_us, late_max_us, early, early_us, skipped, resync_first, resync_idle, lead_us;
    uint64_t arms, arm_failed, unarmed, ticks;
};
static inline uint64_t adreno_vsync_add(uint64_t a, uint64_t b) { return a > UINT64_MAX - b ? UINT64_MAX : a + b; }
static inline void adreno_vsync_init(struct adreno_vsync *v, uint64_t period, uint64_t lead_max, uint64_t idle_limit)
{
    memset(v, 0, sizeof *v);
    v->period = period ? period : 1; v->lead_max = lead_max; v->idle_limit = idle_limit;
}
/* S4: teardown, restart or mode change: nothing armed, no grid; the next arm starts a new one. */
static inline void adreno_vsync_reset(struct adreno_vsync *v) { v->deadline = 0; v->last = 0; }
/* The grid point to arm for at now. in_tick: armed from the tick handler, after adreno_vsync_fired. */
static inline uint64_t adreno_vsync_target(struct adreno_vsync *v, uint64_t now, int in_tick)
{
    const uint64_t p = v->period;
    uint64_t target;
    if (!v->last) {
        target = adreno_vsync_add(now, p);
        v->resync_first++;
    } else if (!in_tick && now > v->last && now - v->last > v->idle_limit) {
        target = adreno_vsync_add(now, p);
        v->resync_idle++;
    } else {
        const uint64_t earliest = adreno_vsync_add(now, in_tick ? p / 4 : p / 2);
        target = adreno_vsync_add(v->last, p);
        if (target < earliest) {
            const uint64_t k = (earliest - target + p - 1) / p;
            v->skipped += k;
            target = k > (UINT64_MAX - target) / p ? UINT64_MAX : target + k * p;
        }
    }
    v->deadline = target;
    v->arms++;
    return target;
}
/* The time to give the timer for target: x with x + min((x - now) >> 3, lead_max) == target (S6); never past. */
static inline uint64_t adreno_vsync_arm_time(struct adreno_vsync *v, uint64_t now, uint64_t target)
{
    if (target <= now) return now;
    uint64_t lead = (target - now) / 9;
    if (lead > v->lead_max) lead = v->lead_max;
    v->lead_sum += lead;
    return target - lead;
}
static inline void adreno_vsync_arm_failed(struct adreno_vsync *v) { v->deadline = 0; v->arm_failed++; }
/* The tick fired at now: its grid point (0 when nothing was armed: a cancel or reset race, S4), lateness against
 * it (S8), early fires counted (S7). The grid point, never the fire time, is what the next target builds on. */
static inline uint64_t adreno_vsync_fired(struct adreno_vsync *v, uint64_t now)
{
    const uint64_t d = v->deadline;
    v->ticks++;
    v->deadline = 0;
    if (!d) { v->unarmed++; return 0; }
    if (now >= d) {
        const uint64_t e = now - d;
        v->late_n++; v->late_sum += e;
        if (e > v->late_max) v->late_max = e;
    } else {
        v->early_n++; v->early_sum += d - now;
    }
    v->last = d;
    return d;
}
static inline void adreno_vsync_next_window(struct adreno_vsync *v)
{
    v->ticks = v->late_n = v->late_sum = v->late_max = v->early_n = v->early_sum = v->unarmed = 0;
    v->arms = v->arm_failed = v->skipped = v->resync_first = v->resync_idle = v->lead_sum = 0;
}
/* to_ns converts timer units to nanoseconds (absolutetime_to_nanoseconds in the kext); sums convert linearly. */
static inline void adreno_vsync_summarize(const struct adreno_vsync *v, uint64_t (*to_ns)(uint64_t),
                                          struct adreno_vsync_summary *s)
{
    memset(s, 0, sizeof *s);
    s->period_ns = to_ns(v->period);
    s->late_us = v->late_n ? to_ns(v->late_sum) / v->late_n / 1000u : 0;
    s->late_max_us = to_ns(v->late_max) / 1000u;
    s->early = v->early_n;
    s->early_us = v->early_n ? to_ns(v->early_sum) / v->early_n / 1000u : 0;
    s->skipped = v->skipped; s->resync_first = v->resync_first; s->resync_idle = v->resync_idle;
    s->lead_us = v->arms ? to_ns(v->lead_sum) / v->arms / 1000u : 0;
    s->arms = v->arms; s->arm_failed = v->arm_failed; s->unarmed = v->unarmed; s->ticks = v->ticks;
}
static inline int adreno_perf_line_vsync(char *b, size_t n, uint64_t seq, const struct adreno_vsync_summary *s)
{
    return snprintf(b, n, "AdrenoDisplay: perf vsync s=%llu period_ns=%llu grid=%llu/%llu early=%llu/%llu skip=%llu "
                    "rs=%llu/%llu lead=%llu arm=%llu/%llu unarmed=%llu ticks=%llu", adreno_perf_cap(seq),
                    adreno_perf_cap(s->period_ns), adreno_perf_cap(s->late_us), adreno_perf_cap(s->late_max_us),
                    adreno_perf_cap(s->early), adreno_perf_cap(s->early_us), adreno_perf_cap(s->skipped),
                    adreno_perf_cap(s->resync_first), adreno_perf_cap(s->resync_idle), adreno_perf_cap(s->lead_us),
                    adreno_perf_cap(s->arms), adreno_perf_cap(s->arm_failed), adreno_perf_cap(s->unarmed),
                    adreno_perf_cap(s->ticks));
}

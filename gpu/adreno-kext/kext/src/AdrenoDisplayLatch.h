/* SPDX-License-Identifier: MIT */
/* AdrenoDisplayLatch.h - the release hold of --present-latch (-DADRENO_LATCH=1; agents/input-latency FAILURE-MODES.md
 * H1-H11) and the perf latch line. Header-only C shared by AdrenoDisplay.cpp and tools/replay-adreno-beam.c. No clock is
 * read here; times are the caller's timebase (mach ticks in the kext).
 *
 * Why: WindowServer renders its next frame when one of its two outstanding swaps completes. The tick that completes the
 * swap on screen also latches the pending one, so the next frame starts rendering at the latch and then waits about a
 * frame for the following latch (b12v6/b12v8: q = 13.3-13.9 ms of a 16.7 ms frame, render R = P - q = 2.8-3.6 ms).
 * The hold copies the pending swap at the latch while the swap on screen stays current, and completes the latter
 * `Rb` before the next latch, Rb = a decaying maximum of the measured render time plus a margin. WindowServer then
 * renders just in time: render start to latch drops from P to Rb.
 *
 * R is measured from each release to the next layer-0 arrival; a latch that finds nothing to show raises it at once. */
#pragma once
#include <stdint.h>
#include <string.h>
#ifdef KERNEL
#include <libkern/libkern.h>     /* snprintf */
#else
#include <stdio.h>
#endif

#define ADRENO_HOLD_FLOOR_US 2000u           /* H1: Rb never below this */

struct adreno_hold {
    int enabled;
    uint64_t margin, floor;                  /* ticks */
    uint64_t r_hi;                           /* decaying maximum of R, ticks (0 = no sample: no hold yet) */
    uint64_t released_at;                    /* the last release, until the next arrival; 0 = none pending */
    /* this window */
    uint64_t r_n, r_sum, r_max, hold_n, hold_sum, rb_last;
    uint64_t precopies, rel_successor, rel_lone, rel_deferred, rel_overdue, misses, ib_after, fallbacks, gated;
};

static inline void adreno_hold_init(struct adreno_hold *h, int enabled, uint64_t margin, uint64_t floor)
{
    memset(h, 0, sizeof *h);
    h->enabled = enabled; h->margin = margin; h->floor = floor;
}
/* H1: the render budget for a frame of `period` ticks: r_hi + margin, at least the floor; period (no hold) until the
 * first R sample or when the budget does not fit. */
static inline uint64_t adreno_hold_budget(const struct adreno_hold *h, uint64_t period)
{
    if (!h->r_hi) return period;
    uint64_t rb = h->r_hi + h->margin;
    if (rb < h->floor) rb = h->floor;
    return rb < period ? rb : period;
}
/* When to release, given the next latch's fire time: Rb before it, never before now (now = release at once). */
static inline uint64_t adreno_hold_release_time(struct adreno_hold *h, uint64_t now, uint64_t next_fire, uint64_t period)
{
    const uint64_t rb = adreno_hold_budget(h, period);
    h->rb_last = rb;
    const uint64_t at = next_fire > now + rb ? next_fire - rb : now;
    h->hold_n++; h->hold_sum += at - now;
    return at;
}
/* A layer-0 swap was first seen pending at now: R since the last release (H11: the first arrival only). */
static inline void adreno_hold_arrival(struct adreno_hold *h, uint64_t now)
{
    if (!h->released_at || now < h->released_at) return;
    const uint64_t r = now - h->released_at;
    h->released_at = 0;
    h->r_n++; h->r_sum += r;
    if (r > h->r_max) h->r_max = r;
    h->r_hi = r > h->r_hi ? r : h->r_hi - h->r_hi / 64;
}
static inline void adreno_hold_released(struct adreno_hold *h, uint64_t now) { h->released_at = now ? now : 1; }
/* H1: a latch with a release before it and nothing to show: R is at least now - release. */
static inline void adreno_hold_missed(struct adreno_hold *h, uint64_t now)
{
    h->misses++;
    if (h->released_at && now > h->released_at && now - h->released_at > h->r_hi) h->r_hi = now - h->released_at;
}
static inline void adreno_hold_next_window(struct adreno_hold *h)
{
    h->r_n = h->r_sum = h->r_max = h->hold_n = h->hold_sum = 0;
    h->precopies = h->rel_successor = h->rel_lone = h->rel_deferred = h->rel_overdue = 0;
    h->misses = h->ib_after = h->fallbacks = h->gated = 0;
}

/* ---- the perf latch line (H9) ----
 * slack=now/peak us, off=lines from the vblank start to the latch point, hold=mean us from latch to release, rb=us,
 * r=samples/mean us/max us, pre=precopies, rel=released with a precopied successor / lone / deferred / overdue at the
 * latch, miss=latches with nothing to show after a release, ibaft=precopies with an IB completed after the swap arrived,
 * fb=latches the hold left to today's path, rs=slack raises by overtake/LATE, gate=fresh copies deferred a latch while
 * the GPU had work (G1-G3). */
struct adreno_latch_summary {
    uint64_t slack_us, slack_peak_us, off, hold_us, rb_us, r_n, r_us, r_max_us, precopies;
    uint64_t rel_successor, rel_lone, rel_deferred, rel_overdue, misses, ib_after, fallbacks, raise_ovt, raise_late, gated;
};
#ifndef ADRENO_PERF_LINE_MAX
#define ADRENO_PERF_LINE_MAX 250
#endif
#ifndef ADRENO_PERF_CAP
#define ADRENO_PERF_CAP 999999999ull
#endif
static inline unsigned long long adreno_latch_cap(uint64_t v, uint64_t cap) { return (unsigned long long)(v < cap ? v : cap); }
static inline int adreno_perf_line_latch(char *buf, size_t size, uint64_t seq, const struct adreno_latch_summary *s)
{
    const uint64_t C = ADRENO_PERF_CAP, U = 99999;
    return snprintf(buf, size, "AdrenoDisplay: perf latch s=%llu slack=%llu/%llu off=%llu hold=%llu rb=%llu r=%llu/%llu/%llu "
                    "pre=%llu rel=%llu/%llu/%llu/%llu miss=%llu ibaft=%llu fb=%llu rs=%llu/%llu gate=%llu",
                    adreno_latch_cap(seq, C), adreno_latch_cap(s->slack_us, U), adreno_latch_cap(s->slack_peak_us, U),
                    adreno_latch_cap(s->off, 9999), adreno_latch_cap(s->hold_us, U), adreno_latch_cap(s->rb_us, U),
                    adreno_latch_cap(s->r_n, C), adreno_latch_cap(s->r_us, U), adreno_latch_cap(s->r_max_us, U),
                    adreno_latch_cap(s->precopies, C), adreno_latch_cap(s->rel_successor, C),
                    adreno_latch_cap(s->rel_lone, C), adreno_latch_cap(s->rel_deferred, C),
                    adreno_latch_cap(s->rel_overdue, C), adreno_latch_cap(s->misses, C), adreno_latch_cap(s->ib_after, C),
                    adreno_latch_cap(s->fallbacks, C), adreno_latch_cap(s->raise_ovt, C), adreno_latch_cap(s->raise_late, C),
                    adreno_latch_cap(s->gated, C));
}

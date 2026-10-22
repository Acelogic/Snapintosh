/* SPDX-License-Identifier: MIT */
/* AdrenoDisplayPipe.h - the perf pipe line (-DADRENO_PIPELINE=1; agents/gpu-pipeline FAILURE-MODES.md O4). Header-only C
 * shared by AdrenoDisplay.cpp (one line per perf window, from AdrenoX2's engine counters) and
 * tools/replay-adreno-latency.c (its caps). No clock and no lock here.
 *
 * on=adreno_pipeline<<1|engine on, then window deltas: fl=IBs that went in flight, ovl=submissions that found a flight
 * (and waited for it), imm=IBs final at START, sync=synchronous clients' IBs, fold=FENCEs folded into a flight,
 * drain=flights finished for a FILL32 or teardown, tmr=flights finished by the completion timer, polls=IB_POLLs,
 * spin_us=submitters' IODelay waiting for a flight, gap_us=mean from a flight's final reply to the next doorbell,
 * max_ms=longest flight since boot, fail=flights that ended in an error. */
#pragma once
#include <stdint.h>
#ifdef KERNEL
#include <libkern/libkern.h>     /* snprintf */
#else
#include <stdio.h>
#endif

/* AdrenoX2's engine totals as AdrenoPipelineCounters fills them (AdrenoX2.cpp), relaxed reads. */
enum { ADRENO_PIPE_C_FLIGHTS, ADRENO_PIPE_C_OVERLAPPED, ADRENO_PIPE_C_IMMEDIATE, ADRENO_PIPE_C_SYNC, ADRENO_PIPE_C_FOLDED,
       ADRENO_PIPE_C_DRAINS, ADRENO_PIPE_C_TIMER, ADRENO_PIPE_C_POLLS, ADRENO_PIPE_C_SPIN_US, ADRENO_PIPE_C_GAP_US,
       ADRENO_PIPE_C_GAP_N, ADRENO_PIPE_C_MAX_US, ADRENO_PIPE_C_FAILURES, ADRENO_PIPE_COUNTERS };
struct adreno_pipe_summary {
    uint64_t on, flights, overlapped, immediate, sync_ibs, folded, drains, timer_finishes, polls, spin_us, gap_us, max_ms,
        failures;
};
#ifndef ADRENO_PERF_LINE_MAX
#define ADRENO_PERF_LINE_MAX 250
#endif
#ifndef ADRENO_PERF_CAP
#define ADRENO_PERF_CAP 999999999ull
#endif
/* One window: totals now against the previous window's (both ADRENO_PIPE_COUNTERS long); state = AdrenoPipelineCounters'. */
static inline void adreno_pipe_window(struct adreno_pipe_summary *s, uint32_t state, const uint64_t *now, const uint64_t *was)
{
    s->on = (state & 1u) | (uint64_t)((state >> 8) & 0xffu) << 1;
    s->flights = now[ADRENO_PIPE_C_FLIGHTS] - was[ADRENO_PIPE_C_FLIGHTS];
    s->overlapped = now[ADRENO_PIPE_C_OVERLAPPED] - was[ADRENO_PIPE_C_OVERLAPPED];
    s->immediate = now[ADRENO_PIPE_C_IMMEDIATE] - was[ADRENO_PIPE_C_IMMEDIATE];
    s->sync_ibs = now[ADRENO_PIPE_C_SYNC] - was[ADRENO_PIPE_C_SYNC];
    s->folded = now[ADRENO_PIPE_C_FOLDED] - was[ADRENO_PIPE_C_FOLDED];
    s->drains = now[ADRENO_PIPE_C_DRAINS] - was[ADRENO_PIPE_C_DRAINS];
    s->timer_finishes = now[ADRENO_PIPE_C_TIMER] - was[ADRENO_PIPE_C_TIMER];
    s->polls = now[ADRENO_PIPE_C_POLLS] - was[ADRENO_PIPE_C_POLLS];
    s->spin_us = now[ADRENO_PIPE_C_SPIN_US] - was[ADRENO_PIPE_C_SPIN_US];
    const uint64_t gaps = now[ADRENO_PIPE_C_GAP_N] - was[ADRENO_PIPE_C_GAP_N];
    s->gap_us = gaps ? (now[ADRENO_PIPE_C_GAP_US] - was[ADRENO_PIPE_C_GAP_US]) / gaps : 0;
    s->max_ms = now[ADRENO_PIPE_C_MAX_US] / 1000u;
    s->failures = now[ADRENO_PIPE_C_FAILURES] - was[ADRENO_PIPE_C_FAILURES];
}
static inline unsigned long long adreno_pipe_cap(uint64_t v) { return (unsigned long long)(v < ADRENO_PERF_CAP ? v : ADRENO_PERF_CAP); }
static inline int adreno_perf_line_pipe(char *buf, size_t size, uint64_t seq, const struct adreno_pipe_summary *s)
{
    return snprintf(buf, size, "AdrenoDisplay: perf pipe s=%llu on=%llu fl=%llu ovl=%llu imm=%llu sync=%llu fold=%llu "
                    "drain=%llu tmr=%llu polls=%llu spin_us=%llu gap_us=%llu max_ms=%llu fail=%llu",
                    adreno_pipe_cap(seq), adreno_pipe_cap(s->on), adreno_pipe_cap(s->flights),
                    adreno_pipe_cap(s->overlapped), adreno_pipe_cap(s->immediate), adreno_pipe_cap(s->sync_ibs),
                    adreno_pipe_cap(s->folded), adreno_pipe_cap(s->drains), adreno_pipe_cap(s->timer_finishes),
                    adreno_pipe_cap(s->polls), adreno_pipe_cap(s->spin_us), adreno_pipe_cap(s->gap_us),
                    adreno_pipe_cap(s->max_ms), adreno_pipe_cap(s->failures));
}

/* SPDX-License-Identifier: MIT */
/* AdrenoDisplayRelatch.h - the relatch (-DADRENO_PRESENT_RELATCH=1; agents/present-pacing FAILURE-MODES.md RL1-RL7, OP1).
 * Header-only C shared by AdrenoDisplay.cpp and tools/replay-adreno-latency.c. No clock, no lock and no beam access here:
 * times and beam positions are the caller's (mach ticks and AdrenoDisplayBeam.h positions in the kext).
 *
 * Why: the present-sync gate defers a layer-0 head whose surface still has a GPU writer at the latch to the next latch, a
 * whole refresh later (b12v17: 7-122 deferrals per 600 copies, each one refresh). The frame that latch chose can still
 * take the copy until shortly before its row 0 is fetched: the copy is a GO's copy (beam-gated, faster than the scan).
 * The relatch asks the write table every `poll` until that deadline and copies the head as soon as it is released; after
 * the deadline it only measures (the release-time histogram), until the next tick ends it. */
#pragma once
#include <stdint.h>
#include <string.h>
#ifdef KERNEL
#include <libkern/libkern.h>     /* snprintf */
#else
#include <stdio.h>
#endif
#include "AdrenoDisplayBeam.h"

#if !ADRENO_LATCH
#error "AdrenoDisplayRelatch.h needs ADRENO_LATCH (the latch's slack sets the relatch's guard)"
#endif

/* OP1: releases after the deferring latch, in bins <1 <2 <3 <4 <6 <9 <17 ms, and not before the next latch */
#define ADRENO_RELATCH_BINS 8u
enum { ADRENO_RELATCH_WAIT = 0, ADRENO_RELATCH_GO = 1, ADRENO_RELATCH_DONE = 2, ADRENO_RELATCH_GONE = 3 };

struct adreno_relatch {
    int enabled;                          /* adreno_relatch: 1 copies, 0 measures only */
    uint64_t poll, guard, ms;             /* ticks: the table poll, the guard, one millisecond (the bins) */
    /* the pending relatch (RL3: the head by identity only, compared and never dereferenced here) */
    int pending, open;                    /* open: the deadline has not passed (a copy may still start) */
    const void *head; uint32_t head_id;
    uint64_t row0, last_pos, since, released;   /* the GO's frame, the last start position, the deferring latch's
                                                 * time, the first time the head was seen released (0 = not yet) */
    /* this window */
    uint64_t armed, go, late, gone, gated, polls, ovt, lead_n, lead_sum, lead_min, wait_sum;
    uint64_t hist[ADRENO_RELATCH_BINS];
};

static inline void adreno_relatch_init(struct adreno_relatch *r, int enabled, uint64_t poll, uint64_t guard, uint64_t ms)
{
    memset(r, 0, sizeof *r);
    r->enabled = enabled; r->poll = poll ? poll : 1; r->guard = guard; r->ms = ms ? ms : 1;
}
/* RL1: the last beam position a relatch copy into the frame whose row 0 leaves at row0 may start from: the fetch margin,
 * 2 lines, the present's head (its maintenance pass and a slow copy's excess, adreno_beam_head), the guard, and the part
 * of the latch's slack that overtakes and LATE fires have added (L1 L2), so the relatch is as careful as the latch. */
static inline uint64_t adreno_relatch_last_pos(const struct adreno_beam *b, uint64_t row0, uint64_t guard)
{
    uint64_t g = guard;
    if (b->slack > b->slack_base) g += b->slack - b->slack_base;
    const uint64_t back = (uint64_t)b->margin + 2 + adreno_beam_head(b) + adreno_beam_lines(b, g);
    return row0 > back ? row0 - back : 0;
}
/* A latch's GO chose the frame of row0 and the sync gate deferred `head` at now: relatch it. */
static inline void adreno_relatch_arm(struct adreno_relatch *r, const struct adreno_beam *b, const void *head, uint32_t id,
                                      uint64_t row0, uint64_t now)
{
    r->pending = 1; r->open = 1; r->head = head; r->head_id = id; r->row0 = row0;
    r->last_pos = adreno_relatch_last_pos(b, row0, r->guard);
    r->since = now; r->released = 0;
    r->armed++;
}
static inline unsigned adreno_relatch_bin(const struct adreno_relatch *r, uint64_t dt)
{
    static const uint8_t edge[ADRENO_RELATCH_BINS - 1] = {1, 2, 3, 4, 6, 9, 17};
    for (unsigned i = 0; i < ADRENO_RELATCH_BINS - 1; i++) if (dt < edge[i] * r->ms) return i;
    return ADRENO_RELATCH_BINS - 1;
}
/* One poll at now: the live head (pointer and swap ID), the beam position, the head's writers (every layer the gate asks
 * for). GO: copy it now into r->row0's frame (the caller still asks the copy gate). WAIT: poll again (r->open: before the
 * deadline; else for the histogram only). DONE: released, nothing to copy (measure only, or after the deadline). GONE:
 * another head (RL3). Every outcome but WAIT and GO ends the relatch. */
static inline int adreno_relatch_check(struct adreno_relatch *r, const void *head, uint32_t id, uint64_t pos,
                                       uint32_t writers, uint64_t now)
{
    if (!r->pending) return ADRENO_RELATCH_GONE;
    if (head != r->head || id != r->head_id) { r->gone++; r->pending = 0; return ADRENO_RELATCH_GONE; }
    r->polls++;
    if (r->open && pos >= r->last_pos) {                  /* RL1: the frame can no longer take it */
        r->open = 0;
        if (writers || !r->released) r->late++;
    }
    if (writers) return ADRENO_RELATCH_WAIT;
    if (!r->released) {
        r->released = now > r->since ? now : r->since + 1;
        r->hist[adreno_relatch_bin(r, r->released - r->since)]++;
    }
    if (r->open && r->enabled) return ADRENO_RELATCH_GO;
    r->pending = 0;
    return ADRENO_RELATCH_DONE;
}
/* The copy gate (G1) refused a GO: poll again (the release stays counted once). */
static inline void adreno_relatch_gated(struct adreno_relatch *r) { r->gated++; }
/* After a GO's swap_begin_gated: copied (the present took row0's frame), its start's lead on row 0 and its wait since the
 * deferring latch (ticks), the beam gates that found an overtake during it (a copy with any is counted once). Ends the
 * relatch. */
static inline void adreno_relatch_copied(struct adreno_relatch *r, int copied, uint64_t lead, uint64_t wait, uint64_t ovt)
{
    r->pending = 0;
    if (!copied) { r->gone++; return; }
    r->go++; r->ovt += ovt ? 1 : 0; r->wait_sum += wait;
    r->lead_n++; r->lead_sum += lead;
    if (!r->lead_min || lead < r->lead_min) r->lead_min = lead;
}
/* A tick that proceeds (RL3 RL4): a head never seen released is binned "not before the next latch". */
static inline void adreno_relatch_tick(struct adreno_relatch *r)
{
    if (!r->pending) return;
    if (!r->released) { r->hist[ADRENO_RELATCH_BINS - 1]++; if (r->open) r->late++; }
    r->pending = 0;
}
static inline void adreno_relatch_cancel(struct adreno_relatch *r) { r->pending = 0; }
static inline void adreno_relatch_next_window(struct adreno_relatch *r)
{
    r->armed = r->go = r->late = r->gone = r->gated = r->polls = r->ovt = 0;
    r->lead_n = r->lead_sum = r->lead_min = r->wait_sum = 0;
    memset(r->hist, 0, sizeof r->hist);
}

/* ---- the perf relatch line (OP1) ----
 * on=relatch|early<<1|urgent<<2, arm=deferrals relatched, go=relatch copies, late=deadline passed before the release,
 * gone=the head changed, gate=GOs the copy gate refused, polls, ovt=relatch copies that overtook the beam, lead=min/mean
 * us from a relatch copy's start to its row 0, wait=mean us from the deferring latch to the copy, rel=releases after the
 * deferring latch (<1 <2 <3 <4 <6 <9 <17 ms, not before the next latch), ef=flights finished before a TO_DEVICE / during
 * one / assist polls, unm=marks released at the finish (agents/present-pacing EP1-EP3). */
#define ADRENO_RELATCH_EARLY_FIELDS 4u    /* pre, assisted, assist polls, early unmarks (AdrenoPipelineEarlyCounters) */
struct adreno_relatch_summary {
    uint64_t on, armed, go, late, gone, gated, polls, ovt, lead_min_us, lead_us, wait_us;
    uint64_t hist[ADRENO_RELATCH_BINS];
    uint64_t early[ADRENO_RELATCH_EARLY_FIELDS];
};
#ifndef ADRENO_PERF_LINE_MAX
#define ADRENO_PERF_LINE_MAX 250
#endif
static inline unsigned long long adreno_relatch_cap(uint64_t v, uint64_t cap) { return (unsigned long long)(v < cap ? v : cap); }
static inline void adreno_relatch_summarize(const struct adreno_relatch *r, uint64_t (*to_ns)(uint64_t), uint64_t on,
                                            const uint64_t *early, struct adreno_relatch_summary *s)
{
    memset(s, 0, sizeof *s);
    s->on = on; s->armed = r->armed; s->go = r->go; s->late = r->late; s->gone = r->gone; s->gated = r->gated;
    s->polls = r->polls; s->ovt = r->ovt;
    s->lead_min_us = to_ns(r->lead_min) / 1000u;
    s->lead_us = r->lead_n ? to_ns(r->lead_sum / r->lead_n) / 1000u : 0;
    s->wait_us = r->go ? to_ns(r->wait_sum / r->go) / 1000u : 0;
    memcpy(s->hist, r->hist, sizeof s->hist);
    if (early) memcpy(s->early, early, sizeof s->early);
}
static inline int adreno_perf_line_relatch(char *buf, size_t size, uint64_t seq, const struct adreno_relatch_summary *s)
{
    const uint64_t C = 99999;
    return snprintf(buf, size, "AdrenoDisplay: perf relatch s=%llu on=%llu arm=%llu go=%llu late=%llu gone=%llu gate=%llu "
                    "polls=%llu ovt=%llu lead=%llu/%llu wait=%llu rel=%llu/%llu/%llu/%llu/%llu/%llu/%llu/%llu "
                    "ef=%llu/%llu/%llu unm=%llu",
                    adreno_relatch_cap(seq, 999999999ull), adreno_relatch_cap(s->on, 7), adreno_relatch_cap(s->armed, C),
                    adreno_relatch_cap(s->go, C), adreno_relatch_cap(s->late, C), adreno_relatch_cap(s->gone, C),
                    adreno_relatch_cap(s->gated, C), adreno_relatch_cap(s->polls, 9999999), adreno_relatch_cap(s->ovt, C),
                    adreno_relatch_cap(s->lead_min_us, C), adreno_relatch_cap(s->lead_us, C), adreno_relatch_cap(s->wait_us, C),
                    adreno_relatch_cap(s->hist[0], C), adreno_relatch_cap(s->hist[1], C), adreno_relatch_cap(s->hist[2], C),
                    adreno_relatch_cap(s->hist[3], C), adreno_relatch_cap(s->hist[4], C), adreno_relatch_cap(s->hist[5], C),
                    adreno_relatch_cap(s->hist[6], C), adreno_relatch_cap(s->hist[7], C), adreno_relatch_cap(s->early[0], C),
                    adreno_relatch_cap(s->early[1], C), adreno_relatch_cap(s->early[2], 9999999),
                    adreno_relatch_cap(s->early[3], C));
}

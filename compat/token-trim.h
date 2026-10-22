/* SPDX-License-Identifier: MIT */
#ifndef SNAP_TOKEN_TRIM_H
#define SNAP_TOKEN_TRIM_H
#include <stdint.h>
#include "cpu.h"
#include "fine-lock.h"
#include "../shadow/sprr-reuse.h"
#include "../shadow/sprr-table-memo.h"

/* SNAP_TOKEN_TRIM (opt-in, default 0; FAILURES-AND-DESIGN.md of batch 5): the
 * two largest holds of the service token that the fine-lock ownership rules let
 * the monitor remove (installed-fresh-20261020-v3: 655 s held, 75% busy).
 *
 * A. Kernel view reuse by write witness. kernel_refresh_impl's exact proof
 *    (sprr_reuse_match: every word of every copied source table equals the
 *    snapshot) re-reads 117 x 512 words on every reuse hit (1.83 M hits,
 *    126.6 s of nested token hold with the one-in-64 verification). The table
 *    memo (shadow/sprr-table-memo.h, SNAP_USER_TREE_MEMO) stamps every arena
 *    page with the clock of its last note, and every post-boot arena store is
 *    noted first. So once the words are proven equal at memo clock P (an exact
 *    hit, or a completed save), a later refresh whose identity and PPERMs are
 *    unchanged and whose source pages all carry stamps <= P is the same hit,
 *    without the reads. Every TOKEN_TRIM_SAMPLE-th such answer is also
 *    compared exactly; a disagreement is terminal (the caller latches
 *    kernel_view_failed) and counted. Anything else takes the exact path.
 *
 * B. Adreno DART MAP/UNMAP (native table 3, endpoints 2 and 3, the virtual
 *    DART SPTM_DART_ADRENO stream 0) as converted calls: the gate shared, no
 *    stripe, the device lock below (FIFO), the token path's body
 *    (sptm_dart_map/unmap and the SMMU CB0 mirror) on a fine memory: the
 *    per-CPU reference batch (atomic deltas), the DART memo, and a publish
 *    that feeds both memos' witnesses (probes/xnuboot.c fine_dart_call).
 *
 * Lock order: gate (shared) < stripes < device < aux. DART calls take no
 * stripe, user calls never take the device lock, the token holder neither.
 *
 * Failure modes (numbers of the design note), and where they are answered:
 *  1-2 an unnoted store, a note/store pair straddling the proof: the memo's
 *      own contract (note before any byte changes, within one critical
 *      section); the proof clock is read after the proof completed; sampled
 *      exact compare, terminal on disagreement.
 *  3   saturated/broken memo: token_trim_witness requires
 *      sprr_table_memo_usable and proof <= clock.
 *  4   a source outside the memo range or recycled: range checked per
 *      source; allocation notes the page; identity compares source PAs.
 *  5   a proof outliving its snapshot: cleared before every save, set only
 *      after a successful one (token_trim_unprove/prove).
 *  6   converted calls' notes: the witness runs under the token only.
 *  7   accounting: a witnessed hit counts calls and hits like a match hit.
 *  8-19 part B: probes/xnuboot.c fine_dart_call.
 *  20-22 defaults, report and prerequisites: below and in xnuboot.c. */
#ifndef SNAP_TOKEN_TRIM
#define SNAP_TOKEN_TRIM 0
#endif
#if SNAP_TOKEN_TRIM
#if !SNAP_FINE_LOCKS || !SNAP_FAST_PAUTH_CALLS
#error "SNAP_TOKEN_TRIM converts calls in the fine-lock dispatcher: build with SNAP_FINE_LOCKS and SNAP_FAST_PAUTH_CALLS"
#endif

#ifndef TOKEN_TRIM_SAMPLE
#define TOKEN_TRIM_SAMPLE 64u
#endif
_Static_assert(TOKEN_TRIM_SAMPLE && !(TOKEN_TRIM_SAMPLE & (TOKEN_TRIM_SAMPLE - 1)), "sample mask");

/* Reported behind "TOKTRIM1" (probes/xnuboot.c OUT_TOKEN_TRIM,
 * tools/perf_counters.py decode_token_trim). Witness words are token-path
 * (plain); device words are written under the device lock. */
struct token_trim_stats {
    uint64_t asks;          /* kernel refreshes that asked the witness */
    uint64_t witnessed;     /* answered by it (each also a reuse hit) */
    uint64_t sampled;       /* witnessed answers also compared exactly */
    uint64_t mismatches;    /* sampled compares that disagreed: terminal, must be 0 */
    uint64_t stale;         /* a source page noted since the proof: exact path */
    uint64_t unproven;      /* no proof, memo unusable, identity or range: exact path */
    uint64_t proofs;        /* proof clocks taken (exact hits, saves) */
    uint64_t dart_maps;     /* converted DART MAPs done */
    uint64_t dart_unmaps;   /* converted DART UNMAPs done */
    uint64_t dart_declines; /* DART calls declined after the device lock (engine) */
    uint64_t device_entries, device_contended, device_wait;  /* the device lock */
    uint64_t reserved[3];
};
_Static_assert(sizeof(struct token_trim_stats) == 16 * 8, "TOKTRIM1 words (perf_counters.py)");
struct token_trim_state {
    uint64_t proof, proven;           /* the memo clock at the last proof; valid */
    struct token_trim_stats stats;
    struct fine_ticket device;        /* part B: the Adreno DART and SMMU mirror */
    uint64_t device_wait[GUEST_CPU_COUNT][2];  /* this CPU's call: device-lock wait ticks, waited */
} __attribute__((aligned(64)));

/* 1: the snapshot is current by witness. 0: no witness (exact path).
 * -2: a copied source page was noted after the proof (exact path). Pure:
 * reads r, v, s and the memo; writes nothing. */
static inline int token_trim_witness(const struct sprr_reuse_state *r,const struct sprr_views *v,
    const struct shadow *s,const uint64_t pp[SPRR_VIEW_CPUS],const struct sprr_table_memo *memo,
    uint64_t proof,uint64_t proven)
{
    if(!proven || !sprr_reuse_configured(v,s,pp) || !r->valid || r->root!=s->root ||
       r->count!=v->count || !sprr_table_memo_usable(memo) || proof>memo->clock)return 0;
    for(unsigned cpu=0;cpu<SPRR_VIEW_CPUS;cpu++)if(r->pperm[cpu]!=pp[cpu])return 0;
    int stale=0;
    for(unsigned n=0;n<v->count;n++) {
        const struct sprr_view_table *a=&r->tables[n],*b=&v->tables[n];
        if(a->source!=b->source || a->level!=b->level || (b->source&4095))return 0;
        for(unsigned cpu=0;cpu<SPRR_VIEW_CPUS;cpu++)if(a->copy[cpu]!=b->copy[cpu])return 0;
        if(b->source<memo->base || (b->source-memo->base)/4096>=memo->pages)return 0;
        stale|=(memo->page[(b->source-memo->base)/4096]>>16)>proof;
    }
    return stale ? -2 : 1;
}
#endif
#endif

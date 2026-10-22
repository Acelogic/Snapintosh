/* SPDX-License-Identifier: MIT */
#pragma once
#include "sprr-view.h"

/* Caller holds the service lock. Save only after a successful full kernel
 * sync/publication; invalidate before any independent private-view mutation.
 * Reuse compares every source descriptor exactly, not a hash or write epoch.
 * Shared branches need no copy update: hardware still reads their canonical
 * tables, and the caller must retain its normal publication and TLBI path. */
struct sprr_reuse_state {
    uint64_t calls,hits,verified,mismatches,errors,saves,invalidations;
    uint64_t valid,root,count,pperm[SPRR_VIEW_CPUS];
    struct sprr_view_table tables[SPRR_VIEW_TABLES];
    uint64_t words[SPRR_VIEW_TABLES][512];
};
static inline void sprr_reuse_invalidate(struct sprr_reuse_state *r)
{r->valid=0;r->invalidations++;}
static inline int sprr_reuse_configured(const struct sprr_views *v,
    const struct shadow *s,const uint64_t pp[SPRR_VIEW_CPUS])
{
    if(!v || !s || !pp || !s->read || !s->root || (s->root&4095) || s->txsz!=17 ||
       s->root!=v->canonical_root || !v->count || v->count>SPRR_VIEW_TABLES)return 0;
    for(unsigned cpu=0;cpu<SPRR_VIEW_CPUS;cpu++)
        if((pp[cpu]&~SPRR_PPERM_MUTABLE)!=SPRR_PPERM_INITIAL)return 0;
    return 1;
}
/* -1 is an invalid/read-failed proof, 0 requires full sync, 1 permits reuse. */
static inline int sprr_reuse_match(struct sprr_reuse_state *r,
    const struct sprr_views *v,const struct shadow *s,const uint64_t pp[SPRR_VIEW_CPUS])
{
    r->calls++;
    if(!sprr_reuse_configured(v,s,pp)) {r->errors++;r->valid=0;return -1;}
    if(!r->valid || r->root!=s->root || r->count!=v->count)return 0;
    for(unsigned cpu=0;cpu<SPRR_VIEW_CPUS;cpu++)if(r->pperm[cpu]!=pp[cpu])return 0;
    for(unsigned n=0;n<v->count;n++) {
        const struct sprr_view_table *a=&r->tables[n],*b=&v->tables[n];
        if(a->source!=b->source || a->level!=b->level)return 0;
        for(unsigned cpu=0;cpu<SPRR_VIEW_CPUS;cpu++)if(a->copy[cpu]!=b->copy[cpu])return 0;
        for(unsigned i=0;i<512;i++) {
            uint64_t word;
            if(s->read(s->ctx,b->source+8UL*i,&word)) {r->errors++;r->valid=0;return -1;}
            if(r->words[n][i]!=word)return 0;
        }
    }
    r->hits++;return 1;
}
#ifndef SNAP_REUSE_MATCH_MAPPED
#define SNAP_REUSE_MATCH_MAPPED 0
#endif
#if SNAP_REUSE_MATCH_MAPPED
/* SNAP_REUSE_MATCH_MAPPED (opt-in; cycle.py installed-fresh
 * --reuse-match-mapped): sprr_reuse_match with each copied source table read
 * through a whole-page reader and compared in one branch-free pass, instead of
 * one reader callback and one branch per word.
 *
 * Why: installed-fresh-neon-20261021-v2 ran 798,532 kernel refreshes under the
 * service token (41.1 s, 51 us each); 797,113 were reuse hits, each re-reading
 * 117 x 512 words through kernel_table_read. Host timing at that shape:
 * 71-74 us per-word, 13 us mapped (analysis/bench-refresh.c).
 *
 * Failure modes, written before the code:
 *  1. A different verdict. Contract: map(map_ctx,pa) for a page-aligned pa
 *     returns non-null only if s->read accepts every word of that page and
 *     reads the same bytes (the monitor's class_table_read and
 *     kernel_table_read share the [work_base,next_table) bound and both read
 *     with plain volatile loads). A table the reader refuses, a source that is
 *     not page-aligned, or a null reader, takes the per-word reads below unchanged, so its
 *     first-mismatch / read-failure order is the original's. A mapped table
 *     either matches in full or returns 0, exactly as the per-word loop would
 *     (no read inside it can fail).
 *  2. Different counters or state: calls, hits, errors and valid change at
 *     exactly the original's points; nothing else is written.
 *  3. A torn comparison: canonical kernel tables change only under the service
 *     token, which every caller holds, as for the per-word reads.
 *  4. A changed default build: the function exists only under the define.
 *  5. Dead flag: probes/xnuboot.c requires SNAP_KERNEL_VIEW_REUSE and
 *     SNAP_CLASS_PROOF_MAPPED (class_table_read) and refuses SNAP_TOKEN_TRIM,
 *     whose witness answers the same call.
 * tools/test-reuse-match-mapped.c drives both forms over random views and
 * corruptions (including refused, straddling and unaligned sources) and
 * requires equal verdicts and states; its mutants must fail. */
static inline int sprr_reuse_match_mapped(struct sprr_reuse_state *r,
    const struct sprr_views *v,const struct shadow *s,const uint64_t pp[SPRR_VIEW_CPUS],
    sprr_table_reader map,void *map_ctx)
{
    r->calls++;
    if(!sprr_reuse_configured(v,s,pp)) {r->errors++;r->valid=0;return -1;}
    if(!r->valid || r->root!=s->root || r->count!=v->count)return 0;
    for(unsigned cpu=0;cpu<SPRR_VIEW_CPUS;cpu++)if(r->pperm[cpu]!=pp[cpu])return 0;
    for(unsigned n=0;n<v->count;n++) {
        const struct sprr_view_table *a=&r->tables[n],*b=&v->tables[n];
        if(a->source!=b->source || a->level!=b->level)return 0;
        for(unsigned cpu=0;cpu<SPRR_VIEW_CPUS;cpu++)if(a->copy[cpu]!=b->copy[cpu])return 0;
        const volatile uint64_t *w=(!map || (b->source&4095)) ? 0 : map(map_ctx,b->source);
        if(!w) {
            for(unsigned i=0;i<512;i++) {
                uint64_t word;
                if(s->read(s->ctx,b->source+8UL*i,&word)) {r->errors++;r->valid=0;return -1;}
                if(r->words[n][i]!=word)return 0;
            }
            continue;
        }
        const uint64_t *saved=r->words[n];
        uint64_t diff=0;
        for(unsigned i=0;i<512;i+=8)
            diff|=(saved[i]^w[i])|(saved[i+1]^w[i+1])|(saved[i+2]^w[i+2])|(saved[i+3]^w[i+3])|
                  (saved[i+4]^w[i+4])|(saved[i+5]^w[i+5])|(saved[i+6]^w[i+6])|(saved[i+7]^w[i+7]);
        if(diff)return 0;
    }
    r->hits++;return 1;
}
#endif
/* Counter-free form of the same exact comparison, for a caller that is not a
 * refresh (the hit/save accounting stays bound to refresh calls). 1 means every
 * copied view equals the saved translation of the CURRENT canonical words
 * under pp; -1 is a read failure (the caller takes its unchanged path). */
static inline int sprr_reuse_current(const struct sprr_reuse_state *r,
    const struct sprr_views *v,const struct shadow *s,const uint64_t pp[SPRR_VIEW_CPUS])
{
    if(!sprr_reuse_configured(v,s,pp))return -1;
    if(!r->valid || r->root!=s->root || r->count!=v->count)return 0;
    for(unsigned cpu=0;cpu<SPRR_VIEW_CPUS;cpu++)if(r->pperm[cpu]!=pp[cpu])return 0;
    for(unsigned n=0;n<v->count;n++) {
        const struct sprr_view_table *a=&r->tables[n],*b=&v->tables[n];
        if(a->source!=b->source || a->level!=b->level)return 0;
        for(unsigned cpu=0;cpu<SPRR_VIEW_CPUS;cpu++)if(a->copy[cpu]!=b->copy[cpu])return 0;
        for(unsigned i=0;i<512;i++) {
            uint64_t word;
            if(s->read(s->ctx,b->source+8UL*i,&word))return -1;
            if(r->words[n][i]!=word)return 0;
        }
    }
    return 1;
}
/* The only permission bit a kernel (user==NULL) view decodes: selector2 A/B.
 * TPRO (bit36) never reaches a kernel copy because raw class9 is refused. */
#define SPRR_KERNEL_VIEW_PPERM UINT64_C(0x100)
/* Re-validate a snapshot after one CPU's permission transaction. Legal only
 * when sprr_reuse_current() returned 1 at the start of that transaction, the
 * transaction changed no canonical word or view identity, and that CPU's copy
 * now equals its translation under pperm (fully synced, or provably unchanged
 * because pperm differs from the old value only outside SPRR_KERNEL_VIEW_PPERM).
 * The other five copies were not written, so the snapshot is exact again. */
static inline int sprr_reuse_repin(struct sprr_reuse_state *r,const struct sprr_views *v,
    unsigned cpu,uint64_t pperm)
{
    if(cpu>=SPRR_VIEW_CPUS || r->count!=v->count || !r->count ||
       (pperm&~SPRR_PPERM_MUTABLE)!=SPRR_PPERM_INITIAL)return 0;
    r->pperm[cpu]=pperm;r->valid=1;return 1;
}
static inline int sprr_reuse_save(struct sprr_reuse_state *r,
    const struct sprr_views *v,const struct shadow *s,const uint64_t pp[SPRR_VIEW_CPUS])
{
    r->valid=0;
    if(!sprr_reuse_configured(v,s,pp)) {r->errors++;return 0;}
    for(unsigned n=0;n<v->count;n++) {
        const struct sprr_view_table *a=&v->tables[n];
        r->tables[n].source=a->source;r->tables[n].level=a->level;
        for(unsigned cpu=0;cpu<SPRR_VIEW_CPUS;cpu++)r->tables[n].copy[cpu]=a->copy[cpu];
        for(unsigned i=0;i<512;i++)
            if(s->read(s->ctx,a->source+8UL*i,&r->words[n][i])) {r->errors++;return 0;}
    }
    r->root=s->root;r->count=v->count;
    for(unsigned cpu=0;cpu<SPRR_VIEW_CPUS;cpu++)r->pperm[cpu]=pp[cpu];
    r->saves++;r->valid=1;return 1;
}

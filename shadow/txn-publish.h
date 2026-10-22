/* SPDX-License-Identifier: MIT */
#pragma once
#include <stdint.h>
#include "root-publish.h"

/* Transaction-end publication from the root dirty bitmap, replacing a clean of
 * every allocated arena line. Same service token, same coverage contract as
 * root installation: every changed store, allocation and pointer mapping is
 * noted before it happens, runtime pages are always cleaned, and guard stores
 * clean themselves. The caller places this exactly where the whole-arena clean
 * was: after the transaction's last store and before its TLBI. No pointer
 * mapped earlier may be written after this call. Validation, private-view
 * refresh and hardware TLBI are unchanged; only cache maintenance is narrowed.
 *
 * Clearing a bit after cleaning its page is exact: a later store re-notes the
 * page. This state never changes root_publish's own call/volume counters.
 *
 * Built-in coverage check: after every successful flush one eligible page is
 * armed as a sentinel with a hash of its contents. Every note touching that
 * page (reported through txn_publish_observe at the same sites as
 * root_publish_note) disarms the check for this interval. At the next flush an
 * unnoted sentinel must hash identically; a difference is a store the bitmap
 * could not have seen, i.e. a page the whole-arena clean would have covered and
 * this one did not. That is terminal and counted; nothing is repaired. Runtime
 * pages and caller-excluded pages (direct guard descriptors) are never armed. */
struct txn_publish_stats {
    uint64_t calls, complete, considered, published, runtime, errors;
    uint64_t armed, checked, noted, retired, mismatches;
    uint64_t sentinel, hash, observed, cursor;
};
static inline uint64_t txn_publish_hash(uint64_t pa)
{
    const volatile uint64_t *w=(const volatile uint64_t *)(uintptr_t)pa;
    uint64_t h=UINT64_C(0xcbf29ce484222325);
    for(unsigned i=0;i<512;i++) {
        h^=w[i]+UINT64_C(0x9e3779b97f4a7c15)*(i+1);
        h*=UINT64_C(0x100000001b3);h^=h>>29;
    }
    return h;
}
/* Call beside every root_publish_note of the arena. size is the noted span. */
static inline void txn_publish_observe(struct txn_publish_stats *s,uint64_t pa,uint64_t size)
{
    /* [pa,pa+size) overlaps [sentinel,sentinel+4096), without overflow. */
    if(s->sentinel && size && pa<s->sentinel+4096 &&
       (pa>=s->sentinel || s->sentinel-pa<size))s->observed=1;
}
/* exclude(ctx,page) returns nonzero for pages written without a note but with
 * their own publication (guard descriptors). hash may be substituted by tests. */
#if SNAP_FINE_LOCKS
/* txn_publish_observe for a converted call: the sentinel is armed only by a
 * token-path flush (stable while the gate is shared); observed is one flag. */
static inline void txn_publish_observe_fine(struct txn_publish_stats *s,uint64_t pa,uint64_t size)
{
    uint64_t sentinel=s->sentinel;
    if(sentinel && size && pa<sentinel+4096 && (pa>=sentinel || sentinel-pa<size))
        __atomic_store_n(&s->observed,1,__ATOMIC_RELAXED);
}
#endif
static inline int txn_publish_flush_with(struct root_publish_state *dirty,
    struct txn_publish_stats *s,uint64_t first,uint64_t allocated,
    int (*publish_page)(void *,uint64_t),int (*exclude)(void *,uint64_t),void *ctx,
    uint64_t (*hash)(uint64_t))
{
    if(s->errors || dirty->errors)return 0;
    s->calls++;
    if(!publish_page || !hash || !root_publish_geometry(first,allocated) ||
       (dirty->always_first|dirty->always_end)&4095 ||
       (dirty->always_first!=dirty->always_end &&
        (dirty->always_end<dirty->always_first || dirty->always_first<first ||
         dirty->always_end>allocated))) {s->errors++;return 0;}
    unsigned pages=(unsigned)((allocated-first)/4096);
    for(unsigned w=0;w<ROOT_PUBLISH_PAGES/64;w++) {
        uint64_t bits=dirty->bitmap[w];
        if(w*64>=pages ? bits!=0 : (pages-w*64<64 && bits>>(pages-w*64))) {
            s->errors++;return 0;
        }
    }
    /* Check the previous interval's sentinel before any cleaning. */
    if(s->sentinel) {
        if(s->observed)s->noted++;
        else if(s->sentinel>=allocated)s->retired++;
        else {
            s->checked++;
            if(hash(s->sentinel)!=s->hash) {s->mismatches++;s->errors++;return 0;}
        }
        s->sentinel=0;
    }
    unsigned published=0,runtime=0;
    for(uint64_t pa=dirty->always_first;pa<dirty->always_end;pa+=4096) {
        if(!publish_page(ctx,pa)) {s->errors++;return 0;}
        runtime++;
    }
    for(unsigned w=0;w<(pages+63)/64;w++) {
        uint64_t bits=dirty->bitmap[w];
        while(bits) {
            unsigned bit=(unsigned)__builtin_ctzll(bits);
            uint64_t pa=first+(uint64_t)(w*64+bit)*4096;
            bits&=bits-1;
            if(pa>=dirty->always_first && pa<dirty->always_end)continue;
            if(!publish_page(ctx,pa)) {s->errors++;return 0;}
            published++;
        }
    }
    /* Every noted page is now clean. Retain all bits on any earlier failure. */
    for(unsigned w=0;w<(pages+63)/64;w++)dirty->bitmap[w]=0;
    s->complete++;s->considered+=pages;s->published+=published;s->runtime+=runtime;
    /* Arm the next sentinel: a rotating sweep over eligible pages. */
    for(unsigned tries=0;tries<pages;tries++) {
        uint64_t index=s->cursor++%pages,pa=first+index*4096;
        if(pa>=dirty->always_first && pa<dirty->always_end)continue;
        if(exclude && exclude(ctx,pa))continue;
        s->sentinel=pa;s->observed=0;s->hash=hash(pa);s->armed++;break;
    }
    return 1;
}
static inline int txn_publish_flush(struct root_publish_state *dirty,
    struct txn_publish_stats *s,uint64_t first,uint64_t allocated,
    int (*publish_page)(void *,uint64_t),int (*exclude)(void *,uint64_t),void *ctx)
{return txn_publish_flush_with(dirty,s,first,allocated,publish_page,exclude,ctx,txn_publish_hash);}

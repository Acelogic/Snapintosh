/* SPDX-License-Identifier: MIT */
/* SNAP_INCREMENTAL_PUBLISH: an index of the root dirty bitmap's newly set
 * bits, so root installation (and transaction-end publication) enumerate the
 * pages noted since the last publish instead of walking every bitmap word of
 * the allocated arena. The bitmap stays authoritative; the index only records
 * which bits root_index_note turned on.
 *
 * Invariant: every set bit outside the always-published runtime range has an
 * entry, unless `overflow` is set. It holds because the three arena note sites
 * (mem_write, table_alloc_owned, sptm_shadow_map) call root_index_note and the
 * only other bitmap writers clear bits (root/txn flush clear all, the private
 * user-view publisher clears selected ones). Entries whose bit was cleared are
 * skipped; duplicates are merged. An overflowed or long index falls back to
 * the unchanged bitmap flush. Pages are published in ascending address order,
 * the same callback sequence as root_publish_flush / txn_publish_flush_with,
 * and every counter those flushes keep is updated identically, so the stopped
 * readers' volume checks still hold. SNAP_INCREMENTAL_PUBLISH_VERIFY compares
 * the listed sequence with a full bitmap enumeration on every listed flush and
 * treats any difference as a terminal tracking error. Service-token serialized,
 * like the bitmap. */
#pragma once
#include <stdint.h>
#include "root-publish.h"
#include "txn-publish.h"

#define ROOT_INDEX_MAX 4096u
/* Listed flushes sort their entries; longer lists take the bitmap scan. */
#define ROOT_INDEX_SORT_MAX 64u
_Static_assert(ROOT_PUBLISH_PAGES<=65536u,"index entries are 16-bit page numbers");
struct root_publish_index {
    uint64_t count,overflow;
    uint64_t notes,appended,overflows,max_count;
    uint64_t flushes,listed,scanned,verified,mismatches,txn_flushes,txn_listed,txn_scanned;
    uint16_t page[ROOT_INDEX_MAX];
};

static inline int root_index_bit(const struct root_publish_state *s,unsigned i)
{return !!(s->bitmap[i/64]&(UINT64_C(1)<<(i%64)));}

/* root_publish_note, recording each page whose bit it turns on. */
static inline int root_index_note(struct root_publish_state *s,struct root_publish_index *x,
    uint64_t first,uint64_t allocated,uint64_t pa,uint64_t size)
{
    /* Exactly root_publish_note's refusals, so a refused note adds nothing. */
    if(s->errors || !root_publish_geometry(first,allocated) || !size || pa<first ||
       pa>=allocated || size>allocated-pa)
        return root_publish_note(s,first,allocated,pa,size);
    unsigned low=(unsigned)((pa-first)/4096),high=(unsigned)((pa-first+size-1)/4096);
    x->notes++;
    for(unsigned i=low;i<=high;i++) {
        if(root_index_bit(s,i))continue;
        if(x->count<ROOT_INDEX_MAX) {x->page[x->count++]=(uint16_t)i;x->appended++;}
        else if(!x->overflow) {x->overflow=1;x->overflows++;}
    }
    if(x->count>x->max_count)x->max_count=x->count;
    return root_publish_note(s,first,allocated,pa,size);
}

static inline void root_index_reset(struct root_publish_index *x)
{x->count=0;x->overflow=0;}

/* Sort and merge duplicates in place; returns the distinct count. */
static inline unsigned root_index_sort(struct root_publish_index *x)
{
    unsigned n=(unsigned)x->count;
    for(unsigned i=1;i<n;i++) {
        uint16_t v=x->page[i];unsigned j=i;
        while(j && x->page[j-1]>v) {x->page[j]=x->page[j-1];j--;}
        x->page[j]=v;
    }
    unsigned out=0;
    for(unsigned i=0;i<n;i++)if(!out || x->page[out-1]!=x->page[i])x->page[out++]=x->page[i];
    x->count=out;return out;
}

/* The ascending union of listed pages and [*ai,always_hi) whose bit is set,
 * one page per call. *li and *ai are cursors (*ai starts at the first runtime
 * page); returns 0 at the end. */
static inline int root_index_next(const struct root_publish_state *s,
    const struct root_publish_index *x,unsigned always_hi,
    unsigned *li,unsigned *ai,unsigned *page)
{
    for(;;) {
        unsigned l=*li<x->count ? x->page[*li] : ~0u;
        unsigned a=*ai<always_hi ? *ai : ~0u;
        unsigned next=l<a ? l : a;
        if(next==~0u)return 0;
        if(l==next)(*li)++;
        if(a==next)(*ai)++;
        if(root_index_bit(s,next)) {*page=next;return 1;}
    }
}

/* Every set bit below `pages`, in the bitmap's own ascending order, must be
 * exactly the listed union. Also refuses any bit at or above `pages`, as the
 * bitmap flushes' validation passes do. 1 = identical. */
static inline int root_index_matches(const struct root_publish_state *s,
    const struct root_publish_index *x,unsigned pages,unsigned always_lo,unsigned always_hi,
    int skip_always)
{
    unsigned li=0,ai=skip_always ? 0 : always_lo,always_end=skip_always ? 0 : always_hi,page;
    for(unsigned w=0;w<ROOT_PUBLISH_PAGES/64;w++) {
        uint64_t bits=s->bitmap[w];
        if(w*64>=pages ? bits!=0 : (pages-w*64<64 && bits>>(pages-w*64)))return 0;
        while(bits) {
            unsigned bit=w*64+(unsigned)__builtin_ctzll(bits);bits&=bits-1;
            if(skip_always && bit>=always_lo && bit<always_hi)continue;
            do {
                if(!root_index_next(s,x,always_end,&li,&ai,&page))return 0;
            } while(skip_always && page>=always_lo && page<always_hi);
            if(page!=bit)return 0;
        }
    }
    while(root_index_next(s,x,always_end,&li,&ai,&page))
        if(!skip_always || page<always_lo || page>=always_hi)return 0;
    return 1;
}

#ifndef SNAP_INCREMENTAL_PUBLISH_VERIFY
#define SNAP_INCREMENTAL_PUBLISH_VERIFY 0
#endif

/* root_publish_flush with the listed enumeration. Same result, callbacks,
 * retained bits on failure and counters. */
static inline int root_index_flush(struct root_publish_state *s,struct root_publish_index *x,
    uint64_t first,uint64_t allocated,int (*publish_page)(void *,uint64_t),void *ctx)
{
    if(s->errors)return 0;
    x->flushes++;
    if(x->overflow || x->count>ROOT_INDEX_SORT_MAX) {
        x->scanned++;
        if(!root_publish_flush(s,first,allocated,publish_page,ctx))return 0;
        root_index_reset(x);return 1;
    }
    s->calls++;
    if(!publish_page || !root_publish_geometry(first,allocated)) {
        s->errors++;return 0;
    }
    unsigned always_lo=0,always_hi=0;
    if(s->always_first || s->always_end) {
        if((s->always_first|s->always_end)&4095 || s->always_end<=s->always_first) {
            s->errors++;return 0;
        }
        if(!root_publish_note(s,first,allocated,s->always_first,
                              s->always_end-s->always_first))return 0;
        always_lo=(unsigned)((s->always_first-first)/4096);
        always_hi=(unsigned)((s->always_end-first)/4096);
    }
    unsigned pages=(unsigned)((allocated-first)/4096),dirty=0,li=0,ai=always_lo,page;
    for(unsigned n=0;n<x->count;n++)if(x->page[n]>=pages) {s->errors++;return 0;}
    root_index_sort(x);
    if(SNAP_INCREMENTAL_PUBLISH_VERIFY) {
        if(!root_index_matches(s,x,pages,always_lo,always_hi,0)) {
            x->mismatches++;s->errors++;return 0;
        }
        x->verified++;
    }
    while(root_index_next(s,x,always_hi,&li,&ai,&page)) {
        if(!publish_page(ctx,first+(uint64_t)page*4096)) {s->errors++;return 0;}
        dirty++;
    }
    /* Clear only after every callback succeeded; a failure retains every bit. */
    for(unsigned n=0;n<x->count;n++)
        s->bitmap[x->page[n]/64]&=~(UINT64_C(1)<<(x->page[n]%64));
    for(unsigned i=always_lo;i<always_hi;i++)s->bitmap[i/64]&=~(UINT64_C(1)<<(i%64));
    root_index_reset(x);x->listed++;
    s->complete++;s->considered+=pages;s->published+=dirty;s->skipped+=pages-dirty;
    return 1;
}

/* txn_publish_flush_with with the listed enumeration: same sentinel check,
 * runtime range first, then noted pages outside it ascending, clear, re-arm. */
static inline int txn_index_flush_with(struct root_publish_state *dirty,struct root_publish_index *x,
    struct txn_publish_stats *s,uint64_t first,uint64_t allocated,
    int (*publish_page)(void *,uint64_t),int (*exclude)(void *,uint64_t),void *ctx,
    uint64_t (*hash)(uint64_t))
{
    if(s->errors || dirty->errors)return 0;
    x->txn_flushes++;
    if(x->overflow || x->count>ROOT_INDEX_SORT_MAX) {
        x->txn_scanned++;
        if(!txn_publish_flush_with(dirty,s,first,allocated,publish_page,exclude,ctx,hash))return 0;
        root_index_reset(x);return 1;
    }
    s->calls++;
    if(!publish_page || !hash || !root_publish_geometry(first,allocated) ||
       (dirty->always_first|dirty->always_end)&4095 ||
       (dirty->always_first!=dirty->always_end &&
        (dirty->always_end<dirty->always_first || dirty->always_first<first ||
         dirty->always_end>allocated))) {s->errors++;return 0;}
    unsigned pages=(unsigned)((allocated-first)/4096);
    unsigned always_lo=(unsigned)(dirty->always_first>first ? (dirty->always_first-first)/4096 : 0);
    unsigned always_hi=(unsigned)(dirty->always_end>first ? (dirty->always_end-first)/4096 : 0);
    if(dirty->always_first==dirty->always_end)always_lo=always_hi=0;
    for(unsigned n=0;n<x->count;n++)if(x->page[n]>=pages) {s->errors++;return 0;}
    root_index_sort(x);
    if(SNAP_INCREMENTAL_PUBLISH_VERIFY) {
        if(!root_index_matches(dirty,x,pages,always_lo,always_hi,1)) {
            x->mismatches++;s->errors++;return 0;
        }
        x->verified++;
    }
    if(s->sentinel) {
        if(s->observed)s->noted++;
        else if(s->sentinel>=allocated)s->retired++;
        else {
            s->checked++;
            if(hash(s->sentinel)!=s->hash) {s->mismatches++;s->errors++;return 0;}
        }
        s->sentinel=0;
    }
    unsigned published=0,runtime=0,li=0,ai=0,page;
    for(uint64_t pa=dirty->always_first;pa<dirty->always_end;pa+=4096) {
        if(!publish_page(ctx,pa)) {s->errors++;return 0;}
        runtime++;
    }
    while(root_index_next(dirty,x,0,&li,&ai,&page)) {
        if(page>=always_lo && page<always_hi)continue;
        if(!publish_page(ctx,first+(uint64_t)page*4096)) {s->errors++;return 0;}
        published++;
    }
    for(unsigned n=0;n<x->count;n++)
        dirty->bitmap[x->page[n]/64]&=~(UINT64_C(1)<<(x->page[n]%64));
    for(unsigned i=always_lo;i<always_hi;i++)dirty->bitmap[i/64]&=~(UINT64_C(1)<<(i%64));
    root_index_reset(x);x->txn_listed++;
    s->complete++;s->considered+=pages;s->published+=published;s->runtime+=runtime;
    for(unsigned tries=0;tries<pages;tries++) {
        uint64_t index=s->cursor++%pages,pa=first+index*4096;
        if(pa>=dirty->always_first && pa<dirty->always_end)continue;
        if(exclude && exclude(ctx,pa))continue;
        s->sentinel=pa;s->observed=0;s->hash=hash(pa);s->armed++;break;
    }
    return 1;
}
static inline int txn_index_flush(struct root_publish_state *dirty,struct root_publish_index *x,
    struct txn_publish_stats *s,uint64_t first,uint64_t allocated,
    int (*publish_page)(void *,uint64_t),int (*exclude)(void *,uint64_t),void *ctx)
{return txn_index_flush_with(dirty,x,s,first,allocated,publish_page,exclude,ctx,txn_publish_hash);}

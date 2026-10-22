/* SPDX-License-Identifier: MIT */
#pragma once
#include <stdint.h>
#include "../compat/monitor-arena.h"

/* Serialized with the monitor service token. This tracks publication, not
 * translation validity: callers retain all tree validation and hardware TLBI.
 * Note allocations before zero/reuse, changed descriptor stores, and every
 * pointer mapping before exposure. The qualified private user-view publisher
 * may clear selected bits after cleaning; other publishers must not clear them.
 * Runtime memory is always
 * included because assembly/hardware can write it without a table callback. */
#define ROOT_PUBLISH_PAGES MONITOR_ARENA_PAGES
struct root_publish_state {
    uint64_t notes, pages_noted, calls, complete, considered, published, skipped, errors;
    uint64_t always_first, always_end;
    uint64_t bitmap[ROOT_PUBLISH_PAGES/64];
};
static inline int root_publish_geometry(uint64_t first,uint64_t allocated)
{
    return !((first|allocated)&4095) && allocated>first &&
        allocated-first<=(uint64_t)ROOT_PUBLISH_PAGES*4096;
}
static inline int root_publish_note(struct root_publish_state *s,uint64_t first,
                                    uint64_t allocated,uint64_t pa,uint64_t size)
{
    if(s->errors)return 0;
    if(!root_publish_geometry(first,allocated) || !size || pa<first ||
       pa>=allocated || size>allocated-pa) {s->errors++;return 0;}
    unsigned low=(unsigned)((pa-first)/4096);
    unsigned high=(unsigned)((pa-first+size-1)/4096);
    for(unsigned i=low;i<=high;i++)s->bitmap[i/64]|=UINT64_C(1)<<(i%64);
    s->notes++;s->pages_noted+=high-low+1;
    return 1;
}
#if SNAP_FINE_LOCKS
#include "../compat/fine-lock.h"
/* root_publish_note for a converted call (compat/fine-lock.h): the same bits
 * and counters by atomic RMW, since converted calls on other roots note at
 * the same time. Only token-path flushes read or clear the bitmap. */
static inline int root_publish_note_fine(struct root_publish_state *s,uint64_t first,
                                         uint64_t allocated,uint64_t pa,uint64_t size)
{
    if(__atomic_load_n(&s->errors,__ATOMIC_RELAXED))return 0;
    if(!root_publish_geometry(first,allocated) || !size || pa<first ||
       pa>=allocated || size>allocated-pa) {fine_add(&s->errors,1);return 0;}
    unsigned low=(unsigned)((pa-first)/4096);
    unsigned high=(unsigned)((pa-first+size-1)/4096);
    for(unsigned i=low;i<=high;i++)
        __atomic_fetch_or(&s->bitmap[i/64],UINT64_C(1)<<(i%64),__ATOMIC_RELAXED);
    fine_add(&s->notes,1);fine_add(&s->pages_noted,high-low+1);
    return 1;
}
#endif
static inline int root_publish_flush(struct root_publish_state *s,uint64_t first,
                                     uint64_t allocated,
                                     int (*publish_page)(void *,uint64_t),void *ctx)
{
    if(s->errors)return 0;
    s->calls++;
    if(!publish_page || !root_publish_geometry(first,allocated)) {
        s->errors++;return 0;
    }
    if(s->always_first || s->always_end) {
        if((s->always_first|s->always_end)&4095 || s->always_end<=s->always_first) {
            s->errors++;return 0;
        }
        if(!root_publish_note(s,first,allocated,s->always_first,
                              s->always_end-s->always_first))return 0;
    }
    unsigned pages=(unsigned)((allocated-first)/4096),dirty=0;
    /* Validate the entire bitmap before issuing a cache-maintenance callback. */
    for(unsigned w=0;w<ROOT_PUBLISH_PAGES/64;w++) {
        uint64_t bits=s->bitmap[w];
        if(w*64>=pages ? bits!=0 : (pages-w*64<64 && bits>>(pages-w*64))) {
            s->errors++;return 0;
        }
    }
    for(unsigned w=0;w<(pages+63)/64;w++) {
        uint64_t bits=s->bitmap[w];
        while(bits) {
            unsigned bit=(unsigned)__builtin_ctzll(bits);
            if(!publish_page(ctx,first+(uint64_t)(w*64+bit)*4096)) {
                s->errors++;return 0;
            }
            dirty++;bits&=bits-1;
        }
    }
    /* On failure retain every bit, including pages already published. Never
     * silently repair or resume after a tracking/publication error. */
    for(unsigned w=0;w<(pages+63)/64;w++)s->bitmap[w]=0;
    s->complete++;s->considered+=pages;s->published+=dirty;s->skipped+=pages-dirty;
    return 1;
}

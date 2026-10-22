/* SPDX-License-Identifier: MIT */
#pragma once
#include <stdint.h>

/* Allocation provenance, not a guess based on the writer callback. Canonical
 * shared/unnest updates use the same callback as private permission copies.
 * Clear a page before every allocation/reuse and retirement; only the allocator
 * used exclusively by sprr_views may mark it private. Serialize with the table
 * allocator and all coverage proofs. No source page may be marked private. */
#include "../compat/monitor-arena.h"
#define SPRR_PRIVATE_PAGES MONITOR_ARENA_PAGES
struct sprr_private_pages {
    uint64_t allocations, private_allocations, retired, writes, private_writes, errors;
    uint64_t bitmap[SPRR_PRIVATE_PAGES/64];
};
static inline int sprr_private_clear(struct sprr_private_pages *p,unsigned index,int retire)
{
    if(index>=SPRR_PRIVATE_PAGES || (retire!=0 && retire!=1)) {p->errors++;return 0;}
    p->bitmap[index/64]&=~(UINT64_C(1)<<(index%64));
    if(retire)p->retired++;else p->allocations++;
    return 1;
}
static inline int sprr_private_mark(struct sprr_private_pages *p,unsigned index)
{
    if(index>=SPRR_PRIVATE_PAGES || (p->bitmap[index/64]&(UINT64_C(1)<<(index%64)))) {
        p->errors++;return 0;
    }
    p->bitmap[index/64]|=UINT64_C(1)<<(index%64);p->private_allocations++;
    return 1;
}
/* Called only for a changed, aligned descriptor in allocated monitor storage.
 * Return1 for a private destination,0 for canonical/other storage,-1 on error.
 * The caller must still advance the epoch for all allocation and recycling. */
static inline int sprr_private_write(struct sprr_private_pages *p,uint64_t first,
                                    uint64_t allocated,uint64_t pa)
{
    if((first|allocated)&4095 || (pa&7) || allocated<=first ||
       allocated-first>(uint64_t)SPRR_PRIVATE_PAGES*4096 ||
       pa<first || pa>=allocated || allocated-pa<8) {p->errors++;return -1;}
    unsigned index=(unsigned)((pa-first)/4096);
    int private=!!(p->bitmap[index/64]&(UINT64_C(1)<<(index%64)));
    p->writes++;p->private_writes+=(unsigned)private;return private;
}
#if SNAP_FINE_LOCKS
#include "../compat/fine-lock.h"
/* sprr_private_write for a converted call: the bitmap changes only on the
 * token path (allocation, release); the counters are atomic. */
static inline int sprr_private_write_fine(struct sprr_private_pages *p,uint64_t first,
                                         uint64_t allocated,uint64_t pa)
{
    if((first|allocated)&4095 || (pa&7) || allocated<=first ||
       allocated-first>(uint64_t)SPRR_PRIVATE_PAGES*4096 ||
       pa<first || pa>=allocated || allocated-pa<8) {fine_add(&p->errors,1);return -1;}
    unsigned index=(unsigned)((pa-first)/4096);
    int private=!!(p->bitmap[index/64]&(UINT64_C(1)<<(index%64)));
    fine_add(&p->writes,1);fine_add(&p->private_writes,(unsigned)private);return private;
}
#endif

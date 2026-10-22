/* SPDX-License-Identifier: MIT */
#pragma once
#include "sprr-view.h"
#include "sprr-class-leaf-memo.h"

/* A whole canonical-tree class exclusion proof. The service lock must cover
 * check, mutation notification and stores. Notify BEFORE every changed table
 * store or zeroing; forget BEFORE pointer-based transactions that bypass the
 * store callback. A newly reachable branch changes a tracked ancestor first.
 * Source pages may not be changed or recycled without that notification.
 * No private descriptor, permission register, publication or TLBI is skipped.
 */
#include "../compat/monitor-arena.h"
#define SPRR_CLASS_PROOF_PAGES MONITOR_ARENA_PAGES
_Static_assert(!SNAP_CLASS_PROOF_WIDE || SPRR_CLASS_WALK_TABLES == SPRR_CLASS_PROOF_PAGES,
               "the wide walk limit is the coverage bitmap's page count");
struct sprr_class_proof {
    uint64_t calls,hits,verified,mismatches,errors,walks,invalidations;
    uint64_t tracked_writes,wide_invalidations,epoch,valid;
    uint64_t root,forbidden,first,limit,saved_epoch;
    struct sprr_view_classes result;
    uint64_t tracked_pages;
    uint64_t bitmap[SPRR_CLASS_PROOF_PAGES/64];
};
static inline int sprr_class_proof_tracked(const struct sprr_class_proof *p,uint64_t pa)
{
    if(pa<p->first || pa>=p->limit)return 0;
    uint64_t page=(pa-p->first)>>12;
    return page<SPRR_CLASS_PROOF_PAGES && !!(p->bitmap[page/64]&(1UL<<(page%64)));
}
static inline void sprr_class_proof_invalidate(struct sprr_class_proof *p)
{
    if(p->valid)p->invalidations++;
    p->valid=0;
    if(p->epoch!=UINT64_MAX)p->epoch++;
}
static inline void sprr_class_proof_note(struct sprr_class_proof *p,uint64_t pa)
{
    if(sprr_class_proof_tracked(p,pa)) {
        p->tracked_writes++;sprr_class_proof_invalidate(p);
    }
}
static inline void sprr_class_proof_forget(struct sprr_class_proof *p)
{p->wide_invalidations++;sprr_class_proof_invalidate(p);}

struct sprr_class_proof_reader {
    struct sprr_class_proof *proof;
    const struct shadow *source;
    int verify;
};
static inline int sprr_class_proof_read(void *ctx,uint64_t pa,uint64_t *out)
{
    struct sprr_class_proof_reader *r=ctx;struct sprr_class_proof *p=r->proof;
    if((pa&7) || pa<p->first || pa>=p->limit || p->limit-pa<8)return -1;
    uint64_t page=(pa-p->first)>>12;
    if(page>=SPRR_CLASS_PROOF_PAGES)return -1;
    uint64_t bit=1UL<<(page%64);
    if(!(p->bitmap[page/64]&bit)) {
        if(r->verify)return -1; /* verification cannot repair missing coverage */
        p->bitmap[page/64]|=bit;p->tracked_pages++;
    }
    return r->source->read(r->source->ctx,pa,out);
}
/* Whole-page form of sprr_class_proof_read for a page-aligned table: pa passes
 * iff every word read of that page would pass (first/limit are page aligned),
 * and marks the page exactly as the first such word read would. The base
 * mapping must apply the source reader's bounds to the whole page. */
struct sprr_class_proof_map_reader {
    struct sprr_class_proof *proof;
    sprr_table_reader base;
    void *base_ctx;
};
static inline const volatile uint64_t *sprr_class_proof_map(void *ctx,uint64_t pa)
{
    struct sprr_class_proof_map_reader *r=ctx;struct sprr_class_proof *p=r->proof;
    if((pa&4095) || pa<p->first || pa>=p->limit || p->limit-pa<4096)return 0;
    uint64_t page=(pa-p->first)>>12;
    if(page>=SPRR_CLASS_PROOF_PAGES)return 0;
    uint64_t bit=1UL<<(page%64);
    if(!(p->bitmap[page/64]&bit)) {p->bitmap[page/64]|=bit;p->tracked_pages++;}
    return r->base(r->base_ctx,pa);
}
static inline int sprr_class_proof_check_with(struct sprr_class_proof *p,
    const struct shadow *s,uint64_t forbidden,uint64_t first,uint64_t limit,
    struct sprr_view_classes *out,sprr_table_reader map,void *map_ctx,
    struct sprr_class_walk_stats *walk);
static inline int sprr_class_proof_check(struct sprr_class_proof *p,
    const struct shadow *s,uint64_t forbidden,uint64_t first,uint64_t limit,
    struct sprr_view_classes *out)
{return sprr_class_proof_check_with(p,s,forbidden,first,limit,out,0,0,0);}
/* map==NULL is the original per-word proof. With map, only a full (miss) walk
 * uses the mapped traversal; every 64th hit still re-walks through the
 * original word reader in verify mode, which rejects any page the mapped walk
 * did not mark and compares its totals with the mapped walk's saved result. */
static inline int sprr_class_proof_check_leaf(struct sprr_class_proof *p,
    const struct shadow *s,uint64_t forbidden,uint64_t first,uint64_t limit,
    struct sprr_view_classes *out,sprr_table_reader map,void *map_ctx,
    struct sprr_class_walk_stats *walk,struct sprr_class_leaf_cache *leaf,
    const struct sprr_table_memo *generations)
{
    if(!p)return 0;
    p->calls++;
    if(leaf && leaf->stats.poisoned) {p->errors++;p->valid=0;return 0;}
    if(!s || !s->read || !out || s->txsz!=17 || (forbidden&~0xffffUL) ||
       !first || ((first|limit)&4095) || first>=limit ||
       limit-first>4096UL*SPRR_CLASS_PROOF_PAGES ||
       s->root<first || s->root>=limit || (s->root&4095)) {
        p->errors++;p->valid=0;return 0;
    }
    int hit=p->valid && p->epoch!=UINT64_MAX && p->saved_epoch==p->epoch &&
        p->root==s->root && p->forbidden==forbidden && p->first==first && p->limit==limit;
    if(hit)p->hits++;
    if(hit && (p->hits&63)) {*out=p->result;return 1;}
    if(hit)p->verified++;
    else {
        p->valid=0;p->root=s->root;p->forbidden=forbidden;p->first=first;p->limit=limit;
        p->tracked_pages=0;
        /* Volatile stores keep this freestanding and avoid a libc memset. */
        volatile uint64_t *bits=p->bitmap;
        for(unsigned i=0;i<SPRR_CLASS_PROOF_PAGES/64;i++)bits[i]=0;
    }
    struct sprr_class_proof_reader reader={p,s,hit};
    struct shadow observed={.txsz=17,.root=s->root,.read=sprr_class_proof_read,.ctx=&reader};
    struct sprr_view_classes full;
    int walked;
    if(map && !hit) {
        struct sprr_class_proof_map_reader mapped={p,map,map_ctx};
        struct shadow direct={.txsz=17,.root=s->root,.ctx=&mapped};
        walked=walk && (leaf ?
            sprr_class_leaf_check(leaf,&direct,forbidden,generations,&full,
                                 sprr_class_proof_map,walk) :
            sprr_views_check_classes_mapped(&direct,forbidden,&full,
                                           sprr_class_proof_map,walk));
    } else walked=sprr_views_check_classes(&observed,forbidden,&full);
    if(!walked ||
       (hit && (full.tables!=p->result.tables || full.pages!=p->result.pages ||
                full.classes!=p->result.classes))) {
        if(hit)p->mismatches++;
        p->errors++;p->valid=0;return 0;
    }
    if(!hit) {
        p->result=full;p->saved_epoch=p->epoch;p->walks++;
        p->valid=p->epoch!=UINT64_MAX;
    }
    *out=full;return 1;
}
static inline int sprr_class_proof_check_with(struct sprr_class_proof *p,
    const struct shadow *s,uint64_t forbidden,uint64_t first,uint64_t limit,
    struct sprr_view_classes *out,sprr_table_reader map,void *map_ctx,
    struct sprr_class_walk_stats *walk)
{return sprr_class_proof_check_leaf(p,s,forbidden,first,limit,out,map,map_ctx,walk,0,0);}

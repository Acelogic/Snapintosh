/* SPDX-License-Identifier: MIT */
#pragma once
#include "shadow.h"
/* SNAP_NATIVE_SHARED (with SNAP_NATIVE_TABLES; docs/NATIVE-TABLES-DESIGN-20260929.md
 * section 11b): one set of 4K level-3 tables for each guest 16K shared-region
 * level-3 table, linked into every nesting 16K user address space, instead
 * of a copy of its leaves in every cached root.
 *
 * A guest 16K level-3 table maps 32 MiB: 2048 leaves of 16K. Its group is up
 * to sixteen 4K level-3 tables of 2 MiB each. Guest leaf j is 4K entries
 * 4*(j%128) .. 4*(j%128)+3 of page j/128, with the output address advancing
 * by 4K and the attributes shadow_map keeps. A page exists only once a leaf
 * of its 2 MiB is valid (XNU nests a whole region whose tables are mostly
 * empty); until then that 2 MiB has no level-2 entry anywhere. A nesting root
 * links the group with the level-2 entries of its existing pages at the
 * group's VA (a nested region sits at the same VA in every address space),
 * and a new page is linked into every linking root before its first leaf.
 * Only fixed native classes are stored in a group, since a group is reachable
 * from every nesting root and every permission variant.
 *
 * Each group records which cached slots link it (one bit per slot), so a
 * released slot gives its links back and a group is freed only when no slot
 * links it. Groups are found by guest table PA through an open-addressing
 * index. Every call is serialized by the caller. Writers go through the
 * shadow callbacks: w (group pages) and s (a root's canonical 4K tree). */
#define NATIVE_SHARED_PAGES 16u
/* Two full regions of 1,824 level-3 tables each (57 GiB, generation78) plus room. */
#define NATIVE_SHARED_GROUPS 4096u
#define NATIVE_SHARED_INDEX 8192u                /* power of two, load <= 1/2 */
/* SNAP_ROOT_CACHE_WIDE (compat/root-wide.h): one link bit per cached slot,
 * 192 of them; struct context keeps the define-free 64-bit twin below. */
#if SNAP_ROOT_CACHE_WIDE
#define NATIVE_SHARED_SLOTS 192u
#define NATIVE_SHARED_SLOT_WORDS (NATIVE_SHARED_SLOTS/64u)
typedef struct {uint64_t w[NATIVE_SHARED_SLOT_WORDS];} native_shared_slots_t;
#define NATIVE_SHARED_SLOT_HAS(m,s) ((((m).w[(s)>>6])>>((s)&63u))&1u)
#define NATIVE_SHARED_SLOT_SET(m,s) ((m).w[(s)>>6]|=UINT64_C(1)<<((s)&63u))
#define NATIVE_SHARED_SLOT_CLEAR(m,s) ((m).w[(s)>>6]&=~(UINT64_C(1)<<((s)&63u)))
#define NATIVE_SHARED_SLOTS_ANY(m) native_shared_slots_any(m)
static inline int native_shared_slots_any(native_shared_slots_t m)
{uint64_t d=0;for(unsigned i=0;i<NATIVE_SHARED_SLOT_WORDS;i++)d|=m.w[i];return d!=0;}
#else
#define NATIVE_SHARED_SLOTS 64u
typedef uint64_t native_shared_slots_t;
#define NATIVE_SHARED_SLOT_HAS(m,s) ((m)>>(s)&1)
#define NATIVE_SHARED_SLOT_SET(m,s) ((m)|=UINT64_C(1)<<(s))
#define NATIVE_SHARED_SLOT_CLEAR(m,s) ((m)&=~(UINT64_C(1)<<(s)))
#define NATIVE_SHARED_SLOTS_ANY(m) (m)
#endif
#define NATIVE_SHARED_SPAN (UINT64_C(1)<<25)     /* 32 MiB: one guest 16K L3 */
_Static_assert(NATIVE_SHARED_GROUPS<0xffffu && NATIVE_SHARED_INDEX>=2*NATIVE_SHARED_GROUPS &&
               !(NATIVE_SHARED_INDEX&(NATIVE_SHARED_INDEX-1)),"native shared index geometry");
struct native_shared_group {
    uint64_t guest;      /* guest 16K L3 table PA; 0: a free record */
    uint64_t shared;     /* the shared root it belongs to */
    uint64_t va;         /* the 32 MiB it maps */
    uint64_t leaves;     /* valid 16K leaves mirrored */
    native_shared_slots_t slots;      /* bit s: cached slot s links it */
    uint64_t pages[NATIVE_SHARED_PAGES];   /* 0: no leaf of that 2 MiB yet */
};
struct native_shared {
    /* errors: refused operations; full: creations refused for want of a
     * record (NATIVE_SHARED_GROUPS). Both are terminal for the audit. stale:
     * slots the caller released because their kept (invalid) trees still
     * linked a group being freed. */
    uint64_t live,created,freed,stores,linked,unlinked,errors,full,stale;
    struct native_shared_group group[NATIVE_SHARED_GROUPS];
    uint16_t index[NATIVE_SHARED_INDEX];   /* group+1 at its guest PA's probe position */
};
#if SNAP_ROOT_CACHE_WIDE
/* The define-free host layout of struct native_shared (64 link bits). */
struct native_shared_group_compat {
    uint64_t guest,shared,va,leaves,slots;
    uint64_t pages[NATIVE_SHARED_PAGES];
};
struct native_shared_compat {
    uint64_t live,created,freed,stores,linked,unlinked,errors,full,stale;
    struct native_shared_group_compat group[NATIVE_SHARED_GROUPS];
    uint16_t index[NATIVE_SHARED_INDEX];
};
#define NATIVE_SHARED_COMPAT native_shared_compat
#else
#define NATIVE_SHARED_COMPAT native_shared
#endif
/* A linking root's canonical tree, for a new page: slot -> its shadow. */
struct native_shared_roots {
    int (*tree)(void *ctx,unsigned slot,struct shadow *out);
    void *ctx;
};
/* Index of the group mirroring guest table `guest`, or -1. */
int native_shared_find(const struct native_shared *,uint64_t guest);
/* The group of shared root `shared`'s guest 16K L3 table `guest`, mapped at
 * va (32 MiB aligned): a zeroed page from w's allocator for each 2 MiB that
 * has a valid leaf, every guest leaf translated into them. Returns its index,
 * or -1 (a non-page or non-native leaf, no free record (full), allocation or
 * read failure). Every guest entry is checked before a page is taken; pages
 * taken before a later failure go to release(release_ctx, pa). */
int native_shared_create(struct native_shared *,const struct shadow *w,uint64_t shared,
                         uint64_t guest,uint64_t va,mmu_read_fn read,void *rctx,
                         void (*release)(void *,uint64_t),void *release_ctx);
/* Before a valid leaf at va: the page of its 2 MiB exists, and every linking
 * root's tree names it (a new page is zeroed, then linked through `roots`
 * into each linking slot's existing level-2 table, whose entry must be 0). */
int native_shared_grow(struct native_shared *,const struct shadow *w,int g,uint64_t va,
                       const struct native_shared_roots *roots);
/* Rewrite the four 4K entries of the 16K leaf at va in group g to `next`
 * (0 clears them; with no page there, nothing is mapped and nothing changes).
 * A valid `next` needs the page (native_shared_grow). Refuses anything else
 * that is not a valid native page. */
int native_shared_store(struct native_shared *,const struct shadow *w,int g,uint64_t va,
                        uint64_t next);
/* Read-only checks for a prepare: the 16K leaf at va in group g holds exactly
 * the translation of the guest value `guest`; `next` could be stored. */
int native_shared_holds(const struct native_shared *,const struct shadow *w,int g,uint64_t va,
                        uint64_t guest);
int native_shared_storable(uint64_t next);
/* Link group g into root tree s for cached slot `slot`: its sixteen 4K L2
 * entries at the group's VA must be empty; tables on the way come from
 * s->alloc. A slot links a group at most once. */
int native_shared_link(struct native_shared *,struct shadow *s,unsigned slot,int g);
/* 1 when those sixteen entries of s name exactly g's existing pages. Read-only. */
int native_shared_linked(const struct native_shared *,const struct shadow *s,int g);
/* Clear a link made by native_shared_link (the entries must name g). */
int native_shared_unlink(struct native_shared *,struct shadow *s,unsigned slot,int g);
/* A released slot's tables are gone: drop its links. */
int native_shared_forget_slot(struct native_shared *,unsigned slot);
/* 1 when cached slot `slot` links group g. */
int native_shared_slot_links(const struct native_shared *,unsigned slot,int g);
/* Free group g, which no slot links; each page goes to release(). */
int native_shared_free(struct native_shared *,int g,void (*release)(void *,uint64_t),void *ctx);
/* Audit: g's pages hold exactly the translation of its guest table, a 2 MiB
 * without a page has no valid guest leaf, g is found through the index, and
 * its leaf count is right. Read-only. */
int native_shared_verify(const struct native_shared *,const struct shadow *w,int g,
                         mmu_read_fn read,void *rctx);

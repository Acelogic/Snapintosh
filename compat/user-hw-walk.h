/* SPDX-License-Identifier: MIT */
#pragma once
/* SNAP_USER_HW_WALK: the hardware walks macOS's own 4K user page tables
 * (SPTM format 1) instead of a monitor-built shadow
 * (docs/USER-HW-WALK-20261017.md). Header-only; probes/xnuboot.c includes it
 * only under the define, and tools/test-user-hw-walk.c tests it on the host.
 *
 * Why it is possible. The A16 has no 16K granule (ID_AA64MMFR0 TGran16=0), so
 * a 16K guest tree can never be walked; with every user pmap forced to 4K
 * (probes/user4k.py, SNAP_KERNEL_USER_4K) the guest's tables are ordinary 4K
 * VMSAv8-64 tables (sptm_mac_user_geometry format 1: L0 root, T0SZ 17, four 4K
 * subtables per 16K typed frame). The SPTM leaf policy
 * (sptm_mac_user_leaf_policy) admits only bits the hardware reads natively,
 * and every admitted user class except TPRO class 9 means the same under
 * SPRR as under plain AP/UXN/PXN (sprr_fixed_native_leaf). Table descriptors
 * carry attributes 3 (or 7, the condemned marker, at level 2): no
 * hierarchical permission bits. The hardware TCR (shadow_tcr) is the same for
 * format 0 and 1 roots: TG0 4K, T0SZ 17.
 *
 * TPRO without S1PIE/S1POE (ID_AA64MMFR3 = 0x1000000000000000). A root with
 * UMPRR18 (the only kind that may hold class 9) never runs on its raw guest
 * root: it runs on one of two monitor copies of the root table, w=0 (TPRO
 * read-only) and w=1 (TPRO writable), plus copies of every table on a path to
 * a class 9 leaf. All other tables are the guest's own, shared by both copies.
 * Each variant has its own hardware ASID, so an EL0 UPERM flip is a TTBR0
 * write. A new class 9 path is linked into the copies (and its VA invalidated)
 * before the raw leaf is stored; every SPTM store into a copied table is
 * re-translated into both copies before the call returns. A root without
 * UMPRR18 runs on its guest root directly.
 *
 * Failure modes this file and its test guard (F-numbers as in the design):
 *  F1  a raw class 9 leaf reachable by hardware (missing or unlinked path);
 *  F2  a path linked without the walk-cache invalidation its leaf needs;
 *  F5  a hardware ASID shared with the slot ASIDs (native_asid) or between
 *      two live roots or variants;
 *  F7  a page-table frame writable by the guest at stage 2 while typed;
 *  F8  stage-2 protection applied to a CPU's tree but not another's, or left
 *      in place after the frame is released;
 *  F9  a copy entry that differs from the translation of its source entry
 *      after a store (stale copy: an unmapped page still reachable);
 *  F10 a hardware-visible leaf with a bit the hardware would interpret beyond
 *      what the policy admits (contiguous, GP, DBM, OA[51:48]);
 *  F11 a table descriptor with hierarchical attributes;
 *  F14 a copy page released while a copied table still links it;
 *  F16 the record table or a variant full: attach refuses (the root keeps the
 *      shadow path), a later path that does not fit is terminal.
 *  F18 a guest descriptor stored in pieces while the hardware walks it: the
 *      SPTM model's 8-byte stores are single accesses (compat/sptm-access.h;
 *      v67's torn leaf, tools/test-descriptor-stores.py).
 * F3/F4/F6/F12/F13/F15/F17 are monitor-side (probes/xnuboot.c): TLBI on every
 * VMID, ASID retirement under ALLE1IS, the shared-region flush, one TCR, the
 * monitor's own walkers, CONFIGURE_ROOT on active roots, 16K roots on the
 * unchanged shadow path. */
#include <stdint.h>
#include "sprr.h"
#include "sptm.h"
#include "sptm-root.h"
#include "sptm-root-policy.h"
/* shadow/ is on every include path (probes/run.py, the host tests). */
#include "mmu.h"
#include "stage2.h"

#define HW_WALK_ROOTS 1024u          /* live hardware-walked user roots */
#define HW_WALK_INDEX (2u*HW_WALK_ROOTS)
#define HW_WALK_TABLES 32u           /* copied tables per UMPRR18 root, root included */
#define HW_WALK_ASID_BASE 0x400u     /* hardware ASIDs: base + 2*record + w */
#define HW_WALK_OWNER 201u           /* table-pool domain of every copy page */
#define HW_WALK_DISCOVER_TABLES 8192u
#define HW_WALK_LEAF_BITS (PT_OA_MASK|PT_LEAF_ATTRS|PT_LEAF_UPPER|3UL|(3UL<<58))
_Static_assert((HW_WALK_INDEX&(HW_WALK_INDEX-1))==0,"open-addressed index is a power of two");
_Static_assert(HW_WALK_ASID_BASE+2u*HW_WALK_ROOTS<=0x10000u,"16-bit hardware ASIDs");
/* The slot ASIDs (probes/xnuboot.c native_asid: 0x100+4*slot+2w+k) end here
 * for the wide cache's 192 slots, and hardware-walk ASIDs start above. */
#define HW_WALK_SLOT_ASID_END (0x100u+4u*192u)
_Static_assert(SPTM_ROOT_CACHE<=192u && HW_WALK_SLOT_ASID_END<=HW_WALK_ASID_BASE,
               "slot ASIDs stay below hardware-walk ASIDs");
_Static_assert(HW_WALK_ROOTS<0xffffu,"record numbers fit the index");

/* Memory access, replaceable on the host. read: guest tables and copies.
 * write: copies only, published (cleaned) before it returns. alloc: a zeroed,
 * published 4K page aliasing nothing. release: a copy page no table links,
 * after the caller's invalidation. table_type: the SPTM type of the frame
 * holding table, or -1. */
struct hw_walk_ops {
    int (*read)(void *ctx,uint64_t pa,uint64_t *out);
    int (*write)(void *ctx,uint64_t pa,uint64_t value);
    uint64_t (*alloc)(void *ctx);
    void (*release)(void *ctx,uint64_t pa);
    int (*table_type)(void *ctx,uint64_t table);
    void *ctx;
};
/* One copied guest table: its two variant copies, its level, the first VA it
 * translates, and the copied parent entry that links it (parent table index,
 * entry index). Parents precede children in the array. */
struct hw_walk_table {
    uint64_t source,va,copy[2];
    uint16_t level,parent,slot,pad;
};
_Static_assert(sizeof(struct hw_walk_table)==40,"copied-table record");
/* entry is the active-root identity monitor paths read where a cached shadow
 * entry used to be (root, XNU's ASID, format 1, flags, valid; no shadow). */
struct hw_walk_root {
    struct sptm_root_cached entry;
    uint64_t umprr;
    uint32_t index,count;            /* own record; copied tables (0: raw root) */
    struct hw_walk_table t[HW_WALK_TABLES];
};
struct hw_walk_stats {
    uint64_t attached,detached,full,fallbacks,installs,refused;
    uint64_t discovered,paths,path_tlbis,refreshes,refreshed,pruned;
    uint64_t verifies,verify_failures,proofs,proof_skips;
    uint64_t s2_protects,s2_unprotects,s2_tables,s2_failures;   /* s2_tables: made at setup (hw_s2_presplit) */
};
/* Locking: everything here is written only by the service-token holder
 * (with SNAP_FINE_LOCKS, the exclusive gate: probes/xnuboot.c FINE_HW_ROOT
 * keeps converted calls away from hardware-walk roots). The lock-free EL0
 * crossing paths (fast_select, user_return_root) only look up the root they
 * run on, whose record cannot change while it is installed; a concurrent
 * index edit for another root can make that lookup miss, never return a
 * different root, and a miss declines to the locked path. Index words are
 * therefore loaded and stored single-copy atomically. */
struct hw_walk_state {
    uint32_t used,pad;
    uint16_t index[HW_WALK_INDEX];   /* record+1, 0 empty */
    struct hw_walk_stats stats;
    struct hw_walk_root roots[HW_WALK_ROOTS];
};

static inline uint64_t hw_walk_span(unsigned level)
{return UINT64_C(1)<<(12+9*(3-level));}
static inline unsigned hw_walk_slot_index(unsigned level,uint64_t va)
{return (unsigned)((va>>(12+9*(3-level)))&511);}
static inline unsigned hw_walk_hash(uint64_t root)
{return (unsigned)(((uint32_t)(root>>14)*UINT32_C(0x9e3779b1))>>21)&(HW_WALK_INDEX-1);}
_Static_assert(HW_WALK_INDEX==2048u,"hw_walk_hash keeps 11 bits");

static inline struct hw_walk_root *hw_walk_find(struct hw_walk_state *st,uint64_t root)
{
    if(!st || !root || (root&0x3fff))return 0;
    unsigned i=hw_walk_hash(root);
    for(unsigned n=0;n<HW_WALK_INDEX;n++,i=(i+1)&(HW_WALK_INDEX-1)) {
        unsigned r=__atomic_load_n(&st->index[i],__ATOMIC_ACQUIRE);
        if(!r)return 0;
        if(r<=HW_WALK_ROOTS && __atomic_load_n(&st->roots[r-1].entry.root,__ATOMIC_RELAXED)==root)
            return &st->roots[r-1];
    }
    return 0;
}
/* The record whose pseudo cache entry e is, or 0 (e is a real cache entry). */
static inline struct hw_walk_root *hw_walk_of_entry(struct hw_walk_state *st,
                                                    const struct sptm_root_cached *e)
{
    if(!st || !e)return 0;
    uintptr_t base=(uintptr_t)&st->roots[0],at=(uintptr_t)e;
    if(at<base || at>=(uintptr_t)&st->roots[HW_WALK_ROOTS])return 0;
    if((at-base)%sizeof(struct hw_walk_root))return 0;
    return &st->roots[(at-base)/sizeof(struct hw_walk_root)];
}
static inline unsigned hw_walk_asid(const struct hw_walk_root *r,unsigned w)
{return HW_WALK_ASID_BASE+2u*r->index+(r->count ? (w&1u) : 0u);}
/* The TTBR0 value of variant w: a copy of the root for an UMPRR18 root, the
 * guest root itself otherwise; each with its own hardware ASID. */
static inline uint64_t hw_walk_ttbr0(const struct hw_walk_root *r,unsigned w)
{
    uint64_t table=r->count ? r->t[0].copy[w&1u] : r->entry.root;
    return table|((uint64_t)hw_walk_asid(r,w)<<48);
}
/* Bits the hardware reads in a leaf, against the policy's admitted set. */
static inline int hw_walk_leaf_bits_ok(uint64_t d)
{return (d&3)==3 && !(d&~HW_WALK_LEAF_BITS);}
static inline int hw_walk_table_ok(unsigned level,uint64_t d)
{
    uint64_t attrs=d&~PT_OA_MASK;
    return (d&PT_OA_MASK) && (attrs==3 || (level==2 && attrs==7));
}
static inline int hw_walk_copied(const struct hw_walk_root *r,uint64_t source)
{
    for(unsigned n=0;n<r->count && n<HW_WALK_TABLES;n++)if(r->t[n].source==source)return (int)n;
    return -1;
}
/* What variant w's copy of table n holds at index i for source entry d:
 * invalid entries as they are; a table pointer redirected to the child's copy
 * when the child has one; a native leaf as it is; class 9 data-only for EL0
 * and EL1, read-only unless w, never executable. 0: no translation. */
static inline int hw_walk_decode(const struct hw_walk_root *r,unsigned n,uint64_t d,
                                 unsigned i,unsigned w,uint64_t *out)
{
    const struct hw_walk_table *t=&r->t[n];
    if(!(d&1)) {*out=d;return 1;}
    if(!t->level && i>=256)return 0;
    if(t->level<3) {
        if(!hw_walk_table_ok(t->level,d))return 0;
        int child=hw_walk_copied(r,d&PT_OA_MASK);
        if(child>=0) {
            if(r->t[child].level!=t->level+1u)return 0;
            d=(d&~PT_OA_MASK)|r->t[child].copy[w&1u];
        }
        *out=d;return 1;
    }
    if(!hw_walk_leaf_bits_ok(d))return 0;
    if(sprr_pte_class(d)==9) {
        if((r->umprr&0xc0000)!=0x40000)return 0;
        d=(d&~(PT_AP|PT_PXN|PT_UXN))|PT_PXN|PT_UXN|(UINT64_C(1)<<6);
        if(!(w&1u))d|=UINT64_C(2)<<6;
    } else if(!sprr_fixed_native_leaf(d))return 0;
    *out=d;return 1;
}
/* Re-translate entries i0..i1 of table n into both copies (stores only what
 * changed). 0: an untranslatable source entry or an access failure. */
static inline int hw_walk_translate(const struct hw_walk_ops *o,struct hw_walk_root *r,
                                    unsigned n,unsigned i0,unsigned i1,uint64_t *stored)
{
    const struct hw_walk_table *t=&r->t[n];
    for(unsigned i=i0;i<=i1 && i<512;i++) {
        uint64_t d;
        if(o->read(o->ctx,t->source+8UL*i,&d))return 0;
        for(unsigned w=0;w<2;w++) {
            uint64_t want,have;
            if(!hw_walk_decode(r,n,d,i,w,&want) || o->read(o->ctx,t->copy[w]+8UL*i,&have))return 0;
            if(have!=want) {
                if(o->write(o->ctx,t->copy[w]+8UL*i,want))return 0;
                if(stored)(*stored)++;
            }
        }
    }
    return 1;
}
static inline int hw_walk_in_use(const struct hw_walk_root *r,uint64_t pa)
{
    for(unsigned n=0;n<r->count;n++)
        if(r->t[n].source==pa || r->t[n].copy[0]==pa || r->t[n].copy[1]==pa)return 1;
    return 0;
}
/* Append a copied table (both copies zero, not yet linked). -1 when full. */
static inline int hw_walk_add(const struct hw_walk_ops *o,struct hw_walk_root *r,uint64_t source,
                              unsigned level,uint64_t va,unsigned parent,unsigned slot)
{
    if(r->count>=HW_WALK_TABLES || !source || (source&4095) || level>3 ||
       hw_walk_copied(r,source)>=0)return -1;
    uint64_t copy[2];
    for(unsigned w=0;w<2;w++) {
        copy[w]=o->alloc(o->ctx);
        if(!copy[w] || (copy[w]&4095) || copy[w]==source || hw_walk_in_use(r,copy[w]) ||
           (w && copy[0]==copy[1])) {
            for(unsigned k=0;k<=w && k<2;k++)if(copy[k])o->release(o->ctx,copy[k]);
            return -1;
        }
    }
    struct hw_walk_table *t=&r->t[r->count];
    *t=(struct hw_walk_table){.source=source,.va=va,.copy={copy[0],copy[1]},
                              .level=(uint16_t)level,.parent=(uint16_t)parent,.slot=(uint16_t)slot};
    return (int)r->count++;
}
/* The guest path to va: path[level] for levels 0..3 (table addresses). The
 * level-3 entry itself may be anything. 0 when a level is not a table. */
static inline int hw_walk_path(const struct hw_walk_ops *o,const struct hw_walk_root *r,
                               uint64_t va,uint64_t path[4])
{
    path[0]=r->entry.root;
    for(unsigned level=0;level<3;level++) {
        uint64_t d;
        if(o->read(o->ctx,path[level]+8UL*hw_walk_slot_index(level,va),&d) ||
           !(d&1) || !hw_walk_table_ok(level,d))return 0;
        path[level+1]=d&PT_OA_MASK;
        for(unsigned k=0;k<=level;k++)if(path[k]==path[level+1])return 0;
    }
    return 1;
}
/* Copy the path to va (4K aligned, below 2^47) where missing and link it into
 * the existing copies. 1: nothing added. 2: a path was linked; the caller
 * invalidates walk caches for va (every VMID) BEFORE storing the class 9
 * leaf (F2). 0: failure (refuse the call). Only a private PAGE_TABLE level-3
 * table may hold class 9 (the leaf policy). */
static inline int hw_walk_prepare(const struct hw_walk_ops *o,struct hw_walk_root *r,uint64_t va)
{
    uint64_t path[4];
    if(!o || !r || !r->count || (va&4095) || va>=(UINT64_C(1)<<47) || !hw_walk_path(o,r,va,path))
        return 0;
    if(o->table_type && o->table_type(o->ctx,path[3])!=SPTM_MAC_PAGE_TABLE)return 0;
    int index[4];unsigned added=0;
    for(unsigned level=0;level<4;level++) {
        index[level]=hw_walk_copied(r,path[level]);
        if(index[level]>=0 && r->t[index[level]].level!=level)return 0;
        if(level && index[level]>=0 && index[level-1]<0)return 0;
    }
    if(index[0]!=0)return 0;
    unsigned first=r->count;
    for(unsigned level=1;level<4;level++) {
        if(index[level]>=0)continue;
        uint64_t base=r->t[index[level-1]].va+(uint64_t)hw_walk_slot_index(level-1,va)*hw_walk_span(level-1);
        index[level]=hw_walk_add(o,r,path[level],level,base,(unsigned)index[level-1],
                                 hw_walk_slot_index(level-1,va));
        if(index[level]<0)break;
        added++;
    }
    if(!added && index[3]>=0)return 1;
    /* Fill the still unreachable copies bottom-up, then link the topmost new
     * one with one store per variant into its existing parent's copies. Until
     * that store nothing can reach them: a failure (no room included) gives
     * them back. */
    int filled=index[1]>=0 && index[2]>=0 && index[3]>=0;
    for(unsigned level=4;filled && level-->1;) {
        unsigned n=(unsigned)index[level];
        if(n>=first && !hw_walk_translate(o,r,n,0,511,0))filled=0;
    }
    if(!filled) {
        for(unsigned n=first;n<r->count;n++)
            for(unsigned w=0;w<2;w++)o->release(o->ctx,r->t[n].copy[w]);
        r->count=first;return 0;
    }
    for(unsigned level=1;level<4;level++) {
        unsigned n=(unsigned)index[level];
        if(n<first)continue;
        if(!hw_walk_translate(o,r,r->t[n].parent,r->t[n].slot,r->t[n].slot,0))return 0;
        break;
    }
    return 2;
}
/* Re-translate every copied entry whose VA span meets [va, va+size) (size 0:
 * every entry). Required after each SPTM store into a guest table of a root
 * with copies, before the call returns (F9). */
static inline int hw_walk_refresh(const struct hw_walk_ops *o,struct hw_walk_root *r,
                                  uint64_t va,uint64_t size,uint64_t *stored)
{
    if(!o || !r)return 0;
    uint64_t end=size ? va+size : 0;
    if(size && end<va)end=UINT64_MAX;
    for(unsigned n=0;n<r->count;n++) {
        const struct hw_walk_table *t=&r->t[n];
        uint64_t span=hw_walk_span(t->level),lo=t->va,hi=t->va+512*span;
        unsigned i0=0,i1=511;
        if(size) {
            if(end<=lo || va>=hi)continue;
            if(va>lo)i0=(unsigned)((va-lo)/span);
            if(end<hi)i1=(unsigned)((end-1-lo)/span);
        }
        if(!hw_walk_translate(o,r,n,i0,i1,stored))return 0;
    }
    return 1;
}
/* Drop copied tables their guest parent no longer links (UNMAP_TABLE,
 * UNNEST), after hw_walk_refresh rewrote the parent entries. Their pages go to
 * pages[] (capacity HW_WALK_TABLES*2) for release AFTER the caller's TLBI
 * (F14). Returns the number of pages, or -1. */
static inline int hw_walk_prune(const struct hw_walk_ops *o,struct hw_walk_root *r,uint64_t *pages)
{
    if(!o || !r || !r->count)return 0;
    uint8_t alive[HW_WALK_TABLES]={0};
    alive[0]=1;
    for(unsigned n=1;n<r->count;n++) {
        const struct hw_walk_table *t=&r->t[n];
        uint64_t d;
        if(t->parent>=n)return -1;
        if(!alive[t->parent])continue;
        if(o->read(o->ctx,r->t[t->parent].source+8UL*t->slot,&d))return -1;
        alive[n]=(d&1) && hw_walk_table_ok(r->t[t->parent].level,d) && (d&PT_OA_MASK)==t->source;
    }
    int released=0;uint16_t map[HW_WALK_TABLES];unsigned kept=0;
    for(unsigned n=0;n<r->count;n++) {
        if(!alive[n]) {pages[released++]=r->t[n].copy[0];pages[released++]=r->t[n].copy[1];continue;}
        map[n]=(uint16_t)kept;
        struct hw_walk_table t=r->t[n];
        if(n)t.parent=map[t.parent];
        /* Field by field through a volatile pointer, moving down: no memmove
         * call in the monitor, and no uint64_t view of the struct. That
         * type-punned read let -Os (the monitor's level) load the words
         * before the remapped parent was stored, so the copies kept their old
         * parent index (installed-fresh-20261018-v55: record 1's level-3
         * copies named themselves as parent and the next UNMAP_TABLE's prune
         * refused, SPTM_SHADOW_FAILED). */
        volatile struct hw_walk_table *to=&r->t[kept++];
        to->source=t.source;to->va=t.va;to->copy[0]=t.copy[0];to->copy[1]=t.copy[1];
        to->level=t.level;to->parent=t.parent;to->slot=t.slot;to->pad=t.pad;
    }
    r->count=kept;
    /* Parents that linked a dropped copy now hold the guest descriptor. */
    if(released && !hw_walk_refresh(o,r,0,0,0))return -1;
    return released;
}
/* Every class 9 leaf below table under policy: mark(va) per leaf. Private
 * tables only: SHARED and COMMPAGE children (types 21/23) cannot hold class 9
 * and are not entered. 0 on a malformed table or the table bound. */
static inline int hw_walk_scan(const struct hw_walk_ops *o,struct hw_walk_root *r,uint64_t table,
    unsigned level,uint64_t base,unsigned *tables,int (*mark)(const struct hw_walk_ops *,
    struct hw_walk_root *,uint64_t,void *),void *arg)
{
    if(!table || (table&4095) || ++*tables>HW_WALK_DISCOVER_TABLES)return 0;
    for(unsigned i=0;i<512;i++) {
        uint64_t d;
        if(o->read(o->ctx,table+8UL*i,&d))return 0;
        if(!(d&1))continue;
        if(!level && i>=256)return 0;
        uint64_t va=base+(uint64_t)i*hw_walk_span(level);
        if(level<3) {
            if(!hw_walk_table_ok(level,d))return 0;
            int type=o->table_type ? o->table_type(o->ctx,d&PT_OA_MASK) : SPTM_MAC_PAGE_TABLE;
            if(type==SPTM_MAC_PAGE_TABLE_SHARED || type==SPTM_MAC_PAGE_TABLE_COMMPAGE)continue;
            if(type!=SPTM_MAC_PAGE_TABLE ||
               !hw_walk_scan(o,r,d&PT_OA_MASK,level+1,va,tables,mark,arg))return 0;
        } else if(!hw_walk_leaf_bits_ok(d))return 0;
        else if(sprr_pte_class(d)==9) {
            if(!mark || !mark(o,r,va,arg))return 0;
        } else if(!sprr_fixed_native_leaf(d))return 0;
    }
    return 1;
}
static inline int hw_walk_mark_prepare(const struct hw_walk_ops *o,struct hw_walk_root *r,
                                       uint64_t va,void *arg)
{(void)arg;return hw_walk_prepare(o,r,va)!=0;}
static inline int hw_walk_mark_covered(const struct hw_walk_ops *o,struct hw_walk_root *r,
                                       uint64_t va,void *arg)
{
    (void)arg;uint64_t path[4];
    if(!r->count || !hw_walk_path(o,r,va,path))return 0;
    for(unsigned level=0;level<4;level++) {
        int n=hw_walk_copied(r,path[level]);
        if(n<0 || r->t[n].level!=level)return 0;
    }
    return 1;
}
/* Audit, read-only. Every copied entry equals the translation of its source,
 * every copy links where its record says, and (deep) every class 9 leaf of
 * the guest tree lies on a copied path. */
static inline int hw_walk_verify(const struct hw_walk_ops *o,struct hw_walk_root *r,int deep,
                                 unsigned *tables)
{
    if(!o || !r || r->count>HW_WALK_TABLES)return 0;
    if(r->count && (r->t[0].source!=r->entry.root || r->t[0].level || r->t[0].va))return 0;
    for(unsigned n=0;n<r->count;n++) {
        const struct hw_walk_table *t=&r->t[n];
        if(!t->source || (t->source&4095) || t->level>3 || hw_walk_copied(r,t->source)!=(int)n)
            return 0;
        for(unsigned w=0;w<2;w++) {
            uint64_t pa=t->copy[w];
            if(!pa || (pa&4095) || hw_walk_copied(r,pa)>=0)return 0;
            for(unsigned k=0;k<r->count;k++)for(unsigned e=0;e<2;e++)
                if((k!=n || e!=w) && r->t[k].copy[e]==pa)return 0;
        }
        if(n) {
            const struct hw_walk_table *p=&r->t[t->parent];uint64_t d;
            if(t->parent>=n || p->level+1u!=t->level ||
               t->va!=p->va+(uint64_t)t->slot*hw_walk_span(p->level) ||
               o->read(o->ctx,p->source+8UL*t->slot,&d) || !(d&1) || (d&PT_OA_MASK)!=t->source)
                return 0;
        }
        for(unsigned i=0;i<512;i++) {
            uint64_t d,copy,want;
            if(o->read(o->ctx,t->source+8UL*i,&d))return 0;
            for(unsigned w=0;w<2;w++)
                if(!hw_walk_decode(r,n,d,i,w,&want) || o->read(o->ctx,t->copy[w]+8UL*i,&copy) ||
                   copy!=want)return 0;
        }
    }
    if(!deep)return 1;
    unsigned seen=0;
    int ok=hw_walk_scan(o,r,r->entry.root,0,0,&seen,hw_walk_mark_covered,0);
    if(tables)*tables=seen;
    return ok;
}
/* Give every copy back (the caller has invalidated) and forget the record. */
static inline void hw_walk_release(const struct hw_walk_ops *o,struct hw_walk_root *r)
{
    for(unsigned n=0;n<r->count && n<HW_WALK_TABLES;n++)
        for(unsigned w=0;w<2;w++)if(r->t[n].copy[w])o->release(o->ctx,r->t[n].copy[w]);
    r->count=0;
}
static inline void hw_walk_unindex(struct hw_walk_state *st,unsigned record)
{
    unsigned i=hw_walk_hash(st->roots[record].entry.root);
    for(unsigned n=0;n<HW_WALK_INDEX && st->index[i]!=record+1u;n++)i=(i+1)&(HW_WALK_INDEX-1);
    if(st->index[i]!=record+1u)return;
    /* Backward-shift deletion: no tombstones, every probe chain stays intact. */
    for(unsigned j=i;;) {
        __atomic_store_n(&st->index[i],0,__ATOMIC_RELAXED);
        for(;;) {
            j=(j+1)&(HW_WALK_INDEX-1);
            if(!st->index[j])return;
            unsigned home=hw_walk_hash(st->roots[st->index[j]-1].entry.root);
            if(i<=j ? (home<=i || home>j) : (home<=i && home>j))break;
        }
        __atomic_store_n(&st->index[i],st->index[j],__ATOMIC_RELAXED);i=j;
    }
}
static inline void hw_walk_detach(struct hw_walk_state *st,const struct hw_walk_ops *o,
                                  struct hw_walk_root *r)
{
    if(!st || !r || !r->entry.root)return;
    hw_walk_release(o,r);
    hw_walk_unindex(st,r->index);
    unsigned index=r->index;
    *r=(struct hw_walk_root){0};r->index=index;
    st->used--;st->stats.detached++;
}
/* A format-1 root's first hardware install: a record, and for UMPRR18 its
 * root copies plus a path for every class 9 leaf already present (the root
 * may have been populated before it ever ran). 0: no room or a tree this file
 * does not admit -- nothing is retained and the caller keeps the shadow path. */
static inline struct hw_walk_root *hw_walk_attach(struct hw_walk_state *st,const struct hw_walk_ops *o,
    uint64_t root,unsigned asid,unsigned flags)
{
    if(!st || !o || !root || (root&0x3fff) || !asid || asid>0xffff)return 0;
    struct hw_walk_root *found=hw_walk_find(st,root);
    if(found)return found;
    if(st->used>=HW_WALK_ROOTS) {st->stats.full++;return 0;}
    unsigned record=HW_WALK_ROOTS;
    for(unsigned n=0;n<HW_WALK_ROOTS;n++)if(!st->roots[n].entry.root) {record=n;break;}
    if(record==HW_WALK_ROOTS) {st->stats.full++;return 0;}
    struct hw_walk_root *r=&st->roots[record];
    *r=(struct hw_walk_root){.entry={.root=root,.asid=asid,.format=1,.flags=flags,.valid=1},
        .umprr=((uint64_t)(flags&8)<<15)|((uint64_t)(flags&1)<<11),.index=record};
    /* A root without UMPRR18 runs raw: it must hold no class 9 at all (a flag
     * cleared by CONFIGURE_ROOT after TPRO leaves were stored, say). */
    int tpro=!!(flags&SPTM_MAC_ROOT_FLAG_UMPRR18);
    unsigned tables=0;
    if((tpro && (hw_walk_add(o,r,root,0,0,0xffff,0)!=0 || !hw_walk_translate(o,r,0,0,511,0))) ||
       !hw_walk_scan(o,r,root,0,0,&tables,tpro ? hw_walk_mark_prepare : 0,0)) {
        hw_walk_release(o,r);*r=(struct hw_walk_root){0};r->index=record;
        st->stats.refused++;return 0;
    }
    if(tpro)st->stats.discovered+=r->count-1;
    unsigned i=hw_walk_hash(root);
    while(st->index[i])i=(i+1)&(HW_WALK_INDEX-1);
    __atomic_store_n(&st->index[i],(uint16_t)(record+1),__ATOMIC_RELEASE);  /* the record first */
    st->used++;st->stats.attached++;
    return r;
}

/* --- the loaded-root audit (compat/sptm-root-policy.h) -------------------- */
/* SWITCH_ROOT notes the policy each CPU loaded (sptm_root_note_loaded),
 * CONFIGURE_ROOT of an active root checks it on every CPU
 * (sptm_root_configure_active, sptm_root_loaded_valid), and both take a root's
 * identity from its shadow-cache entry. A root the hardware walks has none,
 * so the very first hardware-walk SWITCH_ROOT was refused with
 * SPTM_BAD_CONFIG (installed-fresh-20261018-v53: EV_REFERENCE_FAILED 1,
 * root 0x8d592c000, record 0 installed, no cache entry). Its record's entry is
 * that identity. These are the same checks with it: format 1, shadow 0, and
 * never beside a valid cache entry for the same root (one identity per root).
 * Without a record they are exactly the sptm_root_* originals. */
static inline const struct sptm_root_cached *hw_walk_policy_entry(const struct sptm_root_state *s,
    struct hw_walk_state *st,uint64_t root)
{
    const struct sptm_root_cached *e=sptm_root_policy_cache(s,root);
    if(e)return e;
    struct hw_walk_root *r=hw_walk_find(st,root);
    if(!s || !r)return 0;
    for(unsigned i=0;i<SPTM_ROOT_CACHE;i++)if(s->cache[i].root==root && s->cache[i].valid)return 0;
    const struct sptm_root_cached *h=&r->entry;struct sptm_user_geometry g;
    if(h->root!=root || h->valid!=1 || h->shadow || !h->asid || h->asid>0xffff || h->format!=1 ||
       h->flags>0xffff || !sptm_mac_user_geometry(1,(unsigned)h->flags,&g))return 0;
    return h;
}
static inline int hw_walk_note_loaded(const struct sptm_root_state *s,struct hw_walk_state *st,
    struct sptm_loaded_root loaded[SPTM_ROOT_CPUS],unsigned cpu)
{
    if(!s || !loaded || cpu>=SPTM_ROOT_CPUS || !sprr_fixed_state_valid(&s->sprr[cpu]))return 0;
    uint64_t root=s->active[cpu],flags=0;
    if(root) {
        const struct sptm_root_cached *e=hw_walk_policy_entry(s,st,root);
        if(!e)return 0;
        flags=e->flags;
    }
    if(s->sprr[cpu].umprr!=sptm_root_policy_umprr(flags))return 0;
    loaded[cpu]=(struct sptm_loaded_root){root,flags,s->sprr[cpu].resets};
    return 1;
}
static inline int hw_walk_loaded_valid(const struct sptm_root_state *s,struct hw_walk_state *st,
    const struct sptm_loaded_root loaded[SPTM_ROOT_CPUS],unsigned cpu)
{
    if(!s || !loaded || cpu>=SPTM_ROOT_CPUS)return 0;
    const struct sptm_loaded_root *l=&loaded[cpu];
    if(l->root!=s->active[cpu] || l->resets!=s->sprr[cpu].resets ||
       !sprr_fixed_state_valid(&s->sprr[cpu]) ||
       s->sprr[cpu].umprr!=sptm_root_policy_umprr(l->flags))return 0;
    if(!l->root)return !l->flags;
    const struct sptm_root_cached *e=hw_walk_policy_entry(s,st,l->root);
    return e && !((l->flags^e->flags)&~UINT64_C(1));
}
/* sptm_root_configure_active for a cached root, every CPU checked as above. */
static inline int hw_walk_configure_active(struct sptm_root_state *s,struct hw_walk_state *st,
    const struct sptm_loaded_root loaded[SPTM_ROOT_CPUS],uint64_t root,uint16_t before,uint16_t after)
{
    if((before^after)!=SPTM_MAC_ROOT_FLAG_UMPRR11)return 0;
    const struct sptm_root_cached *e=sptm_root_policy_cache(s,root);
    if(!e || e->flags!=before)return 0;
    unsigned active=0;
    for(unsigned cpu=0;cpu<SPTM_ROOT_CPUS;cpu++) {
        if(!hw_walk_loaded_valid(s,st,loaded,cpu))return 0;
        active+=s->active[cpu]==root;
    }
    if(!active)return 0;
    s->cache[e-s->cache].flags=after;
    return 1;
}
/* sptm_root_shared_aliases_hw's test: an active root without a cache entry
 * that the hardware walks (it reads the shared tables themselves). */
static inline int hw_walk_recorded(void *ctx,uint64_t root)
{return hw_walk_find((struct hw_walk_state *)ctx,root)!=0;}

/* --- the SPTM user-call events (probes/xnuboot.c's backend callbacks) ----- */
/* range(ctx, va, size): invalidate [va, va+size) by VA in every ASID and
 * every guest VMID, walk caches included; size 0 is everything. */
struct hw_walk_tlb {void (*range)(void *ctx,uint64_t va,uint64_t size);void *ctx;};
/* Before class 9 is stored at [va, va+size): every page gets a copied path,
 * and a newly linked one is invalidated first (F1, F2). A root without
 * copies (no UMPRR18) never takes class 9. */
static inline int hw_walk_before_tpro(const struct hw_walk_ops *o,struct hw_walk_root *r,
    uint64_t va,uint64_t size,const struct hw_walk_tlb *t,struct hw_walk_stats *s)
{
    if(!r || !r->count || !size || (va&4095) || (size&4095))return 0;
    for(uint64_t off=0;off<size;off+=4096) {
        int p=hw_walk_prepare(o,r,va+off);
        if(!p)return 0;
        if(p==2) {t->range(t->ctx,va+off,4096);s->paths++;s->path_tlbis++;}
    }
    return 1;
}
/* After stores that only add translations over invalid entries (a fresh
 * leaf, a table linked into an empty slot, NEST): the copies follow; nothing
 * can be cached for an invalid entry, so no invalidation. */
static inline int hw_walk_after_add(const struct hw_walk_ops *o,struct hw_walk_root *r,
    uint64_t va,uint64_t size,struct hw_walk_stats *s)
{
    if(!r)return 0;
    if(!r->count)return 1;
    s->refreshes++;
    return hw_walk_refresh(o,r,va,size,&s->refreshed);
}
/* After stores that remove or change translations (UNMAP_REGION, permission
 * and replacement updates): the copies follow, then every VMID forgets the
 * range, before the caller releases any reference (F9, F3). */
static inline int hw_walk_after_change(const struct hw_walk_ops *o,struct hw_walk_root *r,
    uint64_t va,uint64_t size,const struct hw_walk_tlb *t,struct hw_walk_stats *s)
{
    if(!hw_walk_after_add(o,r,va,size,s))return 0;
    t->range(t->ctx,va,size);return 1;
}
/* After a table unlink (UNMAP_TABLE, UNNEST): the copies follow, copies no
 * longer linked are dropped, every VMID forgets everything, and only then
 * are the dropped pages released (F14). */
static inline int hw_walk_after_unlink(const struct hw_walk_ops *o,struct hw_walk_root *r,
    uint64_t va,uint64_t size,const struct hw_walk_tlb *t,struct hw_walk_stats *s)
{
    uint64_t pages[2*HW_WALK_TABLES];int dropped=0;
    if(!hw_walk_after_add(o,r,va,size,s))return 0;
    if(r->count && (dropped=hw_walk_prune(o,r,pages))<0)return 0;
    t->range(t->ctx,0,0);
    for(int i=0;i<dropped;i++)o->release(o->ctx,pages[i]);
    s->pruned+=(unsigned)dropped/2u;
    return 1;
}

/* --- converted calls (SNAP_FINE_HW; docs/FINE-HW-WALK-20261019.md) -------- */
/* A fine-lock converted MAP_PAGE or UNMAP_REGION on a hardware-walk root runs
 * the token path's events under the root's stripe: the same refresh of that
 * root's own copies, nothing allocated, linked or released, and the shared
 * counters handed back for the caller to add atomically (converted calls on
 * different roots run at once). A class-9 leaf needs copied paths, which
 * hw_walk_before_tpro allocates: refused before any store, so the call
 * declines to the token path. */
struct hw_walk_fine_counts {uint64_t refreshes,refreshed;};
static inline int hw_walk_fine_prepare_leaf(const struct hw_walk_root *r,unsigned shift,uint64_t pte)
{return r && shift==12 && sprr_pte_class(pte)!=9;}
static inline int hw_walk_fine_prepare_unmap(const struct hw_walk_root *r,unsigned shift)
{return r && shift==12;}
/* hw_walk_after_add, counters out (MAP_PAGE's fresh leaf: nothing to invalidate). */
static inline int hw_walk_fine_after_add(const struct hw_walk_ops *o,struct hw_walk_root *r,
    uint64_t va,uint64_t size,struct hw_walk_fine_counts *n)
{
    n->refreshes=n->refreshed=0;
    if(!r)return 0;
    if(!r->count)return 1;
    n->refreshes=1;
    return hw_walk_refresh(o,r,va,size,&n->refreshed);
}
/* hw_walk_after_change, counters out (UNMAP_REGION): the copies follow, then
 * every VMID forgets the range. */
static inline int hw_walk_fine_after_change(const struct hw_walk_ops *o,struct hw_walk_root *r,
    uint64_t va,uint64_t size,const struct hw_walk_tlb *t,struct hw_walk_fine_counts *n)
{
    if(!hw_walk_fine_after_add(o,r,va,size,n))return 0;
    t->range(t->ctx,va,size);
    return 1;
}
#if SNAP_SPTM_FINE
/* SNAP_SPTM_FINE (agents/sptm-locks/FAILURE-MODES.md S11g, S19): a converted
 * update -- a replacing MAP_PAGE or a permission update of an existing leaf
 * (UPDATE_DISJOINT, UPDATE_REGION) -- runs probes/xnuboot.c
 * user_commit_update's hardware-walk events: the copies follow the store (the
 * token path's refresh range, nothing allocated, linked or released), then
 * every VMID forgets the range unless the old leaf cannot have been cached
 * (invalidate 0: update_fast_uncached, an AF-clear old leaf). A transition
 * into class 9 needs a copied path (hw_walk_before_tpro allocates): refused
 * before any store, so the call declines to the token path. */
static inline int hw_walk_fine_prepare_update(const struct hw_walk_root *r,unsigned shift,
                                              uint64_t old,uint64_t next)
{return r && shift==12 && (sprr_pte_class(next)!=9 || sprr_pte_class(old)==9);}
static inline int hw_walk_fine_after_update(const struct hw_walk_ops *o,struct hw_walk_root *r,
    uint64_t va,uint64_t size,int invalidate,const struct hw_walk_tlb *t,struct hw_walk_fine_counts *n)
{
    if(!hw_walk_fine_after_add(o,r,va,size,n))return 0;
    if(invalidate)t->range(t->ctx,va,size);
    return 1;
}
#endif

/* --- stage 2: page-table frames read-only while typed (F7, F8) ------------ */
/* Every SPTM table type, user and kernel: the guest reads its tables through
 * the aperture and never writes them; the SPTM (this monitor) is their only
 * writer, so its validation is the only way into a hardware-walked tree. */
static inline int hw_s2_protected_type(unsigned type)
{
    return type==SPTM_MAC_USER_ROOT_TABLE || type==SPTM_MAC_SHARED_ROOT_TABLE ||
           type==SPTM_MAC_PAGE_TABLE || type==SPTM_MAC_PAGE_TABLE_SHARED ||
           type==SPTM_MAC_PAGE_TABLE_ROZONE || type==SPTM_MAC_PAGE_TABLE_COMMPAGE;
}
/* After a completed RETYPE old->next: 1 protect, 0 unprotect, -1 nothing. */
static inline int hw_s2_retype_action(unsigned old,unsigned next)
{
    int a=hw_s2_protected_type(old),b=hw_s2_protected_type(next);
    return a==b ? -1 : b;
}
#define HW_S2_TREES 6u
/* A guest-RAM identity leaf (page or block) as stage2_build writes one:
 * normal memory, RO or RW, executable (no XN: never a monitor range). */
static inline int hw_s2_ram_leaf(uint64_t d,uint64_t base)
{
    return (d&PT_VALID) && (d&PT_OA_MASK)==base &&
        ((d&PT_AP)==S2_AP_RO || (d&PT_AP)==S2_AP_RW) &&
        (d&~(PT_OA_MASK|PT_AP|3UL))==S2_ATTRS;
}
/* Read-only: the frame's four pages are guest-RAM leaves in tree t. */
static inline int hw_s2_check(struct shadow *t,uint64_t frame)
{
    int start=mmu_start_level(12,t->txsz);
    if(start!=1 || frame>=(UINT64_C(1)<<(64-t->txsz)))return 0;
    uint64_t table=t->root,d;
    for(unsigned level=1;level<=3;level++) {
        if(t->read(t->ctx,table+8UL*mmu_index(12,level,frame),&d) || !(d&PT_VALID))return 0;
        if(level<3 && (d&PT_TABLE)) {
            if((d&~PT_OA_MASK)!=(PT_VALID|PT_TABLE))return 0;
            table=d&PT_OA_MASK;continue;
        }
        if(level<3)return hw_s2_ram_leaf(d,frame&~(mmu_level_size(12,level)-1));
        for(unsigned p=0;p<4;p++) {
            if(t->read(t->ctx,table+8UL*mmu_index(12,3,frame+4096UL*p),&d) ||
               (d&3)!=3 || !hw_s2_ram_leaf(d,frame+4096UL*p))return 0;
        }
        return 1;
    }
    return 0;
}
/* The level-2 slot of every tree for ipa. With split, a level-1 block becomes
 * a level-2 table (same attributes) first; without, a block refuses. 0 on
 * failure. */
static inline int hw_s2_l2(struct shadow *t,uint64_t ipa,uint64_t *slot,int split)
{
    int start=mmu_start_level(12,t->txsz);
    if(start!=1 || ipa>=(UINT64_C(1)<<(64-t->txsz)))return 0;
    uint64_t l1=t->root+8UL*mmu_index(12,1,ipa),d;
    if(t->read(t->ctx,l1,&d) || !(d&PT_VALID))return 0;
    if(!(d&PT_TABLE)) {
        if(!split)return 0;
        uint64_t table=shadow_alloc_page(t);
        if(!table)return 0;
        uint64_t base=d&PT_OA_MASK&~((UINT64_C(1)<<30)-1),attrs=d&~PT_OA_MASK;
        for(unsigned n=0;n<512;n++)
            if(t->write(t->ctx,table+8UL*n,(base+((uint64_t)n<<21))|attrs))return 0;
        if(t->write(t->ctx,l1,table|PT_VALID|PT_TABLE))return 0;
        d=table|PT_VALID|PT_TABLE;
    }
    *slot=(d&PT_OA_MASK)+8UL*mmu_index(12,2,ipa);
    return 1;
}
/* Set the S2AP of the four 4K pages of the 16K frame in every tree (RO when
 * ro, else RW): a leaf change only, which needs no break-before-make. Every
 * page must be a guest-RAM identity leaf in a level-3 table of every tree,
 * checked before anything is written: a refusal changes nothing. The trees
 * are live under the other CPUs, so a frame whose path still holds a block
 * refuses rather than change a block size under a running walker
 * (installed-fresh-20261018-v62 and -v63 took a transient stage-2 level-2
 * translation fault on guest RAM after about 3,910 such live splits): the
 * blocks are split once, at setup, by hw_s2_presplit. Returns 0 or -1. The
 * caller publishes and invalidates every VMID (stage 2 by IPA, and the
 * frame's aperture aliases at stage 1). */
static inline int hw_s2_set(struct shadow *trees,unsigned count,uint64_t frame,int ro)
{
    if(!trees || !count || count>HW_S2_TREES || (frame&0x3fff))return -1;
    uint64_t l3[HW_S2_TREES];
    for(unsigned k=0;k<count;k++) {
        uint64_t slot,d;
        if(!hw_s2_check(&trees[k],frame) || !hw_s2_l2(&trees[k],frame,&slot,0) ||
           trees[k].read(trees[k].ctx,slot,&d) || (d&3)!=3)return -1;
        l3[k]=d&PT_OA_MASK;
    }
    for(unsigned pass=0;pass<2;pass++)for(unsigned k=0;k<count;k++) {
        int seen=0;
        for(unsigned j=0;j<k;j++)seen|=l3[j]==l3[k];
        if(seen)continue;
        for(unsigned p=0;p<4;p++) {
            uint64_t ipa=frame+4096UL*p,at=l3[k]+8UL*mmu_index(12,3,ipa),d;
            if(trees[k].read(trees[k].ctx,at,&d))return -1;
            if((d&3)!=3 || !hw_s2_ram_leaf(d,ipa))return -1;
            if(pass && trees[k].write(trees[k].ctx,at,(d&~PT_AP)|(ro ? S2_AP_RO : S2_AP_RW)))return -1;
        }
    }
    return 0;
}
/* At setup, before any vCPU runs: every block of guest RAM in [lo, hi)
 * becomes level-3 leaves in every tree, so that no RETYPE changes a block size
 * later. A level-1 block becomes a level-2 table of 2M blocks first; a 2M
 * block identical in every tree becomes one level-3 table shared by all of
 * them (the trees differ only where a guard split already gave one tree its
 * own table, which it keeps); a 2M block that differs becomes the tree's own
 * table. Every leaf keeps its S2AP and attributes. Blocks that are not
 * guest-RAM identity leaves (XN or device ranges) and holes stay as they are:
 * hw_s2_check refuses their frames at RETYPE anyway. Returns the tables
 * created, or -1. */
static inline int hw_s2_presplit(struct shadow *trees,unsigned count,uint64_t lo,uint64_t hi)
{
    if(!trees || !count || count>HW_S2_TREES || (lo&0x1fffff) || lo>=hi)return -1;
    int created=0;
    for(uint64_t region=lo;region<hi;region+=UINT64_C(1)<<21) {
        uint64_t slot[HW_S2_TREES],d2[HW_S2_TREES];
        int ram[HW_S2_TREES],any=0,same=1;
        for(unsigned k=0;k<count;k++) {
            uint64_t l1;
            ram[k]=0;slot[k]=0;d2[k]=0;
            if(trees[k].read(trees[k].ctx,trees[k].root+8UL*mmu_index(12,1,region),&l1))return -1;
            if(!(l1&PT_VALID))continue;
            if(!(l1&PT_TABLE) && !hw_s2_ram_leaf(l1,region&~((UINT64_C(1)<<30)-1)))continue;
            if(!hw_s2_l2(&trees[k],region,&slot[k],1))return -1;
            if(trees[k].read(trees[k].ctx,slot[k],&d2[k]))return -1;
            ram[k]=(d2[k]&3)==1 && hw_s2_ram_leaf(d2[k],region);
            any|=ram[k];
        }
        if(!any)continue;
        for(unsigned k=0;k<count;k++)same&=ram[k] && d2[k]==d2[0];
        if(same) {
            uint64_t table=shadow_alloc_page(&trees[0]);
            if(!table)return -1;
            uint64_t attrs=(d2[0]&~PT_OA_MASK)|PT_TABLE;
            for(unsigned n=0;n<512;n++)
                if(trees[0].write(trees[0].ctx,table+8UL*n,(region+((uint64_t)n<<12))|attrs))return -1;
            for(unsigned k=0;k<count;k++)
                if(trees[k].write(trees[k].ctx,slot[k],table|PT_VALID|PT_TABLE))return -1;
            created++;
            continue;
        }
        for(unsigned k=0;k<count;k++)if(ram[k]) {
            if(!stage2_split(&trees[k],region))return -1;
            created++;
        }
    }
    return created;
}

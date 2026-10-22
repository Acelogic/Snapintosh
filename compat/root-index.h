/* SPDX-License-Identifier: MIT */
#pragma once
#include "sptm.h"
/* SNAP_ROOT_INDEX: an index of the typed frame map's root frames, by key
 * (USER_ROOT_TABLE by ASID, SHARED_ROOT_TABLE by shared slot), so that
 * TXM35/36/37 (txm_aspace) and a USER_ROOT constructor (sptm_mac_retype's
 * duplicate-ASID refusal) stop scanning every frame record under the token
 * (docs/TOKEN-COSTS-20261018.md). Opt-in, default 0; off, txm.c and sptm.c
 * are token-identical to the code without it.
 *
 * Why (installed-fresh-20261018-v54): the frame map has 2,596,216 records
 * (0x279d780 bytes). Each of about 10,200 root constructors reads byte 2 of
 * every one of them, and each TXM35 and TXM36 (about 20,000) walks every
 * managed frame below alloc_high. That is about 30,000 scans of a 41 MB
 * array: RETYPE held the token 20.0 s at 66 us each, call_other (which holds
 * TXM) 60.8 s.
 *
 * The typed frame map stays the authority. The index only says which
 * records to read: the callers read and check each listed record exactly as
 * the scan did, in the scan's ascending address order, with the scan's
 * range filters. Its keys -- a root record's type (byte 2), a user root's
 * ASID (bytes 4..5), a shared root's slot (byte 8) -- are written only by
 * sptm_mac_retype's commit (sptm_txm_retype changes TXM types only), which
 * calls sptm_root_index_retype with the key it removes and the one it adds.
 * The first lookup builds the index from a full scan of the map.
 *
 * Failure modes (tools/test-token-costs.c checks each; each guard has a
 * mutant that must fail, tools/test-token-costs.py):
 *  R1 a root record missing from the index (a constructor not noted, a
 *     build that skips part of the map): TXM would report TABLE_MISSING, or
 *     a duplicate ASID would be admitted.
 *  R2 a stale entry (a release or a share not noted): the caller re-reads
 *     the record, so a stale entry is skipped exactly as the scan skips the
 *     frame -- but only if the caller re-checks type and key.
 *  R3 order: two matching records must be visited in ascending address
 *     order (the scan's FRAME_BUSY / BAD_TABLE precedence).
 *  R4 the scan's range: only managed frames below alloc_high for TXM; the
 *     whole map for the constructor.
 *  R5 capacity: a full table, or more matches than a lookup returns, falls
 *     back to the scan (never a partial answer).
 *  R6 the sampled audit: 1 in (SPTM_ROOT_INDEX_AUDIT+1) lookups also scans
 *     and must find the same records; a disagreement counts a mismatch,
 *     drops the index (rebuilt on the next lookup) and uses the scan.
 *  M  a default build changes. */
#ifndef SNAP_ROOT_INDEX
#define SNAP_ROOT_INDEX 0
#endif
#if SNAP_ROOT_INDEX
#ifndef SPTM_ROOT_INDEX_SLOTS
#define SPTM_ROOT_INDEX_SLOTS 8192u      /* power of two; at most half full */
#endif
#define SPTM_ROOT_INDEX_LIST 8u          /* a lookup's most matches */
#ifndef SPTM_ROOT_INDEX_AUDIT
#define SPTM_ROOT_INDEX_AUDIT 63u
#endif
#define SPTM_ROOT_KEY_USER(asid) (UINT32_C(0x10000)|(uint32_t)(asid))
#define SPTM_ROOT_KEY_SHARED(slot) (UINT32_C(0x20000)|(uint32_t)(slot))
struct sptm_root_index_entry { uint64_t pa; uint32_t key, reserved; };
/* built: the map was scanned into the table; live: entries; full: inserts
 * refused for want of room (the index is dropped; the scan is used until a
 * rebuild fits); lookups: answered from the table alone; scans: lookups the
 * caller had to scan; audits/mismatches: answers also scanned and their
 * disagreements (must stay 0); notes: retype updates applied; builds. */
struct sptm_root_index_stats {
    uint64_t built, live, full, lookups, scans, audits, mismatches, notes, builds, reserved[7];
};
struct sptm_root_index {
    struct sptm_root_index_stats stats;
    struct sptm_root_index_entry slot[SPTM_ROOT_INDEX_SLOTS];
};
_Static_assert(sizeof(struct sptm_root_index_stats)==128,"root index stats stride");
static inline uint32_t sptm_root_index_key(const volatile uint8_t *f)
{
    if(f[2]==SPTM_MAC_USER_ROOT_TABLE)return SPTM_ROOT_KEY_USER((unsigned)f[4]|(unsigned)f[5]<<8);
    if(f[2]==SPTM_MAC_SHARED_ROOT_TABLE)return SPTM_ROOT_KEY_SHARED(f[8]);
    return 0;
}
static inline unsigned sptm_root_index_hash(uint32_t key)
{return (unsigned)((key*UINT64_C(0x9e3779b97f4a7c15))>>40)&(SPTM_ROOT_INDEX_SLOTS-1);}
static inline int sptm_root_index_insert(struct sptm_root_index *x,uint64_t pa,uint32_t key)
{
    if(x->stats.live>=SPTM_ROOT_INDEX_SLOTS/2) {x->stats.full++;x->stats.built=0;return 0;}
    for(unsigned i=sptm_root_index_hash(key);;i=(i+1)&(SPTM_ROOT_INDEX_SLOTS-1)) {
        struct sptm_root_index_entry *e=&x->slot[i];
        if(e->pa==pa && e->key==key)return 1;
        if(!e->pa) {e->pa=pa;e->key=key;x->stats.live++;return 1;}
    }
}
/* Linear probing with backward-shift deletion (no tombstones). */
static inline void sptm_root_index_remove(struct sptm_root_index *x,uint64_t pa,uint32_t key)
{
    unsigned i=sptm_root_index_hash(key);
    for(;;i=(i+1)&(SPTM_ROOT_INDEX_SLOTS-1)) {
        if(!x->slot[i].pa)return;
        if(x->slot[i].pa==pa && x->slot[i].key==key)break;
    }
    x->stats.live--;
    for(unsigned j=i;;) {
        x->slot[i]=(struct sptm_root_index_entry){0};
        for(;;) {
            j=(j+1)&(SPTM_ROOT_INDEX_SLOTS-1);
            if(!x->slot[j].pa)return;
            unsigned h=sptm_root_index_hash(x->slot[j].key);
            /* Stay when h lies cyclically in (i, j]. */
            if(i<=j ? (i<h && h<=j) : (i<h || h<=j))continue;
            break;
        }
        x->slot[i]=x->slot[j];i=j;
    }
}
/* Build from the whole map (every record; byte 2 decides). */
static inline void sptm_root_index_build(struct sptm_root_index *x,const struct sptm_memory *m)
{
    for(unsigned i=0;i<SPTM_ROOT_INDEX_SLOTS;i++)x->slot[i]=(struct sptm_root_index_entry){0};
    x->stats.live=0;x->stats.builds++;
    uint64_t map_size=((m->frame_high-m->frame_low)>>14)*16;
    volatile uint8_t *all=m->map(m->ctx,m->frame_map_pa,map_size);
    if(!all) {x->stats.built=0;return;}
    for(uint64_t off=0;off<map_size;off+=16) {
        uint32_t key=sptm_root_index_key(all+off);
        if(key && !sptm_root_index_insert(x,m->frame_low+(off/16)*SPTM_MAC_FRAME_SIZE,key))return;
    }
    x->stats.built=1;
}
/* sptm_mac_retype's commit: the record at pa loses `removed` (0: none) and
 * gains `added`. Before the first build there is nothing to keep. */
static inline void sptm_root_index_retype(struct sptm_root_index *x,uint64_t pa,uint32_t removed,uint32_t added)
{
    if(!x || !x->stats.built || removed==added)return;
    if(removed)sptm_root_index_remove(x,pa,removed);
    if(added)sptm_root_index_insert(x,pa,added);
    x->stats.notes++;
}
/* The scan's answer for key: in TXM's range (txm: managed frames from the
 * first one below alloc_high, as txm_aspace walks them) or the whole map
 * (the constructor's), ascending. Count, or -1 beyond the list's room. */
static inline int sptm_root_index_scan(const struct sptm_memory *m,uint32_t key,int txm,
                                       uint64_t out[SPTM_ROOT_INDEX_LIST])
{
    uint64_t map_size=((m->frame_high-m->frame_low)>>14)*16;
    volatile uint8_t *all=m->map(m->ctx,m->frame_map_pa,map_size);
    if(!all)return -1;
    unsigned n=0;
    for(uint64_t pa=txm ? sptm_next_frame(m,0) : m->frame_low;txm ? pa<m->alloc_high : pa<m->frame_high;
        pa=txm ? sptm_next_frame(m,pa+SPTM_MAC_FRAME_SIZE) : pa+SPTM_MAC_FRAME_SIZE) {
        if(sptm_root_index_key(all+((pa-m->frame_low)>>14)*16)!=key)continue;
        if(n==SPTM_ROOT_INDEX_LIST)return -1;
        out[n++]=pa;
    }
    return (int)n;
}
/* The records the scan would visit for key, ascending, in its range: their
 * count, or -1 when the caller must scan (no usable index, a full one, more
 * than SPTM_ROOT_INDEX_LIST matches). 1 in SPTM_ROOT_INDEX_AUDIT+1 answers
 * also scans and must agree; a difference counts a mismatch, drops the index
 * (rebuilt on the next lookup) and answers with the scan. */
static inline int sptm_root_index_candidates(struct sptm_root_index *x,const struct sptm_memory *m,
    uint32_t key,int txm,uint64_t out[SPTM_ROOT_INDEX_LIST])
{
    if(!x)return -1;
    if(!x->stats.built)sptm_root_index_build(x,m);
    if(!x->stats.built) {x->stats.scans++;return -1;}
    unsigned n=0;
    for(unsigned i=sptm_root_index_hash(key);x->slot[i].pa;i=(i+1)&(SPTM_ROOT_INDEX_SLOTS-1)) {
        uint64_t pa=x->slot[i].pa;
        /* txm_aspace visits exactly the fixed points of sptm_next_frame below
         * alloc_high: each visit is one, and no fixed point is stepped over. */
        if(x->slot[i].key!=key || (txm && (pa>=m->alloc_high || sptm_next_frame(m,pa)!=pa)))continue;
        if(n==SPTM_ROOT_INDEX_LIST) {x->stats.scans++;return -1;}
        unsigned k=n++;
        while(k && out[k-1]>pa) {out[k]=out[k-1];k--;}
        out[k]=pa;
    }
    if(!((x->stats.lookups+x->stats.audits)&SPTM_ROOT_INDEX_AUDIT)) {
        uint64_t found[SPTM_ROOT_INDEX_LIST];
        int s=sptm_root_index_scan(m,key,txm,found),same=s==(int)n;
        for(int k=0;same && k<s;k++)same=found[k]==out[k];
        x->stats.audits++;
        if(!same) {
            x->stats.mismatches++;x->stats.built=0;
            for(int k=0;k<s;k++)out[k]=found[k];
            return s;
        }
        return (int)n;
    }
    x->stats.lookups++;
    return (int)n;
}
#endif

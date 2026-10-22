/* SPDX-License-Identifier: MIT */
#pragma once
#include "sptm.h"
/* SNAP_ROOT_VALIDATE_MEMO: level-3 verdicts of SWITCH_ROOT validation, used
 * only when the switch installs an already-cached shadow (a cache hit), where
 * validation is a tripwire and never decides what reaches hardware.
 *
 * An entry says: this level-3 table, reached at `base` under root flags and
 * granule `shift`, with its frame record bytes0..5 equal to `record`, passed
 * the full level-3 scan while the mapped-type epoch was `epoch`. The scan
 * reads only the table page, the frame records (bytes0..2) of the pages its
 * leaves name and static configuration, so an entry is retired when:
 *   - any published store overlaps the table's frame (sptm_root_memo_publish);
 *   - a published store leaves the table frame's record bytes0..5 different
 *     from `record` (type, level; bytes6..15 are counts the caller re-checks
 *     on every walk, or never reads for tables);
 *   - a frame that can back a user leaf changes type while its reference
 *     bytes8..15 are nonzero (sptm_root_memo_retype advances the epoch).
 * Frames with zero references are named by no leaf (sptm-refs.c counts every
 * user leaf), so their retypes cannot change a recorded verdict.
 * The caller still checks root, level-2 tables, every child's frame record,
 * nested links and group structure on every switch, and every 64th validation
 * is a full walk without the memo that must agree (terminal otherwise). */
#if SNAP_UNNEST_4K_FAST
/* compat/nest-fast.h 3, capacity (batch 7, FAILURES-AND-DESIGN): 2,048
 * entries held 8 % of installed-fresh-20261020-v6's UNNEST lookups. Every
 * exit unnests the whole shared region, ~3,450 4K tables under its root's
 * flags (0xb, 0x1), so a verdict is looked up again only after ~7,000-14,000
 * other keys; 99.6 % of records evicted a live entry. 32,768 entries (1 MiB)
 * hold that set. Host tests may set another power of two. */
#ifndef SPTM_ROOT_MEMO_ENTRIES
#define SPTM_ROOT_MEMO_ENTRIES 32768u
#endif
#else
#define SPTM_ROOT_MEMO_ENTRIES 2048u
#endif
#define SPTM_ROOT_MEMO_WAYS 8u
_Static_assert(!(SPTM_ROOT_MEMO_ENTRIES&(SPTM_ROOT_MEMO_ENTRIES-1)),"memo index mask");
struct sptm_root_memo_entry {
    uint64_t table, base, record;
    uint32_t epoch;
    uint16_t flags;
    uint8_t shift, reserved;
};
_Static_assert(sizeof(struct sptm_root_memo_entry)==32,"memo entry stride");
/* calls: memo-assisted validations; hits/misses: level-3 lookups; records:
 * verdicts stored; evictions: live entries displaced by a full window;
 * invalidations: entries dropped by a published store; epoch_bumps: mapped
 * frame type changes; flushes: epoch wraps (every entry cleared); sampled:
 * memo-assisted validations re-walked without the memo; mismatches must stay 0. */
struct sptm_root_memo_stats {
    uint64_t calls,hits,misses,records,evictions,invalidations,epoch_bumps,flushes,sampled,mismatches;
};
struct sptm_root_memo {
    struct sptm_root_memo_stats stats;
    uint64_t epoch, live;
    struct sptm_root_memo_entry entry[SPTM_ROOT_MEMO_ENTRIES];
#if SNAP_UNNEST_4K_FAST
    /* frame_live[h]: the entries with a nonzero table whose 16K frame has
     * index h (sptm_root_memo_frame_live). */
    uint8_t frame_live[SPTM_ROOT_MEMO_ENTRIES];
#endif
};
_Static_assert(__builtin_offsetof(struct sptm_root_memo,stats)==0 &&
               sizeof(struct sptm_root_memo_stats)==80,"kernel-ops-perf root_memo record prefix");
static inline unsigned sptm_root_memo_index(uint64_t frame)
{
    return (unsigned)(((frame>>14)*UINT64_C(0x9e3779b97f4a7c15))>>32)&(SPTM_ROOT_MEMO_ENTRIES-1);
}
#if SNAP_UNNEST_4K_FAST
/* compat/nest-fast.h 3. A 16K frame's entries live in the 32 entries from
 * its index: a 4K table's in the 8-entry window of its quarter of the frame
 * (a 16K table, 16K aligned, in the first, as without the define), so the
 * four tables of a frame under several root flags do not evict each other;
 * the witness scans all 32. An entry's record word holds the frame record's
 * bytes0..5 in bits 47:0 and, for a counted 4K verdict, its table's
 * mapped-leaf count + 1 in bits 63:48 (0: none). Every comparison with
 * record bytes uses bits 47:0; every whole-entry store clears the count. */
#define SPTM_ROOT_MEMO_FRAME_WAYS (4u*SPTM_ROOT_MEMO_WAYS)
#define SPTM_ROOT_MEMO_RECORD(r) ((r)&UINT64_C(0xffffffffffff))
static inline unsigned sptm_root_memo_window(uint64_t table)
{
    return sptm_root_memo_index(table&~UINT64_C(0x3fff))+SPTM_ROOT_MEMO_WAYS*(unsigned)((table>>12)&3);
}
/* The frame filter (batch 7): a nonzero count at the frame's index for each
 * of its entries, so the write witness skips, after one byte, every frame
 * with none (most SPTM publishes). Entries of a frame stay in the 32 slots
 * from its index: a count is at most 32. Its only writers are the only
 * writers of entry[].table: store, drop and the epoch-wrap flush. */
_Static_assert(SPTM_ROOT_MEMO_FRAME_WAYS<=255u && SPTM_ROOT_MEMO_FRAME_WAYS<=SPTM_ROOT_MEMO_ENTRIES,
               "frame filter counts fit a byte");
static inline uint8_t *sptm_root_memo_frame_live(struct sptm_root_memo *memo,uint64_t table)
{
    return &memo->frame_live[sptm_root_memo_index(table&~UINT64_C(0x3fff))];
}
#endif
static inline uint64_t sptm_root_memo_record_bytes(const volatile uint8_t *record)
{
    uint64_t v=0;for(unsigned i=0;i<6;i++)v|=(uint64_t)record[i]<<(8*i);return v;
}
static inline void sptm_root_memo_drop(struct sptm_root_memo *memo,struct sptm_root_memo_entry *e)
{
#if SNAP_UNNEST_4K_FAST
    (*sptm_root_memo_frame_live(memo,e->table))--;
#endif
    *e=(struct sptm_root_memo_entry){0};memo->live--;memo->stats.invalidations++;
}
static inline int sptm_root_memo_find(struct sptm_root_memo *memo,uint64_t table,uint64_t base,
    unsigned flags,unsigned shift,uint64_t record)
{
#if SNAP_UNNEST_4K_FAST
    unsigned h=sptm_root_memo_window(table);
#else
    unsigned h=sptm_root_memo_index(table&~UINT64_C(0x3fff));
#endif
    for(unsigned w=0;w<SPTM_ROOT_MEMO_WAYS;w++) {
        const struct sptm_root_memo_entry *e=&memo->entry[(h+w)&(SPTM_ROOT_MEMO_ENTRIES-1)];
#if SNAP_UNNEST_4K_FAST
        if(e->table==table && e->base==base && e->flags==flags && e->shift==shift &&
           SPTM_ROOT_MEMO_RECORD(e->record)==record && e->epoch==(uint32_t)memo->epoch) {memo->stats.hits++;return 1;}
#else
        if(e->table==table && e->base==base && e->flags==flags && e->shift==shift &&
           e->record==record && e->epoch==(uint32_t)memo->epoch) {memo->stats.hits++;return 1;}
#endif
    }
    memo->stats.misses++;return 0;
}
#if SNAP_NEST_FAST
/* sptm_root_memo_find without its counters: compat/nest-fast.h counts an
 * answered lookup as a hit and a recorded one as a miss, so records ==
 * misses holds for its lookups too. */
static inline int sptm_root_memo_peek(const struct sptm_root_memo *memo,uint64_t table,uint64_t base,
    unsigned flags,unsigned shift,uint64_t record)
{
#if SNAP_UNNEST_4K_FAST
    unsigned h=sptm_root_memo_window(table);
#else
    unsigned h=sptm_root_memo_index(table&~UINT64_C(0x3fff));
#endif
    for(unsigned w=0;w<SPTM_ROOT_MEMO_WAYS;w++) {
        const struct sptm_root_memo_entry *e=&memo->entry[(h+w)&(SPTM_ROOT_MEMO_ENTRIES-1)];
#if SNAP_UNNEST_4K_FAST
        if(e->table==table && e->base==base && e->flags==flags && e->shift==shift &&
           SPTM_ROOT_MEMO_RECORD(e->record)==record && e->epoch==(uint32_t)memo->epoch)return 1;
#else
        if(e->table==table && e->base==base && e->flags==flags && e->shift==shift &&
           e->record==record && e->epoch==(uint32_t)memo->epoch)return 1;
#endif
    }
    return 0;
}
#endif
#if SNAP_UNNEST_4K_FAST
/* sptm_root_memo_peek's match itself (no counters), for its leaf count. */
static inline struct sptm_root_memo_entry *sptm_root_memo_entry_of(struct sptm_root_memo *memo,uint64_t table,
    uint64_t base,unsigned flags,unsigned shift,uint64_t record)
{
    unsigned h=sptm_root_memo_window(table);
    for(unsigned w=0;w<SPTM_ROOT_MEMO_WAYS;w++) {
        struct sptm_root_memo_entry *e=&memo->entry[(h+w)&(SPTM_ROOT_MEMO_ENTRIES-1)];
        if(e->table==table && e->base==base && e->flags==flags && e->shift==shift &&
           SPTM_ROOT_MEMO_RECORD(e->record)==record && e->epoch==(uint32_t)memo->epoch)return e;
    }
    return 0;
}
/* The mapped-leaf count a live entry carries, or UINT64_MAX. */
static inline uint64_t sptm_root_memo_leaves(const struct sptm_root_memo_entry *e)
{return e->record>>48 ? (e->record>>48)-1 : UINT64_MAX;}
static inline void sptm_root_memo_set_leaves(struct sptm_root_memo_entry *e,uint64_t leaves)
{e->record=SPTM_ROOT_MEMO_RECORD(e->record)|(leaves+1)<<48;}
#endif
static inline void sptm_root_memo_store(struct sptm_root_memo *memo,uint64_t table,uint64_t base,
    unsigned flags,unsigned shift,uint64_t record)
{
#if SNAP_UNNEST_4K_FAST
    unsigned h=sptm_root_memo_window(table);
#else
    unsigned h=sptm_root_memo_index(table&~UINT64_C(0x3fff));
#endif
    struct sptm_root_memo_entry *slot=0,*free=0;
    for(unsigned w=0;w<SPTM_ROOT_MEMO_WAYS && !slot;w++) {
        struct sptm_root_memo_entry *e=&memo->entry[(h+w)&(SPTM_ROOT_MEMO_ENTRIES-1)];
        if(e->table==table && e->base==base && e->flags==flags && e->shift==shift)slot=e;
        else if(!free && (!e->table || e->epoch!=(uint32_t)memo->epoch))free=e;
    }
    if(!slot)slot=free;
    if(!slot) {
        slot=&memo->entry[(h+memo->stats.records%SPTM_ROOT_MEMO_WAYS)&(SPTM_ROOT_MEMO_ENTRIES-1)];
        memo->stats.evictions++;
    }
    if(!slot->table)memo->live++;
#if SNAP_UNNEST_4K_FAST
    else (*sptm_root_memo_frame_live(memo,slot->table))--;   /* evicted, stale or the same key */
    if(table)(*sptm_root_memo_frame_live(memo,table))++;
#endif
    *slot=(struct sptm_root_memo_entry){table,base,record,(uint32_t)memo->epoch,
        (uint16_t)flags,(uint8_t)shift,0};
    memo->stats.records++;
}
/* Advance the epoch: every entry recorded before becomes a miss. On wrap of
 * the stored 32-bit epoch, clear all entries so an old value cannot recur. */
static inline void sptm_root_memo_bump(struct sptm_root_memo *memo)
{
    memo->epoch++;memo->stats.epoch_bumps++;
    if(!(uint32_t)memo->epoch) {
        for(unsigned i=0;i<SPTM_ROOT_MEMO_ENTRIES;i++)memo->entry[i]=(struct sptm_root_memo_entry){0};
#if SNAP_UNNEST_4K_FAST
        for(unsigned i=0;i<SPTM_ROOT_MEMO_ENTRIES;i++)memo->frame_live[i]=0;
#endif
        memo->live=0;memo->stats.flushes++;
    }
}
/* Called at every frame-type store with the record as it stands before the
 * store (old type, references). Only types with a user mapping policy can
 * back an admitted leaf; their bytes8..15 are the +8/+12 class counts. */
static inline void sptm_root_memo_retype(struct sptm_root_memo *memo,const volatile uint8_t *record)
{
    if(!memo)return;
    if(!record) {sptm_root_memo_bump(memo);return;}
    if(!sptm_mac_type_policy(record[2]))return;
    for(unsigned i=8;i<16;i++)if(record[i]) {sptm_root_memo_bump(memo);return;}
}
/* Published record of `frame`: drop its entries whose record snapshot no
 * longer matches (an unreadable record drops them all). */
static inline void sptm_root_memo_check_record(struct sptm_root_memo *memo,uint64_t frame,
    const volatile uint8_t *record)
{
    unsigned h=sptm_root_memo_index(frame);
#if SNAP_UNNEST_4K_FAST
    if(!memo->frame_live[h])return;            /* no entry of this frame */
#endif
    uint64_t now=record ? sptm_root_memo_record_bytes(record) : ~UINT64_C(0);
#if SNAP_UNNEST_4K_FAST
    for(unsigned w=0;w<SPTM_ROOT_MEMO_FRAME_WAYS;w++) {
        struct sptm_root_memo_entry *e=&memo->entry[(h+w)&(SPTM_ROOT_MEMO_ENTRIES-1)];
        if(e->table && (e->table&~UINT64_C(0x3fff))==frame && SPTM_ROOT_MEMO_RECORD(e->record)!=now)
            sptm_root_memo_drop(memo,e);
    }
#else
    for(unsigned w=0;w<SPTM_ROOT_MEMO_WAYS;w++) {
        struct sptm_root_memo_entry *e=&memo->entry[(h+w)&(SPTM_ROOT_MEMO_ENTRIES-1)];
        if(e->table && (e->table&~UINT64_C(0x3fff))==frame && e->record!=now)sptm_root_memo_drop(memo,e);
    }
#endif
}
static inline void sptm_root_memo_drop_frame(struct sptm_root_memo *memo,uint64_t frame)
{
    unsigned h=sptm_root_memo_index(frame);
#if SNAP_UNNEST_4K_FAST
    if(!memo->frame_live[h])return;            /* no entry of this frame */
    for(unsigned w=0;w<SPTM_ROOT_MEMO_FRAME_WAYS;w++) {
#else
    for(unsigned w=0;w<SPTM_ROOT_MEMO_WAYS;w++) {
#endif
        struct sptm_root_memo_entry *e=&memo->entry[(h+w)&(SPTM_ROOT_MEMO_ENTRIES-1)];
        if(e->table && (e->table&~UINT64_C(0x3fff))==frame)sptm_root_memo_drop(memo,e);
    }
}
/* The write witness: call for every published store [pa,pa+size) to guest
 * memory (sptm_memory.publish). Small ranges probe the touched frames and
 * records; large ones scan the entries instead, so the cost stays bounded. */
static inline void sptm_root_memo_publish(struct sptm_root_memo *memo,uint64_t frame_map_pa,
    uint64_t frame_low,uint64_t frame_high,volatile uint8_t *(*map)(void *,uint64_t,uint64_t),
    void *ctx,uint64_t pa,uint64_t size)
{
    if(!memo || !memo->live || !size)return;
    uint64_t last=size>UINT64_MAX-pa ? UINT64_MAX : pa+size-1;
    uint64_t first_frame=pa&~UINT64_C(0x3fff),last_frame=last&~UINT64_C(0x3fff);
    uint64_t map_size=frame_high>frame_low ? ((frame_high-frame_low)>>14)*16 : 0;
    uint64_t map_last=frame_map_pa+map_size-1;
    int records=map_size && pa<=map_last && last>=frame_map_pa;
    uint64_t first_record=records ? ((pa>frame_map_pa ? pa : frame_map_pa)-frame_map_pa)/16 : 0;
    uint64_t last_record=records ? ((last<map_last ? last : map_last)-frame_map_pa)/16 : 0;
    uint64_t work=((last_frame-first_frame)>>14)+1+(records ? last_record-first_record+1 : 0);
#if SNAP_UNNEST_4K_FAST
    if(work<=SPTM_ROOT_MEMO_ENTRIES/SPTM_ROOT_MEMO_FRAME_WAYS) {
#else
    if(work<=SPTM_ROOT_MEMO_ENTRIES/SPTM_ROOT_MEMO_WAYS) {
#endif
        for(uint64_t f=first_frame;;f+=0x4000) {sptm_root_memo_drop_frame(memo,f);if(f==last_frame)break;}
        if(records)for(uint64_t r=first_record;r<=last_record;r++)
#if SNAP_UNNEST_4K_FAST
            if(memo->frame_live[sptm_root_memo_index(frame_low+(r<<14))])   /* else nothing to check */
#endif
            sptm_root_memo_check_record(memo,frame_low+(r<<14),map(ctx,frame_map_pa+r*16,16));
        return;
    }
    for(unsigned i=0;i<SPTM_ROOT_MEMO_ENTRIES;i++) {
        struct sptm_root_memo_entry *e=&memo->entry[i];
        if(!e->table)continue;
        uint64_t frame=e->table&~UINT64_C(0x3fff),at=frame_map_pa+((frame-frame_low)>>14)*16;
        if(frame>=first_frame && frame<=last_frame)sptm_root_memo_drop(memo,e);
        else if(records && at<=last && at+15>=pa) {
            const volatile uint8_t *record=map(ctx,at,16);
#if SNAP_UNNEST_4K_FAST
            if(!record || sptm_root_memo_record_bytes(record)!=SPTM_ROOT_MEMO_RECORD(e->record))
                sptm_root_memo_drop(memo,e);
#else
            if(!record || sptm_root_memo_record_bytes(record)!=e->record)sptm_root_memo_drop(memo,e);
#endif
        }
    }
}

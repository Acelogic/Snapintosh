/* SPDX-License-Identifier: MIT */
#pragma once
#include "sptm.h"
/* SNAP_DART_MEMO (compat/sptm-dart.c, docs/DART-MEMO-20261019.md): verdicts
 * of the DART table scan that MAP, UNMAP, MAP_TABLE and DMA translation repeat
 * on every call (2,048 descriptors per level, a managed-frame check per live
 * one, refs == entries + 1).
 *
 * The scan of one table frame reads its page, its own frame record (type,
 * id, sid and level, which frame() checks on every call anyway, and the refs
 * it compares) and, through sptm_managed_frame and sptm_dart_data_frame, only
 * the memory configuration. It never reads the frame records of the frames its
 * descriptors name. So an entry (table, id, sid, level, refs) stays exact
 * while:
 *   - no published store overlaps the table page or its frame record
 *     (sptm_dart_memo_publish, from the monitor's write witness): every SPTM
 *     store is published, retypes and reference counts included;
 *   - the table's refs equal the entry's (compared on every lookup);
 *   - the memory configuration equals the copy the memo keeps (compared on
 *     every lookup; a change flushes every entry).
 * A table becomes reachable only through MAP_TABLE, which requires an all-zero
 * page and publishes it whole, so a recycled frame's old entry is gone before
 * its first use. Writes to typed table frames that bypass the witness are
 * excluded by stage 2, as for the SWITCH_ROOT memo (sptm-root-memo.h); every
 * table is scanned anyway at its 64th hit since the last scan (a count per
 * entry, kept across the re-record after each commit, so no access pattern
 * aliases it away) and must agree. Under the service token only. */
#define SPTM_DART_MEMO_SETS 256u
#define SPTM_DART_MEMO_WAYS 4u
#define SPTM_DART_MEMO_SAMPLE 64u
#define SPTM_DART_MEMO_BOOT_RANGES 8u
_Static_assert(!(SPTM_DART_MEMO_SETS&(SPTM_DART_MEMO_SETS-1)),"memo set mask");
struct sptm_dart_memo_entry {
    uint64_t table;             /* table frame PA; 0 = empty */
    uint32_t refs;              /* the frame record's refs when the scan passed */
    uint8_t id, sid, level, valid;
    uint32_t hits;              /* hits since this table's last scan */
    uint32_t reserved;
};
_Static_assert(sizeof(struct sptm_dart_memo_entry)==24,"memo entry stride");
/* The inputs of sptm_managed_frame and sptm_dart_data_frame, copied whole. */
struct sptm_dart_memo_config {
    uint64_t frame_map_pa, frame_low, frame_high, alloc_low, alloc_high;
    uint64_t sep_firmware_pa, sep_firmware_size, sep_firmware_released, boot_count;
    uint64_t boot_pa[SPTM_DART_MEMO_BOOT_RANGES], boot_pages[SPTM_DART_MEMO_BOOT_RANGES];
};
/* lookups: verdicts asked for; hits answered from the memo (sampled ones
 * included); misses scanned; records stored; invalidations: entries dropped
 * by a published store; flushes: configuration changes; sampled: hits also
 * scanned; mismatches: sampled scans that refused (must stay 0). */
struct sptm_dart_memo_stats {
    uint64_t lookups,hits,misses,records,invalidations,flushes,sampled,mismatches;
};
struct sptm_dart_memo {
    struct sptm_dart_memo_stats stats;
    uint64_t configured, live;
    struct sptm_dart_memo_config config;
    struct sptm_dart_memo_entry entry[SPTM_DART_MEMO_SETS*SPTM_DART_MEMO_WAYS];
};
_Static_assert(__builtin_offsetof(struct sptm_dart_memo,stats)==0 &&
               sizeof(struct sptm_dart_memo_stats)==64,"report prefix");

static inline unsigned sptm_dart_memo_set(uint64_t table)
{
    return (unsigned)(((table>>14)*UINT64_C(0x9e3779b97f4a7c15))>>40)&(SPTM_DART_MEMO_SETS-1);
}
static inline int sptm_dart_memo_config_of(const struct sptm_memory *m,struct sptm_dart_memo_config *c)
{
    if (m->boot_count>SPTM_DART_MEMO_BOOT_RANGES || (m->boot_count && !m->boot_ranges)) return 0;
    *c=(struct sptm_dart_memo_config){m->frame_map_pa,m->frame_low,m->frame_high,m->alloc_low,
        m->alloc_high,m->sep_firmware_pa,m->sep_firmware_size,m->sep_firmware_released,m->boot_count,
        {0},{0}};
    for (unsigned i=0;i<m->boot_count;i++) {c->boot_pa[i]=m->boot_ranges[i].pa;c->boot_pages[i]=m->boot_ranges[i].pages;}
    return 1;
}
static inline int sptm_dart_memo_config_equal(const struct sptm_dart_memo_config *a,
                                              const struct sptm_dart_memo_config *b)
{
    const uint64_t *x=(const uint64_t *)a,*y=(const uint64_t *)b;
    for (unsigned i=0;i<sizeof(*a)/8;i++) if (x[i]!=y[i]) return 0;
    return 1;
}
static inline void sptm_dart_memo_clear(struct sptm_dart_memo *memo)
{
    for (unsigned i=0;i<SPTM_DART_MEMO_SETS*SPTM_DART_MEMO_WAYS;i++)
        memo->entry[i]=(struct sptm_dart_memo_entry){0};
    memo->live=0;
}
/* The memo is usable for m: its configuration is the copy, or it is flushed
 * and takes m's. 0: m's configuration cannot be copied (scan without it). */
static inline int sptm_dart_memo_ready(struct sptm_dart_memo *memo,const struct sptm_memory *m)
{
    struct sptm_dart_memo_config now;
    if (!sptm_dart_memo_config_of(m,&now)) return 0;
    if (memo->configured && sptm_dart_memo_config_equal(&memo->config,&now)) return 1;
    if (memo->configured) memo->stats.flushes++;
    sptm_dart_memo_clear(memo);
    memo->config=now;memo->configured=1;
    return 1;
}
static inline struct sptm_dart_memo_entry *sptm_dart_memo_lookup(struct sptm_dart_memo *memo,
    uint64_t table,unsigned id,unsigned sid,unsigned level,unsigned refs)
{
    struct sptm_dart_memo_entry *set=&memo->entry[sptm_dart_memo_set(table)*SPTM_DART_MEMO_WAYS];
    for (unsigned w=0;w<SPTM_DART_MEMO_WAYS;w++) {
        struct sptm_dart_memo_entry *e=&set[w];
        if (e->valid && e->table==table && e->id==id && e->sid==sid && e->level==level && e->refs==refs)
            return e;
    }
    return 0;
}
static inline void sptm_dart_memo_forget(struct sptm_dart_memo *memo,uint64_t table)
{
    struct sptm_dart_memo_entry *set=&memo->entry[sptm_dart_memo_set(table)*SPTM_DART_MEMO_WAYS];
    for (unsigned w=0;w<SPTM_DART_MEMO_WAYS;w++)
        if (set[w].valid && set[w].table==table) {set[w]=(struct sptm_dart_memo_entry){0};memo->live--;}
}
/* A passing verdict for table (refs as read): one entry per table frame. hits
 * carries the table's count since its last full scan: 0 after a scan, the old
 * entry's after a commit (sptm-dart.c table_committed), so a table that every
 * call changes is still scanned at its SPTM_DART_MEMO_SAMPLE-th hit. */
static inline void sptm_dart_memo_record(struct sptm_dart_memo *memo,uint64_t table,
    unsigned id,unsigned sid,unsigned level,unsigned refs,uint32_t hits)
{
    sptm_dart_memo_forget(memo,table);
    struct sptm_dart_memo_entry *set=&memo->entry[sptm_dart_memo_set(table)*SPTM_DART_MEMO_WAYS],*slot=&set[0];
    for (unsigned w=0;w<SPTM_DART_MEMO_WAYS;w++) if (!set[w].valid) {slot=&set[w];break;}
    if (slot->valid) memo->live--;          /* the set is full: replace way 0 */
    *slot=(struct sptm_dart_memo_entry){table,refs,(uint8_t)id,(uint8_t)sid,(uint8_t)level,1,hits,0};
    memo->live++;memo->stats.records++;
}
/* The hits of table's entry whatever its refs (0 when there is none). */
static inline uint32_t sptm_dart_memo_hits(const struct sptm_dart_memo *memo,uint64_t table)
{
    const struct sptm_dart_memo_entry *set=&memo->entry[sptm_dart_memo_set(table)*SPTM_DART_MEMO_WAYS];
    for (unsigned w=0;w<SPTM_DART_MEMO_WAYS;w++) if (set[w].valid && set[w].table==table) return set[w].hits;
    return 0;
}
static inline void sptm_dart_memo_drop(struct sptm_dart_memo *memo,uint64_t table)
{
    struct sptm_dart_memo_entry *set=&memo->entry[sptm_dart_memo_set(table)*SPTM_DART_MEMO_WAYS];
    for (unsigned w=0;w<SPTM_DART_MEMO_WAYS;w++)
        if (set[w].valid && set[w].table==table) {
            set[w]=(struct sptm_dart_memo_entry){0};memo->live--;memo->stats.invalidations++;
        }
}
/* Every entry, for a store too wide to walk frame by frame. */
static inline void sptm_dart_memo_drop_range(struct sptm_dart_memo *memo,uint64_t low,uint64_t high)
{
    for (unsigned i=0;i<SPTM_DART_MEMO_SETS*SPTM_DART_MEMO_WAYS;i++) {
        struct sptm_dart_memo_entry *e=&memo->entry[i];
        if (e->valid && e->table+0x4000>low && e->table<high) {
            *e=(struct sptm_dart_memo_entry){0};memo->live--;memo->stats.invalidations++;
        }
    }
}
/* The write witness: a published store [pa, pa+size) drops every entry whose
 * table page or frame record it overlaps. Entries are keyed by frame, so a
 * store reaches at most the frames it covers (up to 64 looked up one by one;
 * a wider store walks every entry). */
static inline void sptm_dart_memo_publish(struct sptm_dart_memo *memo,uint64_t pa,uint64_t size)
{
    if (!memo->live || !memo->configured || !size) return;
    uint64_t end=pa+size<pa ? UINT64_MAX : pa+size;
    const struct sptm_dart_memo_config *c=&memo->config;
    /* Table pages. */
    uint64_t first=pa&~UINT64_C(0x3fff),last=(end-1)&~UINT64_C(0x3fff);
    if ((last-first)>>14<64) {for (uint64_t f=first;;f+=0x4000) {sptm_dart_memo_drop(memo,f);if (f==last) break;}}
    else sptm_dart_memo_drop_range(memo,pa,end);
    /* Frame records: 16 bytes per frame from frame_map_pa. */
    uint64_t map_end=c->frame_map_pa+((c->frame_high-c->frame_low)>>14)*16;
    if (pa>=map_end || end<=c->frame_map_pa || !memo->live) return;
    uint64_t r0=pa>c->frame_map_pa ? pa : c->frame_map_pa,r1=end<map_end ? end : map_end;
    uint64_t i0=(r0-c->frame_map_pa)/16,i1=(r1-1-c->frame_map_pa)/16;
    if (i1-i0<64) {for (uint64_t i=i0;i<=i1;i++) sptm_dart_memo_drop(memo,c->frame_low+(i<<14));}
    else sptm_dart_memo_drop_range(memo,c->frame_low+(i0<<14),c->frame_low+((i1+1)<<14));
}

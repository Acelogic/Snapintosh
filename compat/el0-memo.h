/* SPDX-License-Identifier: MIT */
#pragma once
/* SNAP_EL0_MEMO: the lock-free EL0 read's instruction fetch from a per-vCPU
 * memo (probes/xnuboot.c fast_el0_word; batch-6 note, failure modes A1-A15).
 * Header-only; tools/test-el0-memo.c runs this exact code on the host.
 *
 * Why the word must be fetched at all: an UNDEFINED EL0t instruction enters
 * XNU's vector with ESR_EL1 0x02000000 (EC 0, no ISS) and exits to EL2 on the
 * vector page's stage-2 fetch abort, whose FAR is the kernel vector VA, so
 * nothing names the instruction: user_return_root and user_instruction_read
 * read it through the source and hardware tables, and fast_el0_sysreg reads
 * it twice. A memo way keeps, for one EL0 PC 4K page, the address and value of
 * every descriptor both walks read, the leaves and the leaf page PA, with the
 * identity it was read under (root entry, both walk roots, granule, hardware
 * reader, this vCPU's install count and active root). A hit trusts no value
 * from it: el0_memo_check re-reads every recorded descriptor through the same
 * reader and requires each to be unchanged, which is exactly the reads a
 * fresh walk would make now (mmu_walk is a function of its configuration and
 * the values it reads; each address follows from the previous value), and the
 * caller re-reads the code frame's type and the word itself. So the memo only
 * saves the root-cache scan, the walk decoding and the second read: a way is
 * kept only from a read whose double read agreed (el0_memo_keep after
 * fast_el0_sysreg's note), and a hit's own re-read is then its second read.
 *
 * Per vCPU: written only by its own CPU (its fast_el0_word and fast_el0_note,
 * its own root installs), so no atomics. */
#include <stdint.h>
#include "mmu.h"

#define EL0_MEMO_WAYS 4u
#define EL0_MEMO_READS 4u                 /* one per level: a 4K walk from level 0 */

/* One walk's reads in order: addresses and the values they held. */
struct el0_memo_walk {
    uint64_t at[EL0_MEMO_READS],value[EL0_MEMO_READS];
    uint32_t reads,overflow;
};
/* One translation of an EL0 PC page. walk[0] the source tables, walk[1] the
 * hardware tables (the same reads when the hardware walks the guest root). */
struct el0_memo_entry {
    uint64_t page;                        /* pc & ~0xfff */
    uint64_t installs,active;             /* the vCPU's install count and active root */
    const void *entry;                    /* the root's cache entry or record entry */
    uint64_t source_root,hardware_root;
    uint64_t source_leaf,hardware_leaf,page_pa;
    uint32_t source_shift,hardware_kind,valid,pad;
    struct el0_memo_walk walk[2];
};
struct el0_memo_stats {
    uint64_t hits;                        /* answered from a way */
    uint64_t absent;                      /* no way for the page */
    uint64_t stale;                       /* an install, another root or identity: dropped */
    uint64_t changed;                     /* a descriptor, the frame or the word refused: dropped */
    uint64_t fills;                       /* records kept */
};
struct el0_memo_cpu {
    uint64_t installs;                    /* bumped by every root install on this vCPU */
    uint32_t recording,next;              /* a full read records into pending; replacement */
    struct el0_memo_entry pending;        /* the last full read's record */
    struct el0_memo_entry way[EL0_MEMO_WAYS];
    struct el0_memo_stats stats;
};

/* An mmu_read_fn that reads through read/ctx and appends each successful
 * read to walk (a walk longer than EL0_MEMO_READS marks it overflowed). */
struct el0_memo_reader { mmu_read_fn read; void *ctx; struct el0_memo_walk *walk; };
static inline int el0_memo_read(void *opaque,uint64_t pa,uint64_t *out)
{
    struct el0_memo_reader *r=opaque;
    int result=r->read(r->ctx,pa,out);
    if(!result) {
        struct el0_memo_walk *w=r->walk;
        if(w->reads<EL0_MEMO_READS) {w->at[w->reads]=pa;w->value[w->reads]=*out;w->reads++;}
        else w->overflow=1;
    }
    return result;
}
/* 1 when every recorded address still holds its recorded value through read. */
static inline int el0_memo_replay(const struct el0_memo_walk *w,mmu_read_fn read,void *ctx)
{
    if(w->overflow || !w->reads || w->reads>EL0_MEMO_READS)return 0;
    for(unsigned i=0;i<w->reads;i++) {
        uint64_t value;
        if(read(ctx,w->at[i],&value) || value!=w->value[i])return 0;
    }
    return 1;
}

/* A root install on this vCPU: every way it holds is stale from now on. */
static inline void el0_memo_installed(struct el0_memo_cpu *m) {m->installs++;}

/* The way for pc's page, or 0. Every lookup ends the pending record, so only
 * a full read that follows it can be kept. */
static inline struct el0_memo_entry *el0_memo_find(struct el0_memo_cpu *m,uint64_t pc)
{
    uint64_t page=pc&~UINT64_C(0xfff);
    m->pending.valid=0;
    for(unsigned n=0;n<EL0_MEMO_WAYS;n++)
        if(m->way[n].valid && m->way[n].page==page)return &m->way[n];
    m->stats.absent++;
    return 0;
}
/* The way was read since this vCPU's last install, under the active root. */
static inline int el0_memo_current(const struct el0_memo_cpu *m,const struct el0_memo_entry *w,uint64_t active)
{return w->installs==m->installs && w->active==active;}
static inline void el0_memo_drop(struct el0_memo_entry *w) {w->valid=0;}
/* The identity the caller derives now equals the way's, and both walks still
 * read exactly what they read then. */
static inline int el0_memo_check(const struct el0_memo_entry *w,const void *entry,
    uint64_t source_root,unsigned source_shift,uint64_t hardware_root,unsigned hardware_kind,
    mmu_read_fn source_read,void *source_ctx,mmu_read_fn hardware_read,void *hardware_ctx)
{
    return w->entry==entry && w->source_root==source_root && w->source_shift==source_shift &&
        w->hardware_root==hardware_root && w->hardware_kind==hardware_kind &&
        el0_memo_replay(&w->walk[0],source_read,source_ctx) &&
        el0_memo_replay(&w->walk[1],hardware_read,hardware_ctx);
}

/* A full read starts recording pc's page under this vCPU's identity. */
static inline void el0_memo_begin(struct el0_memo_cpu *m,uint64_t pc,uint64_t active)
{
    struct el0_memo_entry *p=&m->pending;
    p->valid=0;p->page=pc&~UINT64_C(0xfff);p->installs=m->installs;p->active=active;
    p->walk[0].reads=p->walk[0].overflow=0;p->walk[1].reads=p->walk[1].overflow=0;
    m->recording=1;
}
/* user_instruction_read accepted both walks: the rest of the record. */
static inline void el0_memo_recorded(struct el0_memo_cpu *m,const void *entry,uint64_t source_root,
    unsigned source_shift,uint64_t hardware_root,unsigned hardware_kind,uint64_t source_leaf,
    uint64_t hardware_leaf,uint64_t pa)
{
    struct el0_memo_entry *p=&m->pending;
    p->entry=entry;p->source_root=source_root;p->source_shift=source_shift;
    p->hardware_root=hardware_root;p->hardware_kind=hardware_kind;
    p->source_leaf=source_leaf;p->hardware_leaf=hardware_leaf;p->page_pa=pa&~UINT64_C(0xfff);
    p->valid=p->walk[0].reads && !p->walk[0].overflow && p->walk[1].reads && !p->walk[1].overflow;
}
/* The full read is over; a failed one keeps nothing. */
static inline void el0_memo_end(struct el0_memo_cpu *m,int read)
{
    m->recording=0;
    if(!read)m->pending.valid=0;
}
/* fast_el0_sysreg accepted the read of pc (both reads agreed) and emulated it
 * under root: keep the pending record if it is that read's, replacing any way
 * of the same page. */
static inline void el0_memo_keep(struct el0_memo_cpu *m,uint64_t pc,uint64_t root)
{
    struct el0_memo_entry *p=&m->pending;
    if(!p->valid || p->page!=(pc&~UINT64_C(0xfff)) || p->source_root!=root || p->installs!=m->installs)
        return;
    struct el0_memo_entry *w=0;
    for(unsigned n=0;n<EL0_MEMO_WAYS && !w;n++)if(m->way[n].valid && m->way[n].page==p->page)w=&m->way[n];
    if(!w)w=&m->way[m->next++%EL0_MEMO_WAYS];
    *w=*p;w->valid=1;
    p->valid=0;m->stats.fills++;
}

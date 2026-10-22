/* SPDX-License-Identifier: MIT */
/* SNAP_FINE_LOCKS concurrency harness (docs/FINE-LOCKS-20261017.md).
 *
 * Six pthreads play six vCPUs. Each issues a random stream of the converted
 * calls -- user MAP_PAGE, UNMAP_REGION and UPDATE_DISJOINT (and, with
 * SNAP_FINE_SWITCH, SWITCH_ROOT cache hits) -- through the real compat
 * engines (compat/sptm-user.c, sptm-root.c, sptm-refs.c, shadow/shadow.c)
 * under the real gate (compat/service-lock.c) and root stripes
 * (compat/fine-lock.h), interleaved with token-path operations that reshape
 * what converted calls read: RETYPE churn of spare frames, SWITCH_ROOT
 * (misses and, without SNAP_FINE_SWITCH, hits), and cache invalidation of an
 * inactive root followed by its rebuild. Each simulated CPU also walks its
 * active root's 4K shadow between calls and caches what it finds in a TLB
 * model, as the hardware walker does while other CPUs run monitor calls.
 * The backend callbacks follow probes/xnuboot.c's user backend (user_backend,
 * user_prepare/commit_leaf, user_prepare/commit_update, user_prepare/
 * commit_unmap): cached shadow commits, per-store publication, a VA TLBI of
 * every CPU before references drop.
 *
 * Checked, per failure mode of the design note:
 *  F1/F2/F11 every frame's +8/+12 counts equal an independent count of the
 *      leaves mapping it in every root's guest tables, and every table's +8
 *      equals its valid entries (refcount invariant); frame types equal the
 *      token-path history (type invariant);
 *  F4/F6/F12 linearizability: every call logs its result and outputs with a
 *      sequence number taken inside its critical section; the log is replayed
 *      single-threaded through the token path (one global lock, absolute
 *      reference stores) from the initial state, and every result, output,
 *      the final guest RAM, the shadow arena and the cache must be equal;
 *      ThreadSanitizer reports any unsynchronized guest-table or count access;
 *  F5  a watchdog fails the run when no call completes for 20 seconds;
 *  F8  every shadow store is published before the TLBI that ends its call;
 *  F9  after every call, no CPU's TLB holds a translation for a page the call
 *      changed that differs from the current shadow (the walker holds its
 *      CPU's TLB lock across walk and fill, as a TLBI completes in-flight
 *      walks);
 *  shadow == guest: every cached valid root's 4K shadow equals its 16K guest
 *      leaves and its leaf count.
 *
 * Build (tools/test-fine-locks.py runs these and the mutants):
 *  clang -std=gnu11 -O1 -g -pthread -fsanitize=thread -DSNAP_FINE_LOCKS=1 \
 *    -Icompat -Ishadow tools/test-fine-locks.c compat/service-lock.c \
 *    compat/sptm*.c shadow/sprr-view.c shadow/mmu.c shadow/shadow.c
 *  (the same with -fsanitize=address,undefined; add -DSNAP_FINE_SWITCH=1
 *  for phase 1b, -DSNAP_FAIR_TOKEN=1 for the FIFO token, with it
 *  -DSNAP_PHASE_FAIR_GATE=1 for the phase-fair gate). Arguments:
 *  [ops-per-cpu] [seed], or "fair" [rounds] for the fairness run below, or
 *  (SNAP_FAIR_TOKEN, plain -O2) "mix" [seconds] [seed] [exp|fixed] [K=F] for
 *  the v5 load model (K=F: a what-if, token hold class K's hold times F). */
#define _GNU_SOURCE
#include <pthread.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#define FINE_RELAX() sched_yield()
#include "fine-lock.h"
#include "service-lock.h"
#include "sptm-user.h"
#include "sptm-refs.h"
#include "sptm-root.h"
#include "shadow.h"
#include "mmu.h"
#if !SNAP_FINE_LOCKS
#error "build with -DSNAP_FINE_LOCKS=1"
#endif
#ifndef SNAP_FAIR_TOKEN
#define SNAP_FAIR_TOKEN 0
#endif
/* SNAP_PHASE_FAIR_GATE: the announced wait's bound in polls (the monitor's is
 * 1/200 s); short enough that withdrawals happen under the sanitizers. */
#ifndef PF_POLLS
#define PF_POLLS 4096u
#endif

#define CPUS GUEST_CPU_COUNT
#define BASE UINT64_C(0x90000000)
#define SIZE UINT64_C(0x2000000)
#define FM (BASE+0x4000)
#define KROOT (BASE+0x8000)
#define PERCPU (BASE+0x10000)
#define ALLOC_LOW (BASE+0x40000)
#define NROOTS 8u
#define NL3 4u
#define NSLOT 40u
#define NDATA 160u
#define NSPARE 16u
#define VBASE UINT64_C(0x100000000)
#define ABASE UINT64_C(0x400000000)
#define APAGES 4096u
#define RW UINT64_C(0x0060000000000f43)
#define RO UINT64_C(0x0060000000000fc3)
#define WW (UINT64_C(1)<<59)
#define AF UINT64_C(0x400)
#define PA_MASK UINT64_C(0x0000ffffffffc000)

static unsigned checks;
#define CHECK(x) do { __atomic_fetch_add(&checks,1,__ATOMIC_RELAXED); if(!(x)) { \
    fprintf(stderr,"FAIL %d: %s\n",__LINE__,#x); fflush(stderr); _exit(1); } } while(0)

/* ---- guest RAM, frame map, shadow arena ---------------------------------- */
static uint8_t *ram, *ram0;
static uint64_t *arena, *arena0;
static uint64_t root_pa[NROOTS], l2_pa[NROOTS], l3_pa[NROOTS][NL3], data_pa[NDATA], spare_pa[NSPARE];
static unsigned spare_type[NSPARE], spare_type0[NSPARE];

struct tctx;
static __thread struct tctx *self;
static int replaying;
static unsigned chaos_seed_global;
static __thread unsigned chaos_seed;
static void chaos(void) { if(!replaying && (rand_r(&chaos_seed)&15)==0) sched_yield(); }

static volatile uint8_t *map(void *ctx,uint64_t pa,uint64_t n)
{
    (void)ctx;
    if(pa<BASE || pa>=BASE+SIZE || n>BASE+SIZE-pa) return NULL;
    return ram+(pa-BASE);
}
static unsigned long publications;
static void publish(void *ctx,uint64_t pa,uint64_t n)
{
    (void)ctx;CHECK(map(0,pa,n)!=NULL);__atomic_fetch_add(&publications,1,__ATOMIC_RELAXED);chaos();
}
static uint64_t get(uint64_t pa,unsigned n)
{uint64_t v=0;for(unsigned i=0;i<n;i++)v|=(uint64_t)ram[pa-BASE+i]<<(8*i);return v;}
static uint64_t meta(uint64_t pa) {return FM+((pa-BASE)>>14)*16;}

/* Arena: exclusive-only allocation (a converted call never allocates). Every
 * word is accessed atomically, as the hardware walker is a concurrent
 * observer of live shadow tables. */
static unsigned arena_owner[APAGES], arena_next, arena_free[APAGES], arena_nfree;
static unsigned arena_owner0[APAGES], arena_next0, arena_free0[APAGES], arena_nfree0;
static uint64_t aload(uint64_t pa) {return __atomic_load_n(&arena[(pa-ABASE)/8],__ATOMIC_RELAXED);}
static void astore(uint64_t pa,uint64_t v) {__atomic_store_n(&arena[(pa-ABASE)/8],v,__ATOMIC_RELAXED);}
static uint64_t arena_take(unsigned owner)
{
    unsigned page;
    if(arena_nfree)page=arena_free[--arena_nfree];
    else if(arena_next<APAGES)page=arena_next++;
    else return 0;
    arena_owner[page]=owner;
    uint64_t pa=ABASE+(uint64_t)page*4096;
    for(unsigned i=0;i<512;i++)astore(pa+8*i,0);
    return pa;
}
static void arena_release_owner(unsigned owner)
{
    for(unsigned p=0;p<arena_next;p++)if(arena_owner[p]==owner) {arena_owner[p]=0;arena_free[arena_nfree++]=p;}
}
static int arena_read(void *ctx,uint64_t pa,uint64_t *v)
{
    (void)ctx;
    if(pa<ABASE || pa>=ABASE+(uint64_t)APAGES*4096 || (pa&7))return -1;
    *v=aload(pa);return 0;
}

/* ---- per-CPU context -------------------------------------------------- */
#define TLB_SIZE 1024u
struct tlb_entry {uint64_t root,va,desc;};
struct tlb {pthread_mutex_t lock;struct tlb_entry e[TLB_SIZE];};
static struct tlb tlbs[CPUS];
struct tctx {
    unsigned cpu, fine;          /* fine: inside a converted call */
    unsigned seed;
    int alloc_refused;           /* the converted call's allocator was asked */
    unsigned dirty_count;        /* shadow stores not yet published (F8) */
    uint64_t dirty[64];
    struct sptm_ref_batch refs;
    struct sptm_ref_fine ref_fine;
    struct sptm_pv_audit audit;
    uint64_t changed_va[80];uint64_t changed_root[80];unsigned changed;
    uint64_t fine_calls,declines,token_calls;
    uint64_t withdrawn;          /* SNAP_PHASE_FAIR_GATE: announced arrivals withdrawn at the bound */
};
static struct tctx tc[CPUS];
static struct sptm_ref_batch global_refs;
static struct sptm_pv_audit global_audit;
static struct guest_service_lock gate;
static struct fine_ticket stripes[FINE_STRIPES];

/* SWITCH_ROOT state: the real cache, active[], each CPU's recorded TTBR0 and
 * the shadow its hardware walks (per CPU, set by install like TTBR0). */
static struct sptm_root_state roots;
static uint64_t guest_ttbr0[CPUS], hw_shadow[CPUS], hw_root[CPUS];
static uint64_t evictions;
static uint64_t kshadow;

static uint64_t tlb_hash(uint64_t root,uint64_t va) {return ((root>>14)*31+(va>>12))%TLB_SIZE;}
static void tlb_fill(unsigned cpu,uint64_t root,uint64_t va,uint64_t desc)
{
    struct tlb *t=&tlbs[cpu];
    unsigned h=(unsigned)tlb_hash(root,va);
    for(unsigned i=0;i<8;i++) {
        struct tlb_entry *e=&t->e[(h+i)%TLB_SIZE];
        if(!e->root || (e->root==root && e->va==va)) {*e=(struct tlb_entry){root,va,desc};return;}
    }
    t->e[h]=(struct tlb_entry){root,va,desc};   /* replacement */
}
/* vaae1is in every VMID: every CPU, every root, the range. Taking each
 * CPU's TLB lock completes its in-flight walk first (F9). */
static void tlbi_range(uint64_t va,uint64_t size)
{
    CHECK(!self || !self->dirty_count);            /* F8: published before the TLBI */
    for(unsigned c=0;c<CPUS;c++) {
        pthread_mutex_lock(&tlbs[c].lock);
        for(unsigned i=0;i<TLB_SIZE;i++) {
            struct tlb_entry *e=&tlbs[c].e[i];
            if(e->root && e->va>=va && e->va-va<size)e->root=0;
        }
        pthread_mutex_unlock(&tlbs[c].lock);
    }
}
static void tlbi_root(uint64_t root)
{
    for(unsigned c=0;c<CPUS;c++) {
        pthread_mutex_lock(&tlbs[c].lock);
        for(unsigned i=0;i<TLB_SIZE;i++)if(tlbs[c].e[i].root==root)tlbs[c].e[i].root=0;
        pthread_mutex_unlock(&tlbs[c].lock);
    }
}
static int shadow_leaf(uint64_t shadow,uint64_t va,uint64_t *desc)
{
    struct mmu_config cfg={12,17,shadow};struct mmu_leaf leaf;
    if(mmu_walk(&cfg,va,arena_read,0,&leaf))return -1;
    *desc=leaf.valid ? leaf.descriptor : 0;return 0;
}
/* Slots spread over each 32 MiB L3 span, so some fall in a 2 MiB shadow
 * region with no table yet: a converted MAP_PAGE there must decline. */
static uint64_t slot_va(unsigned k,unsigned j) {return VBASE+(uint64_t)k*0x2000000+(uint64_t)j*51*0x4000;}
/* The guest walk this CPU's hardware makes between calls. */
static void walk_some(struct tctx *t)
{
    if(replaying || !hw_shadow[t->cpu])return;
    for(unsigned n=0;n<4;n++) {
        uint64_t va=slot_va(rand_r(&t->seed)%NL3,rand_r(&t->seed)%NSLOT)+(rand_r(&t->seed)%4)*4096;
        pthread_mutex_lock(&tlbs[t->cpu].lock);
        uint64_t desc;
        /* A leaf with AF clear faults instead of filling (update_fast_uncached). */
        if(!shadow_leaf(hw_shadow[t->cpu],va,&desc) && desc && (desc&AF))
            tlb_fill(t->cpu,hw_root[t->cpu],va,desc);
        pthread_mutex_unlock(&tlbs[t->cpu].lock);
    }
}

/* ---- the user backend (probes/xnuboot.c user_backend and callbacks) ----- */
static struct sptm_root_cached *cached(uint64_t root)
{
    for(unsigned i=0;i<SPTM_ROOT_CACHE;i++)
        if(roots.cache[i].root==root && roots.cache[i].valid)return &roots.cache[i];
    return 0;
}
static unsigned owner_of(struct sptm_root_cached *e) {return (unsigned)(e-roots.cache)+1;}
static uint64_t fine_alloc(void *ctx) {(void)ctx;self->alloc_refused=1;return 0;}
static uint64_t token_alloc(void *ctx) {return arena_take(*(unsigned *)ctx);}
static unsigned owner_ctx[SPTM_ROOT_CACHE];
static int live_write(void *ctx,uint64_t pa,uint64_t v)
{
    (void)ctx;
    if(pa<ABASE || pa>=ABASE+(uint64_t)APAGES*4096 || (pa&7))return -1;
    astore(pa,v);
    if(self) {CHECK(self->dirty_count<64);self->dirty[self->dirty_count++]=pa&~UINT64_C(63);}
    chaos();
#ifndef MUTANT_NO_PUBLISH
    if(self)for(unsigned i=0;i<self->dirty_count;i++)if(self->dirty[i]==(pa&~UINT64_C(63)))
        self->dirty[i]=self->dirty[--self->dirty_count],i--;
#endif
    return 0;
}
static struct shadow shadow_for(struct sptm_root_cached *e)
{
    unsigned o=owner_of(e);owner_ctx[o-1]=o;
    return (struct shadow){.txsz=17,.root=e->shadow,.alloc=self && self->fine ? fine_alloc : token_alloc,
        .read=arena_read,.write=live_write,.ctx=0,.alloc_ctx=&owner_ctx[o-1]};
}
static struct sptm_memory memory_for(struct tctx *t);
static uint64_t changed_pages;
static void note_changed(uint64_t root,uint64_t va,uint64_t size)
{
    if(!replaying)__atomic_fetch_add(&changed_pages,size>>14,__ATOMIC_RELAXED);
    for(uint64_t off=0;off<size;off+=0x4000)
        if(self && self->changed<80) {self->changed_root[self->changed]=root;self->changed_va[self->changed++]=va+off;}
}
static void tlb_range_commit(uint64_t va,uint64_t size)
{
#ifndef MUTANT_NO_TLBI
    tlbi_range(va,size);
#else
    (void)va;(void)size;
#endif
}
static int prepare_leaf(void *ctx,uint64_t root,uint64_t va,unsigned shift,uint64_t pte)
{
    (void)ctx;(void)pte;struct sptm_root_cached *e=cached(root);
    if(!e)return 0;
    struct shadow s=shadow_for(e);
    return sptm_root_prepare_leaf(e,&s,va,shift);
}
static int commit_leaf(void *ctx,uint64_t root,uint64_t va,unsigned shift,uint64_t pte)
{
    (void)ctx;struct sptm_root_cached *e=cached(root);
    if(!e)return 0;
    struct shadow s=shadow_for(e);struct sptm_memory m=memory_for(self);
    if(!sptm_root_commit_leaf(e,&s,&m,va,shift,pte))return 0;
    note_changed(root,va,UINT64_C(1)<<shift);tlb_range_commit(va,UINT64_C(1)<<shift);return 1;
}
static int prepare_unmap(void *ctx,uint64_t root,uint64_t va,unsigned shift,uint64_t count)
{
    (void)ctx;struct sptm_root_cached *e=cached(root);
    if(!e)return 1;
    struct shadow s=shadow_for(e);struct sptm_memory m=memory_for(self);
    return sptm_root_prepare_unmap(e,&s,&m,va,shift,count);
}
static int prepare_update(void *ctx,uint64_t root,uint64_t va,unsigned shift,uint64_t old,uint64_t next)
{
    (void)old;(void)next;return prepare_unmap(ctx,root,va,shift,1);
}
static int commit_update(void *ctx,uint64_t root,uint64_t va,unsigned shift,uint64_t old,uint64_t next)
{
    (void)ctx;struct sptm_root_cached *e=cached(root);
    if(e) {
        struct shadow s=shadow_for(e);struct sptm_memory m=memory_for(self);
        if(!sptm_root_commit_update(e,&s,&m,va,shift,old,next))return 0;
    }
    note_changed(root,va,UINT64_C(1)<<shift);
    /* update_fast_uncached: an old leaf with AF clear was never cached. */
    if(!(old&AF))return 1;
    tlb_range_commit(va,UINT64_C(1)<<shift);return 1;
}
static int commit_unmap(void *ctx,uint64_t root,uint64_t va,unsigned shift,uint64_t count,uint64_t removed)
{
    (void)ctx;struct sptm_root_cached *e=cached(root);
    if(e) {
        struct shadow s=shadow_for(e);
        if(!sptm_root_commit_unmap(e,&s,va,shift,count,removed))return 0;
    }
    note_changed(root,va,count<<shift);tlb_range_commit(va,count<<shift);return 1;
}
static uint64_t load_active(unsigned cpu) {return __atomic_load_n(&roots.active[cpu],__ATOMIC_RELAXED);}
static uint64_t load_ttbr(unsigned cpu) {return __atomic_load_n(&guest_ttbr0[cpu],__ATOMIC_RELAXED);}
static int resolve(void *ctx,uint64_t root,struct sptm_user_backend *b)
{
    struct tctx *t=ctx;
    memset(b,0,sizeof(*b));
    b->ttbr0=load_ttbr(t->cpu);b->ttbr1=KROOT;
    b->aperture=(struct sptm_aperture){BASE,UINT64_C(0xfffffe0100000000),SIZE};
    b->prepare_leaf=prepare_leaf;b->commit_leaf=commit_leaf;
    b->prepare_unmap=prepare_unmap;b->commit_unmap=commit_unmap;
    b->prepare_update=prepare_update;b->commit_update=commit_update;b->ctx=t;
    for(unsigned c=0;c<CPUS;c++) {
        int active=load_active(c)==root,recorded=(load_ttbr(c)&PA_MASK)==root;
        if(active!=recorded)return 0;
        b->active_refs+=(unsigned)active;
    }
    return !b->active_refs || cached(root)!=0;
}
static struct sptm_memory memory_for(struct tctx *t)
{
    struct sptm_memory m={.frame_map_pa=FM,.frame_low=BASE,.frame_high=BASE+SIZE,
        .alloc_low=ALLOC_LOW,.alloc_high=BASE+SIZE,.map=map,.publish=publish,
        .refs=t && t->fine ? &t->refs : &global_refs,
        .audit=t && t->fine ? &t->audit : &global_audit};
    if(t && t->fine)m.fine=&t->ref_fine;
    return m;
}

/* ---- the call log --------------------------------------------------------- */
enum kind {OP_MAP,OP_UNMAP,OP_UPDATE,OP_SWITCH,OP_RETYPE,OP_INVALIDATE};
struct op {
    unsigned kind,cpu,count;
    uint64_t root,va,arg,options;
    uint64_t rec[3*4];
    /* results */
    int result;uint64_t guest;uint64_t out[8];
    uint64_t seq;int fine;
};
static uint64_t log_max;
static struct op *oplog;
static uint64_t seq_next;
static uint64_t progress;

/* ---- the operations ------------------------------------------------------ */
static uint64_t out_pa(unsigned cpu) {return PERCPU+(uint64_t)cpu*0x4000;}
static uint64_t list_pa(unsigned cpu) {return PERCPU+(uint64_t)cpu*0x4000+0x1000;}
static void put_ram(uint64_t pa,uint64_t v) {for(unsigned i=0;i<8;i++)ram[pa-BASE+i]=(uint8_t)(v>>(8*i));}

static void root_switch_install(void *ctx,uint64_t shadow,uint64_t root,uint64_t asid,unsigned format)
{
    struct tctx *t=ctx;(void)format;
    __atomic_store_n(&guest_ttbr0[t->cpu],asid ? (root|(asid<<48)) : root,__ATOMIC_RELAXED);
    hw_shadow[t->cpu]=asid ? shadow : 0;hw_root[t->cpu]=asid ? root : 0;
}
static int root_build(void *ctx,const struct sptm_memory *m,uint64_t root,unsigned format,
                      unsigned flags,uint64_t previous,uint64_t *result,uint64_t *leaves)
{
    (void)ctx;
    unsigned slot=SPTM_ROOT_CACHE;
    for(unsigned i=0;i<SPTM_ROOT_CACHE;i++) {
        struct sptm_root_cached *e=&roots.cache[i];
        if((previous && e->shadow==previous) || (!previous && !e->shadow && (!e->root || e->root==root))) {slot=i;break;}
    }
    if(slot==SPTM_ROOT_CACHE)return 0;
    arena_release_owner(slot+1);tlbi_root(root);
    owner_ctx[slot]=slot+1;
    struct shadow s={.txsz=17,.root=arena_take(slot+1),.alloc=token_alloc,.read=arena_read,
        .write=live_write,.alloc_ctx=&owner_ctx[slot]};
    if(!s.root || !sptm_root_build_shadow(m,&s,root,format,flags,leaves))return 0;
    *result=s.root;return 1;
}
/* The owner's sampled tree walk on cache hits (native_skip_hit): here a
 * fixed choice per root, so a replay walks exactly the same switches. Roots
 * whose hits are walked always take the token path. */
static int skip_hit(void *ctx) {(void)ctx;return 1;}
static int walked_root(uint64_t root) {return ((root>>14)%5)==0;}
static enum sptm_result do_switch(struct tctx *t,uint64_t root)
{
    struct sptm_memory m=memory_for(t);
    struct sptm_root_backend b={.kernel_root=KROOT,.kernel_shadow=kshadow,.build=root_build,
        .install=root_switch_install,.ctx=t,.evictions=&evictions,
        .skip_hit_validation=walked_root(root) ? 0 : skip_hit};
#if SNAP_FINE_SWITCH
    if(t->fine)return sptm_mac_switch_root_hit(&m,&roots,&b,t->cpu,root,0,0) ? SPTM_OK : SPTM_FRAME_BUSY;
#endif
    return sptm_mac_switch_root(&m,&roots,&b,t->cpu,root,0,0);
}
static void execute(struct tctx *t,struct op *op)
{
    struct sptm_memory m=memory_for(t);
    op->guest=0;memset(op->out,0,sizeof(op->out));
    switch(op->kind) {
    case OP_MAP: {
        struct sptm_user_backend b;
        if(!resolve(t,op->root,&b)) {op->result=-1;break;}
        op->result=sptm_mac_map_user_page(&m,&b,op->root,op->va,op->arg,op->options,out_pa(t->cpu),&op->guest);
        if(op->result==SPTM_OK && !b.active_refs && op->guest==0 && cached(op->root) && !t->fine) {
            /* A fresh leaf in an inactive cached root (mirror off): the token
             * path invalidates the entry (probes/xnuboot.c MAP_PAGE). */
            CHECK(sptm_root_invalidate(&roots,op->root,0));tlbi_root(op->root);
        }
        for(unsigned i=0;i<2;i++)op->out[i]=get(out_pa(t->cpu)+8*i,8);
        break;
    }
    case OP_UNMAP: {
        struct sptm_user_backend b;
        if(!resolve(t,op->root,&b)) {op->result=-1;break;}
        op->result=sptm_mac_unmap_user_region(&m,&b,op->root,op->va,op->count,op->options,out_pa(t->cpu));
        for(unsigned i=0;i<op->count;i++)op->out[i]=get(out_pa(t->cpu)+8*i,8);
        break;
    }
    case OP_UPDATE:
        for(unsigned i=0;i<3*op->count;i++)put_ram(list_pa(t->cpu)+8*i,op->rec[i]);
        op->result=sptm_mac_update_user_disjoint(&m,resolve,t,op->arg,list_pa(t->cpu),op->count,
                                                 op->options,out_pa(t->cpu),&op->guest,0);
        for(unsigned i=0;i<op->count;i++)op->out[i]=get(out_pa(t->cpu)+8*i,8);
        break;
    case OP_SWITCH:
        op->result=do_switch(t,op->root);
        break;
    case OP_RETYPE: {
        unsigned i=(unsigned)op->arg,from=spare_type[i],to=from==11 ? 20 : 11;
        op->result=sptm_mac_retype(&m,spare_pa[i],from,to,to==20 ? 3 : 0);
        if(op->result==SPTM_OK)spare_type[i]=to;
        op->guest=to;
        break;
    }
    case OP_INVALIDATE:
        op->result=sptm_root_invalidate(&roots,op->root,0) ? SPTM_OK : SPTM_FRAME_BUSY;
        if(op->result==SPTM_OK)tlbi_root(op->root);
        break;
    }
}
/* Converted calls: the eligibility xnuboot.c applies before the engine. */
static int fine_candidate(const struct op *op)
{
    if(op->kind==OP_UPDATE || op->kind==OP_UNMAP)return 1;
    if(op->kind==OP_MAP)return 1;
#if SNAP_FINE_SWITCH
    if(op->kind==OP_SWITCH)return 1;
#endif
    return 0;
}
static int lockset_for(const struct op *op,struct fine_lockset *set)
{
    fine_lockset_init(set);
    if(op->kind==OP_UPDATE) {
        for(unsigned i=0;i<op->count;i++)if(!fine_lockset_add(set,op->rec[3*i]))return 0;
        return 1;
    }
#if SNAP_FINE_SWITCH
    if(op->kind==OP_SWITCH) {
        uint64_t old=load_active(self->cpu);
        if(old && !fine_lockset_add(set,old))return 0;
        return op->root==KROOT || fine_lockset_add(set,op->root);
    }
#endif
    return fine_lockset_add(set,op->root);
}
static void lock_set(const struct fine_lockset *set)
{
#ifndef MUTANT_NO_STRIPES
    fine_lockset_acquire(stripes,set);
#else
    (void)set;
#endif
}
static void unlock_set(const struct fine_lockset *set)
{
#ifndef MUTANT_NO_STRIPES
    fine_lockset_release(stripes,set);
#else
    (void)set;
#endif
}
/* Envelope checks that need the stripes (xnuboot.c fine_* preconditions). */
static int fine_admits(struct tctx *t,const struct op *op)
{
    if(op->kind==OP_MAP) {
        /* A cached root no CPU runs: its mirror/invalidation decision is the
         * token path's. */
        struct sptm_user_backend b;
        if(!resolve(t,op->root,&b))return 0;
        return b.active_refs || !cached(op->root);
    }
    return 1;
}
static void token_acquire(struct tctx *t)
{
#if SNAP_FAIR_TOKEN
    uint32_t ticket=guest_service_queue(&gate);
#if SNAP_PHASE_FAIR_GATE
    /* G3: a CPU still at the gate is refused (REENTRY), never left to drain
     * for itself; nothing here stops, so a turn is only OK or BUSY. */
    enum guest_service_result r;
    while((r=guest_service_try_turn(&gate,t->cpu,ticket))!=SERVICE_OK) {CHECK(r==SERVICE_BUSY);FINE_RELAX();}
#else
    while(guest_service_try_turn(&gate,t->cpu,ticket)!=SERVICE_OK)FINE_RELAX();
#endif
#else
    while(guest_service_try(&gate,t->cpu)!=SERVICE_OK)FINE_RELAX();
#endif
    while(!guest_service_drained(&gate))FINE_RELAX();
}
static void log_op(struct op *op,int fine)
{
    op->seq=__atomic_fetch_add(&seq_next,1,__ATOMIC_RELAXED);op->fine=fine;
    CHECK(op->seq<log_max);oplog[op->seq]=*op;
}
/* F9: no CPU caches a translation of a changed page that the shadow no
 * longer holds. Run while the call still holds its locks. */
static void tlb_check(struct tctx *t)
{
    for(unsigned n=0;n<t->changed;n++) {
        uint64_t root=t->changed_root[n];struct sptm_root_cached *e=cached(root);
        for(uint64_t off=0;off<0x4000;off+=4096) {
            uint64_t va=t->changed_va[n]+off,desc=0;
            if(e)CHECK(!shadow_leaf(e->shadow,va,&desc));
            for(unsigned c=0;c<CPUS;c++) {
                pthread_mutex_lock(&tlbs[c].lock);
                unsigned h=(unsigned)tlb_hash(root,va);
                for(unsigned i=0;i<8;i++) {
                    struct tlb_entry *x=&tlbs[c].e[(h+i)%TLB_SIZE];
                    if(x->root==root && x->va==va && x->desc!=desc) {
                        fprintf(stderr,"stale TLB: cpu%u root %#llx va %#llx cached %#llx shadow %#llx\n",c,
                                (unsigned long long)root,(unsigned long long)va,
                                (unsigned long long)x->desc,(unsigned long long)desc);
                        CHECK(!"stale translation after the call");
                    }
                }
                pthread_mutex_unlock(&tlbs[c].lock);
            }
        }
    }
}
static void run(struct tctx *t,struct op *op)
{
    t->changed=0;
    if(fine_candidate(op)) {
#if SNAP_PHASE_FAIR_GATE
        /* SNAP_PHASE_FAIR_GATE: BUSY is an announced arrival; wait for the
         * writer's phase to end, bounded as SNAP_GATE_WAIT bounds it: at the
         * bound withdraw and take the token path (G3, G10). */
        enum guest_service_result r=guest_service_enter_shared(&gate,t->cpu);
        for(unsigned polls=0;r==SERVICE_BUSY;polls++) {
            if(polls>=PF_POLLS) {
                guest_service_leave_shared(&gate,t->cpu);
                break;
            }
            FINE_RELAX();
            r=guest_service_wait_shared(&gate,t->cpu,0);
        }
        if(r!=SERVICE_OK) {
            CHECK(r==SERVICE_BUSY);
            t->withdrawn++;t->declines++;
            goto token;
        }
#else
        for(;;) {
            enum guest_service_result r=guest_service_enter_shared(&gate,t->cpu);
            if(r==SERVICE_OK)break;
            CHECK(r==SERVICE_BUSY);
            while(guest_service_owner(&gate))FINE_RELAX();
        }
#endif
        struct fine_lockset set;
        if(lockset_for(op,&set)) {
            lock_set(&set);
            t->fine=1;
            if(fine_admits(t,op)) {
                t->alloc_refused=0;t->audit=(struct sptm_pv_audit){0};
                struct op attempt=*op;
                execute(t,&attempt);
                CHECK(!t->dirty_count);
                if(attempt.result==SPTM_OK || attempt.result==SPTM_TABLE_MISSING) {
                    log_op(&attempt,1);
                    t->fine=0;
                    tlb_check(t);
                    unlock_set(&set);guest_service_leave_shared(&gate,t->cpu);
                    t->fine_calls++;return;
                }
                /* Declined: preflight refused, nothing was published. */
                CHECK(!t->changed);
            }
            t->fine=0;
            unlock_set(&set);
        }
        guest_service_leave_shared(&gate,t->cpu);
        t->declines++;
    }
#if SNAP_PHASE_FAIR_GATE
token:
#endif
    token_acquire(t);
    t->changed=0;
    execute(t,op);
    CHECK(!t->dirty_count);
    log_op(op,0);
    tlb_check(t);
    guest_service_release(&gate,t->cpu);
    t->token_calls++;
}

/* ---- random operations ---------------------------------------------------- */
static unsigned ops_per_cpu=4000;
/* The frame a slot "should" map: aliases of one frame across roots. */
static uint64_t frame_for(unsigned r,unsigned k,unsigned j) {return data_pa[(r*7+k*13+j*3)%NDATA];}
static uint64_t pte_attrs(unsigned x)
{
    static const uint64_t a[]={RW,RO,RO|WW,RW&~AF,RO&~AF};
    return a[x%5];
}
static void random_op(struct tctx *t,struct op *op)
{
    memset(op,0,sizeof(*op));op->cpu=t->cpu;
    unsigned dice=rand_r(&t->seed)%100;
    unsigned r=rand_r(&t->seed)%NROOTS,k=rand_r(&t->seed)%NL3,j=rand_r(&t->seed)%NSLOT;
    op->root=root_pa[r];op->va=slot_va(k,j);
    if(dice<38) {
        op->kind=OP_MAP;
        uint64_t pa=(rand_r(&t->seed)%16) ? frame_for(r,k,j) : data_pa[rand_r(&t->seed)%NDATA];
        if(rand_r(&t->seed)%50==0)pa=spare_pa[rand_r(&t->seed)%NSPARE];
        op->arg=pa|pte_attrs(rand_r(&t->seed));op->options=rand_r(&t->seed)%2;
    } else if(dice<53) {
        op->kind=OP_UNMAP;op->count=1+rand_r(&t->seed)%4;
        if(j+op->count>NSLOT)op->count=NSLOT-j;
        op->options=rand_r(&t->seed)%2;
    } else if(dice<84) {
        op->kind=OP_UPDATE;
        static const uint64_t options[]={0x2,0x808,0x80a,0x802,0x8,0xa};
        op->options=options[rand_r(&t->seed)%6];
        uint64_t target=frame_for(r,k,j);op->arg=target;
        op->count=1+rand_r(&t->seed)%3;
        uint64_t req=pte_attrs(rand_r(&t->seed));
        for(unsigned n=0;n<op->count;n++) {
            unsigned rr=n ? rand_r(&t->seed)%NROOTS : r,kk=k,jj=j;
            /* Another alias of the same frame where one exists. */
            for(unsigned tries=0;n && tries<64;tries++) {
                kk=rand_r(&t->seed)%NL3;jj=rand_r(&t->seed)%NSLOT;
                if(frame_for(rr,kk,jj)==target)break;
            }
            op->rec[3*n]=root_pa[rr];op->rec[3*n+1]=slot_va(kk,jj);op->rec[3*n+2]=target|req;
        }
    } else if(dice<96) {
        op->kind=OP_SWITCH;
        op->root=rand_r(&t->seed)%4==0 ? KROOT : root_pa[rand_r(&t->seed)%NROOTS];
    } else if(dice<99) {
        op->kind=OP_RETYPE;op->arg=rand_r(&t->seed)%NSPARE;
    } else {
        op->kind=OP_INVALIDATE;
    }
}
static void *worker(void *arg)
{
    struct tctx *t=arg;self=t;chaos_seed=t->seed^0x5bd1e995u;
    struct op op;
    for(unsigned n=0;n<ops_per_cpu;n++) {
        random_op(t,&op);
        if(op.kind==OP_RETYPE) {
            /* Token path only, and only frames that are free. */
            token_acquire(t);
            unsigned i=(unsigned)op.arg;
            int busy=get(meta(spare_pa[i])+8,4) || get(meta(spare_pa[i])+12,4);
            if(!busy) {execute(t,&op);log_op(&op,0);}
            guest_service_release(&gate,t->cpu);
        } else if(op.kind==OP_INVALIDATE) {
            token_acquire(t);
            unsigned r=rand_r(&t->seed)%NROOTS;op.root=root_pa[r];
            int busy=0;for(unsigned c=0;c<CPUS;c++)busy|=roots.active[c]==op.root;
            if(!busy && cached(op.root)) {execute(t,&op);log_op(&op,0);}
            guest_service_release(&gate,t->cpu);
        } else run(t,&op);
        walk_some(t);
        __atomic_fetch_add(&progress,1,__ATOMIC_RELAXED);
    }
    return 0;
}
static void *watchdog(void *arg)
{
    (void)arg;uint64_t last=~UINT64_C(0);unsigned still=0;
    for(;;) {
        sleep(1);
        uint64_t now=__atomic_load_n(&progress,__ATOMIC_RELAXED);
        if(now==last) {if(++still>=20) {fprintf(stderr,"FAIL: no progress for 20 s (deadlock)\n");_exit(3);}}
        else still=0;
        last=now;
    }
    return 0;
}

/* ---- setup, invariants, replay -------------------------------------------- */
static void setup(void)
{
    ram=aligned_alloc(0x4000,SIZE);ram0=aligned_alloc(0x4000,SIZE);
    arena=aligned_alloc(4096,(size_t)APAGES*4096);arena0=aligned_alloc(4096,(size_t)APAGES*4096);
    log_max=(uint64_t)ops_per_cpu*CPUS+16;oplog=calloc(log_max,sizeof(*oplog));
    CHECK(ram && ram0 && arena && arena0 && oplog);
    memset(ram,0,SIZE);memset(arena,0,(size_t)APAGES*4096);
    for(uint64_t pa=BASE;pa<BASE+SIZE;pa+=0x4000)ram[meta(pa)-BASE+2]=11;
    uint64_t next=ALLOC_LOW;
    for(unsigned r=0;r<NROOTS;r++)root_pa[r]=next,next+=0x4000;
    for(unsigned r=0;r<NROOTS;r++)l2_pa[r]=next,next+=0x4000;
    for(unsigned r=0;r<NROOTS;r++)for(unsigned k=0;k<NL3;k++)l3_pa[r][k]=next,next+=0x4000;
    for(unsigned i=0;i<NDATA;i++)data_pa[i]=next,next+=0x4000;
    for(unsigned i=0;i<NSPARE;i++)spare_pa[i]=next,next+=0x4000,spare_type[i]=11;
    struct sptm_memory m=memory_for(0);
    for(unsigned r=0;r<NROOTS;r++) {
        CHECK(sptm_mac_retype(&m,root_pa[r],11,18,((uint64_t)(r+1)<<32)|(2UL<<16)|0)==SPTM_OK);
        CHECK(sptm_mac_retype(&m,l2_pa[r],11,20,2)==SPTM_OK);
        CHECK(sptm_mac_map_user_table(&m,root_pa[r],VBASE,1,l2_pa[r]|3)==SPTM_OK);
        for(unsigned k=0;k<NL3;k++) {
            CHECK(sptm_mac_retype(&m,l3_pa[r][k],11,20,3)==SPTM_OK);
            CHECK(sptm_mac_map_user_table(&m,root_pa[r],slot_va(k,0),2,l3_pa[r][k]|3)==SPTM_OK);
        }
    }
    for(unsigned c=0;c<CPUS;c++) {
        tc[c].cpu=c;tc[c].seed=chaos_seed_global*977+c*7919+1;
        pthread_mutex_init(&tlbs[c].lock,0);
        gate.lifecycle|=(uint64_t)EXECUTOR_RUNNING<<(c*3);
    }
    kshadow=arena_take(1000);
    /* Prefill: every CPU switches to a root (building every cache entry),
     * then maps half of the slots, so updates and unmaps find leaves. */
    for(unsigned c=0;c<CPUS;c++) {
        self=&tc[c];
        CHECK(do_switch(&tc[c],root_pa[c%NROOTS])==SPTM_OK);
    }
    for(unsigned r=CPUS;r<NROOTS;r++) {
        self=&tc[0];CHECK(do_switch(&tc[0],root_pa[r])==SPTM_OK);
    }
    self=&tc[0];CHECK(do_switch(&tc[0],root_pa[0])==SPTM_OK);
    for(unsigned r=0;r<NROOTS;r++)for(unsigned k=0;k<NL3;k++)for(unsigned j=0;j<NSLOT;j+=2) {
        struct op op={.kind=OP_MAP,.root=root_pa[r],.va=slot_va(k,j),.arg=frame_for(r,k,j)|((j&2) ? RO : RW),.options=1};
        execute(&tc[0],&op);CHECK(op.result==SPTM_OK);
    }
    self=0;
    for(unsigned c=0;c<CPUS;c++)tc[c].dirty_count=0;
    memcpy(ram0,ram,SIZE);memcpy(arena0,arena,(size_t)APAGES*4096);
    memcpy(arena_owner0,arena_owner,sizeof(arena_owner));memcpy(arena_free0,arena_free,sizeof(arena_free));
    arena_next0=arena_next;arena_nfree0=arena_nfree;memcpy(spare_type0,spare_type,sizeof(spare_type));
}
static int readonly_leaf(uint64_t pte)
{
    unsigned perm=(unsigned)(((pte>>4)&12)|((pte>>53)&3));
    return (perm&~4u)==11 && !(pte&WW);
}
/* F1/F2/F11 and the type invariant, from the guest tables alone. */
static void check_counts(void)
{
    static int64_t ro[4096],other[4096];
    memset(ro,0,sizeof(ro));memset(other,0,sizeof(other));
    for(unsigned r=0;r<NROOTS;r++)for(unsigned k=0;k<NL3;k++) {
        unsigned valid=0;
        for(unsigned i=0;i<2048;i++) {
            uint64_t pte=get(l3_pa[r][k]+8*i,8);
            if((pte&3)==3 || (pte&UINT64_C(0xe000000000000000)))valid++;
            if((pte&3)!=3)continue;
            unsigned f=(unsigned)(((pte&PA_MASK)-BASE)>>14);
            if(readonly_leaf(pte))ro[f]++;else other[f]++;
        }
        CHECK(get(meta(l3_pa[r][k])+8,2)==valid);
        CHECK(get(meta(l3_pa[r][k])+2,1)==20);
    }
    for(unsigned i=0;i<NDATA+NSPARE;i++) {
        uint64_t pa=i<NDATA ? data_pa[i] : spare_pa[i-NDATA];
        unsigned f=(unsigned)((pa-BASE)>>14);
        if((int64_t)get(meta(pa)+8,4)!=ro[f] || (int64_t)get(meta(pa)+12,4)!=other[f])
            fprintf(stderr,"frame %u: counts %llu/%llu, leaves %lld/%lld\n",i,
                    (unsigned long long)get(meta(pa)+8,4),(unsigned long long)get(meta(pa)+12,4),
                    (long long)ro[f],(long long)other[f]);
        CHECK((int64_t)get(meta(pa)+8,4)==ro[f]);
        CHECK((int64_t)get(meta(pa)+12,4)==other[f]);
        CHECK(get(meta(pa)+2,1)==(i<NDATA ? 11u : spare_type[i-NDATA]));
    }
    for(unsigned i=0;i<NSPARE;i++)CHECK(get(meta(spare_pa[i])+2,1)==spare_type[i]);
}
/* Every cached valid root's shadow equals its guest leaves. */
static void check_shadows(void)
{
    for(unsigned i=0;i<SPTM_ROOT_CACHE;i++) {
        struct sptm_root_cached *e=&roots.cache[i];
        if(!e->valid)continue;
        uint64_t leaves=0;
        for(unsigned k=0;k<NL3;k++)for(unsigned j=0;j<2048;j++) {
            uint64_t va=VBASE+(uint64_t)k*0x2000000+(uint64_t)j*0x4000;
            uint64_t pte=0;
            for(unsigned r=0;r<NROOTS;r++)if(root_pa[r]==e->root)pte=get(l3_pa[r][k]+8*j,8);
            leaves+=(pte&3)==3;
            for(uint64_t off=0;off<0x4000;off+=4096) {
                uint64_t desc;CHECK(!shadow_leaf(e->shadow,va+off,&desc));
                if((pte&3)!=3) {CHECK(!desc);continue;}
                CHECK(desc && (desc&PT_OA_MASK)==(pte&PA_MASK)+off);
                CHECK(!((desc^pte)&(PT_LEAF_ATTRS|PT_LEAF_UPPER)));
            }
        }
        CHECK(e->leaves==leaves);
    }
}
static int cmp_seq(const void *a,const void *b)
{
    const struct op *x=a,*y=b;return x->seq<y->seq ? -1 : x->seq>y->seq;
}
static uint8_t *ram_end;static uint64_t *arena_end;static struct sptm_root_state roots_end;
static void replay(uint64_t n)
{
    ram_end=malloc(SIZE);arena_end=malloc((size_t)APAGES*4096);CHECK(ram_end && arena_end);
    memcpy(ram_end,ram,SIZE);memcpy(arena_end,arena,(size_t)APAGES*4096);roots_end=roots;
    unsigned spare_end[NSPARE];memcpy(spare_end,spare_type,sizeof(spare_end));
    /* Back to the initial state, through the same setup (deterministic). */
    replaying=1;
    memset(&roots,0,sizeof(roots));memset(guest_ttbr0,0,sizeof(guest_ttbr0));
    memset(arena_owner,0,sizeof(arena_owner));arena_next=0;arena_nfree=0;
    memset(ram,0,SIZE);memset(arena,0,(size_t)APAGES*4096);
    for(uint64_t pa=BASE;pa<BASE+SIZE;pa+=0x4000)ram[meta(pa)-BASE+2]=11;
    for(unsigned i=0;i<NSPARE;i++)spare_type[i]=11;
    {
        struct sptm_memory m=memory_for(0);
        for(unsigned r=0;r<NROOTS;r++) {
            CHECK(sptm_mac_retype(&m,root_pa[r],11,18,((uint64_t)(r+1)<<32)|(2UL<<16)|0)==SPTM_OK);
            CHECK(sptm_mac_retype(&m,l2_pa[r],11,20,2)==SPTM_OK);
            CHECK(sptm_mac_map_user_table(&m,root_pa[r],VBASE,1,l2_pa[r]|3)==SPTM_OK);
            for(unsigned k=0;k<NL3;k++) {
                CHECK(sptm_mac_retype(&m,l3_pa[r][k],11,20,3)==SPTM_OK);
                CHECK(sptm_mac_map_user_table(&m,root_pa[r],slot_va(k,0),2,l3_pa[r][k]|3)==SPTM_OK);
            }
        }
        kshadow=arena_take(1000);
        for(unsigned c=0;c<CPUS;c++) {self=&tc[c];CHECK(do_switch(&tc[c],root_pa[c%NROOTS])==SPTM_OK);}
        for(unsigned r=CPUS;r<NROOTS;r++) {self=&tc[0];CHECK(do_switch(&tc[0],root_pa[r])==SPTM_OK);}
        self=&tc[0];CHECK(do_switch(&tc[0],root_pa[0])==SPTM_OK);
        for(unsigned r=0;r<NROOTS;r++)for(unsigned k=0;k<NL3;k++)for(unsigned j=0;j<NSLOT;j+=2) {
            struct op op={.kind=OP_MAP,.root=root_pa[r],.va=slot_va(k,j),.arg=frame_for(r,k,j)|((j&2) ? RO : RW),.options=1};
            execute(&tc[0],&op);CHECK(op.result==SPTM_OK);
        }
    }
    CHECK(!memcmp(ram,ram0,SIZE));CHECK(!memcmp(arena,arena0,(size_t)APAGES*4096));
    qsort(oplog,n,sizeof(*oplog),cmp_seq);
    unsigned long differ=0;
    for(uint64_t i=0;i<n;i++) {
        struct op op=oplog[i];
        CHECK(op.seq==i);
        struct tctx *t=&tc[op.cpu];self=t;t->fine=0;t->changed=0;t->dirty_count=0;
        execute(t,&op);
        if(op.result!=oplog[i].result || op.guest!=oplog[i].guest ||
           memcmp(op.out,oplog[i].out,sizeof(op.out))) {
            if(differ++<5)fprintf(stderr,"replay %llu kind %u cpu %u fine %d: result %d/%d guest %llu/%llu\n",
                (unsigned long long)i,op.kind,op.cpu,oplog[i].fine,oplog[i].result,op.result,
                (unsigned long long)oplog[i].guest,(unsigned long long)op.guest);
        }
    }
    self=0;
    CHECK(!differ);
    CHECK(!memcmp(ram,ram_end,SIZE));
    CHECK(!memcmp(arena,arena_end,(size_t)APAGES*4096));
    CHECK(!memcmp(&roots,&roots_end,sizeof(roots)));
    CHECK(!memcmp(spare_type,spare_end,sizeof(spare_end)));
    replaying=0;
}
/* ---- fairness: an adversarial re-acquire loop ----------------------------
 * Five CPUs release a lock and at once ask for it again; the sixth asks once
 * per round and counts the grants others received between its request and
 * its own grant. A FIFO lock bounds that count by the CPUs already queued
 * (five); an unfair one lets a re-acquirer pass the same waiter again and
 * again (the v26 one-second SERVICE_TIMEOUT across clusters). Checked for a
 * stripe and aux ticket lock and, with SNAP_FAIR_TOKEN, for the token;
 * for the gate, readers cannot enter once a token holder has the word, so a
 * holder's drain waits at most for the readers already inside. */
static uint64_t fair_grants;
static int fair_done;
static struct fine_ticket fair_lock;
static unsigned fair_kind;
static uint64_t reader_entries;
/* Request, then (once *before has been read) wait for the grant: the count
 * starts at the request, so only grants to earlier requests can be in it. */
static void fair_take(unsigned cpu,uint64_t *before)
{
    if(fair_kind==0) {
        uint32_t me=fine_ticket_draw(&fair_lock);
        if(before)*before=__atomic_load_n(&fair_grants,__ATOMIC_RELAXED);
        fine_ticket_wait(&fair_lock,me);
        return;
    }
#if SNAP_FAIR_TOKEN
    uint32_t ticket=guest_service_queue(&gate);
    if(before)*before=__atomic_load_n(&fair_grants,__ATOMIC_RELAXED);
    while(guest_service_try_turn(&gate,cpu,ticket)!=SERVICE_OK)FINE_RELAX();
#else
    if(before)*before=__atomic_load_n(&fair_grants,__ATOMIC_RELAXED);
    while(guest_service_try(&gate,cpu)!=SERVICE_OK)FINE_RELAX();
#endif
    while(!guest_service_drained(&gate))FINE_RELAX();
}
static void fair_give(unsigned cpu)
{
    if(fair_kind==0)fine_ticket_unlock(&fair_lock);
    else CHECK(guest_service_release(&gate,cpu)==SERVICE_OK);
}
/* A converted call's gate entry: with SNAP_PHASE_FAIR_GATE a BUSY arrival is
 * announced and waits for its writer's phase to end, which here is one short
 * hold: a wait of FAIR_POLLS polls is a stalled phase (G1) and fails at once. */
#define FAIR_POLLS (1u<<20)
static int fair_enter(unsigned cpu)
{
    enum guest_service_result r=guest_service_enter_shared(&gate,cpu);
#if SNAP_PHASE_FAIR_GATE
    for(unsigned polls=0;r==SERVICE_BUSY;polls++) {
        CHECK(polls<FAIR_POLLS);
        FINE_RELAX();r=guest_service_wait_shared(&gate,cpu,0);
    }
#endif
    return r==SERVICE_OK;
}
static void *fair_adversary(void *arg)
{
    unsigned cpu=(unsigned)(uintptr_t)arg;
    while(!__atomic_load_n(&fair_done,__ATOMIC_ACQUIRE)) {
        if(fair_kind==2 || fair_kind==4) {
            /* A reader re-entering as fast as it can. */
            if(fair_enter(cpu)) {
                __atomic_fetch_add(&reader_entries,1,__ATOMIC_RELAXED);
                guest_service_leave_shared(&gate,cpu);
            }
            continue;
        }
        fair_take(cpu,0);
        __atomic_fetch_add(&fair_grants,1,__ATOMIC_RELAXED);
        fair_give(cpu);
    }
    return 0;
}
/* Kind 3 (G5): a reader that has seen this many writer grants since its
 * arrival, or polled this often without entering, gives up (the monitor's
 * bound declines it to the token path); counted as starved. */
#define FAIR_STARVED 1000u
static unsigned fair_starved;
static unsigned fairness(unsigned kind,unsigned rounds)
{
    fair_kind=kind;fair_done=0;fair_grants=0;reader_entries=0;fair_starved=0;
    pthread_t th[CPUS];
    for(unsigned c=1;c<CPUS;c++)pthread_create(&th[c],0,fair_adversary,(void *)(uintptr_t)c);
    unsigned worst=0;
    for(unsigned n=0;n<rounds;n++) {
        if(kind==2) {
            /* The token holder's drain: reader entries after its grant. */
            struct tctx t={.cpu=0};
            token_acquire(&t);
            uint64_t before=__atomic_load_n(&reader_entries,__ATOMIC_RELAXED);
            for(unsigned spin=0;spin<64;spin++)FINE_RELAX();
            unsigned late=(unsigned)(__atomic_load_n(&reader_entries,__ATOMIC_RELAXED)-before);
            if(late>worst)worst=late;
            CHECK(guest_service_release(&gate,0)==SERVICE_OK);
            continue;
        }
        if(kind==3) {
            /* G5: five writers re-acquire the token at once; this reader counts
             * the writer grants between its arrival and its entry. */
            enum guest_service_result r=guest_service_enter_shared(&gate,0);
            uint64_t before=__atomic_load_n(&fair_grants,__ATOMIC_RELAXED);
            unsigned passed=0;
            for(unsigned polls=0;r==SERVICE_BUSY;polls++) {
                passed=(unsigned)(__atomic_load_n(&fair_grants,__ATOMIC_RELAXED)-before);
                if(passed>=FAIR_STARVED || polls>=FAIR_POLLS) {
#if SNAP_PHASE_FAIR_GATE
                    guest_service_leave_shared(&gate,0);   /* withdraw */
#endif
                    break;
                }
                FINE_RELAX();
#if SNAP_PHASE_FAIR_GATE
                r=guest_service_wait_shared(&gate,0,0);
#else
                r=guest_service_enter_shared(&gate,0);
#endif
            }
            if(r==SERVICE_OK) {
                passed=(unsigned)(__atomic_load_n(&fair_grants,__ATOMIC_RELAXED)-before);
                guest_service_leave_shared(&gate,0);
            } else {
                CHECK(r==SERVICE_BUSY);fair_starved++;
            }
#if SNAP_PHASE_FAIR_GATE
            CHECK(r==SERVICE_OK && passed<=1);   /* at once: a deadlocked phase would stall every round */
#endif
            if(passed>worst)worst=passed;
            continue;
        }
        if(kind==4) {
            /* G4: five readers re-enter at once; this token holder counts the
             * reader entries completed between its grant and its drain. */
#if SNAP_FAIR_TOKEN
            uint32_t ticket=guest_service_queue(&gate);
            while(guest_service_try_turn(&gate,0,ticket)!=SERVICE_OK)FINE_RELAX();
#else
            while(guest_service_try(&gate,0)!=SERVICE_OK)FINE_RELAX();
#endif
            uint64_t before=__atomic_load_n(&reader_entries,__ATOMIC_RELAXED);
            while(!guest_service_drained(&gate))FINE_RELAX();
            unsigned during=(unsigned)(__atomic_load_n(&reader_entries,__ATOMIC_RELAXED)-before);
            if(during>worst)worst=during;
            CHECK(guest_service_release(&gate,0)==SERVICE_OK);
            continue;
        }
        uint64_t before;
        fair_take(0,&before);
        unsigned passed=(unsigned)(__atomic_load_n(&fair_grants,__ATOMIC_RELAXED)-before);
        fair_give(0);
        if(passed>worst)worst=passed;
    }
    __atomic_store_n(&fair_done,1,__ATOMIC_RELEASE);
    for(unsigned c=1;c<CPUS;c++)pthread_join(th[c],0);
    return worst;
}
static int fair_main(unsigned rounds)
{
    for(unsigned c=0;c<CPUS;c++)gate.lifecycle|=(uint64_t)EXECUTOR_RUNNING<<(c*3);
    unsigned ticket=fairness(0,rounds);
    fprintf(stderr,"ticket lock: at most %u grants passed a waiter (bound %u)\n",ticket,CPUS-1);
    CHECK(ticket<=CPUS-1);
    unsigned token=fairness(1,rounds);
    fprintf(stderr,"token%s: at most %u grants passed a waiter\n",SNAP_FAIR_TOKEN ? " (fair)" : "",token);
#if SNAP_FAIR_TOKEN
    CHECK(token<=CPUS-1);
#endif
    unsigned late=fairness(2,rounds);
    fprintf(stderr,"gate: at most %u reader entries completed after a token grant (bound %u)\n",late,CPUS-1);
    CHECK(late<=CPUS-1);
    /* G5 and G4 (SNAP_PHASE_FAIR_GATE bounds both; the old gate is reported). */
    unsigned passed=fairness(3,rounds/20 ? rounds/20 : 1);
    fprintf(stderr,"gate%s: at most %u writer grants passed a reader between its arrival and its entry"
            " (bound %s; %u of %u readers gave up)\n",SNAP_PHASE_FAIR_GATE ? " (phase-fair)" : "",passed,
            SNAP_PHASE_FAIR_GATE ? "1" : "none",fair_starved,rounds/20 ? rounds/20 : 1);
#if SNAP_PHASE_FAIR_GATE
    CHECK(passed<=1 && !fair_starved);
#endif
    unsigned during=fairness(4,rounds);
    fprintf(stderr,"gate: at most %u reader entries completed during a token holder's drain (bound %u)\n",
            during,CPUS-1);
    CHECK(during<=CPUS-1);
    printf("fine-locks fairness: %u checks passed\n",checks);
    return 0;
}

/* ---- mix: installed-fresh-20261020-v5's load on the real gate -------------
 * A timing model, not a proof. Six threads alternate guest time (exponential,
 * mean MIX_THINK_US) with monitor calls in v5's per-CPU mix (summary.json:
 * 33.44 M locked traps and 55.19 M converted calls in 1,794.8 s on six CPUs).
 * A token call queues (SNAP_FAIR_TOKEN), takes the token, drains the gate as
 * runtime_enter does and holds the token for a time drawn from the token's
 * hold mixture (token_sub classes and the remainder of lock_hold_cpu_seconds,
 * exponential within a class). A converted call takes the gate shared as
 * probes/xnuboot.c's SNAP_GATE_WAIT loop does (a yield and a clock read per
 * poll, the 1/200 s bound, then a token call holding the token's MAP_PAGE
 * mean) and holds it for a time drawn from the converted calls' mixture.
 * Reported for whichever gate this binary was built with: reader (converted)
 * and writer (token) waits, the drain, holds, busy fraction, bound declines
 * and the fairness counts. Needs SNAP_FAIR_TOKEN (the token's queue). */
#if SNAP_FAIR_TOKEN
#include <math.h>
#include <mach/mach_time.h>
struct mix_class {double entries,hold_s;};
static const struct mix_class mix_writer[]={
    {923675,122.90917755208334},{2561058,71.0894146875},{2941963,32.144306354166666},
    {3936317,38.695234791666664},{1626569,19.1203971875},{728833,41.369475989583336},
    {995651,41.19943255208333},{826223,33.729588802083335},{864803,24.925174427083334},
    {1375973,1.9205675520833334},{524102,12.9206834375},{327643,0.145959375},
    /* the rest of the 33,435,749 locked traps and their 670.21 s of hold */
    {33435749.0-17632810.0,670.2132379687498-440.1680390885417}};
static const struct mix_class mix_reader[]={
    {45839396,63.09708927083334},{5319511,124.76948026041667},{1105600,1.5559550520833334},
    {2826839,3.17701734375},{97872,5.579025572916667}};
#define MIX_W (sizeof(mix_writer)/sizeof(mix_writer[0]))
#define MIX_R (sizeof(mix_reader)/sizeof(mix_reader[0]))
#define MIX_READER_SHARE (55189248.0/(55189248.0+33435749.0))
#define MIX_THINK_US 96.1
#define MIX_BOUND_US 5000.0
#define MIX_DECLINED_HOLD_US 27.76   /* token MAP_PAGE: 71.09 s / 2.561 M */
#define MIX_MAX 2000000u
static double mix_tick_us;
static int mix_fixed;            /* holds at their class mean instead of exponential */
static uint64_t mix_grants;
static int mix_go,mix_stop;
struct mix_cpu {
    unsigned cpu;uint64_t rng;
    double wcum[MIX_W],wmean[MIX_W],rcum[MIX_R],rmean[MIX_R];
    uint32_t *rw,*ww,*wd;unsigned nr,nw;
    uint64_t r_hold,w_hold,r_waited,timeouts,ahead,passed_hist[4],passed_max,drained,think;
};
static struct mix_cpu mix[CPUS];
static inline uint64_t mix_now(void) {return mach_absolute_time();}
static inline void mix_relax(void) {__asm__ volatile("yield" ::: "memory");}
static double mix_uniform(struct mix_cpu *m)
{
    m->rng^=m->rng<<13;m->rng^=m->rng>>7;m->rng^=m->rng<<17;
    return ((double)(m->rng>>11)+0.5)/9007199254740992.0;
}
static uint64_t mix_ticks(double us) {return (uint64_t)(us/mix_tick_us+0.5);}
static uint64_t mix_exp(struct mix_cpu *m,double mean_us) {return mix_ticks(-mean_us*log(mix_uniform(m)));}
static uint64_t mix_pick(struct mix_cpu *m,const double *cum,const double *mean,unsigned n)
{
    double u=mix_uniform(m);unsigned k=0;
    while(k+1<n && u>cum[k])k++;
    return mix_fixed ? mix_ticks(mean[k]) : mix_exp(m,mean[k]);
}
static void mix_spin(uint64_t ticks) {uint64_t end=mix_now()+ticks;while(mix_now()<end){}}
static void mix_token(struct mix_cpu *m,uint64_t hold)
{
    uint64_t t0=mix_now();
    uint32_t ticket=guest_service_queue(&gate);
    enum guest_service_result r;
    while((r=guest_service_try_turn(&gate,m->cpu,ticket))!=SERVICE_OK) {CHECK(r==SERVICE_BUSY);mix_relax();}
    uint64_t t1=mix_now();
    if(!guest_service_drained(&gate)) {
        m->drained++;
        while(!guest_service_drained(&gate))mix_relax();
    }
    uint64_t t2=mix_now();
    __atomic_fetch_add(&mix_grants,1,__ATOMIC_RELAXED);
    mix_spin(hold);
    m->w_hold+=hold;
    CHECK(guest_service_release(&gate,m->cpu)==SERVICE_OK);
    if(m->nw<MIX_MAX) {m->ww[m->nw]=(uint32_t)(t2-t0);m->wd[m->nw]=(uint32_t)(t2-t1);m->nw++;}
}
static void mix_converted(struct mix_cpu *m,uint64_t hold,uint64_t bound)
{
    uint64_t t0=mix_now(),before=0;
    enum guest_service_result r;
    unsigned ahead=0;
    for(int waited=0;;waited=1) {
#if SNAP_PHASE_FAIR_GATE
        r=waited ? guest_service_wait_shared(&gate,m->cpu,&ahead) : guest_service_enter_shared(&gate,m->cpu);
#else
        r=guest_service_enter_shared(&gate,m->cpu);
#endif
        if(!waited)before=__atomic_load_n(&mix_grants,__ATOMIC_RELAXED);
        uint64_t now=mix_now();
        if(r!=SERVICE_BUSY) {
            CHECK(r==SERVICE_OK);
            if(waited) {m->r_waited++;m->ahead+=ahead;}
            break;
        }
        if(now-t0>=bound) {
#if SNAP_PHASE_FAIR_GATE
            guest_service_leave_shared(&gate,m->cpu);
#endif
            m->timeouts++;
            if(m->nr<MIX_MAX)m->rw[m->nr++]=(uint32_t)(now-t0);
            mix_token(m,mix_ticks(MIX_DECLINED_HOLD_US));
            return;
        }
        mix_relax();
    }
    uint64_t t1=mix_now(),passed=__atomic_load_n(&mix_grants,__ATOMIC_RELAXED)-before;
    m->passed_hist[passed<3 ? passed : 3]++;
    if(passed>m->passed_max)m->passed_max=passed;
    mix_spin(hold);
    m->r_hold+=hold;
    guest_service_leave_shared(&gate,m->cpu);
    if(m->nr<MIX_MAX)m->rw[m->nr++]=(uint32_t)(t1-t0);
}
static void *mix_worker(void *arg)
{
    struct mix_cpu *m=arg;
    pthread_set_qos_class_self_np(QOS_CLASS_USER_INTERACTIVE,0);
    uint64_t bound=mix_ticks(MIX_BOUND_US);
    while(!__atomic_load_n(&mix_go,__ATOMIC_ACQUIRE)){}
    while(!__atomic_load_n(&mix_stop,__ATOMIC_ACQUIRE)) {
        uint64_t think=mix_exp(m,MIX_THINK_US);
        m->think+=think;mix_spin(think);
        if(mix_uniform(m)<MIX_READER_SHARE)mix_converted(m,mix_pick(m,m->rcum,m->rmean,MIX_R),bound);
        else mix_token(m,mix_pick(m,m->wcum,m->wmean,MIX_W));
    }
    return 0;
}
static int cmp_u32(const void *a,const void *b)
{
    uint32_t x=*(const uint32_t *)a,y=*(const uint32_t *)b;return x<y ? -1 : x>y;
}
static void mix_stats(const char *name,uint32_t *v,uint64_t n,int last)
{
    double sum=0;for(uint64_t i=0;i<n;i++)sum+=v[i];
    qsort(v,n,sizeof(*v),cmp_u32);
#define Q(f) (n ? v[(uint64_t)((double)(n-1)*(f))]*mix_tick_us : 0.0)
    printf("\"%s\":{\"n\":%llu,\"mean_us\":%.3f,\"p50_us\":%.3f,\"p90_us\":%.3f,\"p99_us\":%.3f,\"p999_us\":%.3f,"
           "\"max_us\":%.3f}%s",name,(unsigned long long)n,n ? sum/(double)n*mix_tick_us : 0.0,Q(0.5),Q(0.9),
           Q(0.99),Q(0.999),n ? v[n-1]*mix_tick_us : 0.0,last ? "" : ",");
#undef Q
}
/* shape: "exp" (default) or "fixed"; scale "K=F": token class K's hold times F (a what-if). */
static int mix_main(double seconds,unsigned seed,const char *shape,const char *scale)
{
    mix_fixed=shape && !strcmp(shape,"fixed");
    unsigned scale_class=~0u;double scale_by=1.0;
    if(scale && *scale) {
        char *end;scale_class=(unsigned)strtoul(scale,&end,0);
        CHECK(*end=='=' && scale_class<MIX_W);scale_by=strtod(end+1,0);
    }
    mach_timebase_info_data_t tb;mach_timebase_info(&tb);
    mix_tick_us=(double)tb.numer/(double)tb.denom/1000.0;
    for(unsigned c=0;c<CPUS;c++)gate.lifecycle|=(uint64_t)EXECUTOR_RUNNING<<(c*3);
    double wsum=0,rsum=0;
    for(unsigned k=0;k<MIX_W;k++)wsum+=mix_writer[k].entries;
    for(unsigned k=0;k<MIX_R;k++)rsum+=mix_reader[k].entries;
    pthread_t th[CPUS];
    for(unsigned c=0;c<CPUS;c++) {
        struct mix_cpu *m=&mix[c];
        m->cpu=c;m->rng=0x9e3779b97f4a7c15ull*(seed*8+c+1);
        double acc=0;
        for(unsigned k=0;k<MIX_W;k++) {acc+=mix_writer[k].entries/wsum;m->wcum[k]=acc;
            m->wmean[k]=mix_writer[k].hold_s/mix_writer[k].entries*1e6*(k==scale_class ? scale_by : 1.0);}
        acc=0;
        for(unsigned k=0;k<MIX_R;k++) {acc+=mix_reader[k].entries/rsum;m->rcum[k]=acc;
            m->rmean[k]=mix_reader[k].hold_s/mix_reader[k].entries*1e6;}
        m->rw=calloc(MIX_MAX,4);m->ww=calloc(MIX_MAX,4);m->wd=calloc(MIX_MAX,4);
        CHECK(m->rw && m->ww && m->wd);
        pthread_create(&th[c],0,mix_worker,m);
    }
    uint64_t start=mix_now();
    __atomic_store_n(&mix_go,1,__ATOMIC_RELEASE);
    usleep((useconds_t)(seconds*1e6));
    __atomic_store_n(&mix_stop,1,__ATOMIC_RELEASE);
    for(unsigned c=0;c<CPUS;c++)pthread_join(th[c],0);
    double wall=(double)(mix_now()-start)*mix_tick_us*1e-6;
    CHECK(!gate.owner && !guest_service_readers(&gate));
    uint64_t nr=0,nw=0,r_hold=0,w_hold=0,r_waited=0,timeouts=0,ahead=0,drained=0,passed_max=0,hist[4]={0},think=0;
    for(unsigned c=0;c<CPUS;c++) {
        struct mix_cpu *m=&mix[c];
        nr+=m->nr;nw+=m->nw;r_hold+=m->r_hold;w_hold+=m->w_hold;r_waited+=m->r_waited;timeouts+=m->timeouts;
        ahead+=m->ahead;drained+=m->drained;think+=m->think;
        if(m->passed_max>passed_max)passed_max=m->passed_max;
        for(unsigned k=0;k<4;k++)hist[k]+=m->passed_hist[k];
    }
    uint32_t *rw=calloc(nr ? nr : 1,4),*ww=calloc(nw ? nw : 1,4),*wd=calloc(nw ? nw : 1,4);
    CHECK(rw && ww && wd);
    for(unsigned c=0,i=0,j=0;c<CPUS;c++) {
        memcpy(rw+i,mix[c].rw,mix[c].nr*4ull);i+=mix[c].nr;
        memcpy(ww+j,mix[c].ww,mix[c].nw*4ull);memcpy(wd+j,mix[c].wd,mix[c].nw*4ull);j+=mix[c].nw;
    }
    printf("mix {\"gate\":\"%s\",\"seed\":%u,\"shape\":\"%s\",\"scale\":\"%s\",\"wall_s\":%.3f,\"cpus\":%u,"
           "\"think_us\":%.1f,",SNAP_PHASE_FAIR_GATE ? "phase-fair" : "base",seed,mix_fixed ? "fixed" : "exp",
           scale ? scale : "",wall,CPUS,MIX_THINK_US);
    printf("\"guest_share\":%.4f,\"token_busy\":%.4f,\"reader_hold_us\":%.3f,\"writer_hold_us\":%.3f,",
           think*mix_tick_us*1e-6/wall/CPUS,w_hold*mix_tick_us*1e-6/wall,nr ? r_hold*mix_tick_us/(double)(nr-timeouts) : 0.0,
           nw ? w_hold*mix_tick_us/(double)nw : 0.0);
    printf("\"readers_per_cpu_s\":%.1f,\"writers_per_cpu_s\":%.1f,\"reader_waited\":%.4f,\"timeouts\":%llu,"
           "\"ahead\":%llu,\"passed_max\":%llu,\"passed_hist\":[%llu,%llu,%llu,%llu],\"drained\":%.4f,",
           nr/wall/CPUS,nw/wall/CPUS,nr ? (double)r_waited/(double)nr : 0.0,(unsigned long long)timeouts,
           (unsigned long long)ahead,(unsigned long long)passed_max,(unsigned long long)hist[0],
           (unsigned long long)hist[1],(unsigned long long)hist[2],(unsigned long long)hist[3],
           nw ? (double)drained/(double)nw : 0.0);
    mix_stats("reader_wait",rw,nr,0);mix_stats("writer_wait",ww,nw,0);mix_stats("writer_drain",wd,nw,1);
    printf("}\n");
    return 0;
}
#endif
int main(int argc,char **argv)
{
    if(argc>1 && !strcmp(argv[1],"fair"))return fair_main(argc>2 ? (unsigned)strtoul(argv[2],0,0) : 20000);
#if SNAP_FAIR_TOKEN
    if(argc>1 && !strcmp(argv[1],"mix"))return mix_main(argc>2 ? strtod(argv[2],0) : 10.0,
                                                        argc>3 ? (unsigned)strtoul(argv[3],0,0) : 1,
                                                        argc>4 ? argv[4] : 0,argc>5 ? argv[5] : 0);
#endif
    if(argc>1)ops_per_cpu=(unsigned)strtoul(argv[1],0,0);
    chaos_seed_global=argc>2 ? (unsigned)strtoul(argv[2],0,0) : (unsigned)time(0);
    fprintf(stderr,"seed %u, %u calls per CPU, %u stripes, phase %s\n",chaos_seed_global,ops_per_cpu,
            FINE_STRIPES,SNAP_FINE_SWITCH ? "1b" : "1");
    setup();
    check_counts();check_shadows();
    pthread_t th[CPUS],dog;
    pthread_create(&dog,0,watchdog,0);pthread_detach(dog);
    for(unsigned c=0;c<CPUS;c++)pthread_create(&th[c],0,worker,&tc[c]);
    for(unsigned c=0;c<CPUS;c++)pthread_join(th[c],0);
    uint64_t n=seq_next,fine=0,token=0,declined=0;
    for(unsigned c=0;c<CPUS;c++)fine+=tc[c].fine_calls,token+=tc[c].token_calls,declined+=tc[c].declines;
    CHECK(!gate.owner && !guest_service_readers(&gate));
    for(unsigned s=0;s<FINE_STRIPES;s++)CHECK(!fine_ticket_held(&stripes[s]));
    check_counts();check_shadows();
    replay(n);
    check_counts();check_shadows();
    CHECK(fine>n/4);
    unsigned long kinds[6][3]={{0}};
    for(uint64_t i=0;i<n;i++) {
        unsigned k=oplog[i].kind;kinds[k][oplog[i].result==SPTM_OK ? 0 : 1]++;kinds[k][2]+=oplog[i].fine;
    }
    static const char *names[]={"map","unmap","update","switch","retype","invalidate"};
    for(unsigned k=0;k<6;k++)fprintf(stderr,"  %-10s ok %lu refused %lu converted %lu\n",names[k],
                                    kinds[k][0],kinds[k][1],kinds[k][2]);
    fprintf(stderr,"  changed pages %llu\n",(unsigned long long)changed_pages);
#if SNAP_PHASE_FAIR_GATE
    uint64_t withdrawn=0;
    for(unsigned c=0;c<CPUS;c++)withdrawn+=tc[c].withdrawn;
    fprintf(stderr,"  phase-fair gate: %llu announced arrivals withdrawn at the bound\n",(unsigned long long)withdrawn);
#endif
    fprintf(stderr,"%llu calls logged: %llu converted, %llu token (%llu declined first); replay equal\n",
            (unsigned long long)n,(unsigned long long)fine,(unsigned long long)token,(unsigned long long)declined);
    printf("fine-locks: %u checks passed\n",checks);
    return 0;
}

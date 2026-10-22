/* SPDX-License-Identifier: MIT */
/* SNAP_SPTM_FINE / _RETYPE / _KERNEL concurrency harness
 * (agents/sptm-locks/FAILURE-MODES.md; built on tools/test-fine-locks.c).
 *
 * Six pthreads play six vCPUs. Each issues a random stream of SPTM calls
 * through the real compat engines (compat/sptm-user.c, sptm-refs.c, sptm.c,
 * sptm-unmap.c, sptm-root.c, compat/sptm-fine.h, shadow/shadow.c) under the
 * real gate (compat/service-lock.c), root stripes and FIFO ticket locks
 * (compat/fine-lock.h) and the real frame locks (compat/sptm-frame-lock.h).
 * Converted, as probes/xnuboot.c converts them:
 *   user MAP_PAGE, UNMAP_REGION, UPDATE_DISJOINT (fine locks, unchanged),
 *   user UNMAP_DISJOINT and UPDATE_REGION (SNAP_SPTM_FINE),
 *   RETYPE 11->20, 20->11, 11->11 of spare frames that MAP_PAGE and the kernel
 *   also map (SNAP_SPTM_FINE_RETYPE: exclusive frame lock; every reference
 *   first touch takes its frame shared),
 *   kernel-root MAP_PAGE and UNMAP_REGION (SNAP_SPTM_FINE_KERNEL: KL, the
 *   copy-source check, by-VA invalidation, no refresh),
 * interleaved with token-path calls: every declined call, SWITCH_ROOT misses,
 * cache invalidations, token-path RETYPEs, and kernel calls the converted
 * path refuses (a missing shadow path, which the token path allocates; a
 * kernel-view copy source, which the token path writes and then refreshes
 * every CPU's copy, then TLBI ALLE1IS). Each simulated CPU walks its active
 * user root and its kernel view (copies included) between calls and caches
 * what it finds in a TLB model.
 *
 * Checked (S numbers of the failure modes):
 *  S1/S2 every frame's +8/+12 counts equal an independent recount of the
 *      leaves in every user root and in the kernel tree; every table's +8 its
 *      valid entries;
 *  S3/S4 types: the spare frames' types equal the history; a frame retyped
 *      to PAGE_TABLE is mapped by no leaf and cached by no TLB;
 *  S5/S6 no CPU's TLB holds a translation of a changed page that differs
 *      from its current view after the call (user and kernel);
 *  S7 every shadow store is published before the TLBI that ends its call;
 *  S8 the kernel-view copies equal their sources at the end (a converted
 *      kernel call never writes a copy source);
 *  S12 linearizability: every call logs its result and outputs with a
 *      sequence number taken inside its critical section; the log replayed
 *      single-threaded through the token path from the initial state gives
 *      the same results, outputs, guest RAM, arena (shadows and copies),
 *      cache and types;
 *  S13 a 20 s no-progress watchdog;
 *  S25 every frame-lock word is zero, KL and every stripe free, at the end.
 * ThreadSanitizer reports any unsynchronized access. The pre-lock type reads
 * of compat/sptm-user.c's metadata()/data_type() race with a converted RETYPE
 * by design (every one is re-validated under the frame lock in sptm-refs.c
 * delta()); tools/test-sptm-fine.py builds sptm-user.c with a TSan ignore list
 * naming exactly those two functions.
 *
 * Mutants (-D): MUTANT_NO_FRAME_SHARE, MUTANT_NO_EXCLUSIVE, MUTANT_EARLY_RELEASE,
 * MUTANT_NO_KL, MUTANT_NO_COPIED_CHECK, MUTANT_KERNEL_NO_TLBI, MUTANT_KERNEL_GLOBAL_REFS,
 * MUTANT_NO_STRIPES, MUTANT_NO_PUBLISH: each must fail.
 *
 * Arguments: [ops-per-cpu] [seed]. */
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
#include "sptm-fine.h"
#include "sptm-frame-lock.h"
#include "shadow.h"
#include "mmu.h"
#if !SNAP_FINE_LOCKS || !SNAP_SPTM_FINE || !SNAP_SPTM_FINE_RETYPE || !SNAP_SPTM_FINE_KERNEL
#error "build with -DSNAP_FINE_LOCKS=1 -DSNAP_FINE_HW=1 -DSNAP_SPTM_FINE=1 -DSNAP_SPTM_FINE_RETYPE=1 -DSNAP_SPTM_FINE_KERNEL=1"
#endif
#ifndef SNAP_FAIR_TOKEN
#define SNAP_FAIR_TOKEN 0
#endif
#ifndef PF_POLLS
#define PF_POLLS 4096u
#endif

#define CPUS GUEST_CPU_COUNT
#define BASE UINT64_C(0x90000000)
#define SIZE UINT64_C(0x2000000)
#define FM (BASE+0x4000)
#define PERCPU (BASE+0x10000)
#define ALLOC_LOW (BASE+0x40000)
#define NROOTS 8u
#define NL3 4u
#define NSLOT 40u
#define NDATA 160u
#define NUSPARE 4u           /* spares user and kernel maps take: maps and retypes collide on them */
#define NKSPARE 2u           /* spares only kernel maps take: their counts reach zero right after a kernel unmap */
#define NSPARE (NUSPARE+NKSPARE)
#define RACE NSPARE           /* one more spare, only the aimed race phase uses it */
#define NSPARES (NSPARE+1u)
#define NKL3 2u
#define VBASE UINT64_C(0x100000000)
#define KVBASE UINT64_C(0xffff800200000000)
#define APERTURE_VA UINT64_C(0xfffffe0100000000)
#define ABASE UINT64_C(0x400000000)
#define APAGES 4096u
#define RW UINT64_C(0x0060000000000f43)
#define RO UINT64_C(0x0060000000000fc3)
#define KRW UINT64_C(0x0060000000000703)
#define KRO UINT64_C(0x0060000000000783)
#define WW (UINT64_C(1)<<59)
#define AF UINT64_C(0x400)
#define PA_MASK UINT64_C(0x0000ffffffffc000)
#define KOWNER 1000u
#define COPY_OWNER 1001u
#define NKSPAN 16u          /* 2 MiB shadow spans per 32 MiB guest L3 table */

static unsigned checks;
#define CHECK(x) do { __atomic_fetch_add(&checks,1,__ATOMIC_RELAXED); if(!(x)) { \
    fprintf(stderr,"FAIL %d: %s\n",__LINE__,#x); fflush(stderr); _exit(1); } } while(0)

/* ---- guest RAM, frame map, shadow arena ---------------------------------- */
static uint8_t *ram, *ram0;
static uint64_t *arena, *arena0;
static uint64_t root_pa[NROOTS], l2_pa[NROOTS], l3_pa[NROOTS][NL3], data_pa[NDATA], spare_pa[NSPARES];
static uint64_t kroot_pa, kl2_pa, kl3_pa[NKL3];
static unsigned spare_type[NSPARES], spare_type0[NSPARES];

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
static void put_ram(uint64_t pa,uint64_t v) {for(unsigned i=0;i<8;i++)ram[pa-BASE+i]=(uint8_t)(v>>(8*i));}
static int guest_read(void *ctx,uint64_t pa,uint64_t *out)
{
    (void)ctx;if(pa<BASE || pa+8>BASE+SIZE || (pa&7))return -1;
    *out=*(volatile uint64_t *)(void *)(ram+(pa-BASE));return 0;
}
static int guest_write(void *ctx,uint64_t pa,uint64_t value)
{
    (void)ctx;if(pa<BASE || pa+8>BASE+SIZE || (pa&7))return -1;
    *(volatile uint64_t *)(void *)(ram+(pa-BASE))=value;return 0;
}

/* Arena: token-path allocation only. Every word atomic (walkers read it). */
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
    unsigned cpu, fine, seed, in_kunmap;
    int alloc_refused;
    unsigned dirty_count;
    uint64_t dirty[64];
    struct sptm_ref_batch refs;
    struct sptm_ref_fine ref_fine;
    struct sptm_frame_held frames;
    struct sptm_pv_audit audit;
    uint64_t changed_va[96];uint64_t changed_root[96];unsigned changed;
    uint64_t fine_calls,declines,token_calls,withdrawn;
    uint64_t kinds_fine[10];
};
static struct tctx tc[CPUS];
static struct sptm_ref_batch global_refs;
static struct sptm_pv_audit global_audit;
static struct guest_service_lock gate;
static struct fine_ticket stripes[FINE_STRIPES];
static struct fine_ticket klock;                /* KL */
static struct sptm_frame_locks frame_locks;

static struct sptm_root_state roots;
static uint64_t guest_ttbr0[CPUS], hw_shadow[CPUS], hw_root[CPUS];
static uint64_t evictions;
static uint64_t kshadow;                        /* the kernel's low shadow (switch install) */
static uint64_t kshadow1;                       /* the canonical kernel 4K shadow (TTBR1) */
/* Kernel-view copies: a copied canonical level-3 table and one copy per CPU. */
#define NKCOPY (NKL3*NKSPAN/4u)
struct kcopy {uint64_t source,copy[CPUS];};
static struct kcopy kcopies[NKCOPY];
static unsigned nkcopies;
static unsigned kowner_ctx=KOWNER;

static uint64_t tlb_hash(uint64_t root,uint64_t va) {return ((root>>14)*31+(va>>12))%TLB_SIZE;}
static void tlb_fill(unsigned cpu,uint64_t root,uint64_t va,uint64_t desc)
{
    struct tlb *t=&tlbs[cpu];
    unsigned h=(unsigned)tlb_hash(root,va);
    for(unsigned i=0;i<8;i++) {
        struct tlb_entry *e=&t->e[(h+i)%TLB_SIZE];
        if(!e->root || (e->root==root && e->va==va)) {*e=(struct tlb_entry){root,va,desc};return;}
    }
    t->e[h]=(struct tlb_entry){root,va,desc};
}
/* vaae1is in every VMID: every CPU, every root, the range (F9/S6). */
static void tlbi_range(uint64_t va,uint64_t size)
{
    CHECK(!self || !self->dirty_count);            /* S7: published before the TLBI */
    for(unsigned c=0;c<CPUS;c++) {
        pthread_mutex_lock(&tlbs[c].lock);
        for(unsigned i=0;i<TLB_SIZE;i++) {
            struct tlb_entry *e=&tlbs[c].e[i];
            if(e->root && e->va>=va && e->va-va<size)e->root=0;
        }
        pthread_mutex_unlock(&tlbs[c].lock);
    }
}
static void tlbi_all(void)
{
    CHECK(!self || !self->dirty_count);
    for(unsigned c=0;c<CPUS;c++) {
        pthread_mutex_lock(&tlbs[c].lock);
        for(unsigned i=0;i<TLB_SIZE;i++)tlbs[c].e[i].root=0;
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
static const struct kcopy *copied_of(uint64_t table)
{
    for(unsigned n=0;n<nkcopies;n++)if(kcopies[n].source==table)return &kcopies[n];
    return 0;
}
/* CPU cpu's kernel view of va: the canonical tree, a copied level-3 table
 * read through this CPU's copy. */
static uint64_t kview_leaf(unsigned cpu,uint64_t va)
{
    uint64_t off=va&((UINT64_C(1)<<47)-1),t=kshadow1,d=0;
    for(unsigned level=0;level<3;level++) {
        d=aload(t+8UL*mmu_index(12,level,off));
        if(!(d&PT_VALID) || !(d&PT_TABLE))return 0;
        t=d&PT_OA_MASK;
    }
    const struct kcopy *k=copied_of(t);
    d=aload((k ? k->copy[cpu] : t)+8UL*mmu_index(12,3,off));
    return (d&3)==3 ? d : 0;
}
static uint64_t slot_va(unsigned k,unsigned j) {return VBASE+(uint64_t)k*0x2000000+(uint64_t)j*51*0x4000;}
static uint64_t kslot_va(unsigned k,unsigned j) {return KVBASE+(uint64_t)k*0x2000000+(uint64_t)j*51*0x4000;}
static void walk_some(struct tctx *t)
{
    if(replaying)return;
    for(unsigned n=0;n<4 && hw_shadow[t->cpu];n++) {
        uint64_t va=slot_va(rand_r(&t->seed)%NL3,rand_r(&t->seed)%NSLOT)+(rand_r(&t->seed)%4)*4096;
        pthread_mutex_lock(&tlbs[t->cpu].lock);
        uint64_t desc;
        if(!shadow_leaf(hw_shadow[t->cpu],va,&desc) && desc && (desc&AF))
            tlb_fill(t->cpu,hw_root[t->cpu],va,desc);
        pthread_mutex_unlock(&tlbs[t->cpu].lock);
    }
    for(unsigned n=0;n<4;n++) {
        uint64_t va=kslot_va(rand_r(&t->seed)%NKL3,rand_r(&t->seed)%NSLOT)+(rand_r(&t->seed)%4)*4096;
        pthread_mutex_lock(&tlbs[t->cpu].lock);
        uint64_t desc=kview_leaf(t->cpu,va);
        if(desc && (desc&AF))tlb_fill(t->cpu,kroot_pa,va,desc);
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
        if(self && self->changed<96) {self->changed_root[self->changed]=root;self->changed_va[self->changed++]=va+off;}
}
static void tlb_range_commit(uint64_t va,uint64_t size) {tlbi_range(va,size);}
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
    if(!(old&AF))return 1;                      /* update_fast_uncached */
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
    b->ttbr0=load_ttbr(t->cpu);b->ttbr1=kroot_pa;
    b->aperture=(struct sptm_aperture){BASE,APERTURE_VA,SIZE};
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

/* ---- the kernel side (compat/sptm-fine.h and the token path's original) -- */
static int kernel_copied(void *ctx,uint64_t table)
{
    (void)ctx;
#ifdef MUTANT_NO_COPIED_CHECK
    (void)table;return 0;
#else
    return copied_of(table)!=0;
#endif
}
static void kernel_tlbi(void *ctx,uint64_t va,uint64_t size)
{
    (void)ctx;
#ifdef MUTANT_EARLY_RELEASE
    /* S5: the frame locks dropped between the references' commit and the
     * invalidation (a RETYPE can then reach a frame a TLB still maps). */
    if(self && self->in_kunmap) {sptm_frame_release(&self->frames);for(unsigned i=0;i<20;i++)sched_yield();usleep(200);}
#endif
#ifdef MUTANT_KERNEL_NO_TLBI
    (void)va;(void)size;
#else
    tlbi_range(va,size);
#endif
}
static struct shadow kshadow_for(struct tctx *t)
{
    return (struct shadow){.txsz=17,.root=kshadow1,.alloc=t && t->fine ? fine_alloc : token_alloc,
        .read=arena_read,.write=live_write,.ctx=0,.alloc_ctx=&kowner_ctx};
}
/* kernel_refresh for the harness's views: every copy rewritten from its
 * source, then TLBI ALLE1IS (shadow_tlb_sync). Token path only. */
static void kernel_refresh_all(void)
{
    for(unsigned n=0;n<nkcopies;n++)for(unsigned c=0;c<CPUS;c++)
        for(unsigned i=0;i<512;i++)astore(kcopies[n].copy[c]+8*i,aload(kcopies[n].source+8*i));
    tlbi_all();
}
static const struct sptm_aperture kaperture={BASE,APERTURE_VA,SIZE};
static const struct sptm_moved kmoved={0,0,0,0};
static uint64_t out_pa(unsigned cpu) {return PERCPU+(uint64_t)cpu*0x4000;}
static uint64_t list_pa(unsigned cpu) {return PERCPU+(uint64_t)cpu*0x4000+0x1000;}
static uint64_t tmpl_pa(unsigned cpu) {return PERCPU+(uint64_t)cpu*0x4000+0x2000;}
/* probes/xnuboot.c case SPTM_FN_MAP_PAGE's kernel branch, as the token path
 * runs it: the slot, the plan (a conflict reports and changes nothing), the
 * references, the guest store and outputs, the shadow insert (allocating),
 * the refresh and ALLE1IS, the commit. */
static void token_kmap(struct tctx *t,uint64_t va,uint64_t pte,int *result,uint64_t *guest)
{
    struct sptm_memory m=memory_for(t);
    uint64_t table=kroot_pa;int start=mmu_start_level(14,17);
    for(int level=start;level<3;level++) {
        uint64_t e=get(table+8UL*mmu_index(14,(uint32_t)level,va),8);
        if((e&3)!=3) {*result=SPTM_TABLE_MISSING;return;}
        table=e&PT_OA_MASK;
    }
    uint64_t slot=table+8UL*mmu_index(14,3,va),existing=get(slot,8);
    struct sptm_kernel_leaf plan;
    if((pte&3)!=3 || sptm_mac_kernel_map_leaf(&kaperture,&kmoved,slot,existing,pte,&plan)) {*result=SPTM_BAD_TABLE;return;}
    if(!plan.install) {
        put_ram(out_pa(t->cpu),plan.old);put_ram(out_pa(t->cpu)+8,plan.pointer);
        *guest=plan.status;*result=SPTM_OK;return;
    }
    sptm_refs_begin(m.refs);
    enum sptm_result r=sptm_refs_leaf(&m,table,va,existing,pte);
    if(!r)r=sptm_refs_validate(&m);
    if(r) {*result=r;return;}
    put_ram(slot,pte);
    put_ram(out_pa(t->cpu),existing);put_ram(out_pa(t->cpu)+8,plan.pointer);
    struct mmu_config guest_cfg={.granule_shift=14,.txsz=17,.root=kroot_pa};
    struct mmu_leaf leaf;
    CHECK(!mmu_walk(&guest_cfg,va,guest_read,0,&leaf) && leaf.valid);
    struct shadow s=kshadow_for(t);
    uint64_t off=va&((UINT64_C(1)<<47)-1);
    int put=shadow_insert(&s,&leaf,off,off+0x4000);
    CHECK(put==0);
    note_changed(kroot_pa,va,0x4000);
    kernel_refresh_all();
    sptm_refs_commit(&m);
    *guest=plan.status;*result=SPTM_OK;
}

/* ---- the call log --------------------------------------------------------- */
enum kind {OP_MAP,OP_UNMAP,OP_UPDATE,OP_SWITCH,OP_RETYPE,OP_INVALIDATE,OP_UNMAP_DISJOINT,OP_UPDATE_REGION,
           OP_KMAP,OP_KUNMAP,OP_KINDS};
static const char *kind_names[OP_KINDS]={"map","unmap","update","switch","retype","invalidate",
                                         "unmap_disjoint","update_region","kernel_map","kernel_unmap"};
struct op {
    unsigned kind,cpu,count;
    uint64_t root,va,arg,options,to;
    uint64_t rec[3*4];
    int result;uint64_t guest;uint64_t out[8];
    uint64_t seq;int fine;
};
#define DECLINED (-2)
static uint64_t log_max;
static struct op *oplog;
static uint64_t seq_next;
static uint64_t progress;

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
static int skip_hit(void *ctx) {(void)ctx;return 1;}
static int walked_root(uint64_t root) {return ((root>>14)%5)==0;}
static enum sptm_result do_switch(struct tctx *t,uint64_t root)
{
    struct sptm_memory m=memory_for(t);
    struct sptm_root_backend b={.kernel_root=kroot_pa,.kernel_shadow=kshadow,.build=root_build,
        .install=root_switch_install,.ctx=t,.evictions=&evictions,
        .skip_hit_validation=walked_root(root) ? 0 : skip_hit};
    if(t->fine)return sptm_mac_switch_root_hit(&m,&roots,&b,t->cpu,root,0,0) ? SPTM_OK : SPTM_FRAME_BUSY;
    return sptm_mac_switch_root(&m,&roots,&b,t->cpu,root,0,0);
}
/* S3/S4: a frame now typed PAGE_TABLE is cached by no CPU's TLB. */
static void no_tlb_maps(uint64_t frame)
{
    for(unsigned c=0;c<CPUS;c++) {
        pthread_mutex_lock(&tlbs[c].lock);
        for(unsigned i=0;i<TLB_SIZE;i++) {
            const struct tlb_entry *e=&tlbs[c].e[i];
            if(e->root && (e->desc&PA_MASK)==frame) {
                fprintf(stderr,"use after retype: cpu%u caches va %#llx -> frame %#llx, now a table\n",c,
                        (unsigned long long)e->va,(unsigned long long)frame);
                CHECK(!"a TLB maps a frame retyped to PAGE_TABLE");
            }
        }
        pthread_mutex_unlock(&tlbs[c].lock);
    }
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
    case OP_UNMAP_DISJOINT:
        /* probes/xnuboot.c fine_unmap_disjoint / case SPTM_FN_UNMAP_DISJOINT's user branch. */
        for(unsigned i=0;i<3*op->count;i++)put_ram(list_pa(t->cpu)+8*i,op->rec[i]);
        op->result=sptm_mac_unmap_user_disjoint(&m,resolve,t,op->arg,list_pa(t->cpu),op->count,
                                                out_pa(t->cpu),0);
        for(unsigned i=0;i<op->count;i++)op->out[i]=get(out_pa(t->cpu)+8*i,8);
        break;
    case OP_UPDATE_REGION: {
        /* probes/xnuboot.c fine_update_region / sptm_mac_update_user_region. */
        struct sptm_user_backend b;
        if(!resolve(t,op->root,&b)) {op->result=-1;break;}
        for(unsigned i=0;i<op->count;i++)put_ram(tmpl_pa(t->cpu)+8*i,op->rec[i]);
        op->result=sptm_mac_update_user_region(&m,&b,op->root,op->va,op->count,tmpl_pa(t->cpu),
                                               op->options,out_pa(t->cpu),&op->guest,0);
        for(unsigned i=0;i<op->count;i++)op->out[i]=get(out_pa(t->cpu)+8*i,8);
        break;
    }
    case OP_SWITCH:
        op->result=do_switch(t,op->root);
        break;
    case OP_RETYPE: {
        unsigned i=(unsigned)op->arg,from=(unsigned)op->options,to=(unsigned)op->to;
        if(t->fine) {
            /* probes/xnuboot.c fine_retype: the frame exclusive, or decline. */
#ifndef MUTANT_NO_EXCLUSIVE
            if(!sptm_frame_exclusive(&t->frames,spare_pa[i])) {op->result=DECLINED;break;}
#endif
        }
        op->result=sptm_mac_retype(&m,spare_pa[i],from,to,to==20 ? 3 : 0);
        if(op->result==SPTM_OK) {
            spare_type[i]=to;
            if(to==20 && !replaying)no_tlb_maps(spare_pa[i]);
        } else if(t->fine)op->result=DECLINED;
        op->guest=to;
        break;
    }
    case OP_INVALIDATE:
        op->result=sptm_root_invalidate(&roots,op->root,0) ? SPTM_OK : SPTM_FRAME_BUSY;
        if(op->result==SPTM_OK)tlbi_root(op->root);
        break;
    case OP_KMAP:
        if(t->fine) {
            struct shadow s=kshadow_for(t);
#ifdef MUTANT_KERNEL_GLOBAL_REFS
            /* S1: the kernel call on the token path's batch, absolute stores. */
            m.fine=0;m.refs=&global_refs;m.audit=&global_audit;
#endif
            struct sptm_fine_kernel k={.m=&m,.shadow=&s,.guest_read=guest_read,.guest_write=guest_write,
                .copied=kernel_copied,.tlbi=kernel_tlbi,.ctx=t,.aperture=&kaperture,.moved=&kmoved,.t1sz=17};
            enum sptm_fine_kernel_end e=sptm_fine_kernel_map(&k,kroot_pa,op->va,op->arg,
                (volatile uint64_t *)(void *)(ram+(out_pa(t->cpu)-BASE)));
            CHECK(e!=SPTM_FINE_K_FATAL);
            if(e!=SPTM_FINE_K_DONE) {op->result=DECLINED;break;}
            note_changed(kroot_pa,op->va,0x4000);
            op->result=SPTM_OK;op->guest=k.status;
        } else token_kmap(t,op->va,op->arg,&op->result,&op->guest);
        for(unsigned i=0;i<2;i++)op->out[i]=get(out_pa(t->cpu)+8*i,8);
        break;
    case OP_KUNMAP:
        if(t->fine) {
            struct shadow s=kshadow_for(t);
            struct sptm_fine_kernel k={.m=&m,.shadow=&s,.guest_read=guest_read,.guest_write=guest_write,
                .copied=kernel_copied,.tlbi=kernel_tlbi,.ctx=t,.aperture=&kaperture,.moved=&kmoved,.t1sz=17};
            enum sptm_result r=SPTM_OK;
            t->in_kunmap=1;
            enum sptm_fine_kernel_end e=sptm_fine_kernel_unmap(&k,kroot_pa,op->va,op->count,op->options,
                                                               out_pa(t->cpu),&r);
            t->in_kunmap=0;
            if(e!=SPTM_FINE_K_DONE) {op->result=DECLINED;break;}
            note_changed(kroot_pa,op->va,op->count*0x4000);
            op->result=SPTM_OK;
        } else {
            struct shadow s=kshadow_for(t);
            op->result=sptm_mac_unmap_region(&m,&s,kroot_pa,op->va,op->count,op->options,out_pa(t->cpu));
            if(op->result==SPTM_OK) {note_changed(kroot_pa,op->va,op->count*0x4000);kernel_refresh_all();}
        }
        for(unsigned i=0;i<op->count;i++)op->out[i]=get(out_pa(t->cpu)+8*i,8);
        break;
    }
}
static int fine_candidate(const struct op *op)
{
    return op->kind==OP_UPDATE || op->kind==OP_UNMAP || op->kind==OP_MAP || op->kind==OP_SWITCH ||
           op->kind==OP_UNMAP_DISJOINT || op->kind==OP_UPDATE_REGION || op->kind==OP_RETYPE ||
           op->kind==OP_KMAP || op->kind==OP_KUNMAP;
}
static int kernel_kind(const struct op *op) {return op->kind==OP_KMAP || op->kind==OP_KUNMAP;}
static int lockset_for(const struct op *op,struct fine_lockset *set)
{
    fine_lockset_init(set);
    if(op->kind==OP_UPDATE || op->kind==OP_UNMAP_DISJOINT) {
        for(unsigned i=0;i<op->count;i++)if(!fine_lockset_add(set,op->rec[3*i]))return 0;
        return 1;
    }
    if(op->kind==OP_SWITCH) {
        uint64_t old=load_active(self->cpu);
        if(old && !fine_lockset_add(set,old))return 0;
        return op->root==kroot_pa || fine_lockset_add(set,op->root);
    }
    if(op->kind==OP_RETYPE || kernel_kind(op))return 1;    /* no stripe; KL below */
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
static void klock_take(void)
{
#ifndef MUTANT_NO_KL
    fine_ticket_lock(&klock);
#endif
}
static void klock_give(void)
{
#ifndef MUTANT_NO_KL
    fine_ticket_unlock(&klock);
#endif
}
static int fine_admits(struct tctx *t,const struct op *op)
{
    if(op->kind==OP_MAP) {
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
    enum guest_service_result r;
    while((r=guest_service_try_turn(&gate,t->cpu,ticket))!=SERVICE_OK) {CHECK(r==SERVICE_BUSY);FINE_RELAX();}
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
/* S6: no CPU caches a translation of a changed page that its view no longer
 * holds. Run while the call still holds its locks. */
static void tlb_check(struct tctx *t)
{
    for(unsigned n=0;n<t->changed;n++) {
        uint64_t root=t->changed_root[n];
        struct sptm_root_cached *e=root==kroot_pa ? 0 : cached(root);
        for(uint64_t off=0;off<0x4000;off+=4096) {
            uint64_t va=t->changed_va[n]+off,desc=0;
            if(e)CHECK(!shadow_leaf(e->shadow,va,&desc));
            for(unsigned c=0;c<CPUS;c++) {
                if(root==kroot_pa)desc=kview_leaf(c,va);
                pthread_mutex_lock(&tlbs[c].lock);
                unsigned h=(unsigned)tlb_hash(root,va);
                for(unsigned i=0;i<8;i++) {
                    struct tlb_entry *x=&tlbs[c].e[(h+i)%TLB_SIZE];
                    if(x->root==root && x->va==va && x->desc!=desc) {
                        fprintf(stderr,"stale TLB: cpu%u root %#llx va %#llx cached %#llx view %#llx\n",c,
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
/* probes/xnuboot.c fine_sptm_call's frame-lock lifetime: empty at entry,
 * every first touch through ref_fine.held, one release after the call's
 * last TLBI (S5, S25). */
static void frames_begin(struct tctx *t)
{
    t->frames.locks=&frame_locks;t->frames.count=0;t->frames.exclusive=0;
#ifdef MUTANT_NO_FRAME_SHARE
    t->ref_fine.held=0;
#else
    t->ref_fine.held=&t->frames;
#endif
}
static void run(struct tctx *t,struct op *op)
{
    t->changed=0;
    if(fine_candidate(op)) {
#if SNAP_PHASE_FAIR_GATE
        enum guest_service_result r=guest_service_enter_shared(&gate,t->cpu);
        for(unsigned polls=0;r==SERVICE_BUSY;polls++) {
            if(polls>=PF_POLLS) {guest_service_leave_shared(&gate,t->cpu);break;}
            FINE_RELAX();
            r=guest_service_wait_shared(&gate,t->cpu,0);
        }
        if(r!=SERVICE_OK) {CHECK(r==SERVICE_BUSY);t->withdrawn++;t->declines++;goto token;}
#else
        for(;;) {
            enum guest_service_result r=guest_service_enter_shared(&gate,t->cpu);
            if(r==SERVICE_OK)break;
            CHECK(r==SERVICE_BUSY);
            while(guest_service_owner(&gate))FINE_RELAX();
        }
#endif
        struct fine_lockset set;
        frames_begin(t);
        if(lockset_for(op,&set)) {
            lock_set(&set);
            if(kernel_kind(op))klock_take();
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
                    sptm_frame_release(&t->frames);
                    if(kernel_kind(op))klock_give();
                    unlock_set(&set);guest_service_leave_shared(&gate,t->cpu);
                    t->fine_calls++;t->kinds_fine[op->kind]++;return;
                }
                CHECK(!t->changed);              /* declined: nothing published */
            }
            t->fine=0;
            sptm_frame_release(&t->frames);
            if(kernel_kind(op))klock_give();
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
    t->ref_fine.held=0;
    execute(t,op);
    CHECK(!t->dirty_count);
    log_op(op,0);
    tlb_check(t);
    guest_service_release(&gate,t->cpu);
    t->token_calls++;
}

/* ---- random operations ---------------------------------------------------- */
static unsigned ops_per_cpu=3000;
static uint64_t frame_for(unsigned r,unsigned k,unsigned j) {return data_pa[(r*7+k*13+j*3)%NDATA];}
static uint64_t pte_attrs(unsigned x)
{
    static const uint64_t a[]={RW,RO,RO|WW,RW&~AF,RO&~AF};
    return a[x%5];
}
static void aliases(struct tctx *t,struct op *op,unsigned r,unsigned k,unsigned j,uint64_t target,uint64_t tail)
{
    for(unsigned n=0;n<op->count;n++) {
        unsigned rr=n ? rand_r(&t->seed)%NROOTS : r,kk=k,jj=j;
        for(unsigned tries=0;n && tries<64;tries++) {
            kk=rand_r(&t->seed)%NL3;jj=rand_r(&t->seed)%NSLOT;
            if(frame_for(rr,kk,jj)==target)break;
        }
        op->rec[3*n]=root_pa[rr];op->rec[3*n+1]=slot_va(kk,jj);op->rec[3*n+2]=tail;
    }
}
static void random_op(struct tctx *t,struct op *op)
{
    memset(op,0,sizeof(*op));op->cpu=t->cpu;
    unsigned dice=rand_r(&t->seed)%100;
    unsigned r=rand_r(&t->seed)%NROOTS,k=rand_r(&t->seed)%NL3,j=rand_r(&t->seed)%NSLOT;
    op->root=root_pa[r];op->va=slot_va(k,j);
    static const uint64_t options[]={0x2,0x808,0x80a,0x802,0x8,0xa,0x12};
    if(dice<24) {
        op->kind=OP_MAP;
        uint64_t pa=(rand_r(&t->seed)%16) ? frame_for(r,k,j) : spare_pa[rand_r(&t->seed)%NUSPARE];
        op->arg=pa|pte_attrs(rand_r(&t->seed));op->options=rand_r(&t->seed)%2;
    } else if(dice<34) {
        op->kind=OP_UNMAP;op->count=1+rand_r(&t->seed)%4;
        if(j+op->count>NSLOT)op->count=NSLOT-j;
        op->options=rand_r(&t->seed)%2;
    } else if(dice<44) {
        op->kind=OP_UPDATE;
        op->options=options[rand_r(&t->seed)%6];
        uint64_t target=frame_for(r,k,j);op->arg=target;
        op->count=1+rand_r(&t->seed)%3;
        aliases(t,op,r,k,j,target,target|pte_attrs(rand_r(&t->seed)));
    } else if(dice<54) {
        op->kind=OP_UNMAP_DISJOINT;
        uint64_t target=frame_for(r,k,j);op->arg=target;
        op->count=1+rand_r(&t->seed)%3;
        aliases(t,op,r,k,j,target,(rand_r(&t->seed)%4) ? 0 : UINT64_C(0x4000000000000000));
    } else if(dice<62) {
        op->kind=OP_UPDATE_REGION;op->count=1+rand_r(&t->seed)%3;
        op->options=options[rand_r(&t->seed)%7];
        for(unsigned n=0;n<op->count;n++)op->rec[n]=pte_attrs(rand_r(&t->seed));
    } else if(dice<68) {
        op->kind=OP_SWITCH;
        op->root=rand_r(&t->seed)%4==0 ? kroot_pa : root_pa[rand_r(&t->seed)%NROOTS];
    } else if(dice<78) {
        op->kind=OP_RETYPE;op->arg=rand_r(&t->seed)%NSPARE;
        unsigned x=rand_r(&t->seed)%5;
        op->options=x<2 ? 11 : x<4 ? 20 : 11;op->to=x<2 ? 20 : x<4 ? 11 : 11;
    } else if(dice<90) {
        op->kind=OP_KMAP;
        unsigned kk=rand_r(&t->seed)%NKL3,jj=rand_r(&t->seed)%NSLOT;
        op->va=kslot_va(kk,jj);
        unsigned x=rand_r(&t->seed)%16;
        uint64_t pa=x>1 ? frame_for(kk,jj,kk) : spare_pa[x==0 ? rand_r(&t->seed)%NUSPARE : NUSPARE+rand_r(&t->seed)%NKSPARE];
        op->arg=pa|((rand_r(&t->seed)%2) ? KRW : KRO);
    } else if(dice<98) {
        op->kind=OP_KUNMAP;
        unsigned kk=rand_r(&t->seed)%NKL3,jj=rand_r(&t->seed)%NSLOT;
        op->va=kslot_va(kk,jj);op->count=1+rand_r(&t->seed)%4;op->options=rand_r(&t->seed)%2;
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
        if(op.kind==OP_INVALIDATE) {
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
static void set_meta(uint64_t pa,unsigned type,unsigned level)
{ram[meta(pa)-BASE+2]=(uint8_t)type;ram[meta(pa)-BASE+4]=(uint8_t)level;ram[meta(pa)-BASE+6]=1;}
/* The initial state, deterministic (setup and replay both run it). */
static void build_state(void)
{
    memset(ram,0,SIZE);memset(arena,0,(size_t)APAGES*4096);
    memset(arena_owner,0,sizeof(arena_owner));arena_next=0;arena_nfree=0;
    memset(&roots,0,sizeof(roots));memset(guest_ttbr0,0,sizeof(guest_ttbr0));
    for(uint64_t pa=BASE;pa<BASE+SIZE;pa+=0x4000)ram[meta(pa)-BASE+2]=11;
    for(unsigned i=0;i<NSPARES;i++)spare_type[i]=11;
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
    /* The kernel's 16K tables (T1SZ 17: levels 1..3), written as the loader
     * leaves them; level-3 tables typed PAGE_TABLE so references count. */
    set_meta(kroot_pa,8,1);set_meta(kl2_pa,20,2);
    put_ram(kroot_pa+8UL*mmu_index(14,1,KVBASE),kl2_pa|3);
    for(unsigned k=0;k<NKL3;k++) {
        set_meta(kl3_pa[k],20,3);
        put_ram(kl2_pa+8UL*mmu_index(14,2,kslot_va(k,0)),kl3_pa[k]|3);
    }
    kshadow=arena_take(999);kshadow1=arena_take(KOWNER);
    /* The canonical kernel shadow: every 2 MiB span has its path except one in
     * four (an insert there allocates: token path); one in four of the built
     * level-3 tables is copied by every CPU's kernel view. */
    nkcopies=0;
    for(unsigned k=0;k<NKL3;k++)for(unsigned s=0;s<NKSPAN;s++) {
        if(s%4==3)continue;
        uint64_t off=(kslot_va(k,0)&((UINT64_C(1)<<47)-1))+(uint64_t)s*0x200000,table;
        struct shadow sh=kshadow_for(0);
        CHECK(!shadow_table(&sh,3,off,&table));
        if(s%4==1) {
            CHECK(nkcopies<NKCOPY);
            kcopies[nkcopies].source=table;
            for(unsigned c=0;c<CPUS;c++)CHECK((kcopies[nkcopies].copy[c]=arena_take(COPY_OWNER))!=0);
            nkcopies++;
        }
    }
    for(unsigned c=0;c<CPUS;c++) {self=&tc[c];CHECK(do_switch(&tc[c],root_pa[c%NROOTS])==SPTM_OK);}
    for(unsigned r=CPUS;r<NROOTS;r++) {self=&tc[0];CHECK(do_switch(&tc[0],root_pa[r])==SPTM_OK);}
    self=&tc[0];CHECK(do_switch(&tc[0],root_pa[0])==SPTM_OK);
    for(unsigned r=0;r<NROOTS;r++)for(unsigned k=0;k<NL3;k++)for(unsigned j=0;j<NSLOT;j+=2) {
        struct op op={.kind=OP_MAP,.root=root_pa[r],.va=slot_va(k,j),.arg=frame_for(r,k,j)|((j&2) ? RO : RW),.options=1};
        execute(&tc[0],&op);CHECK(op.result==SPTM_OK);
    }
    for(unsigned k=0;k<NKL3;k++)for(unsigned j=0;j<NSLOT;j+=2) {
        struct op op={.kind=OP_KMAP,.va=kslot_va(k,j),.arg=frame_for(k,j,k)|((j&2) ? KRO : KRW)};
        execute(&tc[0],&op);CHECK(op.result==SPTM_OK);
    }
    self=0;
    for(unsigned c=0;c<CPUS;c++)tc[c].dirty_count=0;
}
static void setup(void)
{
    ram=aligned_alloc(0x4000,SIZE);ram0=aligned_alloc(0x4000,SIZE);
    arena=aligned_alloc(4096,(size_t)APAGES*4096);arena0=aligned_alloc(4096,(size_t)APAGES*4096);
    log_max=(uint64_t)ops_per_cpu*CPUS+16;oplog=calloc(log_max,sizeof(*oplog));
    CHECK(ram && ram0 && arena && arena0 && oplog);
    uint64_t next=ALLOC_LOW;
    for(unsigned r=0;r<NROOTS;r++)root_pa[r]=next,next+=0x4000;
    for(unsigned r=0;r<NROOTS;r++)l2_pa[r]=next,next+=0x4000;
    for(unsigned r=0;r<NROOTS;r++)for(unsigned k=0;k<NL3;k++)l3_pa[r][k]=next,next+=0x4000;
    for(unsigned i=0;i<NDATA;i++)data_pa[i]=next,next+=0x4000;
    for(unsigned i=0;i<NSPARES;i++)spare_pa[i]=next,next+=0x4000;
    kroot_pa=next;next+=0x4000;kl2_pa=next;next+=0x4000;
    for(unsigned k=0;k<NKL3;k++)kl3_pa[k]=next,next+=0x4000;
    CHECK(next<=BASE+SIZE);
    for(unsigned c=0;c<CPUS;c++) {
        tc[c].cpu=c;tc[c].seed=chaos_seed_global*977+c*7919+1;
        pthread_mutex_init(&tlbs[c].lock,0);
        gate.lifecycle|=(uint64_t)EXECUTOR_RUNNING<<(c*3);
    }
    build_state();
    memcpy(ram0,ram,SIZE);memcpy(arena0,arena,(size_t)APAGES*4096);
    memcpy(arena_owner0,arena_owner,sizeof(arena_owner));memcpy(arena_free0,arena_free,sizeof(arena_free));
    arena_next0=arena_next;arena_nfree0=arena_nfree;memcpy(spare_type0,spare_type,sizeof(spare_type));
}
static int readonly_leaf(uint64_t pte)
{
    unsigned perm=(unsigned)(((pte>>4)&12)|((pte>>53)&3));
    return (perm&~4u)==11 && !(pte&WW);
}
/* S1/S2/S3: counts and types from the guest tables alone (user and kernel). */
static void check_counts(void)
{
    static int64_t ro[4096],other[4096];
    memset(ro,0,sizeof(ro));memset(other,0,sizeof(other));
    uint64_t tables[NROOTS*NL3+NKL3];unsigned nt=0;
    for(unsigned r=0;r<NROOTS;r++)for(unsigned k=0;k<NL3;k++)tables[nt++]=l3_pa[r][k];
    for(unsigned k=0;k<NKL3;k++)tables[nt++]=kl3_pa[k];
    for(unsigned n=0;n<nt;n++) {
        unsigned valid=0;
        for(unsigned i=0;i<2048;i++) {
            uint64_t pte=get(tables[n]+8*i,8);
            if((pte&3)==3 || (pte&UINT64_C(0xe000000000000000)))valid++;
            if((pte&3)!=3)continue;
            unsigned f=(unsigned)(((pte&PA_MASK)-BASE)>>14);
            if(readonly_leaf(pte))ro[f]++;else other[f]++;
        }
        CHECK(get(meta(tables[n])+8,2)==valid);
        CHECK(get(meta(tables[n])+2,1)==20);
    }
    for(unsigned i=0;i<NDATA+NSPARES;i++) {
        uint64_t pa=i<NDATA ? data_pa[i] : spare_pa[i-NDATA];
        unsigned f=(unsigned)((pa-BASE)>>14);
        if((int64_t)get(meta(pa)+8,4)!=ro[f] || (int64_t)get(meta(pa)+12,4)!=other[f])
            fprintf(stderr,"frame %u: counts %llu/%llu, leaves %lld/%lld\n",i,
                    (unsigned long long)get(meta(pa)+8,4),(unsigned long long)get(meta(pa)+12,4),
                    (long long)ro[f],(long long)other[f]);
        CHECK((int64_t)get(meta(pa)+8,4)==ro[f]);
        CHECK((int64_t)get(meta(pa)+12,4)==other[f]);
        unsigned type=i<NDATA ? 11u : spare_type[i-NDATA];
        CHECK(get(meta(pa)+2,1)==type);
        if(type==20)CHECK(!ro[f] && !other[f]);  /* S3: a table frame maps as no leaf */
    }
}
static void check_shadows(void)
{
    for(unsigned i=0;i<SPTM_ROOT_CACHE;i++) {
        struct sptm_root_cached *e=&roots.cache[i];
        if(!e->valid)continue;
        uint64_t leaves=0;
        for(unsigned k=0;k<NL3;k++)for(unsigned j=0;j<2048;j++) {
            uint64_t va=VBASE+(uint64_t)k*0x2000000+(uint64_t)j*0x4000,pte=0;
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
    /* The kernel shadow equals the kernel's guest leaves; S8: every copy
     * equals its source. */
    for(unsigned k=0;k<NKL3;k++)for(unsigned j=0;j<2048;j++) {
        uint64_t va=kslot_va(k,0)+(uint64_t)j*0x4000,pte=get(kl3_pa[k]+8*j,8);
        for(uint64_t off=0;off<0x4000;off+=4096)for(unsigned c=0;c<CPUS;c++) {
            uint64_t desc=kview_leaf(c,va+off);
            if((pte&3)!=3) {CHECK(!desc);continue;}
            CHECK(desc && (desc&PT_OA_MASK)==(pte&PA_MASK)+off);
        }
    }
    for(unsigned n=0;n<nkcopies;n++)for(unsigned c=0;c<CPUS;c++)
        for(unsigned i=0;i<512;i++)CHECK(aload(kcopies[n].copy[c]+8*i)==aload(kcopies[n].source+8*i));
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
    unsigned spare_end[NSPARES];memcpy(spare_end,spare_type,sizeof(spare_end));
    replaying=1;
    build_state();
    CHECK(!memcmp(ram,ram0,SIZE));CHECK(!memcmp(arena,arena0,(size_t)APAGES*4096));
    qsort(oplog,n,sizeof(*oplog),cmp_seq);
    unsigned long differ=0;
    for(uint64_t i=0;i<n;i++) {
        struct op op=oplog[i];
        CHECK(op.seq==i);
        struct tctx *t=&tc[op.cpu];self=t;t->fine=0;t->changed=0;t->dirty_count=0;t->ref_fine.held=0;
        execute(t,&op);
        if(op.result!=oplog[i].result || op.guest!=oplog[i].guest ||
           memcmp(op.out,oplog[i].out,sizeof(op.out))) {
            if(differ++<5)fprintf(stderr,"replay %llu kind %s cpu %u fine %d: result %d/%d guest %llu/%llu\n",
                (unsigned long long)i,kind_names[op.kind],op.cpu,oplog[i].fine,oplog[i].result,op.result,
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
/* S5, aimed: a kernel unmap's references drop inside sptm_mac_unmap_region,
 * before its invalidation. CPU 0 maps kernel-only spare Y at one VA, has every
 * CPU's TLB cache it, then unmaps it; CPU 1 keeps retyping Y 11->20->11. The
 * frame lock held until after the invalidation keeps every converted RETYPE
 * out of that window; without it (MUTANT_EARLY_RELEASE) a RETYPE to
 * PAGE_TABLE lands while TLBs still map Y (no_tlb_maps). After the replay,
 * on the final state; not logged. */
static int race_done;
static void *race_unmapper(void *arg)
{
    (void)arg;struct tctx *t=&tc[0];self=t;chaos_seed=0x1234567u;
    uint64_t y=spare_pa[RACE],va=kslot_va(0,1);
    for(unsigned n=0;n<400;n++) {
        struct op op={.kind=OP_KMAP,.cpu=0,.va=va,.arg=y|KRW};
        run(t,&op);
        if(op.result!=SPTM_OK && !(op.result==DECLINED))continue;
        for(unsigned c=0;c<CPUS;c++) {
            pthread_mutex_lock(&tlbs[c].lock);
            uint64_t d=kview_leaf(c,va);
            if(d)tlb_fill(c,kroot_pa,va,d);
            pthread_mutex_unlock(&tlbs[c].lock);
        }
        struct op un={.kind=OP_KUNMAP,.cpu=0,.va=va,.count=1};
        run(t,&un);
        __atomic_fetch_add(&progress,1,__ATOMIC_RELAXED);
    }
    __atomic_store_n(&race_done,1,__ATOMIC_RELEASE);
    return 0;
}
static void *race_retyper(void *arg)
{
    (void)arg;struct tctx *t=&tc[1];self=t;chaos_seed=0x7654321u;
    while(!__atomic_load_n(&race_done,__ATOMIC_ACQUIRE)) {
        struct op a={.kind=OP_RETYPE,.cpu=1,.arg=RACE,.options=11,.to=20};
        run(t,&a);
        struct op b={.kind=OP_RETYPE,.cpu=1,.arg=RACE,.options=20,.to=11};
        run(t,&b);
    }
    return 0;
}
static void retype_race(void)
{
    /* Room in the log for the aimed phase's calls (logged, never replayed). */
    seq_next=0;log_max=UINT64_MAX;
    oplog=realloc(oplog,sizeof(*oplog)*(size_t)200000);CHECK(oplog!=NULL);log_max=200000;
    pthread_t a,b;
    race_done=0;
    pthread_create(&a,0,race_unmapper,0);pthread_create(&b,0,race_retyper,0);
    pthread_join(a,0);pthread_join(b,0);
    self=0;
    for(unsigned i=0;i<SPTM_FRAME_LOCKS;i++)CHECK(!frame_locks.word[i]);
    fprintf(stderr,"  aimed unmap/retype race: %llu calls\n",(unsigned long long)seq_next);
}
/* The frame-lock primitives on their own (compat/sptm-frame-lock.h). */
static void frame_lock_unit(void)
{
    static struct sptm_frame_locks l;static struct sptm_frame_held a,b;
    a.locks=b.locks=&l;
    uint64_t f=BASE+0x100000,g=f+0x4000;
    CHECK(sptm_frame_share(&a,f) && sptm_frame_share(&b,f) && sptm_frame_share(&a,f));
    CHECK(!sptm_frame_exclusive(&b,g) || (sptm_frame_lock_index(g)!=sptm_frame_lock_index(f)));
    sptm_frame_release(&b);                       /* b may hold g exclusive: released too */
    CHECK(!sptm_frame_exclusive(&b,f));           /* a still shares f */
    sptm_frame_release(&a);
    CHECK(sptm_frame_exclusive(&b,f));
    CHECK(!sptm_frame_share(&a,f) && !a.count);   /* refused, nothing held */
    CHECK(!sptm_frame_exclusive(&a,f));
    sptm_frame_release(&b);
    for(unsigned i=0;i<SPTM_FRAME_LOCKS;i++)CHECK(!l.word[i]);
    static struct sptm_frame_held off;CHECK(sptm_frame_share(&off,f) && !off.count);  /* locks off */
}
int main(int argc,char **argv)
{
    if(argc>1)ops_per_cpu=(unsigned)strtoul(argv[1],0,0);
    chaos_seed_global=argc>2 ? (unsigned)strtoul(argv[2],0,0) : (unsigned)time(0);
    fprintf(stderr,"seed %u, %u calls per CPU, %u stripes, %u frame locks\n",chaos_seed_global,ops_per_cpu,
            FINE_STRIPES,SPTM_FRAME_LOCKS);
    frame_lock_unit();
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
    CHECK(!fine_ticket_held(&klock));
    for(unsigned i=0;i<SPTM_FRAME_LOCKS;i++)CHECK(!frame_locks.word[i]);
    check_counts();check_shadows();
    replay(n);
    check_counts();check_shadows();
    unsigned long kinds[OP_KINDS][3]={{0}};
    for(uint64_t i=0;i<n;i++) {
        unsigned k=oplog[i].kind;kinds[k][oplog[i].result==SPTM_OK ? 0 : 1]++;kinds[k][2]+=oplog[i].fine;
    }
    for(unsigned k=0;k<OP_KINDS;k++)fprintf(stderr,"  %-15s ok %6lu refused %6lu converted %6lu\n",kind_names[k],
                                           kinds[k][0],kinds[k][1],kinds[k][2]);
#ifdef DEBUG_STATS
    {
        unsigned long res[32][3]={{0}};
        for(uint64_t i=0;i<n;i++)if(oplog[i].kind==OP_RETYPE) {
            int r=oplog[i].result;unsigned slot=r<0 ? 31u : (unsigned)r%31u;
            res[slot][oplog[i].guest==20]++;res[slot][2]+=oplog[i].arg>=NUSPARE;
        }
        for(unsigned x=0;x<32;x++)if(res[x][0]+res[x][1])fprintf(stderr,"  retype result %u: to11 %lu to20 %lu kspare %lu\n",
                                                               x,res[x][0],res[x][1],res[x][2]);
    }
#endif
    /* Every new conversion must have run converted. */
    CHECK(kinds[OP_UNMAP_DISJOINT][2] && kinds[OP_UPDATE_REGION][2] && kinds[OP_RETYPE][2] &&
          kinds[OP_KMAP][2] && kinds[OP_KUNMAP][2]);
    CHECK(fine>n/4);
    retype_race();
    check_counts();
    fprintf(stderr,"  changed pages %llu, publications %lu\n",(unsigned long long)changed_pages,publications);
    fprintf(stderr,"%llu calls logged: %llu converted, %llu token (%llu declined first); replay equal\n",
            (unsigned long long)n,(unsigned long long)fine,(unsigned long long)token,(unsigned long long)declined);
    printf("sptm-fine: %u checks passed\n",checks);
    return 0;
}

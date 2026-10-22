/* SPDX-License-Identifier: MIT */
/* SNAP_ANS_ASYNC + SNAP_ANS_CONVERTED concurrency harness (agents/nvme-async/FAILURE-MODES.md N1-N4, N9, N10, N12,
 * N18). Six pthreads play six vCPUs; a seventh plays the SSD.
 *
 * Real code under test: compat/ans.c (the virtual ANS2 with its async queue and ans_sptm_converted),
 * compat/ans-window.c and compat/nvme-host.c (the window backend and the physical submit/reap, host ops),
 * compat/sptm-refs.c (fine reference batches, atomic commits, first-touch frame locks), compat/sptm.c
 * (sptm_mac_retype), compat/service-lock.c (the gate: token, readers, the phase-fair wait), compat/fine-lock.h
 * (the FIFO ticket that is the ANS lock), compat/sptm-frame-lock.h. The converted wrappers below repeat
 * probes/xnuboot.c's fine_ans_mmio and fine_ans_sptm (gate shared, ANS lock, the call, the lines, unlock,
 * frame-lock release, gate leave); tools/test-nvme-async.py checks that xnuboot.c keeps that order.
 *
 * Each vCPU loops over SSD commands on its own CIDs, data frames and LBA region: MAP_PAGES (converted, else
 * the token path), the SQE, its data stamp (writes), the I/O doorbell (converted), the wait (randomly: CQ head
 * writes, token-path ticks, nothing), the check of the read data, UNMAP_PAGES (converted; BUSY or any decline
 * goes to the token path, which drains). Interrupts are taken on the token path (the guest's AIC acknowledge):
 * the CQ is consumed there and its head written either there or by a converted 0x100c write. Beside them, on
 * the same data frames: a converted RETYPE 11->20->11 (exclusive frame lock, the real sptm_mac_retype) and a
 * converted reference churn (another converted DMA user: sptm_refs_dart on this CPU's fine batch).
 *
 * Checked: under the token, every data frame's +8/+12 equals the CIDs' pages plus the churn's references, no
 * mapped CID's frame is anything but XNU_DEFAULT, every frame-lock word is zero, the ANS lock is free, the
 * queue's counters balance and the NVMe line equals ans_levels; at every guest write a completion makes, the
 * frame is XNU_DEFAULT and holds a device-write reference (pinned, N1); every read returns its LBAs' last
 * written stamp, and every CQE is consumed exactly once (N4, N12); every command completes even with all
 * waiters parked (ticks only, N3, N18); a 20 s watchdog (deadlock); at the end every reference is gone and
 * every lock word is zero. ThreadSanitizer reports any unsynchronized access.
 *
 * Mutants (-D): MUTANT_NO_ANS_LOCK, MUTANT_NO_GATE, MUTANT_PER_PAGE_COMMIT, MUTANT_UNPINNED_RETYPE,
 * MUTANT_LINES_OUTSIDE_LOCK, MUTANT_PLAIN_ENTRY_READ (ans_dma_frame on the live entry, as the token path reads
 * it: found by this harness, TSan): each must fail.
 *
 * Arguments: [commands-per-cpu] [seed]. */
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
#include "sptm.h"
#include "sptm-refs.h"
#include "sptm-frame-lock.h"
#include "ans.h"
#include "ans-window.h"
#include "nvme-host.h"
#if !SNAP_ANS_ASYNC || !SNAP_ANS_CONVERTED || !SNAP_FINE_LOCKS || !SNAP_SPTM_FINE_RETYPE
#error "build with -DSNAP_ANS_ASYNC=1 -DSNAP_ANS_CONVERTED=1 -DSNAP_FINE_LOCKS=1 -DSNAP_FINE_HW=1 -DSNAP_SPTM_FINE=1 -DSNAP_SPTM_FINE_RETYPE=1"
#endif

#define CPUS 6u
static unsigned checks;
#define CHECK(x) do { __atomic_fetch_add(&checks,1,__ATOMIC_RELAXED); if(!(x)) { \
    fprintf(stderr,"FAIL %d: %s\n",__LINE__,#x); fflush(stderr); _exit(1); } } while(0)

/* ---- guest RAM and the frame map ------------------------------------------------------------------------ */
#define BASE UINT64_C(0x90000000)
#define SIZE UINT64_C(0x1000000)                 /* 16 MiB, 1024 frames */
#define FM (BASE+0x4000)                         /* 1024 x 16 bytes */
#define ASQ (BASE+0x10000)
#define ACQ (BASE+0x11000)
#define IOSQ (BASE+0x14000)
#define IOCQ (BASE+0x18000)
#define TCB(c) (BASE+0x20000+(uint64_t)(c)*0x1000)       /* per CPU: TCB at +0, PRP list at +0x100 */
#define ALLOC_LOW (BASE+0x8000)                  /* frames 0 and the frame map are not managed */
#define FRAMES_PER_CPU 4u
#define DATA(c,i) (BASE+0x100000+((uint64_t)(c)*FRAMES_PER_CPU+(i))*0x4000)
#define NDATA (CPUS*FRAMES_PER_CPU)
static uint8_t *ram;
static volatile uint8_t *gmap(void *ctx,uint64_t pa,uint64_t n)
{
    (void)ctx;
    if(pa<BASE || pa>=BASE+SIZE || n>BASE+SIZE-pa)return NULL;
    return ram+(pa-BASE);
}
static uint8_t *meta(uint64_t pa) {return ram+(FM-BASE)+((pa-BASE)>>14)*16;}
static uint32_t count_at(uint64_t pa,unsigned off) {return __atomic_load_n((uint32_t *)(void *)(meta(pa)+off),__ATOMIC_RELAXED);}
static uint64_t data_frame(unsigned k) {return DATA(k/FRAMES_PER_CPU,k%FRAMES_PER_CPU);}
static int is_data(uint64_t pa,unsigned *k)
{
    uint64_t f=pa&~UINT64_C(0x3fff);
    if(f<DATA(0,0) || f>=DATA(0,0)+(uint64_t)NDATA*0x4000)return 0;
    *k=(unsigned)((f-DATA(0,0))>>14);return 1;
}

/* ---- the virtual ANS2's reservation, the window backend, the SSD ----------------------------------------- */
#define BLOCKS 1024u                              /* 4 KiB virtual blocks: 1 MiB head, 2 MiB SSD, 1 MiB tail */
#define FIRST UINT64_C(1000)
static uint8_t *res;                              /* ANS_WINDOW_BYTES */
static struct ans_state *st;
static uint8_t disk[BLOCKS*4096];                 /* the SSD's window, real LBAs FIRST.. */
static uint32_t bar[0x2000/4] __attribute__((aligned(0x4000)));
static uint64_t now_ns(void) {struct timespec t;clock_gettime(CLOCK_MONOTONIC,&t);return (uint64_t)t.tv_sec*1000000000u+(uint64_t)t.tv_nsec;}
static uint32_t h_rd(void *ctx,uint64_t pa) {(void)ctx;return __atomic_load_n((uint32_t *)(uintptr_t)pa,__ATOMIC_ACQUIRE);}
static void h_wr(void *ctx,uint64_t pa,uint32_t v) {(void)ctx;__atomic_store_n((uint32_t *)(uintptr_t)pa,v,__ATOMIC_RELEASE);}
static void h_clean(void *ctx,uint64_t pa,uint64_t size) {(void)ctx;(void)pa;(void)size;}
static uint64_t h_now(void *ctx) {(void)ctx;return now_ns();}
static const struct nvmeh_ops hops={0,h_rd,h_wr,h_clean,h_now};
#define PARAMS ((struct nvmeh_params *)(res+ANS_WINDOW_NVMEH))
#define NSTATE ((struct nvmeh_state *)(res+ANS_WINDOW_NVMEH+0x80))
static struct ans_window_backend backend(void)
{
    return (struct ans_window_backend){BLOCKS,res+ANS_WINDOW_HEAD,res+ANS_WINDOW_TAIL,res+ANS_WINDOW_STAGE,
        res+ANS_WINDOW_DMA+NVMEH_DATA,&hops,PARAMS,NSTATE,(struct ans_window_flight *)st->async.backend};
}
static int w_read(void *c,uint64_t l,uint64_t n,volatile uint8_t **d) {struct ans_window_backend b=backend();(void)c;return ans_window_read_blocks(&b,l,n,d);}
static int w_buffer(void *c,uint64_t l,uint64_t n,volatile uint8_t **d) {struct ans_window_backend b=backend();(void)c;return ans_window_prepare_write(&b,l,n,d);}
static int w_write(void *c,uint64_t l,uint64_t n) {struct ans_window_backend b=backend();(void)c;return ans_window_write_blocks(&b,l,n);}
static int w_flush(void *c) {(void)c;return nvmeh_flush(&hops,PARAMS,NSTATE);}
static int w_start(void *c,unsigned op,uint64_t l,uint64_t n) {struct ans_window_backend b=backend();(void)c;return ans_window_start(&b,op,l,n);}
static int w_poll(void *c,volatile uint8_t **d) {struct ans_window_backend b=backend();(void)c;return ans_window_poll(&b,d);}
static void w_quiesce(void *c) {struct ans_window_backend b=backend();(void)c;(void)ans_window_quiesce(&b);}
/* The SSD: executes each new SQ entry after a random delay, DMA through the window, then its CQE (phase last). */
static volatile int device_stop;
static unsigned device_cmds;
static void *device(void *arg)
{
    (void)arg;
    unsigned sq=0,cq=0,phase=1,seed=12345;
    uint64_t dma=(uint64_t)(uintptr_t)(res+ANS_WINDOW_DMA);
    while(!__atomic_load_n(&device_stop,__ATOMIC_ACQUIRE)) {
        unsigned tail=__atomic_load_n(&bar[0x1008/4],__ATOMIC_ACQUIRE);
        if(sq==tail) {sched_yield();continue;}
        for(unsigned d=rand_r(&seed)%64;d--;)sched_yield();
        uint32_t *e=(uint32_t *)(uintptr_t)(dma+NVMEH_IOSQ+sq*64);
        sq=(sq+1)%NVMEH_IO_ENTRIES;
        unsigned op=e[0]&0xff,cid=e[0]>>16;
        uint64_t prp1=e[6]|(uint64_t)e[7]<<32,prp2=e[8]|(uint64_t)e[9]<<32,lba=e[10]|(uint64_t)e[11]<<32;
        uint64_t bytes=op ? ((e[12]&0xffff)+1u)*512u : 0,pages=(bytes+4095)/4096;
        CHECK(op<=2 && (!op || (lba>=FIRST && (lba-FIRST)*512+bytes<=sizeof disk)));
        for(uint64_t pg=0;pg<pages;pg++) {
            uint64_t pa=!pg ? prp1 : pages==2 ? prp2 : ((uint64_t *)(uintptr_t)prp2)[pg-1];
            uint64_t len=bytes-pg*4096<4096 ? bytes-pg*4096 : 4096;
            uint8_t *m=disk+(lba-FIRST)*512+pg*4096;
            if(op==2)memcpy((void *)(uintptr_t)pa,m,len);else memcpy(m,(void *)(uintptr_t)pa,len);
        }
        uint32_t *c=(uint32_t *)(uintptr_t)(dma+NVMEH_IOCQ+cq*16);
        c[0]=0;c[1]=0;c[2]=sq|1u<<16;
        __atomic_store_n(&c[3],cid|phase<<16,__ATOMIC_RELEASE);
        cq=(cq+1)%NVMEH_IO_ENTRIES;if(!cq)phase^=1;
        __atomic_fetch_add(&device_cmds,1,__ATOMIC_RELAXED);
    }
    return 0;
}

/* ---- the gate, the ANS lock, frame locks, references ----------------------------------------------------- */
static struct guest_service_lock gate;
static struct fine_ticket ans_lock;
static struct sptm_frame_locks frame_locks;
static struct sptm_ref_batch global_refs;
static struct sptm_pv_audit global_audit;
static int nvme_line;                               /* the AIC's NVMe level, written under ANS exclusion */
static unsigned churn_ro[NDATA],churn_rw[NDATA];    /* the churn's own references, updated inside the gate */
static unsigned long pinned_writes,unpinned_writes,retypes_ok,retypes_busy,map_refused,max_hold_ns,early_unmaps;
struct tctx {
    unsigned cpu,seed;
    struct sptm_ref_batch refs;struct sptm_ref_fine ref_fine;struct sptm_frame_held frames;struct sptm_pv_audit audit;
    unsigned long conv,token,declined,busy,polls;
    uint64_t lba_base;
};
static struct tctx tc[CPUS];
static __thread struct tctx *self;
static __thread int in_ans;                         /* inside an ANS call: its guest stores are completions */
static void publish(void *ctx,uint64_t pa,uint64_t size)
{
    (void)ctx;
    if(!in_ans || (pa>=FM && pa<FM+0x4000))return;    /* a RETYPE's zeroing, a frame-map entry */
    /* N1: a completion's guest store lands on an XNU_DEFAULT frame with a device-write reference. */
    for(uint64_t f=pa&~UINT64_C(0x3fff);f<pa+size;f+=0x4000) {
        if(meta(f)[2]==11 && count_at(f,12)>0)__atomic_fetch_add(&pinned_writes,1,__ATOMIC_RELAXED);
        else {__atomic_fetch_add(&unpinned_writes,1,__ATOMIC_RELAXED);CHECK(!"a completion wrote an unpinned frame");}
    }
}
static struct sptm_memory memory(struct tctx *t)
{
    struct sptm_memory m={.frame_map_pa=FM,.frame_low=BASE,.frame_high=BASE+SIZE,.alloc_low=ALLOC_LOW,
        .alloc_high=BASE+SIZE,.map=gmap,.publish=publish,.refs=t ? &t->refs : &global_refs,
        .audit=t ? &t->audit : &global_audit};
    if(t)m.fine=&t->ref_fine;
    return m;
}
/* The token path's ans_frame_ref (probes/xnuboot.c). */
static int frame_ref(void *ctx,uint64_t pa,int writable,int release)
{
    (void)ctx;
    struct sptm_memory m=memory(0);
    uint64_t f=pa&~UINT64_C(0x3fff);
    if(!sptm_managed_frame(&m,f))return 1;
    if(!release && !ans_dma_frame(meta(f)))return 1;
    sptm_refs_begin(m.refs);
    if((release ? sptm_refs_dart_remove(&m,f,!writable) : sptm_refs_dart(&m,f,!writable)) || sptm_refs_validate(&m))return 1;
    sptm_refs_commit(&m);
    return 0;
}
/* probes/xnuboot.c fine_ans_dma_frame: the counts loaded atomically (they move under other converted calls). */
static int dma_frame(uint64_t f)
{
    volatile uint8_t *e=meta(f);
#ifdef MUTANT_PLAIN_ENTRY_READ
    return ans_dma_frame(e);
#else
    uint8_t copy[16];
    for(unsigned i=0;i<8;i++)copy[i]=e[i];
    uint32_t ro=__atomic_load_n((volatile uint32_t *)(volatile void *)(e+8),__ATOMIC_RELAXED);
    uint32_t other=__atomic_load_n((volatile uint32_t *)(volatile void *)(e+12),__ATOMIC_RELAXED);
    for(unsigned i=0;i<4;i++) {copy[8+i]=(uint8_t)(ro>>(8*i));copy[12+i]=(uint8_t)(other>>(8*i));}
    return ans_dma_frame(copy);
#endif
}
/* probes/xnuboot.c fine_ans_frame_refs. */
static int frame_refs(void *ctx,const uint64_t *pa,unsigned n,int writable,int release)
{
    (void)ctx;
    struct sptm_memory m=memory(self);
#ifdef MUTANT_PER_PAGE_COMMIT
    /* N9's weakening: each page committed on its own; a later conflict leaves the earlier ones. */
    for(unsigned i=0;i<n;i++) {
        uint64_t f=pa[i]&~UINT64_C(0x3fff);
        sptm_refs_begin(m.refs);
        if(release ? sptm_refs_dart_remove(&m,f,!writable) : sptm_refs_dart(&m,f,!writable))return 1;
        if(!release && !dma_frame(f))return 1;
        if(sptm_refs_validate(&m))return 1;
        sptm_refs_commit(&m);
    }
    return 0;
#else
    sptm_refs_begin(m.refs);
    for(unsigned i=0;i<n;i++) {
        uint64_t f=pa[i]&~UINT64_C(0x3fff);
        if(!sptm_managed_frame(&m,f))return 1;
        if(release ? sptm_refs_dart_remove(&m,f,!writable) : sptm_refs_dart(&m,f,!writable))return 1;
        if(!release && !dma_frame(f))return 1;
    }
    if(sptm_refs_validate(&m))return 1;
    sptm_refs_commit(&m);
    return 0;
#endif
}
static int refuse_ref(void *c,uint64_t p,int w,int r) {(void)c;(void)p;(void)w;(void)r;CHECK(!"token reference off the token");return 1;}
static const struct ans_ops token_ops={.ctx=0,.map=gmap,.frame_ref=frame_ref,.publish=publish,.disk_read=w_read,
    .disk_write_buffer=w_buffer,.disk_write=w_write,.disk_flush=w_flush,.disk_start=w_start,.disk_poll=w_poll,
    .disk_quiesce=w_quiesce};
static const struct ans_ops conv_ops={.ctx=0,.map=gmap,.frame_ref=refuse_ref,.publish=publish,.disk_read=w_read,
    .disk_write_buffer=w_buffer,.disk_write=w_write,.disk_flush=w_flush,.disk_start=w_start,.disk_poll=w_poll,
    .disk_quiesce=w_quiesce,.frame_refs=frame_refs};
static void lines(void)                           /* ans_route's NVMe level */
{
    int lv[3];ans_levels(st,lv);nvme_line=lv[2];
}

static void token_acquire(struct tctx *t)
{
    uint32_t ticket=guest_service_queue(&gate);
    enum guest_service_result r;
    while((r=guest_service_try_turn(&gate,t->cpu,ticket))!=SERVICE_OK) {CHECK(r==SERVICE_BUSY);FINE_RELAX();}
    while(!guest_service_drained(&gate))FINE_RELAX();
}
static void token_release(struct tctx *t) {CHECK(guest_service_release(&gate,t->cpu)==SERVICE_OK);}
/* fine_sptm_call's / fine_ans_mmio's L0: shared, bounded; 0 declines. */
static int gate_enter(struct tctx *t)
{
#ifdef MUTANT_NO_GATE
    (void)t;return 1;
#else
    enum guest_service_result r=guest_service_enter_shared(&gate,t->cpu);
    for(unsigned polls=0;r==SERVICE_BUSY;polls++) {
        if(polls>=4096) {guest_service_leave_shared(&gate,t->cpu);return 0;}
        FINE_RELAX();
        r=guest_service_wait_shared(&gate,t->cpu,0);
    }
    CHECK(r==SERVICE_OK);return 1;
#endif
}
static void gate_leave(struct tctx *t)
{
#ifndef MUTANT_NO_GATE
    guest_service_leave_shared(&gate,t->cpu);
#else
    (void)t;
#endif
}
static uint64_t lock_at;
static void ans_take(void)
{
#ifndef MUTANT_NO_ANS_LOCK
    fine_ticket_lock(&ans_lock);
#endif
    lock_at=now_ns();
}
static void ans_give(void)
{
    uint64_t h=now_ns()-lock_at;
    if(h>max_hold_ns)max_hold_ns=h;
#ifndef MUTANT_NO_ANS_LOCK
    fine_ticket_unlock(&ans_lock);
#endif
}
static void frames_begin(struct tctx *t)
{
    t->frames.locks=&frame_locks;t->frames.count=0;t->frames.exclusive=0;t->ref_fine.held=&t->frames;
}

/* ---- token-path and converted ANS calls ------------------------------------------------------------------ */
static void token_tick(struct tctx *t)            /* the locked tick's ans_async_tick */
{
    token_acquire(t);
    in_ans=1;CHECK(!ans_async_progress(st,&token_ops,ANS_ASYNC_STEP_MAX));in_ans=0;
    lines();
    t->token++;
    token_release(t);
}
static void token_mmio(struct tctx *t,uint64_t off,uint64_t v)
{
    token_acquire(t);
    in_ans=1;CHECK(!ans_mmio(st,&token_ops,1,off,4,1,&v));in_ans=0;
    lines();t->token++;
    token_release(t);
}
/* fine_ans_mmio: the I/O SQ doorbell and CQ head; a gate timeout declines to the token path. */
static void conv_mmio(struct tctx *t,uint64_t off,uint64_t v)
{
    if(!gate_enter(t)) {t->declined++;token_mmio(t,off,v);return;}
    ans_take();
    in_ans=1;int r=ans_mmio(st,&conv_ops,1,off,4,1,&v);in_ans=0;
#ifdef MUTANT_LINES_OUTSIDE_LOCK
    ans_give();
    if(!r)lines();
#else
    if(!r)lines();
    ans_give();
#endif
    gate_leave(t);
    CHECK(!r);t->conv++;
}
static uint64_t token_sptm(struct tctx *t,unsigned ep,const uint64_t x[6],int *err)
{
    uint64_t ret=0,xx[6];memcpy(xx,x,sizeof xx);
    token_acquire(t);
    in_ans=1;*err=ans_sptm(st,&token_ops,6,ep,xx,&ret);in_ans=0;
    lines();t->token++;
    if(*err) {CHECK(*err==ANS_E_FRAME && ep==1);st->refusal[0]=0;}   /* MAP of a frame a RETYPE took: refused */
    token_release(t);
    return ret;
}
/* fine_sptm_call + fine_ans_sptm: the gate, the call's frame locks, the ANS lock, ans_sptm_converted, the lines;
 * unlock, frame locks released, gate left; any decline repeats on the token path. */
static uint64_t conv_sptm(struct tctx *t,unsigned ep,const uint64_t x[6],int *err)
{
    if(!gate_enter(t)) {t->declined++;return token_sptm(t,ep,x,err);}
    frames_begin(t);
    ans_take();
    uint64_t ret=0;
    in_ans=1;int r=ans_sptm_converted(st,&conv_ops,ep,x,&ret);in_ans=0;
    if(!r || r==ANS_DECLINE || r==ANS_DECLINE_BUSY)lines();
    ans_give();
    sptm_frame_release(&t->frames);t->ref_fine.held=0;
    gate_leave(t);
    if(r==ANS_DECLINE || r==ANS_DECLINE_BUSY) {
        if(r==ANS_DECLINE_BUSY)t->busy++;
        t->declined++;
        return token_sptm(t,ep,x,err);
    }
    CHECK(!r);*err=0;t->conv++;
    return ret;
}
/* A converted RETYPE (probes/xnuboot.c fine_retype): the frame exclusive or decline; the real sptm_mac_retype. */
static unsigned retype_state[NDATA];
static void conv_retype(struct tctx *t,unsigned k)
{
    if(!gate_enter(t))return;
    frames_begin(t);
    uint64_t f=data_frame(k);
    struct sptm_memory m=memory(t);
    if(sptm_frame_exclusive(&t->frames,f)) {
        unsigned now=__atomic_load_n(&retype_state[k],__ATOMIC_RELAXED),from=now ? 20 : 11,to=now ? 11 : 20;
#ifdef MUTANT_UNPINNED_RETYPE
        /* N1's weakening: the type changes without the reference check. */
        enum sptm_result r=SPTM_OK;meta(f)[2]=(uint8_t)to;(void)m;(void)from;
#else
        enum sptm_result r=sptm_mac_retype(&m,f,from,to,to==20 ? 3 : 0);
#endif
        if(r==SPTM_OK) {__atomic_store_n(&retype_state[k],to==20,__ATOMIC_RELAXED);__atomic_fetch_add(&retypes_ok,1,__ATOMIC_RELAXED);}
        else {CHECK(r==SPTM_FRAME_BUSY || r==SPTM_TYPE_MISMATCH);__atomic_fetch_add(&retypes_busy,1,__ATOMIC_RELAXED);}
    }
    sptm_frame_release(&t->frames);t->ref_fine.held=0;
    gate_leave(t);
}
/* Another converted DMA user of the same frames (a DART map, say): one reference on this CPU's fine batch. */
static void conv_churn(struct tctx *t,unsigned k,int add,int ro)
{
    if(!gate_enter(t))return;
    frames_begin(t);
    struct sptm_memory m=memory(t);
    uint64_t f=data_frame(k);
    unsigned *mine=ro ? &churn_ro[k] : &churn_rw[k];
    if(add || __atomic_load_n(mine,__ATOMIC_RELAXED)) {
        sptm_refs_begin(m.refs);
        if(!(add ? sptm_refs_dart(&m,f,ro) : sptm_refs_dart_remove(&m,f,ro)) && !sptm_refs_validate(&m)) {
            sptm_refs_commit(&m);
            __atomic_fetch_add(mine,add ? 1u : (unsigned)-1,__ATOMIC_RELAXED);   /* inside the gate */
        }
    }
    sptm_frame_release(&t->frames);t->ref_fine.held=0;
    gate_leave(t);
}

/* ---- invariants (token held) ------------------------------------------------------------------------------ */
static void invariants(void)
{
    unsigned ro[NDATA]={0},rw[NDATA]={0},k;
    for(unsigned c=0;c<ANS_CIDS;c++) {
        const struct ans_cid *x=&st->cid[c];
        if(x->state!=3)continue;
        for(unsigned i=0;i<x->count;i++)
            if(is_data(x->prp[i],&k)) {
                if(x->dir&0x100)rw[k]++;else ro[k]++;
                CHECK(meta(data_frame(k))[2]==11);                 /* a mapped CID's frame stays XNU_DEFAULT */
            }
    }
    for(k=0;k<NDATA;k++) {
        uint64_t f=data_frame(k);
        CHECK(count_at(f,8)==ro[k]+__atomic_load_n(&churn_ro[k],__ATOMIC_RELAXED));
        CHECK(count_at(f,12)==rw[k]+__atomic_load_n(&churn_rw[k],__ATOMIC_RELAXED));
    }
    for(unsigned i=0;i<SPTM_FRAME_LOCKS;i++)CHECK(!__atomic_load_n(&frame_locks.word[i],__ATOMIC_RELAXED));
    CHECK(!fine_ticket_held(&ans_lock));
    const struct ans_async *a=&st->async;
    CHECK(a->counter[ANS_A_QUEUED]==a->counter[ANS_A_COMPLETED]+a->count+a->active);
    if(a->active)CHECK(st->cid[a->cur.cid].state==3);
    for(uint32_t i=0;i<a->count;i++)CHECK(st->cid[a->fifo[(a->head+i)%ANS_ASYNC_FIFO].cid].state==3);
    int lv[3];ans_levels(st,lv);CHECK(nvme_line==lv[2]);
    CHECK(!st->refusal[0]);
}

/* ---- the guest ---------------------------------------------------------------------------------------------- */
static uint32_t done_status[ANS_CIDS];
static unsigned done_flag[ANS_CIDS];
static unsigned long cqes;
static pthread_mutex_t guest_irq=PTHREAD_MUTEX_INITIALIZER;   /* the guest's own interrupt-handler lock */
static uint32_t cq_head;
/* The guest's NVMe interrupt: taken through the AIC acknowledge (the token path), the CQ consumed in order;
 * the head written there or by a converted 0x100c write. */
static void guest_irq_handler(struct tctx *t)
{
    pthread_mutex_lock(&guest_irq);
    token_acquire(t);
    unsigned n=0;
    if(nvme_line) {
        invariants();
        uint32_t size=st->cq[1].size;
        while(cq_head!=st->cq[1].tail) {
            uint32_t slot=cq_head;
            uint32_t dw3=*(uint32_t *)(void *)(ram+(IOCQ-BASE)+slot*16+12);
            unsigned cid=dw3&0xffff;
            CHECK(cid<ANS_CIDS && !__atomic_load_n(&done_flag[cid],__ATOMIC_RELAXED));
            done_status[cid]=dw3>>17;
            __atomic_store_n(&done_flag[cid],1,__ATOMIC_RELEASE);
            cq_head=(slot+1)%size;n++;
        }
    }
    uint64_t head=cq_head;
    int on_token=rand_r(&t->seed)&1;
    if(n && on_token) {in_ans=1;CHECK(!ans_mmio(st,&token_ops,1,0x100c,4,1,&head));in_ans=0;lines();}
    token_release(t);
    if(n && !on_token)conv_mmio(t,0x100c,head);
    __atomic_fetch_add(&cqes,n,__ATOMIC_RELAXED);
    pthread_mutex_unlock(&guest_irq);
}
static uint8_t stamp_of(unsigned cpu,uint64_t gen,uint64_t i) {return (uint8_t)(cpu*31+gen*7+i/4096*3+i);}
static uint64_t gen_of[CPUS][64];                 /* the stamp generation each 4 KiB block of a CPU's region holds */
static unsigned parked[CPUS];
static unsigned ops_per_cpu=400;
static unsigned long progress_beat;
static void *vcpu(void *arg)
{
    struct tctx *t=arg;self=t;
    for(unsigned n=0;n<ops_per_cpu;n++) {
        unsigned cid=t->cpu*10+rand_r(&t->seed)%10;
        unsigned op=rand_r(&t->seed)%10<6 ? 2 : rand_r(&t->seed)%5 ? 1 : 0;   /* reads, writes, flushes */
        unsigned blocks=op ? 1+rand_r(&t->seed)%8 : 0;                       /* up to 32 KiB: 2+ frames */
        uint64_t first=rand_r(&t->seed)%(64-blocks+1),lba=t->lba_base+first;
        uint64_t prp[ANS_PRPS];
        for(unsigned i=0;i<blocks;i++)prp[i]=DATA(t->cpu,i/4)+(uint64_t)(i%4)*0x1000;
        /* MAP_PAGES: TCB and PRP list in this CPU's page. */
        uint8_t *tcb=ram+(TCB(t->cpu)-BASE);
        memset(tcb,0,0x80);
        uint16_t dir=op==2 ? 0x100 : op==1 ? 0x200 : 0;
        tcb[1]=(uint8_t)(dir>>8);tcb[4]=(uint8_t)(blocks ? blocks-1 : 0);
        for(unsigned i=0;i<blocks;i++)memcpy(tcb+0x100+8*i,&prp[i],8);
        uint64_t x[6]={1,cid,TCB(t->cpu),TCB(t->cpu)+0x100,blocks,0};
        int err;
        conv_sptm(t,1,x,&err);
        if(err) {__atomic_fetch_add(&map_refused,1,__ATOMIC_RELAXED);continue;}   /* a frame a RETYPE holds */
        uint64_t gen=(uint64_t)n+1;
        if(op==1)for(unsigned i=0;i<blocks;i++)
            for(unsigned b=0;b<4096;b++)ram[prp[i]-BASE+b]=stamp_of(t->cpu,gen,(first+i)*4096+b);
        uint32_t sqe[16]={0};
        sqe[0]=op|cid<<16;sqe[1]=1;sqe[10]=(uint32_t)lba;sqe[11]=(uint32_t)(lba>>32);sqe[12]=blocks ? blocks-1 : 0;
        memcpy(ram+(IOSQ-BASE)+cid*64,sqe,64);
        __atomic_store_n(&done_flag[cid],0,__ATOMIC_RELAXED);
        conv_mmio(t,0x24910,cid);
        if(rand_r(&t->seed)%16==0) {
            /* N1: UNMAP_PAGES before the completion: the converted call declines BUSY (or the command already
             * finished), the token path drains it first; the CQE still reaches the guest exactly once. */
            uint64_t y[6]={1,cid,0,0,0,0};
            CHECK(conv_sptm(t,2,y,&err)==1 && !err);
            uint64_t t1=now_ns();
            while(!__atomic_load_n(&done_flag[cid],__ATOMIC_ACQUIRE)) {
                guest_irq_handler(t);
                CHECK(now_ns()-t1<20000000000u);
            }
            CHECK(done_status[cid]==0);
            if(op==1)for(unsigned i=0;i<blocks;i++)gen_of[t->cpu][first+i]=gen;
            __atomic_fetch_add(&early_unmaps,1,__ATOMIC_RELAXED);
            __atomic_fetch_add(&progress_beat,1,__ATOMIC_RELAXED);
            continue;
        }
        /* The wait: CQ-head writes, token ticks, or nothing at all (parked: the others' ticks must finish it). */
        unsigned style=rand_r(&t->seed)%3;
        __atomic_store_n(&parked[t->cpu],style==2,__ATOMIC_RELAXED);
        uint64_t t0=now_ns();
        while(!__atomic_load_n(&done_flag[cid],__ATOMIC_ACQUIRE)) {
            t->polls++;
            /* The monitor ticks every vCPU (at its deadline, at least every 1 ms); style 0 ticks seldom. */
            if(style==0) {if(!(t->polls%8))token_tick(t);guest_irq_handler(t);}
            else if(style==1) {token_tick(t);guest_irq_handler(t);}
            else sched_yield();
            int others=0;
            for(unsigned c=0;c<CPUS;c++)others|=c!=t->cpu && !__atomic_load_n(&parked[c],__ATOMIC_RELAXED);
            if(style==2 && (!others || now_ns()-t0>50000000u)) {token_tick(t);guest_irq_handler(t);}
            if(now_ns()-t0>=20000000000u) {
                const struct ans_async *a=&st->async;const struct nvmeh_state *ns=NSTATE;
                const struct ans_window_flight *w=(const void *)a->backend;
                fprintf(stderr,"stuck cpu%u cid %u style %u: active %u phys %u count %u cur %u op %u | flight op %llu i %llu n %llu phys %llu f.active %llu | nvmeh tail %llu head %llu phase %llu status %llu | device %u | cq1 tail %u head %u | done %u line %d\n",
                    t->cpu,cid,style,a->active,a->phys,a->count,a->cur.cid,a->op,(unsigned long long)w->op,(unsigned long long)w->i,
                    (unsigned long long)w->n,(unsigned long long)w->phys,(unsigned long long)w->f.active,(unsigned long long)ns->tail,(unsigned long long)ns->head,
                    (unsigned long long)ns->phase,(unsigned long long)ns->status,device_cmds,st->cq[1].tail,st->cq[1].head,done_flag[cid],nvme_line);
            }
            CHECK(now_ns()-t0<20000000000u);                       /* N3, N18: never a lost completion */
        }
        __atomic_store_n(&parked[t->cpu],0,__ATOMIC_RELAXED);
        CHECK(done_status[cid]==0);
        if(op==1)for(unsigned i=0;i<blocks;i++)gen_of[t->cpu][first+i]=gen;
        if(op==2)for(unsigned i=0;i<blocks;i++) {                 /* N4: the data is there when the CQE is */
            uint64_t g=gen_of[t->cpu][first+i];
            for(unsigned b=0;b<4096;b+=509) {
                uint64_t at=(lba+i)*4096+b;                       /* never written: the disk's first pattern */
                uint8_t want=g ? stamp_of(t->cpu,g,(first+i)*4096+b) : (uint8_t)(at*131u+(at>>12));
                CHECK(ram[prp[i]-BASE+b]==want);
            }
        }
        uint64_t y[6]={1,cid,0,0,0,0};
        CHECK(conv_sptm(t,2,y,&err)==1 && !err);
        /* The neighbours on the same frames. */
        unsigned k=rand_r(&t->seed)%NDATA;
        if(rand_r(&t->seed)%3==0) {               /* 11->20, back now or later */
            conv_retype(t,k);
            if(__atomic_load_n(&retype_state[k],__ATOMIC_RELAXED) && rand_r(&t->seed)%2)conv_retype(t,k);
        }
        if(rand_r(&t->seed)%2)conv_churn(t,k,rand_r(&t->seed)%3!=0,rand_r(&t->seed)&1);
        __atomic_fetch_add(&progress_beat,1,__ATOMIC_RELAXED);
    }
    /* Give back every churn reference this run left on the frames. */
    return 0;
}
static void *watchdog(void *arg)
{
    (void)arg;
    unsigned long last=~0UL;
    for(;;) {
        sleep(20);
        unsigned long b=__atomic_load_n(&progress_beat,__ATOMIC_RELAXED);
        if(b==last) {fprintf(stderr,"FAIL: no progress for 20 s (deadlock?)\n");_exit(1);}
        last=b;
    }
    return 0;
}

/* ---- setup: the driver's bring-up on the token path, single-threaded --------------------------------------- */
static void sptm6(unsigned ep,uint64_t a,uint64_t b,uint64_t c,uint64_t d,uint64_t e)
{
    uint64_t x[6]={a,b,c,d,e,0},ret;
    CHECK(!ans_sptm(st,&token_ops,6,ep,x,&ret));
}
static void admin(uint32_t op,uint32_t cdw10,uint32_t cdw11,uint64_t prp1)
{
    static unsigned acid=60;
    uint8_t *tcb=ram+(TCB(0)-BASE);memset(tcb,0,0x80);
    sptm6(1,0,acid,TCB(0),TCB(0)+0x100,0);
    uint32_t q[16]={0};q[0]=op|acid<<16;q[6]=(uint32_t)prp1;q[7]=(uint32_t)(prp1>>32);q[10]=cdw10;q[11]=cdw11;
    memcpy(ram+(ASQ-BASE)+acid*64,q,64);
    uint64_t v=acid;
    CHECK(!ans_mmio(st,&token_ops,1,0x2490c,4,1,&v));
    uint32_t dw3=*(uint32_t *)(void *)(ram+(ACQ-BASE)+st->cq[0].tail*16-16+12);
    CHECK((dw3>>17)==0);
    v=st->cq[0].tail;CHECK(!ans_mmio(st,&token_ops,1,0x1004,4,1,&v));
    sptm6(2,0,acid,0,0,0);
    acid=acid==63 ? 60 : acid+1;
}
static void setup(void)
{
    ram=aligned_alloc(0x4000,SIZE);res=aligned_alloc(0x100000,ANS_WINDOW_BYTES);
    CHECK(ram && res);
    memset(ram,0,SIZE);memset(res,0,ANS_WINDOW_BYTES);
    for(uint64_t pa=BASE;pa<BASE+SIZE;pa+=0x4000)meta(pa)[2]=11;
    st=(struct ans_state *)(void *)res;
    ans_reset(st,(uint64_t)BLOCKS*4096);
    for(unsigned i=0;i<sizeof disk;i++)disk[i]=(uint8_t)(i*131u+(i>>12));
    struct nvmeh_params *p=PARAMS;
    p->flags=NVMEH_F_ENABLE|NVMEH_F_WRITE;p->bar=(uint64_t)(uintptr_t)bar;p->dma_base=(uint64_t)(uintptr_t)(res+ANS_WINDOW_DMA);
    p->io_next_cid=1;p->io_phase=1;p->lba_bytes=512;p->first_lba=FIRST;p->last_lba=FIRST+BLOCKS*8-1;
    p->max_transfer=128*1024;p->timeout_ticks=5000000000u;
    p->write_first_lba=FIRST+256*8;p->write_last_lba=p->last_lba-256*8;
    bar[0x14/4]=0x460001;bar[0x1c/4]=1;bar[0x24/4]=(NVMEH_ADMIN_ENTRIES-1)<<16|(NVMEH_ADMIN_ENTRIES-1);
    uint64_t asq=p->dma_base+NVMEH_ASQ,acq=p->dma_base+NVMEH_ACQ;
    bar[0x28/4]=(uint32_t)asq;bar[0x2c/4]=(uint32_t)(asq>>32);bar[0x30/4]=(uint32_t)acq;bar[0x34/4]=(uint32_t)(acq>>32);
    CHECK(!nvmeh_adopt(&hops,p,NSTATE,BASE,BASE+SIZE));
    /* The SPTM's bootstrap of the controller (tools/test-ans.c sptm_setup, ioqueues_up). */
    sptm6(3,64,2,0,0,0);sptm6(0,0,0,0,0,0);sptm6(4,ASQ,63,ACQ,63,0);sptm6(5,64,64,0,0,0);
    uint64_t v=0x460001;CHECK(!ans_mmio(st,&token_ops,1,0x14,4,1,&v));
    sptm6(7,IOCQ,0,0,0,0);admin(0x05,0x00400001,0x3,IOCQ);
    sptm6(6,IOSQ,0,0,0,0);admin(0x01,0x00400001,0x00010001,IOSQ);
    CHECK(st->ioq==(ANS_IOQ_CQ|ANS_IOQ_SQ|ANS_IOQ_IEN));
    for(unsigned c=0;c<CPUS;c++) {
        tc[c].cpu=c;tc[c].seed=0;tc[c].lba_base=256+(uint64_t)c*64;   /* SSD blocks, inside the write range */
        gate.lifecycle|=(uint64_t)EXECUTOR_RUNNING<<(c*3);
    }
}

int main(int argc,char **argv)
{
    if(argc>1)ops_per_cpu=(unsigned)atoi(argv[1]);
    unsigned seed=argc>2 ? (unsigned)atoi(argv[2]) : 1;
    setup();
    for(unsigned c=0;c<CPUS;c++)tc[c].seed=seed*977+c*7919+1;
    pthread_t th[CPUS],dev,wd;
    CHECK(!pthread_create(&dev,0,device,0));
    CHECK(!pthread_create(&wd,0,watchdog,0));
    for(unsigned c=0;c<CPUS;c++)CHECK(!pthread_create(&th[c],0,vcpu,&tc[c]));
    for(unsigned c=0;c<CPUS;c++)pthread_join(th[c],0);
    /* Quiescence: the churn's references back, then everything zero. */
    self=&tc[0];
    for(unsigned k=0;k<NDATA;k++)
        for(int ro=0;ro<2;ro++)while(__atomic_load_n(ro ? &churn_ro[k] : &churn_rw[k],__ATOMIC_RELAXED))conv_churn(&tc[0],k,0,ro);
    for(unsigned k=0;k<NDATA;k++)if(retype_state[k]) {conv_retype(&tc[0],k);CHECK(!retype_state[k]);}
    token_acquire(&tc[0]);
    invariants();
    for(unsigned k=0;k<NDATA;k++)CHECK(!count_at(data_frame(k),8) && !count_at(data_frame(k),12) && meta(data_frame(k))[2]==11);
    const struct ans_async *a=&st->async;
    CHECK(!a->active && !a->count && a->counter[ANS_A_QUEUED]==a->counter[ANS_A_COMPLETED]);
    CHECK(__atomic_load_n(&cqes,__ATOMIC_RELAXED)==a->counter[ANS_A_COMPLETED]);
    CHECK(!unpinned_writes && pinned_writes);
    token_release(&tc[0]);
    __atomic_store_n(&device_stop,1,__ATOMIC_RELEASE);pthread_join(dev,0);
    CHECK(!gate.owner && !guest_service_readers(&gate));
    unsigned long conv=0,token=0,declined=0,busy=0;
    for(unsigned c=0;c<CPUS;c++) {conv+=tc[c].conv;token+=tc[c].token;declined+=tc[c].declined;busy+=tc[c].busy;}
    printf("PASS test-ans-converted: %u checks; %llu commands (%llu physical, %u SSD), %lu converted calls, "
           "%lu token calls, %lu declines (%lu busy unmaps), %lu MAPs refused on retyped frames, retypes %lu ok / "
           "%lu refused, %lu pinned completion writes, %lu unmaps before completion, max ANS hold %lu us\n",
           checks,(unsigned long long)a->counter[ANS_A_COMPLETED],(unsigned long long)a->counter[ANS_A_PHYSICAL],
           device_cmds,conv,token,declined,busy,map_refused,retypes_ok,retypes_busy,pinned_writes,early_unmaps,max_hold_ns/1000);
    return 0;
}

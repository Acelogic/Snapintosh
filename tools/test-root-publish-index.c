/* SPDX-License-Identifier: MIT */
/* SNAP_INCREMENTAL_PUBLISH (shadow/root-publish-index.h): two monitors run
 * the same operation stream -- arena stores and allocations with their notes,
 * pointer-range notes, private user-view publication, root installation and
 * transaction-end flushes, injected callback failures -- one with the bitmap
 * flushes it replaces, one with the index. After every operation the publish
 * callback sequences, return values, bitmaps, every root/transaction counter
 * (the stopped readers' volume checks use them) and the PoC images must be
 * identical, and after every successful root flush the PoC image must equal
 * the CPU image (an independent whole-arena publisher).
 *
 * Failure inventory: a noted page missing from the index (unpublished table);
 * a page published twice or out of order; a page whose bit the private
 * publisher cleared still published; a runtime page missed or doubled; bits
 * cleared on a failed callback; counters diverging; index overflow or long
 * lists; the sentinel path diverging; allocation growth between flushes;
 * VERIFY missing an invariant break; the listed flush still walking the whole
 * bitmap (scan-bound regression below; -DINDEX_PRE_CHANGE=1 runs it against
 * root_publish_flush, which must fail).
 *
 * cc -std=gnu11 -O2 -g -fsanitize=address,undefined -fno-sanitize-recover=all \
 *    -Icompat -Ishadow tools/test-root-publish-index.c -o build/test-root-publish-index
 * Add -DSNAP_INCREMENTAL_PUBLISH_VERIFY=1 for the verified flush, or build with
 * -O2 and no sanitizer and pass --bench for host timings of both flushes. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "../shadow/root-publish-index.h"
#include "../shadow/user-publish.h"
#ifndef INDEX_PRE_CHANGE
#define INDEX_PRE_CHANGE 0
#endif

static unsigned long long checks;
#define CHECK(x) do {checks++;if(!(x)){fprintf(stderr,"line %d: %s\n",__LINE__,#x);exit(1);}}while(0)
#define PAGES 6144u
#define BASE UINT64_C(0xae1400000)
#define RUNTIME_FIRST 40u
#define RUNTIME_PAGES 97u

struct side {
    struct root_publish_state s;struct root_publish_index x;struct txn_publish_stats t;
    struct user_publish_stats u;
    unsigned char bus[PAGES*4096];
    uint64_t seq[ROOT_PUBLISH_PAGES];unsigned calls,fail;
};
static unsigned char cpu[PAGES*4096];
static struct side A,B;             /* A: bitmap flushes, B: index flushes */
static struct sprr_private_pages priv;
static unsigned allocated;          /* arena pages in use (next_table) */
static unsigned guard[PAGES];
static uint64_t rng=UINT64_C(0x2545f4914f6cdd1d);
static unsigned rnd(unsigned n) {rng^=rng<<13;rng^=rng>>7;rng^=rng<<17;return (unsigned)(rng%n);}

static int publish(void *ctx,uint64_t pa)
{
    struct side *s=ctx;
    CHECK(!(pa&4095) && pa>=BASE && pa-BASE<(uint64_t)PAGES*4096);
    CHECK(s->calls<ROOT_PUBLISH_PAGES);s->seq[s->calls++]=pa;
    if(s->fail && s->calls==s->fail)return 0;
    memcpy(s->bus+(pa-BASE),cpu+(pa-BASE),4096);
    return 1;
}
static int exclude(void *ctx,uint64_t pa) {(void)ctx;return guard[(pa-BASE)/4096];}
static uint64_t hash(uint64_t pa)
{
    uint64_t h=UINT64_C(0xcbf29ce484222325);const unsigned char *p=cpu+(pa-BASE);
    for(unsigned i=0;i<4096;i+=8) {uint64_t w;memcpy(&w,p+i,8);h=(h^w)*UINT64_C(0x100000001b3);}
    return h;
}
static uint64_t limit(void) {return BASE+(uint64_t)allocated*4096;}
static void same(void)
{
    CHECK(A.calls==B.calls && !memcmp(A.seq,B.seq,A.calls*sizeof *A.seq));
    CHECK(!memcmp(A.s.bitmap,B.s.bitmap,sizeof A.s.bitmap));
    CHECK(A.s.notes==B.s.notes && A.s.pages_noted==B.s.pages_noted && A.s.calls==B.s.calls &&
          A.s.complete==B.s.complete && A.s.considered==B.s.considered &&
          A.s.published==B.s.published && A.s.skipped==B.s.skipped && A.s.errors==B.s.errors);
    CHECK(!memcmp(&A.t,&B.t,sizeof A.t) && !memcmp(&A.u,&B.u,sizeof A.u));
}
static void begin(void) {A.calls=B.calls=0;}
static void note(uint64_t pa,uint64_t size)
{
    int a=root_publish_note(&A.s,BASE,limit(),pa,size);
    int b=root_index_note(&B.s,&B.x,BASE,limit(),pa,size);
    CHECK(a==b);
    txn_publish_observe(&A.t,pa,size);txn_publish_observe(&B.t,pa,size);
}
static void store(unsigned offset,uint64_t value)
{
    uint64_t old;memcpy(&old,cpu+offset,8);
    if(old!=value)note(BASE+offset,8);
    memcpy(cpu+offset,&value,8);
}
static void allocate(unsigned page)
{
    note(BASE+(uint64_t)page*4096,4096);
    memset(cpu+(size_t)page*4096,0,4096);
    sprr_private_clear(&priv,page,0);
    if(rnd(3)==0)sprr_private_mark(&priv,page);
}
static int root_flush(void)
{
    begin();
    int a=root_publish_flush(&A.s,BASE,limit(),publish,&A);
#if INDEX_PRE_CHANGE
    int b=root_publish_flush(&B.s,BASE,limit(),publish,&B);
#else
    int b=root_index_flush(&B.s,&B.x,BASE,limit(),publish,&B);
#endif
    CHECK(a==b);same();
    for(unsigned n=1;n<B.calls;n++)CHECK(B.seq[n]>B.seq[n-1]);
    if(a && !A.fail)CHECK(!memcmp(B.bus,cpu,(size_t)allocated*4096));
    return a;
}
static int txn_flush(void)
{
    begin();
    int a=txn_publish_flush_with(&A.s,&A.t,BASE,limit(),publish,exclude,&A,hash);
    int b=txn_index_flush_with(&B.s,&B.x,&B.t,BASE,limit(),publish,exclude,&B,hash);
    CHECK(a==b);same();
    if(a && !A.fail)CHECK(!memcmp(B.bus,cpu,(size_t)allocated*4096));
    return a;
}
static void user_flush(void)
{
    uint64_t pages[USER_PUBLISH_MAX];unsigned count=0;
    for(unsigned tries=0;tries<400 && count<1+rnd(40);tries++) {
        unsigned p=rnd(allocated);
        if(!(priv.bitmap[p/64]&(UINT64_C(1)<<(p%64))))continue;
        int dup=0;for(unsigned k=0;k<count;k++)dup|=pages[k]==BASE+(uint64_t)p*4096;
        if(!dup)pages[count++]=BASE+(uint64_t)p*4096;
    }
    if(!count)return;
    begin();
    int a=user_publish_flush(&A.s,&priv,&A.u,BASE,limit(),pages,count,publish,&A);
    int b=user_publish_flush(&B.s,&priv,&B.u,BASE,limit(),pages,count,publish,&B);
    CHECK(a==b);same();
}
static void reset(void)
{
    memset(&A,0,sizeof A);memset(&B,0,sizeof B);memset(&priv,0,sizeof priv);
    memset(cpu,0xa5,sizeof cpu);memset(guard,0,sizeof guard);
    allocated=RUNTIME_FIRST+RUNTIME_PAGES+64;
    A.s.always_first=B.s.always_first=BASE+(uint64_t)RUNTIME_FIRST*4096;
    A.s.always_end=B.s.always_end=BASE+(uint64_t)(RUNTIME_FIRST+RUNTIME_PAGES)*4096;
    for(unsigned p=0;p<allocated;p++)if(p<RUNTIME_FIRST || p>=RUNTIME_FIRST+RUNTIME_PAGES)allocate(p);
    guard[3]=guard[7]=1;
    CHECK(root_flush());
}

static unsigned listed_root,scanned_root,listed_txn,scanned_txn,failures,overflows;
static void stream(unsigned turns)
{
    reset();
    for(unsigned turn=0;turn<turns;turn++) {
        uint64_t listed=B.x.listed,scanned=B.x.scanned,tl=B.x.txn_listed,ts=B.x.txn_scanned;
        uint64_t over=B.x.overflows;
        unsigned ops=1+rnd(rnd(8)==0 ? 400 : 12);
        for(unsigned n=0;n<ops;n++) {
            unsigned kind=rnd(20);
            if(kind<11) {             /* table store through mem_write */
                unsigned page=rnd(8)==0 ? rnd(allocated) : rnd(64)+RUNTIME_FIRST+RUNTIME_PAGES;
                if(page>=allocated)page=allocated-1;
                if(page>=RUNTIME_FIRST && page<RUNTIME_FIRST+RUNTIME_PAGES)continue;
                store(page*4096+8*rnd(512),rnd(3) ? ((uint64_t)rnd(1u<<30)<<12)|3 : 0);
            } else if(kind<13) {      /* allocation (sometimes a whole shadow build) or reuse */
                if(allocated<PAGES && rnd(2)) {
                    unsigned count=rnd(50)==0 ? 1+rnd(600) : 1;
                    while(count-- && allocated<PAGES)allocate(allocated++);
                }
                else {
                    unsigned page=rnd(allocated);
                    if(page<RUNTIME_FIRST || page>=RUNTIME_FIRST+RUNTIME_PAGES)allocate(page);
                }
            } else if(kind<15) {      /* sptm_shadow_map pointer range, may straddle */
                unsigned first=rnd(allocated);
                uint64_t off=(uint64_t)first*4096+rnd(4096);
                uint64_t size=1+(rnd(60)==0 ? (uint64_t)rnd(allocated)*4096 : rnd(9000));
                if(off+size>(uint64_t)allocated*4096)size=(uint64_t)allocated*4096-off;
                note(BASE+off,size);
                if(rnd(2))memset(cpu+off,(int)rnd(256),size);
            } else if(kind<16) {      /* runtime memory: no note (VNCR, stacks) */
                memset(cpu+(size_t)(RUNTIME_FIRST+rnd(RUNTIME_PAGES))*4096+rnd(4000),(int)rnd(256),64);
            } else if(kind<18)user_flush();
            else if(kind<19) {        /* guard store: cleans its own line */
                unsigned g=rnd(8);if(guard[g]) {
                    unsigned off=g*4096+64*rnd(64);
                    memset(cpu+off,0x5a,64);memcpy(A.bus+off,cpu+off,64);memcpy(B.bus+off,cpu+off,64);
                }
            } else note(BASE+(uint64_t)rnd(allocated)*4096,4096);
        }
        if(turn%997==500) {
            /* More newly set pages than the index holds: a large shadow build
             * plus private-view re-notes (duplicates after a partial clear). */
            while(allocated<4400)allocate(allocated++);
            user_flush();
            for(unsigned p=0;p<allocated;p++)
                if(p<RUNTIME_FIRST || p>=RUNTIME_FIRST+RUNTIME_PAGES)note(BASE+(uint64_t)p*4096,8);
        }
        if(rnd(40)==0)A.fail=B.fail=1+rnd(8);
        int ok=rnd(3)==0 ? txn_flush() : root_flush();
        listed_root+=(unsigned)(B.x.listed-listed);scanned_root+=(unsigned)(B.x.scanned-scanned);
        listed_txn+=(unsigned)(B.x.txn_listed-tl);scanned_txn+=(unsigned)(B.x.txn_scanned-ts);
        overflows+=(unsigned)(B.x.overflows-over);
        if(A.fail) {
            /* Both refused at the same callback with every bit retained. */
            CHECK(!ok || A.calls<A.fail);
            failures+=!ok;
            A.fail=B.fail=0;
            /* Errors latch per structure (root bitmap or transaction
             * stats); later flushes of both monitors must still agree. */
            if(!ok) {root_flush();txn_flush();reset();}
        } else CHECK(ok);
    }
}

/* SNAP_INCREMENTAL_PUBLISH_VERIFY: a bit set without the index (an invariant
 * break) is caught before any publication; without VERIFY the listed flush
 * does not read that word at all -- which is also the scan-bound property. */
static void invariant_break(void)
{
    reset();
    store((RUNTIME_FIRST+RUNTIME_PAGES+5)*4096,0x1234);
    unsigned stray=RUNTIME_FIRST+RUNTIME_PAGES+9;
    B.s.bitmap[stray/64]|=UINT64_C(1)<<(stray%64);
    begin();
    int ok=root_index_flush(&B.s,&B.x,BASE,limit(),publish,&B);
#if SNAP_INCREMENTAL_PUBLISH_VERIFY
    CHECK(!ok && B.x.mismatches==1 && B.s.errors==1 && !B.calls);
#else
    CHECK(ok && B.calls==RUNTIME_PAGES+1);
    CHECK(B.s.bitmap[stray/64]&(UINT64_C(1)<<(stray%64)));
#endif
}
/* Regression: a root installation with k noted pages must not depend on bitmap
 * words outside those pages. A stray bit planted beyond the allocation (which
 * only a whole-bitmap walk can see) must not affect the listed flush. The
 * bitmap flush it replaces walks every word and refuses: INDEX_PRE_CHANGE=1. */
static void scan_bound(void)
{
    reset();
    for(unsigned k=0;k<4;k++)store((RUNTIME_FIRST+RUNTIME_PAGES+3*k)*4096+64,0x77+k);
    unsigned beyond=PAGES+100;
    B.s.bitmap[beyond/64]|=UINT64_C(1)<<(beyond%64);
    begin();
#if INDEX_PRE_CHANGE
    int ok=root_publish_flush(&B.s,BASE,limit(),publish,&B);
#else
    int ok=root_index_flush(&B.s,&B.x,BASE,limit(),publish,&B);
#endif
#if SNAP_INCREMENTAL_PUBLISH_VERIFY
    CHECK(!ok);   /* the verified flush does walk the bitmap, by design */
#else
    CHECK(ok && B.calls==RUNTIME_PAGES+4 && B.s.published>0);
#endif
    B.s.bitmap[beyond/64]=0;
}

/* Host cost of both flushes at the installed-run density: 58,495 allocated
 * pages, the 97-page runtime range, and 3-4 noted pages per installation. */
static double now(void) {struct timespec t;clock_gettime(CLOCK_MONOTONIC,&t);return t.tv_sec+t.tv_nsec*1e-9;}
static int nop(void *ctx,uint64_t pa) {(void)ctx;(void)pa;return 1;}
static void bench(void)
{
    static struct root_publish_state s;static struct root_publish_index x;
    const unsigned pages=58495,iterations=200000;
    uint64_t first=BASE,alloc=BASE+(uint64_t)pages*4096;
    double t[2];
    for(unsigned mode=0;mode<2;mode++) {
        memset(&s,0,sizeof s);memset(&x,0,sizeof x);
        s.always_first=first+(uint64_t)51000*4096;s.always_end=s.always_first+97*4096;
        double start=now();
        for(unsigned i=0;i<iterations;i++) {
            for(unsigned k=0;k<3+(i&1);k++) {
                uint64_t pa=first+(uint64_t)((i*7919u+k*104729u)%pages)*4096;
                if(mode)root_index_note(&s,&x,first,alloc,pa,8);
                else root_publish_note(&s,first,alloc,pa,8);
            }
            int ok=mode ? root_index_flush(&s,&x,first,alloc,nop,0) :
                          root_publish_flush(&s,first,alloc,nop,0);
            if(!ok)exit(2);
        }
        t[mode]=(now()-start)/iterations*1e6;
    }
    printf("{\"pages\":%u,\"runtime_pages\":97,\"noted_per_flush\":3.5,"
           "\"bitmap_flush_us\":%.3f,\"index_flush_us\":%.3f}\n",pages,t[0],t[1]);
}

int main(int argc,char **argv)
{
    if(argc==2 && !strcmp(argv[1],"--bench")) {bench();return 0;}
    scan_bound();
    invariant_break();
    stream(20000);
    CHECK(listed_root>1000 && scanned_root>10 && listed_txn>500 && scanned_txn>5);
    printf("stats: failures %u overflows %u listed %u scanned %u txn %u/%u\n",failures,overflows,listed_root,scanned_root,listed_txn,scanned_txn);
    CHECK(failures>50 && overflows>0);
#if SNAP_INCREMENTAL_PUBLISH_VERIFY
    CHECK(B.x.verified>0 && !B.x.mismatches);
#endif
    printf("PASS: %llu index checks; root flushes listed %u scanned %u, txn listed %u scanned %u, "
           "%u injected failures, %u overflows%s\n",checks,listed_root,scanned_root,listed_txn,
           scanned_txn,failures,overflows,SNAP_INCREMENTAL_PUBLISH_VERIFY ? ", verified" : "");
    return 0;
}

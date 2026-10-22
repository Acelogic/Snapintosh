/* SPDX-License-Identifier: MIT */
/* SNAP_UPDATE_DISJOINT_FAST (compat/update-fast.h A1-A4, V1-V3). Built and
 * mutated by tools/test-update-disjoint-fast.py (-DSNAP_UPDATE_DISJOINT_FAST=1).
 *  1. V1/V2: sprr_views_verify_all equals the conjunction of
 *     sprr_views_verify_cpu over six CPUs on random kernel-shaped views
 *     (levels 0-3, shared branches, blocks, selector 2/4 leaves, per-CPU
 *     PPERM) under random corruptions of copies, sources, copy pointers,
 *     levels and PPERMs.
 *  2. A1-A3: a TLB model (a walk may cache any valid leaf with AF set, never
 *     one with AF clear) over random leaf histories: with the skip rule no
 *     cached translation ever differs from its leaf after an update returns.
 *  3. The real UPDATE_DISJOINT engine on the observed XNU transition pair
 *     (...e43 <-> ...ac3, options 0xa / 0xc0a) hands commit_update the old
 *     guest leaf the rule reads: AF set when clearing, AF clear when setting. */
#define main sptm_user_fixture_main
#include "test-sptm-user.c"
#undef main
#include <stdlib.h>
#include "shadow.h"
#include "sprr-view.h"
#include "update-fast.h"
#if !SNAP_UPDATE_DISJOINT_FAST
#error "build with -DSNAP_UPDATE_DISJOINT_FAST=1"
#endif
#define CHECK(x) do { checks++;if(!(x)){fprintf(stderr,"FAIL %d: %s\n",__LINE__,#x);exit(1);} } while(0)
static uint64_t rng=0x9e3779b97f4a7c15UL;
static unsigned rnd(unsigned n) {rng^=rng<<13;rng^=rng>>7;rng^=rng<<17;return (unsigned)(rng%n);}

/* ---- 1. one-pass verification ------------------------------------------ */
#define HB 0x40000000UL
#define HPAGES 2048u
static uint8_t *hmem;static uint64_t hnext;
static int hread(void *c,uint64_t pa,uint64_t *v)
{(void)c;if(pa<HB || pa>=HB+HPAGES*4096UL || (pa&7))return -1;memcpy(v,hmem+(pa-HB),8);return 0;}
static int hwrite(void *c,uint64_t pa,uint64_t v)
{(void)c;if(pa<HB || pa>=HB+HPAGES*4096UL || (pa&7))return -1;memcpy(hmem+(pa-HB),&v,8);return 0;}
static uint64_t halloc(void *c)
{(void)c;if(hnext>=HPAGES)return 0;uint64_t pa=HB+hnext*4096UL;hnext++;memset(hmem+(pa-HB),0,4096);return pa;}
static void hset(uint64_t pa,uint64_t v) {memcpy(hmem+(pa-HB),&v,8);}
static uint64_t hget(uint64_t pa) {uint64_t v;memcpy(&v,hmem+(pa-HB),8);return v;}
/* A kernel leaf of SPRR class `cls` (AP and PXN/UXN encode it). */
static uint64_t kleaf(unsigned cls)
{return (((uint64_t)(cls>>2)&3)<<6)|((uint64_t)(cls&3)<<53)|0x703UL;}
static const unsigned classes[]={0,3,2,4,1,8,12,15};
static int all_cpus(struct sprr_views *v,const struct shadow *s,const uint64_t *pp)
{
    int ok=1;
    for(unsigned cpu=0;cpu<SPRR_VIEW_CPUS;cpu++)ok&=sprr_views_verify_cpu(v,s,cpu,pp[cpu]);
    return ok;
}
static void one_pass_verification(void)
{
    hmem=calloc(HPAGES,4096);
    unsigned trials=0,accepted=0,refused=0;
    for(unsigned trial=0;trial<1200;trial++) {
        hnext=1;
        struct shadow s={.txsz=17,.root=halloc(0),.alloc=halloc,.read=hread,.write=hwrite};
        uint64_t base=UINT64_C(0x7e0000000000);
        unsigned regions=2+rnd(6),pages=0;uint64_t first[8]={0};
        for(unsigned g=0;g<regions;g++)for(unsigned r=0;r<1+rnd(4);r++)
            for(unsigned i=0;i<8+rnd(40);i++) {
                uint64_t va=base+((uint64_t)g<<30)+((uint64_t)r<<21)+(uint64_t)rnd(512)*4096;
                if(!first[g])first[g]=va;
                uint64_t leaf=kleaf(classes[rnd(8)]);
                pages+=!shadow_map(&s,va,0x900000000UL+(uint64_t)rnd(1u<<16)*4096,4096,leaf&0xfff,leaf&(PT_PXN|PT_UXN));
            }
        CHECK(pages>0);
        /* A block mapping beside the tables (decoded as a level-2 leaf). */
        if(rnd(2))CHECK(!shadow_map(&s,base+((uint64_t)7<<30)+((uint64_t)300<<21),0xa00000000UL,
                                    1UL<<21,kleaf(3)&0xfff,PT_PXN|PT_UXN));
        struct sprr_views v;memset(&v,0,sizeof v);
        CHECK(sprr_views_init(&v,&s));
        /* Copy some paths; the rest stay shared branches of the canonical tree. */
        for(unsigned g=0;g<regions;g++)if(rnd(3))
            CHECK(sprr_views_prepare(&v,&s,first[g]));
        uint64_t pp[SPRR_VIEW_CPUS];
        for(unsigned cpu=0;cpu<SPRR_VIEW_CPUS;cpu++) {
            pp[cpu]=SPRR_PPERM_INITIAL|(rnd(2) ? UINT64_C(0x100):0);
            CHECK(sprr_views_sync_cpu(&v,&s,cpu,pp[cpu]));
        }
        CHECK(sprr_views_verify_all(&v,&s,pp) && all_cpus(&v,&s,pp));
        /* One corruption (or none), then the two verdicts must agree. */
        unsigned n=rnd((unsigned)v.count),cpu=rnd(SPRR_VIEW_CPUS),i=rnd(512);
        switch(rnd(10)) {
        case 0: break;
        case 1: hset(v.tables[n].copy[cpu]+8*i,hget(v.tables[n].copy[cpu]+8*i)^(1UL<<rnd(64)));break;
        case 2: hset(v.tables[n].source+8*i,hget(v.tables[n].source+8*i)^(1UL<<rnd(64)));break;
        case 3: v.tables[n].copy[cpu]=0;break;
        case 4: v.tables[n].copy[cpu]|=8;break;
        case 5: pp[cpu]^=UINT64_C(0x100);break;   /* stale for selector-2 leaves */
        case 6: pp[cpu]^=UINT64_C(1)<<rnd(64);break;
        case 7: v.tables[n].level=rnd(5);break;
        case 8: v.tables[n].source|=8;break;
        case 9: { /* the same word on every CPU's copy: per-CPU decodes still differ */
            for(unsigned c=0;c<SPRR_VIEW_CPUS;c++)
                hset(v.tables[n].copy[c]+8*i,hget(v.tables[n].copy[c]+8*i)^PT_AF);
            break; }
        }
        int want=all_cpus(&v,&s,pp),got=sprr_views_verify_all(&v,&s,pp);
        CHECK(got==want);
        trials++;accepted+=got;refused+=!got;
        if(want && trial%8==0) {
            /* A misaligned copy pointer whose bytes hold the right words:
             * refused for its alignment alone. */
            uint64_t moved=halloc(0),spare=halloc(0);
            CHECK(moved && spare==moved+4096);
            memcpy(hmem+(moved+8-HB),hmem+(v.tables[n].copy[cpu]-HB),4096);
            uint64_t saved=v.tables[n].copy[cpu];v.tables[n].copy[cpu]=moved+8;
            CHECK(!all_cpus(&v,&s,pp) && !sprr_views_verify_all(&v,&s,pp));
            v.tables[n].copy[cpu]=saved;
            CHECK(all_cpus(&v,&s,pp) && sprr_views_verify_all(&v,&s,pp));
        }
    }
    CHECK(accepted>100 && refused>100);
    printf("one pass: %u random views and corruptions agree with six per-CPU verifications "
           "(%u accepted, %u refused)\n",trials,accepted,refused);
    free(hmem);
}

/* ---- 2. the skip rule against a TLB model ------------------------------ */
#define VAS 4u
static uint64_t leaf_now[VAS],tlb[VAS];static int cached[VAS];
static void tlb_walk(unsigned va)
{
    /* Architecture: an entry that would fault (invalid, or AF clear with
     * hardware AF updates off) is never cached; any other one may be. */
    if((leaf_now[va]&3)==3 && (leaf_now[va]&PT_AF) && rnd(2)) {tlb[va]=leaf_now[va];cached[va]=1;}
}
static void tlb_model(void)
{
    unsigned skipped=0,flushed=0;
    memset(leaf_now,0,sizeof leaf_now);memset(cached,0,sizeof cached);
    for(unsigned step=0;step<400000;step++) {
        unsigned va=rnd(VAS);
        if(rnd(3)) {tlb_walk(va);continue;}
        uint64_t old=leaf_now[va],next;
        switch(rnd(6)) {
        case 0: next=0;break;                                         /* unmap */
        case 1: next=0x0060000000000403UL|((uint64_t)rnd(1u<<12)<<14);break; /* map, AF set */
        case 2: next=old^PT_AF;break;                                 /* reference emulation */
        case 3: next=(old&~PT_AF)|(2UL<<6);break;                     /* clear AF, write-protect */
        case 4: next=old|PT_AF;break;
        default: next=old^(1UL<<rnd(12));break;
        }
        if((old&3)!=3 && (next&3)!=3) {leaf_now[va]=next;continue;}
        leaf_now[va]=next;
        /* Only a committed user leaf update (a valid old leaf) may skip;
         * every other transition invalidates, as the monitor does. */
        int skip=(old&3)==3 && update_fast_uncached(old);
        if(skip)skipped++;
        else {cached[va]=0;flushed++;}
        /* After the call returns: no stale translation. */
        for(unsigned a=0;a<VAS;a++)if(cached[a])CHECK(tlb[a]==leaf_now[a]);
    }
    CHECK(skipped>1000 && flushed>1000);
    printf("TLB model: 400000 steps, %u updates skipped their TLBI, %u invalidated, no stale translation\n",
           skipped,flushed);
}

/* ---- 3. what the real engine hands commit_update ------------------------ */
static uint64_t seen_old,seen_next;static unsigned commits;
static int rec_prepare(void *ctx,uint64_t root,uint64_t va,unsigned shift,uint64_t old,uint64_t next)
{(void)ctx;(void)root;(void)va;(void)shift;(void)old;(void)next;return 1;}
static int rec_commit(void *ctx,uint64_t root,uint64_t va,unsigned shift,uint64_t old,uint64_t next)
{(void)ctx;(void)root;(void)va;(void)shift;seen_old=old;seen_next=next;commits++;return 1;}
static int resolve(void *ctx,uint64_t root,struct sptm_user_backend *b)
{(void)ctx;(void)root;*b=backend;b->prepare_update=rec_prepare;b->commit_update=rec_commit;return 1;}
static void engine_pair(void)
{
    /* The observed v33 pair: RW+AF+nG <-> RO with AF clear (and bit 59). An
     * ordinary level-3 table and DEFAULT frame beside the commpage fixture. */
    const uint64_t rw=0x0060000000000e43UL,ro=0x0860000000000ac3UL,va2=0x800000000UL;
    const uint64_t l3=BASE+0x18000,data=BASE+0x1c000,list=BASE+0x20000,scratch=BASE+0x1000;
    struct sptm_memory m=reset(31);uint64_t result=1;
    check(sptm_mac_retype(&m,l3,11,20,3)==SPTM_OK,"ordinary level-3 table");
    check(sptm_mac_map_user_table(&m,ROOT,va2,2,l3|3)==SPTM_OK,"ordinary table link");
    check(sptm_mac_map_user_page(&m,&backend,ROOT,va2,data|rw,1,0,&result)==SPTM_OK && !result,
          "DEFAULT user leaf");
    uint64_t leaf=l3+8*mmu_index(14,3,va2);
    for(unsigned round=0;round<4;round++) {
        unsigned set=round&1;
        struct {uint64_t root,va,req;} rec={ROOT,va2,data|(set ? rw : ro)};
        memcpy(ram+(list-BASE),&rec,24);
        uint64_t before=get(leaf,8);commits=0;
        check(sptm_mac_update_user_disjoint(&m,resolve,0,data,list,1,set ? 0xc0a:0xa,scratch,
                                            &result,0)==SPTM_OK,"observed XNU update accepted");
        check(commits==1 && seen_old==before && seen_next==get(leaf,8),"commit sees the old guest leaf");
        check(!!(seen_old&PT_AF)!=set && update_fast_uncached(seen_old)==(int)set,
              "AF set keeps the TLBI; AF clear is uncached");
    }
    printf("engine: the observed 0xa/0xc0a pair reaches commit_update with the old leaf the rule reads\n");
}
int main(void)
{
    one_pass_verification();
    tlb_model();
    engine_pair();
    printf("PASS: %u update fast-path checks, %u engine failures\n",checks,failures);
    return failures ? 1 : 0;
}

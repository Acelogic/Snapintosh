/* SPDX-License-Identifier: MIT */
/* SNAP_CANONICAL_VIEW_FAST (sptm_root_view_mapped): on user trees built with
 * the real SPTM retype/map calls and the real shadow builder -- up to the
 * installed run's scale (~1,000 canonical tables, ~61k 4K leaves, ordinary
 * DEFAULT pages and TPRO class-9 pages, both source granules) -- the fast
 * proof must return exactly the reference verdict and result, including after
 * every single-word corruption of the canonical shadow, the source tables or
 * the frame metadata. It must also read each source descriptor at most once
 * per source page (plus the upper levels once per level-3 span), which is
 * where the UPERM proof's time goes; -DCANONICAL_PRE_CHANGE=1 points that
 * bound at the reference proof and must fail.
 *
 * Failure inventory: a cached source leaf reused for another page; a cached
 * level-3 table reused across spans; an upper-level invalid/block descriptor
 * or unreadable source word accepted; a shadow table the per-word reader would
 * refuse accepted whole; zero groups hiding a nonzero word; wrong physical
 * address for the 2nd-4th 4K leaf of a 16K page; class-9 policy evaluated with
 * the wrong VA; tables/pages/classes miscounted; e->leaves mismatch accepted.
 *
 * cc -std=gnu11 -O1 -g -fsanitize=address,undefined -fno-sanitize-recover=all -Icompat -Ishadow \
 *    tools/test-canonical-view-fast.c compat/sptm-root.c compat/sptm-user.c compat/sptm.c \
 *    compat/sptm-refs.c shadow/shadow.c shadow/mmu.c -o build/test-canonical-view-fast
 * Build with -O2 and no sanitizer and pass --bench for host timings. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "sptm-user.h"
#include "sptm-refs.h"
#include "sptm-root.h"
#include "mmu.h"
#ifndef CANONICAL_PRE_CHANGE
#define CANONICAL_PRE_CHANGE 0
#endif

static unsigned long long checks;
#define CHECK(x) do {checks++;if(!(x)){fprintf(stderr,"line %d: %s\n",__LINE__,#x);exit(1);}}while(0)
#define BASE UINT64_C(0x90000000)
#define FRAMES 512u
#define SIZE ((uint64_t)FRAMES*0x4000)
#define FM (BASE+0x4000)
#define ROOT (BASE+0x8000)
#define FRAME(i) (BASE+(uint64_t)(i)*0x4000)
#define TABLE0 3u      /* frames 3..130: page tables */
#define DATA0 140u     /* frames 140..203: DEFAULT data */
#define TPRO0 210u     /* frames 210..213: TPRO data */
#define USER_VA UINT64_C(0x100000000)
#define NX UINT64_C(0x0060000000000f43)
#define TPRO_PTE UINT64_C(0x0020000000000e83)
static uint8_t ram[SIZE];
static struct sptm_ref_batch refs;
static unsigned long long source_reads,counting;
static volatile uint8_t *map(void *ctx,uint64_t pa,uint64_t n)
{
    (void)ctx;if(pa<BASE || pa>=BASE+SIZE || n>BASE+SIZE-pa)return 0;
    if(counting && n==8 && pa>=ROOT && pa<FRAME(DATA0))source_reads++;
    return ram+(pa-BASE);
}
static void publish(void *ctx,uint64_t pa,uint64_t n) {(void)ctx;CHECK(map(0,pa,n)!=0);}
static uint64_t get(uint64_t pa,unsigned n)
{uint64_t v=0;for(unsigned i=0;i<n;i++)v|=(uint64_t)ram[pa-BASE+i]<<(8*i);return v;}
static void put(uint64_t pa,uint64_t v,unsigned n)
{for(unsigned i=0;i<n;i++)ram[pa-BASE+i]=(uint8_t)(v>>(8*i));}
static uint64_t meta(uint64_t pa) {return FM+((pa-BASE)>>14)*16;}
static int retype_tpro(void *ctx,uint64_t pa,uint64_t old,uint64_t next)
{(void)ctx;(void)pa;return old==11 && next==17;}

/* The canonical shadow lives in host memory at HW_BASE, as the monitor's lives
 * in its arena; hw_read is the per-word reader, hw_table the whole-table one. */
#define HW_BASE UINT64_C(0xa0000000)
#define HW_PAGES 2048u
static uint8_t hw_ram[HW_PAGES*4096];
static uint64_t hw_next;
static int hw_read(void *ctx,uint64_t pa,uint64_t *d)
{(void)ctx;if(pa<HW_BASE || pa>HW_BASE+sizeof hw_ram-8 || (pa&7))return -1;
 memcpy(d,hw_ram+(pa-HW_BASE),8);return 0;}
static int hw_write(void *ctx,uint64_t pa,uint64_t d)
{(void)ctx;if(pa<HW_BASE || pa>HW_BASE+sizeof hw_ram-8)return -1;
 memcpy(hw_ram+(pa-HW_BASE),&d,8);return 0;}
static uint64_t hw_alloc(void *ctx)
{(void)ctx;if(hw_next>HW_BASE+sizeof hw_ram-4096)return 0;
 uint64_t p=hw_next;hw_next+=4096;memset(hw_ram+(p-HW_BASE),0,4096);return p;}
static const volatile uint64_t *hw_table(void *ctx,uint64_t pa)
{
    (void)ctx;
    /* hw_read accepts all 512 words of a 4K-aligned page exactly when the
     * page lies inside hw_ram. */
    if((pa&4095) || pa<HW_BASE || pa>HW_BASE+sizeof hw_ram-4096)return 0;
    return (const volatile uint64_t *)(void *)(hw_ram+(pa-HW_BASE));
}

static struct sptm_user_backend backend={.aperture={BASE,UINT64_C(0xfffffe0100000000),SIZE}};
struct tree { struct sptm_memory m;struct sptm_root_cached e;struct shadow s;
              unsigned spans,pages,tpro_pages,format; };
static uint64_t rng=UINT64_C(0x6a09e667f3bcc909);
static unsigned rnd(unsigned n) {rng^=rng<<13;rng^=rng>>7;rng^=rng<<17;return (unsigned)(rng%n);}

/* spans x regions x slots source pages (16K) or 4K pages, 1 in tpro_every TPRO. */
static void build(struct tree *t,unsigned format,unsigned spans,unsigned regions,unsigned slots,
                  unsigned tpro_every)
{
    memset(ram,0,sizeof ram);memset(&refs,0,sizeof refs);memset(t,0,sizeof *t);
    for(unsigned i=0;i<FRAMES;i++)put(FM+16UL*i+2,11,1);
    t->m=(struct sptm_memory){.frame_map_pa=FM,.frame_low=BASE,.frame_high=BASE+SIZE,
        .alloc_low=ROOT,.alloc_high=BASE+SIZE,.map=map,.publish=publish,.refs=&refs,
        .retype_user_tpro=retype_tpro};
    struct sptm_memory *m=&t->m;
    unsigned shift=format ? 12:14;uint64_t page=UINT64_C(1)<<shift;
    /* One level-3 frame per span: a 16K table (32 MiB), or four 4K tables
     * in one 16K frame, linked as a group (8 MiB). */
    uint64_t l3_span=format ? UINT64_C(4)<<21 : UINT64_C(1)<<(2*shift-3),region=l3_span/16;
    CHECK(sptm_mac_retype(m,ROOT,11,18,(7UL<<32)|(2UL<<16)|format)==SPTM_OK);
    put(meta(ROOT)+10,0xa,2);   /* CONFIGURE_ROOT flag8: TPRO admitted */
    unsigned next=TABLE0;
    /* 16K: root(L1) -> one L2 -> L3 per span. 4K: root(L0) -> L1 -> L2 -> L3. */
    uint64_t upper_l1=0,upper_l2=0;
    if(format) {
        upper_l1=FRAME(next++);CHECK(sptm_mac_retype(m,upper_l1,11,20,1)==SPTM_OK);
        CHECK(sptm_mac_map_user_table(m,ROOT,USER_VA&~(3UL<<39),0,upper_l1|3)==SPTM_OK);
    }
    upper_l2=FRAME(next++);CHECK(sptm_mac_retype(m,upper_l2,11,20,2)==SPTM_OK);
    CHECK(sptm_mac_map_user_table(m,ROOT,format ? USER_VA&~(3UL<<30) : USER_VA,1,upper_l2|3)==SPTM_OK);
    for(unsigned d=0;d<64;d++)put(meta(FRAME(DATA0+d))+2,11,1);
    for(unsigned d=0;d<4;d++)CHECK(sptm_mac_retype(m,FRAME(TPRO0+d),11,17,0)==SPTM_OK);
    uint64_t result;
    for(unsigned sp=0;sp<spans;sp++) {
        uint64_t span_va=USER_VA+sp*l3_span;
        CHECK(next<DATA0);
        uint64_t l3=FRAME(next++);CHECK(sptm_mac_retype(m,l3,11,20,3)==SPTM_OK);
        CHECK(sptm_mac_map_user_table(m,ROOT,format ? span_va&~(3UL<<21) : span_va,2,l3|3)==SPTM_OK);
        for(unsigned r=0;r<regions;r++)for(unsigned k=0;k<slots;k++) {
            uint64_t va=span_va+r*region+(uint64_t)(k*7%(region/page))*page;
            int tpro=tpro_every && !(t->pages%tpro_every);
            uint64_t pte=tpro ? FRAME(TPRO0+t->pages%4)|TPRO_PTE : FRAME(DATA0+t->pages%64)|NX;
            if(format) pte=(pte&~UINT64_C(0x0000fffffffff000))|((pte&UINT64_C(0x0000fffffffff000))+
                           ((va>>12)&3)*4096);   /* 4K pages inside the 16K frame */
            enum sptm_result res=sptm_mac_map_user_page(m,&backend,ROOT,va,pte,1,0,&result);
            if(res!=SPTM_OK)fprintf(stderr,"map va %llx pte %llx: %d\n",
                                    (unsigned long long)va,(unsigned long long)pte,res);
            CHECK(res==SPTM_OK);
            t->pages++;t->tpro_pages+=(unsigned)tpro;
        }
    }
    t->spans=spans;t->format=format;
    memset(hw_ram,0,sizeof hw_ram);hw_next=HW_BASE+4096;
    t->s=(struct shadow){.txsz=17,.root=HW_BASE,.alloc=hw_alloc,.read=hw_read,.write=hw_write};
    t->e=(struct sptm_root_cached){.root=ROOT,.shadow=HW_BASE,.asid=get(meta(ROOT)+4,2),
        .format=format,.flags=0xa,.valid=1};
    CHECK(sptm_root_build_shadow(m,&t->s,ROOT,format,0xa,&t->e.leaves));
    CHECK(t->e.leaves==t->pages);
}
static struct sptm_view_mapped_stats stats;
static int fast(struct tree *t,struct sptm_fixed_view *out,int tpro)
{
#if CANONICAL_PRE_CHANGE
    return tpro ? sptm_root_canonical_view(&t->e,&t->s,&t->m,out) : sptm_root_fixed_view(&t->e,&t->s,&t->m,out);
#else
    return sptm_root_view_mapped(&t->e,&t->s,&t->m,out,tpro,hw_table,&stats);
#endif
}
static int same(struct tree *t,int tpro)
{
    struct sptm_fixed_view a={0},b={0};
    int ra=tpro ? sptm_root_canonical_view(&t->e,&t->s,&t->m,&a) :
                  sptm_root_fixed_view(&t->e,&t->s,&t->m,&a);
    int rb=sptm_root_view_mapped(&t->e,&t->s,&t->m,&b,tpro,hw_table,&stats);
    CHECK(ra==rb);
    if(ra)CHECK(!memcmp(&a,&b,sizeof a));
    return ra;
}
/* Every single-word corruption class, each restored afterwards. */
static void fuzz(struct tree *t,unsigned rounds,unsigned *passes,unsigned *refusals)
{
    for(unsigned n=0;n<rounds;n++) {
        unsigned kind=rnd(9);uint64_t pa=0,old=0;unsigned bytes=8;int host=0;
        uint64_t leaves=t->e.leaves;
        switch(kind) {
        case 0: case 1: {       /* a canonical shadow word, any level */
            uint64_t used=(hw_next-HW_BASE)/8;pa=HW_BASE+8*(uint64_t)rnd((unsigned)used);host=1;break;}
        case 2: case 3:         /* a source descriptor in a page table */
            pa=FRAME(TABLE0+rnd(t->spans+2))+8*(uint64_t)rnd(2048);break;
        case 4: pa=ROOT+8*(uint64_t)rnd(2048);break;
        case 5: pa=meta(FRAME(DATA0+rnd(64)))+rnd(16);bytes=1;break;
        case 6: pa=meta(FRAME(TPRO0+rnd(4)))+rnd(16);bytes=1;break;
        case 7: pa=meta(FRAME(TABLE0+rnd(t->spans+2)))+rnd(16);bytes=1;break;
        default: t->e.leaves+=rnd(2) ? 1 : -1;break;
        }
        if(pa) {
            if(host)memcpy(&old,hw_ram+(pa-HW_BASE),8);else old=get(pa,bytes);
            uint64_t value;
            switch(rnd(5)) {
            case 0: value=0;break;
            case 1: value=old^(UINT64_C(1)<<rnd(bytes*8));break;
            case 2: value=old^(UINT64_C(1)<<rnd(2));break;              /* valid/table bits */
            case 3: value=old+(bytes==8 ? 4096 : 1);break;              /* PA or type step */
            default: value=((uint64_t)rnd(1u<<31)<<32)|rnd(1u<<31);break;
            }
            if(host)memcpy(hw_ram+(pa-HW_BASE),&value,8);else put(pa,value,bytes);
        }
        int ok_tpro=same(t,1),ok_fixed=same(t,0);
        *passes+=(unsigned)(ok_tpro+ok_fixed);*refusals+=(unsigned)(2-ok_tpro-ok_fixed);
        if(pa) {if(host)memcpy(hw_ram+(pa-HW_BASE),&old,8);else put(pa,old,bytes);}
        t->e.leaves=leaves;
    }
    CHECK(same(t,1));
}
/* Two corruptions the random words above rarely reach, each restored: a source
 * table descriptor above level 3 turned into a block with the same output
 * address (the fast walk must not descend through it), and a canonical 4K leaf
 * that differs from its source leaf only in nG or AttrIndx (same address and
 * class; the fast walk must compare attributes). Both proofs refuse. */
static void targeted(struct tree *t)
{
    unsigned shift=t->format ? 12:14;
    int tpro=same(t,1),fixed=same(t,0);
    uint64_t table=ROOT;
    for(int level=mmu_start_level(shift,17);level<3;level++) {
        uint64_t slot=table+8*(uint64_t)mmu_index(shift,(uint32_t)level,USER_VA),d=get(slot,8);
        CHECK((d&3)==3);
        put(slot,d&~UINT64_C(2),8);
        CHECK(!same(t,1) && !same(t,0));
        put(slot,d,8);table=d&PT_OA_MASK;
    }
    uint64_t hw=t->e.shadow,leaf;
    for(int level=mmu_start_level(12,17);level<3;level++) {
        uint64_t d;CHECK(!hw_read(0,hw+8*(uint64_t)mmu_index(12,(uint32_t)level,USER_VA),&d) && (d&3)==3);
        hw=d&PT_OA_MASK;
    }
    uint64_t slot=hw+8*(uint64_t)mmu_index(12,3,USER_VA);
    CHECK(!hw_read(0,slot,&leaf) && (leaf&3)==3);
    const uint64_t bits[2]={PT_NG,UINT64_C(1)<<2};
    for(unsigned n=0;n<2;n++) {
        CHECK(!hw_write(0,slot,leaf^bits[n]));
        CHECK(!same(t,1) && !same(t,0));
        CHECK(!hw_write(0,slot,leaf));
    }
    CHECK(same(t,1)==tpro && same(t,0)==fixed);
}
/* The regression bound: one source read per source page plus the upper levels
 * once per level-3 span. The reference walks every level for every 4K leaf. */
static void read_bound(struct tree *t)
{
    struct sptm_fixed_view v;source_reads=0;counting=1;
    int ok=fast(t,&v,1);counting=0;
    unsigned levels=t->format ? 4:3;
    unsigned long long bound=(unsigned long long)t->pages+(unsigned long long)t->spans*(levels-1)+16;
    printf("source descriptor reads: %llu for %u source pages in %u spans (bound %llu)\n",
           source_reads,t->pages,t->spans,bound);
    CHECK(ok && v.pages==t->pages*(t->format ? 1:4));
    CHECK(source_reads<=bound);
}
static double now(void) {struct timespec s;clock_gettime(CLOCK_MONOTONIC,&s);return s.tv_sec+s.tv_nsec*1e-9;}
static void bench(void)
{
    static struct tree t;
    /* The installed run's UPERM proofs: ~1,068 tables, ~62.7k 4K leaves. */
    build(&t,0,60,16,16,50);
    struct sptm_fixed_view a,b;
    const unsigned n=200;double t0=now();
    for(unsigned i=0;i<n;i++)CHECK(sptm_root_canonical_view(&t.e,&t.s,&t.m,&a));
    double t1=now();
    for(unsigned i=0;i<n;i++)CHECK(sptm_root_view_mapped(&t.e,&t.s,&t.m,&b,1,hw_table,&stats));
    double t2=now();
    CHECK(!memcmp(&a,&b,sizeof a));
    printf("{\"tables\":%llu,\"leaves\":%llu,\"source_pages\":%u,\"tpro_pages\":%u,"
           "\"reference_ms\":%.3f,\"fast_ms\":%.3f,\"speedup\":%.1f}\n",
           (unsigned long long)a.tables,(unsigned long long)a.pages,t.pages,t.tpro_pages,
           (t1-t0)/n*1e3,(t2-t1)/n*1e3,(t1-t0)/(t2-t1));
}
int main(int argc,char **argv)
{
    if(argc==2 && !strcmp(argv[1],"--bench")) {bench();return 0;}
    static struct tree t;unsigned passes=0,refusals=0;
    for(unsigned format=0;format<2;format++) {
        build(&t,format,format ? 6:8,4,5,7);
        CHECK(t.pages>=format ? 100:150 && t.tpro_pages>0);
        CHECK(same(&t,1));
        CHECK(!same(&t,0));      /* class 9 is not a fixed native leaf */
        read_bound(&t);
        targeted(&t);
        fuzz(&t,format ? 1500:2500,&passes,&refusals);
        build(&t,format,format ? 5:7,3,4,0);   /* no TPRO: both proofs pass */
        CHECK(same(&t,1) && same(&t,0));
        targeted(&t);
        fuzz(&t,1000,&passes,&refusals);
    }
    build(&t,0,60,16,16,50);   /* installed-run scale */
    CHECK(same(&t,1));
    read_bound(&t);
    CHECK(passes>500 && refusals>500);
    printf("PASS: %llu canonical-view checks; %u proofs passed and %u refused identically, "
           "%llu leaves, %llu source-page walks, %llu span walks\n",checks,passes,refusals,
           (unsigned long long)stats.leaves,(unsigned long long)stats.walks,
           (unsigned long long)stats.span_walks);
    return 0;
}

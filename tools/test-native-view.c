/* SPDX-License-Identifier: MIT */
/* SNAP_NATIVE_TABLES user variants (shadow/native-view.c) against the
 * hardware-qualified per-CPU views (shadow/sprr-view.c) as the reference.
 *
 * A canonical 4K user shadow is grown and changed by random operations whose
 * every store goes through the store hook, exactly as the monitor's writer
 * does: admission before the store, propagation after. After every operation
 * both variants must (a) pass the read-only audit and (b) translate every
 * 4K page of the exercised ranges exactly like a freshly synchronized
 * sprr-view copy for the same SPRR state (w=0: TPRO read-only, w=1: TPRO
 * writable, EL0). A raw class 9 leaf in a table without copies is refused
 * before it is stored, and prepare_leaf links a new private path only after
 * its copies are complete.
 *
 * cc -std=gnu11 -O1 -g -fsanitize=address,undefined -fno-sanitize-recover=all -Icompat -Ishadow \
 *    tools/test-native-view.c shadow/native-view.c shadow/sprr-view.c shadow/shadow.c shadow/mmu.c
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "native-view.h"

static unsigned long long checks;
#define CHECK(x) do {checks++;if(!(x)){fprintf(stderr,"line %d: %s\n",__LINE__,#x);exit(1);}}while(0)

#define MAIN_BASE UINT64_C(0x80000000)
#define MAIN_PAGES 6144u
#define REF_BASE UINT64_C(0xa0000000)
#define REF_PAGES 4096u
static uint8_t main_pool[MAIN_PAGES*4096],ref_pool[REF_PAGES*4096];
static uint64_t main_next,ref_next;
static uint8_t *at(uint64_t pa,uint64_t n)
{
    if(pa>=MAIN_BASE && pa<MAIN_BASE+sizeof main_pool && n<=MAIN_BASE+sizeof main_pool-pa)
        return main_pool+(pa-MAIN_BASE);
    if(pa>=REF_BASE && pa<REF_BASE+sizeof ref_pool && n<=REF_BASE+sizeof ref_pool-pa)
        return ref_pool+(pa-REF_BASE);
    return 0;
}
static int rd(void *ctx,uint64_t pa,uint64_t *out)
{(void)ctx;uint8_t *p=at(pa,8);if(!p || (pa&7))return -1;memcpy(out,p,8);return 0;}
static int wr(void *ctx,uint64_t pa,uint64_t v)
{(void)ctx;uint8_t *p=at(pa,8);if(!p || (pa&7))return -1;memcpy(p,&v,8);return 0;}
static uint64_t alloc_main(void *ctx)
{(void)ctx;if(main_next>=MAIN_PAGES)return 0;uint64_t pa=MAIN_BASE+4096*main_next++;
 memset(at(pa,4096),0,4096);return pa;}
static uint64_t alloc_ref(void *ctx)
{(void)ctx;if(ref_next>=REF_PAGES)return 0;uint64_t pa=REF_BASE+4096*ref_next++;
 memset(at(pa,4096),0,4096);return pa;}

static struct sprr_views nv;
static uint64_t canon_root,umprr=0x40000;
static int hooked;
static unsigned refused,propagated;
/* The copies' writer: plain stores, main-pool allocation. */
static struct shadow copies(void)
{return (struct shadow){.txsz=17,.root=canon_root,.alloc=alloc_main,.read=rd,.write=wr};}
/* The canonical writer: the monitor's hook order. */
static int canonical_write(void *ctx,uint64_t pa,uint64_t v)
{
    if(!hooked)return wr(ctx,pa,v);
    if(!native_views_admit(&nv,pa,v,umprr)) {refused++;return -1;}
    if(wr(ctx,pa,v))return -1;
    struct shadow c=copies();
    if(!native_views_store(&nv,&c,pa,v,umprr))return -1;
    propagated++;return 0;
}
static struct shadow canonical(void)
{return (struct shadow){.txsz=17,.root=canon_root,.alloc=alloc_main,.read=rd,.write=canonical_write};}

#define LOW7 UINT64_C(0xf40)          /* class 7: EL0 RW data, never executable */
#define UP7 (PT_PXN|PT_UXN)
#define LOW15 UINT64_C(0xfc0)         /* class 15: read-only data */
#define LOW3 UINT64_C(0xf00)          /* class 3: EL1-only data */
#define LOW9 UINT64_C(0xe80)          /* class 9: TPRO */
#define UP9 PT_PXN
/* Exercised ranges: two 2M regions sharing one L3 parent, one in another
 * L1 entry, one at the top of the user half. */
static const uint64_t region[4]={UINT64_C(0x100000000),UINT64_C(0x100200000),
                                  UINT64_C(0x8000000000),UINT64_C(0x3fffffc00000)};
#define REGION_PAGES 512u
static uint64_t rng=UINT64_C(0x9e3779b97f4a7c15);
static unsigned rnd(unsigned n) {rng^=rng<<13;rng^=rng>>7;rng^=rng<<17;return (unsigned)(rng%n);}
static uint64_t pick_va(void) {return region[rnd(4)]+4096*(uint64_t)rnd(REGION_PAGES);}
static uint64_t data_pa(uint64_t va) {return UINT64_C(0x900000000)+((va*2654435761u)&0x3fff000);}

static uint64_t leaf_at(uint64_t va)
{
    struct mmu_config cfg={12,17,canon_root};struct mmu_leaf l;
    CHECK(!mmu_walk(&cfg,va,rd,0,&l));
    return l.valid ? l.descriptor : 0;
}
/* The canonical level-3 table for va (its path must exist). */
static uint64_t l3_table(uint64_t va)
{
    uint64_t table=canon_root,d;
    for(unsigned level=0;level<3;level++) {
        CHECK(!rd(0,table+8UL*mmu_index(12,level,va),&d) && (d&3)==3);
        table=d&PT_OA_MASK;
    }
    return table;
}
static void map(uint64_t va,unsigned cls)
{
    struct shadow s=canonical();
    uint64_t low=cls==9 ? LOW9 : cls==15 ? LOW15 : cls==3 ? LOW3 : LOW7;
    uint64_t up=cls==9 ? UP9 : UP7;
    if(leaf_at(va) && shadow_unmap(&s,va,4096,0))CHECK(0);
    if(cls==9) {
        CHECK(!shadow_reserve(&s,va,4096));
        struct shadow c=copies();
        int r=native_views_prepare_leaf(&nv,&c,va,umprr);
        CHECK(r==1 || r==2);
        CHECK(native_views_prepare_leaf(&nv,&c,va,umprr)==1);
    }
    CHECK(!shadow_map(&s,va,data_pa(va),4096,low,up));
}
static void differential(void)
{
    struct sprr_views ref;memset(&ref,0,sizeof ref);ref_next=0;
    struct shadow r={.txsz=17,.root=canon_root,.alloc=alloc_ref,.read=rd,.write=wr};
    CHECK(sprr_views_init(&ref,&r) && sprr_views_prepare_user(&ref,&r));
    for(unsigned w=0;w<2;w++) {
        struct sprr_state st={.uperm=SPRR_UPERM_INITIAL|(w ? SPRR_UPERM_TPRO_WRITE : 0),
            .pperm=SPRR_PPERM_INITIAL,.umprr=umprr,.pmprr=SPRR_PMPRR_INITIAL,.resets=1};
        CHECK(sprr_views_sync_user_cpu(&ref,&r,w,&st,1));
    }
    for(unsigned g=0;g<4;g++)for(unsigned p=0;p<REGION_PAGES;p++) {
        uint64_t va=region[g]+4096*(uint64_t)p;
        for(unsigned w=0;w<2;w++) {
            struct mmu_config a={12,17,native_views_root(&nv,w)},b={12,17,sprr_views_root(&ref,w)};
            struct mmu_leaf x,y;
            CHECK(!mmu_walk(&a,va,rd,0,&x) && !mmu_walk(&b,va,rd,0,&y));
            CHECK(x.valid==y.valid);
            if(x.valid)CHECK(x.pa==y.pa && x.descriptor==y.descriptor && x.level==3);
        }
    }
}
static void audit(void)
{
    struct shadow c=copies();
    CHECK(native_views_verify(&nv,&c,umprr));
}

int main(void)
{
    canon_root=alloc_main(0);
    struct shadow c=copies();
    /* A build: fixed and TPRO pages exist before the variants do, stored
     * with no hook, as sptm_root_build_shadow stores them. */
    for(unsigned n=0;n<200;n++) {
        uint64_t va=pick_va();struct shadow s=canonical();
        int tpro=!(n%7) && va<region[2];     /* regions 2 and 3 start without */
        if(leaf_at(va))CHECK(!shadow_unmap(&s,va,4096,0));
        CHECK(!shadow_map(&s,va,data_pa(va),4096,tpro ? LOW9 : n%3 ? LOW7 : LOW15,tpro ? UP9 : UP7));
    }
    CHECK(native_views_sync(&nv,&c,umprr));
    hooked=1;audit();differential();
    /* The first TPRO page of region 3 needs a new path: its level-1, -2 and
     * -3 tables get copies, filled before the root copies link them. */
    {
        uint64_t va=region[3]+4096*7;struct shadow s=canonical();
        if(leaf_at(va))CHECK(!shadow_unmap(&s,va,4096,0));
        CHECK(!shadow_reserve(&s,va,4096));
        unsigned before=(unsigned)nv.count;
        CHECK(native_views_find(&nv,l3_table(va))<0);
        CHECK(native_views_prepare_leaf(&nv,&c,va,umprr)==2 && nv.count==before+3);
        audit();differential();
        CHECK(!shadow_map(&s,va,data_pa(va),4096,LOW9,UP9));
        audit();differential();
    }
    CHECK(native_views_root(&nv,0) && native_views_root(&nv,1) &&
          native_views_root(&nv,0)!=native_views_root(&nv,1) && !native_views_root(&nv,2));
    /* A raw TPRO leaf into a table without copies is refused before the store.
     * `lone` is outside every exercised range, so its level-2 and level-3
     * tables are new and have no copies. */
    const uint64_t lone=UINT64_C(0x4000000000);
    {
        struct shadow s=canonical();
        CHECK(!leaf_at(lone) && !shadow_reserve(&s,lone,4096));
        CHECK(native_views_find(&nv,l3_table(lone))<0);
        unsigned before=refused;
        CHECK(shadow_map(&s,lone,data_pa(lone),4096,LOW9,UP9) && refused==before+1);
        CHECK(!leaf_at(lone));
    }
    audit();
    /* Random maps, TPRO maps, permission changes and unmaps. */
    for(unsigned op=0;op<600;op++) {
        uint64_t va=pick_va();unsigned k=rnd(10);
        struct shadow s=canonical();
        if(k<4)map(va,7);
        else if(k<6)map(va,9);
        else if(k<7)map(va,15);
        else if(k<8)map(va,3);
        else if(k<9) {if(leaf_at(va))CHECK(!shadow_unmap(&s,va,4096,0));}
        else {
            unsigned n=1+rnd(16);uint64_t base=va&~UINT64_C(0xffff);
            CHECK(!shadow_unmap(&s,base,4096*(uint64_t)n,0));
        }
        audit();
        if(!(op%25))differential();
    }
    differential();
    /* Both variants keep sharing every table without a TPRO leaf. */
    unsigned copied=(unsigned)nv.count;
    CHECK(copied>1 && copied<64);
    /* A missing variant copy entry, a stale translation or a raw leaf left in
     * a copy is caught by the audit. */
    {
        const struct sprr_view_table *t=&nv.tables[nv.count-1];uint64_t d,saved;
        unsigned i=0;
        for(;i<512;i++) {CHECK(!rd(0,t->source+8UL*i,&d));if(d&1)break;}
        CHECK(i<512);
        for(unsigned w=0;w<2;w++) {
            CHECK(!rd(0,t->copy[w]+8UL*i,&saved));
            CHECK(!wr(0,t->copy[w]+8UL*i,d));
            CHECK(!native_views_verify(&nv,&c,umprr) || d==saved);
            CHECK(!wr(0,t->copy[w]+8UL*i,0));
            CHECK(!native_views_verify(&nv,&c,umprr) && !native_views_exact(&nv,&c,umprr));
            CHECK(!wr(0,t->copy[w]+8UL*i,saved));
        }
        audit();
    }
    /* A raw TPRO leaf that bypassed admission is found by the audit. */
    {
        uint64_t va=lone+4096,table=l3_table(va),slot=table+8UL*mmu_index(12,3,va);
        CHECK(native_views_find(&nv,table)<0);
        CHECK(!wr(0,slot,(data_pa(va)&PT_OA_MASK)|LOW9|UP9|3));
        /* Coverage is the full walk's alone: every copy is still exact. */
        CHECK(!native_views_verify(&nv,&c,umprr) && native_views_exact(&nv,&c,umprr));
        CHECK(!wr(0,slot,0));
        audit();
    }
    /* A root entry in the upper half, or a leaf class with no native
     * encoding on a copied table, is refused. */
    {
        uint64_t saved;CHECK(!rd(0,canon_root+8UL*256,&saved) && !saved);
        unsigned refusals=refused;uint64_t empty=alloc_main(0);
        CHECK(empty && native_views_find(&nv,empty)<0);
        CHECK(canonical_write(0,canon_root+8UL*256,empty|3) &&
              refused==refusals+1 && !rd(0,canon_root+8UL*256,&saved) && !saved);
        CHECK(!wr(0,canon_root+8UL*256,l3_table(region[0])|3));
        CHECK(!native_views_verify(&nv,&c,umprr));
        CHECK(!wr(0,canon_root+8UL*256,0));
        uint64_t va=region[3]+4096*9;struct shadow s=canonical();
        CHECK(native_views_find(&nv,l3_table(va))>=0);
        if(leaf_at(va))CHECK(!shadow_unmap(&s,va,4096,0));
        unsigned before=refused;
        CHECK(shadow_map(&s,va,data_pa(va),4096,UINT64_C(0xf40),PT_PXN) &&  /* class 5 */
              refused==before+1 && !leaf_at(va));
        audit();
        uint64_t slot=l3_table(va)+8UL*mmu_index(12,3,va);
        CHECK(!wr(0,slot,(data_pa(va)&PT_OA_MASK)|UINT64_C(0xf43)|PT_PXN));
        CHECK(!native_views_verify(&nv,&c,umprr));
        CHECK(!wr(0,slot,0));
        audit();
    }
    /* TPRO needs the root's UMPRR policy. */
    CHECK(!native_views_verify(&nv,&c,0));
    printf("PASS: %llu native-view checks; %u copied tables, %u propagated stores, %u refused stores\n",
           checks,copied,propagated,refused);
    return 0;
}

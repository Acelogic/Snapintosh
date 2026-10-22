/* SPDX-License-Identifier: MIT */
#include <stdio.h>
#include <string.h>
#include "sprr-view.h"
#include "sprr.h"

#define BASE UINT64_C(0x40000000)
#define BYTES (4u<<20)
#define DATA UINT64_C(0x900000000)
#define ATTR (PT_AF|(3UL<<8))
static unsigned char ram[BYTES],before[BYTES];
static uint64_t next,read_fail,forced_alloc;
static unsigned writes,alloc_budget,checks,failed;
static struct sprr_views views;
#define CHECK(x) do {checks++;if(!(x)){failed++;printf("FAIL %u: %s\n",__LINE__,#x);}} while(0)
static int rd(void *ctx,uint64_t pa,uint64_t *out)
{
    (void)ctx;if(pa<BASE || pa>BASE+BYTES-8 || pa==read_fail)return -1;
    memcpy(out,ram+(pa-BASE),8);return 0;
}
static int wr(void *ctx,uint64_t pa,uint64_t value)
{
    (void)ctx;if(pa<BASE || pa>BASE+BYTES-8)return -1;
    memcpy(ram+(pa-BASE),&value,8);writes++;return 0;
}
static uint64_t alloc(void *ctx)
{
    (void)ctx;if(forced_alloc)return forced_alloc;
    if(!alloc_budget || next>BASE+BYTES-4096)return 0;
    alloc_budget--;uint64_t result=next;next+=4096;return result;
}
static void put(uint64_t table,unsigned index,uint64_t desc)
{CHECK(!wr(0,table+8UL*index,desc));}
static void setup(struct shadow *s)
{
    memset(ram,0,sizeof(ram));memset(&views,0,sizeof(views));
    next=BASE+0x10000;alloc_budget=BYTES/4096;read_fail=forced_alloc=0;
    *s=(struct shadow){.txsz=17,.root=BASE,.alloc=alloc,.read=rd,.write=wr};
    put(BASE,0,BASE+0x1000+3);put(BASE+0x1000,0,BASE+0x2000+3);
    put(BASE+0x2000,0,BASE+0x3000+3);put(BASE+0x2000,1,BASE+0x4000+3);
    for(unsigned page=0;page<4;page++)
        put(BASE+0x3000,page,DATA+4096UL*page+3+ATTR+PT_PXN+PT_UXN);
    /* Same PA through an ordinary RW alias in a different, initially shared
     * table. A stage2-wide RO toggle would incorrectly revoke this alias. */
    put(BASE+0x4000,0,DATA+3+ATTR+PT_PXN+PT_UXN);
    writes=0;
}
static struct mmu_leaf walk(unsigned cpu,uint64_t va)
{
    struct mmu_config cfg={12,17,sprr_views_root(&views,cpu)};struct mmu_leaf l={0};
    CHECK(!mmu_walk(&cfg,va,rd,0,&l));return l;
}
static void rights(unsigned cpu,uint64_t va,uint64_t pa,int writable)
{
    struct mmu_leaf l=walk(cpu,va);
    CHECK(l.valid && l.pa==pa);
    CHECK(!!(l.descriptor&(2UL<<6))==!writable);
    CHECK(!(l.descriptor&(1UL<<6)));  /* no EL0 access */
    CHECK((l.descriptor&(PT_PXN|PT_UXN))==(PT_PXN|PT_UXN));
}
static void sync_all(struct shadow *s,const uint64_t *pperm)
{
    for(unsigned cpu=0;cpu<6;cpu++)CHECK(sprr_views_sync_cpu(&views,s,cpu,pperm[cpu]));
}
int main(void)
{
    struct shadow s;setup(&s);
    struct sprr_view_classes proof={0};
    CHECK(sprr_views_check_classes(&s,1UL<<9,&proof));
    CHECK(proof.tables==5 && proof.pages==5 && proof.classes==(1UL<<3));
    for(unsigned bad=0;bad<7;bad++) {
        uint64_t where=BASE+0x2000+16,old=0;
        if(bad==0)where=BASE+0x3000;
        else if(bad==1)where=BASE+0x4000;
        else if(bad==4)where=BASE+8*256;
        CHECK(!rd(0,where,&old));
        uint64_t d=bad<2 ? DATA+3+ATTR+PT_PXN+(2UL<<6) :
            bad==2 ? DATA+1+ATTR+PT_PXN+(2UL<<6) :
            bad==3 ? BASE+0x1000+3 : bad==4 ? BASE+0x3000+3 :
            bad==5 ? DATA+0x1000+1+ATTR+PT_UXN+PT_PXN : 2;
        CHECK(!wr(0,where,d));struct sprr_view_classes original={6,7,8};proof=original;
        memcpy(before,ram,sizeof ram);unsigned saved=writes;
        CHECK(!sprr_views_check_classes(&s,1UL<<9,&proof));
        CHECK(!memcmp(&proof,&original,sizeof proof) && writes==saved && !memcmp(before,ram,sizeof ram));
        CHECK(!wr(0,where,old));
    }
    put(BASE+0x2000,2,DATA+1+ATTR+PT_PXN+PT_UXN);
    CHECK(sprr_views_check_classes(&s,1UL<<9,&proof) && proof.pages==517);
    put(BASE+0x2000,2,0);
    read_fail=BASE+0x4000+4096-8;
    CHECK(!sprr_views_check_classes(&s,1UL<<9,&proof));read_fail=0;
    uint64_t pp[6];for(unsigned cpu=0;cpu<6;cpu++)pp[cpu]=SPRR_PPERM_INITIAL;
    CHECK(sprr_views_init(&views,&s));CHECK(views.count==1);
    CHECK(sprr_views_prepare(&views,&s,0));CHECK(views.count==4);
    CHECK(sprr_views_prepare(&views,&s,3*4096));CHECK(views.count==4);
    sync_all(&s,pp); /* detach live copies before changing canonical attributes */
    for(unsigned cpu=0;cpu<6;cpu++) {
        CHECK(sprr_views_root(&views,cpu)!=s.root);
        for(unsigned other=0;other<cpu;other++)
            CHECK(sprr_views_root(&views,cpu)!=sprr_views_root(&views,other));
        rights(cpu,0,DATA,1);rights(cpu,0x200000,DATA,1);
    }
    /* Retype one 16K aperture page to selector2 in the canonical 4K tree. */
    for(unsigned page=0;page<4;page++)
        put(BASE+0x3000,page,DATA+4096UL*page+3+ATTR+PT_UXN);
    sync_all(&s,pp);
    for(unsigned cpu=0;cpu<6;cpu++) {
        for(unsigned page=0;page<4;page++)rights(cpu,4096UL*page,DATA+4096UL*page,0);
        rights(cpu,0x200000,DATA,1);
    }
    /* Every CPU grants/restores while peers retain their own permission state.
     * Only the current CPU's copied table pages may change. */
    for(unsigned round=0;round<4;round++)for(unsigned cpu=0;cpu<6;cpu++) {
        pp[cpu]^=0x100;memcpy(before,ram,sizeof(ram));
        CHECK(sprr_views_sync_cpu(&views,&s,cpu,pp[cpu]));
        for(unsigned n=0;n<views.count;n++)for(unsigned other=0;other<6;other++)if(other!=cpu)
            CHECK(!memcmp(before+(views.tables[n].copy[other]-BASE),
                          ram+(views.tables[n].copy[other]-BASE),4096));
        CHECK(!memcmp(before,ram,0x10000)); /* canonical tree remains untouched */
        for(unsigned other=0;other<6;other++)for(unsigned page=0;page<4;page++)
            rights(other,4096UL*page,DATA+4096UL*page,!!(pp[other]&0x100));
    }
    /* Selector9 state cannot change selector2's installed permissions or a
     * peer's pages. Both bits can be independently granted and restored. */
    for(unsigned round=0;round<4;round++)for(unsigned cpu=0;cpu<6;cpu++) {
        pp[cpu]^=SPRR_UPERM_TPRO_WRITE;
        if(round&1)pp[cpu]^=0x100;
        CHECK(sprr_views_check_classes(&s,1UL<<9,&proof));
        CHECK(sprr_views_sync_cpu(&views,&s,cpu,pp[cpu]));
        for(unsigned other=0;other<6;other++)for(unsigned page=0;page<4;page++)
            rights(other,4096UL*page,DATA+4096UL*page,!!(pp[other]&0x100));
    }
    /* Permission update of a neighbouring ordinary leaf, then unmap/reuse a
     * protected leaf: refresh must not preserve stale copies. */
    put(BASE+0x3000,4,DATA+0x10000+3+ATTR+PT_UXN+PT_PXN+(2UL<<6));
    put(BASE+0x3000,0,0);sync_all(&s,pp);
    for(unsigned cpu=0;cpu<6;cpu++) {
        CHECK(!walk(cpu,0).valid);rights(cpu,0x4000,DATA+0x10000,0);
    }
    put(BASE+0x3000,0,DATA+0x20000+3+ATTR+PT_PXN+PT_UXN);sync_all(&s,pp);
    for(unsigned cpu=0;cpu<6;cpu++)rights(cpu,0,DATA+0x20000,1);
    /* A second private branch is independent, even when it aliases the same
     * physical frame as the first branch. */
    CHECK(sprr_views_prepare(&views,&s,0x200000));CHECK(views.count==5);
    sync_all(&s,pp);put(BASE+0x4000,0,DATA+3+ATTR+PT_UXN);sync_all(&s,pp);
    for(unsigned cpu=0;cpu<6;cpu++)rights(cpu,0x200000,DATA,0);
    /* Preflight refusals leave all visible table bytes unchanged. */
    memcpy(before,ram,sizeof(ram));unsigned saved=writes;
    CHECK(!sprr_views_sync_cpu(&views,&s,0,SPRR_PPERM_INITIAL^1));
    CHECK(!sprr_views_sync_cpu(&views,&s,6,SPRR_PPERM_INITIAL));
    read_fail=BASE+0x4000+4096-8;
    CHECK(!sprr_views_sync_cpu(&views,&s,0,SPRR_PPERM_INITIAL));read_fail=0;
    CHECK(writes==saved && !memcmp(before,ram,sizeof(ram)));
    put(BASE+0x2000,2,DATA+1+ATTR+PT_UXN); /* class2 block is not a 4K page */
    saved=writes;CHECK(!sprr_views_sync_cpu(&views,&s,0,SPRR_PPERM_INITIAL));
    CHECK(writes==saved);CHECK(!sprr_views_prepare(&views,&s,0x400000));
    put(BASE+0x2000,2,0);
    saved=writes;CHECK(!sprr_views_prepare(&views,&s,0x600000));CHECK(writes==saved);
    /* A failed allocation must never link a partly allocated branch. */
    setup(&s);CHECK(sprr_views_init(&views,&s));sync_all(&s,pp);
    alloc_budget=7;memcpy(before,ram,sizeof(ram));saved=writes;
    CHECK(!sprr_views_prepare(&views,&s,0));CHECK(writes==saved);
    CHECK(!memcmp(before,ram,sizeof(ram)));
    setup(&s);forced_alloc=s.root;CHECK(!sprr_views_init(&views,&s));CHECK(!views.count);
    setup(&s);s.txsz=16;CHECK(!sprr_views_init(&views,&s));
    printf("SPRR private views: %u checks, %u failures\n",checks,failed);
    return failed ? 1 : 0;
}

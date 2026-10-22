/* SPDX-License-Identifier: MIT */
#define main baseline_view_tests
#include "test-sprr-view.c"
#undef main
#include "sprr-reuse.h"

static struct sprr_reuse_state reuse;
static unsigned char expected_ram[BYTES];
static int refresh(struct shadow *s,const uint64_t pp[6])
{
    int match=sprr_reuse_match(&reuse,&views,s,pp);
    if(match<0)return 0;
    if(match) {
        for(unsigned cpu=0;cpu<6;cpu++)
            if(!sprr_views_verify_cpu(&views,s,cpu,pp[cpu])) {
                reuse.mismatches++;reuse.valid=0;return 0;
            }
        reuse.verified++;return 1;
    }
    reuse.valid=0;
    for(unsigned cpu=0;cpu<6;cpu++)if(!sprr_views_sync_cpu(&views,s,cpu,pp[cpu]))return 0;
    return sprr_reuse_save(&reuse,&views,s,pp);
}
static void compare(struct shadow *s,const uint64_t pp[6])
{
    struct sprr_views old=views;memcpy(before,ram,sizeof ram);
    for(unsigned cpu=0;cpu<6;cpu++)CHECK(sprr_views_sync_cpu(&views,s,cpu,pp[cpu]));
    memcpy(expected_ram,ram,sizeof ram);views=old;memcpy(ram,before,sizeof ram);
    CHECK(refresh(s,pp));CHECK(!memcmp(ram,expected_ram,sizeof ram));
    for(unsigned cpu=0;cpu<6;cpu++)CHECK(sprr_views_verify_cpu(&views,s,cpu,pp[cpu]));
}
int main(void)
{
    CHECK(!baseline_view_tests());
    struct shadow s;setup(&s);CHECK(sprr_views_init(&views,&s));
    CHECK(sprr_views_prepare(&views,&s,0));
    for(unsigned i=0;i<4;i++)put(BASE+0x3000,i,DATA+4096UL*i+3+ATTR+PT_UXN);
    uint64_t pp[6];for(unsigned cpu=0;cpu<6;cpu++)pp[cpu]=SPRR_PPERM_INITIAL;
    for(unsigned round=0;round<128;round++) {
        if(round==16)CHECK(sprr_views_prepare(&views,&s,0x200000));
        if(round==24) {
            put(BASE+0x2000,2,BASE+0x5000+3);
            put(BASE+0x5000,0,DATA+3+ATTR+PT_UXN+PT_PXN);
            CHECK(sprr_views_prepare(&views,&s,0x400000));
            put(BASE+0x5000,0,0);
        }
        if(round%9==2)put(BASE+0x3000,4,DATA+0x10000+3+ATTR+PT_UXN+PT_PXN);
        if(round%9==3)put(BASE+0x3000,4,0);
        if(round%7==1)pp[round%6]^=0x100;
        if(round%11==3)pp[round%6]^=SPRR_UPERM_TPRO_WRITE;
        compare(&s,pp);
        unsigned saved_writes=writes;uint64_t saved_syncs[6];
        memcpy(saved_syncs,views.syncs,sizeof saved_syncs);
        CHECK(refresh(&s,pp));
        CHECK(saved_writes==writes && !memcmp(saved_syncs,views.syncs,sizeof saved_syncs));
        for(unsigned cpu=0;cpu<6;cpu++)for(unsigned i=0;i<4;i++)
            rights(cpu,4096UL*i,DATA+4096UL*i,!!(pp[cpu]&0x100));
    }
    CHECK(reuse.hits>128 && !reuse.errors && !reuse.mismatches);

    /* Every word matters, including descriptors whose valid bit is clear. */
    for(unsigned n=0;n<views.count;n++)for(unsigned i=0;i<512;i++) {
        uint64_t pa=views.tables[n].source+8UL*i,old;
        CHECK(!rd(0,pa,&old));CHECK(!wr(0,pa,old^4));
        CHECK(sprr_reuse_match(&reuse,&views,&s,pp)==0);
        CHECK(!wr(0,pa,old));
    }
    CHECK(sprr_reuse_match(&reuse,&views,&s,pp)==1);
    struct sprr_view_table old=views.tables[0];
    views.tables[0].copy[5]+=4096;CHECK(!sprr_reuse_match(&reuse,&views,&s,pp));
    views.tables[0]=old;views.tables[0].source+=4096;CHECK(!sprr_reuse_match(&reuse,&views,&s,pp));
    views.tables[0]=old;views.tables[0].level=1;CHECK(!sprr_reuse_match(&reuse,&views,&s,pp));
    views.tables[0]=old;views.count--;CHECK(!sprr_reuse_match(&reuse,&views,&s,pp));views.count++;
    s.root+=4096;CHECK(sprr_reuse_match(&reuse,&views,&s,pp)==-1);s.root-=4096;
    compare(&s,pp);

    /* Source and copy reads fail closed. A sampled copy discrepancy cannot
     * be repaired by verification: it is reported without a single write. */
    read_fail=views.tables[0].source+4088;unsigned saved_writes=writes;
    CHECK(sprr_reuse_match(&reuse,&views,&s,pp)==-1);
    CHECK(!reuse.valid && writes==saved_writes);read_fail=0;compare(&s,pp);
    uint64_t copy=views.tables[0].copy[5],word;CHECK(!rd(0,copy,&word));
    CHECK(!wr(0,copy,word^4));saved_writes=writes;
    CHECK(!refresh(&s,pp));CHECK(reuse.mismatches==1 && writes==saved_writes);
    CHECK(!wr(0,copy,word));compare(&s,pp);
    read_fail=copy;CHECK(!sprr_views_verify_cpu(&views,&s,5,pp[5]));read_fail=0;
    CHECK(!sprr_views_verify_cpu(&views,&s,6,pp[0]));
    CHECK(!sprr_views_verify_cpu(&views,&s,0,pp[0]^1));

    /* The independent PPERM writer invalidates even for A->B->A. */
    sprr_reuse_invalidate(&reuse);CHECK(!reuse.valid);
    CHECK(sprr_views_sync_cpu(&views,&s,3,pp[3]^0x100));
    CHECK(sprr_views_sync_cpu(&views,&s,3,pp[3]));
    CHECK(!sprr_reuse_match(&reuse,&views,&s,pp));compare(&s,pp);
    read_fail=views.tables[0].source;
    CHECK(!sprr_reuse_save(&reuse,&views,&s,pp) && !reuse.valid);read_fail=0;

    /* A mutation in an un-copied shared branch changes no private descriptor;
     * full synchronization and reuse leave exactly the same hardware views. */
    setup(&s);memset(&reuse,0,sizeof reuse);
    CHECK(sprr_views_init(&views,&s));CHECK(sprr_views_prepare(&views,&s,0));compare(&s,pp);
    put(BASE+0x4000,0,DATA+0x40000+3+ATTR+PT_UXN+PT_PXN);
    uint64_t hits=reuse.hits;compare(&s,pp);CHECK(reuse.hits==hits+1);
    put(BASE+0x3000,0,DATA+3+ATTR+PT_PXN+(2UL<<6)); /* unsupported selector9 */
    saved_writes=writes;CHECK(!refresh(&s,pp));CHECK(writes==saved_writes && !reuse.valid);
    printf("SPRR exact-content reuse: %u checks, %u failures\n",checks,failed);
    return failed ? 1 : 0;
}

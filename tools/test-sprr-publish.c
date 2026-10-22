/* SPDX-License-Identifier: MIT */
#define main baseline_view_tests
#include "test-sprr-view.c"
#undef main
#include "sprr-publish.h"

static struct sprr_publish_state publication;
static unsigned char visible[BYTES],expected[BYTES];
static int tracked_write(void *ctx,uint64_t pa,uint64_t value)
{
    uint64_t old;if(rd(ctx,pa,&old))return -1;
    if(old==value)return 0;
    if(!sprr_publish_note(&publication,&views,pa))return -1;
    return wr(ctx,pa,value);
}
static void publish_cpu(unsigned cpu)
{
    CHECK(sprr_publish_prepare(&publication,&views));
    for(unsigned level=4;level--;)for(unsigned n=0;n<views.count;n++) {
        if(views.tables[n].level!=level)continue;
        publication.pages++;
        if(!sprr_publish_needed(&publication,cpu,n)) {publication.skipped++;continue;}
        uint64_t offset=views.tables[n].copy[cpu]-BASE;
        if(level<3)for(unsigned entry=0;entry<512;entry++) {
            uint64_t d;memcpy(&d,ram+offset+8*entry,8);
            if((d&3)!=3)continue;
            for(unsigned child=0;child<views.count;child++)
                if(views.tables[child].copy[cpu]==(d&PT_OA_MASK)) {
                    uint64_t child_offset=views.tables[child].copy[cpu]-BASE;
                    CHECK(!memcmp(visible+child_offset,ram+child_offset,4096));
                }
        }
        memcpy(visible+offset,ram+offset,4096);
        CHECK(sprr_publish_complete(&publication,cpu,n));
    }
    publication.publishes++;
}
static void compare_cpu(struct shadow *s,unsigned cpu,uint64_t permission)
{
    struct sprr_views original=views;memcpy(before,ram,sizeof ram);
    s->write=wr;CHECK(sprr_views_sync_cpu(&views,s,cpu,permission));
    struct sprr_views wanted=views;memcpy(expected,ram,sizeof ram);
    views=original;memcpy(ram,before,sizeof ram);s->write=tracked_write;
    CHECK(sprr_views_sync_cpu(&views,s,cpu,permission));
    CHECK(!memcmp(ram,expected,sizeof ram) && !memcmp(&views,&wanted,sizeof views));
    publish_cpu(cpu);
    for(unsigned n=0;n<views.count;n++) {
        uint64_t offset=views.tables[n].copy[cpu]-BASE;
        CHECK(!memcmp(visible+offset,expected+offset,4096));
        CHECK(!sprr_publish_needed(&publication,cpu,n));
    }
}
int main(void)
{
    CHECK(!baseline_view_tests());
    struct shadow s;setup(&s);memset(visible,0xa5,sizeof visible);
    CHECK(sprr_views_init(&views,&s));CHECK(sprr_views_prepare(&views,&s,0));
    uint64_t pp[6];for(unsigned cpu=0;cpu<6;cpu++)pp[cpu]=SPRR_PPERM_INITIAL;
    for(unsigned round=0;round<64;round++) {
        if(round==8)CHECK(sprr_views_prepare(&views,&s,0x200000));
        if(round==16) {
            put(BASE+0x2000,2,BASE+0x5000+3);
            put(BASE+0x5000,0,DATA+3+ATTR+PT_UXN+PT_PXN);
            CHECK(sprr_views_prepare(&views,&s,0x400000));
            put(BASE+0x5000,0,0); /* newly private, entirely zero child */
        }
        if(round%7==3)put(BASE+0x3000,0,0);
        else if(round%7==4)put(BASE+0x3000,0,DATA+0x20000+3+ATTR+PT_UXN);
        if(round%5==2)pp[round%6]^=0x100;
        for(unsigned cpu=0;cpu<6;cpu++)compare_cpu(&s,cpu,pp[cpu]);
        CHECK(!publication.errors && publication.count==views.count);
        CHECK(publication.pages==publication.flushed+publication.skipped);
    }
    CHECK(publication.skipped>publication.flushed*4 && publication.writes>0);
    uint64_t flushed=publication.flushed,writes_before=publication.writes;
    for(unsigned cpu=0;cpu<6;cpu++)compare_cpu(&s,cpu,pp[cpu]);
    CHECK(publication.flushed==flushed && publication.writes==writes_before);
    struct sprr_publish_state clean=publication;
    CHECK(sprr_publish_note(&publication,&views,BASE+8)); /* source, not copy */
    CHECK(!memcmp(&clean,&publication,sizeof clean));
    memcpy(before,ram,sizeof ram);clean=publication;s.write=tracked_write;
    CHECK(!sprr_views_sync_cpu(&views,&s,0,SPRR_PPERM_INITIAL^1));
    CHECK(!memcmp(before,ram,sizeof ram) && !memcmp(&clean,&publication,sizeof clean));
    printf("Publication fixture: %llu considered, %llu flushed, %llu skipped\n",
        (unsigned long long)publication.pages,(unsigned long long)publication.flushed,
        (unsigned long long)publication.skipped);

    struct sprr_publish_state p={0};struct sprr_views v={.canonical_root=BASE,.count=128};
    for(unsigned n=0;n<128;n++)for(unsigned cpu=0;cpu<6;cpu++)
        v.tables[n].copy[cpu]=BASE+0x10000+4096UL*(6*n+cpu);
    CHECK(sprr_publish_prepare(&p,&v));
    for(unsigned cpu=0;cpu<6;cpu++)for(unsigned n=0;n<128;n++) {
        CHECK(sprr_publish_needed(&p,cpu,n));CHECK(sprr_publish_complete(&p,cpu,n));
    }
    const unsigned edges[]={0,63,64,127};
    for(unsigned cpu=0;cpu<6;cpu++)for(unsigned i=0;i<4;i++) {
        unsigned n=edges[i];CHECK(sprr_publish_note(&p,&v,v.tables[n].copy[cpu]+4088));
        CHECK(sprr_publish_needed(&p,cpu,n));CHECK(sprr_publish_complete(&p,cpu,n));
    }
    CHECK(!p.errors && p.writes==24 && p.flushed==792);
    v.count=127;CHECK(!sprr_publish_prepare(&p,&v));CHECK(p.count==128);
    v.count=128;v.canonical_root+=4096;CHECK(!sprr_publish_prepare(&p,&v));
    v.canonical_root=BASE;CHECK(!sprr_publish_note(&p,&v,BASE+1));
    CHECK(!sprr_publish_complete(&p,0,0));CHECK(!sprr_publish_complete(&p,6,0));
    CHECK(!sprr_publish_complete(&p,0,128));CHECK(p.errors==6);
    CHECK(!sprr_publish_needed(&p,0,128) && !sprr_publish_needed(&p,6,0));
    printf("SPRR publication: %u checks, %u failures\n",checks,failed);
    return failed ? 1 : 0;
}

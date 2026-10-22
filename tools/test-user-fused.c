/* SPDX-License-Identifier: MIT */
#define main inherited_fused_tests
#define sprr_views_sync_user_all sprr_views_sync_user_fused
#include "test-tpro-view.c"
#undef sprr_views_sync_user_all
#undef main
int sprr_views_sync_user_all(struct sprr_views *,const struct shadow *,
                            const struct sprr_state states[SPRR_VIEW_CPUS],
                            const int el0[SPRR_VIEW_CPUS]);

static uint64_t fail_write;
static int ordered_write(void *ctx,uint64_t pa,uint64_t value)
{
    if(pa==fail_write)return -1;
    /* A copied table pointer must never precede its complete child. */
    if((value&3)==3)for(unsigned n=0;n<views.count;n++)
        for(unsigned cpu=0;cpu<6;cpu++)if((value&PT_OA_MASK)==views.tables[n].copy[cpu]) {
            uint64_t at=views.tables[n].copy[cpu]-BASE;
            CHECK(!memcmp(ram+at,expected+at,4096));
        }
    return wr(ctx,pa,value);
}
static void compare_all(struct shadow *s,const struct sprr_state state[6],const int modes[6])
{
    struct sprr_views original=views;memcpy(before,ram,sizeof ram);uint64_t old_epoch=epoch;
    unsigned old_writes=writes;uint64_t start=reads;s->write=wr;
    int reference=sprr_views_sync_user_all(&views,s,state,modes);
    uint64_t reference_reads=reads-start;unsigned reference_writes=writes-old_writes;
    struct sprr_views wanted=views;memcpy(expected,ram,sizeof ram);
    views=original;epoch=old_epoch;memcpy(ram,before,sizeof ram);
    old_writes=writes;start=reads;s->write=ordered_write;
    int candidate=sprr_views_sync_user_fused(&views,s,state,modes);
    CHECK(candidate==reference);
    CHECK(!memcmp(ram,expected,sizeof ram) && !memcmp(&views,&wanted,sizeof views));
    CHECK(writes-old_writes==reference_writes);
    if(candidate)CHECK(reads-start<reference_reads);
    else CHECK(writes==old_writes);
    s->write=wr;
}
int main(void)
{
    CHECK(!inherited_fused_tests());
    struct shadow s=setup();struct sprr_state state[6]={0};int modes[6];
    for(unsigned cpu=0;cpu<6;cpu++) {sprr_root_reset(&state[cpu],0xa);modes[cpu]=cpu&1;}
    CHECK(sprr_views_init(&views,&s));CHECK(sprr_views_prepare_user(&views,&s));
    /* Every selector and independent CPU permission/mode combination agrees
     * with the original six-view implementation, including all refusals. */
    for(unsigned pattern=0;pattern<64;pattern++) {
        for(unsigned cpu=0;cpu<6;cpu++) {
            state[cpu].uperm=SPRR_UPERM_INITIAL|((uint64_t)((pattern>>cpu)&1)<<36);
            state[cpu].pperm=SPRR_PPERM_INITIAL|((uint64_t)((pattern>>(5-cpu))&1)<<36)|
                ((uint64_t)(cpu&1)<<8);
            modes[cpu]=(int)((pattern+cpu)&1);
        }
        for(unsigned selector=0;selector<16;selector++) {
            put(BASE+0x3000,0,leaf(DATA,selector));compare_all(&s,state,modes);
        }
    }
    put(BASE+0x3000,0,leaf(DATA,9));
    for(unsigned cpu=0;cpu<6;cpu++) {
        state[cpu].uperm^=1;compare_all(&s,state,modes);state[cpu].uperm^=1;
        state[cpu].umprr^=0x40000;compare_all(&s,state,modes);state[cpu].umprr^=0x40000;
        int mode=modes[cpu];modes[cpu]=2;compare_all(&s,state,modes);modes[cpu]=mode;
        uint64_t copy=views.tables[views.count-1].copy[cpu];
        views.tables[views.count-1].copy[cpu]=copy|8;compare_all(&s,state,modes);
        views.tables[views.count-1].copy[cpu]=copy;
    }
    for(unsigned page=0;page<6;page++)for(unsigned edge=0;edge<2;edge++) {
        fail_read=BASE+4096UL*page+(edge ? 4088 : 0);compare_all(&s,state,modes);
    }
    fail_read=0;compare_all(&s,state,modes);
    /* Newly private branches, including an entirely zero child. */
    CHECK(sprr_views_prepare_user_leaf(&views,&s,0x401000));compare_all(&s,state,modes);
    put(BASE+0x5000,1,leaf(DATA+0x10000,9));compare_all(&s,state,modes);
    put(BASE+0x5000,0,0);put(BASE+0x5000,1,0);compare_all(&s,state,modes);
    /* Callback failures remain terminal; no successful sync is counted. */
    struct sprr_views original=views;fail_write=views.tables[0].copy[5];s.write=ordered_write;
    CHECK(!sprr_views_sync_user_fused(&views,&s,state,modes));
    CHECK(!memcmp(original.syncs,views.syncs,sizeof original.syncs));
    printf("Fused six-CPU user views: %u checks, %u failures\n",checks,failures);
    return failures ? 1 : 0;
}

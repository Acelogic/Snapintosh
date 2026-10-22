/* SPDX-License-Identifier: MIT */
#define main inherited_tpro_tests
#include "test-tpro-view.c"
#undef main

static unsigned maps,misaligned;
static uint64_t fail_write,reference_reads,mapped_reads;
static const volatile uint64_t *table_reader(void *ctx,uint64_t pa)
{
    (void)ctx;maps++;
    if((pa&4095) || pa<BASE || pa>BASE+BYTES-4096 ||
       (fail_read>=pa && fail_read-pa<4096))return 0;
    return (const volatile uint64_t *)(ram+(pa-BASE)+!!misaligned);
}
static int checked_write(void *ctx,uint64_t pa,uint64_t value)
{
    if(pa==fail_write)return -1;
    if((value&3)==3)for(unsigned n=0;n<views.count;n++)for(unsigned cpu=0;cpu<6;cpu++)
        if((value&PT_OA_MASK)==views.tables[n].copy[cpu])
            CHECK(!memcmp(ram+(views.tables[n].copy[cpu]-BASE),
                          expected+(views.tables[n].copy[cpu]-BASE),4096));
    return wr(ctx,pa,value);
}
static int reference_write(void *ctx,uint64_t pa,uint64_t value)
{return pa==fail_write ? -1 : wr(ctx,pa,value);}
static int compare(struct shadow *s,unsigned cpu,const struct sprr_state *state,int mode,
    int user,struct sprr_view_proof *proof,struct sprr_view_proof_stats *stats,
    sprr_table_reader reader)
{
    struct sprr_views initial=views;
    struct sprr_view_proof old_proof=*proof;
    struct sprr_view_proof_stats old_stats=*stats;
    uint64_t old_epoch=epoch,start=reads;unsigned old_writes=writes;
    memcpy(before,ram,sizeof ram);s->write=reference_write;
    int reference=user ? sprr_views_sync_user_cached(&views,s,cpu,state,mode,&epoch,proof,stats,1) :
        sprr_views_sync_cpu(&views,s,cpu,state->pperm);
    reference_reads+=reads-start;
    struct sprr_views wanted=views;struct sprr_view_proof wanted_proof=*proof;
    struct sprr_view_proof_stats wanted_stats=*stats;
    uint64_t wanted_epoch=epoch;unsigned wanted_writes=writes-old_writes;
    memcpy(expected,ram,sizeof ram);
    views=initial;epoch=old_epoch;*proof=old_proof;*stats=old_stats;
    memcpy(ram,before,sizeof ram);s->write=checked_write;old_writes=writes;start=reads;maps=0;
    int candidate=user ? sprr_views_sync_user_cached_mapped(&views,s,cpu,state,mode,
        &epoch,proof,stats,1,reader) : sprr_views_sync_cpu_mapped(&views,s,cpu,state->pperm,reader);
    mapped_reads+=reads-start;
    CHECK(candidate==reference);
    CHECK(!memcmp(ram,expected,sizeof ram));CHECK(!memcmp(&views,&wanted,sizeof views));
    CHECK(!memcmp(proof,&wanted_proof,sizeof *proof));CHECK(!memcmp(stats,&wanted_stats,sizeof *stats));
    CHECK(epoch==wanted_epoch && writes-old_writes==wanted_writes);
    if(candidate && reader)CHECK(maps==views.count);
    if(!candidate && !fail_write)CHECK(writes==old_writes && !memcmp(ram,before,sizeof ram));
    s->write=wr;return candidate;
}
#ifndef TEST_VIEW_TABLE_ENTRY
#define TEST_VIEW_TABLE_ENTRY main
#endif
int TEST_VIEW_TABLE_ENTRY(void)
{
    CHECK(!inherited_tpro_tests());
    epoch=0; /* the inherited saturation test intentionally leaves UINT64_MAX */
    struct sprr_state state={0};sprr_root_reset(&state,0xa);
    struct sprr_view_proof proof={0};struct sprr_view_proof_stats stats={0};
    struct shadow s=setup();CHECK(sprr_views_init(&views,&s));CHECK(sprr_views_prepare_user(&views,&s));
    for(unsigned selector=0;selector<16;selector++)for(unsigned cpu=0;cpu<6;cpu++)
        for(unsigned pattern=0;pattern<8;pattern++) {
            put(BASE+0x3000,0,leaf(DATA,selector));
            state.uperm=SPRR_UPERM_INITIAL|((uint64_t)(pattern&1)<<36);
            state.pperm=SPRR_PPERM_INITIAL|((uint64_t)((pattern>>1)&1)<<36)|((uint64_t)(cpu&1)<<8);
            compare(&s,cpu,&state,(pattern>>2)&1,1,&proof,&stats,table_reader);
        }
    put(BASE+0x3000,0,leaf(DATA,9));
    proof=(struct sprr_view_proof){0};stats=(struct sprr_view_proof_stats){0};
    /* Stable coverage hits, misses, periodic independent samples, and epoch
     * saturation must make exactly the same decisions and private stores. */
    for(unsigned i=0;i<260;i++) {
        state.uperm^=SPRR_UPERM_TPRO_WRITE;state.pperm^=SPRR_UPERM_TPRO_WRITE;
        if(!(i%31))sprr_view_epoch_advance(&epoch);
        CHECK(compare(&s,i%6,&state,i&1,1,&proof,&stats,table_reader));
    }
    CHECK(stats.hits>240 && stats.verified>=4 && !stats.mismatches);
    epoch=UINT64_MAX;CHECK(compare(&s,0,&state,0,1,&proof,&stats,table_reader));
    CHECK(!proof.valid);
    CHECK(compare(&s,1,&state,1,1,&proof,&stats,0));
    /* Unmapped/unaligned sources and bad metadata fail before any store. */
    for(unsigned n=0;n<views.count;n++) {
        fail_read=views.tables[n].source+4088;
        CHECK(!compare(&s,0,&state,1,1,&proof,&stats,table_reader));
    }
    fail_read=0;memcpy(before,ram,sizeof ram);unsigned saved=writes;
    misaligned=1;CHECK(!sprr_views_sync_user_cached_mapped(&views,&s,0,&state,1,
        &epoch,&proof,&stats,1,table_reader));
    CHECK(writes==saved && !memcmp(before,ram,sizeof ram) && !proof.valid);misaligned=0;
    /* A cached proof cannot hide corruption from its independent word walk. */
    epoch=42;proof=(struct sprr_view_proof){s.root,views.count,epoch,1};stats.hits=0;
    fail_read=BASE+0x5000;maps=0;
    CHECK(!sprr_views_sync_user_cached_mapped(&views,&s,0,&state,0,&epoch,&proof,&stats,1,table_reader));
    CHECK(!maps && !proof.valid && stats.mismatches==1 && writes==saved);fail_read=0;
    /* Terminal write failure preserves the reference's partial state and
     * does not count a completed sync or renew a proof. */
    fail_write=views.tables[3].copy[0]+2048;
    CHECK(!compare(&s,0,&state,0,1,&proof,&stats,table_reader));fail_write=0;
    /* Kernel selector translation, every CPU, and independent installed-view
     * verification continue through the original per-word reference path. */
    s=setup();proof=(struct sprr_view_proof){0};stats=(struct sprr_view_proof_stats){0};
    for(unsigned i=0;i<4;i++)put(BASE+0x3000,i,leaf(DATA+4096UL*i,2));
    put(BASE+0x4000,0,leaf(DATA,3));put(BASE+0x5000,0,leaf(DATA+0x8000,3));
    CHECK(sprr_views_init(&views,&s));CHECK(sprr_views_prepare(&views,&s,0));
    for(unsigned selector=0;selector<16;selector++)for(unsigned cpu=0;cpu<6;cpu++)
        for(unsigned pattern=0;pattern<4;pattern++) {
            put(BASE+0x3000,0,leaf(DATA,selector));
            state.pperm=SPRR_PPERM_INITIAL|((uint64_t)(pattern&1)<<8)|((uint64_t)(pattern>>1)<<36);
            int ok=compare(&s,cpu,&state,0,0,&proof,&stats,table_reader);
            CHECK(ok==(selector!=9));if(ok)CHECK(sprr_views_verify_cpu(&views,&s,cpu,state.pperm));
        }
    put(BASE+0x3000,0,leaf(DATA,2));
    for(unsigned bad=0;bad<7;bad++) {
        struct sprr_views good=views;uint64_t pp=state.pperm;
        if(bad==0)views.count=SPRR_VIEW_TABLES+1;
        if(bad==1)views.tables[3].source++;
        if(bad==2)views.tables[3].level=4;
        if(bad==3)views.tables[3].copy[0]=0;
        if(bad==4)views.tables[3].copy[0]++;
        if(bad==5)state.pperm=0;
        CHECK(!compare(&s,bad==6 ? 6 : 0,&state,0,0,&proof,&stats,table_reader));
        views=good;state.pperm=pp;
    }
    for(unsigned n=0;n<views.count;n++) {
        fail_read=views.tables[n].source+4088;
        CHECK(!compare(&s,0,&state,0,0,&proof,&stats,table_reader));
    }
    fail_read=0;CHECK(compare(&s,0,&state,0,0,&proof,&stats,0));
    CHECK(mapped_reads<reference_reads);
    printf("Private sync callback reads: %llu mapped versus %llu reference\n",
        (unsigned long long)mapped_reads,(unsigned long long)reference_reads);
    printf("Mapped private sync: %u checks, %u failures\n",checks,failures);
    return !!failures;
}

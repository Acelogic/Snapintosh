/* SPDX-License-Identifier: MIT */
#define TEST_VIEW_TABLE_ENTRY inherited_mapped_tests
#include "test-view-table-read.c"
#undef TEST_VIEW_TABLE_ENTRY

static uint64_t attempts,baseline_attempts,compared_attempts,copy_fail;
static int copy_misaligned,ordering;
static const volatile uint64_t *copy_reader(void *ctx,uint64_t pa)
{
    (void)ctx;
    if(pa==copy_fail || (pa&4095) || pa<BASE || pa>BASE+BYTES-4096)return 0;
    return (const volatile uint64_t *)(ram+(pa-BASE)+!!copy_misaligned);
}
static int idempotent_write(void *ctx,uint64_t pa,uint64_t value)
{
    uint64_t old;attempts++;
    if(rd(ctx,pa,&old))return -1;
    if(old==value)return 0;
    return ordering ? checked_write(ctx,pa,value) : reference_write(ctx,pa,value);
}
static int compare_stores(struct shadow *s,unsigned cpu,const struct sprr_state *state,
    int mode,int user,struct sprr_view_proof *proof,struct sprr_view_proof_stats *stats)
{
    struct sprr_views initial=views;
    struct sprr_view_proof old_proof=*proof;
    struct sprr_view_proof_stats old_stats=*stats;
    uint64_t old_epoch=epoch,start_attempts=attempts;unsigned old_writes=writes;
    memcpy(before,ram,sizeof ram);s->write=idempotent_write;ordering=0;
    int reference=user ? sprr_views_sync_user_cached_mapped(&views,s,cpu,state,mode,
        &epoch,proof,stats,1,table_reader) : sprr_views_sync_cpu_mapped(&views,s,cpu,state->pperm,table_reader);
    uint64_t wanted_attempts=attempts-start_attempts;baseline_attempts+=wanted_attempts;
    struct sprr_views wanted=views;struct sprr_view_proof wanted_proof=*proof;
    struct sprr_view_proof_stats wanted_stats=*stats;
    uint64_t wanted_epoch=epoch;unsigned wanted_writes=writes-old_writes;
    memcpy(expected,ram,sizeof ram);memcpy(ram,before,sizeof ram);
    views=initial;epoch=old_epoch;*proof=old_proof;*stats=old_stats;
    old_writes=writes;start_attempts=attempts;ordering=1;
    struct sprr_store_compare_stats compare={0};
    int candidate=user ? sprr_views_sync_user_cached_compared(&views,s,cpu,state,mode,
        &epoch,proof,stats,1,table_reader,copy_reader,&compare) :
        sprr_views_sync_cpu_compared(&views,s,cpu,state->pperm,table_reader,copy_reader,&compare);
    uint64_t actual_attempts=attempts-start_attempts;compared_attempts+=actual_attempts;
    CHECK(candidate==reference);CHECK(!memcmp(ram,expected,sizeof ram));
    CHECK(!memcmp(&views,&wanted,sizeof views));CHECK(epoch==wanted_epoch);
    CHECK(!memcmp(proof,&wanted_proof,sizeof *proof));CHECK(!memcmp(stats,&wanted_stats,sizeof *stats));
    CHECK(writes-old_writes==wanted_writes);
    if(candidate) {
        CHECK(compare.calls==1 && compare.complete==1 && !compare.failures);
        CHECK(compare.tables==views.count && compare.compared==views.count*512);
        CHECK(compare.compared==compare.skipped+compare.changed);
        CHECK(actual_attempts==compare.changed && wanted_attempts==compare.compared);
    }
    s->write=wr;ordering=0;return candidate;
}
int main(void)
{
    CHECK(!inherited_mapped_tests());epoch=0;
    struct sprr_state state={0};sprr_root_reset(&state,0xa);
    struct sprr_view_proof proof={0};struct sprr_view_proof_stats stats={0};
    struct shadow s=setup();CHECK(sprr_views_init(&views,&s));CHECK(sprr_views_prepare_user(&views,&s));
    for(unsigned selector=0;selector<16;selector++)for(unsigned cpu=0;cpu<6;cpu++)
        for(unsigned pattern=0;pattern<8;pattern++) {
            put(BASE+0x3000,0,leaf(DATA,selector));
            state.uperm=SPRR_UPERM_INITIAL|((uint64_t)(pattern&1)<<36);
            state.pperm=SPRR_PPERM_INITIAL|((uint64_t)((pattern>>1)&1)<<36)|((uint64_t)(cpu&1)<<8);
            compare_stores(&s,cpu,&state,(pattern>>2)&1,1,&proof,&stats);
        }
    put(BASE+0x3000,0,leaf(DATA,9));proof=(struct sprr_view_proof){0};stats=(struct sprr_view_proof_stats){0};
    for(unsigned i=0;i<130;i++) {
        state.uperm^=SPRR_UPERM_TPRO_WRITE;
        CHECK(compare_stores(&s,i%6,&state,i&1,1,&proof,&stats));
    }
    CHECK(stats.verified>=2 && !stats.mismatches);
    /* Every destination mapping is preflighted before the first write. */
    for(unsigned n=0;n<views.count;n++) {
        struct sprr_store_compare_stats c={0};copy_fail=views.tables[n].copy[0];
        memcpy(before,ram,sizeof ram);unsigned old=writes;
        CHECK(!sprr_views_sync_user_cached_compared(&views,&s,0,&state,0,&epoch,&proof,&stats,
            1,table_reader,copy_reader,&c));
        CHECK(c.calls==1 && c.failures==1 && !c.complete && !c.compared);
        CHECK(writes==old && !memcmp(before,ram,sizeof ram) && !proof.valid);
    }
    copy_fail=0;copy_misaligned=1;
    struct sprr_store_compare_stats c={0};unsigned old=writes;
    CHECK(!sprr_views_sync_cpu_compared(&views,&s,0,state.pperm,table_reader,copy_reader,&c));
    CHECK(writes==old && c.failures==1);copy_misaligned=0;
    /* Compare the terminal partial state for a genuinely changed leaf. */
    put(views.tables[3].copy[0],0,0);fail_write=views.tables[3].copy[0];
    CHECK(!compare_stores(&s,0,&state,0,1,&proof,&stats));fail_write=0;
    s=setup();proof=(struct sprr_view_proof){0};stats=(struct sprr_view_proof_stats){0};
    for(unsigned i=0;i<4;i++)put(BASE+0x3000,i,leaf(DATA+4096UL*i,2));
    put(BASE+0x4000,0,leaf(DATA,3));put(BASE+0x5000,0,leaf(DATA+0x8000,3));
    CHECK(sprr_views_init(&views,&s));CHECK(sprr_views_prepare(&views,&s,0));
    for(unsigned selector=0;selector<16;selector++)for(unsigned cpu=0;cpu<6;cpu++)
        for(unsigned pattern=0;pattern<4;pattern++) {
            put(BASE+0x3000,0,leaf(DATA,selector));
            state.pperm=SPRR_PPERM_INITIAL|((uint64_t)(pattern&1)<<8)|((uint64_t)(pattern>>1)<<36);
            int ok=compare_stores(&s,cpu,&state,0,0,&proof,&stats);
            CHECK(ok==(selector!=9));if(ok)CHECK(sprr_views_verify_cpu(&views,&s,cpu,state.pperm));
        }
    CHECK(compared_attempts<baseline_attempts);
    printf("Private callback attempts: %llu compared / %llu reference\n",
        (unsigned long long)compared_attempts,(unsigned long long)baseline_attempts);
    printf("Private store comparison: %u checks, %u failures\n",checks,failures);
    return !!failures;
}

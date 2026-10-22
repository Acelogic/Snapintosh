/* SPDX-License-Identifier: MIT */
#define main inherited_tpro_tests
#include "test-tpro-view.c"
#undef main
#include "sprr-private-pages.h"
#include "../compat/table-pool.h"

static struct sprr_private_pages provenance;
static struct table_pool pool;
static uint32_t used;
static int selective;
static struct sprr_views roots[2], reference_roots[2];
static struct sprr_view_proof proofs[2];
static struct sprr_view_proof_stats counters[2];
static uint64_t total_hits[2],total_reads[2];
static int tracked_write(void *ctx,uint64_t pa,uint64_t value)
{
    (void)ctx;uint64_t old;
    if(rd(0,pa,&old))return -1;
    if(old!=value) {
        int priv=sprr_private_write(&provenance,BASE,BASE+(uint64_t)used*4096,pa);
        if(priv<0)return -1;
        if(!selective || !priv)sprr_view_epoch_advance(&epoch);
    }
    memcpy(ram+(pa-BASE),&value,8);writes++;return 0;
}
static uint64_t allocate(unsigned owner,int private)
{
    int index=table_pool_take(&pool,&used,BYTES/4096,owner);
    if(index<0)return 0;
    CHECK(sprr_private_clear(&provenance,(unsigned)index,0));
    sprr_view_epoch_advance(&epoch);
    uint64_t pa=BASE+(uint64_t)index*4096;memset(ram+(pa-BASE),0,4096);
    if(private)CHECK(sprr_private_mark(&provenance,(unsigned)index));
    return pa;
}
static uint64_t private_alloc(void *ctx) {return allocate(*(unsigned *)ctx,1);}
static struct sprr_user_prepare_plan prepare;
static struct sprr_user_prepare_stats prepared;
static void differential(int mode)
{
    selective=mode;epoch=0;reads=0;used=0;
    memset(ram,0,sizeof ram);memset(&pool,0,sizeof pool);
    memset(&provenance,0,sizeof provenance);memset(roots,0,sizeof roots);
    memset(proofs,0,sizeof proofs);memset(counters,0,sizeof counters);
    memset(&prepared,0,sizeof prepared);
    unsigned owner[2]={1,2};struct shadow s[2];
    struct sprr_state states[6];int modes[6];
    for(unsigned c=0;c<6;c++){sprr_root_reset(&states[c],0xa);modes[c]=c&1;}
    for(unsigned r=0;r<2;r++) {
        uint64_t pages[6];for(unsigned i=0;i<6;i++)pages[i]=allocate(owner[r],0);
        CHECK(!tracked_write(0,pages[0],pages[1]|3));
        CHECK(!tracked_write(0,pages[1],pages[2]|3));
        for(unsigned i=0;i<3;i++)CHECK(!tracked_write(0,pages[2]+8UL*i,pages[i+3]|3));
        CHECK(!tracked_write(0,pages[3],leaf(DATA+4096UL*r,9)));
        CHECK(!tracked_write(0,pages[4],leaf(DATA+8192UL*r,7)));
        s[r]=(struct shadow){.txsz=17,.root=pages[0],.alloc=private_alloc,
            .alloc_ctx=&owner[r],.read=rd,.write=tracked_write};
        CHECK(sprr_views_init(&roots[r],&s[r]));
        CHECK(sprr_views_prepare_sync_user_fused(&roots[r],&s[r],states,modes,&prepare,&prepared));
    }
    for(unsigned step=0;step<768;step++) {
        unsigned r=step&1,cpu=(step/2)%6;
        struct sprr_state st=states[cpu];
        st.uperm|=(uint64_t)((step/3)&1)<<36;
        st.pperm|=(uint64_t)((step/5)&1)<<36;
        /* Canonical change in an ordinary branch, through exactly the same
         * writer callback used by private sync. It must invalidate both roots. */
        if(!(step%47)) {
            uint64_t target=s[r].root+4*4096;
            uint64_t old_epoch=epoch;
            CHECK(!tracked_write(0,target,leaf(DATA+(uint64_t)(step+1)*4096,7)));
            CHECK(epoch==old_epoch+1);
        }
        CHECK(sprr_views_sync_user_cached(&roots[r],&s[r],cpu,&st,(step/2)&1,
            &epoch,&proofs[r],&counters[r],1));
        CHECK(proofs[r].epoch==epoch && !counters[r].mismatches);
    }
    total_hits[mode]=counters[0].hits+counters[1].hits;total_reads[mode]=reads;
    if(!mode){memcpy(expected,ram,sizeof ram);memcpy(reference_roots,roots,sizeof roots);}
    else {CHECK(!memcmp(expected,ram,sizeof ram));CHECK(!memcmp(reference_roots,roots,sizeof roots));}
    CHECK(provenance.private_writes>100 && provenance.writes>provenance.private_writes);
    CHECK(!provenance.errors);
    /* Retirement/reuse transfers a previously private page to a canonical
     * owner. Its bit must be gone before the first new descriptor is written. */
    sprr_view_epoch_advance(&epoch);
    for(unsigned i=0;i<used;i++)if(pool.owner[i]==1)CHECK(sprr_private_clear(&provenance,i,1));
    int retired=table_pool_release(&pool,used,1);CHECK(retired>0);
    for(int i=0;i<retired;i++) {
        uint64_t pa=allocate(3,0),old_epoch=epoch;
        CHECK(pa && !tracked_write(0,pa,3));CHECK(epoch==old_epoch+1);
    }
    /* A stale bit from a previous lifetime is cleared even if a caller omitted
     * retirement cleanup; normal allocation clearing is an independent guard. */
    CHECK(sprr_private_mark(&provenance,0));CHECK(sprr_private_clear(&provenance,0,0));
    CHECK(!sprr_private_write(&provenance,BASE,BASE+(uint64_t)used*4096,BASE));
    /* Fault injection on a sampled cache hit: an uncovered canonical selector9
     * must fail without repairing memory even if its epoch was not advanced. */
    unsigned r=1;uint64_t bad=s[r].root+5*4096,d=leaf(DATA,9);
    memcpy(ram+(bad-BASE),&d,8);proofs[r]=(struct sprr_view_proof){s[r].root,roots[r].count,epoch,1};
    counters[r].hits=64;unsigned n=writes;
    CHECK(!sprr_views_sync_user_cached(&roots[r],&s[r],0,&states[0],0,
        &epoch,&proofs[r],&counters[r],1));
    CHECK(counters[r].mismatches==1 && writes==n && !proofs[r].valid);
}
int main(void)
{
    CHECK(!inherited_tpro_tests());
    differential(0);differential(1);
    CHECK(total_hits[1]>total_hits[0]);CHECK(total_reads[1]<total_reads[0]);
    struct sprr_private_pages p={0};
    for(unsigned i=0;i<SPRR_PRIVATE_PAGES;i++) {
        CHECK(sprr_private_clear(&p,i,0));CHECK(sprr_private_mark(&p,i));
        CHECK(sprr_private_write(&p,BASE,BASE+SPRR_PRIVATE_PAGES*4096UL,
            BASE+i*4096UL+(i&1 ? 4088 : 0))==1);
        CHECK(sprr_private_clear(&p,i,1));
        CHECK(sprr_private_write(&p,BASE,BASE+SPRR_PRIVATE_PAGES*4096UL,BASE+i*4096UL)==0);
    }
    CHECK(!p.errors && p.private_writes==SPRR_PRIVATE_PAGES);
    CHECK(!sprr_private_mark(&p,SPRR_PRIVATE_PAGES));
    CHECK(!sprr_private_clear(&p,SPRR_PRIVATE_PAGES,0));
    CHECK(!sprr_private_clear(&p,0,2));
    CHECK(sprr_private_mark(&p,0));CHECK(!sprr_private_mark(&p,0));
    uint64_t invalid[][3]={{BASE,BASE,BASE},{BASE+1,BASE+4096,BASE},
        {BASE,BASE+4095,BASE},{BASE,BASE+4096,BASE-8},{BASE,BASE+4096,BASE+4096},
        {BASE,BASE+4096,BASE+1},{BASE,BASE+(SPRR_PRIVATE_PAGES+1UL)*4096,BASE}};
    for(unsigned i=0;i<sizeof invalid/sizeof invalid[0];i++)
        CHECK(sprr_private_write(&p,invalid[i][0],invalid[i][1],invalid[i][2])==-1);
    CHECK(p.errors==11);
    printf("Private allocation epoch: %u checks, %u failures; hits %llu vs %llu; reads %llu vs %llu\n",
        checks,failures,(unsigned long long)total_hits[1],(unsigned long long)total_hits[0],
        (unsigned long long)total_reads[1],(unsigned long long)total_reads[0]);
    return failures ? 1 : 0;
}

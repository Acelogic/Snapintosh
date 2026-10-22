/* SPDX-License-Identifier: MIT */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../shadow/root-publish.h"

static unsigned checks;
#define CHECK(x) do {checks++;if(!(x)){fprintf(stderr,"line %d: %s\n",__LINE__,#x);exit(1);}}while(0)
#define PAGES 257u
#define BASE UINT64_C(0xae1400000)
struct fixture {
    unsigned char cpu[PAGES*4096],bus[PAGES*4096],reference[PAGES*4096];
    uint64_t addresses[ROOT_PUBLISH_PAGES];
    unsigned calls,fail;
    int geometry_only;
};
static struct fixture f;
static struct root_publish_state state;
static uint64_t random_state=UINT64_C(0x52c904715eba6293);
static unsigned random32(void)
{
    random_state^=random_state<<13;random_state^=random_state>>7;random_state^=random_state<<17;
    return (unsigned)random_state;
}
static int flush(void *ctx,uint64_t pa)
{
    struct fixture *m=ctx;
    CHECK(!(pa&4095) && pa>=BASE && pa-BASE<(uint64_t)ROOT_PUBLISH_PAGES*4096);
    CHECK(m->calls<ROOT_PUBLISH_PAGES);m->addresses[m->calls++]=pa;
    if(m->fail && m->calls==m->fail)return 0;
    if(!m->geometry_only) {
        CHECK(pa-BASE<sizeof(m->cpu));
        memcpy(m->bus+(pa-BASE),m->cpu+(pa-BASE),4096);
    }
    return 1;
}
static void compare(unsigned pages)
{
    f.calls=0;
    memcpy(f.reference,f.cpu,pages*4096); /* Independent full-arena publisher. */
    CHECK(root_publish_flush(&state,BASE,BASE+(uint64_t)pages*4096,flush,&f));
    CHECK(!memcmp(f.bus,f.reference,pages*4096));
    CHECK(state.calls==state.complete && !state.errors);
    CHECK(state.considered==state.published+state.skipped);
    for(unsigned w=0;w<ROOT_PUBLISH_PAGES/64;w++)CHECK(!state.bitmap[w]);
    for(unsigned n=1;n<f.calls;n++)CHECK(f.addresses[n]>f.addresses[n-1]);
}
static void memory_model(void)
{
    memset(&state,0,sizeof(state));memset(&f,0,sizeof(f));
    unsigned pages=17;
    state.always_first=BASE+2*4096;state.always_end=BASE+5*4096;
    memset(f.cpu,0xa6,pages*4096);
    CHECK(root_publish_note(&state,BASE,BASE+pages*4096,BASE,pages*4096));compare(pages);
    for(unsigned turn=0;turn<900;turn++) {
        uint64_t limit=BASE+(uint64_t)pages*4096;
        for(unsigned n=0;n<19;n++) {
            unsigned offset=(random32()%(pages*512))*8;uint64_t old,value=random32();
            memcpy(&old,f.cpu+offset,8);
            if(n%3==0)value=old;
            uint64_t notes=state.notes;
            if(old!=value)CHECK(root_publish_note(&state,BASE,limit,BASE+offset,8));
            memcpy(f.cpu+offset,&value,8);
            CHECK(state.notes==notes+(old!=value));
        }
        /* Allocation/reuse zeroes every byte even when old words looked valid. */
        if(turn%4==0 && pages<PAGES) {
            pages++;limit=BASE+(uint64_t)pages*4096;
            CHECK(root_publish_note(&state,BASE,limit,limit-4096,4096));
            memset(f.cpu+(pages-1)*4096,0,4096);
        } else {
            unsigned page=random32()%pages;
            CHECK(root_publish_note(&state,BASE,limit,BASE+page*4096,4096));
            memset(f.cpu+page*4096,0,4096);
        }
        /* Pointer transactions may straddle pages, including unaligned ranges;
         * a read-only map conservatively notes pages without changing bytes. */
        unsigned off=random32()%(pages*4096-8201),length=8201;
        CHECK(root_publish_note(&state,BASE,limit,BASE+off,length));
        if(turn%2)memset(f.cpu+off,(int)(turn&255),length);
        /* Hardware/VNCR, stacks and secondary records bypass normal callbacks. */
        memset(f.cpu+2*4096,(int)(turn&255),3*4096);
        /* Guard stores already clean their own cache line, followed by DSB. */
        unsigned guard=(random32()%(pages*64))*64;
        memset(f.cpu+guard,0x5a,64);memcpy(f.bus+guard,f.cpu+guard,64);
        compare(pages);
    }
    uint64_t published=state.published;
    compare(pages);CHECK(state.published-published==3); /* Only runtime pages. */
    CHECK(state.skipped>state.published);
}
static void bitmap_edges(void)
{
    memset(&state,0,sizeof(state));f.geometry_only=1;f.calls=0;
    uint64_t end=BASE+(uint64_t)ROOT_PUBLISH_PAGES*4096;
    for(unsigned i=0;i<ROOT_PUBLISH_PAGES;i++) {
        CHECK(root_publish_note(&state,BASE,end,BASE+(uint64_t)i*4096+4095,1));
        CHECK(state.bitmap[i/64]&(UINT64_C(1)<<(i%64)));
    }
    CHECK(root_publish_flush(&state,BASE,end,flush,&f));CHECK(f.calls==ROOT_PUBLISH_PAGES);
    CHECK(state.published==ROOT_PUBLISH_PAGES && state.skipped==0);
    for(unsigned i=0;i<ROOT_PUBLISH_PAGES;i++)CHECK(f.addresses[i]==BASE+(uint64_t)i*4096);
    f.calls=0;CHECK(root_publish_flush(&state,BASE,end,flush,&f));CHECK(!f.calls);
}
static void invalid_and_failure(void)
{
    const uint64_t bad[][4]={
        {BASE+1,BASE+4096,BASE,8},{BASE,BASE+4095,BASE,8},
        {BASE,BASE,BASE,8},{BASE,BASE-4096,BASE,8},
        {BASE,BASE+(uint64_t)(ROOT_PUBLISH_PAGES+1)*4096,BASE,8},
        {BASE,BASE+4096,BASE-1,1},{BASE,BASE+4096,BASE+4096,1},
        {BASE,BASE+4096,BASE,0},{BASE,BASE+4096,BASE+4095,2},
        {BASE,BASE+4096,BASE,UINT64_MAX},
        {UINT64_MAX-4095,0,UINT64_MAX-4095,8}
    };
    for(unsigned n=0;n<sizeof(bad)/sizeof(bad[0]);n++) {
        memset(&state,0,sizeof(state));f.calls=0;
        CHECK(!root_publish_note(&state,bad[n][0],bad[n][1],bad[n][2],bad[n][3]));
        CHECK(state.errors==1);
        CHECK(!root_publish_flush(&state,BASE,BASE+4096,flush,&f));CHECK(!f.calls);
        for(unsigned w=0;w<ROOT_PUBLISH_PAGES/64;w++)CHECK(!state.bitmap[w]);
    }
    for(unsigned limit=1;limit<130;limit++) {
        memset(&state,0,sizeof(state));f.calls=0;
        state.bitmap[limit/64]=UINT64_C(1)<<(limit%64);
        CHECK(!root_publish_flush(&state,BASE,BASE+(uint64_t)limit*4096,flush,&f));
        CHECK(!f.calls && state.errors==1 && !state.complete);
    }
    for(unsigned which=0;which<5;which++) {
        memset(&state,0,sizeof(state));f.calls=0;
        state.always_first=BASE;state.always_end=BASE+4096;
        if(which==0)state.always_first++;
        if(which==1)state.always_end++;
        if(which==2)state.always_end=BASE;
        if(which==3)state.always_end=BASE+3*4096;
        if(which==4)state.always_first=0;
        CHECK(!root_publish_flush(&state,BASE,BASE+2*4096,flush,&f));CHECK(!f.calls);
    }
    memset(&state,0,sizeof(state));f.calls=0;f.fail=2;
    CHECK(root_publish_note(&state,BASE,BASE+3*4096,BASE,3*4096));
    CHECK(!root_publish_flush(&state,BASE,BASE+3*4096,flush,&f));
    CHECK(state.bitmap[0]==7 && state.errors==1 && !state.complete && f.calls==2);
    CHECK(!root_publish_flush(&state,BASE,BASE+3*4096,flush,&f));CHECK(f.calls==2);
    memset(&state,0,sizeof(state));CHECK(!root_publish_flush(&state,BASE,BASE+4096,0,&f));
}
int main(void)
{
    memory_model();bitmap_edges();invalid_and_failure();
    printf("root publication: %u checks, 0 failures\n",checks);return 0;
}

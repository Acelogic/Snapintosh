/* SPDX-License-Identifier: MIT */
#include "txm.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define BASE 0x100000UL
#define PAGE 0x4000UL
#define TC (BASE+9*PAGE)
#define VA 0xfffffe1000000000UL
static uint8_t memory[24*PAGE],before[sizeof(memory)],hash[32];
static unsigned checks,publishes,copies,copy_fail;
static uint64_t deny;
#define CHECK(x) do {checks++;if(!(x)){fprintf(stderr,"FAIL %u: %s\n",__LINE__,#x);exit(1);}} while(0)
static volatile uint8_t *map(void *ctx,uint64_t pa,uint64_t size)
{
    CHECK(ctx==memory);
    if(pa==deny || pa<BASE || pa-BASE>sizeof(memory) || size>sizeof(memory)-(pa-BASE))return 0;
    return memory+(pa-BASE);
}
static void publish(void *ctx,uint64_t pa,uint64_t size)
{
    CHECK(ctx==memory);
    CHECK((pa==TC && size==PAGE) || (pa>=BASE && pa<BASE+6*PAGE &&
          (pa-BASE)%PAGE==0x3c00 && size==0x50));
    publishes++;
}
static int copy_hash(void *ctx,uint64_t va,uint8_t *out,uint64_t size)
{
    CHECK(ctx==hash && va==0xfffffe2000003ff6UL && size==20);
    copies++;memcpy(out,hash,size);return !copy_fail;
}
static void put64(unsigned off,uint64_t n){memcpy(memory+off,&n,8);}
static uint64_t word(unsigned off){uint64_t n;memcpy(&n,memory+off,8);return n;}
static struct sptm_memory m={.ctx=memory,.map=map,.publish=publish,
    .alloc_low=0x2000000,.alloc_high=0x3000000};
static struct txm_service svc={.stacks_pa=BASE,.stack_count=6,
    .log_pa=BASE+6*PAGE,.log_va=VA-3*PAGE,.rw_pa=BASE+7*PAGE,.ro_pa=BASE+8*PAGE};
static struct txm_trust_cache tc={TC,VA,24+7*24};
static void seed(void)
{
    memset(memory,0xa5,sizeof(memory));memset(memory+10*PAGE,0,PAGE);
    unsigned offset=10*PAGE;memory[offset]=2;memory[offset+20]=7;
    for(unsigned n=0;n<7;n++) {
        memset(memory+offset+24+n*24,0x20+n,20);
        memory[offset+24+n*24+20]=2;memory[offset+24+n*24+21]=n&1;
        memory[offset+24+n*24+22]=n;
    }
    publishes=copies=copy_fail=0;deny=0;
}
int main(void)
{
    const uint64_t lengths[]={0,20,32,64,0x10000};
    for(unsigned cpu=0;cpu<6;cpu++)for(unsigned kind=0;kind<4;kind++)
    for(unsigned n=0;n<9;n++)for(unsigned len=0;len<5;len++) {
        seed();struct txm_trust_state state={0};
        CHECK(txm_trust_bootstrap(&m,&svc,&tc,&state)==SPTM_OK);
        CHECK(state.initialized==1 && state.entries==7 && publishes==1);
        CHECK(word(9*PAGE+0x110)==tc.size && word(9*PAGE+0x118)==VA+PAGE);
        uint64_t args[8]={BASE+cpu*PAGE,kind,0xfffffe2000003ff6UL,lengths[len]},status=0x123;
        memset(hash,n<7 ? 0x20+n : n==7 ? 0 : 0xff,20);
        memset(hash+20,0xde,12); /* Full SHA256 suffix is not part of a v2 entry. */
        memcpy(before,memory,sizeof(memory));
        CHECK(txm_trust_query(&m,&svc,&tc,&state,copy_hash,hash,14,args,&status)==SPTM_OK);
        int hit=kind<2 && n<7;unsigned off=cpu*PAGE+0x3c00;
        uint64_t want=hit ? 0x1000000000UL : kind ? 0x1241100000003UL : 0x1241200000003UL;
        CHECK(status==want && word(off+8)==want && word(off+24)==(hit ? 2UL : 0UL));
        CHECK(word(off+32)==(hit ? VA+0x100 : 0));
        CHECK(word(off+40)==(hit ? VA+PAGE+24+n*24 : 0));
        CHECK(state.queries==1 && state.hits==(unsigned)hit && state.misses==(unsigned)!hit);
        CHECK(state.matched[0]==(hit ? 1UL<<n : 0));
        CHECK(state.last_length==(lengths[len] ? lengths[len] : 20));
        CHECK(copies==(kind<2) && publishes==2);
        CHECK(!memcmp(before+9*PAGE,memory+9*PAGE,5*PAGE));
        memcpy(before+off+8,memory+off+8,9);memcpy(before+off+24,memory+off+24,56);
        CHECK(!memcmp(before,memory,sizeof(memory)));
    }
    for(unsigned test=0;test<19;test++) {
        seed();struct txm_trust_state state={0};struct txm_trust_cache bad=tc;
        CHECK(txm_trust_bootstrap(&m,&svc,&tc,&state)==SPTM_OK);
        uint64_t args[8]={BASE,1,0xfffffe2000003ff6UL,32},status=0x123,selector=14;
        enum sptm_result expected=SPTM_BAD_CONFIG;
        switch(test) {
        case 0:state.initialized=0;break;
        case 1:state.entries++;break;
        case 2:bad.size++;break;
        case 3:bad.pa++;break;
        case 4:bad.va++;break;
        case 5:bad.va=UINT64_MAX&~(PAGE-1);expected=SPTM_BAD_ADDRESS;break;
        case 6:args[0]++;expected=SPTM_BAD_ADDRESS;break;
        case 7:args[0]=BASE+6*PAGE;expected=SPTM_BAD_ADDRESS;break;
        case 8:args[1]=4;expected=SPTM_UNSUPPORTED_OPTIONS;break;
        case 9:args[2]=0;expected=SPTM_BAD_ADDRESS;break;
        case 10:args[2]=UINT64_MAX-31;expected=SPTM_BAD_ADDRESS;break;
        case 11:args[3]=19;expected=SPTM_UNSUPPORTED_OPTIONS;break;
        case 12:args[7]=1;expected=SPTM_UNSUPPORTED_OPTIONS;break;
        case 13:selector=15;expected=SPTM_UNSUPPORTED_OPTIONS;break;
        case 14:copy_fail=1;expected=SPTM_MEMORY_UNAVAILABLE;break;
        case 15:deny=BASE;expected=SPTM_MEMORY_UNAVAILABLE;break;
        case 16:deny=TC;expected=SPTM_MEMORY_UNAVAILABLE;break;
        case 17:put64(9*PAGE+0x118,VA);break;
        case 18:bad.pa=0;break;
        }
        struct txm_trust_state saved=state;memcpy(before,memory,sizeof(memory));publishes=0;
        CHECK(txm_trust_query(&m,&svc,&bad,&state,copy_hash,hash,selector,args,&status)==expected);
        CHECK(status==0x123 && !publishes && !memcmp(before,memory,sizeof(memory)));
        CHECK(!memcmp(&state,&saved,sizeof(state)));
    }
    for(unsigned test=0;test<9;test++) {
        seed();struct txm_trust_state state={0};struct txm_trust_cache bad=tc;
        switch(test) {
        case 0:memory[10*PAGE]=3;break;
        case 1:memory[10*PAGE+20]=8;break;
        case 2:memory[10*PAGE+24]=0xff;break;
        case 3:bad.pa=BASE;break;
        case 4:bad.size=0;break;
        case 5:bad.size=TXM_TRUST_MAX_BYTES+1;break;
        case 6:bad.pa=UINT64_MAX&~(PAGE-1);break;
        case 7:state.initialized=1;break;
        case 8:deny=TC;break;
        }
        memcpy(before,memory,sizeof(memory));struct txm_trust_state saved=state;
        CHECK(txm_trust_bootstrap(&m,&svc,&bad,&state)!=SPTM_OK);
        CHECK(!publishes && !memcmp(memory,before,sizeof(memory)) && !memcmp(&state,&saved,sizeof(state)));
    }
    seed();struct txm_trust_state state={0};uint64_t args[8]={BASE};
    CHECK(txm_trust_bootstrap(&m,&svc,&tc,&state)==SPTM_OK);
    CHECK(txm_info_with_trust(&m,&svc,&tc,&state,3,args)==SPTM_OK);
    CHECK(word(0x3c18)==4 && word(0x3c20)==VA && word(0x3c28)==1 &&
          word(0x3c30)==7 && !word(0x3c38));
    /* The installed OS's static cache has ~18k entries: a hit past the 4096-entry audit bitmap
     * is answered and counted, and writes nothing outside the bitmap (ASan sees an overflow). */
    {
        const uint32_t count=5000;const unsigned offset=10*PAGE;
        memset(memory,0xa5,sizeof(memory));memset(memory+offset,0,24+24*count);
        memory[offset]=2;memcpy(memory+offset+20,&count,4);
        for(unsigned n=0;n<count;n++) {
            uint8_t *e=memory+offset+24+n*24;
            e[0]=(uint8_t)(n>>8);e[1]=(uint8_t)n;memset(e+2,0x11,18);e[20]=2;
        }
        publishes=copies=copy_fail=0;deny=0;
        struct txm_trust_cache big={TC,VA,24+24UL*count};
        struct txm_trust_state big_state={0};
        CHECK(txm_trust_bootstrap(&m,&svc,&big,&big_state)==SPTM_OK && big_state.entries==count);
        uint64_t big_args[8]={BASE,0,0xfffffe2000003ff6UL,20},big_status=0;
        memcpy(hash,memory+offset+24+(count-1)*24,20);
        CHECK(txm_trust_query(&m,&svc,&big,&big_state,copy_hash,hash,14,big_args,&big_status)==SPTM_OK);
        CHECK(big_status==0x1000000000UL && big_state.hits==1 && word(0x3c00+40)==VA+PAGE+24+(count-1)*24UL);
        for(unsigned w=0;w<64;w++)CHECK(!big_state.matched[w]);
    }
    printf("PASS: %u static trust-cache checks\n",checks);
    return 0;
}

/* SPDX-License-Identifier: MIT */
#include "txm.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define BASE 0x100000UL
#define PAGE 0x4000UL
static unsigned checks,maps,pubs;
static uint64_t deny;
static unsigned char memory[6*PAGE],before[sizeof(memory)];
#define CHECK(x) do {checks++;if(!(x)){fprintf(stderr,"FAIL %d: %s\n",__LINE__,#x);exit(1);}} while(0)
static volatile uint8_t *map(void *ctx,uint64_t pa,uint64_t size)
{
    CHECK(ctx==memory);maps++;
    if(pa==deny || pa<BASE || pa-BASE>=sizeof(memory) || size>sizeof(memory)-(pa-BASE))return 0;
    return memory+(pa-BASE);
}
static void publish(void *ctx,uint64_t pa,uint64_t size)
{ CHECK(ctx==memory && size==0x50 && (pa-BASE)%PAGE==0x3c00);pubs++; }
static uint64_t word(unsigned off) {uint64_t v;memcpy(&v,memory+off,8);return v;}
static unsigned copies,copy_fail;
static uint64_t copy_size;
static int copy_hash(void *ctx,uint64_t va,uint8_t *out,uint64_t size)
{
    CHECK(ctx==memory && va==0xfffffe4d67f06e30UL && size>=20 && size<=64);
    copies++;copy_size=size;memset(out,0x9b,size);return !copy_fail;
}
int main(void)
{
    struct sptm_memory m={.ctx=memory,.map=map,.publish=publish};
    struct txm_service s={.stacks_pa=BASE,.stack_count=6};
    const uint64_t sizes[]={0,20,32,UINT64_MAX-1};
    for(unsigned cpu=0;cpu<6;cpu++) for(unsigned kind=0;kind<4;kind++)
    for(unsigned len=0;len<4;len++) {
        /* No mapped hash is needed: all cache lists are empty. */
        uint64_t args[8]={BASE+cpu*PAGE,kind,1,sizes[len]},status=0;
        memset(memory,0xa5,sizeof(memory));memcpy(before,memory,sizeof(memory));maps=pubs=0;
        CHECK(txm_trust_query_empty(&m,&s,14,args,&status)==SPTM_OK);
        CHECK(maps==1 && pubs==1);unsigned off=cpu*PAGE+0x3c00;
        uint64_t want=kind ? 0x1241100000003UL : 0x1241200000003UL;
        CHECK(status==want && word(off+8)==want && !memory[off+16] && !word(off+24));
        CHECK((status&0xffff)==3 && ((status>>40)&255)==0x24);
        for(unsigned i=0;i<6;i++)CHECK(!word(off+32+8*i));
        /* The transport owns only these reply fields, not another CPU's stack. */
        memcpy(before+off+8,memory+off+8,9);
        memcpy(before+off+24,memory+off+24,56);
        CHECK(!memcmp(memory,before,sizeof(memory)));
    }
    for(unsigned test=0;test<22;test++) {
        struct sptm_memory mm=m;struct txm_service ss=s;
        uint64_t args[8]={BASE,1,0xfffffe9569d8b378UL,32},selector=14,status=0x123;
        enum sptm_result want=SPTM_BAD_CONFIG;
        switch(test) {
        case 0:mm.map=0;break;case 1:mm.publish=0;break;
        case 2:ss.stack_count=0;break;case 3:ss.stack_count=257;break;
        case 4:ss.stacks_pa++;break;case 5:ss.stacks_pa=UINT64_MAX&~(PAGE-1);break;
        case 6:args[0]++;want=SPTM_BAD_ADDRESS;break;
        case 7:args[0]=BASE-PAGE;want=SPTM_BAD_ADDRESS;break;
        case 8:args[0]=BASE+6*PAGE;want=SPTM_BAD_ADDRESS;break;
        case 9:args[2]=0;want=SPTM_BAD_ADDRESS;break;
        case 10:args[2]=UINT64_MAX-31;want=SPTM_BAD_ADDRESS;break;
        case 11:args[3]=0;args[2]=UINT64_MAX-19;want=SPTM_BAD_ADDRESS;break;
        case 12:args[1]=4;want=SPTM_UNSUPPORTED_OPTIONS;break;
        case 13:args[1]=0x101;want=SPTM_UNSUPPORTED_OPTIONS;break;
        case 14:selector=13;want=SPTM_UNSUPPORTED_OPTIONS;break;
        case 15:deny=BASE;want=SPTM_MEMORY_UNAVAILABLE;break;
        case 16:case 17:case 18:case 19:args[test-12]=1;want=SPTM_UNSUPPORTED_OPTIONS;break;
        case 20:args[1]=UINT64_MAX;want=SPTM_UNSUPPORTED_OPTIONS;break;
        case 21:args[2]=2;args[3]=UINT64_MAX-1;want=SPTM_BAD_ADDRESS;break;
        }
        memcpy(before,memory,sizeof(memory));maps=pubs=0;
        CHECK(txm_trust_query_empty(&mm,&ss,selector,args,&status)==want);
        CHECK(!pubs && !memcmp(before,memory,sizeof(memory)) && status==0x123);deny=0;
    }
    uint64_t args[8]={BASE,1,1,32},status=0;
    CHECK(txm_trust_query_empty(0,&s,14,args,&status)==SPTM_BAD_CONFIG);
    CHECK(txm_trust_query_empty(&m,0,14,args,&status)==SPTM_BAD_CONFIG);
    CHECK(txm_trust_query_empty(&m,&s,14,0,&status)==SPTM_BAD_CONFIG);
    CHECK(txm_trust_query_empty(&m,&s,14,args,0)==SPTM_BAD_CONFIG);
    for(unsigned cpu=0;cpu<6;cpu++)for(unsigned size=0;size<=64;size++) {
        if(size && size<20)continue;
        uint64_t a[8]={BASE+cpu*PAGE,0xfffffe4d67f06e30UL,size},st=0x123;
        memset(memory,0xa5,sizeof(memory));memcpy(before,memory,sizeof(memory));maps=pubs=copies=0;
        CHECK(txm_compilation_match_empty(&m,&s,copy_hash,memory,30,a,&st)==SPTM_OK);
        unsigned off=cpu*PAGE+0x3c00;
        CHECK(st==8 && word(off+8)==8 && !word(off+24) && copies==1 && maps==1 && pubs==1);
        CHECK(copy_size==(size ? size : 20));
        for(unsigned i=0;i<6;i++)CHECK(!word(off+32+8*i));
        memcpy(before+off+8,memory+off+8,9);memcpy(before+off+24,memory+off+24,56);
        CHECK(!memcmp(memory,before,sizeof(memory)));
    }
    for(unsigned test=0;test<18;test++) {
        uint64_t a[8]={BASE,0xfffffe4d67f06e30UL,32},st=0x123,selector=30;
        struct sptm_memory mm=m;struct txm_service ss=s;
        enum sptm_result want=SPTM_BAD_ADDRESS;
        switch(test) {
        case 0:a[0]++;break;case 1:a[0]=BASE+6*PAGE;break;
        case 2:a[1]=0;break;case 3:a[1]=UINT64_MAX-31;break;
        case 4:a[2]=19;want=SPTM_UNSUPPORTED_OPTIONS;break;
        case 5:a[2]=65;want=SPTM_UNSUPPORTED_OPTIONS;break;
        case 6:copy_fail=1;break;
        case 7:deny=BASE;want=SPTM_MEMORY_UNAVAILABLE;break;
        case 8:selector=29;want=SPTM_UNSUPPORTED_OPTIONS;break;
        case 9:case 10:case 11:case 12:case 13:a[test-6]=1;want=SPTM_UNSUPPORTED_OPTIONS;break;
        case 14:mm.map=0;want=SPTM_BAD_CONFIG;break;
        case 15:mm.publish=0;want=SPTM_BAD_CONFIG;break;
        case 16:ss.stack_count=0;want=SPTM_BAD_CONFIG;break;
        case 17:ss.stacks_pa=UINT64_MAX&~(PAGE-1);want=SPTM_BAD_CONFIG;break;
        }
        memcpy(before,memory,sizeof(memory));pubs=copies=0;
        CHECK(txm_compilation_match_empty(&mm,&ss,copy_hash,memory,selector,a,&st)==want);
        CHECK(!pubs && !memcmp(before,memory,sizeof(memory)) && st==0x123);
        CHECK(copies==(test==6 ? 1u : 0u));copy_fail=0;deny=0;
    }
    CHECK(txm_compilation_match_empty(0,&s,copy_hash,memory,30,args,&status)==SPTM_BAD_CONFIG);
    CHECK(txm_compilation_match_empty(&m,0,copy_hash,memory,30,args,&status)==SPTM_BAD_CONFIG);
    CHECK(txm_compilation_match_empty(&m,&s,0,memory,30,args,&status)==SPTM_BAD_CONFIG);
    CHECK(txm_compilation_match_empty(&m,&s,copy_hash,memory,30,0,&status)==SPTM_BAD_CONFIG);
    CHECK(txm_compilation_match_empty(&m,&s,copy_hash,memory,30,args,0)==SPTM_BAD_CONFIG);
    printf("TXM empty trust query: %u checks passed (native misses, no tokens, six-stack isolation)\n",checks);
}

/* SPDX-License-Identifier: MIT */
#include "txm.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define BASE 0x100000UL
#define PAGE 0x4000UL
static unsigned checks,pubs;
static uint64_t deny,pub_pa,pub_size;
static uint8_t ram[7*PAGE],before[sizeof ram];
#define CHECK(x) do { checks++; if(!(x)) {fprintf(stderr,"FAIL %d: %s\n",__LINE__,#x);exit(1);} } while(0)
static volatile uint8_t *map(void *ctx,uint64_t pa,uint64_t size)
{
    (void)ctx;
    if(pa==deny || pa<BASE || pa-BASE>=sizeof ram || size>sizeof ram-(pa-BASE))return 0;
    return ram+(pa-BASE);
}
static void publish(void *ctx,uint64_t pa,uint64_t size)
{(void)ctx;pubs++;pub_pa=pa;pub_size=size;}
static uint64_t word(unsigned off){uint64_t v;memcpy(&v,ram+off,8);return v;}
static void setup(void)
{memset(ram,0xa5,sizeof ram);memset(ram+6*PAGE,0,PAGE);pubs=0;deny=0;}
int main(int argc,char **argv)
{
    struct sptm_memory m={.map=map,.publish=publish};
    struct txm_service s={.stacks_pa=BASE,.stack_count=6,.ro_pa=BASE+6*PAGE};
    for(unsigned cpu=0;cpu<6;cpu++) {
        setup();uint64_t args[8]={BASE+cpu*PAGE};
        memcpy(before,ram,sizeof ram);
        CHECK(txm_sep_channel_unavailable(&m,&s,7,args)==SPTM_OK);
        unsigned off=cpu*PAGE+0x3c00;
        CHECK(pubs==1 && pub_pa==args[0]+0x3c00 && pub_size==0x50);
        CHECK(word(off+8)==0x29 && word(off+24)==0 && ram[off+16]==0);
        for(unsigned i=0;i<6;i++)CHECK(word(off+32+i*8)==0);
        for(unsigned i=0;i<sizeof ram;i++) {
            int changed=(i>=off+8 && i<off+17) || (i>=off+24 && i<off+80);
            if(!changed)CHECK(ram[i]==before[i]);
        }
    }
    if(argc==2 && !strcmp(argv[1],"--reply")) {
        printf("%llu %llu\n",(unsigned long long)word(5*PAGE+0x3c08),
               (unsigned long long)word(5*PAGE+0x3c18));return 0;
    }
    for(unsigned i=0;i<29;i++) {
        setup();struct sptm_memory bm=m;struct txm_service bs=s;
        uint64_t args[8]={BASE},ep=7;
        enum sptm_result want=SPTM_BAD_CONFIG;
        switch(i) {
        case 0:bm.map=0;break;case 1:bm.publish=0;break;
        case 2:bs.stack_count=0;break;case 3:bs.stack_count=257;break;
        case 4:bs.stacks_pa++;break;case 5:bs.stacks_pa=UINT64_MAX-PAGE+1;break;
        case 6:bs.ro_pa=0;break;case 7:bs.ro_pa++;break;
        case 8:bs.ro_pa=UINT64_MAX-PAGE+1;break;case 9:bs.ro_pa=BASE;break;
        case 10:args[0]++;want=SPTM_BAD_ADDRESS;break;
        case 11:args[0]-=PAGE;want=SPTM_BAD_ADDRESS;break;
        case 12:args[0]+=6*PAGE;want=SPTM_BAD_ADDRESS;break;
        case 13:ep=8;want=SPTM_UNSUPPORTED_OPTIONS;break;
        case 14:deny=BASE;want=SPTM_MEMORY_UNAVAILABLE;break;
        case 15:deny=bs.ro_pa;want=SPTM_MEMORY_UNAVAILABLE;break;
        case 16:ram[6*PAGE+0xa]=1;break;
        case 17:ram[6*PAGE+0x38]=1;break;
        case 18:ram[6*PAGE+0x40]=1;break;
        case 19:ram[6*PAGE+0x48]=1;break;
        case 20:bs.ro_pa=BASE+7*PAGE;want=SPTM_MEMORY_UNAVAILABLE;break;
        case 21:ram[6*PAGE+0xa]=255;break;
        default:args[i-21]=1;want=SPTM_UNSUPPORTED_OPTIONS;break;
        }
        memcpy(before,ram,sizeof ram);
        CHECK(txm_sep_channel_unavailable(&bm,&bs,ep,args)==want);
        CHECK(!pubs && !memcmp(ram,before,sizeof ram));
    }
    uint64_t args[8]={BASE};
    CHECK(txm_sep_channel_unavailable(0,&s,7,args)==SPTM_BAD_CONFIG);
    CHECK(txm_sep_channel_unavailable(&m,0,7,args)==SPTM_BAD_CONFIG);
    CHECK(txm_sep_channel_unavailable(&m,&s,7,0)==SPTM_BAD_CONFIG);
    printf("PASS: %u TXM SEP channel absence checks\n",checks);
}

/* SPDX-License-Identifier: MIT */
#include "txm.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define BASE 0x100000UL
#define PAGE 0x4000UL
static unsigned checks,maps,pubs;
static uint64_t deny;
static unsigned char memory[3*PAGE],before[sizeof(memory)];
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
int main(void)
{
    struct sptm_memory m={.ctx=memory,.map=map,.publish=publish};
    struct txm_service s={.stacks_pa=BASE,.stack_count=2};
    /* Input may be unmapped: the real operation6 never reads its buffer. */
    const uint64_t pointers[]={1,0xfffffe9a3e1b79c0UL,UINT64_MAX-16};
    for(unsigned cpu=0;cpu<2;cpu++) for(unsigned input=0;input<3;input++) {
        uint64_t args[8]={BASE+cpu*PAGE,6,pointers[input],16};
        memset(memory,0xa5,sizeof(memory));memcpy(before,memory,sizeof(memory));maps=pubs=0;
        CHECK(txm_image4(&m,&s,45,args)==SPTM_OK);
        CHECK(maps==1 && pubs==1);unsigned off=cpu*PAGE+0x3c00;
        CHECK(word(off+8)==0x4e00000005UL && !memory[off+16] && !word(off+24));
        /* Decode the same domain/errno fields consumed by the kernel. */
        CHECK((word(off+8)&0xffff)==5 && (word(off+8)>>32)==78);
        for(unsigned i=0;i<6;i++)CHECK(!word(off+32+8*i));
        for(unsigned i=0;i<sizeof(memory);i++) {
            int changed=(i>=off+8 && i<off+16) || i==off+16 || (i>=off+24 && i<off+80);
            if(!changed)CHECK(memory[i]==before[i]);
        }
    }
    for(unsigned test=0;test<24;test++) {
        struct sptm_memory mm=m;struct txm_service ss=s;
        uint64_t args[8]={BASE,6,0xfffffe9a3e1b79c0UL,16},selector=45;
        enum sptm_result want=SPTM_BAD_CONFIG;
        switch(test) {
        case 0:mm.map=0;break;case 1:mm.publish=0;break;
        case 2:ss.stack_count=0;break;case 3:ss.stack_count=257;break;
        case 4:ss.stacks_pa++;break;case 5:ss.stacks_pa=UINT64_MAX&~(PAGE-1);break;
        case 6:args[0]++;want=SPTM_BAD_ADDRESS;break;
        case 7:args[0]=BASE-PAGE;want=SPTM_BAD_ADDRESS;break;
        case 8:args[0]=BASE+2*PAGE;want=SPTM_BAD_ADDRESS;break;
        case 9:args[2]=0;want=SPTM_BAD_ADDRESS;break;
        case 10:args[2]=UINT64_MAX-15;want=SPTM_BAD_ADDRESS;break;
        case 11:args[3]=15;want=SPTM_UNSUPPORTED_OPTIONS;break;
        case 12:args[3]=17;want=SPTM_UNSUPPORTED_OPTIONS;break;
        case 13:selector=44;want=SPTM_UNSUPPORTED_OPTIONS;break;
        case 14:deny=BASE;want=SPTM_MEMORY_UNAVAILABLE;break;
        case 15:case 16:case 17:case 18:args[test-11]=1;want=SPTM_UNSUPPORTED_OPTIONS;break;
        default:args[1]=test-19;want=SPTM_UNSUPPORTED_OPTIONS;break;
        }
        memcpy(before,memory,sizeof(memory));maps=pubs=0;
        CHECK(txm_image4(&mm,&ss,selector,args)==want);
        CHECK(!pubs && !memcmp(before,memory,sizeof(memory)));deny=0;
    }
    uint64_t args[8]={BASE,6,1,16};
    CHECK(txm_image4(0,&s,45,args)==SPTM_BAD_CONFIG);
    CHECK(txm_image4(&m,0,45,args)==SPTM_BAD_CONFIG);
    CHECK(txm_image4(&m,&s,45,0)==SPTM_BAD_CONFIG);
    printf("TXM Image4: %u checks passed (native errno78, reply isolation, no UUID reads)\n",checks);
}

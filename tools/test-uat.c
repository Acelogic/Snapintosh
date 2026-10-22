/* SPDX-License-Identifier: MIT */
#include "uat.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(x) do { checks++; if (!(x)) { fprintf(stderr,"FAIL %d: %s\n",__LINE__,#x); exit(1); } } while(0)
static unsigned checks;
static uint8_t pages[0xc000],saved[0xc000];
static uint64_t base;
static unsigned maps;
static volatile uint8_t *map(void *ctx,uint64_t pa,uint64_t size)
{
    CHECK(ctx==pages);maps++;
    if (pa<base || pa-base>=sizeof(pages) || size>sizeof(pages)-(pa-base)) return NULL;
    return pages+(pa-base);
}
static void store64(unsigned off,uint64_t value)
{ for (unsigned i=0;i<8;i++) pages[off+i]=(uint8_t)(value>>(i*8)); }
int main(void)
{
    struct sptm_aperture a = {0x80000000UL, 0xfffffe0100000000UL, 0x10000000UL};
    struct uat_config c = {0x88000000UL, 1, 43, 64};
    uint64_t result=0;
    const uint64_t queries[] = {0,2,3,4,5,9};
    const uint64_t expected[] = {1,0xfffffe0108000000UL,42,0x3f000000000UL,64,0xfffffe0108008000UL};
    for (unsigned i=0;i<6;i++) {
        CHECK(uat_get_info(&c,&a,queries[i],&result)==SPTM_OK);
        CHECK(result==expected[i]);
    }
    for (unsigned i=0;i<12;i++) {
        unsigned bad[]={1,6,7,8,10,11,12,255,256,0x10002,0x10009,0xffffffffU};
        result=0xdeadbeef;
        CHECK(uat_get_info(&c,&a,bad[i],&result)==SPTM_UNSUPPORTED_OPTIONS);
        CHECK(result==0xdeadbeef);
    }
    for (unsigned i=0;i<9;i++) {
        struct uat_config bad=c;
        enum sptm_result want=SPTM_BAD_CONFIG;
        switch(i) {
        case 0: bad.mode=0; break;
        case 1: bad.va_bits=39; break;
        case 2: bad.va_bits=49; break;
        case 3: bad.segment_limit=0; break;
        case 4: bad.segment_limit=1UL<<32; break;
        case 5: bad.reserved_pa++; break;
        case 6: bad.reserved_pa=a.pa-0x4000; want=SPTM_BAD_ADDRESS; break;
        case 7: bad.reserved_pa=a.pa+a.size-0x8000; want=SPTM_BAD_ADDRESS; break;
        case 8: bad.reserved_pa=UINT64_MAX & ~0x3fffUL; want=SPTM_BAD_ADDRESS; break;
        }
        result=0xdeadbeef;
        CHECK(uat_get_info(&bad,&a,0,&result)==want);
        CHECK(result==0xdeadbeef);
    }
    c.va_bits=40;
    CHECK(uat_get_info(&c,&a,4,&result)==SPTM_OK && result==0x7000000000UL);
    c.va_bits=48;
    CHECK(uat_get_info(&c,&a,4,&result)==SPTM_OK && result==0x7ff000000000UL);
    CHECK(uat_get_info(NULL,&a,0,&result)==SPTM_BAD_CONFIG);
    CHECK(uat_get_info(&c,NULL,0,&result)==SPTM_BAD_ADDRESS);
    CHECK(uat_get_info(&c,&a,0,NULL)==SPTM_BAD_CONFIG);
    c.va_bits=43;base=c.reserved_pa;
    pages[0]=8;store64(0x10,0xfffffe0108004000UL);
    pages[0x18]=64;pages[0x1a]=2;store64(0x4010,0x88008003UL);
    struct sptm_memory memory={.map=map,.ctx=pages};
    memcpy(saved,pages,sizeof(pages));
    CHECK(uat_power_idle(&c,&a,&memory)==SPTM_OK);
    CHECK(!memcmp(saved,pages,sizeof(pages)) && maps==1);
    /* Every UAT/table word, plus all header/descriptor bytes and trailing
     * bytes: changed ownership must fail without clearing a single byte. */
    for (unsigned off=0;off<sizeof(pages);off++) {
        if (off>=0x40 && (off&7) && !(off>=0x4010 && off<0x4018) && off<sizeof(pages)-8) continue;
        pages[off]^=0x80;memcpy(saved,pages,sizeof(pages));
        CHECK(uat_power_idle(&c,&a,&memory)==SPTM_FRAME_BUSY);
        CHECK(!memcmp(saved,pages,sizeof(pages)));pages[off]^=0x80;
    }
    CHECK(uat_power_idle(&c,&a,&memory)==SPTM_OK);
    CHECK(uat_power_idle(NULL,&a,&memory)==SPTM_BAD_CONFIG);
    CHECK(uat_power_idle(&c,NULL,&memory)==SPTM_BAD_ADDRESS);
    CHECK(uat_power_idle(&c,&a,NULL)==SPTM_BAD_CONFIG);
    memory.map=NULL;CHECK(uat_power_idle(&c,&a,&memory)==SPTM_BAD_CONFIG);memory.map=map;
    base+=0x4000;CHECK(uat_power_idle(&c,&a,&memory)==SPTM_MEMORY_UNAVAILABLE);base-=0x4000;
    c.segment_limit=65;CHECK(uat_power_idle(&c,&a,&memory)==SPTM_BAD_CONFIG);c.segment_limit=64;
    a.va++;CHECK(uat_power_idle(&c,&a,&memory)==SPTM_BAD_ADDRESS);a.va--;
    printf("PASS: %u UAT query checks\n", checks);
}

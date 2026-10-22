/* SPDX-License-Identifier: MIT */
#include "sptm-dart.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define BASE 0x8c0000000UL
#define FM (BASE+0x4000)
#define ROOT (BASE+0x10000)
#define MID (BASE+0x14000)
#define LEAF (BASE+0x18000)
#define DATA (BASE+0x20000)
#define SIZE 0x40000UL
#define VA 0x12300000000UL
static uint8_t ram[SIZE],saved[SIZE];
static struct dart_state s;
static uint64_t unavailable;
static unsigned checks;
#define CHECK(x) do { checks++;if (!(x)) {fprintf(stderr,"FAIL %d: %s\n",__LINE__,#x);exit(1);} } while(0)
static uint8_t *meta(uint64_t pa) {return ram+(FM-BASE)+((pa-BASE)>>14)*16;}
static void put(uint64_t pa,uint64_t v) {memcpy(ram+(pa-BASE),&v,8);}
static uint64_t leaf(uint64_t pa,unsigned options,unsigned begin,unsigned end)
{return pa>>4|1|options|((uint64_t)begin<<52)|((uint64_t)end<<40);}
static volatile uint8_t *map(void *ctx,uint64_t pa,uint64_t size)
{CHECK(ctx==ram);return pa==unavailable || pa<BASE || pa>=BASE+SIZE || !size || size>BASE+SIZE-pa ? 0 : ram+(pa-BASE);}
static void publish(void *ctx,uint64_t pa,uint64_t size) {(void)ctx;(void)pa;(void)size;CHECK(0);}
static struct sptm_memory reset(void)
{
    memset(ram,0,sizeof(ram));dart_init(&s);unavailable=0;
    s.initialized_ids=s.powered_ids=1U<<21;s.tcr[1]=9;s.enabled[0]=2;s.ttbr[1]=(ROOT>>12)|1;
    uint64_t tables[]={ROOT,MID,LEAF};
    for (unsigned i=0;i<3;i++) {uint8_t e[16]={0,0,24,0,2,0,5,0,21,1,(uint8_t)i};memcpy(meta(tables[i]),e,16);}
    put(ROOT+((VA>>36)&2047)*8,(MID>>4)|1);
    put(MID+((VA>>25)&2047)*8,(LEAF>>4)|1);
    put(LEAF+((VA>>14)&2047)*8,leaf(DATA,0,0,0xfff));meta(DATA)[2]=11;meta(DATA)[12]=1;
    return (struct sptm_memory){.frame_map_pa=FM,.frame_low=BASE,.frame_high=BASE+SIZE,
        .alloc_low=ROOT,.alloc_high=BASE+SIZE,.map=map,.publish=publish,.ctx=ram};
}
static void refuse(struct sptm_memory *m,uint64_t id,uint64_t sid,uint64_t va,uint64_t n,int w,enum sptm_result want)
{
    struct dart_state before=s;memcpy(saved,ram,SIZE);uint64_t pa=0xbadc0de;
    CHECK(sptm_dart_dma_translate(m,&s,id,sid,va,n,w,&pa)==want);
    CHECK(pa==0xbadc0de && !memcmp(ram,saved,SIZE) && !memcmp(&s,&before,sizeof(s)));
}
int main(void)
{
    struct sptm_memory m=reset();uint64_t pa=0;uint64_t slot=LEAF+((VA>>14)&2047)*8;
    for (int w=0;w<2;w++) {
        CHECK(sptm_dart_dma_translate(&m,&s,21,1,VA+7,0x3ff9,w,&pa)==SPTM_OK && pa==DATA+7);
    }
    CHECK(s.translations==2 && !s.faults);
    refuse(&m,21,1,VA,0,0,SPTM_BAD_ADDRESS);refuse(&m,21,1,VA+1,0x4000,0,SPTM_BAD_ADDRESS);
    refuse(&m,21,1,1UL<<42,1,0,SPTM_BAD_ADDRESS);refuse(&m,21,1,(1UL<<40)-1,1,0,SPTM_BAD_ADDRESS);
    refuse(&m,21,1,VA,16,2,SPTM_BAD_CONFIG);refuse(&m,20,1,VA,16,0,SPTM_BAD_CONFIG);
    refuse(&m,21,0,VA,16,0,SPTM_BAD_CONFIG);refuse(&m,21,2,VA,16,0,SPTM_UNSUPPORTED_OPTIONS);
    for (unsigned i=0;i<256;i++) if (i!=11) {
        m=reset();meta(DATA)[2]=(uint8_t)i;refuse(&m,21,1,VA,16,0,SPTM_TYPE_MISMATCH);
    }
    for (unsigned level=0;level<3;level++) {
        uint64_t table=ROOT+level*0x4000;
        for (unsigned off=0;off<16;off++) {
            m=reset();meta(table)[off]^=1;
            enum sptm_result want=(off==2 || off==6 || off==8 || off==9 || off==10) ? SPTM_TYPE_MISMATCH :
                off<2 ? SPTM_FRAME_BUSY : SPTM_BAD_REFERENCE;
            refuse(&m,21,1,VA,16,1,want);
        }
    }
    m=reset();meta(DATA)[12]=0;refuse(&m,21,1,VA,16,0,SPTM_BAD_REFERENCE);
    m=reset();meta(DATA)[8]=1;meta(DATA)[12]=0;put(slot,leaf(DATA,4,0,0xfff));
    CHECK(sptm_dart_dma_translate(&m,&s,21,1,VA,16,0,&pa)==SPTM_OK);
    refuse(&m,21,1,VA,16,1,SPTM_UNSUPPORTED_OPTIONS);
    m=reset();put(slot,leaf(DATA,8,0,0xfff));refuse(&m,21,1,VA,16,0,SPTM_UNSUPPORTED_OPTIONS);
    CHECK(sptm_dart_dma_translate(&m,&s,21,1,VA,16,1,&pa)==SPTM_OK);
    m=reset();put(slot,leaf(DATA,0,4,7));
    CHECK(sptm_dart_dma_translate(&m,&s,21,1,VA+16,16,1,&pa)==SPTM_OK && pa==DATA+16);
    refuse(&m,21,1,VA+15,1,0,SPTM_BAD_ADDRESS);refuse(&m,21,1,VA+31,2,1,SPTM_BAD_ADDRESS);
    m=reset();s.enabled[0]=0;refuse(&m,21,1,VA,16,0,SPTM_BAD_CONFIG);
    m=reset();s.ttbr[1]=0;refuse(&m,21,1,VA,16,0,SPTM_TABLE_MISSING);
    m=reset();s.ttbr[1]|=2;refuse(&m,21,1,VA,16,0,SPTM_BAD_TABLE);
    m=reset();put(slot,leaf(FM,0,0,0xfff));refuse(&m,21,1,VA,16,1,SPTM_BAD_TABLE);
    m=reset();put(slot,leaf(ROOT,0,0,0xfff));refuse(&m,21,1,VA,16,1,SPTM_TYPE_MISMATCH);
    m=reset();put(slot,0);meta(LEAF)[4]=1;refuse(&m,21,1,VA,16,0,SPTM_TABLE_MISSING);
    m=reset();put(MID+((VA>>25)&2047)*8,(ROOT>>4)|1);refuse(&m,21,1,VA,16,0,SPTM_BAD_TABLE);
    m=reset();put(slot,leaf(DATA,0,8,7));refuse(&m,21,1,VA,16,0,SPTM_BAD_TABLE);
    uint64_t absent[]={ROOT,MID,LEAF,FM+((DATA-BASE)>>14)*16,DATA};
    for (unsigned i=0;i<5;i++) {m=reset();unavailable=absent[i];refuse(&m,21,1,VA,16,0,SPTM_MEMORY_UNAVAILABLE);}
    printf("SPTM DART DMA: %u checks passed (typed tables, ownership, references, permissions, subpages, atomic refusals)\n",checks);
}

/* SPDX-License-Identifier: MIT */
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "sptm-dart.h"

#define BASE 0x8c0000000UL
#define SIZE 0x40000UL
#define FM (BASE+0x4000)
#define ROOT (BASE+0x10000)
#define MID (BASE+0x14000)
#define LEAF (BASE+0x18000)
#define SPARE (BASE+0x1c000)
#define DATA (BASE+0x20000)
#define IOVA (1UL<<40)
static uint8_t ram[SIZE],saved[SIZE];
static struct dart_state state,saved_state;
static uint64_t unavailable,pub_pa[8],pub_size[8];
static unsigned published,checks;
#define CHECK(x) do { checks++; if (!(x)) { fprintf(stderr,"FAIL %d: %s\n",__LINE__,#x); assert(x); } } while (0)
static uint8_t *meta(uint64_t pa) { return ram+(FM-BASE)+((pa-BASE)>>14)*16; }
static uint64_t load64(uint64_t pa)
{ uint64_t v;memcpy(&v,ram+(pa-BASE),8);return v; }
static void put64(uint64_t pa,uint64_t value) { memcpy(ram+(pa-BASE),&value,8); }
static uint64_t descriptor(uint64_t pa) { return (pa>>4)|1; }
static volatile uint8_t *map(void *ctx,uint64_t pa,uint64_t size)
{
    CHECK(ctx==ram);
    if(pa==unavailable || pa<BASE || pa>=BASE+SIZE || size>BASE+SIZE-pa) return 0;
    return ram+(pa-BASE);
}
static void publish(void *ctx,uint64_t pa,uint64_t size)
{
    CHECK(ctx==ram && published<8);
    pub_pa[published]=pa;pub_size[published++]=size;
    /* Metadata publication precedes the first observer-visible link. */
    if(size==8) {
        uint64_t child=(load64(pa)&0x3ffffffc00UL)<<4;
        CHECK(meta(child)[4]==1 && meta(child)[5]==0);
        unsigned nonzero=0;
        for(unsigned i=0;i<2048;i++)nonzero+=load64((pa&~0x3fffUL)+8*i)!=0;
        CHECK(((unsigned)meta(pa&~0x3fffUL)[4]|((unsigned)meta(pa&~0x3fffUL)[5]<<8))==nonzero+1);
    }
}
static void type(uint64_t pa,unsigned level)
{
    uint8_t expected[16]={0,0,24,0,0,0,5,0,21,1,(uint8_t)level,0,0,0,0,0};
    memcpy(meta(pa),expected,16);
}
static void snapshot(void)
{ memcpy(saved,ram,SIZE);saved_state=state;published=0; }
static struct sptm_memory reset(void)
{
    memset(ram,0,SIZE);dart_init(&state);unavailable=0;
    type(ROOT,0);type(MID,1);type(LEAF,2);type(SPARE,0);
    state.initialized_ids=state.powered_ids=1U<<21;
    state.tcr[0]=state.tcr[1]=9;
    snapshot();
    return (struct sptm_memory){.frame_map_pa=FM,.frame_low=BASE,.frame_high=BASE+SIZE,
        .alloc_low=ROOT,.alloc_high=BASE+SIZE,.map=map,.publish=publish,.ctx=ram};
}
static void refused(struct sptm_memory *m,uint64_t id,uint64_t sid,uint64_t iova,
                    uint64_t level,uint64_t pa,enum sptm_result want)
{
    snapshot();
    CHECK(sptm_dart_map_table(m,&state,id,sid,iova,level,pa)==want);
    CHECK(!published && !memcmp(ram,saved,SIZE) && !memcmp(&state,&saved_state,sizeof(state)));
}
static void attach(struct sptm_memory *m,uint64_t level,uint64_t pa,uint64_t iova)
{
    snapshot();
    CHECK(sptm_dart_map_table(m,&state,21,1,iova,level,pa)==SPTM_OK);
    CHECK(pub_pa[0]==pa && pub_size[0]==0x4000);
    CHECK(pub_pa[1]==FM+((pa-BASE)>>14)*16 && pub_size[1]==16);
    CHECK(published==(level ? 4u : 2u));
    CHECK(!memcmp(ram+(pa-BASE),saved+(pa-BASE),0x4000));
    CHECK(!memcmp(state.enabled,saved_state.enabled,sizeof(state.enabled)));
    CHECK(state.translations==saved_state.translations && state.faults==saved_state.faults && state.flushes==saved_state.flushes);
}
static int allow(void *ctx,uint64_t pa,uint64_t size,int write)
{ (void)write;return ctx==ram && pa>=ROOT && pa<BASE+SIZE && size<=BASE+SIZE-pa; }
static int read64(void *ctx,uint64_t pa,uint64_t *value)
{ if(ctx!=ram || !allow(ctx,pa,8,0) || (pa&7)) return -1;*value=load64(pa);return 0; }
int main(void)
{
    struct sptm_memory m=reset();
    state.error=0x80000001;state.error_address=IOVA;state.faults=1;
    attach(&m,0,ROOT,IOVA);
    CHECK(state.ttbr[1]==(ROOT>>12|1) && meta(ROOT)[4]==1);
    CHECK(state.error==0x80000001 && state.error_address==IOVA && state.faults==1);
    refused(&m,21,1,IOVA,0,ROOT,SPTM_FRAME_BUSY);
    refused(&m,21,1,IOVA,0,SPARE,SPTM_TABLE_EXISTS);
    attach(&m,1,MID,IOVA);
    CHECK(load64(ROOT+16*8)==descriptor(MID) && meta(ROOT)[4]==2 && meta(MID)[4]==1);
    attach(&m,2,LEAF,IOVA+(3UL<<25));
    CHECK(load64(MID+3*8)==descriptor(LEAF) && meta(MID)[4]==2 && meta(LEAF)[4]==1);
    CHECK(meta(ROOT)[4]==2);
    type(SPARE,1);
    refused(&m,21,1,IOVA,1,SPARE,SPTM_TABLE_EXISTS);
    type(SPARE,2);
    refused(&m,21,1,IOVA+(1UL<<36),2,SPARE,SPTM_TABLE_MISSING);
    /* A synthetic leaf producer checks the installed format against the
     * independent DART walker. This is not live DMA qualification. */
    put64(LEAF+5*8,descriptor(DATA)|(0xfffUL<<40));
    state.enabled[0]=2;
    const struct dart_memory memory={ram,read64,allow};uint64_t physical=0;
    CHECK(dart_translate(&state,16,&memory,1,IOVA+(3UL<<25)+(5UL<<14)+64,32,0,&physical)==DART_OK);
    CHECK(physical==DATA+64);

    /* Second declared SID and the last IOVA page exercise the high slot
     * bits at both parent levels without modifying the other stream. */
    m=reset();meta(ROOT)[9]=meta(MID)[9]=meta(LEAF)[9]=0;
    const uint64_t last=(1UL<<42)-0x4000;
    CHECK(sptm_dart_map_table(&m,&state,21,0,last,0,ROOT)==SPTM_OK);
    snapshot();CHECK(sptm_dart_map_table(&m,&state,21,0,last,1,MID)==SPTM_OK);
    snapshot();CHECK(sptm_dart_map_table(&m,&state,21,0,last,2,LEAF)==SPTM_OK);
    CHECK(load64(ROOT+63*8)==descriptor(MID) && load64(MID+2047*8)==descriptor(LEAF));
    CHECK(!state.ttbr[1] && state.ttbr[0]==(ROOT>>12|1));

    m=reset();
    const uint64_t bad_iova[]={0,IOVA-0x4000,IOVA+1,1UL<<42,UINT64_MAX};
    for(unsigned i=0;i<sizeof(bad_iova)/sizeof(*bad_iova);i++)
        refused(&m,21,1,bad_iova[i],0,ROOT,SPTM_BAD_ADDRESS);
    const uint64_t bad_pa[]={ROOT-0x4000,ROOT+1,BASE+SIZE,UINT64_MAX};
    for(unsigned i=0;i<sizeof(bad_pa)/sizeof(*bad_pa);i++)
        refused(&m,21,1,IOVA,0,bad_pa[i],SPTM_BAD_ADDRESS);
    refused(&m,32,1,IOVA,0,ROOT,SPTM_UNSUPPORTED_OPTIONS);
    refused(&m,21,256,IOVA,0,ROOT,SPTM_UNSUPPORTED_OPTIONS);
    refused(&m,21,1,IOVA,256,ROOT,SPTM_UNSUPPORTED_OPTIONS);
    refused(&m,19,1,IOVA,0,ROOT,SPTM_BAD_CONFIG);
    refused(&m,20,1,IOVA,1,ROOT,SPTM_BAD_CONFIG);
    for(unsigned i=0;i<16;i++) {
        m=reset();meta(ROOT)[i]^=1;
        enum sptm_result want=(i==0 || i==1 || i==4 || i==5)?SPTM_FRAME_BUSY:
            (i==2 || i==6 || i==8 || i==9 || i==10)?SPTM_TYPE_MISMATCH:SPTM_BAD_REFERENCE;
        refused(&m,21,1,IOVA,0,ROOT,want);
    }
    for(unsigned i=0;i<4;i++) {
        m=reset();
        if(i==0)state.initialized_ids=0;
        if(i==1)state.powered_ids=0;
        if(i==2)state.tcr[1]=1;
        if(i==3)state.tcr[1]=0x89;
        refused(&m,21,1,IOVA,0,ROOT,SPTM_BAD_CONFIG);
    }
    for(unsigned i=0;i<2;i++) {
        m=reset();if(i)state.enabled[0]=2;else state.protect=1;
        refused(&m,21,1,IOVA,0,ROOT,SPTM_FRAME_BUSY);
        m=reset();unavailable=i?ROOT:FM+((ROOT-BASE)>>14)*16;
        refused(&m,21,1,IOVA,0,ROOT,SPTM_MEMORY_UNAVAILABLE);
    }
    m=reset();ram[ROOT-BASE+0x3fff]=1;
    refused(&m,21,1,IOVA,0,ROOT,SPTM_BAD_TABLE);
    m=reset();refused(&m,21,1,IOVA,1,MID,SPTM_TABLE_MISSING);
    state.ttbr[1]=2;refused(&m,21,1,IOVA,1,MID,SPTM_BAD_TABLE);
    m=reset();state.ttbr[0]=ROOT>>12|1;
    refused(&m,21,1,IOVA,0,ROOT,SPTM_FRAME_BUSY);
    for(unsigned i=0;i<8;i++) {
        m=reset();attach(&m,0,ROOT,IOVA);
        if(i==0)meta(ROOT)[4]=0;
        if(i==1)meta(ROOT)[4]=2;
        if(i==2)put64(ROOT+16*8,2);
        if(i==3)put64(ROOT+16*8,descriptor(MID)|4);
        if(i==4)put64(ROOT+16*8,1);
        if(i==5)put64(ROOT+16*8,descriptor(BASE+SIZE));
        if(i==6)meta(ROOT)[9]=0;
        if(i==7)unavailable=ROOT;
        enum sptm_result want=i<2?SPTM_BAD_REFERENCE:i<6?SPTM_BAD_TABLE:
            i==6?SPTM_TYPE_MISMATCH:SPTM_MEMORY_UNAVAILABLE;
        refused(&m,21,1,IOVA,1,MID,want);
    }
    m=reset();attach(&m,0,ROOT,IOVA);attach(&m,1,MID,IOVA);
    unavailable=FM+((MID-BASE)>>14)*16;
    refused(&m,21,1,IOVA,2,LEAF,SPTM_MEMORY_UNAVAILABLE);
    m=reset();m.frame_map_pa=ROOT;
    refused(&m,21,1,IOVA,0,ROOT,SPTM_BAD_CONFIG);
    m=reset();m.alloc_high=BASE+SIZE+1;
    refused(&m,21,1,IOVA,0,ROOT,SPTM_BAD_CONFIG);
    m=reset();m.publish=0;
    refused(&m,21,1,IOVA,0,ROOT,SPTM_BAD_CONFIG);
    printf("sptm-dart: %u checks passed\n",checks);
    return 0;
}

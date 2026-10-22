/* SPDX-License-Identifier: MIT */
#include "sptm-dart.h"
#include "sptm-refs.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define BASE 0x8c0000000UL
#define SIZE 0x40000UL
#define FM (BASE+0x4000)
#define ROOT (BASE+0x10000)
#define MID (BASE+0x14000)
#define LEAF (BASE+0x18000)
#define DATA (BASE+0x20000)
#define DATA2 (BASE+0x24000)
#define VA 0x10000000000UL
static uint8_t ram[SIZE],saved[SIZE],removing[2048];
static struct dart_state s,before;
static struct sptm_ref_batch refs;
static unsigned checks,pubs;
static uint64_t unavailable;
#define CHECK(x) do { checks++;if (!(x)) {fprintf(stderr,"FAIL %d: %s\n",__LINE__,#x);exit(1);} } while(0)
static uint8_t *meta(uint64_t pa) {return ram+(FM-BASE)+((pa-BASE)>>14)*16;}
static uint64_t get(uint64_t pa) {uint64_t v;memcpy(&v,ram+(pa-BASE),8);return v;}
static void put(uint64_t pa,uint64_t v) {memcpy(ram+(pa-BASE),&v,8);}
static uint32_t count(uint64_t pa,unsigned off) {uint32_t v;memcpy(&v,meta(pa)+off,4);return v;}
static void set_count(uint64_t pa,unsigned off,uint32_t v) {memcpy(meta(pa)+off,&v,4);}
static unsigned table_refs(void) {return meta(LEAF)[4]|((unsigned)meta(LEAF)[5]<<8);}
static void set_table_refs(unsigned n) {meta(LEAF)[4]=(uint8_t)n;meta(LEAF)[5]=(uint8_t)(n>>8);}
static volatile uint8_t *map(void *ctx,uint64_t pa,uint64_t n)
{CHECK(ctx==ram);return pa==unavailable || pa<BASE || pa>=BASE+SIZE || !n || n>BASE+SIZE-pa ? 0 : ram+(pa-BASE);}
static void publish(void *ctx,uint64_t pa,uint64_t n)
{
    CHECK(ctx==ram);pubs++;
    if (n==8) {
        CHECK(pa>=LEAF && pa<LEAF+0x4000 && !get(pa));
        CHECK(s.flushes==before.flushes);
        /* No reference may be released while any old translation survives. */
        for (unsigned d=0;d<2;d++) {
            uint64_t data=DATA+d*0x4000,off=FM-BASE+((data-BASE)>>14)*16;
            CHECK(!memcmp(meta(data),saved+off,16));
        }
    } else {
        CHECK(n==16 && pa>=FM && pa<FM+0x4000 && s.flushes==before.flushes+1);
        for (unsigned i=0;i<2048;i++) if (removing[i]) CHECK(get(LEAF+8*i)==0);
    }
}
static struct sptm_memory reset(void)
{
    memset(ram,0,SIZE);memset(&refs,0,sizeof(refs));memset(removing,0,sizeof(removing));dart_init(&s);unavailable=0;pubs=0;
    s.initialized_ids=s.powered_ids=1U<<21;s.tcr[1]=9;s.ttbr[1]=(ROOT>>12)|1;s.enabled[0]=2;
    uint64_t pages[]={ROOT,MID,LEAF};
    for (unsigned i=0;i<3;i++) {uint8_t m[16]={0,0,24,0,(uint8_t)(i==2 ? 1 : 2),0,5,0,21,1,(uint8_t)i};memcpy(meta(pages[i]),m,16);}
    put(ROOT+16*8,(MID>>4)|1);put(MID,(LEAF>>4)|1);
    meta(DATA)[2]=meta(DATA2)[2]=11;memset(ram+(DATA-BASE),0xa5,0x8000);
    /* Existing CPU mappings must survive every DMA teardown. */
    set_count(DATA,8,1);set_count(DATA,12,3);set_count(DATA2,12,2);
    return (struct sptm_memory){.frame_map_pa=FM,.frame_low=BASE,.frame_high=BASE+SIZE,
        .alloc_low=ROOT,.alloc_high=BASE+SIZE,.map=map,.publish=publish,.ctx=ram,.refs=&refs};
}
static void add(unsigned i,uint64_t pa,unsigned flags)
{
    CHECK(i<2048 && !get(LEAF+8*i));put(LEAF+8*i,(pa>>4)|1|flags|(0xfffUL<<40));
    unsigned off=flags&4 ? 8 : 12;set_count(pa,off,count(pa,off)+1);set_table_refs(table_refs()+1);
}
static void snapshot(void) {memcpy(saved,ram,SIZE);before=s;pubs=0;}
static void refused(struct sptm_memory *m,uint64_t id,uint64_t sid,uint64_t va,uint64_t n,uint64_t opt,enum sptm_result want)
{
    snapshot();CHECK(sptm_dart_unmap(m,&s,id,sid,va,n,opt)==want);
    CHECK(!pubs && !memcmp(ram,saved,SIZE) && !memcmp(&s,&before,sizeof(s)));
}
static void unmap_ok(struct sptm_memory *m,uint64_t va,uint64_t n,uint64_t opt)
{
    memset(removing,0,sizeof(removing));
    for (uint64_t a=va&~0x3fffUL;a<va+n;a+=0x4000) removing[(a>>14)&2047]=1;
    snapshot();CHECK(sptm_dart_unmap(m,&s,21,1,va,n,opt)==SPTM_OK);
    CHECK(s.flushes==before.flushes+1 && s.translations==before.translations && s.faults==before.faults);
    CHECK(!memcmp(ram+(DATA-BASE),saved+(DATA-BASE),0x8000));
}
int main(void)
{
    struct sptm_memory m=reset();add(2,DATA,0);add(3,DATA,4);add(5,DATA2,8);
    /* Exact request observed from Apple's AES completion path. */
    unmap_ok(&m,VA+0x8000,0x4000,0);
    CHECK(!get(LEAF+16) && get(LEAF+24) && get(LEAF+40) && table_refs()==3);
    CHECK(count(DATA,12)==3 && count(DATA,8)==2 && count(DATA2,12)==3);
    uint64_t pa=0x55;CHECK(sptm_dart_dma_translate(&m,&s,21,1,VA+0x8000,16,0,&pa)==SPTM_TABLE_MISSING && pa==0x55);
    CHECK(sptm_dart_dma_translate(&m,&s,21,1,VA+0xc000,16,0,&pa)==SPTM_OK && pa==DATA);
    refused(&m,21,1,VA+0x8000,0x4000,0,SPTM_TABLE_MISSING);
    unmap_ok(&m,VA+0x8000,0x4000,2);CHECK(!pubs && table_refs()==3);
    /* Touched subpages remove whole leaves, as the shipped handler does. */
    unmap_ok(&m,VA+0xffff,2,2);CHECK(!get(LEAF+24) && table_refs()==2 && count(DATA,8)==1);
    m=reset();add(0,DATA,0);add(1,DATA,4);add(2,DATA2,0);
    unmap_ok(&m,VA,0xc000,0);CHECK(table_refs()==1 && count(DATA,12)==3 && count(DATA,8)==1 && count(DATA2,12)==2);
    /* Clear all 2048 aliases, aggregate decrements, retain the table's parent reference. */
    m=reset();for (unsigned i=0;i<2048;i++) add(i,DATA,i&1 ? 4 : 0);
    unmap_ok(&m,VA,1UL<<25,0);CHECK(table_refs()==1 && count(DATA,8)==1 && count(DATA,12)==3);
    m=reset();add(0,DATA,0);add(2,DATA2,0);
    refused(&m,21,1,VA,0xc000,0,SPTM_TABLE_MISSING);unmap_ok(&m,VA,0xc000,2);
    for (unsigned field=0;field<16;field++) {
        m=reset();add(0,DATA,0);add(1,DATA2,0);meta(DATA2)[field]^=0x80;
        enum sptm_result want=field==2 ? SPTM_TYPE_MISMATCH : field<2 ? SPTM_FRAME_BUSY : SPTM_BAD_REFERENCE;
        if (field>=8 && field!=11 && field!=15) continue; /* Valid extra aliases. */
        refused(&m,21,1,VA,0x8000,0,want);
    }
    m=reset();add(0,DATA,0);add(1,DATA,0);set_count(DATA,12,1);
    refused(&m,21,1,VA,0x8000,0,SPTM_BAD_REFERENCE);
    m=reset();add(0,DATA,4);set_count(DATA,8,0);refused(&m,21,1,VA,16,0,SPTM_BAD_REFERENCE);
    m=reset();add(0,DATA,0);meta(LEAF)[4]++;
    refused(&m,21,1,VA,16,0,SPTM_BAD_REFERENCE);
    m=reset();add(0,DATA,0);meta(MID)[9]=0;refused(&m,21,1,VA,16,0,SPTM_TYPE_MISMATCH);
    m=reset();add(0,DATA,0);put(MID,(ROOT>>4)|1);refused(&m,21,1,VA,16,0,SPTM_BAD_TABLE);
    m=reset();add(0,DATA,0);put(LEAF,(FM>>4)|1|(0xfffUL<<40));refused(&m,21,1,VA,16,0,SPTM_BAD_TABLE);
    m=reset();add(0,DATA,0);
    const uint64_t badopt[]={1,3,4,UINT64_MAX};
    for (unsigned i=0;i<4;i++) refused(&m,21,1,VA,16,badopt[i],SPTM_UNSUPPORTED_OPTIONS);
    refused(&m,21,1,VA,0,0,SPTM_BAD_ADDRESS);refused(&m,21,1,VA,0x2000001,0,SPTM_BAD_ADDRESS);
    refused(&m,21,1,VA+0x1fffff0,32,0,SPTM_BAD_ADDRESS);refused(&m,21,1,UINT64_MAX,16,0,SPTM_BAD_ADDRESS);
    refused(&m,21,1,(1UL<<42)-16,16,0,SPTM_BAD_ADDRESS);refused(&m,21,1,VA-1,16,0,SPTM_BAD_ADDRESS);
    refused(&m,20,1,VA,16,0,SPTM_BAD_CONFIG);refused(&m,21,0,VA,16,0,SPTM_BAD_CONFIG);
    refused(&m,21,2,VA,16,0,SPTM_UNSUPPORTED_OPTIONS);
    uint64_t missing[]={ROOT,MID,LEAF,FM+((DATA-BASE)>>14)*16};
    for (unsigned i=0;i<4;i++) {unavailable=missing[i];refused(&m,21,1,VA,16,0,SPTM_MEMORY_UNAVAILABLE);}
    unavailable=0;m.refs=0;refused(&m,21,1,VA,16,0,SPTM_BAD_CONFIG);
    printf("SPTM DART UNMAP: %u checks passed (native range, shared references, full span, holes, ordering, atomic refusals)\n",checks);
}

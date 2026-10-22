/* SPDX-License-Identifier: MIT */
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "sptm-dart.h"
#include "sptm-refs.h"

#define BASE 0x8c0000000UL
#ifndef SIZE
#define SIZE 0x180000UL
#endif
#define FM (BASE+0x4000)
#define ROOT (BASE+0x140000)
#define LEAF (BASE+0x144000)
#define LIST (BASE+0x148000)
#define DATA (BASE+0x14c000)
#define FIRMWARE (BASE+0x8000)
#define FIRMWARE_SIZE 0x104000UL
static uint8_t ram[SIZE],saved[SIZE];
static struct dart_state state,saved_state;
static struct sptm_ref_batch refs;
static unsigned checks,pubs;
#define CHECK(x) do { checks++; if (!(x)) { fprintf(stderr,"FAIL %d: %s\n",__LINE__,#x); assert(x); } } while(0)
static uint8_t *meta(uint64_t pa) { return ram+(FM-BASE)+((pa-BASE)>>14)*16; }
static uint64_t get(uint64_t pa) { uint64_t v;memcpy(&v,ram+(pa-BASE),8);return v; }
static void put(uint64_t pa,uint64_t v) { memcpy(ram+(pa-BASE),&v,8); }
static uint32_t count(unsigned off) { uint32_t v;memcpy(&v,meta(DATA)+off,4);return v; }
static volatile uint8_t *map(void *ctx,uint64_t pa,uint64_t n)
{ return ctx==ram && pa>=BASE && pa<BASE+SIZE && n && n<=BASE+SIZE-pa ? ram+(pa-BASE) : 0; }
static void publish(void *ctx,uint64_t pa,uint64_t n)
{ CHECK(map(ctx,pa,n)!=0);pubs++; }
static int allow(void *ctx,uint64_t pa,uint64_t n,int write)
{ (void)write;return map(ctx,pa,n)!=0; }
static int read64(void *ctx,uint64_t pa,uint64_t *v)
{ if(!map(ctx,pa,8))return -1;*v=get(pa);return 0; }
static void snapshot(void) { memcpy(saved,ram,SIZE);saved_state=state;pubs=0; }
static void unchanged(void)
{ CHECK(!pubs && !memcmp(ram,saved,SIZE) && !memcmp(&state,&saved_state,sizeof(state))); }
static struct sptm_memory reset(unsigned sid)
{
    memset(ram,0,SIZE);memset(&refs,0,sizeof(refs));dart_init(&state);
    state.initialized_ids=state.powered_ids=1U<<20;
    state.tcr[0]=state.tcr[1]=1;state.tcr[2]=9;
    for(unsigned level=1;level<3;level++) {
        uint8_t e[16]={0,0,24,0,0,0,5,0,20,(uint8_t)sid,(uint8_t)level,0,0,0,0,0};
        memcpy(meta(level==1 ? ROOT : LEAF),e,16);
    }
    meta(LIST)[2]=meta(DATA)[2]=11;put(LIST,DATA);
    snapshot();
    return (struct sptm_memory){.frame_map_pa=FM,.frame_low=BASE,.frame_high=BASE+SIZE,
        .alloc_low=ROOT,.alloc_high=BASE+SIZE,.map=map,.publish=publish,.ctx=ram,.refs=&refs};
}
static void attach(struct sptm_memory *m,unsigned sid,uint64_t va)
{
    CHECK(sptm_dart_map_table(m,&state,20,sid,va,1,ROOT)==SPTM_OK);
    CHECK(state.ttbr[sid]==(ROOT>>12|1) && meta(ROOT)[4]==1 && !state.enabled[0]);
    CHECK(sptm_dart_map_table(m,&state,20,sid,va,2,LEAF)==SPTM_OK);
    CHECK(meta(ROOT)[4]==2 && meta(LEAF)[4]==1);
    CHECK(get(ROOT+8*((va>>25)&2047))==(LEAF>>4|1));
}
static void firmware_test(void)
{
    uint64_t va=0x10000004000UL;
    for(unsigned flags=0;flags<4;flags++) {
        struct sptm_memory m=reset(0);
        m.sep_firmware_pa=FIRMWARE;m.sep_firmware_size=FIRMWARE_SIZE;
        for(unsigned i=0;i<65;i++) {
            meta(FIRMWARE+i*0x4000)[2]=11;put(LIST+8*i,FIRMWARE+i*0x4000);
        }
        memset(ram+(FIRMWARE-BASE),0xa5,FIRMWARE_SIZE);
        CHECK(sptm_sep_firmware_valid(&m));
        CHECK(!sptm_managed_frame(&m,FIRMWARE));
        snapshot();CHECK(sptm_mac_retype(&m,FIRMWARE,11,24,0x1001400000005UL)==SPTM_BAD_ADDRESS);unchanged();
        snapshot();CHECK(sptm_refs_dart(&m,FIRMWARE,0)==SPTM_BAD_ADDRESS);unchanged();
        for(unsigned id=0;id<32;id++)for(unsigned sid=0;sid<3;sid++) {
            if(id==20 && sid==0)continue;
            sptm_refs_begin(&refs);snapshot();
            CHECK(sptm_refs_dart_stream(&m,id,sid,FIRMWARE,0,0)==SPTM_BAD_ADDRESS);unchanged();
        }
        snapshot();CHECK(sptm_dart_map_table(&m,&state,20,0,va,1,FIRMWARE)==SPTM_BAD_ADDRESS);unchanged();
        attach(&m,0,va);
        snapshot();CHECK(sptm_dart_map(&m,&state,20,0,va,FIRMWARE,0x4000,flags)==SPTM_BAD_ADDRESS);unchanged();
        CHECK(sptm_dart_map(&m,&state,20,0,va,LIST,FIRMWARE_SIZE,flags)==SPTM_OK);
        CHECK(meta(LEAF)[4]==66);
        snapshot();CHECK(sptm_dart_map(&m,&state,20,0,va,LIST,FIRMWARE_SIZE,flags)==SPTM_OK);unchanged();
        CHECK(sptm_dart_enable(&m,&state,20,0)==SPTM_OK);
        for(unsigned i=0;i<65;i++) {
            uint32_t n;memcpy(&n,meta(FIRMWARE+i*0x4000)+(flags&2 ? 8 : 12),4);CHECK(n==1);
            uint64_t physical=0;
            for(int write=0;write<2;write++) {
                int permitted=!(flags&(write ? 2 : 1));
                CHECK(sptm_dart_dma_translate(&m,&state,20,0,va+i*0x4000,0x4000,write,&physical)==
                      (permitted ? SPTM_OK : SPTM_UNSUPPORTED_OPTIONS));
                if(permitted)CHECK(physical==FIRMWARE+i*0x4000);
            }
        }
        CHECK(sptm_dart_unmap(&m,&state,20,0,va,FIRMWARE_SIZE,0)==SPTM_OK);
        CHECK(meta(LEAF)[4]==1);
        for(unsigned i=0;i<65;i++)CHECK(!get(FM+((FIRMWARE+i*0x4000-BASE)>>14)*16+8));
        CHECK(!memcmp(ram+(FIRMWARE-BASE),saved+(FIRMWARE-BASE),FIRMWARE_SIZE));
        uint64_t outside[]={FIRMWARE-0x4000,FIRMWARE+FIRMWARE_SIZE,BASE+0x120000};
        for(unsigned i=0;i<3;i++) {
            meta(outside[i])[2]=11;put(LIST,outside[i]);snapshot();
            CHECK(sptm_dart_map(&m,&state,20,0,va,LIST,0x4000,flags)==SPTM_BAD_ADDRESS);unchanged();
        }
        /* A bad final entry must not partially publish the 64 valid inputs. */
        for(unsigned i=0;i<65;i++)put(LIST+8*i,FIRMWARE+i*0x4000);
        put(LIST+64*8,FIRMWARE+FIRMWARE_SIZE);snapshot();
        CHECK(sptm_dart_map(&m,&state,20,0,va,LIST,FIRMWARE_SIZE,flags)==SPTM_BAD_ADDRESS);unchanged();
    }
    for(unsigned bad=0;bad<8;bad++) {
        struct sptm_memory m=reset(0);m.sep_firmware_pa=FIRMWARE;m.sep_firmware_size=FIRMWARE_SIZE;
        if(bad==0)m.sep_firmware_pa++;
        if(bad==1)m.sep_firmware_size++;
        if(bad==2)m.sep_firmware_size=0;
        if(bad==3)m.sep_firmware_pa=0;
        if(bad==4)m.sep_firmware_pa=ROOT;
        if(bad==5)m.sep_firmware_pa=FM;
        if(bad==6)m.sep_firmware_size=0x1004000;
        if(bad==7)m.sep_firmware_pa=UINT64_MAX-0x3fff;
        snapshot();CHECK(!sptm_sep_firmware_valid(&m));
        CHECK(sptm_dart_map_table(&m,&state,20,0,va,1,ROOT)==SPTM_BAD_CONFIG);unchanged();
    }
    for(unsigned bad=0;bad<4;bad++) {
        struct sptm_memory m=reset(0);m.sep_firmware_pa=FIRMWARE;m.sep_firmware_size=FIRMWARE_SIZE;
        meta(FIRMWARE)[2]=11;put(LIST,FIRMWARE);attach(&m,0,va);
        if(bad==0)meta(FIRMWARE)[2]=35;
        if(bad==1)meta(FIRMWARE)[0]=1;
        if(bad==2)meta(FIRMWARE)[6]=5;
        if(bad==3) { uint32_t full=0x7fffffff;memcpy(meta(FIRMWARE)+12,&full,4); }
        snapshot();CHECK(sptm_dart_map(&m,&state,20,0,va,LIST,0x4000,0)!=SPTM_OK);unchanged();
    }
}
/* After the SEP boots, XNU frees the SEPFW extent into the VM without a
 * monitor call (every frame is already XNU_DEFAULT). Released, the extent is
 * ordinary allocator memory: enumerated, counted, and mappable by any stream. */
static void released_test(void)
{
    uint64_t va=0x10000004000UL,last=FIRMWARE+FIRMWARE_SIZE-0x4000;
    struct sptm_memory m=reset(0);
    m.sep_firmware_pa=FIRMWARE;m.sep_firmware_size=FIRMWARE_SIZE;
    for(unsigned i=0;i<65;i++) {
        meta(FIRMWARE+i*0x4000)[2]=11;put(LIST+8*i,FIRMWARE+i*0x4000);
    }
    attach(&m,0,va);
    CHECK(sptm_dart_map(&m,&state,20,0,va,LIST,FIRMWARE_SIZE,0)==SPTM_OK);
    CHECK(sptm_next_frame(&m,0)==ROOT && !sptm_managed_frame(&m,last));
    sptm_refs_begin(&refs);snapshot();
    CHECK(sptm_refs_dart_stream(&m,20,1,FIRMWARE,0,0)==SPTM_BAD_ADDRESS);unchanged();

    m.sep_firmware_released=1;
    CHECK(sptm_sep_firmware_valid(&m));
    CHECK(sptm_managed_frame(&m,FIRMWARE) && sptm_managed_frame(&m,last));
    CHECK(!sptm_managed_frame(&m,FIRMWARE-0x4000) && !sptm_managed_frame(&m,last+0x4000));
    CHECK(!sptm_managed_frame(&m,FIRMWARE+8));
    unsigned frames=0;
    for(uint64_t pa=sptm_next_frame(&m,0);pa<m.alloc_high;pa=sptm_next_frame(&m,pa+0x4000)) {
        CHECK(sptm_managed_frame(&m,pa));frames++;
    }
    CHECK(frames==65+(BASE+SIZE-ROOT)/0x4000);
    CHECK(sptm_next_frame(&m,last+0x4000)==ROOT && sptm_next_frame(&m,FIRMWARE+4)==FIRMWARE+4);
    /* The boot-time firmware mapping drains through the ordinary path. */
    CHECK(sptm_dart_unmap(&m,&state,20,0,va,FIRMWARE_SIZE,0)==SPTM_OK);
    for(unsigned i=0;i<65;i++)CHECK(!get(FM+((FIRMWARE+i*0x4000-BASE)>>14)*16+8));
    /* Any stream may now map a freed frame, and it counts like any other. */
    sptm_refs_begin(&refs);
    CHECK(sptm_refs_dart_stream(&m,20,1,FIRMWARE,0,0)==SPTM_OK);
    sptm_refs_commit(&m);
    uint32_t n;memcpy(&n,meta(FIRMWARE)+12,4);CHECK(n==1);
    sptm_refs_begin(&refs);
    CHECK(sptm_refs_dart_stream(&m,20,1,FIRMWARE,0,1)==SPTM_OK);
    sptm_refs_commit(&m);
    memcpy(&n,meta(FIRMWARE)+12,4);CHECK(n==0);
    CHECK(sptm_refs_dart(&m,FIRMWARE,1)==SPTM_OK);
    /* Released frames still need XNU_DEFAULT-compatible metadata to count. */
    meta(last)[2]=20;sptm_refs_begin(&refs);
    CHECK(sptm_refs_dart_stream(&m,20,1,last,0,0)==SPTM_TYPE_MISMATCH);
}
int main(void)
{
    struct dart_memory dm={.read64=read64,.allow=allow,.ctx=ram};
    for(unsigned sid=0;sid<2;sid++) {
        uint64_t low=sid ? 0x10000000000UL : 0x10000004000UL;
        uint64_t end=sid ? 0x10050000000UL : 0x100ffff4000UL;
        uint64_t addresses[]={low,low+0x4000000,end-0x4000};
        for(unsigned n=0;n<3;n++)for(unsigned flags=0;flags<4;flags++) {
            struct sptm_memory m=reset(sid);uint64_t va=addresses[n],pa=0;
            snapshot();CHECK(sptm_dart_map_table(&m,&state,20,sid,va,0,ROOT)==SPTM_UNSUPPORTED_OPTIONS);unchanged();
            attach(&m,sid,va);
            CHECK(sptm_dart_map(&m,&state,20,sid,va,LIST,0x4000,flags)==SPTM_OK);
            CHECK(count(flags&2 ? 8 : 12)==1 && meta(LEAF)[4]==2);
            CHECK(sptm_dart_enable(&m,&state,20,sid)==SPTM_OK);
            for(int write=0;write<2;write++) {
                int permitted=!(flags&(write ? 2 : 1));
                CHECK(sptm_dart_dma_translate(&m,&state,20,sid,va+8,16,write,&pa)==
                      (permitted ? SPTM_OK : SPTM_UNSUPPORTED_OPTIONS));
                if(permitted)CHECK(pa==DATA+8);
                CHECK((dart_translate(&state,3,&dm,sid,va+8,16,write,&pa)==DART_OK)==permitted);
                if(permitted)CHECK(pa==DATA+8);
            }
            uint64_t invalid[]={low-1,end,end+0x4000,va-(1UL<<40),va+(1UL<<36)};
            for(unsigned i=0;i<5;i++) {
                snapshot();CHECK(sptm_dart_map(&m,&state,20,sid,invalid[i],LIST,1,flags)==SPTM_BAD_ADDRESS);unchanged();
                CHECK(sptm_dart_dma_translate(&m,&state,20,sid,invalid[i],1,0,&pa)==SPTM_BAD_ADDRESS);unchanged();
                CHECK(dart_translate(&state,3,&dm,sid,invalid[i],1,0,&pa)!=DART_OK);
            }
            snapshot();CHECK(sptm_dart_map(&m,&state,20,sid,end-4,LIST,8,flags)==SPTM_BAD_ADDRESS);unchanged();
            CHECK(sptm_dart_unmap(&m,&state,20,sid,va,0x4000,0)==SPTM_OK);
            CHECK(!count(8) && !count(12) && meta(LEAF)[4]==1);
            CHECK(sptm_dart_dma_translate(&m,&state,20,sid,va,1,0,&pa)==SPTM_TABLE_MISSING);
        }
        for(unsigned mutation=0;mutation<6;mutation++) {
            struct sptm_memory m=reset(sid);attach(&m,sid,low);
            if(mutation==0)state.tcr[sid]=9;
            if(mutation==1)meta(ROOT)[10]=0;
            if(mutation==2)meta(LEAF)[9]^=1;
            if(mutation==3)meta(ROOT)[4]++;
            if(mutation==4)put(ROOT+8*(sid ? 40 : 128),(LEAF>>4)|1);
            if(mutation==5)put(ROOT+8*((low>>25)&2047),(ROOT>>4)|1);
            snapshot();CHECK(sptm_dart_map(&m,&state,20,sid,low,LIST,0x4000,0)!=SPTM_OK);unchanged();
        }
    }
    firmware_test();
    released_test();
    printf("PASS SEP two-level DART and reserved firmware: %u checks\n",checks);
    return 0;
}

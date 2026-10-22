/* SPDX-License-Identifier: MIT */
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "sptm-dart.h"
#include "sptm-refs.h"

#define BASE 0x8c0000000UL
#define SIZE 0x40000UL
#define FM (BASE+0x4000)
#define ROOT (BASE+0x10000)
#define MID (BASE+0x14000)
#define LEAF (BASE+0x18000)
#define LIST (BASE+0x1c000)
#define DATA (BASE+0x20000)
#define DATA2 (BASE+0x24000)
#define IOVA (1UL<<40)
static uint8_t ram[SIZE],saved[SIZE];
static struct dart_state state,saved_state;
static struct sptm_ref_batch refs;
static uint64_t unavailable;
static unsigned checks,pubs;
#define CHECK(x) do { checks++; if (!(x)) { fprintf(stderr,"FAIL %d: %s\n",__LINE__,#x); assert(x); } } while(0)
static uint8_t *meta(uint64_t pa) { return ram+(FM-BASE)+((pa-BASE)>>14)*16; }
static uint64_t get(uint64_t pa) { uint64_t v;memcpy(&v,ram+(pa-BASE),8);return v; }
static void put(uint64_t pa,uint64_t v) { memcpy(ram+(pa-BASE),&v,8); }
static uint32_t count(uint64_t pa,unsigned off) { uint32_t v;memcpy(&v,meta(pa)+off,4);return v; }
static void set_count(uint64_t pa,unsigned off,uint32_t v) { memcpy(meta(pa)+off,&v,4); }
static volatile uint8_t *map(void *ctx,uint64_t pa,uint64_t n)
{
    CHECK(ctx==ram);
    if (pa==unavailable || pa<BASE || pa>=BASE+SIZE || !n || n>BASE+SIZE-pa) return 0;
    return ram+(pa-BASE);
}
static void publish(void *ctx,uint64_t pa,uint64_t n)
{
    CHECK(ctx==ram);pubs++;
    if (n==8 && pa>=LEAF && pa<LEAF+0x4000) {
        uint64_t v=get(pa),data=(v&0x3ffffffc00UL)<<4;
        CHECK(count(data,v&4 ? 8 : 12)>0);
        CHECK(meta(LEAF)[4]+((unsigned)meta(LEAF)[5]<<8)>=2);
    }
}
static void snapshot(void) { memcpy(saved,ram,SIZE);saved_state=state;pubs=0; }
static struct sptm_memory reset(void)
{
    memset(ram,0,SIZE);memset(&refs,0,sizeof(refs));dart_init(&state);unavailable=0;
    state.initialized_ids=state.powered_ids=1U<<21;
    state.tcr[0]=state.tcr[1]=9;state.ttbr[1]=(uint32_t)(ROOT>>12)|1;
    uint64_t tables[]={ROOT,MID,LEAF};
    for(unsigned i=0;i<3;i++) {
        uint8_t e[16]={0,0,24,0,(uint8_t)(i==2 ? 1 : 2),0,5,0,21,1,(uint8_t)i,0,0,0,0,0};
        memcpy(meta(tables[i]),e,16);
    }
    put(ROOT+16*8,(MID>>4)|1);put(MID,(LEAF>>4)|1);
    meta(LIST)[2]=meta(DATA)[2]=meta(DATA2)[2]=11;
    put(LIST,DATA);put(LIST+8,DATA2);set_count(DATA,12,1);
    snapshot();
    return (struct sptm_memory){.frame_map_pa=FM,.frame_low=BASE,.frame_high=BASE+SIZE,
        .alloc_low=ROOT,.alloc_high=BASE+SIZE,.map=map,.publish=publish,.ctx=ram,.refs=&refs};
}
static void refused(struct sptm_memory *m,uint64_t id,uint64_t sid,uint64_t va,
                    uint64_t list,uint64_t size,uint64_t flags,enum sptm_result want)
{
    snapshot();
    CHECK(sptm_dart_map(m,&state,id,sid,va,list,size,flags)==want);
    CHECK(!pubs && !memcmp(saved,ram,SIZE) && !memcmp(&state,&saved_state,sizeof(state)));
}
static void enable_refused(struct sptm_memory *m,uint64_t id,uint64_t sid,enum sptm_result want)
{
    snapshot();CHECK(sptm_dart_enable(m,&state,id,sid)==want);
    CHECK(!pubs && !memcmp(saved,ram,SIZE) && !memcmp(&state,&saved_state,sizeof(state)));
}
static int allow(void *ctx,uint64_t pa,uint64_t n,int write)
{ (void)write;return ctx==ram && pa>=ROOT && pa<BASE+SIZE && n<=BASE+SIZE-pa; }
static int read64(void *ctx,uint64_t pa,uint64_t *v)
{ if(!allow(ctx,pa,8,0))return -1;*v=get(pa);return 0; }
static void translate(uint64_t va,uint64_t n,int write,enum dart_result result,uint64_t expected)
{
    struct dart_memory memory={.read64=read64,.allow=allow,.ctx=ram};
    uint64_t pa=0;
    CHECK(dart_translate(&state,2,&memory,1,va,n,write,&pa)==result);
    if(result==DART_OK)CHECK(pa==expected);
}
int main(void)
{
    struct sptm_memory m=reset();
    CHECK(sptm_dart_map(&m,&state,21,1,IOVA,LIST,0x4000,0)==SPTM_OK);
    CHECK(get(LEAF)==((DATA>>4)|1|(0xfffUL<<40)));
    CHECK(count(DATA,12)==2 && count(DATA,8)==0 && meta(LEAF)[4]==2);
    CHECK(pubs==3 && !memcmp(&state,&saved_state,sizeof(state)));
    snapshot();CHECK(sptm_dart_map(&m,&state,21,1,IOVA,LIST,0x4000,0)==SPTM_OK);
    CHECK(!pubs && !memcmp(saved,ram,SIZE));
    refused(&m,21,1,IOVA,LIST,0x4000,2,SPTM_TABLE_EXISTS);
    CHECK(sptm_dart_enable(&m,&state,21,1)==SPTM_OK);
    CHECK(state.enabled[0]==2);
    translate(IOVA,0x4000,0,DART_OK,DATA);translate(IOVA+5,10,1,DART_OK,DATA+5);

    for(unsigned flags=0;flags<4;flags++) {
        m=reset();CHECK(sptm_dart_map(&m,&state,21,1,IOVA+3,LIST,0x4004,flags)==SPTM_OK);
        CHECK(((get(LEAF)>>40)&0xfff)==0xfff && (get(LEAF)>>52)==0);
        CHECK(((get(LEAF+8)>>40)&0xfff)==1 && (get(LEAF+8)>>52)==0);
        CHECK(count(DATA,flags&2 ? 8 : 12)==(flags&2 ? 1u : 2u));
        CHECK(count(DATA2,flags&2 ? 8 : 12)==1);
        CHECK(meta(LEAF)[4]==3);state.enabled[0]=2;
        if(!(flags&1))translate(IOVA+0x4006,1,0,DART_OK,DATA2+6);
        if(!(flags&2))translate(IOVA+4,4,1,DART_OK,DATA+4);
    }
    m=reset();CHECK(sptm_dart_map(&m,&state,21,1,IOVA+9,LIST,6,2)==SPTM_OK);
    CHECK((get(LEAF)>>52)==2 && ((get(LEAF)>>40)&0xfff)==3);
    state.enabled[0]=2;
    translate(IOVA+8,8,0,DART_OK,DATA+8);
    uint64_t pa=0;struct dart_memory dm={.read64=read64,.allow=allow,.ctx=ram};
    CHECK(dart_translate(&state,2,&dm,1,IOVA+7,1,0,&pa)!=DART_OK);
    CHECK(dart_translate(&state,2,&dm,1,IOVA+16,1,0,&pa)!=DART_OK);
    CHECK(dart_translate(&state,2,&dm,1,IOVA+8,1,1,&pa)!=DART_OK);

    /* Maximum batch, same physical page repeated: accumulate before checking
     * overflow and publish one final data reference count. */
    m=reset();for(unsigned i=0;i<2048;i++)put(LIST+8*i,DATA);
    CHECK(sptm_dart_map(&m,&state,21,1,IOVA,LIST,1UL<<25,0)==SPTM_OK);
    CHECK(count(DATA,12)==2049 && (meta(LEAF)[4]|((unsigned)meta(LEAF)[5]<<8))==2049);
    CHECK(pubs==2050 && refs.count==1);
    m=reset();put(LIST+8,DATA);set_count(DATA,12,INT32_MAX-1);
    refused(&m,21,1,IOVA,LIST,0x8000,0,SPTM_BAD_REFERENCE);
    m=reset();put(LIST+8,ROOT);
    refused(&m,21,1,IOVA,LIST,0x8000,0,SPTM_TYPE_MISMATCH);

    m=reset();meta(LIST)[2]=35;
    CHECK(sptm_dart_map(&m,&state,21,1,IOVA,LIST,0x4000,0)==SPTM_OK);
    for(unsigned typ=0;typ<44;typ++) if(typ!=11) {
        m=reset();meta(DATA)[2]=(uint8_t)typ;
        refused(&m,21,1,IOVA,LIST,0x4000,0,SPTM_TYPE_MISMATCH);
    }
    m=reset();refused(&m,32,1,IOVA,LIST,0x4000,0,SPTM_UNSUPPORTED_OPTIONS);
    refused(&m,21,2,IOVA,LIST,0x4000,0,SPTM_UNSUPPORTED_OPTIONS);
    refused(&m,21,1,IOVA,LIST,0x4000,4,SPTM_UNSUPPORTED_OPTIONS);
    refused(&m,21,1,IOVA,LIST,0,0,SPTM_BAD_ADDRESS);
    refused(&m,21,1,IOVA,LIST,(1UL<<25)+1,0,SPTM_BAD_ADDRESS);
    refused(&m,21,1,IOVA-1,LIST,1,0,SPTM_BAD_ADDRESS);
    refused(&m,21,1,(1UL<<42)-0x4000,LIST,0x4000,0,SPTM_BAD_ADDRESS);
    refused(&m,21,1,IOVA+(1UL<<25)-1,LIST,2,0,SPTM_BAD_ADDRESS);
    refused(&m,21,1,IOVA,LIST+1,1,0,SPTM_BAD_ADDRESS);
    refused(&m,21,1,IOVA,LIST+0x3ff8,0x8000,0,SPTM_BAD_ADDRESS);
    for(unsigned off=0;off<8;off++) if(off!=2) {
        m=reset();meta(DATA)[off]=1;
        refused(&m,21,1,IOVA,LIST,0x4000,0,off<2 ? SPTM_FRAME_BUSY : SPTM_BAD_REFERENCE);
    }
    m=reset();meta(LEAF)[4]=2;refused(&m,21,1,IOVA,LIST,0x4000,0,SPTM_BAD_REFERENCE);
    m=reset();put(LEAF+8,2);refused(&m,21,1,IOVA,LIST,0x4000,0,SPTM_BAD_TABLE);
    m=reset();put(ROOT+16*8,0);meta(ROOT)[4]=1;
    refused(&m,21,1,IOVA,LIST,0x4000,0,SPTM_TABLE_MISSING);
    m=reset();put(MID,(ROOT>>4)|1);refused(&m,21,1,IOVA,LIST,0x4000,0,SPTM_BAD_TABLE);
    m=reset();state.powered_ids=0;refused(&m,21,1,IOVA,LIST,0x4000,0,SPTM_BAD_CONFIG);
    m=reset();state.ttbr[1]=0;refused(&m,21,1,IOVA,LIST,0x4000,0,SPTM_TABLE_MISSING);
    m=reset();unavailable=LIST;refused(&m,21,1,IOVA,LIST,0x4000,0,SPTM_MEMORY_UNAVAILABLE);
    m=reset();unavailable=FM+((DATA-BASE)>>14)*16;
    refused(&m,21,1,IOVA,LIST,0x4000,0,SPTM_MEMORY_UNAVAILABLE);
    m=reset();m.refs=0;refused(&m,21,1,IOVA,LIST,0x4000,0,SPTM_BAD_CONFIG);

    /* ENABLE is W1S, not reset or a synthetic translation. Faults, mapping
     * metadata, counters, unrelated stream bits and protection survive. */
    m=reset();state.error=0x80100010;state.error_mask=0x20;state.error_streams[0]=2;
    state.error_address=IOVA;state.faults=7;state.translations=9;state.flushes=4;
    state.tlb_op=0x400;state.protect=state.protect_lock=1;state.enabled[0]=1;
    snapshot();CHECK(sptm_dart_enable(&m,&state,21,1)==SPTM_OK);
    saved_state.enabled[0]=3;
    CHECK(!pubs && !memcmp(saved,ram,SIZE) && !memcmp(&state,&saved_state,sizeof(state)));
    snapshot();CHECK(sptm_dart_enable(&m,&state,21,1)==SPTM_OK);
    CHECK(!pubs && !memcmp(&state,&saved_state,sizeof(state)));
    m=reset();CHECK(sptm_dart_enable(&m,&state,21,0)==SPTM_OK);CHECK(state.enabled[0]==1);
    CHECK(dart_translate(&state,2,&dm,0,IOVA,4,0,&pa)!=DART_OK);
    enable_refused(&m,32,1,SPTM_UNSUPPORTED_OPTIONS);
    enable_refused(&m,21,2,SPTM_UNSUPPORTED_OPTIONS);
    enable_refused(&m,1UL<<32,1,SPTM_UNSUPPORTED_OPTIONS);
    enable_refused(&m,21,1UL<<32,SPTM_UNSUPPORTED_OPTIONS);
    m=reset();state.powered_ids=0;enable_refused(&m,21,1,SPTM_BAD_CONFIG);
    m=reset();state.tcr[1]=1;enable_refused(&m,21,1,SPTM_BAD_CONFIG);
    m=reset();state.ttbr[1]|=2;enable_refused(&m,21,1,SPTM_BAD_TABLE);
    m=reset();meta(ROOT)[4]=1;enable_refused(&m,21,1,SPTM_BAD_REFERENCE);
    m=reset();meta(ROOT)[9]=0;enable_refused(&m,21,1,SPTM_TYPE_MISMATCH);
    m=reset();meta(ROOT)[0]=1;enable_refused(&m,21,1,SPTM_FRAME_BUSY);
    m=reset();put(ROOT+16*8,(ROOT>>4)|1);enable_refused(&m,21,1,SPTM_BAD_TABLE);
    m=reset();unavailable=ROOT;enable_refused(&m,21,1,SPTM_MEMORY_UNAVAILABLE);
    m=reset();put(ROOT+16*8,0);meta(ROOT)[4]=1;
    CHECK(sptm_dart_enable(&m,&state,21,1)==SPTM_OK);
    CHECK(dart_translate(&state,2,&dm,1,IOVA,4,0,&pa)!=DART_OK);
    printf("PASS: %u DART MAP/ENABLE checks (page lists, permissions, references, atomic refusal)\n",checks);
    return 0;
}

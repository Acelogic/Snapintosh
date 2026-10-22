/* SPDX-License-Identifier: MIT */
/* Native model: guest/software and hardware walks, metadata consumed through
 * an independent physical-to-virtual lookup, and unchanged payload bytes. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "sptm-slide.h"
#include "shadow.h"
#define BASE 0x90000000UL
#define SIZE 0x400000UL
#define META (BASE+0x40000)
#define DATA (BASE+0x80000)
#define SHADOW (BASE+0x200000)
#define VA 0xfffffe0001ffc000UL
#define DEST 0xfffffe01fc000000UL
#define PAGE 0x4000UL
#define VMASK ((1UL<<47)-1)
#define ATTR (PT_AF|PT_SH|PT_AP|PT_CONTIG|PT_UXN)
static uint8_t ram[SIZE],before[SIZE];
static unsigned checks,publications;
static uint64_t next_guest,next_shadow,missing;
static struct sptm_memory memory;
static struct sptm_update_backend backend;
static struct sptm_slide_config config;
static struct sptm_slide_state state;
#define CHECK(x) do { checks++; if(!(x)) { fprintf(stderr,"FAIL %d: %s\n",__LINE__,#x);exit(1); } } while(0)
static uint64_t get(uint64_t pa) { uint64_t v;memcpy(&v,ram+(pa-BASE),8);return v; }
static void put(uint64_t pa,uint64_t v) { memcpy(ram+(pa-BASE),&v,8); }
static volatile uint8_t *map(void *ctx,uint64_t pa,uint64_t n)
{ (void)ctx;return pa<BASE || pa>=SHADOW || n>SHADOW-pa || pa==missing ? NULL : ram+(pa-BASE); }
static volatile uint8_t *map_shadow(void *ctx,uint64_t pa,uint64_t n)
{ (void)ctx;return pa<SHADOW || pa>=next_shadow || n>next_shadow-pa || pa==missing ? NULL : ram+(pa-BASE); }
static void publish(void *ctx,uint64_t pa,uint64_t n)
{ CHECK(map(ctx,pa,n)!=NULL);publications++; }
static int read64(void *ctx,uint64_t pa,uint64_t *v)
{ (void)ctx;if(pa<BASE || pa>BASE+SIZE-8)return -1;*v=get(pa);return 0; }
static int write64(void *ctx,uint64_t pa,uint64_t v)
{ (void)ctx;if(pa<BASE || pa>BASE+SIZE-8)return -1;put(pa,v);return 0; }
static uint64_t alloc(void *ctx)
{ (void)ctx;uint64_t pa=next_shadow;next_shadow+=0x1000;CHECK(next_shadow<=BASE+SIZE);return pa; }
static uint64_t slot(uint64_t va,unsigned granule,unsigned target,int create)
{
    va &= VMASK;
    uint64_t table=granule==14 ? BASE : SHADOW;
    for(unsigned level=granule==14 ? 1 : 0;level<=target;level++) {
        uint64_t p=table+8UL*mmu_index(granule,level,va);
        if(level==target)return p;
        if(!get(p) && create) { put(p,next_guest|3);next_guest+=PAGE;CHECK(next_guest<=META); }
        CHECK((get(p)&3)==3);table=get(p)&PT_OA_MASK;
    }
    abort();
}
static struct mmu_leaf walk(uint64_t va,unsigned granule)
{
    struct mmu_config c={.granule_shift=granule,.txsz=17,.root=granule==14 ? BASE : SHADOW};
    struct mmu_leaf leaf;CHECK(!mmu_walk(&c,va&VMASK,read64,NULL,&leaf));return leaf;
}
static uint64_t physical_to_virtual(uint64_t pa)
{
    uint32_t n;memcpy(&n,ram+(META-BASE),4);
    for(unsigned i=0;i<n;i++) {
        uint64_t p=META+0x10+i*24,start=get(p),va=get(p+8);
        uint32_t pages;memcpy(&pages,ram+(p+16-BASE),4);
        if(pa>=start && pa-start<(uint64_t)pages*PAGE)return va+pa-start;
    }
    return 0;
}
static void setup(void)
{
    memset(ram,0,sizeof(ram));memset(&state,0,sizeof(state));
    next_guest=BASE+PAGE;next_shadow=SHADOW+0x1000;publications=0;missing=0;
    memory=(struct sptm_memory){.frame_low=BASE,.frame_high=SHADOW,
        .alloc_low=BASE+0x100000,.alloc_high=SHADOW,.map=map,.publish=publish};
    backend=(struct sptm_update_backend){.kernel_root=BASE,.shadow_root=SHADOW,.map_shadow=map_shadow};
    config=(struct sptm_slide_config){.table_low=BASE,.table_high=META,.map_pa=META,
        .begin=DEST,.end=DEST+0x4000000,.count=1,.regions={{VA,DATA,5}}};
    put(META,1);put(META+0x10,BASE);put(META+0x18,0xfffffe0100000000UL);
    put(META+0x20,(SHADOW-BASE)/PAGE);
    struct shadow s={.txsz=17,.root=SHADOW,.alloc=alloc,.read=read64,.write=write64};
    for(unsigned n=0;n<5;n++) {
        put(slot(VA+n*PAGE,14,3,1),(DATA+n*PAGE)|3|ATTR);
        CHECK(!shadow_map(&s,(VA+n*PAGE)&VMASK,DATA+n*PAGE,PAGE,ATTR,ATTR));
        memset(ram+(DATA-BASE+n*PAGE),0x31+n,PAGE);
    }
    for(uint64_t n=0;n<0x4000000;n+=0x2000000) (void)slot(DEST+n,14,3,1);
    CHECK(!shadow_reserve(&s,DEST&VMASK,0x4000000));
}
static enum sptm_result slide(uint64_t va,uint64_t count,int locked)
{ return sptm_mac_slide_region(&memory,&backend,&config,&state,va,count,locked); }
static void refused(uint64_t va,uint64_t count,int locked,enum sptm_result expected)
{
    memcpy(before,ram,SIZE);struct sptm_slide_state saved=state;unsigned pubs=publications;
    enum sptm_result got=slide(va,count,locked);
    if(got!=expected) fprintf(stderr,"refusal at %#llx to %#llx: got %u expected %u\n",
        (unsigned long long)va,(unsigned long long)config.begin,got,expected);
    CHECK(got==expected);
    CHECK(!memcmp(before,ram,SIZE));CHECK(!memcmp(&saved,&state,sizeof(state)));CHECK(pubs==publications);
}
static void verify_move(uint64_t old,uint64_t dest,uint64_t pa,unsigned count)
{
    for(unsigned n=0;n<count;n++) for(unsigned q=0;q<4;q++) {
        uint64_t off=n*PAGE+q*0x1000;
        CHECK(!walk(old+off,14).valid);CHECK(!walk(old+off,12).valid);
        struct mmu_leaf g=walk(dest+off,14),s=walk(dest+off,12);
        CHECK(g.valid && s.valid && g.pa==pa+off && s.pa==g.pa);
        CHECK((g.descriptor&(PT_AP|PT_PXN|PT_UXN))==(PT_PXN|PT_UXN));
        CHECK(physical_to_virtual(pa+off)==dest+off);
    }
    CHECK(!memcmp(before+(DATA-BASE),ram+(DATA-BASE),5*PAGE));
}
int main(void)
{
    setup();memcpy(before,ram,SIZE);
    CHECK(slide(VA,5,0)==SPTM_OK);verify_move(VA,DEST,DATA,5);
    CHECK(state.calls==1 && state.pages==5 && state.cursor==DEST+5*PAGE);
    CHECK(physical_to_virtual(DATA-1)==0xfffffe010007ffffUL);
    CHECK(physical_to_virtual(DATA+5*PAGE)==0xfffffe0100094000UL);
    refused(VA,5,0,SPTM_BAD_ADDRESS);
    memcpy(before,ram,SIZE);CHECK(slide(DEST,5,0)==SPTM_OK);
    verify_move(DEST,DEST+5*PAGE,DATA,5);
    CHECK(state.calls==2 && state.pages==10);
    setup();memcpy(before,ram,SIZE);CHECK(slide(VA+PAGE,3,0)==SPTM_OK);
    verify_move(VA+PAGE,DEST,DATA+PAGE,3);
    CHECK(walk(VA,14).valid && walk(VA+4*PAGE,14).valid && state.count==3);
    CHECK(slide(VA,1,0)==SPTM_OK);CHECK(slide(VA+4*PAGE,1,0)==SPTM_OK);
    CHECK(state.calls==3 && state.pages==5);
    setup();refused(VA,5,1,SPTM_FRAME_BUSY);
    refused(VA,0,0,SPTM_BAD_ADDRESS);refused(VA,0x40000,0,SPTM_BAD_ADDRESS);
    refused(VA+1,1,0,SPTM_BAD_ADDRESS);refused(UINT64_MAX-0x3fff,2,0,SPTM_BAD_ADDRESS);
    refused(VA-PAGE,1,0,SPTM_BAD_ADDRESS);refused(VA,6,0,SPTM_BAD_ADDRESS);
    setup();put(slot(VA+4*PAGE,14,3,0),0);refused(VA,5,0,SPTM_BAD_TABLE);
    setup();put(slot(VA+4*PAGE,12,3,0),0);refused(VA,5,0,SPTM_SHADOW_FAILED);
    setup();put(slot(DEST+4*PAGE,14,3,0),DATA|3);refused(VA,5,0,SPTM_BAD_TABLE);
    setup();put(slot(DEST+4*PAGE,12,3,0),DATA|3);refused(VA,5,0,SPTM_SHADOW_FAILED);
    setup();put(slot(VA,14,3,0),(DATA+PAGE)|3|ATTR);refused(VA,5,0,SPTM_BAD_TABLE);
    /* Last source guest table aliases an ancestor; all preceding pages must
     * remain intact. Shadow destination table aliases a different VA prefix. */
    setup();put(slot(VA+PAGE,14,2,0),BASE|3);refused(VA,5,0,SPTM_BAD_TABLE);
    setup();put(slot(DEST,12,2,0),get(slot(VA+PAGE,12,2,0)));
    refused(VA,5,0,SPTM_SHADOW_FAILED);
    setup();config.begin=DEST+0x1fc000;
    put(slot(DEST+0x200000,12,2,0),get(slot(DEST,12,2,0)));
    refused(VA,5,0,SPTM_BAD_TABLE);
    setup();config.begin=DEST+0x1ffc000;
    put(slot(DEST+0x2000000,14,2,0),get(slot(DEST,14,2,0)));
    refused(VA,5,0,SPTM_BAD_TABLE);
    setup();missing=META;refused(VA,5,0,SPTM_MEMORY_UNAVAILABLE);
    setup();missing=SHADOW;refused(VA,5,0,SPTM_SHADOW_FAILED);
    setup();put(META,51);refused(VA,5,0,SPTM_BAD_CONFIG);
    setup();put(META,50);
    for(unsigned i=0;i<50;i++) {
        uint64_t offset=i ? (37+i)*PAGE : 0;
        put(META+0x10+24*i,BASE+offset);
        put(META+0x18+24*i,0xfffffe0100000000UL+offset);
        put(META+0x20+24*i,i ? 1 : 38);
    }
    refused(VA,5,0,SPTM_MEMORY_UNAVAILABLE);
    setup();put(META+0x20,1);refused(VA,5,0,SPTM_BAD_CONFIG);
    setup();put(META,2);put(META+0x28,BASE);put(META+0x30,DEST);put(META+0x38,1);
    refused(VA,5,0,SPTM_BAD_CONFIG);
    setup();config.end=DEST+PAGE;refused(VA,5,0,SPTM_BAD_CONFIG);
    setup();config.regions[0].pa=memory.alloc_low;refused(VA,5,0,SPTM_BAD_CONFIG);
    setup();config.regions[0].pa=BASE;refused(VA,5,0,SPTM_BAD_CONFIG);
    setup();config.count=2;config.regions[1]=config.regions[0];refused(VA,5,0,SPTM_BAD_CONFIG);
    setup();state.cursor=DEST;refused(VA,5,0,SPTM_BAD_CONFIG);
    printf("PASS: %u SLIDE_REGION checks (native, sanitizers on)\n",checks);return 0;
}

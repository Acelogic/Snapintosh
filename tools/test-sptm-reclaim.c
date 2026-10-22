/* SPDX-License-Identifier: MIT */
/* Disposable image data participates in the same CPU/DMA lifecycle as RAM. */
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "sptm-dart.h"
#include "sptm-refs.h"
#include "txm.h"
#define BASE 0x90000000UL
#define PAGE 0x4000UL
#define SIZE (32*PAGE)
#define FM (BASE+PAGE)
#define DATA (BASE+4*PAGE)
#define ROOT (BASE+12*PAGE)
#define MID (ROOT+PAGE)
#define LEAF (MID+PAGE)
#define LIST (LEAF+PAGE)
#define BOOTVA 0xfffffe0008000000UL
#define SLIDVA 0xfffffe030c000000UL
#define VA 0xfffffe2000000000UL
#define RW 0x0060000000000703UL
/* The TXM arena follows the managed range, outside frame_high. */
static uint8_t ram[SIZE+TXM_ASPACE_SIZE],saved[SIZE];
static unsigned checks,pubs;
#define CHECK(x) do {checks++;assert(x);} while(0)
static volatile uint8_t *map(void *ctx,uint64_t pa,uint64_t n)
{ (void)ctx;return pa>=BASE && pa<BASE+sizeof(ram) && n<=BASE+sizeof(ram)-pa ? ram+(pa-BASE) : 0; }
static void publish(void *ctx,uint64_t pa,uint64_t n)
{ (void)ctx;CHECK(map(0,pa,n)!=0);pubs++; }
static uint8_t *meta(uint64_t pa) {return ram+(FM-BASE)+((pa-BASE)>>14)*16;}
static uint32_t refs(uint64_t pa,unsigned off) {uint32_t v;memcpy(&v,meta(pa)+off,4);return v;}
static void put(uint64_t pa,uint64_t value) {memcpy(ram+(pa-BASE),&value,8);}
static void cpu(struct sptm_memory *m,uint64_t va,uint64_t old,uint64_t next)
{
    sptm_refs_begin(m->refs);
    CHECK(sptm_refs_leaf(m,BASE,va,old,next)==SPTM_OK);
    CHECK(sptm_refs_validate(m)==SPTM_OK);sptm_refs_commit(m);
}
static int admit(void *ctx,unsigned kind,unsigned id,unsigned sid,unsigned level)
{ (void)ctx;return kind==5 && id==21 && sid==1 && level<3; }
int main(void)
{
    for(unsigned n=0;n<SIZE/PAGE;n++)meta(BASE+n*PAGE)[2]=11;
    struct sptm_ref_batch batch={0};
    struct sptm_slide_region boot={BOOTVA,DATA,3},alias=boot;
    struct sptm_memory m={.frame_map_pa=FM,.frame_low=BASE,.frame_high=BASE+SIZE,
        .alloc_low=ROOT,.alloc_high=BASE+SIZE,.map=map,.publish=publish,.refs=&batch,
        .boot_ranges=&boot,.boot_count=1,.boot_aliases=&alias,.boot_alias_count=1,
        .admit_iommu=admit};
    CHECK(sptm_boot_memory_valid(&m));
    uint64_t next=sptm_next_frame(&m,0);unsigned frames=0;
    for(;next<m.alloc_high;next=sptm_next_frame(&m,next+PAGE)) {
        CHECK(sptm_managed_frame(&m,next));frames++;
    }
    CHECK(frames==23);
    /* Initial and relocated bootstrap aliases are exempt only for exact PA. */
    cpu(&m,BOOTVA,0,DATA|RW);CHECK(!refs(DATA,12));
    alias.va=SLIDVA;cpu(&m,SLIDVA,0,DATA|RW);CHECK(!refs(DATA,12));
    cpu(&m,SLIDVA,0,(DATA+PAGE)|RW);CHECK(refs(DATA+PAGE,12)==1);
    cpu(&m,SLIDVA,(DATA+PAGE)|RW,0);CHECK(!refs(DATA+PAGE,12));
    memset(ram+(DATA-BASE),0xa6,PAGE);
    CHECK(sptm_mac_retype(&m,DATA,11,35,0)==SPTM_OK);
    for(unsigned i=0;i<PAGE;i++)CHECK(ram[DATA-BASE+i]==0xa6);
    cpu(&m,VA,0,DATA|RW);CHECK(refs(DATA,12)==1);
    memcpy(saved,ram,SIZE);pubs=0;
    CHECK(sptm_mac_retype(&m,DATA,35,11,0)==SPTM_FRAME_BUSY);
    CHECK(!pubs && !memcmp(saved,ram,SIZE));
    cpu(&m,VA,DATA|RW,0);CHECK(!refs(DATA,12));
    CHECK(sptm_mac_retype(&m,DATA,35,11,0)==SPTM_OK);
    /* Reclaimed table frame and data/list pages in the same DART graph. */
    memset(ram+(DATA+PAGE-BASE),0,PAGE);
    uint64_t pages[3]={DATA+PAGE,MID,LEAF};
    struct dart_state dart={.initialized_ids=1U<<21,.powered_ids=1U<<21};
    dart.tcr[1]=9;
    for(unsigned i=0;i<3;i++) {
        CHECK(sptm_mac_retype(&m,pages[i],11,24,5UL|(21UL<<32)|(1UL<<40)|((uint64_t)i<<48))==SPTM_OK);
        CHECK(sptm_dart_map_table(&m,&dart,21,1,1UL<<40,i,pages[i])==SPTM_OK);
    }
    put(DATA+2*PAGE,DATA);
    cpu(&m,VA,0,DATA|RW);
    CHECK(sptm_dart_map(&m,&dart,21,1,1UL<<40,DATA+2*PAGE,PAGE,0)==SPTM_OK);
    CHECK(refs(DATA,12)==2);
    CHECK(sptm_dart_enable(&m,&dart,21,1)==SPTM_OK && dart.enabled[0]==2);
    cpu(&m,VA,DATA|RW,0);CHECK(refs(DATA,12)==1);
    CHECK(sptm_mac_retype(&m,DATA,11,35,0)==SPTM_FRAME_BUSY);
    memcpy(saved,ram,SIZE);pubs=0;
    for(uint64_t pa=BASE;pa<ROOT;pa+=PAGE)if(pa<DATA || pa>=DATA+3*PAGE)
        CHECK(sptm_mac_retype(&m,pa,11,35,0)==SPTM_BAD_ADDRESS);
    CHECK(!pubs && !memcmp(saved,ram,SIZE));
    for(unsigned mode=0;mode<9;mode++) {
        struct sptm_memory bad=m;struct sptm_slide_region br=boot,ar=alias;
        bad.boot_ranges=&br;bad.boot_aliases=&ar;
        switch(mode) {
        case 0:bad.boot_count=9;break;
        case 1:bad.boot_ranges=0;break;
        case 2:br.pa=FM;ar.pa=FM;break;
        case 3:br.pa++;break;
        case 4:br.pages=0;break;
        case 5:br.pages=4097;break;
        case 6:ar.pages--;break;
        case 7:ar.pa+=PAGE;break;
        case 8:bad.boot_alias_count=51;break;
        }
        CHECK(sptm_mac_retype(&bad,DATA+2*PAGE,11,35,0)==SPTM_BAD_CONFIG);
        CHECK(!pubs && !memcmp(saved,ram,SIZE));
    }
    /* TXM searches disjoint owned storage for a root before the main arena. */
    memset(ram,0,SIZE);meta(DATA)[2]=18;meta(DATA)[4]=7;meta(DATA)[8]=0xff;meta(DATA)[10]=2;
    struct txm_service service={.stacks_pa=BASE+8*PAGE,.stack_count=1};
    struct txm_arena arena={BASE+SIZE,0xfffffe0100090000UL};
    struct txm_registry registry={0};uint64_t args[8]={service.stacks_pa,7};
    CHECK(txm_aspace(&m,&service,&arena,&registry,35,args)==SPTM_OK);
    CHECK(registry.root[0]==DATA);
    args[1]=arena.va;CHECK(txm_aspace(&m,&service,&arena,&registry,36,args)==SPTM_OK);
    printf("PASS: %u reclaim lifecycle checks (CPU/DMA counts, reserved frames, TXM roots)\n",checks);
    return 0;
}

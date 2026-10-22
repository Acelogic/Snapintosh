/* SPDX-License-Identifier: MIT */
/* SNAP_REUSE_MATCH_MAPPED (shadow/sprr-reuse.h): host differential of
 * sprr_reuse_match_mapped against sprr_reuse_match. Built and mutated by
 * tools/test-reuse-match-mapped.py:
 *   cc -std=gnu11 -Wall -Wextra -Werror -O1 -g -fsanitize=address,undefined \
 *      -DSNAP_REUSE_MATCH_MAPPED=1 -Icompat -Ishadow tools/test-reuse-match-mapped.c \
 *      shadow/sprr-view.c shadow/shadow.c shadow/mmu.c -o test-reuse-match-mapped
 *
 * Failure inventory (the header's modes 1-2), each held to a check here:
 *  - Random kernel-shaped canonical trees (levels 0-3, blocks, shared
 *    branches, selector-2 leaves), copied paths, six synced CPUs, a saved
 *    snapshot. Then one perturbation per trial: none; a canonical source word
 *    or a snapshot word flipped; a PPERM changed (configured and not); the
 *    snapshot invalidated; a copy identity, level or count changed; the
 *    reader's bound moved below a copied table (page aligned: refused), or
 *    into the middle of one (straddling: the mapped reader refuses, the word
 *    reader accepts a prefix); an unaligned source in both records; a null
 *    page reader. Both forms run on identical copies of the reuse state:
 *    verdict and the whole state (counters, validity, snapshot) must be equal.
 *  - Every outcome (1, 0, -1) and both inner paths (mapped page, per-word
 *    fallback) must occur, or the run fails as unexercised.
 * The readers model the monitor's: kernel_table_read (8-byte reads inside
 * [base, limit)) and class_table_read (a page-aligned page wholly inside it);
 * tools/test-reuse-match-mapped.py checks the monitor's text for both bounds. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "sprr-view.h"
#include "sprr-reuse.h"
#if !SNAP_REUSE_MATCH_MAPPED
#error "build with -DSNAP_REUSE_MATCH_MAPPED=1"
#endif

static unsigned long checks,failed;
#define CHECK(x) do{checks++;if(!(x)){failed++;if(failed<20)fprintf(stderr,"FAIL %d: %s\n",__LINE__,#x);}}while(0)
static uint64_t rng=0x243f6a8885a308d3UL;
static unsigned rnd(unsigned n){rng^=rng<<13;rng^=rng>>7;rng^=rng<<17;return (unsigned)(rng%n);}

#define HB 0x40000000UL
#define HPAGES 4096u
static uint8_t *hmem;static uint64_t hnext,hlimit;      /* hlimit: the readers' bound (bytes) */
static unsigned long word_reads,page_maps,page_refusals;
static int hread(void *c,uint64_t pa,uint64_t *v)
{
    (void)c;word_reads++;
    if((pa&7) || pa<HB || pa>=hlimit || hlimit-pa<8)return -1;
    *v=*(volatile uint64_t *)(hmem+(pa-HB));return 0;
}
static int hwrite(void *c,uint64_t pa,uint64_t v)
{(void)c;if(pa<HB || pa>=HB+HPAGES*4096UL || (pa&7))return -1;memcpy(hmem+(pa-HB),&v,8);return 0;}
static uint64_t halloc(void *c)
{(void)c;if(hnext>=HPAGES)return 0;uint64_t pa=HB+hnext*4096UL;hnext++;memset(hmem+(pa-HB),0,4096);return pa;}
static const volatile uint64_t *hmap(void *c,uint64_t pa)
{
    (void)c;page_maps++;
    if((pa&4095) || pa<HB || pa>=hlimit || hlimit-pa<4096) {page_refusals++;return 0;}
    return (const volatile uint64_t *)(hmem+(pa-HB));
}
static uint64_t kleaf(unsigned cls)
{return (((uint64_t)(cls>>2)&3)<<6)|((uint64_t)(cls&3)<<53)|0x703UL;}
static void flip(uint64_t pa,unsigned bit){uint64_t v;memcpy(&v,hmem+(pa-HB),8);v^=UINT64_C(1)<<bit;memcpy(hmem+(pa-HB),&v,8);}

static struct sprr_views views;
static struct sprr_reuse_state saved,ra,rb;
static unsigned long outcome[3],kinds[14];

static int build(struct shadow *s,uint64_t pp[SPRR_VIEW_CPUS])
{
    static const unsigned classes[]={0,3,2,4,1,8,12,15};
    hnext=1;hlimit=HB+HPAGES*4096UL;
    *s=(struct shadow){.txsz=17,.root=halloc(0),.alloc=halloc,.read=hread,.write=hwrite};
    uint64_t base=UINT64_C(0x7e0000000000),first[8]={0};
    unsigned regions=2+rnd(6),pages=0;
    for(unsigned g=0;g<regions;g++)for(unsigned r=0;r<1+rnd(4);r++)
        for(unsigned i=0;i<8+rnd(60);i++) {
            uint64_t va=base+((uint64_t)g<<30)+((uint64_t)r<<21)+(uint64_t)rnd(512)*4096;
            if(!first[g])first[g]=va;
            uint64_t leaf=kleaf(classes[rnd(8)]);
            pages+=!shadow_map(s,va,0x900000000UL+(uint64_t)rnd(1u<<16)*4096,4096,leaf&0xfff,leaf&(PT_PXN|PT_UXN));
        }
    if(!pages)return 0;
    if(rnd(2) && shadow_map(s,base+((uint64_t)7<<30)+((uint64_t)300<<21),0xa00000000UL,1UL<<21,
                             kleaf(3)&0xfff,PT_PXN|PT_UXN))return 0;
    memset(&views,0,sizeof views);
    if(!sprr_views_init(&views,s))return 0;
    for(unsigned g=0;g<regions;g++)if(rnd(4) && !sprr_views_prepare(&views,s,first[g]))return 0;
    for(unsigned cpu=0;cpu<SPRR_VIEW_CPUS;cpu++) {
        pp[cpu]=SPRR_PPERM_INITIAL|(rnd(2) ? UINT64_C(0x100):0)|(rnd(2) ? UINT64_C(1)<<36:0);
        if(!sprr_views_sync_cpu(&views,s,cpu,pp[cpu]))return 0;
    }
    memset(&saved,0,sizeof saved);
    return sprr_reuse_save(&saved,&views,s,pp);
}

static void trial(void)
{
    struct shadow s;uint64_t pp[SPRR_VIEW_CPUS];
    if(!build(&s,pp)) {CHECK(0);return;}
    CHECK(views.count>=1);
    sprr_table_reader map=hmap;
    unsigned n=rnd((unsigned)views.count),i=rnd(512),cpu=rnd(SPRR_VIEW_CPUS);
    unsigned kind=rnd(14);kinds[kind]++;
    struct sprr_reuse_state *r=&saved;
    switch(kind) {
    case 0: break;
    case 1: flip(views.tables[n].source+8UL*i,rnd(64));break;            /* canonical word */
    case 2: r->words[n][i]^=UINT64_C(1)<<rnd(64);break;                  /* snapshot word */
    case 3: pp[cpu]^=UINT64_C(0x100);break;                              /* configured PPERM */
    case 4: pp[cpu]^=UINT64_C(1)<<rnd(36);break;                         /* unconfigured PPERM */
    case 5: r->valid=0;break;
    case 6: views.tables[n].copy[cpu]^=4096;break;
    case 7: views.tables[n].level^=1;break;
    case 8: if(views.count>1)views.count--;break;
    case 9:  /* refused page: the bound below a copied table, page aligned */
        hlimit=views.tables[n].source;break;
    case 10: /* straddling bound inside a copied table, maybe a mismatch before it */
        hlimit=views.tables[n].source+8UL*(1+rnd(511));
        if(rnd(2))flip(views.tables[n].source+8UL*rnd((unsigned)((hlimit-views.tables[n].source)/8)),rnd(64));
        break;
    case 11: { /* unaligned source in both records, words equal or not */
        uint64_t d=8UL*(1+rnd(511));
        r->tables[n].source+=d;views.tables[n].source+=d;
        if(rnd(2))for(unsigned k=0;k<512;k++) {
            uint64_t w;if(!hread(0,views.tables[n].source+8UL*k,&w))r->words[n][k]=w;
        }
        break;
    }
    case 12: map=0;if(rnd(2))flip(views.tables[n].source+8UL*i,rnd(64));break;
    case 13: /* several tables: a later one refused after equal earlier ones */
        hlimit=views.tables[views.count-1].source;break;
    }
    ra=*r;rb=*r;
    unsigned long refusals=page_refusals,maps=page_maps;
    int a=sprr_reuse_match(&ra,&views,&s,pp);
    int b=sprr_reuse_match_mapped(&rb,&views,&s,pp,map,0);
    CHECK(a==b);
    CHECK(!memcmp(&ra,&rb,sizeof ra));
    if(a>=-1 && a<=1)outcome[a+1]++;
    (void)refusals;(void)maps;
}

int main(void)
{
    hmem=calloc(HPAGES,4096);
    for(unsigned t=0;t<6000;t++)trial();
    printf("trials 6000: outcomes -1:%lu 0:%lu 1:%lu; page maps %lu (refused %lu), word reads %lu\n",
           outcome[0],outcome[1],outcome[2],page_maps,page_refusals,word_reads);
    for(unsigned k=0;k<14;k++)CHECK(kinds[k]>0);
    CHECK(outcome[0]>0 && outcome[1]>0 && outcome[2]>0);
    CHECK(page_maps>page_refusals && page_refusals>0);
    if(failed) {printf("FAILED %lu of %lu checks\n",failed,checks);return 1;}
    printf("PASS: %lu checks\n",checks);return 0;
}

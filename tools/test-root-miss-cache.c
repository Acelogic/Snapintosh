/* SPDX-License-Identifier: MIT */
/* SNAP_ROOT_MISS_FAST, part 1 (compat/root-miss.h E1-E6): which slot a full
 * 64-slot user-root cache gives up, through the real SWITCH_ROOT.
 * Built and mutated by tools/test-root-miss.py; also built without the
 * define, where only the round-robin model runs.
 *  1. root_miss_victim against an independent oracle on random cache states
 *     (named/invalid/valid/empty slots, up to six active roots, random
 *     stamps): never an active, empty or incoming root; an invalid slot
 *     before a valid one; else the least recently installed (E1-E4).
 *  2. Churn: 160 real roots, each mapping its own frame, six CPUs, a skewed
 *     switch trace with kernel switches, invalidations and retirements. After
 *     every operation the real cache (slot names, validity), the builds,
 *     invalidations and evictions counters (E5) and every CPU's installed
 *     translation must equal an independent model: round robin without stamps
 *     (the code as it was, E6) and least recently installed with them. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "sptm-root.h"
#include "sptm-user.h"
#include "sptm-refs.h"
#include "mmu.h"
#if SNAP_ROOT_MISS_FAST
#include "root-miss.h"
#endif
#define PAGE 0x4000UL
#ifndef ROOTS                  /* tools/test-root-wide.py builds 480 */
#define ROOTS 160u
#endif
#ifndef HOT                    /* roots taking 85% of user switches */
#define HOT 24u
#endif
#define BASE 0x80000000UL
#define MAPF 8u                 /* frame-map frames: 8192 records */
#define FRAMES (MAPF+4*ROOTS)
#define SIZE (FRAMES*PAGE)
#define FM BASE
#define VA 0x8000000UL
#define LEAF 0x0060000000000fc3UL
#define CPUS 6u
static unsigned checks;
#define CHECK(x) do { checks++;if(!(x)){fprintf(stderr,"FAIL %d: %s\n",__LINE__,#x);exit(1);} } while(0)
static uint8_t ram[SIZE];
static struct sptm_ref_batch refs;
static volatile uint8_t *map(void *ctx,uint64_t pa,uint64_t n)
{(void)ctx;return pa<BASE || pa>=BASE+SIZE || n>BASE+SIZE-pa ? NULL : ram+(pa-BASE);}
static void publish(void *ctx,uint64_t pa,uint64_t n) {(void)ctx;(void)pa;(void)n;}
static uint64_t root_pa(unsigned i) {return BASE+(MAPF+4*i)*PAGE;}
static uint64_t data_pa(unsigned i) {return root_pa(i)+3*PAGE;}
/* Host shadow arena: 4K pages at a fake PA range. */
#define HOST 0x10000000UL
#define HOST_PAGES (4u*SPTM_ROOT_CACHE+768u)
static uint8_t host[HOST_PAGES*4096];
static uint64_t host_next;
static int host_read(void *ctx,uint64_t pa,uint64_t *v)
{(void)ctx;if(pa<HOST || pa>HOST+sizeof(host)-8 || (pa&7))return -1;memcpy(v,host+(pa-HOST),8);return 0;}
static int host_write(void *ctx,uint64_t pa,uint64_t v)
{(void)ctx;if(pa<HOST || pa>HOST+sizeof(host)-8 || (pa&7))return -1;memcpy(host+(pa-HOST),&v,8);return 0;}
static uint64_t host_alloc(void *ctx)
{(void)ctx;CHECK(host_next<sizeof(host));uint64_t pa=HOST+host_next;host_next+=4096;memset(host+(pa-HOST),0,4096);return pa;}
static struct sptm_memory m;
static struct sptm_root_state s;
static uint64_t stamp[SPTM_ROOT_CACHE],clock_now,evictions,installed[CPUS][2];
static unsigned current_cpu;
static int build(void *ctx,const struct sptm_memory *mm,uint64_t root,unsigned fmt,unsigned flags,
                 uint64_t previous,uint64_t *out,uint64_t *leaves)
{
    (void)ctx;
    struct shadow t={.txsz=17,.root=previous ? previous : host_alloc(0),.alloc=host_alloc,
                     .read=host_read,.write=host_write};
    if(!sptm_root_build_shadow(mm,&t,root,fmt,flags,leaves))return 0;
    *out=t.root;return 1;
}
/* probes/xnuboot.c user_root_install: the installed root's slot is stamped. */
static void install(void *ctx,uint64_t shadow,uint64_t root,uint64_t asid,unsigned fmt)
{
    (void)ctx;(void)fmt;
    installed[current_cpu][0]=shadow;installed[current_cpu][1]=root;
    if(!asid)return;
    unsigned found=0;
    for(unsigned i=0;i<SPTM_ROOT_CACHE;i++)if(s.cache[i].root==root && s.cache[i].valid) {
        stamp[i]=++clock_now;found++;
    }
    CHECK(found==1);
}
static struct sptm_root_backend b={.kernel_root=FM,.kernel_shadow=HOST,.build=build,.install=install,
    .evictions=&evictions};
static void setup(void)
{
    memset(ram,0,sizeof ram);memset(&s,0,sizeof s);memset(stamp,0,sizeof stamp);
    memset(installed,0,sizeof installed);host_next=4096;clock_now=evictions=0;
    for(unsigned f=MAPF;f<FRAMES;f++)ram[(f*16)+2]=SPTM_MAC_DEFAULT;
    m=(struct sptm_memory){.frame_map_pa=FM,.frame_low=BASE,.frame_high=BASE+SIZE,
        .alloc_low=BASE+MAPF*PAGE,.alloc_high=BASE+SIZE,.map=map,.publish=publish,.refs=&refs};
    struct sptm_user_backend ub={.aperture={BASE,0xfffffe0100000000UL,SIZE}};
    for(unsigned i=0;i<ROOTS;i++) {
        uint64_t r=root_pa(i),l2=r+PAGE,l3=r+2*PAGE,result=1;
        CHECK(sptm_mac_retype(&m,r,11,18,((uint64_t)(i+2)<<32)|(2UL<<16))==SPTM_OK);
        CHECK(sptm_mac_retype(&m,l2,11,20,2)==SPTM_OK && sptm_mac_retype(&m,l3,11,20,3)==SPTM_OK);
        CHECK(sptm_mac_map_user_table(&m,r,VA,1,l2|3)==SPTM_OK);
        CHECK(sptm_mac_map_user_table(&m,r,VA,2,l3|3)==SPTM_OK);
        CHECK(sptm_mac_map_user_page(&m,&ub,r,VA,data_pa(i)|LEAF,1,0,&result)==SPTM_OK && !result);
    }
}
/* The model: names and validity per slot, counters, stamps, active roots. */
struct model { uint64_t root[SPTM_ROOT_CACHE];int valid[SPTM_ROOT_CACHE];
               uint64_t stamp[SPTM_ROOT_CACHE],builds,invalidations,evictions,active[CPUS],clock; };
static int model_active(const struct model *x,uint64_t root)
{for(unsigned c=0;c<CPUS;c++)if(x->active[c]==root)return 1;return 0;}
/* Victim of a full cache: -1 none. lru 0 is the original two-pass rotation. */
static int model_victim(const struct model *x,int lru)
{
    for(int pass=0;pass<2;pass++) {
        int best=-1;
        for(unsigned n=0;n<SPTM_ROOT_CACHE;n++) {
            unsigned i=(unsigned)((x->builds+n)%SPTM_ROOT_CACHE);
            if(!x->root[i] || x->valid[i]!=pass || model_active(x,x->root[i]))continue;
            if(!lru || !pass) return (int)i;
            if(best<0 || x->stamp[i]<x->stamp[best])best=(int)i;
        }
        if(best>=0)return best;
    }
    return -1;
}
static void model_switch(struct model *x,unsigned cpu,uint64_t root,int lru,int *hit)
{
    if(root==FM) {x->active[cpu]=0;*hit=-1;return;}
    int entry=-1,empty=-1;
    for(unsigned i=0;i<SPTM_ROOT_CACHE;i++) {
        if(x->root[i]==root)entry=(int)i;
        if(!x->root[i] && empty<0)empty=(int)i;
    }
    *hit=entry>=0 && x->valid[entry];
    if(!*hit) {
        if(entry<0)entry=empty;
        if(entry<0) {
            entry=model_victim(x,lru);CHECK(entry>=0);
            x->root[entry]=0;x->valid[entry]=0;x->invalidations++;x->evictions++;
        }
        x->root[entry]=root;x->valid[entry]=1;x->builds++;
    }
    x->stamp[entry]=++x->clock;x->active[cpu]=root;
}
static int model_invalidate(struct model *x,uint64_t root,int retire)
{
    if(model_active(x,root))return 0;
    for(unsigned i=0;i<SPTM_ROOT_CACHE;i++)if(x->root[i]==root) {
        x->valid[i]=0;if(retire)x->root[i]=0;x->invalidations++;
    }
    return 1;
}
static void compare(const struct model *x)
{
    for(unsigned i=0;i<SPTM_ROOT_CACHE;i++)
        CHECK(s.cache[i].root==x->root[i] && (int)s.cache[i].valid==x->valid[i]);
    CHECK(s.builds==x->builds && s.invalidations==x->invalidations && evictions==x->evictions);
    for(unsigned c=0;c<CPUS;c++) {
        CHECK(s.active[c]==x->active[c]);
        if(!s.active[c])continue;
        /* E1: what this CPU walks still translates its own root's frame. */
        struct mmu_config cfg={12,17,installed[c][0]};struct mmu_leaf leaf;
        unsigned i=(unsigned)((s.active[c]-root_pa(0))/(4*PAGE));
        CHECK(installed[c][1]==s.active[c] && !mmu_walk(&cfg,VA+123,host_read,0,&leaf) &&
              leaf.valid && leaf.pa==data_pa(i)+123);
    }
}
static uint64_t rng;
static unsigned rnd(unsigned n) {rng^=rng<<13;rng^=rng>>7;rng^=rng<<17;return (unsigned)(rng%n);}
/* A skewed trace: a hot set of HOT roots takes 85% of user switches. */
static unsigned pick_root(void) {return rnd(100)<85 ? rnd(HOT) : HOT+rnd(ROOTS-HOT);}
static void churn(int lru,unsigned steps,uint64_t seed,uint64_t *hits,uint64_t *misses)
{
    setup();rng=seed;
    struct model x;memset(&x,0,sizeof x);
#if SNAP_ROOT_MISS_FAST
    b.stamp=lru ? stamp : 0;b.linked_builds=0;
#else
    CHECK(!lru);
#endif
    *hits=*misses=0;
    for(unsigned step=0;step<steps;step++) {
        unsigned cpu=rnd(CPUS),op=rnd(1000);
        if(op<100) {
            current_cpu=cpu;int hit;
            CHECK(sptm_mac_switch_root(&m,&s,&b,cpu,FM,0,0)==SPTM_OK);
            model_switch(&x,cpu,FM,lru,&hit);
        } else if(op<115) {
            uint64_t root=root_pa(pick_root());int retire=op<105;
            int want=model_invalidate(&x,root,retire);
            CHECK(sptm_root_invalidate(&s,root,retire)==want);
        } else {
            uint64_t root=root_pa(pick_root());current_cpu=cpu;int hit;
            CHECK(sptm_mac_switch_root(&m,&s,&b,cpu,root,0,0)==SPTM_OK);
            model_switch(&x,cpu,root,lru,&hit);
            if(hit)(*hits)++;else (*misses)++;
        }
        compare(&x);
    }
}
#if SNAP_ROOT_MISS_FAST
static void victim_oracle(void)
{
    rng=0x9e3779b97f4a7c15UL;
    unsigned picked=0,none=0;
    for(unsigned trial=0;trial<20000;trial++) {
        struct sptm_root_state st;memset(&st,0,sizeof st);
        uint64_t stp[SPTM_ROOT_CACHE];
        for(unsigned i=0;i<SPTM_ROOT_CACHE;i++) {
            /* trial%3: 0 named slots only; 1 also never-used slots; 2 also,
             * rarely, a retired one (shadow, no root). */
            unsigned kind=trial%3==0 ? 2 : rnd(trial%3==2 ? 64 : 6);
            stp[i]=1000+rnd(1u<<20)*64+i;           /* unique */
            if(kind==0)continue;                     /* never used */
            st.cache[i].shadow=0x2000000UL+i*0x1000;
            if(kind==1 && trial%3==2)continue;       /* retired */
            st.cache[i].root=0x1000000UL+i*0x4000;st.cache[i].asid=100+i;
            st.cache[i].valid=rnd(4)!=0;
        }
        st.builds=rnd(1000);
        for(unsigned c=0;c<CPUS;c++)if(rnd(2)) {
            unsigned i=rnd(SPTM_ROOT_CACHE);if(st.cache[i].root)st.active[c]=st.cache[i].root;
        }
        uint64_t incoming=0x1000000UL+(SPTM_ROOT_CACHE+1)*0x4000;
        /* Oracle: inactive named slots; an invalid one first in rotation
         * order, else the smallest stamp. */
        int want=-1;
        for(unsigned n=0;n<SPTM_ROOT_CACHE && want<0;n++) {
            unsigned i=(unsigned)((st.builds+n)%SPTM_ROOT_CACHE);
            const struct sptm_root_cached *e=&st.cache[i];int active=0;
            for(unsigned c=0;c<CPUS;c++)active|=e->root && st.active[c]==e->root;
            if(e->root && !e->valid && !active)want=(int)i;
        }
        if(want<0 && !(trial%3))for(unsigned i=0;i<SPTM_ROOT_CACHE;i++) {
            const struct sptm_root_cached *e=&st.cache[i];int active=0;
            for(unsigned c=0;c<CPUS;c++)active|=st.active[c]==e->root;
            if(e->root && e->valid && !active && (want<0 || stp[i]<stp[want]))want=(int)i;
        }
        struct sptm_root_cached *got=root_miss_victim(&st,stp,incoming);
        if(trial%3) {
            /* Mixed states may hold a retired slot (no root): reclaim_pick
             * prefers it and the caller never evicts then (it is "empty"). */
            int retired=0;
            for(unsigned i=0;i<SPTM_ROOT_CACHE;i++)retired|=!st.cache[i].root && st.cache[i].shadow;
            if(retired) {CHECK(!got);none++;continue;}
            if(want<0)for(unsigned i=0;i<SPTM_ROOT_CACHE;i++) {
                const struct sptm_root_cached *e=&st.cache[i];int active=0;
                for(unsigned c=0;c<CPUS;c++)active|=st.active[c]==e->root;
                if(e->root && e->valid && !active && (want<0 || stp[i]<stp[want]))want=(int)i;
            }
        }
        if(want<0) {CHECK(!got);none++;continue;}
        CHECK(got==&st.cache[want]);
        for(unsigned c=0;c<CPUS;c++)CHECK(st.active[c]!=got->root);
        CHECK(got->root && got->root!=incoming);
        picked++;
    }
    CHECK(picked>10000 && none>100);
    printf("victim: %u random states agree with the oracle (%u without a victim)\n",picked+none,none);
}
#endif
int main(void)
{
    uint64_t hits,misses,lru_hits,lru_misses;
    churn(0,60000,0x1234567887654321UL,&hits,&misses);
    printf("round robin: %llu hits %llu misses, %llu evictions (model agrees after every step)\n",
           (unsigned long long)hits,(unsigned long long)misses,(unsigned long long)evictions);
#if SNAP_ROOT_MISS_FAST
    victim_oracle();
    churn(1,60000,0x1234567887654321UL,&lru_hits,&lru_misses);
    printf("least recently installed: %llu hits %llu misses, %llu evictions (model agrees after every step)\n",
           (unsigned long long)lru_hits,(unsigned long long)lru_misses,(unsigned long long)evictions);
    CHECK(lru_hits+lru_misses==hits+misses);
    printf("synthetic trace: misses %.4f -> %.4f of user switches\n",
           (double)misses/(double)(hits+misses),(double)lru_misses/(double)(lru_hits+lru_misses));
#else
    (void)lru_hits;(void)lru_misses;
#endif
    printf("PASS: %u root-cache victim checks\n",checks);
    return 0;
}

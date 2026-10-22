/* SPDX-License-Identifier: MIT */
/* SNAP_ROOT_CACHE_WIDE (compat/root-wide.h W1, W9): the 192-slot masks, the
 * reclaim exclusion above slot 63 and the native-shared link bits of high
 * slots, against plain reference models. The 192-slot SWITCH_ROOT churn is
 * tools/test-root-miss-cache.c, built wide by tools/test-root-wide.py.
 *  1. sptm_root_mask_t (set, test, one, none, any, ne, low word) equals a
 *     192-entry boolean array under random operations.
 *  2. sptm_root_reclaim_pick with random exclusion sets reaching every word
 *     returns exactly the oldest non-excluded inactive root.
 *  3. Native-shared groups linked by slots spread over 0..191: each slot's
 *     bit alone answers native_shared_slot_links; growth writes the new page
 *     into every linking slot's tree and no other; unlink and forget clear
 *     exactly one slot; a group with any linking slot, low or high, is not
 *     freed. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "sptm-root.h"
#include "native-shared.h"
#include "mmu.h"
#if !SNAP_ROOT_CACHE_WIDE
#error "build with -DSNAP_ROOT_CACHE_WIDE=1"
#endif
static unsigned checks;
#define CHECK(x) do { checks++;if(!(x)){fprintf(stderr,"FAIL %d: %s\n",__LINE__,#x);exit(1);} } while(0)
static uint64_t rng=0x9e3779b97f4a7c15UL;
static unsigned rnd(unsigned n) {rng^=rng<<13;rng^=rng>>7;rng^=rng<<17;return (unsigned)(rng%n);}

static void masks(void)
{
    for(unsigned trial=0;trial<3000;trial++) {
        sptm_root_mask_t a=SPTM_ROOT_MASK_NONE,b=SPTM_ROOT_MASK_NONE;
        unsigned char ra[SPTM_ROOT_CACHE]={0},rb[SPTM_ROOT_CACHE]={0};
        CHECK(!SPTM_ROOT_MASK_ANY(a) && !SPTM_ROOT_MASK_NE(a,b));
        for(unsigned op=0;op<1+rnd(12);op++) {
            unsigned i=rnd(SPTM_ROOT_CACHE);
            if(rnd(2)) {SPTM_ROOT_MASK_SET(a,i);ra[i]=1;} else {SPTM_ROOT_MASK_SET(b,i);rb[i]=1;}
        }
        int any=0,ne=0;uint64_t low=0;
        for(unsigned i=0;i<SPTM_ROOT_CACHE;i++) {
            CHECK(!!SPTM_ROOT_MASK_HAS(a,i)==ra[i] && !!SPTM_ROOT_MASK_HAS(b,i)==rb[i]);
            any|=ra[i];ne|=ra[i]!=rb[i];if(i<64 && ra[i])low|=UINT64_C(1)<<i;
        }
        CHECK(!!SPTM_ROOT_MASK_ANY(a)==any && !!SPTM_ROOT_MASK_NE(a,b)==ne && SPTM_ROOT_MASK_LOW(a)==low);
        unsigned k=rnd(SPTM_ROOT_CACHE);sptm_root_mask_t one=SPTM_ROOT_MASK_ONE(k);
        for(unsigned i=0;i<SPTM_ROOT_CACHE;i++)CHECK(!!SPTM_ROOT_MASK_HAS(one,i)==(i==k));
    }
    printf("masks: 3000 random 192-slot sets agree with a boolean model\n");
}

static void reclaim_exclusion(void)
{
    unsigned picked=0;
    for(unsigned trial=0;trial<4000;trial++) {
        struct sptm_root_state s;memset(&s,0,sizeof s);
        uint64_t stamp[SPTM_ROOT_CACHE];
        for(unsigned i=0;i<SPTM_ROOT_CACHE;i++) {
            s.cache[i]=(struct sptm_root_cached){.root=0x1000000UL+i*0x4000,.shadow=0x2000000UL+i*0x1000,
                                                 .asid=100+i,.valid=1};
            stamp[i]=1000+rnd(1u<<20)*256+i;
        }
        s.builds=rnd(1000);
        for(unsigned c=0;c<SPTM_ROOT_CPUS;c++)if(rnd(2))s.active[c]=s.cache[rnd(SPTM_ROOT_CACHE)].root;
        sptm_root_mask_t ex=SPTM_ROOT_MASK_NONE;unsigned char rex[SPTM_ROOT_CACHE]={0};
        unsigned excluded=trial%4==3 ? SPTM_ROOT_CACHE : rnd(SPTM_ROOT_CACHE);
        for(unsigned n=0;n<excluded;n++) {unsigned i=trial%4==3 ? n : rnd(SPTM_ROOT_CACHE);SPTM_ROOT_MASK_SET(ex,i);rex[i]=1;}
        int want=-1;
        for(unsigned i=0;i<SPTM_ROOT_CACHE;i++) {
            int active=0;for(unsigned c=0;c<SPTM_ROOT_CPUS;c++)active|=s.active[c]==s.cache[i].root;
            if(!rex[i] && !active && (want<0 || stamp[i]<stamp[want]))want=(int)i;
        }
        unsigned got=sptm_root_reclaim_pick(&s,stamp,ex);
        CHECK(want<0 ? got==SPTM_ROOT_CACHE : got==(unsigned)want);
        picked+=want>=0;
    }
    CHECK(picked>2500);
    printf("reclaim: 4000 exclusion sets over 192 slots pick the oldest eligible root\n");
}

/* ---- native-shared link bits of high slots ---------------------------- */
#define HB UINT64_C(0x40000000)
#define HSIZE (16u<<20)
static uint8_t *mem;static uint64_t next_page;
static int rd(void *ctx,uint64_t pa,uint64_t *out)
{(void)ctx;if(pa<HB || pa+8>HB+HSIZE || (pa&7))return -1;memcpy(out,mem+(pa-HB),8);return 0;}
static int wr(void *ctx,uint64_t pa,uint64_t v)
{(void)ctx;if(pa<HB || pa+8>HB+HSIZE || (pa&7))return -1;memcpy(mem+(pa-HB),&v,8);return 0;}
static uint64_t alloc4k(void *ctx)
{(void)ctx;if(next_page+4096>HB+HSIZE)return 0;uint64_t pa=next_page;next_page+=4096;memset(mem+(pa-HB),0,4096);return pa;}
static uint64_t no_alloc(void *ctx) {(void)ctx;return 0;}
static void rel(void *ctx,uint64_t pa) {(void)ctx;(void)pa;}
static struct native_shared ns;
static struct shadow trees_by_slot[SPTM_ROOT_CACHE];static int has_tree[SPTM_ROOT_CACHE];
static int tree(void *ctx,unsigned slot,struct shadow *out)
{(void)ctx;if(slot>=SPTM_ROOT_CACHE || !has_tree[slot])return -1;*out=trees_by_slot[slot];out->alloc=no_alloc;return 0;}
static const struct native_shared_roots roots={tree,0};
/* The level-2 entry a tree holds for 2 MiB page p of group g (0: none). */
static uint64_t tree_entry(const struct shadow *s,int g,unsigned p)
{
    uint64_t table=s->root,d;
    for(unsigned l=0;l<2;l++) {
        if(rd(0,table+8UL*mmu_index(12,l,ns.group[g].va),&d) || !(d&1))return 0;
        table=d&PT_OA_MASK;
    }
    if(rd(0,table+8UL*(mmu_index(12,2,ns.group[g].va)+p),&d))return 0;
    return d;
}
static void high_slot_links(void)
{
    mem=calloc(1,HSIZE);next_page=HB;
    struct shadow w={.txsz=17,.alloc=alloc4k,.read=rd,.write=wr};
    next_page=(next_page+16383)&~UINT64_C(16383);
    uint64_t guest=next_page;next_page+=16384;memset(mem+(guest-HB),0,16384);
    uint64_t va=UINT64_C(0x180000000);
    wr(0,guest,UINT64_C(0x900000000)|UINT64_C(0x0060000000000fc3));     /* leaf 0: page 0 */
    int g=native_shared_create(&ns,&w,UINT64_C(0x8000000),guest,va,rd,0,rel,0);
    CHECK(g>=0);
    const unsigned linked[]={0,3,63,64,70,127,128,150,191};
    unsigned char want[SPTM_ROOT_CACHE]={0};
    for(unsigned n=0;n<sizeof linked/sizeof linked[0];n++) {
        unsigned slot=linked[n];
        trees_by_slot[slot]=(struct shadow){.txsz=17,.alloc=alloc4k,.read=rd,.write=wr};
        trees_by_slot[slot].root=alloc4k(0);has_tree[slot]=1;
        CHECK(native_shared_link(&ns,&trees_by_slot[slot],slot,g));
        want[slot]=1;
    }
    for(unsigned s=0;s<SPTM_ROOT_CACHE;s++)CHECK(native_shared_slot_links(&ns,s,g)==want[s]);
    CHECK(!native_shared_free(&ns,g,rel,0));
    /* A leaf in a new 2 MiB: its page reaches every linking tree, only them. */
    uint64_t leaf=UINT64_C(0x900004000)|UINT64_C(0x0060000000000fc3);
    unsigned p=5;uint64_t at=va+((uint64_t)p<<21);
    wr(0,guest+8UL*((at-va)>>14),leaf);
    CHECK(native_shared_grow(&ns,&w,g,at,&roots) && ns.group[g].pages[p]);
    for(unsigned n=0;n<sizeof linked/sizeof linked[0];n++)
        CHECK((tree_entry(&trees_by_slot[linked[n]],g,p)&PT_OA_MASK)==ns.group[g].pages[p]);
    CHECK(native_shared_store(&ns,&w,g,at,leaf));
    /* Unlink one high slot, forget another: exactly those bits go. */
    CHECK(native_shared_unlink(&ns,&trees_by_slot[150],150,g));want[150]=0;
    CHECK(native_shared_forget_slot(&ns,70));want[70]=0;
    for(unsigned s=0;s<SPTM_ROOT_CACHE;s++)CHECK(native_shared_slot_links(&ns,s,g)==want[s]);
    CHECK(!native_shared_link(&ns,&trees_by_slot[191],191,g));   /* already linked */
    for(unsigned s=0;s<SPTM_ROOT_CACHE;s++)if(want[s] && s!=191)CHECK(native_shared_forget_slot(&ns,s));
    CHECK(!native_shared_free(&ns,g,rel,0));                      /* slot 191 still links it */
    CHECK(native_shared_forget_slot(&ns,191) && native_shared_free(&ns,g,rel,0));
    CHECK(!native_shared_slot_links(&ns,191,g));
    printf("native shared: links of slots 0..191 kept apart; growth reached every linking tree\n");
    free(mem);
}
int main(void)
{
    masks();
    reclaim_exclusion();
    high_slot_links();
    printf("PASS: %u wide root-cache checks\n",checks);
    return 0;
}

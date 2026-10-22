/* SPDX-License-Identifier: MIT */
#include <stdio.h>
#include <string.h>
#include "sptm-user.h"
#include "sptm-refs.h"
#include "mmu.h"
#include "sptm-root.h"
#include "sprr-view.h"
#define BASE UINT64_C(0x90000000)
#define SIZE 0x40000u
#define FM (BASE+0x4000)
#define ROOT (BASE+0x8000)
#define L2 (BASE+0xc000)
#define L3 (BASE+0x10000)
#define DATA (BASE+0x14000)
#define L1 (BASE+0x18000)
#define VA UINT64_C(0x104414000)
static uint8_t ram[SIZE],before[SIZE];
static struct sptm_ref_batch refs;
static unsigned checks,failures,published,transactions;
static int refuse_aperture;
#define CHECK(x) do {checks++;if(!(x)){failures++;printf("FAIL %u: %s\n",__LINE__,#x);}} while(0)
static volatile uint8_t *map(void *ctx,uint64_t pa,uint64_t n)
{
    (void)ctx;if(pa<BASE || pa>=BASE+SIZE || n>BASE+SIZE-pa)return 0;
    return ram+(pa-BASE);
}
static uint64_t get(uint64_t pa,unsigned n)
{uint64_t v=0;for(unsigned i=0;i<n;i++)v|=(uint64_t)ram[pa-BASE+i]<<(8*i);return v;}
static void put(uint64_t pa,uint64_t v,unsigned n)
{for(unsigned i=0;i<n;i++)ram[pa-BASE+i]=(uint8_t)(v>>(8*i));}
static uint64_t meta(uint64_t pa){return FM+((pa-BASE)>>14)*16;}
static void publish(void *ctx,uint64_t pa,uint64_t n)
{CHECK(map(ctx,pa,n)!=0);published++;}
static int retype(void *ctx,uint64_t pa,uint64_t old,uint64_t next)
{
    (void)ctx;CHECK(pa==DATA && get(meta(pa)+2,1)==old);
    CHECK((old==11 && next==17)||(old==17 && next==11));
    transactions++;return !refuse_aperture;
}
static struct sptm_memory setup(unsigned format)
{
    memset(ram,0,sizeof ram);memset(&refs,0,sizeof refs);
    published=transactions=0;refuse_aperture=0;
    for(unsigned i=0;i<SIZE/16384;i++)put(FM+16UL*i+2,11,1);
    struct sptm_memory m={.frame_map_pa=FM,.frame_low=BASE,.frame_high=BASE+SIZE,
        .alloc_low=ROOT,.alloc_high=BASE+SIZE,.map=map,.publish=publish,
        .refs=&refs,.retype_user_tpro=retype};
    CHECK(sptm_mac_retype(&m,ROOT,11,18,(8UL<<32)|(2UL<<16)|format)==SPTM_OK);
    CHECK(sptm_mac_retype(&m,L2,11,20,2)==SPTM_OK);
    CHECK(sptm_mac_retype(&m,L3,11,20,3)==SPTM_OK);
    if(format)CHECK(sptm_mac_retype(&m,L1,11,20,1)==SPTM_OK);
    if(format)CHECK(sptm_mac_map_user_table(&m,ROOT,VA&~(3UL<<39),0,L1|3)==SPTM_OK);
    CHECK(sptm_mac_map_user_table(&m,ROOT,format ? VA&~(3UL<<30) : VA,1,L2|3)==SPTM_OK);
    CHECK(sptm_mac_map_user_table(&m,ROOT,format ? VA&~(3UL<<21) : VA,2,L3|3)==SPTM_OK);
    /* Fixture represents the separately qualified CONFIGURE_ROOT flag8. */
    put(meta(ROOT)+10,0xa,2);
    memset(ram+(DATA-BASE),0xa5,16384);published=transactions=0;
    return m;
}
static void reject_retype(struct sptm_memory *m,unsigned old,unsigned next,unsigned options,
                           enum sptm_result expected)
{
    memcpy(before,ram,sizeof ram);unsigned n=published;
    CHECK(sptm_mac_retype(m,DATA,old,next,options)==expected);
    CHECK(n==published && !memcmp(before,ram,sizeof ram));
}
static int read64(void *ctx,uint64_t pa,uint64_t *d)
{if(!map(ctx,pa,8))return -1;*d=get(pa,8);return 0;}
/* Exercise real source/canonical/private backends as one active transaction. */
#define HW_BASE UINT64_C(0xa0000000)
static uint8_t hw_ram[2u<<20];
static uint64_t hw_next;
static struct shadow hw;
static struct sptm_root_cached cache;
static struct sprr_views cpu_views;
static struct sprr_state cpu_states[6];
static struct sptm_memory *live_memory;
static int hw_read(void *ctx,uint64_t pa,uint64_t *d)
{(void)ctx;if(pa<HW_BASE || pa>HW_BASE+sizeof hw_ram-8)return -1;
 memcpy(d,hw_ram+(pa-HW_BASE),8);return 0;}
static int hw_write(void *ctx,uint64_t pa,uint64_t d)
{(void)ctx;if(pa<HW_BASE || pa>HW_BASE+sizeof hw_ram-8)return -1;
 memcpy(hw_ram+(pa-HW_BASE),&d,8);return 0;}
static uint64_t hw_alloc(void *ctx)
{(void)ctx;if(hw_next>HW_BASE+sizeof hw_ram-4096)return 0;
 uint64_t p=hw_next;hw_next+=4096;return p;}
static int sync_views(void)
{
    for(unsigned cpu=0;cpu<6;cpu++)
        if(!sprr_views_sync_user_cpu(&cpu_views,&hw,cpu,&cpu_states[cpu],cpu!=1))return 0;
    return 1;
}
static int prepare_live(void *ctx,uint64_t root,uint64_t va,unsigned shift,uint64_t pte)
{
    (void)ctx;(void)pte;CHECK(root==ROOT);
    if(!sptm_root_prepare_leaf(&cache,&hw,va,shift))return 0;
    for(uint64_t off=0;off<(1UL<<shift);off+=4096)
        if(!sprr_views_prepare_user_leaf(&cpu_views,&hw,va+off))return 0;
    return sync_views();
}
static int commit_live(void *ctx,uint64_t root,uint64_t va,unsigned shift,uint64_t pte)
{
    (void)ctx;CHECK(root==ROOT);
    if(!sptm_root_commit_leaf(&cache,&hw,live_memory,va,shift,pte))return 0;
    for(unsigned cpu=0;cpu<6;cpu++)for(uint64_t off=0;off<(1UL<<shift);off+=4096) {
        struct mmu_config cfg={12,17,sprr_views_root(&cpu_views,cpu)};struct mmu_leaf l;
        CHECK(!mmu_walk(&cfg,va+off,hw_read,0,&l) && !l.valid);
    }
    return sync_views();
}
static int prepare_remove(void *ctx,uint64_t root,uint64_t va,unsigned shift,uint64_t count)
{(void)ctx;CHECK(root==ROOT);return sptm_root_prepare_unmap(&cache,&hw,live_memory,va,shift,count);}
static int commit_remove(void *ctx,uint64_t root,uint64_t va,unsigned shift,uint64_t count,uint64_t removed)
{(void)ctx;CHECK(root==ROOT);return sptm_root_commit_unmap(&cache,&hw,va,shift,count,removed) && sync_views();}
static int resolve_inactive(void *ctx,uint64_t root,struct sptm_user_backend *b)
{(void)ctx;if(root!=ROOT)return 0;*b=(struct sptm_user_backend){0};return 1;}
/* Page aging: UPDATE_DISJOINT clears AF on every mapping of the frame, as the
 * A16 run requested for its class9 TPRO page (options 0x10a, ...e83 ->
 * ...a83), and the fault path sets it again with option 0x800. */
static void test_aging(struct sptm_memory *m,unsigned shift,uint64_t pte)
{
    const uint64_t list=BASE+0x30000,aged=pte&~PT_AF;uint64_t out=99;
    struct sptm_user_update_state st={0};struct mmu_config cfg={shift,17,ROOT};struct mmu_leaf l={0};
    put(list,ROOT,8);put(list+8,VA,8);put(list+16,aged,8);
    uint64_t data_refs=get(meta(DATA)+8,8),table_refs=get(meta(L3)+8,2);
    CHECK(sptm_mac_update_user_disjoint(m,resolve_inactive,0,DATA,list,1,0x10a,BASE,&out,&st)==SPTM_OK);
    CHECK(!mmu_walk(&cfg,VA,read64,0,&l) && l.valid && l.descriptor==aged && get(BASE,8)==pte);
    CHECK(get(meta(DATA)+8,8)==data_refs && get(meta(L3)+8,2)==table_refs && st.changed==1);
    put(list+16,pte,8);
    CHECK(sptm_mac_update_user_disjoint(m,resolve_inactive,0,DATA,list,1,0x10a,BASE,&out,&st)==SPTM_OK);
    CHECK(!mmu_walk(&cfg,VA,read64,0,&l) && l.descriptor==aged);   /* AF set needs 0x800 */
    CHECK(sptm_mac_update_user_disjoint(m,resolve_inactive,0,DATA,list,1,0x90a,BASE,&out,&st)==SPTM_OK);
    CHECK(!mmu_walk(&cfg,VA,read64,0,&l) && l.descriptor==pte);
    /* Still refused: a class change out of TPRO, and TPRO without its retype. */
    memcpy(before,ram,sizeof ram);
    put(list+16,pte&~(3UL<<53),8);
    CHECK(sptm_mac_update_user_disjoint(m,resolve_inactive,0,DATA,list,1,0x10a,BASE,&out,&st)!=SPTM_OK);
    put(list+16,aged,8);memcpy(before,ram,sizeof ram);m->retype_user_tpro=0;
    CHECK(sptm_mac_update_user_disjoint(m,resolve_inactive,0,DATA,list,1,0x10a,BASE,&out,&st)==SPTM_BAD_CONFIG);
    CHECK(!memcmp(before,ram,sizeof ram));m->retype_user_tpro=retype;
}
static void test_active(struct sptm_memory *m,unsigned format,uint64_t pte)
{
    memset(hw_ram,0,sizeof hw_ram);memset(&cpu_views,0,sizeof cpu_views);
    memset(cpu_states,0,sizeof cpu_states);hw_next=HW_BASE+4096;live_memory=m;
    hw=(struct shadow){.txsz=17,.root=HW_BASE,.alloc=hw_alloc,.read=hw_read,.write=hw_write};
    cache=(struct sptm_root_cached){.root=ROOT,.shadow=HW_BASE,.asid=get(meta(ROOT)+4,2),
        .format=format,.flags=0xa,.valid=1};
    CHECK(sptm_root_build_shadow(m,&hw,ROOT,format,0xa,&cache.leaves));
    CHECK(cache.leaves==1);
    struct sptm_fixed_view proof;
    CHECK(sptm_root_canonical_view(&cache,&hw,m,&proof));
    CHECK(proof.classes==(1UL<<9) && proof.pages==(format ? 1:4));
    CHECK(!sptm_root_fixed_view(&cache,&hw,m,&proof));
    m->retype_user_tpro=0;CHECK(!sptm_root_canonical_view(&cache,&hw,m,&proof));
    CHECK(!sptm_root_build_shadow(m,&hw,ROOT,format,0xa,&cache.leaves));m->retype_user_tpro=retype;
    put(meta(DATA)+2,11,1);CHECK(!sptm_root_canonical_view(&cache,&hw,m,&proof));put(meta(DATA)+2,17,1);
    CHECK(sprr_views_init(&cpu_views,&hw));CHECK(sprr_views_prepare_user(&cpu_views,&hw));
    for(unsigned cpu=0;cpu<6;cpu++)sprr_root_reset(&cpu_states[cpu],0xa);
    cpu_states[0].uperm|=1UL<<36;cpu_states[1].pperm|=1UL<<36;
    CHECK(sync_views());
    unsigned shift=format ? 12:14;uint64_t size=1UL<<shift,result=99;
    struct sptm_user_backend b={.ttbr0=ROOT,.active_refs=1,.prepare_leaf=prepare_live,
        .commit_leaf=commit_live,.prepare_unmap=prepare_remove,.commit_unmap=commit_remove};
    uint64_t refs_before=get(meta(ROOT)+6,2);put(meta(ROOT)+6,refs_before+1,2);
    CHECK(sptm_mac_map_user_page(m,&b,ROOT,VA+size,pte,1,0,&result)==SPTM_OK && result==0);
    CHECK(sptm_root_canonical_view(&cache,&hw,m,&proof) && cache.leaves==2);
    for(unsigned cpu=0;cpu<6;cpu++)for(uint64_t off=0;off<size;off+=4096) {
        struct mmu_config cfg={12,17,sprr_views_root(&cpu_views,cpu)};struct mmu_leaf l;
        CHECK(!mmu_walk(&cfg,VA+size+off,hw_read,0,&l) && l.valid && l.pa==DATA+off);
        CHECK((l.descriptor&(PT_PXN|PT_UXN))==(PT_PXN|PT_UXN));
        CHECK(!!(l.descriptor&(2UL<<6))==(cpu>=2));
    }
    CHECK(sptm_mac_unmap_user_region(m,&b,ROOT,VA+size,1,1,BASE)==SPTM_OK);
    CHECK(cache.leaves==1 && sptm_root_canonical_view(&cache,&hw,m,&proof));
    for(unsigned cpu=0;cpu<6;cpu++) {
        struct mmu_config cfg={12,17,sprr_views_root(&cpu_views,cpu)};struct mmu_leaf l;
        CHECK(!mmu_walk(&cfg,VA+size,hw_read,0,&l) && !l.valid);
    }
    put(meta(ROOT)+6,refs_before,2);
}
int main(void)
{
    for(unsigned format=0;format<2;format++) {
        struct sptm_memory m=setup(format);m.retype_user_tpro=0;
        reject_retype(&m,11,17,0,SPTM_BAD_CONFIG);m.retype_user_tpro=retype;
        refuse_aperture=1;reject_retype(&m,11,17,0,SPTM_SHADOW_FAILED);refuse_aperture=0;
        for(unsigned byte=0;byte<16;byte++)if(byte!=2)for(unsigned bit=0;bit<8;bit++) {
            put(meta(DATA)+byte,1u<<bit,1);
            reject_retype(&m,11,17,0,SPTM_FRAME_BUSY);put(meta(DATA)+byte,0,1);
        }
        reject_retype(&m,11,17,1,SPTM_UNSUPPORTED_OPTIONS);
        unsigned n=transactions;
        CHECK(sptm_mac_retype(&m,DATA,11,17,0)==SPTM_OK);
        CHECK(transactions==n+1 && get(meta(DATA)+2,1)==17);
        for(unsigned i=0;i<16384;i++)CHECK(ram[DATA-BASE+i]==0xa5);
        uint64_t pte=DATA|0x0020000000000e83UL,result=99;
        unsigned shift=format ? 12:14;uint64_t size=1UL<<shift;
        struct sptm_user_backend b={0};
        m.retype_user_tpro=0;memcpy(before,ram,sizeof ram);
        CHECK(sptm_mac_map_user_page(&m,&b,ROOT,VA,pte,1,0,&result)==SPTM_BAD_CONFIG);
        CHECK(result==99 && !memcmp(before,ram,sizeof ram));m.retype_user_tpro=retype;
        CHECK(sptm_mac_map_user_page(&m,&b,ROOT,VA,pte,1,0,&result)==SPTM_OK && !result);
        struct mmu_config cfg={shift,17,ROOT};struct mmu_leaf l={0};
        CHECK(!mmu_walk(&cfg,VA,read64,0,&l) && l.valid && l.pa==DATA && l.descriptor==pte);
        CHECK(get(meta(DATA)+12,4)==1 && !get(meta(DATA)+8,4));
        CHECK(get(meta(L3)+8,2)==1);
        test_aging(&m,shift,pte);
        test_active(&m,format,pte);
        reject_retype(&m,17,11,0,SPTM_FRAME_BUSY);
        /* The type17 descriptor at +0x33 permits mixed RO/other aliases. */
        CHECK(sptm_mac_map_user_page(&m,&b,ROOT,VA+size,DATA|0x0060000000000ec3UL,1,0,&result)==SPTM_OK);
        CHECK(sptm_mac_map_user_page(&m,&b,ROOT,VA+2*size,DATA|0x0060000000000e43UL,1,0,&result)==SPTM_OK);
        CHECK(get(meta(DATA)+12,4)==2 && get(meta(DATA)+8,4)==1 && get(meta(L3)+8,2)==3);
        sptm_refs_begin(&refs);CHECK(sptm_refs_dart(&m,DATA,0)==SPTM_TYPE_MISMATCH);
        sptm_refs_begin(&refs);CHECK(sptm_refs_dart(&m,DATA,1)==SPTM_TYPE_MISMATCH);
        CHECK(sptm_mac_unmap_user_region(&m,&b,ROOT,VA,3,1,BASE)==SPTM_OK);
        CHECK(!get(meta(DATA)+8,8) && !get(meta(L3)+8,2));
        CHECK(sptm_mac_map_user_page(&m,&b,ROOT,VA,DATA|0x0060000000000ec3UL,1,0,&result)==SPTM_OK);
        CHECK(get(meta(DATA)+8,4)==1 && !get(meta(DATA)+12,4));
        reject_retype(&m,17,11,0,SPTM_FRAME_BUSY);
        CHECK(sptm_mac_unmap_user_region(&m,&b,ROOT,VA,1,1,BASE)==SPTM_OK);
        CHECK(sptm_mac_retype(&m,DATA,17,11,0)==SPTM_OK);
        CHECK(get(meta(DATA)+2,1)==11 && !get(meta(DATA)+8,8));
        for(unsigned i=0;i<16384;i++)CHECK(ram[DATA-BASE+i]==0xa5);
        struct sptm_user_geometry g;CHECK(sptm_mac_user_geometry(format,0xa,&g));
        for(unsigned selector=0;selector<16;selector++)for(unsigned sh=0;sh<4;sh++) {
            uint64_t p=DATA|3|PT_AF|(1UL<<11)|((uint64_t)sh<<8)|
                       ((uint64_t)(selector&12)<<4)|((uint64_t)(selector&3)<<53);
            int ok=(selector==7 || selector==9 || selector==15) && sh>=2;
            CHECK((sptm_mac_user_leaf_policy(0xa,20,17,VA,p,&g)==SPTM_OK)==ok);
        }
        CHECK(sptm_mac_user_leaf_policy(2,20,17,VA,pte,&g)==SPTM_UNSUPPORTED_OPTIONS);
        CHECK(sptm_mac_user_leaf_policy(0xa,21,17,VA,pte,&g)==SPTM_TYPE_MISMATCH);
    }
    printf("USER_TPRO lifecycle: %u checks, %u failures\n",checks,failures);
    return !!failures;
}

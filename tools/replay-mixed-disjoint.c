/* SPDX-License-Identifier: MIT */
/* Failure inventory: docs/MIXED-DISJOINT-20260927.md. Written before the fix.
 * Reuse the kernel source/shadow/reference fixture; relocate captured PAs,
 * retaining the real captured descriptor attributes and user VA. */
#define main original_kernel_update_tests
#include "test-sptm-update.c"
#undef main
#include "sptm-user.h"
#include "sptm-root.h"
#define UROOT (BASE+0x24000)
#define UL2 (BASE+0x28000)
#define UL3 (BASE+0x2c000)
#define UVA UINT64_C(0x100f64000)
#undef SCRATCH
#define SCRATCH (BASE+0x3c000)
static uint64_t uold,kold,utemplate,ktemplate,options;
static struct shadow user_hw;
static struct sptm_root_cached user_cache;
static unsigned user_prepared,user_committed,refuse_user;
static struct sptm_user_update_state state;
static uint64_t uslot(void){return UL3+mmu_index(14,3,UVA)*8;}
static int prepare_user(void *ctx,uint64_t root,uint64_t va,unsigned shift,
                        uint64_t old,uint64_t next)
{
    (void)ctx;(void)old;(void)next;user_prepared++;
    return !refuse_user && root==UROOT &&
        sptm_root_prepare_unmap(&user_cache,&user_hw,&memory,va,shift,1);
}
static int commit_user(void *ctx,uint64_t root,uint64_t va,unsigned shift,
                       uint64_t old,uint64_t next)
{
    (void)ctx;user_committed++;
    return root==UROOT && sptm_root_commit_update(&user_cache,&user_hw,&memory,va,shift,old,next);
}
static int resolve_user(void *ctx,uint64_t root,struct sptm_user_backend *b)
{
    (void)ctx;if(root!=UROOT)return 0;
    *b=(struct sptm_user_backend){.ttbr1=ROOT,.prepare_update=prepare_user,
                                .commit_update=commit_user};return 1;
}
#ifdef SPTM_MIXED_DISJOINT
static enum sptm_result prepare_kernel(void *ctx,uint64_t target,uint64_t va,
    uint64_t requested,uint64_t opts,uint64_t scratch,uint64_t bytes,
    struct sptm_update_entry *entry)
{
    (void)ctx;return sptm_kernel_update_prepare(&memory,&backend,target,va,
                                             requested,opts,scratch,bytes,entry);
}
static void commit_kernel(void *ctx,struct sptm_update_entry *entry)
{(void)ctx;sptm_kernel_update_commit(&memory,entry);}
#endif
static enum sptm_result invoke(unsigned count,uint64_t *result)
{
#ifdef SPTM_MIXED_DISJOINT
    struct sptm_mixed_kernel_backend k={.root=ROOT,.workspace=&workspace,
        .prepare=prepare_kernel,.commit=commit_kernel};
    return sptm_mac_update_mixed_disjoint(&memory,resolve_user,0,&k,
        DATA,LIST,count,options,SCRATCH,result,&state);
#else
    if(get(LIST)!=ROOT)return sptm_mac_update_user_disjoint(&memory,resolve_user,0,
        DATA,LIST,count,options,SCRATCH,result,&state);
    enum sptm_result r=sptm_mac_update_disjoint(&memory,&backend,&workspace,
        DATA,LIST,count,options,SCRATCH);
    if(!r)*result=sptm_update_result(&workspace,count,options);return r;
#endif
}
static void request(unsigned at,int kernel)
{
    put(LIST+at*24,kernel?ROOT:UROOT);put(LIST+at*24+8,kernel?VA:UVA);
    put(LIST+at*24+16,kernel?ktemplate:utemplate);
}
static void fixture(int kernel_first)
{
    setup(1);memory.alloc_high=BASE+0x38000;
    put(leaf_slot(VA),kold);
    for(unsigned n=0;n<4;n++)put(shadow_slot(VA+n*4096),
        DATA+n*4096|(kold&(PT_LEAF_ATTRS|PT_LEAF_UPPER))|3);
    CHECK(!sptm_mac_retype(&memory,UROOT,11,18,(8UL<<32)|(2UL<<16)));
    CHECK(!sptm_mac_retype(&memory,UL2,11,20,2));
    CHECK(!sptm_mac_retype(&memory,UL3,11,20,3));
    CHECK(!sptm_mac_map_user_table(&memory,UROOT,UVA,1,UL2|3));
    CHECK(!sptm_mac_map_user_table(&memory,UROOT,UVA,2,UL3|3));
    ram[FM-BASE+((UROOT-BASE)>>14)*16+10]=0xb;
    struct sptm_user_backend ub={.ttbr1=ROOT};uint64_t result=99;
    CHECK(!sptm_mac_map_user_page(&memory,&ub,UROOT,UVA,uold,1,0,&result) && !result);
    user_hw=(struct shadow){.txsz=17,.root=alloc(0),.alloc=alloc,.read=read64,.write=write64};
    user_cache=(struct sptm_root_cached){.root=UROOT,.shadow=user_hw.root,
        .asid=8,.format=0,.flags=0xb,.valid=1};
    CHECK(sptm_root_build_shadow(&memory,&user_hw,UROOT,0,0xb,&user_cache.leaves));
    request(0,kernel_first);request(1,!kernel_first);
    put(SCRATCH,0xfeedface);put(SCRATCH+8,0xfeedface);
    user_prepared=user_committed=refuse_user=publications=0;
    memset(&state,0,sizeof state);
}
static void leaves(int changed)
{
    CHECK(get(uslot())==(changed?utemplate:uold));
    CHECK(get(leaf_slot(VA))==(changed?ktemplate:kold));
    for(unsigned n=0;n<4;n++) {
        CHECK(get(shadow_slot(VA+n*4096))==
              ((DATA+n*4096)|((changed?ktemplate:kold)&(PT_LEAF_ATTRS|PT_LEAF_UPPER))|3));
        struct mmu_config cfg={12,17,user_hw.root};struct mmu_leaf leaf;
        CHECK(!mmu_walk(&cfg,UVA+n*4096,read64,0,&leaf));
        CHECK(leaf.valid && leaf.pa==DATA+n*4096 &&
              (leaf.descriptor&(PT_LEAF_ATTRS|PT_LEAF_UPPER))==
              ((changed?utemplate:uold)&(PT_LEAF_ATTRS|PT_LEAF_UPPER)));
    }
}
static void rejection(unsigned count)
{
    memcpy(before,ram,sizeof ram);uint64_t result=99;
    CHECK(invoke(count,&result)!=SPTM_OK);
    CHECK(!memcmp(before,ram,sizeof ram) && !publications && !user_committed && result==99);
}
int main(int argc,char **argv)
{
    if(argc!=6)return 2;
    uold=(strtoull(argv[1],0,16)&~UINT64_C(0x0000ffffffffc000))|DATA;
    utemplate=(strtoull(argv[2],0,16)&~UINT64_C(0x0000ffffffffc000))|DATA;
    kold=(strtoull(argv[3],0,16)&~UINT64_C(0x0000ffffffffc000))|DATA;
    ktemplate=(strtoull(argv[4],0,16)&~UINT64_C(0x0000ffffffffc000))|DATA;
    options=strtoull(argv[5],0,16);
    CHECK((uold^utemplate)==PT_AF && (kold^ktemplate)==PT_AF && options==0x10a);
    for(int order=0;order<2;order++) {
        fixture(order);uint64_t result=99,counts=get(FM+((DATA-BASE)>>14)*16+8);
        enum sptm_result r=invoke(2,&result);
        printf("order=%s status=%u result=%llu\n",order?"kernel-first":"user-first",r,(unsigned long long)result);
        CHECK(r==SPTM_OK && result==5);leaves(1);
        CHECK(get(SCRATCH)==(order?kold:uold) && get(SCRATCH+8)==(order?uold:kold));
        CHECK(get(FM+((DATA-BASE)>>14)*16+8)==counts);
        CHECK(invoke(2,&result)==SPTM_OK && result==0);leaves(1);
        fixture(order);put(LIST+24,BASE+0x34000);rejection(2);
        fixture(order);refuse_user=1;rejection(2);
        fixture(order);put(shadow_slot(VA),get(shadow_slot(VA))^PT_AF);rejection(2);
        fixture(order);request(2,1);rejection(3); /* duplicate kernel slot */
        fixture(order);request(2,0);put(LIST+64,uold);rejection(3); /* conflicting user duplicate */
    }
    printf("mixed captured request: %u checks; both record orders, old outputs, canonical leaves and late-failure atomicity verified\n",checks);
    return 0;
}

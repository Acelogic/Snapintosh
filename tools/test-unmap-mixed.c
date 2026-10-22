/* SPDX-License-Identifier: MIT */
/* SNAP_UNMAP_MIXED (compat/sptm-user.h M1-M7): endpoint8 UNMAP_DISJOINT with
 * one frame aliased by a user root and the kernel root in one list, the
 * request installed-fresh-20261017-v39 stopped on (UNMAP_DISJOINT target
 * 0xa1dd54000, count 2, BAD_CONFIG). Reuses the kernel source/shadow/reference
 * fixture (tools/test-sptm-update.c) and adds a user root with a cached
 * shadow, as tools/replay-mixed-disjoint.c does for UPDATE_DISJOINT.
 *  1. Without the define's engine: the dispatch's old choice from record 0
 *     refuses both orders (user-first BAD_CONFIG, v39's status 1; kernel-first
 *     BAD_ADDRESS) and changes nothing.
 *  2. The mixed engine removes both aliases in either order: old outputs in
 *     input order, both source leaves cleared, the four kernel shadow leaves
 *     and the user cached shadow cleared, the frame's references released
 *     exactly once, the witness marked mixed; a repeat changes nothing.
 *  3. Every late refusal of either domain leaves memory, publications and the
 *     user commit untouched (whole-batch preflight).
 *  4. A duplicate kernel record sees the removed value|0x80 and releases one
 *     reference; a stale kernel record (another frame) is reported, kept.
 * Build: -DSNAP_UNMAP_MIXED=1 (tools/test-unmap-mixed.py). */
#define main original_kernel_update_tests
#include "test-sptm-update.c"
#undef main
#include "sptm-user.h"
#include "sptm-root.h"
#if !SNAP_UNMAP_MIXED
#error "build with -DSNAP_UNMAP_MIXED=1"
#endif
#define UROOT (BASE+0x24000)
#define UL2 (BASE+0x28000)
#define UL3 (BASE+0x2c000)
#define OTHER_ROOT (BASE+0x34000)
#define UVA UINT64_C(0x100f64000)
#undef SCRATCH
#define SCRATCH (BASE+0x3c000)
/* v39-era descriptors: the user alias of a DEFAULT data frame (nG, AF, SH2,
 * EL0 RW) and the fixture's kernel alias. */
#define UOLD (DATA|UINT64_C(0x0060000000000e43))
#define KOLD OLD
static struct shadow user_hw;
static struct sptm_root_cached user_cache;
static unsigned user_prepared,user_committed,refuse_user;
static struct sptm_shared_update_state witness,kwitness;   /* user, kernel */
static uint64_t uslot(void){return UL3+mmu_index(14,3,UVA)*8;}
/* The frame's two 32-bit mapping counts (frame-table bytes 8-15), summed. */
static uint64_t data_refs(void)
{uint64_t v=get(FM+((DATA-BASE)>>14)*16+8);return (v&0xffffffffu)+(v>>32);}
static int prepare_user(void *ctx,uint64_t root,uint64_t va,unsigned shift,uint64_t count)
{
    (void)ctx;user_prepared++;
    return !refuse_user && root==UROOT &&
        sptm_root_prepare_unmap(&user_cache,&user_hw,&memory,va,shift,count);
}
static int commit_user(void *ctx,uint64_t root,uint64_t va,unsigned shift,
                       uint64_t count,uint64_t removed)
{
    (void)ctx;user_committed++;
    return root==UROOT && sptm_root_commit_unmap(&user_cache,&user_hw,va,shift,count,removed);
}
/* probes/xnuboot.c user_backend's rule for these roots: the root installed in
 * TTBR1 resolves to nothing (v39's refusal); the user root is inactive. */
static int resolve_user(void *ctx,uint64_t root,struct sptm_user_backend *b)
{
    (void)ctx;if(root!=UROOT)return 0;
    *b=(struct sptm_user_backend){.ttbr1=ROOT,.prepare_unmap=prepare_user,
                                .commit_unmap=commit_user};return 1;
}
static struct shadow kernel_shadow(void)
{return (struct shadow){.txsz=17,.root=SHADOW,.alloc=alloc,.read=read64,.write=write64};}
/* The monitor's dispatch before SNAP_UNMAP_MIXED: record 0 picks the engine. */
static enum sptm_result invoke_before(unsigned count)
{
    struct shadow s=kernel_shadow();
    if(get(LIST)==ROOT)
        return sptm_mac_unmap_kernel_disjoint(&memory,&s,ROOT,DATA,LIST,count,SCRATCH,&witness);
    return sptm_mac_unmap_user_disjoint(&memory,resolve_user,0,DATA,LIST,count,SCRATCH,&witness);
}
static enum sptm_result invoke_list(unsigned count,uint64_t list,uint64_t scratch)
{
    struct shadow s=kernel_shadow();const struct sptm_unmap_kernel k={ROOT,&s,&kwitness};
    return sptm_mac_unmap_mixed_disjoint(&memory,resolve_user,0,&k,DATA,list,count,scratch,&witness);
}
static enum sptm_result invoke_scratch(unsigned count,uint64_t scratch)
{return invoke_list(count,LIST,scratch);}
static enum sptm_result invoke(unsigned count){return invoke_scratch(count,SCRATCH);}
static void request(unsigned at,int kernel)
{
    put(LIST+at*24,kernel?ROOT:UROOT);put(LIST+at*24+8,kernel?VA:UVA);put(LIST+at*24+16,0);
}
static void fixture(int kernel_first)
{
    setup(1);memory.alloc_high=BASE+0x38000;
    CHECK(get(leaf_slot(VA))==KOLD);
    CHECK(!sptm_mac_retype(&memory,UROOT,11,18,(8UL<<32)|(2UL<<16)));
    CHECK(!sptm_mac_retype(&memory,UL2,11,20,2));
    CHECK(!sptm_mac_retype(&memory,UL3,11,20,3));
    CHECK(!sptm_mac_map_user_table(&memory,UROOT,UVA,1,UL2|3));
    CHECK(!sptm_mac_map_user_table(&memory,UROOT,UVA,2,UL3|3));
    ram[FM-BASE+((UROOT-BASE)>>14)*16+10]=0xb;
    struct sptm_user_backend ub={.ttbr1=ROOT};uint64_t result=99;
    CHECK(!sptm_mac_map_user_page(&memory,&ub,UROOT,UVA,UOLD,1,0,&result) && !result);
    user_hw=(struct shadow){.txsz=17,.root=alloc(0),.alloc=alloc,.read=read64,.write=write64};
    user_cache=(struct sptm_root_cached){.root=UROOT,.shadow=user_hw.root,
        .asid=8,.format=0,.flags=0xb,.valid=1};
    CHECK(sptm_root_build_shadow(&memory,&user_hw,UROOT,0,0xb,&user_cache.leaves));
    request(0,kernel_first);request(1,!kernel_first);
    for(unsigned n=0;n<4;n++)put(SCRATCH+8*n,0xfeedface);
    user_prepared=user_committed=refuse_user=publications=0;
    memset(&witness,0,sizeof witness);memset(&kwitness,0,sizeof kwitness);
    CHECK(get(uslot())==UOLD && data_refs()==2);
}
static int user_shadow_maps(void)
{
    struct mmu_config cfg={12,17,user_hw.root};struct mmu_leaf leaf;int any=0;
    for(unsigned n=0;n<4;n++)
        any|=!mmu_walk(&cfg,UVA+n*4096,read64,0,&leaf) && leaf.valid;
    return any;
}
static int kernel_shadow_maps(void)
{
    int any=0;for(unsigned n=0;n<4;n++)any|=get(shadow_slot(VA+n*4096))!=0;return any;
}
static void untouched(enum sptm_result r)
{
    CHECK(r!=SPTM_OK);
    CHECK(!memcmp(before,ram,sizeof ram) && !publications && !user_committed &&
          !witness.latest.calls && !kwitness.latest.calls);
}
static void refused(unsigned count,uint64_t scratch)
{
    memcpy(before,ram,sizeof ram);untouched(invoke_scratch(count,scratch));
}
int main(int argc,char **argv)
{
    const char *dump=argc>1 ? argv[1]:0;
    /* 1. v39's request through the old dispatch. */
    for(int order=0;order<2;order++) {
        fixture(order);memcpy(before,ram,sizeof ram);
        enum sptm_result r=invoke_before(2);
        printf("before fix: %s -> status %u\n",order?"kernel-first":"user-first",r);
        CHECK(r==(order ? SPTM_BAD_ADDRESS:SPTM_BAD_CONFIG));untouched(r);
    }
    /* 2. Both orders through the mixed engine. */
    for(int order=0;order<2;order++) {
        fixture(order);
        enum sptm_result r=invoke(2);
        printf("mixed engine: %s -> status %u\n",order?"kernel-first":"user-first",r);
        CHECK(r==SPTM_OK);
        CHECK(get(SCRATCH)==(order?KOLD:UOLD) && get(SCRATCH+8)==(order?UOLD:KOLD));
        CHECK(get(SCRATCH+512)==(order?ROOT:UROOT) && get(SCRATCH+512+24)==(order?UROOT:ROOT));
        CHECK(get(SCRATCH+520)==(order?VA:UVA) && get(SCRATCH+520+24)==(order?UVA:VA));
        CHECK(!get(uslot()) && !get(leaf_slot(VA)));
        CHECK(!kernel_shadow_maps() && !user_shadow_maps());
        CHECK(!data_refs() && user_prepared==1 && user_committed==1 && publications);
        CHECK(!(get(FM+((L3-BASE)>>14)*16+8)&0xffff) && !(get(FM+((UL3-BASE)>>14)*16+8)&0xffff));
        /* Each domain's record in its own witness (M8), as the separate engines leave them. */
        CHECK(witness.latest.calls==1 && witness.latest.entries==1 && witness.latest.count==1 &&
              witness.latest.changed==1 && witness.latest.root==UROOT && witness.latest.va==UVA &&
              witness.latest.shift==14 && witness.latest.last_changed==1 && !witness.latest.options &&
              witness.changed.root==UROOT && witness.changed.changed==1 && witness.latest.target==DATA);
        CHECK(kwitness.latest.calls==1 && kwitness.latest.entries==1 && kwitness.latest.count==1 &&
              kwitness.latest.changed==1 && kwitness.latest.root==ROOT && kwitness.latest.va==VA &&
              kwitness.latest.shift==14 && kwitness.latest.last_changed==1 && !kwitness.latest.flags &&
              kwitness.changed.root==ROOT && kwitness.latest.old==KOLD && !kwitness.latest.next);
        if(!order && dump) {
            FILE *f=fopen(dump,"wb");CHECK(f);
            CHECK(fwrite(ram,1,sizeof ram,f)==sizeof ram && fwrite(&witness,1,sizeof witness,f)==sizeof witness &&
                  fwrite(&kwitness,1,sizeof kwitness,f)==sizeof kwitness);
            fclose(f);
        }
        uint64_t refs=data_refs();publications=0;user_prepared=user_committed=0;
        CHECK(invoke(2)==SPTM_OK && !get(SCRATCH) && !get(SCRATCH+8));
        CHECK(data_refs()==refs && !user_committed && witness.latest.changed==1 &&
              witness.latest.calls==2 && kwitness.latest.calls==2 && kwitness.latest.changed==1 &&
              !witness.latest.last_changed && !kwitness.latest.last_changed);
    }
    /* 3. Late refusals of either domain change nothing. */
    for(int order=0;order<2;order++) {
        unsigned k=order?0:1,u=order?1:0;
        fixture(order);put(LIST+k*24+8,VA+0x1000);refused(2,SCRATCH);      /* kernel VA alignment */
        fixture(order);put(LIST+k*24+8,0x4000);refused(2,SCRATCH);         /* kernel VA range */
        fixture(order);put(shadow_slot(VA+0x2000),get(shadow_slot(VA+0x2000))^PT_AF);
        refused(2,SCRATCH);                                                  /* stale kernel shadow */
        fixture(order);refuse_user=1;memcpy(before,ram,sizeof ram);
        untouched(invoke(2));CHECK(user_prepared==1);                        /* user preparation */
        fixture(order);put(LIST+u*24,OTHER_ROOT);refused(2,SCRATCH);       /* unresolvable user root */
        fixture(order);put(L2+mmu_index(14,2,VA)*8,ROOT|3);refused(2,SCRATCH); /* kernel table loop */
        fixture(order);refused(2,LIST);                                      /* output on the list (managed) */
        {   /* output on the list's own unmanaged page: the user engine alone admits it, the kernel's does not */
            fixture(order);uint64_t moved=SCRATCH+0x800;
            for(unsigned n=0;n<6;n++)put(moved+8*n,get(LIST+8*n));
            memcpy(before,ram,sizeof ram);untouched(invoke_list(2,moved,SCRATCH));
        }
        fixture(order);ram[FM-BASE+((DATA-BASE)>>14)*16]=1;refused(2,SCRATCH); /* busy frame */
    }
    {   /* user and kernel aliases plus a later bad kernel record: no domain publishes */
        fixture(0);request(2,1);put(LIST+48+8,VA+0x8000+0x10);refused(3,SCRATCH);
    }
    /* 4. A repeated kernel record and a stale one. */
    for(unsigned bits=0;bits<8;bits+=7) {
        fixture(0);request(2,1);uint64_t next=(uint64_t)bits<<61;put(LIST+24+16,next|0x1234);
        CHECK(invoke(3)==SPTM_OK);
        CHECK(get(SCRATCH)==UOLD && get(SCRATCH+8)==KOLD && get(SCRATCH+16)==(next|0x80));
        CHECK(get(leaf_slot(VA))==next && !data_refs() && witness.latest.changed==1 &&
              kwitness.latest.changed==1 && kwitness.latest.count==2 && kwitness.latest.entries==2 &&
              !kwitness.latest.last_changed && kwitness.changed.va==VA);
        CHECK((get(FM+((L3-BASE)>>14)*16+8)&0xffff)==!!bits);
    }
    fixture(1);put(leaf_slot(VA),(KOLD&~UINT64_C(0x0000ffffffffc000))|(DATA+0x4000));
    CHECK(invoke(2)==SPTM_OK);
    CHECK(get(SCRATCH)==((KOLD&~UINT64_C(0x0000ffffffffc000))|(DATA+0x4000)) && get(SCRATCH+8)==UOLD);
    CHECK(get(leaf_slot(VA))==((KOLD&~UINT64_C(0x0000ffffffffc000))|(DATA+0x4000)) &&
          !get(uslot()) && data_refs()==1 && witness.latest.changed==1 &&
          kwitness.latest.calls==1 && !kwitness.latest.changed && !kwitness.changed.calls);
    /* kernel 0 is the user engine: the same user-only list, same result. */
    fixture(0);request(0,0);
    struct sptm_shared_update_state w2;memset(&w2,0,sizeof w2);
    CHECK(sptm_mac_unmap_mixed_disjoint(&memory,resolve_user,0,0,DATA,LIST,1,SCRATCH,&w2)==SPTM_OK);
    CHECK(get(SCRATCH)==UOLD && !get(uslot()) && data_refs()==1 && w2.latest.calls==1 && w2.latest.changed==1);
    printf("PASS: %u mixed UNMAP_DISJOINT checks; both orders, outputs, references, shadows and late-failure atomicity\n",checks);
    return 0;
}

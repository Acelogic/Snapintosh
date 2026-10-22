/* SPDX-License-Identifier: MIT */
/* Written before implementation. Failure analysis: TXM-TRANSFER-UNMAP-20260925.md.
 * Reuse the existing kernel/source/shadow/reference fixture; relocate captured
 * addresses but preserve the captured descriptor's permission/software bits. */
#define main existing_update_regression_main
#include "test-sptm-update.c"
#undef main
#include "sptm-user.h"
#undef SCRATCH
#define SCRATCH (BASE+0x3c000)
static uint64_t captured;
static struct sptm_shared_update_state unmaps;
static unsigned mutate_list;
static int replay_read(void *ctx,uint64_t pa,uint64_t *out)
{
    if(mutate_list){put(LIST+24,ROOT+0x4000);mutate_list=0;}
    return read64(ctx,pa,out);
}
static void prepare(unsigned count)
{
    setup(count);memset(&unmaps,0,sizeof(unmaps));mutate_list=0;
    /* Match the monitor's reserved output page, outside managed memory. */
    memory.alloc_high=BASE+0x38000;
    uint64_t value=(captured&~0x0000ffffffffc000UL)|DATA;
    for(unsigned n=0;n<count;n++) {
        uint64_t va=VA+n*0x4000;
        sptm_refs_begin(memory.refs);
        CHECK(!sptm_refs_leaf(&memory,L3,va,OLD,value));
        CHECK(!sptm_refs_validate(&memory));sptm_refs_commit(&memory);
        put(leaf_slot(va),value);put(LIST+n*24+16,0);
        for(unsigned j=0;j<4;j++)put(shadow_slot(va+j*0x1000),
            (DATA+j*0x1000)|(value&(PT_LEAF_ATTRS|PT_LEAF_UPPER))|3);
    }
    publications=0;
}
static enum sptm_result invoke(unsigned count,uint64_t target,uint64_t list,uint64_t scratch)
{
    struct shadow s={.txsz=17,.root=SHADOW,.alloc=alloc,.read=replay_read,.write=write64};
    return sptm_mac_unmap_kernel_disjoint(&memory,&s,ROOT,target,list,count,scratch,&unmaps);
}
static void refused(unsigned count,uint64_t target,uint64_t list,uint64_t scratch)
{
    memcpy(before,ram,SIZE);unsigned pubs=publications;
    CHECK(invoke(count,target,list,scratch)!=SPTM_OK);
    CHECK(!memcmp(before,ram,SIZE) && publications==pubs && !unmaps.latest.calls);
}
int main(int argc,char **argv)
{
    if(argc!=2)return 2;
    captured=strtoull(argv[1],0,16);
    CHECK((captured&3)==3);
    uint64_t old=(captured&~0x0000ffffffffc000UL)|DATA;
    for(unsigned count=1;count<=64;count++) {
        prepare(count);
        CHECK(!invoke(count,DATA,LIST,SCRATCH));
        for(unsigned n=0;n<count;n++) {
            uint64_t va=VA+n*0x4000;
            CHECK(get(SCRATCH+8*n)==old && !get(leaf_slot(va)));
            CHECK(get(SCRATCH+512+24*n)==ROOT && get(SCRATCH+520+24*n)==va);
            for(unsigned j=0;j<4;j++)CHECK(!get(shadow_slot(va+j*0x1000)));
        }
        CHECK(!get(FM+((DATA-BASE)>>14)*16+8));
        CHECK(!get(FM+((L3-BASE)>>14)*16+8));
        CHECK(unmaps.latest.calls==1 && unmaps.latest.changed==count && unmaps.changed.changed==count);
    }
    for(unsigned bits=0;bits<8;bits++) {
        prepare(1);uint64_t next=(uint64_t)bits<<61;
        put(LIST+16,next|0x1234);put(LIST+24,ROOT);put(LIST+32,VA);put(LIST+40,0);
        CHECK(!invoke(2,DATA,LIST,SCRATCH));
        CHECK(get(SCRATCH)==old && get(SCRATCH+8)==(next|0x80));
        CHECK(get(leaf_slot(VA))==next && unmaps.latest.changed==1 && !unmaps.latest.last_changed);
        CHECK(!get(FM+((DATA-BASE)>>14)*16+8));
        CHECK((get(FM+((L3-BASE)>>14)*16+8)&0xffff)==!!bits);
        CHECK(!invoke(1,DATA,LIST,SCRATCH));
        CHECK(get(SCRATCH)==next && unmaps.latest.changed==1 && unmaps.changed.changed==1);
    }
    prepare(1);memcpy(before,ram,SIZE);
    CHECK(!invoke(1,DATA+0x4000,LIST,SCRATCH));
    CHECK(get(SCRATCH)==old && get(leaf_slot(VA))==old && !unmaps.latest.changed);
    uint64_t prior_refs;memcpy(&prior_refs,before+(FM-BASE+((DATA-BASE)>>14)*16+8),8);
    CHECK(get(FM+((DATA-BASE)>>14)*16+8)==prior_refs);
    prepare(2);mutate_list=1;
    CHECK(!invoke(2,DATA,LIST,SCRATCH));
    CHECK(get(SCRATCH+536)==ROOT && !get(leaf_slot(VA+0x4000)));
    prepare(2);put(LIST+24,ROOT+0x4000);refused(2,DATA,LIST,SCRATCH);
    prepare(2);put(LIST+32,0x4000);refused(2,DATA,LIST,SCRATCH);
    prepare(2);put(shadow_slot(VA+0x4000),get(shadow_slot(VA+0x4000))+0x1000);
    refused(2,DATA,LIST,SCRATCH);
    prepare(1);refused(0,DATA,LIST,SCRATCH);
    prepare(1);refused(65,DATA,LIST,SCRATCH);
    prepare(1);refused(1,DATA+1,LIST,SCRATCH);
    prepare(1);refused(1,DATA,LIST+1,SCRATCH);
    prepare(1);refused(2,DATA,LIST+0x3ff0,SCRATCH);
    prepare(1);refused(1,DATA,LIST,ROOT);
    prepare(1);refused(1,DATA,LIST,FM);
    prepare(1);ram[FM-BASE+((LIST-BASE)>>14)*16]=1;refused(1,DATA,LIST,SCRATCH);
    prepare(1);ram[FM-BASE+((DATA-BASE)>>14)*16]=1;refused(1,DATA,LIST,SCRATCH);
    printf("{\"result\":\"PASS\",\"checks\":%u,\"captured_pte\":\"0x%llx\",\"relocated_pte\":\"0x%llx\",\"max_batch\":64,\"boundary\":\"Captured descriptor flags with relocated source/shadow/reference fixture; all-CPU hardware audit remains separate\"}\n",
           checks,(unsigned long long)captured,(unsigned long long)old);
    return 0;
}

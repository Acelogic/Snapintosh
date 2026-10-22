/* SPDX-License-Identifier: MIT */
#define SPTM_USER_UPDATE_TEST_MAIN user_update_fixture_checks
#include "test-user-update.c"
static uint64_t held_refs;
static unsigned held_checks;
static int prepare_replacement(void *ctx,uint64_t root,uint64_t va,unsigned shift,
                               uint64_t old,uint64_t next)
{
    if(!prepare_update(ctx,root,va,shift,old,next))return 0;
    if(sprr_pte_class(next)==9 && sprr_pte_class(old)!=9) {
        for(uint64_t off=0;off<(1UL<<shift);off+=4096)
            if(!sprr_views_prepare_user_leaf(&cpu_views,&hw,va+off))return 0;
        if(!sync_views())return 0;
    }
    return 1;
}
static int commit_replacement(void *ctx,uint64_t root,uint64_t va,unsigned shift,
                              uint64_t old,uint64_t next)
{
    CHECK(get(meta(DATA)+8,8)==held_refs);held_checks++;
    int ok=commit_update(ctx,root,va,shift,old,next);
    if(!ok)printf("commit failed: old=%llx next=%llx type=%llu\n",
        (unsigned long long)old,(unsigned long long)next,(unsigned long long)get(meta(DATA)+2,1));
    return ok;
}
static void check_mapping(uint64_t va,uint64_t pa,unsigned shift,uint64_t pte)
{
    unsigned cls=(unsigned)(((pte>>4)&12)|((pte>>53)&3));
    struct mmu_config source={shift,17,ROOT};struct mmu_leaf leaf;
    CHECK(!mmu_walk(&source,va,read64,0,&leaf) && leaf.valid && leaf.descriptor==pte);
    if(cls!=9) {views(va,pa,shift,pte);return;}
    for(unsigned cpu=0;cpu<6;cpu++)for(uint64_t off=0;off<(1UL<<shift);off+=4096) {
        struct mmu_config cfg={12,17,sprr_views_root(&cpu_views,cpu)};
        CHECK(!mmu_walk(&cfg,va+off,hw_read,0,&leaf) && leaf.valid && leaf.pa==pa+off);
        CHECK((leaf.descriptor&(PT_PXN|PT_UXN))==(PT_PXN|PT_UXN));
        CHECK(leaf.descriptor&0x80); /* Default TPRO view is read-only. */
    }
}
int main(int argc,char **argv)
{
    if(argc==4 && !strcmp(argv[1],"--pte")) {
        uint64_t next=0,result=99;enum sptm_result status=sptm_mac_shared_map_pte(
            strtoull(argv[2],0,16),strtoull(argv[3],0,16),&next,&result);
        printf("%u %llu %016llx\n",status,(unsigned long long)result,(unsigned long long)next);
        return 0;
    }
    const unsigned types[]={11,14,17};
    for(unsigned format=0;format<2;format++)for(unsigned part=0;part<(format?4:1);part++)
    for(unsigned active=0;active<=6;active+=6)for(unsigned family=0;family<3;family++)
    for(unsigned output=0;output<2;output++) {
        struct sptm_memory m=setup(format);unsigned shift=format?12:14,type=types[family];
        uint64_t va=VA+part*4096,pa=DATA+part*4096,size=1UL<<shift;
        if(type!=11)put(meta(DATA)+2,type,1); /* Fixture starts before first mapping. */
        uint64_t ro=pa|0x0060000000000ec3UL;
        uint64_t changed=pa|(type==11 ? 0x0060000000000e43UL :
                            type==14 ? 0x0020000000000ec3UL : 0x0020000000000e83UL);
        uint64_t result=99;
        struct sptm_user_backend empty={0};
        CHECK(sptm_mac_map_user_page(&m,&empty,ROOT,va,ro,1,0,&result)==SPTM_OK);
        CHECK(sptm_mac_map_user_page(&m,&empty,ROOT,va+size,ro,1,0,&result)==SPTM_OK);
        memset(hw_ram,0,sizeof hw_ram);memset(&cpu_views,0,sizeof cpu_views);
        memset(cpu_states,0,sizeof cpu_states);hw_next=HW_BASE+4096;live_memory=&m;
        hw=(struct shadow){.txsz=17,.root=HW_BASE,.alloc=hw_alloc,.read=hw_read,.write=hw_write};
        cache=(struct sptm_root_cached){.root=ROOT,.shadow=HW_BASE,.asid=8,.format=format,.flags=0xa,.valid=1};
        CHECK(sptm_root_build_shadow(&m,&hw,ROOT,format,0xa,&cache.leaves) && cache.leaves==2);
        CHECK(sprr_views_init(&cpu_views,&hw) && sprr_views_prepare_user(&cpu_views,&hw));
        for(unsigned cpu=0;cpu<6;cpu++)sprr_root_reset(&cpu_states[cpu],0xa);
        CHECK(sync_views());
        struct sptm_user_update_state state={0};
        struct sptm_user_backend b={.ttbr0=active?ROOT:0,.active_refs=active,
            .aperture={BASE,0xfffffe0100000000UL,SIZE},
            .prepare_leaf=prepare_live,.commit_leaf=commit_live,
            .prepare_update=prepare_replacement,.commit_update=commit_replacement,.map_updates=&state};
        put(meta(ROOT)+6,get(meta(ROOT)+6,2)+active,2);
        prepared=committed=held_checks=0;fail_prepare=1;held_refs=get(meta(DATA)+8,8);
        memcpy(before,ram,sizeof ram);unsigned publications=published;
        CHECK(sptm_mac_map_user_page(&m,&b,ROOT,va,changed,output,BASE,&result)==SPTM_SHADOW_FAILED);
        CHECK(!memcmp(before,ram,sizeof ram) && publications==published && !committed && !state.calls);
        check_mapping(va,pa,shift,ro);
        fail_prepare=0;prepared=0;
        enum sptm_result status=sptm_mac_map_user_page(&m,&b,ROOT,va,changed,output,BASE,&result);
        if(status)printf("replacement failed: format=%u active=%u type=%u status=%u\n",format,active,type,status);
        /* Shipped MAP_PAGE returns 1 after replacing a valid leaf (...f95d4). */
        CHECK(status==SPTM_OK && result==1 && state.result==1);
        CHECK(committed==1 && held_checks==1 && state.calls==1 && state.old==ro && state.next==changed);
        CHECK(get(meta(DATA)+8,4)==1 && get(meta(DATA)+12,4)==1 && cache.leaves==2);
        check_mapping(va,pa,shift,changed);check_mapping(va+size,pa,shift,ro);
        if(!output)CHECK(get(BASE,8)==ro && get(BASE+8,8)==b.aperture.va+state.slot-BASE);
        held_refs=get(meta(DATA)+8,8);
        CHECK(sptm_mac_map_user_page(&m,&b,ROOT,va,changed,output,BASE,&result)==SPTM_OK && result==1);
        CHECK(committed==1 && held_checks==1 && state.calls==1 && get(meta(DATA)+8,8)==held_refs);
        CHECK(sptm_mac_map_user_page(&m,&b,ROOT,va,ro,output,BASE,&result)==SPTM_OK && result==1);
        CHECK(committed==2 && held_checks==2 && state.calls==2 && state.next==ro);
        CHECK(get(meta(DATA)+8,4)==2 && get(meta(DATA)+12,4)==0);
        check_mapping(va,pa,shift,ro);
        if(type==11) {
            /* Same-PA MAP preserves old AF/shareability, replaces WIRED and
             * normalizes writable history before returning success. */
            uint64_t requested=(changed^0x500)|(3UL<<58);
            held_refs=get(meta(DATA)+8,8);
            CHECK(sptm_mac_map_user_page(&m,&b,ROOT,va,requested,output,BASE,&result)==SPTM_OK && result==1);
            CHECK(state.next==(changed|(1UL<<58)));
            check_mapping(va,pa,shift,state.next);
        }
    }
    /* sptm_mac_map_page_status mirrors ...f9378 (identical: 1), ...f95d4
     * (valid old replaced: 1) and ...f9574 (empty slot: 0). */
    CHECK(sptm_mac_map_page_status(0,0x0060000947a0cec3UL)==0);
    CHECK(sptm_mac_map_page_status(0x0060000947a0cec3UL,0x0060000947a0cec3UL)==1);
    CHECK(sptm_mac_map_page_status(0x0060000947a0cec3UL,0x0060000947a0ce43UL)==1);
    CHECK(sptm_mac_map_page_status(0x46001007b218683UL,0x46001007b218603UL)==1); /* oracle kernel row */
    CHECK(sptm_mac_map_page_status(0x80,0x0060000947a0cec3UL)==0);
    CHECK(sptm_mac_map_page_status(0x80,0x80)==1);
    printf("user same-PA MAP_PAGE: %u checks, %u failures\n",checks,failures);
    return failures!=0;
}

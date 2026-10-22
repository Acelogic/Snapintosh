/* SPDX-License-Identifier: MIT */
#define SPTM_USER_UPDATE_TEST_MAIN update_fixture_checks
#include "test-user-update.c"
#define DATA2 (BASE+0x1c000)
static uint8_t saved_hw[sizeof hw_ram];
static struct sptm_memory region_memory;
static unsigned test_count,test_shift;
static uint64_t test_va;
static uint64_t data_at(unsigned i)
{return (i&1 ? DATA2:DATA)+((test_va+i*(1UL<<test_shift))&0x3fff);}
static void region_setup(unsigned fmt,unsigned part,unsigned active,unsigned count)
{
    region_memory=setup(fmt);test_shift=fmt?12:14;test_va=VA+part*4096;test_count=count;
    uint64_t result;struct sptm_user_backend b={0};
    memset(ram+(DATA2-BASE),0x5a,16384);
    for(unsigned i=0;i<count;i++) {
        uint64_t pa=fmt?data_at(i):(i&1 ? DATA2:DATA);
        CHECK(!sptm_mac_map_user_page(&region_memory,&b,ROOT,test_va+i*(1UL<<test_shift),
            pa|0x0060000000000e43UL,1,0,&result));
        put(LIST+i*8,0x00600000000000c0UL,8);
    }
    memset(hw_ram,0,sizeof hw_ram);memset(&cpu_views,0,sizeof cpu_views);
    memset(cpu_states,0,sizeof cpu_states);hw_next=HW_BASE+4096;live_memory=&region_memory;
    hw=(struct shadow){.txsz=17,.root=HW_BASE,.alloc=hw_alloc,.read=hw_read,.write=hw_write};
    cache=(struct sptm_root_cached){.root=ROOT,.shadow=HW_BASE,.asid=8,.format=fmt,.flags=0xa,.valid=1};
    CHECK(sptm_root_build_shadow(&region_memory,&hw,ROOT,fmt,0xa,&cache.leaves) && cache.leaves==count);
    CHECK(sprr_views_init(&cpu_views,&hw) && sprr_views_prepare_user(&cpu_views,&hw));
    for(unsigned cpu=0;cpu<6;cpu++)sprr_root_reset(&cpu_states[cpu],0xa);
    CHECK(sync_views());
    update_backend=(struct sptm_user_backend){.ttbr0=active?ROOT:0,.active_refs=active,
        .prepare_leaf=prepare_live,.commit_leaf=commit_live,
        .prepare_update=prepare_update,.commit_update=commit_update};
    put(meta(ROOT)+6,get(meta(ROOT)+6,2)+active,2);
    prepared=committed=fail_prepare=0;
}
static enum sptm_result region(unsigned options,uint64_t *result,struct sptm_user_update_state *s)
{return sptm_mac_update_user_region(&region_memory,&update_backend,ROOT,test_va,test_count,
                                  LIST,options,BASE,result,s);}
int main(void)
{
    for(unsigned fmt=0;fmt<2;fmt++)for(unsigned part=0;part<(fmt?4:1);part++)
    for(unsigned active=0;active<=6;active+=3)for(unsigned n=0;n<3;n++) {
        unsigned count=n==0?1:n==1?2:64;region_setup(fmt,part,active,count);
        struct sptm_user_update_state state={0};uint64_t result=99;
        if(count>1) {
            fail_prepare=2;memcpy(before,ram,sizeof ram);memcpy(saved_hw,hw_ram,sizeof hw_ram);
            unsigned prior=published;uint64_t allocated=hw_next;
            CHECK(region(2,&result,&state)==SPTM_SHADOW_FAILED);
            CHECK(!memcmp(before,ram,sizeof ram) && !memcmp(saved_hw,hw_ram,sizeof hw_ram));
            CHECK(prior==published && allocated==hw_next && !committed && !state.calls);
        }
        fail_prepare=prepared=0;CHECK(!region(0x102,&result,&state) && result==5);
        CHECK(committed==count && state.changed==count && state.calls==1 && state.count==count);
        for(unsigned i=0;i<count;i++) {
            uint64_t pa=fmt?data_at(i):(i&1 ? DATA2:DATA),old=pa|0x0060000000000e43UL;
            CHECK(get(BASE+i*8,8)==old);
            views(test_va+i*(1UL<<test_shift),pa,test_shift,old|0x80UL);
            put(LIST+i*8,1UL<<58,8);
        }
        CHECK(get(meta(DATA)+8,4)==(count+1)/2 && !get(meta(DATA)+12,4));
        CHECK(get(meta(DATA2)+8,4)==count/2 && !get(meta(DATA2)+12,4));
        CHECK(!region(0x101,&result,&state) && !result); /* software-only wired bit */
        unsigned prior=committed;CHECK(!region(0x101,&result,&state) && !result && prior==committed);
        CHECK(cache.leaves==count && state.calls==3);
        for(unsigned i=0;i<16384;i++)CHECK(ram[DATA-BASE+i]==0xa5 && ram[DATA2-BASE+i]==0x5a);
    }
    for(unsigned fmt=0;fmt<2;fmt++)for(unsigned bad=0;bad<13;bad++) {
        region_setup(fmt,0,6,2);uint64_t root=ROOT,va=test_va,count=2,input=LIST,scratch=BASE,options=2,result=99;
        struct sptm_user_update_state state={0};
        switch(bad) {
        case 0:count=0;break;case 1:count=65;break;case 2:va++;break;
        case 3:va=(test_va|((1UL<<(2*test_shift-3))-1))&~((1UL<<test_shift)-1);break;
        case 4:input++;break;case 5:scratch=LIST;break;
        case 6:scratch=ROOT;break;case 7:put(meta(DATA2)+2,14,1);break;
        case 8:put(meta(DATA2)+12,0,4);break; /* under-count later writable mapping */
        case 9:update_backend.prepare_update=update_backend.commit_update=0;break;
        case 10:input=BASE+SIZE;break;case 11:options=4;break;
        case 12:put(LIST+8,0,8);break; /* invalid later selector */
        }
        memcpy(before,ram,sizeof ram);memcpy(saved_hw,hw_ram,sizeof hw_ram);unsigned prior=published;
        CHECK(sptm_mac_update_user_region(&region_memory,&update_backend,root,va,count,input,options,scratch,
                                          &result,&state)!=SPTM_OK);
        CHECK(!memcmp(before,ram,sizeof ram) && !memcmp(saved_hw,hw_ram,sizeof hw_ram));
        CHECK(prior==published && !committed && !state.calls);
    }
    for(unsigned fmt=0;fmt<2;fmt++) {
        region_setup(fmt,0,6,2);uint64_t result=99;struct sptm_user_update_state state={0};
        uint64_t empty=test_va+4*(1UL<<(2*test_shift-3));
        CHECK(!sptm_mac_update_user_region(&region_memory,&update_backend,ROOT,empty,
            (1UL<<32)|2,LIST,(1UL<<32)|2,BASE,&result,&state));
        CHECK(!result && !get(BASE,8) && !get(BASE+8,8) && !state.changed && !state.target);
        CHECK(!prepared && !committed && state.count==2 && state.options==2);
    }
    printf("USER_REGION: %u checks, %u failures (45 geometry/activity/span combinations, six private views)\n",checks,failures);
    return !!failures;
}

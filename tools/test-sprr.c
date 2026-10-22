/* SPDX-License-Identifier: MIT */
#include <stdio.h>
#include <string.h>
#include "sprr.h"
static unsigned checks,failed;
static struct sprr_state *changing;
static uint64_t installed,before_change;
static int change_failure;
static unsigned changed;
#define CHECK(v) do {checks++;if(!(v)){failed++;printf("FAIL line %u: %s\n",__LINE__,#v);}} while(0)
static int change(void *ctx,uint64_t next)
{
    CHECK(ctx==changing && changing->pperm==before_change);
    changed++;
    if(change_failure)return 0;
    installed=next;return 1;
}
int main(void)
{
    struct sprr_state cpus[6]={0};
    const uint64_t regs[]={SPRR_UPERM,SPRR_PPERM,SPRR_UMPRR,SPRR_PMPRR};
    for(unsigned cpu=0;cpu<6;cpu++) {
        sprr_root_reset(&cpus[cpu],cpu&1 ? 10 : 2);
        CHECK(sprr_fixed_state_valid(&cpus[cpu]));
        for(unsigned reg=0;reg<4;reg++) {
            uint64_t v=0;
            CHECK(sprr_access(&cpus[cpu],regs[reg],1,&v)==SPRR_OK);
            CHECK(v==(reg==0 ? SPRR_UPERM_INITIAL : reg==1 ? SPRR_PPERM_INITIAL :
                      reg==2 ? (cpu&1 ? 0x40000 : 0) : SPRR_PMPRR_INITIAL));
        }
    }
    struct sprr_state saved[6];memcpy(saved,cpus,sizeof(cpus));
    sprr_root_reset(&cpus[1],0);CHECK(!cpus[1].umprr);
    for(unsigned cpu=0;cpu<6;cpu++)if(cpu!=1)CHECK(!memcmp(&saved[cpu],&cpus[cpu],sizeof(cpus[cpu])));
    for(unsigned reg=0;reg<4;reg++) {
        struct sprr_state s={0};sprr_root_reset(&s,10);
        uint64_t old[4];memcpy(old,&s,sizeof(old));
        uint64_t v=old[reg];
        CHECK(sprr_access(&s,regs[reg],0,&v)==(reg<2 ? SPRR_OK : SPRR_CONTROL_WRITE_UNIMPLEMENTED));
        for(unsigned bit=0;bit<64;bit++) {
            v=old[reg]^(UINT64_C(1)<<bit);
            CHECK(sprr_access(&s,regs[reg],0,&v)==(reg<2 ? SPRR_WRITE_UNIMPLEMENTED : SPRR_CONTROL_WRITE_UNIMPLEMENTED));
            CHECK(!memcmp(old,&s,sizeof(old)));
        }
    }
    struct sprr_state empty={0};uint64_t v=123;
    CHECK(sprr_access(&empty,SPRR_UPERM,1,&v)==SPRR_BAD_STATE && v==123);
    CHECK(sprr_access(0,SPRR_UPERM,1,&v)==SPRR_BAD_STATE);
    CHECK(sprr_access(0,0,1,&v)==SPRR_UNHANDLED);
    CHECK(sprr_access(&cpus[0],SPRR_UPERM,1,0)==SPRR_BAD_STATE);
    for(unsigned bit=0;bit<64;bit++) {
        struct sprr_state s=cpus[0];s.uperm^=UINT64_C(1)<<bit;
        CHECK(sprr_access(&s,SPRR_UPERM,1,&v)==SPRR_BAD_STATE);
    }
    /* Independent access-right comparison: R=1,W=2,X=4. The nibble table is
     * SPRR's EL view, including its special guarded combinations. */
    const unsigned el[16]={0,5,1,3,0,5,1,0,0,4,1,3,0,5,1,3};
    for(unsigned selector=0;selector<16;selector++) {
        uint64_t pte=((uint64_t)(selector>>2)<<6)|((uint64_t)(selector&3)<<53);
        unsigned ap=selector>>2;
        unsigned arm0=(ap&1 ? (ap&2 ? 1 : 3) : 0)|(selector&2 ? 0 : 4);
        unsigned arm1=(ap&2 ? 1 : 3)|(selector&1 ? 0 : 4);
        unsigned apple0=el[(SPRR_UPERM_INITIAL>>(4*selector))&15];
        unsigned apple1=el[(SPRR_PPERM_INITIAL>>(4*selector))&15];
        CHECK(sprr_fixed_native_leaf(pte)==(arm0==apple0 && arm1==apple1));
        CHECK(sprr_pte_class(pte)==selector);
        CHECK(sprr_pte_class(pte|0x0000abcdef120f3fUL)==selector);
    }
    struct sprr_state saturated={0};sprr_root_reset(&saturated,2);
    saturated.resets=saturated.reads=saturated.writes=saturated.rejected=UINT64_MAX;
    sprr_root_reset(&saturated,10);v=0;
    CHECK(sprr_access(&saturated,SPRR_UPERM,1,&v)==SPRR_OK);
    v^=1;CHECK(sprr_access(&saturated,SPRR_UPERM,0,&v)==SPRR_WRITE_UNIMPLEMENTED);
    CHECK(saturated.resets==UINT64_MAX && saturated.reads==UINT64_MAX &&
          saturated.writes==UINT64_MAX && saturated.rejected==UINT64_MAX);
    struct sprr_state dynamic={0};sprr_root_reset(&dynamic,2);changing=&dynamic;
    for(unsigned n=0;n<8;n++) {
        before_change=dynamic.pperm;v=before_change^0x100;
        CHECK(sprr_access_with(&dynamic,SPRR_PPERM,0,&v,change,&dynamic)==SPRR_OK);
        CHECK(dynamic.pperm==installed && dynamic.pperm==v);
        uint64_t got=0;CHECK(sprr_access(&dynamic,SPRR_PPERM,1,&got)==SPRR_OK && got==v);
    }
    before_change=dynamic.pperm;v=before_change^0x100;change_failure=1;
    CHECK(sprr_access_with(&dynamic,SPRR_PPERM,0,&v,change,&dynamic)==SPRR_VIEW_FAILED);
    CHECK(dynamic.pperm==before_change && installed==before_change && changed==9);
    for(unsigned bit=0;bit<64;bit++)if(bit!=8 && bit!=36) {
        v=before_change^(UINT64_C(1)<<bit);
        CHECK(sprr_access_with(&dynamic,SPRR_PPERM,0,&v,change,&dynamic)==SPRR_WRITE_UNIMPLEMENTED);
    }
    CHECK(changed==9 && dynamic.pperm==before_change);
    printf("SPRR fixed-state model: %u checks, %u failures\n",checks,failed);
    return failed ? 1 : 0;
}

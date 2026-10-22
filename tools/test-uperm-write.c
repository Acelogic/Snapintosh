/* SPDX-License-Identifier: MIT */
#include "sprr.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define CHECK(x) do {checks++;if(!(x)){fprintf(stderr,"FAIL %u: %s\n",__LINE__,#x);exit(1);}} while(0)
static unsigned checks;
struct transaction {struct sprr_state *s;uint64_t old,installed;unsigned calls,fail;};
static int change(void *ctx,uint64_t next)
{
    struct transaction *t=ctx;CHECK(t->s->uperm==t->old);t->calls++;
    if(t->fail)return 0;
    t->installed=next;return 1;
}
int main(void)
{
    for(unsigned flags=0;flags<16;flags++) {
        struct sprr_state cpus[6]={0};
        for(unsigned cpu=0;cpu<6;cpu++)sprr_root_reset(&cpus[cpu],flags);
        for(unsigned cpu=0;cpu<6;cpu++) {
            struct sprr_state others[6];memcpy(others,cpus,sizeof cpus);
            struct transaction t={.s=&cpus[cpu],.old=cpus[cpu].uperm,.installed=cpus[cpu].uperm};
            uint64_t next=t.old|SPRR_UPERM_TPRO_WRITE;
            enum sprr_result result=sprr_uperm_write(t.s,next,change,&t);
            CHECK(result==(flags&8 ? SPRR_OK : SPRR_WRITE_UNIMPLEMENTED));
            CHECK(t.calls==!!(flags&8));
            if(flags&8) {
                CHECK(t.s->uperm==next && t.installed==next);
                uint64_t value=0;CHECK(sprr_access(t.s,SPRR_UPERM,1,&value)==SPRR_OK && value==next);
                for(unsigned bit=0;bit<64;bit++)if(bit!=36) {
                    CHECK(sprr_uperm_write(t.s,next^(UINT64_C(1)<<bit),change,&t)==SPRR_WRITE_UNIMPLEMENTED);
                    CHECK(t.calls==1 && t.s->uperm==next);
                }
                t.old=next;t.fail=1;
                CHECK(sprr_uperm_write(t.s,SPRR_UPERM_INITIAL,change,&t)==SPRR_VIEW_FAILED);
                CHECK(t.s->uperm==next && t.installed==next);
                t.fail=0;
                CHECK(sprr_uperm_write(t.s,SPRR_UPERM_INITIAL,change,&t)==SPRR_OK);
                CHECK(t.s->uperm==SPRR_UPERM_INITIAL && t.installed==SPRR_UPERM_INITIAL);
                t.old=SPRR_UPERM_INITIAL;
                CHECK(sprr_uperm_write(t.s,SPRR_UPERM_INITIAL,change,&t)==SPRR_OK && t.calls==4);
                CHECK(sprr_uperm_write(t.s,next,0,&t)==SPRR_WRITE_UNIMPLEMENTED);
                CHECK(sprr_uperm_write(t.s,next,change,&t)==SPRR_OK);
                sprr_root_reset(t.s,0);
                CHECK(t.s->uperm==SPRR_UPERM_INITIAL && !t.s->umprr);
            } else CHECK(t.s->uperm==t.old);
            for(unsigned i=0;i<6;i++)if(i!=cpu)CHECK(!memcmp(&cpus[i],&others[i],sizeof cpus[i]));
        }
    }
    struct sprr_state invalid={0};
    for(unsigned rt=0;rt<32;rt++) {
        struct sprr_state s={0};sprr_root_reset(&s,10);
        struct transaction t={.s=&s,.old=s.uperm,.installed=s.uperm};
        uint64_t regs[31],before[31];
        for(unsigned n=0;n<31;n++)regs[n]=SPRR_UPERM_INITIAL|SPRR_UPERM_TPRO_WRITE;
        memcpy(before,regs,sizeof regs);
        CHECK(sprr_user_write(&s,0xd51ef1a0|rt,regs,change,&t)==(rt==31 ? SPRR_WRITE_UNIMPLEMENTED : SPRR_OK));
        CHECK(!memcmp(before,regs,sizeof regs));
        CHECK(s.uperm==(rt==31 ? SPRR_UPERM_INITIAL : before[0]));
        for(unsigned bit=5;bit<32;bit++) {
            struct sprr_state old=s;
            CHECK(sprr_user_write(&s,(0xd51ef1a0|rt)^(1U<<bit),regs,change,&t)==SPRR_UNHANDLED);
            CHECK(!memcmp(&s,&old,sizeof s) && !memcmp(before,regs,sizeof regs));
        }
        CHECK(sprr_user_write(&s,0xd51ef1a0|rt,0,change,&t)==SPRR_BAD_STATE);
    }
    CHECK(sprr_uperm_write(0,0,change,0)==SPRR_BAD_STATE);
    CHECK(sprr_uperm_write(&invalid,0,change,0)==SPRR_BAD_STATE);
    printf("PASS: %u UPERM transaction and per-CPU lifecycle checks\n",checks);
}

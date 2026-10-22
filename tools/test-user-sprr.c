/* SPDX-License-Identifier: MIT */
#include "sprr.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define CHECK(x) do { checks++;if(!(x)){fprintf(stderr,"FAIL %d: %s\n",__LINE__,#x);exit(1);} } while(0)
static unsigned checks;
int main(void)
{
    for(unsigned flags=0;flags<16;flags++)for(unsigned rt=0;rt<32;rt++) {
        struct sprr_state s={0};sprr_root_reset(&s,flags);
        uint64_t regs[31],before[31];for(unsigned i=0;i<31;i++)regs[i]=before[i]=0xdead+i;
        CHECK(sprr_user_read(&s,0xd53ef1a0|rt,regs)==SPRR_OK);
        CHECK(s.reads==1 && s.uperm==SPRR_UPERM_INITIAL && s.umprr==((uint64_t)(flags&8)<<15|((uint64_t)(flags&1)<<11)));
        for(unsigned i=0;i<31;i++)CHECK(regs[i]==(i==rt ? SPRR_UPERM_INITIAL : before[i]));
        for(unsigned bit=5;bit<32;bit++) {
            struct sprr_state old=s;memcpy(before,regs,sizeof regs);
            CHECK(sprr_user_read(&s,(0xd53ef1a0|rt)^(1U<<bit),regs)==SPRR_UNHANDLED);
            CHECK(!memcmp(&old,&s,sizeof s) && !memcmp(before,regs,sizeof regs));
        }
        struct sprr_state old=s;s.uperm^=1;memcpy(before,regs,sizeof regs);
        CHECK(sprr_user_read(&s,0xd53ef1a0|rt,regs)==SPRR_BAD_STATE);
        CHECK(s.reads==old.reads && !memcmp(before,regs,sizeof regs));
    }
    uint64_t regs[31]={0};struct sprr_state s={0};
    CHECK(sprr_user_read(0,0xd53ef1a9,regs)==SPRR_BAD_STATE);
    CHECK(sprr_user_read(&s,0xd53ef1a9,regs)==SPRR_BAD_STATE);
    sprr_root_reset(&s,0xa);
    CHECK(sprr_user_read(&s,0xd53ef1a9,0)==SPRR_BAD_STATE);
    printf("PASS: %u EL0 SPRR read checks\n",checks);
}

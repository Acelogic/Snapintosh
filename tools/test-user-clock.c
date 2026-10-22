/* SPDX-License-Identifier: MIT */
#include "clock.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define CHECK(x) do { checks++; if(!(x)) {fprintf(stderr,"FAIL %d: %s\n",__LINE__,#x);exit(1);} } while(0)
static unsigned checks;
struct sample {uint64_t value,reads;};
static uint64_t counter(void *ctx) {struct sample *s=ctx;s->reads++;return s->value;}
int main(void)
{
    struct sample sample={0x123456789abc,0};
    struct clock_backend backend={&sample,counter,0};
    for(unsigned rt=0;rt<32;rt++) {
        struct guest_clock clock={.cntkctl=0x4f};uint64_t regs[31],before[31];
        for(unsigned i=0;i<31;i++)regs[i]=before[i]=i+0xbeef;
        CHECK(guest_clock_user_read(&clock,&backend,0xd53cfac0|rt,regs)==CLOCK_OK);
        CHECK(clock.reads==1 && clock.last==sample.value);
        for(unsigned i=0;i<31;i++)CHECK(regs[i]==(i==rt ? sample.value : before[i]));
        for(unsigned bit=5;bit<32;bit++) {
            struct guest_clock old=clock;struct sample old_sample=sample;
            memcpy(before,regs,sizeof regs);
            CHECK(guest_clock_user_read(&clock,&backend,(0xd53cfac0|rt)^(1U<<bit),regs)==CLOCK_UNHANDLED);
            CHECK(!memcmp(&old,&clock,sizeof clock) && !memcmp(&old_sample,&sample,sizeof sample));
            CHECK(!memcmp(before,regs,sizeof regs));
        }
    }
    for(unsigned ctl=0;ctl<256;ctl++) {
        struct guest_clock clock={.cntkctl=ctl};uint64_t regs[31]={0};
        CHECK(guest_clock_user_read(&clock,&backend,0xd53cfac8,regs)==
              (ctl&2 ? CLOCK_OK : CLOCK_CONTROL_UNSUPPORTED));
        CHECK(clock.reads==!!(ctl&2));CHECK(regs[8]==(ctl&2 ? sample.value : 0));
    }
    struct guest_clock clock={.cntkctl=2};uint64_t regs[31]={0};
    CHECK(guest_clock_user_read(&clock,0,0xd53cfac8,regs)==CLOCK_BACKEND_FAILED);
    CHECK(guest_clock_user_read(0,&backend,0xd53cfac8,regs)==CLOCK_BACKEND_FAILED);
    CHECK(guest_clock_user_read(&clock,&backend,0xd53cfac8,0)==CLOCK_BACKEND_FAILED);
    CHECK(!clock.reads && !regs[8]);
    printf("PASS: %u user-clock checks\n",checks);
}

/* SPDX-License-Identifier: MIT */
#include "sprr.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define CHECK(x) do {checks++;if(!(x)){fprintf(stderr,"FAIL %u: %s\n",__LINE__,#x);exit(1);}} while(0)
static unsigned checks;
struct backend {struct sprr_state *s;uint64_t before,installed;unsigned calls,fail;};
static int change(void *ctx,uint64_t pperm)
{
    struct backend *b=ctx;CHECK(b->s->pperm==b->before);b->calls++;
    if(b->fail)return 0;
    b->installed=pperm;return 1;
}
static uint64_t value(unsigned n)
{return SPRR_PPERM_INITIAL|((uint64_t)(n&1)<<8)|((uint64_t)(n>>1)<<36);}
int main(void)
{
    for(unsigned cpu=0;cpu<6;cpu++)for(unsigned old=0;old<4;old++)for(unsigned next=0;next<4;next++) {
        struct sprr_state cpus[6]={0};
        for(unsigned i=0;i<6;i++){sprr_root_reset(&cpus[i],10);cpus[i].pperm=value(old);}
        struct sprr_state before[6];memcpy(before,cpus,sizeof cpus);
        struct backend b={.s=&cpus[cpu],.before=value(old),.installed=value(old),.fail=1};
        uint64_t wanted=value(next),readback=0;
        CHECK(sprr_access_with(b.s,SPRR_PPERM,0,&wanted,change,&b)==(old==next ? SPRR_OK : SPRR_VIEW_FAILED));
        CHECK(b.s->pperm==value(old) && b.installed==value(old));
        b.fail=0;
        CHECK(sprr_access_with(b.s,SPRR_PPERM,0,&wanted,change,&b)==SPRR_OK);
        CHECK(b.s->pperm==wanted && b.installed==wanted);
        CHECK(sprr_access(b.s,SPRR_PPERM,1,&readback)==SPRR_OK && readback==wanted);
        unsigned calls=b.calls;b.before=wanted;
        for(unsigned bit=0;bit<64;bit++)if(bit!=8 && bit!=36) {
            uint64_t bad=wanted^(UINT64_C(1)<<bit);
            CHECK(sprr_access_with(b.s,SPRR_PPERM,0,&bad,change,&b)==SPRR_WRITE_UNIMPLEMENTED);
            CHECK(b.calls==calls && b.s->pperm==wanted && b.installed==wanted);
        }
        for(unsigned i=0;i<6;i++)if(i!=cpu)CHECK(!memcmp(&cpus[i],&before[i],sizeof cpus[i]));
        sprr_root_reset(b.s,0);CHECK(b.s->pperm==SPRR_PPERM_INITIAL);
    }
    printf("PASS: %u PPERM copy-grant/restore and selector2 interaction checks\n",checks);
}

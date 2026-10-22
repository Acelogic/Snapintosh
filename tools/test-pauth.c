/* SPDX-License-Identifier: MIT */
#include "pauth.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(x) do { checks++; if (!(x)) { fprintf(stderr,"FAIL %d: %s\n",__LINE__,#x); exit(1); } } while(0)
static unsigned checks;
struct observed { uint64_t data, modifier; unsigned calls; };
static uint64_t sign(void *ctx, uint64_t data, uint64_t modifier)
{
    struct observed *o = ctx;
    o->data = data; o->modifier = modifier; o->calls++;
    return 0x98765432feedfaceUL;
}
int main(void)
{
    uint64_t regs[31], before[31], sp=0xabc000;
    /* Covers aliasing, XZR sources/discarded result, and the SP modifier. */
    for (unsigned rd=0;rd<32;rd++) for(unsigned rn=0;rn<32;rn++) for(unsigned rm=0;rm<32;rm++) {
        for(unsigned n=0;n<31;n++) regs[n]=before[n]=0x1000+n;
        struct observed o={0};
        uint32_t insn=0x9ac03000 | rd | rn<<5 | rm<<16;
        CHECK(pauth_pacga(insn,regs,sp,sign,&o));
        CHECK(o.calls==1 && o.data==(rn==31?0:before[rn]) && o.modifier==(rm==31?sp:before[rm]));
        for(unsigned n=0;n<31;n++) CHECK(regs[n]==(n==rd?0x9876543200000000UL:before[n]));
    }
    struct observed o={0};
    memcpy(before,regs,sizeof(regs));
    /* Every fixed encoding bit is significant: nearby arithmetic and PAC
     * instructions must stop, never be interpreted as PACGA. */
    for(unsigned bit=0;bit<32;bit++) if((0xffe0fc00U>>bit)&1) {
        CHECK(!pauth_pacga(0x9ac03000U^(1U<<bit),regs,sp,sign,&o));
        CHECK(!memcmp(before,regs,sizeof(regs)) && !o.calls);
    }
    CHECK(!pauth_pacga(0x9ac03000,0,sp,sign,&o));
    CHECK(!pauth_pacga(0x9ac03000,regs,sp,0,&o));
    printf("PASS: %u PACGA operand and refusal checks\n",checks);
}

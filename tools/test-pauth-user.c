/* SPDX-License-Identifier: MIT */
#include "../compat/pauth-user.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

static unsigned checks;
#define CHECK(x) do {assert(x);checks++;} while(0)
static uint64_t encoded(unsigned slot)
{
    if(slot==12)return PAUTH_SYSREG(3,4,15,0,4);
    if(slot>=10)return PAUTH_SYSREG(3,4,15,1,slot-10);
    unsigned key=slot/2;
    return PAUTH_SYSREG(3,0,2,key<2 ? 1 : key<4 ? 2 : 3,
                        (key<4 ? (key&1)*2 : 0)+(slot&1));
}
int main(int argc,char **argv)
{
    struct pauth_user_state s;pauth_user_init(&s);
    if(argc==2 && !strcmp(argv[1],"--boot")) {
        for(unsigned i=0;i<13;i++) {
            uint64_t value=0;assert(pauth_user_reg(&s,encoded(i),1,&value));
            printf("%llx %llx\n",(unsigned long long)encoded(i),(unsigned long long)value);
        }
        return 0;
    }
    const uint64_t expected[]={0xfeedfacefeedfad5UL,0xfeedfacefeedfad6UL,
        0xfeedfacefeedfacfUL,0xfeedfacefeedfad0UL,0xfeedfacefeedfad7UL,
        0xfeedfacefeedfad8UL,0xfeedfacefeedfad1UL,0xfeedfacefeedfad2UL,
        0xfeedfacefeedfad9UL,0xfeedfacefeedfadaUL,0xfeedfacefeedfad3UL,
        0xfeedfacefeedfad4UL,0x11};
    for(unsigned i=0;i<13;i++) {
        uint64_t v=0;CHECK(pauth_user_reg(&s,encoded(i),1,&v));CHECK(v==expected[i]);
    }
    CHECK(s.reads==13 && !s.writes && !s.written_mask && !s.extra_writes);
    struct pauth_user_state cpus[6];
    for(unsigned cpu=0;cpu<6;cpu++)pauth_user_init(&cpus[cpu]);
    for(unsigned round=0;round<128;round++)for(unsigned cpu=0;cpu<6;cpu++) {
        for(unsigned i=0;i<13;i++) {
            struct pauth_user_state before=cpus[cpu];
            uint64_t value=0x1020304050607080UL^((uint64_t)round<<32)^(cpu<<16)^i;
            CHECK(pauth_user_reg(&cpus[cpu],encoded(i),0,&value));
            for(unsigned j=0;j<13;j++) {
                uint64_t old=0,got=0;
                CHECK(pauth_user_reg(&before,encoded(j),1,&old));
                CHECK(pauth_user_reg(&cpus[cpu],encoded(j),1,&got));
                CHECK(got==(i==j ? value:old));
            }
            CHECK(cpus[cpu].writes==round*13+i+1);
            CHECK(cpus[cpu].written_mask==((round ? 0x1fffUL : (1UL<<(i+1))-1)));
        }
    }
    /* Temporary batch JOP selection and restoration preserve other keys. */
    struct pauth_user_state before=s;
    for(unsigned i=10;i<12;i++) {
        uint64_t v=0x1122334455667788UL+i;CHECK(pauth_user_reg(&s,encoded(i),0,&v));
    }
    uint64_t v=before.extra.lo;CHECK(pauth_user_reg(&s,encoded(10),0,&v));
    v=before.extra.hi;CHECK(pauth_user_reg(&s,encoded(11),0,&v));
    CHECK(!memcmp(s.key,before.key,sizeof(s.key)) && !memcmp(&s.extra,&before.extra,sizeof(s.extra)));
    before=s;v=0x5555;
    for(unsigned reg=0;reg<0x400000;reg+=0x422) {
        int known=0;for(unsigned i=0;i<13;i++)known|=reg==encoded(i);
        if(known)continue;
        CHECK(!pauth_user_reg(&s,reg,0,&v));CHECK(!memcmp(&s,&before,sizeof(s)));CHECK(v==0x5555);
    }
    CHECK(!pauth_user_reg(&s,encoded(0),2,&v));CHECK(!pauth_user_reg(0,encoded(0),0,&v));
    CHECK(!pauth_user_reg(&s,encoded(0),0,0));
    printf("pauth user register state: %u checks passed\n",checks);
    return 0;
}

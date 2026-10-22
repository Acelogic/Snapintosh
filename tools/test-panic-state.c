/* SPDX-License-Identifier: MIT */
#include "panic-state.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define CHECK(x) do { checks++; if(!(x)) {fprintf(stderr,"FAIL %d: %s\n",__LINE__,#x);exit(1);} } while(0)
static unsigned checks;
int main(void)
{
    for(unsigned first=0;first<6;first++) {
        struct sptm_panic_state s;sptm_panic_init(&s);
        CHECK(!s.triggered && s.owner==0x8000 && s.phase==0xff);
        for(unsigned cpu=0;cpu<6;cpu++)for(unsigned cmd=0;cmd<7;cmd++)
            CHECK(sptm_panic_dispatch(&s,cpu,(uint64_t)cmd<<56));
        CHECK(sptm_panic_enter(&s,first));
        CHECK(s.triggered==1 && s.owner==first && s.phase==1 && s.entries==1);
        for(unsigned round=0;round<3;round++)for(unsigned cpu=0;cpu<6;cpu++) {
            CHECK(sptm_panic_dispatch(&s,cpu,UINT64_C(0x0200000000000000)));
            CHECK(sptm_panic_enter(&s,cpu));
            CHECK(s.triggered==1 && s.owner==first && s.phase==1);
            for(unsigned cmd=0;cmd<7;cmd++)if(cmd!=2)
                CHECK(!sptm_panic_dispatch(&s,cpu,(uint64_t)cmd<<56));
            CHECK(!sptm_panic_dispatch(&s,cpu,UINT64_C(0x0200000000000001)));
        }
        CHECK(s.entries==19 && s.rejected==126);
        for(unsigned cpu=0;cpu<6;cpu++)CHECK(s.cpu_entries[cpu]==3+(cpu==first));
        struct sptm_panic_state saved=s;
        CHECK(!sptm_panic_enter(&s,6) && !sptm_panic_enter(&s,~0U));
        CHECK(!sptm_panic_dispatch(&s,6,0));
        CHECK(!memcmp(&s,&saved,sizeof(s)));
        s.entries=UINT64_MAX;saved=s;
        CHECK(!sptm_panic_enter(&s,first) && !memcmp(&s,&saved,sizeof(s)));
        sptm_panic_init(&s);CHECK(!s.triggered && s.owner==0x8000 && !s.entries && !s.rejected);
    }
    for(unsigned field=0;field<3;field++) {
        struct sptm_panic_state s;sptm_panic_init(&s);
        if(field==0)s.triggered=2;else if(field==1)s.owner=6;else s.phase=0;
        struct sptm_panic_state saved=s;
        CHECK(!sptm_panic_enter(&s,0) && !sptm_panic_dispatch(&s,0,0));
        CHECK(!memcmp(&s,&saved,sizeof(s)));
    }
    CHECK(!sptm_panic_enter(0,0) && !sptm_panic_dispatch(0,0,0));
    printf("PASS: %u panic flag, first-owner and post-panic refusal checks\n",checks);
}

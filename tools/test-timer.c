/* SPDX-License-Identifier: MIT */
#include "clock.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define CHECK(x) do { checks++; if (!(x)) { fprintf(stderr,"FAIL %d: %s\n",__LINE__,#x); exit(1); } } while(0)
static unsigned checks;
int main(void)
{
    /* The signed relative timer must work near wraparound as well as at zero.
     * Delivery remains level asserted until rearmed, masked or disabled. */
    const uint64_t starts[]={0,100,UINT64_MAX-50,UINT64_C(1)<<63};
    const int32_t intervals[]={INT32_MIN,-1,0,1,10,INT32_MAX};
    for (unsigned s=0;s<4;s++) for(unsigned i=0;i<6;i++) {
        uint64_t now=starts[s], v=(uint64_t)(int64_t)intervals[i];
        struct guest_timer t={0};
        CHECK(guest_timer_access(&t,CLOCK_CNTV_TVAL,0,&v,now)==CLOCK_OK);
        CHECK(t.cval==now+(uint64_t)(int64_t)intervals[i]);
        CHECK(!guest_timer_pending(&t,now));
        for(unsigned ctl=0;ctl<8;ctl++) {
            v=ctl; CHECK(guest_timer_access(&t,CLOCK_CNTV_CTL,0,&v,now)==CLOCK_OK);
            CHECK(t.ctl==(ctl&3));
            uint64_t expected=(ctl&3)|((ctl&1)&&intervals[i]<=0?4:0);
            v=999;CHECK(guest_timer_access(&t,CLOCK_CNTV_CTL,1,&v,now)==CLOCK_OK);
            CHECK(v==expected && guest_timer_pending(&t,now)==(expected==5));
            uint64_t delay=(ctl&3)==1 && intervals[i]>0 && intervals[i]<50 ? (uint32_t)intervals[i]:50;
            CHECK(guest_timer_wait(&t,now,50)==delay);
            CHECK(guest_timer_wait(&t,now,0)==0);
            v=999;CHECK(guest_timer_access(&t,CLOCK_CNTV_TVAL,1,&v,now)==CLOCK_OK);
            CHECK(v==((ctl&1)?(uint32_t)intervals[i]:0));
        }
    }
    struct guest_timer t={0}; uint64_t v=10;
    CHECK(guest_timer_access(&t,CLOCK_CNTV_TVAL,0,&v,100)==CLOCK_OK);
    v=1;CHECK(guest_timer_access(&t,CLOCK_CNTV_CTL,0,&v,100)==CLOCK_OK);
    CHECK(!guest_timer_pending(&t,109)); CHECK(guest_timer_pending(&t,110));
    CHECK(guest_timer_pending(&t,200)); CHECK(guest_timer_wait(&t,200,1000)==1000);
    v=5;CHECK(guest_timer_access(&t,CLOCK_CNTV_CTL,0,&v,200)==CLOCK_OK);
    CHECK(guest_timer_pending(&t,200)); /* Writing ISTATUS cannot acknowledge. */
    v=3;CHECK(guest_timer_access(&t,CLOCK_CNTV_CTL,0,&v,200)==CLOCK_OK);
    CHECK(guest_timer_control(&t,200)==7 && !guest_timer_pending(&t,200));
    v=10;CHECK(guest_timer_access(&t,CLOCK_CNTV_TVAL,0,&v,200)==CLOCK_OK);
    v=1;CHECK(guest_timer_access(&t,CLOCK_CNTV_CTL,0,&v,200)==CLOCK_OK);
    CHECK(!guest_timer_pending(&t,200) && guest_timer_wait(&t,200,100)==10);
    for(unsigned bit=3;bit<64;bit++) {
        struct guest_timer before=t;v=UINT64_C(1)<<bit;
        CHECK(guest_timer_access(&t,CLOCK_CNTV_CTL,0,&v,200)==CLOCK_CONTROL_UNSUPPORTED);
        CHECK(!memcmp(&t,&before,sizeof(t)));
    }
    struct guest_timer before=t;v=123;
    CHECK(guest_timer_access(&t,0,0,&v,200)==CLOCK_UNHANDLED);
    CHECK(!memcmp(&t,&before,sizeof(t)) && v==123);
    CHECK(guest_timer_access(0,CLOCK_CNTV_CTL,0,&v,200)==CLOCK_BACKEND_FAILED);
    CHECK(guest_timer_access(&t,CLOCK_CNTV_CTL,0,0,200)==CLOCK_BACKEND_FAILED);
    struct guest_timer idle={0};
    for(unsigned n=0;n<16;n++) {
        struct guest_timer saved=idle; v=n;
        enum clock_result expected=n&8?CLOCK_CONTROL_UNSUPPORTED:
                                   n&1?CLOCK_TIMER_UNSUPPORTED:CLOCK_OK;
        CHECK(guest_timer_idle_access(&idle,CLOCK_ARCH_CNTP_CTL,0,&v)==expected);
        if(expected!=CLOCK_OK) CHECK(!memcmp(&saved,&idle,sizeof(idle)) && v==n);
        else {
            CHECK(idle.ctl==(n&2) && idle.writes==saved.writes+1);
            CHECK(guest_timer_idle_access(&idle,CLOCK_ARCH_CNTP_CTL,1,&v)==CLOCK_OK);
            CHECK(v==(n&2) && idle.reads==saved.reads+1);
            CHECK(!guest_timer_pending(&idle,UINT64_MAX));
        }
    }
    for(unsigned bit=4;bit<64;bit++) {
        struct guest_timer saved=idle; v=UINT64_C(1)<<bit;
        CHECK(guest_timer_idle_access(&idle,CLOCK_ARCH_CNTP_CTL,0,&v)==CLOCK_CONTROL_UNSUPPORTED);
        CHECK(!memcmp(&saved,&idle,sizeof(idle)));
    }
    CHECK(guest_timer_idle_access(0,CLOCK_ARCH_CNTP_CTL,0,&v)==CLOCK_BACKEND_FAILED);
    CHECK(guest_timer_idle_access(&idle,CLOCK_ARCH_CNTP_CTL,0,0)==CLOCK_BACKEND_FAILED);
    struct guest_timer saved=idle;
    CHECK(guest_timer_idle_access(&idle,CLOCK_CNTV_CTL,0,&v)==CLOCK_UNHANDLED);
    CHECK(!memcmp(&saved,&idle,sizeof(idle)));
    printf("PASS: %u timer checks\n",checks);
}

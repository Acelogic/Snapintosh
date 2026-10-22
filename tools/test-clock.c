/* SPDX-License-Identifier: MIT */
#include "clock.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define CHECK(x) do { checks++; if (!(x)) { fprintf(stderr,"FAIL %d: %s\n",__LINE__,#x); exit(1); } } while(0)
static unsigned checks;
struct fake { uint64_t ticks, control, reads, writes; int fail; };
static uint64_t counter(void *ctx)
{ struct fake *f=ctx; f->reads++; return f->ticks; }
static int control(void *ctx, uint64_t value)
{ struct fake *f=ctx; if (f->fail) return -1; f->control=value; f->writes++; return 0; }
/* round(log2(h/g)) by exact 128-bit comparison of squares: k is the integer
 * with 2^(2k-1) <= (h/g)^2 < 2^(2k+1). Rates below 2^31. */
static int reference_shift(uint64_t h, uint64_t g)
{
    unsigned __int128 H=(unsigned __int128)h*h, G=(unsigned __int128)g*g;
    for (int k=-31; k<=31; k++) {
        int lo=2*k-1, hi=2*k+1;
        int above = lo>=0 ? H>=(G<<lo) : (H<<-lo)>=G;
        int below = hi>=0 ? H<(G<<hi) : (H<<-hi)<G;
        if (above && below) return k<-15 ? -15 : k>15 ? 15 : k;
    }
    return 99;
}
/* SNAP_NATIVE_WFE: the hardware event stream keeps the guest's period to
 * the nearest power of two; every CNTKCTL bit but EVNTI is unchanged. */
static void event_scaling(void)
{
    CHECK(clock_event_shift(19200000,24000000)==0);
    CHECK(clock_event_host_control(0x4f,19200000,24000000)==0x4f);
    CHECK(clock_event_shift(48000000,24000000)==1 && clock_event_shift(12000000,24000000)==-1);
    CHECK(clock_event_shift(1000000000,24000000)==5 && clock_event_shift(24000000,1000000000)==-5);
    /* sqrt(2) * 24 MHz = 33,941,125.5 Hz: the rounding boundary. */
    CHECK(clock_event_shift(33941125,24000000)==0 && clock_event_shift(33941126,24000000)==1);
    CHECK(clock_event_shift(0,24000000)==0 && clock_event_shift(24000000,0)==0);
    CHECK(clock_event_shift(UINT64_C(1)<<32,24000000)==0 && clock_event_shift(1,UINT64_C(1)<<32)==0);
    CHECK(clock_event_shift(UINT32_MAX,1)==15 && clock_event_shift(1,UINT32_MAX)==-15);
    CHECK(clock_event_host_control(0xf4,UINT32_MAX,1)==0xf4 && clock_event_host_control(0x0c,1,UINT32_MAX)==0x0c);
    uint64_t seed=0x243f6a8885a308d3ULL;
    for (unsigned n=0; n<300000; n++) {
        seed^=seed<<13; seed^=seed>>7; seed^=seed<<17;
        uint64_t h=1+(seed&0x7ffffffe)%((seed>>40)%3 ? 0x7ffffffe : 64);
        uint64_t g=1+((seed>>31)&0x7ffffffe)%((seed>>44)%3 ? 0x7ffffffe : 64);
        int want=reference_shift(h,g);
        CHECK(want!=99 && clock_event_shift(h,g)==want);
        uint64_t control=(seed>>8)&0xff;
        int bit=(int)((control>>4)&15)+want;
        bit=bit<0 ? 0 : bit>15 ? 15 : bit;
        CHECK(clock_event_host_control(control,h,g)==((control&~UINT64_C(0xf0))|((uint64_t)bit<<4)));
    }
}

int main(void)
{
    struct guest_clock c={0}; struct fake f={0};
    struct clock_backend b={&f,counter,control}; uint64_t value;
    /* All aliases expose the same time domain, including repeated samples
     * and time advancing without any register access. */
    const uint64_t aliases[]={CLOCK_CNTVCTSS,CLOCK_CNTVCT,
                             CLOCK_ARCH_CNTVCTSS,CLOCK_ARCH_CNTVCT};
    for (unsigned i=0;i<10;i++) {
        f.ticks=(uint64_t)i*19200000;
        for(unsigned j=0;j<4;j++) {
            value=0xdead;
            CHECK(guest_clock_access(&c,&b,aliases[j],1,&value)==CLOCK_OK);
            CHECK(value==f.ticks && c.last==f.ticks && c.first==0);
        }
    }
    CHECK(c.reads==40 && f.reads==40);
    for(unsigned j=0;j<4;j++) {
        struct guest_clock before=c; struct fake host=f; value=123;
        CHECK(guest_clock_access(&c,&b,aliases[j],0,&value)==CLOCK_READ_ONLY);
        CHECK(value==123 && !memcmp(&before,&c,sizeof(c)) && !memcmp(&host,&f,sizeof(f)));
    }
    /* Every supported bit index, direction, permission and enable combination
     * round trips, including disabling a previously enabled stream. */
    for (unsigned v=0;v<256;v++) {
        value=v; CHECK(guest_clock_access(&c,&b,CLOCK_CNTKCTL,0,&value)==CLOCK_OK);
        CHECK(f.control==v && c.cntkctl==v);
        value=0xdead; CHECK(guest_clock_access(&c,&b,CLOCK_CNTKCTL,1,&value)==CLOCK_OK);
        CHECK(value==v);
    }
    CHECK(c.writes==256 && f.writes==256);
    for(unsigned bit=8;bit<64;bit++) {
        struct guest_clock before=c; struct fake host=f;
        value=UINT64_C(1)<<bit;
        CHECK(guest_clock_access(&c,&b,CLOCK_CNTKCTL,0,&value)==CLOCK_CONTROL_UNSUPPORTED);
        CHECK(!memcmp(&before,&c,sizeof(c)) && !memcmp(&host,&f,sizeof(f)));
        CHECK(value==(UINT64_C(1)<<bit));
    }
    const uint64_t refused[]={CLOCK_CNTVCT,CLOCK_CNTVCTSS,CLOCK_CNTV_CTL,CLOCK_CNTV_TVAL,0};
    for(unsigned i=0;i<5;i++) {
        struct guest_clock before=c; struct fake host=f; value=123;
        CHECK(guest_clock_access(&c,&b,refused[i],0,&value)==
              (i<2?CLOCK_READ_ONLY:i<4?CLOCK_TIMER_UNSUPPORTED:CLOCK_UNHANDLED));
        CHECK(value==123 && !memcmp(&before,&c,sizeof(c)) && !memcmp(&host,&f,sizeof(f)));
    }
    f.fail=1; struct guest_clock before=c; struct fake host=f; value=0;
    CHECK(guest_clock_access(&c,&b,CLOCK_CNTKCTL,0,&value)==CLOCK_BACKEND_FAILED);
    CHECK(!memcmp(&before,&c,sizeof(c)) && !memcmp(&host,&f,sizeof(f)));
    b.counter=0;
    CHECK(guest_clock_access(&c,&b,CLOCK_CNTVCT,1,&value)==CLOCK_BACKEND_FAILED);
    CHECK(!memcmp(&before,&c,sizeof(c)));
    CHECK(guest_clock_access(&c,0,CLOCK_CNTVCT,1,&value)==CLOCK_BACKEND_FAILED);
    CHECK(guest_clock_access(0,&b,CLOCK_CNTVCT,1,&value)==CLOCK_BACKEND_FAILED);
    CHECK(guest_clock_access(&c,&b,CLOCK_CNTVCT,1,0)==CLOCK_BACKEND_FAILED);
    event_scaling();
    printf("PASS: %u clock checks\n",checks);
}

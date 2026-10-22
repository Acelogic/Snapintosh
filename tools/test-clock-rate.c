/* SPDX-License-Identifier: MIT */
#include "clock.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define CHECK(x) do { checks++; if (!(x)) { fprintf(stderr,"FAIL %d: %s\n",__LINE__,#x); exit(1); } } while(0)
static unsigned checks;
static uint64_t random_state=0x6ac13b72d958;
static uint64_t next_random(void)
{ random_state^=random_state<<13; random_state^=random_state>>7; random_state^=random_state<<17; return random_state; }
int main(void)
{
    const uint32_t hz[][2]={{19200000,24000000},{24000000,19200000},
        {19200000,19200000},{100000000,24000000},{32768,24000000},
        {1,UINT32_MAX},{UINT32_MAX,1},{UINT32_MAX,UINT32_MAX-1}};
    for(unsigned i=0;i<sizeof(hz)/sizeof(hz[0]);i++) {
        struct clock_rate r;
        CHECK(clock_rate_init(&r,hz[i][0],hz[i][1])==0);
        for(unsigned j=0;j<2000;j++) {
            uint64_t raw=next_random();
            __uint128_t exact=(__uint128_t)raw*r.guest_hz/r.host_hz;
            CHECK(clock_rate_sample(&r,raw)==(uint64_t)exact);
            uint64_t delta=next_random()%1000000000+1;
            uint64_t budget=next_random()%1000000000;
            __uint128_t due=((exact+delta)*r.host_hz+r.guest_hz-1)/r.guest_hz;
            __uint128_t ticks=due-raw;
            uint64_t want=ticks<budget?(uint64_t)ticks:budget;
            CHECK(clock_rate_wait(&r,raw,(uint64_t)exact+delta,budget)==want);
            if (ticks < UINT64_MAX) {
                uint64_t boundary=(uint64_t)ticks;
                CHECK(clock_rate_wait(&r,raw,(uint64_t)exact+delta,boundary)==boundary);
                CHECK(clock_rate_wait(&r,raw,(uint64_t)exact+delta,boundary+1)==boundary);
                if (boundary)
                    CHECK(clock_rate_wait(&r,raw,(uint64_t)exact+delta,boundary-1)==boundary-1);
            }
            CHECK(clock_rate_wait(&r,raw,(uint64_t)exact,budget)==0);
            CHECK(clock_rate_wait(&r,raw,(uint64_t)exact-1,budget)==0);
        }
    }
    struct clock_rate r={3,5}, saved=r;
    struct clock_rate slow={UINT32_MAX,1};
    CHECK(clock_rate_wait(&slow,UINT32_MAX-2,1,5)==2);
    CHECK(clock_rate_wait(&slow,UINT32_MAX-2,1,1)==1);
    CHECK(clock_rate_wait(&slow,1,INT64_MAX,UINT64_MAX)==UINT64_MAX);
    CHECK(clock_rate_init(0,1,1)<0);
    CHECK(clock_rate_init(&r,0,1)<0 && !memcmp(&r,&saved,sizeof(r)));
    CHECK(clock_rate_init(&r,1,0)<0 && !memcmp(&r,&saved,sizeof(r)));
    CHECK(clock_rate_init(&r,1UL<<32,1)<0 && !memcmp(&r,&saved,sizeof(r)));
    CHECK(clock_rate_init(&r,1,1UL<<32)<0 && !memcmp(&r,&saved,sizeof(r)));
    for(unsigned bit=0;bit<16;bit++) for(unsigned direction=0;direction<2;direction++) {
        struct guest_event event={0};
        uint64_t control=4 | direction*8 | bit*16;
        uint64_t now=UINT64_MAX-0x40000, expected=now;
        guest_event_configure(&event,control,now);
        /* Independent reference: find the selected bit edge one tick at a time. */
        do { expected++; } while (((expected>>bit)&1)==(((expected-1)>>bit)&1) ||
                                  ((expected>>bit)&1)==direction);
        CHECK(guest_event_wait(&event,now,UINT64_MAX)==expected-now);
        CHECK(!guest_event_consume(&event,expected-1));
        CHECK(guest_event_consume(&event,expected));
        CHECK(!guest_event_consume(&event,expected));
        uint64_t period=1UL<<(bit+1);
        CHECK(guest_event_wait(&event,expected,UINT64_MAX)==period);
        /* Coalescing, wrapping time, and a pending event surviving disable. */
        now=expected+period*40;
        CHECK(guest_event_wait(&event,now,10)==0);
        guest_event_configure(&event,0,now);
        CHECK(guest_event_consume(&event,now));
        CHECK(!guest_event_consume(&event,now+period));
        CHECK(guest_event_wait(&event,now+period,100)==100);
        guest_event_configure(&event,control,now+period);
        CHECK(guest_event_wait(&event,now+period,1)==1);
    }
    printf("PASS: %u clock rate/event checks\n",checks);
}

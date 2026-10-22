/* SPDX-License-Identifier: MIT */
#include "watchdog.h"
#include "clock.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static unsigned checks;
#define CHECK(x) do { checks++; if (!(x)) { fprintf(stderr, "line %d: %s\n", __LINE__, #x); exit(1); } } while (0)
static void put(struct watchdog_state *s, uint64_t now, uint64_t reg, uint32_t value)
{
    uint64_t v=value;
    CHECK(watchdog_access(s,now,reg,4,1,&v)==WATCHDOG_OK);
}
int main(void)
{
    struct watchdog_state s={0}; uint64_t v=0xdead;
    CHECK(watchdog_access(&s,10,0x1c,4,0,&v)==WATCHDOG_BAD_STATE);
    CHECK(v==0xdead);
    watchdog_init(&s,100);
    CHECK(watchdog_access(&s,110,0x10,4,0,&v)==WATCHDOG_OK && v==10);
    CHECK(watchdog_wait(&s,120,500)==500 && !s.reset);
    put(&s,120,0x10,0); put(&s,120,0x14,100); put(&s,120,0x1c,4);
    CHECK(watchdog_wait(&s,120,500)==100);
    CHECK(watchdog_wait(&s,169,500)==51);
    put(&s,169,0x10,0); /* keepalive moves the deadline */
    CHECK(watchdog_wait(&s,220,500)==49 && !s.reset);
    put(&s,220,0x0c,0); put(&s,220,0x0c,2);
    CHECK(watchdog_access(&s,220,0x0c,4,0,&v)==WATCHDOG_OK && v==0);
    CHECK(watchdog_wait(&s,220,500)==49 && s.control==4 && !s.reset);
    CHECK(watchdog_wait(&s,268,500)==1 && !s.reset);
    CHECK(watchdog_wait(&s,269,500)==0 && s.reset);
    put(&s,269,0x10,0); put(&s,269,0x1c,0);
    CHECK(watchdog_wait(&s,270,500)==0 && s.reset); /* latched */
    watchdog_init(&s,0);
    put(&s,0,0x14,100); put(&s,0,0x1c,4);
    put(&s,99,0x1c,0);
    CHECK(watchdog_wait(&s,200,500)==500 && !s.reset && s.current==200);
    put(&s,200,0x1c,4); /* enabling with current >= bite expires now */
    CHECK(s.reset);
    watchdog_init(&s,0); put(&s,0,0x1c,4); CHECK(s.reset); /* bite zero */
    watchdog_init(&s,0); put(&s,0,0x14,100); put(&s,0,0x1c,4);
    put(&s,20,0x14,10); CHECK(s.reset); /* shortening below current */
    watchdog_init(&s,0); put(&s,0,0x14,100); put(&s,0,0x1c,4);
    put(&s,20,0x10,100); CHECK(s.reset);
    watchdog_init(&s,UINT64_MAX-4); put(&s,UINT64_MAX-4,0x14,20);
    put(&s,UINT64_MAX-4,0x1c,4);
    CHECK(watchdog_wait(&s,5,100)==10 && s.current==10 && !s.reset);
    CHECK(watchdog_wait(&s,15,100)==0 && s.reset);
    watchdog_init(&s,0); put(&s,0,0x14,UINT32_MAX); put(&s,0,0x1c,4);
    CHECK(watchdog_wait(&s,1ULL<<33,500)==0 && s.reset && s.current==0);
    watchdog_init(&s,0);
    CHECK(watchdog_wait(&s,(1ULL<<32)+7,500)==500 && s.current==7 && !s.reset);
    put(&s,(1ULL<<32)+7,0x1c,2); CHECK(s.control==0);
    /* Invalid accesses are atomic, including counter/time state. */
    for (unsigned width=1;width<=8;width*=2) for (unsigned off=0;off<0x40;off++)
        for (unsigned write=0;write<2;write++) {
            if (width==4 && (off==0x0c || off==0x10 || off==0x14 || off==0x1c)) continue;
            struct watchdog_state before=s; v=0;
            CHECK(watchdog_access(&s,(1ULL<<32)+100,off,width,write,&v)!=WATCHDOG_OK);
            CHECK(!memcmp(&s,&before,sizeof(s)) && v==0);
        }
    for (unsigned ctrl=0;ctrl<256;ctrl++) if (ctrl & ~6U) {
        struct watchdog_state before=s; v=ctrl;
        CHECK(watchdog_access(&s,(1ULL<<32)+100,0x1c,4,1,&v)==WATCHDOG_BAD_VALUE);
        CHECK(!memcmp(&s,&before,sizeof(s)) && v==ctrl);
    }
    v=1ULL<<32;
    CHECK(watchdog_access(&s,0,0x10,4,1,&v)==WATCHDOG_BAD_VALUE);
    const uint64_t wd0_bad[]={1,3,4,6,8,UINT64_MAX,1ULL<<32};
    for (unsigned i=0;i<sizeof(wd0_bad)/sizeof(*wd0_bad);i++) {
        struct watchdog_state before=s;v=wd0_bad[i];
        CHECK(watchdog_access(&s,s.last+100,0x0c,4,1,&v)==WATCHDOG_BAD_VALUE);
        CHECK(!memcmp(&s,&before,sizeof(s)) && v==wd0_bad[i]);
    }
    /* Physical wake conversion: every fractional phase must fire at the
     * earliest host tick reaching the watchdog deadline, never after it. */
    struct clock_rate rate; CHECK(!clock_rate_init(&rate,19200000,24000000));
    for (uint64_t raw=0;raw<100;raw++) for (uint32_t bite=1;bite<100;bite++) {
        uint64_t now=clock_rate_sample(&rate,raw);
        watchdog_init(&s,now); put(&s,now,0x14,bite); put(&s,now,0x1c,4);
        uint64_t ticks=watchdog_wait(&s,now,UINT64_MAX);
        uint64_t physical=clock_rate_wait(&rate,raw,now+ticks,1000);
        CHECK(physical>0 && physical<=bite);
        CHECK(watchdog_wait(&s,clock_rate_sample(&rate,raw+physical-1),UINT64_MAX)>0 && !s.reset);
        CHECK(watchdog_wait(&s,clock_rate_sample(&rate,raw+physical),UINT64_MAX)==0 && s.reset);
    }
    printf("PASS: %u watchdog checks\n",checks);
}

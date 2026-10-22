/* SPDX-License-Identifier: MIT
 * Retained sensor words -> production policy -> early stop -> service stop.
 * Failure inventory: docs/A16-THERMAL-GUARD-20261018.md. */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "a16-thermal.h"
#include "early-stop.h"
#include "service-lock.h"
#define CHECK(x) do {if(!(x)){fprintf(stderr,"line %d: %s\n",__LINE__,#x);exit(1);}}while(0)
#define HZ UINT64_C(19200000)
struct bus {uint32_t words[8][19];uint64_t now,reads,fail,slow,step,flick[2],flick_n[2],hot_addr,hot_poll;};
static struct bus baseline;
static struct a16_thermal_state s;
static struct early_stop_state stop;
#define SENSOR(bk,n) (UINT64_C(0xc22c000)+0x1000*(bk)+0xa0+4*(n))
/* Brief VALID clears for flick_n reads of flick[i]; a valid ceiling reading from poll hot_poll. */
#define CEIL (A16_THERMAL_LIMIT_MC/100)
static int mutate(struct bus *b,uint64_t a,uint32_t *v) {
    for(unsigned i=0;i<2;i++)if(a==b->flick[i] && b->flick_n[i]){b->flick_n[i]--;*v&=~(1u<<21);}
    if(a==b->hot_addr && s.polls>=b->hot_poll)*v=(1u<<21)|CEIL;
    return 0;
}
static int read_word(void *ctx,uint64_t a,uint32_t *v) {
    struct bus *b=ctx; b->reads++;
    CHECK(a16_thermal_address_allowed(a));
    if(a==b->fail)return -1;
    for(unsigned i=0;i<8;i++) {
        uint64_t r=0xc222000+0x1000*i,t=0xc22c000+0x1000*i;
        if(a==r){*v=b->words[i][0];return 0;}
        if(a==r+4){*v=b->words[i][1];return 0;}
        if(a==t+0xe4){*v=b->words[i][2];return 0;}
        if(a>=t+0xa0 && a<t+0xe0){*v=b->words[i][3+(a-t-0xa0)/4];return mutate(b,a,v);}
    }
    CHECK(0);return -1;
}
static uint64_t counter(void *ctx) {struct bus *b=ctx;uint64_t t=b->now+b->slow;b->now+=b->step;return t;}
static int step(struct bus *b) {
    struct a16_thermal_io io={b,read_word,counter};
    return a16_thermal_poll(&s,&stop,b->now,HZ,&io);
}
static int admit(struct bus *b) {
    struct a16_thermal_io io={b,read_word,counter};
    return a16_thermal_admit(&s,&stop,HZ,&io);
}
static void admitted(const char *name,int result,uint64_t start,uint64_t end) {
    printf("{\"admit\":\"%s\",\"result\":%d,\"reason\":%llu,\"polls\":%llu,\"invalid_samples\":%llu,\"valid\":%llu,\"elapsed_ticks\":%llu}\n",
           name,result,(unsigned long long)s.reason,(unsigned long long)s.polls,(unsigned long long)s.invalid_samples,
           (unsigned long long)s.valid_count,(unsigned long long)(end-start));
}
static void reset(struct bus *b,uint64_t now) {
    *b=baseline;b->now=now;memset(&s,0,sizeof s);memset(&stop,0,sizeof stop);
    CHECK(!early_stop_request(&stop,EARLY_STOP_SOURCE_GUEST,1,0,1700,1700,now,HZ,0,0,NULL));
}
static void fired(struct bus *b,unsigned reason) {
    CHECK(s.reason==reason && stop.source==EARLY_STOP_SOURCE_THERMAL && stop.accepted_delay==0);
    CHECK(early_stop_fire(&stop,b->now+b->slow,b->now+30*HZ,0));
    struct guest_service_lock lock={0};CHECK(!guest_service_boot(&lock));
    guest_service_stop(&lock,0,SERVICE_STOP_NORMAL);early_stop_finish(&stop,guest_service_stopped(&lock));
    CHECK(stop.outcome==EARLY_STOP_OUTCOME_STOPPED);
    printf("{\"reason\":%u,\"where\":%llu,\"polls\":%llu,\"reads\":%llu,\"stop_outcome\":%llu}\n",reason,(unsigned long long)s.location,(unsigned long long)s.polls,(unsigned long long)s.reads,(unsigned long long)stop.outcome);
}
int main(int argc,char **argv) {
    CHECK(argc==2);FILE *f=fopen(argv[1],"rb");CHECK(f);CHECK(fread(baseline.words,sizeof baseline.words,1,f)==1);CHECK(fgetc(f)==EOF);fclose(f);
    struct bus b;reset(&b,0);CHECK(!step(&b));CHECK(s.ready && s.valid_count==92 && s.peak_mc==35200);
    uint64_t reads=b.reads; b.now=HZ/8;CHECK(!step(&b) && b.reads==reads);
    CHECK(a16_thermal_wait(&s,b.now,HZ,HZ)==HZ/8);
    b.now=HZ/4; b.words[0][3]=(1u<<21)|(CEIL-1);CHECK(!step(&b));CHECK(s.current_mc==A16_THERMAL_LIMIT_MC-100);
    b.now=HZ/2;b.words[0][3]=(1u<<21)|CEIL;CHECK(step(&b));fired(&b,A16_THERMAL_HOT);
    uint64_t fire=stop.fire_ticks;b.now+=HZ;CHECK(step(&b));CHECK(stop.fire_ticks==fire);
    reset(&b,UINT64_MAX-HZ/8);CHECK(!step(&b));b.now+=HZ/4;b.words[7][3]=(1u<<21)|CEIL;CHECK(step(&b));fired(&b,A16_THERMAL_HOT);
    reset(&b,0);CHECK(!step(&b));b.words[0][3]&=~(1u<<21);
    for(int i=1;i<4;i++){b.now=i*HZ/4;CHECK(!step(&b));CHECK(!s.ready);}
    b.now=HZ;CHECK(step(&b));fired(&b,A16_THERMAL_INVALID);
    reset(&b,0);CHECK(!step(&b));b.words[0][3]&=~(1u<<21);b.now=HZ/4;CHECK(!step(&b));b.words[0][3]|=1u<<21;b.now=HZ/2;CHECK(!step(&b) && s.ready);
    reset(&b,0);CHECK(!step(&b));b.now=HZ;CHECK(step(&b));fired(&b,A16_THERMAL_LATE);
    reset(&b,0);b.words[0][0]=0x30020001;CHECK(step(&b));fired(&b,A16_THERMAL_CONFIG);
    for(unsigned bit=0;bit<3;bit++){reset(&b,0);b.words[0][1]^=1u<<(bit==2?21:bit);CHECK(step(&b));fired(&b,A16_THERMAL_CONFIG);}
    reset(&b,0);b.words[0][1]^=1u<<3;CHECK(step(&b));fired(&b,A16_THERMAL_CONFIG);
    reset(&b,0);b.fail=0xc22c000+0xa0;CHECK(step(&b));CHECK(s.location==b.fail);fired(&b,A16_THERMAL_READ);
    reset(&b,0);b.words[0][3]=(1u<<21)|0xff6;CHECK(!step(&b));CHECK((s.raw[0]&0xfff)==0xff6);
    reset(&b,0);b.words[0][3]=(1u<<21)|1201;CHECK(step(&b));fired(&b,A16_THERMAL_RANGE);
    reset(&b,0);b.words[0][3]=(1u<<21)|((4096-401)&0xfff);CHECK(step(&b));fired(&b,A16_THERMAL_RANGE);
    reset(&b,0);b.words[0][3]|=1u<<19;CHECK(step(&b));fired(&b,A16_THERMAL_CRITICAL);
    reset(&b,0);CHECK(!step(&b));for(int i=1;i<40;i++){b.now=i*HZ/4;CHECK(!step(&b));}b.now=10*HZ;CHECK(step(&b));fired(&b,A16_THERMAL_UNCHANGED);
    reset(&b,0);b.slow=HZ/4;CHECK(step(&b));fired(&b,A16_THERMAL_SLOW);
    reset(&b,0);struct a16_thermal_io io={&b,read_word,counter};CHECK(a16_thermal_poll(&s,&stop,0,0,&io));CHECK(!b.reads);
    /* Admission retry (docs/A16-THERMAL-GUARD-20261018.md, 2026-10-19). v73: one
     * brief clear refuses the old single-sample preflight, the retry admits. */
    uint64_t t0;int r;
    reset(&b,0);b.flick[0]=SENSOR(1,3);b.flick_n[0]=1;CHECK(!step(&b));CHECK(!s.ready && s.valid_count==91);
    reset(&b,0);b.step=HZ/1000;b.flick[0]=SENSOR(1,3);b.flick_n[0]=1;t0=b.now;r=admit(&b);admitted("v73-single-clear",r,t0,b.now);
    CHECK(r==0 && s.ready && s.valid_count==92 && s.polls==2 && s.invalid_samples==1 && !s.reason);
    CHECK(s.next_poll==s.last_poll+HZ/4 && stop.source!=EARLY_STOP_SOURCE_THERMAL);
    reset(&b,0);b.step=HZ/1000;b.flick[0]=SENSOR(6,1);b.flick_n[0]=3;b.flick[1]=SENSOR(7,6);b.flick_n[1]=2;t0=b.now;r=admit(&b);admitted("two-sensors",r,t0,b.now);
    CHECK(r==0 && s.ready && s.polls==4 && s.invalid_samples==5);
    /* A sensor that never returns VALID: refuse at the sample bound, then the runtime one-second trip. */
    reset(&b,0);b.step=HZ/1000;b.flick[0]=SENSOR(2,11);b.flick_n[0]=UINT64_MAX;t0=b.now;r=admit(&b);admitted("never-valid",r,t0,b.now);
    CHECK(r==-1 && !s.ready && s.polls==A16_THERMAL_ADMIT_SAMPLES && !s.reason && s.last_poll-t0<HZ/2);
    b.step=0;b.now=s.started+HZ;CHECK(step(&b));CHECK(s.location==SENSOR(2,11));fired(&b,A16_THERMAL_INVALID);
    reset(&b,0);b.step=HZ/20;b.flick[0]=SENSOR(2,11);b.flick_n[0]=UINT64_MAX;t0=b.now;r=admit(&b);admitted("time-bound",r,t0,b.now);
    CHECK(r==-1 && s.polls>=2 && s.polls<A16_THERMAL_ADMIT_SAMPLES && s.last_poll-t0<HZ/2 && !s.reason);
    reset(&b,0);b.flick[0]=SENSOR(2,11);b.flick_n[0]=UINT64_MAX;r=admit(&b);admitted("stuck-counter",r,0,b.now);
    CHECK(r==-1 && s.polls==A16_THERMAL_ADMIT_SAMPLES);
    /* Every attempt is the full policy: a hot second sample trips, it is not retried. */
    reset(&b,0);b.step=HZ/1000;b.flick[0]=SENSOR(1,3);b.flick_n[0]=1;b.hot_addr=SENSOR(0,0);b.hot_poll=2;t0=b.now;r=admit(&b);admitted("hot-retry",r,t0,b.now);
    CHECK(r==1 && s.polls==2);fired(&b,A16_THERMAL_HOT);
    /* A complete sample not yet due admits without MMIO; a partial one is resampled. */
    reset(&b,0);CHECK(!step(&b) && s.ready);reads=b.reads;b.now=HZ/8;CHECK(!admit(&b) && b.reads==reads && s.polls==1);
    reset(&b,0);b.flick[0]=SENSOR(1,3);b.flick_n[0]=1;CHECK(!step(&b) && !s.ready);b.now=HZ/8;b.step=HZ/1000;
    CHECK(!admit(&b) && s.ready && s.polls==2 && s.next_poll==s.last_poll+HZ/4);
    /* Long preparation is not exempt from the gap policy. */
    reset(&b,0);CHECK(!step(&b));b.now=HZ;r=admit(&b);CHECK(r==1);fired(&b,A16_THERMAL_LATE);
    reset(&b,UINT64_MAX-HZ/100);b.step=HZ/1000;b.flick[0]=SENSOR(0,0);b.flick_n[0]=2;t0=b.now;r=admit(&b);admitted("counter-wrap",r,t0,b.now);
    CHECK(r==0 && s.ready && s.polls==3);
    reset(&b,0);io=(struct a16_thermal_io){&b,read_word,counter};CHECK(a16_thermal_admit(&s,&stop,0,&io)==1 && !b.reads && s.reason==A16_THERMAL_CLOCK);
    reset(&b,0);CHECK(a16_thermal_admit(&s,&stop,HZ,NULL)==1 && s.reason==A16_THERMAL_CONFIG && !b.reads);
    CHECK(!a16_thermal_address_allowed(0xc22c00c));
    puts("PASS: production thermal-to-service-stop replay");return 0;
}

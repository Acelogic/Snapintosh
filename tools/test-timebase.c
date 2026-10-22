/* SPDX-License-Identifier: MIT */
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "device.h"
#include "clock.h"

static unsigned checks;
#define CHECK(x) do { assert(x); checks++; } while (0)
static struct device_state state, before;
static uint64_t read_half(const struct device_model *d, uint64_t now, unsigned off)
{
    uint64_t v=UINT64_MAX;
    CHECK(device_model_access_at(d,&state,now,off,4,0,&v)==DEVICE_OK);
    return v;
}
int main(void)
{
    struct device_model d={DEVICE_AOP_TIMEBASE_V1,0x3082a8000UL,0x1000,{24000000}};
    CHECK(device_models_valid(&d,1,0,0));
    CHECK(device_model_start(&d,&state,123,24000000)==DEVICE_OK);
    CHECK(device_model_start(&d,&state,123,19200000)==DEVICE_BAD_CONFIG);
    uint64_t v=42;
    CHECK(device_model_access_state(&d,&state,0,4,0,&v)==DEVICE_BAD_CONFIG && v==42);
    CHECK(device_model_access_at(&d,0,1,0,4,0,&v)==DEVICE_BAD_CONFIG);
    CHECK(device_model_access_at(&d,&state,1,0,4,0,0)==DEVICE_BAD_CONFIG);
    struct clock_rate rate;
    CHECK(clock_rate_init(&rate,19200000,24000000)==0);
    /* Same-domain timestamps agree at arbitrary elapsed times; repeat reads
     * do not increment the peripheral counter or mutate shared device state. */
    const uint64_t samples[]={0,1,0xffffffffUL,0x100000000UL,UINT64_MAX};
    for (unsigned i=0; i<sizeof(samples)/sizeof(samples[0]); i++) {
        uint64_t t=samples[i];
        CHECK((read_half(&d,t,4)<<32 | read_half(&d,t,0))==t);
        CHECK(read_half(&d,t,0)==(uint32_t)t);
    }
    for (uint64_t t=0; t<192000000; t+=123457) {
        uint64_t now=clock_rate_sample(&rate,t);
        CHECK((read_half(&d,now,4)<<32 | read_half(&d,now,0))==now);
    }
    /* A rollover between the first high and the low must be detectable.
     * A retry produces the new epoch, rather than a stale latched half. */
    uint64_t hi=read_half(&d,0xffffffffUL,4), lo=read_half(&d,0x100000000UL,0);
    uint64_t again=read_half(&d,0x100000001UL,4);
    CHECK(hi!=again && lo==0);
    CHECK((read_half(&d,0x100000001UL,4)<<32 | read_half(&d,0x100000002UL,0))==0x100000002UL);
    before=state;
    for (unsigned off=0; off<0x1000; off+=4) {
        v=42;
        CHECK(device_model_access_at(&d,&state,9,off,4,1,&v)==
              (off<8 ? DEVICE_READ_ONLY : DEVICE_UNKNOWN_REGISTER));
        CHECK(v==42 && !memcmp(&state,&before,sizeof(state)));
        if (off>=8) CHECK(device_model_access_at(&d,&state,9,off,4,0,&v)==DEVICE_UNKNOWN_REGISTER && v==42);
    }
    for (unsigned width=0; width<=16; width++) if (width!=4) {
        CHECK(device_model_access_at(&d,&state,9,0,width,0,&v)==DEVICE_BAD_WIDTH);
        CHECK(v==42);
    }
    CHECK(device_model_access_at(&d,&state,9,1,4,0,&v)==DEVICE_BAD_WIDTH);
    CHECK(device_model_access_at(&d,&state,9,0x1000,4,0,&v)==DEVICE_NOT_FOUND);
    CHECK(device_model_wait(&d,&state,0,777)==777 && !device_reset_pending(&d,&state));
    for (unsigned i=0; i<5; i++) {
        struct device_model bad=d;bad.config[i]++;
        CHECK(!device_models_valid(&bad,1,0,0));
    }
    d.span=0x2000;
    CHECK(!device_models_valid(&d,1,0,0));
    printf("PASS: %u AOP timebase checks\n",checks);
}

/* SPDX-License-Identifier: MIT */
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "device.h"
static unsigned checks;
#define CHECK(x) do { assert(x); checks++; } while (0)
static struct device_state states[4], before;
int main(void)
{
    const uint32_t offsets[]={0x7a0,0x38014,0x13c10,0x13c14,0x13c18,0x13c1c,
        0x13c20,0x13c28,0x13c2c,0x13c00,0x18400,0x20400,0x38050,0x13c24,0x48};
    const uint32_t enabled[]={0x6c0400,0x1111,0xffffffff,0xffffffff,0xffffffff,
        0xffffffff,0xffffffff,0xff,0xff,1,1,1,1,0xffff,1};
    const uint32_t gaps[]={0x7a8,0x38010,0x13c38,0x13c3c,0x13c40,0x13c44,
        0x13c48,0x13c50,0x13c54,0x13c04,0x18404,0x20404,0x38054,0x13c4c,0x4c};
    for (unsigned bank=0; bank<4; bank++) {
        struct device_model d={DEVICE_MCC_DCS_COHERENT_V1,0x220400000UL+bank*0x200000,
                               0x39000,{0,0,0,0,0}};
        CHECK(device_models_valid(&d,1,0,0));
        for (unsigned i=0; i<15; i++) {
            uint64_t v=42;
            CHECK(device_model_access_state(&d,&states[bank],offsets[i],4,0,&v)==DEVICE_OK && v==0);
            v=enabled[i] & ~(i==0 ? 0xc0800400U : 0);
            uint64_t want=v;
            CHECK(device_model_access_state(&d,&states[bank],offsets[i],4,1,&v)==DEVICE_OK);
            v=0;
            CHECK(device_model_access_state(&d,&states[bank],offsets[i],4,0,&v)==DEVICE_OK && v==want);
            before=states[bank];v=1UL<<32;
            CHECK(device_model_access_state(&d,&states[bank],offsets[i],4,1,&v)==DEVICE_BAD_VALUE);
            CHECK(!memcmp(&before,&states[bank],sizeof(before)) && v==1UL<<32);
            CHECK(device_model_access_state(&d,&states[bank],offsets[i],8,0,&v)==DEVICE_BAD_WIDTH);
            CHECK(device_model_access_state(&d,&states[bank],gaps[i],4,0,&v)==DEVICE_UNKNOWN_REGISTER);
            CHECK(v==1UL<<32);
        }
        for (unsigned i=0; i<15; i++) {
            uint64_t v=0;
            CHECK(device_model_access_state(&d,&states[bank],offsets[i],4,0,&v)==DEVICE_OK &&
                  v==(enabled[i] & ~(i==0 ? 0xc0800400U : 0)));
        }
    }
    /* SOCNI report mask pairs: distinct values prove that every modeled
     * word survives neighboring writes; gaps/status registers stay refused. */
    const unsigned starts[]={0x1800,0x1a00,0x1400,0x2400,0x2000,0x1c00};
    const unsigned ends[]={0x18c8,0x1ac8,0x14c8,0x24c8,0x20b8,0x1cb0};
    const unsigned strides[]={100,100,100,100,92,88};
    for (unsigned bank=0; bank<6; bank++) {
        struct device_model d={DEVICE_SOCNI_ERRORS_V1,0x100000,0x4000,{bank,0,0,0,0}};
        memset(states,0,sizeof(states));
        CHECK(device_models_valid(&d,1,0,0));
        for (unsigned off=0; off<0x4000; off+=4) {
            unsigned local=(off-starts[bank])%strides[bank];
            int allowed=off>=starts[bank] && off<ends[bank] &&
                !(bank<4 && (local==44 || local==52)) &&
                !(bank==4 && local==48) && !(bank==5 && local==44);
            uint64_t value=0xdeadbeef;
            CHECK(device_model_access_state(&d,&states[0],off,4,0,&value)==
                  (allowed ? DEVICE_OK : DEVICE_UNKNOWN_REGISTER));
            CHECK(value==(allowed ? 0 : 0xdeadbeef));
            value=0x98760000+off;
            CHECK(device_model_access_state(&d,&states[0],off,4,1,&value)==
                  (allowed ? DEVICE_OK : DEVICE_UNKNOWN_REGISTER));
            if (allowed) {
                before=states[0];value=1UL<<32;
                CHECK(device_model_access_state(&d,&states[0],off,4,1,&value)==DEVICE_BAD_VALUE);
                CHECK(!memcmp(&before,&states[0],sizeof(before)));
                CHECK(device_model_access_state(&d,&states[0],off,8,0,&value)==DEVICE_BAD_WIDTH);
            }
        }
        for (unsigned off=starts[bank]; off<ends[bank]; off+=4) {
            uint64_t value=0;
            if (device_model_access_state(&d,&states[0],off,4,0,&value)==DEVICE_OK)
                CHECK(value==0x98760000+off);
        }
        uint64_t v=5;d.config[0]=6;
        CHECK(device_model_access_state(&d,&states[0],0,4,0,&v)==DEVICE_BAD_CONFIG && v==5);
        d.config[0]=bank;d.config[1]=1;
        CHECK(device_model_access_state(&d,&states[0],0,4,0,&v)==DEVICE_BAD_CONFIG && v==5);
    }
    struct device_model policies[2]={
        {DEVICE_PLATFORM_ERROR_POLICY_V1,0x25300a000UL,0x1000,{0x104,1,0,0,0}},
        {DEVICE_PLATFORM_ERROR_POLICY_V1,0x254000000UL,0x20000,{0x4084,0,0,0,0}}};
    CHECK(device_models_valid(policies,2,0,0));
    memset(states,0,sizeof(states));
    for (unsigned i=0; i<2; i++) {
        struct device_model *d=&policies[i];
        for (unsigned off=0; off<d->span; off+=4) {
            uint64_t v=0x12345678;
            int allow=off==d->config[0];
            CHECK(device_model_access_state(d,&states[i],off,4,1,&v)==
                  (allow ? DEVICE_OK : DEVICE_UNKNOWN_REGISTER));
            v=0xdeadbeef;
            CHECK(device_model_access_state(d,&states[i],off,4,0,&v)==
                  (allow && !i ? DEVICE_UNKNOWN_REGISTER : allow ? DEVICE_OK : DEVICE_UNKNOWN_REGISTER));
            CHECK(v==(allow && i ? 0x12345678 : 0xdeadbeef));
        }
        CHECK(states[i].platform_error_policy==0x12345678);
        uint64_t v=0xffffffff;
        CHECK(device_model_access_state(d,&states[i],d->config[0],4,1,&v)==DEVICE_OK);
        v=1UL<<32;before=states[i];
        CHECK(device_model_access_state(d,&states[i],d->config[0],4,1,&v)==DEVICE_BAD_VALUE);
        CHECK(!memcmp(&before,&states[i],sizeof(before)));
        for (unsigned width=1; width<=8; width*=2) if (width!=4)
            CHECK(device_model_access_state(d,&states[i],d->config[0],width,1,&v)==DEVICE_BAD_WIDTH);
        d->config[2]=1;
        CHECK(device_model_access_state(d,&states[i],d->config[0],4,1,&v)==DEVICE_BAD_CONFIG);
        d->config[2]=0;
    }
    printf("PASS: %u DCS/SOCNI/platform error policy and refusal checks\n",checks);
}

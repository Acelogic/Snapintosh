/* SPDX-License-Identifier: MIT */
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "device.h"
static unsigned checks;
#define CHECK(x) do { checks++; assert(x); } while (0)
static struct device_state state, saved;

int main(void)
{
    struct device_model model={DEVICE_WATCHDOG_SMC_DISARM_V1,0x3082b8000UL,0x1000,{8}};
    CHECK(device_models_valid(&model,1,0,0));
    memset(&state,0xa5,sizeof(state));
    CHECK(device_model_start(&model,&state,0,24000000)==DEVICE_OK);
    CHECK(state.watchdog_smc_disarms==0);
    saved=state;
    /* Reproduce native start's str wzr and the named disarm method. */
    uint64_t value=0;
    for (unsigned i=1;i<=3;i++) {
        CHECK(device_model_access_state(&model,&state,8,4,1,&value)==DEVICE_OK);
        saved.watchdog_smc_disarms=i;
        CHECK(value==0 && !memcmp(&state,&saved,sizeof(state)));
        CHECK(!device_reset_pending(&model,&state));
    }
    /* An unsupported timer must never silently accept an arm or expire request. */
    for (unsigned bit=0;bit<64;bit++) {
        value=1UL<<bit;
        CHECK(device_model_access_state(&model,&state,8,4,1,&value)==DEVICE_BAD_VALUE);
        CHECK(value==(1UL<<bit) && !memcmp(&state,&saved,sizeof(state)));
    }
    for (unsigned off=0;off<0x1000;off+=4) {
        value=0;
        CHECK(device_model_access_state(&model,&state,off,4,0,&value)==DEVICE_UNKNOWN_REGISTER);
        if (off!=8) CHECK(device_model_access_state(&model,&state,off,4,1,&value)==DEVICE_UNKNOWN_REGISTER);
        CHECK(!memcmp(&state,&saved,sizeof(state)));
    }
    for (unsigned width=0;width<=16;width++) if (width!=4) {
        CHECK(device_model_access_state(&model,&state,8,width,1,&value)==DEVICE_BAD_WIDTH);
        CHECK(!memcmp(&state,&saved,sizeof(state)));
    }
    for (unsigned off=9;off<12;off++)
        CHECK(device_model_access_state(&model,&state,off,4,1,&value)==DEVICE_BAD_WIDTH);
    CHECK(device_model_access_state(&model,0,8,4,1,&value)==DEVICE_BAD_CONFIG);
    state.watchdog_smc_disarms=UINT32_MAX;
    CHECK(device_model_access_state(&model,&state,8,4,1,&value)==DEVICE_OK);
    CHECK(state.watchdog_smc_disarms==UINT32_MAX);
    for (unsigned i=0;i<5;i++) {
        struct device_model bad=model;bad.config[i]++;
        CHECK(!device_models_valid(&bad,1,0,0));
    }
    struct device_model bad=model;bad.span=0x4000;
    CHECK(!device_models_valid(&bad,1,0,0));
    CHECK(device_model_start(&model,&state,123,24000000)==DEVICE_OK);
    CHECK(state.watchdog_smc_disarms==0);
    printf("PASS: %u SMC watchdog disarm checks\n",checks);
}

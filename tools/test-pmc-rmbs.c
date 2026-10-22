/* SPDX-License-Identifier: MIT */
/* RMBS request submission never creates guest readback or completion. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "device.h"
static unsigned checks;
#define CHECK(x) do { checks++; if (!(x)) { \
    fprintf(stderr,"line %u: %s\n",__LINE__,#x); exit(1); } } while (0)
static struct device_state state,saved,other;
static const struct device_model model={DEVICE_PMC_RMBS_REQUEST_V1,
    0x302860000,0x1000,{0,0,0,0,0}};
static enum device_result access_word(unsigned off,unsigned width,int write,uint64_t *v)
{
    return device_model_access_state(&model,&state,off,width,write,v);
}
int main(void)
{
    CHECK(device_models_valid(&model,1,0,0));
    CHECK(device_model_start(&model,&state,0,24000000)==DEVICE_OK);
    CHECK(!state.pmc_rmbs.valid && !state.pmc_rmbs.value);
    const uint64_t candidates[]={UINT32_MAX,UINT32_MAX,0,1,0xaaaaaaaa,0x55555555,
        0x80000000,0x7fffffff,UINT64_MAX,1UL<<32};
    for (unsigned i=0;i<sizeof(candidates)/sizeof(candidates[0])+64;i++) {
        unsigned n=sizeof(candidates)/sizeof(candidates[0]);
        uint64_t v=i<n ? candidates[i] : 1UL<<(i-n),input=v;saved=state;
        int valid=v<=UINT32_MAX;
        CHECK(access_word(0,4,1,&v)==(valid ? DEVICE_OK : DEVICE_BAD_VALUE));
        if (valid) { saved.pmc_rmbs.value=(uint32_t)v;saved.pmc_rmbs.valid=1; }
        CHECK(v==input && !memcmp(&state,&saved,sizeof(state)));
    }
    for (unsigned off=0;off<0x1000;off+=4) {
        uint64_t v=0x13579bdf;saved=state;
        CHECK(access_word(off,4,0,&v)==DEVICE_UNKNOWN_REGISTER);
        CHECK(v==0x13579bdf && !memcmp(&state,&saved,sizeof(state)));
        if (off) {
            CHECK(access_word(off,4,1,&v)==DEVICE_UNKNOWN_REGISTER);
            CHECK(v==0x13579bdf && !memcmp(&state,&saved,sizeof(state)));
        }
    }
    for (unsigned width=1;width<=16;width*=2) {
        if (width==4) continue;
        for (int write=0;write<=1;write++) {
            uint64_t v=1;saved=state;
            CHECK(access_word(0,width,write,&v)==DEVICE_BAD_WIDTH);
            CHECK(v==1 && !memcmp(&state,&saved,sizeof(state)));
        }
    }
    for (unsigned delta=1;delta<=3;delta++) for (int write=0;write<=1;write++) {
        uint64_t v=1;saved=state;
        CHECK(access_word(delta,4,write,&v)==DEVICE_BAD_WIDTH);
        CHECK(v==1 && !memcmp(&state,&saved,sizeof(state)));
    }
    CHECK(device_model_start(&model,&other,0,24000000)==DEVICE_OK);
    uint64_t v=UINT32_MAX;CHECK(access_word(0,4,1,&v)==DEVICE_OK);
    CHECK(state.pmc_rmbs.valid==1 && state.pmc_rmbs.value==UINT32_MAX);
    CHECK(!other.pmc_rmbs.valid && !other.pmc_rmbs.value);
    saved=state;
    CHECK(access_word(0x1000,4,1,&v)==DEVICE_NOT_FOUND);
    CHECK(device_model_access_state(&model,0,0,4,1,&v)==DEVICE_BAD_CONFIG);
    CHECK(device_model_access_state(&model,&state,0,4,1,0)==DEVICE_BAD_CONFIG);
    for (unsigned i=0;i<5;i++) {
        struct device_model bad=model;bad.config[i]=1;
        CHECK(!device_models_valid(&bad,1,0,0));
        CHECK(device_model_start(&bad,&state,0,24000000)==DEVICE_BAD_CONFIG);
        CHECK(device_model_access_state(&bad,&state,0,4,1,&v)==DEVICE_BAD_CONFIG);
        CHECK(!memcmp(&state,&saved,sizeof(state)));
    }
    struct device_model bad=model;bad.span=0x4000;
    CHECK(!device_models_valid(&bad,1,0,0));
    state.dram_policy=0xfeed;state.pmgr_policy[2]=0xfeedbeef;saved=state;
    saved.pmc_rmbs.value=saved.pmc_rmbs.valid=0;
    CHECK(device_model_start(&model,&state,123,24000000)==DEVICE_OK);
    CHECK(!memcmp(&state,&saved,sizeof(state)));
    printf("PMC RMBS request: %u checks passed\n",checks);
    return 0;
}

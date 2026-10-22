/* SPDX-License-Identifier: MIT */
/* Replay the stock DVMR read/modify/write, idle wait, readback and count. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "device.h"
static unsigned checks;
#define CHECK(x) do { checks++; if (!(x)) { \
    fprintf(stderr,"line %u: %s\n",__LINE__,#x); exit(1); } } while (0)
static struct device_state state,saved,other;
static const struct device_model model={DEVICE_PMC_DVMR_CONFIG_V1,
    0x3028a4000,0x6000,{0,0,0,0,0}};
static enum device_result access_word(unsigned off,unsigned width,int write,uint64_t *v)
{
    return device_model_access_state(&model,&state,off,width,write,v);
}
int main(int argc,char **argv)
{
    CHECK(device_models_valid(&model,1,0,0));
    CHECK(device_model_start(&model,&state,0,24000000)==DEVICE_OK);
    if (argc==2 && !strcmp(argv[1],"--mask")) {
        uint64_t mask=0;
        for (unsigned bit=0;bit<64;bit++) {
            uint64_t v=1UL<<bit;
            if (access_word(0,4,1,&v)==DEVICE_OK) mask|=v;
        }
        printf("%llu\n",(unsigned long long)mask);
        return 0;
    }
    uint64_t v=UINT64_MAX;
    CHECK(access_word(0,4,0,&v)==DEVICE_OK && v==0);
    CHECK(access_word(0x20,4,0,&v)==DEVICE_OK && v==0);
    CHECK(!state.pmc_dvmr.count_valid);
    /* Each agent independently enters/leaves every previous enable set.
     * Count writes are tied to the actual configured mask, not echoed. */
    for (unsigned previous=0;previous<4;previous++) {
        for (unsigned agent=0;agent<2;agent++) for (unsigned on=0;on<2;on++) {
            v=previous;CHECK(access_word(0,4,1,&v)==DEVICE_OK);
            CHECK(access_word(0,4,0,&v)==DEVICE_OK && v==previous);
            unsigned expected=(previous&~(1U<<agent))|(on<<agent);
            v=expected;saved=state;
            CHECK(access_word(0,4,1,&v)==DEVICE_OK);
            saved.pmc_dvmr.enabled=expected;saved.pmc_dvmr.count_valid=0;
            CHECK(!memcmp(&state,&saved,sizeof(state)));
            CHECK(access_word(0x20,4,0,&v)==DEVICE_OK && !(v&1));
            CHECK(access_word(0,4,0,&v)==DEVICE_OK && v==expected);
            unsigned count=(expected&1)+((expected>>1)&1);
            for (unsigned wrong=0;wrong<4;wrong++) {
                if (wrong==count) continue;
                v=wrong;saved=state;
                CHECK(access_word(0x5c14,4,1,&v)==DEVICE_BAD_VALUE);
                CHECK(v==wrong && !memcmp(&state,&saved,sizeof(state)));
            }
            v=count;saved=state;
            CHECK(access_word(0x5c14,4,1,&v)==DEVICE_OK);
            saved.pmc_dvmr.count=count;saved.pmc_dvmr.count_valid=1;
            CHECK(!memcmp(&state,&saved,sizeof(state)));
        }
    }
    for (unsigned bit=0;bit<64;bit++) {
        uint64_t input=1UL<<bit;v=input;saved=state;
        if (bit>=2) {
            CHECK(access_word(0,4,1,&v)==DEVICE_BAD_VALUE);
            CHECK(v==input && !memcmp(&state,&saved,sizeof(state)));
        }
        if (input!=state.pmc_dvmr.count) {
            CHECK(access_word(0x5c14,4,1,&v)==DEVICE_BAD_VALUE);
            CHECK(v==input && !memcmp(&state,&saved,sizeof(state)));
        }
    }
    for (unsigned off=0;off<0x6000;off+=4) for (int write=0;write<=1;write++) {
        if (!off || (off==0x20 && !write) || (off==0x5c14 && write) ||
            off==0x5c18 || (off==0x5c1c && !write)) continue;
        v=0x13579bdf;saved=state;
        CHECK(access_word(off,4,write,&v)==DEVICE_UNKNOWN_REGISTER);
        CHECK(v==0x13579bdf && !memcmp(&state,&saved,sizeof(state)));
    }
    const unsigned offsets[]={0,0x20,0x5c14};
    for (unsigned i=0;i<3;i++) {
        for (unsigned width=1;width<=16;width*=2) for (int write=0;write<=1;write++) {
            if (width==4) continue;
            v=1;saved=state;
            CHECK(access_word(offsets[i],width,write,&v)==DEVICE_BAD_WIDTH);
            CHECK(v==1 && !memcmp(&state,&saved,sizeof(state)));
        }
        for (unsigned delta=1;delta<=3;delta++) for (int write=0;write<=1;write++) {
            v=1;saved=state;
            CHECK(access_word(offsets[i]+delta,4,write,&v)==DEVICE_BAD_WIDTH);
            CHECK(v==1 && !memcmp(&state,&saved,sizeof(state)));
        }
    }
    CHECK(device_model_start(&model,&other,0,24000000)==DEVICE_OK);
    CHECK(!other.pmc_dvmr.enabled && !other.pmc_dvmr.count && !other.pmc_dvmr.count_valid);
    v=1;saved=state;
    CHECK(access_word(0x6000,4,1,&v)==DEVICE_NOT_FOUND);
    CHECK(device_model_access_state(&model,0,0,4,1,&v)==DEVICE_BAD_CONFIG);
    CHECK(device_model_access_state(&model,&state,0,4,1,0)==DEVICE_BAD_CONFIG);
    for (unsigned i=0;i<5;i++) {
        struct device_model bad=model;bad.config[i]=1;
        CHECK(!device_models_valid(&bad,1,0,0));
        CHECK(device_model_start(&bad,&state,0,24000000)==DEVICE_BAD_CONFIG);
        CHECK(device_model_access_state(&bad,&state,0,4,1,&v)==DEVICE_BAD_CONFIG);
        CHECK(!memcmp(&state,&saved,sizeof(state)));
    }
    struct device_model bad=model;bad.span=0x1000;
    CHECK(!device_models_valid(&bad,1,0,0));
    state.dram_policy=0xfeed;state.pmgr_policy[2]=0xfeedbeef;saved=state;
    saved.pmc_dvmr.enabled=saved.pmc_dvmr.count=saved.pmc_dvmr.count_valid=0;
    saved.pmc_dvmr.venc_cluster=8;
    CHECK(device_model_start(&model,&state,123,24000000)==DEVICE_OK);
    CHECK(!memcmp(&state,&saved,sizeof(state)));
    printf("PMC DVMR configuration: %u checks passed\n",checks);
    return 0;
}

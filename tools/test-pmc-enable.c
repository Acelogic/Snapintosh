/* SPDX-License-Identifier: MIT */
/* Voter/RMBS/boost/BWR enables, separate from votes and completion. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "device.h"
static unsigned checks;
#define CHECK(x) do { checks++; if (!(x)) { \
    fprintf(stderr,"line %u: %s\n",__LINE__,#x); exit(1); } } while (0)
static struct device_state state,saved,other;
static const struct device_model model={DEVICE_PMC_ENABLE_POLICY_V1,
    0x3028ac000,0x1000,{0,0,0,0,0}};
static const unsigned offsets[]={0,4,8,12,0x24,0x28,0x20};
static const unsigned masks[]={15,15,15,15,3,0x3f,7};
static enum device_result access_word(unsigned off,unsigned width,int write,uint64_t *v)
{
    return device_model_access_state(&model,&state,off,width,write,v);
}
int main(int argc,char **argv)
{
    CHECK(device_models_valid(&model,1,0,0));
    CHECK(device_model_start(&model,&state,0,24000000)==DEVICE_OK);
    if (argc==2 && !strcmp(argv[1],"--masks")) {
        for (unsigned off=0;off<0x1000;off+=4) {
            uint64_t v=0,mask=0;
            if (access_word(off,4,0,&v)!=DEVICE_OK) continue;
            for (unsigned bit=0;bit<64;bit++) {
                v=1UL<<bit;
                if (access_word(off,4,1,&v)==DEVICE_OK) mask|=1UL<<bit;
            }
            printf("%u %llu\n",off,(unsigned long long)mask);
        }
        return 0;
    }
    /* restorePMC enables static PMP, CLPC, AP (bits 0, 1, 3) on all four
     * rails. Each read/modify/write must preserve previous voters/rails. */
    const unsigned static_bits[]={0,1,3};
    for (unsigned pass=0;pass<2;pass++) for (unsigned voter=0;voter<3;voter++) {
        for (unsigned rail=0;rail<4;rail++) {
            uint64_t v=UINT64_MAX;saved=state;
            CHECK(access_word(4*rail,4,0,&v)==DEVICE_OK);
            v|=1U<<static_bits[voter];
            CHECK(access_word(4*rail,4,1,&v)==DEVICE_OK);
            saved.pmc_enable[rail]|=1U<<static_bits[voter];
            CHECK(!memcmp(&state,&saved,sizeof(state)));
        }
    }
    for (unsigned rail=0;rail<4;rail++) CHECK(state.pmc_enable[rail]==0xb);
    uint64_t v=UINT64_MAX;
    CHECK(access_word(0x24,4,0,&v)==DEVICE_OK && v==0);
    v=(v&~3UL)|3;
    CHECK(access_word(0x24,4,1,&v)==DEVICE_OK);
    CHECK(access_word(0x24,4,0,&v)==DEVICE_OK && v==3);
    /* The stopped ANS stateChange enables boost bit 4. Independent
     * DISPEXT0 BWR bit 2 and later boost bits must preserve prior state. */
    v=0;
    CHECK(access_word(0x28,4,0,&v)==DEVICE_OK && v==0);
    v|=1U<<4;
    CHECK(access_word(0x28,4,1,&v)==DEVICE_OK);
    v=1U<<2;
    CHECK(access_word(0x20,4,1,&v)==DEVICE_OK);
    CHECK(access_word(0x28,4,0,&v)==DEVICE_OK && v==0x10);
    v|=1U<<2;
    CHECK(access_word(0x28,4,1,&v)==DEVICE_OK);
    CHECK(access_word(0x20,4,0,&v)==DEVICE_OK && v==4);
    CHECK(state.pmc_enable[4]==3 && state.pmc_enable[5]==0x14);
    unsigned words=0;
    for (unsigned off=0;off<0x1000;off+=4) {
        int index=-1;
        for (unsigned i=0;i<7;i++) if (off==offsets[i]) index=(int)i;
        v=0x13579bdf;saved=state;
        if (index<0) {
            for (int write=0;write<=1;write++) {
                CHECK(access_word(off,4,write,&v)==DEVICE_UNKNOWN_REGISTER);
                CHECK(v==0x13579bdf && !memcmp(&state,&saved,sizeof(state)));
            }
            continue;
        }
        words++;unsigned mask=masks[index];
        /* Every combination includes individual enable/disable, dynamic
         * GFX bit 2 and mixed settings. No vote data is produced. */
        for (unsigned pattern=0;pattern<=mask;pattern++) {
            v=pattern;saved=state;
            CHECK(access_word(off,4,1,&v)==DEVICE_OK);
            saved.pmc_enable[index]=pattern;
            CHECK(!memcmp(&state,&saved,sizeof(state)));
            v=UINT64_MAX;
            CHECK(access_word(off,4,0,&v)==DEVICE_OK && v==pattern);
        }
        for (unsigned bit=0;bit<64;bit++) {
            v=1UL<<bit;if (!(v&~(uint64_t)mask)) continue;
            v|=mask;uint64_t input=v;saved=state;
            CHECK(access_word(off,4,1,&v)==DEVICE_BAD_VALUE);
            CHECK(v==input && !memcmp(&state,&saved,sizeof(state)));
        }
        for (unsigned width=1;width<=16;width*=2) {
            if (width==4) continue;
            for (int write=0;write<=1;write++) {
                v=1;saved=state;
                CHECK(access_word(off,width,write,&v)==DEVICE_BAD_WIDTH);
                CHECK(v==1 && !memcmp(&state,&saved,sizeof(state)));
            }
        }
        for (unsigned delta=1;delta<=3;delta++) for (int write=0;write<=1;write++) {
            v=1;saved=state;
            CHECK(access_word(off+delta,4,write,&v)==DEVICE_BAD_WIDTH);
            CHECK(v==1 && !memcmp(&state,&saved,sizeof(state)));
        }
    }
    CHECK(words==7);
    CHECK(device_model_start(&model,&other,0,24000000)==DEVICE_OK);
    for (unsigned i=0;i<7;i++) CHECK(other.pmc_enable[i]==0);
    v=1;saved=state;
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
    state.dram_policy=0xfeed;state.pmc_enable[0]=0xf;
    state.pmgr_policy[5]=0xfeedbeef;saved=state;
    for (unsigned i=0;i<7;i++) saved.pmc_enable[i]=0;
    CHECK(device_model_start(&model,&state,123,24000000)==DEVICE_OK);
    CHECK(!memcmp(&state,&saved,sizeof(state)));
    printf("PMC voter/RMBS/boost/BWR enable policy: %u checks passed\n",checks);
    return 0;
}

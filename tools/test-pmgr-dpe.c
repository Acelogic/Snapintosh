/* SPDX-License-Identifier: MIT */
/* Exact SOC DPE configuration words; no fabricated activity or completion. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "device.h"

static unsigned checks;
#define CHECK(x) do { checks++; if (!(x)) { \
    fprintf(stderr,"line %u: %s\n",__LINE__,#x); exit(1); } } while (0)
static struct device_state state,saved,other;
static const struct device_model model={DEVICE_PMGR_SOC_DPE_POLICY_V1,
    0x30020a000,0x3000,{0,0,0,0,0}};
/* Ordered accesses from restoreSOCDPE's read/modify/write sequence, as
 * logical-register offsets. The native decoder uses model-relative offsets. */
static const unsigned sequence[]={
    0x2600,0x2400,0x2700,0x2a00,0x2800,0x2b00,0x2e00,0x2c00,0x2f00,
    0x3200,0x3000,0x3300,0x3600,0x3400,0x3700,0x3a00,0x3800,0x3b00,
    0x3e00,0x3c00,0x3f00,0x4200,0x4300,0x4600,0x4400,0x4700,
    0x4a00,0x4800,0x4b00,
};
static enum device_result access_word(unsigned off,unsigned width,int write,uint64_t *v)
{
    return device_model_access_state(&model,&state,off,width,write,v);
}
int main(int argc,char **argv)
{
    CHECK(device_models_valid(&model,1,0,0));
    CHECK(device_model_start(&model,&state,0,24000000)==DEVICE_OK);
    if (argc==2 && !strcmp(argv[1],"--topology")) {
        for (unsigned off=0;off<model.span;off+=4) {
            uint64_t v=0;
            if (access_word(off,4,0,&v)==DEVICE_OK) printf("%u\n",off+0x2000);
        }
        return 0;
    }
    /* Replay the complete stock restore twice. Prior words must survive
     * every later operation; the skipped group-7 word stays unimplemented. */
    for (unsigned pass=0;pass<2;pass++) for (unsigned i=0;i<29;i++) {
        unsigned off=sequence[i]-0x2000;uint64_t v=UINT64_MAX;
        CHECK(access_word(off,4,0,&v)==DEVICE_OK && v==(pass ? 1 : 0));
        v|=1;CHECK(access_word(off,4,1,&v)==DEVICE_OK);
        for (unsigned j=0;j<29;j++) {
            v=UINT64_MAX;
            CHECK(access_word(sequence[j]-0x2000,4,0,&v)==DEVICE_OK);
            CHECK(v==((pass || j<=i) ? 1 : 0));
        }
    }
    CHECK(state.pmgr_soc_dpe[21]==0);
    unsigned words=0;
    for (unsigned off=0;off<0x3000;off+=4) {
        int known=0;
        for (unsigned i=0;i<29;i++) if (off+0x2000==sequence[i]) known=1;
        uint64_t v=0x13579bdf;saved=state;
        if (!known) {
            for (int write=0;write<=1;write++) {
                CHECK(access_word(off,4,write,&v)==DEVICE_UNKNOWN_REGISTER);
                CHECK(v==0x13579bdf && !memcmp(&state,&saved,sizeof(state)));
            }
            continue;
        }
        words++;
        for (unsigned bit=1;bit<64;bit++) for (unsigned enabled=0;enabled<2;enabled++) {
            v=(1UL<<bit)|enabled;uint64_t input=v;saved=state;
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
        /* Clearing one enable must leave every other programmed word set. */
        v=0;CHECK(access_word(off,4,1,&v)==DEVICE_OK);
        for (unsigned j=0;j<29;j++) {
            v=UINT64_MAX;
            CHECK(access_word(sequence[j]-0x2000,4,0,&v)==DEVICE_OK);
            CHECK(v==(sequence[j]==off+0x2000 ? 0 : 1));
        }
        v=1;CHECK(access_word(off,4,1,&v)==DEVICE_OK);
    }
    CHECK(words==29);
    CHECK(device_model_start(&model,&other,0,24000000)==DEVICE_OK);
    for (unsigned i=0;i<30;i++) CHECK(other.pmgr_soc_dpe[i]==0);
    uint64_t v=1;saved=state;
    CHECK(access_word(0x3000,4,1,&v)==DEVICE_NOT_FOUND);
    CHECK(device_model_access_state(&model,0,0x600,4,1,&v)==DEVICE_BAD_CONFIG);
    CHECK(device_model_access_state(&model,&state,0x600,4,1,0)==DEVICE_BAD_CONFIG);
    for (unsigned i=0;i<5;i++) {
        struct device_model bad=model;bad.config[i]=1;
        CHECK(!device_models_valid(&bad,1,0,0));
        CHECK(device_model_start(&bad,&state,0,24000000)==DEVICE_BAD_CONFIG);
        CHECK(device_model_access_state(&bad,&state,0x600,4,1,&v)==DEVICE_BAD_CONFIG);
        CHECK(!memcmp(&state,&saved,sizeof(state)));
    }
    for (unsigned span=0x1000;span<=0x8000;span+=0x1000) {
        if (span==0x3000) continue;
        struct device_model bad=model;bad.span=span;
        CHECK(!device_models_valid(&bad,1,0,0));
    }
    state.dram_policy=0xfeed;state.ptd_ack=3;
    state.pmgr_policy[30]=0xfeedbeef;saved=state;
    for (unsigned i=0;i<30;i++) saved.pmgr_soc_dpe[i]=0;
    CHECK(device_model_start(&model,&state,1234,24000000)==DEVICE_OK);
    CHECK(!memcmp(&state,&saved,sizeof(state)));
    printf("PMGR SOC DPE policy: %u checks passed\n",checks);
    return 0;
}

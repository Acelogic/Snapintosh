/* SPDX-License-Identifier: MIT */
/* Wake-mask programming; no fabricated causes or low-power completion. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "device.h"

static unsigned checks;
#define CHECK(x) do { checks++; if (!(x)) { \
    fprintf(stderr,"line %u: %s\n",__LINE__,#x); exit(1); } } while (0)
static struct device_state state,saved,other;
static struct device_model model={DEVICE_PMGR_AP_WAKE_MASK_V1,
    0x308004000,0x1000,{0,0,0,0,0}};
static enum device_result access_word(unsigned offset,unsigned width,int write,uint64_t *v)
{
    return device_model_access_state(&model,&state,offset,width,write,v);
}

int main(int argc,char **argv)
{
    CHECK(device_models_valid(&model,1,0,0));
    memset(&state,0,sizeof(state));
    CHECK(device_model_start(&model,&state,0,24000000)==DEVICE_OK);
    if (argc==2 && !strcmp(argv[1],"--valid-masks")) {
        for (unsigned i=0;i<8;i++) printf("%u\n",state.pmgr_wake_mask[i]);
        return 0;
    }
    for (unsigned i=0;i<8;i++)
        CHECK(state.pmgr_wake_mask[i]==(i==7 ? 0x1fffff : UINT32_MAX));
    /* DDR sleep remains disabled, independently of all eight wake masks. */
    for(unsigned repeat=0;repeat<3;repeat++) {
        uint64_t v=~0UL;saved=state;
        CHECK(access_word(0,4,0,&v)==DEVICE_OK && v==0);
        CHECK(access_word(0,4,1,&v)==DEVICE_OK && v==0);
        CHECK(!memcmp(&state,&saved,sizeof(state)));
    }
    for(unsigned bit=0;bit<64;bit++) {
        uint64_t v=1UL<<bit;saved=state;
        CHECK(access_word(0,4,1,&v)==DEVICE_BAD_VALUE);
        CHECK(v==(1UL<<bit) && !memcmp(&state,&saved,sizeof(state)));
    }
    for(unsigned width=0;width<=16;width++)if(width!=4)for(int wr=0;wr<2;wr++) {
        uint64_t v=123;saved=state;
        CHECK(access_word(0,width,wr,&v)==DEVICE_BAD_WIDTH);
        CHECK(v==123 && !memcmp(&state,&saved,sizeof(state)));
    }
    for(unsigned off=1;off<4;off++) {
        uint64_t v=0;saved=state;
        CHECK(access_word(off,4,1,&v)==DEVICE_BAD_WIDTH);
        CHECK(!memcmp(&state,&saved,sizeof(state)));
    }
    unsigned words=0;
    for (unsigned off=4;off<0x1000;off+=4) {
        uint64_t v=0x13579bdf;
        saved=state;
        /* Reads of masks and the distinct wake-cause range are not part of
         * this write-only configuration contract. No invented readback. */
        CHECK(access_word(off,4,0,&v)==DEVICE_UNKNOWN_REGISTER);
        CHECK(v==0x13579bdf && !memcmp(&state,&saved,sizeof(state)));
        if (off<8 || off>0x24) {
            CHECK(access_word(off,4,1,&v)==DEVICE_UNKNOWN_REGISTER);
            CHECK(!memcmp(&state,&saved,sizeof(state)));
            continue;
        }
        words++;
        unsigned index=(off-8)/4;
        uint64_t mask=index==7 ? 0x1fffff : UINT32_MAX;
        for (unsigned bit=0;bit<64;bit++) {
            v=1UL<<bit;saved=state;
            CHECK(access_word(off,4,1,&v)==((v&~mask) ? DEVICE_BAD_VALUE : DEVICE_OK));
            if (!(v&~mask)) saved.pmgr_wake_mask[index]=(uint32_t)v;
            CHECK(v==(1UL<<bit) && !memcmp(&state,&saved,sizeof(state)));
            v=mask&~(1UL<<bit);saved=state;
            CHECK(access_word(off,4,1,&v)==DEVICE_OK);
            saved.pmgr_wake_mask[index]=(uint32_t)v;
            CHECK(!memcmp(&state,&saved,sizeof(state)));
        }
        const uint64_t candidates[]={0,UINT64_MAX,0xaaaaaaaa,0x55555555,0xffffffde,
            0xbffffbff,0xfffeffbb,0xdfff9ff7,0xfffdeef7,0xffffffdf,0xfff7ffff,0x1fef77};
        for (unsigned i=0;i<sizeof(candidates)/sizeof(candidates[0]);i++) {
            v=candidates[i];saved=state;
            CHECK(access_word(off,4,1,&v)==((v&~mask) ? DEVICE_BAD_VALUE : DEVICE_OK));
            if (!(v&~mask)) saved.pmgr_wake_mask[index]=(uint32_t)v;
            CHECK(v==candidates[i] && !memcmp(&state,&saved,sizeof(state)));
        }
        for (unsigned width=1;width<=8;width*=2) {
            if (width==4) continue;
            for (int write=0;write<=1;write++) {
                v=0;saved=state;
                CHECK(access_word(off,width,write,&v)==DEVICE_BAD_WIDTH);
                CHECK(v==0 && !memcmp(&state,&saved,sizeof(state)));
            }
        }
        for (unsigned delta=1;delta<=3;delta++) {
            v=0;saved=state;
            CHECK(access_word(off+delta,4,1,&v)==DEVICE_BAD_WIDTH);
            CHECK(v==0 && !memcmp(&state,&saved,sizeof(state)));
        }
    }
    CHECK(words==8);
    /* Reinitialize only the mask bank and preserve unrelated storage. */
    state.dram_policy=0xfeed;saved=state;
    for (unsigned i=0;i<8;i++) saved.pmgr_wake_mask[i]=i==7 ? 0x1fffff : UINT32_MAX;
    CHECK(device_model_start(&model,&state,1234,24000000)==DEVICE_OK);
    CHECK(!memcmp(&state,&saved,sizeof(state)));
    CHECK(device_model_start(&model,&other,1234,24000000)==DEVICE_OK);
    uint64_t v=0;
    CHECK(access_word(8,4,1,&v)==DEVICE_OK && other.pmgr_wake_mask[0]==UINT32_MAX);
    saved=state;
    CHECK(access_word(0x1000,4,1,&v)==DEVICE_NOT_FOUND);
    CHECK(device_model_access_state(&model,0,8,4,1,&v)==DEVICE_BAD_CONFIG);
    CHECK(device_model_access_state(&model,&state,8,4,1,0)==DEVICE_BAD_CONFIG);
    for (unsigned i=0;i<5;i++) {
        struct device_model bad=model;bad.config[i]=1;
        CHECK(!device_models_valid(&bad,1,0,0));
        CHECK(device_model_access_state(&bad,&state,8,4,1,&v)==DEVICE_BAD_CONFIG);
        CHECK(device_model_start(&bad,&state,0,24000000)==DEVICE_BAD_CONFIG);
        CHECK(!memcmp(&state,&saved,sizeof(state)));
    }
    model.span=0x4000;
    CHECK(!device_models_valid(&model,1,0,0));
    printf("PMGR wake masks: %u checks passed\n",checks);
    return 0;
}

/* SPDX-License-Identifier: MIT */
/* Exact native disable writes must never enable a fused key. */
#include "device.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static unsigned checks;
#define CHECK(x) do {checks++;if (!(x)) {fprintf(stderr,"FAIL %d: %s\n",__LINE__,#x);exit(1);}} while(0)
static const struct device_model model={8,0x3082dc000UL,0x8000,{0,0x40,0x44,0x48,0}};
static struct device_state state,saved;
static void disabled(void)
{
    for(unsigned i=0;i<4;i++) {
        uint64_t v=0;CHECK(device_model_access_state(&model,&state,model.config[i],4,0,&v)==DEVICE_OK);
        CHECK(v==(i ? 0 : 15));
    }
}
static void refuse(uint64_t offset,unsigned width,uint64_t v,enum device_result want)
{
    memcpy(&saved,&state,sizeof(state));uint64_t input=v;
    CHECK(device_model_access_state(&model,&state,offset,width,1,&v)==want);
    CHECK(v==input && !memcmp(&saved,&state,sizeof(state)));disabled();
}
/* docs/PMGR-BPR-20261017.md: config[4] names PMGR's BPR word (range 1 +0x5c030,
 * window +0x30). It starts at 0, stores any 32-bit write, counts both, and leaves
 * the four key controls exactly as they were. */
static void bpr_word(void)
{
    static const struct device_model bpr={8,0x3082dc000UL,0x8000,{0,0x40,0x44,0x48,0x30}};
    struct device_state s,keep;memset(&s,0x5a,sizeof(s));
    CHECK(device_models_valid(&bpr,1,0,0));
    CHECK(device_model_start(&bpr,&s,0,1)==DEVICE_OK);
    CHECK(!s.aes_pmgr_bpr && !s.aes_pmgr_bpr_reads && !s.aes_pmgr_bpr_writes);
    uint64_t v=0xdeadbeef;
    CHECK(device_model_access_state(&bpr,&s,0x30,4,0,&v)==DEVICE_OK && v==0 && s.aes_pmgr_bpr_reads==1);
    const uint32_t values[]={0x1,0x12345678,0xffffffffU,0};
    for(unsigned i=0;i<4;i++) {
        v=values[i];CHECK(device_model_access_state(&bpr,&s,0x30,4,1,&v)==DEVICE_OK);
        v=0;CHECK(device_model_access_state(&bpr,&s,0x30,4,0,&v)==DEVICE_OK && v==values[i]);
    }
    CHECK(s.aes_pmgr_bpr_writes==4 && s.aes_pmgr_bpr_reads==5);
    /* Width, alignment and range refusals change nothing. */
    const uint64_t offsets[]={0x30,0x31,0x32,0x2c};const unsigned widths[]={8,4,2,4};
    for(unsigned i=0;i<4;i++) for(int write=0;write<2;write++) {
        memcpy(&keep,&s,sizeof(s));v=0x1122334455667788ULL;
        enum device_result r=device_model_access_state(&bpr,&s,offsets[i],widths[i],write,&v);
        CHECK(r==(offsets[i]==0x2c ? DEVICE_UNKNOWN_REGISTER : DEVICE_BAD_WIDTH));
        CHECK(!memcmp(&keep,&s,sizeof(s)));
    }
    v=0x100000000ULL;memcpy(&keep,&s,sizeof(s));
    CHECK(device_model_access_state(&bpr,&s,0x30,4,1,&v)==DEVICE_BAD_VALUE && !memcmp(&keep,&s,sizeof(s)));
    /* The key controls are unchanged beside it. */
    for(unsigned i=0;i<4;i++) {
        v=0;CHECK(device_model_access_state(&bpr,&s,bpr.config[i],4,0,&v)==DEVICE_OK && v==(i ? 0 : 15));
        v=0xa050c030;CHECK(device_model_access_state(&bpr,&s,bpr.config[i],4,1,&v)==DEVICE_BAD_VALUE);
    }
    CHECK(s.aes_pmgr_bpr==0);
    /* Invalid placements: a key offset, unaligned, outside the window. */
    const uint64_t bad[]={0x40,0x31,0x8000,0x7ffd};
    for(unsigned i=0;i<4;i++) {
        struct device_model m=bpr;m.config[4]=bad[i];CHECK(!device_models_valid(&m,1,0,0));
    }
    /* A restart clears the word with the counters. */
    CHECK(device_model_start(&bpr,&s,0,1)==DEVICE_OK && !s.aes_pmgr_bpr && !s.aes_pmgr_bpr_writes);
    _Static_assert(__builtin_offsetof(struct device_state,aes_key_disable_writes)==0,"key counters keep offset 0");
}
int main(void)
{
    memset(&state,0xa5,sizeof(state));CHECK(device_model_start(&model,&state,0,1)==DEVICE_OK);
    for(unsigned i=0;i<4;i++)CHECK(!state.aes_key_disable_writes[i]);
    disabled();
    for(unsigned repeat=0;repeat<3;repeat++) for(unsigned i=0;i<4;i++) {
        for(unsigned bit=0;bit<(i ? 1U : 4U);bit++) {
            uint64_t v=i ? 0xa55ac33cUL : 1UL<<bit;
            memcpy(&saved,&state,sizeof(state));saved.aes_key_disable_writes[i]++;
            CHECK(device_model_access_state(&model,&state,model.config[i],4,1,&v)==DEVICE_OK);
            CHECK(!memcmp(&saved,&state,sizeof(state)));disabled();
        }
        for(unsigned bit=0;bit<64;bit++) {
            uint64_t v=(i ? 0xa55ac33cUL : 8UL)^(1UL<<bit);
            if(!i && (v==1 || v==2 || v==4 || v==8))continue;
            refuse(model.config[i],4,v,DEVICE_BAD_VALUE);
        }
        refuse(model.config[i],4,0xa050c030,DEVICE_BAD_VALUE);
        refuse(model.config[i],4,0,DEVICE_BAD_VALUE);
        refuse(model.config[i],8,0xa55ac33c,DEVICE_BAD_WIDTH);
    }
    refuse(4,4,0xa55ac33c,DEVICE_UNKNOWN_REGISTER);
    refuse(0x41,4,0xa55ac33c,DEVICE_BAD_WIDTH);
    uint64_t v=0xa55ac33c;CHECK(device_model_access(&model,0x44,4,1,&v)==DEVICE_BAD_CONFIG);
    state.aes_key_disable_writes[2]=UINT32_MAX;
    CHECK(device_model_access_state(&model,&state,0x44,4,1,&v)==DEVICE_OK);
    CHECK(state.aes_key_disable_writes[2]==UINT32_MAX);disabled();
    CHECK(device_model_start(&model,&state,0,1)==DEVICE_OK);
    for(unsigned i=0;i<4;i++)CHECK(!state.aes_key_disable_writes[i]);disabled();
    /* config[4] == 0: +0x30 stays an unknown register (the model as before). */
    refuse(0x30,4,0,DEVICE_UNKNOWN_REGISTER);
    v=0;CHECK(device_model_access_state(&model,&state,0x30,4,0,&v)==DEVICE_UNKNOWN_REGISTER);
    bpr_word();
    printf("AES key-disable: %u checks passed (native commands, permanent absence, atomic refusals, "
           "PMGR BPR word)\n",checks);
}

/* SPDX-License-Identifier: MIT */
/* Native AES enable/reject/disable contract. No successful crypto operation. */
#include "device.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static unsigned checks;
#define CHECK(x) do { checks++; if (!(x)) { fprintf(stderr,"FAIL %d: %s\n",__LINE__,#x); exit(1); } } while (0)
static struct device_state state, before, peer;
static const struct device_model engine={DEVICE_AES_IDLE_V1,0x38500c000UL,0x4000,{5,0,0,0,0}};
static const struct device_model keys={DEVICE_AES_NO_KEYS_V1,0x3082dc000UL,0x8000,{0,0x40,0x44,0x48,0}};
static uint64_t rd(uint64_t off)
{
    uint64_t v=UINT64_MAX;
    CHECK(device_model_access_state(&engine,&state,off,4,0,&v)==DEVICE_OK);
    CHECK(!device_irq_pending(&engine,&state));
    return v;
}
static void wr(uint64_t off,uint64_t v)
{
    CHECK(device_model_access_state(&engine,&state,off,4,1,&v)==DEVICE_OK);
    CHECK(!device_irq_pending(&engine,&state));
}
static void refuse(uint64_t off,unsigned width,int write,uint64_t v,enum device_result want)
{
    before=state;
    uint64_t original=v;
    CHECK(device_model_access_state(&engine,&state,off,width,write,&v)==want);
    CHECK(v==original && !memcmp(&state,&before,sizeof(state)));
}
int main(void)
{
    const struct device_model models[]={engine,keys};
    CHECK(device_models_valid(models,2,0,0));
    refuse(12,4,0,0,DEVICE_BAD_CONFIG);
    CHECK(device_model_start(&engine,&state,0,24000000)==DEVICE_OK);
    CHECK(device_model_start(&engine,&peer,0,24000000)==DEVICE_OK);
    /* The shipped version-5 _enableAES sequence, repeated over key failures. */
    for (unsigned i=0;i<13;i++) {
        CHECK(rd(12)==0x3f80);
        uint64_t flags=rd(0x18); CHECK(flags==0); wr(0x18,flags);
        wr(0x1c,0x3effe); wr(0x20,0x40); wr(8,1);
        CHECK(state.aes_idle.running==1);
        for (unsigned key=0;key<4;key++) {
            uint64_t disabled=UINT64_MAX;
            CHECK(device_model_access_state(&keys,0,keys.config[key],4,0,&disabled)==DEVICE_OK);
            CHECK(disabled==(key ? 0UL : 15UL));
        }
        /* A disabled-key rejection is native software behavior. The model
         * must refuse even an apparently valid SET_KEY or BARRIER command. */
        refuse(0x200,4,1,0x11000000,DEVICE_UNKNOWN_REGISTER);
        refuse(0x200,4,1,0x88000000,DEVICE_UNKNOWN_REGISTER);
        wr(8,2); wr(0x1c,0); CHECK(rd(0x24)==2);
        flags=rd(0x18); CHECK(flags==0); wr(0x18,flags);
        CHECK(!state.aes_idle.running && !state.aes_idle.irq_enable);
    }
    CHECK(state.aes_idle.starts==13 && state.aes_idle.stops==13);
    CHECK(state.aes_idle.reads==((1U<<3)|(1U<<6)|(1U<<9)));
    CHECK(state.aes_idle.writes==((1U<<2)|(1U<<6)|(1U<<7)|(1U<<8)));
    CHECK(!peer.aes_idle.starts && !peer.aes_idle.running && !peer.aes_idle.writes);
    /* All unimplemented register locations remain side-effect-free refusals. */
    for (uint64_t off=0;off<0x4000;off+=4) {
        if (off!=12 && off!=0x18 && off!=0x24)
            refuse(off,4,0,0,DEVICE_UNKNOWN_REGISTER);
        if (off!=8 && off!=0x18 && off!=0x1c && off!=0x20)
            refuse(off,4,1,0,off==12 || off==0x24 ? DEVICE_READ_ONLY : DEVICE_UNKNOWN_REGISTER);
    }
    for (unsigned width=1;width<=8;width*=2)
        if (width!=4) refuse(12,width,0,0,DEVICE_BAD_WIDTH);
    refuse(13,4,0,0,DEVICE_BAD_WIDTH);
    for (unsigned bit=0;bit<64;bit++) {
        uint64_t v=1UL<<bit;
        if (!(v&0x3effe)) {
            refuse(0x18,4,1,v,DEVICE_BAD_VALUE);
            refuse(0x1c,4,1,v,DEVICE_BAD_VALUE);
        }
        if (v!=0x40) refuse(0x20,4,1,v,DEVICE_BAD_VALUE);
        if (v!=1 && v!=2) refuse(8,4,1,v,DEVICE_BAD_VALUE);
    }
    refuse(8,4,1,3,DEVICE_BAD_VALUE);
    refuse(8,4,1,0,DEVICE_BAD_VALUE);
    refuse(0x4000,4,0,0,DEVICE_NOT_FOUND);
    for (unsigned field=0;field<5;field++) {
        struct device_model bad=engine; bad.config[field]++;
        CHECK(!device_models_valid(&bad,1,0,0));
    }
    struct device_model bad=engine;bad.span=0x8000;
    CHECK(!device_models_valid(&bad,1,0,0));
    CHECK(device_model_start(&engine,&state,0,24000000)==DEVICE_OK);
    CHECK(!memcmp(&state.aes_idle,&peer.aes_idle,sizeof(state.aes_idle)));
    state.aes_idle.running=2;refuse(12,4,0,0,DEVICE_BAD_CONFIG);
    printf("AES idle: %u checks passed; commands, DMA and crypto remain unsupported\n",checks);
    return 0;
}

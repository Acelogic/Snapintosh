/* SPDX-License-Identifier: MIT */
/* A disabled virtual LLT control cannot claim active hardware limits. */
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "device.h"
static unsigned checks;
#define CHECK(x) do { checks++; if (!(x)) { fprintf(stderr,"line %u: %s\n",__LINE__,#x); exit(1); } } while (0)
static struct device_model model={38,0x300740000,0x1000,{0}};
static struct device_state state,saved;
static void refused(unsigned off,unsigned width,int write,uint64_t value,enum device_result want)
{
    uint64_t v=value;saved=state;
    CHECK(device_model_access_state(&model,&state,off,width,write,&v)==want);
    CHECK(v==value && !memcmp(&saved,&state,sizeof(state)));
}
int main(void)
{
    CHECK(sizeof(state)==13000 && offsetof(struct device_state,pmgr_llt_limit)==0);
    CHECK(device_models_valid(&model,1,0,0));
    CHECK(device_model_start(&model,&state,0,24000000)==DEVICE_OK);
    saved=state;
    for(unsigned repeat=0;repeat<3;repeat++) {
        uint64_t v=~0UL;
        CHECK(device_model_access_state(&model,&state,0,4,0,&v)==DEVICE_OK && v==0);
        CHECK(device_model_access_state(&model,&state,0,4,1,&v)==DEVICE_OK && v==0);
        CHECK(!memcmp(&saved,&state,sizeof(state)));
    }
    for(unsigned bit=0;bit<64;bit++)refused(0,4,1,1UL<<bit,DEVICE_BAD_VALUE);
    for(unsigned off=4;off<0x1000;off+=4)for(int wr=0;wr<2;wr++)
        refused(off,4,wr,0,DEVICE_UNKNOWN_REGISTER);
    for(unsigned width=0;width<=16;width++)if(width!=4)for(int wr=0;wr<2;wr++)
        refused(0,width,wr,0,DEVICE_BAD_WIDTH);
    for(unsigned off=1;off<4;off++)refused(off,4,1,0,DEVICE_BAD_WIDTH);
    refused(0x1000,4,0,0,DEVICE_NOT_FOUND);
    for(unsigned bit=0;bit<32;bit++) {
        state.pmgr_llt_limit=1U<<bit;
        refused(0,4,0,0,DEVICE_BAD_VALUE);refused(0,4,1,0,DEVICE_BAD_VALUE);
    }
    CHECK(device_model_start(&model,&state,0,24000000)==DEVICE_OK);
    CHECK(state.pmgr_llt_limit==0);
    for(unsigned i=0;i<5;i++) {
        model.config[i]=1;CHECK(!device_models_valid(&model,1,0,0));
        refused(0,4,1,0,DEVICE_BAD_CONFIG);model.config[i]=0;
    }
    model.base+=0x1000;CHECK(!device_models_valid(&model,1,0,0));
    refused(0,4,1,0,DEVICE_BAD_CONFIG);model.base-=0x1000;
    model.span=0x2000;CHECK(!device_models_valid(&model,1,0,0));
    refused(0,4,1,0,DEVICE_BAD_CONFIG);model.span=0x1000;
    uint64_t v=0;
    CHECK(device_model_access_state(&model,0,0,4,0,&v)==DEVICE_BAD_CONFIG);
    printf("PASS: LLT disabled control %u checks; enables and unknown registers refused\n",checks);
    return 0;
}

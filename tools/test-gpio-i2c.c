/* SPDX-License-Identifier: MIT */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "device.h"
static unsigned checks;
#define CHECK(x) do { checks++;if(!(x)){fprintf(stderr,"FAIL %d: %s\n",__LINE__,#x);exit(1);}}while(0)
static struct device_state state,before;
static struct device_model model={40,0x31a000000,0x100000,{216,7,127,5096408961622,5878381359781}};
static void refuse(unsigned pin,uint64_t v)
{
    before=state;uint64_t input=v;
    CHECK(device_model_access_state(&model,&state,pin*4,4,1,&v)==DEVICE_BAD_VALUE);
    CHECK(v==input && !memcmp(&before,&state,sizeof(state)));
}
int main(void)
{
    const unsigned pins[]={85,169,101,80,164,165,170,171};
    const unsigned muxes[]={1,2,1,1,1,1,1,1};
    CHECK(device_models_valid(&model,1,0,0));
    CHECK(device_model_start(&model,&state,0,24000000)==DEVICE_OK);
    for(unsigned pin=0;pin<216;pin++)for(unsigned mux=1;mux<=3;mux++) {
        int route=0;for(unsigned i=0;i<8;i++)route|=(pin==pins[i] && mux==muxes[i]);
        if(!route){refuse(pin,14|(mux<<5));continue;}
        uint64_t v=14|(mux<<5);
        CHECK(device_model_access_state(&model,&state,pin*4,4,1,&v)==DEVICE_OK);
        CHECK(device_model_access_state(&model,&state,pin*4,4,0,&v)==DEVICE_OK && !(v&1));
        v|=1U<<9;
        CHECK(device_model_access_state(&model,&state,pin*4,4,1,&v)==DEVICE_OK);
        CHECK(device_model_access_state(&model,&state,pin*4,4,0,&v)==DEVICE_OK && (v&1));
        for(unsigned mode=0;mode<7;mode++)refuse(pin,(v&~15UL)|(mode<<1));
        for(unsigned bit=24;bit<64;bit++)refuse(pin,v|(1UL<<bit));
    }
    for(unsigned group=0;group<7;group++)for(unsigned bank=0;bank<7;bank++) {
        uint64_t v=0xffffffff;
        CHECK(device_model_access_state(&model,&state,0x800+group*0x40+bank*4,4,1,&v)==DEVICE_OK);
        CHECK(device_model_access_state(&model,&state,0x800+group*0x40+bank*4,4,0,&v)==DEVICE_OK && !v);
    }
    struct device_model good=model;
    for(unsigned bit=44;bit<64;bit++)for(unsigned word=3;word<=4;word++) {
        model.config[word]|=1UL<<bit;
        CHECK(!device_models_valid(&model,1,0,0));model=good;
    }
    model.config[4]=(model.config[4]&~0x7ffUL)|(model.config[3]&0x7ff);
    CHECK(!device_models_valid(&model,1,0,0));model=good;
    model.config[4]=(model.config[4]&~0x7ffUL)|0x2d9; /* pin+1 exceeds 216 */
    CHECK(!device_models_valid(&model,1,0,0));model=good;
    CHECK(device_model_start(&model,&state,0,24000000)==DEVICE_OK);
    for(unsigned i=0;i<216;i++)CHECK(state.gpio_pin[i]==14);
    printf("PASS: %u GPIO idle-pad routing and refusal checks\n",checks);
}

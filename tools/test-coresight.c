/* SPDX-License-Identifier: MIT */
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "device.h"
static unsigned checks;
#define CHECK(x) do { checks++; if(!(x)) { fprintf(stderr,"FAIL %d: %s\n",__LINE__,#x);exit(1); } } while(0)
static struct device_state states[6],saved;
static void refused(struct device_model *m,struct device_state *s,unsigned off,
                    unsigned width,int write,uint64_t value,enum device_result want)
{
    saved=*s;uint64_t v=value;
    CHECK(device_model_access_state(m,s,off,width,write,&v)==want);
    CHECK(v==value && !memcmp(s,&saved,sizeof(saved)));
}
int main(void)
{
    struct device_model models[6];
    CHECK(sizeof(states[0])==13000 && offsetof(struct device_state,coresight_unlocked)==0);
    for(unsigned i=0;i<6;i++) {
        models[i]=(struct device_model){39,i<4 ? 0x210010000UL+i*0x100000UL :
            0x211010000UL+(i-4)*0x100000UL,0x1000,{i,0,0,0,0}};
        CHECK(device_model_start(&models[i],&states[i],0,24000000)==DEVICE_OK);
    }
    CHECK(device_models_valid(models,6,0,0));
    for(unsigned i=0;i<6;i++) {
        struct device_model *m=&models[i];struct device_state *s=&states[i];
        uint64_t v=99;
        CHECK(device_model_access_state(m,s,0xfb4,4,0,&v)==DEVICE_OK && v==3);
        for(unsigned repeat=0;repeat<2;repeat++) {
            v=0xc5acce55;
            CHECK(device_model_access_state(m,s,0xfb0,4,1,&v)==DEVICE_OK && s->coresight_unlocked==1);
            CHECK(device_model_access_state(m,s,0xfb4,4,0,&v)==DEVICE_OK && v==1);
        }
        for(unsigned j=i+1;j<6;j++)CHECK(states[j].coresight_unlocked==0);
        for(unsigned bit=0;bit<32;bit++) {
            v=0xc5acce55UL^(1UL<<bit);
            CHECK(device_model_access_state(m,s,0xfb0,4,1,&v)==DEVICE_OK && !s->coresight_unlocked);
            CHECK(device_model_access_state(m,s,0xfb4,4,0,&v)==DEVICE_OK && v==3);
            v=0xc5acce55;
            CHECK(device_model_access_state(m,s,0xfb0,4,1,&v)==DEVICE_OK && s->coresight_unlocked);
        }
        refused(m,s,0xfb0,4,0,0,DEVICE_UNKNOWN_REGISTER);
        refused(m,s,0xfb4,4,1,0,DEVICE_BAD_VALUE);
        for(unsigned bit=32;bit<64;bit++)refused(m,s,0xfb0,4,1,1UL<<bit,DEVICE_BAD_VALUE);
        for(unsigned off=0;off<0x1000;off+=4)if(off!=0xfb0 && off!=0xfb4)
            for(int wr=0;wr<2;wr++)refused(m,s,off,4,wr,0,DEVICE_UNKNOWN_REGISTER);
        for(unsigned width=0;width<=16;width++)if(width!=4)
            for(int wr=0;wr<2;wr++)refused(m,s,0xfb0,width,wr,0,DEVICE_BAD_WIDTH);
        for(unsigned off=1;off<4;off++)refused(m,s,0xfb0+off,4,1,0,DEVICE_BAD_WIDTH);
        refused(m,s,0x1000,4,0,0,DEVICE_NOT_FOUND);
        s->coresight_unlocked=2;
        refused(m,s,0xfb0,4,1,0,DEVICE_BAD_VALUE);
        refused(m,s,0xfb4,4,0,0,DEVICE_BAD_VALUE);
        CHECK(device_model_start(m,s,0,24000000)==DEVICE_OK && !s->coresight_unlocked);
        v=0;CHECK(device_model_access_state(m,NULL,0xfb4,4,0,&v)==DEVICE_BAD_CONFIG);
        struct device_model original=*m;
        for(unsigned cfg=0;cfg<5;cfg++) {
            m->config[cfg]=cfg ? 1 : 6;
            CHECK(!device_models_valid(m,1,0,0));
            refused(m,s,0xfb0,4,1,0,DEVICE_BAD_CONFIG);*m=original;
        }
        m->base+=0x1000;CHECK(!device_models_valid(m,1,0,0));
        refused(m,s,0xfb0,4,1,0,DEVICE_BAD_CONFIG);*m=original;
        m->span=0x2000;CHECK(!device_models_valid(m,1,0,0));*m=original;
    }
    printf("PASS: %u CoreSight software-lock lifecycle and refusal checks\n",checks);
}

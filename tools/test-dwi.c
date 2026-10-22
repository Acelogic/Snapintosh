/* SPDX-License-Identifier: MIT */
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "device.h"
static unsigned checks;
#define CHECK(x) do { checks++; if (!(x)) { fprintf(stderr,"FAIL %d: %s\n",__LINE__,#x); exit(1); } } while (0)
static struct device_state states[3], saved;
static struct device_model models[3] = {
    { DEVICE_DWI_STARTUP_V1, 0x300200000UL, 0x4000, {0} },
    { DEVICE_PMGR_ACTIVE_BOOT_V1, 0x300700000UL, 0x11000, {0} },
    { DEVICE_PMGR_ACTIVE_BOOT_V1, 0x300700000UL, 0x11000, {0} },
};
static const unsigned offsets[5]={0,0xd0,4,0x84,0x80};
static const uint64_t startup[5]={1,192000,120,0,0x41};
static void refused(unsigned off, unsigned width, int write, uint64_t value,
                    enum device_result expected)
{
    saved=states[0];uint64_t v=value;
    CHECK(device_model_access_state(&models[0],&states[0],off,width,write,&v)==expected);
    CHECK(v==value && !memcmp(&saved,&states[0],sizeof(saved)));
}
int main(void)
{
    CHECK(sizeof(states[0])==13000 && offsetof(struct device_state,dwi)==0);
    CHECK(device_models_valid(models,2,0,0));
    refused(0,4,1,1,DEVICE_BAD_CONFIG);
    for (unsigned i=0;i<3;i++) CHECK(device_model_start(&models[i],&states[i],0,24000000)==DEVICE_OK);
    refused(0x80,4,1,0x41,DEVICE_BAD_VALUE);
    for (unsigned i=0;i<3;i++) refused(offsets[i],4,0,0xfeed,DEVICE_BAD_VALUE);
    for (unsigned pass=0;pass<2;pass++) {
        for (unsigned i=0;i<5;i++) {
            uint64_t v=startup[i];
            CHECK(device_models_access_at(models,states,2,0,0,offsets[i],4,1,&v)==DEVICE_OK);
            CHECK(states[0].dwi.values[i]==v);
        }
        CHECK(states[0].dwi.written==31);
        for (unsigned i=0;i<3;i++) {
            uint64_t v=~0UL;
            CHECK(device_model_access_state(&models[0],&states[0],offsets[i],4,0,&v)==DEVICE_OK);
            CHECK(v==startup[i]);
        }
    }
    /* No startup write may turn a transaction/status read into success. */
    refused(0x80,4,0,0xfeed,DEVICE_BAD_VALUE);
    refused(0x84,4,0,0xfeed,DEVICE_BAD_VALUE);
    refused(0x80,4,1,0x71,DEVICE_BAD_VALUE);
    refused(0x84,4,1,0x20000000,DEVICE_BAD_VALUE);
    for (unsigned off=0;off<0x4000;off+=4) {
        unsigned i=0;while(i<5 && off!=offsets[i])i++;
        if(i<5)continue;
        refused(off,4,0,0xfeed,DEVICE_UNKNOWN_REGISTER);
        refused(off,4,1,0,DEVICE_UNKNOWN_REGISTER);
    }
    for (unsigned i=0;i<5;i++) {
        for (unsigned bit=0;bit<64;bit++)
            refused(offsets[i],4,1,startup[i]^(1UL<<bit),DEVICE_BAD_VALUE);
        for (unsigned width=1;width<=8;width*=2) if(width!=4)
            refused(offsets[i],width,1,startup[i],DEVICE_BAD_WIDTH);
        for (unsigned low=1;low<4;low++)
            refused(offsets[i]+low,4,1,startup[i],DEVICE_BAD_WIDTH);
    }
    refused(0x4000,4,0,0xfeed,DEVICE_NOT_FOUND);
    /* The PMGR dependency must exist exactly once with the right geometry. */
    uint64_t v=1;saved=states[0];
    CHECK(device_models_access_at(models,states,1,0,0,0,4,1,&v)==DEVICE_BAD_CONFIG);
    CHECK(device_models_access_at(models,states,3,0,0,0,4,1,&v)==DEVICE_BAD_CONFIG);
    models[1].base+=0x1000;
    CHECK(device_models_access_at(models,states,2,0,0,0,4,1,&v)==DEVICE_BAD_CONFIG);
    CHECK(v==1 && !memcmp(&saved,&states[0],sizeof(saved)));
    models[1].base-=0x1000;
    v=0;
    CHECK(device_models_access_at(models,states,2,1,0,0x118,4,1,&v)==DEVICE_BAD_VALUE);
    v=~0UL;
    CHECK(device_models_access_at(models,states,2,1,0,0x118,4,0,&v)==DEVICE_OK && (v&0xff)==0xff);
    for (unsigned i=0;i<5;i++) {
        models[0].config[i]=1;saved=states[0];
        CHECK(!device_models_valid(models,2,0,0));
        CHECK(device_model_start(&models[0],&states[0],0,24000000)==DEVICE_BAD_CONFIG);
        CHECK(!memcmp(&saved,&states[0],sizeof(saved)));models[0].config[i]=0;
    }
    states[0].dwi.written|=32;
    refused(0,4,1,1,DEVICE_BAD_CONFIG);
    CHECK(device_model_start(&models[0],&states[0],0,24000000)==DEVICE_OK);
    CHECK(states[0].dwi.written==0 && states[0].dwi.ready==1);
    for(unsigned i=0;i<5;i++) CHECK(states[0].dwi.values[i]==0);
    printf("PASS: %u DWI startup, status refusal, power, width and atomicity checks\n",checks);
}

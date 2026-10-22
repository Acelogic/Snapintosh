/* SPDX-License-Identifier: MIT */
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "device.h"
static unsigned checks;
#define CHECK(x) do { checks++; if (!(x)) { fprintf(stderr,"FAIL %d: %s\n",__LINE__,#x); exit(1); } } while (0)
static struct device_state states[2], saved;
static struct device_model models[2] = {
    { DEVICE_QSPI_BOOT_V1, 0x385110000UL, 0x5000, {0} },
    { DEVICE_PMGR_ACTIVE_BOOT_V1, 0x300700000UL, 0x11000, {0} },
};
static void refused(unsigned off, unsigned width, int write, uint64_t value,
                    enum device_result expected)
{
    saved=states[0]; uint64_t v=value;
    CHECK(device_model_access_state(&models[0],&states[0],off,width,write,&v)==expected);
    CHECK(v==value && !memcmp(&saved,&states[0],sizeof(saved)));
}
int main(void)
{
    CHECK(sizeof(states[0])==13000 && offsetof(struct device_state,qspi)==0);
    CHECK(device_models_valid(models,2,0,0));
    refused(0x800,4,1,0x100,DEVICE_BAD_CONFIG);
    CHECK(device_model_start(&models[0],&states[0],0,24000000)==DEVICE_OK);
    CHECK(device_model_start(&models[1],&states[1],0,24000000)==DEVICE_OK);
    for (unsigned i=0;i<16;i++) states[0].qspi.tx[i]=states[0].qspi.rx[i]=i+1;
    states[0].qspi.tx_count=states[0].qspi.rx_count=16;
    uint64_t v=0x100;
    CHECK(device_models_access_at(models,states,2,0,0,0x800,4,1,&v)==DEVICE_OK);
    CHECK(states[0].qspi.resets==1 && !states[0].qspi.tx_count && !states[0].qspi.rx_count);
    for (unsigned i=0;i<16;i++) CHECK(!states[0].qspi.tx[i] && !states[0].qspi.rx[i]);
    v=~0UL;
    CHECK(device_models_access_at(models,states,2,0,0,0x800,4,0,&v)==DEVICE_OK && v==0);
    CHECK(device_model_access_state(&models[0],&states[0],0x3c,4,0,&v)==DEVICE_OK && v==1);
    CHECK(device_model_access_state(&models[0],&states[0],0x838,4,0,&v)==DEVICE_OK && v==0x1010);
    for (unsigned off=0;off<0x5000;off+=4) {
        if (off==0x800 || off==0x3c || off==0x838) continue;
        refused(off,4,0,0xfeed,DEVICE_UNKNOWN_REGISTER);
        refused(off,4,1,0,DEVICE_UNKNOWN_REGISTER);
    }
    for (unsigned width=1;width<=8;width*=2) if (width!=4)
        refused(0x800,width,1,0x100,DEVICE_BAD_WIDTH);
    refused(0x801,4,1,0x100,DEVICE_BAD_WIDTH);
    refused(0x5000,4,0,0x123,DEVICE_NOT_FOUND);
    for (unsigned bit=0;bit<64;bit++) if (bit!=8) {
        refused(0x800,4,1,1UL<<bit,DEVICE_BAD_VALUE);
        refused(0x800,4,1,(1UL<<bit)|0x100,DEVICE_BAD_VALUE);
    }
    refused(0x800,4,1,0,DEVICE_BAD_VALUE);
    refused(0x3c,4,1,1,DEVICE_READ_ONLY);
    refused(0x838,4,1,0x1010,DEVICE_READ_ONLY);
    v=0;
    CHECK(device_models_access_at(models,states,2,1,0,0x350,4,1,&v)==DEVICE_OK);
    saved=states[0]; v=0x100;
    CHECK(device_models_access_at(models,states,2,0,0,0x800,4,1,&v)==DEVICE_BAD_VALUE);
    CHECK(v==0x100 && !memcmp(&saved,&states[0],sizeof(saved)));
    v=15;
    CHECK(device_models_access_at(models,states,2,1,0,0x350,4,1,&v)==DEVICE_OK);
    v=0x100;
    CHECK(device_models_access_at(models,states,2,0,0,0x800,4,1,&v)==DEVICE_OK);
    CHECK(states[0].qspi.resets==2);
    CHECK(device_models_access_at(models,states,1,0,0,0x800,4,1,&v)==DEVICE_BAD_CONFIG);
    for (unsigned i=0;i<5;i++) {
        models[0].config[i]=1; saved=states[0];
        CHECK(!device_models_valid(models,2,0,0));
        CHECK(device_model_start(&models[0],&states[0],0,24000000)==DEVICE_BAD_CONFIG);
        CHECK(!memcmp(&saved,&states[0],sizeof(saved))); models[0].config[i]=0;
    }
    printf("PASS: %u QSPI reset, power, identity, bounds and atomic-refusal checks\n",checks);
}

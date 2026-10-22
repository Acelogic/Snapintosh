/* SPDX-License-Identifier: MIT */
/* Saved energy reads back as a constant baseline: never a fabricated live measurement or power vote. */
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "device.h"
static unsigned checks;
#define CHECK(x) do { checks++; if (!(x)) { fprintf(stderr,"line %u: %s\n",__LINE__,#x); exit(1); } } while (0)
static struct device_model models[]={
    {36,0x210059000,0x1000,{0}}, {36,0x210159000,0x1000,{0}},
    {36,0x210259000,0x1000,{0}}, {36,0x210359000,0x1000,{0}},
    {36,0x211059000,0x1000,{0}}, {36,0x211159000,0x1000,{0}},
    {36,0x210e48000,0x1000,{0}}, {36,0x211e48000,0x1000,{0}}
};
static struct device_state states[8],saved[8],expected[8];
static enum device_result access(unsigned bank,unsigned off,unsigned width,int write,uint64_t *v)
{ return device_model_access_state(models+bank,states+bank,off,width,write,v); }
static void refused(unsigned bank,unsigned off,unsigned width,int write,uint64_t value,enum device_result want)
{
    uint64_t v=value;memcpy(saved,states,sizeof(states));
    CHECK(access(bank,off,width,write,&v)==want);
    CHECK(v==value && !memcmp(saved,states,sizeof(states)));
}
int main(void)
{
    CHECK(sizeof(struct device_state)==13000);
    CHECK(offsetof(struct device_state,energy_restore.values)==0);
    CHECK(offsetof(struct device_state,energy_restore.written)==16);
    CHECK(device_models_valid(models,8,0,0));
    for(unsigned bank=0;bank<8;bank++) {
        CHECK(device_model_start(models+bank,states+bank,0,24000000)==DEVICE_OK);
        for(unsigned slot=0;slot<2;slot++) {
            /* IOReport reads an unrestored accumulator as 0, a restored one as
             * its baseline: nothing accumulates (PMGR-IOREPORT-20261017). */
            uint64_t zero=123;memcpy(saved,states,sizeof(states));
            CHECK(access(bank,slot*8,8,0,&zero)==DEVICE_OK && zero==0 && !memcmp(saved,states,sizeof(states)));
            const uint64_t values[]={0,1,0x8000000000000000UL,UINT64_MAX,
                0xa582ee0000000000UL|((uint64_t)bank<<16)|slot};
            for(unsigned n=0;n<sizeof(values)/sizeof(values[0]);n++) {
                uint64_t v=values[n];memcpy(expected,states,sizeof(states));
                expected[bank].energy_restore.values[slot]=v;
                expected[bank].energy_restore.written|=1UL<<slot;
                CHECK(access(bank,slot*8,8,1,&v)==DEVICE_OK);
                CHECK(v==values[n] && !memcmp(expected,states,sizeof(states)));
                uint64_t back=123;CHECK(access(bank,slot*8,8,0,&back)==DEVICE_OK && back==values[n]);
                CHECK(!memcmp(expected,states,sizeof(states)));
            }
            for(unsigned write=0;write<2;write++) {
                for(unsigned width=0;width<=16;width++)if(width!=8)
                    refused(bank,slot*8,width,write,123,DEVICE_BAD_WIDTH);
                for(unsigned byte=1;byte<8;byte++)
                    refused(bank,slot*8+byte,8,write,123,DEVICE_BAD_WIDTH);
            }
        }
        for(unsigned off=16;off<0x1000;off+=8)for(unsigned write=0;write<2;write++)
            refused(bank,off,8,write,123,DEVICE_UNKNOWN_REGISTER);
        refused(bank,0x1000,8,1,123,DEVICE_NOT_FOUND);
        for(unsigned bit=2;bit<64;bit++) {
            states[bank].energy_restore.written=3|(1UL<<bit);
            refused(bank,0,8,1,456,DEVICE_BAD_VALUE);
            refused(bank,0,8,0,456,DEVICE_BAD_VALUE);   /* corrupt: reads refused too */
            states[bank].energy_restore.written=3;
        }
        struct device_model original=models[bank];
        for(unsigned word=0;word<5;word++) {
            models[bank].config[word]=1;
            refused(bank,0,8,1,0,DEVICE_BAD_CONFIG);models[bank]=original;
        }
        models[bank].span=0x2000;refused(bank,0,8,1,0,DEVICE_BAD_CONFIG);models[bank]=original;
    }
    for(unsigned bank=0;bank<8;bank++) {
        memcpy(expected,states,sizeof(states));memset(expected+bank,0,sizeof(*expected));
        CHECK(device_model_start(models+bank,states+bank,0,24000000)==DEVICE_OK);
        CHECK(!memcmp(expected,states,sizeof(states)));
    }
    uint64_t value=0;
    CHECK(device_model_access(models,0,8,1,&value)==DEVICE_BAD_CONFIG);
    CHECK(device_model_access_state(models,states,0,8,1,0)==DEVICE_BAD_CONFIG);
    /* Enable configuration is independent of energy values and CPU power.
     * It may be read back, but never licenses a fabricated sample. */
    struct device_model controls[2]={
        {21,0x210e70000,0x1000,{0}}, {21,0x211e70000,0x1000,{1}}
    };
    static struct device_state control_states[2],control_saved[2];
    const uint64_t enabled=0xa800000000000000UL;
    memcpy(expected,states,sizeof(states));
    for(unsigned cluster=0;cluster<2;cluster++) {
        CHECK(device_model_start(controls+cluster,control_states+cluster,0,24000000)==DEVICE_OK);
        uint64_t v=123;
        CHECK(device_model_access_state(controls+cluster,control_states+cluster,0x178,8,0,&v)==DEVICE_OK && v==0);
        for(unsigned turn=0;turn<6;turn++) {
            uint64_t request=turn%2 ? 0 : enabled;v=request;
            CHECK(device_model_access_state(controls+cluster,control_states+cluster,0x178,8,1,&v)==DEVICE_OK);
            v=123;CHECK(device_model_access_state(controls+cluster,control_states+cluster,0x178,8,0,&v)==DEVICE_OK && v==request);
            /* Enabling licenses no sample: every bank still reads its
             * constant (here the reset 0) and nothing changes. */
            for(unsigned bank=0;bank<8;bank++)for(unsigned slot=0;slot<2;slot++) {
                uint64_t e=123;memcpy(saved,states,sizeof(states));
                CHECK(access(bank,slot*8,8,0,&e)==DEVICE_OK && e==0 && !memcmp(saved,states,sizeof(states)));
            }
        }
        for(unsigned bit=0;bit<64;bit++) {
            v=1UL<<bit;memcpy(control_saved,control_states,sizeof(control_states));
            CHECK(device_model_access_state(controls+cluster,control_states+cluster,0x178,8,1,&v)==DEVICE_BAD_VALUE);
            CHECK(v==(1UL<<bit) && !memcmp(control_saved,control_states,sizeof(control_states)));
            control_states[cluster].pmgr_energy_control=1UL<<bit;
            memcpy(control_saved,control_states,sizeof(control_states));v=enabled;
            CHECK(device_model_access_state(controls+cluster,control_states+cluster,0x178,8,1,&v)==DEVICE_BAD_VALUE);
            CHECK(v==enabled && !memcmp(control_saved,control_states,sizeof(control_states)));
            control_states[cluster].pmgr_energy_control=0;
        }
        for(unsigned width=0;width<=16;width++)if(width!=8) {
            v=enabled;CHECK(device_model_access_state(controls+cluster,control_states+cluster,0x178,width,1,&v)==DEVICE_BAD_WIDTH);
        }
        v=enabled;CHECK(device_model_access_state(controls+cluster,control_states+cluster,0x178,8,1,&v)==DEVICE_OK);
    }
    CHECK(!memcmp(expected,states,sizeof(states)));
    memcpy(control_saved,control_states,sizeof(control_states));
    CHECK(device_model_start(controls,control_states,0,24000000)==DEVICE_OK);
    CHECK(control_states[0].pmgr_energy_control==0);
    CHECK(!memcmp(control_saved+1,control_states+1,sizeof(*control_states)));
    CHECK(device_model_access(controls,0x178,8,0,&value)==DEVICE_BAD_CONFIG);
    printf("PASS: CPU energy restore %u checks; eight isolated baseline pairs\n",checks);
    return 0;
}

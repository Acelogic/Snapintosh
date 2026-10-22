/* SPDX-License-Identifier: MIT */
/* Frozen restore/readback; enabled sampling reads the programmed value (no event producer). */
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "device.h"
static unsigned checks;
#define CHECK(x) do { checks++; if (!(x)) { fprintf(stderr,"line %u: %s\n",__LINE__,#x); exit(1); } } while (0)
static struct device_model models[]={
    {34,0x30006d000,0x2000,{0}}, {34,0x300720000,0x3000,{1}},
    {34,0x300778000,0x1000,{2}}, {34,0x30077c000,0x1000,{3}},
    {34,0x3007a0000,0x1000,{4}}, {34,0x302900000,0x1000,{5}},
};
static struct device_state states[6],saved[6];
static unsigned slots[6][295],counts[6];
static enum device_result access(unsigned g,unsigned off,unsigned width,int write,uint64_t *v)
{ return device_model_access_state(models+g,states+g,off,width,write,v); }
static void reset(void)
{
    memset(states,0,sizeof(states));CHECK(device_models_valid(models,6,0,0));
    for(unsigned g=0;g<6;g++) CHECK(device_model_start(models+g,states+g,0,24000000)==DEVICE_OK);
}
static void put(unsigned g,unsigned off,uint64_t value)
{ CHECK(access(g,off,4,1,&value)==DEVICE_OK); }
static uint64_t get(unsigned g,unsigned off)
{ uint64_t v=123;CHECK(access(g,off,4,0,&v)==DEVICE_OK);return v; }
static void refused(unsigned g,unsigned off,unsigned width,int write,uint64_t value,enum device_result want)
{
    uint64_t v=value;memcpy(saved,states,sizeof(states));
    enum device_result got=access(g,off,width,write,&v);
    if(got!=want)fprintf(stderr,"group%u:%x width%u write%d got%u want%u\n",g,off,width,write,got,want);
    CHECK(got==want);CHECK(v==value && !memcmp(states,saved,sizeof(states)));
}
static void restore(unsigned g,unsigned off,uint64_t v)
{ put(g,off+0x10,(uint32_t)v);put(g,off+0x14,v>>32); }
static void sample(unsigned g,unsigned off,uint64_t v)
{
    /* Stock reader checks high/low/high before joining the two words. */
    uint64_t high=get(g,off+0x14),low=get(g,off+0x10);
    CHECK(high==get(g,off+0x14));CHECK((high<<32|low)==v);
}
int main(int argc,char **argv)
{
    CHECK(sizeof(struct device_state)==13000);
    CHECK(offsetof(struct device_state,pmgr_perf.control)==0);
    CHECK(offsetof(struct device_state,pmgr_perf.extra)==1184);
    CHECK(offsetof(struct device_state,pmgr_perf.written)==1496);
    reset();
    /* Export actual accepted control offsets for independent DT comparison. */
    for(unsigned g=0;g<6;g++) {
        unsigned bias=g==0 ? 0x800 : 0;
        for(unsigned off=bias+0x100;off<models[g].span;off+=0x20) {
            uint64_t v=123;
            enum device_result result=access(g,off,4,0,&v);
            if(result==DEVICE_OK) {
                CHECK(v==0 && counts[g]<295);slots[g][counts[g]++]=off;
                if(argc==2 && !strcmp(argv[1],"--topology"))printf("%u %u\n",g,off-bias);
            } else CHECK(result==DEVICE_UNKNOWN_REGISTER && v==123);
        }
    }
    CHECK(counts[0]==137 && counts[1]==295 && counts[2]==26 &&
          counts[3]==26 && counts[4]==26 && counts[5]==8);
    if(argc==2 && !strcmp(argv[1],"--topology"))return 0;
    for(unsigned g=0;g<6;g++) {
        unsigned bias=g==0 ? 0x800 : 0;
        for(unsigned n=0;n<counts[g];n++) {
            unsigned off=slots[g][n];uint64_t v=0xa5c3987210000000UL|((uint64_t)g<<16)|off;
            CHECK(get(g,off)==0);
            refused(g,off+0x10,4,0,123,DEVICE_BAD_VALUE);
            put(g,off+0x14,v>>32);
            refused(g,off+0x10,4,0,123,DEVICE_BAD_VALUE);
            put(g,off+0x10,(uint32_t)v);sample(g,off,v);
            /* Per-counter enable is frozen while the group is disabled. */
            put(g,off,4);sample(g,off,v);put(g,off,5);sample(g,off,v);
            /* Global enable invalidates the frozen snapshot, but an enabled
             * counter that nothing drives still reads its programmed value:
             * IOReport samples see no activity (docs/PMGR-IOREPORT-20261017.md).
             * Disabling cannot revive the snapshot; a new frozen restore is needed. */
            put(g,bias,1);sample(g,off,v);
            restore(g,off,0);sample(g,off,0);
            put(g,bias,0);refused(g,off+0x10,4,0,123,DEVICE_BAD_VALUE);
            restore(g,off,UINT64_MAX);sample(g,off,UINT64_MAX);
            put(g,off,1);put(g,bias,1);sample(g,off,UINT64_MAX);
            put(g,off,4);put(g,off,0);
            refused(g,off+0x10,4,0,123,DEVICE_BAD_VALUE);
            restore(g,off,v);sample(g,off,v);put(g,bias,0);
            for(unsigned bit=0;bit<64;bit++) {
                if(bit!=0 && bit!=2)refused(g,off,4,1,1UL<<bit,DEVICE_BAD_VALUE);
                if(bit>=32)for(unsigned word=0x10;word<=0x14;word+=4)
                    refused(g,off+word,4,1,1UL<<bit,DEVICE_BAD_VALUE);
            }
            /* Corrupt state cannot be repaired by acknowledging a new write. */
            states[g].pmgr_perf.written[n]=4;
            refused(g,off+0x10,4,1,0,DEVICE_BAD_VALUE);
            refused(g,bias,4,1,1,DEVICE_BAD_VALUE);
            states[g].pmgr_perf.written[n]=3;
            states[g].pmgr_perf.control[n+1]=2;
            refused(g,off,4,1,0,DEVICE_BAD_VALUE);
            refused(g,bias,4,1,1,DEVICE_BAD_VALUE);
            states[g].pmgr_perf.control[n+1]=0;
        }
        for(unsigned off=0;off<models[g].span;off+=4) {
            int known=off==bias;
            for(unsigned n=0;n<counts[g];n++)
                known|=off==slots[g][n] || off==slots[g][n]+0x10 || off==slots[g][n]+0x14;
            if(!known)for(int write=0;write<2;write++)
                refused(g,off,4,write,0,DEVICE_UNKNOWN_REGISTER);
        }
        for(unsigned width=0;width<=16;width++)if(width!=4)
            refused(g,bias,width,1,0,DEVICE_BAD_WIDTH);
        refused(g,bias+1,4,1,0,DEVICE_BAD_WIDTH);
        refused(g,(unsigned)models[g].span,4,0,123,DEVICE_NOT_FOUND);
        for(unsigned bit=1;bit<64;bit++)refused(g,bias,4,1,1UL<<bit,DEVICE_BAD_VALUE);
        states[g].pmgr_perf.control[0]=2;
        refused(g,bias,4,1,0,DEVICE_BAD_VALUE);states[g].pmgr_perf.control[0]=0;
    }
    /* All banks retain distinct high/low values; no alias at slot 255/256. */
    for(unsigned g=0;g<6;g++)for(unsigned n=0;n<counts[g];n++)
        sample(g,slots[g][n],0xa5c3987210000000UL|((uint64_t)g<<16)|slots[g][n]);
    for(unsigned g=0;g<6;g++) {
        uint64_t value=0;
        CHECK(device_model_access(models+g,g==0?0x800:0,4,1,&value)==DEVICE_BAD_CONFIG);
        struct device_model original=models[g];
        for(unsigned cfg=0;cfg<5;cfg++) {
            models[g].config[cfg]=cfg==0 ? 6 : 1;
            refused(g,0,4,1,0,DEVICE_BAD_CONFIG);models[g]=original;
        }
        models[g].span+=0x1000;refused(g,0,4,1,0,DEVICE_BAD_CONFIG);models[g]=original;
        CHECK(device_model_start(models+g,states+g,0,24000000)==DEVICE_OK);
        CHECK(!memcmp(states+g,&(struct device_state){0},sizeof(struct device_state)));
    }
    printf("PASS: SOC performance-counter restore %u checks, 518 exact slots\n",checks);
    return 0;
}

/* SPDX-License-Identifier: MIT */
/* AVE TVM disable, SOC cluster power and encoder/rail ownership. */
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "device.h"
static unsigned checks;
#define CHECK(x) do { checks++; if (!(x)) { fprintf(stderr,"line %u: %s\n",__LINE__,#x); exit(1); } } while (0)
static const struct device_model original[]={
    {18,0x300700000,0x11000,{0}},
    {18,0x308280000,0x9000,{1}},
    {25,0x3003c0000,0x14000,{0x10000,0x1a8,0x1b8,8,DEVICE_PMP_ACTIVE_MASK}},
    {32,0x3028a4000,0x6000,{0}},
    {17,0x285080000,0xc000,{16,44,955,36,0}},
    {17,0x2850a0000,0xc000,{16,44,955,36,0}},
    {17,0x289080000,0xc000,{16,44,967,36,0}},
    {17,0x2890a0000,0xc000,{16,44,967,36,0}},
    {26,0x300780000,0x1000,{DEVICE_PMGR_AVE_CLUSTER_V1}},
    {33,0x300760000,0x1000,{0}},
};
static struct device_model models[11];
static struct device_state states[11],saved[11];
static unsigned count;
static enum device_result access(unsigned i,unsigned off,unsigned width,int write,uint64_t *v)
{ return device_models_access_at(models,states,count,i,0,off,width,write,v); }
static void reset(void)
{
    count=10;memset(models,0,sizeof(models));memcpy(models,original,sizeof(original));
    memset(states,0,sizeof(states));CHECK(device_models_valid(models,count,0,0));
    for(unsigned i=0;i<count;i++) CHECK(device_model_start(models+i,states+i,0,24000000)==DEVICE_OK);
}
static void put(unsigned i,unsigned off,uint64_t value)
{ CHECK(access(i,off,4,1,&value)==DEVICE_OK); }
static uint64_t get(unsigned i,unsigned off)
{ uint64_t v=123;CHECK(access(i,off,4,0,&v)==DEVICE_OK);return v; }
static void refused(unsigned i,unsigned off,unsigned width,int write,uint64_t value,enum device_result want)
{
    uint64_t v=value;memcpy(saved,states,sizeof(states));
    enum device_result got=access(i,off,width,write,&v);
    if(got!=want)fprintf(stderr,"%u:%x width%u write%d got%u want%u\n",i,off,width,write,got,want);
    CHECK(got==want);CHECK(v==value && !memcmp(states,saved,sizeof(states)));
}
static void idle(void)
{
    for(unsigned n=10;n;n--)put(0,0x8000+8*(n-1),0x3f0);
    put(0,0x240,0x3f0);put(0,0x248,0x3f0);
}
int main(void)
{
    reset();CHECK(get(8,8)==15 && states[8].pmgr_ave_cluster==15);
    CHECK(get(8,0)==15 && get(8,4)==15);
    refused(8,0,4,1,0,DEVICE_BAD_VALUE);refused(8,4,4,1,0,DEVICE_BAD_VALUE);
    refused(8,8,4,1,0,DEVICE_BAD_VALUE);
    refused(9,0x400,4,1,0,DEVICE_BAD_VALUE);
    idle();CHECK(get(9,0x400)==0);put(9,0x400,0);CHECK(!(get(9,0x7e0)&2));
    /* Stock RMW and busy poll. Disable cannot alter unrelated power or ACK. */
    uint64_t ack=states[2].pmp_active.ack;
    uint64_t value=get(8,8)&~15UL;put(8,8,value);
    CHECK(get(8,8)==0 && !(get(8,8)&16));CHECK(states[2].pmp_active.ack==ack);
    for(unsigned off=0x8000;off<=0x8048;off+=8)
        refused(0,off,4,1,15,DEVICE_BAD_VALUE);
    refused(0,0x240,4,1,15,DEVICE_BAD_VALUE);
    refused(0,0x248,4,1,15,DEVICE_BAD_VALUE);
    for(unsigned i=4;i<8;i++)refused(i,0,4,0,123,DEVICE_BAD_VALUE);
    refused(2,0x10c40,8,1,DEVICE_PMP_VENC0_BIT,DEVICE_BAD_VALUE);
    refused(2,0x10c40,8,1,DEVICE_PMP_VENC1_BIT,DEVICE_BAD_VALUE);
    /* SOC cluster must stop before its separate virtual PMC rail. */
    put(3,0x5c18,0);CHECK(get(3,0x5c1c)==0);
    refused(8,8,4,1,15,DEVICE_BAD_VALUE);
    put(3,0x5c18,8);put(8,8,15);CHECK(get(8,8)==15);
    refused(3,0x5c18,4,1,0,DEVICE_BAD_VALUE);
    put(0,0x240,15);CHECK((get(0,0x240)&15)==15);
    refused(8,8,4,1,0,DEVICE_BAD_VALUE);
    /* New TVM work is not silently acknowledged by the idle-only backend. */
    reset();idle();
    for(unsigned bit=0;bit<64;bit++)refused(9,0x400,4,1,1UL<<bit,DEVICE_BAD_VALUE);
    refused(9,0x7e0,4,1,0,DEVICE_UNKNOWN_REGISTER);
    for(unsigned off=0;off<0x1000;off+=4) if(off!=0x400 && off!=0x7e0) {
        refused(9,off,4,0,123,DEVICE_UNKNOWN_REGISTER);
        refused(9,off,4,1,0,DEVICE_UNKNOWN_REGISTER);
    }
    for(unsigned width=0;width<=16;width++)if(width!=4) {
        refused(9,0x400,width,0,123,DEVICE_BAD_WIDTH);
        refused(8,8,width,1,0,DEVICE_BAD_WIDTH);
    }
    refused(9,0x401,4,0,123,DEVICE_BAD_WIDTH);
    for(unsigned v=1;v<32;v++)if(v!=15)refused(8,8,4,1,v,DEVICE_BAD_VALUE);
    /* Every owned DART runtime word must be idle, with atomic refusal. */
    for(unsigned bank=4;bank<8;bank++)for(unsigned w=0;w<sizeof(struct dart_state)/4;w++) {
        /* Alignment padding is not an owned DART runtime resource. */
        if(w*4>=offsetof(struct dart_state,tlb_end)+4 &&
           w*4<offsetof(struct dart_state,translations))continue;
        reset();idle();uint32_t one=1;memcpy((char *)&states[bank].dart+w*4,&one,4);
        refused(9,0x7e0,4,0,123,DEVICE_BAD_VALUE);
        refused(8,8,4,1,0,DEVICE_BAD_VALUE);
    }
    for(unsigned u=0;u<2;u++) {
        reset();idle();states[2].pmp_active.request=DEVICE_PMP_VENC0_BIT<<u;
        refused(9,0x400,4,1,0,DEVICE_BAD_VALUE);
    }
    reset();idle();states[2].pmp_active.ack^=1;
    refused(9,0x400,4,0,123,DEVICE_BAD_VALUE);
    /* No direct local call can mutate the owned AVE cluster or fake TVM idle. */
    reset();idle();value=0;
    CHECK(device_model_access_state(models+8,states+8,8,4,1,&value)==DEVICE_BAD_CONFIG);
    CHECK(device_model_access_state(models+9,states+9,0x400,4,1,&value)==DEVICE_BAD_CONFIG);
    for(unsigned i=0;i<10;i++) {
        reset();models[i].base+=0x10000;
        CHECK(!device_models_valid(models,count,0,0));
        refused(9,0x400,4,1,0,DEVICE_BAD_CONFIG);
    }
    reset();models[8].config[0]=0;CHECK(!device_models_valid(models,count,0,0));
    refused(9,0x400,4,0,123,DEVICE_BAD_CONFIG);
    reset();count=11;models[10]=models[9];CHECK(!device_models_valid(models,count,0,0));
    refused(9,0x400,4,0,123,DEVICE_BAD_CONFIG);
    const uint64_t absent[]={0x285100000,0x285800000,0x285050000,0x285094000,0x2850b0000};
    for(unsigned u=0;u<2;u++)for(unsigned w=0;w<5;w++)for(unsigned overlap=0;overlap<2;overlap++) {
        reset();count=11;
        models[10]=(struct device_model){27,absent[w]+u*0x4000000UL-overlap*0x800,0x1000,{0}};
        CHECK(!device_models_valid(models,count,0,0));
        refused(9,0x400,4,0,123,DEVICE_BAD_CONFIG);
    }
    reset();idle();put(8,8,0);states[0].pmgr_venc_sys[0]=15;
    refused(8,8,4,0,123,DEVICE_BAD_VALUE);
    reset();idle();states[8].pmgr_ave_cluster=4;
    refused(9,0x400,4,0,123,DEVICE_BAD_VALUE);
    printf("AVE TVM/cluster ownership: %u checks passed\n",checks);return 0;
}

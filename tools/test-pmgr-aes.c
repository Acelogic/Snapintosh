/* SPDX-License-Identifier: MIT */
/* Native AES clock-off after completion must retain the shared SIO mapper. */
#include "device.h"
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static unsigned checks;
#define CHECK(x) do {checks++;if (!(x)) {fprintf(stderr,"FAIL %d: %s\n",__LINE__,#x);exit(1);}} while(0)
enum { PMGR, AES, SIO, COUNT };
static const struct device_model original[COUNT]={
    {18,0x300700000UL,0x11000,{0,0,0,0,0}},
    {47,0x38500c000UL,0x4000,{5,42,1107,21,1}},
    {17,0x385060000UL,0x20000,{16,300,1120,36,1U<<21}},
};
static struct device_model models[COUNT+1];
static struct device_state states[COUNT+1],saved[COUNT+1];
static unsigned count;
static void reset(void)
{
    count=COUNT;memcpy(models,original,sizeof(original));
    memset(states,0,sizeof(states));CHECK(device_models_valid(models,count,0,0));
    for (unsigned i=0;i<count;i++) CHECK(device_model_start(models+i,states+i,0,24000000)==DEVICE_OK);
    /* State recorded at the real driver's clock-off request. */
    states[AES].aes.threshold=64;states[AES].aes.completed_tag=1;
    states[AES].aes.commands=6;states[AES].aes.transfers=1;states[AES].aes.bytes=16;
    states[AES].aes.barriers=2;states[AES].aes.iv_exports=1;
    memset(&states[AES].aes.keys,0x5a,sizeof(states[AES].aes.keys));
    memset(&states[AES].aes.iv,0xa5,sizeof(states[AES].aes.iv));
    states[SIO].dart.initialized_ids=states[SIO].dart.powered_ids=1U<<21;
    states[SIO].dart.enabled[0]=2;states[SIO].dart.tcr[1]=9;
    states[SIO].dart.ttbr[1]=0x9413e5;states[SIO].dart.flushes=2;
}
static enum device_result ps(unsigned width,int write,uint64_t *v)
{ return device_models_access_at(models,states,count,PMGR,0,0x308,width,write,v); }
static void wr(uint64_t v) { CHECK(ps(4,1,&v)==DEVICE_OK); }
static uint64_t rd(void) { uint64_t v=0;CHECK(ps(4,0,&v)==DEVICE_OK);return v; }
static void refused(uint64_t v,unsigned width,enum device_result want)
{
    memcpy(saved,states,sizeof(states));uint64_t input=v;
    CHECK(ps(width,1,&v)==want);CHECK(v==input && !memcmp(saved,states,sizeof(states)));
}
static void retained(void)
{
    CHECK(!memcmp(states+AES,saved+AES,sizeof(*states)));
    CHECK(!memcmp(states+SIO,saved+SIO,sizeof(*states)));
    uint64_t v=0;CHECK(device_models_access_at(models,states,count,PMGR,0,0x260,4,0,&v)==DEVICE_OK && v==0xff);
    v=0;CHECK(device_models_access_at(models,states,count,PMGR,0,0x260,4,1,&v)==DEVICE_BAD_VALUE);
    unsigned index=99;
    CHECK(device_dart_admit_frame(models,states,count,5,21,1,0,&index)==DEVICE_OK && index==SIO);
}
int main(int argc,char **argv)
{
    reset();CHECK(sizeof(struct device_state)==13000);
    CHECK(offsetof(struct device_state,pmgr_aes)==offsetof(struct device_state,pmgr_cpu_writes)+4);
    CHECK(rd()==0xff && device_aes_powered(models,states,count,AES)==DEVICE_OK);
    memcpy(saved,states,sizeof(states));wr(0x0f0003f0);CHECK(rd()==0x100);
    CHECK(device_aes_powered(models,states,count,AES)==DEVICE_BAD_VALUE);retained();
    wr(0x30f);CHECK(rd()==0xff && device_aes_powered(models,states,count,AES)==DEVICE_OK);retained();
    static const unsigned levels[]={0,4,15};
    for(unsigned from=0;from<3;from++) for(unsigned to=0;to<3;to++) {
        reset();wr(0x300|levels[from]);wr(0x300|levels[from]);
        memcpy(saved,states,sizeof(states));wr(0x0f0500f0|levels[to]);
        unsigned hist=from==to ? 0 : levels[to]==0 ? 0x100 : levels[to]==4 ? 0x200 : 0;
        CHECK(rd()==(0x50000|levels[to]|levels[to]<<4|hist));retained();
        CHECK(device_aes_powered(models,states,count,AES)==(levels[to]==15 ? DEVICE_OK : DEVICE_BAD_VALUE));
        wr(0x300|levels[to]);CHECK(rd()==(levels[to]|levels[to]<<4));
    }
    /* No power transition may discard work or an unconsumed completion. */
    for(unsigned target=0;target<2;target++) {
#define BUSY(field) do {reset();states[AES].aes.field=1;refused(levels[target],4,DEVICE_BAD_VALUE);} while(0)
        BUSY(running);BUSY(header);BUSY(used);BUSY(need);BUSY(irq_status);BUSY(irq_enable);
#undef BUSY
    }
    reset();states[AES].aes.ready=0;refused(0,4,DEVICE_BAD_CONFIG);
    for(unsigned bit=0;bit<32;bit++) if(!((0x30fU>>bit)&1)) {
        reset();states[PMGR].pmgr_aes|=1U<<bit;refused(0,4,DEVICE_BAD_VALUE);
        CHECK(device_aes_powered(models,states,count,AES)==DEVICE_BAD_VALUE);
    }
    for(unsigned level=1;level<15;level++) if(level!=4) {reset();refused(level,4,DEVICE_BAD_VALUE);}
    reset();refused(1UL<<28,4,DEVICE_BAD_VALUE);refused(0,8,DEVICE_BAD_WIDTH);
    for(unsigned bit=0;bit<64;bit++) if(!((0x1f0f03ffUL>>bit)&1)) refused(1UL<<bit,4,DEVICE_BAD_VALUE);
    uint64_t v=0;CHECK(device_model_access_state(models+PMGR,states+PMGR,0x308,4,1,&v)==DEVICE_BAD_VALUE);
    for(unsigned i=0;i<COUNT;i++) {
        reset();models[COUNT]=models[i];states[COUNT]=states[i];count++;
        refused(0,4,DEVICE_BAD_CONFIG);CHECK(device_aes_powered(models,states,count,AES)==DEVICE_BAD_CONFIG);
    }
    for(unsigned i=0;i<COUNT;i++) {
        reset();models[i].kind=0;refused(0,4,DEVICE_BAD_CONFIG);
        CHECK(device_aes_powered(models,states,count,AES)==DEVICE_BAD_CONFIG);
    }
    for(unsigned i=0;i<5;i++) {
        reset();models[SIO].config[i]^=1;refused(0,4,DEVICE_BAD_CONFIG);
        reset();models[AES].config[i]^=1;refused(0,4,DEVICE_BAD_CONFIG);
    }
    reset();CHECK(device_aes_powered(models,states,count,PMGR)==DEVICE_BAD_CONFIG);
    CHECK(device_aes_powered(0,states,count,AES)==DEVICE_BAD_CONFIG);
    CHECK(device_aes_powered(models,0,count,AES)==DEVICE_BAD_CONFIG);
    if(argc==2 && !strcmp(argv[1],"--topology")) puts("776 608 0");
    else printf("AES PMGR lifecycle: %u checks passed (idle admission, wake, retained SIO, atomic refusals)\n",checks);
}

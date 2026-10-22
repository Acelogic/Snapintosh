/* SPDX-License-Identifier: MIT */
#include "device.h"
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static unsigned checks;
#define CHECK(x) do {checks++;if(!(x)){fprintf(stderr,"FAIL %d: %s\n",__LINE__,#x);exit(1);}}while(0)
_Static_assert(sizeof(struct device_state)==13000,"preserve live auditor ABI");
_Static_assert(offsetof(struct device_state,spmi_recovery)==offsetof(struct device_state,pmu_rtc),"recovery alias");
_Static_assert(sizeof(struct device_pmu_rtc)==112,"RTC capture ABI");
static struct device_model model={DEVICE_SPMI_PMU_RTC_V1,0x308700000UL,0x18000,
    {0x14000,0x4000,487,1790200000123456UL,PMU_RTC_CONTRACT}};
static struct device_state state;
static uint64_t now=1000000000UL;
static uint64_t access_at(unsigned reg,int write,uint64_t value)
{
    CHECK(device_model_access_at(&model,&state,now,0x14000+reg,4,write,&value)==DEVICE_OK);
    return value;
}
static uint32_t command(unsigned reg,unsigned n,int write,unsigned sid)
{return (reg<<16)|0x8000|(sid<<8)|((write?0x30:0x38)+n-1);}
static void submit(uint32_t cmd,const uint8_t *bytes,unsigned n)
{
    access_at(4,1,cmd);
    for(unsigned j=0;j<n;j+=4) {
        uint32_t word=0;for(unsigned b=0;b<4 && j+b<n;b++)word|=(uint32_t)bytes[j+b]<<(8*b);
        access_at(4,1,word);
    }
}
static uint64_t counter(void)
{
    uint32_t cmd=command(0xf802,6,0,14);submit(cmd,0,0);
    CHECK(access_at(8,0,0)==((cmd&0xfff)|(63U<<16)));
    uint64_t raw=access_at(8,0,0);raw|=access_at(8,0,0)<<32;
    CHECK(!(raw&1));CHECK(!(raw>>48));CHECK(access_at(0,0,0)&(1U<<24));
    return raw>>1;
}
int main(void)
{
    CHECK(device_model_start(&model,&state,now,24000000)==DEVICE_OK);
    uint64_t seed=(model.config[3]/1000000)*32768+(model.config[3]%1000000)*32768/1000000;
    CHECK(counter()==seed);CHECK(state.pmu_rtc.counter_reads==1);
    CHECK(state.spmi.flags[8]==1);access_at(0x80,1,1);CHECK(state.spmi.flags[8]==0);
    uint64_t first=now;
    for(unsigned i=1;i<=32768;i++) {
        now=first+(uint64_t)i*24000000/32768;
        uint64_t expected=seed+(now-first)*32768/24000000;
        CHECK(counter()==expected);
    }
    CHECK(counter()==seed+32768); /* a read cannot advance the clock */
    now+=24000000*61UL;CHECK(counter()==seed+62UL*32768);
    uint8_t seconds[]={0x78,0x56,0x34,0x12},fraction[]={0xab,0x45};
    uint32_t cmd=command(0xf704,4,1,14);submit(cmd,seconds,4);
    CHECK(access_at(8,0,0)==((cmd&0xfff)|(1U<<15)));
    cmd=command(0xf715,2,1,14);submit(cmd,fraction,2);
    CHECK(access_at(8,0,0)==((cmd&0xfff)|(1U<<15)));
    cmd=command(0xf704,4,0,14);submit(cmd,0,0);
    CHECK(access_at(8,0,0)==((cmd&0xfff)|(15U<<16)));CHECK(access_at(8,0,0)==0x12345678);
    cmd=command(0xf715,2,0,14);submit(cmd,0,0);
    CHECK(access_at(8,0,0)==((cmd&0xfff)|(3U<<16)));CHECK(access_at(8,0,0)==0x45ab);
    CHECK(counter()==seed+62UL*32768); /* offset changes do not rewrite the upcounter */
    uint8_t before[6];memcpy(before,state.pmu_rtc.offset,6);
    for(unsigned sid=0;sid<16;sid++)if(sid!=14) {
        cmd=command(0xf704,4,1,sid);submit(cmd,seconds,4);
        CHECK(access_at(8,0,0)==(cmd&0xfff));CHECK(!memcmp(before,state.pmu_rtc.offset,6));
    }
    unsigned invalid[]={0xf703,0xf708,0xf714,0xf716,0xf800,0x8800};
    for(unsigned i=0;i<sizeof(invalid)/sizeof(*invalid);i++) {
        cmd=command(invalid[i],4,1,14);submit(cmd,seconds,4);
        CHECK(access_at(8,0,0)==(cmd&0xfff));CHECK(!memcmp(before,state.pmu_rtc.offset,6));
    }
    /* Native short writes (opcode40, data at 31:24) reach no RTC field: NACK,
     * one header, failed write ACK, and no change to either offset field. */
    uint64_t rejected=state.pmu_rtc.rejected;
    for(unsigned reg=0;reg<32;reg++) {
        access_at(0x80,1,UINT32_MAX);
        cmd=(0x5aU<<24)|(reg<<16)|0x8000|(14U<<8)|0x40;access_at(4,1,cmd);
        CHECK(access_at(8,0,0)==(cmd&0xfff));CHECK(!memcmp(before,state.pmu_rtc.offset,6));
        CHECK(state.spmi.flags[8]==((1U<<7)|1));CHECK(access_at(0,0,0)==0x01000100);
    }
    CHECK(state.pmu_rtc.rejected==rejected+32);access_at(0x80,1,UINT32_MAX);
    cmd=command(0xf802,4,1,14);submit(cmd,seconds,4);CHECK(access_at(8,0,0)==(cmd&0xfff));
    now--;cmd=command(0xf802,6,0,14);submit(cmd,0,0);
    CHECK(access_at(8,0,0)==(cmd&0xfff));CHECK(access_at(8,0,0)==0);CHECK(access_at(8,0,0)==0);
    CHECK(state.spmi.flags[8]&(1U<<6));
    uint64_t value=0;
    CHECK(device_model_access_state(&model,&state,0x14000,4,0,&value)==DEVICE_BAD_CONFIG);
    model.config[3]=0;CHECK(device_model_start(&model,&state,now,24000000)==DEVICE_BAD_CONFIG);
    CHECK(!state.pmu_rtc.ready);CHECK(device_model_access_at(&model,&state,now,0x14000,4,0,&value)==DEVICE_BAD_CONFIG);
    model.config[3]=PMU_RTC_LIMIT_US;CHECK(device_model_start(&model,&state,now,24000000)==DEVICE_OK);
    CHECK(counter()==(UINT64_C(1)<<47)-1);
    now+=24000000;cmd=command(0xf802,6,0,14);submit(cmd,0,0);
    CHECK(access_at(8,0,0)==(cmd&0xfff));CHECK(access_at(8,0,0)==0);CHECK(access_at(8,0,0)==0);
    model.config[3]=1790200000123456UL;
    CHECK(device_model_start(&model,&state,now,0)==DEVICE_BAD_CONFIG);
    CHECK(device_model_start(&model,&state,now,UINT64_C(1)<<32)==DEVICE_BAD_CONFIG);
    model.base+=0x100000;CHECK(!device_models_valid(&model,1,0,0));model.base-=0x100000;
    model.config[4]^=1;CHECK(!device_models_valid(&model,1,0,0));
    printf("PASS %u RTC timing, packet, persistence, refusal and ABI checks\n",checks);
    return 0;
}

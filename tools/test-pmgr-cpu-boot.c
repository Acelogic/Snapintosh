/* SPDX-License-Identifier: MIT */
/* CPU0 bootstrap requests differ from actual CPU/cluster ownership. */
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "device.h"
static unsigned checks;
#define CHECK(x) do { checks++; if (!(x)) { fprintf(stderr,"line %u: %s\n",__LINE__,#x); exit(1); } } while (0)
static const struct device_model original[]={
    {18,0x300700000,0x11000,{0,DEVICE_PMGR_CPU0_BOOT_V1,0,0,0}},
    {18,0x308280000,0x9000,{1,0,0,0,0}},
    {26,0x300780000,0x1000,{0}},
    {25,0x3003c0000,0x14000,{0x10000,0x1a8,0x1b8,8,DEVICE_PMP_ACTIVE_MASK}},
};
static const unsigned offsets[]={0,8,0x10,0x18,0x30,0x38,0x50,0x58};
static const unsigned actual[]={15,0,0,0,0,0,15,15};
static struct device_model models[5];
static struct device_state states[5],saved[5];
static unsigned count;
static void reset(void)
{
    count=4;memset(models,0,sizeof(models));memcpy(models,original,sizeof(original));
    memset(states,0,sizeof(states));CHECK(device_models_valid(models,count,0,0));
    CHECK(device_models_boot_cpu_valid(models,count,0x80000000));
    for(unsigned i=0;i<count;i++) CHECK(device_model_start(models+i,states+i,0,24000000)==DEVICE_OK);
}
static enum device_result access_word(unsigned index,unsigned off,unsigned width,int write,uint64_t *v)
{ return device_models_access_at(models,states,count,index,0,off,width,write,v); }
static uint64_t read_ps(unsigned cpu)
{
    uint64_t v=UINT64_MAX;CHECK(access_word(0,offsets[cpu],4,0,&v)==DEVICE_OK);return v;
}
static void refused(unsigned index,unsigned off,unsigned width,int write,uint64_t v,enum device_result expected)
{
    uint64_t input=v;memcpy(saved,states,sizeof(states));
    enum device_result result=access_word(index,off,width,write,&v);
    if(result!=expected) fprintf(stderr,"index %u offset %x got %u expected %u\n",index,off,result,expected);
    CHECK(result==expected);CHECK(v==input && !memcmp(saved,states,sizeof(states)));
}
int main(int argc,char **argv)
{
    reset();CHECK(offsetof(struct device_state,pmgr_cpu_boot)==736);
    CHECK(offsetof(struct device_state,pmgr_cpu_reads)==768);
    CHECK(offsetof(struct device_state,pmgr_cpu_writes)==772);
    CHECK(!states[0].pmgr_cpu_reads && !states[0].pmgr_cpu_writes);
    for(unsigned cpu=0;cpu<8;cpu++) {
        CHECK(read_ps(cpu)==actual[cpu]*16);
        CHECK(states[0].pmgr_cpu_boot[cpu]==actual[cpu]*16);
        CHECK(!states[1].pmgr_cpu_boot[cpu]);
        /* Pinned _setPS compares target, control bits, and automatic policy
         * before deciding whether to write/poll. All requested-zero boot
         * entries qualify, including the actually powered boot CPU/CPMs. */
        uint64_t ps=read_ps(cpu);
        CHECK(!(ps&15) && !(ps&0x40000400) && !(ps&(1UL<<28)));
    }
    CHECK(states[0].pmgr_cpu_reads==255 && !states[0].pmgr_cpu_writes);
    uint64_t v=0;CHECK(access_word(2,0,4,0,&v)==DEVICE_OK && v==15);
    CHECK(access_word(2,4,4,0,&v)==DEVICE_OK && v==15);
    /* Actual CPM power remains on, so zero PMGR requests cannot erase
     * physical PMP ACK bits 7/8. PMP's internal reads aren't guest PS reads. */
    reset();v=0x3000;CHECK(access_word(3,0x10c40,8,1,&v)==DEVICE_OK);
    CHECK(states[3].pmp_active.ack==DEVICE_PMP_ACTIVE_MASK);
    CHECK(!states[0].pmgr_cpu_reads && !states[0].pmgr_cpu_writes);
    struct device_state pmp=states[3];
    for(unsigned cpu=0;cpu<8;cpu++) for(unsigned min=0;min<16;min++) {
        v=((uint64_t)min<<16)|0x300|0x0f0000f0;
        CHECK(access_word(0,offsets[cpu],4,1,&v)==DEVICE_OK);
        CHECK(read_ps(cpu)==(((uint64_t)min<<16)|(actual[cpu]<<4)));
        CHECK(!memcmp(&pmp,&states[3],sizeof(pmp)));
    }
    CHECK(states[0].pmgr_cpu_writes==255);
    for(unsigned cpu=0;cpu<8;cpu++) {
        reset();
        for(unsigned target=1;target<16;target++)
            refused(0,offsets[cpu],4,1,target,DEVICE_BAD_VALUE);
        for(unsigned bit=0;bit<64;bit++) if(!((0x0f0f03f0UL>>bit)&1))
            refused(0,offsets[cpu],4,1,1UL<<bit,DEVICE_BAD_VALUE);
        for(unsigned width=0;width<=16;width++) if(width!=4) {
            refused(0,offsets[cpu],width,0,123,DEVICE_BAD_WIDTH);
            refused(0,offsets[cpu],width,1,0,DEVICE_BAD_WIDTH);
        }
        refused(0,offsets[cpu]+1,4,1,0,DEVICE_BAD_WIDTH);
        refused(0,offsets[cpu]+4,4,1,0,DEVICE_UNKNOWN_REGISTER);
        /* Actual bits are read-only and cannot be altered by changing either
         * the request or a corrupted backing word. Refusal preserves masks. */
        for(unsigned bit=0;bit<32;bit++) {
            reset();states[0].pmgr_cpu_boot[cpu]^=1U<<bit;
            refused(0,offsets[cpu],4,0,123,DEVICE_BAD_VALUE);
            refused(0,offsets[cpu],4,1,0,DEVICE_BAD_VALUE);
        }
    }
    reset();
    for(unsigned bit=0;bit<64;bit++)
        CHECK(!device_models_boot_cpu_valid(models,count,0x80000000UL^(1UL<<bit)));
    CHECK(!device_models_boot_cpu_valid(NULL,4,0x80000000));
    CHECK(!device_models_boot_cpu_valid(models,DEVICE_MODEL_MAX+1,0x80000000));
    for(unsigned index=0;index<3;index++) {
        reset();models[index].base+=0x10000;
        CHECK(!device_models_valid(models,count,0,0));
        refused(0,0x58,4,0,123,DEVICE_BAD_CONFIG);
        refused(3,0x10c40,8,1,0x3000,DEVICE_BAD_CONFIG);
    }
    reset();models[2].kind=0;
    refused(0,0x58,4,0,123,DEVICE_BAD_CONFIG);
    reset();count=5;models[4]=models[2];refused(0,0x58,4,1,0,DEVICE_BAD_CONFIG);
    /* The cluster interface still refuses off. A no-vote PMGR read must
     * never be used as proof that either actual cluster has powered down. */
    reset();refused(2,0,4,1,0,DEVICE_BAD_VALUE);refused(2,4,4,1,0,DEVICE_BAD_VALUE);
    for(unsigned cpu=0;cpu<8;cpu++) (void)read_ps(cpu);
    CHECK(device_model_start(models,states,0,24000000)==DEVICE_OK);
    CHECK(!states[0].pmgr_cpu_reads && !states[0].pmgr_cpu_writes);
    for(unsigned cpu=0;cpu<8;cpu++) CHECK(read_ps(cpu)==actual[cpu]*16);
    if(argc==2 && !strcmp(argv[1],"--topology"))
        for(unsigned cpu=0;cpu<8;cpu++) printf("%u 0 %u\n",offsets[cpu],actual[cpu]);
    else printf("PMGR CPU boot requests and actual ownership: %u checks passed\n",checks);
    return 0;
}

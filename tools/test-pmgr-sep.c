/* SPDX-License-Identifier: MIT */
/* SEP_AON idle lifecycle, distinct from main SEP and virtual SEPOS services. */
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "device.h"
static unsigned checks;
#define CHECK(x) do { checks++; if (!(x)) { \
    fprintf(stderr,"line %u: %s\n",__LINE__,#x); exit(1); } } while (0)
enum { PMGR, DART, PMP, AON, EXTRA, COUNT=4 };
static const struct device_model original[COUNT]={
    {18,0x300700000,0x11000,{0,0,0,0,0}},
    {17,0x280b80000,0x20000,{3,44,353,36,1U<<20}},
    {25,0x3003c0000,0x14000,{0x10000,0x1a8,0x1b8,8,DEVICE_PMP_ACTIVE_MASK}},
    {18,0x308280000,0x9000,{1,0,0,0,0}},
};
static struct device_model models[COUNT+1];
static struct device_state states[COUNT+1],saved[COUNT+1];
static unsigned count=COUNT;
static enum device_result access_word(unsigned index,uint64_t off,unsigned width,
                                      int write,uint64_t *v)
{
    return device_models_access_at(models,states,count,index,0,off,width,write,v);
}
static void reset(void)
{
    count=COUNT;memset(models,0,sizeof(models));memcpy(models,original,sizeof(original));
    memset(states,0,sizeof(states));CHECK(device_models_valid(models,count,0,0));
    for (unsigned i=0;i<count;i++) CHECK(device_model_start(models+i,states+i,0,24000000)==DEVICE_OK);
}
static uint64_t read_ps(unsigned off)
{
    uint64_t v=UINT64_MAX;CHECK(access_word(PMGR,off,4,0,&v)==DEVICE_OK);return v;
}
static void write_ps(uint64_t v)
{
    CHECK(access_word(PMGR,0x60,4,1,&v)==DEVICE_OK);
}
static void refused(unsigned index,uint64_t off,unsigned width,int write,
                    uint64_t v,enum device_result expected)
{
    memcpy(saved,states,sizeof(states));uint64_t input=v;
    enum device_result actual=access_word(index,off,width,write,&v);
    if (actual!=expected) fprintf(stderr,"index %u off %llx width %u value %llx: got %u want %u\n",
        index,(unsigned long long)off,width,(unsigned long long)input,actual,expected);
    CHECK(actual==expected);CHECK(v==input && !memcmp(saved,states,sizeof(states)));
}
static void read_capabilities(unsigned index)
{
    const uint32_t expected[]={0x8e000000,1,(36U<<24)|(44U<<16)|(2U<<8),0x30003};
    for (unsigned word=0;word<4;word++) {
        memcpy(saved,states,sizeof(states));uint64_t v=UINT64_MAX;
        CHECK(access_word(index,word*4,4,0,&v)==DEVICE_OK && v==expected[word]);
        CHECK(!memcmp(saved,states,sizeof(states)));
    }
}
static void prepare_powerup(void)
{
    reset();models[DART].config[1]=DEVICE_DART_SEP_BOOT_V1;
    CHECK(device_models_valid(models,count,0,0));write_ps(0);
    CHECK(device_dart_monitor_init(models,states,count,20)==DEVICE_OK);
}
static void powerup_refused(enum device_result expected)
{
    memcpy(saved,states,sizeof(states));
    CHECK(device_dart_monitor_powerup(models,states,count,20)==expected);
    CHECK(!memcmp(saved,states,sizeof(states)));
}
static void test_powerup(void)
{
    reset();models[DART].config[1]=DEVICE_DART_SEP_BOOT_V1;
    powerup_refused(DEVICE_BAD_VALUE); /* INIT is required. */
    for(unsigned level=0;level<3;level++) {
        const unsigned levels[]={0,4,15};
        prepare_powerup();write_ps(levels[level]);read_capabilities(DART);
        refused(DART,0x1000,4,0,123,DEVICE_BAD_VALUE);
        memcpy(saved,states,sizeof(states));
        CHECK(device_dart_monitor_powerup(models,states,count,20)==DEVICE_OK);
        struct dart_state expected={.initialized_ids=1U<<20,.powered_ids=1U<<20};
        expected.tcr[0]=expected.tcr[1]=1;expected.tcr[2]=9;
        CHECK(!memcmp(&states[DART].dart,&expected,sizeof(expected)));
        for(unsigned i=0;i<count;i++)if(i!=DART)
            CHECK(!memcmp(states+i,saved+i,sizeof(*states)));
        read_capabilities(DART);
        for(unsigned sid=0;sid<3;sid++) {
            uint64_t v=123;
            CHECK(access_word(DART,0x1000+4*sid,4,0,&v)==DEVICE_OK && v==(sid<2 ? 1U : 9U));
            CHECK(access_word(DART,0x1400+4*sid,4,0,&v)==DEVICE_OK && v==0);
        }
        memcpy(saved,states,sizeof(states));
        CHECK(device_dart_monitor_powerup(models,states,count,20)==DEVICE_OK);
        CHECK(!memcmp(saved,states,sizeof(states)));
        unsigned index=123;
        CHECK(device_dart_admit_frame(models,states,count,5,20,0,0,&index)==DEVICE_OK);
        CHECK(index==DART && !memcmp(saved,states,sizeof(states)));
        refused(PMGR,0x60,4,1,0,DEVICE_BAD_VALUE); /* no destructive rail transition */
    }
    for(unsigned powered=0;powered<2;powered++) {
        for(unsigned sid=0;sid<DART_STREAMS;sid++) {
            prepare_powerup();if(powered)CHECK(device_dart_monitor_powerup(models,states,count,20)==DEVICE_OK);
            states[DART].dart.tcr[sid]^=1;powerup_refused(DEVICE_BAD_VALUE);
            prepare_powerup();if(powered)CHECK(device_dart_monitor_powerup(models,states,count,20)==DEVICE_OK);
            states[DART].dart.ttbr[sid]=1;powerup_refused(DEVICE_BAD_VALUE);
        }
        for(unsigned bank=0;bank<8;bank++) {
            prepare_powerup();if(powered)CHECK(device_dart_monitor_powerup(models,states,count,20)==DEVICE_OK);
            states[DART].dart.enabled[bank]=1;powerup_refused(DEVICE_BAD_VALUE);
            prepare_powerup();if(powered)CHECK(device_dart_monitor_powerup(models,states,count,20)==DEVICE_OK);
            states[DART].dart.error_streams[bank]=1;powerup_refused(DEVICE_BAD_VALUE);
        }
#define DIRTY(field) do { prepare_powerup(); \
        if(powered)CHECK(device_dart_monitor_powerup(models,states,count,20)==DEVICE_OK); \
        states[DART].dart.field=1;powerup_refused(DEVICE_BAD_VALUE); } while(0)
        DIRTY(error);DIRTY(error_mask);DIRTY(error_address);DIRTY(protect);DIRTY(protect_lock);
        DIRTY(tlb_op);DIRTY(tlb_start);DIRTY(tlb_end);DIRTY(translations);DIRTY(faults);DIRTY(flushes);
#undef DIRTY
    }
    prepare_powerup();states[DART].dart.powered_ids=1U<<21;powerup_refused(DEVICE_BAD_VALUE);
    prepare_powerup();states[PMP].pmp_active.request|=1UL<<27;powerup_refused(DEVICE_BAD_VALUE);
    prepare_powerup();states[PMP].pmp_active.ack|=1UL<<27;powerup_refused(DEVICE_BAD_VALUE);
    prepare_powerup();count=COUNT-1;powerup_refused(DEVICE_BAD_CONFIG);
    for(unsigned field=0;field<5;field++) {
        prepare_powerup();models[DART].config[field]^=1;powerup_refused(DEVICE_BAD_CONFIG);
    }
}
int main(int argc,char **argv)
{
    int topology=argc==2 && !strcmp(argv[1],"--topology");
    reset();CHECK(read_ps(0x60)==0xff && !states[AON].pmgr_sep_aon);
    CHECK(offsetof(struct device_state,pmgr_sep_aon)-offsetof(struct device_state,pmgr_policy)==732);
    uint64_t v=0x3000;CHECK(access_word(PMP,0x10c40,8,1,&v)==DEVICE_OK);
    struct device_state pmp=states[PMP];
    write_ps(0x3f0);CHECK(read_ps(0x60)==0x100);
    CHECK(!memcmp(&pmp,&states[PMP],sizeof(pmp)));
    /* SEP_AON is independent of main SEP and its AFISOCNI0 parent. */
    CHECK(read_ps(0xc00)==0xff && read_ps(0x218)==0xff);
    refused(PMGR,0xc00,4,1,0,DEVICE_BAD_VALUE);
    refused(PMGR,0x218,4,1,0,DEVICE_BAD_VALUE);
    read_capabilities(DART);
    refused(DART,0x104,4,1,1,DEVICE_BAD_VALUE);
    /* Capability INIT works while off, is retained through wake/shutdown,
     * and cannot authorize power, tables or DMA frame ownership. */
    CHECK(device_dart_monitor_init(models,states,count,20)==DEVICE_OK);
    CHECK(states[DART].dart.initialized_ids==(1U<<20));
    memcpy(saved,states,sizeof(states));
    CHECK(device_dart_monitor_init(models,states,count,20)==DEVICE_BAD_VALUE);
    CHECK(device_dart_monitor_powerup(models,states,count,20)==DEVICE_BAD_CONFIG);
    unsigned index=123;
    CHECK(device_dart_admit_frame(models,states,count,5,20,0,0,&index)==DEVICE_BAD_CONFIG && index==123);
    CHECK(!memcmp(saved,states,sizeof(states)));
    write_ps(0x30f);CHECK(read_ps(0x60)==0xff);
    v=0;CHECK(access_word(DART,0,4,0,&v)==DEVICE_OK && v==0x8e000000);
    write_ps(0x304);CHECK(read_ps(0x60)==0x244);
    CHECK(states[DART].dart.initialized_ids==(1U<<20));
    read_capabilities(DART);
    write_ps(0x300);CHECK(read_ps(0x60)==0x100);
    for (unsigned initial=0;initial<2;initial++)
        for (unsigned from=0;from<3;from++) for (unsigned to=0;to<3;to++) {
            static const unsigned levels[]={0,4,15};
            reset();if(initial) CHECK(device_dart_monitor_init(models,states,count,20)==DEVICE_OK);
            write_ps(0x300|levels[from]);write_ps(0x300|levels[from]);
            write_ps(0x0f0000f0|levels[to]);
            unsigned hist=from==to ? 0 : levels[to]==0 ? 0x100 : levels[to]==4 ? 0x200 : 0;
            CHECK(read_ps(0x60)==(levels[to]|(levels[to]<<4)|hist));
            write_ps(0x300|levels[to]);CHECK(read_ps(0x60)==(levels[to]|(levels[to]<<4)));
            CHECK(states[DART].dart.initialized_ids==(initial ? 1U<<20 : 0));
        }
    reset();
    /* Native _dartValidateConfig reads PARAMS0/1 before monitor POWERUP.
     * All four immutable words remain readable when off or clock-gated,
     * before and after capability INIT. No other access gets this exception. */
    for (unsigned init=0;init<2;init++) for (unsigned level=0;level<2;level++) {
        reset();if(init) CHECK(device_dart_monitor_init(models,states,count,20)==DEVICE_OK);
        write_ps(level ? 4 : 0);read_capabilities(DART);
        for (unsigned off=0;off<0x10;off++) for (unsigned width=0;width<=16;width++) {
            if (width!=4 || (off&3)) refused(DART,off,width,0,123,DEVICE_BAD_VALUE);
            refused(DART,off,width,1,0,DEVICE_BAD_VALUE);
        }
        for (unsigned off=0x10;off<0x1000;off+=4) {
            refused(DART,off,4,0,123,DEVICE_BAD_VALUE);
            refused(DART,off,4,1,0,DEVICE_BAD_VALUE);
        }
        const unsigned runtime[]={0x1000,0x1400,0x1800,0x2000,0x4000,0x1fffc};
        for (unsigned i=0;i<sizeof(runtime)/sizeof(runtime[0]);i++) {
            refused(DART,runtime[i],4,0,123,DEVICE_BAD_VALUE);
            refused(DART,runtime[i],4,1,0,DEVICE_BAD_VALUE);
        }
        memcpy(saved,states,sizeof(states));
        CHECK(device_dart_monitor_powerup(models,states,count,20)==DEVICE_BAD_CONFIG);
        unsigned untouched=123;
        CHECK(device_dart_admit_frame(models,states,count,5,20,0,0,&untouched)==DEVICE_BAD_CONFIG);
        CHECK(untouched==123 && !memcmp(saved,states,sizeof(states)));
    }
    reset();
    for (unsigned level=1;level<15;level++) if(level!=4)
        refused(PMGR,0x60,4,1,level,DEVICE_BAD_VALUE);
    for (unsigned bit=0;bit<64;bit++) if(!((0x1f0f03ffUL>>bit)&1))
        refused(PMGR,0x60,4,1,15|(1UL<<bit),DEVICE_BAD_VALUE);
    refused(PMGR,0x60,4,1,1UL<<28,DEVICE_BAD_VALUE);
    refused(PMGR,0x60,4,1,(1UL<<28)|4,DEVICE_BAD_VALUE);
    write_ps(0x100700ff);CHECK(read_ps(0x60)==0x1f0700ff);
    for (unsigned width=0;width<=16;width++) if(width!=4)
        refused(PMGR,0x60,width,1,0x3f0,DEVICE_BAD_WIDTH);
    refused(PMGR,0x61,4,1,0,DEVICE_BAD_WIDTH);
    refused(PMGR,0x64,4,1,0,DEVICE_UNKNOWN_REGISTER);
    for (unsigned level=0;level<2;level++) {
        v=level ? 4 : 0;memcpy(saved,states,sizeof(states));
        CHECK(device_model_access_state(models,states,0x60,4,1,&v)==DEVICE_BAD_VALUE);
        CHECK(!memcmp(saved,states,sizeof(states)));
    }
    /* Every owned runtime word blocks both gating and wake, without clearing
     * it. Initialized capability metadata is the sole allowed nonzero word. */
    for (unsigned transition=0;transition<3;transition++)
        for (unsigned word=0;word<sizeof(struct dart_state)/4;word++) {
            if (word*4>=offsetof(struct dart_state,tlb_end)+4 &&
                word*4<offsetof(struct dart_state,translations)) continue;
            reset();if(transition==2) write_ps(0x300);
            uint32_t one=1;memcpy((char *)&states[DART].dart+word*4,&one,4);
            refused(PMGR,0x60,4,1,transition==2 ? 15 : transition==1 ? 4 : 0,DEVICE_BAD_VALUE);
        }
    /* Virtual SEP-PEARL-V claims are never interpreted as physical ACKs. */
    for (unsigned ack=0;ack<2;ack++) for (unsigned transition=0;transition<3;transition++) {
        reset();if(transition==2) write_ps(0);
        if(ack) states[PMP].pmp_active.ack|=1UL<<27;
        else states[PMP].pmp_active.request|=1UL<<27;
        refused(PMGR,0x60,4,1,transition==2 ? 15 : transition==1 ? 4 : 0,DEVICE_BAD_VALUE);
    }
    reset();refused(PMP,0x10c40,8,1,0x3000|(1UL<<27),DEVICE_BAD_VALUE);
    for (unsigned i=0;i<COUNT;i++) {
        reset();models[i].base+=0x200000;refused(PMGR,0x60,4,1,0,DEVICE_BAD_CONFIG);
        reset();models[i].span+=0x4000;refused(PMGR,0x60,4,1,0,DEVICE_BAD_CONFIG);
        for (unsigned field=0;field<5;field++) {
            reset();models[i].config[field]^=1;refused(PMGR,0x60,4,1,0,DEVICE_BAD_CONFIG);
        }
        reset();models[i].kind=0;refused(PMGR,0x60,4,1,0,DEVICE_BAD_CONFIG);
        reset();count=COUNT+1;models[EXTRA]=models[i];
        refused(PMGR,0x60,4,1,0,DEVICE_BAD_CONFIG);
    }
    reset();count=COUNT-1;refused(PMGR,0x60,4,1,0,DEVICE_BAD_CONFIG);
    /* Partial overlaps and unknown model kinds cannot smuggle a SEP engine
     * or second view of its DART into an idle-only binding. */
    const uint64_t apertures[3][2]={{0x282600000,0x88000},{0x282050000,0x60000},{0x280b80000,0x20000}};
    for (unsigned w=0;w<3;w++) for (unsigned position=0;position<3;position++) {
        reset();count=COUNT+1;models[EXTRA]=(struct device_model){.kind=999,
            .base=position==0 ? apertures[w][0]-0x4000 :
                  position==1 ? apertures[w][0] : apertures[w][0]+apertures[w][1]-0x4000,
            .span=0x8000};
        refused(PMGR,0x60,4,1,0,DEVICE_BAD_CONFIG);
    }
    /* Binding is independent of registry order. */
    reset();struct device_model temp=models[DART];models[DART]=models[AON];models[AON]=temp;
    memset(states,0,sizeof(states));
    for(unsigned i=0;i<COUNT;i++) CHECK(device_model_start(models+i,states+i,0,24000000)==DEVICE_OK);
    write_ps(0);CHECK(read_ps(0x60)==0x100);
    read_capabilities(AON);
    reset();write_ps(0);pmp=states[PMP];
    CHECK(device_model_start(models,states,0,24000000)==DEVICE_OK);
    CHECK(read_ps(0x60)==0xff && !memcmp(&pmp,&states[PMP],sizeof(pmp)));
    test_powerup();
    if(topology) puts("96 0");
    else printf("PMGR SEP_AON with SEP DART ownership: %u checks passed\n",checks);
    return 0;
}

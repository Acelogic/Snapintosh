/* SPDX-License-Identifier: MIT */
/* ANE physical power is distinct from virtual PMP vote/readiness and APF. */
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "device.h"
static unsigned checks;
#define CHECK(x) do { checks++; if (!(x)) { \
    fprintf(stderr,"line %u: %s\n",__LINE__,#x); exit(1); } } while (0)
static const struct device_model original[]={
    {18,0x300700000,0x11000,{0,0,0,0,0}},
    {17,0x401800000,0xc000,{16,44,656,36,0}},
    {17,0x401820000,0x20000,{16,44,656,36,0}},
    {17,0x401840000,0x20000,{16,44,656,36,0}},
    {25,0x3003c0000,0x14000,{0x10000,0x1a8,0x1b8,8,DEVICE_PMP_ACTIVE_MASK}},
    {18,0x308280000,0x9000,{1,0,0,0,0}},
};
static struct device_model models[6];
static struct device_state states[6],saved[6];
static enum device_result access_word(unsigned index,unsigned off,unsigned width,
                                      int write,uint64_t *v)
{
    return device_models_access_at(models,states,6,index,0,off,width,write,v);
}
static void reset(void)
{
    memcpy(models,original,sizeof(models));memset(states,0,sizeof(states));
    CHECK(device_models_valid(models,6,0,0));
    for (unsigned i=0;i<6;i++) CHECK(device_model_start(models+i,states+i,0,24000000)==DEVICE_OK);
}
static uint64_t read_word(void)
{
    uint64_t v=UINT64_MAX;CHECK(access_word(0,0x290,4,0,&v)==DEVICE_OK);return v;
}
static void write_word(uint64_t v)
{
    CHECK(access_word(0,0x290,4,1,&v)==DEVICE_OK);
}
static void refused(unsigned index,unsigned off,unsigned width,int write,
                    uint64_t v,enum device_result expected)
{
    memcpy(saved,states,sizeof(states));uint64_t input=v;
    enum device_result actual=access_word(index,off,width,write,&v);
    if (actual!=expected) fprintf(stderr,"index %u off %x width %u value %llx: got %u want %u\n",
        index,off,width,(unsigned long long)input,actual,expected);
    CHECK(actual==expected);CHECK(v==input && !memcmp(saved,states,sizeof(states)));
}
static void init_policy(void)
{
    reset();
    for (unsigned bank=1;bank<=3;bank++) {
        models[bank].config[1]=DEVICE_DART_ANE_INIT_V1;
        models[bank].config[4]=1;
    }
    CHECK(device_models_valid(models,6,0,0));
}
static void init_refused(unsigned count,enum device_result expected)
{
    memcpy(saved,states,sizeof(states));
    CHECK(device_dart_monitor_init(models,states,count,0)==expected);
    CHECK(!memcmp(saved,states,sizeof(states)));
}
static void capability_init(void)
{
    static const unsigned levels[]={0,4,15};
    for (unsigned l=0;l<3;l++) {
        init_policy();write_word(levels[l]);
        memcpy(saved,states,sizeof(states));
        for (unsigned b=1;b<=3;b++) saved[b].dart.initialized_ids=1;
        CHECK(device_dart_monitor_init(models,states,6,0)==DEVICE_OK);
        CHECK(!memcmp(saved,states,sizeof(states)));
        init_refused(6,DEVICE_BAD_VALUE);
        CHECK(device_dart_monitor_powerup(models,states,6,0)==DEVICE_BAD_CONFIG);
        for (unsigned sid=0;sid<16;sid++) for (unsigned level=0;level<4;level++) {
            unsigned index=123;
            CHECK(device_dart_admit_frame(models,states,6,5,0,sid,level,&index)!=DEVICE_OK);
            CHECK(index==123);
        }
        CHECK(!memcmp(saved,states,sizeof(states)));
        for (unsigned to=0;to<3;to++) {
            write_word(levels[to]);
            for (unsigned b=1;b<=3;b++) CHECK(states[b].dart.initialized_ids==1);
        }
    }
    for (unsigned bank=1;bank<=3;bank++) {
        /* No partial commit after discovering an initialized/stale bank. */
        for (unsigned bit=0;bit<32;bit++) {
            init_policy();states[bank].dart.initialized_ids=1U<<bit;
            init_refused(6,DEVICE_BAD_VALUE);
        }
        for (unsigned field=0;field<5;field++) {
            init_policy();models[bank].config[field]^=1;
            init_refused(6,DEVICE_BAD_CONFIG);
        }
        init_policy();models[bank]=original[bank];
        init_refused(6,DEVICE_BAD_CONFIG); /* no legacy/new mixture */
        init_policy();models[bank].base+=0x10000;init_refused(6,DEVICE_BAD_CONFIG);
        init_policy();models[bank].span+=0x4000;init_refused(6,DEVICE_BAD_CONFIG);
        /* Capability capture preserves every other DART state word. It
         * neither restores power nor clears faults, tables or DMA state. */
        for (unsigned word=0;word<sizeof(struct dart_state)/4;word++) {
            if (4*word==offsetof(struct dart_state,initialized_ids)) continue;
            init_policy();uint32_t one=1;
            memcpy((char *)&states[bank].dart+4*word,&one,4);
            memcpy(saved,states,sizeof(states));
            for (unsigned b=1;b<=3;b++) saved[b].dart.initialized_ids=1;
            CHECK(device_dart_monitor_init(models,states,6,0)==DEVICE_OK);
            CHECK(!memcmp(saved,states,sizeof(states)));
            if (word*4>=offsetof(struct dart_state,tlb_end)+4 &&
                word*4<offsetof(struct dart_state,translations)) continue;
            refused(0,0x290,4,1,0,DEVICE_BAD_VALUE);
        }
    }
    for (unsigned removed=0;removed<6;removed++) {
        init_policy();models[removed]=models[5];
        init_refused(5,DEVICE_BAD_CONFIG);
    }
    init_policy();models[2]=models[1];init_refused(6,DEVICE_BAD_CONFIG);
    /* Reordering descriptors must not change the three-instance contract. */
    init_policy();struct device_model tmp=models[1];models[1]=models[3];models[3]=tmp;
    CHECK(device_dart_monitor_init(models,states,6,0)==DEVICE_OK);
    for (unsigned b=1;b<=3;b++) CHECK(states[b].dart.initialized_ids==1);
}
int main(int argc,char **argv)
{
    int topology=argc==2 && !strcmp(argv[1],"--topology");
    reset();CHECK(read_word()==0xff && !states[5].pmgr_ane);
    uint64_t v=0x3000;
    CHECK(access_word(4,0x10c40,8,1,&v)==DEVICE_OK);
    struct device_state pmp=states[4];
    write_word(0x3f0);CHECK(read_word()==0x100 && states[0].pmgr_ane==0x100);
    CHECK(!memcmp(&pmp,&states[4],sizeof(pmp)));
    v=0;CHECK(access_word(0,0x228,4,0,&v)==DEVICE_OK && v==0xff);
    refused(0,0x228,4,1,0,DEVICE_BAD_VALUE);
    for (unsigned bank=1;bank<=3;bank++) {
        refused(bank,0,4,0,0x1234,DEVICE_BAD_VALUE);
        refused(bank,0x104,4,1,1,DEVICE_BAD_VALUE);
    }
    /* APF/controller execution and virtual PMP admission remain unsupported. */
    memcpy(saved,states,sizeof(states));
    CHECK(device_dart_monitor_init(models,states,6,0)==DEVICE_NOT_FOUND);
    CHECK(device_dart_monitor_powerup(models,states,6,0)==DEVICE_NOT_FOUND);
    unsigned index=123;
    CHECK(device_dart_admit_frame(models,states,6,5,0,0,0,&index)==DEVICE_NOT_FOUND && index==123);
    CHECK(!memcmp(saved,states,sizeof(states)));
    refused(4,0x10c40,8,1,0x3400,DEVICE_BAD_VALUE);
    /* Standalone model access cannot wake or gate this owned system domain. */
    v=15;CHECK(device_model_access_state(models,states,0x290,4,1,&v)==DEVICE_BAD_VALUE);
    write_word(0x30f);CHECK(read_word()==0xff);
    for (unsigned bank=1;bank<=3;bank++) {
        v=0;CHECK(access_word(bank,0,4,0,&v)==DEVICE_OK && v==0x8e000000);
    }
    for (unsigned from=0;from<3;from++) for (unsigned to=0;to<3;to++) {
        static const unsigned levels[]={0,4,15};
        reset();write_word(0x300|levels[from]);write_word(0x300|levels[from]);
        write_word(0x0f0000f0|levels[to]);
        unsigned hist=from==to ? 0 : levels[to]==0 ? 0x100 : levels[to]==4 ? 0x200 : 0;
        CHECK(read_word()==(levels[to]|(levels[to]<<4)|hist));
        write_word(0x300|levels[to]);CHECK(read_word()==(levels[to]|(levels[to]<<4)));
    }
    reset();
    for (unsigned level=1;level<15;level++) if(level!=4)
        refused(0,0x290,4,1,level,DEVICE_BAD_VALUE);
    for (unsigned bit=0;bit<64;bit++) if (!((0x1f0f03ffUL>>bit)&1))
        refused(0,0x290,4,1,15|(1UL<<bit),DEVICE_BAD_VALUE);
    refused(0,0x290,4,1,1UL<<28,DEVICE_BAD_VALUE);
    refused(0,0x290,4,1,(1UL<<28)|4,DEVICE_BAD_VALUE);
    write_word(0x100700ff);CHECK(read_word()==0x1f0700ff);
    for (unsigned width=0;width<=16;width++) if(width!=4)
        refused(0,0x290,width,1,0x3f0,DEVICE_BAD_WIDTH);
    refused(0,0x291,4,1,0,DEVICE_BAD_WIDTH);
    refused(0,0x294,4,1,0,DEVICE_UNKNOWN_REGISTER);
    /* A virtual vote or virtual ACK is never withdrawn or converted into
     * a physical power acknowledgment. Both block the transition. */
    for (unsigned ack=0;ack<2;ack++) {
        reset();
        if (ack) states[4].pmp_active.ack|=1UL<<10;
        else states[4].pmp_active.request|=1UL<<10;
        refused(0,0x290,4,1,0x3f0,DEVICE_BAD_VALUE);
    }
    /* Every runtime DART word in all three banks prevents gating. The zero
     * logical-ID binding means even capability initialization is not admitted. */
    for (unsigned bank=1;bank<=3;bank++)
        for (unsigned word=0;word<sizeof(struct dart_state)/4;word++) {
            if (word*4>=offsetof(struct dart_state,tlb_end)+4 &&
                word*4<offsetof(struct dart_state,translations)) continue;
            reset();uint32_t one=1;memcpy((char *)&states[bank].dart+4*word,&one,4);
            refused(0,0x290,4,1,0x3f0,DEVICE_BAD_VALUE);
        }
    for (unsigned bank=1;bank<=3;bank++) {
        for (unsigned field=0;field<5;field++) {
            reset();models[bank].config[field]^=1;
            refused(0,0x290,4,1,0x3f0,DEVICE_BAD_CONFIG);
        }
        reset();models[bank].base+=0x10000;refused(0,0x290,4,1,0,DEVICE_BAD_CONFIG);
        reset();models[bank].span+=0x4000;refused(0,0x290,4,1,0,DEVICE_BAD_CONFIG);
    }
    reset();models[2]=models[1];refused(0,0x290,4,1,0,DEVICE_BAD_CONFIG);
    for (unsigned i=0;i<6;i+=4) {
        reset();models[i].base+=0x20000;refused(0,0x290,4,1,0,DEVICE_BAD_CONFIG);
    }
    reset();models[5].base+=0x10000;refused(0,0x290,4,1,0,DEVICE_BAD_CONFIG);
    reset();v=0;CHECK(device_models_access_at(models,states,5,0,0,0x290,4,1,&v)==DEVICE_BAD_CONFIG);
    reset();write_word(0);CHECK(device_model_start(models,states,0,24000000)==DEVICE_OK);
    CHECK(read_word()==0xff);
    capability_init();
    if (topology) puts("656 552");
    else printf("PMGR ANE: %u checks passed\n",checks);
    return 0;
}

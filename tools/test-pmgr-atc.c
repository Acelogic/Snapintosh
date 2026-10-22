/* SPDX-License-Identifier: MIT */
/* ATC power topology and two-bank USB DART admission, through production MMIO. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include "device.h"
static unsigned checks;
#define CHECK(x) do { checks++; if (!(x)) { \
    fprintf(stderr,"line %u: %s\n",__LINE__,#x); exit(1); } } while (0)
static const struct device_model original[]={
    {18,0x300700000,0x11000,{0,0,0,0,0}},
    {17,0x40af00000,0xc000,{16,44,1248,36,1U<<22}},
    {17,0x40af80000,0xc000,{16,44,1248,36,1U<<22}},
    {18,0x308280000,0x9000,{1,0,0,0,0}},
};
static struct device_model models[4];
static struct device_state states[4],saved[4];
static enum device_result access_word(unsigned index,unsigned off,unsigned width,
                                      int write,uint64_t *v)
{
    return device_models_access_at(models,states,4,index,0,off,width,write,v);
}
static void reset(void)
{
    memcpy(models,original,sizeof(models));memset(states,0,sizeof(states));
    CHECK(device_models_valid(models,4,0,0));
    for (unsigned i=0;i<4;i++) CHECK(device_model_start(models+i,states+i,0,24000000)==DEVICE_OK);
}
static uint64_t read_word(unsigned unit)
{
    uint64_t v=UINT64_MAX;CHECK(access_word(0,0x3e0+8*unit,4,0,&v)==DEVICE_OK);return v;
}
static void write_word(unsigned unit,uint64_t v)
{
    CHECK(access_word(0,0x3e0+8*unit,4,1,&v)==DEVICE_OK);
}
static void refused(unsigned index,unsigned off,unsigned width,int write,
                    uint64_t v,enum device_result expected)
{
    memcpy(saved,states,sizeof(states));uint64_t input=v;
    enum device_result actual=access_word(index,off,width,write,&v);
    if (actual!=expected) fprintf(stderr,"index %u offset %x width %u write %d value %llx: result %u expected %u\n",
        index,off,width,write,(unsigned long long)input,actual,expected);
    CHECK(actual==expected);
    CHECK(v==input && !memcmp(saved,states,sizeof(states)));
}
static void gate(unsigned level)
{
    for (int i=2;i>=0;i--) write_word((unsigned)i,0x3f0|level);
}
static void wake(void)
{
    for (unsigned i=0;i<3;i++) write_word(i,0x30f);
}
int main(int argc,char **argv)
{
    int topology=argc==2 && !strcmp(argv[1],"--topology");
    reset();
    /* Reached Apple write: desired off, stale actual active, W1C history. */
    write_word(2,0x3f0);CHECK(read_word(2)==0x100);
    CHECK(read_word(0)==0xff && read_word(1)==0xff);
    for (unsigned bank=1;bank<=2;bank++) {
        refused(bank,0,4,0,0x1234,DEVICE_BAD_VALUE);
        refused(bank,0x100,4,1,1,DEVICE_BAD_VALUE);
    }
    wake();
    for (unsigned bank=1;bank<=2;bank++) {
        uint64_t value=0;
        CHECK(access_word(bank,0,4,0,&value)==DEVICE_OK && value==0x8e000000);
    }
    /* Parent-first gating fails; child-first wake fails. Both independent
     * external AFISOCNI2 and local AON parents remain required. */
    refused(0,0x3e0,4,1,0x3f0,DEVICE_BAD_VALUE);
    refused(0,0x3e8,4,1,0x3f0,DEVICE_BAD_VALUE);
    gate(0);
    refused(0,0x3e8,4,1,15,DEVICE_BAD_VALUE);
    refused(0,0x3f0,4,1,15,DEVICE_BAD_VALUE);
    refused(0,0x228,4,1,0,DEVICE_BAD_VALUE);
    uint64_t v=0;CHECK(access_word(0,0x228,4,0,&v)==DEVICE_OK && v==0xff);
    wake();
    for (unsigned from=0;from<3;from++) for (unsigned to=0;to<3;to++) {
        static const unsigned level[]={0,4,15};
        reset();gate(level[from]);
        /* Clear transition history while retaining each committed level. */
        for (unsigned i=0;i<3;i++) write_word(i,0x300|level[from]);
        if (level[to]>level[from]) {
            for (unsigned i=0;i<3;i++) write_word(i,level[to]);
        } else gate(level[to]);
        unsigned history=from==to ? 0 : level[to]==0 ? 0x100 : level[to]==4 ? 0x200 : 0;
        for (unsigned i=0;i<3;i++) {
            CHECK(read_word(i)==(level[to]|(level[to]<<4)|history));
            write_word(i,0x300|level[to]);CHECK(read_word(i)==(level[to]|(level[to]<<4)));
        }
    }
    reset();
    for (unsigned i=0;i<3;i++) for (unsigned target=0;target<16;target++) {
        if (target!=0 && target!=4 && target!=15)
            refused(0,0x3e0+8*i,4,1,target,DEVICE_BAD_VALUE);
    }
    for (unsigned bit=0;bit<64;bit++) {
        uint64_t allowed=(1UL<<28)|(15UL<<16)|(15UL<<24)|0x3ff;
        if (!((1UL<<bit)&allowed)) refused(0,0x3f0,4,1,(1UL<<bit)|15,DEVICE_BAD_VALUE);
    }
    refused(0,0x3f0,4,1,(1UL<<28)|4,DEVICE_BAD_VALUE);
    refused(0,0x3f0,4,1,(1UL<<28),DEVICE_BAD_VALUE);
    for (unsigned width=0;width<=16;width++) if (width!=4)
        refused(0,0x3f0,width,1,0x3f0,DEVICE_BAD_WIDTH);
    refused(0,0x3e4,4,1,0,DEVICE_UNKNOWN_REGISTER);
    refused(0,0x3e1,4,1,0,DEVICE_BAD_WIDTH);
    /* A standalone model cannot authorize a level change. */
    v=0x3f0;CHECK(device_model_access_state(models,states,0x3f0,4,1,&v)==DEVICE_BAD_VALUE);
    /* A bound capability may remain initialized while off, but every other
     * nonzero DART word represents unaudited runtime state. Test both banks,
     * including the highest SID and every 64-bit counter half. */
    CHECK(device_dart_monitor_init(models,states,4,22)==DEVICE_OK);
    gate(0);wake();
    CHECK(states[1].dart.initialized_ids==(1U<<22) && states[2].dart.initialized_ids==(1U<<22));
    for (unsigned bank=1;bank<=2;bank++) {
        for (unsigned word=0;word<sizeof(struct dart_state)/4;word++) {
            /* Padding is not runtime state. */
            if (word*4>=offsetof(struct dart_state,tlb_end)+4 &&
                word*4<offsetof(struct dart_state,translations)) continue;
            reset();
            uint32_t one=1;memcpy((char *)&states[bank].dart+4*word,&one,4);
            refused(0,0x3f0,4,1,0x3f0,DEVICE_BAD_VALUE);
        }
    }
    reset();gate(0);
    CHECK(device_dart_monitor_init(models,states,4,22)==DEVICE_OK);
    CHECK(states[1].dart.initialized_ids==(1U<<22) && states[2].dart.initialized_ids==(1U<<22));
    CHECK(device_dart_monitor_powerup(models,states,4,22)==DEVICE_BAD_CONFIG);
    unsigned index=123;
    CHECK(device_dart_admit_frame(models,states,4,5,22,0,0,&index)==DEVICE_BAD_CONFIG && index==123);
    /* Invalid/missing bindings fail atomically. */
    for (unsigned bank=1;bank<=2;bank++) {
        for (unsigned field=0;field<5;field++) {
            reset();models[bank].config[field]^=1;
            refused(0,0x3f0,4,1,0x3f0,DEVICE_BAD_CONFIG);
        }
        reset();models[bank].base+=0x10000;
        refused(0,0x3f0,4,1,0x3f0,DEVICE_BAD_CONFIG);
    }
    reset();models[2]=models[1];refused(0,0x3f0,4,1,0x3f0,DEVICE_BAD_CONFIG);
    reset();v=0x3f0;
    CHECK(device_models_access_at(models,states,2,0,0,0x3f0,4,1,&v)==DEVICE_BAD_CONFIG);
    CHECK(device_models_access_at(models,states,4,4,0,0x3f0,4,1,&v)==DEVICE_BAD_CONFIG);
    CHECK(device_models_access_at(models,states,DEVICE_MODEL_MAX+1,0,0,0x3f0,4,1,&v)==DEVICE_BAD_CONFIG);
    CHECK(device_models_access_at(0,states,4,0,0,0x3f0,4,1,&v)==DEVICE_BAD_CONFIG);
    CHECK(device_models_access_at(models,0,4,0,0,0x3f0,4,1,&v)==DEVICE_BAD_CONFIG);
    CHECK(device_models_access_at(models,states,4,0,0,0x3f0,4,1,0)==DEVICE_BAD_CONFIG);
    reset();gate(0);
    CHECK(device_model_start(models,states,0,24000000)==DEVICE_OK);
    for (unsigned i=0;i<3;i++) CHECK(read_word(i)==0xff && !states[3].pmgr_atc[i]);
    if (topology) {
        puts("992 0 0\n1000 552 992\n1008 1000 0");
    } else printf("PMGR ATC: %u checks passed\n",checks);
    return 0;
}

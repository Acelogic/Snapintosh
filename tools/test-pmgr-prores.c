/* SPDX-License-Identifier: MIT */
/* APR DART ownership and atomic requests spanning three physical systems. */
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
    {17,0x295020000,0x20000,{1,44,1257,36,8}},
    {25,0x3003c0000,0x14000,{0x10000,0x1a8,0x1b8,8,DEVICE_PMP_ACTIVE_MASK}},
    {18,0x308280000,0x9000,{1,0,0,0,0}},
    {17,0x381020000,0x20000,{16,44,943,36,16}},
    {17,0x3228c0000,0xc000,{16,44,341,36,0}},
    {17,0x3228e0000,0xc000,{16,44,341,36,0}},
    {17,0x322900000,0xc000,{16,44,341,36,0}},
};
static struct device_model models[9];
static struct device_state states[9],saved[9];
static const unsigned offsets[3]={0x270,0x268,0x250};
static const uint64_t bits[3]={DEVICE_PMP_AVD_BIT,DEVICE_PMP_ISP_BIT,DEVICE_PMP_PRORES_BIT};
static enum device_result access(unsigned i,unsigned off,unsigned w,int write,uint64_t *v)
{ return device_models_access_at(models,states,8,i,0,off,w,write,v); }
static void reset(void)
{
    memset(models,0,sizeof(models));memcpy(models,original,sizeof(original));
    memset(states,0,sizeof(states));CHECK(device_models_valid(models,8,0,0));
    for (unsigned i=0;i<8;i++) CHECK(device_model_start(models+i,states+i,0,24000000)==DEVICE_OK);
}
static void ps(unsigned off,uint64_t v) { CHECK(access(0,off,4,1,&v)==DEVICE_OK); }
static uint64_t read_ps(unsigned off)
{ uint64_t v=0;CHECK(access(0,off,4,0,&v)==DEVICE_OK);return v; }
static void vote(uint64_t v) { CHECK(access(2,0x10c40,8,1,&v)==DEVICE_OK); }
static void pair(unsigned off,uint64_t data,uint64_t meta)
{
    uint64_t v[2]={123,456};CHECK(device_model_read_pair(models+2,states+2,off,v)==DEVICE_OK);
    CHECK(v[0]==data && v[1]==meta);
}
static void refused(unsigned i,unsigned off,unsigned w,int write,uint64_t v,enum device_result want)
{
    memcpy(saved,states,sizeof(states));uint64_t input=v;
    enum device_result got=access(i,off,w,write,&v);
    if (got!=want) fprintf(stderr,"index %u offset %x: got %u expected %u\n",i,off,got,want);
    CHECK(got==want);CHECK(v==input && !memcmp(saved,states,sizeof(states)));
}
static void idle_children(void)
{ for (unsigned n=13;n;n--) ps(0x4000+8*(n-1),0x3f0); }
static uint64_t pattern(unsigned p)
{ uint64_t v=0;for (unsigned i=0;i<3;i++) if (p&(1U<<i)) v|=bits[i];return v; }
int main(int argc,char **argv)
{
    int topology=argc==2 && !strcmp(argv[1],"--topology");
    const uint64_t bit=DEVICE_PMP_PRORES_BIT,mask=DEVICE_PMP_ACTIVE_MASK,all=pattern(7);
    reset();CHECK(read_ps(0x250)==0xff && !states[3].pmgr_prores);
    CHECK(offsetof(struct device_state,pmgr_prores)-offsetof(struct device_state,pmgr_policy)==696);
    vote(0x3000);pair(0x1880,0x3000,2);pair(0x18c0,mask,2);
    ps(0x250,0x3f0);CHECK(read_ps(0x250)==0x100);pair(0x18c0,mask&~bit,2);
    pair(0x1880,0x3000,0);ps(0x250,0);pair(0x18c0,mask&~bit,0);
    vote(0x3000);pair(0x18c0,mask&~bit,2);
    refused(1,0,4,0,123,DEVICE_BAD_VALUE);refused(1,0x104,4,1,1,DEVICE_BAD_VALUE);
    ps(0x250,15);pair(0x18c0,mask,2);pair(0x1880,0x3000,2);
    CHECK(read_ps(0x218)==0xff);refused(0,0x218,4,1,0,DEVICE_BAD_VALUE);
    uint64_t v=0;CHECK(access(1,0,4,0,&v)==DEVICE_OK && v==0x8e000000);
    ps(0x250,0);vote(0x3000|bit);refused(0,0x250,4,1,0,DEVICE_BAD_VALUE);
    vote(0x3000);CHECK(!(read_ps(0x250)&15));
    CHECK(device_dart_monitor_init(models,states,8,3)==DEVICE_OK);
    vote(0x3000|bit);vote(0x3000);CHECK(states[1].dart.initialized_ids==8);
    CHECK(device_dart_monitor_powerup(models,states,8,3)==DEVICE_BAD_CONFIG);
    unsigned index=123;
    CHECK(device_dart_admit_frame(models,states,8,5,3,0,0,&index)==DEVICE_BAD_CONFIG && index==123);
    v=15;memcpy(saved,states,sizeof(states));
    CHECK(device_model_access_state(models,states,0x250,4,1,&v)==DEVICE_BAD_VALUE);
    v=0x3000|bit;CHECK(device_model_access_state(models+2,states+2,0x10c40,8,1,&v)==DEVICE_BAD_VALUE);
    CHECK(!memcmp(saved,states,sizeof(states)));
    /* Every old/new combination exercises the three-domain transaction,
     * including simultaneous wake/release and unchanged bits. */
    for (unsigned before=0;before<8;before++) for (unsigned after=0;after<8;after++) {
        reset();idle_children();for (unsigned i=0;i<3;i++) ps(offsets[i],0);
        vote(0x3000|pattern(before));vote(0x3000|pattern(after));
        pair(0x1880,0x3000|pattern(after),2);
        pair(0x18c0,(mask&~all)|pattern(after),2);
        for (unsigned i=0;i<3;i++) CHECK((read_ps(offsets[i])&15)==((after&(1U<<i)) ? 15 : 0));
    }
    /* Failure in the last domain cannot commit the earlier domains. */
    for (unsigned word=0;word<sizeof(struct dart_state)/4;word++) {
        if (word*4>=offsetof(struct dart_state,tlb_end)+4 &&
            word*4<offsetof(struct dart_state,translations)) continue;
        reset();idle_children();uint32_t one=1;memcpy((char *)&states[1].dart+4*word,&one,4);
        refused(0,0x250,4,1,0,DEVICE_BAD_VALUE);
        vote(all);refused(2,0x10c40,8,1,0,DEVICE_BAD_VALUE);
    }
    reset();idle_children();ps(0x270,0);ps(0x268,0);vote(bit);
    states[1].dart.enabled[0]=1;refused(2,0x10c40,8,1,bits[0]|bits[1],DEVICE_BAD_VALUE);
    reset();idle_children();vote(all);ps(0x250,0x100700ff);
    refused(2,0x10c40,8,1,0,DEVICE_BAD_VALUE);
    ps(0x250,0x7000f);vote(0);CHECK(read_ps(0x250)==0x70100);
    ps(0x250,0x70100);CHECK(read_ps(0x250)==0x70000);
    for (unsigned t=1;t<15;t++) refused(0,0x250,4,1,t,DEVICE_BAD_VALUE);
    for (unsigned b=0;b<64;b++) if (!((0x1f0f03ffUL>>b)&1))
        refused(0,0x250,4,1,15|(1UL<<b),DEVICE_BAD_VALUE);
    for (unsigned w=0;w<=16;w++) if (w!=4) refused(0,0x250,w,1,0,DEVICE_BAD_WIDTH);
    for (unsigned w=0;w<=16;w++) if (w!=8) refused(2,0x10c40,w,1,bit,DEVICE_BAD_WIDTH);
    refused(0,0x251,4,1,0,DEVICE_BAD_WIDTH);refused(0,0x254,4,1,0,DEVICE_UNKNOWN_REGISTER);
    refused(2,0x10c40,8,1,bit|(1UL<<10),DEVICE_BAD_VALUE);
    for (unsigned field=0;field<5;field++) {
        reset();models[1].config[field]^=1;
        refused(0,0x250,4,1,0,DEVICE_BAD_CONFIG);
        refused(2,0x10c40,8,1,all,DEVICE_BAD_CONFIG);
    }
    for (unsigned i=0;i<4;i++) {
        reset();models[i].base+=0x10000;refused(0,0x250,4,1,0,DEVICE_BAD_CONFIG);
        reset();models[8]=models[i];v=0;memcpy(saved,states,sizeof(states));
        CHECK(device_models_access_at(models,states,9,0,0,0x250,4,1,&v)==DEVICE_BAD_CONFIG);
        CHECK(!memcmp(saved,states,sizeof(states)));
    }
    reset();models[1].span=0xc000;refused(0,0x250,4,1,0,DEVICE_BAD_CONFIG);
    reset();states[2].pmp_active.ack^=bit;
    refused(0,0x250,4,1,0,DEVICE_BAD_VALUE);refused(2,0x10c40,8,1,bit,DEVICE_BAD_VALUE);
    reset();ps(0x250,0);CHECK(device_model_start(models,states,0,24000000)==DEVICE_OK);
    refused(0,0x250,4,1,15,DEVICE_BAD_VALUE);
    CHECK(device_model_start(models+2,states+2,0,24000000)==DEVICE_OK);
    CHECK(read_ps(0x250)==0xff);pair(0x18c0,mask,0);
    if (topology) puts("592 536 14");
    else printf("PMGR/PMP PRORES: %u checks passed\n",checks);
    return 0;
}

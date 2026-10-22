/* SPDX-License-Identifier: MIT */
/* MSR/ASE ordering, separate JPEG ownership, and atomic media power votes. */
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
    {18,0x308280000,0x9000,{1,0,0,0,0}},
    {25,0x3003c0000,0x14000,{0x10000,0x1a8,0x1b8,8,DEVICE_PMP_ACTIVE_MASK}},
    {32,0x3028a4000,0x6000,{0,0,0,0,0}},
    {17,0x285080000,0xc000,{16,44,955,36,0}},
    {17,0x2850a0000,0xc000,{16,44,955,36,0}},
    {17,0x289080000,0xc000,{16,44,967,36,0}},
    {17,0x2890a0000,0xc000,{16,44,967,36,0}},
    {17,0x381020000,0x20000,{16,44,943,36,16}},
    {17,0x295020000,0x20000,{1,44,1257,36,8}},
    {17,0x3228c0000,0xc000,{16,44,341,36,0}},
    {17,0x3228e0000,0xc000,{16,44,341,36,0}},
    {17,0x322900000,0xc000,{16,44,341,36,0}},
    {17,0x291260000,0x20000,{16,44,1087,36,1U<<19}},
    {17,0x28d020000,0xc000,{2,44,1041,36,3U<<13}},
    {17,0x28d080000,0xc000,{1,44,1044,36,1U<<15}},
};
enum { COUNT=sizeof(original)/sizeof(original[0]) };
static struct device_model models[COUNT+1];
static struct device_state states[COUNT+1],saved[COUNT+1];
static const unsigned offsets[7]={0x270,0x268,0x250,0x240,0x248,0x238,0x230};
static const uint64_t bits[7]={DEVICE_PMP_AVD_BIT,DEVICE_PMP_ISP_BIT,DEVICE_PMP_PRORES_BIT,
    DEVICE_PMP_VENC0_BIT,DEVICE_PMP_VENC1_BIT,DEVICE_PMP_MSR_BIT,DEVICE_PMP_JPG_BIT};
static enum device_result access(unsigned i,unsigned off,unsigned w,int write,uint64_t *v)
{ return device_models_access_at(models,states,COUNT,i,0,off,w,write,v); }
static void reset(void)
{
    memset(models,0,sizeof(models));memcpy(models,original,sizeof(original));
    memset(states,0,sizeof(states));CHECK(device_models_valid(models,COUNT,0,0));
    for (unsigned i=0;i<COUNT;i++) CHECK(device_model_start(models+i,states+i,0,24000000)==DEVICE_OK);
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
{
    for (unsigned n=10;n;n--) ps(0x8000+8*(n-1),0x3f0);
    for (unsigned n=13;n;n--) ps(0x4000+8*(n-1),0x3f0);
    ps(0x298,0x3f0);
}
static uint64_t pattern(unsigned p)
{ uint64_t v=0;for (unsigned i=0;i<7;i++) if (p&(1U<<i)) v|=bits[i];return v; }
int main(int argc,char **argv)
{
    int topology=argc==2 && !strcmp(argv[1],"--topology");
    const uint64_t mask=DEVICE_PMP_ACTIVE_MASK,images=bits[5]|bits[6],all=pattern(127);
    reset();CHECK(read_ps(0x238)==0xff && read_ps(0x230)==0xff);
    CHECK(!states[1].pmgr_msr && !states[1].pmgr_jpg);
    CHECK(offsetof(struct device_state,pmgr_msr)-offsetof(struct device_state,pmgr_policy)==708);
    CHECK(offsetof(struct device_state,pmgr_jpg)-offsetof(struct device_state,pmgr_policy)==712);
    refused(0,0x238,4,1,0,DEVICE_BAD_VALUE); /* ASE active */
    ps(0x298,4);refused(0,0x238,4,1,0,DEVICE_BAD_VALUE); /* clock gated is not off */
    ps(0x298,0);vote(0x3000);pair(0x1880,0x3000,2);pair(0x18c0,mask,2);
    ps(0x238,0x3f0);CHECK(read_ps(0x238)==0x100);pair(0x18c0,mask&~bits[5],2);
    refused(0,0x298,4,1,4,DEVICE_BAD_VALUE);refused(0,0x298,4,1,15,DEVICE_BAD_VALUE);
    uint64_t v=15;memcpy(saved,states,sizeof(states));
    CHECK(device_model_access_state(models,states,0x298,4,1,&v)==DEVICE_BAD_VALUE);
    CHECK(device_model_access_state(models,states,0x238,4,1,&v)==DEVICE_BAD_VALUE);
    CHECK(!memcmp(saved,states,sizeof(states)));
    ps(0x230,0x3f0);CHECK(read_ps(0x230)==0x100);pair(0x18c0,mask&~images,2);
    pair(0x1880,0x3000,0);ps(0x238,0);ps(0x230,0);pair(0x18c0,mask&~images,0);
    for (unsigned b=13;b<16;b++) {
        refused(b,0,4,0,123,DEVICE_BAD_VALUE);refused(b,0x104,4,1,1,DEVICE_BAD_VALUE);
    }
    vote(0x3000|images);pair(0x18c0,mask,2);ps(0x298,4);
    refused(2,0x10c40,8,1,0x3000,DEVICE_BAD_VALUE);
    ps(0x298,0);vote(0x3000);CHECK(!(read_ps(0x238)&15) && !(read_ps(0x230)&15));
    CHECK(read_ps(0x218)==0xff);refused(0,0x218,4,1,0,DEVICE_BAD_VALUE);
    /* Capability-only initialization survives power cycles, including two
     * logical JPEG IDs sharing bank zero. It never authorizes DMA work. */
    const unsigned ids[]={19,13,14,15};
    for (unsigned i=0;i<4;i++) {
        CHECK(device_dart_monitor_init(models,states,COUNT,ids[i])==DEVICE_OK);
        CHECK(device_dart_monitor_powerup(models,states,COUNT,ids[i])==DEVICE_BAD_CONFIG);
        unsigned index=123;
        CHECK(device_dart_admit_frame(models,states,COUNT,5,ids[i],0,0,&index)==DEVICE_BAD_CONFIG && index==123);
    }
    vote(0x3000|images);vote(0x3000);
    CHECK(states[13].dart.initialized_ids==(1U<<19));
    CHECK(states[14].dart.initialized_ids==(3U<<13));
    CHECK(states[15].dart.initialized_ids==(1U<<15));
    /* Every seven-domain old/new vote combination validates simultaneous
     * wake/release with independent media banks and retained display votes. */
    for (unsigned before=0;before<128;before++) for (unsigned after=0;after<128;after++) {
        reset();idle_children();for (unsigned i=0;i<7;i++) ps(offsets[i],0);
        vote(0x3000|pattern(before));vote(0x3000|pattern(after));
        pair(0x1880,0x3000|pattern(after),2);pair(0x18c0,(mask&~all)|pattern(after),2);
        for (unsigned i=0;i<7;i++) CHECK((read_ps(offsets[i])&15)==((after&(1U<<i)) ? 15 : 0));
    }
    /* Late-domain refusal leaves all previously preflighted domains and
     * transport metadata untouched, including simultaneous wake/release. */
    for (unsigned bank=13;bank<16;bank++) {
        unsigned off=bank==13 ? 0x238 : 0x230;
        for (unsigned word=0;word<sizeof(struct dart_state)/4;word++) {
            if (word*4>=offsetof(struct dart_state,tlb_end)+4 &&
                word*4<offsetof(struct dart_state,translations)) continue;
            reset();idle_children();uint32_t one=1;memcpy((char *)&states[bank].dart+4*word,&one,4);
            refused(0,off,4,1,0,DEVICE_BAD_VALUE);
            vote(0x3000|all);refused(2,0x10c40,8,1,0x3000,DEVICE_BAD_VALUE);
        }
        reset();idle_children();for (unsigned i=0;i<5;i++) ps(offsets[i],0);
        vote(0x3000|images);states[bank].dart.enabled[0]=1;
        refused(2,0x10c40,8,1,0x3000|pattern(31),DEVICE_BAD_VALUE);
    }
    /* Each JPEG bank accepts only its own initialized IDs. */
    for (unsigned bank=14;bank<16;bank++) {
        reset();states[bank].dart.initialized_ids=bank==14 ? 1U<<15 : 3U<<13;
        refused(0,0x230,4,1,0,DEVICE_BAD_VALUE);
    }
    for (unsigned d=5;d<7;d++) {
        reset();idle_children();vote(0x3000|bits[d]);ps(offsets[d],0x100700ff);
        refused(2,0x10c40,8,1,0x3000,DEVICE_BAD_VALUE);
        ps(offsets[d],0x7000f);vote(0x3000);CHECK(read_ps(offsets[d])==0x70100);
        ps(offsets[d],0x70100);CHECK(read_ps(offsets[d])==0x70000);
        for (unsigned target=1;target<15;target++) refused(0,offsets[d],4,1,target,DEVICE_BAD_VALUE);
        for (unsigned w=0;w<=16;w++) if (w!=4) refused(0,offsets[d],w,1,0,DEVICE_BAD_WIDTH);
        refused(0,offsets[d]+1,4,1,0,DEVICE_BAD_WIDTH);
        refused(0,offsets[d]+4,4,1,0,DEVICE_UNKNOWN_REGISTER);
        for (unsigned b=0;b<64;b++) if (!((0x1f0f03ffUL>>b)&1))
            refused(0,offsets[d],4,1,1UL<<b,DEVICE_BAD_VALUE);
        reset();idle_children();ps(offsets[d],0);
        CHECK(device_model_start(models,states,0,24000000)==DEVICE_OK);
        refused(0,offsets[d],4,1,15,DEVICE_BAD_VALUE); /* stale PMP ACK after partial reset */
        CHECK(device_model_start(models+2,states+2,0,24000000)==DEVICE_OK);
        CHECK(read_ps(offsets[d])==0xff);pair(0x18c0,mask,0);
    }
    /* No VENC cluster dependency may leak into scaler/JPEG transitions. */
    reset();idle_children();ps(0x240,0);ps(0x248,0);v=0;
    CHECK(access(3,0x5c18,4,1,&v)==DEVICE_OK);
    vote(images);vote(0);vote(images);CHECK(states[3].pmc_dvmr.venc_cluster==0);
    for (unsigned bank=13;bank<16;bank++) {
        unsigned off=bank==13 ? 0x238 : 0x230;
        for (unsigned field=0;field<5;field++) {
            reset();idle_children();models[bank].config[field]^=1;
            refused(0,off,4,1,0,DEVICE_BAD_CONFIG);
            refused(2,0x10c40,8,1,all,DEVICE_BAD_CONFIG);
        }
        reset();idle_children();models[bank].base+=0x10000;
        refused(0,off,4,1,0,DEVICE_BAD_CONFIG);
        reset();idle_children();models[bank].span^=0x4000;
        refused(0,off,4,1,0,DEVICE_BAD_CONFIG);
        reset();idle_children();models[bank].config[4]|=bank==13 ? 1U<<13 : 1U<<19;
        refused(0,off,4,1,0,DEVICE_BAD_CONFIG);
    }
    for (unsigned i=0;i<COUNT;i++) if (i<3 || i>=13) {
        reset();idle_children();models[COUNT]=models[i];v=0;
        memcpy(saved,states,sizeof(states));unsigned off=i==13 ? 0x238 : 0x230;
        CHECK(device_models_access_at(models,states,COUNT+1,0,0,off,4,1,&v)==DEVICE_BAD_CONFIG);
        CHECK(!memcmp(saved,states,sizeof(states)));
        reset();idle_children();models[i].kind=0;
        refused(0,off,4,1,0,DEVICE_BAD_CONFIG);
    }
    if (topology) puts("568 536 61 18\n560 536 0 19");
    else printf("PMGR/PMP scaler and JPEG systems: %u checks passed\n",checks);
    return 0;
}

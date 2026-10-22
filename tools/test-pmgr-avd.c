/* SPDX-License-Identifier: MIT */
/* Physical PMGR state, PMP requests/ACK and DART resources form one lifecycle. */
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
    {17,0x381020000,0x20000,{16,44,943,36,16}},
    {25,0x3003c0000,0x14000,{0x10000,0x1a8,0x1b8,8,DEVICE_PMP_ACTIVE_MASK}},
    {18,0x308280000,0x9000,{1,0,0,0,0}},
};
static struct device_model models[4];
static struct device_state states[4],saved[4];
static enum device_result access(unsigned i,unsigned off,unsigned width,int write,uint64_t *v)
{ return device_models_access_at(models,states,4,i,0,off,width,write,v); }
static void reset(void)
{
    memcpy(models,original,sizeof(models));memset(states,0,sizeof(states));
    CHECK(device_models_valid(models,4,0,0));
    for (unsigned i=0;i<4;i++) CHECK(device_model_start(models+i,states+i,0,24000000)==DEVICE_OK);
}
static void write_ps(uint64_t v) { CHECK(access(0,0x270,4,1,&v)==DEVICE_OK); }
static void vote(uint64_t v) { CHECK(access(2,0x10c40,8,1,&v)==DEVICE_OK); }
static uint64_t read_ps(void)
{ uint64_t v=0;CHECK(access(0,0x270,4,0,&v)==DEVICE_OK);return v; }
static uint64_t read_pmp(unsigned off)
{ uint64_t v=0;CHECK(access(2,off,8,0,&v)==DEVICE_OK);return v; }
static void pair(unsigned off,uint64_t data,uint64_t meta)
{
    uint64_t v[2]={123,456};
    CHECK(device_model_read_pair(models+2,states+2,off,v)==DEVICE_OK);
    CHECK(v[0]==data && v[1]==meta);
}
static void refused(unsigned i,unsigned off,unsigned width,int write,uint64_t v,enum device_result want)
{
    memcpy(saved,states,sizeof(states));uint64_t input=v;
    enum device_result got=access(i,off,width,write,&v);
    if(got!=want) fprintf(stderr,"index %u offset %x: got %u expected %u\n",i,off,got,want);
    CHECK(got==want);CHECK(v==input && !memcmp(saved,states,sizeof(states)));
}
int main(int argc,char **argv)
{
    int topology=argc==2 && !strcmp(argv[1],"--topology");
    const uint64_t bit=DEVICE_PMP_AVD_BIT,mask=DEVICE_PMP_ACTIVE_MASK,offmask=mask&~bit;
    reset();CHECK(read_ps()==0xff && !states[3].pmgr_avd);
    pair(0x18c0,mask,0);pair(0x1880,0,0);
    /* Reached PMGR shutdown publishes actual off despite no new AP vote. */
    write_ps(0x3f0);CHECK(read_ps()==0x100);
    pair(0x18c0,offmask,2);pair(0x18c0,offmask,0);pair(0x1880,0,0);
    write_ps(0);pair(0x18c0,offmask,0); /* no phantom transition event */
    vote(0x3000);pair(0x18c0,offmask,2);pair(0x1880,0x3000,2);
    CHECK(read_pmp(0x18c0)==offmask); /* ordinary and pair reads agree */
    refused(1,0,4,0,123,DEVICE_BAD_VALUE);
    refused(1,0x104,4,1,1,DEVICE_BAD_VALUE);
    /* Direct wake reports actual on without inventing a vote. */
    write_ps(15);pair(0x18c0,mask,2);pair(0x1880,0x3000,0);
    uint64_t v=0;CHECK(access(1,0,4,0,&v)==DEVICE_OK && v==0x8e000000);
    v=0;CHECK(access(0,0x220,4,0,&v)==DEVICE_OK && v==0xff);
    refused(0,0x220,4,1,0,DEVICE_BAD_VALUE);
    /* AP voter wake and release own both request and actual state. */
    write_ps(0x300);vote(0x3000|bit);CHECK((read_ps()&0xff)==0xff);
    pair(0x18c0,mask,2);pair(0x1880,0x3000|bit,2);
    refused(0,0x270,4,1,0x3f0,DEVICE_BAD_VALUE);
    vote(0x3000);CHECK((read_ps()&0xff)==0);
    pair(0x18c0,offmask,2);pair(0x1880,0x3000,2);
    /* Unrelated recorded votes cannot be released by including an AVD change. */
    refused(2,0x10c40,8,1,bit,DEVICE_BAD_VALUE);
    vote(0x3000|bit);refused(2,0x10c40,8,1,0,DEVICE_BAD_VALUE);
    vote(0x3000|bit);pair(0x18c0,mask,2);pair(0x1880,0x3000|bit,2);
    /* Local transport cannot manufacture wake/ACK or release ownership. */
    vote(0x3000);v=0x3000|bit;memcpy(saved,states,sizeof(states));
    CHECK(device_model_access_state(models+2,states+2,0x10c40,8,1,&v)==DEVICE_BAD_VALUE);
    CHECK(!memcmp(saved,states,sizeof(states)));
    v=15;CHECK(device_model_access_state(models,states,0x270,4,1,&v)==DEVICE_BAD_VALUE);
    /* Capability initialization survives power-off; execution/frame policy
     * remains unimplemented for this decoder DART (logical ID 4). */
    CHECK(device_dart_monitor_init(models,states,4,4)==DEVICE_OK);
    CHECK(states[1].dart.initialized_ids==16);
    vote(0x3000|bit);vote(0x3000);CHECK(states[1].dart.initialized_ids==16);
    CHECK(device_dart_monitor_powerup(models,states,4,4)==DEVICE_BAD_CONFIG);
    unsigned index=123;
    CHECK(device_dart_admit_frame(models,states,4,5,4,0,0,&index)==DEVICE_BAD_CONFIG && index==123);
    /* Every accepted control remains local to this PS and transport. */
    reset();write_ps(0x100700ff);vote(bit);
    refused(2,0x10c40,8,1,0,DEVICE_BAD_VALUE); /* cannot disable auto policy silently */
    write_ps(0x7000f);vote(0);CHECK(read_ps()==0x70100);
    write_ps(0x70100);CHECK(read_ps()==0x70000); /* W1C history */
    for (unsigned target=1;target<15;target++) refused(0,0x270,4,1,target,DEVICE_BAD_VALUE);
    for (unsigned bitno=0;bitno<64;bitno++) if (!((0x1f0f03ffUL>>bitno)&1))
        refused(0,0x270,4,1,15|(1UL<<bitno),DEVICE_BAD_VALUE);
    for (unsigned width=0;width<=16;width++) if (width!=4)
        refused(0,0x270,width,1,0x3f0,DEVICE_BAD_WIDTH);
    for (unsigned width=0;width<=16;width++) if (width!=8)
        refused(2,0x10c40,width,1,bit,DEVICE_BAD_WIDTH);
    refused(0,0x271,4,1,0,DEVICE_BAD_WIDTH);refused(0,0x274,4,1,0,DEVICE_UNKNOWN_REGISTER);
    refused(2,0x10c40,8,1,bit|(1UL<<10),DEVICE_BAD_VALUE);
    refused(2,0x10c40,8,1,bit|(1UL<<63),DEVICE_BAD_VALUE);
    /* A resource blocks direct gating and vote release atomically, including
     * metadata and PS policy. Do not erase mappings/errors to make it pass. */
    for (unsigned word=0;word<sizeof(struct dart_state)/4;word++) {
        if (word*4>=offsetof(struct dart_state,tlb_end)+4 &&
            word*4<offsetof(struct dart_state,translations)) continue;
        reset();uint32_t one=1;memcpy((char *)&states[1].dart+4*word,&one,4);
        refused(0,0x270,4,1,0x3f0,DEVICE_BAD_VALUE);
        vote(bit);refused(2,0x10c40,8,1,0,DEVICE_BAD_VALUE);
    }
    reset();states[2].pmp_active.ack^=bit;
    refused(0,0x270,4,1,0,DEVICE_BAD_VALUE);refused(2,0x10c40,8,1,bit,DEVICE_BAD_VALUE);
    for (unsigned field=0;field<5;field++) {
        reset();models[1].config[field]^=1;
        refused(0,0x270,4,1,0,DEVICE_BAD_CONFIG);refused(2,0x10c40,8,1,bit,DEVICE_BAD_CONFIG);
    }
    for (unsigned i=0;i<4;i++) {
        reset();models[i].base+=0x10000;
        refused(0,0x270,4,1,0,DEVICE_BAD_CONFIG);
    }
    reset();v=bit;CHECK(device_models_access_at(models,states,3,2,0,0x10c40,8,1,&v)==DEVICE_BAD_CONFIG);
    reset();write_ps(0);CHECK(device_model_start(models,states,0,24000000)==DEVICE_OK);
    /* Model-local reset is not a registry reset; detect its stale ACK until
     * the associated transport is explicitly reset too. */
    refused(0,0x270,4,1,0,DEVICE_BAD_VALUE);
    CHECK(device_model_start(models+2,states+2,0,24000000)==DEVICE_OK);
    CHECK(read_ps()==0xff);pair(0x18c0,mask,0);
    if (topology) puts("624 544 17");
    else printf("PMGR/PMP AVD: %u checks passed\n",checks);
    return 0;
}

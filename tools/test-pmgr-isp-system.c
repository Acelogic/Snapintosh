/* SPDX-License-Identifier: MIT */
/* ISP system/children, three DART banks and physical PMP votes are coupled. */
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
    {17,0x3228c0000,0xc000,{16,44,341,36,0}},
    {25,0x3003c0000,0x14000,{0x10000,0x1a8,0x1b8,8,DEVICE_PMP_ACTIVE_MASK}},
    {18,0x308280000,0x9000,{1,0,0,0,0}},
    {17,0x3228e0000,0xc000,{16,44,341,36,0}},
    {17,0x322900000,0xc000,{16,44,341,36,0}},
    {17,0x381020000,0x20000,{16,44,943,36,16}},
};
static struct device_model models[8];
static struct device_state states[8],saved[8];
static const unsigned banks[3]={1,4,5};
static enum device_result access(unsigned i,unsigned off,unsigned width,int write,uint64_t *v)
{ return device_models_access_at(models,states,7,i,0,off,width,write,v); }
static void reset(void)
{
    memset(models,0,sizeof(models));memcpy(models,original,sizeof(original));
    memset(states,0,sizeof(states));CHECK(device_models_valid(models,7,0,0));
    for (unsigned i=0;i<7;i++) CHECK(device_model_start(models+i,states+i,0,24000000)==DEVICE_OK);
}
static void write_ps(unsigned off,uint64_t v)
{ CHECK(access(0,off,4,1,&v)==DEVICE_OK); }
static uint64_t read_ps(unsigned off)
{ uint64_t v=0;CHECK(access(0,off,4,0,&v)==DEVICE_OK);return v; }
static void vote(uint64_t v) { CHECK(access(2,0x10c40,8,1,&v)==DEVICE_OK); }
static void pair(unsigned off,uint64_t data,uint64_t meta)
{
    uint64_t v[2]={123,456};CHECK(device_model_read_pair(models+2,states+2,off,v)==DEVICE_OK);
    CHECK(v[0]==data && v[1]==meta);
}
static void refused(unsigned i,unsigned off,unsigned width,int write,uint64_t v,enum device_result want)
{
    memcpy(saved,states,sizeof(states));uint64_t input=v;
    enum device_result got=access(i,off,width,write,&v);
    if (got!=want) fprintf(stderr,"index %u offset %x: got %u expected %u\n",i,off,got,want);
    CHECK(got==want);CHECK(v==input && !memcmp(saved,states,sizeof(states)));
}
static void idle_children(void)
{ for (unsigned n=13;n;n--) write_ps(0x4000+8*(n-1),0x3f0); }
int main(int argc,char **argv)
{
    int topology=argc==2 && !strcmp(argv[1],"--topology");
    const uint64_t bit=DEVICE_PMP_ISP_BIT,avd=DEVICE_PMP_AVD_BIT;
    const uint64_t mask=DEVICE_PMP_ACTIVE_MASK,offmask=mask&~bit;
    reset();CHECK(read_ps(0x268)==0xff && !states[3].pmgr_isp_sys);
    CHECK(offsetof(struct device_state,pmgr_isp_sys)-offsetof(struct device_state,pmgr_policy)==692);
    refused(0,0x268,4,1,0x3f0,DEVICE_BAD_VALUE); /* live children */
    idle_children();vote(0x3000);pair(0x1880,0x3000,2);pair(0x18c0,mask,2);
    write_ps(0x268,0x3f0);CHECK(read_ps(0x268)==0x100);
    pair(0x18c0,offmask,2);pair(0x1880,0x3000,0);
    write_ps(0x268,0);pair(0x18c0,offmask,0);
    vote(0x3000);pair(0x18c0,offmask,2); /* unchanged vote cannot reset ACK */
    for (unsigned child=0;child<13;child++) {
        refused(0,0x4000+8*child,4,1,15,DEVICE_BAD_VALUE);
        refused(0,0x4000+8*child,4,1,4,DEVICE_BAD_VALUE);
    }
    for (unsigned bank=0;bank<3;bank++) {
        refused(banks[bank],0,4,0,123,DEVICE_BAD_VALUE);
        refused(banks[bank],0x104,4,1,1,DEVICE_BAD_VALUE);
    }
    CHECK(read_ps(0x220)==0xff);refused(0,0x220,4,1,0,DEVICE_BAD_VALUE);
    write_ps(0x268,15);pair(0x18c0,mask,2);pair(0x1880,0x3000,2);
    for (unsigned bank=0;bank<3;bank++) {
        uint64_t v=0;CHECK(access(banks[bank],0,4,0,&v)==DEVICE_OK && v==0x8e000000);
    }
    write_ps(0x4000,15);refused(0,0x268,4,1,0,DEVICE_BAD_VALUE);
    write_ps(0x4000,0);write_ps(0x268,0);
    /* Votes wake only the system; children remain off until explicit writes. */
    vote(0x3000|bit);CHECK((read_ps(0x268)&0xff)==0xff);
    for (unsigned child=0;child<13;child++) CHECK(!(read_ps(0x4000+8*child)&15));
    refused(0,0x268,4,1,0,DEVICE_BAD_VALUE);
    write_ps(0x4018,15);refused(2,0x10c40,8,1,0x3000,DEVICE_BAD_VALUE);
    write_ps(0x4018,0);vote(0x3000);pair(0x18c0,offmask,2);
    uint64_t v=0;CHECK(access(2,0x18c0,8,0,&v)==DEVICE_OK && v==offmask);
    v=15;memcpy(saved,states,sizeof(states));
    CHECK(device_model_access_state(models,states,0x268,4,1,&v)==DEVICE_BAD_VALUE);
    CHECK(device_model_access_state(models,states,0x4000,4,1,&v)==DEVICE_BAD_VALUE);
    v=0x3000|bit;
    CHECK(device_model_access_state(models+2,states+2,0x10c40,8,1,&v)==DEVICE_BAD_VALUE);
    CHECK(!memcmp(saved,states,sizeof(states)));
    /* An individual child also blocks parent off, even if its immediate
     * parent was damaged/reset. Test both active and clock-gated ownership. */
    for (unsigned child=0;child<13;child++) for (unsigned level=4;level<=15;level+=11) {
        reset();idle_children();states[0].pmgr_isp[child]=level;
        refused(0,0x268,4,1,0,DEVICE_BAD_VALUE);
        vote(bit);refused(2,0x10c40,8,1,0,DEVICE_BAD_VALUE);
    }
    /* Multi-domain requests are all-or-nothing, in either direction. */
    reset();idle_children();write_ps(0x270,0);write_ps(0x268,0);
    vote(0x3000|bit|avd);CHECK((read_ps(0x270)&15)==15 && (read_ps(0x268)&15)==15);
    pair(0x18c0,mask,2);pair(0x1880,0x3000|bit|avd,2);
    write_ps(0x4000,15);refused(2,0x10c40,8,1,0x3000,DEVICE_BAD_VALUE);
    write_ps(0x4000,0);vote(0x3000);
    CHECK(!(read_ps(0x270)&15) && !(read_ps(0x268)&15));
    pair(0x18c0,mask&~(bit|avd),2);pair(0x1880,0x3000,2);
    vote(0x3000|avd);vote(0x3000|bit); /* swap awake domain in one request */
    CHECK(!(read_ps(0x270)&15) && (read_ps(0x268)&15)==15);
    refused(2,0x10c40,8,1,avd,DEVICE_BAD_VALUE); /* must retain display votes */
    vote(0x3000|avd);CHECK((read_ps(0x270)&15)==15 && !(read_ps(0x268)&15));
    vote(0x3000|bit|avd);write_ps(0x268,0x100700ff);
    refused(2,0x10c40,8,1,0x3000,DEVICE_BAD_VALUE); /* ISP auto policy preserved */
    write_ps(0x268,0x7000f);vote(0x3000);
    CHECK(read_ps(0x268)==0x70100);write_ps(0x268,0x70100);CHECK(read_ps(0x268)==0x70000);
    vote(0x3000|bit|avd);write_ps(0x270,0x100000ff);
    refused(2,0x10c40,8,1,0x3000,DEVICE_BAD_VALUE); /* AVD auto policy preserved */
    /* Every DART runtime word in every bank blocks both direct and bundled
     * release, preserving unrelated AVD state and all request metadata. */
    for (unsigned bank=0;bank<3;bank++) for (unsigned word=0;word<sizeof(struct dart_state)/4;word++) {
        if (word*4>=offsetof(struct dart_state,tlb_end)+4 &&
            word*4<offsetof(struct dart_state,translations)) continue;
        reset();idle_children();uint32_t one=1;
        memcpy((char *)&states[banks[bank]].dart+4*word,&one,4);
        refused(0,0x268,4,1,0x3f0,DEVICE_BAD_VALUE);
        vote(bit|avd);refused(2,0x10c40,8,1,0,DEVICE_BAD_VALUE);
    }
    reset();idle_children();
    for (unsigned target=1;target<15;target++) refused(0,0x268,4,1,target,DEVICE_BAD_VALUE);
    for (unsigned b=0;b<64;b++) if (!((0x1f0f03ffUL>>b)&1))
        refused(0,0x268,4,1,15|(1UL<<b),DEVICE_BAD_VALUE);
    for (unsigned w=0;w<=16;w++) if (w!=4) refused(0,0x268,w,1,0,DEVICE_BAD_WIDTH);
    for (unsigned w=0;w<=16;w++) if (w!=8) refused(2,0x10c40,w,1,bit,DEVICE_BAD_WIDTH);
    refused(0,0x269,4,1,0,DEVICE_BAD_WIDTH);refused(0,0x26c,4,1,0,DEVICE_UNKNOWN_REGISTER);
    refused(2,0x10c40,8,1,bit|(1UL<<10),DEVICE_BAD_VALUE);
    refused(2,0x10c40,8,1,bit|(1UL<<63),DEVICE_BAD_VALUE);
    for (unsigned bank=0;bank<3;bank++) for (unsigned field=0;field<5;field++) {
        reset();idle_children();models[banks[bank]].config[field]^=1;
        refused(0,0x268,4,1,0,DEVICE_BAD_CONFIG);
        refused(2,0x10c40,8,1,bit|avd,DEVICE_BAD_CONFIG);
    }
    for (unsigned i=0;i<6;i++) {
        reset();idle_children();models[i].base+=0x10000;
        refused(0,0x268,4,1,0,DEVICE_BAD_CONFIG);
    }
    for (unsigned i=0;i<6;i++) {
        reset();models[7]=models[i];v=0;memcpy(saved,states,sizeof(states));
        CHECK(device_models_access_at(models,states,8,0,0,0x268,4,1,&v)==DEVICE_BAD_CONFIG);
        CHECK(!memcmp(saved,states,sizeof(states)));
    }
    reset();v=bit;CHECK(device_models_access_at(models,states,5,2,0,0x10c40,8,1,&v)==DEVICE_BAD_CONFIG);
    /* Combined SMMU/APF ISP monitor execution is still unimplemented. */
    for (unsigned id=0;id<32;id++) if (id!=4) {
        CHECK(device_dart_monitor_init(models,states,7,id)==DEVICE_NOT_FOUND);
        CHECK(device_dart_monitor_powerup(models,states,7,id)==DEVICE_NOT_FOUND);
    }
    reset();idle_children();states[2].pmp_active.ack^=bit;
    refused(0,0x268,4,1,0,DEVICE_BAD_VALUE);refused(2,0x10c40,8,1,bit,DEVICE_BAD_VALUE);
    reset();idle_children();write_ps(0x268,0);
    CHECK(device_model_start(models,states,0,24000000)==DEVICE_OK);
    refused(0,0x268,4,1,15,DEVICE_BAD_VALUE); /* stale transport after partial reset */
    CHECK(device_model_start(models+2,states+2,0,24000000)==DEVICE_OK);
    CHECK(read_ps(0x268)==0xff);pair(0x18c0,mask,0);
    if (topology) puts("616 544 11");
    else printf("PMGR/PMP ISP system: %u checks passed\n",checks);
    return 0;
}

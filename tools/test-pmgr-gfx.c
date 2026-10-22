/* SPDX-License-Identifier: MIT */
/* GFX power requires independent UAT admission; PMP transactions stay atomic. */
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "device.h"
static unsigned checks,admissions;
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
    {29,0x481000000,0x1000,{0,0,0,0,0}},
};
enum { COUNT=sizeof(original)/sizeof(original[0]) };
static struct device_model models[COUNT+1];
static struct device_state states[COUNT+1],saved[COUNT+1];
static int idle=1;
static int admit(void *ctx) { CHECK(ctx==&idle);admissions++;return idle; }
static struct device_power_resources resources={&idle,admit};
static const unsigned offsets[8]={0x270,0x268,0x250,0x240,0x248,0x238,0x230,0x1f0};
static const uint64_t bits[8]={DEVICE_PMP_AVD_BIT,DEVICE_PMP_ISP_BIT,DEVICE_PMP_PRORES_BIT,
    DEVICE_PMP_VENC0_BIT,DEVICE_PMP_VENC1_BIT,DEVICE_PMP_MSR_BIT,DEVICE_PMP_JPG_BIT,DEVICE_PMP_GFX_BIT};
static enum device_result access(unsigned i,unsigned off,unsigned w,int write,uint64_t *v)
{ return device_models_access_power_at(models,states,COUNT,i,0,off,w,write,v,&resources); }
static void reset(void)
{
    memset(models,0,sizeof(models));memcpy(models,original,sizeof(original));
    memset(states,0,sizeof(states));CHECK(device_models_valid(models,COUNT,0,0));
    for (unsigned i=0;i<COUNT;i++) CHECK(device_model_start(models+i,states+i,0,24000000)==DEVICE_OK);
    idle=1;admissions=0;resources.gfx_idle=admit;
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
{ uint64_t v=0;for (unsigned i=0;i<8;i++) if (p&(1U<<i)) v|=bits[i];return v; }
int main(int argc,char **argv)
{
    const uint64_t mask=DEVICE_PMP_ACTIVE_MASK,bit=DEVICE_PMP_GFX_BIT,all=pattern(255);
    reset();CHECK(read_ps(0x1f0)==0xff && !states[1].pmgr_gfx && !admissions);
    CHECK(offsetof(struct device_state,pmgr_gfx)-offsetof(struct device_state,pmgr_policy)==716);
    uint64_t v=0;memcpy(saved,states,sizeof(states));
    CHECK(device_models_access_at(models,states,COUNT,0,0,0x1f0,4,1,&v)==DEVICE_BAD_CONFIG);
    CHECK(device_model_access_state(models,states,0x1f0,4,1,&v)==DEVICE_BAD_VALUE);
    CHECK(!memcmp(saved,states,sizeof(states)));
    resources.gfx_idle=NULL;refused(0,0x1f0,4,1,0,DEVICE_BAD_CONFIG);resources.gfx_idle=admit;
    idle=0;refused(0,0x1f0,4,1,0,DEVICE_BAD_VALUE);idle=1;
    vote(0x3000);pair(0x1880,0x3000,2);pair(0x18c0,mask,2);
    ps(0x1f0,0x3f0);CHECK(read_ps(0x1f0)==0x100);pair(0x18c0,mask&~bit,2);
    ps(0x1f0,0);pair(0x18c0,mask&~bit,0);pair(0x1880,0x3000,0);
    idle=0;refused(0,0x1f0,4,1,15,DEVICE_BAD_VALUE);
    refused(2,0x10c40,8,1,0x3000|bit,DEVICE_BAD_VALUE);idle=1;
    vote(0x3000|bit);CHECK(read_ps(0x1f0)==0x1ff);pair(0x18c0,mask,2);
    refused(0,0x1f0,4,1,0,DEVICE_BAD_VALUE);vote(0x3000);
    CHECK(read_ps(0x198)==0xff && read_ps(0x1a8)==0xff);
    refused(0,0x198,4,1,0,DEVICE_BAD_VALUE);refused(0,0x1a8,4,1,0,DEVICE_BAD_VALUE);
    /* All prior media configurations with complementary or unchanged
     * targets, crossed with all four GFX transitions. Existing exhaustive
     * seven-domain tests remain separate; late GFX refusal is new here. */
    for (unsigned before=0;before<128;before++) for (unsigned same=0;same<2;same++)
    for (unsigned g0=0;g0<2;g0++) for (unsigned g1=0;g1<2;g1++) {
        reset();idle_children();for (unsigned i=0;i<8;i++) ps(offsets[i],0);
        unsigned a=same ? before : before^127;
        uint64_t old=0x3000|pattern(before|(g0<<7)),next=0x3000|pattern(a|(g1<<7));
        vote(old);
        if (g0!=g1) {
            idle=0;refused(2,0x10c40,8,1,next,DEVICE_BAD_VALUE);idle=1;
        }
        vote(next);pair(0x1880,next,2);pair(0x18c0,(mask&~all)|pattern(a|(g1<<7)),2);
        for (unsigned i=0;i<8;i++) CHECK((read_ps(offsets[i])&15)==(((a|(g1<<7))&(1U<<i)) ? 15 : 0));
    }
    reset();idle_children();ps(0x240,0);ps(0x248,0);v=0;
    CHECK(access(3,0x5c18,4,1,&v)==DEVICE_OK);ps(0x1f0,0);ps(0x1f0,15);
    CHECK(states[3].pmc_dvmr.venc_cluster==0);
    reset();vote(bit);ps(0x1f0,0x100700ff);refused(2,0x10c40,8,1,0,DEVICE_BAD_VALUE);
    ps(0x1f0,0x7000f);vote(0);CHECK(read_ps(0x1f0)==0x70100);
    ps(0x1f0,0x70100);CHECK(read_ps(0x1f0)==0x70000);
    for (unsigned t=1;t<15;t++) refused(0,0x1f0,4,1,t,DEVICE_BAD_VALUE);
    for (unsigned w=0;w<=16;w++) if (w!=4) refused(0,0x1f0,w,1,0,DEVICE_BAD_WIDTH);
    for (unsigned b=0;b<64;b++) if (!((0x1f0f03ffUL>>b)&1)) refused(0,0x1f0,4,1,1UL<<b,DEVICE_BAD_VALUE);
    refused(0,0x1f1,4,1,0,DEVICE_BAD_WIDTH);refused(0,0x1f4,4,1,0,DEVICE_UNKNOWN_REGISTER);
    for (unsigned i=0;i<COUNT;i++) if (i<3 || i==16) {
        reset();models[i].base+=0x10000;refused(0,0x1f0,4,1,0,DEVICE_BAD_CONFIG);
        reset();models[COUNT]=models[i];v=0;memcpy(saved,states,sizeof(states));
        CHECK(device_models_access_power_at(models,states,COUNT+1,0,0,0x1f0,4,1,&v,&resources)==DEVICE_BAD_CONFIG);
        CHECK(!memcmp(saved,states,sizeof(states)));
        reset();models[i].kind=0;refused(0,0x1f0,4,1,0,DEVICE_BAD_CONFIG);
    }
    for (unsigned policy=0;policy<4;policy++) {
        reset();states[16].pmgr_axi2af[0]=policy&1;states[16].pmgr_axi2af[1]=policy>>1;
        ps(0x1f0,0);ps(0x1f0,15);
        CHECK(states[16].pmgr_axi2af[0]==(policy&1) && states[16].pmgr_axi2af[1]==policy>>1);
    }
    for (unsigned field=0;field<5;field++) {
        reset();models[16].config[field]=1;refused(0,0x1f0,4,1,0,DEVICE_BAD_CONFIG);
    }
    reset();models[16].span=0x2000;refused(0,0x1f0,4,1,0,DEVICE_BAD_CONFIG);
    reset();states[16].pmgr_axi2af[1]=2;refused(0,0x1f0,4,1,0,DEVICE_BAD_VALUE);
    /* Any new model overlapping SGX or either ASC must join admission. */
    const uint64_t bases[]={0x480000000,0x480d00000,0x482600000,0x482e00000,0x47ffff000};
    for (unsigned i=0;i<sizeof(bases)/sizeof(bases[0]);i++) {
        reset();models[COUNT]=models[3];models[COUNT].base=bases[i];
        v=0;memcpy(saved,states,sizeof(states));
        CHECK(device_models_access_power_at(models,states,COUNT+1,0,0,0x1f0,4,1,&v,&resources)==DEVICE_BAD_CONFIG);
        CHECK(!memcmp(saved,states,sizeof(states)));
    }
    reset();ps(0x1f0,0);CHECK(device_model_start(models,states,0,24000000)==DEVICE_OK);
    refused(0,0x1f0,4,1,15,DEVICE_BAD_VALUE);
    CHECK(device_model_start(models+2,states+2,0,24000000)==DEVICE_OK);
    CHECK(read_ps(0x1f0)==0xff);pair(0x18c0,mask,0);
    if (argc==2 && !strcmp(argv[1],"--topology")) puts("496 408 424 9");
    else printf("PMGR/PMP GFX with resource admission: %u checks passed\n",checks);
    return 0;
}

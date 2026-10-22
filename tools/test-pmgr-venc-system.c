/* SPDX-License-Identifier: MIT */
/* VENC system/DART/cluster ordering and atomic five-domain PMP requests. */
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
};
static struct device_model models[14];
static struct device_state states[14],saved[14];
static const unsigned offsets[5]={0x270,0x268,0x250,0x240,0x248};
static const uint64_t bits[5]={DEVICE_PMP_AVD_BIT,DEVICE_PMP_ISP_BIT,DEVICE_PMP_PRORES_BIT,
                              DEVICE_PMP_VENC0_BIT,DEVICE_PMP_VENC1_BIT};
static enum device_result access(unsigned i,unsigned off,unsigned w,int write,uint64_t *v)
{ return device_models_access_at(models,states,13,i,0,off,w,write,v); }
static void reset(void)
{
    memset(models,0,sizeof(models));memcpy(models,original,sizeof(original));
    memset(states,0,sizeof(states));CHECK(device_models_valid(models,13,0,0));
    for (unsigned i=0;i<13;i++) CHECK(device_model_start(models+i,states+i,0,24000000)==DEVICE_OK);
}
static void ps(unsigned off,uint64_t v) { CHECK(access(0,off,4,1,&v)==DEVICE_OK); }
static uint64_t read_ps(unsigned off)
{ uint64_t v=0;CHECK(access(0,off,4,0,&v)==DEVICE_OK);return v; }
static void vote(uint64_t v) { CHECK(access(2,0x10c40,8,1,&v)==DEVICE_OK); }
static void cluster(uint64_t v) { CHECK(access(3,0x5c18,4,1,&v)==DEVICE_OK); }
static void cluster_state(unsigned expected)
{
    for (unsigned off=0x5c18;off<=0x5c1c;off+=4) {
        uint64_t v=123;CHECK(access(3,off,4,0,&v)==DEVICE_OK && v==expected);
    }
}
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
}
static uint64_t pattern(unsigned p)
{ uint64_t v=0;for (unsigned i=0;i<5;i++) if (p&(1U<<i)) v|=bits[i];return v; }
int main(int argc,char **argv)
{
    int topology=argc==2 && !strcmp(argv[1],"--topology");
    const uint64_t mask=DEVICE_PMP_ACTIVE_MASK,enc=bits[3]|bits[4],all=pattern(31);
    reset();CHECK(read_ps(0x240)==0xff && read_ps(0x248)==0xff);
    CHECK(!states[1].pmgr_venc_sys[0] && !states[1].pmgr_venc_sys[1]);
    CHECK(offsetof(struct device_state,pmgr_venc_sys)-offsetof(struct device_state,pmgr_policy)==700);
    cluster_state(8);refused(3,0x5c18,4,1,0,DEVICE_BAD_VALUE);
    refused(0,0x240,4,1,0,DEVICE_BAD_VALUE);refused(0,0x248,4,1,0,DEVICE_BAD_VALUE);
    idle_children();vote(0x3000);pair(0x1880,0x3000,2);pair(0x18c0,mask,2);
    ps(0x248,0x3f0);CHECK(read_ps(0x248)==0x100);pair(0x18c0,mask&~bits[4],2);
    refused(3,0x5c18,4,1,0,DEVICE_BAD_VALUE); /* sibling still active */
    ps(0x240,0x3f0);pair(0x18c0,mask&~enc,2);pair(0x1880,0x3000,0);
    cluster(0);cluster_state(0);pair(0x18c0,mask&~enc,0); /* cluster has no PMP row */
    for (unsigned u=0;u<2;u++) {
        refused(0,0x240+8*u,4,1,15,DEVICE_BAD_VALUE);
        refused(2,0x10c40,8,1,0x3000|bits[u+3],DEVICE_BAD_VALUE);
    }
    for (unsigned c=0;c<10;c++) {
        refused(0,0x8000+8*c,4,1,15,DEVICE_BAD_VALUE);
        refused(0,0x8000+8*c,4,1,4,DEVICE_BAD_VALUE);
    }
    for (unsigned bank=4;bank<8;bank++) {
        refused(bank,0,4,0,123,DEVICE_BAD_VALUE);
        refused(bank,0x104,4,1,1,DEVICE_BAD_VALUE);
    }
    cluster(8);ps(0x240,15);ps(0x8000,15);
    CHECK(!(read_ps(0x248)&15));refused(3,0x5c18,4,1,0,DEVICE_BAD_VALUE);
    refused(0,0x240,4,1,0,DEVICE_BAD_VALUE);
    uint64_t v=0;CHECK(access(4,0,4,0,&v)==DEVICE_OK && v==0x8e000000);
    refused(6,0,4,0,123,DEVICE_BAD_VALUE); /* other system stays off */
    ps(0x8000,0);ps(0x240,0);vote(0x3000|enc);
    for (unsigned c=0;c<10;c++) CHECK(!(read_ps(0x8000+8*c)&15));
    refused(0,0x248,4,1,0,DEVICE_BAD_VALUE);
    vote(0x3000);cluster(0);vote(0x3000);pair(0x18c0,mask&~enc,2);
    /* Local access cannot bypass ownership for cluster/system wake. */
    v=8;memcpy(saved,states,sizeof(states));
    CHECK(device_model_access_state(models+3,states+3,0x5c18,4,1,&v)==DEVICE_BAD_VALUE);
    v=15;CHECK(device_model_access_state(models,states,0x240,4,1,&v)==DEVICE_BAD_VALUE);
    CHECK(device_model_access_state(models,states,0x8000,4,1,&v)==DEVICE_BAD_VALUE);
    CHECK(!memcmp(saved,states,sizeof(states)));
    /* All 1,024 old/new physical request combinations, including shared
     * encoder parent and unrelated media, preserve exact ACK and AP votes. */
    for (unsigned before=0;before<32;before++) for (unsigned after=0;after<32;after++) {
        reset();idle_children();for (unsigned i=0;i<5;i++) ps(offsets[i],0);
        vote(0x3000|pattern(before));vote(0x3000|pattern(after));
        pair(0x1880,0x3000|pattern(after),2);pair(0x18c0,(mask&~all)|pattern(after),2);
        for (unsigned i=0;i<5;i++) CHECK((read_ps(offsets[i])&15)==((after&(1U<<i)) ? 15 : 0));
        cluster_state(8);
    }
    /* Child ownership blocks direct off and bundled release; no sibling
     * or unrelated media transition can leak through a failed preflight. */
    for (unsigned c=0;c<10;c++) for (unsigned level=4;level<=15;level+=11) {
        reset();idle_children();states[0].pmgr_venc[c]=level;
        refused(0,0x240+8*(c/5),4,1,0,DEVICE_BAD_VALUE);
        vote(all);refused(2,0x10c40,8,1,0,DEVICE_BAD_VALUE);
    }
    for (unsigned bank=4;bank<8;bank++) for (unsigned word=0;word<sizeof(struct dart_state)/4;word++) {
        if (word*4>=offsetof(struct dart_state,tlb_end)+4 &&
            word*4<offsetof(struct dart_state,translations)) continue;
        reset();idle_children();uint32_t one=1;memcpy((char *)&states[bank].dart+4*word,&one,4);
        refused(0,0x240+8*((bank-4)/2),4,1,0,DEVICE_BAD_VALUE);
        vote(all);refused(2,0x10c40,8,1,0,DEVICE_BAD_VALUE);
        /* Corrupt off-state ownership must also refuse shared cluster gate. */
        states[0].pmgr_venc_sys[0]=states[0].pmgr_venc_sys[1]=0;
        states[2].pmp_active.request=0;states[2].pmp_active.ack=mask&~enc;
        refused(3,0x5c18,4,1,0,DEVICE_BAD_VALUE);
    }
    reset();idle_children();for (unsigned i=0;i<5;i++) ps(offsets[i],0);
    cluster(0);refused(2,0x10c40,8,1,all,DEVICE_BAD_VALUE); /* no partial wakes */
    cluster(8);vote(all);ps(0x248,0x100700ff);
    refused(2,0x10c40,8,1,0,DEVICE_BAD_VALUE); /* preserve auto policy */
    ps(0x248,0x7000f);vote(0);CHECK(read_ps(0x248)==0x70100);
    ps(0x248,0x70100);CHECK(read_ps(0x248)==0x70000);
    for (unsigned u=0;u<2;u++) {
        for (unsigned t=1;t<15;t++) refused(0,0x240+8*u,4,1,t,DEVICE_BAD_VALUE);
        for (unsigned w=0;w<=16;w++) if (w!=4) refused(0,0x240+8*u,w,1,0,DEVICE_BAD_WIDTH);
    }
    for (unsigned b=0;b<64;b++) if (b!=3) refused(3,0x5c18,4,1,1UL<<b,DEVICE_BAD_VALUE);
    for (unsigned w=0;w<=16;w++) if (w!=4) {
        refused(3,0x5c18,w,1,0,DEVICE_BAD_WIDTH);refused(3,0x5c1c,w,0,0,DEVICE_BAD_WIDTH);
    }
    refused(3,0x5c1c,4,1,8,DEVICE_UNKNOWN_REGISTER);
    for (unsigned i=0;i<8;i++) {
        reset();models[i].base+=0x10000;refused(0,0x248,4,1,0,DEVICE_BAD_CONFIG);
        refused(3,0x5c18,4,1,8,DEVICE_BAD_CONFIG);
        reset();models[13]=models[i];v=0;memcpy(saved,states,sizeof(states));
        CHECK(device_models_access_at(models,states,14,0,0,0x248,4,1,&v)==DEVICE_BAD_CONFIG);
        CHECK(!memcmp(saved,states,sizeof(states)));
    }
    for (unsigned i=3;i<8;i++) for (unsigned field=0;field<5;field++) {
        reset();models[i].config[field]^=1;refused(0,0x240,4,1,0,DEVICE_BAD_CONFIG);
        refused(2,0x10c40,8,1,enc,DEVICE_BAD_CONFIG);
    }
    reset();states[3].pmc_dvmr.venc_cluster=1;
    refused(3,0x5c18,4,1,8,DEVICE_BAD_VALUE);refused(0,0x248,4,1,0,DEVICE_BAD_VALUE);
    reset();idle_children();ps(0x240,0);ps(0x248,0);cluster(0);
    CHECK(device_model_start(models,states,0,24000000)==DEVICE_OK);
    refused(0,0x240,4,1,15,DEVICE_BAD_VALUE);refused(0,0x8000,4,1,15,DEVICE_BAD_VALUE);
    CHECK(device_model_start(models+3,states+3,0,24000000)==DEVICE_OK);
    refused(0,0x240,4,1,15,DEVICE_BAD_VALUE); /* PMP still stale */
    CHECK(device_model_start(models+2,states+2,0,24000000)==DEVICE_OK);
    CHECK(read_ps(0x240)==0xff);cluster_state(8);
    if (topology) puts("576 536 322 15\n584 536 322 16\n23576 23580 8");
    else printf("PMGR/PMP VENC systems and PMC cluster: %u checks passed\n",checks);
    return 0;
}

/* SPDX-License-Identifier: MIT */
#include "device.h"
#include "mmio.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static unsigned checks;
#define CHECK(x) do { checks++; if (!(x)) { \
    fprintf(stderr,"FAIL %d: %s\n",__LINE__,#x); exit(1); } } while (0)
static struct device_model models[]={
    {DEVICE_PTD_PMP_ACTIVE_V1,0x3003c0000,0x14000,{0x10000,0x1a8,0x1b8,8,DEVICE_PMP_ACTIVE_MASK}},
    {DEVICE_PMGR_ACTIVE_BOOT_V1,0x300700000,0x11000,{0,0,0,0,0}},
    {DEVICE_PMGR_ACTIVE_BOOT_V1,0x308280000,0x9000,{1,0,0,0,0}}
};
static struct device_state state,saved,power;
static void refused(unsigned off,unsigned width,int write,uint64_t v,enum device_result error)
{
    saved=state;uint64_t before=v;
    CHECK(device_model_access_state(models,&state,off,width,write,&v)==error);
    CHECK(v==before && !memcmp(&state,&saved,sizeof(state)));
}
static uint64_t read64(unsigned off)
{
    uint64_t v=~0UL;
    CHECK(device_model_access_state(models,&state,off,8,0,&v)==DEVICE_OK);
    return v;
}
static void write64(unsigned off,uint64_t value)
{
    CHECK(device_model_access_state(models,&state,off,8,1,&value)==DEVICE_OK);
}
static void pair(unsigned off,uint64_t data,uint64_t metadata)
{
    uint64_t values[2]={~0UL,~0UL};
    CHECK(device_model_read_pair(models,&state,off,values)==DEVICE_OK);
    CHECK(values[0]==data && values[1]==metadata);
}
int main(int argc,char **argv)
{
    CHECK(device_models_valid(models,3,0,0));
    if (argc==2 && !strcmp(argv[1],"--supported-mask")) {
        printf("%llu\n",(unsigned long long)models[0].config[4]);return 0;
    }
    CHECK(!device_models_valid(models,1,0,0));
    CHECK(!device_models_valid(models,2,0,0));
    struct device_model original=models[2];
    models[2].base+=0x1000;CHECK(!device_models_valid(models,3,0,0));models[2]=original;
    models[2].config[0]=2;CHECK(!device_models_valid(models,3,0,0));models[2]=original;
    /* All twelve physical source rows resolve to permanent active-state
     * registers. Even a retained automatic policy cannot turn one off. */
    const unsigned slots[]={7,8,9,11,12,13,14,15,16,17,18,19};
    const unsigned offsets[]={0x50,0x58,0x1f0,0x268,0x280,0x288,
                              0x250,0x240,0x248,0x270,0x238,0x230};
    uint64_t mask=0;
    CHECK(device_model_start(models+1,&power,0,24000000)==DEVICE_OK);
    for (unsigned i=0;i<12;i++) {
        mask|=1UL<<slots[i];uint64_t v=0;
        CHECK(device_model_access_state(models+1,&power,offsets[i],4,0,&v)==DEVICE_OK);
        CHECK((v&0xff)==0xff);
        v=0x100f000f;
        CHECK(device_model_access_state(models+1,&power,offsets[i],4,1,&v)==DEVICE_OK);
        CHECK(device_model_access_state(models+1,&power,offsets[i],4,0,&v)==DEVICE_OK);
        CHECK((v&0xff)==0xff);
    }
    CHECK(mask==models[0].config[4]);
    /* Encoder/ISP subdomain gating cannot change system-domain witnesses. */
    for (int i=9;i>=0;i--) {
        uint64_t v=0x3f0;
        CHECK(device_model_access_state(models+1,&power,0x8000+8*(unsigned)i,4,1,&v)==DEVICE_OK);
        CHECK(device_model_access_state(models+1,&power,0x8000+8*(unsigned)i,4,0,&v)==DEVICE_OK);
        CHECK((v&0xff)==0);
    }
    for (int i=12;i>=0;i--) {
        uint64_t v=0x3f0;
        CHECK(device_model_access_state(models+1,&power,0x4000+8*(unsigned)i,4,1,&v)==DEVICE_OK);
        CHECK(device_model_access_state(models+1,&power,0x4000+8*(unsigned)i,4,0,&v)==DEVICE_OK);
        CHECK((v&0xff)==0);
    }
    for (unsigned i=0;i<12;i++) {
        uint64_t v=0;
        CHECK(device_model_access_state(models+1,&power,offsets[i],4,0,&v)==DEVICE_OK);
        CHECK((v&0xff)==0xff);
    }
    /* Enumerate every possible initial vote set, then add the remaining
     * domains. Reads retain data; only metadata consumes each update. */
    for (unsigned subset=0;subset<4096;subset++) {
        uint64_t request=0;
        for (unsigned i=0;i<12;i++) if (subset&(1U<<i)) request|=1UL<<slots[i];
        CHECK(device_model_start(models,&state,0,24000000)==DEVICE_OK);
        pair(0x1880,0,0);pair(0x18c0,mask,0);
        write64(0x10c40,request);
        CHECK(read64(0x1880)==request && read64(0x18c0)==mask);
        pair(0x18c0,mask,2);pair(0x18c0,mask,0);
        pair(0x1880,request,2);pair(0x1880,request,0);
        write64(0x10c40,mask);
        pair(0x1880,mask,2);pair(0x18c0,mask,2);
        if (request!=mask) refused(0x10c40,8,1,request,DEVICE_BAD_VALUE);
        /* Independent MCC cache quota traffic must not consume the PMP
         * reply, and a PMP acknowledgment cannot overwrite an MCC reply. */
        write64(0x10c40,mask);
        write64(0x10000+(0x1a8+9)*8,0);
        write64(0x10000+(0x1a8+8)*8,0x1001);
        pair(0x1c00,1,2);pair(0x18c0,mask,2);
    }
    CHECK(device_model_start(models,&state,0,24000000)==DEVICE_OK);
    for (unsigned bit=0;bit<64;bit++) if (!(mask&(1UL<<bit)))
        refused(0x10c40,8,1,1UL<<bit,DEVICE_BAD_VALUE);
    write64(0x10c40,mask);
    for (unsigned bit=0;bit<64;bit++) if (mask&(1UL<<bit))
        refused(0x10c40,8,1,mask&~(1UL<<bit),DEVICE_BAD_VALUE);
    /* Exact LDP x8,x9,[x8] at the stopped _readPTD caller. */
    uint64_t regs[31]={0};regs[8]=models[0].base+0x1880;
    struct mmio_pair decoded;
    CHECK(mmio_ldp64_decode(0xa9402508,0x92000005,regs,0,&decoded));
    CHECK(decoded.address==regs[8] && decoded.reg[0]==8 && decoded.reg[1]==9);
    uint64_t values[2];
    CHECK(device_model_read_pair(models,&state,0x1880,values)==DEVICE_OK);
    mmio_ldp64_complete(&decoded,values,regs);
    CHECK(regs[8]==mask && regs[9]==2);
    for (unsigned off=0;off<0x4000;off+=16) {
        if (off==0x10 || off==0x1880 || off==0x18c0 ||
            (off>=0x1a80 && off<0x1b20) || (off>=0x1b80 && off<0x1c10)) continue;
        saved=state;values[0]=123;values[1]=456;
        CHECK(device_model_read_pair(models,&state,off,values)==DEVICE_UNKNOWN_REGISTER);
        CHECK(values[0]==123 && values[1]==456 && !memcmp(&state,&saved,sizeof(state)));
    }
    /* Readiness does not authorize other voters or packets. */
    pair(0x10,0,0); /* An individual model start never publishes readiness. */
    for (unsigned off=0x10c48;off<=0x10c78;off+=8)
        refused(off,8,1,mask,DEVICE_UNKNOWN_REGISTER);
    refused(0x10c40,8,0,0,DEVICE_UNKNOWN_REGISTER);
    for (unsigned off=0x1880;off<=0x18c8;off+=8) {
        if (off!=0x1880 && off!=0x1888 && off!=0x18c0 && off!=0x18c8) continue;
        refused(off,8,1,0,DEVICE_READ_ONLY);
        for (unsigned width=1;width<=16;width*=2) if (width!=8)
            refused(off,width,0,0,DEVICE_BAD_WIDTH);
        for (unsigned delta=1;delta<8;delta++) refused(off+delta,8,0,0,DEVICE_BAD_WIDTH);
    }
    saved=state;
    for (unsigned i=0;i<5;i++) {
        original=models[0];models[0].config[i]^=1;
        CHECK(!device_models_valid(models,3,0,0));
        CHECK(device_model_start(models,&state,0,24000000)==DEVICE_BAD_CONFIG);
        CHECK(!memcmp(&state,&saved,sizeof(state)));models[0]=original;
    }
    state.dram_policy=0x1234;
    CHECK(device_model_start(models,&state,0,24000000)==DEVICE_OK);
    CHECK(state.dram_policy==0x1234 && !state.pmp_active.request && state.pmp_active.ack==mask);
    CHECK(!state.pmp_active.request_updated && !state.pmp_active.ack_updated);
    CHECK(!state.ptd_ack && !state.ptd_request_updated && !state.ptd_reply_updated);
    printf("PMP active-domain transport: %u checks passed\n",checks);
}

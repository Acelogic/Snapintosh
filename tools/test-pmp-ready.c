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
    {DEVICE_PMGR_ACTIVE_BOOT_V1,0x308280000,0x9000,{1,0,0,0,0}},
    {DEVICE_AOP_TIMEBASE_V1,0x400000000,0x1000,{24000000,0,0,0,0}}
};
static struct device_state states[4],saved;
static void pair(uint64_t data,uint64_t metadata)
{
    uint64_t values[2]={123,456};
    CHECK(device_model_read_pair(models,states,0x10,values)==DEVICE_OK);
    CHECK(values[0]==data && values[1]==metadata);
}
static void refused(uint64_t off,unsigned width,int write,enum device_result result)
{
    saved=states[0];uint64_t value=123;
    CHECK(device_model_access_state(models,states,off,width,write,&value)==result);
    CHECK(value==123 && !memcmp(&saved,states,sizeof(saved)));
}
int main(void)
{
    CHECK(sizeof(struct device_state)==13000);
    CHECK(device_models_valid(models,4,0,0));
    CHECK(device_model_start(models,states,0,24000000)==DEVICE_OK);
    pair(0,0);pair(0,0);
    CHECK(device_models_start(models,states,2,0,24000000)==DEVICE_BAD_CONFIG);
    pair(0,0);
    CHECK(device_models_start(models,states,4,0,19000000)==DEVICE_BAD_CONFIG);
    pair(0,0); /* A later failing backend must not publish readiness. */
    CHECK(device_models_start(models,states,4,0,24000000)==DEVICE_OK);
    CHECK(states[1].pmgr_gfx==15 && states[1].pmgr_avd==15);
    CHECK(states[0].pmp_active.ack==DEVICE_PMP_ACTIVE_MASK);
    CHECK(!states[0].pmp_active.status_reads);
    uint64_t value=0;
    CHECK(device_model_access_state(models,states,0x10,8,0,&value)==DEVICE_OK && value==1);
    CHECK(states[0].pmp_active.ready_updated==1); /* Data reads retain update. */
    pair(1,2);pair(1,0);
    CHECK(states[0].pmp_active.status_reads==2);
    CHECK(!states[0].pmp_active.request_updated && !states[0].pmp_active.ack_updated);
    for (unsigned off=0x10;off<=0x18;off+=8) {
        refused(off,8,1,DEVICE_READ_ONLY);
        for (unsigned width=1;width<=16;width*=2)
            if (width!=8) refused(off,width,0,DEVICE_BAD_WIDTH);
        for (unsigned delta=1;delta<8;delta++) refused(off+delta,8,0,DEVICE_BAD_WIDTH);
    }
    refused(0x10008,8,1,DEVICE_UNKNOWN_REGISTER); /* No guest status producer. */
    refused(0x80,8,0,DEVICE_UNKNOWN_REGISTER); /* DVFS is still unimplemented. */
    refused(0x10c48,8,1,DEVICE_UNKNOWN_REGISTER); /* Other voter is unknown. */
    states[0].pmp_active.status_reads=UINT32_MAX;pair(1,0);
    CHECK(states[0].pmp_active.status_reads==UINT32_MAX);
    /* Registry ordering does not affect the publication dependency. */
    for (unsigned slot=0;slot<4;slot++) {
        struct device_model reordered[4];memcpy(reordered,models,sizeof(models));
        reordered[0]=models[slot];reordered[slot]=models[0];
        CHECK(device_models_start(reordered,states,4,0,24000000)==DEVICE_OK);
        CHECK(states[slot].pmp_active.ready==1 && states[slot].pmp_active.ready_updated==1);
        CHECK(device_models_start(reordered,states,4,0,19000000)==DEVICE_BAD_CONFIG);
        CHECK(!states[slot].pmp_active.ready && !states[slot].pmp_active.ready_updated);
    }
    CHECK(device_models_start(models,states,4,0,24000000)==DEVICE_OK);
    /* Exact native fault instruction, including base/destination alias. */
    uint64_t regs[31]={0},values[2];regs[8]=models[0].base+0x10;
    struct mmio_pair decoded;
    CHECK(mmio_ldp64_decode(0xa9402508,0x92000005,regs,0,&decoded));
    CHECK(decoded.address==regs[8]);
    CHECK(device_model_read_pair(models,states,0x10,values)==DEVICE_OK);
    mmio_ldp64_complete(&decoded,values,regs);
    CHECK(regs[8]==1 && regs[9]==2);
    CHECK(device_model_start(models,states,0,24000000)==DEVICE_OK);
    CHECK(!states[0].pmp_active.ready && !states[0].pmp_active.status_reads);
    pair(0,0);
    printf("PMP service readiness: %u checks passed\n",checks);
}

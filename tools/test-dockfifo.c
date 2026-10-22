/* SPDX-License-Identifier: MIT */
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "device.h"

static unsigned checks;
#define CHECK(x) do { assert(x); checks++; } while (0)
static struct device_model model={DEVICE_DOCK_FIFO_V1,0x314b00000UL,0x35000,
                                  {0x14000,0x28000,1137,2048,0}};
static struct device_state state, saved;

static uint64_t access_at(struct device_model *d, struct device_state *s,
                          uint64_t off, int write, uint64_t value)
{
    CHECK(device_model_access_state(d,s,off,4,write,&value)==DEVICE_OK);
    return value;
}
static uint64_t rd(uint64_t off) { return access_at(&model,&state,off,0,0); }
static void wr(uint64_t off, uint64_t v) { access_at(&model,&state,off,1,v); }
static void reset(void) { CHECK(device_model_start(&model,&state,0,0)==DEVICE_OK); }
static void reject(uint64_t off, unsigned width, int write, uint64_t v,
                   enum device_result result)
{
    saved=state; uint64_t original=v;
    CHECK(device_model_access_state(&model,&state,off,width,write,&v)==result);
    CHECK(v==original && !memcmp(&state,&saved,sizeof(state)));
}

int main(void)
{
    CHECK(device_models_valid(&model,1,0,0));
    reset(); CHECK(rd(4)==0); CHECK(rd(0x14004)==0);
    /* Both directions, every supported transaction width; peer reads are
     * the only consumption. Repeat past the ring boundary several times. */
    for (unsigned side=0; side<2; side++) {
        uint64_t tx=0x2c000+0x8000*side, rx=0x2c000+0x8000*(side^1);
        for (unsigned round=0; round<600; round++) for (unsigned n=1; n<=4; n++) {
            uint32_t data=0xdac0b000+round;
            wr(tx+n*4,data);
            CHECK(rd(tx+0x14)==2048-n && rd(rx+0x2c)==n);
            uint64_t want=n==4 ? data : (((uint64_t)data & ((1UL<<(8*n))-1))<<8)|n;
            CHECK(rd(rx+0x18+n*4)==want);
            CHECK(rd(tx+0x14)==2048 && rd(rx+0x2c)==0);
        }
    }
    reset();
    for (unsigned i=0; i<512; i++) wr(0x34010,0x12340000+i);
    CHECK(rd(0x34014)==0 && rd(0x2c02c)==2048);
    reject(0x34004,4,1,0x77,DEVICE_BAD_VALUE);
    for (unsigned i=0; i<512; i++) CHECK(rd(0x2c028)==0x12340000+i);
    CHECK(rd(0x2c01c)==0 && rd(0x2c020)==0 && rd(0x2c024)==0);
    reject(0x2c028,4,0,0xdeadbeef,DEVICE_BAD_VALUE);
    wr(0x34008,0xabcd); reject(0x2c028,4,0,7,DEVICE_BAD_VALUE);
    CHECK(rd(0x2c024)==0xabcd02); /* partial RX24 carries exact byte count */
    for (unsigned i=0; i<0x35000; i+=4) {
        int known=i==4 || i==0x14000 || i==0x14004;
        for (unsigned side=0; side<2; side++) {
            unsigned off=i-(0x28000+side*0x8000);
            known |= off==0 || off==4 || off==0x4014 || off==0x402c ||
                     (off>=0x4004 && off<=0x4010) || (off>=0x401c && off<=0x4028);
        }
        if (!known) reject(i,4,0,0x11223344,DEVICE_UNKNOWN_REGISTER);
    }
    reject(4,4,1,1,DEVICE_READ_ONLY);
    reject(0x35000,4,0,1,DEVICE_NOT_FOUND);
    reject(0x14000,4,1,16,DEVICE_BAD_VALUE);
    reject(0x14004,4,1,1UL<<32,DEVICE_BAD_VALUE);
    reject(0x30004,4,1,2049,DEVICE_BAD_VALUE);
    reject(0x34010,4,1,1UL<<32,DEVICE_BAD_VALUE);
    reject(0x34014,4,1,0,DEVICE_READ_ONLY);
    reject(0x34010,4,0,0,DEVICE_UNKNOWN_REGISTER);
    for (unsigned width=1; width<=8; width*=2) if (width!=4)
        reject(4,width,0,99,DEVICE_BAD_WIDTH);
    reject(5,4,0,99,DEVICE_BAD_WIDTH);
    /* Zero threshold is a real active level. W1C reasserts while true; after
     * service it clears. Masks gate both the status and the AIC source. */
    reset(); wr(0x30004,4); wr(0x14000,8);
    CHECK(rd(0x14004)==0);
    wr(0x2c010,0x76543210); CHECK(rd(0x14004)==8);
    wr(0x14004,8); CHECK(rd(0x14004)==8);
    CHECK(rd(0x34028)==0x76543210); wr(0x14004,8); CHECK(rd(0x14004)==0);
    wr(0x30004,0); CHECK(rd(0x14004)==8);
    wr(0x14000,0); CHECK(rd(0x14004)==0);
    /* Heterogeneous sources sharing an AIC line are ORed, never clobbered. */
    struct device_model models[3]={
        {DEVICE_AIC3_FLAT_V1,0x301000000UL,0x1cc000,{1280,4096,0x40000,10,0}},
        model,{DEVICE_SPMI_GEN3_EMPTY_V1,0x308600000UL,0x18000,{0x14000,0x4000,1137,256,256}}};
    static struct device_state states[3], before[3];
    CHECK(device_models_valid(models,3,0,0));
    access_at(&models[0],&states[0],0x14,1,1);
    access_at(&models[0],&states[0],0x14600+(1137/32)*4,1,1U<<(1137%32));
    access_at(&models[1],&states[1],0x14000,1,8);
    CHECK(device_models_route_irqs(models,states,3)==DEVICE_OK);
    CHECK(device_irq_pending(&models[0],&states[0]));
    states[2].spmi.flags[0]=states[2].spmi.enable[0]=1;
    access_at(&models[1],&states[1],0x14000,1,0);
    CHECK(device_models_route_irqs(models,states,3)==DEVICE_OK);
    CHECK(device_irq_pending(&models[0],&states[0]));
    states[2].spmi.flags[0]=0;
    CHECK(device_models_route_irqs(models,states,3)==DEVICE_OK);
    CHECK(!device_irq_pending(&models[0],&states[0]));
    memcpy(before,states,sizeof(states)); models[1].config[2]=1280;
    CHECK(device_models_route_irqs(models,states,3)==DEVICE_BAD_CONFIG);
    CHECK(!memcmp(before,states,sizeof(states)));
    CHECK(device_models_route_irqs(&model,&state,1)==DEVICE_BAD_CONFIG);
    const uint64_t bad[][2]={{0,0},{1,0},{2,4096},{3,2047},{4,1}};
    for (unsigned i=0; i<sizeof(bad)/sizeof(bad[0]); i++) {
        uint64_t old=model.config[bad[i][0]];
        model.config[bad[i][0]]=bad[i][1];
        reject(4,4,0,77,DEVICE_BAD_CONFIG); model.config[bad[i][0]]=old;
    }
    model.span+=0x1000; reject(4,4,0,77,DEVICE_BAD_CONFIG); model.span-=0x1000;
    reset(); CHECK(rd(0x34014)==2048 && rd(0x3402c)==0 && rd(0x14000)==0);
    printf("PASS: %u DockChannel FIFO, backpressure and interrupt checks\n",checks);
}

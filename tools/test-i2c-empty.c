/* SPDX-License-Identifier: MIT */
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "device.h"
static unsigned checks;
#define CHECK(x) do { checks++; if (!(x)) { fprintf(stderr,"FAIL %d: %s\n",__LINE__,#x); exit(1); } } while (0)
static struct device_model models[3]={
    {DEVICE_I2C_EMPTY_V1,0x385018000UL,0x4000,{2,6,1110,0,0}},
    {DEVICE_PMGR_ACTIVE_BOOT_V1,0x300700000UL,0x11000,{0}},
    {DEVICE_AIC3_FLAT_V1,0x301000000UL,0x1cc000,{1280,4096,0x40000,10,0}},
};
static struct device_state states[3],saved;
static uint64_t access(unsigned index,unsigned off,int write,uint64_t value)
{
    CHECK(device_model_access_state(&models[index],&states[index],off,4,write,&value)==DEVICE_OK);
    return value;
}
static void wr(unsigned off,uint64_t value) { (void)access(0,off,1,value); }
static uint64_t rd(unsigned off) { return access(0,off,0,0xfeed); }
static void refused(unsigned off,unsigned width,int write,uint64_t value,enum device_result code)
{
    uint64_t v=value;saved=states[0];
    CHECK(device_model_access_state(&models[0],&states[0],off,width,write,&v)==code);
    CHECK(v==value && !memcmp(&saved,&states[0],sizeof(saved)));
}
static void route(void) { CHECK(device_models_route_irqs(models,states,3)==DEVICE_OK); }
int main(void)
{
    CHECK(sizeof(states[0])==13000 && offsetof(struct device_state,i2c)==0);
    CHECK(sizeof(struct device_i2c_empty)==128);
    CHECK(device_models_valid(models,3,0,0));
    refused(0x1c,4,1,4,DEVICE_BAD_CONFIG);
    for (unsigned i=0;i<3;i++) CHECK(device_model_start(&models[i],&states[i],0,24000000)==DEVICE_OK);
    refused(0,4,1,0x150,DEVICE_BAD_VALUE); /* disabled */
    wr(0x1c,4);CHECK(rd(0x14)==0x10100);
    wr(0x14,0x2aa00040);wr(0x18,0);wr(0x10,0x80000000);
    CHECK(rd(0x14)==0x10118 && rd(0x28)==6);
    wr(0x38,0x476673a9);wr(0x30,0x46340000);wr(0x2c,0x46330000);
    CHECK(rd(0x38)==0x476673a9 && rd(0x30)==0x46340000 && rd(0x2c)==0x46330000);
    wr(0x1c,rd(0x1c)|0x800);
    CHECK(rd(4)==0x100 && rd(8)==0 && rd(0xc)==0);
    refused(0,4,1,0x150,DEVICE_BAD_VALUE); /* pre-transfer contract not programmed */
    refused(0x40,4,0,0xfeed,DEVICE_BAD_VALUE); /* no synthetic diagnostic history */
    for (unsigned bit=0;bit<32;bit++) if (bit!=20)
        refused(0x40,4,1,1U<<bit,DEVICE_BAD_VALUE);
    wr(0x40,0x100000);
    CHECK(states[0].i2c.shadow_command==0x100000 && states[0].i2c.shadow_writes==1);
    /* Every 7-bit address and both directions are absent: no invented data. */
    for (unsigned a=0;a<256;a++) {
        wr(0x1c,0xe04);wr(0x14,UINT32_MAX);wr(0,0x100|a);
        CHECK(states[0].i2c.last_address==a && states[0].i2c.nacks==a+1);
        CHECK((rd(0x14)&0x08200000)==0x08200000);
        CHECK(rd(4)==0x100 && rd(8)==0 && rd(0xc)==0);
        CHECK(states[0].i2c.blocked==1 && rd(0x1c)==0x804);
        refused(0x40,4,1,0x100000,DEVICE_BAD_VALUE); /* never discard in-flight error state */
    }
    /* Following bytes really occupy the TX FIFO until reset after NACK. */
    for (unsigned i=0;i<16;i++) { wr(0,i|(i==15 ? 0x200 : 0));CHECK(rd(8)==i+1); }
    CHECK((rd(0x14)&0x30000)==0x20000);
    refused(0,4,1,0,DEVICE_BAD_VALUE);
    wr(0x14,UINT32_MAX);CHECK((rd(0x14)&0x30000)==0x20000);
    wr(0x1c,0xe04);CHECK(rd(8)==0 && !states[0].i2c.blocked && rd(0x1c)==0x804);
    for (unsigned i=0;i<16;i++) CHECK(states[0].i2c.tx[i]==0);
    CHECK((rd(0x14)&0x30000)==0x10000);
    /* Local masks and AIC ownership govern a real level, including W1C. */
    access(2,0x14,1,1);access(2,0x14600+(1110/32)*4,1,1U<<(1110%32));
    wr(0,0x150);route();CHECK(!device_irq_pending(&models[2],&states[2]));
    wr(0x18,0x08200000);route();CHECK(device_irq_pending(&models[2],&states[2]));
    wr(0x14,1U<<21);route();CHECK(device_irq_pending(&models[2],&states[2]));
    wr(0x14,1U<<27);route();CHECK(!device_irq_pending(&models[2],&states[2]));
    wr(0x1c,0xe04);wr(0,0x151);route();CHECK(device_irq_pending(&models[2],&states[2]));
    CHECK(access(2,0x40000,0,0)==0x10456);
    CHECK(!device_irq_pending(&models[2],&states[2]));
    wr(0x18,0);route();access(2,0x14600+(1110/32)*4,1,1U<<(1110%32));
    CHECK(!device_irq_pending(&models[2],&states[2]));
    wr(0x18,1U<<21);route();CHECK(device_irq_pending(&models[2],&states[2]));
    wr(0x14,UINT32_MAX);route();CHECK(!device_irq_pending(&models[2],&states[2]));
    /* Native combined transfer: halt, address+data+restart+read, resume.
     * Nothing executes while halted, and only the absent address is consumed.
     * The actual NACK drives the same masked level and AIC path as above. */
    wr(0x1c,0xe04);wr(0x44,1);CHECK(rd(0x44)==1);
    unsigned nacks=states[0].i2c.nacks;
    const unsigned command[]={0x150,0x23,0x151,0x601};
    for (unsigned i=0;i<4;i++) {
        wr(0,command[i]);CHECK(rd(8)==i+1 && states[0].i2c.tx[i]==command[i]);
        CHECK(!(rd(0x14)&0x08200000) && rd(4)==0x100);
        route();CHECK(!device_irq_pending(&models[2],&states[2]));
    }
    CHECK(states[0].i2c.nacks==nacks && !states[0].i2c.blocked);
    for (unsigned bit=1;bit<32;bit++) refused(0x44,4,1,1U<<bit,DEVICE_BAD_VALUE);
    wr(0x44,0);route();CHECK(rd(0x44)==0 && device_irq_pending(&models[2],&states[2]));
    CHECK(states[0].i2c.nacks==nacks+1 && states[0].i2c.last_address==0x50);
    CHECK(rd(8)==3 && states[0].i2c.blocked && rd(4)==0x100);
    for (unsigned i=0;i<3;i++) CHECK(states[0].i2c.tx[i]==command[i+1]);
    CHECK(states[0].i2c.tx[3]==0);
    wr(0x44,1);wr(0x44,0);CHECK(states[0].i2c.nacks==nacks+1 && rd(8)==3);
    wr(0x14,UINT32_MAX);route();CHECK(!device_irq_pending(&models[2],&states[2]));
    /* Reset flushes a halted queue but retains HALT. Disabling then resuming
     * also cannot execute a pending address until the controller is enabled. */
    wr(0x44,1);wr(0x1c,0xe04);CHECK(rd(0x44)==1 && rd(8)==0);
    wr(0,0x152);wr(0x1c,0xe04);wr(0x44,0);
    CHECK(states[0].i2c.nacks==nacks+1 && !states[0].i2c.blocked);
    wr(0x44,1);wr(0,0x153);wr(0x1c,4);wr(0x44,0);
    CHECK(states[0].i2c.nacks==nacks+1 && rd(8)==1);
    wr(0x1c,0x804);CHECK(states[0].i2c.nacks==nacks+2 && rd(8)==0);
    wr(0x1c,0xe04);wr(0x14,UINT32_MAX);wr(0x18,0);
    for (unsigned off=0;off<0x4000;off+=4) {
        if (off<=0x1c || off==0x28 || off==0x2c || off==0x30 || off==0x38 || off==0x40 || off==0x44) continue;
        refused(off,4,0,0xfeed,DEVICE_UNKNOWN_REGISTER);
        refused(off,4,1,0,DEVICE_UNKNOWN_REGISTER);
    }
    for (unsigned off=4;off<=0x28;off+=4)
        if (off<=0xc || off==0x28) refused(off,4,1,0,DEVICE_READ_ONLY);
    for (unsigned width=1;width<=8;width*=2) if(width!=4) refused(0x1c,width,1,4,DEVICE_BAD_WIDTH);
    refused(0x1d,4,1,4,DEVICE_BAD_WIDTH);refused(0x4000,4,0,0,DEVICE_NOT_FOUND);
    refused(0x1c,4,1,1UL<<32,DEVICE_BAD_VALUE);
    refused(0x1c,4,1,1U<<12,DEVICE_BAD_VALUE);
    refused(0x10,4,1,1U<<29,DEVICE_BAD_VALUE); /* no slave mode */
    refused(0x10,4,1,1U<<30,DEVICE_BAD_VALUE); /* no bitbang */
    wr(0x1c,0xe04);refused(0,4,1,0x450,DEVICE_BAD_VALUE);
    refused(0,4,1,0x50,DEVICE_BAD_VALUE);refused(0,4,0,0,DEVICE_BAD_VALUE);
    uint64_t v=4;saved=states[0];states[1].pmgr_i2c[2]=0;
    CHECK(device_models_access_at(models,states,3,0,0,0x1c,4,1,&v)==DEVICE_BAD_VALUE);
    CHECK(!memcmp(&saved,&states[0],sizeof(saved)));
    states[1].pmgr_i2c[2]=15;
    CHECK(device_models_access_at(models,states,3,0,0,0x1c,4,1,&v)==DEVICE_OK);
    CHECK(device_models_access_at(models,states,1,0,0,0x1c,4,1,&v)==DEVICE_BAD_CONFIG);
    for (unsigned i=0;i<5;i++) {
        models[0].config[i]++;saved=states[0];
        CHECK(!device_models_valid(models,3,0,0));
        CHECK(device_model_start(&models[0],&states[0],0,24000000)==DEVICE_BAD_CONFIG);
        CHECK(!memcmp(&saved,&states[0],sizeof(saved)));models[0].config[i]--;
    }
    states[0].i2c.tx_count=17;refused(0x14,4,0,0,DEVICE_BAD_CONFIG);
    CHECK(device_models_route_irqs(models,states,3)==DEVICE_BAD_CONFIG);
    CHECK(device_model_start(&models[0],&states[0],0,24000000)==DEVICE_OK);
    CHECK(states[0].i2c.nacks==0 && states[0].i2c.resets==0 && !states[0].i2c.blocked);
    printf("PASS: %u I2C empty-bus, FIFO, IRQ, power and refusal checks\n",checks);
}

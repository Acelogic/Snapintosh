/* SPDX-License-Identifier: MIT */
#include "device.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static unsigned checks;
#define CHECK(x) do {checks++;if (!(x)) {fprintf(stderr,"FAIL %d: %s\n",__LINE__,#x);exit(1);}} while(0)
static const struct device_model models[]={
    {DEVICE_AES_SOFTWARE_V1,0x38500c000UL,0x4000,{5,42,1107,21,1}},
    {DEVICE_AIC3_FLAT_V1,0x301000000UL,0x1cc000,{1280,4096,0x40000,10,0}},
};
static struct device_state states[2];
static void wr(unsigned off,uint64_t v)
{CHECK(aes_engine_access(&states[0].aes,0,off,4,1,&v)==AES_OK);CHECK(device_models_route_irqs(models,states,2)==DEVICE_OK);}
static uint64_t aic(unsigned off,int w,uint64_t v)
{CHECK(device_model_access_state(&models[1],&states[1],off,4,w,&v)==DEVICE_OK);return v;}
int main(void)
{
    CHECK(sizeof(struct device_state)==13000 && sizeof(struct aes_engine)<=13000);
    CHECK(device_models_valid(models,2,0,0));
    for (unsigned i=0;i<2;i++) CHECK(device_model_start(&models[i],&states[i],0,24000000)==DEVICE_OK);
    aic(0x14,1,1);aic(0x14600+(1107/32)*4,1,1U<<(1107%32));
    wr(8,1);wr(0x1c,0x20);CHECK(!device_irq_pending(&models[1],&states[1]));
    /* No completion for the incomplete software key. */
    wr(0x200,0x10910000);for (unsigned i=0;i<8;i++) wr(0x200,i);
    CHECK(!device_irq_pending(&models[1],&states[1]));
    wr(0x200,0x88000001);CHECK(device_irq_pending(&models[1],&states[1]));
    CHECK(aic(0x40000,0,0)==0x10453);CHECK(!device_irq_pending(&models[1],&states[1]));
    wr(0x18,0x20);aic(0x14600+(1107/32)*4,1,1U<<(1107%32));
    CHECK(!device_irq_pending(&models[1],&states[1]));
    wr(0x1c,0);wr(0x200,0x88000000);CHECK(!device_irq_pending(&models[1],&states[1]));
    wr(0x1c,0x20);CHECK(device_irq_pending(&models[1],&states[1]));
    wr(0x18,0x20);CHECK(!device_irq_pending(&models[1],&states[1]));
    states[0].aes.irq_status=1;CHECK(device_models_route_irqs(models,states,2)==DEVICE_BAD_CONFIG);
    CHECK(device_model_start(&models[0],&states[0],0,24000000)==DEVICE_OK);
    struct aes_engine empty={.ready=1};CHECK(!memcmp(&states[0].aes,&empty,sizeof(empty)));
    printf("AES AIC integration: %u checks passed (mask, completion, acknowledge, reset)\n",checks);
}

/* SPDX-License-Identifier: MIT */
/* PTD v1 policy: selector packing and W1S/W1C. No readiness producer. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "device.h"
static unsigned checks;
#define CHECK(x) do { checks++; if (!(x)) { \
    fprintf(stderr,"line %u: %s\n",__LINE__,#x); exit(1); } } while (0)
static struct device_state state,saved,other;
static struct device_model model={DEVICE_PTD_IRQ_CONFIG_V1,
    0x3003d8000,0x1000,{0,0,0,0,0}};
static enum device_result access_word(unsigned offset,unsigned width,int write,uint64_t *v)
{
    return device_model_access_state(&model,&state,offset,width,write,v);
}
static void refused(unsigned offset,unsigned width,int write,uint64_t v,
                    enum device_result expected)
{
    uint64_t original=v;saved=state;
    CHECK(access_word(offset,width,write,&v)==expected);
    CHECK(v==original && !memcmp(&state,&saved,sizeof(state)));
}
int main(void)
{
    CHECK(device_models_valid(&model,1,0,0));
    CHECK(device_model_start(&model,&state,0,24000000)==DEVICE_OK);
    /* Exercise every entry using the stock driver's formula rather than
     * the model's inverse offset mapping. Different destinations and live
     * neighbours catch half-window, lane and entry-number aliasing. */
    for (unsigned pass=0;pass<2;pass++) for (unsigned entry=0;entry<1024;entry++) {
        unsigned q=entry/4,offset=0x400+((q&1)<<9)+(entry/8)*4;
        unsigned shift=8*(entry%4),irq=(entry+pass*17)%32;
        uint64_t v=~0UL;
        CHECK(access_word(offset,4,0,&v)==DEVICE_OK);
        CHECK(v==state.ptd_irq.route[q]);
        uint64_t next=(v&~(31UL<<shift))|((uint64_t)irq<<shift);
        saved=state;saved.ptd_irq.route[q]=(uint32_t)next;
        CHECK(access_word(offset,4,1,&next)==DEVICE_OK);
        CHECK(!memcmp(&state,&saved,sizeof(state)));
        CHECK(access_word(offset,4,0,&v)==DEVICE_OK && v==next);
        unsigned bank=entry/32;v=1UL<<(entry%32);
        saved=state;saved.ptd_irq.enabled[bank]|=(uint32_t)v;
        CHECK(access_word(0x200+bank*4,4,1,&v)==DEVICE_OK);
        CHECK(!memcmp(&state,&saved,sizeof(state)));
        CHECK(access_word(0x200+bank*4,4,1,&v)==DEVICE_OK);
        CHECK(!memcmp(&state,&saved,sizeof(state))); /* W1S is idempotent */
    }
    for (unsigned entry=0;entry<1024;entry++) {
        unsigned bank=entry/32;uint64_t v=1UL<<(entry%32);
        saved=state;saved.ptd_irq.enabled[bank]&=~(uint32_t)v;
        CHECK(access_word(0x300+bank*4,4,1,&v)==DEVICE_OK);
        CHECK(!memcmp(&state,&saved,sizeof(state)));
        CHECK(access_word(0x300+bank*4,4,1,&v)==DEVICE_OK);
        CHECK(!memcmp(&state,&saved,sizeof(state)));
    }
    for (unsigned off=0;off<0x1000;off+=4) {
        int route=off>=0x400 && off<0x800;
        int gate=(off>=0x200 && off<0x280)||(off>=0x300 && off<0x380);
        if (!route) refused(off,4,0,0xdeadbeef,DEVICE_UNKNOWN_REGISTER);
        if (!route && !gate) refused(off,4,1,0xdeadbeef,DEVICE_UNKNOWN_REGISTER);
        else {
            for (unsigned bit=0;bit<64;bit++) {
                uint64_t v=1UL<<bit;
                if (v&~(route ? 0x1f1f1f1fUL : 0xffffffffUL))
                    refused(off,4,1,v,DEVICE_BAD_VALUE);
            }
            for (unsigned width=1;width<=8;width*=2) if (width!=4)
                for (int write=0;write<=1;write++)
                    refused(off,width,write,0,DEVICE_BAD_WIDTH);
            for (unsigned delta=1;delta<=3;delta++)
                refused(off+delta,4,1,0,DEVICE_BAD_WIDTH);
        }
    }
    /* Match the live stopped caller: slot 1 -> IRQ 11, then enable bit 1. */
    CHECK(device_model_start(&model,&state,0,24000000)==DEVICE_OK);
    uint64_t v=0xb00;
    CHECK(access_word(0x400,4,1,&v)==DEVICE_OK);
    v=2;CHECK(access_word(0x200,4,1,&v)==DEVICE_OK);
    CHECK(state.ptd_irq.route[0]==0xb00 && state.ptd_irq.enabled[0]==2);
    CHECK(device_model_start(&model,&other,0,24000000)==DEVICE_OK);
    CHECK(other.ptd_irq.route[0]==0 && other.ptd_irq.enabled[0]==0);
    refused(0,4,0,0xdead,DEVICE_UNKNOWN_REGISTER); /* pending != configuration */
    refused(0x100,4,0,0xdead,DEVICE_UNKNOWN_REGISTER);
    refused(0x1000,4,1,0,DEVICE_NOT_FOUND);
    state.dram_policy=0xfeed;saved=state;
    memset(&saved.ptd_irq,0,sizeof(saved.ptd_irq));
    CHECK(device_model_start(&model,&state,0,24000000)==DEVICE_OK);
    CHECK(!memcmp(&state,&saved,sizeof(state)));
    CHECK(device_model_access_state(&model,0,0x400,4,0,&v)==DEVICE_BAD_CONFIG);
    CHECK(device_model_access_state(&model,&state,0x400,4,0,0)==DEVICE_BAD_CONFIG);
    for (unsigned i=0;i<5;i++) {
        struct device_model bad=model;bad.config[i]=1;
        CHECK(!device_models_valid(&bad,1,0,0));
        CHECK(device_model_start(&bad,&state,0,24000000)==DEVICE_BAD_CONFIG);
        CHECK(device_model_access_state(&bad,&state,0x400,4,1,&v)==DEVICE_BAD_CONFIG);
        CHECK(!memcmp(&state,&saved,sizeof(state)));
    }
    model.span=0x2000;CHECK(!device_models_valid(&model,1,0,0));
    printf("PTD IRQ configuration: %u checks passed\n",checks);
    return 0;
}

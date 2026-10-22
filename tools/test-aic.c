/* SPDX-License-Identifier: MIT */
#include "aic.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define CHECK(x) do { checks++; if (!(x)) { fprintf(stderr,"FAIL %d: %s\n",__LINE__,#x); exit(1); } } while(0)
static unsigned checks;
static struct aic_config config={4096,0xa,0x40000};
static struct aic_state state;
static uint64_t read32(uint64_t reg)
{
    uint64_t v=UINT64_MAX;
    CHECK(aic_access(&config,&state,reg,4,0,&v)==AIC_OK);
    return v;
}
static void write32(uint64_t reg,uint64_t v)
{ CHECK(aic_access(&config,&state,reg,4,1,&v)==AIC_OK); }

int main(void)
{
    CHECK(aic_config_valid(&config));
    CHECK(!aic_pending(&config,&state));
    CHECK(read32(0)==10 && read32(4)==4096 && read32(12)==0x01001000);
    CHECK(read32(0x14)==0 && read32(config.event)==0);
    for(unsigned irq=0;irq<4096;irq++) {
        memset(&state,0,sizeof(state));
        uint64_t word=(irq/32)*4, bit=UINT64_C(1)<<(irq&31);
        CHECK(read32(0x10000+irq*4)==0);
        write32(0x10000+irq*4,0);
        CHECK(read32(0x14400+word)==UINT32_MAX);
        CHECK(aic_set_level(&config,&state,irq,1)==AIC_OK);
        CHECK(read32(0x14800+word)==bit);
        write32(0x14600+word,bit);
        CHECK(!aic_pending(&config,&state)); /* global gate still closed */
        CHECK(read32(config.event)==0 && state.events==0);
        write32(0x14,1);
        CHECK(aic_pending(&config,&state));
        CHECK(read32(config.event)==(0x10000|irq));
        CHECK(state.events==1 && !aic_pending(&config,&state));
        CHECK(read32(0x14400+word)==UINT32_MAX); /* destructive auto-mask */
        CHECK(read32(0x14800+word)==bit); /* source still asserted */
        CHECK(read32(config.event)==0);
        write32(0x14600+word,bit); /* Darwin's completion/unmask */
        CHECK(aic_pending(&config,&state)); /* level re-delivery */
        CHECK(aic_set_level(&config,&state,irq,0)==AIC_OK);
        CHECK(!aic_pending(&config,&state));
        write32(0x14000+word,bit);
        CHECK(read32(0x14200+word)==bit && aic_pending(&config,&state));
        write32(0x14,0);
        CHECK(!aic_pending(&config,&state));
        CHECK(read32(config.event)==0 && read32(0x14000+word)==bit);
        write32(0x14,1);
        CHECK(read32(config.event)==(0x10000|irq));
        CHECK(read32(0x14000+word)==0); /* consumes software request */
        write32(0x14600+word,bit);
        CHECK(!aic_pending(&config,&state));
        write32(0x14000+word,bit);
        write32(0x14200+word,bit);
        CHECK(!aic_pending(&config,&state));
        write32(0x14400+word,bit);
        CHECK(read32(0x14600+word)==UINT32_MAX);
    }
    memset(&state,0,sizeof(state));
    /* Independent pending sources survive another source's acknowledgement. */
    write32(0x14000,0x80000001); write32(0x14004,1);
    write32(0x14600,0x80000001); write32(0x14604,1); write32(0x14,1);
    CHECK(read32(config.event)==0x10000 && aic_pending(&config,&state));
    CHECK(read32(config.event)==0x1001f && aic_pending(&config,&state));
    CHECK(read32(config.event)==0x10020 && !aic_pending(&config,&state));
    CHECK(read32(config.event)==0 && state.events==3);
    /* Every refusal is atomic: state and the caller's operand stay intact. */
    const uint64_t readonly[]={0,4,12,0x40000,0x14800,0x149fc};
    for(unsigned i=0;i<sizeof(readonly)/sizeof(*readonly);i++) {
        struct aic_state before=state;uint64_t v=123;
        CHECK(aic_access(&config,&state,readonly[i],4,1,&v)==AIC_READ_ONLY);
        CHECK(v==123 && !memcmp(&before,&state,sizeof(state)));
    }
    for(unsigned bit=0;bit<64;bit++) {
        struct aic_state before=state;uint64_t v=UINT64_C(1)<<bit;
        CHECK(aic_access(&config,&state,0x10000,4,1,&v)==AIC_BAD_VALUE);
        if(bit) CHECK(aic_access(&config,&state,0x14,4,1,&v)==AIC_BAD_VALUE);
        CHECK(v==(UINT64_C(1)<<bit) && !memcmp(&before,&state,sizeof(state)));
    }
    for(unsigned size=0;size<17;size++) if(size!=4) {
        uint64_t v=1;struct aic_state before=state;
        CHECK(aic_access(&config,&state,0x14,size,1,&v)==AIC_BAD_WIDTH);
        CHECK(v==1 && !memcmp(&before,&state,sizeof(state)));
    }
    const uint64_t unknown[]={8,0x10,0x18,0x1000,0x14a00,0x30000,0x40004};
    for(unsigned i=0;i<sizeof(unknown)/sizeof(*unknown);i++) for(unsigned w=0;w<2;w++) {
        uint64_t v=123;struct aic_state before=state;
        CHECK(aic_access(&config,&state,unknown[i],4,w,&v)==AIC_UNKNOWN_REGISTER);
        CHECK(v==123 && !memcmp(&before,&state,sizeof(state)));
    }
    config.irqs=1280;memset(&state,0,sizeof(state));
    /* Capacity determines register positions; inactive slots never produce IRQs. */
    for(unsigned word=40;word<128;word++) {
        write32(0x14000+word*4,UINT32_MAX);write32(0x14600+word*4,UINT32_MAX);
        CHECK(read32(0x14200+word*4)==0 && read32(0x14800+word*4)==0);
        CHECK(read32(0x14400+word*4)==UINT32_MAX);
    }
    write32(0x14,1);CHECK(!aic_pending(&config,&state));
    struct aic_state before=state;uint64_t v=0;
    CHECK(aic_set_level(&config,&state,1280,1)==AIC_BAD_VALUE);
    CHECK(aic_set_level(&config,&state,4095,0)==AIC_BAD_VALUE);
    CHECK(aic_set_level(&config,&state,1,2)==AIC_BAD_VALUE);
    CHECK(aic_access(&config,&state,0x10000+1280*4,4,0,&v)==AIC_UNKNOWN_REGISTER);
    CHECK(aic_access(&config,&state,0x14000,4,1,&(uint64_t){1UL<<32})==AIC_BAD_VALUE);
    CHECK(aic_access(&config,&state,0x14601,4,1,&v)==AIC_BAD_WIDTH);
    CHECK(!memcmp(&before,&state,sizeof(state)));
    CHECK(aic_access(&config,0,config.event,4,0,&v)==AIC_BAD_CONFIG);
    CHECK(aic_access(&config,&state,0,4,0,0)==AIC_BAD_CONFIG);
    CHECK(aic_set_level(&config,0,1,1)==AIC_BAD_CONFIG);
    CHECK(!aic_pending(0,&state) && !aic_pending(&config,0));
    const struct aic_config invalid[]={{0,10,0x40000},{31,10,0x40000},
        {4097,10,0x40000},{1280,11,0x40000},{1280,10,0x10000},{1280,10,0x40001}};
    for(unsigned i=0;i<sizeof(invalid)/sizeof(*invalid);i++) {
        CHECK(!aic_config_valid(&invalid[i]));
        CHECK(aic_access(&invalid[i],&state,0,4,0,&v)==AIC_BAD_CONFIG);
        CHECK(aic_set_level(&invalid[i],&state,0,1)==AIC_BAD_CONFIG);
        CHECK(!aic_pending(&invalid[i],&state));
    }
    printf("PASS: %u AIC checks\n",checks);
}

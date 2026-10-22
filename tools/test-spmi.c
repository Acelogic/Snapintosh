/* SPDX-License-Identifier: MIT */
/* cc -std=c11 -Wall -Wextra -Werror -O1 -g -fsanitize=address,undefined -Icompat
 * tools/test-spmi.c compat/device.c compat/dart.c compat/aic.c compat/watchdog.c compat/clock.c
 * -o build/test-spmi; build/test-spmi */
#include "device.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static unsigned checks;
#define CHECK(x) do { checks++; if (!(x)) { fprintf(stderr,"FAIL %d: %s\n",__LINE__,#x); exit(1); } } while(0)
static struct device_model bus={DEVICE_SPMI_GEN3_EMPTY_V1,0x308600000UL,0x18000,{0x14000,0x4000,492,256,256}};
static struct device_state state, before, routed[3], saved[3];
static uint64_t read_at(uint64_t offset)
{
    uint64_t value=UINT64_MAX;
    CHECK(device_model_access_state(&bus,&state,offset,4,0,&value)==DEVICE_OK);
    return value;
}
static uint64_t rd(unsigned reg) { return read_at(bus.config[0]+reg); }
static void wr(unsigned reg, uint64_t value)
{
    CHECK(device_model_access_state(&bus,&state,bus.config[0]+reg,4,1,&value)==DEVICE_OK);
}
static void reject(uint64_t offset, unsigned width, int write, uint64_t value,
                   enum device_result want)
{
    before=state; uint64_t original=value;
    CHECK(device_model_access_state(&bus,&state,offset,width,write,&value)==want);
    CHECK(value==original && !memcmp(&state,&before,sizeof(state)));
}
static void reset(void)
{
    CHECK(device_model_start(&bus,&state,0,1)==DEVICE_OK);
    CHECK(rd(0)==0x01000100 && rd(0x80)==0 && rd(0x40)==0);
}
static void inspect_fault_queue(void)
{
    before=state;
    CHECK(read_at(bus.config[1])==0x01000000);
    CHECK(!memcmp(&state,&before,sizeof(state)));
    reject(bus.config[1]+8,4,0,123,DEVICE_BAD_VALUE);
}
static void drain(unsigned slave, unsigned opcode, unsigned bytes)
{
    CHECK(rd(8)==((slave<<8)|opcode)); /* neither ACK nor valid parity */
    for (unsigned i=0; i<(bytes+3)/4; i++) CHECK(rd(8)==0); /* invalid-frame slots */
    CHECK(rd(0)==0x01000100);
}
static void access(struct device_model *m, struct device_state *s, unsigned reg, uint64_t val)
{
    CHECK(device_model_access_state(m,s,reg,4,1,&val)==DEVICE_OK);
}
int main(void)
{
    CHECK(device_models_valid(&bus,1,0,0));
    reset();
    inspect_fault_queue();
    CHECK(state.spmi_recovery.config_reads==0 && state.spmi_recovery.config_writes==0);
    CHECK(state.spmi_recovery.fifo_clears==0);
    /* Native failed short-read recovery: the header is consumed first, but
     * its invalid padding remains until resetQueueBase explicitly drains it. */
    wr(4,0x8c60);
    CHECK(rd(8)==0xc60 && state.spmi.rx_count==1);
    uint64_t configuration=rd(0xa0);
    CHECK(configuration==0);
    wr(0xa0,0);
    CHECK(state.spmi.rx_count==1 && rd(0x80)==0x41);
    CHECK(rd(8)==0 && rd(0)==0x01000100);
    wr(0xa0,configuration);
    CHECK(state.spmi_recovery.config_reads==1 && state.spmi_recovery.config_writes==2);
    CHECK(state.spmi_recovery.fifo_clears==0 && rd(0x80)==0x41);
    wr(0x80,UINT32_MAX);
    /* An incomplete TX instead needs the actual FIFO clear action. Neither
     * the configuration save/restore nor an ACTION zero write clears data. */
    wr(4,0x830f); wr(4,0x12345678);
    configuration=rd(0xa0); wr(0xa0,0); wr(0xa4,0);
    CHECK(state.spmi.tx_words==2 && state.spmi.tx_need==5);
    wr(0xa4,1);
    CHECK(state.spmi.tx_words==0 && state.spmi.rx_count==0 && rd(0xa4)==0);
    wr(0xa0,configuration);
    CHECK(state.spmi_recovery.fifo_clears==1);
    wr(4,0x8010); wr(0xa4,1);
    CHECK(state.spmi.rx_count==0 && rd(0x80)==0x81); /* clear is not an IRQ ACK */
    for (unsigned bit=0; bit<32; bit++)
        reject(bus.config[0]+0xa0,4,1,1U<<bit,DEVICE_BAD_VALUE);
    reject(bus.config[0]+0xa0,8,0,0,DEVICE_BAD_WIDTH);
    reject(bus.config[0]+0xa0,4,1,1UL<<32,DEVICE_BAD_VALUE);
    state.spmi_recovery.config_reads=state.spmi_recovery.config_writes=UINT32_MAX;
    state.spmi_recovery.fifo_clears=UINT32_MAX;
    CHECK(rd(0xa0)==0); wr(0xa0,0); wr(0xa4,1);
    CHECK(state.spmi_recovery.config_reads==UINT32_MAX &&
          state.spmi_recovery.config_writes==UINT32_MAX &&
          state.spmi_recovery.fifo_clears==UINT32_MAX);
    reset();
    for (unsigned slave=0; slave<16; slave++) for (unsigned n=1; n<=16; n++) {
        uint32_t cmd=(0x42U<<16)|(slave<<8)|0x20|(n-1);
        wr(4,cmd);
        CHECK(rd(0)==(0x100 | ((1+(n+3)/4)<<16)));
        CHECK(rd(0x80)==(1U<<6));
        inspect_fault_queue(); /* fault inspection cannot consume the response */
        drain(slave,0x20|(n-1),n);
        wr(0x80,UINT32_MAX);
    }
    for (unsigned n=1; n<=16; n++) {
        wr(4,(0x55U<<16)|0x8300|(n-1));
        CHECK(!(rd(0)&0x100) && (rd(0)&0x01000000));
        for (unsigned word=0; word<(n+3)/4; word++) {
            CHECK(rd(0x80)==0);
            wr(4,0xdead0000|word);
        }
        CHECK(rd(0x80)==0x81); /* failed ACK plus requested ALERT */
        inspect_fault_queue();
        drain(3,n-1,0);
        wr(0x80,0x80); CHECK(rd(0x80)==1);
        wr(0x80,1); CHECK(rd(0x80)==0);
    }
    for (unsigned n=1; n<=8; n++) {
        wr(4,0xffff8200U|0x38|(n-1));
        CHECK(rd(0x80)==0x41);
        inspect_fault_queue();
        CHECK(rd(8)==(0x200U|0x38|(n-1)));
        for (unsigned i=0; i<(n+3)/4; i++) CHECK(rd(8)==0);
        wr(0x80,UINT32_MAX);
    }
    reset();
    /* Stock performPayloadlessTransaction embeds the register-zero byte in
     * the header, with opcode80. It must complete without another TX word. */
    for (unsigned slave=0; slave<16; slave++) for (unsigned byte=0; byte<128; byte++)
        for (unsigned alert=0; alert<2; alert++) {
            wr(4,(byte<<24)|(alert<<15)|(slave<<8)|0x80);
            CHECK(state.spmi.tx_words==0 && state.spmi.tx_need==0);
            CHECK(rd(0x80)==(0x80|alert));
            inspect_fault_queue();
            drain(slave,0x80,0);
            wr(0x80,UINT32_MAX);
        }
    /* Stock short reads have one invalid-frame byte and an EXTRA register;
     * the opcode itself stays60. Fault inspection must retain both words. */
    for (unsigned slave=0; slave<16; slave++) for (unsigned reg=0; reg<32; reg++)
        for (unsigned alert=0; alert<2; alert++) {
            wr(4,(reg<<16)|(alert<<15)|(slave<<8)|0x60);
            CHECK(rd(0)==0x00020100);
            CHECK(rd(0x80)==(0x40|alert));
            inspect_fault_queue();
            wr(0x80,UINT32_MAX);
            drain(slave,0x60,1);
        }
    /* Stock registerReadWriteCommand short writes: opcode40, register at
     * bits20:16, data byte at bits31:24, no FIFO payload. A missing slave
     * gives exactly one header with neither ACK nor data, and the failed
     * write-ACK flag, as for every other write form on this empty bus. */
    for (unsigned slave=0; slave<16; slave++) for (unsigned reg=0; reg<32; reg++)
        for (unsigned byte=0; byte<256; byte+=0x55) for (unsigned alert=0; alert<2; alert++) {
            wr(4,(byte<<24)|(reg<<16)|(alert<<15)|(slave<<8)|0x40);
            CHECK(state.spmi.tx_words==0 && state.spmi.tx_need==0);
            CHECK(rd(0)==0x00010100);
            CHECK(rd(0x80)==(0x80|alert));
            inspect_fault_queue();
            wr(0x80,UINT32_MAX);
            drain(slave,0x40,0);
        }
    /* Reproduce the native fault/response IRQ ordering: diagnostic queue
     * inspection and W1C must leave each payloadless negative reply intact. */
    for (unsigned slave=0; slave<16; slave++) for (unsigned op=0x10; op<=0x13; op++) {
        wr(4,0x8000|(slave<<8)|op);
        CHECK(rd(0x80)==0x81);
        inspect_fault_queue();
        wr(0x80,0x80);
        CHECK(rd(0x80)==1);
        inspect_fault_queue();
        wr(0x80,1);
        drain(slave,op,0);
    }
    for (unsigned i=0; i<256; i++) wr(4,0x10); /* one-word negative replies */
    CHECK(rd(0)==0x02000100); /* count wraps, FULL distinguishes 256 from 0 */
    inspect_fault_queue();
    reject(bus.config[0]+4,4,1,0x10,DEVICE_BAD_VALUE);
    for (unsigned i=0; i<256; i++) CHECK(rd(8)==0x10);
    CHECK(rd(0)==0x01000100);
    for (unsigned cycle=0; cycle<300; cycle++) { wr(4,0x1c); drain(0,0x1c,10); }
    wr(4,0xf); wr(4,0xaabbccdd); /* partial packet, then FIFO clear */
    CHECK(!(rd(0)&0x100)); wr(0xa4,1); CHECK(rd(0)==0x01000100);
    wr(0xa4,0); CHECK(rd(0xa4)==0);
    for (unsigned bank=0; bank<9; bank++) {
        wr(0x20+bank*4,0x12345678); CHECK(rd(0x20+bank*4)==0x12345678);
        wr(0x60+bank*4,UINT32_MAX); CHECK(rd(0x60+bank*4)==0);
    }
    /* 0x14..0x1b are never issued (executeCommand refuses those types);
     * short-write register numbers above 0x1f cannot be encoded natively. */
    const uint32_t badcmd[]={0x14,0x15,0x16,0x1a,0x1b,0x41,0x5f,0x61,0x7f,0x81,0xff,
                             0x7000,0x01000020,0x10010,
                             0x80000080,0x00010080,0x00ff0080,0x00200060,0x01000060,
                             0x00200040,0x00400040,0x00800040,0xffe00040,0x7040};
    for (unsigned i=0; i<sizeof(badcmd)/sizeof(badcmd[0]); i++)
        reject(bus.config[0]+4,4,1,badcmd[i],DEVICE_BAD_VALUE);
    reject(bus.config[0]+4,4,1,1UL<<32,DEVICE_BAD_VALUE);
    reject(bus.config[0]+0xa4,4,1,2,DEVICE_BAD_VALUE);
    reject(bus.config[0],4,1,0,DEVICE_READ_ONLY);
    reject(bus.config[0]+8,4,1,0,DEVICE_READ_ONLY);
    reject(bus.config[0]+1,4,0,0,DEVICE_BAD_WIDTH);
    reject(bus.config[0],8,0,0,DEVICE_BAD_WIDTH);
    reject(0,4,0,0,DEVICE_UNKNOWN_REGISTER);
    reject(0x8000,4,0,0,DEVICE_UNKNOWN_REGISTER);
    reject(0x4004,4,1,0,DEVICE_UNKNOWN_REGISTER);
    reject(0x4000,4,1,0,DEVICE_READ_ONLY);
    reject(0x4008,4,1,0,DEVICE_READ_ONLY);
    reject(0x4000,8,0,0,DEVICE_BAD_WIDTH);
    reject(0x4001,4,0,0,DEVICE_BAD_WIDTH);
    CHECK(rd(0xa0)==0);
    reset();
    struct device_model models[3]={{DEVICE_AIC3_FLAT_V1,0x301000000UL,0x1cc000,
                                   {1280,4096,0x40000,10,0}},bus,bus};
    models[2].base=0x308700000UL; /* two producers share IRQ 492 for this test */
    CHECK(device_models_valid(models,3,0,0));
    CHECK(device_models_route_irqs(models,routed,3)==DEVICE_OK);
    access(&models[0],&routed[0],0x14,1);
    access(&models[0],&routed[0],0x14600+(492/32)*4,1U<<(492%32));
    for (unsigned i=1; i<3; i++) {
        access(&models[i],&routed[i],0x14004,0x8010);
        CHECK(device_models_route_irqs(models,routed,3)==DEVICE_OK);
        if (i==1) CHECK(!device_irq_pending(&models[0],&routed[0])); /* locally masked */
        access(&models[i],&routed[i],0x14040,1);
        CHECK(device_models_route_irqs(models,routed,3)==DEVICE_OK);
        CHECK(device_irq_pending(&models[0],&routed[0]));
    }
    access(&models[1],&routed[1],0x14080,1);
    CHECK(device_models_route_irqs(models,routed,3)==DEVICE_OK);
    CHECK(device_irq_pending(&models[0],&routed[0])); /* second producer still high */
    uint64_t event=0;
    CHECK(device_model_access_state(&models[0],&routed[0],0x40000,4,0,&event)==DEVICE_OK);
    CHECK(event==0x101ec && !device_irq_pending(&models[0],&routed[0]));
    access(&models[2],&routed[2],0x14080,1);
    CHECK(device_models_route_irqs(models,routed,3)==DEVICE_OK);
    access(&models[0],&routed[0],0x14600+(492/32)*4,1U<<(492%32));
    CHECK(!device_irq_pending(&models[0],&routed[0]));
    memcpy(saved,routed,sizeof(saved)); models[2].config[2]=1280;
    CHECK(device_models_route_irqs(models,routed,3)==DEVICE_BAD_CONFIG);
    CHECK(!memcmp(saved,routed,sizeof(saved)));
    CHECK(device_models_route_irqs(&bus,&state,1)==DEVICE_BAD_CONFIG);
    CHECK(device_models_route_irqs(0,0,0)==DEVICE_OK);
    const uint64_t invalid[][2]={{0,0},{0,0x14004},{0,UINT64_MAX},{1,0},{1,0x1000},
                                  {1,0x14000},{2,4096},{3,255},{4,257}};
    struct device_model original=bus;
    for (unsigned i=0; i<sizeof(invalid)/sizeof(invalid[0]); i++) {
        bus.config[invalid[i][0]]=invalid[i][1];
        CHECK(!device_models_valid(&bus,1,0,0));
        reject(0,4,0,123,DEVICE_BAD_CONFIG);
        bus=original;
    }
    bus.base=0x500000000UL; bus.config[0]=0x8000; bus.span=0xc000;
    CHECK(device_models_valid(&bus,1,0,0));
    reset(); wr(4,0x10); inspect_fault_queue(); drain(0,0x10,0); /* alternate gen-3 placement */
    printf("PASS: %u SPMI FIFO, refusal and AIC routing checks\n",checks);
    return 0;
}

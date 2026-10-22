/* SPDX-License-Identifier: MIT */
/* cc -std=c11 -Wall -Wextra -Werror -O1 -g -fsanitize=address,undefined -Icompat
 * tools/test-platform-io.c compat/device.c compat/aic.c compat/watchdog.c
 * compat/clock.c compat/dart.c -o build/test-platform-io; build/test-platform-io */
#include "device.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static unsigned checks;
#define CHECK(x) do { checks++; if (!(x)) { fprintf(stderr,"FAIL %d: %s\n",__LINE__,#x); exit(1); } } while(0)
static struct device_state state, before;
static const struct device_model gpio={DEVICE_GPIO_QUIET_V1,0x314838000UL,0x4000,{10,7,0x70,0,0}};
static const struct device_model aes={DEVICE_AES_NO_KEYS_V1,0x3082dc000UL,0x8000,{0,0x40,0x44,0x48,0}};

static uint64_t read32(const struct device_model *m, uint64_t offset)
{
    uint64_t value=UINT64_MAX;
    CHECK(device_model_access_state(m,&state,offset,4,0,&value)==DEVICE_OK);
    return value;
}
static void write32(const struct device_model *m, uint64_t offset, uint64_t value)
{
    CHECK(device_model_access_state(m,&state,offset,4,1,&value)==DEVICE_OK);
}
static void refuse(const struct device_model *m, uint64_t offset, unsigned width,
                   int write, uint64_t value, enum device_result want)
{
    before=state;
    uint64_t original=value;
    CHECK(device_model_access_state(m,&state,offset,width,write,&value)==want);
    CHECK(value==original);
    CHECK(!memcmp(&state,&before,sizeof(state)));
}
int main(void)
{
    CHECK(device_models_valid(&gpio,1,0,0));
    CHECK(device_models_valid(&aes,1,0,0));
    CHECK(device_model_start(&gpio,&state,123,24000000)==DEVICE_OK);
    for (unsigned pin=0; pin<10; pin++) {
        CHECK(read32(&gpio,pin*4)==0x4000e);
        write32(&gpio,pin*4,0x40003);
        CHECK(read32(&gpio,pin*4)==0x40003); /* output high */
        write32(&gpio,pin*4,0x40002);
        CHECK(read32(&gpio,pin*4)==0x40002); /* output low */
        write32(&gpio,pin*4,0x4000f);
        CHECK(read32(&gpio,pin*4)==0x4000e); /* input stays externally low */
    }
    for (unsigned group=4; group<7; group++) {
        uint64_t off=0x800+group*0x40;
        CHECK(read32(&gpio,off)==0);
        write32(&gpio,off,UINT32_MAX); /* boot init ACK includes unused bits */
        CHECK(read32(&gpio,off)==0);
        refuse(&gpio,off+4,4,0,0,DEVICE_UNKNOWN_REGISTER);
    }
    refuse(&gpio,0x800,4,1,UINT32_MAX,DEVICE_UNKNOWN_REGISTER);
    refuse(&gpio,40,4,0,0,DEVICE_UNKNOWN_REGISTER);
    refuse(&gpio,0x4000,4,0,0,DEVICE_NOT_FOUND);
    for (unsigned width=1; width<=8; width*=2)
        if (width!=4) refuse(&gpio,0,width,0,0,DEVICE_BAD_WIDTH);
    refuse(&gpio,1,4,0,0,DEVICE_BAD_WIDTH);
    /* A held-low GPIO-function pad can assert only a level-low interrupt.
     * The never-firing modes are admitted; see tools/test-gpio-irq.c. */
    refuse(&gpio,0,4,1,0x40006,DEVICE_BAD_VALUE);
    for (unsigned mode=2; mode<=6; mode++) if (mode!=3) {
        write32(&gpio,0,0x40000 | (mode<<1));
        CHECK(read32(&gpio,0)==(0x40000U | (mode<<1)));
    }
    write32(&gpio,0,0x4000f);
    CHECK(read32(&gpio,0)==0x4000e);
    for (unsigned bit=0; bit<64; bit++)
        if (!((0xe78fefUL>>bit)&1))
            refuse(&gpio,0,4,1,0x4000e | (1UL<<bit),DEVICE_BAD_VALUE);
    refuse(&gpio,0,4,1,0x4002e,DEVICE_BAD_VALUE); /* peripheral mux */
    refuse(&gpio,0,4,1,0x3000e,DEVICE_BAD_VALUE); /* unsupported group */
    write32(&gpio,0,0x240003); /* lock an output high */
    write32(&gpio,0,0x240002); /* data remains writable */
    refuse(&gpio,0,4,1,0x40002,DEVICE_BAD_VALUE); /* no unlocking */
    refuse(&gpio,0,4,1,0x240202,DEVICE_BAD_VALUE);
    CHECK(device_model_start(&gpio,&state,0,24000000)==DEVICE_OK);
    CHECK(read32(&gpio,0)==0x4000e); /* VM reset clears lock and output */
    struct device_model main_gpio=gpio;
    main_gpio.config[0]=216; main_gpio.config[2]=0x7f;
    CHECK(device_model_start(&main_gpio,&state,0,24000000)==DEVICE_OK);
    for (unsigned group=0; group<7; group++) for (unsigned bank=0; bank<7; bank++) {
        write32(&main_gpio,0x800+group*0x40+bank*4,UINT32_MAX);
        CHECK(read32(&main_gpio,0x800+group*0x40+bank*4)==0);
    }
    for (unsigned pin=0; pin<216; pin++) CHECK(read32(&main_gpio,pin*4)==14);
    struct device_model rx=main_gpio;
    rx.kind=DEVICE_GPIO_UART_RX_IDLE_V1; rx.config[3]=0x200aa; rx.config[4]=0;
    CHECK(device_model_start(&rx,&state,0,24000000)==DEVICE_OK);
    write32(&rx,169*4,0x4e); /* stock driver's intermediate input-disabled write */
    CHECK(read32(&rx,169*4)==0x4e);
    write32(&rx,169*4,0x24e);
    CHECK(read32(&rx,169*4)==0x24f); /* disconnected UART receive line is idle high */
    write32(&rx,169*4,0x24f); /* DATA is sampled, not an externally writable input */
    CHECK(read32(&rx,169*4)==0x24f);
    for (unsigned pin=0; pin<216; pin++) if (pin!=169)
        refuse(&rx,pin*4,4,1,0x24e,DEVICE_BAD_VALUE);
    for (unsigned mode=0; mode<7; mode++)
        refuse(&rx,169*4,4,1,0x240 | (mode<<1),DEVICE_BAD_VALUE);
    refuse(&rx,169*4,4,1,0x22e,DEVICE_BAD_VALUE);
    refuse(&rx,169*4,4,1,0x26e,DEVICE_BAD_VALUE);
    write32(&rx,169*4,0x20e); /* disconnecting mux returns to ordinary low GPIO */
    CHECK(read32(&rx,169*4)==0x20e);
    write32(&rx,169*4,0x20024e);
    CHECK(read32(&rx,169*4)==0x20024f);
    refuse(&rx,169*4,4,1,0x20e,DEVICE_BAD_VALUE); /* route is locked */
    CHECK(device_model_start(&rx,&state,0,24000000)==DEVICE_OK);
    CHECK(read32(&rx,169*4)==14);
    rx.config[4]=0x10056; /* UART4's independent idle route */
    write32(&rx,85*4,0x2e);
    CHECK(read32(&rx,85*4)==0x2e);
    write32(&rx,85*4,0x22e);
    CHECK(read32(&rx,85*4)==0x22f);
    write32(&rx,169*4,0x24e);
    CHECK(read32(&rx,169*4)==0x24f);
    CHECK(read32(&rx,85*4)==0x22f);
    for (unsigned i=0; i<5; i++) {
        struct device_model bad=rx;
        if (i==0) bad.config[3]=0x200d9;
        if (i==1) bad.config[3]=0;
        if (i==2) bad.config[4]=0x40056;
        if (i==3) bad.config[4]=0x100aa;
        if (i==4) bad.config[4]=0x10000;
        CHECK(!device_models_valid(&bad,1,0,0));
    }
    struct device_model idle=main_gpio;
    idle.kind=DEVICE_GPIO_IDLE_INPUTS_V1;
    idle.config[3]=0x10056UL | (0x200aaUL<<18) | (0x10066UL<<36);
    idle.config[4]=0;
    CHECK(device_model_start(&idle,&state,0,24000000)==DEVICE_OK);
    const unsigned idle_pins[]={85,169,101}, idle_mux[]={1,2,1};
    for (unsigned i=0; i<3; i++) {
        uint32_t value=14 | (idle_mux[i]<<5);
        write32(&idle,idle_pins[i]*4,value);
        CHECK(read32(&idle,idle_pins[i]*4)==value);
        write32(&idle,idle_pins[i]*4,value|0x200);
        CHECK(read32(&idle,idle_pins[i]*4)==(value|0x201));
    }
    for (unsigned pin=0; pin<216; pin++) if (pin!=85 && pin!=169 && pin!=101)
        refuse(&idle,pin*4,4,1,0x22e,DEVICE_BAD_VALUE);
    for (unsigned mode=0; mode<7; mode++)
        refuse(&idle,101*4,4,1,0x220 | (mode<<1),DEVICE_BAD_VALUE);
    write32(&idle,101*4,0x20e);
    CHECK(read32(&idle,101*4)==0x20e);
    /* Exercise all slots across the two config words, not only slot 0. */
    idle.config[4]=0x10001UL | (0x20002UL<<18) | (0x30003UL<<36);
    CHECK(device_model_start(&idle,&state,0,24000000)==DEVICE_OK);
    for (unsigned pin=0; pin<3; pin++) {
        uint32_t value=0x20e | ((pin+1)<<5);
        write32(&idle,pin*4,value);
        CHECK(read32(&idle,pin*4)==(value|1));
    }
    for (unsigned i=0; i<5; i++) {
        struct device_model bad=idle;
        if (i==0) bad.config[3] |= 1UL<<63;
        if (i==1) bad.config[4] |= 1UL<<54;
        if (i==2) bad.config[4]=0x10066; /* duplicate pin in different word */
        if (i==3) bad.config[3] &= ~0x3ffffUL;
        if (i==4) bad.config[4]=0x100d9; /* pin past end */
        CHECK(!device_models_valid(&bad,1,0,0));
        refuse(&bad,0,4,1,0x22e,DEVICE_BAD_CONFIG);
    }
    CHECK(read32(&aes,0)==15); /* legacy UID/GID and UID0 disable bits */
    for (unsigned i=1; i<4; i++)
        CHECK(read32(&aes,aes.config[i])!=0xa050c030); /* dedicated keys absent */
    for (unsigned i=0; i<4; i++) {
        refuse(&aes,aes.config[i],4,1,0,DEVICE_BAD_VALUE);
        refuse(&aes,aes.config[i],8,0,0,DEVICE_BAD_WIDTH);
    }
    refuse(&aes,4,4,0,0,DEVICE_UNKNOWN_REGISTER);
    refuse(&aes,1,4,0,0,DEVICE_BAD_WIDTH);
    const uint64_t invalid[][2]={{0,0},{0,257},{1,0},{1,8},{2,0},{2,128},{3,1},{4,1}};
    for (unsigned i=0; i<sizeof(invalid)/sizeof(invalid[0]); i++) {
        struct device_model bad=gpio;
        bad.config[invalid[i][0]]=invalid[i][1];
        CHECK(!device_models_valid(&bad,1,0,0));
        refuse(&bad,0,4,0,0,DEVICE_BAD_CONFIG);
    }
    for (unsigned i=0; i<4; i++) {
        struct device_model bad=aes;
        bad.config[i]=aes.config[(i+1)%4];
        CHECK(!device_models_valid(&bad,1,0,0));
        bad=aes; bad.config[i]=0x8000;
        CHECK(!device_models_valid(&bad,1,0,0));
        bad=aes; bad.config[i]++;
        CHECK(!device_models_valid(&bad,1,0,0));
    }
    struct device_model relocated=gpio;
    relocated.base=0x500000000UL;
    CHECK(device_models_valid(&relocated,1,0,0));
    CHECK(device_model_start(&relocated,&state,0,1)==DEVICE_OK);
    CHECK(read32(&relocated,0)==0x4000e);
    printf("PASS: %u GPIO/AES model checks\n",checks);
    return 0;
}

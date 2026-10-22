/* SPDX-License-Identifier: MIT */
/* GPIO interrupt-mode admission on every audited j700 GPIO controller.
 * cc -std=c11 -Wall -Wextra -Werror -O1 -g -fsanitize=address,undefined -Icompat
 * tools/test-gpio-irq.c compat/device.c compat/aic.c compat/watchdog.c
 * compat/clock.c compat/dart.c compat/aes-engine.c compat/aes.c compat/mmio.c
 * compat/sep-bootstrap.c compat/sep-pnon.c compat/sep-xars.c
 * -o build/test-gpio-irq; build/test-gpio-irq */
#include "device.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static unsigned checks;
#define CHECK(x) do { checks++; if (!(x)) { fprintf(stderr,"FAIL %d: %s\n",__LINE__,#x); exit(1); } } while(0)
static struct device_state state, before;

/* Exact descriptors emitted by probes/devicemodel.py for the
 * j700ap-26A428-bootfb-xars-uniform profile. */
static const struct device_model controllers[]={
    {DEVICE_GPIO_IDLE_PADS_V2,0x31a000000UL,0x100000,{0xd8,7,0x7f,0x4a299a55256UL,0x558aad532a5UL}},
    {DEVICE_GPIO_QUIET_V1,0x314838000UL,0x4000,{0xa,7,0x70,0,0}},
    {DEVICE_GPIO_QUIET_V1,0x310824000UL,0x4000,{0x39,7,0x70,0,0}},
    {DEVICE_GPIO_QUIET_V1,0x3081f0000UL,0x4000,{0x1e,7,0x70,0,0}},
    {DEVICE_GPIO_QUIET_V1,0x30c820000UL,0x4000,{0x6,7,0x60,0,0}},
};

/* 26A428 AppleT8101GPIOIC::_decodeVectorInfo at 0xfffffe000916086c:
 * type bit2 -> 0xc; else bit0 selects level (0x4/0x6) or edge (0x8/0xa)
 * and bit1 selects high/rising (0x4/0x8) over low/falling (0x6/0xa). */
static unsigned decode_vector_info(unsigned type)
{
    unsigned b=type&2, edge=b^0xa, level=b^6;
    return (type&4) ? 0xc : (type&1) ? level : edge;
}

static uint64_t rd(const struct device_model *m, uint64_t offset)
{
    uint64_t value=UINT64_MAX;
    CHECK(device_model_access_state(m,&state,offset,4,0,&value)==DEVICE_OK);
    return value;
}
static void wr(const struct device_model *m, uint64_t offset, uint64_t value)
{
    CHECK(device_model_access_state(m,&state,offset,4,1,&value)==DEVICE_OK);
}
static void refuse(const struct device_model *m, uint64_t offset, uint64_t value)
{
    before=state;
    uint64_t original=value;
    CHECK(device_model_access_state(m,&state,offset,4,1,&value)==DEVICE_BAD_VALUE);
    CHECK(value==original && !memcmp(&state,&before,sizeof(state)));
}
static uint64_t pending(unsigned group, unsigned pin)
{
    return 0x800+group*0x40+(pin/32)*4;
}

int main(void)
{
    /* The mapping the driver uses, independently of the model. */
    static const unsigned expected_mode[8]={5,3,4,2,6,6,6,6};
    for (unsigned type=0; type<8; type++)
        CHECK(decode_vector_info(type)==expected_mode[type]<<1);
    for (unsigned c=0; c<sizeof(controllers)/sizeof(*controllers); c++) {
        const struct device_model *m=&controllers[c];
        CHECK(device_models_valid(m,1,0,0));
        CHECK(device_model_start(m,&state,0,24000000)==DEVICE_OK);
        for (unsigned pin=0; pin<m->config[0]; pin++)
            for (unsigned group=0; group<7; group++) {
                uint64_t init=((uint64_t)group<<16)|0x20e;
                if (!(m->config[2]&(1UL<<group))) {
                    refuse(m,pin*4,init);
                    refuse(m,pin*4,(init&~0xeUL)|0x8); /* rising, unsupported group */
                    continue;
                }
                /* initVector: mode 7 plus input enable and the IRQ group. */
                wr(m,pin*4,init);
                CHECK(rd(m,pin*4)==init);
                for (unsigned type=0; type<8; type++) {
                    uint64_t cfg=(init&~0xeUL)|decode_vector_info(type);
                    if (decode_vector_info(type)==6) {
                        /* level-low on an externally held-low pad would
                         * assert immediately: no producer, refuse intact. */
                        refuse(m,pin*4,cfg);
                        CHECK(rd(m,pin*4)==init);
                        continue;
                    }
                    /* enableVector clears pending for level types first. */
                    if (type&1) wr(m,pending(group,pin),1UL<<(pin%32));
                    wr(m,pin*4,cfg);
                    CHECK(rd(m,pin*4)==cfg); /* DATA reads the low pad */
                    CHECK(rd(m,pending(group,pin))==0);
                    /* disableVectorHard: clear bits 3:1 (mode 0). */
                    wr(m,pin*4,cfg&~0xeUL);
                    CHECK(rd(m,pin*4)==(cfg&~0xeUL));
                    wr(m,pin*4,init);
                }
                /* Releasing a driven-high output is a falling edge. */
                wr(m,pin*4,((uint64_t)group<<16)|3);
                refuse(m,pin*4,(init&~0xeUL)|0xa);
                refuse(m,pin*4,(init&~0xeUL)|0xc);
                refuse(m,pin*4,(init&~0xeUL)|0x6);
                CHECK(rd(m,pin*4)==(((uint64_t)group<<16)|3));
                wr(m,pin*4,(init&~0xeUL)|0x8); /* rising cannot occur */
                wr(m,pin*4,((uint64_t)group<<16)|3);
                wr(m,pin*4,(init&~0xeUL)|0x4); /* level-high: pad now low */
                wr(m,pin*4,((uint64_t)group<<16)|2); /* output low */
                wr(m,pin*4,(init&~0xeUL)|0xa);
                wr(m,pin*4,((uint64_t)group<<16)|2);
                wr(m,pin*4,(init&~0xeUL)|0xc);
                /* Peripheral function plus interrupt stays refused. */
                for (unsigned mux=1; mux<4; mux++)
                    for (unsigned mode=2; mode<=6; mode++)
                        refuse(m,pin*4,(init&~0xeUL)|(mux<<5)|(mode<<1));
                /* A locked pad keeps its configuration. */
                wr(m,pin*4,init|(1UL<<21));
                refuse(m,pin*4,(init&~0xeUL)|(1UL<<21)|0x8);
                CHECK(device_model_start(m,&state,0,24000000)==DEVICE_OK);
            }
        /* Unknown configuration bits still refuse in interrupt modes. */
        uint64_t first=(uint64_t)__builtin_ctzll(m->config[2])<<16;
        wr(m,0,first|0x208);
        for (unsigned bit=0; bit<64; bit++)
            if (!((0xe78fefUL>>bit)&1)) refuse(m,0,first|0x208|(1UL<<bit));
    }
    /* A declared idle-high route: leaving it lowers the pad, so falling and
     * either-edge modes would latch. Rising and level-high cannot. */
    const struct device_model *main_gpio=&controllers[0];
    CHECK(device_model_start(main_gpio,&state,0,24000000)==DEVICE_OK);
    unsigned routes[][2]={{85,1},{169,2},{101,1},{80,1},{164,1},{165,1},{170,1},{171,1}};
    for (unsigned r=0; r<8; r++) {
        unsigned pin=routes[r][0], mux=routes[r][1];
        uint64_t idle=0x20e|(mux<<5);
        wr(main_gpio,pin*4,idle);
        CHECK(rd(main_gpio,pin*4)==(idle|1)); /* idle high */
        refuse(main_gpio,pin*4,0x20a);
        refuse(main_gpio,pin*4,0x20c);
        refuse(main_gpio,pin*4,0x206);
        refuse(main_gpio,pin*4,idle&~0xeUL);   /* mux kept, mode 0 */
        wr(main_gpio,pin*4,0x208);
        CHECK(rd(main_gpio,pin*4)==0x208);
        wr(main_gpio,pin*4,idle);
        wr(main_gpio,pin*4,0x204);
        CHECK(rd(main_gpio,pin*4)==0x204);
        /* Once the pad is ordinary and low, every edge mode is inert. */
        wr(main_gpio,pin*4,0x20a);
        wr(main_gpio,pin*4,0x20c);
        wr(main_gpio,pin*4,0x20e);
        refuse(main_gpio,pin*4,0x206);
    }
    printf("PASS: %u GPIO interrupt-mode admission checks\n",checks);
    return 0;
}

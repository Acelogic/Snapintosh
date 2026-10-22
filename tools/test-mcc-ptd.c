/* SPDX-License-Identifier: MIT */
#include "device.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static unsigned checks;
#define CHECK(x) do { checks++; if (!(x)) { fprintf(stderr,"FAIL %d: %s\n",__LINE__,#x); exit(1); } } while(0)
static struct device_model model={DEVICE_MCC_PTD_COHERENT_V1,0x3003c0000UL,
                                 0x14000,{0x10000,0x1a8,0x1b8,8,0}};
static struct device_state state, snapshot;

static uint64_t read64(uint64_t offset)
{
    uint64_t v=~0UL;
    CHECK(device_model_access_state(&model,&state,offset,8,0,&v)==DEVICE_OK);
    return v;
}
static void write64(uint64_t offset, uint64_t value)
{
    CHECK(device_model_access_state(&model,&state,offset,8,1,&value)==DEVICE_OK);
}
static void refused(uint64_t offset, unsigned width, int write,
                    uint64_t value, enum device_result expected)
{
    uint64_t original=value;
    snapshot=state;
    CHECK(device_model_access_state(&model,&state,offset,width,write,&value)==expected);
    CHECK(value==original && !memcmp(&state,&snapshot,sizeof(state)));
}
int main(void)
{
    CHECK(device_models_valid(&model,1,0,0));
    uint64_t v=42;
    CHECK(device_model_access(&model,0x1c00,8,0,&v)==DEVICE_BAD_CONFIG && v==42);
    for (unsigned placement=0;placement<2;placement++) {
        if (placement) {
            model.base=0x500000000UL; model.span=0x24000;
            model.config[0]=0x20000; model.config[1]=20; model.config[2]=60;
        }
        memset(&state,0,sizeof(state));
        CHECK(device_models_valid(&model,1,0,0));
        uint64_t db=model.config[1]*16, reply=model.config[2]*16;
        uint64_t update=model.config[0]+model.config[1]*8;
        CHECK(read64(reply+8*16)==0); /* no fabricated completion on reset */
        refused(update+8*8,8,1,0x1002,DEVICE_BAD_VALUE); /* payload required */
        write64(update+9*8,17);
        refused(update+8*8,8,1,0x1002,DEVICE_BAD_VALUE); /* capacity is zero */
        CHECK(read64(reply+8*16)==0);
        write64(update+9*8,0);
        for (unsigned i=0;i<8;i++) {
            uint64_t request=0x123430003fff2000UL ^ ((uint64_t)i<<48);
            write64(update+i*8,request);
            CHECK(read64(db+i*16)==request); /* RMW must retain other clients */
            CHECK(read64(db+i*16+8)==2 && read64(db+i*16+8)==0);
            CHECK(read64(reply+i*16)==0); /* no cache means no nonzero grants */
            CHECK(read64(reply+i*16+8)==2 && read64(reply+i*16+8)==0);
            refused(update+i*8,8,1,request|(1UL<<14),DEVICE_BAD_VALUE);
        }
        for (uint64_t bad=0;bad<16;bad++)
            if (bad!=1) refused(update+8*8,8,1,(bad<<12)|2,DEVICE_BAD_VALUE);
        refused(update+8*8,8,1,0x1000,DEVICE_BAD_VALUE);
        refused(update+8*8,8,1,(1UL<<63)|0x1002,DEVICE_BAD_VALUE);
        const uint64_t sequences[]={2,0xfff,1,2};
        for (unsigned i=0;i<4;i++) {
            write64(update+9*8,0);
            CHECK(read64(reply+8*16)==(i ? sequences[i-1] : 0));
            write64(update+8*8,0x1000|sequences[i]);
            CHECK(read64(reply+8*16)==sequences[i]);
            CHECK(read64(reply+8*16+8)==2 && read64(reply+8*16+8)==0);
            CHECK(read64(db+8*16)==(0x1000|sequences[i]));
            refused(update+8*8,8,1,0x1003,DEVICE_BAD_VALUE); /* no stale payload */
        }
        for (unsigned i=0;i<8;i++) {
            CHECK(read64(reply+i*16)==0);
            CHECK(read64(reply+i*16+8)==2 && read64(reply+i*16+8)==0);
        }
        refused(db,8,1,0,DEVICE_READ_ONLY);
        refused(reply,8,1,0,DEVICE_READ_ONLY);
        refused(update,8,0,0,DEVICE_UNKNOWN_REGISTER);
        refused(model.config[0]+model.config[2]*8,8,1,0,DEVICE_UNKNOWN_REGISTER);
        refused(0x4000,8,0,0,DEVICE_UNKNOWN_REGISTER);
        refused(model.config[0]+0x3ff8,8,0,0,DEVICE_UNKNOWN_REGISTER);
        refused(model.span,8,0,0,DEVICE_NOT_FOUND);
        for(unsigned width=1;width<=16;width*=2) if(width!=8) {
            refused(db,width,0,0,DEVICE_BAD_WIDTH);
            refused(update,width,1,0,DEVICE_BAD_WIDTH);
        }
        for(unsigned align=1;align<8;align++) {
            refused(db+align,8,0,0,DEVICE_BAD_WIDTH);
            refused(update+align,8,1,0,DEVICE_BAD_WIDTH);
        }
    }
    const uint64_t bad[][5]={{0x1000,20,60,8,0},{0x20000,20,60,0,0},
        {0x20000,20,60,9,0},{0x20000,20,21,8,0},{0x20000,1015,60,8,0},
        {0x20000,20,1016,8,0},{0x20000,20,60,8,1},{~0UL,20,60,8,0}};
    for(unsigned i=0;i<sizeof(bad)/sizeof(*bad);i++) {
        memcpy(model.config,bad[i],sizeof(model.config));
        CHECK(!device_models_valid(&model,1,0,0));
        refused(0,8,0,42,DEVICE_BAD_CONFIG);
    }
    printf("PASS: %u MCC PTD checks\n",checks);
}

/* SPDX-License-Identifier: MIT */
/* Exact boot configuration ABI; sampled data words read 0 (no AON producer). */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "device.h"

static unsigned checks;
#define CHECK(x) do { checks++; if (!(x)) { \
    fprintf(stderr,"line %u: %s\n",__LINE__,#x); exit(1); } } while (0)
static struct device_state state, saved, other;

static enum device_result access_word(struct device_model *m, unsigned off,
                                     unsigned width, int write, uint64_t *v)
{
    return device_model_access_state(m,&state,off,width,write,v);
}

int main(int argc, char **argv)
{
    int topology=argc==2 && !strcmp(argv[1],"--topology");
    for (unsigned group=6;group<=7;group++) {
        struct device_model m={DEVICE_PMGR_AON_COUNTER_CONFIG_V1,
            group==6 ? 0x30827b000UL : 0x3082b4000UL,0x1000,{group,0,0,0,0}};
        unsigned base=group==6 ? 0x800 : 0, count=group==6 ? 6 : 69;
        CHECK(device_models_valid(&m,1,0,0));
        memset(&state,0,sizeof(state));
        CHECK(device_model_start(&m,&state,123,24000000)==DEVICE_OK);
        unsigned found=0;
        for (unsigned off=0;off<0x1000;off+=4) {
            uint64_t v=0xdeadbeef;
            saved=state;
            enum device_result r=access_word(&m,off,4,0,&v);
            int present=off==base || (off>=base+0x100 &&
                off<base+0x100+count*0x20 && !((off-base-0x100)&31));
            /* IOReport samples each slot's data words; nothing programs an
             * AON value, so both halves read 0 and stay unwritable
             * (docs/PMGR-IOREPORT-20261017.md). */
            int data=off>=base+0x100 && off<base+0x100+count*0x20 &&
                (((off-base-0x100)&31)==0x10 || ((off-base-0x100)&31)==0x14);
            if (data) {
                CHECK(r==DEVICE_OK && v==0 && !memcmp(&state,&saved,sizeof(state)));
                v=1;CHECK(access_word(&m,off,4,1,&v)==DEVICE_READ_ONLY);
                CHECK(!memcmp(&state,&saved,sizeof(state)));
                continue;
            }
            CHECK(r==(present ? DEVICE_OK : DEVICE_UNKNOWN_REGISTER));
            CHECK(!memcmp(&state,&saved,sizeof(state)));
            if (!present) {
                CHECK(v==0xdeadbeef);
                CHECK(access_word(&m,off,4,1,&v)==DEVICE_UNKNOWN_REGISTER);
                CHECK(!memcmp(&state,&saved,sizeof(state)));
                continue;
            }
            found++;
            if (topology) printf("%u %u\n",group,off);
            CHECK(v==0);
            unsigned index=off==base ? 0 : 1+(off-base-0x100)/0x20;
            unsigned mask=index ? 5 : 1;
            /* Every admitted configuration survives readback, including
             * enable/disable and both audited modes; no neighbor changes. */
            for (unsigned val=0;val<8;val++) {
                v=val; saved=state;
                r=access_word(&m,off,4,1,&v);
                CHECK(r==((val&~mask) ? DEVICE_BAD_VALUE : DEVICE_OK));
                if (!(val&~mask)) saved.pmgr_counter_config[index]=val;
                CHECK(!memcmp(&state,&saved,sizeof(state)));
                if (!(val&~mask)) {
                    v=UINT64_MAX;
                    CHECK(access_word(&m,off,4,0,&v)==DEVICE_OK);
                    CHECK(v==val);
                }
            }
            for (unsigned bit=0;bit<64;bit++) {
                if ((1UL<<bit)&mask) continue;
                v=(1UL<<bit)|mask; saved=state;
                CHECK(access_word(&m,off,4,1,&v)==DEVICE_BAD_VALUE);
                CHECK(v==((1UL<<bit)|mask));
                CHECK(!memcmp(&state,&saved,sizeof(state)));
            }
            for (unsigned width=1;width<=8;width*=2) {
                if (width==4) continue;
                for (int write=0;write<=1;write++) {
                    v=1;saved=state;
                    CHECK(access_word(&m,off,width,write,&v)==DEVICE_BAD_WIDTH);
                    CHECK(v==1 && !memcmp(&state,&saved,sizeof(state)));
                }
            }
            for (unsigned delta=1;delta<=3;delta++) {
                for (int write=0;write<=1;write++) {
                    v=1;saved=state;
                    CHECK(access_word(&m,off+delta,4,write,&v)==DEVICE_BAD_WIDTH);
                    CHECK(v==1 && !memcmp(&state,&saved,sizeof(state)));
                }
            }
        }
        CHECK(found==count+1);
        /* Global disable preserves per-counter settings; each VM/descriptor
         * owns its own latches. Reset affects only this model's union member. */
        uint64_t v=5;
        CHECK(access_word(&m,base+0x100,4,1,&v)==DEVICE_OK);
        v=0;saved=state;
        CHECK(access_word(&m,base,4,1,&v)==DEVICE_OK);
        saved.pmgr_counter_config[0]=0;
        CHECK(!memcmp(&state,&saved,sizeof(state)));
        memset(&other,0,sizeof(other));
        v=UINT64_MAX;
        CHECK(device_model_access_state(&m,&other,base+0x100,4,0,&v)==DEVICE_OK && v==0);
        CHECK(state.pmgr_counter_config[1]==5);
        state.dram_policy=UINT64_MAX;saved=state;
        for (unsigned i=0;i<70;i++) saved.pmgr_counter_config[i]=0;
        CHECK(device_model_start(&m,&state,123,24000000)==DEVICE_OK);
        CHECK(!memcmp(&state,&saved,sizeof(state)));
        v=3;saved=state;
        CHECK(access_word(&m,0x1000,4,0,&v)==DEVICE_NOT_FOUND);
        CHECK(v==3 && !memcmp(&state,&saved,sizeof(state)));
        CHECK(device_model_access_state(&m,0,base,4,0,&v)==DEVICE_BAD_CONFIG);
        CHECK(device_model_access_state(&m,&state,base,4,0,0)==DEVICE_BAD_CONFIG);
        for (unsigned i=0;i<5;i++) {
            struct device_model bad=m;
            bad.config[i]=i ? 1 : 8;
            CHECK(!device_models_valid(&bad,1,0,0));
            CHECK(device_model_access_state(&bad,&state,base,4,1,&v)==DEVICE_BAD_CONFIG);
            CHECK(!memcmp(&state,&saved,sizeof(state)));
        }
        m.span=0x4000;
        CHECK(!device_models_valid(&m,1,0,0));
    }
    if (!topology) printf("PMGR counter configuration: %u checks passed\n",checks);
    return 0;
}

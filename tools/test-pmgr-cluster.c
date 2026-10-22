/* SPDX-License-Identifier: MIT */
/* Replay the stock cluster-enable RMW/poll and independent gating policies. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "device.h"

static unsigned checks;
#define CHECK(x) do { checks++; if (!(x)) { \
    fprintf(stderr,"line %u: %s\n",__LINE__,#x); exit(1); } } while (0)
static struct device_state states[2], saved, other;
static const struct device_model models[]={
    {DEVICE_PMGR_CPU_CLUSTER_ACTIVE_V1,0x300780000,0x1000,{0,0,0,0,0}},
    {DEVICE_PMGR_SOC_GATE_POLICY_V1,0x300724000,0x1000,{0,0,0,0,0}},
};
static const unsigned gates[]={0,0x40,0x60,0x68};
static enum device_result access_word(unsigned model,unsigned off,unsigned width,
                                     int write,uint64_t *v)
{
    return device_model_access_state(&models[model],&states[model],off,width,write,v);
}

int main(void)
{
    CHECK(device_models_valid(models,2,0,0));
    for (unsigned m=0;m<2;m++) {
        CHECK(device_model_start(&models[m],&states[m],0,24000000)==DEVICE_OK);
        /* Exhaust the page: unknown offsets must neither return data nor
         * corrupt the neighboring policy/transport state. */
        unsigned admitted=0;
        for (unsigned off=0;off<0x1000;off+=4) {
            int index=-1;
            if (!m && off<=4) index=(int)(off/4);
            if (m) for (unsigned i=0;i<4;i++) if (off==gates[i]) index=(int)i;
            uint64_t v=0x13579bdf;saved=states[m];
            if (index<0) {
                for (int write=0;write<=1;write++) {
                    CHECK(access_word(m,off,4,write,&v)==DEVICE_UNKNOWN_REGISTER);
                    CHECK(v==0x13579bdf && !memcmp(&states[m],&saved,sizeof(saved)));
                }
                continue;
            }
            admitted++;
            CHECK(access_word(m,off,4,0,&v)==DEVICE_OK);
            CHECK(v==(m ? 0 : 15));
            CHECK(!memcmp(&states[m],&saved,sizeof(saved)));
            /* AppleT8140PMGR preserves the upper bits, requests active in
             * bits 0..3, then polls bit 4 for zero. */
            if (!m) {
                v=(v&~15UL)|15;
                CHECK(access_word(m,off,4,1,&v)==DEVICE_OK);
                v=UINT64_MAX;
                CHECK(access_word(m,off,4,0,&v)==DEVICE_OK);
                CHECK((v&0x10)==0 && (v&15)==15);
                CHECK(!memcmp(&states[m],&saved,sizeof(saved)));
                for (unsigned requested=0;requested<16;requested++) {
                    v=requested;
                    CHECK(access_word(m,off,4,1,&v)==
                          (requested==15 ? DEVICE_OK : DEVICE_BAD_VALUE));
                    CHECK(v==requested && !memcmp(&states[m],&saved,sizeof(saved)));
                }
            } else {
                /* restoreHW sets bit 31; enableCPMPowerDomainGating can
                 * clear it. No request changes another word or instance. */
                for (unsigned enabled=0;enabled<4;enabled++) {
                    v=UINT64_MAX;
                    CHECK(access_word(m,off,4,0,&v)==DEVICE_OK);
                    v=(v&0x7fffffff)|((uint64_t)(enabled&1)<<31);
                    CHECK(access_word(m,off,4,1,&v)==DEVICE_OK);
                    saved.pmgr_soc_gate[index]=(uint32_t)v;
                    CHECK(!memcmp(&states[m],&saved,sizeof(saved)));
                    v=UINT64_MAX;
                    CHECK(access_word(m,off,4,0,&v)==DEVICE_OK);
                    CHECK(v==((uint64_t)(enabled&1)<<31));
                }
            }
            for (unsigned bit=0;bit<64;bit++) {
                v=(m ? 0x80000000UL : 15UL)^(1UL<<bit);
                uint64_t input=v;saved=states[m];
                int valid=m && bit==31;
                CHECK(access_word(m,off,4,1,&v)==(valid ? DEVICE_OK : DEVICE_BAD_VALUE));
                if (valid) saved.pmgr_soc_gate[index]=0;
                CHECK(v==input && !memcmp(&states[m],&saved,sizeof(saved)));
            }
            for (unsigned width=1;width<=16;width*=2) {
                if (width==4) continue;
                for (int write=0;write<=1;write++) {
                    v=15;saved=states[m];
                    CHECK(access_word(m,off,width,write,&v)==DEVICE_BAD_WIDTH);
                    CHECK(v==15 && !memcmp(&states[m],&saved,sizeof(saved)));
                }
            }
            for (unsigned delta=1;delta<=3;delta++) for (int write=0;write<=1;write++) {
                v=15;saved=states[m];
                CHECK(access_word(m,off+delta,4,write,&v)==DEVICE_BAD_WIDTH);
                CHECK(v==15 && !memcmp(&states[m],&saved,sizeof(saved)));
            }
        }
        CHECK(admitted==(m ? 4 : 2));
        uint64_t v=15;saved=states[m];
        CHECK(access_word(m,0x1000,4,0,&v)==DEVICE_NOT_FOUND);
        CHECK(device_model_access_state(&models[m],0,0,4,0,&v)==DEVICE_BAD_CONFIG);
        CHECK(device_model_access_state(&models[m],&states[m],0,4,0,0)==DEVICE_BAD_CONFIG);
        for (unsigned i=0;i<5;i++) {
            /* config[0] selects a cluster variant (up to the AVE cluster);
             * one past the last variant is the unknown value here. */
            struct device_model bad=models[m];
            bad.config[i]=models[m].kind==DEVICE_PMGR_CPU_CLUSTER_ACTIVE_V1 && !i ?
                DEVICE_PMGR_AVE_CLUSTER_V1+1 : 1;
            CHECK(!device_models_valid(&bad,1,0,0));
            CHECK(device_model_start(&bad,&states[m],0,24000000)==DEVICE_BAD_CONFIG);
            CHECK(device_model_access_state(&bad,&states[m],0,4,1,&v)==DEVICE_BAD_CONFIG);
            CHECK(!memcmp(&states[m],&saved,sizeof(saved)));
        }
        struct device_model bad=models[m];bad.span=0x4000;
        CHECK(!device_models_valid(&bad,1,0,0));
    }
    /* A new VM starts with its own zero policy; reset touches only owned
     * words, preserving the surrounding union and legacy transport state. */
    memset(&other,0,sizeof(other));
    CHECK(device_model_start(&models[1],&other,0,24000000)==DEVICE_OK);
    for (unsigned i=0;i<4;i++) {
        uint64_t v=0x80000000;
        CHECK(access_word(1,gates[i],4,1,&v)==DEVICE_OK);
        CHECK(other.pmgr_soc_gate[i]==0);
    }
    states[1].dram_policy=0xfeed;states[1].ptd_ack=3;
    states[1].pmgr_policy[4]=0xfeedbeef;saved=states[1];
    for (unsigned i=0;i<4;i++) saved.pmgr_soc_gate[i]=0;
    CHECK(device_model_start(&models[1],&states[1],123,24000000)==DEVICE_OK);
    CHECK(!memcmp(&states[1],&saved,sizeof(saved)));
    printf("PMGR CPU cluster and SOC gating: %u checks passed\n",checks);
    return 0;
}

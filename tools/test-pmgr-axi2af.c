/* SPDX-License-Identifier: MIT */
/* Two retained workaround controls per domain, without bus completion. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "device.h"
static unsigned checks;
#define CHECK(x) do { checks++; if (!(x)) { \
    fprintf(stderr,"line %u: %s\n",__LINE__,#x); exit(1); } } while (0)
static struct device_state states[10],saved;
static struct device_model models[10];
static enum device_result access_word(unsigned domain,unsigned off,unsigned width,
                                     int write,uint64_t *v)
{
    return device_model_access_state(&models[domain],&states[domain],off,width,write,v);
}
int main(int argc,char **argv)
{
    for (unsigned i=0;i<10;i++) {
        models[i]=(struct device_model){DEVICE_PMGR_AXI2AF_POLICY_V1,
            0x1000000+0x1000*i,0x1000,{0,0,0,0,0}};
        CHECK(device_model_start(&models[i],&states[i],0,24000000)==DEVICE_OK);
    }
    CHECK(device_models_valid(models,10,0,0));
    if (argc==2 && !strcmp(argv[1],"--registers")) {
        for (unsigned off=0;off<0x1000;off+=4) {
            uint64_t v=0;
            if (access_word(0,off,4,0,&v)==DEVICE_OK) printf("%u\n",off);
        }
        return 0;
    }
    /* Replay force-enable for ten independent domains. The stock helper
     * reads each word and ORs one; repeated restore is idempotent. */
    for (unsigned pass=0;pass<2;pass++) for (unsigned domain=0;domain<10;domain++) {
        for (unsigned word=0;word<2;word++) {
            uint64_t v=UINT64_MAX;
            CHECK(access_word(domain,0x104+4*word,4,0,&v)==DEVICE_OK);
            CHECK(v==(pass ? 1 : 0));v|=1;
            CHECK(access_word(domain,0x104+4*word,4,1,&v)==DEVICE_OK);
        }
        for (unsigned j=0;j<10;j++) for (unsigned word=0;word<2;word++)
            CHECK(states[j].pmgr_axi2af[word]==((pass || j<=domain) ? 1 : 0));
    }
    for (unsigned domain=0;domain<10;domain++) for (unsigned pattern=0;pattern<4;pattern++) {
        for (unsigned word=0;word<2;word++) {
            uint64_t v=(pattern>>word)&1;saved=states[domain];
            CHECK(access_word(domain,0x104+4*word,4,1,&v)==DEVICE_OK);
            saved.pmgr_axi2af[word]=(uint32_t)v;
            CHECK(!memcmp(&saved,&states[domain],sizeof(saved)));
        }
        for (unsigned word=0;word<2;word++) {
            uint64_t v=UINT64_MAX;
            CHECK(access_word(domain,0x104+4*word,4,0,&v)==DEVICE_OK);
            CHECK(v==((pattern>>word)&1));
        }
    }
    for (unsigned off=0;off<0x1000;off+=4) {
        uint64_t v=1;saved=states[0];
        if (off!=0x104 && off!=0x108) {
            for (int write=0;write<=1;write++) {
                CHECK(access_word(0,off,4,write,&v)==DEVICE_UNKNOWN_REGISTER);
                CHECK(v==1 && !memcmp(&states[0],&saved,sizeof(saved)));
            }
            continue;
        }
        for (unsigned bit=1;bit<64;bit++) for (unsigned enabled=0;enabled<2;enabled++) {
            v=(1UL<<bit)|enabled;uint64_t input=v;
            CHECK(access_word(0,off,4,1,&v)==DEVICE_BAD_VALUE);
            CHECK(v==input && !memcmp(&states[0],&saved,sizeof(saved)));
        }
        for (unsigned width=1;width<=16;width*=2) {
            if (width==4) continue;
            for (int write=0;write<=1;write++) {
                v=1;CHECK(access_word(0,off,width,write,&v)==DEVICE_BAD_WIDTH);
                CHECK(v==1 && !memcmp(&states[0],&saved,sizeof(saved)));
            }
        }
        for (unsigned delta=1;delta<=3;delta++) for (int write=0;write<=1;write++) {
            v=1;CHECK(access_word(0,off+delta,4,write,&v)==DEVICE_BAD_WIDTH);
            CHECK(v==1 && !memcmp(&states[0],&saved,sizeof(saved)));
        }
    }
    uint64_t v=1;saved=states[0];
    CHECK(access_word(0,0x1000,4,1,&v)==DEVICE_NOT_FOUND);
    CHECK(device_model_access_state(&models[0],0,0x104,4,1,&v)==DEVICE_BAD_CONFIG);
    CHECK(device_model_access_state(&models[0],&states[0],0x104,4,1,0)==DEVICE_BAD_CONFIG);
    for (unsigned i=0;i<5;i++) {
        struct device_model bad=models[0];bad.config[i]=1;
        CHECK(!device_models_valid(&bad,1,0,0));
        CHECK(device_model_start(&bad,&states[0],0,24000000)==DEVICE_BAD_CONFIG);
        CHECK(device_model_access_state(&bad,&states[0],0x104,4,1,&v)==DEVICE_BAD_CONFIG);
        CHECK(!memcmp(&states[0],&saved,sizeof(saved)));
    }
    struct device_model bad=models[0];bad.span=0x4000;
    CHECK(!device_models_valid(&bad,1,0,0));
    states[0].dram_policy=0xfeed;states[0].pmgr_policy[2]=0xfeedbeef;saved=states[0];
    saved.pmgr_axi2af[0]=saved.pmgr_axi2af[1]=0;
    CHECK(device_model_start(&models[0],&states[0],123,24000000)==DEVICE_OK);
    CHECK(!memcmp(&states[0],&saved,sizeof(saved)));
    printf("PMGR AXI2AF policy: %u checks passed\n",checks);
    return 0;
}

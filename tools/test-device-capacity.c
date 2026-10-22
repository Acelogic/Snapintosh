/* SPDX-License-Identifier: MIT */
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "device.h"
static unsigned checks;
#define CHECK(x) do { checks++; assert(x); } while (0)
static struct device_model models[DEVICE_MODEL_MAX];
static struct device_state states[DEVICE_MODEL_MAX],saved;
/* Replay the stock CLPC nine-lane selection at 9b8225c/9b82320:
 * an all-zero register disables the channel, then the highest admitted
 * CPU count no greater than the topology count is selected. */
static int clpc_cpu_count(uint64_t table,unsigned weight,unsigned cpus)
{
    if(!(table&0x1fffffffffffUL))return -1;
    for(int cpu=8;cpu>=0;cpu--)
        if((unsigned)cpu<=cpus && ((table>>(5*cpu))&31)<=weight)return cpu;
    return -1;
}
int main(void)
{
    CHECK(DEVICE_MODEL_MAX==128 && DEVICE_RESET_WORDS==2);
    for(unsigned i=0;i<DEVICE_MODEL_MAX;i++) {
        models[i]=(struct device_model){DEVICE_PMGR_CPU_PERF_BOOT_V1,
            0x1000000UL+i*0x2000,0x1000,{0}};
        CHECK(device_model_start(&models[i],&states[i],0,24000000)==DEVICE_OK);
    }
    CHECK(device_models_valid(models,DEVICE_MODEL_MAX,0,0));
    uint64_t offset=0;
    CHECK(device_model_find(models,DEVICE_MODEL_MAX,models[127].base+0x48,&offset)==127 && offset==0x48);
    CHECK(!device_models_valid(models,DEVICE_MODEL_MAX+1,0,0));
    const unsigned producers[]={0,63,64,127};
    for(unsigned i=0;i<4;i++) {
        unsigned n=producers[i];models[n].kind=DEVICE_WATCHDOG_WD1_V1;
        models[n].config[0]=24000000;
        CHECK(device_model_start(&models[n],&states[n],100,24000000)==DEVICE_OK);
        CHECK(device_model_access_at(&models[n],&states[n],100,0x14,4,1,&(uint64_t){100})==DEVICE_OK);
        CHECK(device_model_access_at(&models[n],&states[n],100,0x1c,4,1,&(uint64_t){4})==DEVICE_OK);
        CHECK(device_model_wait(&models[n],&states[n],200,1000)==0);
    }
    uint64_t bits[DEVICE_RESET_WORDS]={0};
    CHECK(device_latch_resets(models,states,DEVICE_MODEL_MAX,bits)==DEVICE_OK);
    CHECK(bits[0]==(1UL|(1UL<<63)) && bits[1]==(1UL|(1UL<<63)));
    CHECK(device_latch_resets(0,0,0,bits)==DEVICE_OK);
    CHECK(bits[0]==(1UL|(1UL<<63)) && bits[1]==(1UL|(1UL<<63)));
    CHECK(device_latch_resets(models,states,DEVICE_MODEL_MAX+1,bits)==DEVICE_BAD_CONFIG);
    CHECK(device_latch_resets(0,states,1,bits)==DEVICE_BAD_CONFIG);
    CHECK(device_latch_resets(models,0,1,bits)==DEVICE_BAD_CONFIG);
    CHECK(device_latch_resets(models,states,1,0)==DEVICE_BAD_CONFIG);
    models[127].config[4]=1;bits[0]=bits[1]=0;
    CHECK(device_latch_resets(models,states,DEVICE_MODEL_MAX,bits)==DEVICE_BAD_CONFIG);
    CHECK(!bits[0] && !bits[1]);
    struct device_model *m=&models[1];saved=states[1];
    for(unsigned off=0;off<m->span;off+=8) {
        uint64_t value=UINT64_MAX;
        enum device_result result=device_model_access_state(m,&states[1],off,8,0,&value);
        CHECK(result==(off==0x48 ? DEVICE_OK : DEVICE_UNKNOWN_REGISTER));
        CHECK(value==(off==0x48 ? 0 : UINT64_MAX));
        value=UINT64_MAX;
        CHECK(device_model_access_state(m,&states[1],off,8,1,&value)==
            (off==0x48 ? DEVICE_READ_ONLY : DEVICE_UNKNOWN_REGISTER));
        CHECK(value==UINT64_MAX && !memcmp(&states[1],&saved,sizeof(saved)));
    }
    for(unsigned width=0;width<=16;width++) if(width!=8) {
        uint64_t v=1;
        CHECK(device_model_access(m,0x48,width,0,&v)==DEVICE_BAD_WIDTH && v==1);
    }
    for(unsigned i=1;i<8;i++) {
        uint64_t v=1;
        CHECK(device_model_access(m,0x48+i,8,0,&v)==DEVICE_BAD_WIDTH && v==1);
    }
    struct device_model bad_group=*m;bad_group.config[0]=2;
    CHECK(!device_models_valid(&bad_group,1,0,0));
    for(unsigned i=1;i<5;i++) {
        struct device_model bad=*m;bad.config[i]=1;
        CHECK(!device_models_valid(&bad,1,0,0));
    }
    struct device_model bad=*m;bad.span=0x4000;
    CHECK(!device_models_valid(&bad,1,0,0));
    struct device_model fane=*m;fane.config[0]=1;
    CHECK(device_models_valid(&fane,1,0,0));
    uint64_t fane_word=UINT64_MAX;
    CHECK(device_model_access_state(&fane,&states[1],0x50,8,0,&fane_word)==DEVICE_OK);
    CHECK(fane_word==((1UL<<29)|(1UL<<34)|(1UL<<39)) && !memcmp(&states[1],&saved,sizeof(saved)));
    /* The stock getter publishes these indices as fANE0/1/2. CLPC converts
     * them through ANEFrequencies and DVMR classification before filtering
     * zero frequencies. Index one has active ANE frequency metadata. */
    for(unsigned index=0;index<3;index++) CHECK(((fane_word>>(29+5*index))&31)==1);
    for(unsigned off=0;off<fane.span;off+=8) {
        uint64_t v=UINT64_MAX;
        int known=off==0x48 || off==0x50;
        CHECK(device_model_access(&fane,off,8,0,&v)==(known ? DEVICE_OK : DEVICE_UNKNOWN_REGISTER));
        CHECK(v==(off==0x50 ? fane_word : off==0x48 ? 0 : UINT64_MAX));
        v=UINT64_MAX;
        CHECK(device_model_access(&fane,off,8,1,&v)==(known ? DEVICE_READ_ONLY : DEVICE_UNKNOWN_REGISTER));
        CHECK(v==UINT64_MAX);
    }
    for(unsigned width=0;width<=16;width++) if(width!=8) {
        uint64_t v=1;
        CHECK(device_model_access(&fane,0x50,width,0,&v)==DEVICE_BAD_WIDTH && v==1);
    }
    for(unsigned delta=1;delta<8;delta++) {
        uint64_t v=1;
        CHECK(device_model_access(&fane,0x50+delta,8,0,&v)==DEVICE_BAD_WIDTH && v==1);
    }
    for(unsigned cluster=0;cluster<2;cluster++) {
        struct device_model table={DEVICE_PMGR_DVMR_WEIGHTS_V1,
            0x210e70000UL+cluster*0x1000000UL,0x1000,{cluster,0,0,0,0}};
        CHECK(device_models_valid(&table,1,0,0));
        unsigned found=0;
        for(unsigned off=0;off<table.span;off+=8) {
            /* Stateful energy enables have independent read/write and
             * corruption coverage in test-pmgr-energy.c. */
            if(off==0x178)continue;
            int known=off==0xa8 || off==0xd0 || (cluster && (off==0xb0 || off==0xd8));
            uint64_t v=UINT64_MAX;
            CHECK(device_model_access_state(&table,&states[1],off,8,0,&v)==
                (known ? DEVICE_OK : DEVICE_UNKNOWN_REGISTER));
            CHECK(v==(known ? (cluster && off==0xb0 ? 0x1fffffff8000UL : 0) : UINT64_MAX));
            if(cluster && off==0xb0) {
                CHECK(clpc_cpu_count(0,0,2)==-1);
                for(unsigned cpus=0;cpus<=2;cpus++)
                    for(unsigned weight=0;weight<32;weight++)
                        CHECK(clpc_cpu_count(v,weight,cpus)==(int)cpus);
                /* ANE-only type for two CPUs is 7 (native table 76e5bb1).
                 * CLPC classifies it as two and preserves all three
                 * nonzero frequencies (9b82be0/9b82c00/9b82c58). */
                int classification=clpc_cpu_count(v,0,2);
                for(int component=0;component<3;component++)
                    CHECK(classification>=component);
                CHECK((v>>45)==0);
            }
            CHECK(!memcmp(&states[1],&saved,sizeof(saved)));
            v=UINT64_MAX;
            CHECK(device_model_access(&table,off,8,1,&v)==
                (known ? DEVICE_READ_ONLY : DEVICE_UNKNOWN_REGISTER));
            CHECK(v==UINT64_MAX);
            if(!known)continue;
            found++;
            for(unsigned width=0;width<=16;width++) if(width!=8) {
                v=1;CHECK(device_model_access(&table,off,width,0,&v)==DEVICE_BAD_WIDTH && v==1);
            }
            for(unsigned delta=1;delta<8;delta++) {
                v=1;CHECK(device_model_access(&table,off+delta,8,0,&v)==DEVICE_BAD_WIDTH && v==1);
            }
        }
        CHECK(found==(cluster ? 4u : 2u));
        bad=table;bad.config[0]=2;CHECK(!device_models_valid(&bad,1,0,0));
        for(unsigned i=1;i<5;i++) {
            bad=table;bad.config[i]=1;CHECK(!device_models_valid(&bad,1,0,0));
        }
    }
    printf("device capacity and DVMR: %u checks passed\n",checks);
}

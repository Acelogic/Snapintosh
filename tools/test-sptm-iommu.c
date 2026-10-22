/* SPDX-License-Identifier: MIT */
/* Link sptm.c, sptm-refs.c, device.c, dart.c, aic.c, watchdog.c, clock.c. */
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "sptm-refs.h"
#include "device.h"

#define BASE 0x90000000UL
#define SIZE 0x20000UL
#define FM (BASE+0x1000)
#define PAGE (BASE+0x8000)
#define TABLE (BASE+0xc000)
static uint8_t ram[SIZE], saved[SIZE];
static struct device_model models[5];
static struct device_state states[5], saved_states[5];
static struct sptm_ref_batch refs;
static unsigned checks, published, model_count;
static uint64_t unavailable;
#define CHECK(x) do { checks++; if (!(x)) { fprintf(stderr,"FAIL %d: %s\n",__LINE__,#x); assert(x); } } while (0)
static uint8_t *entry(uint64_t pa) { return ram+0x1000+((pa-BASE)>>14)*16; }
static volatile uint8_t *map(void *ctx,uint64_t pa,uint64_t size)
{
    CHECK(ctx==states);
    if (pa==unavailable || pa<BASE || pa>=BASE+SIZE || size>BASE+SIZE-pa) return 0;
    return ram+(pa-BASE);
}
static void publish(void *ctx,uint64_t pa,uint64_t size)
{
    CHECK(ctx==states && pa==FM+((PAGE-BASE)>>14)*16 && size==16);
    CHECK(entry(PAGE)[2]==24);
    published++;
}
static int admit(void *ctx,unsigned cls,unsigned id,unsigned sid,unsigned level)
{
    CHECK(ctx==states);
    return device_dart_admit_frame(models,states,model_count,cls,id,sid,level,0)==DEVICE_OK;
}
static uint64_t options(unsigned id,unsigned sid,unsigned level)
{ return 5UL|((uint64_t)id<<32)|((uint64_t)sid<<40)|((uint64_t)level<<48); }
static void snapshot(void)
{
    memcpy(saved,ram,sizeof(ram));memcpy(saved_states,states,sizeof(states));
    published=0;
}
static struct sptm_memory reset(void)
{
    memset(ram,0xa5,sizeof(ram));
    memset(ram+0x1000,0,SIZE/0x4000*16);
    for (uint64_t pa=BASE;pa<BASE+SIZE;pa+=0x4000) entry(pa)[2]=11;
    models[0]=(struct device_model){DEVICE_AIC3_FLAT_V1,0x301000000UL,0x1cc000,{1280,4096,0x40000,10,0}};
    models[1]=(struct device_model){DEVICE_DART_T8110_V1,0x385060000UL,0x20000,{16,DEVICE_DART_SIO_BOOT_V1,1120,36,1U<<21}};
    models[2]=models[1];models[2].base+=0x20000;
    memset(states,0,sizeof(states));model_count=2;unavailable=0;
    for (unsigned i=0;i<model_count;i++)
        CHECK(device_model_start(&models[i],&states[i],0,24000000)==DEVICE_OK);
    CHECK(device_dart_monitor_init(models,states,model_count,21)==DEVICE_OK);
    CHECK(device_dart_monitor_powerup(models,states,model_count,21)==DEVICE_OK);
    snapshot();
    return (struct sptm_memory){.frame_map_pa=FM,.frame_low=BASE,.frame_high=BASE+SIZE,
        .alloc_low=PAGE,.alloc_high=BASE+SIZE,.map=map,.publish=publish,.ctx=states,
        .refs=&refs,.admit_iommu=admit};
}
static void refused(struct sptm_memory *m,uint64_t old,uint64_t next,uint64_t opts,
                    enum sptm_result want)
{
    snapshot();
    CHECK(sptm_mac_retype(m,PAGE,old,next,opts)==want);
    CHECK(!published && !memcmp(ram,saved,sizeof(ram)));
    CHECK(!memcmp(states,saved_states,sizeof(states)));
}
static struct sptm_memory reset_sep(void)
{
    struct sptm_memory m=reset();
    memset(models,0,sizeof(models));memset(states,0,sizeof(states));model_count=4;
    models[0]=(struct device_model){18,0x300700000,0x11000,{0,0,0,0,0}};
    models[1]=(struct device_model){17,0x280b80000,0x20000,{3,DEVICE_DART_SEP_BOOT_V1,353,36,1U<<20}};
    models[2]=(struct device_model){25,0x3003c0000,0x14000,{0x10000,0x1a8,0x1b8,8,DEVICE_PMP_ACTIVE_MASK}};
    models[3]=(struct device_model){18,0x308280000,0x9000,{1,0,0,0,0}};
    for (unsigned i=0;i<model_count;i++)
        CHECK(device_model_start(models+i,states+i,0,24000000)==DEVICE_OK);
    CHECK(device_models_valid(models,model_count,0,0));
    CHECK(device_dart_monitor_init(models,states,model_count,20)==DEVICE_OK);
    CHECK(device_dart_monitor_powerup(models,states,model_count,20)==DEVICE_OK);
    snapshot();return m;
}
static void test_sep(void)
{
    struct sptm_memory m;
    for (unsigned sid=0;sid<2;sid++) for (unsigned level=0;level<4;level++) {
        m=reset_sep();
        CHECK(sptm_mac_retype(&m,PAGE,11,24,options(20,sid,level))==SPTM_OK);
        uint8_t expected[16]={0,0,24,0,0,0,5,0,20,(uint8_t)sid,(uint8_t)level,0,0,0,0,0};
        CHECK(!memcmp(entry(PAGE),expected,16));
        memcpy(saved+(entry(PAGE)-ram),expected,16);
        CHECK(published==1 && !memcmp(ram,saved,sizeof(ram)));
        CHECK(!memcmp(states,saved_states,sizeof(states)));
        refused(&m,11,24,options(20,sid,level),SPTM_TYPE_MISMATCH);
    }
    for (unsigned mutation=0;mutation<9;mutation++) {
        m=reset_sep();
        if(mutation==0)states[1].dart.initialized_ids=0;
        if(mutation==1)states[1].dart.powered_ids=0;
        if(mutation==2)states[1].dart.tcr[0]=9;
        if(mutation==3)states[2].pmp_active.request|=1UL<<27;
        if(mutation==4)states[2].pmp_active.ack|=1UL<<27;
        if(mutation==5)model_count=3;
        if(mutation==6)models[1].config[1]=44;
        if(mutation==7)models[1].base+=0x20000;
        if(mutation==8)models[1].config[4]=1U<<19;
        refused(&m,11,24,options(20,0,1),SPTM_UNSUPPORTED_OPTIONS);
    }
    m=reset_sep();
    for(unsigned sid=2;sid<256;sid++)refused(&m,11,24,options(20,sid,1),SPTM_UNSUPPORTED_OPTIONS);
    for(unsigned level=4;level<256;level++)refused(&m,11,24,options(20,0,level),SPTM_UNSUPPORTED_OPTIONS);
}
int main(void)
{
    test_sep();
    struct sptm_memory m;
    m=reset();unsigned selected=99;
    CHECK(device_dart_admit_frame(models,states,model_count,5,21,1,0,&selected)==DEVICE_OK && selected==1);
    CHECK(device_dart_admit_frame(models,states,model_count,5,20,1,0,&selected)==DEVICE_NOT_FOUND && selected==1);
    for (unsigned sid=0;sid<2;sid++) for (unsigned level=0;level<4;level++) {
        m=reset();
        CHECK(sptm_mac_retype(&m,PAGE,11,24,options(21,sid,level))==SPTM_OK);
        uint8_t expected[16]={0,0,24,0,0,0,5,0,21,(uint8_t)sid,(uint8_t)level,0,0,0,0,0};
        CHECK(!memcmp(entry(PAGE),expected,16));
        memcpy(saved+(entry(PAGE)-ram),expected,16);
        CHECK(published==1 && !memcmp(ram,saved,sizeof(ram)));
        CHECK(!memcmp(states,saved_states,sizeof(states)));
        refused(&m,11,24,options(21,sid,level),SPTM_TYPE_MISMATCH);
        refused(&m,24,11,0,SPTM_UNSUPPORTED_RETYPE);
        /* Ordinary CPU accounting must never overwrite IOMMU ownership. */
        entry(TABLE)[2]=20;entry(TABLE)[4]=3;
        snapshot();
        for (unsigned remove=0;remove<2;remove++) {
            entry(TABLE)[8]=(uint8_t)remove;snapshot();
            sptm_refs_begin(&refs);
            uint64_t pte=PAGE|0x00600000000007c3UL;
            CHECK(sptm_refs_leaf(&m,TABLE,0,remove?pte:0,remove?0:pte)==SPTM_TYPE_MISMATCH);
            CHECK(!memcmp(ram,saved,sizeof(ram)) && !published);
        }
        sptm_refs_begin(&refs);
        CHECK(sptm_refs_leaf(&m,PAGE,0,0,TABLE|3)==SPTM_TYPE_MISMATCH);
        CHECK(!memcmp(ram,saved,sizeof(ram)) && !published);
    }
    m=reset();m.admit_iommu=0;
    refused(&m,11,24,options(21,1,0),SPTM_BAD_CONFIG);
    m=reset();
    for (unsigned bit=0;bit<64;bit++)
        if ((bit>=8 && bit<32) || bit>=56)
            refused(&m,11,24,options(21,1,0)|(1UL<<bit),SPTM_UNSUPPORTED_OPTIONS);
    for (unsigned cls=0;cls<256;cls++) if (cls!=5)
        refused(&m,11,24,(options(21,1,0)&~255UL)|cls,SPTM_UNSUPPORTED_OPTIONS);
    for (unsigned id=0;id<256;id++) if (id!=21)
        refused(&m,11,24,options(id,1,0),SPTM_UNSUPPORTED_OPTIONS);
    for (unsigned sid=2;sid<256;sid++)
        refused(&m,11,24,options(21,sid,0),SPTM_UNSUPPORTED_OPTIONS);
    for (unsigned level=4;level<256;level++)
        refused(&m,11,24,options(21,1,level),SPTM_UNSUPPORTED_OPTIONS);
    for (unsigned byte=0;byte<16;byte++) if (byte<2 || byte==4 || byte>=8) {
        m=reset();entry(PAGE)[byte]=1;
        refused(&m,11,24,options(21,1,0),SPTM_FRAME_BUSY);
    }
    for (unsigned i=0;i<2;i++) {
        m=reset();unavailable=i?PAGE:FM+((PAGE-BASE)>>14)*16;
        refused(&m,11,24,options(21,1,0),SPTM_MEMORY_UNAVAILABLE);
    }
    for (unsigned i=0;i<7;i++) {
        m=reset();
        if(i==0) states[1].dart.initialized_ids=0;
        if(i==1) states[1].dart.powered_ids=0;
        if(i==2) states[1].dart.tcr[1]=0x89;
        if(i==3) states[1].dart.tcr[1]=1;
        if(i==4) model_count=3;
        if(i==5) models[1].config[1]=44;
        if(i==6) models[1].config[4]=0;
        refused(&m,11,24,options(21,1,0),SPTM_UNSUPPORTED_OPTIONS);
    }
    /* Logical ID follows the validated model binding, not a hardcoded 21. */
    m=reset();models[1].config[4]=1U<<7;
    states[1].dart.initialized_ids=states[1].dart.powered_ids=1U<<7;
    CHECK(sptm_mac_retype(&m,PAGE,11,24,options(7,0,3))==SPTM_OK);
    CHECK(entry(PAGE)[8]==7 && entry(PAGE)[10]==3);
    printf("sptm-iommu: %u checks passed\n",checks);
    return 0;
}

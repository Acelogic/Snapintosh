/* SPDX-License-Identifier: MIT */
/* Idle media subgraph lifecycle, dependencies and power-history semantics. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "device.h"
static unsigned checks;
#define CHECK(x) do { checks++; if (!(x)) { \
    fprintf(stderr,"line %u: %s\n",__LINE__,#x); exit(1); } } while (0)
static struct device_state state,saved,other;
static const struct device_model model={DEVICE_PMGR_ACTIVE_BOOT_V1,
    0x300700000,0x11000,{0,0,0,0,0}};
#ifdef PMGR_TEST_MISC
#define DOMAIN_COUNT 3
#define DOMAIN_BASE 0x170
#define FIRST_TREE 1
#define DOMAIN_NAME "MISC"
#define SUBSTATES(s) ((s).pmgr_misc)
static const unsigned parents[3]={0,0,0};
#elif defined(PMGR_TEST_PWM)
#define DOMAIN_COUNT 2
#define DOMAIN_BASE 0x2b8
#define FIRST_TREE 1
#define DOMAIN_NAME "PWM"
#define SUBSTATES(s) ((s).pmgr_aux)
static const unsigned parents[2]={0x260,0x260};
#elif defined(PMGR_TEST_ASE)
#define DOMAIN_COUNT 1
#define DOMAIN_BASE 0x298
#define FIRST_TREE 1
#define DOMAIN_NAME "ASE"
#define SUBSTATES(s) ((s).pmgr_aux+2)
static const unsigned parents[1]={0x238};
#elif defined(PMGR_TEST_SENSOR)
#define DOMAIN_COUNT 2
#define DOMAIN_BASE 0x188
#define FIRST_TREE 1
#define DOMAIN_NAME "SENSOR"
#define SUBSTATES(s) ((s).pmgr_aux+3)
static const unsigned parents[2]={0,0};
#elif defined(PMGR_TEST_SPI)
#define DOMAIN_COUNT 5
#define DOMAIN_BASE 0x330
#define FIRST_TREE 1
#define DOMAIN_NAME "SPI"
#define SUBSTATES(s) ((s).pmgr_spi)
static const unsigned parents[5]={0x2f0,0x2f0,0x2f0,0x2f0,0x2f0};
#elif defined(PMGR_TEST_I2C)
#define DOMAIN_COUNT 5
#define DOMAIN_BASE 0x2c8
#define FIRST_TREE 1
#define DOMAIN_NAME "I2C"
#define SUBSTATES(s) ((s).pmgr_i2c)
static const unsigned parents[5]={0x260,0x260,0x260,0x260,0x260};
#elif defined(PMGR_TEST_DPA)
#define DOMAIN_COUNT 2
#define DOMAIN_BASE 0x390
#define FIRST_TREE 1
#define DOMAIN_NAME "DPA"
#define SUBSTATES(s) ((s).pmgr_dpa)
static const unsigned parents[2]={0x300,0x300};
#elif defined(PMGR_TEST_ISP)
#define DOMAIN_COUNT 13
#define DOMAIN_BASE 0x4000
#define FIRST_TREE 3
#define DOMAIN_NAME "ISP"
#define SUBSTATES(s) ((s).pmgr_isp)
/* Independent expectation from the DT's device IDs 106..118. */
static const unsigned parents[13]={0x268,0x4000,0x4000,0x268,0x4018,0x4018,
    0x4018,0x4018,0x4018,0x4018,0x4048,0x4048,0x4058};
#else
#define DOMAIN_COUNT 10
#define DOMAIN_BASE 0x8000
#define FIRST_TREE 5
#define DOMAIN_NAME "VENC"
#define SUBSTATES(s) ((s).pmgr_venc)
/* Independent expectation from the DT's device IDs 119..128. */
static const unsigned parents[10]={0x240,0x8000,0x8000,0x8000,0x8018,
                                  0x248,0x8028,0x8028,0x8028,0x8040};
#endif
static unsigned offset(unsigned unit) {
#ifdef PMGR_TEST_MISC
    static const unsigned offsets[3]={0x170,0x180,0x1a0};return offsets[unit];
#else
    return DOMAIN_BASE+8*unit;
#endif
}
static unsigned level(unsigned unit) { return SUBSTATES(state)[unit]&15; }
static enum device_result access_word(unsigned off,int write,uint64_t *v)
{
    return device_model_access_state(&model,&state,off,4,write,v);
}
static uint64_t read_word(unsigned off)
{
    uint64_t v=UINT64_MAX;
    CHECK(access_word(off,0,&v)==DEVICE_OK);
    return v;
}
static void write_word(unsigned off,uint64_t v)
{
    CHECK(access_word(off,1,&v)==DEVICE_OK);
}
static void refused(unsigned off,uint64_t v)
{
    saved=state;uint64_t input=v;
    CHECK(access_word(off,1,&v)==DEVICE_BAD_VALUE);
    CHECK(v==input && !memcmp(&state,&saved,sizeof(state)));
}
static void reset(void)
{
    CHECK(device_model_start(&model,&state,0,24000000)==DEVICE_OK);
    for (unsigned i=0;i<DOMAIN_COUNT;i++) CHECK(read_word(offset(i))==0xff);
}
static void gate_all(unsigned target)
{
    for (int i=DOMAIN_COUNT-1;i>=0;i--) write_word(offset((unsigned)i),0x3f0|target);
}
static void wake_parents(unsigned unit)
{
    unsigned parent=parents[unit];
    if (parent>=DOMAIN_BASE) {
        unsigned index=(parent-DOMAIN_BASE)/8;
        wake_parents(index);write_word(parent,0x30f);
    } else if (parent) CHECK((read_word(parent)&0xff)==0xff);
}
int main(int argc,char **argv)
{
    int topology=argc==2 && !strcmp(argv[1],"--topology");
    CHECK(device_models_valid(&model,1,0,0));
    reset();
    /* The reached write requests the last subdomain off, ignoring actual
     * bits and clearing old histories. The transition itself sets history. */
    unsigned last=DOMAIN_COUNT-1;
    write_word(offset(last),0x3f0);
    CHECK(read_word(offset(last))==0x100 && level(last)==0);
    if (parents[last]) CHECK(read_word(parents[last])==0xff);
    if (parents[0]) CHECK(read_word(parents[0])==0xff);
    write_word(offset(last),0x100);CHECK(read_word(offset(last))==0);
    write_word(offset(last),0xf);CHECK(read_word(offset(last))==0xff);
    /* Parent-first shutdown must fail without disturbing any state. */
    for (unsigned i=0;i<DOMAIN_COUNT;i++) {
        int has_child=0;
        for (unsigned j=0;j<DOMAIN_COUNT;j++) has_child|=parents[j]==offset(i);
        if (has_child) { refused(offset(i),0x3f0);refused(offset(i),0x3f4); }
    }
    /* Reverse topological gating and forward activation, including W1C
     * histories of direct off and clock-gate transitions. */
    gate_all(4);
    for (unsigned i=0;i<DOMAIN_COUNT;i++) CHECK(read_word(offset(i))==0x244);
    gate_all(0);
    for (unsigned i=0;i<DOMAIN_COUNT;i++) CHECK(read_word(offset(i))==0x100);
    for (unsigned i=0;i<DOMAIN_COUNT;i++) write_word(offset(i),0xf);
    for (unsigned i=0;i<DOMAIN_COUNT;i++) CHECK(read_word(offset(i))==0x1ff);
    for (unsigned i=0;i<DOMAIN_COUNT;i++) write_word(offset(i),0x300|15);
    for (unsigned i=0;i<DOMAIN_COUNT;i++) CHECK(read_word(offset(i))==0xff);
    /* Exercise each edge: a child cannot wake with a gated parent, but
     * succeeds after its ancestor chain has been explicitly activated. */
    for (unsigned i=0;i<DOMAIN_COUNT;i++) {
        reset();gate_all(0);
        if (parents[i]>=DOMAIN_BASE) {
            refused(offset(i),15);refused(offset(i),4);
        }
        wake_parents(i);
        write_word(offset(i),4);CHECK((read_word(offset(i))&0xff)==0x44);
        write_word(offset(i),15);CHECK((read_word(offset(i))&0xff)==0xff);
        if (parents[i]>=DOMAIN_BASE) {
            refused(parents[i],0);refused(parents[i],4);
        }
        write_word(offset(i),0);CHECK((read_word(offset(i))&0xff)==0);
        /* A forged ACTUAL/AUTO_STATE value cannot alter committed state. */
        write_word(offset(i),0x0f0000f0);
        CHECK((read_word(offset(i))&0x0f0000ff)==0);
        for (unsigned target=1;target<15;target++) if (target!=4)
            refused(offset(i),target);
        refused(offset(i),(1UL<<28));refused(offset(i),(1UL<<28)|4);
    }
    reset();
    /* Independent graphs and unrelated system/PMP domains stay isolated. */
    for (int i=FIRST_TREE-1;i>=0;i--) write_word(offset((unsigned)i),0);
    for (unsigned i=FIRST_TREE;i<DOMAIN_COUNT;i++) CHECK(read_word(offset(i))==0xff);
    CHECK(read_word(0x240)==0xff && read_word(0x248)==0xff);
    CHECK(read_word(0x300)==0xff && read_word(0x260)==0xff);
    CHECK(read_word(0x2f0)==0xff);
    refused(0x2f0,0);
    CHECK(read_word(0x238)==0xff);
    refused(0x238,0);
    refused(0x300,0);refused(0x260,0);
    refused(0x240,0);refused(0x248,0);refused(0x280,0);
    CHECK(device_model_start(&model,&other,0,24000000)==DEVICE_OK);
    for (unsigned i=0;i<DOMAIN_COUNT;i++) CHECK(SUBSTATES(other)[i]==15);
    for (unsigned i=0;i<FIRST_TREE;i++) CHECK(level(i)==0);
    reset();
    for (unsigned i=0;i<DOMAIN_COUNT;i++) {
        for (unsigned bit=0;bit<64;bit++) if (!((0x1f0f03ffUL>>bit)&1))
            refused(offset(i),15|(1UL<<bit));
        write_word(offset(i),0x100700ff);
        CHECK(read_word(offset(i))==0x1f0700ff);
    }
    state.dram_policy=0xabcdef;saved=state;
    memset(saved.pmgr_policy,0,sizeof(saved.pmgr_policy));
    for (unsigned i=0;i<10;i++) saved.pmgr_venc[i]=15;
    for (unsigned i=0;i<13;i++) saved.pmgr_isp[i]=15;
    for (unsigned i=0;i<3;i++) saved.pmgr_atc[i]=15;
    for (unsigned i=0;i<2;i++) saved.pmgr_dpa[i]=15;
    for (unsigned i=0;i<5;i++) saved.pmgr_spi[i]=saved.pmgr_i2c[i]=15;
    for (unsigned i=0;i<5;i++) saved.pmgr_aux[i]=15;
    saved.pmgr_ane=15;
    saved.pmgr_avd=15;
    saved.pmgr_isp_sys=15;
    saved.pmgr_prores=15;
    saved.pmgr_venc_sys[0]=saved.pmgr_venc_sys[1]=15;
    saved.pmgr_msr=saved.pmgr_jpg=saved.pmgr_gfx=15;
    for (unsigned i=0;i<3;i++) saved.pmgr_misc[i]=15;
    saved.pmgr_sep_aon=15;
    CHECK(device_model_start(&model,&state,0,24000000)==DEVICE_OK);
    CHECK(!memcmp(&state,&saved,sizeof(state)));
    if (topology) {
        for (unsigned i=0;i<DOMAIN_COUNT;i++) printf("%u %u\n",offset(i),parents[i]);
    } else printf("PMGR " DOMAIN_NAME " lifecycle: %u checks passed\n",checks);
    return 0;
}

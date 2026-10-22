/* SPDX-License-Identifier: MIT */
#define PMGR_TEST_MISC
#define main misc_lifecycle_tests
#include "test-pmgr-venc.c"
#undef main
static struct device_state registry[4],snapshot[4];
static const struct device_model models[]={
    {18,0x300700000,0x11000,{0,0,0,0,0}},
    {18,0x308280000,0x9000,{1,0,0,0,0}},
    {25,0x3003c0000,0x14000,{0x10000,0x1a8,0x1b8,8,DEVICE_PMP_ACTIVE_MASK}},
    {22,0x30827b000,0x1000,{6,0,0,0,0}},
};
static enum device_result mmio(unsigned index,unsigned off,unsigned width,int write,uint64_t *v)
{ return device_models_access_at(models,registry,4,index,0,off,width,write,v); }
static void init(void)
{
    memset(registry,0,sizeof(registry));
    for (unsigned i=0;i<4;i++) CHECK(device_model_start(models+i,registry+i,0,24000000)==DEVICE_OK);
    uint64_t v=0x3000;CHECK(mmio(2,0x10c40,8,1,&v)==DEVICE_OK);
    v=1;CHECK(mmio(3,0x800,4,1,&v)==DEVICE_OK);
}
int main(int argc,char **argv)
{
    int result=misc_lifecycle_tests(argc,argv);
    if (argc==2 && !strcmp(argv[1],"--topology")) return result;
    const unsigned levels[3]={0,4,15};
    /* All three independent-domain configurations and transitions preserve
     * non-PMP state, including active AON counter policy and PMP metadata. */
    for (unsigned before=0;before<27;before++) for (unsigned after=0;after<27;after++) {
        init();unsigned pattern=before;
        for (unsigned i=0;i<3;i++) {
            uint64_t v=levels[pattern%3];pattern/=3;
            CHECK(mmio(0,offset(i),4,1,&v)==DEVICE_OK);
        }
        memcpy(snapshot,registry,sizeof(registry));pattern=after;
        for (unsigned i=0;i<3;i++) {
            uint64_t v=levels[pattern%3];pattern/=3;
            CHECK(mmio(0,offset(i),4,1,&v)==DEVICE_OK);
        }
        CHECK(!memcmp(snapshot+1,registry+1,sizeof(registry)-sizeof(registry[0])));
        pattern=after;
        for (unsigned i=0;i<3;i++) {
            uint64_t v=99;CHECK(mmio(0,offset(i),4,0,&v)==DEVICE_OK);
            CHECK((v&255)==17*levels[pattern%3]);pattern/=3;
        }
    }
    init();
    for (unsigned i=0;i<3;i++) {
        for (unsigned width=0;width<=16;width++) if (width!=4) {
            uint64_t v=0;memcpy(snapshot,registry,sizeof(registry));
            CHECK(mmio(0,offset(i),width,1,&v)==DEVICE_BAD_WIDTH);
            CHECK(!memcmp(snapshot,registry,sizeof(registry)));
        }
        for (unsigned delta=1;delta<=4;delta++) {
            uint64_t v=0;memcpy(snapshot,registry,sizeof(registry));
            CHECK(mmio(0,offset(i)+delta,4,1,&v)==(delta==4 ? DEVICE_UNKNOWN_REGISTER : DEVICE_BAD_WIDTH));
            CHECK(!memcmp(snapshot,registry,sizeof(registry)));
        }
        uint64_t v=0;memcpy(snapshot,registry,sizeof(registry));
        CHECK(mmio(1,offset(i),4,1,&v)==DEVICE_UNKNOWN_REGISTER);
        CHECK(!memcmp(snapshot,registry,sizeof(registry)));
    }
    /* Neighbors and CPU/SEP registers must never enter this leaf whitelist. */
    const unsigned fixed[]={0,8,0x10,0x18,0x30,0x38,0x50,0x58,0x60,0x168,0x178,0x198,0x1a8};
    for (unsigned i=0;i<sizeof(fixed)/sizeof(fixed[0]);i++) {
        uint64_t v=0;memcpy(snapshot,registry,sizeof(registry));
        /* SEP_AON requires a complete SEP/DART ownership binding, which this
         * independent-leaf registry deliberately lacks. */
        CHECK(mmio(0,fixed[i],4,1,&v)==(fixed[i]==0x60 ? DEVICE_BAD_CONFIG : DEVICE_BAD_VALUE));
        CHECK(!memcmp(snapshot,registry,sizeof(registry)));
    }
    printf("PMGR independent-leaf registry: %u checks passed\n",checks);
    return result;
}

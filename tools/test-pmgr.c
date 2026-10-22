/* SPDX-License-Identifier: MIT */
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "device.h"

static struct device_state state[2], saved;
static unsigned checks;
#define CHECK(x) do { checks++; if (!(x)) { fprintf(stderr,"FAIL %d: %s\n",__LINE__,#x); assert(x); } } while (0)
static const struct device_model models[2]={
    {DEVICE_PMGR_ACTIVE_BOOT_V1,0x300700000UL,0x11000,{0,0,0,0,0}},
    {DEVICE_PMGR_ACTIVE_BOOT_V1,0x308280000UL,0x9000,{1,0,0,0,0}}
};
static void refused(const struct device_model *m,struct device_state *s,
                    uint64_t off,unsigned width,int write,uint64_t value,
                    enum device_result want)
{
    if (s) saved=*s;
    uint64_t v=value;
    enum device_result result=device_model_access_state(m,s,off,width,write,&v);
    if (result!=want) fprintf(stderr,"group %llu offset %llx value %llx: got %u expected %u\n",
        (unsigned long long)m->config[0],(unsigned long long)off,(unsigned long long)value,result,want);
    CHECK(result==want);
    CHECK(v==value && (!s || !memcmp(s,&saved,sizeof(saved))));
}
static void fuse_bank(void)
{
    const struct device_model fuse={DEVICE_PMGR_AON_FUSES_V1,0x3082c8000UL,0x4000,{0}};
    /* Offsets from the stock reportPMGRAONFuseReg table, including its gap. */
    const unsigned offsets[]={0x114,0x118,0x11c,0x120,0x124,0x128,0x12c,0x214,0x218,0x21c,0x80c};
    struct device_model registry[]={models[0],models[1],fuse};
    CHECK(device_models_valid(registry,3,0,0));
    memset(&state[0],0xa5,sizeof(state[0]));saved=state[0];
    CHECK(device_model_start(&fuse,&state[0],0,24000000)==DEVICE_OK);
    CHECK(!memcmp(&state[0],&saved,sizeof(saved)));
    unsigned found=0;
    for (unsigned off=0;off<fuse.span;off+=4) {
        int known=0;
        for (unsigned i=0;i<sizeof(offsets)/sizeof(offsets[0]);i++)known|=off==offsets[i];
        uint64_t value=UINT64_MAX;
        if (!known) {
            refused(&fuse,&state[0],off,4,0,value,DEVICE_UNKNOWN_REGISTER);
            refused(&fuse,&state[0],off,4,1,value,DEVICE_UNKNOWN_REGISTER);
            continue;
        }
        found++;
        uint64_t expected=off==0x80c ? UINT32_C(0x10000000) : 0;
        CHECK(device_model_access_state(&fuse,&state[0],off,4,0,&value)==DEVICE_OK && value==expected);
        CHECK(!memcmp(&state[0],&saved,sizeof(saved)));
        value=UINT64_MAX;
        CHECK(device_model_access(&fuse,off,4,0,&value)==DEVICE_OK && value==expected);
        if (off==0x80c) CHECK((value>>28)!=0 && !(value&UINT32_C(0x0fffffff)));
        for (unsigned width=0;width<=16;width++) if(width!=4) {
            refused(&fuse,&state[0],off,width,0,UINT64_MAX,DEVICE_BAD_WIDTH);
            refused(&fuse,&state[0],off,width,1,UINT64_MAX,DEVICE_BAD_WIDTH);
        }
        for (unsigned delta=1;delta<4;delta++)
            refused(&fuse,&state[0],off+delta,4,0,UINT64_MAX,DEVICE_BAD_WIDTH);
        refused(&fuse,&state[0],off,4,1,0,DEVICE_READ_ONLY);
        refused(&fuse,&state[0],off,4,1,UINT64_MAX,DEVICE_READ_ONLY);
    }
    CHECK(found==11);
    refused(&fuse,&state[0],fuse.span,4,0,1,DEVICE_NOT_FOUND);
    for (unsigned i=0;i<5;i++) {
        struct device_model bad=fuse;bad.config[i]=1;
        CHECK(!device_models_valid(&bad,1,0,0));
        refused(&bad,&state[0],0x114,4,0,1,DEVICE_BAD_CONFIG);
    }
    struct device_model bad=fuse;bad.span=0x8000;
    refused(&bad,&state[0],0x114,4,0,1,DEVICE_BAD_CONFIG);
    bad=fuse;bad.span=0x1000;
    refused(&bad,&state[0],0x114,4,0,1,DEVICE_BAD_CONFIG);
    CHECK(device_model_access(&fuse,0x114,4,0,0)==DEVICE_BAD_CONFIG);
}
int main(int argc,char **argv)
{
    int topology=argc==2 && !strcmp(argv[1],"--topology");
    CHECK(device_models_valid(models,2,0,0));
    for (unsigned group=0;group<2;group++) {
        struct device_state *s=&state[group];
        const struct device_model *m=&models[group];
        CHECK(device_model_start(m,s,0,24000000)==DEVICE_OK);
        unsigned count=0;
        for (uint64_t off=0;off<m->span;off+=4) {
            uint64_t value=0;
            enum device_result r=device_model_access_state(m,s,off,4,0,&value);
            if (r==DEVICE_UNKNOWN_REGISTER) {
                refused(m,s,off,4,1,0xff,DEVICE_UNKNOWN_REGISTER);continue;
            }
            CHECK(r==DEVICE_OK && value==0xff);
            count++;
            if (topology) { printf("%u %llu\n",group,(unsigned long long)off);continue; }
            for (unsigned automatic=0;automatic<2;automatic++)
                for (unsigned minimum=0;minimum<16;minimum++) {
                    uint64_t policy=((uint64_t)automatic<<28)|((uint64_t)minimum<<16);
                    value=policy|0xff;
                    CHECK(device_model_access_state(m,s,off,4,1,&value)==DEVICE_OK);
                    value=0;
                    CHECK(device_model_access_state(m,s,off,4,0,&value)==DEVICE_OK);
                    CHECK(value==(policy|0xff|(automatic ? 15UL<<24 : 0)));
                    /* Hardware-owned fields and clearing zero histories do
                     * not let a guest forge a different power state. */
                    value=policy|0x0f00030f;
                    CHECK(device_model_access_state(m,s,off,4,1,&value)==DEVICE_OK);
                    value=0;
                    CHECK(device_model_access_state(m,s,off,4,0,&value)==DEVICE_OK);
                    CHECK(value==(policy|0xff|(automatic ? 15UL<<24 : 0)));
                }
            for (unsigned target=0;target<15;target++) {
                if (!group && ((off>=0x8000 && off<=0x8048) ||
                               off==0x170 || off==0x180 || off==0x1a0 ||
                               (off>=0x2b8 && off<=0x2c0) || off==0x298 ||
                               (off>=0x188 && off<=0x190) ||
                               (off>=0x330 && off<=0x350) ||
                               (off>=0x2c8 && off<=0x2e8) ||
                               (off>=0x390 && off<=0x398) ||
                               (off>=0x4000 && off<=0x4060)) && (target==0 || target==4))
                    continue; /* dependency/lifecycle sequences have a dedicated suite */
                refused(m,s,off,4,1,target,DEVICE_BAD_VALUE);
            }
            value=0xff;
            CHECK(device_model_access_state(m,s,off,4,1,&value)==DEVICE_OK);
        }
        CHECK(count==(group ? 14u : 124u));
        if (topology) continue;
        for (unsigned bit=0;bit<64;bit++)
            if (!((0x1f0f03ffUL>>bit)&1))
                refused(m,s,0,4,1,0xff|(1UL<<bit),DEVICE_BAD_VALUE);
        for (unsigned width=0;width<=16;width++) if(width!=4)
            refused(m,s,0,width,0,0xbad,DEVICE_BAD_WIDTH);
        refused(m,s,1,4,0,0xbad,DEVICE_BAD_WIDTH);
        refused(m,s,m->span,4,0,0xbad,DEVICE_NOT_FOUND);
        refused(m,0,0,4,0,0xbad,DEVICE_BAD_CONFIG);
        struct device_model bad=*m;bad.config[0]=2;
        refused(&bad,s,0,4,0,0xbad,DEVICE_BAD_CONFIG);
        for(unsigned i=1;i<5;i++) {
            bad=*m;bad.config[i]=(i==1 && !group) ? 2 : 1;
            refused(&bad,s,0,4,0,0xbad,DEVICE_BAD_CONFIG);
        }
        bad=*m;bad.span+=0x1000;
        refused(&bad,s,0,4,0,0xbad,DEVICE_BAD_CONFIG);
        uint64_t v=0x100700ff;
        CHECK(device_model_access_state(m,s,0,4,1,&v)==DEVICE_OK);
        CHECK(device_model_start(m,s,0,24000000)==DEVICE_OK);
        v=0;
        CHECK(device_model_access_state(m,s,0,4,0,&v)==DEVICE_OK && v==0xff);
    }
    if (!topology) {
        fuse_bank();
        printf("pmgr: %u checks passed\n",checks);
    }
    return 0;
}

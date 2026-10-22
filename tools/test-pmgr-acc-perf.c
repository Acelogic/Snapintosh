/* SPDX-License-Identifier: MIT */
/* ACC counter restore must not manufacture CPU activity measurements. */
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "device.h"
static unsigned checks;
#define CHECK(x) do { checks++; if (!(x)) { fprintf(stderr,"line %u: %s\n",__LINE__,#x); exit(1); } } while (0)
static struct device_model models[]={
    {35,0x210e20000,0x2000,{0}}, {35,0x211e20000,0x2000,{1}}
};
static struct device_state states[2],saved[2];
static enum device_result access(unsigned c,unsigned off,unsigned width,int write,uint64_t *v)
{ return device_model_access_state(models+c,states+c,off,width,write,v); }
static void refused(unsigned c,unsigned off,unsigned width,int write,uint64_t value,enum device_result want)
{
    uint64_t v=value;memcpy(saved,states,sizeof(states));
    enum device_result got=access(c,off,width,write,&v);
    if(got!=want)fprintf(stderr,"cluster%u:%x width%u write%d got%u want%u\n",c,off,width,write,got,want);
    CHECK(got==want);CHECK(v==value && !memcmp(saved,states,sizeof(states)));
}
int main(int argc,char **argv)
{
    CHECK(sizeof(struct device_state)==13000);
    CHECK(offsetof(struct device_state,acc_perf.values)==0);
    CHECK(offsetof(struct device_state,acc_perf.written)==576);
    CHECK(device_models_valid(models,2,0,0));
    for(unsigned c=0;c<2;c++) {
        CHECK(device_model_start(models+c,states+c,0,24000000)==DEVICE_OK);
        unsigned count=0;
        for(unsigned off=0;off<0x2000;off+=8) {
            uint64_t value=0xa5730100ee000000UL|((uint64_t)c<<16)|off;
            if(off==0x20) {
                memcpy(saved,states,sizeof(states));
                CHECK(access(c,off,8,0,&value)==DEVICE_OK && value==0);
                CHECK(!memcmp(saved,states,sizeof(states)));
                for(unsigned bit=0;bit<64;bit++)
                    refused(c,off,8,1,1UL<<bit,DEVICE_BAD_VALUE);
                refused(c,off,8,1,0,DEVICE_BAD_VALUE);
                for(unsigned width=0;width<=16;width++)if(width!=8)
                    refused(c,off,width,0,0,DEVICE_BAD_WIDTH);
                for(unsigned byte=1;byte<8;byte++)
                    refused(c,off+byte,8,0,0,DEVICE_BAD_WIDTH);
                continue;
            }
            int known=((off>=0x400 && off<0x400+8*(c?18:8)) ||
                       (off>=0x500 && off<0x500+8*(c?18:8)) ||
                       off==0x680 || off==0x688 || off==0x7e0 || off==0x7e8 ||
                       off==0x800 || off==0x808 ||
                       (!c && (off==0x820 || off==0x828 || off==0x840 || off==0x848)) ||
                       (!c && off>=0x10e8 && off<=0x1120) ||
                       (off>=0x11e8 && off<=0x11e8+8*(c?17:7)));
            if(!known) {
                refused(c,off,8,1,value,DEVICE_UNKNOWN_REGISTER);
                refused(c,off,8,0,value,DEVICE_UNKNOWN_REGISTER);continue;
            }
            count++;
            if(argc==2 && !strcmp(argv[1],"--topology"))printf("%u %u\n",c,off);
            /* IOReport samples read the restored value, or 0 before any
             * restore: no event/time source runs (PMGR-IOREPORT-20261017). An
             * aliased P setter domain may already hold this test's own value. */
            uint64_t before=0xdeadbeef;memcpy(saved,states,sizeof(states));
            CHECK(access(c,off,8,0,&before)==DEVICE_OK && !memcmp(saved,states,sizeof(states)));
            CHECK(before==0 || (before&~0x1ffffUL)==0xa5730100ee000000UL);
            CHECK(access(c,off,8,1,&value)==DEVICE_OK);
            uint64_t after=0;CHECK(access(c,off,8,0,&after)==DEVICE_OK && after==value);
            unsigned matches=0;
            for(unsigned n=0;n<72;n++)if(states[c].acc_perf.values[n]==value) {
                CHECK(states[c].acc_perf.written[n/64]&(1UL<<(n%64)));matches++;
            }
            CHECK(matches==1);
            for(unsigned width=0;width<=16;width++)if(width!=8)
                refused(c,off,width,1,value,DEVICE_BAD_WIDTH);
            for(unsigned byte=1;byte<8;byte++)refused(c,off+byte,8,1,value,DEVICE_BAD_WIDTH);
        }
        CHECK(count==(c?60:42));
        uint64_t command=~0UL;
        memcpy(saved,states,sizeof(states));
        CHECK(access(c,0x20,8,0,&command)==DEVICE_OK && command==0);
        CHECK(!memcmp(saved,states,sizeof(states)));
        CHECK(__builtin_popcountll(states[c].acc_perf.written[0])+
              __builtin_popcountll(states[c].acc_perf.written[1])==(int)count);
        refused(c,0x2000,8,1,0,DEVICE_NOT_FOUND);
        for(unsigned bit=0;bit<128;bit++) {
            uint64_t before=states[c].acc_perf.written[bit/64];
            if(before&(1UL<<(bit%64)))continue;
            states[c].acc_perf.written[bit/64]|=1UL<<(bit%64);
            refused(c,0x400,8,1,0,DEVICE_BAD_VALUE);states[c].acc_perf.written[bit/64]=before;
        }
        struct device_model original=models[c];
        for(unsigned word=0;word<5;word++) {
            models[c].config[word]=word?1:2;
            refused(c,0x400,8,1,0,DEVICE_BAD_CONFIG);models[c]=original;
        }
        models[c].span=0x1000;refused(c,0x400,8,1,0,DEVICE_BAD_CONFIG);models[c]=original;
    }
    /* Reset one bank leaves the other bank intact, including 64-bit high words. */
    memcpy(saved,states,sizeof(states));
    CHECK(device_model_start(models,states,0,24000000)==DEVICE_OK);
    CHECK(!memcmp(states,&(struct device_state){0},sizeof(*states)));
    CHECK(!memcmp(states+1,saved+1,sizeof(*states)));
    uint64_t value=0;
    CHECK(device_model_access(models,0x400,8,1,&value)==DEVICE_BAD_CONFIG);
    if(argc==1)printf("PASS: ACC counter restore %u checks; 42 E / 60 P slots\n",checks);
    return 0;
}

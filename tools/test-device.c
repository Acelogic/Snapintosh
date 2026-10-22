/* SPDX-License-Identifier: MIT */
#include "device.h"
#include <stdio.h>
#include <stdlib.h>
#define CHECK(x) do { checks++; if (!(x)) { fprintf(stderr,"FAIL %d: %s\n",__LINE__,#x); exit(1); } } while(0)
static unsigned checks;
int main(void)
{
    struct device_model wd={DEVICE_WATCHDOG_WD1_V1,0x3082b0000UL,0x4000,{24000000,0,0,0,0}};
    struct device_state ws={0}, other={0};
    uint64_t v=0;
    CHECK(device_models_valid(&wd,1,0,0));
    CHECK(device_model_access_state(&wd,&ws,0x1c,4,0,&v)==DEVICE_BAD_CONFIG);
    CHECK(device_model_access_at(&wd,&ws,100,0x1c,4,0,&v)==DEVICE_BAD_CONFIG);
    CHECK(device_model_start(&wd,&ws,100,19200000)==DEVICE_BAD_CONFIG);
    CHECK(!ws.watchdog.ready);
    CHECK(device_model_start(&wd,&ws,100,24000000)==DEVICE_OK);
    CHECK(device_model_start(&wd,&other,100,24000000)==DEVICE_OK);
    CHECK(device_model_access_at(&wd,&ws,100,0x14,4,1,&(uint64_t){100})==DEVICE_OK);
    CHECK(device_model_access_at(&wd,&ws,100,0x1c,4,1,&(uint64_t){4})==DEVICE_OK);
    CHECK(device_model_wait(&wd,&ws,199,1000)==1);
    CHECK(!device_reset_pending(&wd,&ws));
    CHECK(device_model_wait(&wd,&ws,200,1000)==0);
    CHECK(device_reset_pending(&wd,&ws));
    CHECK(device_model_wait(&wd,&other,200,1000)==1000 && !device_reset_pending(&wd,&other));
    CHECK(device_model_access_at(&wd,&ws,200,0x4000,4,0,&v)==DEVICE_NOT_FOUND);
    CHECK(device_model_access_at(&wd,&ws,200,0x20,4,0,&v)==DEVICE_UNKNOWN_REGISTER);
    CHECK(device_model_access_at(&wd,&ws,200,0x14,8,0,&v)==DEVICE_BAD_WIDTH);
    CHECK(device_model_access_at(&wd,&ws,200,0x1c,4,1,&(uint64_t){1})==DEVICE_BAD_VALUE);
    wd.config[0]=0; CHECK(!device_models_valid(&wd,1,0,0));
    wd.config[0]=1UL<<32; CHECK(!device_models_valid(&wd,1,0,0));
    wd.config[0]=24000000; wd.config[1]=1; CHECK(!device_models_valid(&wd,1,0,0));
    struct device_model d={DEVICE_MCC_COHERENT_V1,0x220000000UL,0x140000,{4,0,0,0,0}};
    struct device_state counters={0};
    /* Replay the stock SRAM reporter: sixteen 19-bit quantities in 512-byte
     * units. No private MCC SRAM is backed, irrespective of DRAM size. */
    uint64_t sram_bytes=0;
    for (unsigned i=0; i<16; i++) {
        uint64_t off=0x34400+i*16, value=0xdead;
        CHECK(device_model_access_state(&d,&counters,off,4,0,&value)==DEVICE_OK && value==0);
        sram_bytes+=(value & 0x7ffff)*512;
        value=0xdead;
        CHECK(device_model_access(&d,off,4,0,&value)==DEVICE_OK && value==0);
        for (unsigned width=1; width<=8; width*=2) if (width!=4) {
            value=0xdead;
            CHECK(device_model_access_state(&d,&counters,off,width,0,&value)==DEVICE_BAD_WIDTH);
            CHECK(value==0xdead);
        }
        for (unsigned word=1; word<4; word++) {
            value=0xdead;
            CHECK(device_model_access_state(&d,&counters,off+word*4,4,0,&value)==DEVICE_UNKNOWN_REGISTER);
            CHECK(value==0xdead);
        }
        for (unsigned bank=1; bank<4; bank++) {
            value=0xdead;
            CHECK(device_model_access_state(&d,&counters,off+bank*0x40000,4,0,&value)==DEVICE_UNKNOWN_REGISTER);
            CHECK(value==0xdead);
        }
        value=0xdead;
        CHECK(device_model_access_state(&d,&counters,off,4,1,&value)==DEVICE_READ_ONLY);
        CHECK(value==0xdead);
        CHECK(device_model_access_state(&d,&counters,off,4,0,&value)==DEVICE_OK && value==0);
    }
    CHECK(sram_bytes==0);
    const uint64_t sram_edges[]={0x343fc,0x34500,0x34401,0x34402};
    for (unsigned i=0;i<sizeof(sram_edges)/sizeof(sram_edges[0]);i++) {
        uint64_t value=0xdead;
        CHECK(device_model_access_state(&d,&counters,sram_edges[i],4,0,&value)==
              (sram_edges[i]&3 ? DEVICE_BAD_WIDTH : DEVICE_UNKNOWN_REGISTER));
        CHECK(value==0xdead);
    }
    for (unsigned bank=0; bank<4; bank++) for (unsigned i=0; i<7; i++) {
        uint64_t off=bank*0x40000+0x25000+i*8, value=0xdead;
        CHECK(device_model_access_state(&d,&counters,off,4,0,&value)==DEVICE_OK && value==0);
        value=(bank+1)*0x110000+i;
        CHECK(device_model_access_state(&d,&counters,off,4,1,&value)==DEVICE_OK);
        value=0;
        CHECK(device_model_access_state(&d,&counters,off,4,0,&value)==DEVICE_OK &&
              value==(bank+1)*0x110000+i);
        CHECK(device_model_access_state(&d,&counters,off+4,4,0,&value)==DEVICE_UNKNOWN_REGISTER);
        CHECK(device_model_access_state(&d,&counters,off,8,0,&value)==DEVICE_BAD_WIDTH);
        value=1UL<<32;
        CHECK(device_model_access_state(&d,&counters,off,4,1,&value)==DEVICE_BAD_VALUE);
    }
    for (unsigned bank=0; bank<4; bank++) for (unsigned i=0; i<7; i++) {
        uint64_t value=0;
        CHECK(device_model_access_state(&d,&counters,bank*0x40000+0x25000+i*8,4,0,&value)==DEVICE_OK &&
              value==(bank+1)*0x110000+i);
    }
    for (unsigned i=0; i<223; i++) {
        uint64_t off=i<191 ? 0x9000+4*i : 0xa800+4*(i-191), value=0xdead;
        CHECK(device_model_access(&d,off,4,0,&value)==DEVICE_OK && value==0);
        value=0xdead;
        CHECK(device_model_access(&d,off,4,1,&value)==DEVICE_READ_ONLY && value==0xdead);
        CHECK(device_model_access(&d,off,8,0,&value)==DEVICE_BAD_WIDTH && value==0xdead);
    }
    const uint64_t timeout_gaps[]={0x8ffc,0x92fc,0xa7fc,0xa880,0x49000};
    for (unsigned i=0; i<sizeof(timeout_gaps)/sizeof(timeout_gaps[0]); i++) {
        uint64_t value=0xdead;
        CHECK(device_model_access(&d,timeout_gaps[i],4,0,&value)==DEVICE_UNKNOWN_REGISTER);
        CHECK(value==0xdead);
    }
    const struct device_range excluded[]={{0xda000000,0x1b000000},{0xf9a20000,0x13c8000}};
    CHECK(device_models_valid(&d,1,excluded,2));
    struct device_state idle={0};
    CHECK(device_model_access_state(&d,&idle,0x10082c,4,1,&(uint64_t){0})==DEVICE_OK);
    v=42; CHECK(device_model_access_state(&d,&idle,0x10082c,4,0,&v)==DEVICE_OK && v==0);
    CHECK(device_model_access_state(&d,&idle,0x10082c,4,1,&(uint64_t){1})==DEVICE_BAD_VALUE);
    CHECK(device_model_access_state(&d,&idle,0x10082c,4,1,&(uint64_t){2})==DEVICE_BAD_VALUE);
    CHECK(device_model_access_state(&d,&idle,0x10082c,8,1,&(uint64_t){0})==DEVICE_BAD_WIDTH);
    CHECK(device_model_access_state(&d,&idle,0x100830,4,1,&(uint64_t){0})==DEVICE_UNKNOWN_REGISTER);
    CHECK(device_models_valid(0,0,0,0));
    CHECK(!device_models_valid(&d,DEVICE_MODEL_MAX+1,0,0));
    CHECK(!device_models_valid(0,1,0,0));
    CHECK(!device_models_valid(&d,1,0,1));
    for(unsigned bank=0;bank<4;bank++) {
        uint64_t off=0xdead,value=0xdead;
        CHECK(device_model_find(&d,1,d.base+bank*0x40000+0x2c,&off)==0);
        CHECK(off==bank*0x40000+0x2c);
        CHECK(device_model_access(&d,off,4,0,&value)==DEVICE_OK && value==0);
        /* Independent consumer from the reached readCacheSize bit fields. */
        CHECK((((value>>8)&0xffff)*1024*d.config[0])==0);
        for(unsigned width=1;width<=8;width*=2) if(width!=4) {
            value=0xdead;
            CHECK(device_model_access(&d,off,width,0,&value)==DEVICE_BAD_WIDTH);
            CHECK(value==0xdead);
        }
        value=0xdead;
        CHECK(device_model_access(&d,off,4,1,&value)==DEVICE_READ_ONLY);
        CHECK(value==0xdead);
        CHECK(device_model_access(&d,off+1,4,0,&value)==DEVICE_BAD_WIDTH);
        for(unsigned group=0;group<=32;group++) {
            uint64_t quota=0xdead, reg=bank*0x40000+0xa000+group*4;
            CHECK(device_model_access(&d,reg,4,0,&quota)==DEVICE_OK && quota==0);
            CHECK(((quota&63)<<17)*d.config[0]==0);
            CHECK(device_model_access(&d,reg,4,1,&quota)==DEVICE_READ_ONLY);
        }
        CHECK(device_model_access(&d,bank*0x40000+0x9ffc,4,0,&value)==DEVICE_UNKNOWN_REGISTER);
        CHECK(device_model_access(&d,bank*0x40000+0xa084,4,0,&value)==DEVICE_UNKNOWN_REGISTER);
        for(unsigned counter=0;counter<32;counter++) {
            uint64_t sample=0xdead, reg=bank*0x40000+0x29000+counter*8;
            CHECK(device_model_access_state(&d,&counters,reg,8,0,&sample)==DEVICE_OK && sample==0);
            sample=0xdead;
            CHECK(device_model_access_state(&d,&counters,reg,8,1,&sample)==DEVICE_READ_ONLY && sample==0xdead);
            CHECK(device_model_access(&d,reg,4,0,&sample)==DEVICE_BAD_WIDTH);
            CHECK(device_model_access(&d,reg+4,8,0,&sample)==DEVICE_BAD_WIDTH);
            CHECK(sample==0xdead);
        }
        CHECK(device_model_access(&d,bank*0x40000+0x28000,4,1,&value)==DEVICE_BAD_WIDTH);
        CHECK(device_model_access(&d,bank*0x40000+0x29100,8,0,&value)!=DEVICE_OK);
    }
    for(unsigned bank=0;bank<4;bank++) {
        const uint64_t control=bank*0x40000+0x28000;
        uint64_t value=0xdead;
        CHECK(device_model_access_state(&d,&counters,control,8,0,&value)==DEVICE_OK && value==0);
        for(unsigned index=0;index<32;index++) {
            const uint64_t reg=bank*0x40000+0x29000+index*8;
            CHECK(device_mcc_event(&d,&counters,bank,index,17)==DEVICE_OK);
            CHECK(device_model_access_state(&d,&counters,reg,8,0,&value)==DEVICE_OK && value==0);
            /* Enable exactly this source, emit traffic, snapshot, disable. */
            value=1UL<<index;
            CHECK(device_model_access_state(&d,&counters,control,8,1,&value)==DEVICE_OK);
            CHECK(device_mcc_event(&d,&counters,bank,index,17)==DEVICE_OK);
            CHECK(device_model_access_state(&d,&counters,reg,8,0,&value)==DEVICE_OK && value==17);
            value=0;
            CHECK(device_model_access_state(&d,&counters,control,8,1,&value)==DEVICE_OK);
            CHECK(device_mcc_event(&d,&counters,bank,index,200)==DEVICE_OK);
            CHECK(device_model_access_state(&d,&counters,reg,8,0,&value)==DEVICE_OK && value==17);
            value=1UL<<index;
            CHECK(device_model_access_state(&d,&counters,control,8,1,&value)==DEVICE_OK);
            CHECK(device_mcc_event(&d,&counters,bank,index,UINT64_MAX)==DEVICE_OK);
            CHECK(device_model_access_state(&d,&counters,reg,8,0,&value)==DEVICE_OK && value==16);
            value=1UL<<32;
            CHECK(device_model_access_state(&d,&counters,control,8,1,&value)==DEVICE_BAD_VALUE);
            CHECK(device_model_access_state(&d,&counters,control,8,0,&value)==DEVICE_OK && value==(1UL<<index));
            value=0;
            CHECK(device_model_access_state(&d,&counters,control,8,1,&value)==DEVICE_OK);
        }
        for(unsigned b=0;b<4;b++) for(unsigned i=0;i<32;i++)
            CHECK(counters.counter[b][i]==(b<=bank ? 16 : 0));
    }
    CHECK(device_mcc_event(&d,&counters,4,0,1)==DEVICE_BAD_VALUE);
    CHECK(device_mcc_event(&d,&counters,0,32,1)==DEVICE_BAD_VALUE);
    CHECK(device_mcc_event(&d,0,0,0,1)==DEVICE_BAD_CONFIG);
    CHECK(device_mcc_event(0,&counters,0,0,1)==DEVICE_BAD_CONFIG);
    uint64_t absent=0xdead;
    CHECK(device_model_access(&d,0x29000,8,0,&absent)==DEVICE_BAD_CONFIG && absent==0xdead);
    for(unsigned b=0;b<4;b++) {
        CHECK(device_mcc_cache_event(&d,&counters,b,0,10+b)==DEVICE_OK);
        CHECK(device_mcc_cache_event(&d,&counters,b,1,1)==DEVICE_BAD_VALUE);
        CHECK(device_mcc_cache_event(&d,&counters,b,1,0)==DEVICE_OK);
        CHECK(device_model_access_state(&d,&counters,b*0x40000+0x2a058,8,0,&absent)==DEVICE_OK && absent==0);
        CHECK(device_model_access_state(&d,&counters,b*0x40000+0x2a060,8,0,&absent)==DEVICE_OK && absent==10+b);
        CHECK(device_model_access_state(&d,&counters,b*0x40000+0x2a060,4,0,&absent)==DEVICE_BAD_WIDTH);
        CHECK(device_model_access_state(&d,&counters,b*0x40000+0x2a060,8,1,&absent)==DEVICE_READ_ONLY);
    }
    CHECK(device_mcc_cache_event(&d,&counters,4,0,1)==DEVICE_BAD_VALUE);
    CHECK(device_mcc_cache_event(&d,&counters,0,2,1)==DEVICE_BAD_VALUE);
    CHECK(device_mcc_cache_event(&d,0,0,0,1)==DEVICE_BAD_CONFIG);
    CHECK(device_mcc_cache_event(0,&counters,0,0,1)==DEVICE_BAD_CONFIG);
    CHECK(device_mcc_cache_event(&d,&counters,0,0,UINT64_MAX)==DEVICE_OK);
    CHECK(device_model_access_state(&d,&counters,0x2a060,8,0,&absent)==DEVICE_OK && absent==9);
    struct device_state profile={0}, other_profile={0};
    const uint64_t profile_regs[]={0x2a010,0x2e000,0x2a008,0x2a000};
    const uint64_t profile_values[]={0x10000000,0x100,0x71f,0x11};
    for(unsigned b=0;b<4;b++) for(unsigned i=0;i<4;i++) {
        uint64_t reg=b*0x40000+profile_regs[i], v=0xdead;
        unsigned width=profile_regs[i]==0x2e000 ? 4 : 8;
        CHECK(device_model_access_state(&d,&profile,reg,width,0,&v)==DEVICE_OK && v==0);
        v=profile_values[i];
        CHECK(device_model_access_state(&d,&profile,reg,width,1,&v)==DEVICE_OK);
        CHECK(device_model_access_state(&d,&profile,reg,width,0,&v)==DEVICE_OK && v==profile_values[i]);
        v=UINT64_MAX;
        CHECK(device_model_access_state(&d,&profile,reg,width,1,&v)==DEVICE_BAD_VALUE);
        CHECK(device_model_access_state(&d,&profile,reg,width,0,&v)==DEVICE_OK && v==profile_values[i]);
        CHECK(device_model_access_state(&d,&profile,reg,12-width,1,&v)==DEVICE_BAD_WIDTH);
        CHECK(device_model_access_state(&d,&profile,reg+4,8,1,&v)!=DEVICE_OK);
        CHECK(device_model_access(&d,reg,width,0,&v)==DEVICE_BAD_CONFIG);
        CHECK(device_model_access_state(&d,&other_profile,reg,width,0,&v)==DEVICE_OK && v==0);
        for(unsigned next=b+1;next<4;next++)
            CHECK(device_model_access_state(&d,&profile,next*0x40000+profile_regs[i],width,0,&v)==DEVICE_OK && v==0);
    }
    absent=0;
    CHECK(device_model_access_state(&d,&profile,0x2a000,8,1,&absent)==DEVICE_OK);
    absent=1;
    CHECK(device_model_access_state(&d,&profile,0x2a000,8,1,&absent)==DEVICE_OK);
    CHECK(device_model_access_state(&d,&profile,0x2a000,8,0,&absent)==DEVICE_OK && absent==1);
    CHECK(device_model_access_state(&d,&profile,0x2a018,8,0,&absent)!=DEVICE_OK);
    CHECK(device_model_access_state(&d,&profile,0x2e008,8,0,&absent)!=DEVICE_OK);
    CHECK(profile.counter[0][32]==0 && profile.counter[0][33]==0);
    for(unsigned ways=0;ways<=12;ways++) {
        absent=ways;
        CHECK(device_model_access_state(&d,&profile,0x102800,4,1,&absent)==DEVICE_OK);
        CHECK(device_model_access_state(&d,&profile,0x102800,4,0,&absent)==DEVICE_OK && absent==ways);
        CHECK(device_model_access_state(&d,&other_profile,0x102800,4,0,&absent)==DEVICE_OK && absent==0);
        CHECK(device_model_access_state(&d,&profile,0x2c,4,0,&absent)==DEVICE_OK && absent==0);
        for(unsigned bank=0;bank<4;bank++) {
            uint64_t status=0, reg=bank*0x40000+0x2804;
            CHECK(device_model_access_state(&d,&profile,reg,4,0,&status)==DEVICE_OK);
            CHECK(status==((uint64_t)ways<<24 | (uint64_t)ways<<8));
            CHECK(device_model_access_state(&d,&other_profile,reg,4,0,&status)==DEVICE_OK && status==0);
            status=123;
            CHECK(device_model_access_state(&d,&profile,reg,4,1,&status)==DEVICE_READ_ONLY);
            CHECK(status==123 && profile.cache_way_policy==ways);
            CHECK(device_model_access_state(&d,&profile,reg,8,0,&status)==DEVICE_BAD_WIDTH);
        }
    }
    absent=13;
    CHECK(device_model_access_state(&d,&profile,0x102800,4,1,&absent)==DEVICE_BAD_VALUE);
    CHECK(device_model_access_state(&d,&profile,0x102800,4,0,&absent)==DEVICE_OK && absent==12);
    CHECK(device_model_access_state(&d,&profile,0x102800,8,1,&absent)==DEVICE_BAD_WIDTH);
    CHECK(device_model_access_state(&d,&profile,0x102804,4,1,&absent)==DEVICE_UNKNOWN_REGISTER);
    CHECK(device_model_access_state(&d,&profile,0x10082c,4,1,&absent)==DEVICE_BAD_VALUE);
    struct device_model socni={DEVICE_MCC_SOCNI_V1,0x24f008000UL,0x8000,{36,0,0,0,0}};
    struct device_state fabric={0};
    CHECK(device_models_valid(&socni,1,0,0));
    uint64_t start=3;
    CHECK(device_model_access_state(&socni,&fabric,0,4,1,&start)==DEVICE_OK);
    CHECK(device_mcc_event(&socni,&fabric,0,0,10)==DEVICE_OK);
    CHECK(device_model_access_state(&socni,&fabric,0x4000,8,0,&start)==DEVICE_OK && start==0);
    CHECK(device_model_access_state(&socni,&fabric,0,4,1,&start)==DEVICE_OK);
    start=2;
    CHECK(device_model_access_state(&socni,&fabric,0x100,4,1,&start)==DEVICE_BAD_VALUE);
    CHECK(device_model_access_state(&socni,&fabric,0x100,4,0,&start)==DEVICE_OK && start==0);
    start=1;
    CHECK(device_model_access_state(&socni,&fabric,0x100,4,1,&start)==DEVICE_OK);
    for(unsigned index=0;index<36;index++) {
        uint64_t v=0xdead, ctl=index*4, reg=0x4000+index*8;
        CHECK(device_model_access_state(&socni,&fabric,ctl,4,0,&v)==DEVICE_OK && v==0);
        CHECK(device_mcc_event(&socni,&fabric,0,index,10)==DEVICE_OK);
        CHECK(device_model_access_state(&socni,&fabric,reg,8,0,&v)==DEVICE_OK && v==0);
        v=3;
        CHECK(device_model_access_state(&socni,&fabric,ctl,4,1,&v)==DEVICE_OK);
        CHECK(device_mcc_event(&socni,&fabric,0,index,10)==DEVICE_OK);
        CHECK(device_model_access_state(&socni,&fabric,reg,8,0,&v)==DEVICE_OK && v==10);
        for(unsigned invalid=1;invalid<=4;invalid++) if(invalid!=3) {
            v=invalid;
            CHECK(device_model_access_state(&socni,&fabric,ctl,4,1,&v)==DEVICE_BAD_VALUE);
            CHECK(device_model_access_state(&socni,&fabric,ctl,4,0,&v)==DEVICE_OK && v==3);
        }
        v=0;
        CHECK(device_model_access_state(&socni,&fabric,ctl,4,1,&v)==DEVICE_OK);
        CHECK(device_mcc_event(&socni,&fabric,0,index,10)==DEVICE_OK);
        CHECK(device_model_access_state(&socni,&fabric,reg,8,0,&v)==DEVICE_OK && v==10);
        CHECK(device_model_access_state(&socni,&fabric,reg,8,1,&v)==DEVICE_READ_ONLY);
        CHECK(device_model_access_state(&socni,&fabric,reg,4,0,&v)==DEVICE_BAD_WIDTH);
        CHECK(device_model_access_state(&socni,&fabric,ctl,8,0,&v)==DEVICE_BAD_WIDTH);
        CHECK(v==10);
        for(unsigned i=0;i<36;i++) CHECK(fabric.counter[0][i]==(i<=index ? 10 : 0));
    }
    CHECK(device_mcc_event(&socni,&fabric,0,36,1)==DEVICE_BAD_VALUE);
    CHECK(device_mcc_event(&socni,&fabric,1,0,1)==DEVICE_BAD_VALUE);
    CHECK(device_model_access_state(&socni,&fabric,36*4,4,0,&absent)==DEVICE_UNKNOWN_REGISTER);
    CHECK(device_model_access_state(&socni,&fabric,0x4000+36*8,8,0,&absent)==DEVICE_UNKNOWN_REGISTER);
    CHECK(device_model_access_state(&socni,&fabric,1,4,0,&absent)==DEVICE_BAD_WIDTH);
    CHECK(device_model_access_state(&socni,&fabric,0x4004,8,0,&absent)==DEVICE_BAD_WIDTH);
    CHECK(device_model_access(&socni,0,4,0,&absent)==DEVICE_BAD_CONFIG);
    start=0;
    CHECK(device_model_access_state(&socni,&fabric,0x100,4,1,&start)==DEVICE_OK);
    start=3;
    CHECK(device_model_access_state(&socni,&fabric,0,4,1,&start)==DEVICE_OK);
    CHECK(device_mcc_event(&socni,&fabric,0,0,10)==DEVICE_OK);
    CHECK(device_model_access_state(&socni,&fabric,0x4000,8,0,&start)==DEVICE_OK && start==10);
    for(unsigned invalid=0;invalid<3;invalid++) {
        struct device_model bad=socni;
        if(invalid==0) bad.config[0]=0;
        if(invalid==1) bad.config[0]=65;
        if(invalid==2) bad.span=0x4000;
        CHECK(!device_models_valid(&bad,1,0,0));
    }
    const uint64_t bad[]={0,0x28,0x30,0x10002c,0x13fffc};
    for(unsigned i=0;i<5;i++) {
        uint64_t value=0xdead;
        CHECK(device_model_access(&d,bad[i],4,0,&value)==DEVICE_UNKNOWN_REGISTER);
        CHECK(value==0xdead);
    }
    uint64_t off=0xdead,value=0xdead;
    CHECK(device_model_find(&d,1,d.base-1,&off)==-1 && off==0xdead);
    CHECK(device_model_find(&d,1,d.base+d.span,&off)==-1 && off==0xdead);
    CHECK(device_model_access(&d,d.span,4,0,&value)==DEVICE_NOT_FOUND && value==0xdead);
    CHECK(device_model_access(&d,0x2c,4,0,0)==DEVICE_BAD_CONFIG);
    CHECK(device_model_access(0,0x2c,4,0,&value)==DEVICE_BAD_CONFIG);
    for(unsigned i=0;i<11;i++) {
        struct device_model bad=d;
        switch(i) {
        case 0:bad.kind=99;break;
        case 1:bad.base++;break;
        case 2:bad.span++;break;
        case 3:bad.span=0;break;
        case 4:bad.base=1UL<<36;break;
        case 5:bad.span=1UL<<36;break;
        case 6:bad.config[0]=0;break;
        case 7:bad.config[0]=5;break;
        case 8:bad.config[1]=1;break;
        case 9:bad.config[4]=1;break;
        case 10:bad.span=0xc0000;break;
        }
        CHECK(!device_models_valid(&bad,1,0,0));
        CHECK(device_model_access(&bad,0x2c,4,0,&value)==DEVICE_BAD_CONFIG && value==0xdead);
    }
    struct device_model pair[]={d,d};
    CHECK(!device_models_valid(pair,2,0,0));
    pair[1].base+=d.span;
    CHECK(device_models_valid(pair,2,0,0));
    const struct device_range overlap[]={{d.base+0x2c,4}};
    CHECK(!device_models_valid(&d,1,overlap,1));
    const struct device_range overflow[]={{UINT64_MAX,2}};
    CHECK(!device_models_valid(&d,1,overflow,1));
    struct device_model dcs={DEVICE_MCC_DCS_COHERENT_V1,0x220400000UL,0x8000,{0}};
    struct device_state banks[4]={{0}};
    CHECK(device_models_valid(&dcs,1,0,0));
    struct device_state dcs_perf={0};
    for(unsigned i=0;i<10;i++) for(unsigned word=0;word<6;word++) {
        value=0x3ff001aU + 0x100*i + word;
        uint64_t selector=0x590+i*24+word*4, expected=value;
        CHECK(device_model_access_state(&dcs,&dcs_perf,selector,4,1,&value)==DEVICE_OK);
        CHECK(device_model_access_state(&dcs,&dcs_perf,selector,4,0,&value)==DEVICE_OK && value==expected);
    }
    value=0x3ff;
    CHECK(device_model_access_state(&dcs,&dcs_perf,0x584,4,1,&value)==DEVICE_OK);
    for(unsigned i=0;i<10;i++) CHECK(device_mcc_event(&dcs,&dcs_perf,0,i,100+i)==DEVICE_OK);
    for(unsigned i=0;i<10;i++) {
        value=1|(1UL<<(4+i));
        CHECK(device_model_access_state(&dcs,&dcs_perf,0x580,4,1,&value)==DEVICE_OK);
        CHECK(device_model_access_state(&dcs,&dcs_perf,0x580,4,0,&value)==DEVICE_OK && value==0);
        for(unsigned j=0;j<10;j++) {
            CHECK(device_model_access_state(&dcs,&dcs_perf,0x4000+j*8,8,0,&value)==DEVICE_OK);
            CHECK(value==(j<=i ? 0 : 100+j));
        }
    }
    value=0x1111;
    CHECK(device_model_access_state(&dcs,&dcs_perf,0x588,4,1,&value)==DEVICE_OK);
    for(unsigned i=0;i<4;i++) CHECK(device_mcc_event(&dcs,&dcs_perf,0,10+i,24*(100+i))==DEVICE_OK);
    for(unsigned i=0;i<4;i++) {
        value=0x1111|(1UL<<(16+4*i));
        CHECK(device_model_access_state(&dcs,&dcs_perf,0x588,4,1,&value)==DEVICE_OK);
        CHECK(device_model_access_state(&dcs,&dcs_perf,0x588,4,0,&value)==DEVICE_OK && value==0x1111);
        for(unsigned j=0;j<4;j++) {
            CHECK(device_model_access_state(&dcs,&dcs_perf,0x4050+j*8,8,0,&value)==DEVICE_OK);
            CHECK(value==(j<=i ? 0 : 24*(100+j)));
        }
    }
    value=0x3f023f01;
    CHECK(device_model_access_state(&dcs,&dcs_perf,0x58c,4,1,&value)==DEVICE_OK);
    value=0;
    CHECK(device_model_access_state(&dcs,&dcs_perf,0x58c,4,0,&value)==DEVICE_OK && value==0x3f023f01);
    const uint64_t invalid_dcs[][2]={{0x580,1},{0x580,0x10},{0x580,0x4001},
        {0x584,0x400},{0x588,2},{0x588,0x20000},{0x58c,0x40}};
    for(unsigned i=0;i<sizeof(invalid_dcs)/sizeof(*invalid_dcs);i++) {
        value=invalid_dcs[i][1];
        CHECK(device_model_access_state(&dcs,&dcs_perf,invalid_dcs[i][0],4,1,&value)==DEVICE_BAD_VALUE);
        CHECK(value==invalid_dcs[i][1]);
    }
    CHECK(dcs_perf.counter_enable[0]==0x3ff && dcs_perf.counter_enable[1]==0x1111);
    CHECK(dcs_perf.dcs_power_select==0x3f023f01);
    value=0;
    CHECK(device_model_access_state(&dcs,&dcs_perf,0x584,4,1,&value)==DEVICE_OK);
    CHECK(device_model_access_state(&dcs,&dcs_perf,0x588,4,1,&value)==DEVICE_OK);
    for(unsigned i=0;i<14;i++) {
        CHECK(device_mcc_event(&dcs,&dcs_perf,0,i,123)==DEVICE_OK);
        CHECK(device_model_access_state(&dcs,&dcs_perf,0x4000+i*8,8,0,&value)==DEVICE_OK && value==0);
    }
    CHECK(device_mcc_event(&dcs,&dcs_perf,1,0,1)==DEVICE_BAD_VALUE);
    CHECK(device_mcc_event(&dcs,&dcs_perf,0,14,1)==DEVICE_BAD_VALUE);
    CHECK(device_model_access_state(&dcs,&dcs_perf,0x680,4,0,&value)==DEVICE_UNKNOWN_REGISTER);
    CHECK(device_model_access_state(&dcs,&dcs_perf,0x4000,4,0,&value)==DEVICE_BAD_WIDTH);
    CHECK(device_model_access_state(&dcs,&dcs_perf,0x4004,8,0,&value)==DEVICE_BAD_WIDTH);
    CHECK(device_model_access_state(&dcs,&dcs_perf,0x4000,8,1,&value)==DEVICE_READ_ONLY);
    /* Each DCS independently snapshots, selects and restores opaque policy. */
    for (unsigned bank=0;bank<4;bank++) {
        uint64_t snapshot=0xdead, policy=0x55555340U+bank;
        CHECK(device_model_access_state(&dcs,&banks[bank],0x1d48,4,0,&snapshot)==DEVICE_OK);
        CHECK(snapshot==0);
        CHECK(device_model_access_state(&dcs,&banks[bank],0x1d48,4,1,&policy)==DEVICE_OK);
        for (unsigned i=0;i<4;i++) {
            value=0xdead;
            CHECK(device_model_access_state(&dcs,&banks[i],0x1d48,4,0,&value)==DEVICE_OK);
            CHECK(value==(i<=bank ? 0x55555340U+i : 0));
        }
    }
    for (unsigned bank=0;bank<4;bank++) {
        value=0;
        CHECK(device_model_access_state(&dcs,&banks[bank],0x1d48,4,1,&value)==DEVICE_OK);
        CHECK(banks[bank].dram_policy==0);
    }
    value=UINT64_MAX;
    CHECK(device_model_access_state(&dcs,&banks[0],0x1d48,4,1,&value)==DEVICE_OK);
    CHECK(banks[0].dram_policy==UINT32_MAX && value==UINT64_MAX);
    for(unsigned write=0;write<2;write++) {
        value=0xdead;
        CHECK(device_model_access_state(&dcs,&banks[0],0x1d44,4,write,&value)==DEVICE_UNKNOWN_REGISTER);
        CHECK(device_model_access_state(&dcs,&banks[0],0x1d49,4,write,&value)==DEVICE_BAD_WIDTH);
        CHECK(device_model_access_state(&dcs,&banks[0],0x1d48,8,write,&value)==DEVICE_BAD_WIDTH);
        CHECK(value==0xdead && banks[0].dram_policy==UINT32_MAX);
    }
    CHECK(device_model_access(&dcs,0x1d48,4,0,&value)==DEVICE_BAD_CONFIG);
    dcs.config[0]=1;
    CHECK(!device_models_valid(&dcs,1,0,0));
    dcs.config[0]=0; dcs.span=0x1000;
    CHECK(!device_models_valid(&dcs,1,0,0));
    struct device_model aic={DEVICE_AIC3_FLAT_V1,0x301000000UL,0x1cc000,
                            {1280,4096,0x40000,0xa,0}};
    struct device_state aic_state={0};
    CHECK(device_models_valid(&aic,1,0,0));
    const uint64_t regs[]={0,4,12,0x40000}, expected[]={0xa,1280,0x01001000,0};
    for(unsigned i=0;i<4;i++) {
        value=0xdead;
        CHECK(device_model_access_state(&aic,&aic_state,regs[i],4,0,&value)==DEVICE_OK && value==expected[i]);
        CHECK(device_model_access_state(&aic,&aic_state,regs[i],4,1,&value)==DEVICE_READ_ONLY && value==expected[i]);
        CHECK(device_model_access(&aic,regs[i],8,0,&value)==DEVICE_BAD_WIDTH);
        CHECK(device_model_access(&aic,regs[i]+1,4,0,&value)==DEVICE_BAD_WIDTH);
    }
    /* Unknown registers stay explicit refusals even with a delivery backend. */
    for(unsigned write=0;write<2;write++) {
        value=0xdead;
        CHECK(device_model_access_state(&aic,&aic_state,0x18,4,write,&value)==DEVICE_UNKNOWN_REGISTER);
        CHECK(device_model_access_state(&aic,&aic_state,0x14a00,4,write,&value)==DEVICE_UNKNOWN_REGISTER);
        CHECK(device_model_access_state(&aic,&aic_state,8,4,write,&value)==DEVICE_UNKNOWN_REGISTER);
        CHECK(value==0xdead);
    }
    CHECK(!device_irq_pending(&aic,&aic_state));
    value=1;CHECK(device_model_access_state(&aic,&aic_state,0x14,4,1,&value)==DEVICE_OK);
    value=1UL<<31;CHECK(device_model_access_state(&aic,&aic_state,0x14000,4,1,&value)==DEVICE_OK);
    CHECK(!device_irq_pending(&aic,&aic_state));
    CHECK(device_model_access_state(&aic,&aic_state,0x14600,4,1,&value)==DEVICE_OK);
    CHECK(device_irq_pending(&aic,&aic_state));
    CHECK(device_model_access_state(&aic,&aic_state,0x40000,4,0,&value)==DEVICE_OK);
    CHECK(value==0x1001f && !device_irq_pending(&aic,&aic_state));
    CHECK(!device_irq_pending(&aic,0) && !device_irq_pending(0,&aic_state));
    value=1UL<<7;CHECK(device_model_access_state(&aic,&aic_state,0x14600,4,1,&value)==DEVICE_OK);
    CHECK(device_irq_set_level(&aic,&aic_state,7,1)==DEVICE_OK);
    CHECK(device_irq_pending(&aic,&aic_state));
    CHECK(device_model_access_state(&aic,&aic_state,0x14800,4,0,&value)==DEVICE_OK && value==(1UL<<7));
    CHECK(device_irq_set_level(&aic,&aic_state,7,0)==DEVICE_OK);
    CHECK(!device_irq_pending(&aic,&aic_state));
    CHECK(device_irq_set_level(&aic,&aic_state,1280,1)==DEVICE_BAD_VALUE);
    CHECK(device_irq_set_level(0,&aic_state,0,1)==DEVICE_BAD_CONFIG);
    CHECK(device_irq_set_level(&aic,0,0,1)==DEVICE_BAD_CONFIG);
    const uint64_t badcfg[][5]={{0,4096,0x40000,0xa,0},{1281,4096,0x40000,0xa,0},
        {4128,4096,0x40000,0xa,0},{1280,2048,0x40000,0xa,0},{1280,4096,0x10000,0xa,0},
        {1280,4096,0x40001,0xa,0},{1280,4096,0x1cc000,0xa,0},{1280,4096,0x40000,1,0},
        {1280,4096,0x40000,0,0},{1280,4096,0x40000,0xb,0},{1280,4096,0x40000,0xa,1}};
    for(unsigned i=0;i<sizeof(badcfg)/sizeof(*badcfg);i++) {
        for(unsigned j=0;j<5;j++) aic.config[j]=badcfg[i][j];
        CHECK(!device_models_valid(&aic,1,0,0));
    }
    printf("PASS: %u device model checks\n",checks);
}

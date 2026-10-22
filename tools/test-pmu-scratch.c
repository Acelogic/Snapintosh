/* SPDX-License-Identifier: MIT */
/* SNAP_SPMI_SCRATCH host test. Build with -DSNAP_SPMI_SCRATCH=1 (see the
 * patch notes); tools/test-pmu-rtc.c keeps testing the default contract. */
#include "device.h"
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if !SNAP_SPMI_SCRATCH
#error "build with -DSNAP_SPMI_SCRATCH=1"
#endif
static unsigned checks;
#define CHECK(x) do {checks++;if(!(x)){fprintf(stderr,"FAIL %d: %s\n",__LINE__,#x);exit(1);}}while(0)
_Static_assert(sizeof(struct device_state)==13000,"preserve live auditor ABI");
_Static_assert(sizeof(struct device_pmu_rtc)==112,"RTC capture ABI");
_Static_assert(offsetof(struct device_state,pmu_scratch)==offsetof(struct device_state,pmu_rtc),"same union");
_Static_assert(offsetof(struct device_pmu_scratch,legacy)>=sizeof(struct device_pmu_rtc),"no RTC overlap");
static struct device_model model={DEVICE_SPMI_PMU_RTC_V1,0x308700000UL,0x18000,
    {0x14000,0x4000,487,1790200000123456UL,PMU_RTC_CONTRACT}};
static struct device_state state;
static uint64_t now=1000000000UL;
static uint64_t access_at(unsigned reg,int write,uint64_t value)
{
    CHECK(device_model_access_at(&model,&state,now,0x14000+reg,4,write,&value)==DEVICE_OK);
    return value;
}
static uint32_t command(unsigned reg,unsigned n,int write,unsigned sid)
{return (reg<<16)|0x8000|(sid<<8)|((write?0x30:0x38)+n-1);}
static void submit(uint32_t cmd,const uint8_t *bytes,unsigned n)
{
    access_at(4,1,cmd);
    for(unsigned j=0;j<n;j+=4) {
        uint32_t word=0;for(unsigned b=0;b<4 && j+b<n;b++)word|=(uint32_t)bytes[j+b]<<(8*b);
        access_at(4,1,word);
    }
}
/* One long read. Returns 1 when served (all frames valid), 0 when NACKed
 * (header without frame bits, zero padding, failed-read flag). */
static int rd(unsigned reg,unsigned n,unsigned sid,uint8_t *out)
{
    access_at(0x80,1,UINT32_MAX);
    uint32_t cmd=command(reg,n,0,sid);submit(cmd,0,0);
    uint32_t hdr=(uint32_t)access_at(8,0,0);
    uint8_t bytes[8]={0};
    for(unsigned j=0;j<n;j+=4){uint32_t w=(uint32_t)access_at(8,0,0);for(unsigned b=0;b<4;b++)if(j+b<8)bytes[j+b]=(uint8_t)(w>>(8*b));}
    CHECK(access_at(0,0,0)&(1U<<24)); /* RX drained: no stray frames */
    if(hdr==((cmd&0xfff)|(((1U<<n)-1)<<16))) {
        CHECK(!(state.spmi.flags[8]&(1U<<6)));
        if(out)memcpy(out,bytes,n);
        return 1;
    }
    CHECK(hdr==(cmd&0xfff));CHECK(state.spmi.flags[8]&(1U<<6));
    for(unsigned b=0;b<n;b++)CHECK(!bytes[b]);
    return 0;
}
static int wr(unsigned reg,unsigned n,unsigned sid,const uint8_t *in)
{
    access_at(0x80,1,UINT32_MAX);
    uint32_t cmd=command(reg,n,1,sid);submit(cmd,in,n);
    uint32_t hdr=(uint32_t)access_at(8,0,0);
    CHECK(access_at(0,0,0)&(1U<<24));
    if(hdr==((cmd&0xfff)|(1U<<15))){CHECK(!(state.spmi.flags[8]&(1U<<7)));return 1;}
    CHECK(hdr==(cmd&0xfff));CHECK(state.spmi.flags[8]&(1U<<7));
    return 0;
}
static int served(unsigned a,unsigned n)
{
    if(a>=0xf700&&a+n<=0xf800)
        return !((a<0xf708&&a+n>0xf704)||(a<0xf717&&a+n>0xf715));
    return a>=0x8f80&&a+n<=0x9000;
}
static int rtc_field(unsigned a,unsigned n)
{
    return (a>=0xf704&&a<=0xf707&&n<=0xf708-a)||(a>=0xf715&&a<=0xf716&&n<=0xf717-a)||
           (a>=0xf802&&a<=0xf807&&n<=0xf808-a);
}
int main(void)
{
    CHECK(device_model_start(&model,&state,now,24000000)==DEVICE_OK);
    uint8_t b[8];
    /* The exact 26A428 steady poll (b11v1 console): every read now served, zero. */
    static const unsigned poll[][2]={{0x8f84,4},{0xf701,1},{0xf708,4},{0xf702,1},
        {0xf718,1},{0xf719,2},{0xf700,1},{0x8fdc,4}};
    for(unsigned i=0;i<8;i++){memset(b,0xee,8);CHECK(rd(poll[i][0],poll[i][1],14,b));for(unsigned k=0;k<poll[i][1];k++)CHECK(!b[k]);}
    /* Boot sequence: writes f701/f702/f703/f708 are ACKed and read back. */
    uint8_t v1[]={0x5a},v4[]={0x11,0x22,0x33,0x44},v8[]={1,2,3,4,5,6,7,8};
    CHECK(wr(0xf701,1,14,v1));CHECK(rd(0xf701,1,14,b)&&b[0]==0x5a);
    CHECK(wr(0xf708,4,14,v4));CHECK(rd(0xf708,4,14,b)&&!memcmp(b,v4,4));
    CHECK(rd(0xf709,2,14,b)&&b[0]==0x22&&b[1]==0x33);
    CHECK(wr(0x8fdc,4,14,v4));CHECK(rd(0x8fdc,4,14,b)&&!memcmp(b,v4,4));
    /* The 56-byte LPM log at 8f80 arrives as seven 8-byte long reads. */
    CHECK(wr(0x8f80,8,14,v8));
    for(unsigned k=0;k<7;k++){CHECK(rd(0x8f80+8*k,8,14,b));if(!k)CHECK(!memcmp(b,v8,8));}
    /* RTC fields keep their own model and storage. */
    uint64_t rejected=state.pmu_rtc.rejected,reads=state.pmu_scratch.reads,writes=state.pmu_scratch.writes;
    CHECK(wr(0xf704,4,14,v4));CHECK(!memcmp(state.pmu_rtc.offset,v4,4));
    for(unsigned k=4;k<8;k++)CHECK(!state.pmu_scratch.legacy[k]);
    CHECK(rd(0xf704,4,14,b)&&!memcmp(b,v4,4));CHECK(rd(0xf802,6,14,b));
    CHECK(state.pmu_rtc.rejected==rejected);CHECK(state.pmu_scratch.reads==reads);
    CHECK(state.pmu_scratch.writes==writes);
    /* Exhaustive address/length map, reads and writes, SID 14 and others. */
    unsigned served_reads=0;
    for(unsigned a=0;a<0x10000;a++)for(unsigned n=1;n<=8;n++){
        rejected=state.pmu_rtc.rejected;reads=state.pmu_scratch.reads;
        int ok=rd(a,n,14,0);
        CHECK(ok==(served(a,n)||rtc_field(a,n)));
        if(served(a,n)){served_reads++;CHECK(state.pmu_scratch.reads==reads+1);CHECK(state.pmu_rtc.rejected==rejected);}
        else {CHECK(state.pmu_scratch.reads==reads);CHECK(state.pmu_rtc.rejected==rejected+!ok);}
    }
    CHECK(served_reads==2918); /* (address,length) pairs, counted independently */
    for(unsigned sid=0;sid<16;sid++)if(sid!=14)for(unsigned i=0;i<8;i++)CHECK(!rd(poll[i][0],poll[i][1],sid,0));
    for(unsigned sid=0;sid<16;sid++)if(sid!=14)CHECK(!wr(0xf701,1,sid,v1));
    CHECK(rd(0xf701,1,14,b)&&b[0]==0x5a);
    for(unsigned a=0xf6f8;a<0xf808;a++)CHECK(wr(a,1,14,v1)==(served(a,1)||(rtc_field(a,1)&&a<0xf800)));
    CHECK(!wr(0x8800,4,14,v4));CHECK(!wr(0xf802,4,14,v4));
    /* Other command forms still refuse: extended (8-bit address) and short. */
    access_at(0x80,1,UINT32_MAX);
    uint32_t cmd=(0x19U<<16)|(14U<<8)|0x21;access_at(4,1,cmd);
    CHECK(access_at(8,0,0)==(cmd&0xfff));CHECK(access_at(8,0,0)==0);
    cmd=(0x5aU<<24)|(0x01U<<16)|(14U<<8)|0x40;access_at(4,1,cmd);
    CHECK(access_at(8,0,0)==(cmd&0xfff));
    /* Restart clears the scratchpad (volatile; nothing persists). */
    CHECK(device_model_start(&model,&state,now,24000000)==DEVICE_OK);
    CHECK(rd(0xf701,1,14,b)&&!b[0]);CHECK(rd(0xf708,4,14,b)&&!b[0]&&!b[3]);
    CHECK(state.pmu_scratch.reads==2&&!state.pmu_scratch.writes);
    printf("PASS %u PMU scratchpad, RTC coexistence, refusal and ABI checks\n",checks);
    return 0;
}

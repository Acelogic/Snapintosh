/* SPDX-License-Identifier: MIT */
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "device.h"
#include "mmio.h"
static unsigned checks;
#define CHECK(x) do { checks++; if (!(x)) { \
    fprintf(stderr,"line %u: %s\n",__LINE__,#x); exit(1); } } while (0)
static struct device_model model={45,0x282600000,0x9000,{8,0,0,0,0}};
static struct device_state state,before;
static void reset(void)
{
    memset(&state,0xa5,sizeof(state));
    CHECK(device_model_start(&model,&state,0,24000000)==DEVICE_OK);
    CHECK(state.sep_asc.ready==1 && state.sep_asc.enable[0]==1 && !state.sep_asc.enable[1]);
}
static uint64_t read_control(unsigned side)
{
    uint64_t v=UINT64_MAX;
    CHECK(device_model_access_state(&model,&state,0x8110+4*side,4,0,&v)==DEVICE_OK);
    return v;
}
static void control(unsigned side,uint64_t v)
{
    CHECK(device_model_access_state(&model,&state,0x8110+4*side,4,1,&v)==DEVICE_OK);
}
static void refused(unsigned off,unsigned width,int write,uint64_t v,enum device_result result)
{
    before=state;uint64_t original=v;
    CHECK(device_model_access_state(&model,&state,off,width,write,&v)==result);
    CHECK(v==original && !memcmp(&before,&state,sizeof(state)));
}
static void pair_refused(unsigned off,enum device_result result)
{
    uint64_t v[2]={0x1122334455667788UL,0xffeeddccbbaa9988UL};
    before=state;
    CHECK(device_model_write_pair(&model,&state,off,v)==result);
    CHECK(!memcmp(&before,&state,sizeof(state)));
}
static void test_frontend(void)
{
    reset();CHECK(read_control(0)==0x20001 && read_control(1)==0x20000);
    control(1,read_control(1)|1);CHECK(read_control(1)==0x20001);
    CHECK(state.sep_asc.reads[0]==1 && state.sep_asc.reads[1]==3 && state.sep_asc.writes[1]==1);
    for (unsigned i=0;i<8;i++) {
        uint64_t v[2]={0x500ffUL+i,0x1122334455660000UL+i};
        CHECK(device_model_write_pair(&model,&state,0x8800,v)==DEVICE_OK);
        CHECK(state.sep_asc.count==i+1 && state.sep_asc.submitted==i+1);
        CHECK(!memcmp(state.sep_asc.request[i],v,sizeof(v)));
        uint64_t status=read_control(0);
        CHECK(((status>>20)&15)==i+1 && !(status&(1<<17)));
        CHECK(!!(status&(1<<16))==(i==7));
        CHECK(read_control(1)==0x20001 && !device_irq_pending(&model,&state));
    }
    pair_refused(0x8800,DEVICE_BAD_VALUE);
    refused(0x8800,8,1,123,DEVICE_BAD_VALUE);
    before=state;control(0,0);CHECK(!state.sep_asc.enable[0]);
    CHECK(!memcmp(before.sep_asc.request,state.sep_asc.request,sizeof(state.sep_asc.request)));
    control(0,1);CHECK(state.sep_asc.count==8);
    uint64_t receive[2]={123,456};before=state;
    CHECK(device_model_read_pair(&model,&state,0x8830,receive)==DEVICE_BAD_VALUE);
    CHECK(receive[0]==123 && receive[1]==456 && !memcmp(&before,&state,sizeof(state)));
    refused(0x8830,8,0,999,DEVICE_BAD_VALUE);
    refused(0x8838,8,1,999,DEVICE_READ_ONLY);
    reset();uint64_t first=123,second=456;
    refused(0x8808,8,1,second,DEVICE_BAD_VALUE);
    CHECK(device_model_access_state(&model,&state,0x8800,8,1,&first)==DEVICE_OK);
    CHECK(state.sep_asc.staged_valid && !state.sep_asc.count);
    pair_refused(0x8800,DEVICE_BAD_VALUE);
    refused(0x8800,8,1,999,DEVICE_BAD_VALUE);
    control(0,0);refused(0x8808,8,1,second,DEVICE_BAD_VALUE);
    control(0,1);
    CHECK(device_model_access_state(&model,&state,0x8808,8,1,&second)==DEVICE_OK);
    CHECK(state.sep_asc.request[0][0]==first && state.sep_asc.request[0][1]==second);
    CHECK(!state.sep_asc.staged_valid && !state.sep_asc.staged && state.sep_asc.count==1);
    for (unsigned side=0;side<2;side++) {
        for (unsigned width=0;width<=16;width++) if (width!=4)
            refused(0x8110+4*side,width,0,0,DEVICE_BAD_WIDTH);
        for (unsigned bit=0;bit<64;bit++) if (!((0x00f3ff01UL>>bit)&1))
            refused(0x8110+4*side,4,1,1UL<<bit,DEVICE_BAD_VALUE);
    }
    for (unsigned width=0;width<=16;width++) if (width!=8) {
        refused(0x8800,width,1,0,DEVICE_BAD_WIDTH);
        refused(0x8830,width,0,0,DEVICE_BAD_WIDTH);
    }
    for (unsigned off=0;off<0x9000;off+=4) {
        if (off==0x8110 || off==0x8114 || off==0x8800 || off==0x8808 || off==0x8830 || off==0x8838) continue;
        refused(off,4,0,0xfeed,DEVICE_UNKNOWN_REGISTER);
        refused(off,4,1,0xfeed,DEVICE_UNKNOWN_REGISTER);
    }
    pair_refused(0x8808,DEVICE_UNKNOWN_REGISTER);
    pair_refused(0x8804,DEVICE_BAD_WIDTH);
    pair_refused(0x8ff8,DEVICE_NOT_FOUND);
    for (unsigned field=0;field<5;field++) {
        reset();model.config[field]^=1;
        pair_refused(0x8800,DEVICE_BAD_CONFIG);model.config[field]^=1;
    }
    for (unsigned field=0;field<5;field++) {
        reset();uint32_t bad=100;
        memcpy((char *)&state.sep_asc+offsetof(struct device_sep_asc,ready)+4*field,&bad,4);
        pair_refused(0x8800,DEVICE_BAD_CONFIG);
        refused(0x8114,4,0,9,DEVICE_BAD_CONFIG);
    }
    reset();state.sep_asc.submitted=1;pair_refused(0x8800,DEVICE_BAD_CONFIG);
    reset();state.sep_asc.staged=1;pair_refused(0x8800,DEVICE_BAD_CONFIG);
    for (unsigned slot=0;slot<8;slot++) for (unsigned word=0;word<2;word++) {
        reset();state.sep_asc.request[slot][word]=1;
        pair_refused(0x8800,DEVICE_BAD_CONFIG);
    }
    reset();control(0,0);pair_refused(0x8800,DEVICE_BAD_VALUE);
}
static void test_power_binding(void)
{
    struct device_model models[]={
        {18,0x300700000,0x11000,{0,0,0,0,0}},
        {17,0x280b80000,0x20000,{3,DEVICE_DART_SEP_BOOT_V1,353,36,1U<<20}},
        {25,0x3003c0000,0x14000,{0x10000,0x1a8,0x1b8,8,DEVICE_PMP_ACTIVE_MASK}},
        {18,0x308280000,0x9000,{1,0,0,0,0}},
        {45,0x282600000,0x9000,{8,0,0,0,0}},
    };
    static struct device_state states[5],saved[5];
    memset(states,0,sizeof(states));
    for (unsigned i=0;i<5;i++) CHECK(device_model_start(models+i,states+i,0,24000000)==DEVICE_OK);
    uint64_t v=0;
    CHECK(device_models_valid(models,5,0,0));
    enum device_result initial=device_models_access_at(models,states,5,0,0,0x60,4,0,&v);
    if (initial!=DEVICE_OK || v!=0xff) fprintf(stderr,"SEP binding read result%u value%llx\n",initial,(unsigned long long)v);
    CHECK(initial==DEVICE_OK && v==0xff);
    const unsigned levels[]={0,4,15};
    for (unsigned i=0;i<3;i++) {
        v=levels[i];CHECK(device_models_access_at(models,states,5,0,0,0x60,4,1,&v)==DEVICE_OK);
    }
    /* Mailbox enable state alone has no firmware or DMA producer. */
    v=1;CHECK(device_models_access_at(models,states,5,4,0,0x8114,4,1,&v)==DEVICE_OK);
    for (unsigned staged=0;staged<2;staged++) {
        CHECK(device_model_start(models+4,states+4,0,24000000)==DEVICE_OK);
        uint64_t packet[2]={0x500ff,0};
        if (staged) {
            v=packet[0];CHECK(device_models_access_at(models,states,5,4,0,0x8800,8,1,&v)==DEVICE_OK);
        } else CHECK(device_model_write_pair(models+4,states+4,0x8800,packet)==DEVICE_OK);
        for (unsigned i=0;i<3;i++) {
            memcpy(saved,states,sizeof(states));v=levels[i];
            CHECK(device_models_access_at(models,states,5,0,0,0x60,4,1,&v)==DEVICE_BAD_VALUE);
            CHECK(!memcmp(saved,states,sizeof(states)) && v==levels[i]);
        }
        v=0;CHECK(device_models_access_at(models,states,5,0,0,0x60,4,0,&v)==DEVICE_OK);
    }
    CHECK(device_model_start(models+4,states+4,0,24000000)==DEVICE_OK);
    models[4].config[1]=1;models[4].config[2]=346;models[4].config[3]=343;
    uint64_t reply[2]={0x706e6f6e050000fdUL,0};
    CHECK(device_sep_asc_reply(models+4,states+4,reply)==DEVICE_OK);
    memcpy(saved,states,sizeof(states));v=0;
    CHECK(device_models_access_at(models,states,5,0,0,0x60,4,1,&v)==DEVICE_BAD_VALUE);
    CHECK(!memcmp(saved,states,sizeof(states)));
    v=1;CHECK(device_model_access_state(models+4,states+4,0x8114,4,1,&v)==DEVICE_OK);
    uint64_t received[2];
    CHECK(device_model_read_pair(models+4,states+4,0x8830,received)==DEVICE_OK);
    CHECK(!memcmp(reply,received,sizeof(reply)));
    v=0;CHECK(device_models_access_at(models,states,5,0,0,0x60,4,1,&v)==DEVICE_OK);
    CHECK(device_dart_monitor_init(models,states,5,20)==DEVICE_OK);
    CHECK(device_dart_monitor_powerup(models,states,5,20)==DEVICE_OK);
    CHECK(states[1].dart.powered_ids==(1U<<20) && states[1].dart.tcr[0]==1);
    memcpy(saved,states,sizeof(states));v=0;
    CHECK(device_models_access_at(models,states,5,0,0,0x60,4,1,&v)==DEVICE_BAD_VALUE);
    CHECK(!memcmp(saved,states,sizeof(states)));
    /* The exception does not authorize different or larger SEP models. */
    models[4].span=0x88000;v=0;
    CHECK(device_models_access_at(models,states,5,0,0,0x60,4,0,&v)==DEVICE_BAD_CONFIG);
    models[4].span=0x9000;models[4].base=0x282050000;
    CHECK(device_models_access_at(models,states,5,0,0,0x60,4,0,&v)==DEVICE_BAD_CONFIG);
}

static void reject_decode(uint32_t word,uint64_t esr,const uint64_t regs[31],uint64_t sp)
{
    struct mmio_pair pair={123,{11,12}},saved=pair;
    CHECK(!mmio_stp64_decode(word,esr,regs,sp,&pair));
    CHECK(!memcmp(&pair,&saved,sizeof(pair)));
}
static void test_store_pairs(void)
{
    uint64_t regs[31],saved[31];
    for (unsigned i=0;i<31;i++) regs[i]=0x10000;
    memcpy(saved,regs,sizeof(regs));
    for (unsigned base=0;base<32;base++) for (unsigned imm=0;imm<128;imm++) {
        uint32_t word=0xa9000000U|(imm<<15)|(10<<10)|(base<<5)|9;
        struct mmio_pair pair;
        int delta=(int)imm;if (imm&64) delta-=128;
        CHECK(mmio_stp64_decode(word,0x92000047,regs,0x10000,&pair));
        CHECK(pair.address==(uint64_t)(0x10000+(int64_t)delta*8) && pair.reg[0]==9 && pair.reg[1]==10);
        CHECK(!memcmp(regs,saved,sizeof(regs)));
    }
    for (unsigned first=0;first<32;first++) for (unsigned second=0;second<32;second++) {
        uint32_t word=0xa9000000U|(second<<10)|(8<<5)|first;
        struct mmio_pair pair;
        CHECK(mmio_stp64_decode(word,0x9200004f,regs,0x10000,&pair));
        CHECK(pair.reg[0]==first && pair.reg[1]==second);
    }
    const uint32_t native=0xa9002909; /* STP x9,x10,[x8], native8b08a78. */
    for (unsigned bit=0;bit<32;bit++) if (bit>=22)
        reject_decode(native^(1U<<bit),0x92000047,regs,0x10000);
    for (unsigned bit=6;bit<32;bit++) if (bit<=10 || bit>=24)
        reject_decode(native,0x92000047^(1UL<<bit),regs,0x10000);
    for (unsigned fault=0;fault<64;fault++) if ((fault&0x3c)!=4 && (fault&0x3c)!=12)
        reject_decode(native,0x92000040|fault,regs,0x10000);
    regs[8]=0;reject_decode(native|(127<<15),0x92000047,regs,0x10000);
    regs[8]=UINT64_MAX-7;reject_decode(native,0x92000047,regs,0x10000);
    regs[8]=UINT64_MAX-15;reject_decode(native|(2<<15),0x92000047,regs,0x10000);
    regs[8]=0x10001;reject_decode(native,0x92000047,regs,0x10000);
    reject_decode((native&~(31U<<5))|(31<<5),0x92000047,regs,0x10008);
    regs[8]=0x282608800;regs[9]=0x500ff;regs[10]=0;
    struct mmio_pair pair;CHECK(mmio_stp64_decode(native,0x92000047,regs,0,&pair));
    uint64_t v[2]={regs[pair.reg[0]],regs[pair.reg[1]]};
    reset();CHECK(device_model_write_pair(&model,&state,pair.address-model.base,v)==DEVICE_OK);
    CHECK(state.sep_asc.request[0][0]==0x500ff && !state.sep_asc.request[0][1]);
}
static void read_pair_refused(unsigned offset,enum device_result want)
{
    uint64_t out[2]={0x12345678,0xabcdef};before=state;
    CHECK(device_model_read_pair(&model,&state,offset,out)==want);
    CHECK(out[0]==0x12345678 && out[1]==0xabcdef && !memcmp(&before,&state,sizeof(state)));
}

static void test_reply_transport(void)
{
    reset();uint64_t packet[2]={0x706e6f6e050000fdUL,0};before=state;
    CHECK(device_sep_asc_reply(&model,&state,packet)==DEVICE_BAD_CONFIG);
    CHECK(!memcmp(&before,&state,sizeof(state)));
    model.config[1]=1;model.config[2]=346;model.config[3]=343;
    reset();read_pair_refused(0x8830,DEVICE_BAD_VALUE);
    for (unsigned batch=0;batch<512;batch++) {
        control(1,0);
        for (unsigned i=0;i<8;i++) {
            uint64_t msg[2]={(uint64_t)batch*8+i,~((uint64_t)batch*8+i)};
            CHECK(device_model_write_pair(&model,&state,0x8800,msg)==DEVICE_OK);
            CHECK(device_sep_asc_reply(&model,&state,msg)==DEVICE_OK);
        }
        CHECK((read_control(1)&0xf10000)==0x810000);
        before=state;CHECK(device_sep_asc_reply(&model,&state,packet)==DEVICE_BAD_VALUE);
        CHECK(!memcmp(&before,&state,sizeof(state)));
        read_pair_refused(0x8830,DEVICE_BAD_VALUE); /* queued but disabled */
        read_pair_refused(0x8838,DEVICE_UNKNOWN_REGISTER);
        read_pair_refused(0x8834,DEVICE_BAD_WIDTH);
        read_pair_refused(0x8ff8,DEVICE_NOT_FOUND);
        control(1,1);
        /* The stock driver's exact LDP X8,X9,[X8], with the fault at either lane. */
        uint64_t regs[31]={0};regs[8]=model.base+0x8830;
        struct mmio_pair pair;
        CHECK(mmio_ldp64_decode(0xa9402508,0x92000007,regs,0,&pair));
        for (unsigned i=0;i<8;i++) {
            uint64_t request[2],out[2];
            CHECK(device_sep_asc_take_request(&model,&state,request)==DEVICE_OK);
            CHECK(device_model_read_pair(&model,&state,0x8830,out)==DEVICE_OK);
            CHECK(out[0]==(uint64_t)batch*8+i && out[1]==~out[0]);
            CHECK(!memcmp(request,out,sizeof(out)));
            mmio_ldp64_complete(&pair,out,regs);CHECK(regs[8]==out[0] && regs[9]==out[1]);
            CHECK(((read_control(1)>>12)&15)==((i+1)%8));
        }
        CHECK(state.sep_asc.submitted==state.sep_asc.consumed &&
              state.sep_asc.published==state.sep_asc.delivered);
        CHECK((read_control(1)&0xf30000)==0x20000);
        read_pair_refused(0x8830,DEVICE_BAD_VALUE);
        uint64_t out[2]={123,456};before=state;
        CHECK(device_sep_asc_take_request(&model,&state,out)==DEVICE_BAD_VALUE);
        CHECK(out[0]==123 && out[1]==456 && !memcmp(&before,&state,sizeof(state)));
    }
    for (unsigned kind=0;kind<5;kind++) {
        reset();control(1,1);
        if (kind==0) state.sep_asc.reply_count=9;
        if (kind==1) state.sep_asc.published=1;
        if (kind==2) state.sep_asc.delivered=1;
        if (kind==3) state.sep_asc.reply[7][1]=1;
        if (kind==4) state.sep_asc.consumed=1;
        read_pair_refused(0x8830,DEVICE_BAD_CONFIG);
        before=state;CHECK(device_sep_asc_reply(&model,&state,packet)==DEVICE_BAD_CONFIG);
        CHECK(!memcmp(&before,&state,sizeof(state)));
    }
    reset();state.sep_asc.submitted=state.sep_asc.consumed=UINT64_MAX;
    pair_refused(0x8800,DEVICE_BAD_VALUE);
    refused(0x8800,8,1,123,DEVICE_BAD_VALUE);
    state.sep_asc.published=state.sep_asc.delivered=UINT64_MAX;
    before=state;CHECK(device_sep_asc_reply(&model,&state,packet)==DEVICE_BAD_VALUE);
    CHECK(!memcmp(&before,&state,sizeof(state)));
    model.config[1]=model.config[2]=model.config[3]=0;
}

static void test_reply_irqs(void)
{
    struct device_model models[]={
        {45,0x282600000,0x9000,{8,1,346,343,0}},
        {DEVICE_AIC3_FLAT_V1,0x301000000UL,0x1cc000,{1280,4096,0x40000,10,0}},
    };
    static struct device_state states[2],saved[2];
    for (unsigned i=0;i<2;i++) CHECK(device_model_start(models+i,states+i,0,24000000)==DEVICE_OK);
    CHECK(device_models_route_irqs(models,states,2)==DEVICE_OK);
    CHECK(states[1].aic.level[343/32]&(1U<<(343%32)));
    CHECK(!(states[1].aic.level[346/32]&(1U<<(346%32))));
    uint64_t message[2]={0x706e6f6e050000fdUL,0},out[2];
    CHECK(device_model_write_pair(models,states,0x8800,message)==DEVICE_OK);
    CHECK(device_sep_asc_reply(models,states,message)==DEVICE_OK);
    CHECK(device_models_route_irqs(models,states,2)==DEVICE_OK);
    CHECK(!(states[1].aic.level[343/32]&(1U<<(343%32))));
    CHECK(!(states[1].aic.level[346/32]&(1U<<(346%32)))); /* disabled */
    uint64_t value=1;CHECK(device_model_access_state(models,states,0x8114,4,1,&value)==DEVICE_OK);
    CHECK(device_models_route_irqs(models,states,2)==DEVICE_OK);
    CHECK(states[1].aic.level[346/32]&(1U<<(346%32)));
    CHECK(device_sep_asc_take_request(models,states,out)==DEVICE_OK);
    CHECK(device_model_read_pair(models,states,0x8830,out)==DEVICE_OK);
    CHECK(device_models_route_irqs(models,states,2)==DEVICE_OK);
    CHECK(states[1].aic.level[343/32]&(1U<<(343%32)));
    CHECK(!(states[1].aic.level[346/32]&(1U<<(346%32))));
    states[0].sep_asc.reply_count=9;memcpy(saved,states,sizeof(states));
    CHECK(device_models_route_irqs(models,states,2)==DEVICE_BAD_CONFIG);
    CHECK(!memcmp(saved,states,sizeof(states)));
}

int main(void)
{
    test_frontend();test_power_binding();test_store_pairs();
    test_reply_transport();test_reply_irqs();
    printf("SEP ASC request/reply transport and integer pairs: %u checks passed\n",checks);
    return 0;
}

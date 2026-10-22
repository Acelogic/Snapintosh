/* SPDX-License-Identifier: MIT */
#define main transport_checks
#include "test-sep-asc.c"
#undef main

/* Exercise controls without admitting any firmware/shared-memory buffer. */
static enum device_result device_sep_rom_status_step(const struct device_model *m,
    struct device_state *s) {return device_sep_rom_step(m,s,0);}

static void rom_reset(void)
{
    model=(struct device_model){45,0x282600000,0x9000,{8,1,346,343,1}};
    reset();
}
static void request(uint64_t first,uint64_t second)
{
    const uint64_t words[2]={first,second};
    CHECK(device_model_write_pair(&model,&state,0x8800,words)==DEVICE_OK);
}
int main(int argc,char **argv)
{
    if(argc==3 && !strcmp(argv[1],"--reply")) {
        unsigned tag=(unsigned)strtoul(argv[2],0,0);CHECK(tag<256);
        rom_reset();request(0x200ff|(uint64_t)tag<<8,0);
        CHECK(device_sep_rom_status_step(&model,&state)==DEVICE_OK);
        printf("%llx\n",(unsigned long long)state.sep_asc.reply[0][0]);return 0;
    }
    transport_checks();
    for(unsigned tag=0;tag<256;tag++) {
        rom_reset();uint64_t req=0x200ff|(uint64_t)tag<<8;
        request(req,0);CHECK(device_sep_rom_status_step(&model,&state)==DEVICE_OK);
        CHECK(state.sep_asc.rom_status_replies==1 && state.sep_asc.consumed==1);
        CHECK(state.sep_asc.rom_last_request==req && state.sep_asc.rom_last_reply==(0x1006600ffUL|(uint64_t)tag<<8));
        CHECK(!state.sep_asc.count && state.sep_asc.reply_count==1 && state.sep_asc.published==1);
        control(1,1);uint64_t out[2];
        CHECK(device_model_read_pair(&model,&state,0x8830,out)==DEVICE_OK);
        CHECK(out[0]==state.sep_asc.rom_last_reply && !out[1] && state.sep_asc.delivered==1);
        before=state;CHECK(device_sep_rom_status_step(&model,&state)==DEVICE_OK);
        CHECK(!memcmp(&before,&state,sizeof state));
    }
    for(unsigned bit=0;bit<128;bit++) {
        if(bit>=8 && bit<16)continue; /* Tags are permitted and echoed. */
        rom_reset();request(0x201ff^(bit<64 ? 1UL<<bit : 0),bit>=64 ? 1UL<<(bit-64) : 0);
        before=state;
        CHECK(device_sep_rom_status_step(&model,&state)!=DEVICE_OK);
        CHECK(!memcmp(&before,&state,sizeof state));
    }
    rom_reset();
    for(unsigned i=0;i<8;i++){request(0x201ff,0);CHECK(device_sep_rom_status_step(&model,&state)==DEVICE_OK);}
    request(0x201ff,0);before=state;
    CHECK(device_sep_rom_status_step(&model,&state)==DEVICE_BAD_VALUE);
    CHECK(!memcmp(&before,&state,sizeof state));
    control(1,1);uint64_t out[2];
    CHECK(device_model_read_pair(&model,&state,0x8830,out)==DEVICE_OK);
    CHECK(device_sep_rom_status_step(&model,&state)==DEVICE_OK);
    CHECK(state.sep_asc.rom_status_replies==9 && !state.sep_asc.count);
    for(unsigned i=0;i<6;i++) {
        rom_reset();request(0x201ff,0);
        if(i==0)state.sep_asc.rom_status_replies=1;
        if(i==1)state.sep_asc.rom_last_request=0x201ff;
        if(i==2)state.sep_asc.rom_last_reply=0x1006601ff;
        if(i==3)state.sep_asc.ready=0;
        if(i==4)model.config[4]=0;
        if(i==5)model.config[1]=0;
        before=state;CHECK(device_sep_rom_status_step(&model,&state)==DEVICE_BAD_CONFIG);
        CHECK(!memcmp(&before,&state,sizeof state));
    }
    rom_reset();request(0x901ff,0);before=state;
    CHECK(device_sep_rom_status_step(&model,&state)==DEVICE_UNKNOWN_REGISTER);
    CHECK(!memcmp(&before,&state,sizeof state));
    CHECK(device_sep_asc_take_request(&model,&state,out)==DEVICE_BAD_CONFIG);
    CHECK(device_sep_asc_reply(&model,&state,out)==DEVICE_BAD_CONFIG);
    struct device_model models[]={model,{DEVICE_AIC3_FLAT_V1,0x301000000UL,0x1cc000,{1280,4096,0x40000,10,0}}};
    static struct device_state states[2];
    for(unsigned i=0;i<2;i++)CHECK(device_model_start(models+i,states+i,0,24000000)==DEVICE_OK);
    uint64_t words[2]={0x201ff,0},enable=1;
    CHECK(device_model_write_pair(models,states,0x8800,words)==DEVICE_OK);
    CHECK(device_sep_rom_status_step(models,states)==DEVICE_OK);
    CHECK(device_models_route_irqs(models,states,2)==DEVICE_OK);
    CHECK(!(states[1].aic.level[346/32]&(1U<<(346%32))));
    CHECK(device_model_access_state(models,states,0x8114,4,1,&enable)==DEVICE_OK);
    CHECK(device_models_route_irqs(models,states,2)==DEVICE_OK);
    CHECK(states[1].aic.level[346/32]&(1U<<(346%32)));
    CHECK(states[1].aic.level[343/32]&(1U<<(343%32)));
    CHECK(device_model_read_pair(models,states,0x8830,out)==DEVICE_OK);
    CHECK(device_models_route_irqs(models,states,2)==DEVICE_OK);
    CHECK(!(states[1].aic.level[346/32]&(1U<<(346%32))));
    printf("PASS: %u transport and ROM status checks\n",checks);return 0;
}

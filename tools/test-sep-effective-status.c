/* SPDX-License-Identifier: MIT */
#define SEP_PNON_TEST_MAIN pnon_checks
#include "test-sep-pnon.c"
int main(int argc,char **argv)
{
    CHECK(argc==2 || (argc==3 && !strcmp(argv[1],"--wire")));
    FILE *f=fopen(argv[argc-1],"rb");CHECK(f);
    CHECK(fread(saved_payload,1,sizeof saved_payload,f)==sizeof saved_payload);
    CHECK(fgetc(f)==EOF);CHECK(!fclose(f));
    CHECK(DEVICE_SEP_EFFECTIVE_STATUS==0);
    for(unsigned tag=1;tag<256;tag++) {
        pnon_reset();uint64_t req=0x140000|(uint64_t)tag<<8;
        uint64_t response=call(req,1);
        CHECK(response==req && !(response>>32));
        CHECK(state.sep_asc.status_queries==1 && state.sep_asc.status_last_request==req);
        CHECK(state.sep_asc.consumed==6 && state.sep_asc.published==8 && state.sep_asc.delivered==8);
        CHECK(!state.sep_asc.pnon.negotiations && !state.sep_asc.pnon.queries && !entropy_calls);
        CHECK(call(req,1)==req && state.sep_asc.status_queries==2);
        if(argc==3){printf("%llx\n",(unsigned long long)response);continue;}
        configure_buffers(tag,0);CHECK(call(SEP_PNON_QUERY,1)==SEP_PNON_REPLY);
        entropy_value=0x12345678;CHECK(call(0x360000|(uint64_t)tag<<8,1)==(0x1234567800360000UL|(uint64_t)tag<<8));
        CHECK(call(req,1)==req && state.sep_asc.status_queries==3);
        CHECK(state.sep_asc.pnon.negotiations==4 && state.sep_asc.pnon.queries==1 && state.sep_asc.entropy_words==1);
    }
    if(argc==3)return 0;
    for(unsigned bit=0;bit<64;bit++) {
        if(bit>=8 && bit<16)continue;
        pnon_reset();submit(0x140800^(1UL<<bit));before=state;
        CHECK(device_sep_rom_step(&model,&state,&resources)!=DEVICE_OK);
        CHECK(!memcmp(&state,&before,sizeof state));
    }
    for(unsigned test=0;test<9;test++) {
        pnon_reset();uint64_t req=0x140800;
        if(test==0)req=0x140000;
        if(test==1)active(); /* Mode3 cannot assert this explicit mode7 policy. */
        if(test==2){service_reset();model.config[4]=7;} /* Before ROM startup. */
        if(test>=3)call(req,1);
        submit(req);
        if(test==3)state.sep_asc.status_queries++;
        if(test==4)state.sep_asc.status_last_request=0;
        if(test==5)state.sep_asc.status_last_request|=1UL<<32;
        if(test==6)state.sep_asc.status_last_request=0x140000;
        if(test==7)state.sep_asc.status_queries=UINT64_MAX;
        if(test==8)state.sep_asc.request[0][1]=1;
        before=state;CHECK(device_sep_rom_step(&model,&state,&resources)!=DEVICE_OK);
        CHECK(!memcmp(&state,&before,sizeof state));
    }
    pnon_reset();
    for(unsigned i=0;i<8;i++){submit(0x140800);CHECK(device_sep_rom_step(&model,&state,&resources)==DEVICE_OK);}
    submit(0x140800);before=state;
    CHECK(device_sep_rom_step(&model,&state,&resources)==DEVICE_BAD_VALUE);
    CHECK(!memcmp(&state,&before,sizeof state));
    printf("PASS: %u explicit virtual effective-status checks\n",checks);return 0;
}

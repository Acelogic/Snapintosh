/* SPDX-License-Identifier: MIT */
#define SEP_ROM_TEST_MAIN rom_checks
#include "test-sep-rom-boot.c"
static uint8_t payload[0x14000],saved_payload[sizeof payload];
static unsigned resource_reads,fail_read,bad_layout;
static unsigned entropy_calls,entropy_fail;
static uint32_t entropy_value;
static int entropy_source(void *ctx,uint32_t *out)
{
    CHECK(ctx==&admits);entropy_calls++;
    *out=entropy_value; /* Deliberately writes even on failure. */
    return !entropy_fail;
}
static int resource_read(void *ctx,uint32_t off,size_t size,void *out)
{
    CHECK(ctx==payload);resource_reads++;
    CHECK(off<=sizeof payload && size<=sizeof payload-off);
    if(resource_reads==fail_read)return 0;
    memcpy(out,payload+off,size);return 1;
}
static int service_start(void *ctx,uint64_t iova,uint64_t size,struct sep_bootstrap *out)
{
    CHECK(ctx==&admits && iova==SH && size==sizeof payload);admits++;
    struct sep_bootstrap_reader reader={payload,resource_read};
    if(sep_bootstrap_parse(&reader,size,out)!=SEP_BOOTSTRAP_OK)return 0;
    if(bad_layout)out->panic_offset++;
    return 1;
}
static void service_reset(void)
{
    boot_reset();model.config[4]=3;resources.bootstrap=service_start;
    resources.entropy32=entropy_source;entropy_calls=entropy_fail=0;entropy_value=0;
    resource_reads=fail_read=bad_layout=0;memcpy(payload,saved_payload,sizeof payload);
}
static uint64_t service_word(void){return ((SH>>12)<<32)|(sizeof payload>>12<<16)|0xfe;}
static void submit(uint64_t word)
{
    uint64_t words[2]={word,0};
    CHECK(device_model_write_pair(&model,&state,0x8800,words)==DEVICE_OK);
}
static void active(void)
{
    service_reset();bootstrap();call(image(),1);
    CHECK(call(service_word(),1)==0xd0000);
}
#ifndef SEP_SERVICE_TEST_MAIN
#define SEP_SERVICE_TEST_MAIN main
#endif
int SEP_SERVICE_TEST_MAIN(int argc,char **argv)
{
    CHECK(argc==2 || (argc==3 && (!strcmp(argv[1],"--notification") || !strcmp(argv[1],"--entropy"))));
    FILE *f=fopen(argv[argc-1],"rb");CHECK(f);
    CHECK(fread(saved_payload,1,sizeof saved_payload,f)==sizeof saved_payload);
    CHECK(fgetc(f)==EOF);CHECK(!fclose(f));
    if(argc==3 && !strcmp(argv[1],"--entropy")) {
        active();
        for(unsigned tag=1;tag<256;tag++) {
            entropy_value=tag*0x01010101U;
            printf("%llx\n",(unsigned long long)call(0x360000|(uint64_t)tag<<8,1));
        }
        return 0;
    }
    if(argc==3) {
        service_reset();bootstrap();call(image(),1);submit(service_word());
        CHECK(device_sep_rom_step(&model,&state,&resources)==DEVICE_OK);
        uint64_t pair[2];CHECK(device_model_read_pair(&model,&state,0x8830,pair)==DEVICE_OK);
        CHECK(!pair[1]);printf("%llx\n",(unsigned long long)pair[0]);return 0;
    }
    for(unsigned tag=0;tag<256;tag++) {
        service_reset();uint64_t t=(uint64_t)tag<<8;
        CHECK(call(0x200ff|t,1)==(0x1006600ffUL|t));
        CHECK(call(0x500ff|t,1)==(0x6900ff|t));
        CHECK(call(0x200ff|t,1)==(0x2006600ffUL|t));
        uint64_t fw=(image()&~0xff00UL)|t;
        if(tag&1){submit(fw);CHECK(device_sep_rom_step(&model,&state,&resources)==DEVICE_OK);}
        else CHECK(call(fw,1)==(0x6a00ff|t));
        submit(service_word()|t);
        CHECK(device_sep_rom_step(&model,&state,&resources)==DEVICE_OK);
        CHECK(state.sep_asc.service_ready==1 && state.sep_asc.service_notifications==1);
        CHECK(state.sep_asc.rom_stage==3 && state.sep_asc.consumed==5 && state.sep_asc.published==5);
        CHECK(state.sep_asc.bootstrap.panic_offset==0x4000 && state.sep_asc.bootstrap.panic_size==0x8000);
        CHECK(state.sep_asc.bootstrap.flags_offset==0xc000 && state.sep_asc.bootstrap.scot_offset==0x10000);
        CHECK(resource_reads==4 && admits==2 && !memcmp(payload,saved_payload,sizeof payload));
        uint64_t pair[2];
        if(tag&1){CHECK(device_model_read_pair(&model,&state,0x8830,pair)==DEVICE_OK);CHECK(pair[0]==(0x6a00ff|t) && !pair[1]);}
        CHECK(device_model_read_pair(&model,&state,0x8830,pair)==DEVICE_OK);
        CHECK(pair[0]==0xd0000 && !pair[1]);
        CHECK(state.sep_asc.delivered==5 && !state.sep_asc.reply_count);
        before=state;CHECK(device_sep_rom_step(&model,&state,&resources)==DEVICE_OK);
        CHECK(!memcmp(&before,&state,sizeof state));
    }
    for(unsigned test=0;test<7;test++) {
        service_reset();bootstrap();call(image(),1);
        if(test<4)fail_read=test+1;
        if(test==4)payload[0xc008]=1;
        if(test==5)resources.bootstrap=0;
        if(test==6)bad_layout=1;
        submit(service_word());before=state;
        CHECK(device_sep_rom_step(&model,&state,&resources)!=DEVICE_OK);
        CHECK(!memcmp(&before,&state,sizeof state));
    }
    service_reset();bootstrap();call(image(),1);submit(service_word());
    CHECK(device_sep_rom_step(&model,&state,&resources)==DEVICE_OK);
    for(unsigned test=0;test<3;test++) {
        struct device_state bad=state;
        if(test==0)bad.sep_asc.service_ready=0;
        if(test==1)bad.sep_asc.service_notifications=2;
        if(test==2)bad.sep_asc.bootstrap.flags[0]=1;
        before=bad;CHECK(device_sep_rom_step(&model,&bad,&resources)==DEVICE_BAD_CONFIG);
        CHECK(!memcmp(&before,&bad,sizeof bad));
    }
    active();uint64_t last_rom=state.sep_asc.rom_last_request;
    for(unsigned tag=1;tag<256;tag++) {
        const uint32_t values[]={0,1,0x80000000U,0xffffffffU,tag*0x01010101U};
        for(unsigned i=0;i<sizeof(values)/sizeof(values[0]);i++) {
            entropy_value=values[i];uint64_t req=0x360000|(uint64_t)tag<<8;
            CHECK(call(req,1)==((uint64_t)entropy_value<<32|req));
            CHECK(state.sep_asc.entropy_words==entropy_calls);
            CHECK(state.sep_asc.entropy_last_request==req);
            CHECK(state.sep_asc.rom_last_request==last_rom && !state.sep_asc.rom_last_reply);
            CHECK(state.sep_asc.published==5+entropy_calls && state.sep_asc.consumed==5+entropy_calls);
            CHECK(state.sep_asc.delivered==state.sep_asc.published);
            for(unsigned j=0;j<DEVICE_SEP_ASC_MESSAGES;j++)CHECK(!state.sep_asc.reply[j][0] && !state.sep_asc.reply[j][1]);
        }
    }
    for(unsigned test=0;test<9;test++) {
        active();uint64_t req=0x360100;
        if(test==0)resources.entropy32=0;
        if(test==1){entropy_value=0xcafebabe;entropy_fail=1;}
        if(test==2)req=0x360000;
        if(test==3)req|=1;
        if(test==4)req|=1UL<<24;
        if(test==5)req|=1UL<<32;
        if(test==6){service_reset();bootstrap();}
        if(test==7)for(unsigned i=0;i<DEVICE_SEP_ASC_MESSAGES;i++) {
            submit(0x360100+(i<<8));CHECK(device_sep_rom_step(&model,&state,&resources)==DEVICE_OK);
        }
        uint64_t pair[2]={req,test==8};
        CHECK(device_model_write_pair(&model,&state,0x8800,pair)==DEVICE_OK);
        before=state;unsigned calls=entropy_calls;
        CHECK(device_sep_rom_step(&model,&state,&resources)!=DEVICE_OK);
        CHECK(!memcmp(&before,&state,sizeof state));
        CHECK(entropy_calls==calls+(test==1));
    }
    active();call(0x360100,1);
    for(unsigned test=0;test<5;test++) {
        struct device_state bad=state;
        if(test==0)bad.sep_asc.entropy_words++;
        if(test==1)bad.sep_asc.entropy_last_request=0;
        if(test==2)bad.sep_asc.entropy_last_request|=1UL<<32;
        if(test==3)bad.sep_asc.entropy_last_request=0x360000;
        if(test==4)bad.sep_asc.entropy_words=UINT64_MAX;
        before=bad;CHECK(device_sep_rom_step(&model,&bad,&resources)==DEVICE_BAD_CONFIG);
        CHECK(!memcmp(&before,&bad,sizeof bad));
    }
    printf("PASS: %u resource-backed SEP startup, notification and entropy checks\n",checks);return 0;
}

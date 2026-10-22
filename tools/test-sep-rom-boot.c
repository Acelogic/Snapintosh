/* SPDX-License-Identifier: MIT */
#define main transport_checks
#include "test-sep-asc.c"
#undef main
#define FW 0x10000004000UL
#define FW_SIZE 0x5dc000UL
#define SH 0x10001000000UL
#define SH_SIZE 0x28000UL
static unsigned admits,deny_buffer;
static int admit(void *ctx,unsigned kind,uint64_t iova,uint64_t size)
{
    CHECK(ctx==&admits);admits++;
    CHECK(kind<=1);
    return !deny_buffer && iova==(kind ? SH : FW) && size==(kind ? SH_SIZE : FW_SIZE);
}
static struct device_sep_rom_resources resources={&admits,FW_SIZE,admit,0,0,0,0,0};
static void boot_reset(void)
{
    model=(struct device_model){45,0x282600000,0x9000,{8,1,346,343,1}};
    reset();control(1,1);admits=deny_buffer=0;
}
static uint64_t call(uint64_t word,int response)
{
    uint64_t words[2]={word,0};
    CHECK(device_model_write_pair(&model,&state,0x8800,words)==DEVICE_OK);
    CHECK(device_sep_rom_step(&model,&state,&resources)==DEVICE_OK);
    if(!response){CHECK(!state.sep_asc.reply_count);return 0;}
    uint64_t out[2];CHECK(device_model_read_pair(&model,&state,0x8830,out)==DEVICE_OK);
    CHECK(!out[1]);return out[0];
}
static void bootstrap(void)
{
    CHECK(call(0x201ff,1)==0x1006601ffUL);
    CHECK(call(0x501ff,1)==0x6901ff);
    CHECK(state.sep_asc.rom_stage==1);
    CHECK(call(0x201ff,1)==0x2006601ffUL);
}
static uint64_t image(void){return ((FW>>12)<<32)|0x200601ff;}
static uint64_t shared(void){return ((SH>>12)<<32)|((SH_SIZE>>12)<<16)|0x1fe;}
#ifndef SEP_ROM_TEST_MAIN
#define SEP_ROM_TEST_MAIN main
#endif
int SEP_ROM_TEST_MAIN(int argc,char **argv)
{
    if(argc==2 && !strcmp(argv[1],"--trace")) {
        boot_reset();printf("%llx\n",(unsigned long long)call(0x201ff,1));
        printf("%llx\n",(unsigned long long)call(0x501ff,1));
        printf("%llx\n",(unsigned long long)call(0x201ff,1));
        printf("%llx\n",(unsigned long long)call(image(),1));
        call(shared(),0);return 0;
    }
    for(unsigned tag=0;tag<256;tag++) {
        boot_reset();uint64_t t=(uint64_t)tag<<8;
        CHECK(call(0x200ff|t,1)==(0x1006600ffUL|t));
        CHECK(call(0x500ff|t,1)==(0x6900ff|t));
        CHECK(call(0x200ff|t,1)==(0x2006600ffUL|t));
        CHECK(call((image()&~0xff00UL)|t,1)==(0x6a00ff|t));
        call((shared()&~0xff00UL)|t,0);
        CHECK(state.sep_asc.rom_stage==3 && state.sep_asc.consumed==5);
        CHECK(state.sep_asc.published==4 && state.sep_asc.delivered==4);
        CHECK(state.sep_asc.rom_firmware_iova==FW && state.sep_asc.rom_firmware_size==FW_SIZE);
        CHECK(state.sep_asc.rom_shared_iova==SH && state.sep_asc.rom_shared_size==SH_SIZE && admits==2);
        before=state;CHECK(device_sep_rom_step(&model,&state,&resources)==DEVICE_OK);
        CHECK(!memcmp(&state,&before,sizeof state));
    }
    for(unsigned test=0;test<16;test++) {
        boot_reset();uint64_t word=0x501ff;struct device_sep_rom_resources res=resources;
        if(test!=0)bootstrap();
        if(test>=2)word=image();
        if(test==2)res.admit=0;
        if(test==3)res.firmware_size=0;
        if(test==4)res.firmware_size++;
        if(test==5)res.firmware_size=0x1004000;
        if(test==6)deny_buffer=1;
        if(test==7)word+=(1UL<<32);
        if(test==8)word=0x601ff;
        if(test>=9) {call(image(),1);word=shared();}
        if(test==9)deny_buffer=1;
        if(test==10)word=0x1fe;
        if(test==11)word=(word&~0xffff0000UL)|0x1010000;
        if(test==12)word+=(1UL<<32);
        if(test==13)word=((FW>>12)<<32)|((SH_SIZE>>12)<<16)|0x1fe;
        if(test==14)word=image();
        if(test==15)word=0x201ff;
        uint64_t words[2]={word,0};CHECK(device_model_write_pair(&model,&state,0x8800,words)==DEVICE_OK);
        before=state;CHECK(device_sep_rom_step(&model,&state,&res)!=DEVICE_OK);
        CHECK(!memcmp(&state,&before,sizeof state));
    }
    boot_reset();bootstrap();call(image(),1);call(shared(),0);
    for(unsigned field=0;field<5;field++) {
        struct device_state bad=state;
        uint64_t *fields[]={&bad.sep_asc.rom_stage,&bad.sep_asc.rom_firmware_iova,
            &bad.sep_asc.rom_firmware_size,&bad.sep_asc.rom_shared_iova,&bad.sep_asc.rom_shared_size};
        *fields[field]=UINT64_MAX;before=bad;
        CHECK(device_sep_rom_step(&model,&bad,&resources)==DEVICE_BAD_CONFIG);
        CHECK(!memcmp(&before,&bad,sizeof bad));
    }
    /* Two old ready queries cannot replace the post-TZ0 status transition. */
    boot_reset();call(0x201ff,1);call(0x201ff,1);call(0x501ff,1);
    uint64_t words[2]={image(),0};
    CHECK(device_model_write_pair(&model,&state,0x8800,words)==DEVICE_OK);
    before=state;CHECK(device_sep_rom_step(&model,&state,&resources)==DEVICE_BAD_VALUE);
    CHECK(!memcmp(&before,&state,sizeof state));
    for(unsigned param=0;param<256;param++) {
        if(param==0x20)continue;
        boot_reset();bootstrap();
        words[0]=(image()&~0xff000000UL)|((uint64_t)param<<24);
        CHECK(device_model_write_pair(&model,&state,0x8800,words)==DEVICE_OK);
        before=state;CHECK(device_sep_rom_step(&model,&state,&resources)==DEVICE_UNKNOWN_REGISTER);
        CHECK(!memcmp(&before,&state,sizeof state));
        CHECK(!admits);
    }
    printf("PASS: %u virtual ROM boot and buffer handoff checks\n",checks);return 0;
}

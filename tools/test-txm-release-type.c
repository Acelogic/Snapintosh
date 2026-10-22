/* SPDX-License-Identifier: MIT */
#define main nonce_fixture_checks
#include "test-txm-nonce.c"
#undef main

static void record_type(unsigned offset,const uint8_t input[64])
{
    for(unsigned i=0;i<64;i++) {
        unsigned at=offset+i;
        ram[at<PAGE ? 8*PAGE+at : 12*PAGE+at-PAGE]=input[i];
    }
}
static enum sptm_result release(struct txm_release_type *state,unsigned cpu,
                               unsigned offset,uint64_t *status)
{
    uint64_t args[8]={BASE+cpu*PAGE,0,VA+offset,64};
    return txm_image4_release_type(&memory,&service,state,txm_copy_kernel_input,
                                   &kernel,45,args,status);
}
int main(int argc,char **argv)
{
    if(argc==3 && !strcmp(argv[1],"--record")) {
        uint8_t input[64];CHECK(strlen(argv[2])==128);
        for(unsigned i=0;i<64;i++) {
            char byte[3]={argv[2][i*2],argv[2][i*2+1],0};
            input[i]=(uint8_t)strtoul(byte,0,16);
        }
        setup();struct txm_release_type state={0};uint64_t status;
        record_type(0,input);CHECK(release(&state,0,0,&status)==SPTM_OK);
        printf("%llu ",(unsigned long long)status);
        for(unsigned i=0;i<64;i++)printf("%02x",state.value[i]);
        CHECK(release(&state,1,0,&status)==SPTM_OK);
        printf(" %llu\n",(unsigned long long)status);return 0;
    }
    /* Every possible64-byte split and every position of the first NUL,
     * including empty, unterminated and arbitrary non-ASCII input. */
    for(unsigned offset=PAGE-64;offset<PAGE;offset++)for(unsigned end=0;end<=64;end++) {
        setup();uint8_t input[64],expected[64]={0};
        for(unsigned i=0;i<64;i++)input[i]=(uint8_t)(0x80+i);
        if(end<64)input[end]=0;
        unsigned length=end<62 ? end:62;
        memcpy(expected,input,length);record_type(offset,input);
        struct txm_release_type state={0};uint64_t status=~0UL;
        CHECK(release(&state,offset&1,offset,&status)==SPTM_OK && !status);
        CHECK(state.calls==1 && state.sets==1 && !state.rejections && state.length==length);
        CHECK(!memcmp(state.value,expected,64) && !memcmp(state.input,input,64));
        uint64_t reply=BASE+(offset&1)*PAGE+0x3c00;
        CHECK(!get(reply+8) && !get(reply+24));
        for(unsigned i=0;i<6;i++)CHECK(!get(reply+32+8*i));
        struct txm_release_type saved=state;
        memset(input,'Z',64);record_type(offset,input);
        CHECK(release(&state,!(offset&1),offset,&status)==SPTM_OK);
        CHECK(status==((37UL<<32)|5) && state.last_status==status);
        CHECK(state.calls==2 && state.sets==1 && state.rejections==1);
        CHECK(!memcmp(state.value,saved.value,64) && !memcmp(state.input,saved.input,64));
    }
    for(unsigned initialized=0;initialized<2;initialized++)for(unsigned test=0;test<22;test++) {
        setup();uint8_t input[64]={0};memcpy(input,"User",4);record_type(PAGE-10,input);
        struct txm_release_type state={0};uint64_t status=0;
        if(initialized)CHECK(release(&state,0,PAGE-10,&status)==SPTM_OK);
        struct txm_release_type saved=state;
        uint64_t args[8]={BASE,0,VA+PAGE-10,64},selector=45;
        struct txm_kernel_memory k=kernel;
        switch(test) {
        case 0:deny=BASE;break;case 1:deny=slot(1);break;
        case 2:deny=slot(2);break;case 3:deny=slot(3);break;
        case 4:deny=BASE+8*PAGE+PAGE-10;break;case 5:deny=BASE+12*PAGE;break;
        case 6:put(slot(3)+8,0);break;case 7:put(slot(1),BASE+3*PAGE+0x1000+3);break;
        case 8:put(slot(3),BASE+8*PAGE+3);break;case 9:args[2]=0;break;
        case 10:args[2]=VA&0x7fffffffffff;break;case 11:args[2]=UINT64_MAX-63;break;
        case 12:args[3]=63;break;case 13:args[4]=1;break;case 14:args[0]+=PAGE*2;break;
        case 15:args[1]=1;break;case 16:selector=46;break;case 17:k.root++;break;
        case 18:k.tcr=0;break;case 19:put(slot(2),BASE+sizeof(ram)+3);break;
        case 20:put(slot(3)+8,BASE+sizeof(ram)+PT_AF+3);break;case 21:args[7]=1;break;
        }
        unsigned old_pubs=pubs;status=0x1234;memcpy(before,ram,sizeof ram);
        CHECK(txm_image4_release_type(&memory,&service,&state,txm_copy_kernel_input,
                                      &k,selector,args,&status)!=SPTM_OK);
        CHECK(pubs==old_pubs && status==0x1234 && !memcmp(&state,&saved,sizeof state));
        CHECK(!memcmp(before,ram,sizeof ram));
    }
    setup();struct txm_release_type state={0};uint64_t status,args[8]={BASE,0,VA,64};
    CHECK(txm_image4_release_type(&memory,&service,0,txm_copy_kernel_input,&kernel,45,args,&status)==SPTM_BAD_CONFIG);
    CHECK(txm_image4_release_type(&memory,&service,&state,0,&kernel,45,args,&status)==SPTM_BAD_CONFIG);
    CHECK(txm_image4_release_type(&memory,&service,&state,txm_copy_kernel_input,&kernel,45,args,0)==SPTM_BAD_CONFIG);
    printf("TXM release type: %u checks passed\n",checks);return 0;
}

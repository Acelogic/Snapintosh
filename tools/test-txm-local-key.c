/* SPDX-License-Identifier: MIT */
#define main nonce_fixture_checks
#include "test-txm-nonce.c"
#undef main

static void key_input(unsigned offset,const uint8_t value[97])
{
    for(unsigned i=0;i<97;i++) {
        unsigned at=offset+i;
        ram[at<PAGE ? 8*PAGE+at : 12*PAGE+at-PAGE]=value[i];
    }
}
static enum sptm_result key_call(struct txm_local_key *state,unsigned cpu,unsigned offset)
{
    uint64_t args[8]={BASE+cpu*PAGE,VA+offset};
    return txm_set_local_key(&memory,&service,state,txm_copy_kernel_input,&kernel,26,args);
}
int main(int argc,char **argv)
{
    if(argc==3 && !strcmp(argv[1],"--record")) {
        uint8_t value[97];CHECK(strlen(argv[2])==194);
        for(unsigned i=0;i<97;i++) {
            char byte[3]={argv[2][i*2],argv[2][i*2+1],0};
            value[i]=(uint8_t)strtoul(byte,0,16);
        }
        setup();key_input(0,value);struct txm_local_key state={0};
        CHECK(key_call(&state,0,0)==SPTM_OK);
        for(unsigned i=0;i<97;i++)printf("%02x",state.value[i]);
        CHECK(key_call(&state,1,0)==SPTM_FRAME_BUSY);
        printf(" duplicate-stopped\n");return 0;
    }
    /* Every split across two nonadjacent physical pages, both CPU stacks. */
    for(unsigned offset=PAGE-97;offset<PAGE;offset++) {
        setup();uint8_t value[97];
        for(unsigned i=0;i<97;i++)value[i]=(uint8_t)(i+offset);
        key_input(offset,value);struct txm_local_key state={0};
        CHECK(key_call(&state,offset&1,offset)==SPTM_OK);
        CHECK(state.sets==1 && state.input_va==VA+offset && pubs==1);
        CHECK(state.stack_pa==BASE+(offset&1)*PAGE && !memcmp(state.value,value,97));
        uint64_t reply=state.stack_pa+0x3c00;
        CHECK(!get(reply+8) && !get(reply+24));
        for(unsigned i=0;i<6;i++)CHECK(!get(reply+32+i*8));
        struct txm_local_key saved=state;
        memset(value,0xcc,97);key_input(offset,value);memcpy(before,ram,sizeof ram);
        CHECK(key_call(&state,!(offset&1),offset)==SPTM_FRAME_BUSY);
        CHECK(pubs==1 && !memcmp(&state,&saved,sizeof state) && !memcmp(before,ram,sizeof ram));
    }
    /* Every failure must leave the record and reply untouched. */
    for(unsigned test=0;test<25;test++) {
        setup();uint8_t value[97]={0};key_input(PAGE-48,value);
        struct txm_local_key state={0},saved=state;
        struct txm_service s=service;struct txm_kernel_memory k=kernel;
        uint64_t args[8]={BASE,VA+PAGE-48},selector=26;
        switch(test) {
        case 0:deny=BASE;break;case 1:deny=slot(1);break;
        case 2:deny=slot(2);break;case 3:deny=slot(3);break;
        case 4:deny=BASE+8*PAGE+PAGE-48;break;case 5:deny=BASE+12*PAGE;break;
        case 6:put(slot(3)+8,0);break;case 7:put(slot(1),BASE+3*PAGE+0x1000+3);break;
        case 8:put(slot(3),BASE+8*PAGE+3);break;case 9:args[1]=0;break;
        case 10:args[1]=VA&0x7fffffffffff;break;case 11:args[1]=UINT64_MAX-96;break;
        case 12:args[2]=1;break;case 13:args[7]=1;break;case 14:args[0]+=PAGE*2;break;
        case 15:args[0]++;break;case 16:selector=27;break;case 17:k.root++;break;
        case 18:k.tcr=0;break;case 19:put(slot(2),BASE+sizeof(ram)+3);break;
        case 20:put(slot(3)+8,BASE+sizeof(ram)+PT_AF+3);break;
        case 21:s.stack_count=0;break;case 22:s.stack_count=257;break;
        case 23:s.stacks_pa=UINT64_MAX-PAGE+1;break;
        case 24:state.sets=saved.sets=2;break;
        }
        memcpy(before,ram,sizeof ram);
        CHECK(txm_set_local_key(&memory,&s,&state,txm_copy_kernel_input,&k,selector,args)!=SPTM_OK);
        CHECK(!pubs && !memcmp(&state,&saved,sizeof state) && !memcmp(before,ram,sizeof ram));
    }
    setup();uint64_t args[8]={BASE,VA};struct txm_local_key state={0};
    CHECK(txm_set_local_key(0,&service,&state,txm_copy_kernel_input,&kernel,26,args)==SPTM_BAD_CONFIG);
    CHECK(txm_set_local_key(&memory,&service,0,txm_copy_kernel_input,&kernel,26,args)==SPTM_BAD_CONFIG);
    CHECK(txm_set_local_key(&memory,&service,&state,0,&kernel,26,args)==SPTM_BAD_CONFIG);
    CHECK(txm_set_local_key(&memory,&service,&state,txm_copy_kernel_input,&kernel,26,0)==SPTM_BAD_CONFIG);
    printf("TXM local key: %u checks passed\n",checks);return 0;
}

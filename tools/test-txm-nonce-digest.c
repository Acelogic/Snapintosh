/* SPDX-License-Identifier: MIT */
/* Share the real 16K guest walker fixture, including nonadjacent data pages. */
#define main existing_nonce_tests
#include "test-txm-nonce.c"
#undef main

static void digest_input(unsigned offset,unsigned length,uint8_t pattern)
{
    for(unsigned i=0;i<length;i++) {
        unsigned at=offset+i;
        ram[at<PAGE ? 8*PAGE+at : 12*PAGE+at-PAGE]=(uint8_t)(pattern+i);
    }
}
static enum sptm_result digest_call(struct txm_nonce_digest_registry *r,
    unsigned cpu,uint64_t domain,unsigned offset,unsigned length)
{
    uint64_t args[8]={BASE+cpu*PAGE,domain,VA+offset,length};
    return txm_image4_nonce_digest(&memory,&service,r,txm_copy_kernel_input,
                                  &kernel,52,args);
}
static void check_reply(unsigned cpu)
{
    uint64_t reply=BASE+cpu*PAGE+0x3c00;
    CHECK(!get(reply+8) && !get(reply+24));
    for(unsigned i=0;i<6;i++)CHECK(!get(reply+32+8*i));
}
int main(void)
{
    /* All accepted lengths and all domains, alternating service stacks. */
    for(unsigned length=1;length<=48;length++) {
        setup();struct txm_nonce_digest_registry r={0};
        for(unsigned domain=0;domain<17;domain++) {
            digest_input(0,length,(uint8_t)domain);
            CHECK(digest_call(&r,domain&1,domain,0,length)==SPTM_OK);
            CHECK(r.sets==domain+1 && pubs==domain+1);
            CHECK(r.entries[domain].length==length);
            for(unsigned i=0;i<48;i++)
                CHECK(r.entries[domain].bytes[i]==(i<length ? domain+i : 0));
            check_reply(domain&1);
            struct txm_nonce_digest_registry saved=r;
            memcpy(before,ram,sizeof(ram));
            CHECK(digest_call(&r,!(domain&1),domain,0,length)==SPTM_FRAME_BUSY);
            CHECK(!memcmp(&saved,&r,sizeof(r)) && pubs==domain+1);
            CHECK(!memcmp(before,ram,sizeof(ram)));
            digest_input(0,length,(uint8_t)(domain+99));
            memcpy(before,ram,sizeof(ram));
            CHECK(digest_call(&r,domain&1,domain,0,length)==SPTM_FRAME_BUSY);
            CHECK(!memcmp(&saved,&r,sizeof(r)) && pubs==domain+1);
            CHECK(!memcmp(before,ram,sizeof(ram)));
        }
    }
    /* All 48-byte split points with an unmapped physical gap between pages. */
    for(unsigned offset=PAGE-48;offset<PAGE;offset++) {
        setup();struct txm_nonce_digest_registry r={0};
        digest_input(offset,48,11);
        CHECK(digest_call(&r,offset&1,2,offset,48)==SPTM_OK);
        CHECK(r.sets==1 && r.entries[2].length==48 && pubs==1);
        for(unsigned i=0;i<48;i++)CHECK(r.entries[2].bytes[i]==11+i);
        check_reply(offset&1);
        if(offset>PAGE-48) {
            memset(&r,0,sizeof(r));pubs=0;deny=BASE+12*PAGE;
            struct txm_nonce_digest_registry saved=r;memcpy(before,ram,sizeof(ram));
            CHECK(digest_call(&r,offset&1,2,offset,48)==SPTM_BAD_ADDRESS);
            CHECK(!memcmp(&r,&saved,sizeof(r)) && !pubs);
            CHECK(!memcmp(ram,before,sizeof(ram)));
        }
    }
    /* Shipped w0/w21 instructions normalize the domain to 32 bits. */
    for(unsigned i=0;i<17;i++) {
        setup();struct txm_nonce_digest_registry r={0};digest_input(0,48,5);
        CHECK(digest_call(&r,0,0xffffffff00000000UL|i,0,48)==SPTM_OK);
        CHECK(r.sets==1 && r.entries[i].length==48);
    }
    /* Every rejected input must leave both RAM/reply and registry untouched. */
    for(unsigned test=0;test<35;test++) {
        setup();struct txm_nonce_digest_registry r={0},saved=r;
        digest_input(PAGE-10,48,42);
        uint64_t args[8]={BASE,2,VA+PAGE-10,48},selector=52;
        struct txm_kernel_memory k=kernel;
        struct txm_service s=service;struct sptm_memory m=memory;
        txm_copyin_fn copy=txm_copy_kernel_input;
        switch(test) {
        case 0:deny=BASE;break;case 1:deny=slot(1);break;
        case 2:deny=slot(2);break;case 3:deny=slot(3);break;
        case 4:deny=BASE+8*PAGE+PAGE-10;break;case 5:deny=BASE+12*PAGE;break;
        case 6:put(slot(3)+8,0);break;
        case 7:put(slot(1),BASE+3*PAGE+0x1000+3);break;
        case 8:put(slot(3),BASE+8*PAGE+3);break;
        case 9:args[2]=0;break;case 10:args[2]=VA&0x7fffffffffff;break;
        case 11:args[2]=UINT64_MAX-47;break;case 12:args[3]=49;break;
        case 13:args[4]=1;break;case 14:args[0]+=PAGE*2;break;
        case 15:args[1]=17;break;case 16:selector=53;break;
        case 17:k.root++;break;case 18:k.tcr=0;break;
        case 19:put(slot(2),BASE+sizeof(ram)+3);break;
        case 20:put(slot(3)+8,BASE+sizeof(ram)+PT_AF+3);break;
        case 21:args[3]=0;break;case 22:args[1]=UINT64_MAX;break;
        case 23:args[0]++;break;case 24:args[0]-=PAGE;break;
        case 25:args[5]=1;break;case 26:args[6]=1;break;case 27:args[7]=1;break;
        case 28:s.stack_count=0;break;case 29:s.stack_count=257;break;
        case 30:s.stacks_pa++;break;case 31:s.stacks_pa=0xffffffffffffc000UL;break;
        case 32:m.map=0;break;case 33:m.publish=0;break;case 34:copy=0;break;
        }
        memcpy(before,ram,sizeof(ram));
        CHECK(txm_image4_nonce_digest(&m,&s,&r,copy,&k,selector,args)!=SPTM_OK);
        CHECK(!pubs && !memcmp(&r,&saved,sizeof(r)));
        CHECK(!memcmp(ram,before,sizeof(ram)));
    }
    setup();struct txm_nonce_digest_registry r={0};
    uint64_t args[8]={BASE,2,VA,48};
    CHECK(txm_image4_nonce_digest(0,&service,&r,txm_copy_kernel_input,&kernel,52,args)==SPTM_BAD_CONFIG);
    CHECK(txm_image4_nonce_digest(&memory,0,&r,txm_copy_kernel_input,&kernel,52,args)==SPTM_BAD_CONFIG);
    CHECK(txm_image4_nonce_digest(&memory,&service,0,txm_copy_kernel_input,&kernel,52,args)==SPTM_BAD_CONFIG);
    CHECK(txm_image4_nonce_digest(&memory,&service,&r,txm_copy_kernel_input,&kernel,52,0)==SPTM_BAD_CONFIG);
    printf("TXM nonce digest: %u checks passed (17 domains, lengths 1..48, duplicate refusal, page splits, fault atomicity)\n",checks);
    return 0;
}

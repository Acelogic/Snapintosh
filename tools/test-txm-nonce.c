/* SPDX-License-Identifier: MIT */
#include "txm.h"
#include "../shadow/mmu.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define BASE 0x100000UL
#define PAGE 0x4000UL
#define VA 0xfffffe0002000000UL
static uint8_t ram[16*PAGE],before[sizeof(ram)];
static unsigned checks,pubs;
static uint64_t deny;
#define CHECK(x) do {checks++;if(!(x)){fprintf(stderr,"FAIL %d: %s\n",__LINE__,#x);exit(1);}} while(0)
static volatile uint8_t *map(void *ctx,uint64_t pa,uint64_t size)
{
    CHECK(ctx==ram);
    if(pa<BASE || pa-BASE>=sizeof(ram) || size>sizeof(ram)-(pa-BASE) ||
       (deny && pa<=deny && deny-pa<size))return 0;
    return ram+(pa-BASE);
}
static void publish(void *ctx,uint64_t pa,uint64_t size)
{CHECK(ctx==ram && (pa==BASE+0x3c00 || pa==BASE+PAGE+0x3c00) && size==0x50);pubs++;}
static void put(uint64_t pa,uint64_t word) {memcpy(ram+(pa-BASE),&word,8);}
static uint64_t get(uint64_t pa) {uint64_t v;memcpy(&v,ram+(pa-BASE),8);return v;}
static struct sptm_memory memory={.map=map,.publish=publish,.ctx=ram};
static struct txm_service service={.stacks_pa=BASE,.stack_count=2};
static struct txm_kernel_memory kernel={&memory,BASE+2*PAGE,(1UL<<30)|(17UL<<16)};
static uint64_t slot(unsigned level)
{return BASE+(level+1)*PAGE+8*mmu_index(14,level,VA);}
static void setup(void)
{
    memset(ram,0,sizeof(ram));deny=pubs=0;
    put(slot(1),BASE+3*PAGE+3);put(slot(2),BASE+4*PAGE+3);
    put(slot(3),BASE+8*PAGE+PT_AF+3);
    put(slot(3)+8,BASE+12*PAGE+PT_AF+3);
}
static void input(unsigned offset,uint64_t domain,uint32_t flags,uint8_t pattern)
{
    uint8_t data[44];memcpy(data,&domain,8);memcpy(data+8,&flags,4);
    for(unsigned i=12;i<44;i++)data[i]=pattern+i;
    for(unsigned i=0;i<44;i++) {
        unsigned at=offset+i;
        ram[(at<PAGE ? 8*PAGE+at : 12*PAGE+at-PAGE)]=data[i];
    }
}
static enum sptm_result call(struct txm_nonce_registry *registry,unsigned cpu,
    unsigned offset,uint64_t *status)
{
    uint64_t args[8]={BASE+cpu*PAGE,3,VA+offset,44};
    return txm_image4_nonce(&memory,&service,registry,txm_copy_kernel_input,
                          &kernel,45,args,status);
}
int main(void)
{
    /* Every64-byte split: the shared helper now also carries cdhash inputs. */
    for(unsigned offset=PAGE-64;offset<PAGE;offset++) {
        setup();uint8_t expected[64],out[64];
        for(unsigned i=0;i<64;i++) {
            expected[i]=(uint8_t)(i+offset);
            unsigned at=offset+i;
            ram[at<PAGE ? 8*PAGE+at : 12*PAGE+at-PAGE]=expected[i];
        }
        CHECK(txm_copy_kernel_input(&kernel,VA+offset,out,64));
        CHECK(!memcmp(out,expected,64));
        if(offset>PAGE-64) {
            deny=BASE+12*PAGE;memset(out,0xaa,sizeof(out));
            memset(expected,0xaa,sizeof(expected));
            CHECK(!txm_copy_kernel_input(&kernel,VA+offset,out,64));
            CHECK(!memcmp(out,expected,64));
        }
    }
    const uint32_t domains[]={0x70646d67,0x63707478,0x64766469,0x63316274,
        0x63316162,0x6331676e,0x6331736d,0x64316d61,0x63316765,0x63316572,
        0x63316169,0x6331616c};
    /* Every possible split of the 44-byte record, into nonadjacent RAM pages. */
    for(unsigned offset=PAGE-44;offset<PAGE;offset++) {
        setup();struct txm_nonce_registry registry={0};uint64_t status=~0UL;
        input(offset,domains[0],0xfffffe95,7);
        CHECK(call(&registry,offset&1,offset,&status)==SPTM_OK && !status);
        CHECK(registry.sets==1 && !registry.rejections && pubs==1);
        CHECK(registry.entries[0].initialized==1 && registry.entries[0].domain==domains[0]);
        CHECK(registry.entries[0].flags==0x15);
        for(unsigned i=0;i<16;i++) {
            CHECK(registry.entries[0].first[i]==7+12+i);
            CHECK(registry.entries[0].second[i]==7+28+i);
        }
        uint64_t reply=BASE+(offset&1)*PAGE+0x3c00;
        CHECK(!get(reply+8) && !get(reply+24));
        for(unsigned i=0;i<6;i++)CHECK(!get(reply+32+8*i));
        struct txm_nonce saved=registry.entries[0];
        input(offset,domains[0],0,33);
        CHECK(call(&registry,!(offset&1),offset,&status)==SPTM_OK);
        CHECK(status==((37UL<<32)|5) && registry.sets==1 && registry.rejections==1);
        CHECK(!memcmp(&saved,&registry.entries[0],sizeof(saved)));
    }
    setup();struct txm_nonce_registry registry={0};uint64_t status=~0UL;
    for(unsigned i=0;i<12;i++) {
        input(0,domains[i],i,4*i);
        CHECK(call(&registry,i&1,0,&status)==SPTM_OK && !status);
        CHECK(registry.entries[i].initialized && registry.entries[i].domain==domains[i]);
        CHECK(registry.entries[i].flags==i && registry.sets==i+1);
    }
    struct txm_nonce_registry saved=registry;
    const uint64_t bad_ids[]={0,0xdeadbeef,(1UL<<32)|domains[0],UINT64_MAX};
    for(unsigned i=0;i<4;i++) {
        input(0,bad_ids[i],0,0);
        CHECK(call(&registry,0,0,&status)==SPTM_OK);
        CHECK(status==(((uint64_t)(i<2 ? 2 : 84)<<32)|5));
        CHECK(!memcmp(registry.entries,saved.entries,sizeof(saved.entries)));
    }
    /* Map and pointer faults must not publish a reply or change nonce state. */
    for(unsigned test=0;test<21;test++) {
        setup();memset(&registry,0,sizeof(registry));saved=registry;
        input(PAGE-10,domains[0],0,0);
        uint64_t args[8]={BASE,3,VA+PAGE-10,44},selector=45;
        struct txm_kernel_memory k=kernel;
        switch(test) {
        case 0:deny=BASE;break;case 1:deny=slot(1);break;
        case 2:deny=slot(2);break;case 3:deny=slot(3);break;
        case 4:deny=BASE+8*PAGE+PAGE-10;break;case 5:deny=BASE+12*PAGE;break;
        case 6:put(slot(3)+8,0);break;
        case 7:put(slot(1),BASE+3*PAGE+0x1000+3);break;
        case 8:put(slot(3),BASE+8*PAGE+3);break;
        case 9:args[2]=0;break;case 10:args[2]=VA&0x7fffffffffff;break;
        case 11:args[2]=UINT64_MAX-43;break;case 12:args[3]=43;break;
        case 13:args[4]=1;break;case 14:args[0]+=PAGE*2;break;
        case 15:args[1]=2;break;case 16:selector=46;break;
        case 17:k.root++;break;case 18:k.tcr=0;break;
        case 19:put(slot(2),BASE+sizeof(ram)+3);break;
        case 20:put(slot(3)+8,BASE+sizeof(ram)+PT_AF+3);break;
        }
        memcpy(before,ram,sizeof(ram));status=0x1234;
        CHECK(txm_image4_nonce(&memory,&service,&registry,txm_copy_kernel_input,
                              &k,selector,args,&status)!=SPTM_OK);
        CHECK(!pubs && status==0x1234 && !memcmp(&registry,&saved,sizeof(saved)));
        CHECK(!memcmp(ram,before,sizeof(ram)));
    }
    setup();uint8_t out[44],original[44];memset(out,0xcc,44);memcpy(original,out,44);
    deny=BASE+12*PAGE;
    CHECK(!txm_copy_kernel_input(&kernel,VA+PAGE-10,out,44));
    CHECK(!memcmp(out,original,44));
    CHECK(!txm_copy_kernel_input(0,VA,out,44));
    CHECK(!txm_copy_kernel_input(&kernel,VA,0,44));
    CHECK(!txm_copy_kernel_input(&kernel,VA,out,TXM_LOCAL_KEY_BYTES+1));
    uint64_t args[8]={BASE,3,VA,44};
    CHECK(txm_image4_nonce(&memory,&service,0,txm_copy_kernel_input,&kernel,45,args,&status)==SPTM_BAD_CONFIG);
    CHECK(txm_image4_nonce(&memory,&service,&registry,0,&kernel,45,args,&status)==SPTM_BAD_CONFIG);
    CHECK(txm_image4_nonce(&memory,&service,&registry,txm_copy_kernel_input,&kernel,45,args,0)==SPTM_BAD_CONFIG);
    printf("TXM nonce: %u checks passed (12 domains, duplicate preservation, page-split copy, fault atomicity)\n",checks);
    return 0;
}

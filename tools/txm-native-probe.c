/* SPDX-License-Identifier: MIT
 * RAM-only A16 integration probe: production adapter + pinned native Image4.
 * Inputs and record live outside the adapter's three-MiB private workspace.
 * Failure inventory: docs/TXM-TRUST-LOAD-20260925.md. */
#include "txm-native.h"

struct probe_record {
    struct txm_native_params params;
    uint64_t payload, payload_size, manifest, manifest_size, retained;
    uint64_t checks, failures, completed;
    struct txm_native_state state;
    struct { uint64_t transport, status, size, offset; } cases[7];
    uint64_t pfr0,pfr1,init_status;
};
/* Separate from the outer assembly's SIMD input/output at +0x200/+0x400. */
struct coexist_record {
    uint64_t payload,size,retained;
    struct {uint64_t transport,status,size,offset;} cases[7];
    uint64_t invalid_refusals,completed;
};
struct triple_record {
    uint64_t payload,size,retained;
    struct {uint64_t transport,status,size,offset;} cases[8];
    uint64_t invalid_refusals,completed;
};
static void check(struct probe_record *r,int ok)
{r->checks++;if(!ok)r->failures++;}

uint64_t txm_native_probe(struct probe_record *r)
{
    struct txm_native_result result;
    struct txm_native_cache cache={0};
    __asm__ volatile("mrs %0,id_aa64pfr0_el1; mrs %1,id_aa64pfr1_el1"
        :"=r"(r->pfr0),"=r"(r->pfr1));
    check(r,txm_native_init(&r->params,&r->state,1UL<<32,0)!=0);
    check(r,txm_native_init(&r->params,&r->state,0,1UL<<24)!=0);
    check(r,r->state.phase==0 && r->state.calls==0);
    r->init_status=(uint64_t)(int64_t)txm_native_init(&r->params,&r->state,
        r->pfr0&~(15UL<<32),r->pfr1&~(15UL<<24));
    check(r,r->init_status==0);
    if(r->failures)return 1;
    const uint64_t expected[]={1,0x82301,0xda502,0xca302,0xca302,1,0x82301};
    for(unsigned i=0;i<7;i++) {
        volatile uint8_t *edited=0;
        if(i==2)edited=(volatile uint8_t *)(r->payload+r->payload_size-1);
        if(i==3)edited=(volatile uint8_t *)(r->manifest+1246);
        if(i==4)edited=(volatile uint8_t *)(r->manifest+3065);
        if(edited)*edited^=1;
        check(r,txm_native_stage(&r->params,&r->state,
            (const uint8_t *)r->payload,r->payload_size,
            (const uint8_t *)r->manifest,r->manifest_size)==0);
        /* Native library performs duplicate checking against the supplied
         * existing static/dynamic module. No authentication result is mocked. */
        const struct txm_native_cache *old=i==1 || i==6 ? &cache:0;
        if(i==6)cache.type=0;
        uint64_t transport=txm_native_load(&r->params,&r->state,13,
            i==6 ? old:0,i==1 ? old:0,&result);
        r->cases[i].transport=transport;r->cases[i].status=result.status;
        r->cases[i].size=result.size;
        r->cases[i].offset=result.payload ? (uint64_t)result.payload-r->params.work:0;
        check(r,!transport && result.status==expected[i]);
        if(expected[i]==1) {
            check(r,result.size==r->payload_size-23 &&
                  (uint64_t)result.payload==r->params.work+TXM_NATIVE_PAYLOAD+23);
            for(uint64_t n=0;n<result.size;n++) {
                check(r,result.payload[n]==((uint8_t *)r->payload)[23+n]);
                ((uint8_t *)r->retained)[n]=result.payload[n];
            }
            cache=(struct txm_native_cache){13,(const uint8_t *)r->retained,result.size};
        } else check(r,!result.size && !result.payload);
        if(edited)*edited^=1;
        check(r,*(volatile uint8_t *)(r->params.work+TXM_NATIVE_STACK+0x78)==0);
        check(r,r->state.phase==1);
    }
    /* Invalid staging cannot destroy the last owned input or call native code. */
    uint64_t calls=r->state.calls;
    check(r,txm_native_stage(&r->params,&r->state,(const uint8_t *)r->payload,
        TXM_NATIVE_COPY_MAX+1,(const uint8_t *)r->manifest,r->manifest_size)!=0);
    check(r,r->state.calls==calls && r->state.phase==1);
    check(r,txm_native_load(&r->params,&r->state,13,0,0,&result)!=0);
    check(r,r->state.calls==calls);
    struct coexist_record *co=(void *)((uint8_t *)r+0x800);
    if(co->payload) {
        struct txm_native_cache os={13,(const uint8_t *)r->retained,r->payload_size-23};
        struct txm_native_cache app={14,(const uint8_t *)co->retained,co->size-23};
        const uint64_t wanted[]={1,0x82301,0x82301,0xda502,0xca302,0xca302,1};
        for(unsigned i=0;i<7;i++) {
            uint64_t data=i==2 ? r->payload:co->payload, size=i==2 ? r->payload_size:co->size;
            unsigned type=i==2 ? 13:14, count=i==1 || i==2 ? 2:1;
            struct txm_native_cache caches[2]={count==2 ? app:os,os};
            volatile uint8_t *edited=0;
            if(i==3)edited=(volatile uint8_t *)(data+size-1);
            if(i==4)edited=(volatile uint8_t *)(r->manifest+1246);
            if(i==5)edited=(volatile uint8_t *)(r->manifest+3065);
            if(edited)*edited^=1;
            check(r,txm_native_stage(&r->params,&r->state,(const uint8_t *)data,size,
                  (const uint8_t *)r->manifest,r->manifest_size)==0);
            if(i==6) {
                uint64_t before=r->state.calls;
                check(r,txm_native_load_caches(&r->params,&r->state,12,0,caches,count,&result)!=0);
                check(r,txm_native_load_caches(&r->params,&r->state,type,0,caches,TXM_NATIVE_CACHE_MAX+1,&result)!=0);
                check(r,txm_native_load_caches(&r->params,&r->state,type,0,0,1,&result)!=0);
                check(r,r->state.phase==2 && r->state.calls==before);
                co->invalid_refusals=3;
            }
            uint64_t rc=txm_native_load_caches(&r->params,&r->state,type,0,caches,count,&result);
            co->cases[i].transport=rc;co->cases[i].status=result.status;co->cases[i].size=result.size;
            co->cases[i].offset=result.payload ? (uint64_t)result.payload-r->params.work:0;
            check(r,!rc && result.status==wanted[i]);
            if(wanted[i]==1) {
                check(r,result.size==co->size-23 &&
                      (uint64_t)result.payload==r->params.work+TXM_NATIVE_PAYLOAD+23);
                for(uint64_t n=0;n<result.size;n++) {
                    check(r,result.payload[n]==((uint8_t *)co->payload)[23+n]);
                    ((uint8_t *)co->retained)[n]=result.payload[n];
                }
            } else check(r,!result.size && !result.payload);
            if(edited)*edited^=1;
            for(uint64_t n=0;n<os.size;n++)check(r,os.payload[n]==((uint8_t *)r->payload)[23+n]);
            for(uint64_t n=0;n<app.size;n++)check(r,app.payload[n]==((uint8_t *)co->payload)[23+n]);
            check(r,r->state.phase==1 && *(volatile uint8_t *)(r->params.work+TXM_NATIVE_STACK+0x78)==0);
        }
        co->completed=1;
        struct triple_record *tri=(void *)((uint8_t *)r+0xa00);
        if(tri->payload) {
            struct txm_native_cache rosetta={27,(const uint8_t *)tri->retained,tri->size-23};
            const uint64_t expected[]={1,0x82301,0x82301,0x82301,0xda502,0xca302,0xca302,1};
            for(unsigned i=0;i<8;i++) {
                unsigned type=i==2 ? 14:(i==3 ? 13:27), count=i>=1 && i<=3 ? 3:2;
                uint64_t data=type==14 ? co->payload:(type==13 ? r->payload:tri->payload);
                uint64_t size=type==14 ? co->size:(type==13 ? r->payload_size:tri->size);
                struct txm_native_cache caches[3]={count==3 ? rosetta:app,count==3 ? app:os,os};
                volatile uint8_t *edited=0;
                if(i==4)edited=(volatile uint8_t *)(data+size-1);
                if(i==5)edited=(volatile uint8_t *)(r->manifest+1246);
                if(i==6)edited=(volatile uint8_t *)(r->manifest+3065);
                if(edited)*edited^=1;
                check(r,txm_native_stage(&r->params,&r->state,(const uint8_t *)data,size,
                    (const uint8_t *)r->manifest,r->manifest_size)==0);
                if(i==7) {
                    uint64_t before=r->state.calls;
                    check(r,txm_native_load_caches(&r->params,&r->state,28,0,caches,count,&result)!=0);
                    check(r,txm_native_load_caches(&r->params,&r->state,type,0,caches,TXM_NATIVE_CACHE_MAX+1,&result)!=0);
                    caches[1].type=28;
                    check(r,txm_native_load_caches(&r->params,&r->state,type,0,caches,count,&result)!=0);
                    caches[1]=os;
                    check(r,r->state.phase==2 && r->state.calls==before);
                    tri->invalid_refusals=3;
                }
                uint64_t rc=txm_native_load_caches(&r->params,&r->state,type,0,caches,count,&result);
                tri->cases[i].transport=rc;tri->cases[i].status=result.status;tri->cases[i].size=result.size;
                tri->cases[i].offset=result.payload ? (uint64_t)result.payload-r->params.work:0;
                check(r,!rc && result.status==expected[i]);
                if(expected[i]==1) {
                    check(r,result.size==tri->size-23 &&
                        (uint64_t)result.payload==r->params.work+TXM_NATIVE_PAYLOAD+23);
                    for(uint64_t n=0;n<result.size;n++) {
                        check(r,result.payload[n]==((uint8_t *)tri->payload)[23+n]);
                        ((uint8_t *)tri->retained)[n]=result.payload[n];
                    }
                } else check(r,!result.size && !result.payload);
                if(edited)*edited^=1;
                for(uint64_t n=0;n<os.size;n++)check(r,os.payload[n]==((uint8_t *)r->payload)[23+n]);
                for(uint64_t n=0;n<app.size;n++)check(r,app.payload[n]==((uint8_t *)co->payload)[23+n]);
                for(uint64_t n=0;n<rosetta.size;n++)check(r,rosetta.payload[n]==((uint8_t *)tri->payload)[23+n]);
                check(r,r->state.phase==1 && *(volatile uint8_t *)(r->params.work+TXM_NATIVE_STACK+0x78)==0);
            }
            tri->completed=1;
        }
    }
    r->completed=1;
    return r->failures ? 1:0;
}

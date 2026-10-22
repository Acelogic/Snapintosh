/* SPDX-License-Identifier: MIT */
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "../compat/sep-xars.h"

static unsigned checks;
#define CHECK(v) do {assert(v);checks++;} while(0)
struct fixture {unsigned calls,fail,alias,drift,slots,last_bytes;};
static int bind(void *ctx,const struct sep_xars *s,unsigned d,uint64_t iova,
                uint64_t size,uint64_t out[SEP_XARS_PAGES])
{
    struct fixture *f=ctx;(void)s;(void)iova;
    CHECK(d<2 && size==SEP_XARS_SIZE);f->calls++;
    for(unsigned i=0;i<SEP_XARS_PAGES;i++)out[i]=0x100000+(f->alias ? 0 : d*0x8000+i*0x4000)+f->drift*0x40000;
    return !f->fail;
}
static int validate(void *ctx,const struct sep_xars *s)
{
    struct fixture *f=ctx;CHECK(s->stage[0]==2 && s->stage[1]==2);f->calls++;return !f->fail;
}
static int slot(void *ctx,const struct sep_xars *s,unsigned bytes)
{
    struct fixture *f=ctx;CHECK(s->stage[0]==2 && s->stage[1]==2);
    CHECK(bytes==SEP_XARS_SLOT_BYTES || bytes==SEP_XARS_EPOCH_BYTES);
    f->slots++;f->last_bytes=bytes;return !f->fail;
}
static uint64_t slot_request(unsigned tag,unsigned index)
{return (uint64_t)index<<48|(uint64_t)SEP_XARS_SLOT_INFO<<16|(uint64_t)tag<<8|2;}
static uint64_t neg(unsigned op,unsigned tag,uint64_t data)
{return data<<32|2UL<<24|(uint64_t)op<<16|(uint64_t)tag<<8;}
static void rejected(struct sep_xars *s,const struct sep_xars_io *io,uint64_t request)
{
    struct sep_xars before=*s;uint64_t reply=0x0123456789abcdefUL;
    CHECK(sep_xars_step(s,io,request,&reply)!=SEP_XARS_OK);
    CHECK(!memcmp(s,&before,sizeof(*s)) && reply==0x0123456789abcdefUL);
}
static struct sep_xars ready(const struct sep_xars_io *io,unsigned tag)
{
    struct sep_xars s={.ready=1,.advertisements=2};uint64_t reply;
    for(unsigned d=0;d<2;d++) {
        CHECK(sep_xars_step(&s,io,neg(4+d,tag,SEP_XARS_SIZE),&reply)==SEP_XARS_OK);
        CHECK(reply==(neg(4+d,tag,SEP_XARS_SIZE)&~0xff000000UL));
        CHECK(sep_xars_step(&s,io,neg(2+d,tag,0x10000000+d*8),&reply)==SEP_XARS_OK);
    }
    CHECK(sep_xars_valid(&s));return s;
}
int main(void)
{
    struct fixture f={0};const struct sep_xars_io io={&f,bind,validate,slot};
    struct sep_xars empty={0};CHECK(sep_xars_valid(&empty));rejected(&empty,&io,0xa0102);
    struct sep_xars s={.ready=1,.advertisements=2};
    rejected(&s,&io,0xa0102);rejected(&s,&io,neg(2,1,0x10000000));
    uint64_t samples[3]={0};const unsigned commands[3]={0xa,0xb,0x20};
    for(unsigned tag=1;tag<256;tag++) {
        s=ready(&io,tag);
        for(unsigned i=0;i<3;i++) {
            uint64_t request=(uint64_t)commands[i]<<16|(uint64_t)tag<<8|2,reply=0;
            CHECK(sep_xars_step(&s,&io,request,&reply)==SEP_XARS_OK);
            CHECK(reply==(0x10002UL|(uint64_t)tag<<8) && sep_xars_valid(&s));
            if(tag==7)samples[i]=reply;
        }
        for(unsigned op=0;op<256;op++)if(op!=0xa && op!=0xb && op!=0x20 && op!=SEP_XARS_SLOT_INFO &&
                                       op!=SEP_XARS_EPOCHS)
            rejected(&s,&io,(uint64_t)op<<16|(uint64_t)tag<<8|2);
        for(unsigned bit=24;bit<64;bit++)rejected(&s,&io,0xa0002UL|(uint64_t)tag<<8|1UL<<bit);
        /* Empty AP nonce slots 0 and 1: status0, 56-byte length, state0. */
        for(unsigned index=0;index<2;index++) {
            uint64_t request=slot_request(tag,index),reply=0;unsigned before=f.slots;
            CHECK(sep_xars_step(&s,&io,request,&reply)==SEP_XARS_OK && f.slots==before+1);
            CHECK(reply==((uint64_t)SEP_XARS_SLOT_BYTES<<24|(uint64_t)tag<<8|2));
            CHECK(!(reply>>16&255) && (reply>>24&0xffff)==56 && !(reply>>48&255));
            CHECK(sep_xars_valid(&s) && s.last_request==request);
            struct sep_xars bad=s;bad.last_reply^=1UL<<48;CHECK(!sep_xars_valid(&bad));
            bad=s;bad.last_reply^=1UL<<24;CHECK(!sep_xars_valid(&bad));
            bad=s;bad.last_reply|=1UL<<16;CHECK(!sep_xars_valid(&bad));
        }
        for(unsigned index=2;index<256;index++)rejected(&s,&io,slot_request(tag,index));
        for(unsigned bit=24;bit<64;bit++)if(bit!=48)
            rejected(&s,&io,slot_request(tag,0)|1UL<<bit);
        rejected(&s,&io,slot_request(0,0));rejected(&s,&io,slot_request(tag,0)^3);
        /* getFullEpochs: eight empty 4-byte slots, status0, length 32 in
         * bytes3-4. The kernel panics on any other length, so it is never
         * refused; anything but the bare opcode is not this request. */
        {
            uint64_t request=(uint64_t)SEP_XARS_EPOCHS<<16|(uint64_t)tag<<8|2,reply=0;
            unsigned before=f.slots;
            CHECK(sep_xars_step(&s,&io,request,&reply)==SEP_XARS_OK && f.slots==before+1);
            CHECK(f.last_bytes==SEP_XARS_EPOCH_BYTES);
            CHECK(reply==((uint64_t)SEP_XARS_EPOCH_BYTES<<24|(uint64_t)tag<<8|2));
            CHECK(!(reply>>16&255) && (reply>>24&0xffff)==32 && !(reply>>40));
            CHECK(sep_xars_valid(&s) && s.last_request==request);
            struct sep_xars bad=s;bad.last_reply^=1UL<<24;CHECK(!sep_xars_valid(&bad));
            bad=s;bad.last_reply|=1UL<<16;CHECK(!sep_xars_valid(&bad));
            for(unsigned bit=24;bit<64;bit++)rejected(&s,&io,request|1UL<<bit);
            rejected(&s,&io,request&~0xff00UL);rejected(&s,&io,request^3);
        }
        CHECK(s.queries==6);
    }
    {
        struct sep_xars early={.ready=1,.advertisements=2};rejected(&early,&io,slot_request(1,0));
        early=ready(&io,1);const struct sep_xars_io missing={&f,bind,validate,0};
        rejected(&early,&missing,slot_request(1,0));
        f.fail=1;rejected(&early,&io,slot_request(1,1));f.fail=0;
        early.queries=UINT64_MAX;rejected(&early,&io,slot_request(1,0));
        early=ready(&io,1);f.fail=1;rejected(&early,&io,(uint64_t)SEP_XARS_EPOCHS<<16|0x102);f.fail=0;
        rejected(&early,&missing,(uint64_t)SEP_XARS_EPOCHS<<16|0x102);
    }
    s=ready(&io,1);
    f.fail=1;rejected(&s,&io,0xa0102);rejected(&s,&io,neg(2,1,0x10000000));f.fail=0;
    f.drift=1;rejected(&s,&io,neg(2,1,0x10000000));f.drift=0;
    f.alias=1;rejected(&s,&io,neg(2,1,0x10000000));f.alias=0;
    for(unsigned bit=0;bit<64;bit++) {
        struct sep_xars bad=s;bad.physical[0][0]^=1UL<<bit;
        if(!sep_xars_valid(&bad))rejected(&bad,&io,0xa0102);
    }
    s.queries=UINT64_MAX;rejected(&s,&io,0xa0102);
    s=ready(&io,1);s.negotiations=UINT64_MAX;rejected(&s,&io,neg(4,1,SEP_XARS_SIZE));
    s=ready(&io,1);rejected(&s,&io,neg(3,1,0x10000000));
    rejected(&s,&io,neg(4,1,SEP_XARS_SIZE+1));rejected(&s,&io,0xa0002);
    uint64_t empty_slots[2],full_epochs;
    s=ready(&io,6);CHECK(sep_xars_step(&s,&io,(uint64_t)SEP_XARS_EPOCHS<<16|0x602,&full_epochs)==SEP_XARS_OK);
    for(unsigned index=0;index<2;index++) {
        s=ready(&io,6);CHECK(sep_xars_step(&s,&io,slot_request(6,index),&empty_slots[index])==SEP_XARS_OK);
    }
    printf("{\"checks\":%u,\"advertisements\":[%llu,%llu],\"refusals\":[%llu,%llu,%llu],"
           "\"empty_slots\":[[%llu,%llu],[%llu,%llu]],\"full_epochs\":[[%llu,%llu]]}\n",
           checks,(unsigned long long)SEP_XARS_AD_NAME,(unsigned long long)SEP_XARS_AD_OOL,
           (unsigned long long)samples[0],(unsigned long long)samples[1],(unsigned long long)samples[2],
           (unsigned long long)slot_request(6,0),(unsigned long long)empty_slots[0],
           (unsigned long long)slot_request(6,1),(unsigned long long)empty_slots[1],
           (unsigned long long)((uint64_t)SEP_XARS_EPOCHS<<16|0x602),(unsigned long long)full_epochs);
    return 0;
}

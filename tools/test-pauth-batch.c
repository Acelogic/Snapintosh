/* SPDX-License-Identifier: MIT */
#include "../compat/pauth-batch.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
#define LOW 0x80000000UL
#define META 0x90000000UL
#define SCRATCH (LOW+0x10000)
#define SCRATCH_VA 0xfffffe0100010000UL
static unsigned checks;
#define CHECK(x) do {assert(x);checks++;} while(0)
struct fixture {
    uint8_t mem[0x14000],meta[5*16],before[0x4000];
    struct pauth_batch_state state;
    unsigned signs,publishes,fail_at,mutate;
    uint64_t input,count,deny;
};
static struct fixture f;
static volatile uint8_t *map(void *ctx,uint64_t pa,uint64_t size)
{
    struct fixture *f=ctx;
    if(f->deny==pa)return 0;
    if(pa>=LOW && pa-LOW<sizeof(f->mem) && size<=sizeof(f->mem)-(pa-LOW))return f->mem+(pa-LOW);
    if(pa>=META && pa-META<sizeof(f->meta) && size<=sizeof(f->meta)-(pa-META))return f->meta+(pa-META);
    return 0;
}
static uint64_t synthetic(const struct pauth_batch_entry *e)
{return e->pointer^e->modifier^0x1234000000000000UL^e->key;}
static int sign(void *ctx,const struct pauth_batch_entry *e,uint64_t tbi,uint64_t tbid,uint64_t *out)
{
    struct fixture *f=ctx;(void)tbi;(void)tbid;
    unsigned index=f->signs++;
    if(f->mutate)memset(f->mem+(f->input-LOW),0xee,f->count*24);
    if(index==f->fail_at)return 0;
    *out=synthetic(e);return 1;
}
static void publish(void *ctx,uint64_t pa,uint64_t size)
{
    struct fixture *f=ctx;CHECK(pa==SCRATCH && size==512+f->count*24);
    CHECK(f->signs==f->count);f->publishes++;
    CHECK(!memcmp(f->mem+(SCRATCH-LOW)+512,f->state.input,f->count*24));
    CHECK(!memcmp(f->mem+(SCRATCH-LOW),f->state.output,f->count*8));
}
static struct sptm_memory memory(void)
{return (struct sptm_memory){.frame_map_pa=META,.frame_low=LOW,.frame_high=LOW+sizeof(f.mem),
    .map=map,.publish=publish,.ctx=&f};}
static void setup(uint64_t input,uint64_t count)
{
    memset(&f,0,sizeof(f));memset(f.mem,0xa5,sizeof(f.mem));
    f.input=input;f.count=count;f.fail_at=999;
    for(unsigned i=0;i<5;i++)f.meta[i*16+2]=SPTM_MAC_DEFAULT;
    if(count<=64 && input>=LOW && input-LOW<=sizeof(f.mem)-count*24)
        for(unsigned i=0;i<count;i++) {
            struct pauth_batch_entry e={0x100000000UL+16*i,0x9876000000000000UL+i,(i&1)*2,0x55aa55aa};
            memcpy(f.mem+(input-LOW)+24*i,&e,24);
        }
    memcpy(f.before,f.mem+(SCRATCH-LOW),sizeof(f.before));
}
static enum sptm_result execute(uint64_t input,uint64_t count,uint64_t tbi,uint64_t tbid)
{
    struct sptm_memory m=memory();
    return pauth_batch_sign(&m,&f.state,input,count,SCRATCH,SCRATCH_VA,tbi,tbid,sign,&f);
}
static void unchanged(void)
{CHECK(!f.publishes);CHECK(!memcmp(f.before,f.mem+(SCRATCH-LOW),sizeof(f.before)));}
int main(int argc,char **argv)
{
    int replay=argc==2 && !strcmp(argv[1],"--replay");
    for(unsigned count=1;count<=64;count++)for(unsigned unaligned=0;unaligned<2;unaligned++) {
        setup(LOW+0x10+unaligned,count);CHECK(execute(f.input,count,0,0)==SPTM_OK);
        CHECK(f.signs==count && f.publishes==1 && f.state.calls==1 && f.state.records==count);
        CHECK(f.state.result_va==SCRATCH_VA+512 && f.state.restored_calls==count);
        CHECK(!memcmp(f.mem+(SCRATCH-LOW)+count*8,f.before+count*8,512-count*8));
        CHECK(!memcmp(f.mem+(SCRATCH-LOW)+512+count*24,f.before+512+count*24,0x4000-512-count*24));
        if(replay && !unaligned) {
            printf("%u",count);
            for(unsigned i=0;i<count;i++)printf(" %llx",(unsigned long long)f.state.output[i]);
            puts("");
        }
    }
    for(unsigned type=0;type<256;type++) {
        setup(LOW+16,64);f.meta[2]=(uint8_t)type;
        int accepted=type==11 || type==35;
        CHECK((execute(f.input,64,0,0)==SPTM_OK)==accepted);
        if(!accepted) {CHECK(!f.signs);unchanged();}
    }
    for(unsigned index=0;index<64;index++) {
        setup(LOW+16,64);f.mem[16+index*24+16]=1;
        CHECK(execute(f.input,64,0,0)==SPTM_BAD_CONFIG);CHECK(!f.signs);unchanged();
        setup(LOW+16,64);f.fail_at=index;
        CHECK(execute(f.input,64,0,0)==SPTM_SHADOW_FAILED);
        CHECK(f.state.failed_index==index && f.state.restored_calls==index);unchanged();
    }
    for(unsigned lock=0;lock<65536;lock+=2) {
        setup(LOW+16,1);f.meta[0]=(uint8_t)lock;f.meta[1]=(uint8_t)(lock>>8);
        CHECK((execute(f.input,1,0,0)==SPTM_OK)==(lock<=0xfff1));
    }
    for(unsigned lock=1;lock<65536;lock+=2) {
        setup(LOW+16,1);f.meta[0]=(uint8_t)lock;f.meta[1]=(uint8_t)(lock>>8);
        CHECK(execute(f.input,1,0,0)==SPTM_FRAME_BUSY);unchanged();
    }
    for(unsigned key=0;key<=2;key+=2)for(unsigned tbi=0;tbi<2;tbi++)for(unsigned tbid=0;tbid<2;tbid++) {
        setup(LOW+16,1);struct pauth_batch_entry e={0xab00000100000000UL,7,key,9};
        memcpy(f.mem+16,&e,24);
        int valid=tbi && (key==2 || !tbid);
        CHECK((execute(f.input,1,tbi,tbid)==SPTM_OK)==valid);
        if(!valid) {CHECK(!f.signs);unchanged();}
    }
    const uint64_t counts[]={0,65,UINT64_MAX};
    for(unsigned i=0;i<3;i++) {setup(LOW+16,counts[i]);CHECK(execute(f.input,counts[i],0,0)!=SPTM_OK);unchanged();}
    const uint64_t addresses[]={LOW-1,LOW+sizeof(f.mem),UINT64_MAX,LOW+0x4000-1535};
    for(unsigned i=0;i<4;i++) {setup(addresses[i],64);CHECK(execute(f.input,64,0,0)!=SPTM_OK);unchanged();}
    for(unsigned i=0;i<3;i++) {
        setup(LOW+16,64);f.deny=i==0 ? META : i==1 ? f.input : SCRATCH;
        CHECK(execute(f.input,64,0,0)==SPTM_MEMORY_UNAVAILABLE);unchanged();
    }
    setup(LOW+16,64);f.mutate=1;CHECK(execute(f.input,64,0,0)==SPTM_OK);
    for(unsigned i=0;i<64;i++)CHECK(f.state.output[i]==synthetic(&f.state.input[i]));
    setup(SCRATCH+0x100,64);CHECK(execute(f.input,64,0,0)==SPTM_OK);
    for(unsigned i=0;i<64;i++)CHECK(f.state.output[i]==synthetic(&f.state.input[i]));
    if(!replay)printf("pauth batch: %u sanitizer checks passed\n",checks);
    return 0;
}

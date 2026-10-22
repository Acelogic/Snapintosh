/* SPDX-License-Identifier: MIT */
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "device.h"

static unsigned checks;
#define CHECK(x) do { if (!(x)) { fprintf(stderr,"FAIL line %d: %s\n",__LINE__,#x); assert(x); } checks++; } while (0)
#define BASE 0x8c0000000UL
#define DATA (BASE+0xc000)
#define FULL (0xfffUL<<40)
static uint64_t pages[4][2048];
static struct dart_state s, before;
static unsigned reads, deny, failed_read;
static int allow(void *ctx,uint64_t pa,uint64_t size,int write)
{
    CHECK(ctx==pages);
    (void)write;
    return !deny && size && pa>=BASE && pa<BASE+sizeof(pages) && size<=BASE+sizeof(pages)-pa;
}
static int read64(void *ctx,uint64_t pa,uint64_t *value)
{
    CHECK(ctx==pages && !(pa&7) && pa>=BASE && pa+8<=BASE+sizeof(pages));
    reads++;
    if (failed_read) return -1;
    *value=pages[(pa-BASE)/0x4000][(pa&0x3fff)/8];
    return 0;
}
static const struct dart_memory mem={pages,read64,allow};
static uint64_t reg(unsigned off)
{
    uint64_t v=0xdead;
    CHECK(dart_access(&s,19,off,4,0,&v)==DART_OK);
    return v;
}
static void put(unsigned off,uint64_t v)
{
    CHECK(dart_access(&s,19,off,4,1,&v)==DART_OK);
}
static void refused(unsigned off,unsigned width,int write,uint64_t value,enum dart_result result)
{
    before=s; uint64_t v=value;
    CHECK(dart_access(&s,19,off,width,write,&v)==result);
    CHECK(v==value && !memcmp(&s,&before,sizeof(s)));
}
static void setup(int four)
{
    dart_init(&s); memset(pages,0,sizeof(pages)); deny=failed_read=reads=0;
    put(0xc00,1U<<18); put(0x1048,four ? 9 : 1);
    put(0x1448,(BASE>>12)|1);
    if (four) { pages[0][1]=((BASE+0x4000)>>4)|1; pages[1][3]=((BASE+0x8000)>>4)|1; }
    else pages[0][3]=((BASE+0x8000)>>4)|1;
    pages[2][7]=(DATA>>4)|FULL|1;
}
static void translated(uint64_t iova,uint64_t size,int write,uint64_t expected)
{
    uint64_t pa=0xbad;
    CHECK(dart_translate(&s,19,&mem,18,iova,size,write,&pa)==DART_OK && pa==expected);
}
static void faulted(uint64_t iova,uint64_t size,int write,unsigned code)
{
    put(0x100,1U<<31); uint64_t pa=0xbad;
    CHECK(dart_translate(&s,19,&mem,18,iova,size,write,&pa)==DART_FAULT && pa==0xbad);
    CHECK(s.error==(0x80000000U|(18U<<20)|(write?1U<<28:0)|code));
    CHECK(s.error_address==iova && dart_irq_pending(&s));
}
int main(void)
{
    dart_init(&s);
    CHECK(reg(0)==0x8e000000 && reg(4)==1 && reg(8)==0x242c0200 && reg(12)==0x130013);
    for (unsigned off=0;off<16;off+=4) refused(off,4,1,0,DART_READ_ONLY);
    for (unsigned w=0;w<=16;w++) if(w!=4) refused(0,w,0,77,DART_BAD_WIDTH);
    refused(1,4,0,1,DART_BAD_WIDTH); refused(0x10,4,0,1,DART_UNKNOWN_REGISTER);
    refused(0x170,4,1,1,DART_READ_ONLY); refused(0xc00,4,1,1UL<<32,DART_BAD_VALUE);
    put(0xc00,UINT32_MAX); CHECK(reg(0xc00)==0x7ffff);
    put(0xc04,UINT32_MAX); CHECK(reg(0xc04)==0);
    put(0xc20,1U<<18); CHECK(reg(0xc20)==0x3ffff);
    refused(0x104c,4,1,1,DART_UNKNOWN_REGISTER); refused(0x144c,4,0,0,DART_UNKNOWN_REGISTER);
    for (unsigned v=0;v<256;v++) if ((v&~15U)||(v&3)==3) refused(0x1000,4,1,v,DART_BAD_VALUE);
    refused(0x1400,4,1,2,DART_BAD_VALUE); refused(0x1400,4,1,1U<<24,DART_BAD_VALUE);
    put(0x200,1); refused(0x1000,4,1,1,DART_BAD_VALUE);
    put(0x204,1); put(0x1000,1); put(0x208,1); put(0x200,1); put(0x204,1);
    CHECK(reg(0x208)==1 && reg(0x200)==1);
    refused(0x1400,4,1,1,DART_BAD_VALUE); refused(0x208,4,1,32,DART_BAD_VALUE);
    dart_init(&s);
    for (unsigned cmd=0;cmd<8;cmd++) {
        if (cmd==0 || cmd==1 || cmd==4) { put(0x80,0x80008000U|(cmd<<8)); CHECK(!(reg(0x80)>>31)); }
        else refused(0x80,4,1,0x8000|(cmd<<8),DART_BAD_VALUE);
    }
    put(0x98,0x100); put(0xa0,0x80); refused(0x80,4,1,0xc100,DART_BAD_VALUE);
    put(0xa0,0x100); put(0x80,0xc112);
    refused(0x80,4,1,0x8113,DART_BAD_VALUE); refused(0x80,4,1,0x8001,DART_BAD_VALUE);
    refused(0x80,4,1,0x10000,DART_BAD_VALUE); refused(0x98,4,1,1,DART_BAD_VALUE);
    const uint64_t io=(3UL<<25)|(7UL<<14);
    for (int four=0;four<=1;four++) {
        uint64_t iova=io+(four ? 1UL<<36 : 0);
        setup(four);
        for (unsigned off=0;off<0x4000;off+=127) {
            translated(iova+off,1,0,DATA+off); translated(iova+off,1,1,DATA+off);
        }
        translated(iova,0x4000,0,DATA);
        CHECK(reads==s.translations*(four?3:2));
        /* A changed guest PTE is observed without retaining stale mappings. */
        pages[2][7]=((DATA-0x4000)>>4)|FULL|1;
        translated(iova+123,2,1,DATA-0x4000+123);
        put(0x80,0x8112); translated(iova,0x4000,0,DATA-0x4000);
        pages[2][7]=(DATA>>4)|FULL|5; faulted(iova,4,1,1U<<4);
        translated(iova,4,0,DATA);
        pages[2][7]=(DATA>>4)|FULL|9; faulted(iova,4,0,1U<<5);
        translated(iova,4,1,DATA);
        pages[2][7]=(DATA>>4)|(2UL<<52)|(4UL<<40)|1; // bytes [8,20)
        translated(iova+8,12,1,DATA+8);
        faulted(iova+7,1,0,1U<<29); faulted(iova+20,1,0,1U<<29);
        faulted(iova+16,5,1,1U<<29);
        pages[2][7]=0; faulted(iova,4,0,1U<<3);
        pages[four?1:0][3]=0; faulted(iova,4,0,1U<<2);
        if (four) { pages[0][1]=0; faulted(iova,4,0,1U<<1); }
        setup(four); put(0x1448,0); faulted(iova,4,0,1);
        setup(four); put(0xc20,1U<<18); faulted(iova,4,0,1);
        setup(four); deny=1; reads=0; faulted(iova,4,0,1U<<7); CHECK(reads==0);
        setup(four); failed_read=1; faulted(iova,4,0,1U<<7);
        setup(four); pages[2][7]=((BASE+sizeof(pages))>>4)|FULL|1; faulted(iova,4,0,1U<<6);
        setup(four); pages[2][7]=((1UL<<36)>>4)|FULL|1; faulted(iova,4,0,1U<<6);
        setup(four); pages[0][four?1:3]=(BASE>>4)|1; faulted(iova,4,0,1U<<7);
    }
    setup(0); faulted(1UL<<36,4,0,1U<<6);
    setup(1); faulted(1UL<<44,4,0,1U<<6);
    setup(0); put(0x1048,2); translated(DATA+8,4,1,DATA+8); CHECK(reads==0);
    faulted(0x300000000,4,0,1U<<6); faulted(1UL<<36,4,0,1U<<6);
    // Keep the first error address while recording another stream's fault.
    uint32_t first=s.error; uint64_t first_pa=s.error_address, pa=0xbad;
    CHECK(dart_translate(&s,19,&mem,1,0x1234,4,1,&pa)==DART_FAULT && pa==0xbad);
    CHECK(s.error==(first|(1U<<19)) && s.error_address==first_pa && reg(0x1c0)==((1U<<18)|2));
    put(0x104,UINT32_MAX); CHECK(!dart_irq_pending(&s)); put(0x104,0); CHECK(dart_irq_pending(&s));
    CHECK(reg(0x170)==(uint32_t)first_pa && reg(0x174)==first_pa>>32);
    put(0x1c0,2); CHECK(reg(0x1c0)==1U<<18);
    put(0x100,1U<<31); CHECK(!dart_irq_pending(&s) && reg(0x100)==0);
    before=s;
    CHECK(dart_translate(&s,19,&mem,19,0,4,0,&pa)==DART_BAD_CONFIG);
    CHECK(dart_translate(&s,19,&mem,0,0,0,0,&pa)==DART_BAD_CONFIG);
    CHECK(dart_translate(&s,19,&mem,0,0x3fff,2,0,&pa)==DART_BAD_CONFIG);
    CHECK(dart_translate(&s,19,&mem,0,0,4,2,&pa)==DART_BAD_CONFIG);
    CHECK(!memcmp(&s,&before,sizeof(s)) && pa==0xbad);
    // Last SID and all eight stream banks remain representable.
    dart_init(&s);
    for (unsigned i=0;i<8;i++) {
        uint64_t v=UINT32_MAX;
        CHECK(dart_access(&s,256,0xc00+i*4,4,1,&v)==DART_OK && s.enabled[i]==UINT32_MAX);
    }
    CHECK(dart_translate(&s,256,&mem,255,0,4,0,&pa)==DART_FAULT && s.error_streams[7]==0x80000000U);
    // Integration: both access APIs and shared AIC fault lines.
    struct device_model models[]={
        {DEVICE_AIC3_FLAT_V1,0x301000000UL,0x1cc000,{1280,4096,0x40000,10,0}},
        {DEVICE_DART_T8110_V1,0x385060000UL,0x20000,{19,44,1120,36,0}},
        {DEVICE_DART_T8110_V1,0x385080000UL,0x20000,{19,44,1120,36,0}}};
    static struct device_state states[3];
    CHECK(device_models_valid(models,3,0,0));
    for (unsigned i=0;i<3;i++) CHECK(device_model_start(&models[i],&states[i],0,24000000)==DEVICE_OK);
    uint64_t v=0;
    CHECK(device_model_access_state(&models[1],&states[1],0,4,0,&v)==DEVICE_OK && v==0x8e000000);
    CHECK(device_model_access_at(&models[1],&states[1],99,4,4,0,&v)==DEVICE_OK && v==1);
    CHECK(device_model_access(&models[1],0,4,0,&v)==DEVICE_BAD_CONFIG);
    states[1].dart.error=0x80000001U; states[2].dart.error=0xa0000000U;
    CHECK(device_models_route_irqs(models,states,3)==DEVICE_OK && states[0].aic.level[35]==1);
    states[1].dart.error=0;
    CHECK(device_models_route_irqs(models,states,3)==DEVICE_OK && states[0].aic.level[35]==1);
    states[2].dart.error_mask=1U<<29;
    CHECK(device_models_route_irqs(models,states,3)==DEVICE_OK && states[0].aic.level[35]==0);
    // INIT captures immutable capabilities exactly once per logical ID. It
    // neither resets MMIO state nor enables translation. All instances commit
    // together; aliases use distinct logical bits over the same physical state.
    models[1].config[4]=models[2].config[4]=(1U<<21)|2;
    static struct device_state saved[3];
    memcpy(saved,states,sizeof(states));
    CHECK(device_dart_monitor_init(models,states,3,32)==DEVICE_BAD_CONFIG);
    CHECK(device_dart_monitor_init(models,states,3,20)==DEVICE_NOT_FOUND);
    CHECK(!memcmp(saved,states,sizeof(states)));
    models[2].config[0]=18;
    CHECK(device_dart_monitor_init(models,states,3,21)==DEVICE_BAD_CONFIG);
    CHECK(!memcmp(saved,states,sizeof(states)));models[2].config[0]=19;
    CHECK(device_dart_monitor_init(models,states,3,21)==DEVICE_OK);
    saved[1].dart.initialized_ids=saved[2].dart.initialized_ids=1U<<21;
    CHECK(!memcmp(saved,states,sizeof(states)));
    CHECK(device_dart_monitor_init(models,states,3,21)==DEVICE_BAD_VALUE);
    CHECK(!memcmp(saved,states,sizeof(states)));
    states[1].dart.initialized_ids=0;memcpy(saved,states,sizeof(states));
    CHECK(device_dart_monitor_init(models,states,3,21)==DEVICE_BAD_VALUE);
    CHECK(!memcmp(saved,states,sizeof(states)));
    CHECK(device_dart_monitor_init(models,states,3,1)==DEVICE_OK);
    CHECK(states[1].dart.initialized_ids==2 && states[2].dart.initialized_ids==((1U<<21)|2));
    // First power-up is bound to one audited SIO bank, after INIT. Refusal
    // must not erase state or partially initialize another matching bank.
    for (unsigned i=1;i<3;i++) {
        dart_init(&states[i].dart);
        models[i].config[0]=16;
        models[i].config[1]=DEVICE_DART_SIO_BOOT_V1;
        models[i].config[4]=1U<<21;
    }
    memcpy(saved,states,sizeof(states));
    CHECK(device_dart_monitor_powerup(models,states,2,32)==DEVICE_BAD_CONFIG);
    CHECK(device_dart_monitor_powerup(models,states,2,20)==DEVICE_NOT_FOUND);
    CHECK(device_dart_monitor_powerup(models,states,2,21)==DEVICE_BAD_VALUE);
    CHECK(!memcmp(saved,states,sizeof(states)));
    CHECK(device_dart_monitor_init(models,states,3,21)==DEVICE_OK);
    memcpy(saved,states,sizeof(states));
    CHECK(device_dart_monitor_powerup(models,states,3,21)==DEVICE_BAD_CONFIG);
    CHECK(!memcmp(saved,states,sizeof(states)));
    models[1].config[1]=44;
    CHECK(device_dart_monitor_powerup(models,states,2,21)==DEVICE_BAD_CONFIG);
    CHECK(!memcmp(saved,states,sizeof(states)));
    models[1].config[1]=DEVICE_DART_SIO_BOOT_V1;
    for (unsigned i=0;i<DART_STREAMS;i++) {
        states[1].dart.tcr[i]=1;
        CHECK(device_dart_monitor_powerup(models,states,2,21)==DEVICE_BAD_VALUE);
        states[1].dart.tcr[i]=0;
        states[1].dart.ttbr[i]=1;
        CHECK(device_dart_monitor_powerup(models,states,2,21)==DEVICE_BAD_VALUE);
        states[1].dart.ttbr[i]=0;
        CHECK(!memcmp(saved,states,sizeof(states)));
    }
    for (unsigned i=0;i<8;i++) {
        states[1].dart.enabled[i]=1;
        CHECK(device_dart_monitor_powerup(models,states,2,21)==DEVICE_BAD_VALUE);
        states[1].dart.enabled[i]=0;
        states[1].dart.error_streams[i]=1;
        CHECK(device_dart_monitor_powerup(models,states,2,21)==DEVICE_BAD_VALUE);
        states[1].dart.error_streams[i]=0;
        CHECK(!memcmp(saved,states,sizeof(states)));
    }
    uint32_t *nonzero32[]={&states[1].dart.powered_ids,&states[1].dart.error,
        &states[1].dart.error_mask,&states[1].dart.protect,&states[1].dart.protect_lock,
        &states[1].dart.tlb_op,&states[1].dart.tlb_start,&states[1].dart.tlb_end};
    for (unsigned i=0;i<sizeof(nonzero32)/sizeof(*nonzero32);i++) {
        *nonzero32[i]=1;
        CHECK(device_dart_monitor_powerup(models,states,2,21)==DEVICE_BAD_VALUE);
        *nonzero32[i]=0;
        CHECK(!memcmp(saved,states,sizeof(states)));
    }
    uint64_t *nonzero64[]={&states[1].dart.error_address,&states[1].dart.translations,
        &states[1].dart.faults,&states[1].dart.flushes};
    for (unsigned i=0;i<sizeof(nonzero64)/sizeof(*nonzero64);i++) {
        *nonzero64[i]=1;
        CHECK(device_dart_monitor_powerup(models,states,2,21)==DEVICE_BAD_VALUE);
        *nonzero64[i]=0;
        CHECK(!memcmp(saved,states,sizeof(states)));
    }
    CHECK(device_dart_monitor_powerup(models,states,2,21)==DEVICE_OK);
    saved[1].dart.tcr[0]=saved[1].dart.tcr[1]=9;
    saved[1].dart.powered_ids=1U<<21;
    CHECK(!memcmp(saved,states,sizeof(states)));
    for (unsigned i=0;i<16;i++) {
        CHECK(device_model_access_state(&models[1],&states[1],0x1000+i*4,4,0,&v)==DEVICE_OK);
        CHECK(v==(i<2 ? 9 : 0));
        CHECK(device_model_access_state(&models[1],&states[1],0x1400+i*4,4,0,&v)==DEVICE_OK && !v);
    }
    for (unsigned off=0x210;off<=0x22c;off+=4) {
        if (off!=0x210 && off!=0x228 && off!=0x22c)continue;
        v=0xdead;
        CHECK(device_model_access_state(&models[1],&states[1],off,4,0,&v)==DEVICE_OK && !v);
        v=1;
        CHECK(device_model_access_state(&models[1],&states[1],off,4,1,&v)==DEVICE_READ_ONLY);
    }
    // Power-up alone authorizes no DMA. The repeat must preserve this fault
    // and its IRQ, even after the caller has changed exposed registers.
    unsigned old_reads=reads;pa=0xbad;
    CHECK(dart_translate(&states[1].dart,16,&mem,0,0,4,0,&pa)==DART_FAULT);
    CHECK(pa==0xbad && reads==old_reads && !states[1].dart.enabled[0]);
    CHECK(device_models_route_irqs(models,states,2)==DEVICE_OK && states[0].aic.level[35]==1);
    memcpy(saved,states,sizeof(states));
    CHECK(device_dart_monitor_powerup(models,states,2,21)==DEVICE_OK);
    CHECK(!memcmp(saved,states,sizeof(states)));
    printf("PASS: %u DART register, translation, ownership, fault and IRQ checks\n",checks);
}

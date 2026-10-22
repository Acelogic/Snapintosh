/* SPDX-License-Identifier: MIT */
/* Real device/DART/monitor callback path; host memory/cache observation fixture. */
#define SIZE 0x200000UL
#define state dart_fixture_state
#define main unused_dart_checks
#include "test-sptm-dart-sep.c"
#undef main
#undef state
#include "sks-device-e2e-bridge.c"
#include "aes.h"

static const uint64_t addresses[7]={SH,SH+0x40000,SH+0x80000,
    SH+0xc0000,SH+0xe0000,SH+0x100000,SH+0x140000};
static const unsigned lengths[7]={5,7,5,2,2,2,2};
#define TX_PA (DATA+21*0x4000)
#define RX_PA (DATA+23*0x4000)
struct fixture_params { struct device_model models[4]; unsigned model_count; };
struct context {
    struct fixture_params *params;
    struct device_state model_state[4];
    uint8_t sep_sks_request[SEP_SKS_WIRE_MAX];
};
static struct context monitor;
static struct fixture_params params;
static struct sptm_memory memory;
static unsigned fault_mode,publish_phase,cache_publications;
static uint64_t fault_slot,fault_old_slot,fault_old_counter,fault_old_identity;
static volatile uint8_t *fixture_map(void *ctx,uint64_t pa,uint64_t n)
{
    if(fault_mode==1 && pa==TX_PA && n<0x4000)return 0;
    if(fault_mode==2 && pa==RX_PA && n<=SEP_SKS_REPLY_BYTES)return 0;
    if(fault_mode==7 && publish_phase && pa==FM+((DATA-BASE)>>14)*16)return 0;
    return map(ctx,pa,n);
}
static struct sptm_memory sptm_context_memory(struct context *c)
{ CHECK(c==&monitor);return memory; }
static void sptm_publish(struct context *c,uint64_t address,uint64_t n)
{
    CHECK(c==&monitor && address>=(uint64_t)ram && address+n<=(uint64_t)ram+SIZE);
    cache_publications++;
}
/* Generated verbatim from probes/xnuboot.c by replay-sks-monitor.py. */
#include "sks-monitor-callbacks.h"
static struct sep_rom_dma_context dma;
static int observe_publish(void *ctx,const struct sep_sks_endpoint *s,const uint8_t *reply,uint16_t n)
{
    publish_phase=1;int result=sep_sks_publish(ctx,s,reply,n);publish_phase=0;return result;
}
static const struct sep_sks_endpoint_io sks_io={&dma,sep_sks_bind,sep_sks_prepare,observe_publish};
static const struct sep_pnon_io pnon_io={&dma,sep_pnon_bind,sep_pnon_query};
static const struct sep_xars_io xars_io={&dma,sep_xars_bind,sep_xars_validate,sep_xars_slot};

int sks_monitor_start(void)
{
    fault_mode=publish_phase=cache_publications=0;
    memory=reset(0);attach(&memory,0,SH);
    unsigned cursor=0;
    for(unsigned span=0;span<7;span++) {
        for(unsigned page=0;page<lengths[span];page++) {
            uint64_t pa=DATA+(cursor+page)*0x4000;
            meta(pa)[2]=11;put(LIST+8*page,pa);
        }
        CHECK(sptm_dart_map(&memory,&dart_fixture_state,20,0,addresses[span],LIST,
            lengths[span]*0x4000,0)==SPTM_OK);
        cursor+=lengths[span];
    }
    CHECK(cursor==25 && sptm_dart_enable(&memory,&dart_fixture_state,20,0)==SPTM_OK);
    memory.map=fixture_map;
    params=(struct fixture_params){.models={
        {18,0x300700000,0x11000,{0,0,0,0,0}},
        {17,0x280b80000,0x20000,{3,DEVICE_DART_SEP_BOOT_V1,353,36,1U<<20}},
        {25,0x3003c0000,0x14000,{0x10000,0x1a8,0x1b8,8,DEVICE_PMP_ACTIVE_MASK}},
        {18,0x308280000,0x9000,{1,0,0,0,0}}},.model_count=4};
    memset(&monitor,0,sizeof(monitor));monitor.params=&params;
    for(unsigned i=0;i<4;i++)CHECK(device_model_start(params.models+i,monitor.model_state+i,0,24000000)==DEVICE_OK);
    monitor.model_state[1].dart=dart_fixture_state;
    dma=(struct sep_rom_dma_context){.c=&monitor,.shared_iova=SH,.shared_size=0x14000,
        .asc=&state.sep_asc,.pnon_refusal=1};
    int result=sks_device_start(&sks_io,&pnon_io,&xars_io);if(result)return result;
    for(unsigned owner=1;owner<=2;owner++)for(unsigned direction=0;direction<2;direction++) {
        unsigned span=owner==1 ? 1+direction : 3+direction;
        uint64_t words[2]={((uint64_t)lengths[span]*0x4000<<32)|((uint64_t)owner<<24)|
            ((uint64_t)(4+direction)<<16)|0x500,
            ((addresses[span]>>12)<<32)|((uint64_t)owner<<24)|((uint64_t)(2+direction)<<16)|0x500};
        for(unsigned i=0;i<2;i++) {
            uint64_t reply;result=sks_device_exchange(words[i],&reply);
            if(result || reply!=(words[i]&~0xff000000UL))return result ? result : -10;
        }
    }
    memset(ram+(RX_PA-BASE),0xa5,0x8000);return 0;
}
void *sks_monitor_buffer(unsigned direction)
{ return direction<2 ? ram+((direction ? RX_PA : TX_PA)-BASE) : 0; }
void *sks_monitor_ram(void){return ram;}
unsigned sks_monitor_ram_size(void){return SIZE;}
void *sks_monitor_dart(void){return &monitor.model_state[1].dart;}
unsigned sks_monitor_dart_size(void){return sizeof(struct dart_state);}
uint64_t sks_monitor_translations(void){return monitor.model_state[1].dart.translations;}
unsigned sks_monitor_publications(void){return cache_publications;}
unsigned sks_monitor_refusal(void){return dma.refusal;}
int sks_monitor_scratch_clear(void)
{ for(unsigned i=0;i<sizeof(monitor.sep_sks_request);i++)if(monitor.sep_sks_request[i])return 0;return 1; }
void sks_monitor_fault(unsigned mode)
{
    if(!mode) {
        if(fault_mode==3 || fault_mode==4)put(fault_slot,fault_old_slot);
        if(fault_mode==5 || fault_mode==8)monitor.model_state[1].dart.translations=fault_old_counter;
        if(fault_mode==6)state.sep_asc.xars.physical[1][1]=fault_old_identity;
        fault_mode=0;dma.refusal=SPTM_OK;return;
    }
    CHECK(!fault_mode);fault_mode=mode;
    fault_slot=LEAF+8*(((addresses[6]+0x4000)>>14)&2047);fault_old_slot=get(fault_slot);
    fault_old_counter=monitor.model_state[1].dart.translations;
    fault_old_identity=state.sep_asc.xars.physical[1][1];
    if(mode==3)put(fault_slot,fault_old_slot|8);
    if(mode==4)put(fault_slot,(fault_old_slot&~0xfffffffc00UL)|(DATA>>4));
    if(mode==5)monitor.model_state[1].dart.translations=UINT64_MAX-49;
    if(mode==6)state.sep_asc.xars.physical[1][1]+=0x4000;
    if(mode==8)monitor.model_state[1].dart.translations=UINT64_MAX-75;
}

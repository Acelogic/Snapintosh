/* SPDX-License-Identifier: MIT */
/* Host fixture boundary for the native SKS -> real device queue E2E replay. */
#include "device.h"
#include <string.h>
#define FW 0x10000004000UL
#define FW_BYTES 0x5dc000UL
#define SH 0x10001000000UL
static struct device_model model;
static struct device_state state;
static struct device_sep_rom_resources resources;
static uint64_t adverts[7];

static int admit(void *ctx,unsigned kind,uint64_t iova,uint64_t size)
{
    (void)ctx;return kind==0 && iova==FW && size==FW_BYTES;
}
static int bootstrap(void *ctx,uint64_t iova,uint64_t size,struct sep_bootstrap *out)
{
    (void)ctx;if(iova!=SH || size!=0x14000)return 0;
    *out=(struct sep_bootstrap){.panic_offset=0x4000,.panic_size=0x8000,
        .flags_offset=0xc000,.scot_offset=0x10000};return 1;
}
static int entropy(void *ctx,uint32_t *out){(void)ctx;*out=0x12345678;return 1;}
int sks_device_submit(uint64_t word)
{
    uint64_t pair[2]={word,0};return device_model_write_pair(&model,&state,0x8800,pair);
}
int sks_device_step(void){return device_sep_rom_step(&model,&state,&resources);}
int sks_device_receive(uint64_t *out)
{
    uint64_t pair[2];int result=device_model_read_pair(&model,&state,0x8830,pair);
    if(!result){if(pair[1])return -2;*out=pair[0];}return result;
}
int sks_device_exchange(uint64_t word,uint64_t *out)
{
    int result=sks_device_submit(word);if(result)return result;
    result=sks_device_step();return result ? result : sks_device_receive(out);
}
int sks_device_start(const struct sep_sks_endpoint_io *sks,
                     const struct sep_pnon_io *pnon,const struct sep_xars_io *xars)
{
    memset(&state,0,sizeof(state));memset(adverts,0,sizeof(adverts));
    model=(struct device_model){DEVICE_SEP_ASC_MAILBOX_V1,0x282600000,0x9000,{8,1,346,343,59}};
    resources=(struct device_sep_rom_resources){.firmware_size=FW_BYTES,.admit=admit,
        .bootstrap=bootstrap,.entropy32=entropy,.pnon=pnon,.xars=xars,.sks=sks};
    int result=device_model_start(&model,&state,0,24000000);if(result)return result;
    uint64_t enable=1;
    result=device_model_access_state(&model,&state,0x8114,4,1,&enable);if(result)return result;
    const uint64_t requests[]={0x201ff,0x501ff,0x201ff,((FW>>12)<<32)|0x200601ff};
    const uint64_t expected[]={0x1006601ffUL,0x6901ff,0x2006601ffUL,0x6a01ff};
    for(unsigned i=0;i<4;i++) {
        uint64_t reply=0;result=sks_device_exchange(requests[i],&reply);
        if(result || reply!=expected[i])return result ? result : -3;
    }
    result=sks_device_submit(((SH>>12)<<32)|(0x14UL<<16)|0x1fe);if(result)return result;
    result=sks_device_step();if(result)return result;
    for(unsigned i=0;i<7;i++)if((result=sks_device_receive(&adverts[i])))return result;
    return sks_device_step();
}
const struct sep_sks_endpoint *sks_device_endpoint(void){return &state.sep_asc.sks;}
const void *sks_device_state(void){return &state;}
unsigned sks_device_state_size(void){return sizeof(state);}
const uint64_t *sks_device_advertisements(void){return adverts;}
void sks_device_counters(uint64_t out[8])
{
    const struct device_sep_asc *s=&state.sep_asc;
    const uint64_t values[]={s->submitted,s->consumed,s->published,s->delivered,s->count,
        s->reply_count,s->sks.queries,s->sks.wire.updates};memcpy(out,values,sizeof(values));
}

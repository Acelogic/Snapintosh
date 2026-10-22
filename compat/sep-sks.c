/* SPDX-License-Identifier: MIT */
#include "sep-sks.h"
#include "sha256.h"
#include <stddef.h>

static uint32_t u32(const uint8_t *p)
{
    return (uint32_t)p[0]|(uint32_t)p[1]<<8|(uint32_t)p[2]<<16|(uint32_t)p[3]<<24;
}
static uint64_t u64(const uint8_t *p) { return u32(p)|(uint64_t)u32(p+4)<<32; }
static void put32(uint8_t *p,uint32_t value)
{
    for(unsigned i=0;i<4;i++)p[i]=(uint8_t)(value>>(8*i));
}
static void copy(uint8_t *out,const uint8_t *in,uint32_t bytes)
{
    for(uint32_t i=0;i<bytes;i++)out[i]=in[i];
}
static int overlap(const void *a,uint32_t an,const void *b,uint32_t bn)
{
    uintptr_t x=(uintptr_t)a,y=(uintptr_t)b;
    return an && bn && (x<=y ? y-x<an : x-y<bn);
}
static int environment_valid(const uint8_t *p)
{
    return u32(p)==1 && (u32(p+8)==4 || u32(p+8)==6);
}

enum sep_sks_wire_result sep_sks_wire(struct sep_sks_wire_state *state,
    uint32_t command,const uint8_t *request,uint32_t request_bytes,
    uint8_t *reply,uint32_t reply_capacity,uint32_t *reply_bytes)
{
    if(!reply_bytes)return SEP_SKS_MALFORMED;
    /* Do not let the size output alias the inputs before clearing it. */
    if(overlap(reply_bytes,4,state,state ? sizeof(*state) : 0) ||
       overlap(reply_bytes,4,request,request_bytes) ||
       overlap(reply_bytes,4,reply,reply_capacity))return SEP_SKS_MALFORMED;
    *reply_bytes=0;
    if(!state || !request || !reply)return SEP_SKS_MALFORMED;
    if(state->environment_valid>1 || (!!state->updates)!=state->environment_valid ||
       (state->environment_valid && !environment_valid(state->environment)))return SEP_SKS_BAD_STATE;
    if(request_bytes<80 || request_bytes>SEP_SKS_WIRE_MAX)return SEP_SKS_MALFORMED;
    uint32_t version=u32(request+20),header=u32(request);
    if((version!=1 && version!=2) || header!=(version==1 ? 72U : 80U) ||
       request_bytes<header+8 || u32(request+32)!=0)return SEP_SKS_MALFORMED;
    if(overlap(request,request_bytes,reply,reply_capacity) ||
       overlap(request,request_bytes,state,sizeof(*state)) ||
       overlap(reply,reply_capacity,state,sizeof(*state)))return SEP_SKS_MALFORMED;
    uint8_t digest[32];
    q1n1_sha256(request+20,request_bytes-20,digest);
    unsigned diff=0;
    for(unsigned i=0;i<16;i++)diff|=digest[i]^request[i+4];
    if(diff || u32(request+header+4)!=0)return SEP_SKS_MALFORMED;
    if(command!=SEP_SKS_GET_CAPABILITIES && command!=SEP_SKS_SET_ENVIRONMENT)
        return SEP_SKS_REFUSED;
    uint32_t body=header+4;
    if(request_bytes<body+16)return SEP_SKS_MALFORMED;
    uint32_t payload_bytes=u32(request+body+12);
    if(payload_bytes>SEP_SKS_ENV_BYTES || payload_bytes!=request_bytes-body-16)
        return SEP_SKS_MALFORMED;
    if(u64(request+body+4)!=1)return SEP_SKS_REFUSED;
    uint32_t wanted;
    if(command==SEP_SKS_GET_CAPABILITIES) {
        if(payload_bytes)return SEP_SKS_MALFORMED;
        wanted=body+16;
    } else {
        if(payload_bytes!=SEP_SKS_ENV_BYTES || !environment_valid(request+body+16))
            return SEP_SKS_MALFORMED;
        if(state->updates==UINT64_MAX)return SEP_SKS_BAD_STATE;
        wanted=body+4;
    }
    if(reply_capacity<wanted)return SEP_SKS_NO_SPACE;
    /* All refusals precede this commit section. Header identity is echoed and
     * the native truncated SHA256 digest covers every byte starting at +20. */
    copy(reply,request,body);
    for(uint32_t i=body;i<wanted;i++)reply[i]=0;
    if(command==SEP_SKS_GET_CAPABILITIES)put32(reply+body+4,2);
    q1n1_sha256(reply+20,wanted-20,digest);
    copy(reply+4,digest,16);
    if(command==SEP_SKS_SET_ENVIRONMENT) {
        copy(state->environment,request+body+16,SEP_SKS_ENV_BYTES);
        state->environment_valid=1;
        state->updates++;
    }
    *reply_bytes=wanted;
    return SEP_SKS_SUCCESS;
}

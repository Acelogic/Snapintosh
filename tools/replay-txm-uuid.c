/* SPDX-License-Identifier: MIT */
/* Replay adapter written before the service; see docs/TXM-UUID-20260925.md. */
#include "txm.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define BASE 0x100000UL
#define PAGE 0x4000UL
static uint8_t memory[0x120000], before[sizeof(memory)], input[16];
static unsigned publications, fail_copy;
static volatile uint8_t *map(void *ctx, uint64_t pa, uint64_t size)
{
    if(ctx!=memory || pa<BASE || pa-BASE>=sizeof(memory) || size>sizeof(memory)-(pa-BASE))return 0;
    return memory+(pa-BASE);
}
static void publish(void *ctx,uint64_t pa,uint64_t size)
{ (void)ctx;(void)pa;(void)size;publications++; }
static int copy(void *ctx,uint64_t va,uint8_t *out,uint64_t size)
{
    if(ctx!=input || va!=0xfffffe9a362ebb98UL || size!=16 || fail_copy)return 0;
    memcpy(out,input,16);return 1;
}
int main(int argc,char **argv)
{
    if(argc!=4 || strlen(argv[2])!=32)return 2;
    for(unsigned n=0;n<16;n++){unsigned byte;if(sscanf(argv[2]+2*n,"%2x",&byte)!=1)return 3;input[n]=(uint8_t)byte;}
    FILE *f=fopen(argv[1],"rb");if(!f)return 4;
    size_t size=fread(memory+3*PAGE,1,TXM_TRUST_MAX_BYTES,f);if(ferror(f) || !feof(f))return 5;fclose(f);
    struct sptm_memory m={.ctx=memory,.map=map,.publish=publish};
    struct txm_service s={.stacks_pa=BASE,.stack_count=1};
    struct txm_trust_cache tc={BASE+2*PAGE,0xfffffe0110008000UL,size};
    struct txm_trust_state state={0};
    if(!strcmp(argv[3],"empty"))memset(&tc,0,sizeof(tc));
    if(txm_trust_bootstrap(&m,&s,&tc,&state))return 6;
    uint64_t a[8]={BASE,0xfffffe9a362ebb98UL}, status=0x123;
    if(!strcmp(argv[3],"null-input"))a[1]=0;
    if(!strcmp(argv[3],"wrap-input"))a[1]=UINT64_MAX-15;
    if(!strcmp(argv[3],"bad-stack"))a[0]++;
    if(!strcmp(argv[3],"extra-argument"))a[2]=1;
    if(!strcmp(argv[3],"copy-failure"))fail_copy=1;
    if(!strcmp(argv[3],"corrupt-view"))memory[2*PAGE+0x18]=1;
    publications=0;memcpy(before,memory,sizeof(memory));
    enum sptm_result result=txm_trust_uuid(&m,&s,&tc,&state,copy,input,16,a,&status);
    uint64_t reply_status,reply_count;
    memcpy(&reply_status,memory+0x3c08,8);memcpy(&reply_count,memory+0x3c18,8);
    printf("{\"result\":%d,\"status\":\"0x%llx\",\"reply_status\":\"0x%llx\",\"reply_count\":%llu,\"publishes\":%u,\"unchanged\":%s}\n",
           result,(unsigned long long)status,(unsigned long long)reply_status,(unsigned long long)reply_count,
           publications,memcmp(before,memory,sizeof(memory))?"false":"true");
    return 0;
}

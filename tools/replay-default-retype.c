/* SPDX-License-Identifier: MIT */
/* Written before implementation; see TXM-TRANSFER-RETYPE-20260925.md.
 * Run against the captured full 16K page, refusing any payload change. */
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "sptm.h"
#define BASE 0x90000000UL
#define FM (BASE+0x4000)
#define PAGE (BASE+0x8000)
static uint8_t ram[0x10000],before[sizeof(ram)],payload[0x4000];
static unsigned checks,published;
#define CHECK(x) do {checks++;if(!(x)){fprintf(stderr,"FAIL %d: %s\n",__LINE__,#x);exit(1);}}while(0)
static volatile uint8_t *map(void *ctx,uint64_t pa,uint64_t size)
{
    (void)ctx;return pa<BASE || pa>=BASE+sizeof(ram) || size>BASE+sizeof(ram)-pa ?
        NULL:ram+(pa-BASE);
}
static void publish(void *ctx,uint64_t pa,uint64_t size)
{
    (void)ctx;CHECK(pa==FM+32 && size==16);published++;
}
static struct sptm_memory memory={.frame_map_pa=FM,.frame_low=BASE,.frame_high=BASE+0x10000,
    .alloc_low=PAGE,.alloc_high=BASE+0x10000,.map=map,.publish=publish};
static uint8_t *meta(void){return ram+(FM-BASE)+32;}
static void setup(void)
{
    memset(ram,0,sizeof(ram));memcpy(ram+(PAGE-BASE),payload,sizeof(payload));
    meta()[2]=11;published=0;
}
static void refuse(uint64_t pa,uint64_t old,uint64_t next,uint64_t options)
{
    memcpy(before,ram,sizeof(ram));
    CHECK(sptm_mac_retype(&memory,pa,old,next,options)!=SPTM_OK);
    CHECK(!published && !memcmp(before,ram,sizeof(ram)));
}
int main(int argc,char **argv)
{
    if(argc!=2)return 2;
    FILE *f=fopen(argv[1],"rb");CHECK(f!=NULL);
    CHECK(fread(payload,1,sizeof(payload),f)==sizeof(payload));CHECK(fgetc(f)==EOF);fclose(f);
    setup();CHECK(sptm_mac_retype_supported(11,11));
    CHECK(sptm_mac_apple_retype(11,11));
    CHECK(!sptm_mac_retype(&memory,PAGE,11,11,0));
    CHECK(published==1 && meta()[2]==11);
    CHECK(!memcmp(ram+(PAGE-BASE),payload,sizeof(payload)));
    for(unsigned n=0;n<16;n++)CHECK(meta()[n]==(n==2 ? 11:0));
    /* Common reset clears non-reference bytes; DEFAULT preserves byte3. */
    setup();meta()[3]=0xa0;meta()[4]=0x80;meta()[5]=0xaa;meta()[6]=0xbb;meta()[7]=0xcc;
    CHECK(!sptm_mac_retype(&memory,PAGE,11,11,0));
    CHECK(meta()[3]==0xa0 && !meta()[4] && !meta()[5] && !meta()[6] && !meta()[7]);
    CHECK(!memcmp(ram+(PAGE-BASE),payload,sizeof(payload)));
    for(unsigned n=0;n<2;n++){setup();meta()[n]=1;refuse(PAGE,11,11,0);}
    for(unsigned n=8;n<16;n++){setup();meta()[n]=1;refuse(PAGE,11,11,0);}
    for(unsigned n=1;n<4;n++){setup();meta()[4]=n;refuse(PAGE,11,11,0);}
    setup();meta()[2]=14;refuse(PAGE,11,11,0);
    setup();refuse(PAGE+1,11,11,0);setup();refuse(FM,11,11,0);
    setup();refuse(PAGE,11,11,1);setup();refuse(PAGE,14,14,0);
    printf("{\"result\":\"PASS\",\"checks\":%u,\"payload_bytes_preserved\":16384,\"boundary\":\"Captured payload and guarded metadata lifecycle; hardware aperture/TLBI proof is separate\"}\n",checks);
    return 0;
}

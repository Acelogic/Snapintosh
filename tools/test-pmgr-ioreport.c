/* SPDX-License-Identifier: MIT */
/* ApplePMGR's IOReport update against the PMGR counter models
 * (docs/PMGR-IOREPORT-20261017.md). Every access of the update path
 * (pmgr-ioreport-accesses.h: SoC perf groups 0-7, ACC counters, CPU energy
 * accumulators, PMP V2 energy nodes, cluster power states) is replayed against
 * the models the J700 installed profile builds, with their exact configs:
 *  - cold (nothing restored): every read is DEVICE_OK, counters read 0, active
 *    clusters 15, and no state changes;
 *  - after the kernel's restore writes, with SoC sampling enabled: each counter
 *    reads its restored value, stable across the stock high/low/high read;
 *  - refusals kept: writes to the new read-only words, corrupt state and
 *    partial restores are still refused.
 *
 * cc -std=gnu11 -O1 -g -fsanitize=address,undefined -fno-sanitize-recover=all -Icompat \
 *    tools/test-pmgr-ioreport.c compat/device.c compat/mmio.c compat/sep-bootstrap.c \
 *    compat/sep-pnon.c compat/aes.c compat/aic.c compat/dart.c compat/sep-sks-endpoint.c \
 *    compat/sep-xars.c compat/watchdog.c compat/clock.c -o build/test-pmgr-ioreport
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "device.h"
#include "pmgr-ioreport-accesses.h"

static unsigned long checks;
#define CHECK(x) do {checks++;if(!(x)){fprintf(stderr,"line %d: %s\n",__LINE__,#x);exit(1);}} while(0)

/* The built model list of installed-fresh-20261017-v1 (params.models), for the
 * indices the update path reaches. test-profile.py pins the same words. */
static struct device_model models[128];
static struct device_state states[128],saved;
static void define(unsigned i,uint64_t kind,uint64_t base,uint64_t span,uint64_t c0,uint64_t c1,
                   uint64_t c2,uint64_t c3,uint64_t c4)
{
    models[i]=(struct device_model){kind,base,span,{c0,c1,c2,c3,c4}};
}
static void build(void)
{
    define(10,25,0x3003c0000,0x14000,0x10000,0x1a8,0x1b8,8,0xffb80);
    define(70,22,0x30827b000,0x1000,6,0,0,0,0);
    define(71,22,0x3082b4000,0x1000,7,0,0,0,0);
    define(74,26,0x300780000,0x1000,1,0,0,0,0);
    const uint64_t soc[6][2]={{0x30006d000,0x2000},{0x300720000,0x3000},{0x300778000,0x1000},
                              {0x30077c000,0x1000},{0x3007a0000,0x1000},{0x302900000,0x1000}};
    for(unsigned g=0;g<6;g++)define(91+g,34,soc[g][0],soc[g][1],g,0,0,0,0);
    define(97,35,0x210e20000,0x2000,0,0,0,0,0);
    define(98,35,0x211e20000,0x2000,1,0,0,0,0);
    const uint64_t energy[8]={0x210059000,0x210159000,0x210259000,0x210359000,
                              0x211059000,0x211159000,0x210e48000,0x211e48000};
    for(unsigned i=0;i<8;i++)define(99+i,36,energy[i],0x1000,0,0,0,0,0);
    memset(states,0,sizeof(states));
    for(unsigned i=0;i<128;i++)if(models[i].span)
        CHECK(device_model_start(&models[i],&states[i],0,24000000)==DEVICE_OK);
}
static enum device_result rd(unsigned m,unsigned off,unsigned width,uint64_t *v)
{ return device_model_access_state(&models[m],&states[m],off,width,0,v); }
static enum device_result wr(unsigned m,unsigned off,unsigned width,uint64_t v)
{ return device_model_access_state(&models[m],&states[m],off,width,1,&v); }
static uint64_t pattern(unsigned m,unsigned off) { return 0x5a00000000000000ULL|((uint64_t)m<<32)|off*0x10001U; }

/* Per-counter enable (mode 1, enable bit 2) for every sampled slot, then the
 * group's global enable: the state the kernel leaves before IOReport samples. */
static void enable_sampling(void)
{
    for(unsigned g=0;g<6;g++) {
        unsigned m=91+g,bias=g==0 ? 0x800 : 0;
        for(unsigned n=0;n<IOREPORT_ACCESSES;n++) {
            const struct ioreport_access *a=&ioreport_accesses[n];
            if(a->model==m && (a->offset&0x1f)==0x10)CHECK(wr(m,a->offset-0x10,4,5)==DEVICE_OK);
        }
        CHECK(wr(m,bias,4,1)==DEVICE_OK);
    }
}
/* What each access must read: cold, nothing has been programmed. */
static uint64_t cold(const struct ioreport_access *a)
{
    if(a->kind==26)return 15;   /* every cluster, AVE included, is active at reset */
    return 0;
}
int main(void)
{
    unsigned per_kind[64]={0};
    /* 1. Cold: nothing restored, SoC sampling enabled as the kernel leaves it
     * before IOReport runs. Every update-path read is admitted, reads the
     * unprogrammed value and changes nothing. */
    build();
    enable_sampling();
    for(unsigned n=0;n<IOREPORT_ACCESSES;n++) {
        const struct ioreport_access *a=&ioreport_accesses[n];
        CHECK(models[a->model].kind==a->kind);per_kind[a->kind]++;
        memcpy(&saved,&states[a->model],sizeof(saved));uint64_t v=0xdeadbeef;
        enum device_result r=rd(a->model,a->offset,a->width,&v);
        if(r!=DEVICE_OK || v!=cold(a))
            fprintf(stderr,"model %u kind %u +0x%x w%u -> %u value %#llx\n",a->model,a->kind,a->offset,a->width,r,
                    (unsigned long long)v);
        CHECK(r==DEVICE_OK && v==cold(a));
        CHECK(!memcmp(&saved,&states[a->model],sizeof(saved)));
    }
    CHECK(per_kind[34]==1036 && per_kind[22]==150 && per_kind[35]==24 && per_kind[36]==16 &&
          per_kind[25]==6 && per_kind[26]==5);

    /* 2. The kernel's restore writes, then SoC sampling enabled. */
    build();
    for(unsigned n=0;n<IOREPORT_ACCESSES;n++) {
        const struct ioreport_access *a=&ioreport_accesses[n];
        if(a->kind==34 && (a->offset&0x1f)==0x10) {     /* frozen restore, low then high */
            uint64_t v=pattern(a->model,a->offset&~0x1fU);
            CHECK(wr(a->model,a->offset,4,(uint32_t)v)==DEVICE_OK);
            CHECK(wr(a->model,a->offset+4,4,v>>32)==DEVICE_OK);
        }
        if(a->kind==35 || a->kind==36)CHECK(wr(a->model,a->offset,8,pattern(a->model,a->offset))==DEVICE_OK);
    }
    enable_sampling();
    for(unsigned n=0;n<IOREPORT_ACCESSES;n++) {
        const struct ioreport_access *a=&ioreport_accesses[n];
        uint64_t v=0xdeadbeef,want=cold(a);
        if(a->kind==34) {
            uint64_t full=pattern(a->model,a->offset&~0x1fU);
            want=(a->offset&0x1f)==0x14 ? full>>32 : (uint32_t)full;
        }
        if(a->kind==35 || a->kind==36)want=pattern(a->model,a->offset);
        CHECK(rd(a->model,a->offset,a->width,&v)==DEVICE_OK && v==want);
        if(a->kind==34 && (a->offset&0x1f)==0x14) {   /* stock high/low/high */
            uint64_t low=0,high=0;
            CHECK(rd(a->model,a->offset-4,4,&low)==DEVICE_OK && rd(a->model,a->offset,4,&high)==DEVICE_OK);
            CHECK(high==v && (high<<32|low)==pattern(a->model,a->offset&~0x1fU));
        }
    }

    /* 3. Refusals kept, atomically. */
    build();
    for(unsigned n=0;n<IOREPORT_ACCESSES;n++) {
        const struct ioreport_access *a=&ioreport_accesses[n];
        enum device_result want=a->kind==22 ? DEVICE_READ_ONLY : a->kind==25 ? DEVICE_READ_ONLY :
                                a->kind==26 && a->offset>=0xc ? DEVICE_READ_ONLY : DEVICE_OK;
        if(want==DEVICE_OK)continue;
        if(a->kind==22 && (a->offset&0x1f)!=0x10 && (a->offset&0x1f)!=0x14)continue;
        memcpy(&saved,&states[a->model],sizeof(saved));
        CHECK(wr(a->model,a->offset,a->width,1)==want && !memcmp(&saved,&states[a->model],sizeof(saved)));
    }
    /* Corrupt restore bitmaps are still refused on read. */
    states[97].acc_perf.written[1]|=1ULL<<63;uint64_t v=0;
    CHECK(rd(97,0x408,8,&v)==DEVICE_BAD_VALUE);
    states[99].energy_restore.written=4;
    CHECK(rd(99,0,8,&v)==DEVICE_BAD_VALUE);
    /* A frozen, half-restored SoC counter is still refused. */
    build();CHECK(wr(92,0x110,4,7)==DEVICE_OK);
    CHECK(rd(92,0x110,4,&v)==DEVICE_BAD_VALUE && rd(92,0x114,4,&v)==DEVICE_BAD_VALUE);
    /* An offset outside the update path stays unknown. */
    CHECK(rd(74,0x14,4,&v)==DEVICE_UNKNOWN_REGISTER);
    CHECK(rd(10,0x1b50,8,&v)==DEVICE_UNKNOWN_REGISTER);
    printf("PASS: %lu IOReport counter checks over %u update-path accesses\n",checks,IOREPORT_ACCESSES);
    return 0;
}

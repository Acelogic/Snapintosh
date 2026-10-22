/* SPDX-License-Identifier: MIT */
#include "sptm-root.h"
#include "txm.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define BASE 0x100000UL
#define PAGE 0x4000UL
/* Managed frames start after the frame map, one stack page and the TXM arena. */
#define ROOT (BASE+2*PAGE+TXM_ASPACE_SIZE)
/* 304 pages with the 8-page arena; the managed frames keep their count when
 * -DSNAP_TXM_ASPACE_WIDE=1 widens the arena (compat/txm.h). */
#define FIXTURE_PAGES (296u+TXM_ASPACE_PAGES)
static uint8_t bytes[FIXTURE_PAGES*PAGE],saved[sizeof(bytes)];
static struct txm_registry registry,saved_registry;
static struct sptm_shared_registry shared_regions,saved_regions;
static struct sptm_root_state roots;
static unsigned checks,published,flushed,converted,deny_retirement;
static uint64_t deny;
#define CHECK(x) do { checks++;if(!(x)){fprintf(stderr,"FAIL %d: %s\n",__LINE__,#x);exit(1);} } while(0)
static volatile uint8_t *map(void *ctx,uint64_t pa,uint64_t size)
{
    (void)ctx;
    return pa==deny || pa<BASE || pa-BASE>=sizeof(bytes) || size>sizeof(bytes)-(pa-BASE)
        ? NULL : bytes+(pa-BASE);
}
static void publish(void *ctx,uint64_t pa,uint64_t size)
{(void)ctx;(void)pa;(void)size;published++;}
static struct sptm_memory m;
static struct txm_arena arena={BASE+2*PAGE,0xfffffe0100008000UL};
static struct txm_service service={.stacks_pa=BASE+PAGE,.stack_count=1};
static uint8_t *meta(uint64_t pa){return bytes+((pa-BASE)/PAGE)*16;}
static int share(void *ctx,uint64_t pa,uint16_t asid,uint8_t slot)
{
    (void)ctx;struct txm_share_plan plan;
    if(deny_retirement || txm_share_prepare(&m,&arena,&registry,pa,asid,slot,&plan))return 0;
    if(!sptm_root_invalidate(&roots,pa,1))return 0;
    flushed++;txm_share_commit(&m,&registry,&plan);converted++;return 1;
}
static int retire(void *ctx,uint64_t pa,uint8_t slot)
{
    (void)ctx;
    if(deny_retirement)return 0;
    for(unsigned i=0;i<registry.count;i++)
        if(registry.root[i]==pa || (registry.root[i] && registry.shared[i] && registry.asid[i]==slot))return 0;
    if(!sptm_root_invalidate(&roots,pa,1))return 0;
    flushed++;return 1;
}
static int retire_user(void *ctx,uint64_t pa,uint16_t asid)
{
    (void)ctx;
    for(unsigned i=0;i<registry.count;i++)
        if(registry.root[i]==pa || (!registry.shared[i] && registry.asid[i]==asid))return 0;
    if(!sptm_root_invalidate(&roots,pa,1))return 0;
    flushed++;return 1;
}
static void reset(void)
{
    memset(bytes,0,sizeof(bytes));memset(&registry,0,sizeof(registry));memset(&roots,0,sizeof(roots));
    memset(&shared_regions,0,sizeof(shared_regions));
    m=(struct sptm_memory){.frame_map_pa=BASE,.frame_low=BASE,.frame_high=BASE+FIXTURE_PAGES*PAGE,
        .alloc_low=ROOT,.alloc_high=BASE+FIXTURE_PAGES*PAGE,.map=map,.publish=publish,
        .share_user_root=share,.retire_shared_root=retire,.retire_user_root=retire_user,
        .shared_regions=&shared_regions};
    for(uint64_t pa=ROOT;pa<m.alloc_high;pa+=PAGE)meta(pa)[2]=11;
    deny=0;deny_retirement=published=flushed=converted=0;
}
static void create(uint64_t pa,unsigned asid,unsigned fmt,unsigned flags)
{
    CHECK(sptm_mac_retype(&m,pa,11,18,((uint64_t)asid<<32)|((uint64_t)flags<<16)|fmt)==SPTM_OK);
    uint64_t args[8]={service.stacks_pa,asid};
    CHECK(txm_aspace(&m,&service,&arena,&registry,35,args)==SPTM_OK);
}
static void snapshot(void){memcpy(saved,bytes,sizeof(bytes));saved_registry=registry;saved_regions=shared_regions;published=0;}
static void unchanged(void)
{CHECK(!published);CHECK(!memcmp(saved,bytes,sizeof(bytes)));CHECK(!memcmp(&saved_registry,&registry,sizeof(registry)));
 CHECK(!memcmp(&saved_regions,&shared_regions,sizeof(shared_regions)));}
int main(void)
{
    const unsigned formats[]={0,0,1,1,1},flags[]={2,0x22,2,6,0x22};
    for(unsigned f=0;f<5;f++)for(unsigned out=0;out<2;out++) {
        reset();create(ROOT,9,formats[f],flags[f]);
        roots.cache[0]=(struct sptm_root_cached){.root=ROOT,.asid=9,.valid=1};
        uint8_t object[256];memcpy(object,bytes+2*PAGE,256);
        CHECK(sptm_mac_retype(&m,ROOT,18,19,0xfedcba9876543200UL|out)==SPTM_OK);
        CHECK(converted==1 && flushed==1 && roots.invalidations==1 && !roots.cache[0].root && !roots.cache[0].valid);
        const uint8_t expected[16]={0,0,19,0,0,0,0,0,0,0,0,0,(uint8_t)out,0,0,0};
        CHECK(!memcmp(meta(ROOT),expected,16));
        object[0x22]=0;object[0x23]=0;object[0x24]=1;object[0x25]=0;
        CHECK(!memcmp(object,bytes+2*PAGE,256));
        CHECK(registry.root[0]==ROOT && registry.shared[0]==1 && registry.asid[0]==0);
        /* Old ASID is reusable while the shared object is still alive. */
        create(ROOT+PAGE,9,formats[f],flags[f]);
        CHECK(registry.root[1]==ROOT+PAGE && registry.asid[1]==9 && !registry.shared[1]);
        snapshot();CHECK(sptm_mac_retype(&m,ROOT,19,11,0)==SPTM_FRAME_BUSY);unchanged();
        uint64_t args[8]={service.stacks_pa,arena.va};
        CHECK(txm_aspace(&m,&service,&arena,&registry,36,args)==SPTM_OK);
        CHECK(!registry.root[0] && !registry.shared[0]);
        CHECK(sptm_mac_retype(&m,ROOT,19,11,0)==SPTM_OK);
        CHECK(meta(ROOT)[2]==11);
        CHECK(sptm_mac_retype(&m,ROOT+PAGE,18,19,out)==SPTM_OK);
        CHECK(meta(ROOT+PAGE)[8]==0 && registry.shared[1] && registry.asid[1]==0);
    }
    /* Read-only rejection: all six CPU ownership cases, malformed refs,
     * identity mismatch, unavailable object/map, and exhausted shared pool. */
    for(unsigned test=0;test<24;test++) {
        reset();create(ROOT,9,0,2);uint64_t options=0;
        enum sptm_result expected=SPTM_FRAME_BUSY;
        if(test<6)roots.active[test]=ROOT;
        else switch(test) {
        case 6:meta(ROOT)[6]=1;break;
        case 7:meta(ROOT)[7]=1;break;
        case 8:meta(ROOT)[8]=0;expected=SPTM_BAD_TABLE;break;
        case 9:meta(ROOT)[10]=0x10;expected=SPTM_BAD_TABLE;break;
        case 10:meta(ROOT)[0]=1;break;
        case 11:meta(ROOT)[4]=0;expected=SPTM_BAD_TABLE;break;
        case 12:options=2;expected=SPTM_UNSUPPORTED_OPTIONS;break;
        case 13:bytes[ROOT-BASE]=3;expected=SPTM_BAD_TABLE;break;
        case 14:deny=BASE+2*PAGE;break;
        case 15:deny=BASE;expected=SPTM_MEMORY_UNAVAILABLE;break;
        case 16:registry.root[0]=ROOT+PAGE;break;
        case 17:registry.count=0;break;
        case 18:bytes[2*PAGE+0x18]=1;break;
        case 19:bytes[2*PAGE+0x28]=1;break;
        case 20:bytes[2*PAGE+0x48]=1;break;
        case 21:deny_retirement=1;break;
        case 22:m.share_user_root=0;expected=SPTM_BAD_CONFIG;break;
        case 23:
            for(unsigned i=0;i<255;i++){uint64_t pa=ROOT+(i+1)*PAGE;uint8_t *p=meta(pa);p[2]=19;p[8]=i;
                shared_regions.slots[i]=(struct sptm_shared_slot){.state=1,.root=pa};}
            expected=SPTM_MEMORY_UNAVAILABLE;break;
        }
        snapshot();CHECK(sptm_mac_retype(&m,ROOT,18,19,options)==expected);unchanged();CHECK(!converted && !flushed);
    }
    /* Shared metadata references and identity remain protected at teardown. */
    for(unsigned test=0;test<8;test++) {
        reset();create(ROOT,9,0,2);CHECK(!sptm_mac_retype(&m,ROOT,18,19,0));
        uint64_t args[8]={service.stacks_pa,arena.va};CHECK(!txm_aspace(&m,&service,&arena,&registry,36,args));
        enum sptm_result expected=SPTM_FRAME_BUSY;
        switch(test){
        case 0:meta(ROOT)[4]=1;break;case 1:meta(ROOT)[6]=1;break;
        case 2:meta(ROOT)[8]=255;expected=SPTM_BAD_TABLE;break;
        case 3:meta(ROOT)[10]=2;expected=SPTM_BAD_TABLE;break;
        case 4:meta(ROOT+PAGE)[2]=19;meta(ROOT+PAGE)[8]=0;expected=SPTM_BAD_TABLE;break;
        case 5:m.retire_shared_root=0;expected=SPTM_BAD_CONFIG;break;
        case 6:deny_retirement=1;break;case 7:roots.active[5]=ROOT;break;
        }
        snapshot();CHECK(sptm_mac_retype(&m,ROOT,19,11,0)==expected);unchanged();
    }
    reset();create(ROOT,9,0,2);
    /* Invalid software bits survive conversion; no blind page clearing. */
    memset(bytes+(ROOT-BASE),0xa4,PAGE);memcpy(saved,bytes,sizeof(bytes));
    CHECK(!sptm_mac_retype(&m,ROOT,18,19,0));CHECK(!memcmp(saved+(ROOT-BASE),bytes+(ROOT-BASE),PAGE));
    reset();create(ROOT,9,0,2);
    for(unsigned slot=0;slot<12;slot++) {
        uint64_t pa=ROOT+slot*PAGE;
        if(slot)create(pa,9,0,2);
        CHECK(!sptm_mac_retype(&m,pa,18,19,0));CHECK(meta(pa)[8]==slot);
        CHECK(registry.asid[slot]==slot && registry.shared[slot]);
    }
    /* Includes shared slot9 concurrent with a new ordinary ASID9. */
    create(ROOT+12*PAGE,9,0,2);
    CHECK(registry.asid[12]==9 && !registry.shared[12]);
    uint64_t args[8]={service.stacks_pa,arena.va+12*256};
    CHECK(!txm_aspace(&m,&service,&arena,&registry,36,args));
    CHECK(!sptm_mac_retype(&m,ROOT+12*PAGE,18,11,0));
    CHECK(registry.shared[9] && registry.asid[9]==9 && meta(ROOT+9*PAGE)[2]==19);
    /* Nested references prevent shared unregister before any object writes. */
    meta(ROOT)[4]=1;args[1]=arena.va;snapshot();
    CHECK(txm_aspace(&m,&service,&arena,&registry,36,args)==SPTM_FRAME_BUSY);unchanged();
    printf("PASS: %u shared-root lifecycle checks\n",checks);
    return 0;
}

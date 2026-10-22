/* SPDX-License-Identifier: MIT */
/* SNAP_TXN_DIRTY_PUBLISH: transaction-end publication from the root dirty
 * bitmap must leave the bus (PoC) image byte-identical to a clean of every
 * allocated arena line, across noted stores, allocation, pointer ranges,
 * unnoted runtime pages, self-cleaned guard lines and interleaved root
 * installations. The built-in sentinel must catch an unnoted store and never
 * fire on noted, runtime or excluded pages. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../shadow/txn-publish.h"

static unsigned checks;
#define CHECK(x) do {checks++;if(!(x)){fprintf(stderr,"line %d: %s\n",__LINE__,#x);exit(1);}}while(0)
#define PAGES 193u
#define BASE UINT64_C(0xae1400000)
static unsigned char cpu[PAGES*4096],bus[PAGES*4096],reference[PAGES*4096];
static unsigned calls,fail_at,guard_page_mask[PAGES];
static uint64_t addresses[ROOT_PUBLISH_PAGES];
static struct root_publish_state dirty;
static struct txn_publish_stats stats;
static uint64_t random_state=UINT64_C(0x3c6ef372fe94f82b);
static unsigned random32(void)
{
    random_state^=random_state<<13;random_state^=random_state>>7;random_state^=random_state<<17;
    return (unsigned)random_state;
}
static int flush(void *ctx,uint64_t pa)
{
    (void)ctx;
    CHECK(!(pa&4095) && pa>=BASE && pa-BASE<sizeof cpu);
    CHECK(calls<ROOT_PUBLISH_PAGES);addresses[calls++]=pa;
    if(fail_at && calls==fail_at)return 0;
    memcpy(bus+(pa-BASE),cpu+(pa-BASE),4096);
    return 1;
}
static int exclude(void *ctx,uint64_t pa)
{
    (void)ctx;CHECK(!(pa&4095) && pa>=BASE);
    return guard_page_mask[(pa-BASE)/4096];
}
static uint64_t model_hash(uint64_t pa)
{
    CHECK(!(pa&4095) && pa>=BASE && pa-BASE<sizeof cpu);
    uint64_t h=UINT64_C(0xcbf29ce484222325);const unsigned char *p=cpu+(pa-BASE);
    for(unsigned i=0;i<4096;i++) {h^=p[i];h*=UINT64_C(0x100000001b3);}
    return h;
}
/* The monitor's note sites call both root_publish_note and the observer. */
static void note(uint64_t limit,uint64_t pa,uint64_t size)
{
    CHECK(root_publish_note(&dirty,BASE,limit,pa,size));
    txn_publish_observe(&stats,pa,size);
}
static void store(uint64_t limit,unsigned offset,uint64_t value)
{
    uint64_t old;memcpy(&old,cpu+offset,8);
    if(old!=value)note(limit,BASE+offset,8);  /* mem_write notes changed stores */
    memcpy(cpu+offset,&value,8);
}
static void txn(unsigned pages)
{
    calls=0;memcpy(reference,cpu,pages*4096);  /* whole-arena clean */
    uint64_t runtime=stats.runtime,complete=stats.complete;
    CHECK(txn_publish_flush_with(&dirty,&stats,BASE,BASE+(uint64_t)pages*4096,flush,
                                 exclude,0,model_hash));
    CHECK(!memcmp(bus,reference,pages*4096));
    CHECK(stats.complete==complete+1 && !stats.errors && !stats.mismatches);
    CHECK(stats.runtime-runtime==(dirty.always_end-dirty.always_first)/4096);
    for(unsigned w=0;w<ROOT_PUBLISH_PAGES/64;w++)CHECK(!dirty.bitmap[w]);
    for(unsigned n=1;n<calls;n++)CHECK(addresses[n]>addresses[n-1] ||
        /* runtime pages first, then noted pages in ascending order */
        (addresses[n-1]>=dirty.always_first && addresses[n-1]<dirty.always_end));
    for(unsigned n=0;n<calls;n++)for(unsigned k=0;k<n;k++)CHECK(addresses[n]!=addresses[k]);
    if(stats.sentinel) {
        uint64_t s=stats.sentinel;
        CHECK(!(s>=dirty.always_first && s<dirty.always_end) && !guard_page_mask[(s-BASE)/4096]);
        CHECK(s<BASE+(uint64_t)pages*4096 && stats.hash==model_hash(s) && !stats.observed);
    }
}
static void root_install(unsigned pages)
{
    calls=0;memcpy(reference,cpu,pages*4096);
    CHECK(root_publish_flush(&dirty,BASE,BASE+(uint64_t)pages*4096,flush,0));
    CHECK(!memcmp(bus,reference,pages*4096));
}
static void memory_model(void)
{
    memset(&dirty,0,sizeof dirty);memset(&stats,0,sizeof stats);
    unsigned pages=23;
    dirty.always_first=BASE+3*4096;dirty.always_end=BASE+7*4096;
    guard_page_mask[11]=guard_page_mask[12]=1;
    memset(cpu,0xa6,sizeof cpu);memset(bus,0x5c,sizeof bus);
    note(BASE+pages*4096,BASE,pages*4096);txn(pages);
    uint64_t armed=0;
    for(unsigned turn=0;turn<1500;turn++) {
        uint64_t limit=BASE+(uint64_t)pages*4096;
        for(unsigned n=0;n<13;n++) {
            unsigned page=random32()%pages,offset=page*4096+(random32()%512)*8;
            if(guard_page_mask[page] || (BASE+page*4096>=dirty.always_first &&
                                         BASE+page*4096<dirty.always_end))continue;
            store(limit,offset,n%3 ? random32() : 0);
        }
        /* Some turns deliberately store into the armed sentinel (noted). */
        if(stats.sentinel && turn%5==0)
            store(limit,(unsigned)(stats.sentinel-BASE)+8*(random32()%512),random32()|1);
        if(turn%6==0 && pages<PAGES) {
            pages++;limit=BASE+(uint64_t)pages*4096;
            note(limit,limit-4096,4096);memset(cpu+(pages-1)*4096,0,4096);
        } else if(turn%6==3) {
            unsigned page=random32()%pages;
            if(!guard_page_mask[page] && !(BASE+page*4096>=dirty.always_first &&
                                           BASE+page*4096<dirty.always_end)) {
                note(limit,BASE+page*4096,4096);memset(cpu+page*4096,0,4096);
            }
        }
        /* Pointer transaction: the whole mapped (unaligned) range is noted at
         * map time, then written through the pointer before the flush. */
        if(turn%4==1) {
            unsigned off=16*4096+random32()%((pages-17)*4096-8201),length=8201;
            note(limit,BASE+off,length);
            if(turn%8==1)for(unsigned i=0;i<length;i++)cpu[off+i]^=(unsigned char)(i*7+turn);
        }
        /* Unnoted runtime memory (VNCR, stacks, output, secondary records). */
        memset(cpu+3*4096+(turn%4)*4096,(int)(turn&255),512);
        /* Guard descriptor lines: stored and cleaned directly, never noted. */
        unsigned guard=(11+turn%2)*4096+(random32()%64)*64;
        memset(cpu+guard,(int)(0x40+(turn&15)),64);memcpy(bus+guard,cpu+guard,64);
        if(turn%7==6)root_install(pages);
        uint64_t checked=stats.checked,noted=stats.noted;
        txn(pages);armed++;
        CHECK(stats.checked+stats.noted+stats.retired>=checked+noted);
    }
    CHECK(stats.armed==armed+1 && stats.checked>100 && stats.noted>100 && !stats.retired);
    CHECK(stats.published<stats.considered/4);
    /* A flush with nothing noted publishes exactly the runtime pages. */
    uint64_t published=stats.published;txn(pages);CHECK(stats.published==published);
    printf("model: %llu flushes, %llu noted pages published of %llu considered; "
           "%llu sentinels checked, %llu noted\n",(unsigned long long)stats.complete,
           (unsigned long long)stats.published,(unsigned long long)stats.considered,
           (unsigned long long)stats.checked,(unsigned long long)stats.noted);
}
/* Every coverage gap the sentinel can see is reported, terminally, before any
 * cache maintenance, and nothing is repaired or cleared. */
static void sentinel_detects(void)
{
    memset(&dirty,0,sizeof dirty);memset(&stats,0,sizeof stats);
    memset(guard_page_mask,0,sizeof guard_page_mask);
    unsigned pages=40;uint64_t limit=BASE+pages*4096;
    dirty.always_first=BASE;dirty.always_end=BASE+2*4096;
    note(limit,BASE,pages*4096);txn(pages);
    CHECK(stats.sentinel==BASE+2*4096);   /* runtime pages are skipped */
    for(unsigned round=0;round<3*pages;round++) {
        uint64_t s=stats.sentinel;CHECK(s);
        if(round%3==0) {
            /* Unnoted store: a path that bypassed every note site. */
            cpu[s-BASE+8*(round%512)]^=0x80;
            store(limit,(unsigned)((s-BASE+4096)%(pages*4096)),random32());
            uint64_t bits[ROOT_PUBLISH_PAGES/64];memcpy(bits,dirty.bitmap,sizeof bits);
            calls=0;
            CHECK(!txn_publish_flush_with(&dirty,&stats,BASE,limit,flush,exclude,0,model_hash));
            CHECK(!calls && stats.mismatches==1 && stats.errors==1);
            CHECK(!memcmp(bits,dirty.bitmap,sizeof bits));
            /* Latched: no later flush proceeds. */
            CHECK(!txn_publish_flush_with(&dirty,&stats,BASE,limit,flush,exclude,0,model_hash));
            CHECK(!calls);
            /* Reset the model for the next case. */
            cpu[s-BASE+8*(round%512)]^=0x80;stats.errors=stats.mismatches=0;
            note(limit,BASE,pages*4096);stats.sentinel=0;txn(pages);
        } else if(round%3==1) {
            /* A pointer mapped (noted) BEFORE the flush and written after it
             * violates the flush contract: also detected. */
            uint64_t target=stats.sentinel;
            cpu[target-BASE+16]^=1;
            calls=0;
            CHECK(!txn_publish_flush_with(&dirty,&stats,BASE,limit,flush,exclude,0,model_hash));
            CHECK(stats.mismatches==1);
            cpu[target-BASE+16]^=1;stats.errors=stats.mismatches=0;stats.sentinel=0;txn(pages);
        } else {
            /* An identical-value store is not a change and is not noted. */
            uint64_t word;memcpy(&word,cpu+(s-BASE),8);store(limit,(unsigned)(s-BASE),word);
            uint64_t checked=stats.checked;txn(pages);CHECK(stats.checked==checked+1);
        }
    }
    /* Excluded (guard) and runtime pages are never armed, whatever the cursor. */
    memset(&stats,0,sizeof stats);
    for(unsigned p=0;p<pages;p++)guard_page_mask[p]=p%2;
    for(unsigned n=0;n<4*pages;n++) {
        txn(pages);
        CHECK(stats.sentinel && !guard_page_mask[(stats.sentinel-BASE)/4096] &&
              stats.sentinel>=BASE+2*4096);
    }
    /* No eligible page: nothing is armed, flushes still complete. */
    for(unsigned p=0;p<pages;p++)guard_page_mask[p]=1;
    txn(pages);CHECK(!stats.sentinel);txn(pages);
    memset(guard_page_mask,0,sizeof guard_page_mask);
    /* A sentinel beyond a (hypothetically) smaller allocation retires. */
    memset(&stats,0,sizeof stats);stats.cursor=pages-1;txn(pages);
    CHECK(stats.sentinel==BASE+(uint64_t)(pages-1)*4096);
    calls=0;CHECK(txn_publish_flush_with(&dirty,&stats,BASE,BASE+(uint64_t)(pages-1)*4096,
                                         flush,exclude,0,model_hash));
    CHECK(stats.retired==1);
}
static void invalid_and_failure(void)
{
    /* Geometry and runtime range must be valid before any maintenance. */
    const uint64_t bad[][4]={ /* first, allocated, always_first, always_end */
        {BASE+1,BASE+4096,0,0},{BASE,BASE+4095,0,0},{BASE,BASE,0,0},
        {BASE,BASE+(uint64_t)(ROOT_PUBLISH_PAGES+1)*4096,0,0},
        {BASE,BASE+2*4096,BASE+1,BASE+4096},{BASE,BASE+2*4096,BASE,BASE+4097},
        {BASE,BASE+2*4096,BASE+4096,BASE},{BASE,BASE+2*4096,BASE,BASE+3*4096},
        {BASE,BASE+2*4096,0,BASE+4096},{BASE+4096,BASE+3*4096,BASE,BASE+4096}};
    for(unsigned n=0;n<sizeof bad/sizeof bad[0];n++) {
        memset(&dirty,0,sizeof dirty);memset(&stats,0,sizeof stats);calls=0;
        dirty.always_first=bad[n][2];dirty.always_end=bad[n][3];
        CHECK(!txn_publish_flush_with(&dirty,&stats,bad[n][0],bad[n][1],flush,exclude,0,model_hash));
        CHECK(!calls && stats.errors==1 && !stats.complete);
    }
    for(unsigned limit=1;limit<130;limit++) {
        memset(&dirty,0,sizeof dirty);memset(&stats,0,sizeof stats);calls=0;
        dirty.bitmap[limit/64]=UINT64_C(1)<<(limit%64);
        CHECK(!txn_publish_flush_with(&dirty,&stats,BASE,BASE+(uint64_t)limit*4096,
                                      flush,exclude,0,model_hash));
        CHECK(!calls && stats.errors==1 && !stats.complete);
    }
    /* Callback failure retains every bit, latches, and never repairs. */
    memset(&dirty,0,sizeof dirty);memset(&stats,0,sizeof stats);calls=0;fail_at=3;
    dirty.always_first=BASE;dirty.always_end=BASE+4096;
    CHECK(root_publish_note(&dirty,BASE,BASE+4*4096,BASE+4096,3*4096));
    CHECK(!txn_publish_flush_with(&dirty,&stats,BASE,BASE+4*4096,flush,exclude,0,model_hash));
    CHECK(dirty.bitmap[0]==14 && stats.errors==1 && !stats.complete && calls==3);
    fail_at=0;calls=0;
    CHECK(!txn_publish_flush_with(&dirty,&stats,BASE,BASE+4*4096,flush,exclude,0,model_hash));
    CHECK(!calls);
    /* A latched root-publication error also stops transaction publication. */
    memset(&dirty,0,sizeof dirty);memset(&stats,0,sizeof stats);dirty.errors=1;
    CHECK(!txn_publish_flush_with(&dirty,&stats,BASE,BASE+4096,flush,exclude,0,model_hash));
    CHECK(!stats.calls);
    memset(&dirty,0,sizeof dirty);
    CHECK(!txn_publish_flush_with(&dirty,&stats,BASE,BASE+4096,0,exclude,0,model_hash));
    memset(&stats,0,sizeof stats);
    CHECK(!txn_publish_flush_with(&dirty,&stats,BASE,BASE+4096,flush,exclude,0,0));
    /* Root publication counters are never touched by transaction flushes. */
    memset(&dirty,0,sizeof dirty);memset(&stats,0,sizeof stats);
    CHECK(root_publish_note(&dirty,BASE,BASE+8*4096,BASE,8*4096));
    struct root_publish_state before=dirty;
    CHECK(txn_publish_flush_with(&dirty,&stats,BASE,BASE+8*4096,flush,exclude,0,model_hash));
    CHECK(dirty.notes==before.notes && dirty.pages_noted==before.pages_noted &&
          dirty.calls==before.calls && dirty.complete==before.complete &&
          dirty.published==before.published && dirty.considered==before.considered);
    /* The observer tracks exactly the armed page and overlapping spans. */
    memset(&stats,0,sizeof stats);stats.sentinel=BASE+4*4096;
    txn_publish_observe(&stats,BASE+3*4096,4096);CHECK(!stats.observed);
    txn_publish_observe(&stats,BASE+5*4096,8);CHECK(!stats.observed);
    txn_publish_observe(&stats,BASE+4*4096,0);CHECK(!stats.observed);
    txn_publish_observe(&stats,BASE+3*4096+4095,2);CHECK(stats.observed);
    stats.observed=0;txn_publish_observe(&stats,BASE+4*4096+4095,1);CHECK(stats.observed);
    stats.observed=0;txn_publish_observe(&stats,BASE,64*4096);CHECK(stats.observed);
    stats.sentinel=0;stats.observed=0;txn_publish_observe(&stats,BASE,64*4096);CHECK(!stats.observed);
}
int main(void)
{
    memory_model();sentinel_detects();invalid_and_failure();
    printf("transaction publication: %u checks, 0 failures\n",checks);return 0;
}

/* SPDX-License-Identifier: MIT */
#include "txm.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BASE 0x100000UL
#define PAGE 0x4000UL
static unsigned checks, published;
static uint64_t deny, published_pa, published_size;
/* Managed frames end at ARENA_PAGE; the TXM arena sits above them so a
 * full registry has one root frame per slot. */
#define ARENA_PAGE (7+TXM_ASPACE_LIMIT+1)
static uint8_t memory[(ARENA_PAGE+TXM_ASPACE_PAGES) * PAGE], before[sizeof(memory)];
#define CHECK(x) do { checks++; if (!(x)) { fprintf(stderr, "FAIL line %d: %s\n", __LINE__, #x); exit(1); } } while (0)
static volatile uint8_t *map(void *ctx, uint64_t pa, uint64_t size)
{
    (void)ctx;
    if (pa == deny || pa < BASE || pa - BASE >= sizeof(memory) ||
        size > sizeof(memory) - (pa - BASE)) return NULL;
    return memory + (pa - BASE);
}
static void publish(void *ctx, uint64_t pa, uint64_t size)
{
    (void)ctx; published++; published_pa=pa; published_size=size;
}
static uint64_t word(unsigned offset)
{
    uint64_t v; memcpy(&v, memory + offset, 8); return v;
}

static void root_entry(unsigned slot, unsigned asid)
{
    uint8_t *f = memory + 6 * PAGE + (7 + slot) * 16;
    memset(f, 0, 16);
    f[2] = 18; f[4] = asid; f[5] = asid >> 8; f[8] = 0xff; f[10] = 2;
}

static void developer_mode(struct txm_service *s)
{
    struct sptm_memory m = {.map=map, .publish=publish};
    for (unsigned n=0; n<s->stack_count; n++) for (unsigned enable=0; enable<2; enable++) {
        uint64_t args[8] = {s->stacks_pa+n*PAGE, enable};
        memset(memory,0xa5,sizeof(memory)); memcpy(before,memory,sizeof(memory));
        published=0;
        CHECK(txm_developer_mode(&m,s,31,args)==SPTM_OK);
        unsigned start=(unsigned)(args[0]-BASE)+0x3c00;
        CHECK(published==1 && published_pa==args[0]+0x3c00 && published_size==0x50);
        CHECK(word(start+8)==0 && memory[start+0x10]==0 && word(start+0x18)==0);
        for (unsigned i=0;i<6;i++) CHECK(word(start+0x20+8*i)==0);
        /* Only the transport reply changes, never policy or another stack. */
        for (unsigned i=0;i<sizeof(memory);i++) {
            int changed=(i>=start+8 && i<start+16) || i==start+16 ||
                        (i>=start+24 && i<start+80);
            if (!changed && memory[i]!=before[i]) {CHECK(0);}
        }
        CHECK(word(start)==0xa5a5a5a5a5a5a5a5UL);
    }
    for (unsigned n=0;n<20;n++) {
        struct sptm_memory bm=m;struct txm_service bs=*s;
        uint64_t args[8]={s->stacks_pa,1}, selector=31;
        enum sptm_result expected=SPTM_BAD_CONFIG;
        switch(n) {
        case 0:bs.stack_count=0;break;
        case 1:bs.stack_count=257;break;
        case 2:bs.stacks_pa++;break;
        case 3:bs.stacks_pa=UINT64_MAX&~(PAGE-1);break;
        case 4:bm.map=0;break;
        case 5:bm.publish=0;break;
        case 6:args[0]++;expected=SPTM_BAD_ADDRESS;break;
        case 7:args[0]=s->stacks_pa-PAGE;expected=SPTM_BAD_ADDRESS;break;
        case 8:args[0]=s->stacks_pa+s->stack_count*PAGE;expected=SPTM_BAD_ADDRESS;break;
        case 9:args[1]=2;expected=SPTM_UNSUPPORTED_OPTIONS;break;
        case 10:args[1]=UINT64_MAX;expected=SPTM_UNSUPPORTED_OPTIONS;break;
        case 11:selector=32;expected=SPTM_UNSUPPORTED_OPTIONS;break;
        case 12:deny=args[0];expected=SPTM_MEMORY_UNAVAILABLE;break;
        default:args[2+(n-13)%6]=1;expected=SPTM_UNSUPPORTED_OPTIONS;break;
        }
        memcpy(before,memory,sizeof(memory));published=0;
        CHECK(txm_developer_mode(&bm,&bs,selector,args)==expected);
        CHECK(!published && !memcmp(before,memory,sizeof(memory)));deny=0;
    }
    uint64_t args[8]={s->stacks_pa,1};
    CHECK(txm_developer_mode(0,s,31,args)==SPTM_BAD_CONFIG);
    CHECK(txm_developer_mode(&m,0,31,args)==SPTM_BAD_CONFIG);
    CHECK(txm_developer_mode(&m,s,31,0)==SPTM_BAD_CONFIG);
}

static void registration(struct txm_service *s)
{
    struct sptm_memory m = {.frame_map_pa=BASE+6*PAGE, .frame_low=BASE,
        .frame_high=BASE+ARENA_PAGE*PAGE, .alloc_low=BASE+7*PAGE, .alloc_high=BASE+ARENA_PAGE*PAGE,
        .map=map, .publish=publish};
    struct txm_arena a = {BASE+ARENA_PAGE*PAGE, 0xfffffe010008c000UL};
    struct txm_registry r = {0}, saved;
    uint64_t args[8] = {BASE, 1};
    memset(memory, 0, sizeof(memory));
    root_entry(0, 1);
    for (unsigned test = 0; test < 19; test++) {
        struct sptm_memory badm=m; struct txm_arena bada=a;
        struct txm_service bads=*s;
        struct txm_registry badr=r;
        uint64_t badargs[8]; memcpy(badargs, args, sizeof(args));
        enum sptm_result expected=SPTM_BAD_CONFIG;
        switch (test) {
        case 0: badargs[1]=0; expected=SPTM_UNSUPPORTED_OPTIONS; break;
        case 1: badargs[1]=0x10000; expected=SPTM_UNSUPPORTED_OPTIONS; break;
        case 2: badargs[2]=1; expected=SPTM_UNSUPPORTED_OPTIONS; break;
        case 3: badargs[7]=1; expected=SPTM_UNSUPPORTED_OPTIONS; break;
        case 4: badargs[0]++; expected=SPTM_BAD_ADDRESS; break;
        case 5: badargs[0]=s->log_pa; expected=SPTM_BAD_ADDRESS; break;
        case 6: badargs[1]=2; expected=SPTM_TABLE_MISSING; break;
        case 7: badr.count=TXM_ASPACE_LIMIT+1; break;
        case 8: bada.pa=m.alloc_low; break;
        case 9: bada.pa=m.frame_map_pa; break;
        case 10: bada.pa=s->stacks_pa; break;
        case 11: bada.va=UINT64_MAX & ~(PAGE-1); break;
        case 12: badm.frame_map_pa=UINT64_MAX & ~15UL; break;
        case 13: badm.alloc_high=m.frame_high+PAGE; break;
        case 14: bads.stack_count=0; break;
        case 15: deny=a.pa; expected=SPTM_MEMORY_UNAVAILABLE; break;
        case 16: deny=BASE; expected=SPTM_MEMORY_UNAVAILABLE; break;
        case 17: deny=m.frame_map_pa; expected=SPTM_MEMORY_UNAVAILABLE; break;
        case 18: bada.va=s->ro_va; break;
        }
        memcpy(before, memory, sizeof(memory)); saved=badr; published=0;
        CHECK(txm_aspace(&badm, &bads, &bada, &badr, 35, badargs)==expected);
        CHECK(!published && memcmp(before, memory, sizeof(memory))==0);
        CHECK(memcmp(&saved, &badr, sizeof(saved))==0);
        deny=0;
    }
    root_entry(1, 1);
    CHECK(txm_aspace(&m, s, &a, &r, 35, args)==SPTM_FRAME_BUSY);
    memset(memory+6*PAGE+(7+1)*16, 0, 16);
    memory[6*PAGE+7*16+10]=0x10;
    CHECK(txm_aspace(&m, s, &a, &r, 35, args)==SPTM_BAD_TABLE);
    root_entry(0, 1);
    for (unsigned n=0; n<TXM_ASPACE_LIMIT; n++) {
        unsigned id=n==TXM_ASPACE_LIMIT-1 ? 0xffff : n+1;
        root_entry(n, id); args[1]=id;
        /* Address-space registration accepts every modeled root-control
         * combination, including the flags0 constructor used by the shell. */
        const unsigned flags[]={0,1,2,3,8,9,10,11};
        memory[6*PAGE+(7+n)*16+10]=(uint8_t)flags[n%8];
        CHECK(txm_aspace(&m, s, &a, &r, 35, args)==SPTM_OK);
        CHECK(word(0x3c18)==1 && word(0x3c20)==a.va+n*0x100);
        unsigned o=ARENA_PAGE*PAGE+n*0x100;
        CHECK(word(o+0x18)==0 && memory[o+0x22]==(id&255) && memory[o+0x23]==(id>>8));
        CHECK(memory[o+0x24]==0 && word(o+0x38)==a.va+n*0x100+0x80);
        CHECK(r.count==n+1 && r.root[n]==m.alloc_low+n*PAGE && r.asid[n]==id);
        memcpy(before, memory, sizeof(memory)); saved=r; published=0;
        CHECK(txm_aspace(&m, s, &a, &r, 35, args)==SPTM_FRAME_BUSY);
        CHECK(!published && memcmp(before, memory, sizeof(memory))==0);
        CHECK(memcmp(&saved, &r, sizeof(saved))==0);
    }
    args[1]=0x1234;
    CHECK(txm_aspace(&m, s, &a, &r, 35, args)==SPTM_MEMORY_UNAVAILABLE);
    CHECK(!published && memcmp(before, memory, sizeof(memory))==0);
    CHECK(memcmp(&saved, &r, sizeof(saved))==0);
    args[1]=a.va;
    for (unsigned test=0; test<7; test++) {
        uint64_t badargs[8]; memcpy(badargs,args,sizeof(args));
        enum sptm_result expected=SPTM_BAD_ADDRESS;
        switch(test) {
        case 0: badargs[1]++; break;
        case 1: badargs[1]+=TXM_ASPACE_SIZE; break;
        case 2: badargs[1]-=0x100; break;
        case 3: memory[6*PAGE+7*16+10]=0x10; expected=SPTM_BAD_TABLE; break;
        case 4: memory[ARENA_PAGE*PAGE+0x28]=1; expected=SPTM_FRAME_BUSY; break;
        case 5: deny=a.pa; expected=SPTM_MEMORY_UNAVAILABLE; break;
        case 6: badargs[2]=1; expected=SPTM_UNSUPPORTED_OPTIONS; break;
        }
        memcpy(before,memory,sizeof(memory)); saved=r; published=0;
        CHECK(txm_aspace(&m,s,&a,&r,36,badargs)==expected);
        CHECK(!published && memcmp(before,memory,sizeof(memory))==0);
        CHECK(memcmp(&saved,&r,sizeof(saved))==0);
        deny=0; root_entry(0,1); memory[ARENA_PAGE*PAGE+0x28]=0;
    }
    CHECK(txm_aspace(&m,s,&a,&r,36,args)==SPTM_OK);
    CHECK(word(0x3c18)==0 && word(0x3c20)==0 && r.root[0]==0 && r.asid[0]==0);
    for (unsigned n=0;n<0x100;n++) CHECK(memory[ARENA_PAGE*PAGE+n]==0);
    CHECK(txm_aspace(&m,s,&a,&r,36,args)==SPTM_BAD_ADDRESS);
    args[1]=1;
    CHECK(txm_aspace(&m,s,&a,&r,35,args)==SPTM_OK);
    CHECK(word(0x3c20)==a.va && r.count==TXM_ASPACE_LIMIT && r.root[0]==m.alloc_low);
}
static void independent_hierarchy_lifetime(struct txm_service *s)
{
    struct sptm_memory m={.frame_map_pa=BASE+6*PAGE,.frame_low=BASE,
        .frame_high=BASE+ARENA_PAGE*PAGE,.alloc_low=BASE+7*PAGE,.alloc_high=BASE+ARENA_PAGE*PAGE,
        .map=map,.publish=publish};
    struct txm_arena a={BASE+ARENA_PAGE*PAGE,0xfffffe010008c000UL};
    for(unsigned test=0;test<15;test++) {
        memset(memory,0,sizeof(memory));root_entry(0,2);
        if(test==10) memory[6*PAGE+7*16+10]=0x22;
        if(test>=11) memory[6*PAGE+7*16+12]=1;
        if(test==14) memory[6*PAGE+7*16+10]=6;
        struct txm_registry r={0};uint64_t args[8]={BASE,2};
        CHECK(txm_aspace(&m,s,&a,&r,35,args)==SPTM_OK);args[1]=a.va;
        uint64_t tte=(BASE+8*PAGE)|3;memcpy(memory+7*PAGE,&tte,8);
        unsigned rootmeta=6*PAGE+7*16,l2meta=6*PAGE+8*16,l3meta=6*PAGE+9*16;
        memory[rootmeta+6]=1;
        memory[l2meta+2]=20;memory[l2meta+4]=2;memory[l2meta+6]=1;
        if(test>=11) {
            memory[l2meta+4]=1;
            for(unsigned n=1;n<4;n++) {tte=(BASE+8*PAGE+n*0x1000)|3;memcpy(memory+7*PAGE+n*8,&tte,8);}
        }
        /* TXM36 does not consume source PTEs. Even unreadable or invalid
         * hierarchy contents belong to SPTM validation, not this call. */
        switch(test) {
        case 1: memory[l2meta+6]=0;break;
        case 2: memory[l2meta+4]=3;break;
        case 3: memory[rootmeta+6]=0;break;
        case 4: memory[l2meta+8]=1;break;
        case 5: deny=BASE+8*PAGE;break;
        case 6: tte=(BASE+7*PAGE)|3;memcpy(memory+8*PAGE,&tte,8);break;
        case 7: memory[l2meta+2]=23;break;
        case 8: case 9:
            tte=(BASE+9*PAGE)|3;memcpy(memory+8*PAGE,&tte,8);memory[l2meta+8]=1;
            memory[l3meta+2]=20;memory[l3meta+4]=3;memory[l3meta+6]=1;
            if(test==9) memory[9*PAGE]=3;
            break;
        case 12: memory[7*PAGE+24]=0;break;
        case 13: memory[8*PAGE+0x3000]=3;break;
        }
        memcpy(before,memory,sizeof(memory));published=0;
        CHECK(txm_aspace(&m,s,&a,&r,36,args)==SPTM_OK);
        /* Frame map and hierarchy pages are untouched; only the arena object clears. */
        CHECK(!memcmp(before+6*PAGE,memory+6*PAGE,(ARENA_PAGE-6)*PAGE));
        CHECK(!r.root[0] && !r.asid[0]);
        deny=0;
    }
}
int main(void)
{
    struct sptm_memory m = {.map=map, .publish=publish};
    struct txm_service s = {BASE, 2, BASE + 2 * PAGE, 0xfffffe0100080000UL,
        BASE + 3 * PAGE, 0xfffffe0100084000UL, BASE + 4 * PAGE, 0xfffffe0100088000UL};
    uint64_t args[8] = {BASE};
    memset(memory, 0xa5, sizeof(memory));
    memset(memory + 2 * PAGE, 0, PAGE);
    for (unsigned n = 0; n < 2; n++) {
        args[0] = BASE + n * PAGE;
        unsigned o = n * PAGE + 0x3c00;
        CHECK(txm_info(&m, &s, 1, args) == SPTM_OK);
        CHECK(published_pa == args[0] + 0x3c00 && published_size == 0x50);
        CHECK(word(o + 8) == 0 && memory[o + 0x10] == 0);
        CHECK(word(o + 0x18) == 3);
        CHECK(word(o + 0x20) == s.log_va);
        CHECK(word(o + 0x28) == s.log_va + 0x3ff0);
        CHECK(word(o + 0x30) == s.log_va + 0x3ff8);
        CHECK(word(o + 0x38) == 0 && word(o + 0x40) == 0 && word(o + 0x48) == 0);
        CHECK(memory[o] == 0xa5 && memory[o + 0x11] == 0xa5 && memory[o + 0x50] == 0xa5);
        CHECK(word(2 * PAGE + 0x3ff0) == 0 && word(2 * PAGE + 0x3ff8) == 0);
    }
    args[0] = BASE;
    CHECK(txm_info(&m, &s, 2, args) == SPTM_OK);
    CHECK(word(0x3c18) == 6 && word(0x3c20) == s.rw_va);
    CHECK(word(0x3c28) == s.ro_va + 0x3ff0 && word(0x3c48) == s.ro_va);
    CHECK(word(0x3c30) == 0 && word(0x3c38) == 0 && word(0x3c40) == 0);
    CHECK(txm_info(&m, &s, 3, args) == SPTM_OK);
    CHECK(word(0x3c18) == 4 && word(0x3c08) == 0 && memory[0x3c10] == 0);
    for (unsigned n = 0; n < 6; n++) CHECK(word(0x3c20 + 8*n) == 0);
    memcpy(before, memory, sizeof(memory)); published = 0;
    CHECK(txm_info(&m, &s, 4, args) == SPTM_UNSUPPORTED_OPTIONS);
    /* GetTrustCacheInfo accepts no inputs beyond a dedicated stack, and
     * failed queries leave the previous reply and backing state unchanged. */
    for (unsigned n = 1; n < 8; n++) {
        args[n] = 1;
        CHECK(txm_info(&m, &s, 3, args) == SPTM_UNSUPPORTED_OPTIONS);
        args[n] = 0;
    }
    args[0] = s.log_pa;
    CHECK(txm_info(&m, &s, 3, args) == SPTM_BAD_ADDRESS);
    args[0] = BASE; deny = BASE;
    CHECK(txm_info(&m, &s, 3, args) == SPTM_MEMORY_UNAVAILABLE);
    deny = 0;
    deny = s.ro_pa;
    CHECK(txm_info(&m, &s, 2, args) == SPTM_MEMORY_UNAVAILABLE);
    deny = 0;
    struct txm_service alias = s;
    alias.rw_pa = BASE;
    CHECK(txm_info(&m, &alias, 2, args) == SPTM_BAD_CONFIG);
    alias = s; alias.ro_va = UINT64_MAX & ~(PAGE - 1);
    CHECK(txm_info(&m, &alias, 2, args) == SPTM_BAD_CONFIG);
    for (unsigned n = 0; n < 5; n++) {
        uint64_t bad[] = {BASE - PAGE, BASE + 1, BASE + 2 * PAGE, 0, UINT64_MAX};
        args[0] = bad[n];
        CHECK(txm_info(&m, &s, 1, args) == SPTM_BAD_ADDRESS);
    }
    args[0] = BASE;
    for (unsigned n = 1; n < 8; n++) {
        args[n] = 1;
        CHECK(txm_info(&m, &s, 1, args) == SPTM_UNSUPPORTED_OPTIONS);
        args[n] = 0;
    }
    deny = s.log_pa;
    CHECK(txm_info(&m, &s, 1, args) == SPTM_MEMORY_UNAVAILABLE);
    deny = BASE;
    CHECK(txm_info(&m, &s, 1, args) == SPTM_MEMORY_UNAVAILABLE);
    deny = 0;
    struct txm_service bad = s;
    bad.stack_count = 0;
    CHECK(txm_info(&m, &bad, 1, args) == SPTM_BAD_CONFIG);
    bad = s; bad.log_pa = BASE;
    CHECK(txm_info(&m, &bad, 1, args) == SPTM_BAD_CONFIG);
    bad = s; bad.stacks_pa = UINT64_MAX & ~(PAGE - 1);
    CHECK(txm_info(&m, &bad, 1, args) == SPTM_BAD_CONFIG);
    bad = s; bad.log_va = UINT64_MAX & ~(PAGE - 1);
    CHECK(txm_info(&m, &bad, 1, args) == SPTM_BAD_CONFIG);
    CHECK(txm_info(NULL, &s, 1, args) == SPTM_BAD_CONFIG);
    CHECK(txm_info(&m, NULL, 1, args) == SPTM_BAD_CONFIG);
    CHECK(txm_info(&m, &s, 1, NULL) == SPTM_BAD_CONFIG);
    CHECK(published == 0 && memcmp(before, memory, sizeof(memory)) == 0);
    registration(&s);
    independent_hierarchy_lifetime(&s);
    developer_mode(&s);
    printf("PASS: %u TXM transport and registration checks\n", checks);
}

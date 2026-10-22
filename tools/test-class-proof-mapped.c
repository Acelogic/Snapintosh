/* SPDX-License-Identifier: MIT */
/* SNAP_CLASS_PROOF_MAPPED: a class-proof full walk through one bounded mapping
 * per table (with eight-word zero groups) must leave the ENTIRE proof state
 * byte-identical to the original per-word walk after every operation: return
 * value, totals, bitmap, tracked pages, counters, epoch and validity, for valid
 * trees, every rejected descriptor form, cycles, count limits, read failures
 * and sampled verification. Neither walk may write table memory. */
#define main baseline_view_tests
#include "test-sprr-view.c"
#undef main
#include "sprr-class-proof.h"
#include "sprr-class-leaf-memo.h"

static struct sprr_class_proof ref,mapped;
static struct sprr_class_walk_stats wstats;
static unsigned map_calls;
/* The monitor's word reader (kernel_table_read) accepts or refuses every word
 * of a page-aligned table alike: its only failure is the allocation bound.
 * Model that: an injected failure word refuses its whole page. The mapped
 * equivalence depends on exactly this page-uniform verdict. */
static int prd(void *ctx,uint64_t pa,uint64_t *out)
{
    if(read_fail && (pa&~UINT64_C(4095))==(read_fail&~UINT64_C(4095)))return -1;
    return rd(ctx,pa,out);
}
/* rd()'s bounds and failure word applied to a whole page. */
static const volatile uint64_t *map_read(void *ctx,uint64_t pa)
{
    (void)ctx;map_calls++;
    if((pa&4095) || pa<BASE || pa>BASE+BYTES-4096)return 0;
    if(read_fail>=pa && read_fail<pa+4096)return 0;
    return (const volatile uint64_t *)(void *)(ram+(pa-BASE));
}
static uint64_t random_state=UINT64_C(0xbb67ae8584caa73b);
static unsigned rnd(unsigned n)
{
    random_state^=random_state<<13;random_state^=random_state>>7;random_state^=random_state<<17;
    return (unsigned)(random_state%n);
}
static int both(struct shadow *s,uint64_t forbidden,uint64_t first,uint64_t limit)
{
    struct sprr_view_classes a={1,2,3},b={1,2,3};
    memcpy(before,ram,sizeof ram);unsigned saved=writes;
    int r=sprr_class_proof_check(&ref,s,forbidden,first,limit,&a);
    int m=sprr_class_proof_check_with(&mapped,s,forbidden,first,limit,&b,map_read,0,&wstats);
    CHECK(r==m);CHECK(!memcmp(&a,&b,sizeof a));
    CHECK(!memcmp(&ref,&mapped,sizeof ref));
    CHECK(saved==writes && !memcmp(before,ram,sizeof ram));
    return r;
}
static int check2(struct shadow *s){return both(s,1UL<<9,BASE,BASE+BYTES);}
static void note2(uint64_t pa){sprr_class_proof_note(&ref,pa);sprr_class_proof_note(&mapped,pa);}
static void forget2(void){sprr_class_proof_forget(&ref);sprr_class_proof_forget(&mapped);}
static void change(uint64_t pa,uint64_t word)
{
    uint64_t old;CHECK(!rd(0,pa,&old));if(old!=word)note2(pa);CHECK(!wr(0,pa,word));
}
/* Random canonical kernel-like tree: up to 48 tables with table, leaf, block,
 * zero, invalid, forbidden-class and cyclic descriptors. */
static uint64_t random_leaf(unsigned level)
{
    uint64_t size=level==3 ? 4096 : level==2 ? 0x200000 : 0x40000000;
    uint64_t oa=DATA+size*(1+rnd(8)),d=oa|ATTR;
    d|=level==3 ? 3 : 1;
    switch(rnd(8)) {
    case 0:d|=PT_UXN;break;                 /* selector2 */
    case 1:d|=PT_PXN|PT_UXN;break;          /* fixed RO */
    case 2:d|=PT_PXN|(2UL<<6);break;        /* class9: forbidden */
    case 3:d|=PT_PXN|PT_UXN|(1UL<<6);break;
    case 4:d+=4096;break;                    /* misaligned block/leaf OA */
    default:d|=PT_PXN;break;
    }
    return d;
}
static uint64_t valid_leaf(unsigned level)
{
    uint64_t size=level==3 ? 4096 : 0x200000;
    uint64_t d=(DATA+size*(1+rnd(8)))|ATTR|(level==3 ? 3 : 1);
    return d|(rnd(2) ? PT_UXN : PT_PXN|PT_UXN);   /* selector2 or fixed */
}
/* Random well-formed tree (levels 0..3, blocks at L2, sparse L3 leaves) with,
 * one time in three, a single injected defect anywhere in it. */
static void random_tree(unsigned tables)
{
    memset(ram,0,sizeof ram);
    unsigned level_of[48]={0},used=1;
    for(unsigned t=1;t<tables;t++) {
        unsigned parent=rnd(t);if(level_of[parent]==3)parent=0;
        level_of[t]=level_of[parent]+1;used++;
        unsigned index=parent==0 ? rnd(256) : rnd(512);
        CHECK(!wr(0,BASE+4096UL*parent+8UL*index,BASE+4096UL*t+3));
    }
    for(unsigned t=0;t<used;t++) {
        if(level_of[t]<2)continue;
        for(unsigned e=0;e<1+rnd(40);e++) {
            unsigned index=rnd(512);uint64_t at=BASE+4096UL*t+8UL*index,old;
            CHECK(!rd(0,at,&old));if(old)continue;
            CHECK(!wr(0,at,valid_leaf(level_of[t])));
        }
    }
    if(rnd(3))return;
    unsigned t=rnd(used),index=rnd(512);uint64_t d;
    switch(rnd(7)) {
    case 0:d=random_leaf(level_of[t]<3 ? level_of[t] : 3)|PT_PXN|(2UL<<6);break; /* class9 */
    case 1:d=2;break;                                   /* invalid */
    case 2:d=BASE+4096UL*rnd(used)+3;break;             /* alias or cycle */
    case 3:d=BASE+BYTES+3;break;                        /* outside the arena */
    case 4:d=BASE+4096UL*rnd(used)+3+(1UL<<52);break;   /* table with attributes */
    case 5:d=random_leaf(level_of[t]);break;            /* possibly misaligned */
    default:d=valid_leaf(3);break;                      /* leaf at the wrong level */
    }
    CHECK(!wr(0,BASE+4096UL*t+8UL*index,d));
}
/* Failure inventory: docs/CLASS-LEAF-MEMO-20260926.md. This is a differential
 * mutation replay against the original word walker, not a second expected-value
 * implementation of the candidate. The monitor does not enable it yet. */
static struct sprr_table_memo leaf_generations;
static struct sprr_class_leaf_cache leaf_cache;
static void leaf_init(struct shadow *s)
{
    setup(s);s->read=prd;
    memset(&leaf_generations,0,sizeof leaf_generations);
    memset(&leaf_cache,0,sizeof leaf_cache);
    leaf_generations.base=BASE;leaf_generations.pages=BYTES/4096;
    for(unsigned i=0;i<BYTES/4096;i++)
        sprr_table_memo_alloc(&leaf_generations,BASE+4096UL*i);
}
static void leaf_change(uint64_t pa,uint64_t word)
{
    sprr_table_memo_note(&leaf_generations,pa);CHECK(!wr(0,pa,word));
}
static int leaf_both(struct shadow *s,uint64_t forbidden)
{
    struct sprr_view_classes a={11,22,33},b=a;
    struct sprr_class_walk_stats walk={0};
    memcpy(before,ram,sizeof ram);unsigned saved=writes;
    int r=sprr_views_check_classes(s,forbidden,&a);
    int m=sprr_class_leaf_check(&leaf_cache,s,forbidden,&leaf_generations,
                              &b,map_read,&walk);
    CHECK(r==m);CHECK(!memcmp(&a,&b,sizeof a));
    CHECK(saved==writes && !memcmp(before,ram,sizeof ram));
    return r;
}
static void leaf_replay(void)
{
    struct shadow s;leaf_init(&s);
    CHECK(leaf_both(&s,1UL<<9));CHECK(leaf_cache.stats.scans==2);
    CHECK(leaf_both(&s,1UL<<9));CHECK(leaf_cache.stats.hits==2);
    uint64_t scans=leaf_cache.stats.scans;
    for(unsigned n=0;n<60;n++)CHECK(leaf_both(&s,1UL<<9));
    CHECK(leaf_cache.stats.scans==scans);
    /* A noted write invalidates exactly that leaf, while its peer still hits. */
    leaf_change(BASE+0x3000+32,DATA+0x4000+3+ATTR+PT_PXN+PT_UXN);
    CHECK(leaf_both(&s,1UL<<9));CHECK(leaf_cache.stats.scans==scans+1);
    CHECK(leaf_both(&s,1UL<<9));CHECK(leaf_cache.stats.verified>=2);
    /* Policy is checked against every hit; no policy-specific success token. */
    CHECK(!leaf_both(&s,1UL<<3));CHECK(leaf_both(&s,0));
    for(unsigned bit=0;bit<16;bit++)leaf_both(&s,1UL<<bit);
    CHECK(!leaf_both(&s,0xffff));
    leaf_change(BASE+0x2000,0);CHECK(leaf_both(&s,0));
    leaf_change(BASE+0x3000,DATA+3+ATTR+PT_PXN+(2UL<<6));
    leaf_change(BASE+0x2000,BASE+0x3000+3);CHECK(!leaf_both(&s,1UL<<9));
    CHECK(leaf_both(&s,0));
    /* Allocator reuse, zeroing, and a transaction's pre-store note. */
    sprr_table_memo_alloc(&leaf_generations,BASE+0x3000);
    memset(ram+0x3000,0,4096);CHECK(leaf_both(&s,1UL<<9));
    sprr_table_memo_note(&leaf_generations,BASE+0x4000);
    put(BASE+0x4000,0,2);CHECK(!leaf_both(&s,0));
    leaf_change(BASE+0x4000,DATA+3+ATTR+PT_PXN+PT_UXN);CHECK(leaf_both(&s,0));
    /* Cached mappings still invoke the page reader and preserve its refusal. */
    read_fail=BASE+0x4000+4088;CHECK(!leaf_both(&s,0));read_fail=0;
    CHECK(leaf_both(&s,0));
    /* Reinterpret an old leaf as an L2 table: its L3 summary cannot be used. */
    leaf_change(BASE+0x1000,BASE+0x4000+3);CHECK(!leaf_both(&s,0));
    leaf_change(BASE+0x1000,BASE+0x2000+3);CHECK(leaf_both(&s,0));
    /* Aliases retain traversal counts; cycles and the root upper half refuse. */
    leaf_change(BASE+0x2000+16,BASE+0x4000+3);CHECK(leaf_both(&s,0));
    leaf_change(BASE+0x1000+8,BASE+3);CHECK(!leaf_both(&s,0));
    leaf_change(BASE+0x1000+8,0);
    leaf_change(BASE+0x800,BASE+0x1000+3);CHECK(!leaf_both(&s,0));
    leaf_change(BASE+0x800,0);CHECK(leaf_both(&s,0));
    /* No allocator eligibility, bad/saturated generation records: full walk. */
    leaf_generations.page[4]&=~SPRR_TABLE_MEMO_POOL;
    put(BASE+0x4000,0,2);CHECK(!leaf_both(&s,0));
    sprr_table_memo_alloc(&leaf_generations,BASE+0x4000);
    put(BASE+0x4000,0,DATA+3+ATTR+PT_PXN+PT_UXN);CHECK(leaf_both(&s,0));
    leaf_generations.stats.errors=1;put(BASE+0x4000,0,2);CHECK(!leaf_both(&s,0));
    leaf_generations.stats.errors=0;sprr_table_memo_note(&leaf_generations,BASE+0x4000);
    put(BASE+0x4000,0,DATA+3+ATTR+PT_PXN+PT_UXN);CHECK(leaf_both(&s,0));
    leaf_generations.clock=SPRR_TABLE_MEMO_CLOCK_MAX;
    put(BASE+0x4000,0,2);CHECK(!leaf_both(&s,0));
    /* Arena identity and generation restart cannot retain old claims. */
    leaf_init(&s);CHECK(leaf_both(&s,0));
    leaf_generations.base-=4096;leaf_generations.pages++;
    CHECK(leaf_both(&s,0));CHECK(leaf_cache.stats.resets>=2);
    leaf_generations.base=BASE;leaf_generations.pages=BYTES/4096;
    CHECK(leaf_both(&s,0));
    leaf_generations.clock--;put(BASE+0x3000,0,2);CHECK(!leaf_both(&s,0));
    /* Sampled missed-note detection must refuse and stay disabled. */
    leaf_init(&s);CHECK(leaf_both(&s,0));leaf_cache.stats.calls=63;
    put(BASE+0x3000,0,0);CHECK(!sprr_class_leaf_check(&leaf_cache,&s,0,
        &leaf_generations,&(struct sprr_view_classes){0},map_read,
        &(struct sprr_class_walk_stats){0}));
    CHECK(leaf_cache.stats.mismatches==1 && leaf_cache.stats.poisoned);
    CHECK(!sprr_class_leaf_check(&leaf_cache,&s,0,&leaf_generations,
        &(struct sprr_view_classes){0},map_read,&(struct sprr_class_walk_stats){0}));
    /* Random structural and content mutations, including reuse and failures. */
    leaf_init(&s);unsigned accepted=0,rejected=0;
    for(unsigned round=0;round<1600;round++) {
        if(!(round%20)) {
            for(unsigned t=0;t<48;t++)sprr_table_memo_alloc(&leaf_generations,BASE+4096UL*t);
            random_tree(4+rnd(44));
        }
        uint64_t pa=BASE+4096UL*rnd(48)+8UL*rnd(512),word;
        CHECK(!rd(0,pa,&word));
        if(!rnd(3))leaf_change(pa,rnd(3) ? valid_leaf(3) : random_leaf(3));
        if(!rnd(8))read_fail=BASE+4096UL*rnd(48)+8UL*rnd(512);
        if(leaf_both(&s,round%7 ? 1UL<<9 : 0))accepted++;else rejected++;
        read_fail=0;
    }
    CHECK(accepted>100 && rejected>100 && !leaf_cache.stats.mismatches);
    printf("class leaf memo replay: %u accepted, %u rejected; %llu hits, %llu scans, %llu verified\n",
        accepted,rejected,(unsigned long long)leaf_cache.stats.hits,
        (unsigned long long)leaf_cache.stats.scans,(unsigned long long)leaf_cache.stats.verified);
    /* Repeated sparse updates of a 256-leaf tree: fixed work, full oracle on
     * every transaction, with all summaries rechecked every64th transaction. */
    leaf_init(&s);memset(ram,0,sizeof ram);
    put(BASE,0,BASE+0x1000+3);put(BASE+0x1000,0,BASE+0x2000+3);
    for(unsigned t=0;t<256;t++) {
        put(BASE+0x2000,t,BASE+0x3000+4096UL*t+3);
        put(BASE+0x3000+4096UL*t,0,DATA+4096UL*t+3+ATTR+PT_PXN+PT_UXN);
    }
    CHECK(leaf_both(&s,1UL<<9));
    for(unsigned n=0;n<128;n++) {
        leaf_change(BASE+0x3000+4096UL*(n%256)+8,
                    DATA+4096UL*(n+256)+3+ATTR+PT_PXN+PT_UXN);
        CHECK(leaf_both(&s,1UL<<9));
    }
    CHECK(leaf_cache.stats.verified==510 && leaf_cache.stats.scans==894);
    CHECK(!leaf_cache.stats.mismatches && !leaf_cache.stats.poisoned);
    printf("class leaf sparse replay: 129 transactions, 33024 reference leaf scans, %llu candidate scans, %llu verified claims\n",
        (unsigned long long)leaf_cache.stats.scans,(unsigned long long)leaf_cache.stats.verified);
    /* Traversal-count overflow still refuses even with shared cached leaves. */
    leaf_init(&s);memset(ram,0,sizeof ram);
    for(unsigned i=0;i<256;i++)put(BASE,i,BASE+0x1000+3);
    for(unsigned i=0;i<40;i++)put(BASE+0x1000,i,BASE+0x2000+3);
    put(BASE+0x2000,0,BASE+0x3000+3);CHECK(!leaf_both(&s,0));
    s.txsz=16;CHECK(!leaf_both(&s,0));s.txsz=17;CHECK(!leaf_both(&s,1UL<<16));
}
static struct sprr_class_proof whole_reference,whole_candidate;
static int whole_both(struct shadow *s,uint64_t forbidden)
{
    struct sprr_view_classes a={11,22,33},b=a;
    struct sprr_class_walk_stats walk={0};
    memcpy(before,ram,sizeof ram);unsigned saved=writes;
    int r=sprr_class_proof_check(&whole_reference,s,forbidden,BASE,BASE+BYTES,&a);
    int m=sprr_class_proof_check_leaf(&whole_candidate,s,forbidden,BASE,BASE+BYTES,
        &b,map_read,0,&walk,&leaf_cache,&leaf_generations);
    CHECK(r==m);CHECK(!memcmp(&a,&b,sizeof a));
    CHECK(!memcmp(&whole_reference,&whole_candidate,sizeof whole_reference));
    CHECK(saved==writes && !memcmp(before,ram,sizeof ram));
    return r;
}
static void whole_change(uint64_t pa,uint64_t word)
{
    sprr_class_proof_note(&whole_reference,pa);
    sprr_class_proof_note(&whole_candidate,pa);leaf_change(pa,word);
}
static void whole_forget(void)
{
    sprr_class_proof_forget(&whole_reference);sprr_class_proof_forget(&whole_candidate);
}
static void leaf_whole_replay(void)
{
    struct shadow s;leaf_init(&s);
    CHECK(whole_both(&s,1UL<<9));
    for(unsigned n=0;n<130;n++)CHECK(whole_both(&s,1UL<<9));
    CHECK(whole_candidate.verified==2 && whole_candidate.tracked_pages==5);
    /* A full re-proof reuses leaves but must restore every coverage bit. */
    whole_forget();CHECK(whole_both(&s,1UL<<9));
    CHECK(whole_candidate.tracked_pages==5);
    whole_change(BASE+0x2000,0);CHECK(whole_both(&s,0));
    whole_change(BASE+0x3000,DATA+3+ATTR+PT_PXN+(2UL<<6));
    whole_change(BASE+0x2000,BASE+0x3000+3);CHECK(!whole_both(&s,1UL<<9));
    CHECK(whole_both(&s,0));
    /* Model a direct writable mapping and an allocator-issued zeroed page. */
    whole_forget();sprr_table_memo_note(&leaf_generations,BASE+0x3000);
    put(BASE+0x3000,0,DATA+3+ATTR+PT_PXN+PT_UXN);CHECK(whole_both(&s,1UL<<9));
    sprr_class_proof_note(&whole_reference,BASE+0x4000);
    sprr_class_proof_note(&whole_candidate,BASE+0x4000);
    sprr_table_memo_alloc(&leaf_generations,BASE+0x4000);
    memset(ram+0x4000,0,4096);CHECK(whole_both(&s,1UL<<9));
    unsigned accepted=0,rejected=0;
    for(unsigned round=0;round<1600;round++) {
        if(!(round%40)) {
            whole_forget();
            for(unsigned t=0;t<48;t++)sprr_table_memo_alloc(&leaf_generations,BASE+4096UL*t);
            random_tree(4+rnd(44));
        }
        uint64_t pa=BASE+4096UL*rnd(48)+8UL*rnd(512),word;CHECK(!rd(0,pa,&word));
        if(!rnd(3))whole_change(pa,rnd(3) ? valid_leaf(3) : random_leaf(3));
        if(!rnd(16)) {whole_forget();read_fail=BASE+4096UL*rnd(48);}
        if(whole_both(&s,round%7 ? 1UL<<9 : 0))accepted++;else rejected++;
        read_fail=0;
    }
    CHECK(accepted>100 && rejected>100);
    /* Even an otherwise valid whole-proof hit cannot conceal a poisoned leaf cache. */
    leaf_init(&s);memset(&whole_reference,0,sizeof whole_reference);
    memset(&whole_candidate,0,sizeof whole_candidate);CHECK(whole_both(&s,0));
    leaf_cache.stats.poisoned=1;
    CHECK(!sprr_class_proof_check_leaf(&whole_candidate,&s,0,BASE,BASE+BYTES,
        &(struct sprr_view_classes){0},map_read,0,&(struct sprr_class_walk_stats){0},
        &leaf_cache,&leaf_generations));
    CHECK(!whole_candidate.valid);
    printf("whole class leaf replay: %u accepted, %u rejected; all proof state and coverage matched\n",
        accepted,rejected);
}
int main(void)
{
    CHECK(!baseline_view_tests());
    struct shadow s;setup(&s);s.read=prd;
    CHECK(!((uintptr_t)ram&7));
    CHECK(check2(&s));CHECK(ref.walks==1 && ref.tracked_pages==5);
    for(unsigned n=0;n<200;n++)CHECK(check2(&s));
    CHECK(ref.verified==3 && wstats.tables==5);
    /* Every descriptor of every covered page: invalidate, re-prove. */
    for(unsigned page=0;page<5;page++)for(unsigned i=0;i<512;i+=3) {
        uint64_t pa=BASE+page*4096UL+i*8UL,old;CHECK(!rd(0,pa,&old));
        change(pa,old^4);check2(&s);change(pa,old);CHECK(check2(&s));
    }
    /* New/detached branches, forbidden classes, zeroing, pointer forgets. */
    change(BASE+0x5000,DATA+3+ATTR+PT_PXN+PT_UXN);change(BASE+0x2000+16,BASE+0x5000+3);
    CHECK(check2(&s) && ref.tracked_pages==6);
    change(BASE+0x5000,DATA+3+ATTR+PT_PXN+(2UL<<6));CHECK(!check2(&s));
    change(BASE+0x5000,DATA+3+ATTR+PT_PXN+PT_UXN);CHECK(check2(&s));
    change(BASE+0x2000+16,0);CHECK(check2(&s) && ref.tracked_pages==5);
    note2(BASE+0x4000);memset(ram+0x4000,0,4096);CHECK(check2(&s));
    forget2();put(BASE+0x3000,0,DATA+3+ATTR+PT_PXN+(2UL<<6));CHECK(!check2(&s));
    put(BASE+0x3000,0,DATA+3+ATTR+PT_PXN+PT_UXN);CHECK(check2(&s));
    /* Roots, policies and arena bounds, including rejected configurations. */
    s.root=BASE+0x6000;CHECK(check2(&s));s.root=BASE;CHECK(check2(&s));
    CHECK(!both(&s,1UL<<3,BASE,BASE+BYTES));CHECK(check2(&s));
    CHECK(both(&s,0,BASE,BASE+BYTES-4096));CHECK(check2(&s));
    CHECK(!both(&s,1UL<<16,BASE,BASE+BYTES));CHECK(!both(&s,0,BASE+4096,BASE+BYTES));
    CHECK(!both(&s,0,BASE,BASE+BYTES+1));
    /* A root inside the arena but whose children lie beyond the proof limit. */
    CHECK(!both(&s,1UL<<9,BASE,BASE+0x3000));CHECK(check2(&s));
    s.txsz=16;CHECK(!check2(&s));s.txsz=17;CHECK(check2(&s));
    /* Read failures on the first, a middle and the last word of a table. */
    const uint64_t fails[]={BASE+0x3000,BASE+0x3000+2048,BASE+0x3000+4088,BASE+4088,BASE+0x2000+8};
    for(unsigned n=0;n<5;n++) {
        forget2();read_fail=fails[n];CHECK(!check2(&s));read_fail=0;CHECK(check2(&s));
    }
    /* Sampled verification: missed notification and missing coverage. */
    ref.hits=mapped.hits=63;put(BASE+0x3000,1,DATA+4096+3+ATTR+PT_PXN+(2UL<<6));
    CHECK(!check2(&s) && ref.mismatches==1);
    put(BASE+0x3000,1,DATA+4096+3+ATTR+PT_PXN+PT_UXN);CHECK(check2(&s));
    ref.hits=mapped.hits=127;ref.bitmap[0]&=~(1UL<<4);mapped.bitmap[0]&=~(1UL<<4);
    CHECK(!check2(&s) && ref.mismatches==2);CHECK(check2(&s));
    /* Aliases, blocks, cycles, upper-half root entries. */
    change(BASE+0x2000+16,BASE+0x3000+3);CHECK(check2(&s) && ref.result.tables==6);
    change(BASE+0x2000+24,DATA+1+ATTR+PT_PXN+PT_UXN);check2(&s);
    change(BASE+0x1000+8,BASE+3);CHECK(!check2(&s));change(BASE+0x1000+8,0);check2(&s);
    change(BASE+0x800,BASE+0x1000+3);CHECK(!check2(&s));change(BASE+0x800,0);check2(&s);
    /* The 8192-table limit, reached through a wide fan-out of one shared L3. */
    memset(ram,0,sizeof ram);
    for(unsigned i=0;i<256;i++)put(BASE,i,BASE+0x1000+3);
    for(unsigned i=0;i<40;i++)put(BASE+0x1000,i,BASE+0x2000+3);
    put(BASE+0x2000,0,BASE+0x3000+3);
    forget2();CHECK(!check2(&s));
    for(unsigned i=0;i<256;i++)put(BASE,i,i<8 ? BASE+0x1000+3 : 0);
    forget2();CHECK(check2(&s) && ref.result.tables>=8*40*2);
    /* Random trees, random notes and forgets, random failing words. */
    unsigned accepted=0,rejected=0;
    for(unsigned round=0;round<4000;round++) {
        if(round%20==0) {random_tree(4+rnd(44));forget2();}
        switch(rnd(6)) {
        case 0:forget2();break;
        case 1:{uint64_t pa=BASE+4096UL*rnd(48)+8UL*rnd(512);uint64_t w;
                CHECK(!rd(0,pa,&w));change(pa,rnd(4) ? w : rnd(2) ? valid_leaf(3) : random_leaf(3));}break;
        case 2:if(!rnd(4)) {read_fail=BASE+4096UL*rnd(48)+8UL*rnd(512);forget2();}break;
        case 3:if(!rnd(8)) {ref.hits|=63;mapped.hits|=63;}break;
        default:break;
        }
        if(both(&s,1UL<<9,BASE,BASE+BYTES))accepted++;else rejected++;
        read_fail=0;
    }
    CHECK(accepted>200 && rejected>200);
    CHECK(wstats.groups>wstats.tables*16 && wstats.empty_groups>wstats.groups/2);
    printf("mapped class walk: %llu tables, %llu of %llu groups empty; %u accepted, %u rejected\n",
           (unsigned long long)wstats.tables,(unsigned long long)wstats.empty_groups,
           (unsigned long long)wstats.groups,accepted,rejected);
    /* Direct API: bad inputs refuse, a NULL walk refuses without state. */
    struct sprr_view_classes out;struct sprr_class_walk_stats k={0};
    CHECK(!sprr_views_check_classes_mapped(0,0,&out,map_read,&k));
    CHECK(!sprr_views_check_classes_mapped(&s,0,&out,0,&k));
    CHECK(!sprr_views_check_classes_mapped(&s,0,0,map_read,&k));
    CHECK(!sprr_views_check_classes_mapped(&s,0,&out,map_read,0));
    CHECK(!sprr_views_check_classes_mapped(&s,1UL<<16,&out,map_read,&k));
    CHECK(!k.tables);
    CHECK(!sprr_class_proof_check_with(&mapped,&s,1UL<<9,BASE,BASE+BYTES,&out,map_read,0,0) ||
          mapped.valid);
    leaf_replay();
    leaf_whole_replay();
    printf("mapped class proof: %u checks, %u failures\n",checks,failed);
    return failed ? 1 : 0;
}

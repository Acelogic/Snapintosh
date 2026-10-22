/* SPDX-License-Identifier: MIT */
/* SNAP_KERNEL_PPERM_FAST (shadow/sprr-class-fast.h): host differential and
 * fault replay of the incremental kernel class proof.
 *
 * Failure inventory: the header's modes 1-9, each held to a check here.
 *  A. Differential (modes 1-4, 6, 7, 9). Random kernel-like trees and random
 *     mutations, every store made through a model of one of the monitor's
 *     paths: mem_write (table memo, then class proof, then the store),
 *     table_alloc_owned (both notes, then zeroing), an SPTM transaction
 *     (class-proof forget, sptm_shadow_map's per-page memo note, pointer
 *     stores) and directly carved storage (never allocator-issued; its stores
 *     may bypass the table memo). After EVERY proof the verdict, the output
 *     and the whole proof state (counters, epoch, validity, bitmap, result)
 *     must equal both the production proof (mapped misses, word-verified
 *     hits) and the original word proof, and no table byte may change.
 *  B. Faults (modes 1, 5). A store the table memo missed is found by the
 *     first sampled leaf rescan, at most 64 incremental walks later, and the
 *     poisoned cache then refuses everything, hits included. A store both
 *     witnesses missed, and a coverage-only swap to an untracked page, are
 *     refused at the same 64th hit as the production proof, state equal.
 *  C. The refusing mapping on its own (mode 5).
 *  --bench (built without sanitizers): one ~5,200-table tree shaped like the
 *     v33/v34 canonical kernel tree (dense level-3 tables), walk timings.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "sprr-class-fast.h"
#include "sprr.h"

#define BASE UINT64_C(0x40000000)
#define MAX_PAGES 6400u
#define DATA UINT64_C(0x900000000)
#define ATTR (PT_AF|(3UL<<8))
_Static_assert(MAX_PAGES<=SPRR_CLASS_PROOF_PAGES && MAX_PAGES<=SPRR_TABLE_MEMO_PAGES, "arena");

static uint64_t ram[MAX_PAGES*512];
static unsigned arena_pages,carved;          /* proof limit; pages never allocator-issued */
static uint64_t next_table,root,forbidden=UINT64_C(1)<<9;
static uint64_t freelist[MAX_PAGES];static unsigned nfree;
static unsigned level_of[MAX_PAGES];          /* level+1 of a linked table, 0 if none */
static uint64_t slot_of[MAX_PAGES];           /* the descriptor that links it */
static struct sprr_table_memo memo;
static struct sprr_class_leaf_cache leaf;
static struct sprr_class_proof ref,fast,word;
static struct sprr_class_walk_stats wref,wfast;
static unsigned long checks,failed,proofs,accepted,refused,map_calls,base_calls;
#define CHECK(x) do {checks++;if(!(x)){failed++;if(failed<20)printf("FAIL %d: %s\n",__LINE__,#x);}} while(0)

static uint64_t rs=UINT64_C(0x9e3779b97f4a7c15);
static unsigned rnd(unsigned n)
{rs^=rs<<13;rs^=rs>>7;rs^=rs<<17;return (unsigned)(rs%n);}
static uint64_t *at(uint64_t pa){return &ram[(pa-BASE)/8];}
static unsigned page_of(uint64_t pa){return (unsigned)((pa-BASE)/4096);}

/* kernel_table_read: its only failure is the allocation bound. */
static int word_read(void *ctx,uint64_t pa,uint64_t *out)
{
    (void)ctx;
    if((pa&7) || pa<BASE || pa>=next_table || next_table-pa<8)return -1;
    *out=*(volatile uint64_t *)at(pa);return 0;
}
/* class_table_read: the same bound for a whole page. */
static const volatile uint64_t *page_read(void *ctx,uint64_t pa)
{
    (void)ctx;map_calls++;
    if((pa&4095) || pa<BASE || pa>=next_table || next_table-pa<4096)return 0;
    return at(pa);
}
static struct shadow kshadow(void)
{return (struct shadow){.txsz=17,.root=root,.read=word_read};}

/* ---- the monitor's write paths ---- */
static void note_all(uint64_t pa)
{sprr_class_proof_note(&ref,pa);sprr_class_proof_note(&fast,pa);sprr_class_proof_note(&word,pa);}
static void forget_all(void)
{sprr_class_proof_forget(&ref);sprr_class_proof_forget(&fast);sprr_class_proof_forget(&word);}
/* mem_write: table memo first, then the class proof, then the store. */
static void mw(uint64_t pa,uint64_t value)
{
    if(pa<BASE || pa>=next_table || (pa&7)) {CHECK(0);return;}
    if(*at(pa)!=value) {sprr_table_memo_note(&memo,pa);note_all(pa);}
    *at(pa)=value;
}
/* table_alloc_owned: both notes, then zeroing. Carved pages are never issued. */
static uint64_t alloc_table(void)
{
    uint64_t pa;
    if(nfree && (rnd(2) || next_table>=BASE+4096UL*arena_pages))pa=freelist[--nfree];
    else if(next_table<BASE+4096UL*arena_pages) {pa=next_table;next_table+=4096;}
    else return 0;
    note_all(pa);sprr_table_memo_alloc(&memo,pa);
    for(unsigned i=0;i<512;i++)at(pa)[i]=0;
    return pa;
}
/* sptm_shadow_map: every page a transaction may store through is noted. */
static volatile uint64_t *map_shadow(uint64_t pa,uint64_t size)
{
    for(uint64_t page=pa&~UINT64_C(4095);page<pa+size;page+=4096)sprr_table_memo_note(&memo,page);
    return at(pa);
}
/* Directly carved storage: never summarized, so stores may skip the memo. */
static void carved_write(uint64_t pa,uint64_t value)
{
    CHECK(page_of(pa)<carved);
    if(*at(pa)!=value)note_all(pa);
    *at(pa)=value;
}

/* ---- descriptors ---- */
static uint64_t with_class(uint64_t d,unsigned cls)
{
    d&=~((UINT64_C(3)<<6)|(UINT64_C(3)<<53));
    return d|((uint64_t)(cls>>2)<<6)|((uint64_t)(cls&3)<<53);
}
static const unsigned common[]={3,3,3,11,11,1,2,7,8,10,12,13,15};
static unsigned valid_class(void){return common[rnd(sizeof common/sizeof *common)];}
static uint64_t leaf_at(unsigned level,unsigned cls)
{
    uint64_t size=level==3 ? 4096 : level==2 ? 0x200000 : 0x40000000;
    return with_class((DATA+size*(1+rnd(64)))|ATTR|(level==3 ? 3 : 1),cls);
}

/* ---- the three proofs, compared after every call ---- */
static int last_ref;static struct sprr_view_classes last_ref_out,last_fast_out;
static int prove_all(int compare_fast)
{
    struct shadow s=kshadow();
    struct sprr_view_classes a={11,22,33},b=a,c=a;
    int w=sprr_class_proof_check(&word,&s,forbidden,BASE,BASE+4096UL*arena_pages,&c);
    int r=sprr_class_proof_check_with(&ref,&s,forbidden,BASE,BASE+4096UL*arena_pages,&a,
                                      page_read,0,&wref);
    int f=sprr_class_proof_check_fast(&fast,&s,forbidden,BASE,BASE+4096UL*arena_pages,&b,
                                      page_read,0,&wfast,&leaf,&memo);
    proofs++;
    CHECK(w==r);CHECK(!memcmp(&a,&c,sizeof a));CHECK(!memcmp(&ref,&word,sizeof ref));
    if(compare_fast) {
        CHECK(f==r);CHECK(!memcmp(&a,&b,sizeof a));CHECK(!memcmp(&ref,&fast,sizeof ref));
    }
    if(!r)CHECK(a.tables==11 && a.pages==22 && a.classes==33);   /* no partial output */
    if(!f)CHECK(b.tables==11 && b.pages==22 && b.classes==33);
    if(r)accepted++;else refused++;
    last_ref=r;last_ref_out=a;last_fast_out=b;
    return compare_fast ? r : f;
}
static void reset_machines(unsigned pages,unsigned carve)
{
    memset(ram,0,sizeof ram);memset(level_of,0,sizeof level_of);memset(slot_of,0,sizeof slot_of);
    memset(&memo,0,sizeof memo);memset(&leaf,0,sizeof leaf);
    memset(&ref,0,sizeof ref);memset(&fast,0,sizeof fast);memset(&word,0,sizeof word);
    arena_pages=pages;carved=carve;nfree=0;forbidden=UINT64_C(1)<<9;
    memo.base=BASE;memo.pages=pages;
    next_table=BASE+4096UL*carve;
    root=BASE;level_of[0]=1;
}
static void link_table(uint64_t parent,unsigned index,uint64_t child,unsigned level,int carved_store)
{
    if(carved_store)carved_write(parent+8UL*index,child|3);else mw(parent+8UL*index,child|3);
    level_of[page_of(child)]=level+1;slot_of[page_of(child)]=parent+8UL*index;
}
static void fill_leaves(uint64_t table,unsigned level,unsigned count,int carved_store)
{
    for(unsigned n=0;n<count;n++) {
        unsigned i=rnd(512);
        uint64_t d=leaf_at(level,valid_class());
        if(carved_store)carved_write(table+8UL*i,d);else mw(table+8UL*i,d);
    }
}
/* Root(L0, carved) -> L1 (carved) -> L2 x l2 -> L3 x l3, one L2 block or two,
 * page 2 is a carved L3 table. Level-3 fill is sparse to dense. */
static void fresh_tree(unsigned pages,unsigned l2,unsigned l3)
{
    reset_machines(pages,3);
    uint64_t l1=BASE+4096;
    link_table(root,rnd(256),l1,1,1);
    uint64_t l2t[8];
    for(unsigned i=0;i<l2 && i<8;i++) {
        l2t[i]=alloc_table();
        unsigned index;do index=rnd(512);while(at(l1)[index]);
        link_table(l1,index,l2t[i],2,0);
        for(unsigned b=0;b<1+rnd(2);b++) {
            do index=rnd(512);while(at(l2t[i])[index]);
            mw(l2t[i]+8UL*index,leaf_at(2,valid_class()));
        }
    }
    for(unsigned i=0;i<l3;i++) {
        uint64_t parent=l2t[rnd(l2)],t=i==0 ? BASE+8192 : alloc_table();
        unsigned index;do index=rnd(512);while(at(parent)[index]);
        link_table(parent,index,t,3,i==0 ? 0 : 0);
        fill_leaves(t,3,rnd(4) ? 8+rnd(120) : 400+rnd(112),i==0);
    }
}

/* ---- A. differential under random mutations ---- */
struct defect {uint64_t pa,old;};
static struct defect defects[16];static unsigned ndefects;
static int random_table(unsigned level,uint64_t *out)
{
    for(unsigned tries=0;tries<64;tries++) {
        unsigned p=rnd(page_of(next_table));
        if(level_of[p]==level+1) {*out=BASE+4096UL*p;return 1;}
    }
    return 0;
}
static void store(uint64_t pa,uint64_t value)
{
    if(page_of(pa)<carved && rnd(2))carved_write(pa,value);else mw(pa,value);
}
static void add_defect(uint64_t pa,uint64_t value)
{
    if(ndefects>=16)return;
    for(unsigned i=0;i<ndefects;i++)if(defects[i].pa==pa)return;
    defects[ndefects++]=(struct defect){pa,*at(pa)};store(pa,value);
}
static void repair_one(void)
{
    if(!ndefects)return;
    unsigned i=rnd(ndefects);struct defect d=defects[i];
    defects[i]=defects[--ndefects];
    store(d.pa,d.old);
}
static void mutate(void)
{
    uint64_t t,u;unsigned i;
    switch(rnd(20)) {
    case 0: case 1: case 2: case 3: case 4:      /* a noted level-3 leaf change */
        if(random_table(3,&t)) {
            i=rnd(512);store(t+8UL*i,rnd(5) ? leaf_at(3,valid_class()) : 0);
        }
        break;
    case 5:                                      /* a whole level-3 rewrite */
        if(random_table(3,&t))for(i=0;i<512;i++)if(rnd(3))mw(t+8UL*i,rnd(4) ? leaf_at(3,valid_class()) : 0);
        break;
    case 6: case 7:                              /* an SPTM transaction */
        forget_all();
        for(unsigned n=0;n<1+rnd(3);n++)if(random_table(3,&t)) {
            volatile uint64_t *w=map_shadow(t,4096);
            for(unsigned k=0;k<1+rnd(6);k++)w[rnd(512)]=rnd(6) ? leaf_at(3,valid_class()) : 0;
        }
        if(rnd(3) && random_table(2,&t)) {   /* and an L2 block */
            volatile uint64_t *w=map_shadow(t,4096);i=rnd(512);
            if(!w[i] || (w[i]&3)==1)w[i]=rnd(2) ? leaf_at(2,valid_class()) : 0;
        }
        break;
    case 8:                                      /* a new level-3 table */
        if(random_table(2,&u) && (t=alloc_table())) {
            fill_leaves(t,3,1+rnd(200),0);
            i=rnd(512);if(!at(u)[i])link_table(u,i,t,3,0);else freelist[nfree++]=t;
        }
        break;
    case 9:                                      /* unlink and free one */
        if(random_table(3,&t) && page_of(t)>=carved && slot_of[page_of(t)]) {
            int aliased=0;
            for(unsigned k=0;k<ndefects;k++)aliased|=(defects[k].pa==slot_of[page_of(t)]) ||
                ((*at(defects[k].pa)&PT_OA_MASK)==t) || (defects[k].pa&~UINT64_C(4095))==t;
            if(aliased)break;
            mw(slot_of[page_of(t)],0);level_of[page_of(t)]=0;slot_of[page_of(t)]=0;
            freelist[nfree++]=t;
        }
        break;
    case 10:                                     /* carved storage, memo bypassed */
        i=rnd(512);carved_write(BASE+8192+8UL*i,rnd(4) ? leaf_at(3,valid_class()) : 0);
        break;
    case 11: {                                   /* a defect, repaired later */
        unsigned kind=rnd(9);
        if(kind==0 && random_table(3,&t)) {i=rnd(512);add_defect(t+8UL*i,leaf_at(3,9));}
        else if(kind==1 && random_table(3,&t)) {i=rnd(512);add_defect(t+8UL*i,2);}
        else if(kind==2 && random_table(3,&t)) {i=rnd(512);add_defect(t+8UL*i,leaf_at(2,3)&~UINT64_C(2));}
        else if(kind==3 && random_table(2,&t)) {
            i=rnd(512);if(!at(t)[i])add_defect(t+8UL*i,leaf_at(2,3)+4096);  /* misaligned block */
        } else if(kind==4 && random_table(2,&t) && random_table(3,&u)) {
            i=rnd(512);if(!at(t)[i])add_defect(t+8UL*i,u|3);                /* alias */
        } else if(kind==5 && random_table(2,&t)) {
            i=rnd(512);if(!at(t)[i])add_defect(t+8UL*i,(BASE+4096)|3);      /* cycle */
        } else if(kind==6) add_defect(root+8UL*(256+rnd(256)),(BASE+4096)|3); /* upper half */
        else if(kind==7 && random_table(2,&t) && random_table(3,&u)) {
            i=rnd(512);if(!at(t)[i])add_defect(t+8UL*i,u|3|(UINT64_C(1)<<52));
        } else if(kind==8 && random_table(2,&t)) {
            i=rnd(512);if(!at(t)[i])add_defect(t+8UL*i,(BASE+4096UL*arena_pages)|3);
        }
        break;
    }
    case 12: case 13: case 14: repair_one();break;
    case 15:                                     /* another forbidden mask, briefly */
        forbidden=rnd(3) ? UINT64_C(1)<<9 : (UINT64_C(1)<<9)|(UINT64_C(1)<<(1+rnd(15)));
        break;
    case 16:                                     /* a no-op store and a forget */
        if(random_table(3,&t)) {i=rnd(512);mw(t+8UL*i,*at(t+8UL*i));}
        if(rnd(2))forget_all();
        break;
    default:                                     /* an L2 block change */
        if(random_table(2,&t)) {
            i=rnd(512);
            if(!at(t)[i] || (at(t)[i]&3)==1)mw(t+8UL*i,rnd(3) ? leaf_at(2,valid_class()) : 0);
        }
        break;
    }
}
static void differential(uint64_t seed,unsigned steps)
{
    rs=seed;ndefects=0;
    fresh_tree(1024,2+rnd(5),12+rnd(28));
    static unsigned char snapshot[sizeof ram];
    for(unsigned step=0;step<steps;step++) {
        if(rnd(10)) {for(unsigned n=0;n<1+rnd(3);n++)mutate();}
        unsigned burst=rnd(12)==0 ? 64+rnd(80) : 1+rnd(3);
        int snap=!(step%16);
        if(snap)memcpy(snapshot,ram,(size_t)(next_table-BASE));
        for(unsigned n=0;n<burst;n++)prove_all(1);
        if(snap)CHECK(!memcmp(snapshot,ram,(size_t)(next_table-BASE)));
        if(rnd(8)==0)forbidden=UINT64_C(1)<<9;
        if(rnd(3)==0)repair_one();
    }
    while(ndefects)repair_one();
    forbidden=UINT64_C(1)<<9;
    for(unsigned n=0;n<130;n++)prove_all(1);
}

/* ---- B. faults ---- */
static uint64_t occupied(uint64_t table)
{
    for(unsigned i=0;i<512;i++)if(at(table)[i])return table+8UL*i;
    return 0;
}
static uint64_t other_l3(uint64_t not)
{
    uint64_t t;
    for(unsigned n=0;n<200;n++)if(random_table(3,&t) && t!=not && page_of(t)>=carved)return t;
    return 0;
}
/* A store the table memo missed (the class proof was told): the stale summary
 * may answer until the first sampled rescan (leaf call 64), which poisons; then
 * every proof refuses, hits and repairs included. */
static void fault_missed_memo_note(uint64_t seed,unsigned kind)
{
    rs=seed;fresh_tree(1024,3,16);
    CHECK(prove_all(1)==1);
    CHECK(leaf.stats.calls==1 && !leaf.stats.poisoned);
    uint64_t t=other_l3(0),pa=occupied(t),old=*at(pa);
    uint64_t bad=kind==0 ? with_class(old,9) : kind==1 ? (old&~UINT64_C(3))|1 : with_class(old,6);
    note_all(pa);*at(pa)=bad;                /* no sprr_table_memo_note */
    uint64_t perturb=other_l3(t),p=perturb+8UL*511,a=leaf_at(3,3),b=leaf_at(3,11);
    unsigned stale=0,detected=0;
    for(unsigned n=0;n<200;n++) {
        mw(p,(n&1) ? a : b);                 /* a noted store elsewhere: a miss */
        int r=prove_all(0);
        CHECK(last_ref==(kind==2));          /* class6 is valid; the others refuse */
        if(!detected) {
            if(r && (kind!=2 || last_fast_out.classes!=last_ref_out.classes))stale++;
            if(!r || leaf.stats.poisoned)detected=(unsigned)leaf.stats.calls;
        } else CHECK(!r);
    }
    CHECK(detected==64);CHECK(stale<=63);
    CHECK(leaf.stats.poisoned==1 && leaf.stats.mismatches==1);
    /* terminal: hits, a repair and a fresh miss all refuse */
    for(unsigned n=0;n<70;n++)CHECK(!prove_all(0));
    mw(pa,old);
    for(unsigned n=0;n<70;n++)CHECK(!prove_all(0));
}
/* A restarted generation source (the monitor initializes it once, at boot):
 * a page whose new generation happens to equal the one its summary was saved
 * under must still be rescanned, because the clock went backwards. */
static void fault_clock_restart(void)
{
    rs=0x7777;fresh_tree(1024,3,16);
    CHECK(prove_all(1)==1);
    uint64_t t=other_l3(0),pa=occupied(t);
    uint64_t saved=leaf.entry[page_of(t)].generation,old_clock=memo.clock;
    CHECK(saved>8 && saved<old_clock);
    if(!(saved>8 && saved<old_clock))return;
    memset(memo.page,0,sizeof memo.page);memo.clock=0;
    uint64_t spare=next_table;next_table+=4096;  /* an unlinked page */
    while(memo.clock<saved-1)sprr_table_memo_note(&memo,spare);
    *at(pa)=with_class(*at(pa),6);
    sprr_table_memo_note(&memo,pa);note_all(pa);
    CHECK(memo.page[page_of(t)]>>16==saved);
    for(unsigned p=0;p<page_of(next_table);p++)      /* pool status again */
        if(p>=carved && p!=page_of(t))memo.page[p]|=SPRR_TABLE_MEMO_POOL;
    memo.page[page_of(t)]|=SPRR_TABLE_MEMO_POOL;
    for(unsigned n=0;n<3;n++)CHECK(prove_all(1)==1);
    CHECK(leaf.stats.resets==2);
}
/* A poisoned cache refuses even a proof whose cached result is current. */
static void poisoned_refuses_hits(void)
{
    rs=0x5150;fresh_tree(1024,3,16);
    CHECK(prove_all(1)==1);CHECK(prove_all(1)==1);
    uint64_t hits=fast.hits;
    leaf.stats.poisoned=1;
    for(unsigned n=0;n<4;n++)CHECK(!prove_all(0));
    CHECK(fast.hits==hits && !fast.valid);
}
/* A store both witnesses missed: production and fast refuse at the same 64th
 * hit, with equal state throughout (an L2 block: always rescanned). For a
 * level-3 table the states are equal up to that refusal. */
static void fault_missed_both(uint64_t seed,int level3)
{
    rs=seed;fresh_tree(1024,3,16);
    CHECK(prove_all(1)==1);
    uint64_t t,pa=0;
    if(level3) {t=other_l3(0);pa=occupied(t);}
    else {
        CHECK(random_table(2,&t));
        for(unsigned i=0;i<512 && !pa;i++)if((at(t)[i]&3)==1)pa=t+8UL*i;
    }
    CHECK(pa!=0);if(!pa)return;
    *at(pa)=with_class(*at(pa),6);           /* class6 appears nowhere else */
    unsigned refusals=0;
    for(unsigned n=0;n<200;n++) {
        int r=prove_all(1);
        if(!r) {refusals++;CHECK(ref.hits==64 && ref.verified==1);}
        if(level3 && refusals)break;   /* the next miss reuses the stale summary (fault 1) */
    }
    CHECK(refusals==1);CHECK(ref.mismatches==1);
    CHECK(fast.mismatches==1);
}
/* A coverage-only fault: an L2 entry now names an untracked copy of its
 * level-3 table. Totals are equal; only the refusing mapping can see it. */
static void fault_coverage(uint64_t seed)
{
    rs=seed;fresh_tree(1024,3,16);
    CHECK(prove_all(1)==1);
    uint64_t t=other_l3(0),copy=next_table;
    next_table+=4096;                        /* no allocation note: untracked */
    memcpy(at(copy),at(t),4096);
    *at(slot_of[page_of(t)])=copy|3;         /* no note of any kind */
    unsigned refusals=0;
    for(unsigned n=0;n<200;n++)if(!prove_all(1))refusals++;
    CHECK(refusals==1);CHECK(ref.mismatches==1 && fast.mismatches==1);
}

/* ---- C. the refusing mapping ---- */
static const volatile uint64_t *counting_base(void *ctx,uint64_t pa)
{base_calls++;return page_read(ctx,pa);}
static void verify_reader(void)
{
    reset_machines(64,0);next_table=BASE+4096UL*64;
    struct sprr_class_proof *p=&fast;p->first=BASE;p->limit=BASE+4096UL*64;
    p->bitmap[0]=UINT64_C(1)<<3;p->tracked_pages=1;
    struct sprr_class_proof saved;memcpy(&saved,p,sizeof saved);
    struct sprr_class_proof_map_reader r={p,counting_base,0};
    base_calls=0;
    CHECK(sprr_class_proof_map_verify(&r,BASE+3*4096)==at(BASE+3*4096));CHECK(base_calls==1);
    CHECK(!sprr_class_proof_map_verify(&r,BASE+4*4096));
    CHECK(!sprr_class_proof_map_verify(&r,BASE+3*4096+8));
    CHECK(!sprr_class_proof_map_verify(&r,BASE-4096));
    CHECK(!sprr_class_proof_map_verify(&r,BASE+4096UL*64));
    CHECK(base_calls==1);CHECK(!memcmp(&saved,p,sizeof saved));
    /* and the marking form it shadows does mark */
    struct sprr_class_proof_map_reader m={p,counting_base,0};
    CHECK(sprr_class_proof_map(&m,BASE+4*4096)!=0);CHECK(p->bitmap[0]==((UINT64_C(1)<<3)|(UINT64_C(1)<<4)));
}

/* ---- --bench ---- */
static double now_us(void)
{struct timespec t;clock_gettime(CLOCK_MONOTONIC,&t);return t.tv_sec*1e6+t.tv_nsec/1e3;}
static int dcmp(const void *a,const void *b)
{double x=*(const double *)a,y=*(const double *)b;return x<y ? -1 : x>y;}
static double median(double *v,unsigned n){qsort(v,n,sizeof *v,dcmp);return v[n/2];}
static void bench(void)
{
    rs=0x5eed;reset_machines(MAX_PAGES,0);
    next_table=BASE+4096;level_of[0]=1;memo.pages=MAX_PAGES;
    uint64_t l1=alloc_table();link_table(root,1,l1,1,0);
    enum {L3=5180,L2=(L3+511)/512};
    uint64_t l2[L2];
    for(unsigned i=0;i<L2;i++) {l2[i]=alloc_table();link_table(l1,i,l2[i],2,0);}
    for(unsigned i=0;i<L3;i++) {
        uint64_t t=alloc_table();link_table(l2[i/512],i%512,t,3,0);
        for(unsigned g=0;g<64;g++) {
            if(rnd(100)<3)continue;            /* v33: 3.1% empty eight-word groups */
            for(unsigned k=0;k<8;k++)mw(t+8UL*(8*g+k),leaf_at(3,valid_class()));
        }
    }
    struct shadow s=kshadow();struct sprr_view_classes o;
    CHECK(prove_all(1));
    printf("bench tree: %lu tables, %lu pages, classes %#lx\n",(unsigned long)ref.result.tables,
           (unsigned long)ref.result.pages,(unsigned long)ref.result.classes);
    enum {N=21};double v[N];
    struct sprr_class_proof_map_reader mr={&ref,page_read,0};
    struct shadow direct={.txsz=17,.root=root,.ctx=&mr};
    struct sprr_class_proof_reader wr={&ref,&s,1};
    struct shadow observed={.txsz=17,.root=root,.read=sprr_class_proof_read,.ctx=&wr};
    for(unsigned n=0;n<N;n++) {double t=now_us();CHECK(sprr_views_check_classes(&observed,forbidden,&o));v[n]=now_us()-t;}
    double word_us=median(v,N);
    for(unsigned n=0;n<N;n++) {struct sprr_class_walk_stats w={0};double t=now_us();
        CHECK(sprr_views_check_classes_mapped(&direct,forbidden,&o,sprr_class_proof_map,&w));v[n]=now_us()-t;}
    double mapped_us=median(v,N);
    for(unsigned n=0;n<N;n++) {struct sprr_class_walk_stats w={0};double t=now_us();
        CHECK(sprr_views_check_classes_mapped(&direct,forbidden,&o,sprr_class_proof_map_verify,&w));v[n]=now_us()-t;}
    double verify_us=median(v,N);
    printf("word walk (production hit verification): %.0f us\n",word_us);
    printf("mapped walk (production miss):           %.0f us\n",mapped_us);
    printf("refusing mapped walk (fast verification): %.0f us\n",verify_us);
    unsigned dirty[]={0,8,64,512};
    for(unsigned d=0;d<4;d++) {
        unsigned n_ok=0;
        for(unsigned n=0;n<N;n++) {
            for(unsigned k=0;k<dirty[d];k++) {
                uint64_t t=BASE+4096UL*(2+L2+rnd(L3));mw(t+8UL*rnd(512),leaf_at(3,valid_class()));
            }
            if(!((leaf.stats.calls+1)%64))leaf.stats.calls++;  /* time the unsampled walk */
            struct sprr_class_walk_stats w={0};double t=now_us();
            CHECK(sprr_class_leaf_check(&leaf,&direct,forbidden,&memo,&o,sprr_class_proof_map,&w));
            v[n_ok++]=now_us()-t;
        }
        printf("incremental walk, %3u changed L3 tables:   %.0f us\n",dirty[d],median(v,n_ok));
    }
    leaf.stats.calls=63;
    {struct sprr_class_walk_stats w={0};double t=now_us();
     CHECK(sprr_class_leaf_check(&leaf,&direct,forbidden,&memo,&o,sprr_class_proof_map,&w));
     printf("incremental walk, sampled full rescan:    %.0f us\n",now_us()-t);}
    printf("ratios: word/mapped %.2f, verify/mapped %.2f\n",word_us/mapped_us,verify_us/mapped_us);
}

int main(int argc,char **argv)
{
    if(argc>1 && !strcmp(argv[1],"--bench")) {bench();return failed!=0;}
    verify_reader();
    unsigned long d0=checks;
    static const uint64_t seeds[]={0x243f6a8885a308d3,0x13198a2e03707344,0xa4093822299f31d0,
                                   0x082efa98ec4e6c89,0x452821e638d01377};
    for(unsigned s=0;s<sizeof seeds/sizeof *seeds;s++)differential(seeds[s],2000);
    unsigned long d1=checks;
    CHECK(fast.calls>0);
    printf("differential: %lu checks, %lu proofs (%lu accepted, %lu refused); last seed: "
           "proof hits %lu, verified %lu, walks %lu; leaf calls %lu, hits %lu, scans %lu, "
           "sampled %lu\n",d1-d0,proofs,accepted,refused,(unsigned long)fast.hits,
           (unsigned long)fast.verified,(unsigned long)fast.walks,(unsigned long)leaf.stats.calls,
           (unsigned long)leaf.stats.hits,(unsigned long)leaf.stats.scans,
           (unsigned long)leaf.stats.verified);
    CHECK(fast.verified>0 && fast.walks>0 && leaf.stats.hits>leaf.stats.scans && leaf.stats.verified>0);
    CHECK(!leaf.stats.poisoned && !leaf.stats.mismatches);
    CHECK(accepted>refused/4 && refused>0);
    for(unsigned k=0;k<3;k++)fault_missed_memo_note(0x1234+k,k);
    fault_missed_both(0x77,0);fault_missed_both(0x78,1);
    fault_coverage(0x99);
    fault_clock_restart();
    poisoned_refuses_hits();
    if(failed) {printf("FAILED %lu of %lu checks\n",failed,checks);return 1;}
    printf("PASS: %lu checks\n",checks);return 0;
}

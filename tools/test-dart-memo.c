/* SPDX-License-Identifier: MIT */
/* SNAP_DART_MEMO (compat/sptm-dart-memo.h, docs/DART-MEMO-20261019.md): DART
 * services with table verdicts against compat/sptm-dart.c without them.
 *
 * Failure inventory this covers, each as checks with the expected result:
 *   - a different result: two worlds, each with its own RAM image, frame
 *     records, DART state and reference batch, one driven by sptm-dart.c as
 *     it was (linked with ref_ names), one with the memo, run the same random
 *     sequence on the Adreno DART (id 31, two levels) and on id 21 (three
 *     levels): MAP_TABLE, MAP (aligned and partial ranges, all options, page
 *     lists with repeats), UNMAP (options 0 and 2), ENABLE and DMA
 *     translation. After every call the results, both RAM images, both
 *     states and both reference batches must be identical;
 *   - a stale verdict after a published change: published stores of garbage,
 *     of well-formed descriptors to unmanaged frames and of zero into live
 *     tables, published reference-count changes, and later repairs, with the
 *     memo world answering exactly as the reference does throughout;
 *   - a configuration change: alloc_high moved below half the data frames and
 *     back between calls, so leaf tables naming them fail their scan (the
 *     memo flushes);
 *   - the witness and the refs comparison: a published store to a table's
 *     frame record drops its entry (and a neighbour's does not), and an
 *     unpublished reference-count change is refused at once;
 *   - a stale verdict after an unpublished write (excluded by stage 2, so
 *     only bounded): a corruption without a publish must be refused by the
 *     memo within two sampling periods of calls, with a mismatch counted;
 *   - no speedup: with --speed, MAP and UNMAP of one page into a nearly full
 *     Adreno level-2 table must be at least 4x faster with the memo.
 * tools/test-dart-memo.py builds this, requires weakened code to fail it and
 * checks the sources and the monitor builds. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "sptm-dart.h"
#include "sptm-refs.h"
#include "sptm-dart-memo.h"

enum sptm_result ref_sptm_dart_map_table(const struct sptm_memory *,struct dart_state *,uint64_t,uint64_t,
                                         uint64_t,uint64_t,uint64_t);
enum sptm_result ref_sptm_dart_map(const struct sptm_memory *,struct dart_state *,uint64_t,uint64_t,uint64_t,
                                   uint64_t,uint64_t,uint64_t);
enum sptm_result ref_sptm_dart_unmap(const struct sptm_memory *,struct dart_state *,uint64_t,uint64_t,uint64_t,
                                     uint64_t,uint64_t);
enum sptm_result ref_sptm_dart_enable(const struct sptm_memory *,struct dart_state *,uint64_t,uint64_t);
enum sptm_result ref_sptm_dart_dma_translate(const struct sptm_memory *,struct dart_state *,uint64_t,uint64_t,
                                             uint64_t,uint64_t,int,uint64_t *);

static unsigned long checks,failures;
#define CHECK(cond,...) do { checks++; if(!(cond)) { failures++; \
    if(failures<20) { printf("FAIL %s:%d: ",__FILE__,__LINE__); printf(__VA_ARGS__); printf("\n"); } } } while(0)

static uint64_t rng=0x853c49e6748fea9bu;
static uint64_t next(void) {rng^=rng<<13;rng^=rng>>7;rng^=rng<<17;return rng;}

#define BASE 0x8c0000000UL
#define SIZE 0x400000UL
#define FM (BASE+0x4000)
#define ALLOC (BASE+0x10000)
#define TABLES 16u
#define TABLE(i) (ALLOC+(uint64_t)(i)*0x4000)
#define LIST (ALLOC+TABLES*0x4000)
#define DATA0 (LIST+0x8000)
#define DATA_FRAMES 120u
#define DATA(i) (DATA0+(uint64_t)(i)*0x4000)
_Static_assert(DATA0+DATA_FRAMES*0x4000<=BASE+SIZE,"layout");

struct world {
    uint8_t *ram;
    struct dart_state state;
    struct sptm_ref_batch refs;
    struct sptm_memory m;
    struct sptm_dart_memo memo;
    int memo_on;
};
static uint8_t *meta_of(struct world *w,uint64_t pa) {return w->ram+(FM-BASE)+((pa-BASE)>>14)*16;}
static uint64_t get(struct world *w,uint64_t pa) {uint64_t v;memcpy(&v,w->ram+(pa-BASE),8);return v;}
static void put(struct world *w,uint64_t pa,uint64_t v) {memcpy(w->ram+(pa-BASE),&v,8);}
static volatile uint8_t *map(void *ctx,uint64_t pa,uint64_t n)
{
    struct world *w=ctx;
    if(pa<BASE || pa>=BASE+SIZE || !n || n>BASE+SIZE-pa)return 0;
    return w->ram+(pa-BASE);
}
static void publish(void *ctx,uint64_t pa,uint64_t n)
{
    struct world *w=ctx;
    if(w->memo_on)sptm_dart_memo_publish(&w->memo,pa,n);
}

static unsigned first_level(unsigned id) {return id==31 ? 1 : 0;}
static uint64_t window(unsigned id) {return id==31 ? UINT64_C(1)<<30 : UINT64_C(1)<<40;}

static void world_init(struct world *w,int memo_on,unsigned id)
{
    if(!w->ram)w->ram=malloc(SIZE);
    memset(w->ram,0,SIZE);
    memset(&w->state,0,sizeof(w->state));memset(&w->refs,0,sizeof(w->refs));memset(&w->memo,0,sizeof(w->memo));
    w->memo_on=memo_on;
    w->state.initialized_ids=w->state.powered_ids=1U<<id;
    w->state.tcr[0]=w->state.tcr[1]=first_level(id) ? 1 : 9;
    for(unsigned i=0;i<TABLES;i++)meta_of(w,TABLE(i))[2]=11;
    meta_of(w,LIST)[2]=11;meta_of(w,LIST+0x4000)[2]=35;
    for(unsigned i=0;i<DATA_FRAMES;i++)meta_of(w,DATA(i))[2]=11;
    w->m=(struct sptm_memory){.frame_map_pa=FM,.frame_low=BASE,.frame_high=BASE+SIZE,.alloc_low=ALLOC,
        .alloc_high=BASE+SIZE,.map=map,.publish=publish,.ctx=w,.refs=&w->refs};
    w->m.dart_memo=memo_on ? &w->memo : 0;
}
/* Type a free table frame for (id, sid, level), as RETYPE would. */
static void type_table(struct world *w,uint64_t pa,unsigned id,unsigned sid,unsigned level)
{
    uint8_t e[16]={0,0,24,0,0,0,5,0,(uint8_t)id,(uint8_t)sid,(uint8_t)level,0,0,0,0,0};
    memcpy(meta_of(w,pa),e,16);
    publish(w,meta_of(w,pa)-w->ram+BASE,16);
}

struct pair {struct world a,b;unsigned id,sid,tables,leaves;uint64_t leaf_iova[TABLES];};
/* The reference batches without their pointers into each world's RAM. */
static int refs_same(const struct sptm_ref_batch *a,const struct sptm_ref_batch *b)
{
    if(a->count!=b->count)return 0;
    for(unsigned i=0;i<a->count && i<SPTM_REF_MAX;i++) {
        const struct sptm_ref_entry *x=&a->entries[i],*y=&b->entries[i];
        if(x->pa!=y->pa || x->ro!=y->ro || x->other!=y->other || x->type!=y->type)return 0;
    }
    return 1;
}
/* What a DART service can write: frame records, tables and the page lists
 * (the data frames themselves are never written). */
static int same(struct pair *p)
{
    return !memcmp(p->a.ram+(FM-BASE),p->b.ram+(FM-BASE),0x4000) &&
           !memcmp(p->a.ram+(ALLOC-BASE),p->b.ram+(ALLOC-BASE),DATA0-ALLOC) &&
           !memcmp(&p->a.state,&p->b.state,sizeof(p->a.state)) && refs_same(&p->a.refs,&p->b.refs);
}
#define BOTH(call_a,call_b,what) do { enum sptm_result ra=(call_a),rb=(call_b); \
    CHECK(ra==rb,"%s: reference %d, memo %d",what,ra,rb); \
    CHECK(same(p),"%s: worlds differ after the call (result %d)",what,ra); } while(0)

static void pair_init(struct pair *p,unsigned id)
{
    world_init(&p->a,0,id);world_init(&p->b,1,id);
    p->id=id;p->sid=0;p->tables=0;p->leaves=0;
    unsigned first=first_level(id);
    for(unsigned l=first;l<3 && p->tables<TABLES;l++) {      /* the root (and id 21's level 1) */
        if(l==2)break;
        uint64_t t=TABLE(p->tables++);
        type_table(&p->a,t,id,p->sid,l);type_table(&p->b,t,id,p->sid,l);
        BOTH(ref_sptm_dart_map_table(&p->a.m,&p->a.state,id,p->sid,window(id),l,t),
             sptm_dart_map_table(&p->b.m,&p->b.state,id,p->sid,window(id),l,t),"MAP_TABLE root");
    }
    BOTH(ref_sptm_dart_enable(&p->a.m,&p->a.state,id,p->sid),sptm_dart_enable(&p->b.m,&p->b.state,id,p->sid),
         "ENABLE");
}
/* A new level-2 table for the next 32 MiB of the window. */
static void add_leaf(struct pair *p)
{
    if(p->tables>=TABLES)return;
    uint64_t t=TABLE(p->tables++),iova=window(p->id)+(uint64_t)p->leaves*(UINT64_C(1)<<25);
    type_table(&p->a,t,p->id,p->sid,2);type_table(&p->b,t,p->id,p->sid,2);
    BOTH(ref_sptm_dart_map_table(&p->a.m,&p->a.state,p->id,p->sid,iova,2,t),
         sptm_dart_map_table(&p->b.m,&p->b.state,p->id,p->sid,iova,2,t),"MAP_TABLE leaf");
    p->leaf_iova[p->leaves++]=iova;
}
static void fill_list(struct pair *p,unsigned count,unsigned list_frame)
{
    uint64_t list=LIST+0x4000*list_frame;
    for(unsigned i=0;i<count;i++) {
        uint64_t d=next()%40==0 ? TABLE(0) : DATA(next()%DATA_FRAMES);   /* a table: refused */
        if(i && next()%5==0)d=get(&p->a,list+8*(i-1));                  /* a repeat */
        put(&p->a,list+8*i,d);put(&p->b,list+8*i,d);
    }
}

struct corruption {uint64_t pa,value;int live;};
static void step(struct pair *p,struct corruption *c,unsigned n)
{
    unsigned op=(unsigned)(next()%1000);
    uint64_t base=p->leaves ? p->leaf_iova[next()%p->leaves] : window(p->id);
    if(op<20 || !p->leaves) {add_leaf(p);return;}
    if(op<560) {                                             /* MAP */
        unsigned count=1+(unsigned)(next()%6),slot=(unsigned)(next()%(2048-count)),lf=(unsigned)(next()%2);
        fill_list(p,count,lf);
        uint64_t iova=base+(uint64_t)slot*0x4000,size=(uint64_t)count*0x4000;
        if(next()%6==0) {uint64_t off=next()%0x4000;iova+=off;size-=off;if(next()%2)size-=next()%0x3000;}
        uint64_t options=next()%4;
        BOTH(ref_sptm_dart_map(&p->a.m,&p->a.state,p->id,p->sid,iova,LIST+0x4000*lf,size,options),
             sptm_dart_map(&p->b.m,&p->b.state,p->id,p->sid,iova,LIST+0x4000*lf,size,options),"MAP");
    } else if(op<820) {                                      /* UNMAP */
        unsigned count=1+(unsigned)(next()%6),slot=(unsigned)(next()%(2048-count));
        uint64_t options=next()%3==0 ? 0 : 2;
        BOTH(ref_sptm_dart_unmap(&p->a.m,&p->a.state,p->id,p->sid,base+(uint64_t)slot*0x4000,
                                 (uint64_t)count*0x4000,options),
             sptm_dart_unmap(&p->b.m,&p->b.state,p->id,p->sid,base+(uint64_t)slot*0x4000,
                             (uint64_t)count*0x4000,options),"UNMAP");
    } else if(op<900) {                                      /* DMA translation */
        uint64_t iova=base+(next()%2048)*0x4000+next()%0x100,pa=0,pb=0;int write=(int)(next()%2);
        BOTH(ref_sptm_dart_dma_translate(&p->a.m,&p->a.state,p->id,p->sid,iova,16,write,&pa),
             sptm_dart_dma_translate(&p->b.m,&p->b.state,p->id,p->sid,iova,16,write,&pb),"DMA translate");
        CHECK(pa==pb,"DMA translate: %llx vs %llx",(unsigned long long)pa,(unsigned long long)pb);
    } else if(op<930) {                                      /* a published corruption */
        if(c->live)return;
        uint64_t t=TABLE(next()%p->tables),slot=t+8*(next()%2048),v;
        switch(next()%4) {
        case 0:v=next();break;                                      /* garbage */
        case 1:v=(FM>>4)|1;break;                                   /* a frame below alloc_low */
        case 2:v=((BASE+SIZE)>>4)|1;break;                          /* outside the frames */
        default:v=0;break;                                          /* a live entry removed */
        }
        c->pa=slot;c->value=get(&p->a,slot);c->live=1;
        put(&p->a,slot,v);put(&p->b,slot,v);publish(&p->a,slot,8);publish(&p->b,slot,8);
    } else if(op<950) {                                      /* a published refs change */
        if(c->live)return;
        uint64_t t=TABLE(next()%p->tables);
        uint8_t *ma=meta_of(&p->a,t),*mb=meta_of(&p->b,t);
        c->pa=t;c->value=ma[4];c->live=2;
        ma[4]=mb[4]=(uint8_t)(ma[4]+(next()%2 ? 1 : 255));
        publish(&p->a,FM+((t-BASE)>>14)*16,16);publish(&p->b,FM+((t-BASE)>>14)*16,16);
    } else if(op<990) {                                      /* the repair, published */
        if(!c->live)return;
        if(c->live==1) {put(&p->a,c->pa,c->value);put(&p->b,c->pa,c->value);
                        publish(&p->a,c->pa,8);publish(&p->b,c->pa,8);}
        else {meta_of(&p->a,c->pa)[4]=meta_of(&p->b,c->pa)[4]=(uint8_t)c->value;
              publish(&p->a,FM+((c->pa-BASE)>>14)*16,16);publish(&p->b,FM+((c->pa-BASE)>>14)*16,16);}
        c->live=0;
    } else {                                                  /* a configuration change */
        /* The tables stay managed, half the data frames do not: a leaf table
         * naming one of them must now fail its scan (the memo flushes). */
        uint64_t high=p->a.m.alloc_high==BASE+SIZE ? DATA(DATA_FRAMES/2) : BASE+SIZE;
        p->a.m.alloc_high=p->b.m.alloc_high=high;
    }
    (void)n;
}

static void differential(unsigned id,unsigned steps)
{
    struct pair *p=calloc(1,sizeof(*p));
    pair_init(p,id);
    struct corruption c={0};
    for(unsigned n=0;n<steps && failures<20;n++)step(p,&c,n);
    const struct sptm_dart_memo_stats *s=&p->b.memo.stats;
    printf("differential id %u: %u steps, %u tables; memo lookups %llu hits %llu misses %llu records %llu "
           "invalidations %llu flushes %llu sampled %llu mismatches %llu\n",id,steps,p->tables,
           (unsigned long long)s->lookups,(unsigned long long)s->hits,(unsigned long long)s->misses,
           (unsigned long long)s->records,(unsigned long long)s->invalidations,(unsigned long long)s->flushes,
           (unsigned long long)s->sampled,(unsigned long long)s->mismatches);
    CHECK(s->hits>s->misses && s->invalidations && s->flushes && s->sampled && !s->mismatches,
          "coverage or a mismatch (published changes must never reach a sampled scan)");
    free(p->a.ram);free(p->b.ram);free(p);
}

/* An unpublished write: refused within one sampling period of hits. */
static void silent(void)
{
    struct pair *p=calloc(1,sizeof(*p));
    pair_init(p,31);add_leaf(p);
    for(unsigned i=0;i<1500;i++) {
        put(&p->a,LIST+8*0,DATA(i%DATA_FRAMES));put(&p->b,LIST+8*0,DATA(i%DATA_FRAMES));
        BOTH(ref_sptm_dart_map(&p->a.m,&p->a.state,31,0,p->leaf_iova[0]+(uint64_t)i*0x4000,LIST,0x4000,0),
             sptm_dart_map(&p->b.m,&p->b.state,31,0,p->leaf_iova[0]+(uint64_t)i*0x4000,LIST,0x4000,0),"fill");
    }
    /* A published store to the leaf table's frame record drops its entry, even
     * one that leaves the record as it was (frame() and the refs comparison
     * would see any real change; the witness must not depend on that). */
    uint64_t before=p->b.memo.stats.invalidations,record=FM+((TABLE(1)-BASE)>>14)*16;
    publish(&p->b,record,16);
    CHECK(p->b.memo.stats.invalidations==before+1,"a published frame-record store kept the entry");
    publish(&p->b,record+16,16);   /* the next frame's record: not this table's */
    CHECK(p->b.memo.stats.invalidations==before+1,"a neighbouring record store dropped the entry");
    put(&p->a,LIST,DATA(0));put(&p->b,LIST,DATA(0));
    BOTH(ref_sptm_dart_map(&p->a.m,&p->a.state,31,0,p->leaf_iova[0]+1500*0x4000,LIST,0x4000,0),
         sptm_dart_map(&p->b.m,&p->b.state,31,0,p->leaf_iova[0]+1500*0x4000,LIST,0x4000,0),"after a record store");
    /* An unpublished reference-count change is refused at once: the lookup
     * compares refs, so it cannot hit. Then put back. */
    meta_of(&p->a,TABLE(1))[4]++;meta_of(&p->b,TABLE(1))[4]++;
    BOTH(ref_sptm_dart_map(&p->a.m,&p->a.state,31,0,p->leaf_iova[0]+1501*0x4000,LIST,0x4000,0),
         sptm_dart_map(&p->b.m,&p->b.state,31,0,p->leaf_iova[0]+1501*0x4000,LIST,0x4000,0),"unpublished refs");
    meta_of(&p->a,TABLE(1))[4]--;meta_of(&p->b,TABLE(1))[4]--;
    uint64_t bad=TABLE(1)+8*2047;   /* the leaf table, a free slot */
    put(&p->a,bad,3);put(&p->b,bad,3);   /* bits outside the descriptor: no publish */
    unsigned refused_at=0;
    for(unsigned i=0;i<256 && !refused_at;i++) {         /* 4 sampling periods of 64 */
        uint64_t iova=p->leaf_iova[0]+(uint64_t)(1600+i%400)*0x4000;
        enum sptm_result ra=ref_sptm_dart_map(&p->a.m,&p->a.state,31,0,iova,LIST,0x4000,0);
        enum sptm_result rb=sptm_dart_map(&p->b.m,&p->b.state,31,0,iova,LIST,0x4000,0);
        CHECK(ra==SPTM_BAD_TABLE,"the reference accepted a corrupted table");
        if(rb==SPTM_BAD_TABLE)refused_at=i+1;
        if(rb==SPTM_OK)sptm_dart_unmap(&p->b.m,&p->b.state,31,0,iova,0x4000,0);
    }
    printf("silent corruption: refused after %u calls, mismatches %llu\n",refused_at,
           (unsigned long long)p->b.memo.stats.mismatches);
    CHECK(refused_at && refused_at<=128 && p->b.memo.stats.mismatches>=1,
          "an unpublished corruption outlived the sampling bound");
    free(p->a.ram);free(p->b.ram);free(p);
}

static double now(void) {struct timespec t;clock_gettime(CLOCK_MONOTONIC,&t);return t.tv_sec+t.tv_nsec*1e-9;}
static int speed(void)
{
    struct pair *p=calloc(1,sizeof(*p));
    pair_init(p,31);add_leaf(p);
    for(unsigned i=0;i<2000;i++) {
        put(&p->a,LIST,DATA(i%DATA_FRAMES));put(&p->b,LIST,DATA(i%DATA_FRAMES));
        ref_sptm_dart_map(&p->a.m,&p->a.state,31,0,p->leaf_iova[0]+(uint64_t)i*0x4000,LIST,0x4000,0);
        sptm_dart_map(&p->b.m,&p->b.state,31,0,p->leaf_iova[0]+(uint64_t)i*0x4000,LIST,0x4000,0);
    }
    double best[2]={1e9,1e9};
    for(unsigned rep=0;rep<5;rep++)for(unsigned w=0;w<2;w++) {
        struct world *x=w ? &p->b : &p->a;
        double t0=now();
        for(unsigned i=0;i<2000;i++) {
            uint64_t iova=p->leaf_iova[0]+(uint64_t)(2000+i%40)*0x4000;
            if(w){sptm_dart_map(&x->m,&x->state,31,0,iova,LIST,0x4000,0);sptm_dart_unmap(&x->m,&x->state,31,0,iova,0x4000,0);}
            else {ref_sptm_dart_map(&x->m,&x->state,31,0,iova,LIST,0x4000,0);
                  ref_sptm_dart_unmap(&x->m,&x->state,31,0,iova,0x4000,0);}
        }
        double t=(now()-t0)/2000;if(t<best[w])best[w]=t;
    }
    printf("speed: MAP+UNMAP of one page into a 2,000-entry level-2 table: %.2f us without the memo, "
           "%.2f us with it (%.1fx)\n",best[0]*1e6,best[1]*1e6,best[0]/best[1]);
    CHECK(best[1]*4<=best[0],"the memo is not 4x faster");
    CHECK(same(p),"the speed run left the worlds different");
    free(p->a.ram);free(p->b.ram);free(p);
    return failures!=0;
}

int main(int argc,char **argv)
{
    if(argc>1 && !strcmp(argv[1],"--speed"))return speed();
    unsigned steps=argc>1 ? (unsigned)strtoul(argv[1],0,0) : 40000;
    differential(31,steps);
    differential(21,steps);
    silent();
    if(failures) {printf("FAIL: %lu of %lu checks\n",failures,checks);return 1;}
    printf("PASS: %lu checks\n",checks);
    return 0;
}

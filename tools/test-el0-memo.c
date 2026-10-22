/* SPDX-License-Identifier: MIT */
/* SNAP_EL0_MEMO, offline: compat/el0-memo.h (the EL0 read's fetch memo),
 * compat/fast-vector.h with FAST_CROSS_EL0_MEMO (a proven fetch skips the
 * repeat read) and compat/pauth-domain.c pauth_domain_user_cached_wide (the
 * second-level derivation cache). Built and run by tools/test-el0-memo.py
 * (ASan/UBSan); pauth-domain.c is linked twice, once renamed ref_* without the
 * define, as the reference derivation.
 *
 * Written before the implementation. Failure modes (the batch-6 EL0 memo note,
 * FAILURES-AND-DESIGN.md section 4):
 *  A3  a replay that accepts although a descriptor either walk would read now
 *      differs, or refuses although none does (every recorded address re-read,
 *      in order, through the walk's reader);
 *  A4  a replay accepted under another identity (entry, roots, granule, reader);
 *  A1  a way used after this vCPU installed a root or its active root changed;
 *  A8  a record kept that is not the last full read's (pending cleared by every
 *      lookup and begin; kept only complete, for the same page, root and
 *      install count), or kept twice for one page;
 *  A9  another PC of the same 4K page answered with a different translation;
 *      a record with more reads than levels, or none, kept;
 *  A12 fast_el0_sysreg with a proven fetch: anything but the single read,
 *      or an ordinary fetch without its repeat read;
 *  B1  a derivation-cache answer other than pauth_domain_user_with's for the
 *      same inputs (pools within the first level, within and beyond the
 *      second, forced set collisions, one-word changes);
 *  B2  an answer kept across a domain epoch change (both levels);
 *  B5  counters: hits + misses = answered calls, misses = derivations;
 *  B6  a refusal that touched either level. */
#include "el0-memo.h"
#include "fast-vector.h"
#include "pauth-domain.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static unsigned long checks;
#define CHECK(x) do { if(!(x)) {fprintf(stderr,"FAIL %s:%d: %s\n",__FILE__,__LINE__,#x);abort();} checks++; } while(0)

static uint64_t seed=0x9e3779b97f4a7c15ULL;
static uint64_t rnd(void) {seed^=seed<<13;seed^=seed>>7;seed^=seed<<17;return seed;}

/* ---- a guest RAM of table pages ---------------------------------------- */
#define PAGES 1024u
#define BASE UINT64_C(0x880000000)
static uint64_t ram[PAGES][512];
static unsigned used;
static unsigned long ram_reads;
static int ram_read(void *ctx,uint64_t pa,uint64_t *out)
{
    (void)ctx;
    if((pa&7) || pa<BASE || pa>=BASE+(uint64_t)PAGES*4096)return -1;
    ram_reads++;
    *out=ram[(pa-BASE)/4096][(pa&4095)/8];
    return 0;
}
static uint64_t *slot_of(uint64_t pa) {return &ram[(pa-BASE)/4096][(pa&4095)/8];}
/* n zeroed pages, aligned to n (1 or 4). */
static uint64_t alloc(unsigned n)
{
    used=(used+n-1)/n*n;
    assert(used+n<=PAGES);
    uint64_t pa=BASE+(uint64_t)used*4096;
    memset(ram[used],0,(size_t)n*4096);used+=n;
    return pa;
}
#define LEAF_BITS (PT_AF|PT_AP|PT_PXN|PT_SH|(UINT64_C(1)<<2))
/* Map va's page to frame (a 16K-aligned PA) in cfg's tree. */
static void map(const struct mmu_config *cfg,uint64_t va,uint64_t frame)
{
    unsigned table_pages=cfg->granule_shift==14 ? 4 : 1;
    uint64_t table=cfg->root;
    for(int level=mmu_start_level(cfg->granule_shift,cfg->txsz);level<3;level++) {
        uint64_t *d=slot_of(table+8*mmu_index(cfg->granule_shift,(uint32_t)level,va));
        if(!(*d&1))*d=alloc(table_pages)|3;
        table=*d&PT_OA_MASK;
    }
    uint64_t size=mmu_level_size(cfg->granule_shift,3);
    *slot_of(table+8*mmu_index(cfg->granule_shift,3,va))=((frame|(va&0x3fff))&PT_OA_MASK&~(size-1))|LEAF_BITS|3;
}

/* A fresh walk's read sequence, through the recording reader. */
static int walk_reads(const struct mmu_config *cfg,uint64_t va,struct el0_memo_walk *w,struct mmu_leaf *leaf)
{
    memset(w,0,sizeof *w);
    struct el0_memo_reader r={ram_read,0,w};
    return mmu_walk(cfg,va,el0_memo_read,&r,leaf);
}
static int same_walk(const struct el0_memo_walk *a,const struct el0_memo_walk *b)
{
    if(a->reads!=b->reads || a->overflow!=b->overflow)return 0;
    for(unsigned i=0;i<a->reads;i++)if(a->at[i]!=b->at[i] || a->value[i]!=b->value[i])return 0;
    return 1;
}

static int dummy_entry[4];
#define ACTIVE UINT64_C(0x8d592c000)

/* Record pc through both trees the way fast_el0_word's full read does, and keep it. */
static struct el0_memo_entry *record(struct el0_memo_cpu *m,const struct mmu_config *s,const struct mmu_config *h,
                                     unsigned kind,uint64_t pc)
{
    el0_memo_begin(m,pc,ACTIVE);
    CHECK(m->recording==1 && !m->pending.valid);
    struct el0_memo_reader rs={ram_read,0,&m->pending.walk[0]},rh={ram_read,0,&m->pending.walk[1]};
    struct mmu_leaf a,b;
    CHECK(!mmu_walk(s,pc,el0_memo_read,&rs,&a) && a.valid && a.level==3);
    CHECK(!mmu_walk(h,pc,el0_memo_read,&rh,&b) && b.valid && b.level==3 && a.pa==b.pa);
    el0_memo_recorded(m,&dummy_entry[0],s->root,s->granule_shift,h->root,kind,a.descriptor,b.descriptor,a.pa);
    el0_memo_end(m,1);
    CHECK(!m->recording && m->pending.valid);
    uint64_t fills=m->stats.fills;
    el0_memo_keep(m,pc,s->root);
    CHECK(m->stats.fills==fills+1 && !m->pending.valid);
    struct el0_memo_entry *w=el0_memo_find(m,pc);
    CHECK(w && w->valid && w->page==(pc&~UINT64_C(0xfff)) && w->page_pa==(a.pa&~UINT64_C(0xfff)));
    CHECK(w->source_leaf==a.descriptor && w->hardware_leaf==b.descriptor && w->entry==&dummy_entry[0]);
    return w;
}

static void test_replay_model(void)
{
    unsigned accepted=0,refused=0;
    for(unsigned trial=0;trial<4000;trial++) {
        used=0;
        unsigned shift=rnd()%2 ? 12 : 14,shared=shift==12 && rnd()%2;
        struct mmu_config s={shift,17,alloc(shift==14 ? 4 : 1)};
        struct mmu_config h=shared ? s : (struct mmu_config){12,17,alloc(1)};
        uint64_t vas[24];
        for(unsigned n=0;n<24;n++) {
            /* Clustered user VAs, so tables are shared between mappings. */
            uint64_t va=(UINT64_C(0x180000000)+((rnd()%(n<12 ? 64 : 1u<<20))<<12))&((UINT64_C(1)<<47)-1);
            /* One frame per 16K region, so both granules agree on every 4K page. */
            uint64_t frame=UINT64_C(0x900000000)+((((va>>14)*UINT64_C(0x9e3779b97f4a7c15))>>52)<<14);
            vas[n]=va;map(&s,va,frame);if(!shared)map(&h,va,frame);
        }
        struct el0_memo_cpu m;memset(&m,0,sizeof m);
        uint64_t pc=(vas[rnd()%24]&~UINT64_C(0xfff))|((rnd()%1024)*4);
        struct el0_memo_entry *w=record(&m,&s,&h,shared,pc);
        CHECK(el0_memo_current(&m,w,ACTIVE));
        CHECK(el0_memo_check(w,&dummy_entry[0],s.root,shift,h.root,shared,ram_read,0,ram_read,0));
        /* A4: any other identity refuses. */
        CHECK(!el0_memo_check(w,&dummy_entry[1],s.root,shift,h.root,shared,ram_read,0,ram_read,0));
        CHECK(!el0_memo_check(w,&dummy_entry[0],s.root^0x4000,shift,h.root,shared,ram_read,0,ram_read,0));
        CHECK(!el0_memo_check(w,&dummy_entry[0],s.root,shift^6,h.root,shared,ram_read,0,ram_read,0));
        CHECK(!el0_memo_check(w,&dummy_entry[0],s.root,shift,h.root^0x1000,shared,ram_read,0,ram_read,0));
        CHECK(!el0_memo_check(w,&dummy_entry[0],s.root,shift,h.root,!shared,ram_read,0,ram_read,0));
        /* A3: one mutation, then accept iff both fresh read sequences are the recorded ones. */
        unsigned k=rnd()%2,i=w->walk[k].reads ? (unsigned)(rnd()%w->walk[k].reads) : 0;
        switch(rnd()%8) {
        case 0: break;                                                     /* nothing */
        case 1: *slot_of(w->walk[k].at[i])^=UINT64_C(1)<<(rnd()%64);break; /* one recorded bit */
        case 2: *slot_of(w->walk[k].at[i])=rnd();break;                     /* a recorded word */
        case 3: {                                                          /* an unrelated word */
            uint64_t pa=BASE+(rnd()%used)*4096+(rnd()%512)*8;
            *slot_of(pa)^=UINT64_C(1)<<(rnd()%64);break;
        }
        case 4: if(i+1<w->walk[k].reads) {                                 /* a relink to an equal copy */
                uint64_t child=w->walk[k].value[i]&PT_OA_MASK;
                unsigned n=(k==0 && shift==14) ? 4 : 1;
                uint64_t copy=alloc(n);
                memcpy(ram[(copy-BASE)/4096],ram[(child-BASE)/4096],(size_t)n*4096);
                *slot_of(w->walk[k].at[i])=(w->walk[k].value[i]&~PT_OA_MASK)|copy;
            }
            break;
        case 5: *slot_of(w->walk[k].at[w->walk[k].reads-1])&=~UINT64_C(1);break;   /* leaf invalid */
        case 6: *slot_of(w->walk[k].at[w->walk[k].reads-1])^=UINT64_C(1)<<(14+rnd()%20);break; /* leaf OA */
        case 7: map(&s,vas[rnd()%24]^((rnd()%8)<<12),UINT64_C(0x940000000)+((rnd()%64)<<14));break;
        }
        struct el0_memo_walk fs,fh;struct mmu_leaf a,b;
        int rs=walk_reads(&s,pc,&fs,&a),rh=walk_reads(&h,pc,&fh,&b);
        int same=same_walk(&fs,&w->walk[0]) && same_walk(&fh,&w->walk[1]);
        int ok=el0_memo_check(w,&dummy_entry[0],s.root,shift,h.root,shared,ram_read,0,ram_read,0);
        CHECK(ok==same);
        if(!ok) {refused++;continue;}
        accepted++;
        CHECK(!rs && !rh);
        /* A9: every PC of the page translates as recorded. */
        for(unsigned n=0;n<8;n++) {
            uint64_t other=w->page|((rnd()%1024)*4);
            CHECK(!mmu_walk(&s,other,ram_read,0,&a) && a.valid && a.level==3 && a.descriptor==w->source_leaf);
            CHECK(!mmu_walk(&h,other,ram_read,0,&b) && b.valid && b.level==3 && b.descriptor==w->hardware_leaf);
            CHECK(a.pa==(w->page_pa|(other&0xfff)) && b.pa==a.pa);
        }
    }
    CHECK(accepted>500 && refused>500);
    printf("replay model: %u accepted, %u refused\n",accepted,refused);
}

static void test_semantics(void)
{
    used=0;
    struct mmu_config s={12,17,alloc(1)};
    for(unsigned n=0;n<8;n++)map(&s,UINT64_C(0x180000000)+((uint64_t)n<<12),UINT64_C(0x900000000)+((uint64_t)n<<14));
    struct el0_memo_cpu m;memset(&m,0,sizeof m);
    uint64_t pc=UINT64_C(0x180000040);
    CHECK(!el0_memo_find(&m,pc) && m.stats.absent==1);
    struct el0_memo_entry *w=record(&m,&s,&s,1,pc);
    /* A1: an install, or another active root, makes the way stale. */
    CHECK(el0_memo_current(&m,w,ACTIVE) && !el0_memo_current(&m,w,ACTIVE+0x4000));
    el0_memo_installed(&m);
    CHECK(!el0_memo_current(&m,w,ACTIVE));
    w=record(&m,&s,&s,1,pc);
    CHECK(el0_memo_current(&m,w,ACTIVE));
    /* A8: one way per page; a lookup clears the pending record. */
    unsigned ways=0;
    for(unsigned n=0;n<EL0_MEMO_WAYS;n++)ways+=m.way[n].valid && m.way[n].page==(pc&~UINT64_C(0xfff));
    CHECK(ways==1);
    el0_memo_begin(&m,pc,ACTIVE);m.pending.valid=1;
    CHECK(el0_memo_find(&m,pc)==w && !m.pending.valid);
    /* Not kept: no pending; another page; another root; an install between. */
    uint64_t fills=m.stats.fills;
    el0_memo_keep(&m,pc,s.root);CHECK(m.stats.fills==fills);
    uint64_t pc2=UINT64_C(0x180001010);
    el0_memo_begin(&m,pc2,ACTIVE);
    struct el0_memo_reader r={ram_read,0,&m.pending.walk[0]},r2={ram_read,0,&m.pending.walk[1]};
    struct mmu_leaf a,b;
    CHECK(!mmu_walk(&s,pc2,el0_memo_read,&r,&a) && !mmu_walk(&s,pc2,el0_memo_read,&r2,&b));
    el0_memo_recorded(&m,&dummy_entry[0],s.root,12,s.root,1,a.descriptor,b.descriptor,a.pa);
    el0_memo_end(&m,1);
    struct el0_memo_entry saved=m.pending;
    el0_memo_keep(&m,pc2+0x1000,s.root);CHECK(m.stats.fills==fills);
    m.pending=saved;el0_memo_keep(&m,pc2,s.root+0x4000);CHECK(m.stats.fills==fills);
    m.pending=saved;el0_memo_installed(&m);el0_memo_keep(&m,pc2,s.root);CHECK(m.stats.fills==fills);
    /* A failed read keeps nothing. */
    m.pending=saved;m.pending.installs=m.installs;m.recording=1;el0_memo_end(&m,0);
    CHECK(!m.pending.valid && !m.recording);
    el0_memo_keep(&m,pc2,s.root);CHECK(m.stats.fills==fills);
    /* A9: more reads than levels, or none, never complete a record. */
    struct el0_memo_walk over;memset(&over,0,sizeof over);
    struct el0_memo_reader ro={ram_read,0,&over};uint64_t v;
    for(unsigned n=0;n<EL0_MEMO_READS+1;n++)CHECK(!el0_memo_read(&ro,s.root,&v));
    CHECK(over.reads==EL0_MEMO_READS && over.overflow);
    CHECK(!el0_memo_replay(&over,ram_read,0));
    el0_memo_begin(&m,pc2,ACTIVE);m.pending.walk[0]=over;m.pending.walk[1]=over;m.pending.walk[1].overflow=0;
    el0_memo_recorded(&m,&dummy_entry[0],s.root,12,s.root,1,1,1,0x900000000);el0_memo_end(&m,1);
    CHECK(!m.pending.valid);
    el0_memo_begin(&m,pc2,ACTIVE);
    el0_memo_recorded(&m,&dummy_entry[0],s.root,12,s.root,1,1,1,0x900000000);el0_memo_end(&m,1);
    CHECK(!m.pending.valid);
    struct el0_memo_walk none;memset(&none,0,sizeof none);
    CHECK(!el0_memo_replay(&none,ram_read,0));
    /* A failing reader refuses. */
    struct el0_memo_walk bad=m.way[0].walk[0];bad.at[0]=1;
    CHECK(!el0_memo_replay(&bad,ram_read,0));
    /* Replacement: round robin over distinct pages; a dropped way is gone. */
    memset(&m,0,sizeof m);
    for(unsigned n=0;n<EL0_MEMO_WAYS+1;n++)record(&m,&s,&s,1,UINT64_C(0x180000000)+((uint64_t)n<<12)+8);
    CHECK(!el0_memo_find(&m,UINT64_C(0x180000008)));
    for(unsigned n=1;n<EL0_MEMO_WAYS+1;n++)CHECK(el0_memo_find(&m,UINT64_C(0x180000000)+((uint64_t)n<<12)));
    w=el0_memo_find(&m,UINT64_C(0x180001000));
    el0_memo_drop(w);
    CHECK(!el0_memo_find(&m,UINT64_C(0x180001000)));
}

/* ---- fast_el0_sysreg with FAST_CROSS_EL0_MEMO --------------------------- */
#define UPERM_READ 0xd53ef1a0u
#define CLOCK_WORD 0xd53cfac0u
struct fetch_env { int ret[2];uint32_t word[2];unsigned calls,notes; };
static int env_fetch(void *ctx,uint64_t pc,struct fast_el0_fetch *out)
{
    struct fetch_env *e=ctx;(void)pc;
    unsigned n=e->calls++;
    if(n>1)return 0;
    if(e->ret[n])*out=(struct fast_el0_fetch){0x11,0x22,0x9000000c0,ACTIVE,e->word[n]};
    return e->ret[n];
}
static void env_note(void *ctx,unsigned kind,uint64_t pc,uint32_t word,uint64_t saved,uint64_t root)
{struct fetch_env *e=ctx;(void)kind;(void)pc;(void)word;(void)saved;(void)root;e->notes++;}
static uint64_t env_counter(void *ctx) {(void)ctx;return UINT64_C(0x123456789);}
static int env_control(void *ctx,uint64_t value) {(void)ctx;(void)value;return 0;}

static unsigned run_sysreg(struct fetch_env *e,int sprr_ok,uint64_t regs[32])
{
    struct clock_backend clock={e,env_counter,env_control};
    struct guest_clock gc;memset(&gc,0,sizeof gc);gc.cntkctl=3;
    struct sprr_state sprr;memset(&sprr,0,sizeof sprr);
    if(sprr_ok)sprr_root_reset(&sprr,8);
    uint64_t outcomes[FAST_EL0_RESULTS-1]={0},spsr=0xdead,elr=0;
    const struct fast_el0_hw hw={.ctx=e,.fetch=env_fetch,.clock=&clock,.note=env_note};
    const struct fast_el0_vcpu v={&gc,&sprr,regs,outcomes,&spsr};
    const uint64_t vhcr=(UINT64_C(1)<<34)|(UINT64_C(1)<<31)|(UINT64_C(1)<<27);
    unsigned r=fast_el0_sysreg(&hw,&v,0x400,FAST_EL0_SYSREG_ESR,UINT64_C(0x180000000),0x20000000,vhcr,&elr);
    CHECK(outcomes[r-1]==1);
    if(r==FAST_EL0_CLOCK || r==FAST_EL0_UPERM)CHECK(elr==UINT64_C(0x180000004) && spsr==0x20000000);
    else CHECK(elr==0 && spsr==0xdead);
    return r;
}
static void test_sysreg(void)
{
    uint64_t regs[32];
    struct fetch_env e;
    /* A proven fetch is the only read. */
    memset(&e,0,sizeof e);e.ret[0]=FAST_EL0_FETCH_PROVEN;e.word[0]=UPERM_READ|5;memset(regs,0,sizeof regs);
    CHECK(run_sysreg(&e,1,regs)==FAST_EL0_UPERM && e.calls==1 && e.notes==1);
    memset(&e,0,sizeof e);e.ret[0]=FAST_EL0_FETCH_PROVEN;e.word[0]=CLOCK_WORD|7;
    CHECK(run_sysreg(&e,1,regs)==FAST_EL0_CLOCK && e.calls==1 && e.notes==1);
    /* An ordinary fetch keeps its repeat read, and a disagreement declines. */
    memset(&e,0,sizeof e);e.ret[0]=e.ret[1]=1;e.word[0]=e.word[1]=UPERM_READ|5;
    CHECK(run_sysreg(&e,1,regs)==FAST_EL0_UPERM && e.calls==2 && e.notes==1);
    memset(&e,0,sizeof e);e.ret[0]=e.ret[1]=1;e.word[0]=UPERM_READ|5;e.word[1]=UPERM_READ|6;
    CHECK(run_sysreg(&e,1,regs)==FAST_EL0_GUARD && e.calls==2 && !e.notes);
    memset(&e,0,sizeof e);e.ret[0]=1;e.word[0]=UPERM_READ|5;
    CHECK(run_sysreg(&e,1,regs)==FAST_EL0_GUARD && e.calls==2 && !e.notes);
    /* A proven fetch still goes through every guard. */
    memset(&e,0,sizeof e);e.ret[0]=FAST_EL0_FETCH_PROVEN;e.word[0]=UPERM_READ|5;
    CHECK(run_sysreg(&e,0,regs)==FAST_EL0_GUARD && e.calls==1 && !e.notes);
    memset(&e,0,sizeof e);e.ret[0]=FAST_EL0_FETCH_PROVEN;e.word[0]=0xd51ef1a0u|5;
    CHECK(run_sysreg(&e,1,regs)==FAST_EL0_WORD && e.calls==1 && !e.notes);
    memset(&e,0,sizeof e);
    CHECK(run_sysreg(&e,1,regs)==FAST_EL0_GUARD && e.calls==1 && !e.notes);
}

/* ---- the derivation cache ------------------------------------------------ */
int ref_pauth_domain_user_with(const struct pauth_domain *,const struct pauth_user_state *,
                               struct pauth_key_pair output[PAUTH_KEYS],int hardware);
static void random_state(struct pauth_user_state *s)
{
    memset(s,0,sizeof *s);
    for(unsigned k=0;k<PAUTH_KEYS;k++)s->key[k]=(struct pauth_key_pair){rnd(),rnd()};
    s->extra=(struct pauth_key_pair){rnd(),rnd()};s->apctl=0x11;s->writes=rnd();
}
struct derive_run { struct pauth_derive_cache l1;struct pauth_derive_wide wide;unsigned long calls; };
static void derive_one(const struct pauth_domain *d,struct derive_run *r,const struct pauth_user_state *s,uint64_t epoch)
{
    struct pauth_key_pair got[PAUTH_KEYS],want[PAUTH_KEYS];
    CHECK(ref_pauth_domain_user_with(d,s,want,0));
    memset(got,0xa5,sizeof got);
    CHECK(pauth_domain_user_cached_wide(d,s,&r->l1,&r->wide,epoch,got,0));
    CHECK(!memcmp(got,want,sizeof got));
    r->calls++;
    CHECK(r->l1.hits+r->l1.misses==r->calls && r->wide.derived==r->l1.misses && r->wide.hits<=r->l1.hits);
}
static void test_derive(void)
{
    uint8_t key[32];for(unsigned i=0;i<32;i++)key[i]=(uint8_t)(0x40+i*7);
    struct pauth_domain d;memset(&d,0,sizeof d);CHECK(pauth_domain_init(&d,key));
    static struct derive_run r;
    static struct pauth_user_state pool[700];
    for(unsigned n=0;n<700;n++)random_state(&pool[n]);
    const unsigned sizes[]={4,40,100,700};
    for(unsigned z=0;z<4;z++) {
        memset(&r,0,sizeof r);
        unsigned p=sizes[z];
        for(unsigned pass=0;pass<4;pass++)
            for(unsigned n=0;n<p;n++)derive_one(&d,&r,&pool[(n*7+pass)%p],1);
        /* Within the second level's capacity only sets with more than WAYS
         * members miss again; beyond it, misses but always exact answers. */
        unsigned crowded=0,count[PAUTH_DERIVE_WIDE_SETS]={0};
        for(unsigned n=0;n<p;n++)count[pauth_derive_wide_set(&pool[n])]++;
        for(unsigned set=0;set<PAUTH_DERIVE_WIDE_SETS;set++)
            if(count[set]>PAUTH_DERIVE_WIDE_WAYS)crowded+=count[set];
        if(p<=PAUTH_DERIVE_CACHE)CHECK(r.l1.misses==p && !r.wide.hits);
        else if(!crowded)CHECK(r.l1.misses==p);
        else CHECK(r.l1.misses<=p+3*crowded);
        printf("derive pool %u: %lu calls, %lu derivations, %lu second-level hits\n",
               p,r.calls,(unsigned long)r.l1.misses,(unsigned long)r.wide.hits);
    }
    /* B1: forced collisions (nine states of one set) and one-word changes. */
    memset(&r,0,sizeof r);
    struct pauth_user_state same[9];unsigned found=0,want=pauth_derive_wide_set(&pool[0]);
    for(unsigned n=0;n<700 && found<9;n++)if(pauth_derive_wide_set(&pool[n])==want)same[found++]=pool[n];
    while(found<9) {struct pauth_user_state t;random_state(&t);if(pauth_derive_wide_set(&t)==want)same[found++]=t;}
    for(unsigned pass=0;pass<5;pass++)for(unsigned n=0;n<9;n++)derive_one(&d,&r,&same[n],1);
    for(unsigned n=0;n<2000;n++) {
        struct pauth_user_state t=pool[rnd()%40];
        uint64_t *words=(uint64_t *)&t;unsigned w=(unsigned)(rnd()%13);   /* key[5], extra: 12 words, then apctl */
        if(w<12)words[w]^=UINT64_C(1)<<(rnd()%64);
        derive_one(&d,&r,&t,1);
    }
    /* B2: an epoch change flushes both levels. */
    memset(&r,0,sizeof r);
    derive_one(&d,&r,&pool[0],1);derive_one(&d,&r,&pool[0],1);
    CHECK(r.l1.misses==1 && r.l1.hits==1);
    derive_one(&d,&r,&pool[0],2);
    CHECK(r.l1.misses==2 && r.wide.flushes==2 && r.wide.epoch==2);
    for(unsigned n=0;n<PAUTH_DERIVE_CACHE+2;n++)derive_one(&d,&r,&pool[n+1],2);
    derive_one(&d,&r,&pool[0],2);   /* out of the 8-entry level, in the second */
    CHECK(r.wide.hits==1);
    derive_one(&d,&r,&pool[0],2);   /* and back in the first */
    CHECK(r.wide.hits==1);
    /* B6: refusals touch nothing. */
    struct derive_run before=r;struct pauth_key_pair out[PAUTH_KEYS];
    struct pauth_domain none;memset(&none,0,sizeof none);
    CHECK(!pauth_domain_user_cached_wide(&none,&pool[0],&r.l1,&r.wide,2,out,0));
    struct pauth_user_state bad=pool[0];bad.apctl=0x10;
    CHECK(!pauth_domain_user_cached_wide(&d,&bad,&r.l1,&r.wide,2,out,0));
    CHECK(!pauth_domain_user_cached_wide(&d,&pool[0],&r.l1,&r.wide,2,out,2));
    CHECK(!pauth_domain_user_cached_wide(&d,&pool[0],&r.l1,&r.wide,0,out,0));
    CHECK(!pauth_domain_user_cached_wide(&d,&pool[0],0,&r.wide,2,out,0));
    CHECK(!pauth_domain_user_cached_wide(&d,&pool[0],&r.l1,0,2,out,0));
    CHECK(!memcmp(&before,&r,sizeof r));
}

int main(void)
{
    test_semantics();
    test_replay_model();
    test_sysreg();
    test_derive();
    printf("PASS: %lu checks\n",checks);
    return 0;
}

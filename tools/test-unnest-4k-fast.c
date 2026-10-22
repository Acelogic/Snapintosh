/* SPDX-License-Identifier: MIT */
/* SNAP_UNNEST_4K_FAST (compat/nest-fast.h, docs/UNNEST-4K-FAST-20261020.md):
 * UNNEST_REGION on 4K (format 1) user roots answers nested shared level-3
 * tables, and their mapped-leaf counts, from the SWITCH_ROOT memo. Exercised
 * on the real format-1 NEST/UNNEST fixtures (test-sptm-nest.c), with the memo
 * and its write witness wired as the monitor wires them and a backend shaped
 * like the hardware-walk route's hw_prepare/commit_nest/unnest (the plan is
 * recorded; there is no shadow).
 *
 * The oracle is the build without the define: tools/test-unnest-4k-fast.py
 * builds this file with and without it and requires every "step" line
 * (result, the plan's descriptors and leaves, and a digest of all fixture
 * memory) to be identical. Lines starting with '#' are a build's own checks
 * and counters and are not compared. Scenarios are seeded and deterministic:
 * four consumers with root flags 2, 3, 0xa and 0xb; shared 4K tables holding
 * four-page groups of one 16K data frame, single pages, compressed markers,
 * invalid nonzero descriptors, policy failures and unmanaged frames; full and
 * partial NEST/UNNEST; published leaf changes in each of a frame's four
 * tables; root-flag toggles; a mapped-frame retype (the memo epoch); a store
 * published by a large range; locked and unmappable tables. The failure
 * modes U1-U11 are in the document; the checks below name them. */
#define SPTM_NEST_TEST_MAIN nest_fixture_checks
#include "test-sptm-nest.c"
#include "sptm-root-memo.h"
#if SNAP_NEST_FAST || SNAP_DETACH_FAST
#include "nest-fast.h"
static struct sptm_nest_fast_stats st;
#endif
#ifndef SNAP_UNNEST_4K_FAST
#define SNAP_UNNEST_4K_FAST 0
#endif
static struct sptm_root_memo memo;
/* The monitor's sptm_publish: every SPTM store reaches the memo's witness. */
static void witness(void *ctx,uint64_t pa,uint64_t size)
{
    published++;
    sptm_root_memo_publish(&memo,m.frame_map_pa,m.frame_low,m.frame_high,map,ctx,pa,size);
}
static uint64_t rng;
static uint64_t rnd(void) {rng^=rng<<13;rng^=rng>>7;rng^=rng<<17;return rng;}

/* ---- the hardware-walk route's backend: no shadow, the plan recorded. */
static struct sptm_unnest_plan last_plan;
static uint64_t nest_commits,unnest_commits,plan_leaves,plan_descriptors;
static int cap_prepare_nest(void *ctx,uint64_t root,uint64_t shared,uint64_t va,unsigned shift,uint64_t pages)
{(void)ctx;(void)root;(void)shared;(void)va;(void)pages;return shift==12;}
static int cap_commit_nest(void *ctx,uint64_t root,uint64_t shared,uint64_t va,unsigned shift,uint64_t pages)
{(void)ctx;(void)root;(void)shared;(void)va;(void)shift;(void)pages;nest_commits++;return 1;}
static int cap_prepare_unnest(void *ctx,uint64_t root,uint64_t shared,unsigned shift,const struct sptm_unnest_plan *p)
{(void)ctx;(void)root;(void)shared;(void)p;return shift==12;}
static int cap_commit_unnest(void *ctx,uint64_t root,uint64_t shared,unsigned shift,const struct sptm_unnest_plan *p)
{
    (void)ctx;(void)root;(void)shared;(void)shift;
    last_plan=*p;unnest_commits++;plan_leaves+=p->leaves;plan_descriptors+=p->descriptors;return 1;
}

#define CONSUMERS 4u
static const unsigned consumer_flags[CONSUMERS]={2,3,0xa,0xb};
static uint64_t consumer[CONSUMERS];
static unsigned groups;                                 /* 16K frames of four shared 4K tables */
#define SPAN4 UINT64_C(0x200000)                        /* one 4K level-3 table */
#define DMASK UINT64_C(0x0000ffffffffc000)
#define LEAF UINT64_C(0x0060000000000fc3)               /* DEFAULT data, RO NX (class 15) */
#define LEAF_RW (LEAF&~UINT64_C(0x80))                  /* DEFAULT data, RW NX (class 7) */
#define EXEC UINT64_C(0x0020000000000fc3)               /* USER_EXEC data, RO+X (class 13) */
#define NDATA 24u
static uint64_t data_frame[NDATA];
static uint64_t child_of(unsigned t) {return word(slot_at(ROOT,2,START+t*SPAN4))&geom.pa_mask;}
static uint64_t record_pa(uint64_t pa) {return m.frame_map_pa+((pa-BASE)>>14)*16;}
static uint64_t digest(void)
{
    uint64_t h=UINT64_C(0xcbf29ce484222325);
    for(size_t i=0;i<sizeof(bytes);i+=8) {uint64_t w;memcpy(&w,bytes+i,8);h=(h^w)*UINT64_C(0x100000001b3);}
    uint64_t extra[]={registry.bindings,nest_commits,unnest_commits,plan_leaves,plan_descriptors,
                      last_plan.leaves,last_plan.descriptors,last_plan.base,last_plan.count};
    for(unsigned i=0;i<sizeof(extra)/8;i++)h=(h^extra[i])*UINT64_C(0x100000001b3);
    return h;
}
static unsigned step_no;
static void step(const char *what,int r)
{
    printf("step %u %s r=%d plan=%llu/%llu total=%llu/%llu digest=%016llx\n",step_no++,what,r,
           (unsigned long long)last_plan.descriptors,(unsigned long long)last_plan.leaves,
           (unsigned long long)plan_descriptors,(unsigned long long)plan_leaves,(unsigned long long)digest());
}
/* A good leaf of data frame d's 4K page k, attributes its type admits. */
static uint64_t good_leaf(uint64_t d,unsigned k)
{
    uint64_t pa=d+(uint64_t)k*4096;
    return meta(d)[2]==14 ? pa|EXEC : pa|(rnd()%2 ? LEAF : LEAF_RW);
}
/* A leaf the checked loop refuses, or skips, or a hole. */
static uint64_t bad_leaf(void)
{
    uint64_t d=data_frame[rnd()%NDATA],good=good_leaf(d,(unsigned)(rnd()%4));
    switch(rnd()%7) {
    case 0: return UINT64_C(0x2000000000000000)<<(rnd()%3);   /* compressed marker (skipped) */
    case 1: return UINT64_C(0xe000000000000000);               /* marker */
    case 2: return good&~UINT64_C(2);                          /* invalid, nonzero */
    case 3: return meta(d)[2]==14 ? (good&~EXEC)|LEAF : good&~PT_UXN;   /* policy */
    case 4: return UINT64_C(0x0000700000000000)|LEAF;          /* unmanaged frame */
    case 5: return (good&~UINT64_C(0x300))|UINT64_C(0x100);    /* policy: SH below inner */
    default: return 0;
    }
}
/* setup()'s format-1 fixture with `n` frames of shared tables, four
 * consumers, the memo and its witness, and random leaves. */
static void scenario(unsigned n,unsigned seed,int bad)
{
    rng=seed*UINT64_C(0x9e3779b97f4a7c15)+1;groups=n;
    setup(1,0,n,0);
    backend.prepare_nest=cap_prepare_nest;backend.commit_nest=cap_commit_nest;
    backend.prepare_unnest=cap_prepare_unnest;backend.commit_unnest=cap_commit_unnest;
    nest_commits=unnest_commits=plan_leaves=plan_descriptors=0;memset(&last_plan,0,sizeof(last_plan));
    memset(&memo,0,sizeof(memo));m.root_memo=&memo;m.publish=witness;
#if SNAP_NEST_FAST || SNAP_DETACH_FAST
    memset(&st,0,sizeof(st));m.nest_fast=&st;
#endif
    consumer[0]=USER;
    for(unsigned k=1;k<CONSUMERS;k++) {
        uint64_t pa=next_frame;next_frame+=PAGE;
        create(pa,10+k,1,2);parents(pa,20,START);
        CHECK(!sptm_mac_set_shared_region(&m,pa,ROOT));
        consumer[k]=pa;
    }
    for(unsigned k=0;k<CONSUMERS;k++)sethalf(consumer[k],10,consumer_flags[k]);
    for(unsigned i=0;i<NDATA;i++) {
        data_frame[i]=next_frame;next_frame+=PAGE;
        if(i%5==4)meta(data_frame[i])[2]=14;            /* USER_EXEC data */
        setword(record_pa(data_frame[i])+8,1);          /* referenced: a mapped user frame */
    }
    CHECK(next_frame<USER2);
    for(unsigned t=0;t<4*n;t++) {
        uint64_t child=child_of(t);
        unsigned groups4=(unsigned)(rnd()%40);
        for(unsigned g=0;g<groups4;g++) {
            unsigned at=4*(unsigned)(rnd()%128);uint64_t d=data_frame[rnd()%NDATA];
            for(unsigned k=0;k<4;k++)setword(child+8UL*(at+k),good_leaf(d,k));
        }
        for(unsigned s=(unsigned)(rnd()%6);s;s--)
            setword(child+8UL*(rnd()%512),good_leaf(data_frame[rnd()%NDATA],(unsigned)(rnd()%4)));
        if(bad && rnd()%3==0)setword(child+8UL*(rnd()%512),bad_leaf());
    }
    for(unsigned f=0;f<n;f++) {
        uint64_t frame=child_of(4*f)&~(PAGE-1);unsigned valid=0;
        for(unsigned i=0;i<2048;i++)valid+=(word(frame+8UL*i)&3)==3;
        sethalf(frame,8,valid);
    }
    step_no=0;
}
static int nest(unsigned c,uint64_t va,uint64_t pages)
{return sptm_mac_nest_region(&m,&backend,consumer[c],ROOT,va,pages);}
static int unnest(unsigned c,uint64_t va,uint64_t pages)
{return sptm_mac_unnest_region(&m,&backend,consumer[c],ROOT,va,pages);}
static uint64_t all_pages(void) {return (uint64_t)groups*4*SPAN4/4096;}
/* A range the NEST/UNNEST validator admits: both ends in a group's first
 * table (level-2 index a multiple of four), partial ends at random pages. */
static void random_range(uint64_t *va,uint64_t *pages)
{
    unsigned a=(unsigned)(rnd()%groups),b=a+(unsigned)(rnd()%(groups-a+1));
    uint64_t o1=rnd()%3==0 ? rnd()%512 : 0,o2=b<groups && rnd()%3==0 ? rnd()%512 : 0;
    uint64_t start=START+4UL*a*SPAN4+o1*4096,end=START+4UL*b*SPAN4+o2*4096;
    if(end<=start)end=start+4096;
    *va=start;*pages=(end-start)/4096;
}
/* A published store as the SPTM makes one. */
static void change_leaf(unsigned t,unsigned at,uint64_t leaf)
{
    uint64_t slot=child_of(t)+8UL*at;
    setword(slot,leaf);witness(0,slot,8);
}
static void retype_mapped(uint64_t d,unsigned type)
{
    sptm_root_memo_retype(m.root_memo,meta(d));
    meta(d)[2]=(uint8_t)type;witness(0,record_pa(d),16);
}

/* ---- the define-on build's own checks (not compared). */
/* validate_table's level-3 rules for a SHARED 4K table, restated (U2). */
static int ref_shared_ok(uint64_t table,uint64_t base,unsigned flags)
{
    struct sptm_user_geometry g;
    if(!sptm_mac_user_geometry(1,flags,&g))return 0;
    for(unsigned i=0;i<512;i++) {
        uint64_t pte=word(table+8UL*i),va=base+(uint64_t)i*4096;
        if(!pte || !(pte&~UINT64_C(0xe000000000000000)))continue;
        if((pte&3)!=3 || va>=g.va_limit || !sprr_fixed_native_leaf(pte))return 0;
        uint64_t pa=pte&DMASK;
        if(!sptm_managed_frame(&m,pa))return 0;
        uint8_t *d=meta(pa);
        if(d[0] || d[1] || sptm_mac_user_leaf_policy(flags,21,d[2],va,pte,&g) ||
           !map(0,pte&g.pa_mask,4096))return 0;
    }
    return 1;
}
static uint64_t ref_count(uint64_t table)
{
    uint64_t n=0;
    for(unsigned i=0;i<512;i++) {uint64_t pte=word(table+8UL*i);n+=(pte&~UINT64_C(0xe000000000000000))!=0;}
    return n;
}
static uint64_t counted_total;
#if SNAP_NEST_FAST && SNAP_UNNEST_4K_FAST
/* C1, C2: the frame filter equals a recount of every nonzero entry (stale
 * epochs included) by its table's 16K frame index, and live counts them. */
static void audit_filter(void)
{
    static uint8_t want[SPTM_ROOT_MEMO_ENTRIES];
    uint64_t nonzero=0;
    memset(want,0,sizeof(want));
    for(unsigned i=0;i<SPTM_ROOT_MEMO_ENTRIES;i++)if(memo.entry[i].table) {
        want[sptm_root_memo_index(memo.entry[i].table&~UINT64_C(0x3fff))]++;nonzero++;
    }
    CHECK(!memcmp(want,memo.frame_live,sizeof(want)) && nonzero==memo.live);
}
#endif
static void audit_memo(const char *where)
{
#if SNAP_NEST_FAST && SNAP_UNNEST_4K_FAST
    audit_filter();
    unsigned live=0,counted=0;
    for(unsigned i=0;i<SPTM_ROOT_MEMO_ENTRIES;i++) {
        const struct sptm_root_memo_entry *e=&memo.entry[i];
        if(!e->table || e->epoch!=(uint32_t)memo.epoch)continue;
        live++;
        int named=0,flagged=0;
        for(unsigned t=0;t<4*groups;t++)named|=child_of(t)==e->table && START+t*SPAN4==e->base;
        for(unsigned k=0;k<CONSUMERS;k++)flagged|=e->flags==consumer_flags[k] || e->flags==(consumer_flags[k]^1u);
        CHECK(named && flagged && e->shift==12);                          /* U2 */
        CHECK(ref_shared_ok(e->table,e->base,e->flags));                  /* U1, U9 */
        uint64_t now=sptm_root_memo_record_bytes(meta(e->table));
        CHECK((e->record&UINT64_C(0xffffffffffff))==now);                 /* U6 */
        if(e->record>>48) {CHECK((e->record>>48)-1==ref_count(e->table));counted++;}   /* U3 */
    }
    CHECK(memo.stats.records==memo.stats.misses && memo.stats.hits==st.nest_hits+st.unnest_hits);  /* U8 */
    CHECK(st.mismatches==0 && st.nest_records+st.unnest_records==memo.stats.records);
    CHECK(st.unnest_counted<=st.unnest_hits && st.unnest_hits+st.unnest_scans<=st.unnest_tables);
    if(!where)return;                       /* a mid-scenario audit: checks only */
    printf("# %s memo live=%u counted=%u hits=%llu misses=%llu evictions=%llu invalidations=%llu "
           "unnest tables=%llu hits=%llu counted=%llu scans=%llu walked=%llu sampled=%llu\n",where,live,counted,
           (unsigned long long)memo.stats.hits,(unsigned long long)memo.stats.misses,
           (unsigned long long)memo.stats.evictions,(unsigned long long)memo.stats.invalidations,
           (unsigned long long)st.unnest_tables,(unsigned long long)st.unnest_hits,
           (unsigned long long)st.unnest_counted,(unsigned long long)st.unnest_scans,
           (unsigned long long)st.unnest_walked,(unsigned long long)st.sampled);
    counted_total+=st.unnest_counted;
#else
    (void)where;(void)ref_shared_ok;(void)ref_count;(void)counted_total;
#endif
}

static void scenarios(void)
{
    for(unsigned seed=1;seed<=48;seed++) {
        unsigned n=1+seed%4;int bad=seed%3==0;
        scenario(n,seed,bad);
        for(unsigned c=0;c<CONSUMERS;c++)step("nest",nest(c,START,all_pages()));
        for(unsigned op=0;op<36;op++) {
            unsigned c=(unsigned)(rnd()%CONSUMERS),k=(unsigned)(rnd()%14);
            uint64_t va,pages;random_range(&va,&pages);
            switch(k) {
            case 0: case 1: case 2: case 3:
                step("unnest",unnest(c,va,pages));break;
            case 4: case 5: case 6:
                step("nest",nest(c,va,pages));break;
            case 7: {                                   /* U1: a published store in any of the four */
                unsigned t=(unsigned)(rnd()%(4*groups)),at=(unsigned)(rnd()%512);
                uint64_t old=word(child_of(t)+8UL*at);
                int refused=bad && rnd()%2;
                change_leaf(t,at,refused ? bad_leaf() : good_leaf(data_frame[rnd()%NDATA],(unsigned)(rnd()%4)));
                step("unnest-changed",unnest(c,START,all_pages()));
                step("nest-changed",nest(c,START,all_pages()));
                if(refused) {
                    change_leaf(t,at,old);
                    step("unnest-restored",unnest(c,START,all_pages()));
                    step("nest-restored",nest(c,START,all_pages()));
                }
                break; }
            case 8: {                                   /* UMPRR11 toggles: another verdict key */
                sethalf(consumer[c],10,half(consumer[c],10)^1u);witness(0,record_pa(consumer[c])+10,2);
                step("unnest-flags",unnest(c,va,pages));break; }
            case 9: {                                   /* U9: a mapped frame changes type */
                uint64_t d=data_frame[rnd()%NDATA];unsigned type=meta(d)[2];
                retype_mapped(d,type==14 ? 11 : 14);
                step("unnest-retyped",unnest(c,START,all_pages()));
                step("nest-retyped",nest(c,START,all_pages()));
                retype_mapped(d,type);
                step("unnest-retyped-back",unnest(c,START,all_pages()));
                step("nest-retyped-back",nest(c,START,all_pages()));
                break; }
            case 10: {                                  /* U1: a store published by a large range */
                unsigned t=(unsigned)(rnd()%(4*groups));
                setword(child_of(t)+8UL*(rnd()%512),good_leaf(data_frame[rnd()%NDATA],0));
                /* C5: the whole fixture (the small path at the define's
                 * capacity), or 2,048 frames (the large path at any). */
                witness(0,BASE,step_no&1 ? 2048*PAGE : sizeof(bytes));
                step("unnest-large",unnest(c,START,all_pages()));
                step("nest-large",nest(c,START,all_pages()));
                break; }
            case 11: {                                  /* U4: a locked table frame refuses first */
                uint64_t frame=child_of((unsigned)(rnd()%(4*groups)))&~(PAGE-1);
                meta(frame)[0]=1;
                /* U6: its verdicts go on the record check, through the small
                 * path or the large one (the whole frame map: 305 records;
                 * the large path at 2,048 entries, C5). */
                if(rnd()%2)witness(0,record_pa(frame),16);else witness(0,m.frame_map_pa,PAGE);
                audit_memo(0);
                step("unnest-locked",unnest(c,START,all_pages()));
                meta(frame)[0]=0;witness(0,record_pa(frame),16);
                step("unnest-unlocked",unnest(c,START,all_pages()));
                break; }
            case 12: {                                  /* U4: an unmappable table page */
                deny=child_of((unsigned)(rnd()%(4*groups)));
                step("unnest-denied",unnest(c,START,all_pages()));
                deny=0;
                step("nest-denied",nest(c,START,all_pages()));
                break; }
            default:
                step("unnest-all",unnest(c,START,all_pages()));
                step("nest-all",nest(c,START,all_pages()));
                step("unnest-again",unnest(c,START,all_pages()));
                step("nest-again",nest(c,START,all_pages()));
                break;
            }
        }
        for(unsigned c=0;c<CONSUMERS;c++) {
            step("unnest-end",unnest(c,START,all_pages()));
            step("nest-end",nest(c,START,all_pages()));
        }
        audit_memo("scenario");
    }
}
/* U7: four tables x four flag values of one frame, twice over: the second
 * round answers every table from a counted verdict, with no eviction. */
static void crowding(void)
{
    scenario(2,777,0);
    for(unsigned c=0;c<CONSUMERS;c++)step("crowd-nest",nest(c,START,all_pages()));
    for(unsigned round=0;round<3;round++) {
#if SNAP_NEST_FAST && SNAP_UNNEST_4K_FAST
        uint64_t scans=st.unnest_scans,counted=st.unnest_counted,hits=st.unnest_hits;
#endif
        for(unsigned c=0;c<CONSUMERS;c++) {
            step("crowd-unnest",unnest(c,START,all_pages()));
            step("crowd-nest",nest(c,START,all_pages()));
        }
#if SNAP_NEST_FAST && SNAP_UNNEST_4K_FAST
        if(round) {
            uint64_t answered=st.unnest_hits-hits,tables=(uint64_t)CONSUMERS*4*groups;
            printf("# crowding round %u: hits %llu counted %llu scans %llu evictions %llu\n",round,
                   (unsigned long long)answered,(unsigned long long)(st.unnest_counted-counted),
                   (unsigned long long)(st.unnest_scans-scans),(unsigned long long)memo.stats.evictions);
            CHECK(st.unnest_scans==scans && answered==tables && memo.stats.evictions==0);
            CHECK(st.unnest_counted-counted+1>=tables-(tables+SPTM_NEST_FAST_SAMPLE)/(SPTM_NEST_FAST_SAMPLE+1));
        }
#endif
    }
    audit_memo("crowding");
}
#if SNAP_NEST_FAST && SNAP_UNNEST_4K_FAST
/* C8 and C1: installed-fresh-20261020-v6's working set, 3,450 shared 4K
 * tables at random 4K slots of a 16 MiB block, each at its own 2 MiB base,
 * under root flags 0x1 and 0xb. At the define's capacity every key is found
 * again with no eviction. Then frame drops, a store set over stale entries
 * (an epoch bump) and the epoch wrap, each followed by the filter recount. */
static void capacity(void)
{
    static unsigned perm[4096];
    const unsigned keys=3450;const uint64_t pa0=UINT64_C(0x8d5a00000),va0=UINT64_C(0x19c000000);
    const uint64_t rec=UINT64_C(0x0300150000);
    memset(&memo,0,sizeof(memo));rng=UINT64_C(0x5eed);
    for(unsigned i=0;i<4096;i++)perm[i]=i;
    for(unsigned i=4095;i>0;i--) {unsigned j=(unsigned)(rnd()%(i+1)),t=perm[i];perm[i]=perm[j];perm[j]=t;}
    unsigned found=0;
    for(unsigned round=0;round<2;round++)for(unsigned f=0;f<2;f++)for(unsigned i=0;i<keys;i++) {
        uint64_t t=pa0+(uint64_t)perm[i]*4096,b=va0+(uint64_t)i*0x200000;
        if(round)found+=(unsigned)sptm_root_memo_peek(&memo,t,b,f ? 0xb : 0x1,12,rec);
        else sptm_root_memo_store(&memo,t,b,f ? 0xb : 0x1,12,rec);
    }
    printf("# capacity %u entries: %u of %u keys found, live %llu, evictions %llu\n",SPTM_ROOT_MEMO_ENTRIES,found,
           2*keys,(unsigned long long)memo.live,(unsigned long long)memo.stats.evictions);
#ifndef TEST_MEMO_CAPACITY_OVERRIDDEN               /* the define's own capacity */
    CHECK(found==2*keys && !memo.stats.evictions && memo.live==2*keys);
#endif
    audit_filter();
    for(unsigned i=0;i<keys;i+=7)sptm_root_memo_drop_frame(&memo,(pa0+(uint64_t)perm[i]*4096)&~UINT64_C(0x3fff));
    audit_filter();
    for(unsigned i=0;i<keys;i+=7)CHECK(!sptm_root_memo_peek(&memo,pa0+(uint64_t)perm[i]*4096,va0+(uint64_t)i*0x200000,
                                                            0xb,12,rec));
    sptm_root_memo_bump(&memo);                 /* every entry stale: stores reuse them */
    for(unsigned i=0;i<keys;i++)sptm_root_memo_store(&memo,pa0+(uint64_t)perm[4095-i]*4096,va0+(uint64_t)i*0x200000,
                                                     0xa,12,rec);
    audit_filter();
    memo.epoch=UINT32_MAX;sptm_root_memo_bump(&memo);    /* the wrap clears everything */
    audit_filter();
    CHECK(!memo.live && memo.stats.flushes==1);
    memset(&memo,0,sizeof(memo));
}
#endif
#if SNAP_NEST_FAST && SNAP_UNNEST_4K_FAST && SPTM_NEST_FAST_SAMPLE==0
/* U5: with every answered table sampled, a store made behind the SPTM is
 * refused with a counted mismatch: a policy failure (the verdict), and a
 * valid leaf that changes only the count. */
static void stale(void)
{
    for(unsigned kind=0;kind<2;kind++) {
        scenario(2,900+kind,0);
        CHECK(!nest(0,START,all_pages()) && !unnest(0,START,all_pages()) && !nest(0,START,all_pages()));
        uint64_t child=child_of(1),d=data_frame[0];unsigned at=0;
        while(word(child+8UL*at))at++;
        setword(child+8UL*at,kind ? good_leaf(d,0) : ((d|LEAF)&~PT_UXN));   /* not published */
        uint64_t before=st.mismatches;
        int r=unnest(0,START,all_pages());
        printf("# stale %s refused r=%d (mismatches %llu)\n",kind ? "count" : "verdict",r,
               (unsigned long long)st.mismatches);
        CHECK(r==SPTM_SHADOW_FAILED && st.mismatches==before+1);
    }
}
#endif

int main(void)
{
    scenarios();
    crowding();
#if SNAP_NEST_FAST && SNAP_UNNEST_4K_FAST
    capacity();
#if SPTM_NEST_FAST_SAMPLE==0
    stale();
    CHECK(!counted_total);                  /* every hit was rescanned */
#else
    CHECK(counted_total>0);                 /* U6: counts survive the calls' own link updates */
#endif
    printf("# counted hits %llu\n",(unsigned long long)counted_total);
#endif
    printf("PASS: %u checks\n",checks);
    (void)nest_fixture_checks;
    return 0;
}

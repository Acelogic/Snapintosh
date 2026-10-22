/* SPDX-License-Identifier: MIT */
/* SNAP_NEST_FAST and SNAP_DETACH_FAST (compat/nest-fast.h) on the real
 * NEST/UNNEST/linked-group fixtures (test-native-shared-nest.c), with the
 * SWITCH_ROOT memo and its write witness wired as the monitor wires them.
 *
 * The oracle is the build without the defines: tools/test-token-costs.py
 * compiles this file with and without them and requires every "step" line
 * (result, leaves, group counters and a digest of all fixture memory) to be
 * identical. Lines starting with '#' are this build's own checks and
 * counters and are not compared. Scenarios are seeded and deterministic:
 * shared tables hold random leaves (valid, read-only, compressed markers,
 * invalid nonzero descriptors, policy failures, unmanaged frames), and the
 * steps nest, unnest, re-nest, nest a second consumer, change leaves through
 * the witness, retype a mapped frame (the memo epoch), and detach private
 * level-3 tables under random shadow states. */
#define SPTM_UNNEST_TEST_MAIN unnest_fixture_checks
#include "test-sptm-unnest.c"
/* test-native-shared-nest.c's linked callbacks and setup, verbatim. */
#include "native-shared.h"

static struct native_shared ns;
static uint64_t links_of(int g) {return (uint64_t)__builtin_popcountll(ns.group[g].slots);}
static int slot_links_any(unsigned slot)
{
    for(int g=0;g<(int)NATIVE_SHARED_GROUPS;g++)if(native_shared_slot_links(&ns,slot,g))return 1;
    return 0;
}
static unsigned link_slot;
static struct shadow group_w;
static uint64_t no_alloc_hw(void *ctx) {(void)ctx;return 0;}
static void no_release(void *ctx,uint64_t pa) {(void)ctx;(void)pa;CHECK(!"a group create failed after taking pages");}
/* The shadow a link callback writes: the current cache's tree. */
static struct shadow link_tree;
static int t_group(void *ctx,uint64_t child,uint64_t va)
{
    (void)ctx;int g=native_shared_find(&ns,child);
    if(g>=0)return ns.group[g].va==va ? g : -1;
    return native_shared_create(&ns,&group_w,ROOT,child,va,read_hw,0,no_release,0);
}
static int t_link(void *ctx,uint64_t child,uint64_t va,uint64_t *leaves)
{
    (void)ctx;int g=native_shared_find(&ns,child);
    if(g<0 || ns.group[g].va!=va || !native_shared_link(&ns,&link_tree,link_slot,g))return 0;
    *leaves=ns.group[g].leaves;return 1;
}
static int t_linked(void *ctx,uint64_t child,uint64_t va,uint64_t *leaves)
{
    (void)ctx;int g=native_shared_find(&ns,child);
    if(g<0 || ns.group[g].va!=va || !native_shared_slot_links(&ns,link_slot,g) ||
       !native_shared_linked(&ns,&link_tree,g))return 0;
    *leaves=ns.group[g].leaves;return 1;
}
static int t_unlink(void *ctx,uint64_t child,uint64_t va,uint64_t *leaves)
{
    (void)ctx;int g=native_shared_find(&ns,child);
    if(g<0 || ns.group[g].va!=va)return 0;
    *leaves=ns.group[g].leaves;
    return native_shared_unlink(&ns,&link_tree,link_slot,g);
}
static const struct sptm_root_links links={t_group,t_link,t_linked,t_unlink,0};
static unsigned lprep,lcommit,lfail;
static int l_prepare(void *ctx,uint64_t root,uint64_t shared,uint64_t va,unsigned shift,uint64_t pages)
{
    (void)ctx;CHECK(root==cache.root);lprep++;link_tree=hw;
    return !lfail && sptm_root_prepare_nest_linked(&cache,&hw,&m,shared,va,shift,pages,&links);
}
static int l_commit(void *ctx,uint64_t root,uint64_t shared,uint64_t va,unsigned shift,uint64_t pages)
{
    (void)ctx;CHECK(root==cache.root);lcommit++;
    /* Commit allocates nothing: every table was made by prepare. */
    struct shadow fixed=hw;fixed.alloc=no_alloc_hw;link_tree=fixed;
    int ok=sptm_root_commit_nest_linked(&cache,&fixed,&m,shared,va,shift,pages,&links);
    if(ok)flushed++;return ok;
}
static int l_unprepare(void *ctx,uint64_t root,uint64_t shared,unsigned shift,const struct sptm_unnest_plan *p)
{
    (void)ctx;CHECK(root==cache.root);unprep++;link_tree=hw;
    return !unfail && sptm_root_prepare_unnest_linked(&cache,&hw,&m,shared,shift,p,&links);
}
static int l_uncommit(void *ctx,uint64_t root,uint64_t shared,unsigned shift,const struct sptm_unnest_plan *p)
{
    (void)ctx;CHECK(root==cache.root);uncommit++;
    struct shadow fixed=hw;fixed.alloc=no_alloc_hw;link_tree=fixed;
    if(!sptm_root_commit_unnest_linked(&cache,&fixed,&m,shared,shift,p,&links))return 0;
    last_plan=*p;flushed++;return 1;
}
/* Linked setup: the same fixture, a fresh group set, linked callbacks. */
static void lsetup(unsigned active,int populated)
{
    setup(0,active,3,populated);
    memset(&ns,0,sizeof(ns));link_slot=0;
    group_w=(struct shadow){.txsz=17,.alloc=alloc_hw,.read=read_hw,.write=write_hw};
    backend.prepare_nest=l_prepare;backend.commit_nest=l_commit;
    backend.prepare_unnest=l_unprepare;backend.commit_unnest=l_uncommit;
    lprep=lcommit=lfail=unprep=uncommit=unfail=0;memset(&last_plan,0,sizeof(last_plan));
}
#include "sptm-root-memo.h"
#if SNAP_NEST_FAST || SNAP_DETACH_FAST
#include "nest-fast.h"
static struct sptm_nest_fast_stats st;
#endif
static struct sptm_root_memo memo;
static int witness_on=1;
/* The monitor's sptm_publish: every SPTM store reaches the memo's witness. */
static void witness(void *ctx,uint64_t pa,uint64_t size)
{
    published++;
    if(witness_on)sptm_root_memo_publish(&memo,m.frame_map_pa,m.frame_low,m.frame_high,map,ctx,pa,size);
}
static uint64_t rng;
static uint64_t rnd(void) {rng^=rng<<13;rng^=rng>>7;rng^=rng<<17;return rng;}
static uint64_t digest(void)
{
    uint64_t h=UINT64_C(0xcbf29ce484222325);
    for(size_t i=0;i<sizeof(bytes);i+=8) {uint64_t w;memcpy(&w,bytes+i,8);h=(h^w)*UINT64_C(0x100000001b3);}
    uint64_t extra[]={cache.leaves,cache.valid,ns.live,ns.created,ns.linked,ns.unlinked,ns.stores,ns.errors,
                      registry.bindings,lprep,lcommit,unprep,uncommit,last_plan.leaves,last_plan.descriptors};
    for(unsigned i=0;i<sizeof(extra)/8;i++)h=(h^extra[i])*UINT64_C(0x100000001b3);
    return h;
}
static unsigned step_no;
static void step(const char *what,int r)
{
    printf("step %u %s r=%d leaves=%llu live=%llu linked=%llu unlinked=%llu plan=%llu/%llu digest=%016llx\n",
           step_no++,what,r,(unsigned long long)cache.leaves,(unsigned long long)ns.live,
           (unsigned long long)ns.linked,(unsigned long long)ns.unlinked,
           (unsigned long long)last_plan.descriptors,(unsigned long long)last_plan.leaves,
           (unsigned long long)digest());
}
#define SPAN (UINT64_C(1)<<25)
#define DMASK UINT64_C(0x0000ffffffffc000)
#define LEAF UINT64_C(0x0060000000000fc3)
static unsigned tables;
static uint64_t child_of(unsigned i) {return word(slot_at(ROOT,2,START+i*SPAN))&geom.pa_mask;}
static uint64_t data_of(unsigned i) {return word(child_of(i))&DMASK;}
/* A random leaf for table i: mostly valid; bad kinds only when allowed. */
static uint64_t random_leaf(unsigned i,int bad)
{
    uint64_t data=data_of(i),k=rnd()%100;
    if(!bad || k<70)return data|(k&1 ? LEAF : (LEAF&~UINT64_C(0x80)));
    if(k<76)return UINT64_C(0x2000000000000000);                 /* compressed marker */
    if(k<82)return (data|LEAF)&~UINT64_C(2);                     /* invalid, nonzero */
    if(k<88)return (data|LEAF)&~PT_UXN;                          /* policy: exec on DEFAULT */
    if(k<94)return UINT64_C(0x0000700000000000)|LEAF;            /* unmanaged frame */
    return 0;
}
/* The fixture's linked setup (lsetup) with `n` populated shared tables, the
 * memo and its witness, then random leaves in the first 384 entries of each
 * table (three 2 MiB group pages at most). */
static void scenario(unsigned n,unsigned seed,int bad)
{
    rng=seed*UINT64_C(0x9e3779b97f4a7c15)+1;tables=n;
    setup(0,0,n,1);
    memset(&ns,0,sizeof(ns));link_slot=0;
    group_w=(struct shadow){.txsz=17,.alloc=alloc_hw,.read=read_hw,.write=write_hw};
    backend.prepare_nest=l_prepare;backend.commit_nest=l_commit;
    backend.prepare_unnest=l_unprepare;backend.commit_unnest=l_uncommit;
    lprep=lcommit=lfail=unprep=uncommit=unfail=0;memset(&last_plan,0,sizeof(last_plan));
    memset(&memo,0,sizeof(memo));m.root_memo=&memo;m.publish=witness;witness_on=1;
#if SNAP_NEST_FAST || SNAP_DETACH_FAST
    memset(&st,0,sizeof(st));m.nest_fast=&st;
#endif
    for(unsigned i=0;i<n;i++) {
        uint64_t child=child_of(i);
        unsigned count=(unsigned)(rnd()%48),valid=1;
        for(unsigned k=0;k<count;k++) {
            unsigned at=1+(unsigned)(rnd()%383);
            uint64_t leaf=random_leaf(i,bad && (rnd()%4==0));
            if((word(child+8UL*at)&3)==3)valid--;
            setword(child+8UL*at,leaf);valid+=(leaf&3)==3;
        }
        sethalf(child,8,valid);
    }
    step_no=0;
}
static int nest(uint64_t root,uint64_t va,uint64_t pages)
{return sptm_mac_nest_region(&m,&backend,root,ROOT,va,pages);}
static int unnest(uint64_t root,uint64_t va,uint64_t pages)
{return sptm_mac_unnest_region(&m,&backend,root,ROOT,va,pages);}
/* A leaf change of the shared root as the SPTM makes it: the guest store and
 * its publication (the witness), and the group's mirror of it. */
static void change_leaf(unsigned i,unsigned at,uint64_t leaf)
{
    uint64_t child=child_of(i),slot=child+8UL*at;
    setword(slot,leaf);witness(0,slot,8);
    int g=native_shared_find(&ns,child);
    if(g>=0)(void)native_shared_store(&ns,&group_w,g,START+i*SPAN+(uint64_t)at*PAGE,
                                      (leaf&3)==3 && native_shared_storable(leaf) ? leaf : 0);
}
/* Replace or clear a valid leaf (its group page exists), or (bad) give it
 * exec attributes its DEFAULT frame's policy refuses. */
static void change_existing(unsigned i,int bad)
{
    uint64_t child=child_of(i);
    for(unsigned tries=0;tries<64;tries++) {
        unsigned at=(unsigned)(rnd()%384);
        uint64_t old=word(child+8UL*at);
        if((old&3)!=3 || !(old&PT_UXN))continue;
        unsigned k=(unsigned)(rnd()%4);
        uint64_t next=k==0 ? 0 : k==1 && bad ? old&~PT_UXN : (old&DMASK)|(rnd()%2 ? LEAF : LEAF&~UINT64_C(0x80));
        change_leaf(i,at,next);
        sethalf(child,8,half(child,8)-!next);
        return;
    }
}
/* A mapped frame changes type as sptm_mac_retype does: the memo sees the
 * record it replaces, then the store is published. */
static void retype_mapped(uint64_t data,unsigned type)
{
    uint64_t at=m.frame_map_pa+((data-BASE)>>14)*16;
    sptm_root_memo_retype(m.root_memo,meta(data));
    meta(data)[2]=(uint8_t)type;witness(0,at,16);
}
/* validate_table's level-3 rules for a SHARED table (the meaning of a
 * verdict), restated independently for the memo audit below. */
static int ref_shared_ok(uint64_t table,uint64_t base,unsigned flags)
{
    struct sptm_user_geometry g;
    if(!sptm_mac_user_geometry(0,flags,&g))return 0;
    for(unsigned i=0;i<2048;i++) {
        uint64_t pte=word(table+8UL*i),va=base+(uint64_t)i*PAGE;
        if(!pte || !(pte&~UINT64_C(0xe000000000000000)))continue;
        if((pte&3)!=3 || va>=g.va_limit || !sprr_fixed_native_leaf(pte))return 0;
        uint64_t pa=pte&DMASK;
        if(!sptm_managed_frame(&m,pa))return 0;
        uint8_t *d=meta(pa);
        if(d[0] || d[1] || sptm_mac_user_leaf_policy(flags,21,d[2],va,pte,&g) || !map(0,pa,PAGE))return 0;
    }
    return 1;
}
static void audit_memo(const char *where)
{
#if SNAP_NEST_FAST
    /* N2: every live verdict names a table the shared root holds at its base,
     * under the consumer's flags, and is true now; N6: accounting. */
    unsigned live=0;
    for(unsigned i=0;i<SPTM_ROOT_MEMO_ENTRIES;i++) {
        const struct sptm_root_memo_entry *e=&memo.entry[i];
        if(!e->table || e->epoch!=(uint32_t)memo.epoch)continue;
        live++;
        int named=0;
        for(unsigned t=0;t<tables;t++)named|=child_of(t)==e->table && START+t*SPAN==e->base;
        CHECK(named && e->flags==2 && e->shift==14);
        CHECK(ref_shared_ok(e->table,e->base,e->flags));
    }
    CHECK(memo.stats.records==memo.stats.misses && memo.stats.hits==st.nest_hits+st.unnest_hits);
    CHECK(st.mismatches==0 && st.nest_records+st.unnest_records==memo.stats.records);
    printf("# %s memo live=%u hits=%llu misses=%llu records=%llu nest tables=%llu hits=%llu scans=%llu walked=%llu "
           "unnest tables=%llu hits=%llu scans=%llu walked=%llu sampled=%llu\n",where,live,
           (unsigned long long)memo.stats.hits,(unsigned long long)memo.stats.misses,
           (unsigned long long)memo.stats.records,(unsigned long long)st.nest_tables,
           (unsigned long long)st.nest_hits,(unsigned long long)st.nest_scans,(unsigned long long)st.nest_walked,
           (unsigned long long)st.unnest_tables,(unsigned long long)st.unnest_hits,
           (unsigned long long)st.unnest_scans,(unsigned long long)st.unnest_walked,
           (unsigned long long)st.sampled);
#else
    (void)where;(void)ref_shared_ok;
#endif
}
static struct sptm_root_cached second;
static struct shadow second_hw;
static void second_consumer(void)
{
    struct sptm_root_cached first=cache;struct shadow first_hw=hw;
    create(USER2,11,0,2);parents(USER2,20,START);
    CHECK(!sptm_mac_set_shared_region(&m,USER2,ROOT));
    cache=(struct sptm_root_cached){.root=USER2,.shadow=alloc_hw(0),.asid=11,.format=0,.flags=2,.valid=1};
    hw.root=cache.shadow;link_slot=1;
    step("nest-second",nest(USER2,START,tables*SPAN/PAGE));
    step("unnest-second",unnest(USER2,START+SPAN,SPAN/PAGE));
    step("renest-second",nest(USER2,START+SPAN,SPAN/PAGE));
    second=cache;second_hw=hw;
    cache=first;hw=first_hw;link_slot=0;
}
static void nest_scenarios(void)
{
    for(unsigned seed=1;seed<=60;seed++) {
        unsigned n=2+seed%6;int bad=seed%3==0;
        scenario(n,seed,bad);
        step("nest",nest(USER,START,n*SPAN/PAGE));
        uint64_t a=rnd()%n,b=1+rnd()%(n-a);
        step("unnest",unnest(USER,START+a*SPAN,b*SPAN/PAGE));
        step("renest",nest(USER,START+a*SPAN,b*SPAN/PAGE));
        step("unnest-all",unnest(USER,START,n*SPAN/PAGE));
        step("nest-all",nest(USER,START,n*SPAN/PAGE));
        second_consumer();
        /* Leaf changes through the witness, then the same calls again. */
        for(unsigned k=0;k<3;k++)change_existing((unsigned)(rnd()%n),bad);
        step("unnest-changed",unnest(USER,START,n*SPAN/PAGE));
        step("nest-changed",nest(USER,START,n*SPAN/PAGE));
        /* A mapped frame becomes USER_EXEC: its DEFAULT-attribute leaves now
         * fail policy; the memo's epoch retires every verdict. */
        if(seed%4==1) {
            retype_mapped(data_of((unsigned)(rnd()%n)),14);
            step("unnest-retyped",unnest(USER,START,n*SPAN/PAGE));
            step("nest-retyped",nest(USER,START,n*SPAN/PAGE));
        }
        /* A compressed marker appears in a nested table: both UNNEST paths
         * skip it without counting a mapped leaf, as validate_table does (N4). */
        if(seed%5==2) {
            change_leaf(0,1+(unsigned)(rnd()%383),UINT64_C(0x2000000000000000));
            step("unnest-marker",unnest(USER,START,n*SPAN/PAGE));
        }
        audit_memo("nest");
    }
}
#if SNAP_NEST_FAST && SPTM_NEST_FAST_SAMPLE==0
/* N5: a verdict the witness never retired (a store made behind the SPTM) is
 * caught by the rescan of every answered table here: the call fails and a
 * mismatch is counted. */
static void stale_verdict(void)
{
    scenario(3,7,0);
    CHECK(!nest(USER,START,3*SPAN/PAGE) && !unnest(USER,START,3*SPAN/PAGE));
    uint64_t child=child_of(1);
    setword(child+8*7,(data_of(1)|LEAF)&~PT_UXN);       /* not published */
    uint64_t before=st.mismatches;
    CHECK(nest(USER,START,3*SPAN/PAGE)!=SPTM_OK && st.mismatches==before+1);
    printf("# stale verdict refused (mismatches %llu)\n",(unsigned long long)st.mismatches);
}
#endif

/* ---- SNAP_DETACH_FAST: direct prepare/commit detach under random states. */
static uint64_t private_child;
#define PRIVATE_VA UINT64_C(0x100000000)
static void detach_setup(unsigned seed)
{
    scenario(2,seed+1000,0);
    parents(USER,20,PRIVATE_VA);
    private_child=allocate(20,3);
    CHECK(!sptm_mac_map_user_table_live(&m,&backend,USER,PRIVATE_VA,2,private_child|3));
}
/* A random state of the guest table and of the shadow's 32 MiB. */
static void detach_state(void)
{
    unsigned k=(unsigned)(rnd()%8);
    uint64_t va=PRIVATE_VA+(rnd()%2048)*PAGE;
    switch(k) {
    case 0: break;                                              /* both empty */
    case 1: (void)(!shadow_map(&hw,va,0x900000000UL,4096,0xf43,PT_PXN|PT_UXN));
            (void)(!shadow_unmap(&hw,va,4096,0));break;          /* empty shadow L3 table */
    case 2: (void)(!shadow_map(&hw,va,0x900000000UL,4096,0xf43,PT_PXN|PT_UXN));break;  /* stale leaf */
    case 3: (void)(!shadow_map(&hw,PRIVATE_VA+(rnd()%16)*0x200000,rnd()%2 ? 0x900000000UL : 0x400000UL,
                               0x200000,0xf41,PT_PXN|PT_UXN));
            break;                                              /* a 2 MiB block (output readable or not) */
    case 4: setword(private_child+8*(rnd()%2048),0x0000000900000000UL|LEAF);break;  /* guest leaf */
    case 5: setword(private_child+8*(rnd()%2048),UINT64_C(0x2000000000000000));break;/* guest marker */
    case 6: { uint64_t x=va&~UINT64_C(0x1fffff);
              (void)(!shadow_map(&hw,x,0x900000000UL,4096,0xf43,PT_PXN|PT_UXN));
              (void)(!shadow_map(&hw,x+0x200000-4096,0x900004000UL,4096,0xf43,PT_PXN|PT_UXN));
              (void)(!shadow_unmap(&hw,x,4096,0));break; }        /* leaf at a table's end */
    default: (void)(!shadow_map(&hw,PRIVATE_VA-4096,0x900000000UL,4096,0xf43,PT_PXN|PT_UXN));
             (void)(!shadow_map(&hw,PRIVATE_VA+SPAN,0x900000000UL,4096,0xf43,PT_PXN|PT_UXN));
             break;                                             /* neighbours only */
    }
}
static void detach_scenarios(void)
{
#if SNAP_DETACH_FAST
    uint64_t fast=0,slow=0;
#endif
    unsigned prepared_ok=0;
    for(unsigned seed=0;seed<160;seed++) {
        detach_setup(seed);
        for(unsigned k=0;k<1+seed%3;k++)detach_state();
        cache.leaves=rnd()%3;
        uint64_t removed=rnd()%4==0;
        int a=sptm_root_prepare_detach(&cache,&hw,&m,PRIVATE_VA,14,2,removed);
        step("detach-prepare",a);prepared_ok+=a!=0;
        int b=sptm_root_commit_detach(&cache,&hw,PRIVATE_VA,14,2,removed);
        step("detach-commit",b);
        /* Through the SPTM call too (its word-wise emptiness check). */
        int c=sptm_mac_unmap_user_table(&m,&backend,USER,PRIVATE_VA,2);
        step("unmap-table",c);
#if SNAP_DETACH_FAST
        fast+=st.detach_fast;slow+=st.detach_slow;
#endif
    }
    printf("# detach prepares admitted %u of 160\n",prepared_ok);
    CHECK(prepared_ok>20 && prepared_ok<140);
#if SNAP_DETACH_FAST
    printf("# detach fast=%llu slow=%llu\n",(unsigned long long)fast,(unsigned long long)slow);
    CHECK(fast>0 && slow>0);
#endif
}
#if SNAP_DETACH_FAST
/* D1-D3: shadow_range_empty against mmu_walk and shadow_unmap. */
static void range_property(void)
{
    unsigned answers[3]={0};
    for(unsigned seed=0;seed<400;seed++) {
        rng=seed*UINT64_C(0x9e3779b97f4a7c15)+7;
        detach_setup(seed);
        for(unsigned k=0;k<(unsigned)(rnd()%4);k++)detach_state();
        uint64_t va=PRIVATE_VA-0x400000+(rnd()%0x3000)*4096,size=(rnd()%0x3000)*4096;
        if(rnd()%10==0)size|=0x800;                         /* refused alignment */
        int r=shadow_range_empty(&hw,va,size);
        int check=shadow_unmap(&hw,va,size,1),any=0,block=0;
        if(!((va|size)&0xfff))for(uint64_t at=va;at<va+size;at+=4096) {
            struct mmu_config cfg={12,17,hw.root};struct mmu_leaf leaf;
            if(mmu_walk(&cfg,at,read_hw,0,&leaf))continue;
            if(leaf.valid) {any=1;block|=leaf.level<3;}
        }
        if(r==1)CHECK(!any && !check);
        if(r==0)CHECK(any);
        if(r==-1)CHECK(check || block);
        if(!any && !check && !block)CHECK(r==1);
        answers[r+1]++;
    }
    printf("# range property: %u refused, %u mapped, %u empty\n",answers[0],answers[1],answers[2]);
    CHECK(answers[0] && answers[1] && answers[2]);
}
#endif

int main(void)
{
    (void)links_of;(void)slot_links_any;(void)lsetup;
    nest_scenarios();
#if SNAP_NEST_FAST && SPTM_NEST_FAST_SAMPLE==0
    stale_verdict();
#endif
    detach_scenarios();
#if SNAP_DETACH_FAST
    range_property();
#endif
    printf("PASS: %u checks\n",checks);
    return 0;
}

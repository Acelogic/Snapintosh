/* SPDX-License-Identifier: MIT */
/* SNAP_ROOT_MISS_FAST, part 2 (compat/root-miss.h M1-M6): retained shared
 * verdicts on a SWITCH_ROOT miss and inside the linked build, through the
 * real SWITCH_ROOT, NEST, MAP_PAGE, memo witness and native-shared fixtures.
 * Built and mutated by tools/test-root-miss.py (-DSNAP_ROOT_MISS_FAST=1).
 *  1. A miss answers exactly the SHARED level-3 tables from memo, in both
 *     walks; private tables are never looked up; the installed translation
 *     equals a copying build of the same guest tree.
 *  2. M1: an unpublished change to a private table that a hit's verdict
 *     covers is refused by the next miss (scanned in full); nothing installs.
 *  3. M1: a shared child whose group the build would create is scanned in
 *     full first: an unpublished inadmissible leaf there is refused and no
 *     group is created.
 *  4. A linked child with an existing group: an unpublished change never
 *     reaches hardware (the group's leaves are installed), and the sampled
 *     memo-free reference walk refuses on a miss (M5), counted.
 *  5. M3: a published store retires the verdict; the next miss rescans it.
 *  6. M4: memo calls count cache-hit validations only; records == misses;
 *     sampled <= root_validate.sampled.
 *  7. A 4K-format root's miss consults no verdict.
 *  8. Random published sequences: the memo-assisted miss verdict equals a
 *     full copying build's verdict every time. */
#define SPTM_UNNEST_TEST_MAIN unnest_fixture_checks
#include "test-sptm-unnest.c"
/* tools/test-native-shared-nest.c's linked fixture, verbatim. */
#include "native-shared.h"

static struct native_shared ns;
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
/* Every 4K address of [va, va+size) translates alike through both trees. */
static int same(uint64_t a,uint64_t b,uint64_t va,uint64_t size)
{
    struct mmu_config x={12,17,a},y={12,17,b};
    for(uint64_t at=va;at<va+size;at+=4096) {
        struct mmu_leaf p,q;
        if(mmu_walk(&x,at,read_hw,0,&p) || mmu_walk(&y,at,read_hw,0,&q) || p.valid!=q.valid ||
           (p.valid && (p.pa!=q.pa || (p.descriptor^q.descriptor)&(PT_LEAF_ATTRS|PT_LEAF_UPPER|3))))
            return 0;
    }
    return 1;
}
static uint64_t fresh_tree(void) {return alloc_hw(0);}

#include "sptm-refs.h"
#include "sptm-root-memo.h"
#include "root-miss.h"
#if !SNAP_ROOT_MISS_FAST
#error "build with -DSNAP_ROOT_MISS_FAST=1"
#endif
#define LEAF 0x0060000000000fc3UL           /* the fixture's admitted NX user leaf */
#define PVA 0x100000000UL                   /* a private level-3 table, same level-2 table */
#define SPAN (1UL<<25)
static struct sptm_root_memo memo;
static struct sptm_root_validate_stats vs;
static struct sptm_root_state rs;
static struct sptm_ref_batch miss_refs;
static void (*fixture_publish)(void *,uint64_t,uint64_t);
static uint64_t private_l3,private_data,build_base;
static unsigned build_calls,installs_seen,memo_in_build=1;
static uint64_t installed_shadow;
static void witness_publish(void *ctx,uint64_t pa,uint64_t size)
{
    sptm_root_memo_publish(&memo,m.frame_map_pa,m.frame_low,m.frame_high,map,ctx,pa,size);
    fixture_publish(ctx,pa,size);
}
static int grouped(void *ctx,uint64_t child,uint64_t va)
{(void)ctx;(void)va;return native_shared_find(&ns,child)>=0;}
static int miss_build(void *ctx,const struct sptm_memory *mm,uint64_t root,unsigned fmt,
                      unsigned flags,uint64_t previous,uint64_t *out,uint64_t *leaves)
{
    (void)ctx;(void)previous;build_calls++;
    /* The cache holds one root: every build reuses the same fresh region. */
    if(build_base)next_shadow=build_base;
    struct shadow t={.txsz=17,.root=fresh_tree(),.alloc=alloc_hw,.read=read_hw,.write=write_hw};
    native_shared_forget_slot(&ns,7);
    link_tree=t;link_slot=7;
    int ok=fmt ? sptm_root_build_shadow(mm,&t,root,fmt,flags,leaves) :
        sptm_root_build_linked_memo(mm,&t,root,fmt,flags,leaves,&links,
                                    memo_in_build ? &memo : 0,grouped);
    *out=t.root;return ok;
}
static void miss_install(void *ctx,uint64_t shadow,uint64_t root,uint64_t asid,unsigned fmt)
{(void)ctx;(void)root;(void)asid;(void)fmt;installs_seen++;installed_shadow=shadow;}
static struct sptm_root_backend sb={.kernel_root=BASE,.kernel_shadow=BASE,.build=miss_build,
    .install=miss_install,.validate=&vs,.memo=&memo,.linked_builds=1};
static enum sptm_result sw(unsigned cpu,uint64_t root)
{return sptm_mac_switch_root(&m,&rs,&sb,cpu,root,0,0);}
/* Leave on cpu and drop the cached shadow: the next switch is a miss. */
static void evict(unsigned cpu,uint64_t root)
{CHECK(sw(cpu,BASE)==SPTM_OK);CHECK(sptm_root_invalidate(&rs,root,0));}
static uint64_t lookups(void) {return memo.stats.hits+memo.stats.misses;}
static uint64_t child_at(unsigned i) {return word(slot_at(ROOT,2,START+i*SPAN))&geom.pa_mask;}
static uint64_t private_slot(void) {return private_l3+8*sptm_mac_user_index(&geom,3,PVA);}
/* One 16K user root nesting three populated shared tables (linked groups
 * exist) plus one private level-3 table with one NX leaf. */
static void scene(void)
{
    lsetup(0,1);
    CHECK(!sptm_mac_nest_region(&m,&backend,USER,ROOT,START,3*SPAN/PAGE));
    m.refs=&miss_refs;
    parents(USER,20,PVA);
    private_l3=allocate(20,3);
    CHECK(!sptm_mac_map_user_table_live(&m,&backend,USER,PVA,2,private_l3|3));
    private_data=next_frame;next_frame+=PAGE;CHECK(next_frame<USER2);
    uint64_t result=1;
    CHECK(sptm_mac_map_user_page(&m,&backend,USER,PVA,private_data|LEAF,1,0,&result)==SPTM_OK && !result);
    fixture_publish=m.publish;m.publish=witness_publish;m.root_memo=&memo;
    memset(&memo,0,sizeof memo);memset(&vs,0,sizeof vs);memset(&rs,0,sizeof rs);
    build_calls=installs_seen=0;installed_shadow=0;memo_in_build=1;
    build_base=next_shadow;
}
static uint64_t hw_leaf(uint64_t shadow,uint64_t va)
{
    struct mmu_config cfg={12,17,shadow};struct mmu_leaf leaf;
    CHECK(!mmu_walk(&cfg,va,read_hw,0,&leaf));
    return leaf.valid ? leaf.descriptor : 0;
}
/* The installed tree translates every mapped 4K exactly as a copying build. */
static void same_as_copy(void)
{
    uint64_t saved=next_shadow,leaves=0;
    struct shadow copy={.txsz=17,.root=fresh_tree(),.alloc=alloc_hw,.read=read_hw,.write=write_hw};
    CHECK(sptm_root_build_shadow(&m,&copy,USER,0,2,&leaves));
    CHECK(same(copy.root,installed_shadow,START,3*SPAN) && same(copy.root,installed_shadow,PVA,PAGE));
    next_shadow=saved;
}
static void lookups_on_miss(void)
{
    scene();
    uint64_t before=lookups();
    CHECK(sw(0,USER)==SPTM_OK && build_calls==1 && installs_seen==1);
    /* Empty memo: the walk misses and records the 3 shared tables; the build
     * finds them; the private table is never looked up. */
    CHECK(lookups()-before==6 && memo.stats.misses==3 && memo.stats.hits==3 && memo.stats.records==3);
    CHECK(!memo.stats.calls);
    same_as_copy();
    CHECK(sw(0,BASE)==SPTM_OK);
    /* A walked hit answers every level-3 table it can, private included. */
    CHECK(sw(1,USER)==SPTM_OK && build_calls==1 && memo.stats.calls==1);
    CHECK(memo.stats.records==4 && memo.stats.misses==4);
    CHECK(sw(1,BASE)==SPTM_OK && sptm_root_invalidate(&rs,USER,0));
    before=lookups();uint64_t hits=memo.stats.hits;
    CHECK(sw(2,USER)==SPTM_OK && build_calls==2);
    CHECK(lookups()-before==6 && memo.stats.hits-hits==6);
    CHECK(memo.stats.calls==1 && memo.stats.records==memo.stats.misses);
    CHECK(vs.validations==3 && memo.stats.sampled<=vs.sampled && !vs.mismatches);
    same_as_copy();
    evict(2,USER);
}
static void private_change_refused(void)
{
    scene();
    CHECK(sw(0,USER)==SPTM_OK);evict(0,USER);
    CHECK(sw(1,USER)==SPTM_OK);              /* miss: built, verdicts for shared */
    CHECK(sw(1,BASE)==SPTM_OK);
    CHECK(sw(2,USER)==SPTM_OK && memo.stats.calls==1);  /* walked hit: private verdict too */
    CHECK(sw(2,BASE)==SPTM_OK);
    uint64_t slot=private_slot(),old=word(slot);
    setword(slot,old&~PT_UXN);              /* unpublished: user-executable DEFAULT frame */
    /* A hit still answers from the verdict (the existing trust model) and
     * installs the cached shadow: the changed leaf is not in it. */
    CHECK(sw(3,USER)==SPTM_OK && (hw_leaf(installed_shadow,PVA)&PT_UXN));
    evict(3,USER);
    /* The linked build on its own scans the copied table too. */
    {
        uint64_t saved=next_shadow,leaves=0;
        struct shadow t={.txsz=17,.root=fresh_tree(),.alloc=alloc_hw,.read=read_hw,.write=write_hw};
        link_tree=t;link_slot=8;
        CHECK(!sptm_root_build_linked_memo(&m,&t,USER,0,2,&leaves,&links,&memo,grouped));
        native_shared_forget_slot(&ns,8);next_shadow=saved;
    }
    unsigned builds=build_calls,installs=installs_seen;
    CHECK(sw(4,USER)==SPTM_BAD_TABLE);       /* the miss scans the private table */
    CHECK(build_calls==builds && installs_seen==installs && !rs.active[4]);
    setword(slot,old);
    CHECK(sw(4,USER)==SPTM_OK && (hw_leaf(installed_shadow,PVA)&PT_UXN));
    evict(4,USER);
}
static void created_group_scanned(void)
{
    scene();
    CHECK(sw(0,USER)==SPTM_OK);evict(0,USER);
    uint64_t child=child_at(1),old=word(child);
    memset(&ns,0,sizeof ns);                /* no group exists: the build would create it */
    build_base=0;                           /* new group pages: stop reusing the build region */
    setword(child,old&~PT_UXN);             /* unpublished, inadmissible */
    uint64_t hits=memo.stats.hits;unsigned installs=installs_seen;
    CHECK(sw(1,USER)==SPTM_MEMORY_UNAVAILABLE);
    /* Refused before child 1's group exists (child 0's, admissible, was made). */
    CHECK(memo.stats.hits>hits && installs_seen==installs && native_shared_find(&ns,child)<0);
    setword(child,old);
    CHECK(sw(1,USER)==SPTM_OK && ns.live==3);
    same_as_copy();
    evict(1,USER);
}
static void linked_change_and_reference_walk(void)
{
    scene();
    CHECK(sw(0,USER)==SPTM_OK);evict(0,USER);
    uint64_t child=child_at(0),old=word(child);
    setword(child,old&~PT_UXN);             /* unpublished; its group keeps the old leaf */
    vs.validations=1;
    CHECK(sw(1,USER)==SPTM_OK);
    CHECK(hw_leaf(installed_shadow,START)&PT_UXN);   /* the guest change reached no hardware */
    evict(1,USER);
    vs.validations=63;                      /* the next walk is the sampled reference */
    unsigned installs=installs_seen;
    CHECK(sw(2,USER)==SPTM_BAD_TABLE);
    CHECK(vs.mismatches==1 && memo.stats.mismatches==1 && installs_seen==installs);
    setword(child,old);
}
static void published_store_retires(void)
{
    scene();
    CHECK(sw(0,USER)==SPTM_OK);evict(0,USER);
    uint64_t child=child_at(2),old=word(child);
    setword(child,old&~PT_UXN);m.publish(0,child,8);  /* a published violation */
    uint64_t misses=memo.stats.misses;
    CHECK(sw(1,USER)==SPTM_BAD_TABLE && memo.stats.misses==misses+1);
    setword(child,old);m.publish(0,child,8);
    CHECK(sw(1,USER)==SPTM_OK);
    evict(1,USER);
}
static void four_k_root_consults_nothing(void)
{
    setup(1,0,3,1);
    uint64_t span=1UL<<(2*geom.shift-3);
    CHECK(!sptm_mac_nest_region(&m,&backend,USER,ROOT,START,3*geom.group*span/geom.page_size));
    fixture_publish=m.publish;m.publish=witness_publish;m.root_memo=&memo;
    memset(&memo,0,sizeof memo);memset(&vs,0,sizeof vs);memset(&rs,0,sizeof rs);
    build_base=0;
    uint64_t before=lookups();
    CHECK(sw(0,USER)==SPTM_OK && lookups()==before);
    CHECK(sw(0,BASE)==SPTM_OK && sptm_root_invalidate(&rs,USER,0));
    CHECK(sw(1,USER)==SPTM_OK && lookups()==before);
    CHECK(sw(1,BASE)==SPTM_OK);
    CHECK(sw(2,USER)==SPTM_OK && lookups()>before && memo.stats.calls==1);  /* a hit does */
    CHECK(sw(2,BASE)==SPTM_OK);
}
/* Reference: a full copying build of the current guest tree (no verdicts). */
static int reference_ok(void)
{
    uint64_t saved=next_shadow,leaves=0;
    struct shadow copy={.txsz=17,.root=fresh_tree(),.alloc=alloc_hw,.read=read_hw,.write=write_hw};
    int ok=sptm_root_build_shadow(&m,&copy,USER,0,2,&leaves);
    next_shadow=saved;return ok;
}
static uint64_t rng=0x2545f4914f6cdd1dUL;
static unsigned rnd(unsigned n) {rng^=rng<<13;rng^=rng>>7;rng^=rng<<17;return (unsigned)(rng%n);}
static void random_published(void)
{
    scene();
    CHECK(sw(0,USER)==SPTM_OK);evict(0,USER);
    struct shadow w=group_w;
    unsigned agree=0,refused=0,accepted=0;
    for(unsigned step=0;step<1500;step++) {
        unsigned which=rnd(4);
        uint64_t slot=which<3 ? child_at(which) : private_slot();
        uint64_t old=word(slot),next=old;
        unsigned op=rnd(16);
        if(op<8)next=old^PT_AF;                /* admissible either way */
        else if(op==8)next=old&~PT_UXN;        /* inadmissible */
        else if(op<13)next=old|PT_UXN;         /* restore */
        if(next!=old) {
            setword(slot,next);m.publish(0,slot,8);
            if(which<3) {                      /* the shared update keeps its group */
                int g=native_shared_find(&ns,child_at(which));
                CHECK(g>=0 && native_shared_store(&ns,&w,g,START+which*SPAN,next));
            }
        }
        if(rnd(3))continue;
        int want=reference_ok();
        unsigned cpu=rnd(6);
        if(rnd(16)==0)vs.validations=63;       /* sometimes the sampled walk */
        enum sptm_result r=sw(cpu,USER);
        CHECK((r==SPTM_OK)==want);
        agree+=(r==SPTM_OK)==want;
        if(r==SPTM_OK) {accepted++;evict(cpu,USER);} else refused++;
    }
    CHECK(agree==accepted+refused && accepted && refused && !vs.mismatches);
    /* A refused walk records nothing (the monitor would stop there). */
    CHECK(memo.stats.records<=memo.stats.misses && !memo.stats.mismatches);
    printf("random: %u published-sequence misses agree with full builds (%u accepted, %u refused)\n",
           agree,accepted,refused);
}
int main(void)
{
    nesting_fixture_checks(1,0);
    unnest_fixture_checks();
    unsigned before=checks;
    lookups_on_miss();
    private_change_refused();
    created_group_scanned();
    linked_change_and_reference_walk();
    published_store_retires();
    four_k_root_consults_nothing();
    random_published();
    printf("PASS: %u miss-verdict checks (%u total)\n",checks-before,checks);
    return 0;
}

/* SPDX-License-Identifier: MIT */
/* SNAP_NATIVE_SHARED through the real NEST/UNNEST/SWITCH_ROOT fixtures: a
 * 16K root links its nested shared level-3 tables to shared 4K groups
 * (sptm_root_*_linked, shadow/native-shared.c). Every result is compared
 * with the copying path it replaces: the same hardware translation at
 * every 4K address, the same leaf counts, the same refusals. */
#define SPTM_UNNEST_TEST_MAIN unnest_fixture_checks
#include "test-sptm-unnest.c"
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

static void nest_matrix(void)
{
    uint64_t span=1UL<<25;
    for(unsigned active=0;active<=6;active++)for(unsigned populated=0;populated<2;populated++)
    for(unsigned variant=0;variant<3;variant++) {
        lsetup(active,populated);
        uint64_t va=START,pages=2*span/PAGE;unsigned count=2;
        if(variant==1){va+=PAGE;pages=1;count=1;}
        if(variant==2){va+=span+PAGE;pages=span/PAGE;count=2;}
        CHECK(!sptm_mac_nest_region(&m,&backend,USER,ROOT,va,pages));
        CHECK(lprep==1 && lcommit==1);
        /* The guest side, refusals of a repeat and leaf counts: as copying. */
        prepared=committed=1;verify(va,pages,count,populated);
        uint64_t base=va&~(span-1);
        CHECK(ns.live==count && ns.linked==count);
        for(unsigned n=0;n<count;n++) {
            uint64_t child=word(slot_at(ROOT,2,base+n*span))&geom.pa_mask;
            int g=native_shared_find(&ns,child);
            CHECK(g>=0 && links_of(g)==1 && ns.group[g].leaves==(uint64_t)populated);
            CHECK(native_shared_linked(&ns,&hw,g) && native_shared_verify(&ns,&group_w,g,read_hw,0));
        }
        /* A copying build of the same guest tree is the same translation. */
        struct shadow copy={.txsz=17,.root=fresh_tree(),.alloc=alloc_hw,.read=read_hw,.write=write_hw};
        uint64_t cleaves=0;
        CHECK(sptm_root_build_shadow(&m,&copy,USER,0,2,&cleaves));
        CHECK(cleaves==cache.leaves && same(copy.root,cache.shadow,base,count*span));
    }
}

static void second_consumer_and_build(void)
{
    uint64_t span=1UL<<25,pages=span/PAGE;
    lsetup(0,1);
    CHECK(!sptm_mac_nest_region(&m,&backend,USER,ROOT,START+PAGE,pages));
    struct sptm_root_cached first=cache;struct shadow first_hw=hw;
    create(USER2,11,0,2);parents(USER2,20,START);
    CHECK(!sptm_mac_set_shared_region(&m,USER2,ROOT));
    cache=(struct sptm_root_cached){.root=USER2,.shadow=alloc_hw(0),.asid=11,.format=0,.flags=2,.valid=1};
    hw.root=cache.shadow;link_slot=1;
    uint64_t created=ns.created;
    CHECK(!sptm_mac_nest_region(&m,&backend,USER2,ROOT,START+PAGE,pages));
    /* No new groups: the second address space links the same ones. */
    CHECK(ns.created==created && ns.live==2 && cache.leaves==first.leaves && cache.leaves==2);
    for(unsigned n=0;n<2;n++) {
        int g=native_shared_find(&ns,word(slot_at(ROOT,2,START+n*span))&geom.pa_mask);
        CHECK(g>=0 && links_of(g)==2);
    }
    CHECK(same(first.shadow,cache.shadow,START,2*span));
    /* A group store is seen by both address spaces at once. */
    int g=native_shared_find(&ns,word(slot_at(ROOT,2,START))&geom.pa_mask);
    uint64_t child=ns.group[g].guest,data=word(child)&0x0000ffffffffc000UL;
    /* A second mapping of the fixture's data frame keeps the guest tree valid. */
    setword(child+8*5,data|0x0060000000000fc3UL);
    CHECK(native_shared_store(&ns,&group_w,g,START+5*PAGE,data|0x0060000000000fc3UL));
    CHECK(ns.group[g].leaves==2 && native_shared_verify(&ns,&group_w,g,read_hw,0));
    struct mmu_config a={12,17,first.shadow},b={12,17,cache.shadow};struct mmu_leaf x,y;
    CHECK(!mmu_walk(&a,START+5*PAGE+4096,read_hw,0,&x) && !mmu_walk(&b,START+5*PAGE+4096,read_hw,0,&y));
    CHECK(x.valid && y.valid && x.pa==data+4096 && y.pa==x.pa);
    /* A linked build equals a copying build of the same guest tree. */
    struct shadow built={.txsz=17,.root=fresh_tree(),.alloc=alloc_hw,.read=read_hw,.write=write_hw};
    struct shadow copied={.txsz=17,.root=fresh_tree(),.alloc=alloc_hw,.read=read_hw,.write=write_hw};
    uint64_t lleaves=0,cleaves=0;link_tree=built;link_slot=2;
    CHECK(sptm_root_build_linked(&m,&built,USER2,0,2,&lleaves,&links));
    CHECK(sptm_root_build_shadow(&m,&copied,USER2,0,2,&cleaves));
    CHECK(lleaves==cleaves && lleaves==3 && same(built.root,copied.root,0,UINT64_C(1)<<33));
    CHECK(links_of(g)==3 && ns.created==created);
    /* A tree that is not fresh is refused (clearing it could clear shared
     * leaves): here one private leaf far from the shared region. */
    struct shadow used={.txsz=17,.root=fresh_tree(),.alloc=alloc_hw,.read=read_hw,.write=write_hw};
    CHECK(!shadow_map(&used,0x10000000UL,0x900000000UL,4096,0xf43,PT_PXN|PT_UXN));
    link_tree=used;link_slot=4;
    CHECK(!sptm_root_build_linked(&m,&used,USER2,0,2,&lleaves,&links) && !slot_links_any(4));
    link_tree=built;link_slot=2;
    /* A 4K root never links. */
    CHECK(!sptm_root_build_linked(&m,&copied,USER2,1,2,&lleaves,&links));
    /* Releasing slot 2 gives its links back. */
    CHECK(native_shared_forget_slot(&ns,2) && links_of(g)==2);
    cache=first;hw=first_hw;link_slot=0;
}

static void unnest_linked_checks(void)
{
    uint64_t span=1UL<<25;
    for(unsigned populated=0;populated<2;populated++)for(unsigned variant=0;variant<3;variant++) {
        lsetup(0,populated);
        CHECK(!sptm_mac_nest_region(&m,&backend,USER,ROOT,START,3*span/PAGE));
        uint64_t va=START,pages=span/PAGE;unsigned count=1;
        if(variant==1){va+=PAGE;pages=1;}
        if(variant==2){va+=span+PAGE;pages=span/PAGE;count=2;}
        uint64_t first=va&~(span-1),original=cache.leaves;
        CHECK(!sptm_mac_unnest_region(&m,&backend,USER,ROOT,va,pages));
        CHECK(unprep==1 && uncommit==1 && last_plan.descriptors==count);
        CHECK(last_plan.leaves==(populated?count:0) && cache.leaves==original-last_plan.leaves);
        CHECK(ns.unlinked==count && ns.live==3);
        for(unsigned i=0;i<3;i++) {
            uint64_t addr=START+i*span;
            int removed=addr>=first && addr<first+count*span;
            int g=native_shared_find(&ns,word(slot_at(ROOT,2,addr))&geom.pa_mask);
            CHECK(g>=0 && links_of(g)==(uint64_t)!removed && native_shared_slot_links(&ns,link_slot,g)==!removed);
            /* Entries name the group's pages while linked; an unlinked group with
             * pages is gone from the tree (a pageless one maps nothing either way). */
            int pages=0;
            for(unsigned p=0;p<NATIVE_SHARED_PAGES;p++)pages+=!!ns.group[g].pages[p];
            CHECK(removed ? !pages || !native_shared_linked(&ns,&hw,g) : native_shared_linked(&ns,&hw,g));
            CHECK(pages==(populated ? 1 : 0));
            struct mmu_config cfg={12,17,cache.shadow};struct mmu_leaf leaf;
            CHECK(!mmu_walk(&cfg,addr,read_hw,0,&leaf) && leaf.valid==(populated && !removed));
        }
        /* Re-nest relinks the retained groups. */
        CHECK(!sptm_mac_nest_region(&m,&backend,USER,ROOT,va,pages));
        CHECK(cache.leaves==original && ns.live==3);
    }
    /* Refusals leave guest, groups and links unchanged. */
    for(unsigned bad=0;bad<3;bad++) {
        lsetup(0,1);
        CHECK(!sptm_mac_nest_region(&m,&backend,USER,ROOT,START,span/PAGE));
        int g=native_shared_find(&ns,word(slot_at(ROOT,2,START))&geom.pa_mask);
        uint64_t table=0;
        if(bad==0)unfail=1;
        if(bad==1) {  /* the root's link was lost */
            struct mmu_config cfg={12,17,cache.shadow};(void)cfg;
            CHECK(!shadow_table(&hw,2,START,&table));
            setword(table+8*mmu_index(12,2,START),0);
        }
        if(bad==2)link_slot=5;  /* another slot's records */
        snapshot();
        CHECK(sptm_mac_unnest_region(&m,&backend,USER,ROOT,START,span/PAGE)!=SPTM_OK);
        CHECK(!uncommit && links_of(g)==1);
        if(!bad)unchanged();
    }
    /* A shared leaf this root's policy refuses (user-executable, but its
     * frame is not USER_EXEC) keeps the nest out, as copying did. */
    lsetup(0,1);
    {
        uint64_t child=word(slot_at(ROOT,2,START))&geom.pa_mask;
        setword(child,word(child)&~PT_UXN);
        snapshot();
        CHECK(sptm_mac_nest_region(&m,&backend,USER,ROOT,START,span/PAGE)!=SPTM_OK);
        CHECK(!lcommit && ns.linked==0);
    }
    /* UNNEST refuses groups whose leaves differ from the plan's count. */
    lsetup(0,1);
    CHECK(!sptm_mac_nest_region(&m,&backend,USER,ROOT,START,span/PAGE));
    {
        int g=native_shared_find(&ns,word(slot_at(ROOT,2,START))&geom.pa_mask);
        CHECK(g>=0);ns.group[g].leaves++;
        CHECK(sptm_mac_unnest_region(&m,&backend,USER,ROOT,START,span/PAGE)!=SPTM_OK && !uncommit);
        ns.group[g].leaves--;
    }
    /* A nest over a range the root's tree already maps is refused before
     * any guest change; a failed prepare allocates no link. */
    lsetup(0,1);
    CHECK(!shadow_map(&hw,START+span,0x900000000UL,4096,0xf43,PT_PXN|PT_UXN));
    snapshot();
    CHECK(sptm_mac_nest_region(&m,&backend,USER,ROOT,START,2*span/PAGE)!=SPTM_OK);
    CHECK(!lcommit && ns.linked==0);
}

int main(void)
{
    nesting_fixture_checks(1,0);
    unnest_fixture_checks();
    unsigned before=checks;
    nest_matrix();second_consumer_and_build();unnest_linked_checks();
    printf("PASS: %u linked shared-region checks on the NEST/UNNEST/SWITCH_ROOT fixtures (%u total)\n",
           checks-before,checks);
    return 0;
}

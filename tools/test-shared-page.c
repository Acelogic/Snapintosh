/* SPDX-License-Identifier: MIT */
#define SPTM_NEST_TEST_MAIN nesting_fixture_checks
#include "test-sptm-nest.c"
#include "sptm-refs.h"
#include "sprr-view.h"
#define BOUND (USER2+PAGE)
#define DATA (BASE+190*PAGE)
#define OUT (BASE+PAGE+0x1000)
static struct sptm_ref_batch refs;
static struct sprr_views views[3];
static struct sprr_state states[3][6];
static uint64_t plan;
static unsigned fail_alias,prepare_count,commits,flushes,nested;
static void check_recorded_roots(void)
{
    struct sptm_root_state s={0};
    /* Native first shared-page request: CPU0 owns a user root, the other
     * CPUs have switched to the kernel (active=0, recorded TTBR0 nonzero). */
    s.active[0]=USER;
    CHECK(sptm_root_recorded_matches(&s,0,USER|(10UL<<48),ROOT));
    for(unsigned cpu=1;cpu<6;cpu++) {
        CHECK(sptm_root_recorded_matches(&s,cpu,ROOT,ROOT));
        CHECK(sptm_root_recorded_matches(&s,cpu,0,ROOT));
        CHECK(!sptm_root_recorded_matches(&s,cpu,USER,ROOT));
        CHECK(!sptm_root_recorded_matches(&s,cpu,ROOT|(10UL<<48),ROOT));
    }
    CHECK(!sptm_root_recorded_matches(&s,0,ROOT,ROOT));
    CHECK(!sptm_root_recorded_matches(&s,0,0,ROOT));
    CHECK(!sptm_root_recorded_matches(&s,0,USER2,ROOT));
    CHECK(!sptm_root_recorded_matches(&s,6,0,ROOT));
}
static struct shadow shadow_for(unsigned i)
{struct shadow s=hw;s.root=roots.cache[i].shadow;return s;}
static int sync_view(unsigned i)
{
    struct shadow s=shadow_for(i);
    for(unsigned cpu=0;cpu<6;cpu++)
        if(!sprr_views_sync_user_cpu(&views[i],&s,cpu,&states[i][cpu],cpu!=1))return 0;
    return 1;
}
static int prepare_shared(void *ctx,uint64_t root,uint64_t va,unsigned shift,uint64_t old,uint64_t next)
{
    (void)ctx;(void)next;uint64_t mask;
    if(!sptm_root_shared_aliases(&m,&roots,root,va,shift,&mask))return 0;
    for(unsigned i=0;i<3;i++)if(mask&(1UL<<i)) {
        struct shadow s=shadow_for(i);prepare_count++;
        if(prepare_count==fail_alias ||
           !sptm_root_prepare_unmap(&roots.cache[i],&s,&m,va,shift,1) ||
           (!old && !sptm_root_prepare_leaf(&roots.cache[i],&s,va,shift)))return 0;
    }
    plan=mask;return 1;
}
static int commit_shared(void *ctx,uint64_t root,uint64_t va,unsigned shift,uint64_t old,uint64_t next)
{
    (void)ctx;uint64_t mask;
    if(!sptm_root_shared_aliases(&m,&roots,root,va,shift,&mask) || mask!=plan)return 0;
    for(unsigned i=0;i<3;i++)if(mask&(1UL<<i)) {
        struct shadow s=shadow_for(i);
        if(!(old ? sptm_root_commit_update(&roots.cache[i],&s,&m,va,shift,old,next) :
                   sptm_root_commit_leaf(&roots.cache[i],&s,&m,va,shift,next)) || !sync_view(i))return 0;
    }
    commits++;flushes++;return 1;
}
static int prepare_shared_unmap(void *ctx,uint64_t root,uint64_t va,unsigned shift,uint64_t count)
{
    (void)ctx;uint64_t mask;
    if(!sptm_root_shared_aliases(&m,&roots,root,va,shift,&mask))return 0;
    for(unsigned i=0;i<3;i++)if(mask&(1UL<<i)) {
        struct shadow s=shadow_for(i);prepare_count++;
        if(prepare_count==fail_alias || !sptm_root_prepare_unmap(&roots.cache[i],&s,&m,va,shift,count))return 0;
    }
    plan=mask;return 1;
}
static int commit_shared_unmap(void *ctx,uint64_t root,uint64_t va,unsigned shift,uint64_t count,uint64_t removed)
{
    (void)ctx;uint64_t mask;
    if(!sptm_root_shared_aliases(&m,&roots,root,va,shift,&mask) || mask!=plan)return 0;
    /* Data ownership cannot be released before every alias and TLB. */
    CHECK(!removed || word(m.frame_map_pa+((DATA-BASE)>>14)*16+8));
    for(unsigned i=0;i<3;i++)if(mask&(1UL<<i)) {
        struct shadow s=shadow_for(i);
        if(!sptm_root_commit_unmap(&roots.cache[i],&s,va,shift,count,removed) || !sync_view(i))return 0;
    }
    commits++;flushes++;return 1;
}
static void init(unsigned fmt,unsigned active,unsigned aliases)
{
    setup(fmt,0,2,0);nested=aliases;
    memset(&refs,0,sizeof refs);m.refs=&refs;
    if(aliases)CHECK(!sptm_mac_nest_region(&m,&backend,USER,ROOT,START,
        (1UL<<(2*geom.shift-3))*geom.group/geom.page_size));
    roots.cache[0]=cache;
    create(USER2,11,fmt,2);parents(USER2,20,START);
    CHECK(!sptm_mac_set_shared_region(&m,USER2,ROOT));
    cache=(struct sptm_root_cached){.root=USER2,.shadow=alloc_hw(0),.asid=11,.format=fmt,.flags=2,.valid=1};
    hw.root=cache.shadow;
    if(aliases==2)CHECK(!sptm_mac_nest_region(&m,&backend,USER2,ROOT,START,
        (1UL<<(2*geom.shift-3))*geom.group/geom.page_size));
    roots.cache[1]=cache;
    create(BOUND,12,fmt,2);parents(BOUND,20,START);
    CHECK(!sptm_mac_set_shared_region(&m,BOUND,ROOT));
    roots.cache[2]=(struct sptm_root_cached){.root=BOUND,.shadow=alloc_hw(0),.asid=12,.format=fmt,.flags=2,.valid=1};
    memset(views,0,sizeof views);memset(states,0,sizeof states);
    for(unsigned i=0;i<3;i++) {
        struct shadow s=shadow_for(i);
        CHECK(sptm_root_build_shadow(&m,&s,roots.cache[i].root,fmt,2,&roots.cache[i].leaves));
        CHECK(sprr_views_init(&views[i],&s) && sprr_views_prepare_user(&views[i],&s));
        for(unsigned cpu=0;cpu<6;cpu++)sprr_root_reset(&states[i][cpu],2);
        CHECK(sync_view(i));
    }
    for(unsigned cpu=0;cpu<active;cpu++)roots.active[cpu]=USER;
    sethalf(USER,6,half(USER,6)+active);
    backend=(struct sptm_user_backend){.aperture={BASE,0xfffffe0100000000UL,sizeof(bytes)},
        .prepare_shared_leaf=prepare_shared,.commit_shared_leaf=commit_shared,
        .prepare_shared_unmap=prepare_shared_unmap,.commit_shared_unmap=commit_shared_unmap};
    fail_alias=prepare_count=commits=flushes=0;published=0;
    memset(bytes+DATA-BASE,0xa5,PAGE);setword(OUT,0xfeedface);setword(OUT+8,0xabcdef);
}
static void verify_leaf(uint64_t va,uint64_t pte)
{
    CHECK(word(slot_at(ROOT,3,va))==pte);
    for(unsigned i=0;i<3;i++) {
        int valid=i<nested && pte;
        for(unsigned cpu=0;cpu<7;cpu++)for(uint64_t off=0;off<geom.page_size;off+=4096) {
            struct mmu_config cfg={12,17,cpu==6 ? roots.cache[i].shadow:sprr_views_root(&views[i],cpu)};
            struct mmu_leaf leaf;
            CHECK(!mmu_walk(&cfg,va+off,read_hw,0,&leaf) && leaf.valid==valid);
            if(valid) {
                CHECK(leaf.pa==(pte&geom.pa_mask)+off);
                CHECK((leaf.descriptor&(PT_LEAF_ATTRS|PT_LEAF_UPPER))==(pte&(PT_LEAF_ATTRS|PT_LEAF_UPPER)));
                CHECK(!(leaf.descriptor&(3UL<<58)));
            }
        }
        struct shadow s=shadow_for(i);struct sptm_fixed_view proof;
        CHECK(sptm_root_canonical_view(&roots.cache[i],&s,&m,&proof));
        CHECK(roots.cache[i].leaves==(unsigned)valid);
    }
}
#ifndef SPTM_SHARED_PAGE_TEST_MAIN
#define SPTM_SHARED_PAGE_TEST_MAIN main
#endif
int SPTM_SHARED_PAGE_TEST_MAIN(int argc,char **argv)
{
    if(argc==4 && !strcmp(argv[1],"--pte")) {
        uint64_t next=0,result=99;
        unsigned status=sptm_mac_shared_map_pte(strtoull(argv[2],0,16),strtoull(argv[3],0,16),&next,&result);
        printf("%u %llu %016llx\n",status,(unsigned long long)result,(unsigned long long)next);return 0;
    }
    for(unsigned fmt=0;fmt<2;fmt++)for(unsigned part=0;part<(fmt?4:1);part++)
    for(unsigned active=0;active<=6;active+=6)for(unsigned aliases=0;aliases<=2;aliases++)
    for(unsigned ng=0;ng<2;ng++) {
        init(fmt,active,aliases);
        uint64_t va=START+part*(1UL<<(2*geom.shift-3))+geom.page_size;
        uint64_t ro=DATA|(part*0x1000*(fmt!=0))|0x00600000000006c3UL|((uint64_t)ng<<11),result=99;
        CHECK(!sptm_mac_map_user_page(&m,&backend,ROOT,va,ro,0,OUT,&result) && result==0);
        CHECK(!word(OUT));CHECK(word(OUT+8)==0xfffffe0100000000UL+slot_at(ROOT,3,va)-BASE);
        CHECK(word(m.frame_map_pa+((DATA-BASE)>>14)*16+8)==1);verify_leaf(va,ro);
        CHECK(commits==1 && flushes==1 && plan==((1UL<<aliases)-1));
        unsigned old_commits=commits;
        CHECK(!sptm_mac_map_user_page(&m,&backend,ROOT,va,ro,1,0,&result) && result==1);
        CHECK(commits==old_commits);verify_leaf(va,ro);
        uint64_t rw=ro&~0x80UL;
        /* Replacing a valid shared leaf reports 1 (shipped ...f95d4). */
        CHECK(!sptm_mac_map_user_page(&m,&backend,ROOT,va,rw,0,OUT,&result) && result==1);
        CHECK(word(OUT)==ro);CHECK(word(m.frame_map_pa+((DATA-BASE)>>14)*16+8)==(1UL<<32));
        verify_leaf(va,rw);
        CHECK(!sptm_mac_map_user_page(&m,&backend,ROOT,va,ro|(1UL<<59),1,0,&result));
        CHECK(word(m.frame_map_pa+((DATA-BASE)>>14)*16+8)==(1UL<<32));verify_leaf(va,ro|(1UL<<59));
        old_commits=commits;
        CHECK(!sptm_mac_map_user_page(&m,&backend,ROOT,va,ro+PAGE,0,OUT,&result) && result==6);
        CHECK(word(OUT)==(ro|(1UL<<59)) && commits==old_commits);verify_leaf(va,ro|(1UL<<59));
        CHECK(!sptm_mac_unmap_user_region(&m,&backend,ROOT,va,1,0,OUT));
        CHECK(word(OUT)==(ro|(1UL<<59)));CHECK(!word(m.frame_map_pa+((DATA-BASE)>>14)*16+8));
        verify_leaf(va,0);
        for(unsigned i=0;i<PAGE;i++)CHECK(bytes[DATA-BASE+i]==0xa5);
    }
    /* A failure in a later cached alias cannot publish a shared source leaf,
     * metadata or old-PTE output. Empty host reservations may be retained. */
    init(0,6,2);uint64_t va=START+PAGE,ro=DATA|0x00600000000006c3UL,result=99;
    fail_alias=2;memcpy(saved,bytes,250*PAGE);
    CHECK(sptm_mac_map_user_page(&m,&backend,ROOT,va,ro,0,OUT,&result)==SPTM_SHADOW_FAILED);
    CHECK(!memcmp(saved,bytes,250*PAGE) && !commits);verify_leaf(va,0);
    fail_alias=0;CHECK(!sptm_mac_map_user_page(&m,&backend,ROOT,va,ro,0,OUT,&result));
    fail_alias=prepare_count+2;memcpy(saved,bytes,250*PAGE);
    CHECK(sptm_mac_unmap_user_region(&m,&backend,ROOT,va,1,0,OUT)==SPTM_SHADOW_FAILED);
    CHECK(!memcmp(saved,bytes,250*PAGE));verify_leaf(va,ro);
    /* Ordinary user-root calls must not mutate a shared slot through only one
     * alias. Unbound/invalid geometry and cache corruption must fail too. */
    CHECK(sptm_mac_map_user_page(&m,&backend,USER2,va,ro|PT_NG,1,0,&result)==SPTM_TYPE_MISMATCH);
    init(0,0,2);roots.cache[1].asid++;
    CHECK(sptm_mac_map_user_page(&m,&backend,ROOT,va,ro,0,OUT,&result)==SPTM_SHADOW_FAILED);
    CHECK(!word(slot_at(ROOT,3,va)) && !commits);
    init(0,0,2);backend.prepare_shared_leaf=0;
    CHECK(sptm_mac_map_user_page(&m,&backend,ROOT,va,ro,0,OUT,&result)==SPTM_BAD_CONFIG);
    init(0,0,2);CHECK(sptm_mac_map_user_page(&m,&backend,ROOT,va,ro,0,DATA,&result)==SPTM_BAD_ADDRESS);
    CHECK(sptm_mac_map_user_page(&m,&backend,ROOT,0,ro,1,0,&result)==SPTM_BAD_ADDRESS);
    /* Typed executable shared pages retain their independently established
     * code-data type; DEFAULT cannot obtain execute permission. */
    init(0,0,2);uint64_t rx=ro&~PT_UXN;
    CHECK(sptm_mac_map_user_page(&m,&backend,ROOT,va,rx,1,0,&result)==SPTM_UNSUPPORTED_OPTIONS);
    meta(DATA)[2]=14;
    CHECK(!sptm_mac_map_user_page(&m,&backend,ROOT,va,rx,0,OUT,&result));verify_leaf(va,rx);
    CHECK(!sptm_mac_map_user_page(&m,&backend,ROOT,va,ro,0,OUT,&result));verify_leaf(va,ro);
    CHECK(!sptm_mac_unmap_user_region(&m,&backend,ROOT,va,1,0,OUT));verify_leaf(va,0);
    /* Populate an uninstalled shared page first, then nest its containing
     * table. The new consumer must see it without a second data reference. */
    init(0,0,0);
    CHECK(!sptm_mac_map_user_page(&m,&backend,ROOT,va,ro,0,OUT,&result));
    cache=roots.cache[0];hw.root=cache.shadow;
    struct sptm_user_backend late={.prepare_nest=prepare,.commit_nest=commit};
    CHECK(!sptm_mac_nest_region(&m,&late,USER,ROOT,START,1));
    roots.cache[0]=cache;nested=1;CHECK(sync_view(0));verify_leaf(va,ro);
    CHECK(word(m.frame_map_pa+((DATA-BASE)>>14)*16+8)==1);
    check_recorded_roots();
    printf("PASS: %u shared-page checks (source refs, cached aliases, six views, both geometries)\n",checks);
    return 0;
}

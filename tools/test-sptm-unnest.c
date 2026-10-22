/* SPDX-License-Identifier: MIT */
#define SPTM_NEST_TEST_MAIN nesting_fixture_checks
#include "test-sptm-nest.c"
#include "sprr-view.h"
static struct sprr_views private_views,other_views;
static struct sprr_state permissions[6];
static struct sptm_unnest_plan last_plan;
static unsigned unprep,uncommit,unfail;
static int sync_private(struct sprr_views *v,struct shadow *s)
{
    for(unsigned cpu=0;cpu<6;cpu++)
        if(!sprr_views_sync_user_cpu(v,s,cpu,&permissions[cpu],cpu!=1))return 0;
    return 1;
}
static int unprepare(void *ctx,uint64_t root,uint64_t shared,unsigned shift,
                     const struct sptm_unnest_plan *p)
{
    (void)ctx;CHECK(root==cache.root);unprep++;
    return !unfail && sptm_root_prepare_unnest(&cache,&hw,&m,shared,shift,p);
}
static int uncommit_fn(void *ctx,uint64_t root,uint64_t shared,unsigned shift,
                       const struct sptm_unnest_plan *p)
{
    (void)ctx;CHECK(root==cache.root);uncommit++;
    /* All original links must still be held until this callback flushes. */
    for(unsigned i=0;i<p->count;i++)if(p->mask[i/64]&(1UL<<(i%64)))
        CHECK(half(word(slot_at(ROOT,2,p->base+i*p->span))&~(PAGE-1),6)>=2);
    if(!sptm_root_commit_unnest(&cache,&hw,&m,shared,shift,p) ||
       !sync_private(&private_views,&hw))return 0;
    last_plan=*p;flushed++;return 1;
}
static void views_init(struct sprr_views *v,struct shadow *s)
{
    memset(v,0,sizeof(*v));
    CHECK(sprr_views_init(v,s) && sprr_views_prepare_user(v,s));
    CHECK(sync_private(v,s));
}
static void init(unsigned fmt,unsigned active,unsigned populated)
{
    setup(fmt,active,3,populated!=0);
    uint64_t span=1UL<<(2*geom.shift-3);
    if(populated==2)for(unsigned i=0;i<3*geom.group;i++) {
        uint64_t child=word(slot_at(ROOT,2,START+i*span))&geom.pa_mask;
        uint64_t pte=word(child),data=pte&0x0000ffffffffc000UL;
        meta(data)[2]=14;setword(child,pte&~PT_UXN);
        setword(m.frame_map_pa+((data-BASE)>>14)*16+8,(uint64_t)geom.group<<32);
    }
    CHECK(!sptm_mac_nest_region(&m,&backend,USER,ROOT,START,3*geom.group*span/geom.page_size));
    for(unsigned cpu=0;cpu<6;cpu++)sprr_root_reset(&permissions[cpu],2);
    views_init(&private_views,&hw);
    backend.prepare_unnest=unprepare;backend.commit_unnest=uncommit_fn;
    unprep=uncommit=unfail=0;memset(&last_plan,0,sizeof(last_plan));
}
static void check_views(struct sprr_views *v,uint64_t va,int present,uint64_t expected)
{
    for(unsigned cpu=0;cpu<6;cpu++)for(unsigned off=0;off<geom.page_size;off+=4096) {
        struct mmu_config cfg={12,17,sprr_views_root(v,cpu)};struct mmu_leaf leaf;
        CHECK(!mmu_walk(&cfg,va+off,read_hw,0,&leaf));CHECK(leaf.valid==present);
        if(present)CHECK(leaf.pa==(expected&geom.pa_mask)+off);
    }
}
#ifndef SPTM_UNNEST_TEST_MAIN
#define SPTM_UNNEST_TEST_MAIN main
#endif
int SPTM_UNNEST_TEST_MAIN(void)
{
    for(unsigned fmt=0;fmt<2;fmt++)for(unsigned active=0;active<=6;active++)
    for(unsigned populated=0;populated<3;populated++)for(unsigned variant=0;variant<3;variant++) {
        init(fmt,active,populated);
        uint64_t span=1UL<<(2*geom.shift-3),va=START,pages=geom.group*span/geom.page_size;
        unsigned count=geom.group;
        if(variant==1){va+=geom.page_size;pages=1;count=1;}
        if(variant==2){va+=geom.group*span+geom.page_size;count=geom.group+1;}
        uint64_t first=va&~(span-1),original=cache.leaves;
        snapshot();unsigned before=flushed;
        CHECK(!sptm_mac_unnest_region(&m,&backend,USER,ROOT,va,pages));
        CHECK(unprep==1 && uncommit==1 && flushed==before+1);
        CHECK(last_plan.descriptors==count && last_plan.leaves==(populated?count:0));
        CHECK(cache.leaves==original-last_plan.leaves);
        CHECK(half(ROOT,4)==1 && registry.bindings==1 && meta(USER)[8]==meta(ROOT)[8]);
        for(unsigned i=0;i<3*geom.group;i++) {
            uint64_t addr=START+i*span,src=slot_at(ROOT,2,addr),pte=word(src);
            int removed=addr>=first && addr<first+count*span;
            CHECK(word(slot_at(USER,2,addr))==(removed?0:pte));
            CHECK(!memcmp(bytes+(src-BASE),saved+(src-BASE),8));
            uint64_t child=pte&~(PAGE-1);unsigned lost=0;
            for(unsigned j=0;j<count;j++)lost+=(word(slot_at(ROOT,2,first+j*span))&~(PAGE-1))==child;
            CHECK(half(child,6)==1+geom.group-lost);
            CHECK(!memcmp(bytes+(child-BASE),saved+(child-BASE),PAGE));
            uint64_t leaf=word(pte&geom.pa_mask);
            check_views(&private_views,addr,populated&&!removed,leaf);
            if(populated) {
                uint64_t data=leaf&0x0000ffffffffc000UL,mp=m.frame_map_pa+((data-BASE)>>14)*16;
                CHECK(!memcmp(bytes+(mp-BASE),saved+(mp-BASE),16));
            }
        }
        /* Repeated UNNEST is an idempotent no-op, then re-nest populated
         * DEFAULT or USER_EXEC pages without changing their source refs. */
        CHECK(!sptm_mac_unnest_region(&m,&backend,USER,ROOT,va,pages));
        CHECK(!last_plan.descriptors && !last_plan.leaves);
        CHECK(!sptm_mac_nest_region(&m,&backend,USER,ROOT,va,pages));
        CHECK(sync_private(&private_views,&hw));CHECK(cache.leaves==original);
    }
    for(unsigned fmt=0;fmt<2;fmt++) {
        init(fmt,0,1);uint64_t span=1UL<<(2*geom.shift-3),pages=geom.group*span/geom.page_size;
        struct sptm_root_cached consumer=cache;struct shadow first_hw=hw;
        create(USER2,11,fmt,2);parents(USER2,20,START);
        CHECK(!sptm_mac_set_shared_region(&m,USER2,ROOT));
        cache=(struct sptm_root_cached){.root=USER2,.shadow=alloc_hw(0),.asid=11,.format=fmt,.flags=2,.valid=1};
        hw.root=cache.shadow;
        CHECK(!sptm_mac_nest_region(&m,&backend,USER2,ROOT,START,pages));
        views_init(&other_views,&hw);
        cache=consumer;hw=first_hw;
        CHECK(!sptm_mac_unnest_region(&m,&backend,USER,ROOT,START,pages));
        for(unsigned i=0;i<geom.group;i++) {
            uint64_t va=START+i*span,pte=word(slot_at(ROOT,2,va));
            CHECK(word(slot_at(USER2,2,va))==pte);
            check_views(&other_views,va,1,word(pte&geom.pa_mask));
        }
        CHECK(half(ROOT,4)==2 && registry.bindings==2);
        /* An ordinary table in the span remains installed; adjacent holes
         * and shared entries are handled independently. */
        uint64_t ordinary=allocate(20,3),dst=slot_at(USER,2,START);
        sethalf(ordinary,6,1);
        for(unsigned i=0;i<geom.group;i++)setword(dst+i*8,(ordinary+i*geom.page_size)|3);
        sethalf(dst&~(PAGE-1),8,half(dst&~(PAGE-1),8)+geom.group);
        CHECK(!sptm_mac_unnest_region(&m,&backend,USER,ROOT,START,2*pages));
        for(unsigned i=0;i<geom.group;i++)CHECK(word(dst+i*8)==((ordinary+i*geom.page_size)|3));
    }
    /* v71: UNNEST of a shared table with a compressed marker must remove
     * the alias, not resolve the marker as PA 0 or count it as a mapping.
     * Failure modes: docs/UNNEST-COMPRESSED-20261018.md (written first). */
    static const uint64_t compressed[]={1UL<<61,1UL<<62,1UL<<63,
        (1UL<<63)|(1UL<<62),0xe000000000000000UL};
    for(unsigned fmt=0;fmt<2;fmt++)for(unsigned active=0;active<=6;active+=6)
    for(unsigned populated=0;populated<=1;populated++)for(unsigned k=0;k<5;k++) {
        init(fmt,active,populated);
        uint64_t span=1UL<<(2*geom.shift-3),va=START+geom.page_size;
        uint64_t child=word(slot_at(ROOT,2,START))&geom.pa_mask;
        uint64_t frame=child&~(PAGE-1),marker_slot=child+7*8;
        setword(marker_slot,compressed[k]);sethalf(frame,8,half(frame,8)+1);
        uint64_t original=cache.leaves;unsigned links_before=half(frame,6);
        snapshot();
        CHECK(sptm_mac_unnest_region(&m,&backend,USER,ROOT,va,1)==SPTM_OK);
        CHECK(unprep==1 && uncommit==1 && last_plan.descriptors==1);
        CHECK(last_plan.leaves==populated && cache.leaves==original-populated);
        CHECK(half(frame,6)==links_before-1);
        CHECK(word(marker_slot)==compressed[k]);
        CHECK(!memcmp(bytes+(frame-BASE),saved+(frame-BASE),PAGE));
        CHECK(half(ROOT,4)==1 && registry.bindings==1);
        for(unsigned i=0;i<3*geom.group;i++) {
            uint64_t at=START+i*span,src=slot_at(ROOT,2,at);
            CHECK(!memcmp(bytes+(src-BASE),saved+(src-BASE),8));
            CHECK(word(slot_at(USER,2,at))==(i?word(src):0));
            if(populated) {
                uint64_t data=word(word(src)&geom.pa_mask)&0x0000ffffffffc000UL;
                uint64_t mp=m.frame_map_pa+((data-BASE)>>14)*16;
                CHECK(!memcmp(bytes+(mp-BASE),saved+(mp-BASE),16));
            }
        }
        check_views(&private_views,START,0,0);
        check_views(&private_views,START+7*geom.page_size,0,0);
        CHECK(!sptm_mac_unnest_region(&m,&backend,USER,ROOT,va,1));
        CHECK(!last_plan.descriptors && !last_plan.leaves);
        CHECK(!sptm_mac_nest_region(&m,&backend,USER,ROOT,va,1));
        CHECK(sync_private(&private_views,&hw) && cache.leaves==original);
        CHECK(half(frame,6)==links_before && word(marker_slot)==compressed[k]);
        check_views(&private_views,START,populated,word(child));
        check_views(&private_views,START+7*geom.page_size,0,0);
    }
    /* A marker is only bits 63:61. Keep unknown and pending entries fatal,
     * with no publication or reference changes. */
    for(unsigned fmt=0;fmt<2;fmt++)for(unsigned k=0;k<3;k++) {
        init(fmt,0,0);
        uint64_t child=word(slot_at(ROOT,2,START))&geom.pa_mask;
        static const uint64_t bad_markers[]={(1UL<<63)|0x80,(1UL<<63)|0x1000,1UL<<60};
        setword(child+7*8,bad_markers[k]);snapshot();
        CHECK(sptm_mac_unnest_region(&m,&backend,USER,ROOT,START+geom.page_size,1)!=SPTM_OK);
        unchanged();CHECK(!unprep && !uncommit);
    }
    for(unsigned fmt=0;fmt<2;fmt++)for(unsigned bad=0;bad<11;bad++) {
        init(fmt,0,1);uint64_t span=1UL<<(2*geom.shift-3),va=START,pages=geom.group*span/geom.page_size;
        uint64_t dst=slot_at(USER,2,va),child=word(dst)&~(PAGE-1);
        switch(bad) {
        case 0:pages=0;break;case 1:va++;break;
        case 2:sethalf(child,6,geom.group);break;
        case 3:sethalf(dst&~(PAGE-1),8,0);break;
        case 4:meta(child)[0]=1;break;case 5:unfail=1;break;
        case 6:meta(USER)[8]=255;break;case 7:meta(ROOT)[12]^=1;break;
        case 8:setword(dst,word(slot_at(ROOT,2,START+geom.group*span)));break;
        case 9:deny=child;break;
        case 10:pages=(1UL<<(3*geom.shift-6))/geom.page_size+1;break;
        }
        snapshot();CHECK(sptm_mac_unnest_region(&m,&backend,USER,ROOT,va,pages)!=SPTM_OK);
        unchanged();CHECK(!uncommit);
    }
    init(0,0,0);CHECK(!sptm_mac_unnest_region(&m,&backend,USER,ROOT,START,(1UL<<32)|1));
    printf("PASS: %u UNNEST checks (126 geometry/activity/payload/range combinations, private views, refs, failure atomicity)\n",checks);
    return 0;
}

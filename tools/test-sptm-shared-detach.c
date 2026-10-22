/* SPDX-License-Identifier: MIT */
#define SPTM_UNNEST_TEST_MAIN unnest_fixture_checks
#include "test-sptm-unnest.c"
static struct sptm_shared_detach_state history;
static uint64_t expected_child,expected_slot;
static unsigned detach_prepares,detach_commits,detach_fail;
static int detach_prepare(void *ctx,uint64_t root,uint64_t va,unsigned shift,
                          unsigned level,uint64_t removed)
{
    (void)ctx;(void)va;CHECK(root==ROOT && shift==geom.shift && !removed);
    CHECK(word(expected_slot) && half(expected_child,6)==1);
    CHECK(!half(expected_child,8) && level<3);detach_prepares++;
    return !detach_fail;
}
static int detach_commit(void *ctx,uint64_t root,uint64_t va,unsigned shift,
                         unsigned level,uint64_t removed)
{
    (void)ctx;(void)va;(void)shift;(void)level;CHECK(root==ROOT && !removed);
    /* Lifetime references survive until the invalidation callback. */
    for(unsigned i=0;i<geom.group;i++)CHECK(!word(expected_slot+i*8));
    CHECK(half(expected_child,6)==1 && !history.calls);
    detach_commits++;flushed++;return 1;
}
static struct sptm_user_backend detach_backend(void)
{
    memset(&history,0,sizeof(history));detach_prepares=detach_commits=detach_fail=0;
    expected_slot=slot_at(ROOT,2,START);expected_child=word(expected_slot)&~(PAGE-1);
    return (struct sptm_user_backend){.prepare_detach=detach_prepare,
        .commit_detach=detach_commit,.shared_detaches=&history};
}
int main(void)
{
    for(unsigned fmt=0;fmt<2;fmt++)for(unsigned active=0;active<=6;active++) {
        init(fmt,active,0);uint64_t span=1UL<<(2*geom.shift-3),pages=geom.group*span/geom.page_size;
        struct sptm_user_backend b=detach_backend();
        snapshot();CHECK(sptm_mac_unmap_user_table(&m,&b,ROOT,START,2)==SPTM_BAD_REFERENCE);
        unchanged();CHECK(!detach_prepares && !history.calls);
        CHECK(!sptm_mac_unnest_region(&m,&backend,USER,ROOT,START,pages));
        uint64_t parent=expected_slot&~(PAGE-1),before=half(parent,8);
        snapshot();CHECK(!sptm_mac_unmap_user_table(&m,&b,ROOT,START,0x10002));
        CHECK(detach_prepares==1 && detach_commits==1 && history.calls==1);
        CHECK(!half(expected_child,6) && half(parent,8)==before-1);
        CHECK(half(ROOT,4)==1 && registry.bindings==1 && meta(USER)[8]==meta(ROOT)[8]);
        struct sptm_shared_detach_record *v=&history.records[0];
        CHECK(v->root==ROOT && v->va==START && v->child==expected_child && v->slot==expected_slot);
        CHECK(v->format==fmt && v->level==2 && v->parent_count==before && v->bindings==1);
        for(unsigned i=0;i<3*geom.group;i++) {
            uint64_t addr=START+i*span;check_views(&private_views,addr,0,0);
            if(i>=geom.group) {
                uint64_t src=slot_at(ROOT,2,addr),pte=word(src);
                CHECK(!memcmp(bytes+(src-BASE),saved+(src-BASE),8));
                CHECK(word(slot_at(USER,2,addr))==pte);
            }
        }
        CHECK(!sptm_mac_retype(&m,expected_child,21,11,0));
        CHECK(meta(expected_child)[2]==11);
    }
    for(unsigned fmt=0;fmt<2;fmt++)for(unsigned bad=0;bad<11;bad++) {
        init(fmt,0,bad==0);uint64_t span=1UL<<(2*geom.shift-3);
        CHECK(!sptm_mac_unnest_region(&m,&backend,USER,ROOT,START,geom.group*span/geom.page_size));
        struct sptm_user_backend b=detach_backend();
        switch(bad) {
        case 0:break; /* populated source survives unnest and cannot detach */
        case 1:sethalf(expected_child,6,2);break;
        case 2:sethalf(expected_child,6,0);break;
        case 3:sethalf(expected_child,8,1);break;
        case 4:setword(expected_child,0x80);break;
        case 5:sethalf(expected_slot&~(PAGE-1),8,0);break;
        case 6:meta(expected_child)[0]=1;break;
        case 7:detach_fail=1;break;
        case 8:b.prepare_detach=b.commit_detach=0;break;
        case 9:deny=expected_child;break;
        case 10:setword(expected_slot,word(expected_slot)|4);break;
        }
        snapshot();CHECK(sptm_mac_unmap_user_table(&m,&b,ROOT,START,2)!=SPTM_OK);
        unchanged();CHECK(!detach_commits && !history.calls);
    }
    /* A second bound root with an actual alias still prevents source cleanup. */
    for(unsigned fmt=0;fmt<2;fmt++) {
        init(fmt,0,0);uint64_t span=1UL<<(2*geom.shift-3),pages=geom.group*span/geom.page_size;
        struct sptm_root_cached first_cache=cache;struct shadow first_hw=hw;
        create(USER2,11,fmt,2);parents(USER2,20,START);
        CHECK(!sptm_mac_set_shared_region(&m,USER2,ROOT));
        cache=(struct sptm_root_cached){.root=USER2,.shadow=alloc_hw(0),.asid=11,.format=fmt,.flags=2,.valid=1};
        hw.root=cache.shadow;CHECK(!sptm_mac_nest_region(&m,&backend,USER2,ROOT,START,pages));
        struct sptm_root_cached second_cache=cache;struct shadow second_hw=hw;
        cache=first_cache;hw=first_hw;
        CHECK(!sptm_mac_unnest_region(&m,&backend,USER,ROOT,START,pages));
        struct sptm_user_backend b=detach_backend();snapshot();
        CHECK(sptm_mac_unmap_user_table(&m,&b,ROOT,START,2)==SPTM_BAD_REFERENCE);unchanged();
        cache=second_cache;hw=second_hw;views_init(&private_views,&hw);
        CHECK(!sptm_mac_unnest_region(&m,&backend,USER2,ROOT,START,pages));
        CHECK(!sptm_mac_unmap_user_table(&m,&b,ROOT,START,2));
        CHECK(half(ROOT,4)==2 && registry.bindings==2 && history.records[0].bindings==2);
    }
    printf("PASS: %u shared source detach checks (both geometries, 0..6 active CPUs, aliases, refs, failure atomicity)\n",checks);
    return 0;
}

/* SPDX-License-Identifier: MIT */
/* SWITCH_ROOT step B (compat/inactive-mirror.h): MAP_PAGE and MAP_TABLE on a
 * cached root that no CPU has installed. The monitor keeps the cached shadow
 * exactly when inactive_mirror_keep() allows it (MAP_TABLE: whenever the root
 * is cached). A kept shadow must translate like an independent rebuild of
 * the guest tree, and the next switch must install it without a build. The
 * leaf and update callbacks below make the same library calls as the
 * monitor's user_prepare_leaf/user_commit_leaf and user_prepare_update/
 * user_commit_update. */
#define SPTM_UNMAP_FIXTURE
#include "test-sptm-user-unmap.c"
#include "inactive-mirror.h"
#define L3B (BASE+0x1c000)
static unsigned updated;
static int prep_update(void *ctx,uint64_t root,uint64_t va,unsigned shift,uint64_t old,uint64_t next)
{
    (void)ctx;(void)old;(void)next;
    check(root==state.cache[0].root,"update selects the cached root");
    struct shadow s=shadow(state.cache[0].shadow);
    return sptm_root_prepare_unmap(&state.cache[0],&s,&memory,va,shift,1);
}
static int commit_update(void *ctx,uint64_t root,uint64_t va,unsigned shift,uint64_t old,uint64_t next)
{
    (void)ctx;(void)root;updated++;
    struct shadow s=shadow(state.cache[0].shadow);
    return sptm_root_commit_update(&state.cache[0],&s,&memory,va,shift,old,next);
}
/* The cached shadow resolves every 4K page of the first 64 MiB exactly like a
 * from-scratch build of the current guest tree (the rebuild the next switch
 * would otherwise run), and counts the same leaves. */
static int same_as_rebuild(unsigned fmt)
{
    struct shadow fresh=shadow(halloc(0));uint64_t leaves=0;
    if(!fresh.root || !sptm_root_build_shadow(&memory,&fresh,ROOT,fmt,(unsigned)get(meta(ROOT)+10,2),&leaves))
        return 0;
    if(leaves!=state.cache[0].leaves)return 0;
    struct mmu_config kept={12,17,state.cache[0].shadow},built={12,17,fresh.root};
    for(uint64_t va=0;va<(64UL<<20);va+=4096) {
        struct mmu_leaf a,b;
        int ra=mmu_walk(&kept,va,hread,0,&a),rb=mmu_walk(&built,va,hread,0,&b);
        if(ra!=rb || a.valid!=b.valid)return 0;
        if(a.valid && (a.pa!=b.pa ||
           (a.descriptor&(PT_LEAF_ATTRS|PT_LEAF_UPPER))!=(b.descriptor&(PT_LEAF_ATTRS|PT_LEAF_UPPER))))
            return 0;
    }
    return 1;
}
static void deactivate(void)
{
    for(cpu_now=0;cpu_now<6;cpu_now++)
        check(!sptm_mac_switch_root(&memory,&state,&rb,cpu_now,BASE,0,0),"deactivate root");
    backend.active_refs=0;backend.ttbr0=BASE;cpu_now=0;
}
static uint64_t data_pte(unsigned fmt,unsigned subpage,unsigned ro)
{return (DATA+(fmt ? subpage*4096:0))|0x0060000000000e43UL|(ro ? 0x80:0);}
int main(void)
{
    uint64_t pte=data_pte(0,0,0),tpro=(pte&~(3UL<<53)&~0xc0UL)|0x80|(1UL<<53);
    check(sprr_pte_class(tpro)==9 && sprr_pte_class(pte)!=9,"class fixtures");
    const uint64_t room=INACTIVE_MIRROR_ARENA_PAGES;
    check(inactive_mirror_admit(0,1,pte,INACTIVE_MIRROR_BUDGET-1,room) &&
          !inactive_mirror_admit(0,1,pte,INACTIVE_MIRROR_BUDGET,room),"at most the budget per slot");
    check(!inactive_mirror_admit(0,1,pte,0,room-1),"never into a nearly full arena");
    check(!inactive_mirror_admit(0,1,tpro,0,room),"a fresh TPRO leaf keeps the rebuild");
    check(!inactive_mirror_admit(1,1,pte,0,room) && !inactive_mirror_admit(0,0,pte,0,room),
          "only a cached root no CPU has installed");
    check(!inactive_mirror_keep(0,1,1),"an uncached root is never kept");
    for(unsigned fmt=0;fmt<2;fmt++) {
        uint64_t size=fmt ? 4096:16384,va=0x4000,result=99;
        setup_remove(fmt);updated=0;
        backend.prepare_update=prep_update;backend.commit_update=commit_update;
        insert(fmt,va,0,0);
        deactivate();
        uint64_t builds=state.builds,shadow_root=state.cache[0].shadow;
        check(state.cache[0].valid && same_as_rebuild(fmt),"inactive cached shadow starts equal");

        /* Fresh leaf, within budget: the live pair runs for the inactive root. */
        uint64_t fresh=data_pte(fmt,1,0);unsigned p=prepared,c0=committed;
        backend.mirror=(unsigned)inactive_mirror_admit(backend.active_refs,1,fresh,0,room);
        check(backend.mirror && !sptm_mac_map_user_page(&memory,&backend,ROOT,va+size,fresh,1,0,&result) &&
              !result,"fresh leaf inserted into an inactive cached root");
        check(prepared==p+1 && committed==c0+1,"mirrored through prepare_leaf and commit_leaf");
        check(inactive_mirror_keep(1,result,committed==c0+1),"mirrored shadow kept");
        check(same_as_rebuild(fmt),"mirrored shadow equals a rebuild");

        /* Identical request: nothing stored, nothing to mirror. */
        check(!sptm_mac_map_user_page(&memory,&backend,ROOT,va+size,fresh,1,0,&result) && result==1 &&
              committed==c0+1 && !updated,"identical request stores nothing");
        check(inactive_mirror_keep(1,result,0) && same_as_rebuild(fmt),"unchanged shadow kept");

        /* Same-PA replacement: the update callbacks mirror it. */
        backend.mirror=0;
        check(!sptm_mac_map_user_page(&memory,&backend,ROOT,va+size,fresh|0x80,1,0,&result) && result==1 &&
              updated==1 && committed==c0+1,"same-PA replacement goes through the update pair");
        check(inactive_mirror_keep(1,result,0) && same_as_rebuild(fmt),"replaced shadow kept and equal");

        /* An empty table adds no mapping. */
        check(!sptm_mac_retype(&memory,L3B,11,20,3),"allocate a second leaf table");
        check(!sptm_mac_map_user_table_live(&memory,&backend,ROOT,32UL<<20,2,L3B|3),
              "empty table linked into the inactive root");
        check(same_as_rebuild(fmt),"shadow still equal after an empty table");

        /* The next switch validates the grown tree and installs the kept
         * shadow: no build, and the mirrored leaf resolves read-only. */
        cpu_now=0;
        check(!sptm_mac_switch_root(&memory,&state,&rb,0,ROOT,0,0) && state.builds==builds &&
              state.cache[0].shadow==shadow_root && installed[0]==shadow_root,"kept shadow installed without a build");
        struct mmu_config cfg={12,17,installed[0]};struct mmu_leaf leaf;
        check(!mmu_walk(&cfg,va+size+19,hread,0,&leaf) && leaf.valid && leaf.pa==(fresh&PT_OA_MASK)+19 &&
              (leaf.descriptor&0x80),"installed view resolves the mirrored replacement");

        /* Budget spent: no callbacks, and the stale shadow must be dropped. */
        deactivate();
        uint64_t spent=data_pte(fmt,2,0);p=prepared;c0=committed;
        backend.mirror=(unsigned)inactive_mirror_admit(0,1,spent,INACTIVE_MIRROR_BUDGET,room);
        check(!backend.mirror && !sptm_mac_map_user_page(&memory,&backend,ROOT,va+2*size,spent,1,0,&result) &&
              !result && prepared==p && committed==c0,"over budget: guest leaf only");
        check(!inactive_mirror_keep(1,result,0),"an unmirrored fresh leaf is not kept");
        check(!same_as_rebuild(fmt),"keeping it would install a stale shadow");
        check(sptm_root_invalidate(&state,ROOT,0) && !state.cache[0].valid,"invalidated");
        check(!sptm_mac_switch_root(&memory,&state,&rb,0,ROOT,0,0) && state.builds==builds+1 &&
              same_as_rebuild(fmt),"next switch rebuilds the complete tree");
        for(cpu_now=0;cpu_now<6;cpu_now++)
            check(!sptm_mac_switch_root(&memory,&state,&rb,cpu_now,BASE,0,0),"leave root for the next format");
        backend.mirror=0;backend.prepare_update=0;backend.commit_update=0;
    }
    printf("Inactive mirror: %u checks, %u failures\n",checks,failures);
    return failures ? 1:0;
}

/* SPDX-License-Identifier: MIT */
#define main tpro_lifecycle_tests
#include "test-user-tpro.c"
#undef main
#include <stdlib.h>
#define LIST (BASE+0x20000)
#define HISTORY (1UL<<59)
static struct sptm_user_backend update_backend;
static unsigned prepared,committed,fail_prepare;
static int resolve_update(void *ctx,uint64_t root,struct sptm_user_backend *b)
{(void)ctx;if(root!=ROOT)return 0;*b=update_backend;return 1;}
static int prepare_update(void *ctx,uint64_t root,uint64_t va,unsigned shift,uint64_t old,uint64_t next)
{
    (void)ctx;(void)old;(void)next;CHECK(root==ROOT);prepared++;
    return prepared!=fail_prepare && sptm_root_prepare_unmap(&cache,&hw,live_memory,va,shift,1);
}
static int commit_update(void *ctx,uint64_t root,uint64_t va,unsigned shift,uint64_t old,uint64_t next)
{
    (void)ctx;CHECK(root==ROOT);committed++;
    return sptm_root_commit_update(&cache,&hw,live_memory,va,shift,old,next) && sync_views();
}
static void record(unsigned n,uint64_t va,uint64_t pte)
{put(LIST+n*24,ROOT,8);put(LIST+n*24+8,va,8);put(LIST+n*24+16,pte,8);}
static void views(uint64_t va,uint64_t pa,unsigned shift,uint64_t pte)
{
    for(unsigned cpu=0;cpu<7;cpu++)for(uint64_t off=0;off<(1UL<<shift);off+=4096) {
        struct mmu_config cfg={12,17,cpu==6 ? hw.root:sprr_views_root(&cpu_views,cpu)};
        struct mmu_leaf leaf;
        CHECK(!mmu_walk(&cfg,va+off,hw_read,0,&leaf) && leaf.valid && leaf.pa==pa+off);
        CHECK((leaf.descriptor&(PT_LEAF_ATTRS|PT_LEAF_UPPER))==(pte&(PT_LEAF_ATTRS|PT_LEAF_UPPER)));
        CHECK(!(leaf.descriptor&(3UL<<58)));
    }
}
#ifndef SPTM_USER_UPDATE_TEST_MAIN
#define SPTM_USER_UPDATE_TEST_MAIN main
#endif
int SPTM_USER_UPDATE_TEST_MAIN(int argc,char **argv)
{
    if(argc==5 && !strcmp(argv[1],"--pte")) {
        uint64_t next=0;enum sptm_result r=sptm_mac_user_update_pte(
            strtoull(argv[2],0,16),strtoull(argv[3],0,16),strtoull(argv[4],0,16),&next);
        printf("%u %016llx\n",r,(unsigned long long)next);return 0;
    }
    for(unsigned format=0;format<2;format++)for(unsigned part=0;part<(format?4:1);part++)
    for(unsigned active=0;active<=6;active+=6) {
        struct sptm_memory m=setup(format);unsigned shift=format?12:14;uint64_t size=1UL<<shift;
        uint64_t va=VA+part*4096,pa=DATA+part*4096,old=pa|0x0860000000000ec3UL;
        uint64_t rw=pa|0x0060000000000e43UL,result=99;
        struct sptm_user_backend b={0};
        /* MAP_PAGE strips writable history, but preserves an exact existing
         * descriptor. The user update service has its own selection rules. */
        CHECK(sptm_mac_map_user_page(&m,&b,ROOT,va,rw|HISTORY,1,0,&result)==SPTM_OK && result==0);
        /* The slot now holds a valid leaf: shipped MAP_PAGE reports 1. */
        CHECK(sptm_mac_map_user_page(&m,&b,ROOT,va,rw|HISTORY,1,0,&result)==SPTM_OK && result==1);
        CHECK(sptm_mac_unmap_user_region(&m,&b,ROOT,va,1,1,BASE)==SPTM_OK);
        CHECK(sptm_mac_map_user_page(&m,&b,ROOT,va,old,1,0,&result)==SPTM_OK);
        CHECK(sptm_mac_map_user_page(&m,&b,ROOT,va+size,old,1,0,&result)==SPTM_OK);
        memset(hw_ram,0,sizeof hw_ram);memset(&cpu_views,0,sizeof cpu_views);
        memset(cpu_states,0,sizeof cpu_states);hw_next=HW_BASE+4096;live_memory=&m;
        hw=(struct shadow){.txsz=17,.root=HW_BASE,.alloc=hw_alloc,.read=hw_read,.write=hw_write};
        cache=(struct sptm_root_cached){.root=ROOT,.shadow=HW_BASE,.asid=8,.format=format,.flags=0xa,.valid=1};
        CHECK(sptm_root_build_shadow(&m,&hw,ROOT,format,0xa,&cache.leaves) && cache.leaves==2);
        CHECK(sprr_views_init(&cpu_views,&hw) && sprr_views_prepare_user(&cpu_views,&hw));
        for(unsigned cpu=0;cpu<6;cpu++)sprr_root_reset(&cpu_states[cpu],0xa);
        CHECK(sync_views());
        update_backend=(struct sptm_user_backend){.ttbr0=active?ROOT:0,.active_refs=active,
            .prepare_leaf=prepare_live,.commit_leaf=commit_live,
            .prepare_update=prepare_update,.commit_update=commit_update};
        put(meta(ROOT)+6,get(meta(ROOT)+6,2)+active,2);
        prepared=committed=0;fail_prepare=2;
        record(0,va,rw);record(1,va+size,rw);
        memcpy(before,ram,sizeof ram);unsigned n=published;uint64_t allocated=hw_next;
        struct sptm_user_update_state state={0};
        CHECK(sptm_mac_update_user_disjoint(&m,resolve_update,0,DATA,LIST,2,0xc0a,BASE,&result,&state)==SPTM_SHADOW_FAILED);
        CHECK(n==published && !memcmp(before,ram,sizeof ram) && !committed && !state.calls && allocated==hw_next);
        views(va,pa,shift,old);views(va+size,pa,shift,old);
        fail_prepare=prepared=0;
        CHECK(sptm_mac_update_user_disjoint(&m,resolve_update,0,DATA,LIST,2,0xc0a,BASE,&result,&state)==SPTM_OK && !result);
        CHECK(committed==2 && cache.leaves==2 && state.changed==2 && state.next==rw && state.old==old);
        CHECK(get(BASE,8)==old && get(BASE+8,8)==old && get(meta(DATA)+12,4)==2 && !get(meta(DATA)+8,4));
        views(va,pa,shift,rw);views(va+size,pa,shift,rw);
        record(0,va,rw|HISTORY);
        CHECK(sptm_mac_update_user_disjoint(&m,resolve_update,0,DATA,LIST,1,2,BASE,&result,&state)==SPTM_OK);
        CHECK(state.next==(rw|HISTORY) && get(meta(DATA)+12,4)==2);
        views(va,pa,shift,rw);
        CHECK(sptm_mac_map_user_page(&m,&update_backend,ROOT,va,rw|HISTORY,1,0,&result)==SPTM_OK && result==1);
        record(0,va,rw);
        CHECK(sptm_mac_update_user_disjoint(&m,resolve_update,0,DATA,LIST,1,2,BASE,&result,&state)==SPTM_OK);
        /* The captured call repeats a write revocation for the same slot.
         * Observe sequential old values, but transfer its ownership once. */
        record(0,va,old&~HISTORY);record(1,va,old&~HISTORY);
        unsigned revoke_commits=committed;uint64_t revoke_changed=state.changed;
        CHECK(sptm_mac_update_user_disjoint(&m,resolve_update,0,DATA,LIST,2,2,BASE,&result,&state)==SPTM_OK && !result);
        CHECK(committed==revoke_commits+1 && state.changed==revoke_changed+1);
        CHECK(get(BASE,8)==rw && get(BASE+8,8)==(old&~HISTORY));
        CHECK(get(meta(DATA)+8,4)==1 && get(meta(DATA)+12,4)==1);
        views(va,pa,shift,old&~HISTORY);views(va+size,pa,shift,rw);
        /* Revoke write access synchronously even with option400; preserve
         * software history and then clear it with the selected update. */
        record(0,va,old);record(1,va+size,old);
        CHECK(sptm_mac_update_user_disjoint(&m,resolve_update,0,DATA,LIST,2,0x402,BASE,&result,&state)==SPTM_OK);
        views(va,pa,shift,old);views(va+size,pa,shift,old);
        record(0,va,old&~HISTORY);record(1,va+size,old&~HISTORY);
        CHECK(sptm_mac_update_user_disjoint(&m,resolve_update,0,DATA,LIST,2,2,BASE,&result,&state)==SPTM_OK);
        CHECK(get(meta(DATA)+8,4)==2 && !get(meta(DATA)+12,4));
        record(0,va,rw);record(1,va+size,rw);n=committed;
        CHECK(sptm_mac_update_user_disjoint(&m,resolve_update,0,DATA,LIST,2,0xd0a,BASE,&result,&state)==SPTM_OK && !result);
        CHECK(committed==n && get(BASE,8)==(old&~HISTORY));
        /* Access-flag clearing and fault-only restoration, including a
         * deferred result only when hardware-visible attributes change. */
        uint64_t ro=old&~HISTORY;
        record(0,va,ro&~PT_AF);
        CHECK(sptm_mac_update_user_disjoint(&m,resolve_update,0,DATA,LIST,1,8,BASE,&result,&state)==SPTM_OK);
        views(va,pa,shift,ro&~PT_AF);
        record(0,va,ro);
        CHECK(sptm_mac_update_user_disjoint(&m,resolve_update,0,DATA,LIST,1,0x108,BASE,&result,&state)==SPTM_OK && !result);
        views(va,pa,shift,ro&~PT_AF);
        CHECK(sptm_mac_update_user_disjoint(&m,resolve_update,0,DATA,LIST,1,0x908,BASE,&result,&state)==SPTM_OK && result==5);
        views(va,pa,shift,ro);
        record(0,va,ro|(1UL<<58));
        CHECK(sptm_mac_update_user_disjoint(&m,resolve_update,0,DATA,LIST,1,0x101,BASE,&result,&state)==SPTM_OK && !result);
        views(va,pa,shift,ro);
        struct sptm_fixed_view proof;CHECK(sptm_root_canonical_view(&cache,&hw,&m,&proof));
        CHECK(cache.leaves==2 && get(meta(L3)+8,2)==2);
        /* Repeated satisfied records report every old PTE, with one unchanged
         * ownership edge and no publication into canonical or private views. */
        uint64_t unchanged_pte=ro|(1UL<<58),changed_before=state.changed;
        unsigned commits_before=committed;
        for(unsigned repeat=2;repeat<=64;repeat*=2) {
            for(unsigned i=0;i<repeat;i++)record(i,va,unchanged_pte);
            CHECK(sptm_mac_update_user_disjoint(&m,resolve_update,0,DATA,LIST,repeat,2,BASE,&result,&state)==SPTM_OK);
            CHECK(!result && state.count==repeat && state.changed==changed_before && committed==commits_before);
            CHECK(get(meta(DATA)+8,4)==2 && !get(meta(DATA)+12,4));
            for(unsigned i=0;i<repeat;i++)CHECK(get(BASE+i*8,8)==unchanged_pte);
        }
        views(va,pa,shift,ro);
        /* A stale target, invalid later record and conflicting duplicate must not
         * change a valid earlier record or release its reference. */
        uint64_t stale=BASE+0x24000;n=committed;
        CHECK(sptm_mac_update_user_disjoint(&m,resolve_update,0,stale,LIST,1,0xc0a,BASE,&result,&state)==SPTM_OK && !result);
        CHECK(committed==n && get(BASE,8)==(ro|(1UL<<58)));
        record(0,va,ro&~PT_AF);record(1,va,ro);
        memcpy(before,ram,sizeof ram);n=published;
        CHECK(sptm_mac_update_user_disjoint(&m,resolve_update,0,DATA,LIST,2,8,BASE,&result,&state)==SPTM_BAD_ADDRESS);
        CHECK(n==published && !memcmp(before,ram,sizeof ram));
        record(1,va,ro&~PT_AF);
        commits_before=committed;changed_before=state.changed;
        CHECK(sptm_mac_update_user_disjoint(&m,resolve_update,0,DATA,LIST,2,8,BASE,&result,&state)==SPTM_OK && !result);
        CHECK(committed==commits_before+1 && state.changed==changed_before+1);
        CHECK(get(BASE,8)==unchanged_pte && get(BASE+8,8)==(unchanged_pte&~PT_AF));
        CHECK(get(meta(DATA)+8,4)==2 && !get(meta(DATA)+12,4));
        views(va,pa,shift,ro&~PT_AF);
        record(0,va,ro);
        record(1,1UL<<47,ro);
        memcpy(before,ram,sizeof ram);n=published;
        CHECK(sptm_mac_update_user_disjoint(&m,resolve_update,0,DATA,LIST,2,0x808,BASE,&result,&state)==SPTM_BAD_ADDRESS);
        CHECK(n==published && !memcmp(before,ram,sizeof ram));
        for(unsigned i=0;i<16384;i++)CHECK(ram[DATA-BASE+i]==0xa5);
    }
    printf("USER_UPDATE: %u checks, %u failures\n",checks,failures);return !!failures;
}

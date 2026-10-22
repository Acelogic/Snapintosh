/* SPDX-License-Identifier: MIT */
#define main inactive_user_tests
#include "test-sptm-user.c"
#undef main
#include "sptm-root.h"
#define HOST 0x10000000UL
static uint8_t host[0x100000];
static uint64_t next_host,host_limit,installed[6];
static unsigned cpu_now,prepared,committed;
static struct sptm_root_state state;
static struct sptm_memory memory;
static int hread(void *ctx,uint64_t pa,uint64_t *out)
{(void)ctx;if(pa<HOST || pa>HOST+sizeof(host)-8 || pa&7)return -1;
 memcpy(out,host+(pa-HOST),8);return 0;}
static int hwrite(void *ctx,uint64_t pa,uint64_t v)
{(void)ctx;if(pa<HOST || pa>HOST+sizeof(host)-8 || pa&7)return -1;
 memcpy(host+(pa-HOST),&v,8);return 0;}
static uint64_t halloc(void *ctx)
{(void)ctx;if(next_host>=host_limit)return 0;
 uint64_t pa=HOST+next_host;next_host+=4096;memset(host+(pa-HOST),0,4096);return pa;}
static struct shadow shadow(uint64_t root)
{return (struct shadow){.txsz=17,.root=root,.alloc=halloc,.read=hread,.write=hwrite};}
static int build(void *ctx,const struct sptm_memory *m,uint64_t root,unsigned fmt,
                 unsigned flags,uint64_t old,uint64_t *out,uint64_t *leaves)
{(void)ctx;struct shadow s=shadow(old ? old:halloc(0));
 if(!sptm_root_build_shadow(m,&s,root,fmt,flags,leaves))return 0;
 *out=s.root;return 1;}
static void install(void *ctx,uint64_t sh,uint64_t root,uint64_t asid,unsigned fmt)
{(void)ctx;(void)root;(void)asid;(void)fmt;installed[cpu_now]=sh;}
static int prep(void *ctx,uint64_t root,uint64_t va,unsigned shift,uint64_t pte)
{(void)ctx;(void)pte;prepared++;check(state.cache[0].root==root,"prepare selects correct root");
 struct shadow s=shadow(state.cache[0].shadow);
 return sptm_root_prepare_leaf(&state.cache[0],&s,va,shift);}
static int commit(void *ctx,uint64_t root,uint64_t va,unsigned shift,uint64_t pte)
{(void)ctx;committed++;check(state.cache[0].root==root,"commit selects correct root");
 struct shadow s=shadow(state.cache[0].shadow);
 return sptm_root_commit_leaf(&state.cache[0],&s,&memory,va,shift,pte);}
static struct sptm_root_backend rb={.kernel_root=BASE,.kernel_shadow=HOST,.build=build,.install=install};
static void setup(unsigned fmt)
{
    memset(&state,0,sizeof(state));memset(host,0,sizeof(host));
    next_host=4096;host_limit=sizeof(host);prepared=committed=0;
    memset(ram,0,SIZE);fail_pa=0;publications=0;
    backend=(struct sptm_user_backend){.aperture={BASE,0xfffffe0100000000UL,SIZE}};
    for(unsigned i=0;i<SIZE/0x4000;i++)ram[FM-BASE+i*16+2]=11;
    memory=(struct sptm_memory){.frame_map_pa=FM,.frame_low=BASE,.frame_high=BASE+SIZE,
        .alloc_low=ROOT,.alloc_high=BASE+SIZE,.map=map,.publish=publish,.refs=&refs};
    check(sptm_mac_retype(&memory,ROOT,11,18,(2UL<<32)|(2UL<<16)|fmt)==SPTM_OK,"fresh root constructor");
    if(fmt)check(sptm_mac_retype(&memory,L1,11,20,1)==SPTM_OK,"allocate L1 group");
    check(sptm_mac_retype(&memory,L2,11,20,2)==SPTM_OK,"allocate L2 group");
    check(sptm_mac_retype(&memory,L3,11,20,3)==SPTM_OK,"allocate ordinary user table");
    for(cpu_now=0;cpu_now<6;cpu_now++)
        check(sptm_mac_switch_root(&memory,&state,&rb,cpu_now,ROOT,0,0)==SPTM_OK,
              "activate empty root on six CPUs");
    backend.ttbr0=ROOT|(2UL<<48);backend.ttbr1=BASE;backend.active_refs=6;
    backend.prepare_leaf=prep;backend.commit_leaf=commit;
}
#ifndef SPTM_LIVE_FIXTURE
int main(void)
{
    for(unsigned fmt=0;fmt<2;fmt++) {
        setup(fmt);uint64_t result=99,va=0x4000;
        uint64_t pa=DATA+(fmt ? 8192:0),pte=pa|0x0060000000000e43UL;
        memcpy(before,ram,SIZE);
        check(sptm_mac_map_user_page(&memory,&backend,ROOT,va,pte,0,BASE,&result)==SPTM_TABLE_MISSING,
              "active empty root reports missing table");
        check(!memcmp(before,ram,SIZE) && !prepared && !committed && result==99,
              "missing table leaves source, output, refs and shadow unchanged");
        if(fmt)check(sptm_mac_map_user_table_live(&memory,&backend,ROOT,va,0,L1|3)==SPTM_OK,
                     "active root L1 group attached");
        check(sptm_mac_map_user_table_live(&memory,&backend,ROOT,va,1,L2|3)==SPTM_OK,
              "active L2 attached");
        check(sptm_mac_map_user_table_live(&memory,&backend,ROOT,va,2,L3|3)==SPTM_OK,
              "active L3 attached");
        check(get(meta(ROOT)+6,2)==7,"six CPU refs coexist with one root child");
        check(sptm_mac_map_user_page(&memory,&backend,ROOT,va,pte,0,BASE,&result)==SPTM_OK && result==0,
              "ordinary user data inserted into active root");
        check(prepared==1 && committed==1,"prepare and commit exactly once");
        uint64_t allocated=next_host;
        for(unsigned cpu=0;cpu<6;cpu++)for(unsigned off=0;off<(fmt ? 4096:16384);off+=4096) {
            struct mmu_config cfg={12,17,installed[cpu]};struct mmu_leaf leaf;
            check(!mmu_walk(&cfg,va+off+19,hread,0,&leaf) && leaf.valid && leaf.pa==pa+off+19,
                  "all six hardware views resolve inserted data");
            check((leaf.descriptor&(PT_LEAF_ATTRS|PT_LEAF_UPPER))==
                  (pte&(PT_LEAF_ATTRS|PT_LEAF_UPPER)),"user permissions/shareability/nG/NX preserved");
        }
        check(next_host==allocated && get(meta(DATA)+12,4)==1 && get(meta(DATA)+8,4)==0,
              "commit allocated nothing and counted one writable reference");
        check(sptm_mac_map_user_page(&memory,&backend,ROOT,va,pte,0,BASE,&result)==SPTM_OK && result==1,
              "identical live mapping returns old descriptor");
        check(prepared==1 && committed==1 && get(BASE,8)==pte,"duplicate avoids double-commit and returns old PTE");
        check(sptm_mac_unmap_user_table(&memory,&backend,ROOT,va,2)==SPTM_FRAME_BUSY,
              "active detach remains guarded until lifetime backend exists");
        /* Same source L3 allocation frame, new hardware L3 page: force OOM
         * before any guest mutation, then retry using the untouched request. */
        memcpy(before,ram,SIZE);host_limit=next_host;
        check(sptm_mac_map_user_page(&memory,&backend,ROOT,0x200000,pte|0x80,1,0,&result)==SPTM_MEMORY_UNAVAILABLE,
              "private allocation failure refuses transaction");
        check(!memcmp(before,ram,SIZE) && committed==1,"OOM preserves source and reference counts");
        host_limit=sizeof(host);
        check(sptm_mac_map_user_page(&memory,&backend,ROOT,0x200000,pte|0x80,1,0,&result)==SPTM_OK,
              "RO data alias installed after available memory returns");
        check(get(meta(DATA)+8,4)==1 && get(meta(DATA)+12,4)==1,"RO and RW aliases independently counted");
        /* Not WAS_WRITABLE (bit 59): the shipped SPTM clears it from a
         * writable request (...f9240..f92a8) instead of refusing it, as
         * test-user-was-writable.c checks. */
        for(unsigned bad=0;bad<4;bad++) {
            uint64_t badpte=pte;
            if(bad==0)badpte&=~(1UL<<54);
            if(bad==1)badpte&=~(1UL<<11);
            if(bad==2)badpte|=1UL<<52;
            if(bad==3)badpte&=~(1UL<<6);
            memcpy(before,ram,SIZE);
            check(sptm_mac_map_user_page(&memory,&backend,ROOT,0x8000,badpte,1,0,&result)==SPTM_UNSUPPORTED_OPTIONS,
                  "unsupported executable/global/software-bit policy rejected");
            check(!memcmp(before,ram,SIZE),"policy refusal cannot change source or refs");
        }
        check(sptm_root_invalidate(&state,ROOT,1)==0,"active populated root cannot retire");
        for(cpu_now=0;cpu_now<6;cpu_now++) {
            check(sptm_mac_switch_root(&memory,&state,&rb,cpu_now,BASE,0,0)==SPTM_OK,"switch back to kernel");
            check(sptm_mac_switch_root(&memory,&state,&rb,cpu_now,ROOT,0,0)==SPTM_OK,
                  "reactivation validates populated ordinary-data root");
        }
        backend.active_refs=0;backend.prepare_leaf=0;backend.commit_leaf=0;
    }
    printf("Active user mapping: %u checks, %u failures\n",checks,failures);
    return failures ? 1:0;
}
#endif

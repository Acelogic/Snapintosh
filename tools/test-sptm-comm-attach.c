/* SPDX-License-Identifier: MIT */
#define SPTM_LIVE_FIXTURE
#include "test-sptm-live.c"
#define ROOT2 (BASE+0x1c000)
#define L22 (BASE+0x20000)
#define L12 (BASE+0x24000)
#define DATA2 (BASE+0x28000)
#define DATA3 (BASE+0x2c000)
static unsigned attach_preps,attach_commits,attach_flushes,attach_fail;
static uint64_t prep_alloc;
static struct sptm_root_cached *cached(uint64_t root)
{for(unsigned i=0;i<SPTM_ROOT_CACHE;i++)if(state.cache[i].root==root && state.cache[i].valid)return &state.cache[i];return 0;}
static int attach_prepare(void *ctx,uint64_t root,uint64_t va,unsigned shift,uint64_t child)
{
    (void)ctx;attach_preps++;
    if(attach_fail==1)return 0;
    struct sptm_root_cached *e=cached(root);if(!e)return 1;
    struct shadow s=shadow(e->shadow);
    int ok=sptm_root_prepare_attach(e,&s,&memory,va,shift,child);
    prep_alloc=next_host;return ok;
}
static int attach_commit(void *ctx,uint64_t root,uint64_t va,unsigned shift,uint64_t child)
{
    (void)ctx;attach_commits++;
    if(attach_fail==2)return 0;
    struct sptm_root_cached *e=cached(root);
    if(e) {
        struct shadow s=shadow(e->shadow);
        if(!sptm_root_commit_attach(e,&s,&memory,va,shift,child))return 0;
        check(next_host==prep_alloc,"attach commit performs no allocation");
    }
    attach_flushes++;return 1;
}
static int detach_prepare(void *ctx,uint64_t root,uint64_t va,unsigned shift,unsigned level,uint64_t count)
{
    (void)ctx;struct sptm_root_cached *e=cached(root);if(!e)return 1;
    struct shadow s=shadow(e->shadow);
    return sptm_root_prepare_detach(e,&s,&memory,va,shift,level,count);
}
static int detach_commit(void *ctx,uint64_t root,uint64_t va,unsigned shift,unsigned level,uint64_t count)
{
    (void)ctx;struct sptm_root_cached *e=cached(root);if(!e)return 1;
    struct shadow s=shadow(e->shadow);
    if(!sptm_root_commit_detach(e,&s,va,shift,level,count))return 0;
    attach_flushes++;return 1;
}
static struct sptm_user_backend for_root(uint64_t root)
{
    struct sptm_user_backend b={.ttbr0=BASE,.ttbr1=BASE,
        .prepare_leaf=prep,.commit_leaf=commit,
        .prepare_attach=attach_prepare,.commit_attach=attach_commit,
        .prepare_detach=detach_prepare,.commit_detach=detach_commit};
    for(unsigned cpu=0;cpu<6;cpu++)b.active_refs+=state.active[cpu]==root;
    if(b.active_refs)b.ttbr0=root;
    return b;
}
static uint64_t last_va(unsigned flags,unsigned fmt)
{return (1UL<<(flags==6 ? 47 : flags==0x22 ? 32:36))-(fmt ? 4096:16384);}
static uint64_t group_va(unsigned fmt,uint64_t va)
{return fmt ? va&~(3UL<<21):va;}
static void retained(unsigned fmt,unsigned flags,int active)
{
    memset(&state,0,sizeof(state));memset(host,0,sizeof(host));
    next_host=4096;host_limit=sizeof(host);attach_preps=attach_commits=attach_flushes=attach_fail=0;
    backend=(struct sptm_user_backend){.aperture={BASE,0xfffffe0100000000UL,SIZE}};
    uint64_t va=last_va(flags,fmt),size=fmt ? 4096:16384,result;
    memory=reset_geometry(31,flags,va,fmt);
    check(!sptm_mac_retype(&memory,DATA2,11,30,0),"retained RO data type30");
    check(!sptm_mac_retype(&memory,DATA3,11,29,0),"retained RO data type29");
    check(!sptm_mac_map_user_page(&memory,&backend,ROOT,va-2*size,DATA|RX,1,0,&result),"build code leaf");
    check(!sptm_mac_map_user_page(&memory,&backend,ROOT,va-size,DATA2|NX,1,0,&result),"build first RO leaf");
    check(!sptm_mac_map_user_page(&memory,&backend,ROOT,va,DATA3|NX,1,0,&result),"build second RO leaf");
    check(!sptm_mac_unmap_user_table(&memory,&backend,ROOT,group_va(fmt,va),2),"retain table without parent");
    check(get(meta(L3)+6,2)==0 && get(meta(L3)+8,2)==3,"detached table retains three leaves");
    if(active)for(cpu_now=0;cpu_now<6;cpu_now++)
        check(!sptm_mac_switch_root(&memory,&state,&rb,cpu_now,ROOT,0,0),"activate root before attachment");
    backend=for_root(ROOT);
}
static void payload_refs(void)
{
    check(get(meta(DATA)+12,4)==1 && !get(meta(DATA)+8,4),"code reference remains one");
    check(get(meta(DATA2)+8,4)==1 && !get(meta(DATA2)+12,4),"type30 reference remains one");
    check(get(meta(DATA3)+8,4)==1 && !get(meta(DATA3)+12,4),"type29 reference remains one");
    check(get(meta(L3)+8,2)==3,"three source PTEs remain counted once");
}
static void hardware(uint64_t root,unsigned fmt,unsigned flags,int populated)
{
    struct sptm_root_cached *e=cached(root);check(e!=0,"root has cached hardware map");if(!e)return;
    check(e->leaves==(populated ? 3u:0u),"cached leaf count matches attachment");
    uint64_t va=last_va(flags,fmt),size=fmt ? 4096:16384;
    const uint64_t pages[]={DATA,DATA2,DATA3};
    for(unsigned i=0;i<3;i++)for(unsigned off=0;off<size;off+=4096) {
        struct mmu_config cfg={12,17,e->shadow};struct mmu_leaf leaf;
        check(!mmu_walk(&cfg,va-(2-i)*size+off,hread,0,&leaf),"independent hardware walk");
        check(leaf.valid==populated,"expected hardware validity");
        if(populated) {
            check(leaf.pa==pages[i]+off,"comm payload resolves through 4K hardware");
            check((leaf.descriptor&(PT_LEAF_ATTRS|PT_LEAF_UPPER))==
                  ((i ? NX:RX)&(PT_LEAF_ATTRS|PT_LEAF_UPPER)),"RO/NX and user executable permissions preserved");
        }
    }
}
int main(void)
{
    const unsigned formats[]={0,1,0,1,1},flags[]={2,2,0x22,0x22,6};
    for(unsigned variant=0;variant<5;variant++)for(unsigned order=0;order<2;order++) {
        unsigned fmt=formats[variant],fl=flags[variant];uint64_t va=group_va(fmt,last_va(fl,fmt));
        retained(fmt,fl,1);
        check(!sptm_mac_map_user_table_live(&memory,&backend,ROOT,va,2,L3|3),"attach populated table to six active CPUs");
        hardware(ROOT,fmt,fl,1);payload_refs();
        check(attach_preps==1 && attach_commits==1 && attach_flushes==1,"attach has preflight and commit/flush");
        check(get(meta(ROOT)+6,2)==7 && get(meta(L3)+6,2)==1,"active root refs plus one commpage parent");
        check(!sptm_mac_retype(&memory,ROOT2,11,18,(3UL<<32)|((uint64_t)fl<<16)|fmt),"allocate second root");
        check(!sptm_mac_retype(&memory,L22,11,20,2),"allocate second L2");
        if(fmt) {
            check(!sptm_mac_retype(&memory,L12,11,20,1),"allocate second L1");
            check(!sptm_mac_map_user_table(&memory,ROOT2,va&~(3UL<<39),0,L12|3),"second L1 group");
        }
        check(!sptm_mac_map_user_table(&memory,ROOT2,fmt ? va&~(3UL<<30):va,1,L22|3),"second L2 group");
        struct sptm_user_backend b=for_root(ROOT2);
        check(!sptm_mac_map_user_table_live(&memory,&b,ROOT2,va,2,L3|3),"share retained table with inactive root");
        check(get(meta(L3)+6,2)==2,"two parent links counted separately");payload_refs();
        cpu_now=0;check(!sptm_mac_switch_root(&memory,&state,&rb,0,ROOT2,0,0),"activate root with shared commpage");
        hardware(ROOT2,fmt,fl,1);hardware(ROOT,fmt,fl,1);
        uint64_t first=order ? ROOT2:ROOT,second=order ? ROOT:ROOT2;
        b=for_root(first);check(!sptm_mac_unmap_user_table(&memory,&b,first,va,2),"detach first sharing root");
        hardware(first,fmt,fl,0);hardware(second,fmt,fl,1);payload_refs();
        check(get(meta(L3)+6,2)==1,"one parent survives detachment");
        b=for_root(second);check(!sptm_mac_unmap_user_table(&memory,&b,second,va,2),"detach final sharing root");
        hardware(second,fmt,fl,0);payload_refs();check(!get(meta(L3)+6,2),"retained child has no parents");
        /* Cached but inactive attachment cannot defer updating its old shadow. */
        for(cpu_now=0;cpu_now<6;cpu_now++)check(!sptm_mac_switch_root(&memory,&state,&rb,cpu_now,BASE,0,0),"return CPU to kernel");
        b=for_root(ROOT);uint64_t builds=state.builds;
        check(!sptm_mac_map_user_table_live(&memory,&b,ROOT,va,2,L3|3),"attach to inactive cached root");
        hardware(ROOT,fmt,fl,1);cpu_now=0;
        check(!sptm_mac_switch_root(&memory,&state,&rb,0,ROOT,0,0) && state.builds==builds,"reactivate without stale shadow or rebuild");
    }
    for(unsigned fmt=0;fmt<2;fmt++)for(unsigned bad=0;bad<20;bad++) {
        retained(fmt,2,1);uint64_t va=group_va(fmt,last_va(2,fmt)),tte=L3|3;
        struct sptm_user_geometry g;check(sptm_mac_user_geometry(fmt,2,&g),"fixture geometry");
        uint64_t first=L3+8*(2048-3),end=L3+8*2047;
        switch(bad) {
        case 0:put(meta(L3)+6,0xfff9,2);break;
        case 1:put(meta(L3)+8,2,2);break;
        case 2:put(first,DATA|NX|0x800,8);break;
        case 3:put(end,DATA3|RX,8);break;
        case 4:put(meta(DATA)+12,0,4);break;
        case 5:put(meta(DATA3)+8,0,4);break;
        case 6:put(meta(DATA3)+2,11,1);break;
        case 7:put(meta(L3)+2,20,1);break;
        case 8:tte|=4;break;
        case 9:va=0;break;
        case 10:fail_pa=DATA3;break;
        case 11:fail_pa=L3;break;
        case 12:backend.prepare_attach=0;break;
        case 13:backend.commit_attach=0;break;
        case 14:attach_fail=1;break;
        case 15:host_limit=next_host;break;
        case 16:put(meta(L3),1,1);break;
        case 17:put(meta(L3)+4,2,1);break;
        case 18: {
            struct shadow s=shadow(cached(ROOT)->shadow);
            check(!shadow_map(&s,last_va(2,fmt),DATA,4096,NX,NX),"seed stale hardware mapping");break;
        }
        case 19: {
            struct shadow s=shadow(cached(ROOT)->shadow);
            uint64_t hole=(va&~(2048*g.page_size-1));
            check(!shadow_map(&s,hole,DATA,4096,NX,NX),"seed stale mapping in an otherwise absent hole");break;
        }
        }
        memcpy(before,ram,SIZE);unsigned pub=publications;
        check(sptm_mac_map_user_table_live(&memory,&backend,ROOT,va,2,tte)!=SPTM_OK,"invalid retained attachment refused");
        check(!memcmp(before,ram,SIZE) && pub==publications,"rejected preflight leaves source and metadata unchanged");
        check(!attach_commits,"invalid preflight cannot commit");
    }
    retained(0,2,1);attach_fail=2;
    check(sptm_mac_map_user_table_live(&memory,&backend,ROOT,VA,2,L3|3)==SPTM_SHADOW_FAILED,"commit failure is fatal");
    check(get(meta(L3)+6,2)==1,"fatal post-publication failure retains child refs");payload_refs();
    printf("Commpage attachment: %u checks, %u failures\n",checks,failures);
    return failures ? 1:0;
}

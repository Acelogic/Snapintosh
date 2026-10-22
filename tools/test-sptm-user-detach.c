/* SPDX-License-Identifier: MIT */
#define SPTM_UNMAP_FIXTURE
#include "test-sptm-user-unmap.c"
static unsigned detach_prepared,detach_committed,detach_reads,detach_fail;
static int counted_read(void *ctx,uint64_t pa,uint64_t *out)
{detach_reads++;return hread(ctx,pa,out);}
static int prepare_detach(void *ctx,uint64_t root,uint64_t va,unsigned shift,unsigned level,uint64_t removed)
{
    (void)ctx;detach_prepared++;check(root==ROOT,"detach selects requested root");
    struct shadow s=shadow(state.cache[0].shadow);s.read=counted_read;
    return sptm_root_prepare_detach(&state.cache[0],&s,&memory,va,shift,level,removed);
}
static int commit_detach(void *ctx,uint64_t root,uint64_t va,unsigned shift,unsigned level,uint64_t removed)
{
    (void)ctx;(void)root;detach_committed++;
    check(!memcmp(metadata_before,ram+(FM-BASE),sizeof(metadata_before)),
          "table unlink retains all metadata references until invalidation");
    if(detach_fail)return 0;
    struct shadow s=shadow(state.cache[0].shadow);
    if(!sptm_root_commit_detach(&state.cache[0],&s,va,shift,level,removed))return 0;
    struct sptm_user_geometry g;
    check(sptm_mac_user_geometry((unsigned)state.cache[0].format,(unsigned)state.cache[0].flags,&g),"cached geometry");
    uint64_t span=mmu_level_size(shift,level)*g.group,base=va&~(span-1),end=base+span;
    if(end>g.va_limit)end=g.va_limit;
    /* Independent sparse hardware walk, after removal but before simulated TLBI. */
    for(unsigned cpu=0;cpu<6;cpu++)if(state.active[cpu]==ROOT) {
        struct mmu_config cfg={12,17,installed[cpu]};struct mmu_leaf leaf;
        for(uint64_t addr=base;addr<end;) {
            check(!mmu_walk(&cfg,addr,hread,0,&leaf) && !leaf.valid,"all hardware views lack detached mappings");
            uint64_t step=mmu_level_size(12,leaf.level);addr=(addr&~(step-1))+step;
        }
    }
    check(!memcmp(metadata_before,ram+(FM-BASE),sizeof(metadata_before)),
          "reference release still waits for TLB boundary");
    flushes++;return 1;
}
static enum sptm_result detach(uint64_t va,unsigned level)
{
    memcpy(metadata_before,ram+(FM-BASE),sizeof(metadata_before));
    return sptm_mac_unmap_user_table(&memory,&backend,ROOT,va,level);
}
static void callbacks(void)
{
    backend.prepare_detach=prepare_detach;backend.commit_detach=commit_detach;
    detach_prepared=detach_committed=detach_reads=detach_fail=0;
}
static enum sptm_result condemn(uint64_t va,unsigned yes,uint64_t *result)
{return sptm_mac_condemn_user_table(&memory,&backend,ROOT,va,yes,result);}
int main(void)
{
    for(unsigned fmt=0;fmt<2;fmt++) {
        unsigned shift=fmt ? 12:14;uint64_t size=1UL<<shift,va=0x4000,result=99;
        setup_remove(fmt);callbacks();uint64_t pte=insert(fmt,va,0,0);
        insert(fmt,va+size,1,1);
        uint64_t other_va=fmt ? 0x800000:0x2000000,other_table=BASE+0x1c000;
        check(!sptm_mac_retype(&memory,other_table,11,20,3),"allocate unrelated L3");
        check(!sptm_mac_map_user_table_live(&memory,&backend,ROOT,other_va,2,other_table|3),"attach unrelated L3");
        insert(fmt,other_va,1,0);
        memcpy(before,ram,SIZE);memcpy(host_before,host,sizeof(host));
        check(!condemn(va,1,&result) && result==0,"condemn populated table");
        for(unsigned n=0;n<(fmt ? 4u:1u);n++)before[L2-BASE+n*8]|=4;
        check(!memcmp(before,ram,SIZE) && !memcmp(host_before,host,sizeof(host)),
              "condemn changes only grouped parent lifetime bits");
        check(!condemn(va,1,&result) && result==7,"duplicate condemnation returns7");
        check(sptm_mac_map_user_page(&memory,&backend,ROOT,va,pte,1,0,&result)==SPTM_TABLE_MISSING,
              "even identical mapping cannot insert into condemned table");
        check(detach(va,2)==SPTM_FRAME_BUSY,"nonempty ordinary table cannot detach");
        for(cpu_now=0;cpu_now<6;cpu_now++) {
            check(!sptm_mac_switch_root(&memory,&state,&rb,cpu_now,BASE,0,0),"leave condemned root");
            check(!sptm_mac_switch_root(&memory,&state,&rb,cpu_now,ROOT,0,0),"reactivate populated condemned root");
            struct mmu_config cfg={12,17,installed[cpu_now]};struct mmu_leaf leaf;
            check(!mmu_walk(&cfg,va,hread,0,&leaf) && leaf.valid && leaf.pa==DATA,
                  "condemnation retains existing hardware translations");
        }
        check(!condemn(va,0,&result) && result==0,"uncondemn restores table");
        result=99;check(condemn(va,0,&result)==SPTM_BAD_TABLE && result==99,"uncondemn wrong state refused");
        check(!sptm_mac_map_user_page(&memory,&backend,ROOT,va,pte,1,0,&result) && result==1,
              "uncondemn restores insertion admission");
        check(!condemn(va,1,&result),"mark table for actual removal");
        check(!remove_pages(va,2,1,BASE),"region removal operates through condemned parent");
        uint64_t allocated=next_host;
        check(!detach(va,2),"active condemned empty table detaches");
        check(get(meta(L3)+6,2)==0 && get(meta(L2)+8,2)==1 && get(meta(ROOT)+6,2)==7,
              "only selected link references released; all six CPU refs retained");
        check(state.cache[0].valid && state.cache[0].leaves==1 && next_host==allocated,
              "active cache preserved without allocation");
        struct mmu_config cfg={12,17,state.cache[0].shadow};struct mmu_leaf leaf;
        check(!mmu_walk(&cfg,other_va,hread,0,&leaf) && leaf.valid && leaf.pa==DATA,
              "unrelated user mapping survives detach");
        check(!condemn(va,1,&result) && result==7,"absent L3 condemnation returns7");
        check(!sptm_mac_retype(&memory,L3,20,11,0) && !sptm_mac_retype(&memory,L3,11,20,3),
              "detached allocation frame can be recycled");
        check(!sptm_mac_map_user_table_live(&memory,&backend,ROOT,0,2,L3|3),"reattach recycled table to active root");
        insert(fmt,va,0,0);check(!remove_pages(va,1,1,BASE),"remove recycled mapping");
        check(!detach(va,2),"unmarked ordinary empty table also detaches");
        check(!remove_pages(other_va,1,1,BASE) && !detach(other_va,2),"remove unrelated subtree");
        check(!detach(0,1),"detach empty L2 while root active");
        if(fmt)check(!detach(0,0),"detach full empty L1 group while root active");
        check(get(meta(ROOT)+6,2)==6 && !state.cache[0].leaves,"only active CPU references remain");
        check(detach_reads<100000,"sparse preflight avoids pagewise huge-address-space scan");

        for(unsigned bad=0;bad<14;bad++) {
            setup_remove(fmt);callbacks();result=99;uint64_t addr=va;unsigned yes=1;
            switch(bad) {
            case 0:addr++;break;
            case 1:addr=1UL<<47;break;
            case 2:yes=2;break;
            case 3:put(meta(L3)+2,23,1);break;
            case 4:put(meta(L3)+4,2,1);break;
            case 5:put(meta(L3)+6,2,2);break;
            case 6:put(meta(L3)+8,2049,2);break;
            case 7:put(L2,L3|0x103,8);break;
            case 8:put(L2,ROOT|3,8);break;
            case 9:fail_pa=L2;break;
            case 10:fail_pa=meta(L3);break;
            case 11:backend.active_refs=0;break;
            case 12:put(meta(ROOT)+6,0,2);break;
            case 13:put(meta(L3),1,1);break;
            }
            memcpy(before,ram,SIZE);memcpy(host_before,host,sizeof(host));unsigned pub=publications;
            check(condemn(addr,yes,&result)!=SPTM_OK && result==99,"invalid condemnation refused");
            check(!memcmp(before,ram,SIZE) && !memcmp(host_before,host,sizeof(host)) && publications==pub,
                  "invalid condemnation is atomic");
        }
        if(fmt)for(unsigned bad=1;bad<4;bad++) {
            setup_remove(fmt);callbacks();put(L2+bad*8,(L3+bad*4096)|7,8);
            memcpy(before,ram,SIZE);unsigned pub=publications;
            check(!condemn(va,1,&result) && result==7,"mixed group reports condemnation race");
            check(!memcmp(before,ram,SIZE) && publications==pub,"late group conflict cannot partially mark earlier descriptors");
            put(L2,L3|7,8);memcpy(before,ram,SIZE);
            check(condemn(va,0,&result)!=SPTM_OK && !memcmp(before,ram,SIZE),"partial uncondemn refused atomically");
        }
        for(unsigned bad=0;bad<7;bad++) {
            setup_remove(fmt);callbacks();
            if(bad==0) {insert(fmt,va,0,0);put(source_slot(fmt,va),0,8);put(meta(L3)+8,0,2);}
            if(bad==1)backend.commit_detach=0;
            if(bad==2) {backend.prepare_detach=0;backend.commit_detach=0;}
            if(bad==3)put(meta(L3)+6,0,2);
            if(bad==4)put(meta(L2)+8,0,2);
            if(bad==5)state.cache[0].asid++;
            if(bad==6)put(L3,1,8);
            memcpy(before,ram,SIZE);memcpy(host_before,host,sizeof(host));unsigned pub=publications;
            check(detach(va,2)!=SPTM_OK,"bad detach refuses");
            check(!memcmp(before,ram,SIZE) && !memcmp(host_before,host,sizeof(host)) && publications==pub && !detach_committed,
                  "failed detach preflight preserves both views and ownership");
        }
        setup_remove(fmt);callbacks();detach_fail=1;
        check(detach(va,2)==SPTM_SHADOW_FAILED && get(meta(L3)+6,2)==1 && get(meta(L2)+8,2)==1,
              "fatal detach failure cannot release table references");

        /* Retained commpage data: removing a parent is not unmapping its owned
         * leaf references. Exercise populated detachment on all six CPUs. */
        setup(fmt);callbacks();
        check(!sptm_mac_retype(&memory,L3,20,11,0) && !sptm_mac_retype(&memory,L3,11,23,3),"commpage table constructor");
        check(!sptm_mac_retype(&memory,DATA,11,29,0),"commpage data constructor");
        if(fmt)check(!sptm_mac_map_user_table_live(&memory,&backend,ROOT,VA&~(3UL<<39),0,L1|3),"commpage L1");
        check(!sptm_mac_map_user_table_live(&memory,&backend,ROOT,fmt ? VA&~(3UL<<30):VA,1,L2|3),"commpage L2");
        check(!sptm_mac_map_user_table_live(&memory,&backend,ROOT,fmt ? VA&~(3UL<<21):VA,2,L3|3),"commpage L3");
        check(!sptm_mac_map_user_page(&memory,&backend,ROOT,VA,DATA|NX,1,0,&result),"active commpage leaf");
        uint64_t table_va=fmt ? VA&~(3UL<<21):VA;
        check(condemn(table_va,1,&result)==SPTM_TYPE_MISMATCH,"commpage cannot be condemned");
        check(!detach(table_va,2),"active populated commpage detaches");
        check(!get(meta(L3)+6,2) && get(meta(L3)+8,2)==1 && get(meta(DATA)+8,4)==1,
              "commpage table and data leaf references retained after parent removal");
        check(!state.cache[0].leaves && state.cache[0].valid,"commpage removed from live hardware cache");
    }
    printf("User table lifetime: %u checks, %u failures\n",checks,failures);
    return failures ? 1:0;
}

/* SPDX-License-Identifier: MIT */
#define SPTM_LIVE_FIXTURE
#include "test-sptm-live.c"
static uint8_t host_before[sizeof(host)],metadata_before[SIZE/0x4000*16];
static unsigned unmap_prepared,unmap_committed,flushes,fail_commit;
static int prepare_remove(void *ctx,uint64_t root,uint64_t va,unsigned shift,uint64_t count)
{
    (void)ctx;unmap_prepared++;
    check(root==state.cache[0].root,"unmap selects requested root");
    struct shadow s=shadow(state.cache[0].shadow);
    return sptm_root_prepare_unmap(&state.cache[0],&s,&memory,va,shift,count);
}
static int commit_remove(void *ctx,uint64_t root,uint64_t va,unsigned shift,
                         uint64_t count,uint64_t removed)
{
    (void)ctx;(void)root;unmap_committed++;
    check(!memcmp(metadata_before,ram+(FM-BASE),sizeof(metadata_before)),
          "source removal retains all references until hardware invalidation");
    if(fail_commit)return 0;
    struct shadow s=shadow(state.cache[0].shadow);
    if(!sptm_root_commit_unmap(&state.cache[0],&s,va,shift,count,removed))return 0;
    for(unsigned cpu=0;cpu<6;cpu++)if(state.active[cpu]==ROOT) {
        struct mmu_config cfg={12,17,installed[cpu]};struct mmu_leaf leaf;
        for(uint64_t off=0;off<(count<<shift);off+=4096)
            check(!mmu_walk(&cfg,va+off,hread,0,&leaf) && !leaf.valid,
                  "every active hardware view loses every removed 4K leaf");
    }
    check(!memcmp(metadata_before,ram+(FM-BASE),sizeof(metadata_before)),
          "references still held at broadcast TLB boundary");
    flushes++;return 1;
}
static enum sptm_result remove_pages(uint64_t va,uint64_t count,uint64_t options,uint64_t scratch)
{
    memcpy(metadata_before,ram+(FM-BASE),sizeof(metadata_before));
    return sptm_mac_unmap_user_region(&memory,&backend,ROOT,va,count,options,scratch);
}
static void setup_remove(unsigned fmt)
{
    setup(fmt);unmap_prepared=unmap_committed=flushes=fail_commit=0;
    backend.prepare_unmap=prepare_remove;backend.commit_unmap=commit_remove;
    if(fmt)check(!sptm_mac_map_user_table_live(&memory,&backend,ROOT,0,0,L1|3),"link L1");
    check(!sptm_mac_map_user_table_live(&memory,&backend,ROOT,0,1,L2|3),"link L2");
    check(!sptm_mac_map_user_table_live(&memory,&backend,ROOT,0,2,L3|3),"link L3");
}
static uint64_t source_slot(unsigned fmt,uint64_t va)
{
    struct mmu_config cfg={fmt ? 12:14,17,ROOT};uint64_t table=ROOT;
    for(unsigned l=mmu_start_level(cfg.granule_shift,17);l<3;l++)
        table=get(table+8*mmu_index(cfg.granule_shift,l,va),8)&PT_OA_MASK;
    return table+8*mmu_index(cfg.granule_shift,3,va);
}
static uint64_t hw_slot(uint64_t va)
{
    uint64_t table=state.cache[0].shadow,v;
    for(unsigned l=0;l<3;l++) {
        check(!hread(0,table+8*mmu_index(12,l,va),&v),"read hardware hierarchy");
        table=v&PT_OA_MASK;
    }
    return table+8*mmu_index(12,3,va);
}
static uint64_t insert(unsigned fmt,uint64_t va,unsigned ro,unsigned subpage)
{
    uint64_t pte=(DATA+(fmt ? subpage*4096:0))|0x0060000000000e43UL|(ro ? 0x80:0),result;
    check(!sptm_mac_map_user_page(&memory,&backend,ROOT,va,pte,1,0,&result),"insert user mapping");
    return pte;
}
#ifndef SPTM_UNMAP_FIXTURE
int main(void)
{
    for(unsigned fmt=0;fmt<2;fmt++) {
        unsigned shift=fmt ? 12:14;uint64_t size=1UL<<shift,va=0x4000,ptes[64];
        setup_remove(fmt);
        for(unsigned i=0;i<64;i++)ptes[i]=insert(fmt,va+i*size,i&1,i&3);
        insert(fmt,0x200000,1,0);
        uint64_t allocated=next_host;unsigned pub=publications;
        check(!remove_pages(va,64,1,BASE),"maximum batch removed");
        check(unmap_prepared==1 && unmap_committed==1 && flushes==1 && publications>pub,
              "one preflight, commit and invalidation per batch");
        for(unsigned i=0;i<64;i++) {
            check(get(BASE+i*8,8)==ptes[i],"exact prior-PTE output order");
            check(get(source_slot(fmt,va+i*size),8)==0,"source leaf removed");
        }
        check(next_host==allocated && state.cache[0].leaves==1,"no allocation, surviving shadow leaf counted");
        check(get(meta(DATA)+8,4)==1 && !get(meta(DATA)+12,4) && get(meta(L3)+8,2)==1,
              "only outside RO alias retains references");
        check(get(meta(ROOT)+6,2)==7,"six active CPU references preserved");
        check(!remove_pages(va,64,0,BASE),"duplicate removal succeeds");
        for(unsigned i=0;i<64;i++)check(get(BASE+i*8,8)==0,"duplicate returns zero prior PTEs");
        check(state.cache[0].leaves==1 && get(meta(DATA)+8,4)==1,"duplicate does not release surviving alias");
        check(!remove_pages(1UL<<42,64,1,BASE),"missing parent returns empty batch");
        for(unsigned i=0;i<64;i++)check(get(BASE+i*8,8)==0,"absent parent returns zeros");
        for(cpu_now=0;cpu_now<6;cpu_now++)
            check(!sptm_mac_switch_root(&memory,&state,&rb,cpu_now,BASE,0,0),"deactivate root");
        backend.active_refs=0;backend.ttbr0=BASE;
        check(!remove_pages(0x200000,1,1,BASE),"inactive cached root removes surviving alias");
        check(!state.cache[0].leaves && !get(meta(DATA)+8,4) && !get(meta(L3)+8,2),"last references released");
        cpu_now=0;
        check(!sptm_mac_switch_root(&memory,&state,&rb,0,ROOT,0,0) && state.builds==1,
              "reactivation safely reuses empty cached shadow");
        check(!sptm_mac_switch_root(&memory,&state,&rb,0,BASE,0,0),"deactivate for table teardown");
        check(!sptm_mac_unmap_user_table(&memory,&backend,ROOT,0,2),"empty ordinary leaf table detaches");
        check(!sptm_mac_retype(&memory,L3,20,11,0),"detached empty leaf table can be recycled");
        check(!sptm_mac_unmap_user_table(&memory,&backend,ROOT,0,1),"empty L2 detaches");
        if(fmt)check(!sptm_mac_unmap_user_table(&memory,&backend,ROOT,0,0),"empty L1 group detaches");
        check(!get(meta(ROOT)+6,2),"inactive root has no remaining children or CPU references");

        for(unsigned bad=0;bad<27;bad++) {
            setup_remove(fmt);uint64_t first=insert(fmt,va,0,0),second=insert(fmt,va+size,1,1);
            uint64_t addr=va,count=2,options=1,scratch=BASE;
            switch(bad) {
            case 0:count=0;break;
            case 1:count=65;break;
            case 2:options=2;break;
            case 3:options=0x100;break;
            case 4:addr++;break;
            case 5:addr=(1UL<<(2*shift-3))-size;break;
            case 6:addr=1UL<<47;break;
            case 7:count=UINT64_MAX;break;
            case 8:scratch++;break;
            case 9:scratch=FM;break;
            case 10:scratch=L3;break;
            case 11:scratch=FM-8;break;
            case 12:scratch=ROOT-8;break;
            case 13:fail_pa=BASE+8;break;
            case 14:put(source_slot(fmt,va+size),second&~PT_UXN,8);break;
            case 15:put(source_slot(fmt,va+size),1UL<<63,8);break;
            case 16:put(meta(DATA)+8,0,4);break;
            case 17:put(meta(L3)+8,1,2);break;
            case 18:hwrite(0,hw_slot(va+size),second^0x4000);break;
            case 19:hwrite(0,hw_slot(va+size+size-4096),0);break;
            case 20:put(meta(L3)+2,23,1);break;
            case 21:backend.prepare_unmap=0;break;
            case 22:backend.prepare_unmap=0;backend.commit_unmap=0;break;
            case 23:state.cache[0].leaves=1;break;
            case 24:state.cache[0].asid++;break;
            case 25:memory.aperture_va=va+size;memory.aperture_size=size;break;
            case 26:scratch=UINT64_MAX-7;break;
            }
            memcpy(before,ram,SIZE);memcpy(host_before,host,sizeof(host));
            struct sptm_root_state old_state=state;allocated=next_host;pub=publications;
            enum sptm_result r=remove_pages(addr,count,options,scratch);
            if(!r)printf("case %u format %u unexpectedly accepted\n",bad,fmt);
            check(r!=SPTM_OK,"invalid batch refused");
            check(!memcmp(before,ram,SIZE) && !memcmp(host_before,host,sizeof(host)) &&
                  !memcmp(&old_state,&state,sizeof(state)),"preflight refusal preserves source/output/refs/hardware/cache");
            check(!unmap_committed && !flushes && next_host==allocated && publications==pub,
                  "refused batch performs no commit, allocation or publication");
            (void)first;
        }
        setup_remove(fmt);insert(fmt,va,0,0);fail_commit=1;put(BASE,0x11223344,8);
        check(remove_pages(va,1,1,BASE)==SPTM_SHADOW_FAILED,"failed commit is fatal, never success");
        check(get(meta(DATA)+12,4)==1 && get(meta(L3)+8,2)==1 && get(BASE,8)==0x11223344,
              "fatal commit failure retains ownership and leaves output unacknowledged");
    }
    printf("User unmapping: %u checks, %u failures\n",checks,failures);
    return failures ? 1:0;
}
#endif

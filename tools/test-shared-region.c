/* SPDX-License-Identifier: MIT */
#define SPTM_SHARED_PAGE_TEST_MAIN shared_page_fixture_checks
#include "test-shared-page.c"
#define INPUT (OUT+0x400)
#define EXEC_DATA (DATA+PAGE)
static uint8_t hw_before[sizeof(bytes)];
static unsigned batch_count,batch_shift,batch_populated;
static uint64_t batch_va,prior[64];
static int commit_region(void *ctx,uint64_t root,uint64_t va,unsigned shift,uint64_t count,
                          const struct sptm_shared_update_entry *entries)
{
    (void)ctx;uint64_t mask;
    if(!sptm_root_shared_aliases(&m,&roots,root,va,shift,&mask) || mask!=plan)return 0;
    for(unsigned i=0;i<3;i++)if(mask&(1UL<<i)) {
        struct shadow s=shadow_for(i);
        for(uint64_t n=0;n<count;n++)if(entries[n].old!=entries[n].next)
            if(!sptm_root_commit_update(&roots.cache[i],&s,&m,va+(n<<shift),shift,
                                       entries[n].old,entries[n].next))return 0;
        if(!sync_view(i))return 0;
    }
    commits++;flushes++;return 1;
}
static void setup_region(unsigned fmt,unsigned part,unsigned active,unsigned aliases,unsigned count,unsigned mixed)
{
    init(fmt,active,aliases);batch_shift=geom.shift;batch_count=count;batch_populated=0;
    batch_va=START+part*(1UL<<(2*geom.shift-3))+geom.page_size;
    memset(bytes+EXEC_DATA-BASE,0x5a,PAGE);meta(EXEC_DATA)[2]=14;
    for(unsigned n=0;n<count;n++) {
        uint64_t va=batch_va+((uint64_t)n<<geom.shift),result=99;
        unsigned kind=mixed ? n%4:1;
        prior[n]=0;
        if(kind) {
            uint64_t pa=(kind==2 ? EXEC_DATA:DATA)+(va&(geom.page_size==4096 ? 0x3fff:0));
            prior[n]=pa|(kind==2 ? 0x00200000000006c3UL:0x0060000000000643UL);
            if(kind==3)prior[n]|=PT_NG;
            CHECK(!sptm_mac_map_user_page(&m,&backend,ROOT,va,prior[n],1,0,&result));
            batch_populated++;
        }
        setword(INPUT+n*8,0x800);
    }
    backend.prepare_shared_update=prepare_shared_unmap;
    backend.commit_shared_update=commit_region;
    prepare_count=commits=flushes=published=0;
}
static void verify_batch(int updated)
{
    for(unsigned n=0;n<batch_count;n++) {
        uint64_t va=batch_va+((uint64_t)n<<batch_shift),pte=prior[n];
        if(pte && updated)pte|=PT_NG;
        CHECK(word(slot_at(ROOT,3,va))==pte);
        for(unsigned i=0;i<3;i++)for(unsigned cpu=0;cpu<7;cpu++)
        for(uint64_t off=0;off<geom.page_size;off+=4096) {
            struct mmu_config cfg={12,17,cpu==6 ? roots.cache[i].shadow:sprr_views_root(&views[i],cpu)};
            struct mmu_leaf leaf;
            CHECK(!mmu_walk(&cfg,va+off,read_hw,0,&leaf) && leaf.valid==(i<nested && !!pte));
            if(leaf.valid) {
                CHECK(leaf.pa==(pte&geom.pa_mask)+off);
                CHECK(!((leaf.descriptor^pte)&(PT_LEAF_ATTRS|PT_LEAF_UPPER)));
            }
        }
    }
    for(unsigned i=0;i<3;i++) {
        struct shadow s=shadow_for(i);struct sptm_fixed_view proof;
        CHECK(sptm_root_canonical_view(&roots.cache[i],&s,&m,&proof));
        CHECK(roots.cache[i].leaves==(i<nested ? batch_populated:0));
    }
}
static enum sptm_result update_region(uint64_t options,uint64_t *result,struct sptm_shared_update_state *s)
{return sptm_mac_update_shared_region(&m,&backend,ROOT,batch_va,batch_count,INPUT,options,OUT,result,s);}
/* UPDATE_DISJOINT on the shared-region root (A16 installed-fresh-20261017-v11: page aging, options 0x10a). */
static int resolve_shared(void *ctx,uint64_t root,struct sptm_user_backend *b)
{(void)ctx;(void)root;*b=backend;return 1;}
static void verify_aged(unsigned aged)
{
    for(unsigned n=0;n<batch_count;n++) {
        uint64_t va=batch_va+((uint64_t)n<<batch_shift),pte=prior[n]&~(n<aged ? PT_AF:0);
        CHECK(word(slot_at(ROOT,3,va))==pte);
        for(unsigned i=0;i<3;i++)for(unsigned cpu=0;cpu<7;cpu++)
        for(uint64_t off=0;off<geom.page_size;off+=4096) {
            struct mmu_config cfg={12,17,cpu==6 ? roots.cache[i].shadow:sprr_views_root(&views[i],cpu)};
            struct mmu_leaf leaf;
            CHECK(!mmu_walk(&cfg,va+off,read_hw,0,&leaf) && leaf.valid==(i<nested));
            if(leaf.valid)CHECK(leaf.pa==(pte&geom.pa_mask)+off &&
                                !((leaf.descriptor^pte)&(PT_LEAF_ATTRS|PT_LEAF_UPPER)));
        }
    }
    for(unsigned i=0;i<3;i++) {
        struct shadow s=shadow_for(i);struct sptm_fixed_view proof;
        CHECK(sptm_root_canonical_view(&roots.cache[i],&s,&m,&proof));
        CHECK(roots.cache[i].leaves==(i<nested ? batch_populated:0));
    }
}
int main(int argc,char **argv)
{
    if(argc==5 && !strcmp(argv[1],"--pte")) {
        uint64_t next=0;unsigned status=sptm_mac_shared_ng_pte(strtoull(argv[2],0,16),
            strtoull(argv[3],0,16),strtoull(argv[4],0,16),&next);
        printf("%u %016llx\n",status,(unsigned long long)next);return 0;
    }
    for(unsigned fmt=0;fmt<2;fmt++)for(unsigned part=0;part<(fmt?4:1);part++)
    for(unsigned active=0;active<=6;active+=6)for(unsigned aliases=0;aliases<=2;aliases++)
    for(unsigned size=0;size<3;size++)for(unsigned mixed=0;mixed<2;mixed++) {
        setup_region(fmt,part,active,aliases,size==0?1:size==1?2:64,mixed);
        struct sptm_shared_update_state state={0};uint64_t result=99;
        memcpy(saved,bytes,250*PAGE);unsigned changes=0;
        for(unsigned n=0;n<batch_count;n++)changes+=prior[n] && !(prior[n]&PT_NG);
        CHECK(!update_region(0x104,&result,&state) && result==(changes?5:0));
        CHECK(state.latest.calls==1 && state.latest.entries==batch_count && state.latest.changed==changes);
        CHECK(state.changed.calls==!!changes && state.changed.last_changed==!!changes);
        CHECK(commits==!!changes && flushes==!!changes);verify_batch(1);
        for(unsigned n=0;n<batch_count;n++)CHECK(word(OUT+n*8)==prior[n]);
        /* nG changes no data bytes, type, child count or RO/RW references. */
        CHECK(!memcmp(saved+(m.frame_map_pa-BASE),bytes+(m.frame_map_pa-BASE),250*16));
        CHECK(!memcmp(saved+(DATA-BASE),bytes+(DATA-BASE),2*PAGE));
        struct sptm_user_update_state witness=state.changed;unsigned old_commits=commits;
        CHECK(!update_region(4,&result,&state) && !result && commits==old_commits);
        CHECK(!memcmp(&witness,&state.changed,sizeof witness));verify_batch(1);
    }
    for(unsigned fmt=0;fmt<2;fmt++)for(unsigned bad=0;bad<17;bad++) {
        setup_region(fmt,0,6,2,64,1);uint64_t result=99,root=ROOT,va=batch_va,
            count=64,input=INPUT,scratch=OUT,options=4;
        struct sptm_shared_update_state state={0};
        switch(bad) {
        case 0:count=0;break;case 1:count=65;break;case 2:va++;break;
        case 3:va=(va|((1UL<<(2*geom.shift-3))-1))&~(geom.page_size-1);break;
        case 4:input++;break;case 5:scratch=INPUT;break;case 6:scratch=ROOT;break;
        case 7:setword(INPUT+62*8,0);break; /* later executable leaf lacks nG template */
        case 8:meta(EXEC_DATA)[2]=11;break;
        case 9:backend.prepare_shared_update=0;break;
        case 10:backend.commit_shared_update=0;break;case 11:root=USER;break;
        case 12:options=6;break;case 13:fail_alias=2;break;
        case 14:roots.cache[1].asid++;break;
        case 15:input=BASE+sizeof bytes;break;
        case 16:m.shared_regions->slots[0].size=va-m.shared_regions->slots[0].start+geom.page_size;break;
        }
        memcpy(saved,bytes,250*PAGE);memcpy(hw_before,bytes,sizeof bytes);
        CHECK(sptm_mac_update_shared_region(&m,&backend,root,va,count,input,options,scratch,
                                            &result,&state)!=SPTM_OK);
        CHECK(!memcmp(saved,bytes,250*PAGE) && !memcmp(hw_before,bytes,sizeof bytes));
        CHECK(!commits && !published && !state.latest.calls && result==99);
    }
    /* Absent source table: exact old-zero output, no alias transaction.
     * Upper argument halves are ignored by the pinned endpoint wrapper. */
    setup_region(0,0,6,2,64,1);uint64_t result=99;struct sptm_shared_update_state state={0};
    uint64_t empty=batch_va+4*(1UL<<(2*geom.shift-3));
    CHECK(!sptm_mac_update_shared_region(&m,&backend,ROOT,empty,(1UL<<32)|64,
        INPUT,(1UL<<32)|4,OUT,&result,&state));
    CHECK(!result && !commits && state.latest.count==64 && !state.latest.changed);
    for(unsigned n=0;n<64;n++)CHECK(!word(OUT+n*8));
    /* Page aging on shared-region leaves: every record clears AF on its DEFAULT
     * leaf through the shared-update backend (one alias transaction each); the
     * old descriptors come back in scratch and the call answers 5 (option 0x100,
     * hardware-visible change). A stale record (other frame) is reported, not
     * changed; a shared root outside its slot or a missing backend is refused
     * with nothing written. */
    for(unsigned fmt=0;fmt<2;fmt++)for(unsigned active=0;active<=6;active+=6)
    for(unsigned aliases=0;aliases<=2;aliases++)for(unsigned size=0;size<2;size++) {
        unsigned count=size ? 3:1;
        setup_region(fmt,0,active,aliases,count,0);
        for(unsigned n=0;n<count;n++) {
            uint64_t va=batch_va+((uint64_t)n<<batch_shift);
            setword(INPUT+n*24,ROOT);setword(INPUT+n*24+8,va);setword(INPUT+n*24+16,prior[n]&~PT_AF);
        }
        struct sptm_user_update_state st={0};uint64_t result=99;
        memcpy(saved,bytes,250*PAGE);
        CHECK(!sptm_mac_update_user_disjoint(&m,resolve_shared,0,DATA,INPUT,count,0x10a,OUT,&result,&st));
        CHECK(result==5 && st.calls==1 && st.changed==count && commits==count && flushes==count);
        for(unsigned n=0;n<count;n++)CHECK(word(OUT+n*8)==prior[n]);
        verify_aged(count);
        /* AF changes no data bytes, type, child count or RO/RW references. */
        CHECK(!memcmp(saved+(m.frame_map_pa-BASE),bytes+(m.frame_map_pa-BASE),250*16));
        CHECK(!memcmp(saved+(DATA-BASE),bytes+(DATA-BASE),2*PAGE));
        /* Aging again: nothing changes, no alias transaction, result 0. */
        unsigned old_commits=commits;result=99;
        CHECK(!sptm_mac_update_user_disjoint(&m,resolve_shared,0,DATA,INPUT,count,0x10a,OUT,&result,&st));
        CHECK(!result && commits==old_commits);verify_aged(count);
    }
    for(unsigned fmt=0;fmt<2;fmt++)for(unsigned bad=0;bad<4;bad++) {
        setup_region(fmt,0,6,2,2,0);
        for(unsigned n=0;n<2;n++) {
            uint64_t va=batch_va+((uint64_t)n<<batch_shift);
            setword(INPUT+n*24,ROOT);setword(INPUT+n*24+8,va);setword(INPUT+n*24+16,prior[n]&~PT_AF);
        }
        uint64_t target=DATA;
        switch(bad) {
        case 0:backend.prepare_shared_update=0;break;
        case 1:backend.commit_shared_update=0;break;
        case 2:m.shared_regions->slots[0].size=batch_va-m.shared_regions->slots[0].start;break;
        case 3:target=EXEC_DATA;break;   /* stale list: reported unchanged, not refused */
        }
        struct sptm_user_update_state st={0};uint64_t result=99;
        memcpy(saved,bytes,250*PAGE);memcpy(hw_before,bytes,sizeof bytes);
        enum sptm_result r=sptm_mac_update_user_disjoint(&m,resolve_shared,0,target,INPUT,2,0x10a,OUT,&result,&st);
        if(bad==3) {
            CHECK(!r && !result && !commits && word(OUT)==prior[0] && word(OUT+8)==prior[1]);
            verify_aged(0);
        } else {
            CHECK(r!=SPTM_OK && result==99 && !commits && !published);
            CHECK(!memcmp(saved,bytes,250*PAGE) && !memcmp(hw_before,bytes,sizeof bytes));
        }
    }
    printf("SHARED_REGION: %u checks passed (NX/RX/holes, active/inactive aliases, six private views)\n",checks);
    return 0;
}

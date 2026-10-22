/* SPDX-License-Identifier: MIT */
/* Compressed user PTEs: the whole lifecycle XNU drives once its compressor runs.
 *
 * pmap_disconnect_options(PMAP_OPTIONS_COMPRESSOR) sends UNMAP_DISJOINT with a
 * template of ARM_PTE_COMPRESSED (bit63, optionally ALT bit62). The slot then
 * holds an invalid software marker. After that:
 *
 *   SWITCH_ROOT  the process runs again. Apple never walks the tables; this
 *                monitor validates them, and must accept the marker without
 *                publishing it to hardware.
 *   MAP_PAGE     the page is faulted back in. Apple's ...f92cc/f9490/f9574
 *                installs over any invalid descriptor without bit7 and returns
 *                0 (tools/replay-map-page-status.py, "compressed" rows). XNU's
 *                pmap_enter (ba61544) adds a PV entry only for status 0; the
 *                marker had none, so 1 would lose the new mapping's PV entry.
 *                The prior-PTE output is the marker (XNU ba62e30 accepts only
 *                bits63:61|7 in it and treats it as compressed).
 *   UNMAP_REGION the range is removed. Apple's callback ...fd2f8..fd32c keeps
 *                the marker for option0 and clears it for option1 (XNU passes
 *                PMAP_OPTIONS_REMOVE>>8 at ba63360); never BAD_TABLE. Either
 *                way the prior-PTE output is the marker (XNU ba634b0 counts it).
 *
 * Apple's table count (...ecbe8, +8 u16) counts a leaf as occupied when it is
 * valid or has any of bits63:61; the marker keeps its table allocated until it
 * is replaced or removed. Both page geometries. */
#define SPTM_UNMAP_FIXTURE
#include "test-sptm-user-unmap.c"
#define LIST (BASE+0x20000)
#define MARKER (1UL<<63)
#define MARKER_ALT ((1UL<<63)|(1UL<<62))

static int resolve_root(void *ctx,uint64_t root,struct sptm_user_backend *out)
{(void)ctx;if(root!=ROOT)return 0;*out=backend;return 1;}
static enum sptm_result compress(uint64_t va,uint64_t marker)
{
    put(LIST,ROOT,8);put(LIST+8,va,8);put(LIST+16,marker,8);
    memcpy(metadata_before,ram+(FM-BASE),sizeof(metadata_before));
    return sptm_mac_unmap_user_disjoint(&memory,resolve_root,0,DATA,LIST,1,BASE,0);
}
static int hw_valid(uint64_t va,uint64_t size)
{
    int all=1,none=1;
    for(unsigned cpu=0;cpu<6;cpu++)if(state.active[cpu]==ROOT)
        for(uint64_t off=0;off<size;off+=4096) {
            struct mmu_config cfg={12,17,installed[cpu]};struct mmu_leaf leaf;
            if(mmu_walk(&cfg,va+off,hread,0,&leaf))return -1;
            all&=leaf.valid;none&=!leaf.valid;
        }
    return all ? 1 : none ? 0 : -1;
}
int main(void)
{
    for(unsigned fmt=0;fmt<2;fmt++)for(unsigned alt=0;alt<2;alt++) {
        unsigned shift=fmt ? 12:14;uint64_t size=1UL<<shift,va=0x4000,result;
        uint64_t marker=alt ? MARKER_ALT:MARKER;
        setup_remove(fmt);
        uint64_t pte=insert(fmt,va,0,0),slot_pa=source_slot(fmt,va);
        check(get(meta(DATA)+12,4)==1 && get(meta(L3)+8,2)==1 && state.cache[0].leaves==1,
              "resident page counted");
        check(!compress(va,marker),"UNMAP_DISJOINT installs the compressed marker");
        check(get(slot_pa,8)==marker && get(BASE,8)==pte,"marker stored, old leaf returned");
        check(!get(meta(DATA)+12,4) && get(meta(L3)+8,2)==1 && !state.cache[0].leaves,
              "marker drops the data reference, keeps the table occupied");
        check(hw_valid(va,size)==0,"compressed page absent from every hardware view");

        /* The process is scheduled again: a switch must validate the marker. */
        cpu_now=0;
        check(sptm_mac_switch_root(&memory,&state,&rb,0,BASE,0,0)==SPTM_OK,"switch CPU0 to kernel");
        check(sptm_mac_switch_root(&memory,&state,&rb,0,ROOT,0,0)==SPTM_OK,
              "SWITCH_ROOT accepts a root holding a compressed marker");
        /* A full rebuild (cache eviction) must skip the marker, not map it. */
        for(cpu_now=0;cpu_now<6;cpu_now++)
            check(!sptm_mac_switch_root(&memory,&state,&rb,cpu_now,BASE,0,0),"deactivate for rebuild");
        check(sptm_root_invalidate(&state,ROOT,0),"invalidate cached shadow");
        unsigned builds=state.builds;
        for(cpu_now=0;cpu_now<6;cpu_now++)
            check(sptm_mac_switch_root(&memory,&state,&rb,cpu_now,ROOT,0,0)==SPTM_OK,
                  "rebuild from tables holding a compressed marker");
        check(state.builds==builds+1 && !state.cache[0].leaves && hw_valid(va,size)==0,
              "rebuilt shadow has no leaf for the marker");
        check(get(slot_pa,8)==marker,"switching never alters the marker");

        /* Refault: MAP_PAGE over the marker, with the prior-PTE output. */
        put(BASE,0x1111,8);put(BASE+8,0x2222,8);unsigned before_commits=committed;
        enum sptm_result r=sptm_mac_map_user_page(&memory,&backend,ROOT,va,pte,0,BASE,&result);
        check(r==SPTM_OK,"MAP_PAGE installs over a compressed marker");
        check(r==SPTM_OK && result==0,"status 0 (new mapping): XNU enters a PV entry");
        check(get(slot_pa,8)==pte,"new leaf stored");
        check(get(BASE,8)==marker && get(BASE+8,8)==0xfffffe0100000000UL+(slot_pa-BASE),
              "prior-PTE output is the marker and its slot pointer");
        check(get(meta(DATA)+12,4)==1 && get(meta(L3)+8,2)==1,
              "data reference restored; occupied count unchanged by marker->leaf");
        check(committed==before_commits+1 && state.cache[0].leaves==1 && hw_valid(va,size)==1,
              "refaulted page published to every hardware view");

        /* UNMAP_REGION option0 retains, option1 removes, both report it. */
        check(!compress(va,marker),"compress again");
        uint64_t neighbour=insert(fmt,va+size,1,0);
        check(get(meta(L3)+8,2)==2,"marker and neighbour both occupy the table");
        put(BASE,0x3333,8);
        r=remove_pages(va,3,0,BASE);
        check(r==SPTM_OK,"UNMAP_REGION option0 accepts a compressed marker");
        check(get(BASE,8)==marker && get(BASE+8,8)==neighbour && !get(BASE+16,8),
              "option0 prior PTEs: marker, removed leaf, empty");
        check(get(slot_pa,8)==marker && get(meta(L3)+8,2)==1,
              "option0 keeps the marker and its table count");
        check(!get(meta(DATA)+8,4) && !get(meta(DATA)+12,4) && !state.cache[0].leaves,
              "only the valid neighbour's references and shadow leaf released");
        r=remove_pages(va,3,1,BASE);
        check(r==SPTM_OK,"UNMAP_REGION option1 accepts a compressed marker");
        check(get(BASE,8)==marker && !get(BASE+8,8),"option1 reports the removed marker");
        check(!get(slot_pa,8) && !get(meta(L3)+8,2),"option1 clears the marker and its table count");
        r=remove_pages(va,3,1,BASE);
        check(r==SPTM_OK && !get(BASE,8),"repeat removal reports an empty slot");

        /* The now empty table can be detached, as XNU does when the mapping
         * count it reads from +8 reaches zero. */
        for(cpu_now=0;cpu_now<6;cpu_now++)
            check(!sptm_mac_switch_root(&memory,&state,&rb,cpu_now,BASE,0,0),"deactivate for teardown");
        backend.active_refs=0;backend.ttbr0=BASE;
        check(!sptm_mac_unmap_user_table(&memory,&backend,ROOT,0,2),"table freed after the marker is removed");
    }
    for(unsigned fmt=0;fmt<2;fmt++) {
        /* Mixed option1 batch on an inactive cached root: valid, marker, hole. */
        unsigned shift=fmt ? 12:14;uint64_t size=1UL<<shift,va=0x4000;
        setup_remove(fmt);
        insert(fmt,va,0,0);check(!compress(va,MARKER),"marker at first slot");
        uint64_t second=insert(fmt,va+size,1,0);
        for(cpu_now=0;cpu_now<6;cpu_now++)
            check(!sptm_mac_switch_root(&memory,&state,&rb,cpu_now,BASE,0,0),"deactivate");
        backend.active_refs=0;backend.ttbr0=BASE;
        check(remove_pages(va,3,1,BASE)==SPTM_OK,"inactive mixed batch");
        check(get(BASE,8)==MARKER && get(BASE+8,8)==second && !get(BASE+16,8),"mixed prior PTEs");
        check(!get(meta(L3)+8,2) && !get(meta(DATA)+8,4) && !state.cache[0].leaves,
              "mixed batch releases one leaf and one marker");

        /* A transient in-flight descriptor (bit7) is never stored by this
         * monitor; Apple would answer FLUSH_PENDING. Keep refusing it. */
        setup_remove(fmt);uint64_t result;
        put(source_slot(fmt,va),MARKER|0x80,8);put(meta(L3)+8,1,2);
        memcpy(before,ram,SIZE);
        check(sptm_mac_map_user_page(&memory,&backend,ROOT,va,DATA|0x0060000000000e43UL,1,0,&result)!=SPTM_OK &&
              !memcmp(before,ram,SIZE),"in-flight descriptor still refused without mutation");

        /* Apple's +8 occupancy test is bits63:61 (...ecbe8), not only 63:62. */
        setup_remove(fmt);insert(fmt,va,0,0);
        check(!compress(va,1UL<<61),"bit61-only software state");
        check(get(meta(L3)+8,2)==1,"bit61-only software state keeps its table count");
        check(remove_pages(va,1,1,BASE)==SPTM_OK && !get(meta(L3)+8,2) &&
              !get(source_slot(fmt,va),8),"option1 removes it and releases the count");
    }
    printf("Compressed user PTEs: %u checks, %u failures\n",checks,failures);
    return failures ? 1:0;
}

/* SPDX-License-Identifier: MIT */
/* A compressed shared-region page faulted back in (installed-fresh-20261018-v69).
 *
 * v69 stopped on MAP_PAGE root 0x902b4c000 (a shared-region root,
 * shared_regions.slots[2]) VA 0x3555a4000 PTE 0x0060000a33e0c6c3: "table is
 * already present". For a shared root that answer has one source,
 * sptm_mac_shared_map_pte refusing an invalid nonzero old leaf, and the only
 * such leaf the model stores is XNU's compressed marker:
 * pmap_disconnect_options(PMAP_OPTIONS_COMPRESSOR) sends UNMAP_DISJOINT with a
 * template of ARM_PTE_COMPRESSED (bit63, ALT bit62), which leaves bits63:61 in
 * every alias, the shared region's included. Apple's MAP_PAGE installs over it
 * there as on ordinary roots (tools/replay-map-page-status.py root type 19,
 * "compressed" rows: status 0); in-flight bit7 stays FLUSH_PENDING.
 *
 * The whole lifecycle on the shared root, both geometries, with zero, one and
 * two nested cached aliases, active or not: map; compress (the marker stays,
 * the data reference goes, the table stays occupied, every alias loses the
 * leaf); refault (status 0, prior-PTE output the marker, one data reference,
 * the table count unchanged, every alias sees the new leaf through its insert
 * path); then v69's own call, VA 0x3555a4000 with its PTE attributes, over a
 * marker; and a bit7 slot, still refused with nothing changed. CHECK stops
 * at the first failure (the fixture's).
 *
 *   test-shared-compressed                 the lifecycle; prints PASS: N checks
 *   test-shared-compressed --pte OLD REQ   sptm_mac_shared_map_pte alone:
 *                                          "status result next" */
#define SPTM_SHARED_PAGE_TEST_MAIN shared_page_checks
#include "test-shared-page.c"
#define LIST (BASE+192*PAGE)
#define SCRATCH (BASE+PAGE)
#define V69_VA 0x3555a4000UL
#define V69_ATTRS 0x00600000000006c3UL   /* 0x0060000a33e0c6c3 without its OA */

static int resolve_shared(void *ctx,uint64_t root,struct sptm_user_backend *out)
{(void)ctx;if(root!=ROOT)return 0;*out=backend;return 1;}
static enum sptm_result compress(uint64_t va,uint64_t marker)
{
    setword(LIST,ROOT);setword(LIST+8,va);setword(LIST+16,marker);
    return sptm_mac_unmap_user_disjoint(&m,resolve_shared,0,DATA,LIST,1,SCRATCH,0);
}
static uint64_t data_refs(void){return word(m.frame_map_pa+((DATA-BASE)>>14)*16+8);}
static unsigned table_count(uint64_t va){return half(slot_at(ROOT,3,va)&~(PAGE-1),8);}
/* Every cached alias that nests va translates it as pte (0: not at all). */
static void aliases_see(uint64_t va,uint64_t pte)
{
    for(unsigned i=0;i<3;i++) {
        int valid=i<nested && pte;
        for(unsigned cpu=0;cpu<7;cpu++)for(uint64_t off=0;off<geom.page_size;off+=4096) {
            struct mmu_config cfg={12,17,cpu==6 ? roots.cache[i].shadow:sprr_views_root(&views[i],cpu)};
            struct mmu_leaf leaf;
            CHECK(!mmu_walk(&cfg,va+off,read_hw,0,&leaf) && leaf.valid==valid);
            if(valid)CHECK(leaf.pa==(pte&geom.pa_mask)+off);
        }
        CHECK(roots.cache[i].leaves==(unsigned)valid);
    }
}
/* Link a shared level-3 table for va (v69's VA lies outside the fixture's
 * first group). The model attaches shared tables only while the root is
 * unbound (sptm-user.c config, mode 1), and init() has bound it: the binding
 * count and the backend's active references are set aside for the attach. */
static void shared_table_at(uint64_t va)
{
    unsigned bound=half(ROOT,4),active=backend.active_refs;
    sethalf(ROOT,4,0);backend.active_refs=0;
    parents(ROOT,21,va);
    uint64_t span=1UL<<(2*geom.shift-3),aligned=va&~(span*geom.group-1);
    if(!word(slot_at(ROOT,2,va)))
        CHECK(!sptm_mac_map_user_table_live(&m,&backend,ROOT,aligned,2,allocate(21,3)|3));
    sethalf(ROOT,4,bound);backend.active_refs=active;
}
int main(int argc,char **argv)
{
    /* --pte OLD REQUESTED: the shared-root leaf selection alone ("status result next"). */
    if(argc==4 && !strcmp(argv[1],"--pte")) {
        uint64_t next=0,result=99;
        unsigned status=sptm_mac_shared_map_pte(strtoull(argv[2],0,16),strtoull(argv[3],0,16),&next,&result);
        printf("%u %llu %016llx\n",status,(unsigned long long)result,(unsigned long long)next);return 0;
    }
    (void)shared_page_checks;
    static const uint64_t markers[]={1UL<<63,1UL<<62,(1UL<<63)|(1UL<<62),1UL<<61};
    unsigned cycles=0;
    for(unsigned fmt=0;fmt<2;fmt++)for(unsigned part=0;part<(fmt?4:1);part++)
    for(unsigned active=0;active<=6;active+=6)for(unsigned aliases=0;aliases<=2;aliases++)
    for(unsigned k=0;k<4;k++) {
        init(fmt,active,aliases);
        uint64_t va=START+part*(1UL<<(2*geom.shift-3))+geom.page_size,result=99;
        uint64_t pte=DATA|(part*0x1000*(fmt!=0))|V69_ATTRS,marker=markers[k];
        CHECK(!sptm_mac_map_user_page(&m,&backend,ROOT,va,pte,0,OUT,&result) && result==0);
        unsigned count=table_count(va);
        CHECK(count==1 && data_refs()==1);aliases_see(va,pte);
        /* Compress: the marker stays, the data reference goes, the table stays. */
        CHECK(compress(va,marker)==SPTM_OK);
        CHECK(word(slot_at(ROOT,3,va))==marker);
        CHECK(!data_refs() && table_count(va)==count);
        aliases_see(va,0);
        /* Refault: v69's call. Status 0, the marker as the prior PTE. */
        setword(OUT,0xfeedface);setword(OUT+8,0xabcdef);
        enum sptm_result r=sptm_mac_map_user_page(&m,&backend,ROOT,va,pte,0,OUT,&result);
        CHECK(r==SPTM_OK);               /* the v69 refusal: SPTM_TABLE_EXISTS */
        CHECK(result==0 && word(OUT)==marker);
        CHECK(word(OUT+8)==0xfffffe0100000000UL+slot_at(ROOT,3,va)-BASE);
        CHECK(word(slot_at(ROOT,3,va))==pte);
        CHECK(data_refs()==1 && table_count(va)==count);
        verify_leaf(va,pte);
        /* And it unmaps as any leaf does. */
        CHECK(!sptm_mac_unmap_user_region(&m,&backend,ROOT,va,1,0,OUT) && word(OUT)==pte);
        CHECK(!data_refs());verify_leaf(va,0);
        cycles++;
    }
    /* v69's VA and PTE attributes, over a marker, in a 4K shared table. */
    for(unsigned active=0;active<=6;active+=6) {
        init(1,active,0);shared_table_at(V69_VA);
        uint64_t pte=DATA|V69_ATTRS,result=99;
        CHECK(!sptm_mac_map_user_page(&m,&backend,ROOT,V69_VA,pte,0,OUT,&result) && result==0);
        CHECK(compress(V69_VA,1UL<<63)==SPTM_OK && word(slot_at(ROOT,3,V69_VA))==(1UL<<63));
        CHECK(sptm_mac_map_user_page(&m,&backend,ROOT,V69_VA,pte,0,OUT,&result)==SPTM_OK);
        CHECK(result==0 && word(OUT)==(1UL<<63) && word(slot_at(ROOT,3,V69_VA))==pte && data_refs()==1);
    }
    /* In flight (bit7, FLUSH_PENDING): never stored here, still refused, nothing changed. */
    for(unsigned fmt=0;fmt<2;fmt++) {
        init(fmt,6,2);uint64_t va=START+geom.page_size,pte=DATA|V69_ATTRS,result=99;
        CHECK(!sptm_mac_map_user_page(&m,&backend,ROOT,va,pte,0,OUT,&result));
        CHECK(compress(va,1UL<<63)==SPTM_OK);
        setword(slot_at(ROOT,3,va),(1UL<<63)|0x80);
        snapshot();
        CHECK(sptm_mac_map_user_page(&m,&backend,ROOT,va,pte,0,OUT,&result)==SPTM_TABLE_EXISTS);
        unchanged();
    }
    /* The leaf selection itself (shared_map_pte), against Apple's rows. */
    uint64_t next=0,result=99;
    for(unsigned k=0;k<4;k++) {
        CHECK(sptm_mac_shared_map_pte(markers[k],0x0060000a33e0c6c3UL,&next,&result)==SPTM_OK);
        CHECK(result==0 && next==0x0060000a33e0c6c3UL);
        CHECK(sptm_mac_map_page_status(markers[k],0x0060000a33e0c6c3UL)==0);
    }
    CHECK(sptm_mac_shared_map_pte(0x80,0x0060000a33e0c6c3UL,&next,&result)==SPTM_TABLE_EXISTS);
    CHECK(sptm_mac_shared_map_pte((1UL<<63)|0x80,0x0060000a33e0c6c3UL,&next,&result)==SPTM_TABLE_EXISTS);
    /* WAS_WRITABLE is normalized as for an empty slot (writable class 7). */
    CHECK(sptm_mac_shared_map_pte(1UL<<63,0x0860000a33e0c643UL,&next,&result)==SPTM_OK);
    uint64_t empty=0,er=99;
    CHECK(sptm_mac_shared_map_pte(0,0x0860000a33e0c643UL,&empty,&er)==SPTM_OK && next==empty && result==er);
    printf("PASS: %u checks (%u compress/refault cycles on shared roots)\n",checks,cycles);
    return 0;
}

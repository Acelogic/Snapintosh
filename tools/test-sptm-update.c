/* SPDX-License-Identifier: MIT */
/* cc -std=gnu11 -O1 -g -fsanitize=address,undefined -fno-sanitize-recover=all
 * -Icompat -Ishadow tools/test-sptm-update.c compat/sptm-update.c compat/sptm-refs.c
 * compat/sptm-unmap.c shadow/mmu.c
 * shadow/shadow.c -o build/test-sptm-update */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "sptm.h"
#include "sptm-refs.h"
#include "sptm-nx-update.h"
#include "shadow.h"
#define BASE 0x90000000UL
#define SIZE 0x100000UL
#define ROOT BASE
#define FM (BASE+0x4000)
#define L2 (BASE+0x8000)
#define L3 (BASE+0xc000)
#define LIST (BASE+0x10000)
#define SCRATCH (BASE+0x14000)
#define DATA (BASE+0x18000)
#define SHADOW (BASE+0x40000)
#define VA 0xfffffea9b40ac000UL
#define OLD (DATA|0x0060000000000603UL)
static unsigned checks,publications;
static uint8_t ram[SIZE],before[SIZE];
static uint64_t next_shadow;
static struct sptm_update_workspace workspace;
static struct sptm_ref_batch references;
#define CHECK(x) do { checks++; if (!(x)) { fprintf(stderr,"FAIL %d: %s\n",__LINE__,#x); exit(1); } } while(0)
static volatile uint8_t *map(void *ctx,uint64_t pa,uint64_t size)
{
    (void)ctx;
    return pa<BASE || pa>=SHADOW || size>SHADOW-pa ? NULL : ram+(pa-BASE);
}
static volatile uint8_t *map_shadow(void *ctx,uint64_t pa,uint64_t size)
{
    (void)ctx;
    return pa<SHADOW || pa>=next_shadow || size>next_shadow-pa ? NULL : ram+(pa-BASE);
}
static void publish(void *ctx,uint64_t pa,uint64_t size)
{
    CHECK(map(ctx,pa,size)!=NULL);publications++;
}
static uint64_t get(uint64_t pa)
{
    uint64_t v;memcpy(&v,ram+(pa-BASE),8);return v;
}
static void put(uint64_t pa,uint64_t v) { memcpy(ram+(pa-BASE),&v,8); }
static int read64(void *ctx,uint64_t pa,uint64_t *v)
{
    (void)ctx;
    if (pa<BASE || pa>BASE+SIZE-8) return -1;
    *v=get(pa);return 0;
}
static int write64(void *ctx,uint64_t pa,uint64_t v)
{
    (void)ctx;
    if (pa<BASE || pa>BASE+SIZE-8) return -1;
    put(pa,v);return 0;
}
static uint64_t alloc(void *ctx)
{
    (void)ctx;uint64_t pa=next_shadow;next_shadow+=0x1000;
    CHECK(next_shadow<=BASE+SIZE);return pa;
}
static uint64_t leaf_slot(uint64_t va) { return L3+mmu_index(14,3,va)*8; }
static struct sptm_memory memory;
static struct sptm_update_backend backend;
static void setup(unsigned count)
{
    memset(ram,0,sizeof(ram));publications=0;next_shadow=SHADOW+0x1000;
    memory=(struct sptm_memory){.frame_map_pa=FM,.frame_low=BASE,.frame_high=SHADOW,
        .alloc_low=L2,.alloc_high=SHADOW,.map=map,.publish=publish,.refs=&references};
    backend=(struct sptm_update_backend){.kernel_root=ROOT,.shadow_root=SHADOW,
        .map_shadow=map_shadow};
    for (unsigned i=0;i<(SHADOW-BASE)/0x4000;i++) ram[FM-BASE+i*16+2]=11;
    ram[FM-BASE+2*16+2]=20;ram[FM-BASE+2*16+4]=2;
    ram[FM-BASE+3*16+2]=20;ram[FM-BASE+3*16+4]=3;
    put(ROOT+mmu_index(14,1,VA)*8,L2|3);put(L2+mmu_index(14,2,VA)*8,L3|3);
    struct shadow s={.txsz=17,.root=SHADOW,.alloc=alloc,.read=read64,.write=write64};
    for (unsigned i=0;i<count;i++) {
        uint64_t va=VA+i*0x4000;
        put(leaf_slot(va),OLD);put(LIST+i*24,ROOT);put(LIST+i*24+8,va);
        put(LIST+i*24+16,OLD&~PT_AF);put(SCRATCH+i*8,0xfeedface);
        CHECK(!shadow_map(&s,va&((1UL<<47)-1),DATA,0x4000,
                          OLD&PT_LEAF_ATTRS,OLD&PT_LEAF_UPPER));
        sptm_refs_begin(memory.refs);
        CHECK(sptm_refs_leaf(&memory,L3,va,0,OLD)==SPTM_OK);
        CHECK(sptm_refs_validate(&memory)==SPTM_OK);sptm_refs_commit(&memory);
    }
    publications=0;
}
static enum sptm_result update(uint64_t count,uint64_t options)
{
    return sptm_mac_update_disjoint(&memory,&backend,&workspace,DATA,LIST,
                                     count,options,SCRATCH);
}
static void unchanged(enum sptm_result want,uint64_t count,uint64_t options)
{
    memcpy(before,ram,SIZE);unsigned pubs=publications;
    CHECK(update(count,options)==want);CHECK(!memcmp(before,ram,SIZE));
    CHECK(publications==pubs);
}
static uint64_t shadow_slot(uint64_t va)
{
    va&=(1UL<<47)-1;
    uint64_t table=SHADOW;
    for (unsigned level=0;level<3;level++)
        table=get(table+mmu_index(12,level,va)*8)&PT_OA_MASK;
    return table+mmu_index(12,3,va)*8;
}
static unsigned admission_calls, admission_deny_at;
static int admit_update(void *ctx,uint64_t va,uint64_t pa,uint64_t size,
                        uint64_t low,uint64_t upper)
{
    unsigned index=admission_calls++;
    CHECK(ctx==&memory && size==0x4000 && pa==DATA);
    CHECK(va==((VA+index*0x4000)&((1UL<<47)-1)));
    CHECK(low==((OLD&~PT_AF)&PT_LEAF_ATTRS));
    CHECK(upper==(OLD&PT_LEAF_UPPER));
    return admission_calls!=admission_deny_at;
}
static void test_admission(void)
{
    for(unsigned region=0;region<2;region++)for(unsigned deny=0;deny<3;deny++) {
        setup(2);admission_calls=0;admission_deny_at=deny;
        backend.admit=admit_update;backend.ctx=&memory;
        if(region) {put(LIST,OLD&~PT_AF);put(LIST+8,OLD&~PT_AF);}
        memcpy(before,ram,SIZE);
        enum sptm_result r=region ?
            sptm_mac_update_region(&memory,&backend,&workspace,ROOT,VA,2,LIST,8,SCRATCH):
            update(2,8);
        CHECK(admission_calls==(deny ? deny:2));
        if(deny) {
            CHECK(r==SPTM_SHADOW_FAILED);
            CHECK(!memcmp(before,ram,SIZE) && !publications);
        } else {
            CHECK(r==SPTM_OK && publications);
            for(unsigned i=0;i<2;i++) {
                CHECK(get(leaf_slot(VA+i*0x4000))==(OLD&~PT_AF));
                CHECK(get(shadow_slot(VA+i*0x4000))==(OLD&~PT_AF));
            }
        }
    }
}
/* Options 0x10/0x20 (SH/AttrIndx): pmap_batch_set_cache_attributes' groups
 * (0x130) reach this engine for kernel aliases. memory.clean_frame must run
 * once per changed frame, after preflight and before the first store. */
static unsigned clean_calls,clean_refuse;
static uint64_t clean_last;
static uint8_t clean_snapshot[SIZE];
static int clean_frame(void *ctx,uint64_t pa,uint64_t size)
{
    CHECK(ctx==&memory && size==0x4000);
    CHECK(!memcmp(clean_snapshot,ram,SIZE) && !publications);
    clean_calls++;clean_last=pa;return !clean_refuse;
}
#define WC ((OLD&~SPTM_UPDATE_ATTRS)|(1UL<<2))  /* XNU's WCOMB template: AttrIndx1, SH0 */
#define FRAME_MASK 0x0000ffffffffc000UL
static void attr_setup(unsigned count,uint64_t leaf,uint64_t templ)
{
    setup(count);memory.ctx=&memory;memory.clean_frame=clean_frame;
    clean_calls=clean_refuse=0;clean_last=0;
    for (unsigned i=0;i<count;i++) {
        uint64_t va=VA+i*0x4000;
        put(leaf_slot(va),leaf);put(LIST+i*24+16,templ);
        for (unsigned j=0;j<4;j++) put(shadow_slot(va+j*0x1000),leaf+j*0x1000);
    }
    memcpy(clean_snapshot,ram,SIZE);
}
static void attr_changed(unsigned count,uint64_t leaf,uint64_t next)
{
    for (unsigned i=0;i<count;i++) {
        uint64_t va=VA+i*0x4000;
        CHECK(get(SCRATCH+i*8)==leaf && get(leaf_slot(va))==next);
        for (unsigned j=0;j<4;j++) CHECK(get(shadow_slot(va+j*0x1000))==next+j*0x1000);
    }
}
static void test_attributes(void)
{
    /* WB -> write-combined on 1, 2 and 64 aliases of one frame: one clean,
     * every guest and 4K shadow leaf changes AttrIndx/SH only, old PTEs are
     * returned, counts stay, and 0x100 reports 5. */
    const unsigned counts[]={1,2,64};
    for (unsigned c=0;c<3;c++) {
        unsigned n=counts[c];attr_setup(n,OLD,WC);
        uint8_t metadata[256];memcpy(metadata,ram+(FM-BASE),sizeof(metadata));
        CHECK(update(n,0x130)==SPTM_OK);
        CHECK(clean_calls==1 && clean_last==DATA && publications);
        attr_changed(n,OLD,WC);CHECK(sptm_update_result(&workspace,n,0x130)==5);
        CHECK(!memcmp(metadata,ram+(FM-BASE),sizeof(metadata)));
        /* And back to write-back, outer shareable: the continuation header. */
        for (unsigned i=0;i<n;i++) put(LIST+i*24+16,OLD);
        memcpy(clean_snapshot,ram,SIZE);publications=0;
        CHECK(update(n,0x130)==SPTM_OK && clean_calls==2);
        attr_changed(n,WC,OLD);
    }
    /* SH alone, AttrIndx alone, and together with AF/WIRED/permissions. */
    attr_setup(1,OLD,(OLD&~0x300UL)|0x300UL);
    CHECK(update(1,0x10)==SPTM_OK && clean_calls==1);
    attr_changed(1,OLD,(OLD&~0x300UL)|0x300UL);CHECK(!sptm_update_result(&workspace,1,0x10));
    attr_setup(1,OLD,OLD|0x1c);
    CHECK(update(1,0x20)==SPTM_OK && clean_calls==1);attr_changed(1,OLD,OLD|0x1c);
    attr_setup(1,OLD,(WC&~PT_AF)|0x80|(1UL<<58));
    CHECK(update(1,0x13b)==SPTM_OK && clean_calls==1);
    CHECK(get(leaf_slot(VA))==((WC&~PT_AF)|0x80|(1UL<<58)));
    CHECK(get(shadow_slot(VA))==((WC&~PT_AF)|0x80));
    /* The selector copies only what its option names: SH/AttrIndx of a
     * template stay unapplied without 0x10/0x20, so no clean is needed. */
    attr_setup(2,OLD,WC&~PT_AF);
    CHECK(update(2,0x108)==SPTM_OK && !clean_calls);attr_changed(2,OLD,OLD&~PT_AF);
    attr_setup(2,OLD,WC);
    CHECK(update(2,0x110)==SPTM_OK && clean_calls==1);
    attr_changed(2,OLD,OLD&~0x300UL);
    /* Unchanged attributes: nothing to clean, nothing to report. */
    attr_setup(2,OLD,OLD);
    CHECK(update(2,0x130)==SPTM_OK && !clean_calls);
    attr_changed(2,OLD,OLD);CHECK(!sptm_update_result(&workspace,2,0x130));
    /* Refusals change nothing: no clean hook, a failed clean, nG and bits
     * outside the engine's set (0x40, 0x200 is stripped by MULTIPAGE only). */
    attr_setup(2,OLD,WC);memory.clean_frame=0;unchanged(SPTM_UNSUPPORTED_OPTIONS,2,0x130);
    attr_setup(2,OLD,WC);clean_refuse=1;unchanged(SPTM_MEMORY_UNAVAILABLE,2,0x130);
    CHECK(clean_calls==1);
    const uint64_t refused[]={0x134,0x170,0x330,0x100,0x1130};
    for (unsigned i=0;i<5;i++) {
        attr_setup(2,OLD,WC);unchanged(SPTM_UNSUPPORTED_OPTIONS,2,refused[i]);
        CHECK(!clean_calls);
    }
    /* A late bad record keeps the earlier changed record and its clean away. */
    attr_setup(2,OLD,WC);put(LIST+24+16,WC^PT_AP);
    unchanged(SPTM_UNSUPPORTED_OPTIONS,2,0x132);CHECK(!clean_calls);
    /* ...fdea0: leaving posted AttrIndx 5/7 clears the deferral (result 0);
     * staying posted, or entering it, keeps result 5. */
    const struct {uint64_t from,to,result;} posted[]={
        {OLD|0x14,WC,0},{OLD|0x14,OLD|0x1c,5},{OLD|0x1c,OLD|0x14,5},{OLD|0x1c,OLD|0x18,0},
        {OLD,OLD|0x14,5},{OLD|0x10,OLD,5}};
    for (unsigned i=0;i<6;i++) {
        attr_setup(2,posted[i].from,posted[i].to);put(LIST+24+16,posted[i].from);
        memcpy(clean_snapshot,ram,SIZE);
        CHECK(update(2,0x130)==SPTM_OK && clean_calls==1);
        CHECK(sptm_update_result(&workspace,2,0x130)==posted[i].result);
        CHECK(get(leaf_slot(VA))==posted[i].to && get(leaf_slot(VA+0x4000))==posted[i].from);
    }
    /* UPDATE_REGION: one clean per distinct frame; an unmanaged frame's
     * attributes are refused (EL2 maintains only managed frames). */
    const uint64_t other=DATA+0x4000,other_leaf=(OLD&~FRAME_MASK)|other;
    attr_setup(3,OLD,0);
    put(leaf_slot(VA+0x4000),other_leaf);
    for (unsigned j=0;j<4;j++) put(shadow_slot(VA+0x4000+j*0x1000),other_leaf+j*0x1000);
    for (unsigned i=0;i<3;i++) put(LIST+i*8,i==1 ? (other_leaf&~SPTM_UPDATE_ATTRS)|4 : WC);
    memcpy(clean_snapshot,ram,SIZE);
    CHECK(sptm_mac_update_region(&memory,&backend,&workspace,ROOT,VA,3,LIST,0x120,SCRATCH)==SPTM_OK);
    CHECK(clean_calls==2 && clean_last==other);
    CHECK(get(leaf_slot(VA))==((OLD&~0x1cUL)|4) && get(leaf_slot(VA+0x8000))==((OLD&~0x1cUL)|4));
    CHECK(get(leaf_slot(VA+0x4000))==((other_leaf&~0x1cUL)|4));
    CHECK(get(shadow_slot(VA+0x4000+0x3000))==((other_leaf&~0x1cUL)|4)+0x3000);
    CHECK(sptm_update_result(&workspace,3,0x120)==5);
    const uint64_t unmanaged=(OLD&~FRAME_MASK)|FM;
    attr_setup(1,unmanaged,unmanaged|4);put(LIST,unmanaged|4);
    memcpy(before,ram,SIZE);
    CHECK(sptm_mac_update_region(&memory,&backend,&workspace,ROOT,VA,1,LIST,0x20,SCRATCH)==
          SPTM_UNSUPPORTED_OPTIONS);
    CHECK(!memcmp(before,ram,SIZE) && !publications && !clean_calls);
    /* The kernel prepare used by mixed transactions applies the same rule. */
    attr_setup(1,OLD,WC);struct sptm_update_entry e;
    CHECK(sptm_kernel_update_prepare(&memory,&backend,DATA,VA,WC,0x130,SCRATCH,8,&e)==SPTM_OK);
    CHECK(e.old==OLD && e.next==WC && !clean_calls && !memcmp(clean_snapshot,ram,SIZE));
    memory.clean_frame=0;
    CHECK(sptm_kernel_update_prepare(&memory,&backend,DATA,VA,WC,0x130,SCRATCH,8,&e)==
          SPTM_UNSUPPORTED_OPTIONS);
    CHECK(sptm_kernel_update_prepare(&memory,&backend,DATA,VA,WC,0x134,SCRATCH,8,&e)==
          SPTM_UNSUPPORTED_OPTIONS);
}
int main(int argc,char **argv)
{
    if(argc==5 && !strcmp(argv[1],"--pte")) {
        uint64_t next=0;
        unsigned result=sptm_nx_update_pte(strtoull(argv[2],0,16),strtoull(argv[3],0,16),
            strtoull(argv[4],0,16),&next,0);
        printf("%u %016llx\n",result,(unsigned long long)next);return 0;
    }
    /* A full-size list of distinct aliases exercises every result slot and
     * all 256 hardware leaves. Frame metadata/counts must stay unchanged. */
    setup(64);uint8_t metadata[256];memcpy(metadata,ram+(FM-BASE),sizeof(metadata));
    CHECK(update(64,0x10a)==SPTM_OK);
    CHECK(!memcmp(metadata,ram+(FM-BASE),sizeof(metadata)));
    for (unsigned i=0;i<64;i++) {
        uint64_t va=VA+i*0x4000;
        CHECK(get(SCRATCH+i*8)==OLD);CHECK(get(leaf_slot(va))==(OLD&~PT_AF));
        for (unsigned j=0;j<4;j++) {
            struct mmu_leaf g,s;
            struct mmu_config gc={.granule_shift=14,.txsz=17,.root=ROOT};
            struct mmu_config sc={.granule_shift=12,.txsz=17,.root=SHADOW};
            CHECK(!mmu_walk(&gc,va+j*0x1000,read64,NULL,&g));
            CHECK(!mmu_walk(&sc,va+j*0x1000,read64,NULL,&s));
            CHECK(g.valid && s.valid && g.pa==s.pa);
            CHECK(!(g.descriptor&PT_AF) && !(s.descriptor&PT_AF));
            CHECK((s.descriptor&(PT_LEAF_ATTRS|PT_LEAF_UPPER))==
                  (g.descriptor&(PT_LEAF_ATTRS|PT_LEAF_UPPER)));
        }
    }
    /* Clearing AF is one-way without option 0x800; a template cannot raise it.
     * Wired is guest software metadata and must not leak into shadow entries. */
    put(LIST+16,OLD|(1UL<<58));CHECK(update(1,9)==SPTM_OK);
    CHECK(get(SCRATCH)==(OLD&~PT_AF));
    CHECK(get(leaf_slot(VA))==((OLD&~PT_AF)|(1UL<<58)));
    CHECK(!(get(shadow_slot(VA))&((1UL<<58)|PT_AF)));
    setup(2);put(LIST+24+16,(OLD&~PT_AF)^PT_AP);
    unchanged(SPTM_UNSUPPORTED_OPTIONS,2,0x10a); /* late failure is atomic */
    setup(2);put(shadow_slot(VA+0x4000+0x3000),OLD^PT_UXN);
    unchanged(SPTM_SHADOW_FAILED,2,0x10a);
    setup(2);put(LIST+24+8,VA);unchanged(SPTM_BAD_ADDRESS,2,8);
    setup(2);put(LIST+24,ROOT+0x4000);unchanged(SPTM_BAD_ADDRESS,2,8);
    setup(2);put(LIST+24+8,VA+1);unchanged(SPTM_BAD_ADDRESS,2,8);
    setup(2);put(LIST+24+8,0x1000);unchanged(SPTM_BAD_ADDRESS,2,8);
    setup(1);put(L2+mmu_index(14,2,VA)*8,ROOT|3);
    unchanged(SPTM_BAD_TABLE,1,8);
    setup(1);put(ROOT+mmu_index(14,1,VA)*8,(BASE+SIZE)|3);
    unchanged(SPTM_MEMORY_UNAVAILABLE,1,8);
    setup(1);ram[FM-BASE+((DATA-BASE)>>14)*16+2]=20;
    unchanged(SPTM_TYPE_MISMATCH,1,8);
    for (unsigned bit=0;bit<64;bit++) if (!((1UL<<bit)&SPTM_UPDATE_OPTIONS)) {
        setup(1);unchanged(SPTM_UNSUPPORTED_OPTIONS,1,8|(1UL<<bit));
    }
    setup(1);unchanged(SPTM_UNSUPPORTED_OPTIONS,1,0);
    unchanged(SPTM_BAD_ADDRESS,0,8);unchanged(SPTM_BAD_ADDRESS,65,8);
    /* Stale PFN, invalid leaves, and a hole preserve exact old-PTE output. */
    const uint64_t skipped[]={OLD+0x4000,0,0xc000000000000080UL};
    for (unsigned i=0;i<3;i++) {
        setup(1);put(leaf_slot(VA),skipped[i]);CHECK(update(1,0x10a)==SPTM_OK);
        CHECK(get(SCRATCH)==skipped[i]);CHECK(get(leaf_slot(VA))==skipped[i]);
        CHECK(get(shadow_slot(VA))==OLD);
    }
    setup(1);put(ROOT+mmu_index(14,1,VA)*8,0);
    CHECK(update(1,8)==SPTM_OK);CHECK(!get(SCRATCH));
    /* Return buffers must not corrupt the active walk or the descriptor list. */
    const uint64_t bad_scratch[]={LIST,L3,ROOT,FM,UINT64_MAX-7};
    for (unsigned i=0;i<5;i++) {
        setup(1);memcpy(before,ram,SIZE);
        CHECK(sptm_mac_update_disjoint(&memory,&backend,&workspace,DATA,LIST,1,8,
                                      bad_scratch[i])!=SPTM_OK);
        CHECK(!memcmp(before,ram,SIZE));CHECK(!publications);
    }
    /* MAP -> read-only UPDATE_REGION -> UNMAP uses the same reference state.
     * Two aliases of a restricted frame must change together; leaving an RW
     * alias while creating RO references is rejected without partial writes. */
    setup(2);ram[FM-BASE+6*16+2]=35;
    put(LIST,0x0060000000000080UL);put(LIST+8,0x0060000000000080UL);
    memcpy(before,ram,SIZE);
    CHECK(sptm_mac_update_region(&memory,&backend,&workspace,ROOT,VA,1,LIST,2,SCRATCH)==SPTM_FRAME_BUSY);
    CHECK(!memcmp(before,ram,SIZE));CHECK(!publications);
    CHECK(sptm_mac_update_region(&memory,&backend,&workspace,ROOT,VA,2,LIST,2,SCRATCH)==SPTM_OK);
    CHECK(get(FM+6*16+8)==2); /* low u32 RO=2, high u32 other=0 */
    CHECK((get(FM+3*16+8)&0xffff)==2);
    for (unsigned i=0;i<2;i++) {
        CHECK(get(SCRATCH+i*8)==OLD);
        CHECK(get(leaf_slot(VA+i*0x4000))==(OLD|PT_AP&0x80));
        for (unsigned j=0;j<4;j++) CHECK((get(shadow_slot(VA+i*0x4000+j*0x1000))&PT_AP)==0x80);
    }
    struct shadow s={.txsz=17,.root=SHADOW,.alloc=alloc,.read=read64,.write=write64};
    CHECK(sptm_mac_unmap_region(&memory,&s,ROOT,VA,2,0,SCRATCH)==SPTM_OK);
    CHECK(!get(FM+6*16+8));CHECK(!(get(FM+3*16+8)&0xffff));
    CHECK(get(SCRATCH)==(OLD|0x80));CHECK(!get(leaf_slot(VA)));
    /* Same-frame replacements have zero net deltas; malformed counts cannot
     * wrap, and no operation publishes an unvalidated counter plan. */
    setup(1);put(FM+6*16+8,0);memcpy(before,ram,SIZE);
    sptm_refs_begin(memory.refs);CHECK(sptm_refs_leaf(&memory,L3,VA,OLD,OLD|0x80)==SPTM_BAD_REFERENCE);
    CHECK(sptm_refs_validate(&memory)==SPTM_BAD_REFERENCE);CHECK(!memcmp(before,ram,SIZE));
    setup(1);put(FM+6*16+8,0x7fffffff00000000UL);
    sptm_refs_begin(memory.refs);CHECK(sptm_refs_leaf(&memory,L3,VA,0,OLD)==SPTM_OK);
    CHECK(sptm_refs_validate(&memory)==SPTM_BAD_REFERENCE);
    setup(1);put(FM+3*16+8,2048);
    sptm_refs_begin(memory.refs);CHECK(sptm_refs_leaf(&memory,L3,VA,0,OLD)==SPTM_OK);
    CHECK(sptm_refs_validate(&memory)==SPTM_BAD_REFERENCE);
    setup(1);memory.aperture_va=VA;memory.aperture_size=0x4000;
    sptm_refs_begin(memory.refs);CHECK(sptm_refs_leaf(&memory,L3,VA,0,OLD)==SPTM_OK);
    CHECK(references.count==0);CHECK(sptm_refs_validate(&memory)==SPTM_OK);
    setup(2);put(LIST,0x0060000000000080UL);put(LIST+8,0x0040000000000080UL);
    memcpy(before,ram,SIZE);
    CHECK(sptm_mac_update_region(&memory,&backend,&workspace,ROOT,VA,2,LIST,2,SCRATCH)==SPTM_UNSUPPORTED_OPTIONS);
    CHECK(!memcmp(before,ram,SIZE));CHECK(!publications);
    /* Captured kernel RW -> RO+history on one or 64 aliases. The history
     * stays in source only; reference category remains other, not RO. */
    for(unsigned count=1;count<=64;count+=63) {
        setup(count);
        uint64_t history=1UL<<59,ro=OLD|0x80|history;
        for(unsigned i=0;i<count;i++)put(LIST+i*24+16,ro);
        CHECK(update(count,0xa)==SPTM_OK);
        CHECK(!sptm_update_result(&workspace,count,0xa));
        CHECK(get(FM+6*16+8)==((uint64_t)count<<32));
        for(unsigned i=0;i<count;i++) {
            CHECK(get(SCRATCH+i*8)==OLD);CHECK(get(leaf_slot(VA+i*0x4000))==ro);
            for(unsigned j=0;j<4;j++)CHECK(get(shadow_slot(VA+i*0x4000+j*0x1000))==
                ((OLD+0x1000*j)|0x80));
            put(LIST+i*24+16,OLD);
        }
        CHECK(update(count,0x102)==SPTM_OK); /* no fault option: RO stays */
        CHECK(!sptm_update_result(&workspace,count,0x102));
        CHECK(get(leaf_slot(VA))==ro);
        CHECK(update(count,0xd02)==SPTM_OK);
        CHECK(sptm_update_result(&workspace,count,0xd02)==5);
        CHECK(get(FM+6*16+8)==((uint64_t)count<<32));
        for(unsigned i=0;i<count;i++) {
            CHECK(get(SCRATCH+i*8)==ro);CHECK(get(leaf_slot(VA+i*0x4000))==OLD);
            for(unsigned j=0;j<4;j++)CHECK(get(shadow_slot(VA+i*0x4000+j*0x1000))==OLD+0x1000*j);
            put(LIST+i*24+16,ro);
        }
        CHECK(update(count,0x102)==SPTM_OK);
        CHECK(sptm_update_result(&workspace,count,0x102)==5);
        for(unsigned i=0;i<count;i++)put(LIST+i*24+16,OLD|0x80);
        CHECK(update(count,0x102)==SPTM_OK); /* clear history, same hardware */
        CHECK(!sptm_update_result(&workspace,count,0x102));
        CHECK(get(FM+6*16+8)==count);
        CHECK(sptm_mac_unmap_region(&memory,&s,ROOT,VA,count,0,SCRATCH)==SPTM_OK);
        CHECK(!get(FM+6*16+8));
    }
    setup(1);put(LIST+16,OLD&~PT_AF);CHECK(update(1,8)==SPTM_OK);
    put(LIST+16,OLD);CHECK(update(1,0xd08)==SPTM_OK);
    CHECK(get(leaf_slot(VA))==OLD);CHECK(get(shadow_slot(VA))==OLD);
    CHECK(sptm_update_result(&workspace,1,0xd08)==5);
    put(LIST+16,OLD|(1UL<<58));CHECK(update(1,0x101)==SPTM_OK);
    CHECK(!sptm_update_result(&workspace,1,0x101));
    CHECK(!(get(shadow_slot(VA))&(3UL<<58)));
    setup(2);put(LIST+16,OLD|0x80|(1UL<<59));
    put(LIST+24+16,OLD^PT_UXN);unchanged(SPTM_UNSUPPORTED_OPTIONS,2,0xa);
    setup(1);ram[FM-BASE+6*16+2]=10;unchanged(SPTM_TYPE_MISMATCH,1,0xa);
    test_admission();
    test_attributes();
    printf("PASS: %u SPTM update/reference checks\n",checks);
}

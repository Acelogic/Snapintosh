/* SPDX-License-Identifier: MIT */
/* XNU-consumer model for user MAP_PAGE / UNMAP_REGION / table teardown.
 *
 * XNU keeps its own per-page PV list and trusts the monitor for two facts:
 *
 *  - MAP_PAGE status (kernelcache ba61544): 0 = new mapping, so
 *    pmap_enter_pv (ba77af8) appends the returned PTE pointer; 1 = the slot
 *    already held a valid leaf, no PV change; 6 = different PA, remove+retry.
 *  - UNMAP_REGION previous PTEs: each valid one removes ONE PV entry whose
 *    pointer equals that slot (pmap_remove_range_options -> pmap_remove_pv).
 *
 * After the leaf table's SPTM mapping count reaches zero XNU condemns,
 * unmaps and frees it (pmap_remove_options_internal -> pmap_tte_deallocate),
 * which clears the table page's PV head. A later PV walk of a data page
 * (arm_force_fast_fault_with_flush_range, ba69c18) resolves each foreign
 * PTE pointer's table through that PV head; a NULL head is the data abort at
 * ba6a2cc with FAR 0x64c0000000000000 seen in
 * bootfb-sep-bodies-2400s-20260924.
 *
 * The invariants checked here are therefore: every PV pointer lies in a live
 * page table and points at a valid leaf for the page, and the PV count equals
 * the monitor's data-frame reference count. */
#include <stdio.h>
#include <string.h>
#include "sptm-user.h"
#include "sptm-refs.h"
#include "mmu.h"
#ifndef SPTM_USER_MAP_VALID /* lets the model run against older monitors */
#define SPTM_USER_MAP_VALID 1u
#endif
#define BASE 0x90000000UL
#define SIZE 0x40000UL
#define FM (BASE+0x4000)
#define ROOT (BASE+0x8000)
#define L2 (BASE+0xc000)
#define L3A (BASE+0x10000)
#define DATA (BASE+0x14000)
#define L3B (BASE+0x18000)
#define OTHER (BASE+0x1c000)
#define APERTURE 0xfffffe0100000000UL
#define VA_A 0x4000UL
#define VA_B (0x2000000UL+0x8000UL)
#define RO 0x0060000000000ec3UL
#define RW 0x0060000000000e43UL
static unsigned checks,failures;
static uint8_t ram[SIZE];
static struct sptm_ref_batch refs;
static void check(int ok,const char *what)
{ checks++;if(!ok){failures++;printf("FAIL: %s\n",what);} }
static volatile uint8_t *map(void *ctx,uint64_t pa,uint64_t n)
{
    (void)ctx;
    if(pa<BASE || pa>=BASE+SIZE || n>BASE+SIZE-pa)return NULL;
    return ram+(pa-BASE);
}
static void publish(void *ctx,uint64_t pa,uint64_t n){(void)ctx;(void)pa;(void)n;}
static uint64_t get(uint64_t pa,unsigned n)
{ uint64_t v=0;for(unsigned i=0;i<n;i++)v|=(uint64_t)ram[pa-BASE+i]<<(8*i);return v; }
static uint64_t meta(uint64_t pa){return FM+((pa-BASE)>>14)*16;}
static uint64_t slot_of(uint64_t table,uint64_t va){return table+8*mmu_index(14,3,va);}
static struct sptm_user_backend backend={.aperture={BASE,APERTURE,SIZE}};
static struct sptm_memory m;

/* XNU's view: the PV list of DATA. pvva holds the pointer XNU recorded (the
 * one MAP_PAGE returned); pv the slot's physical address, for the walk. */
static uint64_t pv[16],pvva[16];static unsigned npv;
/* SLIDE_REGION moved L3A's frame: XNU's phystokv (the published table) now
 * names it at MOVED_VA, while the linear alias stays mapped. An entry outside
 * the moved window (an unslid remainder at its bootstrap VA) must not count. */
#define MOVED_VA 0xfffffe030c058000UL
static int moved;
static const struct sptm_slide_region slid[2]={
    {MOVED_VA,L3A,1},{0xfffffe000ca78000UL,L3B,1}};
static uint64_t phystokv(uint64_t pa)
{ return moved && pa>=L3A && pa<L3A+0x4000 ? MOVED_VA+(pa-L3A) : APERTURE+(pa-BASE); }
static int table_live[2];
static const uint64_t tables[2]={L3A,L3B};

static void reset(void)
{
    memset(ram,0,SIZE);npv=0;table_live[0]=table_live[1]=1;
    backend.moved=(struct sptm_moved){moved ? slid : 0,moved ? 2 : 0,
        MOVED_VA&~0xffffffUL,(MOVED_VA&~0xffffffUL)+0x4000000};
    for(unsigned i=0;i<SIZE/0x4000;i++)ram[FM-BASE+i*16+2]=11;
    m=(struct sptm_memory){.frame_map_pa=FM,.frame_low=BASE,.frame_high=BASE+SIZE,
        .alloc_low=ROOT,.alloc_high=BASE+SIZE,.map=map,.publish=publish,.refs=&refs};
    check(!sptm_mac_retype(&m,ROOT,11,18,(2UL<<32)|(2UL<<16)),"root");
    check(!sptm_mac_retype(&m,L2,11,20,2),"L2");
    check(!sptm_mac_retype(&m,L3A,11,20,3) && !sptm_mac_retype(&m,L3B,11,20,3),"two L3s");
    check(!sptm_mac_map_user_table(&m,ROOT,VA_A,1,L2|3),"link L2");
    check(!sptm_mac_map_user_table(&m,ROOT,VA_A,2,L3A|3),"link L3A");
    check(!sptm_mac_map_user_table(&m,ROOT,VA_B,2,L3B|3),"link L3B");
}
/* pmap_enter_options_internal's consumer of the MAP_PAGE status. */
static uint64_t xnu_enter(uint64_t va,uint64_t pte)
{
    uint64_t result=99;
    enum sptm_result r=sptm_mac_map_user_page(&m,&backend,ROOT,va,pte,0,BASE,&result);
    check(r==SPTM_OK,"MAP_PAGE accepted");
    if(r)return 99;
    uint64_t ptep=get(BASE+8,8),slot=slot_of(tables[va>=0x2000000UL],va);
    check(ptep==phystokv(slot),"MAP_PAGE returns the pointer XNU's phystokv computes");
    if(result==0 && npv<16) {pvva[npv]=ptep;pv[npv++]=slot;}   /* pmap_enter_pv */
    return result;
}
static unsigned table_index(uint64_t va){return va>=0x2000000UL;}
/* pmap_remove_options_internal for one page: UNMAP_REGION, PV removal by
 * the reported previous PTE, then leaf-table teardown when the SPTM count
 * reaches zero (condemn, UNMAP_TABLE, retype back to DEFAULT). */
static void xnu_remove(uint64_t va)
{
    unsigned t=table_index(va);uint64_t table=tables[t];
    check(!sptm_mac_unmap_user_region(&m,&backend,ROOT,va,1,1,BASE),"UNMAP_REGION");
    uint64_t prev=get(BASE,8);
    if((prev&3)==3 && ((prev&0x0000ffffffffc000UL)==DATA)) {
        /* pmap_remove_pv matches by pointer, recomputed with phystokv. */
        for(unsigned i=0;i<npv;i++)if(pvva[i]==phystokv(slot_of(table,va))) {
            memmove(pv+i,pv+i+1,(npv-i-1)*sizeof pv[0]);
            memmove(pvva+i,pvva+i+1,(npv-i-1)*sizeof pvva[0]);npv--;break;
        }
    }
    if(!get(meta(table)+8,2)) {
        uint64_t result=99;
        check(!sptm_mac_condemn_user_table(&m,&backend,ROOT,va&~0x1ffffffUL,1,&result) && !result,"condemn");
        check(!sptm_mac_unmap_user_table(&m,&backend,ROOT,va&~0x1ffffffUL,2),"UNMAP_TABLE");
        check(!sptm_mac_retype(&m,table,20,11,0),"free leaf table (PV head of table page cleared)");
        table_live[t]=0;
    }
}
/* arm_force_fast_fault_with_flush_range: every foreign PV pointer must still
 * resolve to a live page table (non-NULL PVH) holding a valid leaf for DATA. */
static void xnu_pv_walk(uint64_t current,const char *what)
{
    for(unsigned i=0;i<npv;i++) {
        if(pv[i]==current)continue;              /* flush_range fast path */
        uint64_t table=pv[i]&~0x3fffUL;
        int live=get(meta(table)+2,1)==20 && get(meta(table)+4,1)==3;
        check(live,what);
        if(live)check((get(pv[i],8)&3)==3 && (get(pv[i],8)&0x0000ffffffffc000UL)==DATA,
                      "PV pointer names a valid leaf of this page");
    }
}
static void pv_matches_refs(const char *what)
{ check(npv==get(meta(DATA)+8,4)+get(meta(DATA)+12,4),what); }

static void scenarios(void)
{
    uint64_t r;
    /* 1. Write fault after a read-only mapping: same PA, new permission. */
    reset();
    check(xnu_enter(VA_A,DATA|RO)==0,"fresh insert returns SUCCESS");
    pv_matches_refs("one mapping, one PV entry");
    r=xnu_enter(VA_A,DATA|RW);
    check(r==SPTM_USER_MAP_VALID,"same-PA permission change returns MAP_VALID (SPTM 270f95d4)");
    check(get(slot_of(L3A,VA_A),8)==(DATA|RW),"permission change is published");
    check(npv==1,"no duplicate PV entry for the upgraded slot");
    pv_matches_refs("PV count equals SPTM data references after upgrade");
    r=xnu_enter(VA_A,DATA|RW);
    check(r==SPTM_USER_MAP_VALID && npv==1,"identical request returns MAP_VALID");
    r=xnu_enter(VA_A,DATA|RO);
    check(r==SPTM_USER_MAP_VALID && npv==1,"downgrade of a valid leaf returns MAP_VALID");

    /* 2. Second mapping of the page stays alive (other VA, other table). */
    check(xnu_enter(VA_B,DATA|RO)==0 && npv==2,"second mapping is a new PV entry");
    pv_matches_refs("two mappings, two PV entries");

    /* 3. Remove the first mapping; its table empties and is freed. */
    xnu_remove(VA_A);
    check(!table_live[0],"emptied leaf table was freed");
    check(npv==1 && pv[0]==slot_of(L3B,VA_B),"only the surviving mapping remains in the PV list");
    pv_matches_refs("PV count equals SPTM data references after teardown");

    /* 4. madvise(MADV_FREE_REUSABLE) over VA_B walks DATA's PV list. */
    xnu_pv_walk(slot_of(L3B,VA_B),"no PV pointer into a freed table (panic: FAR 0x64c0000000000000)");
    /* The same walk from a range that does not cover VA_B. */
    xnu_pv_walk(0,"full PV walk sees only live tables");

    /* 5. Different-PA request still conflicts without mutation. */
    r=xnu_enter(VA_B,OTHER|RO);
    check(r==SPTM_USER_MAP_CONFLICT && npv==1 && get(slot_of(L3B,VA_B),8)==(DATA|RO),
          "different PA returns 6 and leaves the leaf");

    /* 6. Repeated fault/upgrade/remove cycles never accumulate PV entries. */
    reset();
    check(xnu_enter(VA_B,DATA|RO)==0,"anchor mapping");
    for(unsigned n=0;n<32;n++) {
        if(!table_live[0]) {
            check(!sptm_mac_retype(&m,L3A,11,20,3),"reallocate L3A");
            check(!sptm_mac_map_user_table(&m,ROOT,VA_A,2,L3A|3),"relink L3A");
            table_live[0]=1;
        }
        check(xnu_enter(VA_A,DATA|RO)==0,"cycle insert");
        check(xnu_enter(VA_A,DATA|RW)==SPTM_USER_MAP_VALID,"cycle upgrade");
        xnu_remove(VA_A);
        xnu_pv_walk(slot_of(L3B,VA_B),"cycle leaves no stale PV pointer");
        pv_matches_refs("cycle keeps PV count equal to SPTM references");
    }
    check(npv==1,"after 32 cycles only the anchor mapping is tracked");
}
int main(void)
{
    scenarios();
    moved=1;scenarios();   /* the same lifecycle with L3A on a slid frame */
    /* The pointer helper itself: precedence, window filter and bounds. */
    struct sptm_aperture a={BASE,APERTURE,SIZE};
    struct sptm_moved mv={slid,2,MOVED_VA&~0xffffffUL,(MOVED_VA&~0xffffffUL)+0x4000000};
    check(sptm_published_pointer(&a,&mv,L3A+0x10,8)==MOVED_VA+0x10,"moved frame uses its slid alias");
    check(sptm_published_pointer(&a,&mv,L3A+0x3ff8,16)==0,"a pointer may not cross the moved span");
    check(sptm_published_pointer(&a,&mv,L3B,8)==APERTURE+(L3B-BASE),"an unslid remainder keeps the linear alias");
    check(sptm_published_pointer(&a,&mv,DATA,8)==APERTURE+(DATA-BASE),"ordinary RAM keeps the linear alias");
    check(sptm_published_pointer(&a,0,L3A,8)==APERTURE+(L3A-BASE),"no moved list is the linear aperture");
    mv.count=65;
    check(sptm_published_pointer(&a,&mv,L3A,8)==APERTURE+(L3A-BASE),"an oversized moved list is ignored");
    printf("XNU PV-list consumer model: %u checks, %u failures\n",checks,failures);
    return failures!=0;
}

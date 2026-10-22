/* SPDX-License-Identifier: MIT */
/* Monitor PV self-check counters (struct sptm_pv_audit).
 *
 *  - moved_pointers: MAP_PAGE returned a PTE pointer through a SLIDE_REGION
 *    alias, not the linear aperture (the ~21 min pmap panic's mechanism).
 *  - remaps: a committed valid -> valid leaf change with a different PA.
 *    Apple refuses these in MAP_PAGE (CONFLICT 6) so XNU removes the old PV
 *    entry first; an accepted one would leave that entry behind.
 *  - duplicate_records: UPDATE/UNMAP_DISJOINT records repeating an earlier
 *    record's (root, VA) in one call. Apple accepts and applies them in order
 *    (tools/replay-disjoint-duplicates.py); they are counted, not refused.
 * The counters observe; every result below is the one the monitor gave
 * before they existed (a NULL audit runs the same paths). */
#include <stdio.h>
#include <string.h>
#include "sptm-user.h"
#include "sptm-refs.h"
#include "mmu.h"
#define BASE 0x90000000UL
#define SIZE 0x40000UL
#define FM (BASE+0x4000)
#define ROOT (BASE+0x8000)
#define L2 (BASE+0xc000)
#define L3A (BASE+0x10000)
#define DATA (BASE+0x14000)
#define L3B (BASE+0x18000)
#define OTHER (BASE+0x1c000)
#define LIST (BASE+0x20000)
#define KROOT (BASE+0x24000)
#define SHADOW (BASE+0x28000)
#define APERTURE 0xfffffe0100000000UL
#define MOVED_VA 0xfffffe030c058000UL
#define VA_A 0x4000UL
#define VA_B (0x2000000UL+0x8000UL)
#define KVA 0xffff800000004000UL
#define RO 0x0060000000000ec3UL
#define RW 0x0060000000000e43UL
static unsigned checks,failures;
static uint8_t ram[SIZE];
static struct sptm_ref_batch refs;
static struct sptm_pv_audit audit;
static void check(int ok,const char *what)
{ checks++;if(!ok){failures++;printf("FAIL: %s\n",what);} }
static volatile uint8_t *map(void *ctx,uint64_t pa,uint64_t n)
{
    (void)ctx;
    if(pa<BASE || pa>=BASE+SIZE || n>BASE+SIZE-pa)return NULL;
    return ram+(pa-BASE);
}
static void publish(void *ctx,uint64_t pa,uint64_t n){(void)ctx;(void)pa;(void)n;}
static uint64_t get(uint64_t pa){uint64_t v=0;for(unsigned i=0;i<8;i++)v|=(uint64_t)ram[pa-BASE+i]<<(8*i);return v;}
static void put(uint64_t pa,uint64_t v){for(unsigned i=0;i<8;i++)ram[pa-BASE+i]=(uint8_t)(v>>(8*i));}
static uint64_t slot_of(uint64_t table,uint64_t va){return table+8*mmu_index(14,3,va);}
static const struct sptm_slide_region slid[2]={{MOVED_VA,L3A,1},{0xfffffe000ca78000UL,L3B,1}};
static struct sptm_user_backend backend={.aperture={BASE,APERTURE,SIZE}};
static struct sptm_memory m;
static int resolve(void *ctx,uint64_t root,struct sptm_user_backend *out)
{(void)ctx;if(root!=ROOT)return 0;*out=backend;return 1;}

static void reset(int moved,int audited)
{
    memset(ram,0,SIZE);memset(&audit,0,sizeof audit);
    backend.moved=(struct sptm_moved){moved ? slid : 0,moved ? 2 : 0,
        MOVED_VA&~0xffffffUL,(MOVED_VA&~0xffffffUL)+0x4000000};
    for(unsigned i=0;i<SIZE/0x4000;i++)ram[FM-BASE+i*16+2]=11;
    m=(struct sptm_memory){.frame_map_pa=FM,.frame_low=BASE,.frame_high=BASE+SIZE,
        .alloc_low=ROOT,.alloc_high=BASE+SIZE,.map=map,.publish=publish,.refs=&refs,
        .audit=audited ? &audit : 0};
    check(!sptm_mac_retype(&m,ROOT,11,18,(2UL<<32)|(2UL<<16)),"root");
    check(!sptm_mac_retype(&m,L2,11,20,2),"L2");
    check(!sptm_mac_retype(&m,L3A,11,20,3) && !sptm_mac_retype(&m,L3B,11,20,3),"two L3s");
    check(!sptm_mac_map_user_table(&m,ROOT,VA_A,1,L2|3),"link L2");
    check(!sptm_mac_map_user_table(&m,ROOT,VA_A,2,L3A|3),"link L3A");
    check(!sptm_mac_map_user_table(&m,ROOT,VA_B,2,L3B|3),"link L3B");
}
static uint64_t enter(uint64_t va,uint64_t pte,uint64_t options)
{
    uint64_t result=99;
    check(!sptm_mac_map_user_page(&m,&backend,ROOT,va,pte,options,BASE,&result),"MAP_PAGE");
    return result;
}
static void records(unsigned n,const uint64_t (*r)[3])
{ for(unsigned i=0;i<n;i++)for(unsigned w=0;w<3;w++)put(LIST+24*i+8*w,r[i][w]); }

static void moved_pointers(void)
{
    for(int audited=0;audited<2;audited++) {
        reset(1,audited);
        check(enter(VA_A,DATA|RO,0)==0 && get(BASE+8)==MOVED_VA+(slot_of(L3A,VA_A)-L3A),
              "moved table: the slid alias is returned");
        check(audit.moved_pointers==(uint64_t)audited,"a slid pointer is counted once");
        check(enter(VA_A,DATA|RW,0)==1 && audit.moved_pointers==2UL*audited,
              "a replacement on the moved table is returned through it again");
        check(enter(VA_B,DATA|RO,0)==0 && audit.moved_pointers==2UL*audited,
              "the unslid table keeps the linear alias and is not counted");
        check(enter(VA_B,OTHER|RO,0)==SPTM_USER_MAP_CONFLICT && audit.moved_pointers==2UL*audited,
              "a conflict on the unslid table publishes the linear alias");
        check(enter(VA_A,OTHER|RO,0)==SPTM_USER_MAP_CONFLICT && audit.moved_pointers==3UL*audited,
              "a conflict on the moved table still publishes (and counts) its alias");
        check(enter(VA_A,DATA|RW,1)==1 && audit.moved_pointers==3UL*audited,
              "option1 publishes no pointer and counts none");
    }
    reset(0,1);
    check(enter(VA_A,DATA|RO,0)==0 && audit.moved_pointers==0,"no slide state: nothing counted");
}

static void remaps(void)
{
    reset(0,1);
    check(enter(VA_A,DATA|RO,0)==0 && enter(VA_A,DATA|RW,0)==1,"insert then same-PA upgrade");
    check(enter(VA_A,OTHER|RW,0)==SPTM_USER_MAP_CONFLICT,"user MAP_PAGE refuses a different PA");
    check(!audit.remaps && !audit.pending,"no remap on any user MAP_PAGE path");
    /* The kernel MAP_PAGE path (probes/xnuboot.c) accepts a different PA and
     * reaches the counter through the same reference transaction: */
    sptm_refs_begin(&refs);
    check(!sptm_refs_leaf(&m,L3A,VA_A,DATA|RW,OTHER|RW) && !sptm_refs_validate(&m),
          "different-PA transition preflights");
    check(audit.pending==1 && !audit.remaps,"preflight alone is not a remap");
    sptm_refs_commit(&m);
    check(audit.remaps==1 && !audit.pending && audit.remap_va==VA_A &&
          audit.remap_old==(DATA|RW) && audit.remap_next==(OTHER|RW),"commit counts it with its witness");
    sptm_refs_begin(&refs);
    check(!sptm_refs_leaf(&m,L3A,VA_A,OTHER|RW,OTHER|RO),"same-PA permission change");
    check(!sptm_refs_leaf(&m,L3A,VA_A,OTHER|RO,0),"removal");
    check(!sptm_refs_leaf(&m,L3A,VA_A,0,DATA|RO),"fresh insert");
    sptm_refs_commit(&m);
    check(audit.remaps==1,"permission changes, removals and inserts are not remaps");
    /* A 4K-granule user leaf can differ in PA bits 13:12 alone. */
    sptm_refs_begin(&refs);
    check(!sptm_refs_leaf(&m,L3A,VA_A,DATA|RO,(DATA+0x1000)|RO),"4K remap within one frame");
    sptm_refs_commit(&m);
    check(audit.remaps==2 && audit.remap_next==((DATA+0x1000)|RO),"sub-16K remap counted");
    /* A batch refused after preflight is dropped by the dispatcher's reset. */
    sptm_refs_begin(&refs);
    check(!sptm_refs_leaf(&m,L3A,VA_A,DATA|RO,OTHER|RO),"abandoned remap preflight");
    audit.pending=0;                 /* probes/xnuboot.c: at every call entry */
    sptm_refs_begin(&refs);sptm_refs_commit(&m);
    check(audit.remaps==2,"an abandoned batch is never counted");
    reset(0,0);
    sptm_refs_begin(&refs);
    check(!sptm_refs_leaf(&m,L3A,VA_A,0,DATA|RO),"no audit: fresh insert");
    sptm_refs_commit(&m);
}

static void user_duplicates(void)
{
    struct sptm_user_update_state state={0};uint64_t result=99;
    /* The captured duplicate revocation (USER-UPDATE-DISJOINT-20260922). */
    for(int audited=0;audited<2;audited++) {
        reset(0,audited);
        check(enter(VA_A,DATA|RW,0)==0,"RW mapping");
        const uint64_t pair[2][3]={{ROOT,VA_A,DATA|RO},{ROOT,VA_A,DATA|RO}};
        records(2,pair);
        check(!sptm_mac_update_user_disjoint(&m,resolve,0,DATA,LIST,2,2,BASE,&result,&state),
              "identical revocation pair is accepted");
        check(get(BASE)==(DATA|RW) && get(BASE+8)==(DATA|RO) && get(slot_of(L3A,VA_A))==(DATA|RO),
              "old descriptors and the published leaf are unchanged by counting");
        check(audit.duplicate_records==(uint64_t)audited,"one duplicate record");
    }
    check(audit.duplicate_root==ROOT && audit.duplicate_va==VA_A,"duplicate witness");
    const uint64_t distinct[2][3]={{ROOT,VA_A,DATA|RO},{ROOT,VA_B,DATA|RO}};
    records(2,distinct);
    check(!sptm_mac_update_user_disjoint(&m,resolve,0,DATA,LIST,2,2,BASE,&result,&state) &&
          audit.duplicate_records==1,"distinct VAs are not duplicates");
    const uint64_t conflicting[2][3]={{ROOT,VA_A,DATA|RW},{ROOT,VA_A,DATA|RO}};
    records(2,conflicting);
    check(sptm_mac_update_user_disjoint(&m,resolve,0,DATA,LIST,2,2,BASE,&result,&state)!=SPTM_OK,
          "conflicting duplicates stay refused by the monitor");
    check(audit.duplicate_records==2,"...and are counted, naming the stop");

    /* UNMAP_DISJOINT: identical, interleaved and triple records. */
    struct sptm_shared_update_state unmap={0};
    reset(0,1);
    check(enter(VA_A,DATA|RO,0)==0 && enter(VA_B,DATA|RO,0)==0,"two mappings");
    const uint64_t triple[4][3]={{ROOT,VA_A,0},{ROOT,VA_B,0},{ROOT,VA_A,0},{ROOT,VA_A,0}};
    records(4,triple);
    check(!sptm_mac_unmap_user_disjoint(&m,resolve,0,DATA,LIST,4,BASE,&unmap),"unmap with repeats");
    check(get(BASE)==(DATA|RO) && get(BASE+8)==(DATA|RO) && get(BASE+16)==0x80 && get(BASE+24)==0x80,
          "Apple's sequential old values (replay: transient 0x80)");
    check(audit.duplicate_records==2 && audit.duplicate_va==VA_A,"two repeats of VA_A counted");
}

static volatile uint8_t *shadow_map(void *ctx,uint64_t pa,uint64_t n){return map(ctx,pa,n);}
static void kernel_duplicates(void)
{
    reset(0,1);
    struct sptm_update_workspace w;
    struct sptm_update_backend b={.kernel_root=KROOT,.shadow_root=SHADOW,.map_shadow=shadow_map};
    const uint64_t pair[2][3]={{KROOT,KVA,DATA|RO},{KROOT,KVA,DATA|RO}};
    records(2,pair);
    check(!sptm_mac_update_disjoint(&m,&b,&w,DATA,LIST,2,2,BASE),
          "kernel pair with no table is two no-ops");
    check(audit.duplicate_records==1 && audit.duplicate_root==KROOT && audit.duplicate_va==KVA,
          "kernel duplicate counted");
    const uint64_t distinct[2][3]={{KROOT,KVA,DATA|RO},{KROOT,KVA+0x4000,DATA|RO}};
    records(2,distinct);
    check(!sptm_mac_update_disjoint(&m,&b,&w,DATA,LIST,2,2,BASE) && audit.duplicate_records==1,
          "distinct kernel VAs are not duplicates");
}

int main(void)
{
    moved_pointers();
    remaps();
    user_duplicates();
    kernel_duplicates();
    printf("PV self-check counters: %u checks, %u failures\n",checks,failures);
    return failures!=0;
}

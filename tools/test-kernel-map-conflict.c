/* SPDX-License-Identifier: MIT */
/* Kernel-root MAP_PAGE: the old-leaf decision and the PTE pointer, as XNU's
 * kernel pmap consumes them.
 *
 * Apple (tools/replay-kernel-map-conflict.py, SPTM_KERNEL_ROOT_TABLE = 8):
 * a valid leaf of another PA returns 6 at ...f95dc with no CAS, no TLBI and
 * no reference move, and reports the old PTE and slot pointer. XNU's
 * pmap_enter (kernelcache ba615e4) answers 6 with pmap_remove over
 * [VA,VA+16K) (ba615f8 -> ba62ff8), which drops the old page's PV entry by
 * pointer, then retries; status 0 appends a PV entry (ba77af8).
 *
 * The monitor used to replace the leaf and return 0: XNU then had two PV
 * entries naming one slot, and the old page's entry names a slot that now
 * maps the new page.
 *
 * The pointer half: the slot's table lives on a frame SLIDE_REGION moved,
 * so the only pointer XNU can later match is the one its phystokv computes
 * from the published physical-to-virtual table. That path is exercised end
 * to end here: a real sptm_mac_slide_region call, the monitor's moved list
 * (sptm_slide_moved, what xnu_moved returns) and the published table. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "sptm-slide.h"
#include "shadow.h"

#ifndef SPTM_MAC_MAP_CONFLICT
/* Before the fix: probes/xnuboot.c's kernel MAP_PAGE, verbatim in effect.
 * Lets this model run against the older monitor to show the failure. */
#define SPTM_MAC_MAP_CONFLICT 6u
struct sptm_kernel_leaf { uint64_t status, old, pointer; int install; };
static enum sptm_result sptm_mac_kernel_map_leaf(const struct sptm_aperture *a,
    const struct sptm_moved *moved, uint64_t slot_pa, uint64_t old,
    uint64_t requested, struct sptm_kernel_leaf *out)
{
    uint64_t pointer=sptm_published_pointer(a,moved,slot_pa,8);
    if(!pointer)return SPTM_BAD_ADDRESS;
    *out=(struct sptm_kernel_leaf){.old=old,.pointer=pointer,.install=1,
        .status=((old&3)==3 && !((old^requested)&PT_OA_MASK)) ?
            sptm_mac_map_page_status(old,requested) : 0};
    return SPTM_OK;
}
static inline struct sptm_moved sptm_slide_moved(const struct sptm_slide_state *s,
    const struct sptm_slide_config *config)
{ return (struct sptm_moved){s->count ? s->regions : 0,s->count,config->begin,config->end}; }
#endif

#define BASE 0x90000000UL
#define SIZE 0x400000UL
#define META (BASE+0x40000)
#define BOOT (BASE+0x80000)          /* five bootstrap frames SLIDE_REGION moves */
#define PAGE_A (BASE+0x120000)
#define PAGE_B (BASE+0x124000)
#define SHADOW (BASE+0x200000)
#define LINEAR 0xfffffe0100000000UL  /* phystokv of BASE before any slide */
#define BOOT_VA 0xfffffe0001ffc000UL
#define DEST 0xfffffe01fc000000UL
#define KVA_MOVED 0xfffffe0040004000UL   /* L3 table: BOOT+PAGE, slid */
#define KVA_LINEAR 0xfffffe0042008000UL  /* L3 table: ordinary frame */
#define PAGE 0x4000UL
#define VMASK ((1UL<<47)-1)
#define ATTR (PT_AF|PT_SH|PT_AP|PT_CONTIG|PT_UXN)
#define RO 0x0060000000000e83UL
#define RW 0x0060000000000e03UL

static uint8_t ram[SIZE];
static unsigned checks,failures;
static uint64_t next_guest,next_shadow;
static struct sptm_memory memory;
static struct sptm_update_backend backend;
static struct sptm_slide_config config;
static struct sptm_slide_state state;
static struct sptm_aperture aperture={BASE,LINEAR,SHADOW-BASE};
static void check(int ok,const char *what)
{ checks++;if(!ok){failures++;printf("FAIL: %s\n",what);} }
#define REQUIRE(x) do{ if(!(x)){printf("setup failed: %s\n",#x);exit(2);} }while(0)
static uint64_t get(uint64_t pa){uint64_t v;memcpy(&v,ram+(pa-BASE),8);return v;}
static void put(uint64_t pa,uint64_t v){memcpy(ram+(pa-BASE),&v,8);}
static volatile uint8_t *map(void *ctx,uint64_t pa,uint64_t n)
{ (void)ctx;return pa<BASE || pa>=SHADOW || n>SHADOW-pa ? NULL : ram+(pa-BASE); }
static volatile uint8_t *map_shadow(void *ctx,uint64_t pa,uint64_t n)
{ (void)ctx;return pa<SHADOW || pa>=next_shadow || n>next_shadow-pa ? NULL : ram+(pa-BASE); }
static void publish(void *ctx,uint64_t pa,uint64_t n){(void)ctx;(void)pa;(void)n;}
static int read64(void *ctx,uint64_t pa,uint64_t *v)
{ (void)ctx;if(pa<BASE || pa>BASE+SIZE-8)return -1;*v=get(pa);return 0; }
static int write64(void *ctx,uint64_t pa,uint64_t v)
{ (void)ctx;if(pa<BASE || pa>BASE+SIZE-8)return -1;put(pa,v);return 0; }
static uint64_t alloc(void *ctx)
{ (void)ctx;uint64_t pa=next_shadow;next_shadow+=0x1000;REQUIRE(next_shadow<=BASE+SIZE);return pa; }
static uint64_t slot(uint64_t va,unsigned granule,unsigned target,int create)
{
    va&=VMASK;
    uint64_t table=granule==14 ? BASE : SHADOW;
    for(unsigned level=granule==14 ? 1 : 0;level<=target;level++) {
        uint64_t p=table+8UL*mmu_index(granule,level,va);
        if(level==target)return p;
        if(!get(p) && create){put(p,next_guest|3);next_guest+=PAGE;REQUIRE(next_guest<=META);}
        REQUIRE((get(p)&3)==3);table=get(p)&PT_OA_MASK;
    }
    abort();
}
/* XNU's phystokv: the physical-to-virtual table SLIDE_REGION republishes. */
static uint64_t phystokv(uint64_t pa)
{
    uint32_t n;memcpy(&n,ram+(META-BASE),4);
    for(unsigned i=0;i<n;i++) {
        uint64_t p=META+0x10+i*24,start=get(p),va=get(p+8);
        uint32_t pages;memcpy(&pages,ram+(p+16-BASE),4);
        if(pa>=start && pa-start<(uint64_t)pages*PAGE)return va+pa-start;
    }
    return 0;
}

/* Boot as far as XNU needs: a 16K kernel tree, bootstrap frames mapped at
 * BOOT_VA, SLIDE_REGION moving them, and one of them then serving as the L3
 * table for KVA_MOVED. */
static void setup(void)
{
    memset(ram,0,sizeof ram);memset(&state,0,sizeof state);
    next_guest=BASE+PAGE;next_shadow=SHADOW+0x1000;
    memory=(struct sptm_memory){.frame_low=BASE,.frame_high=SHADOW,
        .alloc_low=BASE+0x100000,.alloc_high=SHADOW,.map=map,.publish=publish};
    backend=(struct sptm_update_backend){.kernel_root=BASE,.shadow_root=SHADOW,.map_shadow=map_shadow};
    config=(struct sptm_slide_config){.table_low=BASE,.table_high=META,.map_pa=META,
        .begin=DEST,.end=DEST+0x4000000,.count=1,.regions={{BOOT_VA,BOOT,5}}};
    put(META,1);put(META+0x10,BASE);put(META+0x18,LINEAR);put(META+0x20,(SHADOW-BASE)/PAGE);
    struct shadow s={.txsz=17,.root=SHADOW,.alloc=alloc,.read=read64,.write=write64};
    for(unsigned n=0;n<5;n++) {
        put(slot(BOOT_VA+n*PAGE,14,3,1),(BOOT+n*PAGE)|3|ATTR);
        REQUIRE(!shadow_map(&s,(BOOT_VA+n*PAGE)&VMASK,BOOT+n*PAGE,PAGE,ATTR,ATTR));
    }
    for(uint64_t n=0;n<0x4000000;n+=0x2000000)(void)slot(DEST+n,14,3,1);
    REQUIRE(!shadow_reserve(&s,DEST&VMASK,0x4000000));
    REQUIRE(sptm_mac_slide_region(&memory,&backend,&config,&state,BOOT_VA,5,0)==SPTM_OK);
    put(slot(KVA_MOVED,14,2,1),(BOOT+PAGE)|3);
    memset(ram+(BOOT+PAGE-BASE),0,PAGE);
    (void)slot(KVA_LINEAR,14,3,1);
}

/* The monitor's kernel MAP_PAGE after the walk (probes/xnuboot.c), with the
 * per-CPU output area as out[2]. */
static uint64_t out[2];
static uint64_t leaf_slot(uint64_t va){return slot(va,14,3,0);}
static uint64_t kernel_map_page(uint64_t va,uint64_t pte)
{
    uint64_t at=leaf_slot(va),existing=get(at);
    struct sptm_moved moved=sptm_slide_moved(&state,&config);
    struct sptm_kernel_leaf plan;
    if(sptm_mac_kernel_map_leaf(&aperture,&moved,at,existing,pte,&plan)!=SPTM_OK)return 99;
    out[0]=plan.old;out[1]=plan.pointer;
    if(plan.install)put(at,pte);
    return plan.status;
}

/* XNU's kernel pmap: PV lists for two pages, each entry the pointer MAP_PAGE
 * returned (pv) and, for checking, the slot it was returned for. */
static uint64_t pv[2][8],pvslot[2][8];static unsigned npv[2],conflicts;
static unsigned page_of(uint64_t pte){return (pte&PT_OA_MASK&~(PAGE-1))==PAGE_B;}
static void pv_drop(uint64_t va)
{
    uint64_t at=leaf_slot(va),prev=get(at);
    put(at,0);                                        /* UNMAP_REGION */
    if((prev&3)!=3)return;
    unsigned p=page_of(prev);
    for(unsigned i=0;i<npv[p];i++)if(pv[p][i]==phystokv(at)) {   /* pmap_remove_pv */
        memmove(pv[p]+i,pv[p]+i+1,(npv[p]-i-1)*8);
        memmove(pvslot[p]+i,pvslot[p]+i+1,(npv[p]-i-1)*8);npv[p]--;return;
    }
    check(0,"pmap_remove_pv finds the PV entry by the recomputed pointer");
}
static uint64_t xnu_enter(uint64_t va,uint64_t pte)
{
    uint64_t at=leaf_slot(va),before=get(at);
    uint64_t status=kernel_map_page(va,pte);
    check(out[1]==phystokv(at),"MAP_PAGE returns the slot pointer XNU's phystokv computes");
    if(status==SPTM_MAC_MAP_CONFLICT) {
        conflicts++;
        check(get(at)==before && out[0]==before,"CONFLICT leaves the leaf and reports it");
        pv_drop(va);                                  /* ba615f8 -> ba62ff8 */
        uint64_t retry=kernel_map_page(va,pte);
        check(retry==0,"retry after removal is a new mapping");
        if(retry==0 && npv[page_of(pte)]<8) {
            pv[page_of(pte)][npv[page_of(pte)]]=out[1];pvslot[page_of(pte)][npv[page_of(pte)]++]=at;
        }
    } else if(status==0 && npv[page_of(pte)]<8) {    /* pmap_enter_pv */
        pv[page_of(pte)][npv[page_of(pte)]]=out[1];pvslot[page_of(pte)][npv[page_of(pte)]++]=at;
    }
    return status;
}
/* Every PV entry names a live leaf of its own page, and each page's PV count
 * equals the leaves that map it. */
static void pv_consistent(const char *what)
{
    const uint64_t pages[2]={PAGE_A,PAGE_B},slots[2]={leaf_slot(KVA_MOVED),leaf_slot(KVA_LINEAR)};
    for(unsigned p=0;p<2;p++) {
        unsigned leaves=0;
        for(unsigned s=0;s<2;s++)
            leaves+=(get(slots[s])&3)==3 && (get(slots[s])&PT_OA_MASK&~(PAGE-1))==pages[p];
        check(npv[p]==leaves,what);
        for(unsigned i=0;i<npv[p];i++) {
            uint64_t leaf=get(pvslot[p][i]);
            check(pv[p][i]==phystokv(pvslot[p][i]),what);
            check((leaf&3)==3 && (leaf&PT_OA_MASK&~(PAGE-1))==pages[p],what);
        }
    }
}

static void lifecycle(uint64_t va,const char *name)
{
    char what[160];
    npv[0]=npv[1]=0;conflicts=0;
    snprintf(what,sizeof what,"%s: fresh map returns 0",name);
    check(xnu_enter(va,PAGE_A|RO)==0,what);
    snprintf(what,sizeof what,"%s: same-PA permission change returns 1",name);
    check(xnu_enter(va,PAGE_A|RW)==1,what);
    snprintf(what,sizeof what,"%s: valid leaf of another PA returns CONFLICT(6)",name);
    check(xnu_enter(va,PAGE_B|RO)==SPTM_MAC_MAP_CONFLICT && conflicts==1,what);
    snprintf(what,sizeof what,"%s: after remove+retry the leaf maps the new page",name);
    check(get(leaf_slot(va))==(PAGE_B|RO),what);
    snprintf(what,sizeof what,"%s: no PV entry names a slot that maps another page",name);
    pv_consistent(what);
    check(npv[0]==0 && npv[1]==1,"old page has no PV entry, new page has one");
    /* A sub-page PA (bit 12/13) is a different page to ...f92e8 too. */
    snprintf(what,sizeof what,"%s: a PA differing in bit 12 conflicts",name);
    check(xnu_enter(va,(PAGE_B+0x1000)|RO)==SPTM_MAC_MAP_CONFLICT,what);
    pv_drop(va);npv[0]=npv[1]=0;put(leaf_slot(va),0);
}

int main(void)
{
    setup();
    /* The pointer path alone, before any mapping. */
    struct sptm_moved moved=sptm_slide_moved(&state,&config);
    check(state.count>=1 && moved.regions==state.regions && moved.low==DEST && moved.high==DEST+0x4000000,
          "the moved list is the slide state bounded by the reserved window");
    uint64_t ms=leaf_slot(KVA_MOVED),ls=leaf_slot(KVA_LINEAR);
    check((ms&~(PAGE-1))==BOOT+PAGE,"KVA_MOVED's L3 table is the slid bootstrap frame");
    check(phystokv(ms)==DEST+PAGE+(ms&(PAGE-1)),"published phystokv names the slid alias");
    check(phystokv(ls)==LINEAR+(ls-BASE),"an unmoved table keeps the linear alias");
    struct sptm_kernel_leaf k;
    check(!sptm_mac_kernel_map_leaf(&aperture,&moved,ms,0,PAGE_A|RO,&k) && k.install && !k.status &&
          k.pointer==phystokv(ms),"kernel MAP_PAGE on a slid table returns the slid alias");
    check(k.pointer!=LINEAR+(ms-BASE),"not the linear alias pmap_remove_pv can never match");
    check(!sptm_mac_kernel_map_leaf(&aperture,&moved,ls,0,PAGE_A|RO,&k) && k.pointer==phystokv(ls),
          "kernel MAP_PAGE on an ordinary table returns the linear alias");
    struct sptm_moved none=sptm_slide_moved(&(struct sptm_slide_state){0},&config);
    check(!sptm_mac_kernel_map_leaf(&aperture,&none,ms,0,PAGE_A|RO,&k) && k.pointer==LINEAR+(ms-BASE),
          "before any slide the table is linear");

    /* The old-leaf decision alone. */
    const uint64_t attrs[4]={RO,RW,0x0020000000000e43UL,0x0460000000000603UL};
    for(unsigned i=0;i<4;i++) for(unsigned j=0;j<4;j++) {
        uint64_t old=PAGE_A|attrs[i],req=PAGE_B|attrs[j];
        check(!sptm_mac_kernel_map_leaf(&aperture,&moved,ls,old,req,&k) && !k.install &&
              k.status==SPTM_MAC_MAP_CONFLICT && k.old==old && k.pointer==phystokv(ls),
              "valid different-PA leaf: CONFLICT, no install, old + pointer reported");
        check(!sptm_mac_kernel_map_leaf(&aperture,&moved,ls,old,PAGE_A|attrs[j],&k) && k.install &&
              k.status==1,"valid same-PA leaf: installed, status 1");
    }
    check(!sptm_mac_kernel_map_leaf(&aperture,&moved,ls,(PAGE_A|RO)|(1UL<<55),(PAGE_A|RO),&k) &&
          k.install && k.status==1,"software bits above the OA are not a different page");
    check(!sptm_mac_kernel_map_leaf(&aperture,&moved,ls,(PAGE_A|RO)&~3UL,PAGE_B|RO,&k) &&
          k.install && k.status==0,"an invalid old descriptor never conflicts");
    check(!sptm_mac_kernel_map_leaf(&aperture,&moved,ls,1UL<<62,PAGE_B|RO,&k) &&
          k.install && k.status==0,"a compressed marker is not a valid leaf");
    check(sptm_mac_kernel_map_leaf(&aperture,&moved,BASE+SIZE,0,PAGE_A|RO,&k)==SPTM_BAD_ADDRESS,
          "a slot XNU cannot name is refused");

    /* XNU's kernel pmap on both kinds of table. */
    lifecycle(KVA_MOVED,"slid table");
    lifecycle(KVA_LINEAR,"linear table");
    /* Both at once: one page mapped twice, then one of them retargeted. */
    npv[0]=npv[1]=0;
    check(xnu_enter(KVA_MOVED,PAGE_A|RO)==0 && xnu_enter(KVA_LINEAR,PAGE_A|RO)==0,"two mappings of A");
    check(xnu_enter(KVA_MOVED,PAGE_B|RW)==SPTM_MAC_MAP_CONFLICT,"retarget one of them");
    pv_consistent("two tables, one retargeted: PV lists match the leaves");
    check(npv[0]==1 && pvslot[0][0]==ls && npv[1]==1 && pvslot[1][0]==ms,
          "A keeps only the linear mapping, B only the slid one");

    printf("kernel MAP_PAGE conflict/pointer: %u checks, %u failures\n",checks,failures);
    return failures!=0;
}

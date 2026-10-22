/* SPDX-License-Identifier: MIT */
/* SNAP_USER_HW_WALK (compat/user-hw-walk.h): when the hardware walks macOS's
 * own 4K (format 1) user tables, it must see exactly what the monitor's shadow
 * path would have installed. Built with -DSNAP_USER_HW_WALK=1 and run by
 * tools/test-user-hw-walk.py, which also runs weakened copies of the header
 * against it; every one of them must make this program FAIL.
 *
 * What it protects, and the regression that makes it fail:
 *  1. Differential: randomized format-1 trees are built and changed only
 *     through the real SPTM model (MAP_TABLE, MAP_PAGE fresh and replacing,
 *     UNMAP_REGION, UNMAP_TABLE, NEST, UNNEST over a bound shared region,
 *     DEFAULT/USER_EXEC/USER_TPRO data, random AttrIndx/SH/AF/RO and software
 *     bits), with the hardware-walk events applied as the monitor applies
 *     them. After every call, every page of the touched ranges and the whole
 *     nested shared range is walked through the hardware-walk TTBR0 of both
 *     TPRO variants and through the shadow path of the same guest tree (a
 *     fresh sptm_root_build_shadow plus native_views_sync, what SWITCH_ROOT
 *     installs today). The leaves must agree in every bit the hardware reads.
 *     Fails on: raw or wrongly translated class 9 (F1), a stale or missing
 *     copy entry (F9), a refresh that misses an entry, discovery that misses
 *     a class 9 leaf present before the first install.
 *  2. Hardware view: every walked hardware-walk leaf has only bits the policy
 *     admits (F10), is never class 9 (F1), and every table on the way carries
 *     no hierarchical attribute (F11).
 *  3. TLB discipline: across each call, any hardware-walk VA whose valid leaf
 *     changed, or whose valid table pointer at some level changed, must lie
 *     in an invalidation the events requested during that call (F2, F3).
 *  4. Copy pages: a released copy is linked by no remaining copy (F14); no
 *     copy page leaks; the audit (hw_walk_verify, deep) holds after every call
 *     and refuses deliberately corrupted copies, raw class 9 behind the
 *     events' back, table attributes and contiguous leaves.
 *  5. Records: the open-addressed index survives random attach/detach at
 *     full load; a full table refuses (F16); hardware ASIDs are distinct per
 *     record and variant and above the slot ASIDs (F5).
 *  6. Stage 2 (F7, F8): page-table frames become read-only in all six
 *     per-CPU trees and RW again on release, with neighbors, a guarded page
 *     and attributes unchanged; identical blocks share one level-3 table; a
 *     frame outside guest RAM or in a non-RAM range is refused unchanged; the
 *     RETYPE action table protects exactly the SPTM table types.
 *  7. SWITCH_ROOT (compat/sptm-root.c): an eligible root installs with no
 *     build and identical reference/active bookkeeping; an ineligible one
 *     builds as before; -1 and a bad reference count refuse, nothing installed.
 * 11. Stage-2 pre-split (installed-fresh-20261018-v62): guest RAM is split to
 *     level 3 in every tree at setup (one shared table per 2M, guard tables
 *     kept, permissions kept); afterwards no protect or unprotect changes a
 *     level-1 or level-2 descriptor, and without the pre-split a RETYPE
 *     refuses with nothing changed instead of splitting a live block.
 * 10. Copy-table compaction (installed-fresh-20261018-v55): after a prune
 *     every moved copy carries its remapped parent; v55's eight tables are
 *     replayed, also by an -Os build of this program (the monitor's level),
 *     where the old uint64_t-view copy lost the remap.
 *  9. The loaded-root audit (installed-fresh-20261018-v53): after a
 *     hardware-walk SWITCH_ROOT the CPU's loaded policy is noted from the
 *     record (the cache-only sptm_root_note_loaded refused it with
 *     SPTM_BAD_CONFIG and stopped v53); CONFIGURE_ROOT of an active cached
 *     root and the shared-region alias snapshot admit hardware-walk roots on
 *     other CPUs; every original refusal still refuses.
 * 12. Converted events (SNAP_FINE_HW, docs/FINE-HW-WALK-20261019.md): in a
 *     third of the trials every MAP_PAGE and UNMAP_REGION first runs with the
 *     backend probes/xnuboot.c fine_hw_backend builds (compat/user-hw-walk.h
 *     hw_walk_fine_*: refresh with counters handed back, no allocation). A
 *     call the converted events refuse (a class-9 leaf, a replacement, a
 *     shared-region leaf) must change nothing and is then repeated with the
 *     token path's events, as the monitor declines it; every check of part 1
 *     holds after every call, converted calls refresh copies on TPRO roots,
 *     and the stale TPRO copy of part 8 does not happen.
 *  8. Fine locks: the backend a converted call (SNAP_FINE_LOCKS) would give
 *     an inactive hardware-walk root runs no event, and the TPRO copy then
 *     keeps a removed leaf, which the audit sees (why probes/xnuboot.c
 *     FINE_HW_ROOT declines those calls; tools/test-user-hw-walk.py binds the
 *     declines in the monitor source). */
#define SPTM_NEST_TEST_MAIN nesting_fixture_checks
#include "test-sptm-nest.c"
#include "sptm-refs.h"
#include "native-view.h"
#include "user-hw-walk.h"
#if !SNAP_USER_HW_WALK
#error "build with -DSNAP_USER_HW_WALK=1"
#endif

static unsigned failures;
static unsigned failed_lines[64],nfailed_lines;
static void note_failure(int line,const char *what)
{
    failures++;
    for(unsigned i=0;i<nfailed_lines;i++)if(failed_lines[i]==(unsigned)line)return;
    if(nfailed_lines<64)failed_lines[nfailed_lines++]=(unsigned)line;
    fprintf(stderr,"FAIL %d: %s\n",line,what);
}
#define EXPECT(x) do {checks++;if(!(x))note_failure(__LINE__,#x);} while(0)

/* --- copy memory: hardware-walk copies (1) and shadow-path pages (2) ------- */
#define CBASE UINT64_C(0x40000000)
#define CPAGES 3072u
static uint8_t cmem[CPAGES*4096u];
static uint8_t cused[CPAGES];
static uint64_t seed=0x9e3779b97f4a7c15UL;
static uint64_t rnd(void){seed^=seed<<13;seed^=seed>>7;seed^=seed<<17;return seed;}
static int in_c(uint64_t pa){return pa>=CBASE && pa<CBASE+sizeof(cmem);}
static int t_read(void *ctx,uint64_t pa,uint64_t *out)
{
    (void)ctx;
    if(pa&7)return -1;
    if(in_c(pa)) {memcpy(out,cmem+(pa-CBASE),8);return 0;}
    if(!map(0,pa,8))return -1;
    *out=word(pa);return 0;
}
static unsigned guest_writes;
static int t_write(void *ctx,uint64_t pa,uint64_t v)
{
    (void)ctx;
    if((pa&7) || !in_c(pa) || !cused[(pa-CBASE)/4096]) {guest_writes++;return -1;}
    memcpy(cmem+(pa-CBASE),&v,8);return 0;
}
static uint64_t c_alloc(uint8_t kind)
{
    for(unsigned i=0;i<CPAGES;i++)if(!cused[i]) {
        cused[i]=kind;memset(cmem+4096UL*i,0,4096);return CBASE+4096UL*i;
    }
    return 0;
}
static unsigned fail_alloc_after;   /* nonzero: that many more copy allocations succeed */
static uint64_t hw_alloc(void *ctx)
{
    (void)ctx;
    if(fail_alloc_after && !--fail_alloc_after)return 0;
    return c_alloc(1);
}
static uint64_t legacy_alloc(void *ctx){(void)ctx;return c_alloc(2);}
static void legacy_reset(void){for(unsigned i=0;i<CPAGES;i++)if(cused[i]==2)cused[i]=0;}
static struct hw_walk_state *st;
static struct hw_walk_root *current;
static unsigned bad_releases;
/* Copy pages hardware may have walked (linked when a check last looked). */
static uint8_t ever_linked[CPAGES];
static int full_invalidation(void);
/* F14: a released copy must be linked by no remaining copy of the record. */
static int linked_by_copy(const struct hw_walk_root *r,uint64_t page)
{
    if(!r)return 0;
    for(unsigned n=0;n<r->count;n++)for(unsigned w=0;w<2;w++)
        for(unsigned i=0;i<512;i++) {
            uint64_t d;t_read(0,r->t[n].copy[w]+8UL*i,&d);
            if((d&1) && (d&PT_OA_MASK)==page)return 1;
        }
    return 0;
}
static void hw_release(void *ctx,uint64_t pa)
{
    (void)ctx;
    if(!in_c(pa) || (pa&4095) || cused[(pa-CBASE)/4096]!=1 || linked_by_copy(current,pa)) {bad_releases++;return;}
    /* F14: a page hardware may have walked goes back only after every VMID
     * forgot everything during this call. */
    if(ever_linked[(pa-CBASE)/4096] && !full_invalidation()) {bad_releases++;return;}
    cused[(pa-CBASE)/4096]=0;ever_linked[(pa-CBASE)/4096]=0;
}
static int t_type(void *ctx,uint64_t table)
{
    (void)ctx;uint64_t frame=table&~0x3fffUL;
    if(!sptm_managed_frame(&m,frame))return -1;
    return meta(frame)[2];
}
static struct hw_walk_ops ops={t_read,t_write,hw_alloc,hw_release,t_type,0};

/* --- requested invalidations --------------------------------------------- */
static struct {uint64_t va,size;} inval[4096];
static unsigned invals,inval_overflow;
static void tlb_range(void *ctx,uint64_t va,uint64_t size)
{
    (void)ctx;
    if(invals==sizeof(inval)/sizeof(inval[0])) {inval_overflow=1;return;}
    inval[invals].va=va;inval[invals].size=size;invals++;
}
static struct hw_walk_tlb tlb={tlb_range,0};
static int full_invalidation(void)
{
    for(unsigned i=0;i<invals;i++)if(!inval[i].size)return 1;
    return inval_overflow;
}
/* An invalidation by VA removes, at every level, the cached entry whose VA
 * range holds that address: the level-l entry used for va is covered when an
 * invalidated range meets va's level-l span. */
static int covered(uint64_t va,unsigned level)
{
    if(inval_overflow)return 1;
    uint64_t span=hw_walk_span(level),lo=va&~(span-1),hi=lo+span;
    for(unsigned i=0;i<invals;i++) {
        if(!inval[i].size)return 1;
        uint64_t a=inval[i].va,b=inval[i].va+inval[i].size;
        if(a<hi && b>lo)return 1;
    }
    return 0;
}
/* --- the monitor's backend events, as probes/xnuboot.c applies them ------ */
static int h_prepare_leaf(void *ctx,uint64_t root,uint64_t va,unsigned shift,uint64_t pte)
{
    (void)ctx;struct hw_walk_root *r=hw_walk_find(st,root);
    if(!r || sprr_pte_class(pte)!=9)return 1;
    return hw_walk_before_tpro(&ops,r,va,UINT64_C(1)<<shift,&tlb,&st->stats);
}
static int h_commit_leaf(void *ctx,uint64_t root,uint64_t va,unsigned shift,uint64_t pte)
{
    (void)ctx;(void)pte;struct hw_walk_root *r=hw_walk_find(st,root);
    return !r || hw_walk_after_add(&ops,r,va,UINT64_C(1)<<shift,&st->stats);
}
static int h_prepare_unmap(void *ctx,uint64_t root,uint64_t va,unsigned shift,uint64_t count)
{(void)ctx;(void)root;(void)va;(void)shift;(void)count;return 1;}
static int h_commit_unmap(void *ctx,uint64_t root,uint64_t va,unsigned shift,uint64_t count,uint64_t removed)
{
    (void)ctx;(void)removed;struct hw_walk_root *r=hw_walk_find(st,root);
    if(!r) {tlb_range(0,va,count<<shift);return 1;}
    return hw_walk_after_change(&ops,r,va,count<<shift,&tlb,&st->stats);
}
static int h_prepare_update(void *ctx,uint64_t root,uint64_t va,unsigned shift,uint64_t old,uint64_t next)
{
    (void)ctx;struct hw_walk_root *r=hw_walk_find(st,root);
    if(!r || sprr_pte_class(next)!=9 || sprr_pte_class(old)==9)return 1;
    return hw_walk_before_tpro(&ops,r,va,UINT64_C(1)<<shift,&tlb,&st->stats);
}
static int h_commit_update(void *ctx,uint64_t root,uint64_t va,unsigned shift,uint64_t old,uint64_t next)
{
    (void)ctx;(void)old;(void)next;struct hw_walk_root *r=hw_walk_find(st,root);
    if(!r) {tlb_range(0,va,UINT64_C(1)<<shift);return 1;}
    return hw_walk_after_change(&ops,r,va,UINT64_C(1)<<shift,&tlb,&st->stats);
}
static int h_prepare_detach(void *ctx,uint64_t root,uint64_t va,unsigned shift,unsigned level,uint64_t removed)
{(void)ctx;(void)root;(void)va;(void)shift;(void)level;(void)removed;return 1;}
static int h_commit_detach(void *ctx,uint64_t root,uint64_t va,unsigned shift,unsigned level,uint64_t removed)
{
    (void)ctx;(void)shift;(void)removed;struct hw_walk_root *r=hw_walk_find(st,root);
    if(!r) {tlb_range(0,0,0);return 1;}
    return hw_walk_after_unlink(&ops,r,va,geom.group*hw_walk_span(level),&tlb,&st->stats);
}
static int h_prepare_nest(void *ctx,uint64_t root,uint64_t shared,uint64_t va,unsigned shift,uint64_t pages)
{(void)ctx;(void)root;(void)shared;(void)va;(void)shift;(void)pages;return 1;}
static int h_commit_nest(void *ctx,uint64_t root,uint64_t shared,uint64_t va,unsigned shift,uint64_t pages)
{
    (void)ctx;(void)shared;struct hw_walk_root *r=hw_walk_find(st,root);
    return !r || hw_walk_after_add(&ops,r,va,pages<<shift,&st->stats);
}
static int h_prepare_unnest(void *ctx,uint64_t root,uint64_t shared,unsigned shift,const struct sptm_unnest_plan *p)
{(void)ctx;(void)root;(void)shared;(void)shift;(void)p;return 1;}
static int h_commit_unnest(void *ctx,uint64_t root,uint64_t shared,unsigned shift,const struct sptm_unnest_plan *p)
{
    (void)ctx;(void)shared;(void)shift;struct hw_walk_root *r=hw_walk_find(st,root);
    if(!r) {tlb_range(0,0,0);return 1;}
    return hw_walk_after_unlink(&ops,r,p->base,p->span*p->count,&tlb,&st->stats);
}
static void hw_backend(void)
{
    backend.prepare_leaf=h_prepare_leaf;backend.commit_leaf=h_commit_leaf;
    backend.prepare_unmap=h_prepare_unmap;backend.commit_unmap=h_commit_unmap;
    backend.prepare_update=h_prepare_update;backend.commit_update=h_commit_update;
    backend.prepare_detach=h_prepare_detach;backend.commit_detach=h_commit_detach;
    backend.prepare_nest=h_prepare_nest;backend.commit_nest=h_commit_nest;
    backend.prepare_unnest=h_prepare_unnest;backend.commit_unnest=h_commit_unnest;
    backend.prepare_attach=0;backend.commit_attach=0;
    backend.active_refs=0;backend.mirror=1;backend.ttbr0=backend.ttbr1=0;
}

/* --- part 12: the converted events (probes/xnuboot.c fine_hw_*) --------- */
static int fine_mode;
static unsigned fine_maps,fine_unmaps,fine_declined_maps,fine_declined_unmaps,fine_declined_class9,
    fine_declined_replace,fine_declined_changed;
static struct hw_walk_fine_counts fine_totals;
static int f_prepare_leaf(void *ctx,uint64_t root,uint64_t va,unsigned shift,uint64_t pte)
{(void)ctx;(void)va;return hw_walk_fine_prepare_leaf(hw_walk_find(st,root),shift,pte);}
static int f_commit_leaf(void *ctx,uint64_t root,uint64_t va,unsigned shift,uint64_t pte)
{
    (void)ctx;(void)pte;struct hw_walk_fine_counts n;
    int ok=hw_walk_fine_after_add(&ops,hw_walk_find(st,root),va,UINT64_C(1)<<shift,&n);
    fine_totals.refreshes+=n.refreshes;fine_totals.refreshed+=n.refreshed;return ok;
}
static int f_prepare_unmap(void *ctx,uint64_t root,uint64_t va,unsigned shift,uint64_t count)
{(void)ctx;(void)va;(void)count;return hw_walk_fine_prepare_unmap(hw_walk_find(st,root),shift);}
static int f_commit_unmap(void *ctx,uint64_t root,uint64_t va,unsigned shift,uint64_t count,uint64_t removed)
{
    (void)ctx;(void)removed;struct hw_walk_fine_counts n;
    int ok=hw_walk_fine_after_change(&ops,hw_walk_find(st,root),va,count<<shift,&tlb,&n);
    fine_totals.refreshes+=n.refreshes;fine_totals.refreshed+=n.refreshed;return ok;
}
#if !SNAP_SPTM_FINE
static int f_decline_update(void *ctx,uint64_t root,uint64_t va,unsigned shift,uint64_t old,uint64_t next)
{(void)ctx;(void)root;(void)va;(void)shift;(void)old;(void)next;return 0;}
#else
/* SNAP_SPTM_FINE (agents/sptm-locks): probes/xnuboot.c fine_hw_prepare_update
 * and fine_hw_commit_update, i.e. compat/user-hw-walk.h hw_walk_fine_*_update:
 * a replacement or permission update runs converted (refresh, then the range
 * invalidated unless the old leaf had AF clear); entering class 9 declines. */
static unsigned fine_replaced,fine_updated,fine_declined_into9,fine_update_skips,fine_unexpected;
static int f_prepare_update(void *ctx,uint64_t root,uint64_t va,unsigned shift,uint64_t old,uint64_t next)
{(void)ctx;(void)va;return hw_walk_fine_prepare_update(hw_walk_find(st,root),shift,old,next);}
static int f_commit_update(void *ctx,uint64_t root,uint64_t va,unsigned shift,uint64_t old,uint64_t next)
{
    (void)ctx;(void)next;struct hw_walk_fine_counts n;
    int invalidate=!((old&3)==3 && !(old&UINT64_C(0x400)));    /* update_fast_uncached */
    fine_update_skips+=!invalidate;
    int ok=hw_walk_fine_after_update(&ops,hw_walk_find(st,root),va,UINT64_C(1)<<shift,invalidate,&tlb,&n);
    fine_totals.refreshes+=n.refreshes;fine_totals.refreshed+=n.refreshed;return ok;
}
#endif
/* fine_hw_backend: no shared-root, detach, attach or nest callbacks; an
 * inactive root, so the events run through the mirror. */
static struct sptm_user_backend fine_backend(void)
{
    struct sptm_user_backend b={0};
    b.prepare_leaf=f_prepare_leaf;b.commit_leaf=f_commit_leaf;
    b.prepare_unmap=f_prepare_unmap;b.commit_unmap=f_commit_unmap;
#if SNAP_SPTM_FINE
    b.prepare_update=f_prepare_update;b.commit_update=f_commit_update;
#else
    b.prepare_update=f_decline_update;b.commit_update=f_decline_update;
#endif
    b.active_refs=0;b.mirror=1;b.ttbr0=b.ttbr1=0;
    return b;
}

/* --- a strict model of the hardware walk -------------------------------- */
/* A walk records, per level, the table it read and the entry it used: the
 * entries are what walk caches and TLBs hold (one per level and VA range). */
struct walked {uint64_t leaf,path[4],entry[4];int bad;};
static struct walked hw_walk_va(uint64_t root,uint64_t va)
{
    struct walked w={0};uint64_t table=root;
    for(unsigned level=0;level<4;level++) {
        uint64_t d;
        w.path[level]=table;
        if(t_read(0,table+8UL*hw_walk_slot_index(level,va),&d)) {w.bad=1;return w;}
        w.entry[level]=d;
        if(!(d&1))return w;
        if(level==3) {if((d&3)==3)w.leaf=d;return w;}
        if((d&3)!=3) {w.bad=1;return w;}            /* no blocks in user trees */
        if(d>>59)w.bad=1;                            /* APTable/UXNTable/PXNTable/NSTable */
        table=d&PT_OA_MASK;
    }
    return w;
}
#define HW_BITS (PT_OA_MASK|PT_LEAF_ATTRS|PT_LEAF_UPPER|PT_CONTIG|(UINT64_C(3)<<50)|3UL)

/* --- the guest tree and its operations ---------------------------------- */
#define R1 UINT64_C(0x100000000)
#define R2 UINT64_C(0x7ffe000000)
#define RSPAN UINT64_C(0x1000000)
static uint64_t data_frame[3][6];       /* DEFAULT, USER_EXEC, USER_TPRO */
static uint64_t scratch_out;
static unsigned tpro_root,ops_done,refused_ops,class9_maps,detaches,unnests,reattaches;
static uint64_t paths_total,pruned_total;
static uint64_t discovered_total;
static int allow_retype(void *ctx,uint64_t pa,uint64_t old,uint64_t next)
{(void)ctx;(void)pa;(void)old;(void)next;return 1;}
static struct sptm_ref_batch test_refs;
static uint64_t region_va(void)
{
    uint64_t base=(rnd()&1) ? R1 : R2;
    return base+((rnd()%(RSPAN/4096))<<12);
}
static void ensure_tables(uint64_t root,uint64_t va)
{
    for(unsigned l=0;l<3;l++) {
        uint64_t slot=slot_at(root,l,va);
        if(word(slot))continue;
        uint64_t aligned=va&~((uint64_t)(geom.group-1)<<(12+(3-l)*9));
        CHECK(!sptm_mac_map_user_table_live(&m,&backend,root,aligned,l,allocate(20,l+1)|3));
        /* MAP_TABLE has no callback: the monitor refreshes the copies after it. */
        struct hw_walk_root *r=hw_walk_find(st,root);
        if(r)CHECK(hw_walk_after_add(&ops,r,aligned,geom.group*hw_walk_span(l),&st->stats));
    }
}
static uint64_t template_for(unsigned kind)
{
    uint64_t sh=(uint64_t)(2+(rnd()&1))<<8,sw=(rnd()&1)<<58;
    if(kind==0) {
        uint64_t t=UINT64_C(0x0060000000000843)|sh|sw|((rnd()&7)<<2);
        if(rnd()&1)t|=0x400;
        if(rnd()&1)t|=0x80;
        return t;
    }
    if(kind==1) {
        uint64_t t=UINT64_C(0x0020000000000cc3)|sh|sw;
        if(rnd()&1)t|=PT_UXN;
        if(rnd()&1)t&=~UINT64_C(0x400);
        return t;
    }
    static const uint64_t tpro[3]={UINT64_C(0x0060000000000c43),UINT64_C(0x0060000000000cc3),
                                   UINT64_C(0x0020000000000c83)};
    uint64_t t=tpro[rnd()%(tpro_root ? 3 : 2)]|sh|sw;
    if(rnd()&1)t&=~UINT64_C(0x400);
    return t;
}
static uint64_t touched[512];
static unsigned ntouched;
static void touch(uint64_t va)
{
    va&=~UINT64_C(0xfff);
    for(unsigned i=0;i<ntouched;i++)if(touched[i]==va)return;
    if(ntouched<sizeof(touched)/8)touched[ntouched++]=va;
}

/* Every VA the checks walk: touched pages and their neighbours, the nested
 * shared range, and the first page of every 2M of both regions. */
static uint64_t vas[16384];
static unsigned nvas;
static void collect(void)
{
    nvas=0;
    for(unsigned i=0;i<ntouched;i++)for(int d=-1;d<=1;d++)vas[nvas++]=touched[i]+(uint64_t)(int64_t)d*4096;
    for(uint64_t va=START;va<START+3*geom.group*hw_walk_span(2);va+=4096)vas[nvas++]=va;
    for(uint64_t off=0;off<RSPAN;off+=UINT64_C(1)<<21) {vas[nvas++]=R1+off;vas[nvas++]=R2+off;}
}
static struct walked before[2][16384];
static void snapshot_hw(void)
{
    collect();invals=0;inval_overflow=0;
    for(unsigned w=0;w<2;w++)for(unsigned i=0;i<nvas;i++)
        before[w][i]=current ? hw_walk_va(hw_walk_ttbr0(current,w)&PT_OA_MASK,vas[i]) : (struct walked){0};
}
static struct sprr_views legacy_views;
static unsigned compared,class9_seen;
/* Every check after one SPTM call. */
static void verify_all(const char *what)
{
    if(!current)return;
    /* The shadow path for the same tree: build, then both TPRO variants. */
    legacy_reset();memset(&legacy_views,0,sizeof(legacy_views));
    struct shadow ls={.txsz=17,.root=legacy_alloc(0),.alloc=legacy_alloc,.read=t_read,.write=t_write};
    uint64_t leaves=0;
    unsigned flags=meta(USER)[10];
    CHECK(sptm_root_build_shadow(&m,&ls,USER,1,flags,&leaves));
    struct sprr_state reset={0};sprr_root_reset(&reset,flags);
    CHECK(native_views_sync(&legacy_views,&ls,reset.umprr));
    EXPECT(hw_walk_verify(&ops,current,1,0));
    for(unsigned w=0;w<2;w++)for(unsigned i=0;i<nvas;i++) {
        uint64_t va=vas[i];
        struct walked a=hw_walk_va(hw_walk_ttbr0(current,w)&PT_OA_MASK,va);
        struct walked b=hw_walk_va(native_views_root(&legacy_views,w),va);
        EXPECT(!a.bad);
        EXPECT(!!a.leaf==!!b.leaf);
        if(a.leaf && b.leaf)EXPECT((a.leaf&HW_BITS)==(b.leaf&HW_BITS));
        if(a.leaf) {
            EXPECT(hw_walk_leaf_bits_ok(a.leaf) && !(a.leaf&(PT_CONTIG|(UINT64_C(3)<<50))));
            EXPECT(sprr_pte_class(a.leaf)!=9 && sprr_fixed_native_leaf(a.leaf));
        }
        compared++;
        /* TLB discipline across the call: a cached entry (any level) that
         * was valid and now differs must have been invalidated. An entry that
         * was invalid is never cached, so a fresh one needs nothing. */
        const struct walked *o=&before[w][i];
        for(unsigned l=0;l<4;l++) {
            if(!(o->entry[l]&1) || o->entry[l]==a.entry[l])continue;
#if SNAP_SPTM_FINE
            /* A valid leaf with AF clear faults on every walk: never cached
             * (compat/update-fast.h A1, the converted update's skip). */
            if(l==3 && (o->entry[l]&3)==3 && !(o->entry[l]&UINT64_C(0x400)))continue;
#endif
            if(!covered(va,l) && getenv("HW_DEBUG"))
                fprintf(stderr,"uncovered %s va=%llx w=%u level %u old=%llx new=%llx invals=%u\n",what,
                        (unsigned long long)va,w,l,(unsigned long long)o->entry[l],
                        (unsigned long long)a.entry[l],invals);
            EXPECT(covered(va,l));
        }
    }
    for(unsigned n=0;n<current->count;n++)for(unsigned w=0;w<2;w++)
        ever_linked[(current->t[n].copy[w]-CBASE)/4096]=1;
    /* No copy page leaks: exactly the record's copies are in use. */
    unsigned used=0;
    for(unsigned i=0;i<CPAGES;i++)used+=cused[i]==1;
    unsigned expect=0;
    for(unsigned r=0;r<HW_WALK_ROOTS;r++)if(st->roots[r].entry.root)expect+=2*st->roots[r].count;
    if((used!=expect || bad_releases || guest_writes) && getenv("HW_DEBUG"))
        fprintf(stderr,"%s: used %u expect %u bad_releases %u guest_writes %u\n",what,used,expect,bad_releases,guest_writes);
    EXPECT(used==expect);
    EXPECT(!bad_releases && !guest_writes);
    /* Every class 9 leaf of the guest tree is behind a copy (deep verify)
     * and the guest tree indeed holds the ones we mapped. */
    for(unsigned i=0;i<ntouched;i++) {
        struct walked g=hw_walk_va(USER,touched[i]);
        if(g.leaf && sprr_pte_class(g.leaf)==9)class9_seen++;
    }
}
static void op_map(void)
{
    uint64_t va=region_va();
    ensure_tables(USER,va);
    unsigned kind=(unsigned)(rnd()%10);kind=kind<5 ? 0 : kind<7 ? 1 : 2;
    uint64_t frame=data_frame[kind][rnd()%6];
    uint64_t pte=(frame+((rnd()&3)<<12))|template_for(kind),result=0;
    snapshot_hw();
    enum sptm_result r=SPTM_BAD_CONFIG;
    if(fine_mode && current) {
        struct sptm_user_backend b=fine_backend();uint64_t before=word(slot_at(USER,3,va));
        r=sptm_mac_map_user_page(&m,&b,USER,va,pte,1,0,&result);
        if(r==SPTM_OK)fine_maps++;
        else {
            fine_declined_maps++;fine_declined_class9+=sprr_pte_class(pte)==9;
            fine_declined_changed+=word(slot_at(USER,3,va))!=before;
        }
    }
    if(r!=SPTM_OK)r=sptm_mac_map_user_page(&m,&backend,USER,va,pte,1,0,&result);
    if(r!=SPTM_OK) {
        if(getenv("HW_DEBUG"))fprintf(stderr,"map refused %d pte %llx\n",r,(unsigned long long)pte);
        refused_ops++;return;
    }
    if(sprr_pte_class(pte)==9)class9_maps++;
    touch(va);ops_done++;verify_all("map");
}
static int mapped_va(uint64_t *out)
{
    for(unsigned tries=0;tries<64 && ntouched;tries++) {
        uint64_t va=touched[rnd()%ntouched];
        struct walked g=hw_walk_va(USER,va);
        if(g.leaf) {*out=va;return 1;}
    }
    return 0;
}
static void op_replace(void)
{
    uint64_t va,result=0;
    if(!mapped_va(&va))return;
    uint64_t old=hw_walk_va(USER,va).leaf,frame=old&PT_OA_MASK&~UINT64_C(0x3fff);
    unsigned kind=meta(frame)[2]==14 ? 1 : meta(frame)[2]==17 ? 2 : 0;
    uint64_t pte=(old&PT_OA_MASK)|template_for(kind);
    snapshot_hw();
    enum sptm_result r=SPTM_BAD_CONFIG;
    int declined9=0,fine_tried=0;(void)declined9;(void)fine_tried;
    if(fine_mode && current && pte!=old) {
        /* A replacement: prepare_update declines before the store (with
         * SNAP_SPTM_FINE only one entering class 9). */
        struct sptm_user_backend b=fine_backend();fine_tried=1;
        r=sptm_mac_map_user_page(&m,&b,USER,va,pte,1,0,&result);
        if(r==SPTM_OK) {
            fine_maps++;
#if SNAP_SPTM_FINE
            fine_replaced++;
#endif
        }
        else {
            fine_declined_maps++;fine_declined_replace++;fine_declined_changed+=hw_walk_va(USER,va).leaf!=old;
#if SNAP_SPTM_FINE
            declined9=sprr_pte_class(pte)==9 && sprr_pte_class(old)!=9;
            fine_declined_into9+=(unsigned)declined9;
#endif
        }
    }
#if SNAP_SPTM_FINE
    int fine_failed=fine_tried && r!=SPTM_OK;
#endif
    if(r!=SPTM_OK)r=sptm_mac_map_user_page(&m,&backend,USER,va,pte,1,0,&result);
#if SNAP_SPTM_FINE
    /* A converted replacement the token path then accepts: only class 9. */
    fine_unexpected+=fine_failed && r==SPTM_OK && !declined9;
#endif
    if(r!=SPTM_OK) {
        if(getenv("HW_DEBUG"))fprintf(stderr,"replace refused %d old %llx pte %llx\n",r,(unsigned long long)old,(unsigned long long)pte);
        refused_ops++;return;
    }
    if(sprr_pte_class(pte)==9)class9_maps++;
    ops_done++;verify_all("replace");
}
/* UPDATE_REGION (endpoint 5): a permission template per page, Apple's rows
 * per data type. Rights only go down (pmap_protect): class 9 leaves become
 * class 15 here, inside copied tables. */
static unsigned updates,update_out_of9;
static void op_update(void)
{
    uint64_t va;
    if(!mapped_va(&va))return;
    uint64_t count=1;
    uint64_t leaf=hw_walk_va(USER,va).leaf,frame=leaf&PT_OA_MASK&~UINT64_C(0x3fff);
    unsigned type=meta(frame)[2];
    static const uint64_t by_type[3][3]={
        {UINT64_C(0x00600000000000c0),UINT64_C(0x0060000000000040),UINT64_C(0x00600000000000c0)},
        {UINT64_C(0x00200000000000c0),UINT64_C(0x00600000000000c0),UINT64_C(0x00200000000000c0)},
        {UINT64_C(0x0020000000000080),UINT64_C(0x00600000000000c0),UINT64_C(0x0060000000000040)}};
    unsigned row=type==14 ? 1 : type==17 ? 2 : 0;
    uint64_t list=BASE+202*PAGE,out=BASE+203*PAGE,result=0;
    setword(list,by_type[row][rnd()%3]);
    uint64_t before9=0;
    for(uint64_t i=0;i<count;i++) {struct walked g=hw_walk_va(USER,va+4096*i);before9+=g.leaf && sprr_pte_class(g.leaf)==9;}
    struct sptm_user_update_state state={0};
    snapshot_hw();
    uint64_t options=(rnd()&1) ? 0x102 : 2;
    enum sptm_result r=SPTM_BAD_CONFIG;
#if SNAP_SPTM_FINE
    /* probes/xnuboot.c fine_update_region on a hardware-walk root: the
     * converted events first; a refusal leaves the tree unchanged. */
    if(fine_mode && current) {
        struct sptm_user_backend b=fine_backend();uint64_t before=word(slot_at(USER,3,va));
        r=sptm_mac_update_user_region(&m,&b,USER,va,count,list,options,out,&result,&state);
        if(r==SPTM_OK)fine_updated++;
        else fine_declined_changed+=word(slot_at(USER,3,va))!=before;
    }
    int fine_refused=fine_mode && current && r!=SPTM_OK;
    if(r!=SPTM_OK)
#endif
    r=sptm_mac_update_user_region(&m,&backend,USER,va,count,list,options,out,&result,&state);
#if SNAP_SPTM_FINE
    fine_unexpected+=fine_refused && r==SPTM_OK && !(sprr_pte_class(word(list))==9);
#endif
    if(r!=SPTM_OK) {if(getenv("HW_DEBUG"))fprintf(stderr,"update refused %d first %llx\n",r,(unsigned long long)word(list));refused_ops++;return;}
    uint64_t after9=0;
    for(uint64_t i=0;i<count;i++) {struct walked g=hw_walk_va(USER,va+4096*i);after9+=g.leaf && sprr_pte_class(g.leaf)==9;}
    if(after9<before9)update_out_of9++;
    updates++;ops_done++;verify_all("update");
}
static void op_unmap(void)
{
    uint64_t va;
    if(!mapped_va(&va))return;
    uint64_t count=1+rnd()%8,room=512-hw_walk_slot_index(3,va);
    if(count>room)count=room;
    snapshot_hw();
    enum sptm_result r=SPTM_BAD_CONFIG;
    if(fine_mode && current) {
        struct sptm_user_backend b=fine_backend();uint64_t before=word(slot_at(USER,3,va));
        r=sptm_mac_unmap_user_region(&m,&b,USER,va,count,1,scratch_out);
        if(r==SPTM_OK)fine_unmaps++;
        else {fine_declined_unmaps++;fine_declined_changed+=word(slot_at(USER,3,va))!=before;}
    }
    if(r!=SPTM_OK)CHECK(!sptm_mac_unmap_user_region(&m,&backend,USER,va,count,1,scratch_out));
    ops_done++;verify_all("unmap");
}
/* Empty every leaf of one 8 MiB group, then detach its level-3 tables. */
static void op_detach(void)
{
    uint64_t va,group=geom.group*hw_walk_span(2);
    if(!mapped_va(&va))return;
    va&=~(group-1);
    for(uint64_t at=va;at<va+group;at+=64*4096)
        if(word(slot_at(USER,2,at))&1) {
            snapshot_hw();
            CHECK(!sptm_mac_unmap_user_region(&m,&backend,USER,at,64,1,scratch_out));
            verify_all("unmap-all");
        }
    snapshot_hw();
    enum sptm_result r=sptm_mac_unmap_user_table(&m,&backend,USER,va,2);
    if(r!=SPTM_OK) {if(getenv("HW_DEBUG"))fprintf(stderr,"detach refused %d\n",r);refused_ops++;return;}
    ops_done++;detaches++;verify_all("detach");
}
static void op_unnest_renest(void)
{
    uint64_t group=geom.group*hw_walk_span(2),va=START+group*(rnd()%3);
    snapshot_hw();
    enum sptm_result u=sptm_mac_unnest_region(&m,&backend,USER,ROOT,va,group/4096);
    if(u!=SPTM_OK) {if(getenv("HW_DEBUG"))fprintf(stderr,"unnest refused %d\n",u);refused_ops++;return;}
    ops_done++;unnests++;verify_all("unnest");
    snapshot_hw();
    CHECK(!sptm_mac_nest_region(&m,&backend,USER,ROOT,va,group/4096));
    ops_done++;verify_all("nest");
}
static void attach_now(void)
{
    unsigned flags=meta(USER)[10],asid=meta(USER)[4]|(unsigned)meta(USER)[5]<<8;
    current=hw_walk_attach(st,&ops,USER,asid,flags);
    CHECK(current!=0);
    snapshot_hw();verify_all("attach");
}
static void trial(unsigned t)
{
    setup(1,0,3,1);
    fine_mode=t%3==2;
    tpro_root=t&1;
    if(tpro_root)meta(USER)[10]|=SPTM_MAC_ROOT_FLAG_UMPRR18;
    m.retype_user_tpro=allow_retype;m.retype_user_exec=allow_retype;
    memset(&test_refs,0,sizeof(test_refs));m.refs=&test_refs;
    scratch_out=BASE+201*PAGE;
    hw_backend();
    memset(st,0,sizeof(*st));current=0;
    for(unsigned i=0;i<CPAGES;i++)cused[i]=ever_linked[i]=0;
    ntouched=0;bad_releases=guest_writes=0;
    static const unsigned types[3]={11,14,17};
    for(unsigned k=0;k<3;k++)for(unsigned i=0;i<6;i++) {
        data_frame[k][i]=next_frame;next_frame+=PAGE;CHECK(next_frame<USER2);
        if(types[k]!=11)CHECK(!sptm_mac_retype(&m,data_frame[k][i],11,types[k],0));
    }
    /* Nest the whole shared fixture range first (fresh L2 entries). */
    CHECK(!sptm_mac_nest_region(&m,&backend,USER,ROOT,START,3*geom.group*hw_walk_span(2)/4096));
    /* Attach early or after a populated start (discovery of class 9). */
    unsigned attach_at=(t&2) ? 0 : 8+(unsigned)(rnd()%8);
    unsigned steps=70;
    for(unsigned s=0;s<steps;s++) {
        if(s==attach_at)attach_now();
        if(!current) {op_map();continue;}
        unsigned op=(unsigned)(rnd()%20);
        if(op<8)op_map();
        else if(op<10)op_replace();
        else if(op<12)op_update();
        else if(op<16)op_unmap();
        else if(op<18)op_detach();
        else if(op<19)op_unnest_renest();
        else {
            /* CONFIGURE_ROOT on an inactive root: everything flushed, the
             * record dropped, rebuilt with discovery at the next install. */
            tlb_range(0,0,0);struct hw_walk_root *gone=current;current=0;hw_walk_detach(st,&ops,gone);attach_now();
            reattaches++;
        }
    }
    discovered_total+=st->stats.discovered;paths_total+=st->stats.paths;pruned_total+=st->stats.pruned;
}

/* --- deliberately broken inputs: the audit must refuse each one ---------- */
static void corrupted_inputs(void)
{
    setup(1,0,3,1);meta(USER)[10]|=SPTM_MAC_ROOT_FLAG_UMPRR18;tpro_root=1;
    m.retype_user_tpro=allow_retype;m.retype_user_exec=allow_retype;
    memset(&test_refs,0,sizeof(test_refs));m.refs=&test_refs;scratch_out=BASE+201*PAGE;
    hw_backend();memset(st,0,sizeof(*st));
    for(unsigned i=0;i<CPAGES;i++)cused[i]=0;
    for(unsigned i=0;i<6;i++){data_frame[2][i]=next_frame;next_frame+=PAGE;
        CHECK(!sptm_mac_retype(&m,data_frame[2][i],11,17,0));}
    current=hw_walk_attach(st,&ops,USER,10,meta(USER)[10]);CHECK(current);
    uint64_t va=R1+0x5000,result;
    ensure_tables(USER,va);
    CHECK(!sptm_mac_map_user_page(&m,&backend,USER,va,data_frame[2][0]|UINT64_C(0x0020000000000f83),1,0,&result));
    EXPECT(current->count==4 && hw_walk_verify(&ops,current,1,0));
    /* SNAP_FINE_LOCKS: a converted call's backend for a root no CPU runs and
     * no cache entry holds (probes/xnuboot.c fine_user_backend) has no
     * mirror, no active references and callbacks that find no cache entry,
     * so UNMAP_REGION changes the guest tree with no hardware-walk event. On
     * a hardware-walk root the TPRO copy keeps the removed leaf: the reason
     * FINE_HW_ROOT sends every call naming such a root to the token path. */
    {
        struct sptm_user_backend token=backend;
        backend.mirror=0;backend.active_refs=0;backend.prepare_unmap=0;backend.commit_unmap=0;
        CHECK(!sptm_mac_unmap_user_region(&m,&backend,USER,va,1,1,scratch_out));
        backend=token;
        EXPECT(!hw_walk_va(USER,va).leaf && hw_walk_va(hw_walk_ttbr0(current,0)&PT_OA_MASK,va).leaf);
        EXPECT(!hw_walk_verify(&ops,current,0,0));
        /* The token path's events repair it. */
        EXPECT(hw_walk_after_change(&ops,current,va,4096,&tlb,&st->stats) && hw_walk_verify(&ops,current,1,0));
        EXPECT(!hw_walk_va(hw_walk_ttbr0(current,0)&PT_OA_MASK,va).leaf);
        CHECK(!sptm_mac_map_user_page(&m,&backend,USER,va,data_frame[2][0]|UINT64_C(0x0020000000000f83),1,0,&result));
        EXPECT(hw_walk_verify(&ops,current,1,0));
    }
    /* Part 12: the converted events (SNAP_FINE_HW) on the same inactive TPRO
     * root keep the copies exact; re-mapping the class-9 leaf declines and
     * leaves the tree unchanged, the token path's events then map it. */
    {
        struct sptm_user_backend b=fine_backend();
        CHECK(!sptm_mac_unmap_user_region(&m,&b,USER,va,1,1,scratch_out));
        EXPECT(!hw_walk_va(USER,va).leaf && !hw_walk_va(hw_walk_ttbr0(current,0)&PT_OA_MASK,va).leaf);
        EXPECT(hw_walk_verify(&ops,current,1,0));
        EXPECT(sptm_mac_map_user_page(&m,&b,USER,va,data_frame[2][0]|UINT64_C(0x0020000000000f83),1,0,&result)
               !=SPTM_OK && !hw_walk_va(USER,va).leaf);
        CHECK(!sptm_mac_map_user_page(&m,&backend,USER,va,data_frame[2][0]|UINT64_C(0x0020000000000f83),1,0,&result));
        EXPECT(hw_walk_verify(&ops,current,1,0));
    }
    /* A copy entry changed behind the events' back (F9). */
    uint64_t at=current->t[3].copy[0]+8UL*hw_walk_slot_index(3,va),saved;
    t_read(0,at,&saved);uint64_t bad=saved&~PT_UXN;memcpy(cmem+(at-CBASE),&bad,8);
    EXPECT(!hw_walk_verify(&ops,current,0,0));
    memcpy(cmem+(at-CBASE),&saved,8);EXPECT(hw_walk_verify(&ops,current,1,0));
    /* A raw class 9 leaf stored without the events (F1): uncovered. */
    uint64_t other=R2+0x3000;ensure_tables(USER,other);
    uint64_t gslot=slot_at(USER,3,other);
    setword(gslot,data_frame[2][1]|UINT64_C(0x0020000000000f83));
    EXPECT(hw_walk_verify(&ops,current,0,0) && !hw_walk_verify(&ops,current,1,0));
    struct walked raw=hw_walk_va(hw_walk_ttbr0(current,0)&PT_OA_MASK,other);
    EXPECT(raw.leaf && sprr_pte_class(raw.leaf)==9);
    setword(gslot,0);EXPECT(hw_walk_verify(&ops,current,1,0));
    /* A contiguous leaf in a copied table is untranslatable (F10). */
    uint64_t cslot=slot_at(USER,3,va+0x1000);
    setword(cslot,data_frame[2][2]|UINT64_C(0x0060000000000c43)|PT_CONTIG);
    EXPECT(!hw_walk_refresh(&ops,current,va+0x1000,4096,0));
    EXPECT(!hw_walk_verify(&ops,current,1,0));
    setword(cslot,0);EXPECT(hw_walk_refresh(&ops,current,va+0x1000,4096,0));
    /* A table descriptor with APTable set (F11): no copy may carry it. */
    uint64_t tslot=slot_at(USER,2,va),tte=word(tslot);
    setword(tslot,tte|(UINT64_C(1)<<61));
    EXPECT(!hw_walk_refresh(&ops,current,va,4096,0));
    EXPECT(!hw_walk_verify(&ops,current,1,0));
    EXPECT(!hw_walk_va(hw_walk_ttbr0(current,0)&PT_OA_MASK,va).bad);
    setword(tslot,tte);EXPECT(hw_walk_refresh(&ops,current,va,4096,0) && hw_walk_verify(&ops,current,1,0));
    /* A path that cannot get its copies is refused and gives its pages back
     * (F16): nothing new is linked and no page leaks. */
    unsigned before_count=current->count,before_used=0,after_used=0;
    for(unsigned i=0;i<CPAGES;i++)before_used+=cused[i]==1;
    uint64_t far=R2+0x1000;
    fail_alloc_after=3;
    EXPECT(hw_walk_prepare(&ops,current,far)==0);
    fail_alloc_after=0;
    for(unsigned i=0;i<CPAGES;i++)after_used+=cused[i]==1;
    EXPECT(current->count==before_count && before_used==after_used && !bad_releases);
    EXPECT(hw_walk_verify(&ops,current,1,0));
    /* A root without UMPRR18 holding class 9 is not attached (F1). */
    tlb_range(0,0,0);{struct hw_walk_root *gone=current;current=0;hw_walk_detach(st,&ops,gone);}
    meta(USER)[10]&=(uint8_t)~SPTM_MAC_ROOT_FLAG_UMPRR18;
    EXPECT(!hw_walk_attach(st,&ops,USER,10,meta(USER)[10]));
    meta(USER)[10]|=SPTM_MAC_ROOT_FLAG_UMPRR18;
    current=hw_walk_attach(st,&ops,USER,10,meta(USER)[10]);
    EXPECT(current && current->count==4 && hw_walk_verify(&ops,current,1,0));
    current=0;
}

/* --- the record index and hardware ASIDs (F5, F16) ----------------------- */
static int zero_read(void *ctx,uint64_t pa,uint64_t *out){(void)ctx;(void)pa;*out=0;return 0;}
static uint8_t zpages[2*HW_WALK_ROOTS+8];
static uint64_t zero_alloc(void *ctx)
{(void)ctx;for(unsigned i=0;i<sizeof(zpages);i++)if(!zpages[i]){zpages[i]=1;return UINT64_C(0x7000000000)+4096UL*i;}return 0;}
static void zero_release(void *ctx,uint64_t pa){(void)ctx;zpages[(pa-UINT64_C(0x7000000000))/4096]=0;}
static int zero_write(void *ctx,uint64_t pa,uint64_t v){(void)ctx;(void)pa;(void)v;return 0;}
static void records(void)
{
    struct hw_walk_ops z={zero_read,zero_write,zero_alloc,zero_release,0,0};
    memset(st,0,sizeof(*st));memset(zpages,0,sizeof(zpages));
    static uint64_t live[HW_WALK_ROOTS];unsigned n=0;
    for(unsigned round=0;round<20;round++) {
        while(n<HW_WALK_ROOTS) {
            uint64_t root=UINT64_C(0x800000000)+((rnd()%(1u<<20))<<14);
            int dup=0;for(unsigned i=0;i<n;i++)dup|=live[i]==root;
            if(dup)continue;
            unsigned flags=(rnd()&1) ? 0xa : 2;
            struct hw_walk_root *r=hw_walk_attach(st,&z,root,1+(unsigned)(rnd()%0xfffe),flags);
            EXPECT(r!=0 && r->entry.root==root && (r->count==1)==(flags==0xa));
            live[n++]=root;
        }
        EXPECT(!hw_walk_attach(st,&z,UINT64_C(0x400000000),5,2) && st->used==HW_WALK_ROOTS);
        for(unsigned i=0;i<n;i++)EXPECT(hw_walk_find(st,live[i]) && hw_walk_find(st,live[i])->entry.root==live[i]);
        /* Distinct hardware ASIDs for every live record and variant, all
         * above the slot ASIDs and inside 16 bits. */
        static uint8_t seen[0x10000];memset(seen,0,sizeof(seen));
        for(unsigned i=0;i<HW_WALK_ROOTS;i++) {
            struct hw_walk_root *r=&st->roots[i];
            unsigned a0=hw_walk_asid(r,0),a1=hw_walk_asid(r,1);
            EXPECT(a0>=0x100u+4u*192u && a1<0x10000u);   /* above the wide cache's slot ASIDs */
            EXPECT((a0==a1)==(r->count==0));
            EXPECT(!seen[a0]);seen[a0]=1;
            if(a1!=a0) {EXPECT(!seen[a1]);seen[a1]=1;}
            EXPECT((hw_walk_ttbr0(r,1)>>48)==a1 && (hw_walk_ttbr0(r,0)&PT_OA_MASK)==
                   (r->count ? r->t[0].copy[0] : r->entry.root));
        }
        unsigned drop=1+(unsigned)(rnd()%(n-1));
        for(unsigned k=0;k<drop;k++) {
            unsigned i=(unsigned)(rnd()%n);
            struct hw_walk_root *r=hw_walk_find(st,live[i]);
            EXPECT(r!=0);if(r)hw_walk_detach(st,&z,r);
            EXPECT(!hw_walk_find(st,live[i]));
            live[i]=live[--n];
        }
        for(unsigned i=0;i<n;i++)EXPECT(hw_walk_find(st,live[i])!=0);
        EXPECT(st->used==n);
    }
    unsigned zp=0;for(unsigned i=0;i<sizeof(zpages);i++)zp+=zpages[i];
    unsigned want=0;for(unsigned i=0;i<HW_WALK_ROOTS;i++)want+=2*st->roots[i].count;
    EXPECT(zp==want);
}

/* --- stage 2 (F7, F8) ----------------------------------------------------- */
#define SBASE UINT64_C(0x50000000)
static uint8_t smem[8u<<20];
static uint64_t snext;
static int s_read(void *ctx,uint64_t pa,uint64_t *out)
{(void)ctx;if(pa<SBASE || pa-SBASE>sizeof(smem)-8)return -1;memcpy(out,smem+(pa-SBASE),8);return 0;}
static int s_write(void *ctx,uint64_t pa,uint64_t v)
{(void)ctx;if(pa<SBASE || pa-SBASE>sizeof(smem)-8)return -1;memcpy(smem+(pa-SBASE),&v,8);return 0;}
static uint64_t s_alloc(void *ctx)
{(void)ctx;if(snext+4096>sizeof(smem))return 0;uint64_t pa=SBASE+snext;snext+=4096;memset(smem+(pa-SBASE),0,4096);return pa;}
/* The stage-2 leaf for ipa, page or block; *pa its translation. */
static uint64_t s2_leaf(struct shadow *t,uint64_t ipa,uint64_t *pa)
{
    struct mmu_config cfg={12,28,t->root};struct mmu_leaf leaf;
    if(mmu_walk(&cfg,ipa,s_read,0,&leaf) || !leaf.valid)return 0;
    if(pa)*pa=leaf.pa;
    return leaf.descriptor;
}
static int s2_presplit_done;
static void stage2_checks(void)
{
    struct shadow trees[HW_S2_TREES];
    snext=0;
    const uint64_t lo=UINT64_C(0x80000000),hi=UINT64_C(0xa0000000),guard=UINT64_C(0x80345000);
    /* A 1G block of guest RAM below lo stays unsplit: RETYPE must refuse there. */
    const uint64_t gig=UINT64_C(0x40000000);
    struct stage2_range ranges[3]={{gig,lo,S2_AP_RW|S2_ATTRS,0},{lo,hi,S2_AP_RW|S2_ATTRS,0},
                                   {hi,hi+0x400000,S2_AP_RO|S2_ATTRS,S2_XN}};
    for(unsigned k=0;k<HW_S2_TREES;k++) {
        trees[k]=(struct shadow){.txsz=28,.root=s_alloc(0),.alloc=s_alloc,.read=s_read,.write=s_write};
        CHECK(!stage2_build(&trees[k],ranges,3));
        uint64_t l1;CHECK(!s_read(0,trees[k].root+8UL*mmu_index(12,1,gig),&l1) && (l1&3)==1);
    }
    /* CPU 2's tree carries a guard split, as guard_add makes one. */
    uint64_t g3=stage2_split(&trees[2],guard),gslot=g3+8UL*mmu_index(12,3,guard),gd;
    CHECK(g3 && !s_read(0,gslot,&gd));CHECK(!s_write(0,gslot,gd&~(UINT64_C(1)<<7)));
    /* v62: without the setup pre-split a RETYPE refuses rather than change a
     * block size under the running CPUs, and changes nothing. */
    {
        static uint8_t before[sizeof(smem)];memcpy(before,smem,sizeof(smem));uint64_t sn=snext;
        EXPECT(hw_s2_set(trees,HW_S2_TREES,lo+0x1000000,1)<0);
        EXPECT(hw_s2_set(trees,HW_S2_TREES,gig+0x200000,1)<0);       /* a 1G block */
        EXPECT(sn==snext && !memcmp(before,smem,sizeof(smem)));
    }
    /* Setup: every 2M of guest RAM in level-3 leaves, permissions kept. */
    /* One read-only 2M block in every tree (as the boot's read-only regions
     * are): the pre-split keeps it read-only. */
    const uint64_t ro_region=lo+UINT64_C(0xa00000);
    for(unsigned k=0;k<HW_S2_TREES;k++) {
        uint64_t l1,l2,at;
        CHECK(!s_read(0,trees[k].root+8UL*mmu_index(12,1,ro_region),&l1) && (l1&3)==3);
        at=(l1&PT_OA_MASK)+8UL*mmu_index(12,2,ro_region);
        CHECK(!s_read(0,at,&l2) && (l2&3)==1);
        CHECK(!s_write(0,at,(l2&~PT_AP)|S2_AP_RO));
    }
    /* And one 2M block that differs between trees (read-only in tree 4 only):
     * each tree gets its own table there, with its own permissions. */
    const uint64_t diff_region=lo+UINT64_C(0xc00000);
    {
        uint64_t l1,l2,at;
        CHECK(!s_read(0,trees[4].root+8UL*mmu_index(12,1,diff_region),&l1) && (l1&3)==3);
        at=(l1&PT_OA_MASK)+8UL*mmu_index(12,2,diff_region);
        CHECK(!s_read(0,at,&l2) && (l2&3)==1);
        CHECK(!s_write(0,at,(l2&~PT_AP)|S2_AP_RO));
    }
    /* What every probed page translates to, with which permissions. */
    static const uint64_t probe[7]={0x80000000,0x80345000,0x80346000,0x9ffff000,0xa0001000,0x80a03000,0x80c05000};
    uint64_t was[HW_S2_TREES][7][2];
    for(unsigned k=0;k<HW_S2_TREES;k++)for(unsigned i=0;i<7;i++) {
        uint64_t pa=0,d=s2_leaf(&trees[k],probe[i],&pa);
        was[k][i][0]=pa;was[k][i][1]=d&~(PT_OA_MASK|UINT64_C(3));
    }
    int pre=hw_s2_presplit(trees,HW_S2_TREES,lo,hi);
    /* One shared table per 2M; in the guard's 2M tree 2 keeps its own and the
     * other five get their own; in the differing 2M all six get their own. */
    EXPECT(pre==(int)((hi-lo)>>21)-2+(HW_S2_TREES-1)+HW_S2_TREES);
    for(unsigned k=0;k<HW_S2_TREES;k++) {
        for(unsigned i=0;i<7;i++) {
            uint64_t pa=0,d=s2_leaf(&trees[k],probe[i],&pa);
            EXPECT(pa==was[k][i][0] && (d&~(PT_OA_MASK|UINT64_C(3)))==was[k][i][1]);
        }
        EXPECT((s2_leaf(&trees[k],ro_region+0x1ff000,0)&PT_AP)==S2_AP_RO);
        EXPECT((s2_leaf(&trees[k],diff_region+0x1ff000,0)&PT_AP)==(k==4 ? S2_AP_RO : S2_AP_RW));
        for(uint64_t ipa=lo;ipa<hi;ipa+=UINT64_C(1)<<21) {
            uint64_t l1,l2;
            CHECK(!s_read(0,trees[k].root+8UL*mmu_index(12,1,ipa),&l1) && (l1&3)==3);
            CHECK(!s_read(0,(l1&PT_OA_MASK)+8UL*mmu_index(12,2,ipa),&l2));
            EXPECT((l2&3)==3);
            if(k==2 && (ipa>>21)==(guard>>21))EXPECT((l2&PT_OA_MASK)==g3);
        }
        /* The XN range past guest RAM keeps its blocks. */
        uint64_t l1;CHECK(!s_read(0,trees[k].root+8UL*mmu_index(12,1,hi),&l1));
    }
    EXPECT(hw_s2_presplit(trees,HW_S2_TREES,lo,hi)==0);    /* idempotent */
    /* Every level-1 and level-2 descriptor from now on: no RETYPE may change one. */
    static uint64_t upper[HW_S2_TREES][64+64*512];
    for(unsigned k=0;k<HW_S2_TREES;k++)for(unsigned i=0;i<64;i++) {
        uint64_t l1;CHECK(!s_read(0,trees[k].root+8UL*i,&l1));upper[k][i]=l1;
        for(unsigned j=0;j<512;j++) {
            uint64_t l2=0;
            if((l1&3)==3)CHECK(!s_read(0,(l1&PT_OA_MASK)+8UL*j,&l2));
            upper[k][64+i*512+j]=l2;
        }
    }
    uint64_t frames[24];unsigned n=0;
    frames[n++]=(guard&~UINT64_C(0x3fff))^0x4000;         /* same 2M as the guard, other frame */
    frames[n++]=lo+0x1000000;frames[n++]=lo+0x1004000;   /* two frames of one 2M region */
    while(n<24) {
        uint64_t f=lo+((rnd()%((hi-lo)>>14))<<14);
        if((f>>14)==(guard>>14) || (f>>21)==((lo+UINT64_C(0xa00000))>>21) ||
           (f>>21)==((lo+UINT64_C(0xc00000))>>21))continue;
        int dup=0;for(unsigned i=0;i<n;i++)dup|=frames[i]==f;
        if(!dup)frames[n++]=f;
    }
    uint8_t ro[24]={0};
    for(unsigned round=0;round<200;round++) {
        unsigned i=(unsigned)(rnd()%n);int want=!ro[i];
        EXPECT(hw_s2_set(trees,HW_S2_TREES,frames[i],want)==0);
        ro[i]=(uint8_t)want;
        for(unsigned k=0;k<HW_S2_TREES;k++)for(unsigned j=0;j<n;j++)for(unsigned p=0;p<4;p++) {
            uint64_t ipa=frames[j]+4096UL*p,pa=0,d=s2_leaf(&trees[k],ipa,&pa);
            EXPECT(d && pa==ipa && (d&~(PT_OA_MASK|PT_AP|3UL))==S2_ATTRS);
            EXPECT((d&PT_AP)==(ro[j] ? S2_AP_RO : S2_AP_RW));
        }
        for(unsigned k=0;k<HW_S2_TREES;k++) {
            uint64_t d=s2_leaf(&trees[k],guard,0),e=s2_leaf(&trees[k],guard+0x1000,0);
            EXPECT((d&PT_AP)==(k==2 ? S2_AP_RO : S2_AP_RW) && (e&PT_AP)==S2_AP_RW);
            EXPECT((s2_leaf(&trees[k],lo+0x1008000,0)&PT_AP)==S2_AP_RW);
        }
    }
    for(unsigned k=0;k<HW_S2_TREES;k++)for(unsigned i=0;i<64;i++) {
        uint64_t l1;CHECK(!s_read(0,trees[k].root+8UL*i,&l1));EXPECT(l1==upper[k][i]);
        if((l1&3)==3)for(unsigned j=0;j<512;j++) {
            uint64_t l2;CHECK(!s_read(0,(l1&PT_OA_MASK)+8UL*j,&l2));EXPECT(l2==upper[k][64+i*512+j]);
        }
    }
    s2_presplit_done=1;
    /* Identical blocks share one level-3 table across all six trees. */
    uint64_t shared=0;
    for(unsigned k=0;k<HW_S2_TREES;k++) {
        uint64_t l1,l2;
        CHECK(!s_read(0,trees[k].root+8UL*mmu_index(12,1,lo+0x1000000),&l1));
        CHECK(!s_read(0,(l1&PT_OA_MASK)+8UL*mmu_index(12,2,lo+0x1000000),&l2));
        EXPECT((l2&3)==3);
        if(!k)shared=l2&PT_OA_MASK;
        EXPECT((l2&PT_OA_MASK)==shared);
    }
    /* Outside guest RAM, or in a non-RAM (XN) range: refused, nothing changes.
     * The XN range is split to level 3 first (as a boot split would be), so
     * that only the guest-RAM test can refuse it. */
    for(unsigned k=0;k<HW_S2_TREES;k++)CHECK(stage2_split(&trees[k],hi+0x100000));
    static uint8_t saved[sizeof(smem)];memcpy(saved,smem,sizeof(smem));uint64_t sn=snext;
    EXPECT(hw_s2_set(trees,HW_S2_TREES,gig+0x200000,1)<0);           /* never pre-split */
    EXPECT(hw_s2_set(trees,HW_S2_TREES,UINT64_C(0x30000000),1)<0);
    EXPECT(hw_s2_set(trees,HW_S2_TREES,hi+0x100000,0)<0);
    EXPECT(hw_s2_set(trees,HW_S2_TREES,frames[3]+0x1000,1)<0);
    for(unsigned k=0;k<HW_S2_TREES;k++)
        EXPECT((s2_leaf(&trees[k],hi+0x100000,0)&PT_AP)==S2_AP_RO);
    EXPECT(sn==snext && !memcmp(saved,smem,sizeof(smem)));
    /* RETYPE actions: exactly the SPTM table types are protected. */
    for(unsigned a=0;a<64;a++)for(unsigned b=0;b<64;b++) {
        int pa=a==18||a==19||a==20||a==21||a==22||a==23,pb=b==18||b==19||b==20||b==21||b==22||b==23;
        EXPECT(hw_s2_retype_action(a,b)==(pa==pb ? -1 : pb));
    }
}

/* --- SWITCH_ROOT through the hook (compat/sptm-root.c) -------------------- */
static int loaded_checks_done;
static unsigned sw_builds,sw_installs,hw_installs,eligible_answer=1;
static uint64_t hw_installed_root;
static int sw_build(void *ctx,const struct sptm_memory *mm,uint64_t root,unsigned fmt,
                    unsigned flags,uint64_t old,uint64_t *shadow,uint64_t *leaves)
{(void)ctx;(void)old;sw_builds++;*shadow=hw.root;return sptm_root_build_shadow(mm,&hw,root,fmt,flags,leaves);}
/* A hardware-walk install comes as install(shadow 0), as probes/xnuboot.c
 * user_root_install expects it. */
static void sw_install(void *ctx,uint64_t shadow,uint64_t root,uint64_t asid,unsigned fmt)
{
    (void)ctx;(void)asid;(void)fmt;
    if(shadow)sw_installs++;else {hw_installs++;hw_installed_root=root;}
}
static int sw_eligible(void *ctx,const struct sptm_memory *mm,uint64_t root,unsigned asid,
                       unsigned fmt,unsigned flags)
{(void)ctx;(void)mm;(void)root;(void)asid;(void)flags;return fmt==1 ? (int)eligible_answer : 0;}
static void switch_root_checks(void)
{
    for(unsigned fmt=0;fmt<2;fmt++) {
        setup(fmt,0,3,1);memset(&roots,0,sizeof(roots));
        struct sptm_root_backend rb={.kernel_root=BASE+249*PAGE,.kernel_shadow=hw.root,
            .build=sw_build,.install=sw_install,.hw_eligible=sw_eligible};
        sw_builds=sw_installs=hw_installs=0;eligible_answer=1;
        unsigned refs=half(USER,6);
        EXPECT(sptm_mac_switch_root(&m,&roots,&rb,0,USER,0,0)==SPTM_OK);
        EXPECT(roots.active[0]==USER && half(USER,6)==refs+1 && roots.user_switches==1);
        EXPECT(fmt ? (hw_installs==1 && !sw_builds && !sw_installs && hw_installed_root==USER &&
                      !roots.cache[0].root)
                   : (!hw_installs && sw_builds==1 && sw_installs==1));
        EXPECT(sptm_mac_switch_root(&m,&roots,&rb,1,USER,0,0)==SPTM_OK && half(USER,6)==refs+2);
        EXPECT(sptm_mac_switch_root(&m,&roots,&rb,0,rb.kernel_root,0,0)==SPTM_OK &&
               !roots.active[0] && half(USER,6)==refs+1);
        if(!fmt)continue;
        /* Refusals install nothing and change no reference. */
        eligible_answer=(unsigned)-1;unsigned before=hw_installs;
        EXPECT(sptm_mac_switch_root(&m,&roots,&rb,2,USER,0,0)==SPTM_BAD_TABLE);
        EXPECT(hw_installs==before && half(USER,6)==refs+1 && !roots.active[2]);
        eligible_answer=1;sethalf(USER,6,0);
        EXPECT(sptm_mac_switch_root(&m,&roots,&rb,2,USER,0,0)==SPTM_BAD_REFERENCE);
        EXPECT(hw_installs==before && !roots.active[2]);
        sethalf(USER,6,refs+1);
        /* Without the hook the (now inactive) 4K root builds a shadow, as today. */
        EXPECT(sptm_mac_switch_root(&m,&roots,&rb,1,rb.kernel_root,0,0)==SPTM_OK && half(USER,6)==refs);
        rb.hw_eligible=0;sw_builds=0;
        EXPECT(sptm_mac_switch_root(&m,&roots,&rb,3,USER,0,0)==SPTM_OK && sw_builds==1 &&
               half(USER,6)==refs+1 && roots.cache[0].root==USER);
    }
}

/* --- the loaded-root audit after a hardware-walk install (v53) ------------
 * installed-fresh-20261018-v53 stopped on its first hardware-walk SWITCH_ROOT:
 * the switch installed record 0 (root 0x8d592c000, no build, no cache entry),
 * then probes/xnuboot.c's case SPTM_FN_SWITCH_ROOT asked sptm_root_note_loaded
 * for the CPU's loaded policy, which looks the root up in the shadow cache
 * only, and recorded EV_REFERENCE_FAILED with SPTM_BAD_CONFIG (code 1). The
 * same sequence here: the original refuses (the regression this pins), the
 * hardware-walk audit notes it. Also the two other cache-only readers of the
 * active roots: CONFIGURE_ROOT of a cached root active on one CPU while
 * another runs a hardware-walk root, and the shared-region alias snapshot. */
static void loaded_root_checks(void)
{
    setup(1,0,3,1);memset(&roots,0,sizeof(roots));memset(st,0,sizeof(*st));
    for(unsigned i=0;i<CPAGES;i++)cused[i]=0;
    struct sptm_root_backend rb={.kernel_root=BASE+249*PAGE,.kernel_shadow=hw.root,
        .build=sw_build,.install=sw_install,.hw_eligible=sw_eligible};
    sw_builds=sw_installs=hw_installs=0;eligible_answer=1;
    meta(USER)[10]|=SPTM_MAC_ROOT_FLAG_UMPRR18;    /* v53's root: flags 0xa */
    unsigned flags=meta(USER)[10],asid=meta(USER)[4]|(unsigned)meta(USER)[5]<<8;
    struct sptm_loaded_root loaded[SPTM_ROOT_CPUS];memset(loaded,0,sizeof(loaded));
    for(unsigned cpu=0;cpu<SPTM_ROOT_CPUS;cpu++) {
        sprr_root_reset(&roots.sprr[cpu],0);CHECK(sptm_root_note_loaded(&roots,loaded,cpu));
    }
    struct hw_walk_root *r=hw_walk_attach(st,&ops,USER,asid,flags);
    CHECK(r!=0);
    EXPECT(sptm_mac_switch_root(&m,&roots,&rb,1,USER,0,0)==SPTM_OK && roots.active[1]==USER &&
           hw_installs==1 && !sw_builds && !roots.cache[0].root);
    struct sptm_loaded_root before=loaded[1];
    /* The v53 refusal, kept as it was: no cache entry, nothing noted. */
    EXPECT(!sptm_root_note_loaded(&roots,loaded,1) && !memcmp(&before,&loaded[1],sizeof(before)));
    EXPECT(hw_walk_policy_entry(&roots,st,USER)==&r->entry);
    EXPECT(hw_walk_note_loaded(&roots,st,loaded,1) && loaded[1].root==USER && loaded[1].flags==flags &&
           loaded[1].resets==roots.sprr[1].resets);
    EXPECT(hw_walk_loaded_valid(&roots,st,loaded,1) && !sptm_root_loaded_valid(&roots,loaded,1));
    for(unsigned cpu=0;cpu<SPTM_ROOT_CPUS;cpu++)EXPECT(hw_walk_loaded_valid(&roots,st,loaded,cpu));
    /* Still the original's checks: a UMPRR the flags do not give, a record
     * whose identity is not admissible, a valid cache entry beside the record,
     * a root that has neither. Each refuses and notes nothing. */
    uint64_t umprr=roots.sprr[1].umprr;roots.sprr[1].umprr^=UINT64_C(1)<<11;
    before=loaded[1];EXPECT(!hw_walk_note_loaded(&roots,st,loaded,1) && !memcmp(&before,&loaded[1],sizeof(before)));
    roots.sprr[1].umprr=umprr;
    r->entry.format=0;EXPECT(!hw_walk_note_loaded(&roots,st,loaded,1));r->entry.format=1;
    r->entry.shadow=hw.root;EXPECT(!hw_walk_note_loaded(&roots,st,loaded,1));r->entry.shadow=0;
    roots.cache[7]=(struct sptm_root_cached){.root=USER,.shadow=hw.root,.asid=asid,.format=1,.flags=flags,.valid=1};
    EXPECT(hw_walk_policy_entry(&roots,st,USER)==&roots.cache[7]);   /* the cache identity, as before */
    /* A valid but unusable entry (no shadow): the cache cannot answer, and
     * the record must not answer for it either. */
    roots.cache[7].shadow=0;EXPECT(!hw_walk_policy_entry(&roots,st,USER) && !hw_walk_note_loaded(&roots,st,loaded,1));
    roots.cache[7].shadow=hw.root;
    roots.cache[7].valid=0;      /* an invalidated slot naming the root (CONFIGURE of an inactive root) */
    EXPECT(hw_walk_policy_entry(&roots,st,USER)==&r->entry && hw_walk_note_loaded(&roots,st,loaded,1));
    roots.cache[7]=(struct sptm_root_cached){0};
    roots.active[2]=USER2;sprr_root_reset(&roots.sprr[2],0);
    EXPECT(!hw_walk_note_loaded(&roots,st,loaded,2) && !sptm_root_note_loaded(&roots,loaded,2));
    roots.active[2]=0;CHECK(hw_walk_note_loaded(&roots,st,loaded,2));
    /* CONFIGURE_ROOT (UMPRR11) of a cached root active on CPU 2 while CPU 1
     * runs the hardware-walk root: the original refuses on CPU 1's record. */
    roots.cache[3]=(struct sptm_root_cached){.root=USER2,.shadow=hw.root,.asid=asid+1,.format=1,.flags=0,.valid=1};
    roots.active[2]=USER2;sprr_root_reset(&roots.sprr[2],0);CHECK(sptm_root_note_loaded(&roots,loaded,2));
    EXPECT(!sptm_root_configure_active(&roots,loaded,USER2,0,SPTM_MAC_ROOT_FLAG_UMPRR11) && !roots.cache[3].flags);
    EXPECT(hw_walk_configure_active(&roots,st,loaded,USER2,0,SPTM_MAC_ROOT_FLAG_UMPRR11) &&
           roots.cache[3].flags==SPTM_MAC_ROOT_FLAG_UMPRR11);
    EXPECT(hw_walk_loaded_valid(&roots,st,loaded,2));     /* only UMPRR11 differs */
    EXPECT(!hw_walk_configure_active(&roots,st,loaded,USER2,0,SPTM_MAC_ROOT_FLAG_UMPRR11));   /* flags moved on */
    roots.active[2]=0;roots.cache[3]=(struct sptm_root_cached){0};
    sprr_root_reset(&roots.sprr[2],0);CHECK(hw_walk_note_loaded(&roots,st,loaded,2));
    /* The shared-region alias snapshot: the original refuses while any CPU
     * runs a hardware-walk root (no cache entry); the hardware-walk form
     * admits it as no alias, and still refuses an unaccounted active root. */
    sptm_root_mask_t mask=SPTM_ROOT_MASK_ONE(5);
    EXPECT(!sptm_root_shared_aliases(&m,&roots,ROOT,START,12,&mask));
    EXPECT(sptm_root_shared_aliases_hw(&m,&roots,ROOT,START,12,&mask,hw_walk_recorded,st) &&
           !SPTM_ROOT_MASK_ANY(mask));
    roots.active[3]=USER2;
    EXPECT(!sptm_root_shared_aliases_hw(&m,&roots,ROOT,START,12,&mask,hw_walk_recorded,st));
    roots.active[3]=0;
    /* Back to the kernel: the CPU's record is the kernel's again. */
    EXPECT(sptm_mac_switch_root(&m,&roots,&rb,1,rb.kernel_root,0,0)==SPTM_OK && !roots.active[1]);
    EXPECT(hw_walk_note_loaded(&roots,st,loaded,1) && !loaded[1].root && !loaded[1].flags);
    loaded_checks_done=1;
}

/* --- copy-table compaction (v55) ------------------------------------------
 * installed-fresh-20261018-v55 stopped on UNMAP_TABLE (SPTM_SHADOW_FAILED,
 * va 0x10308f000, level 2) of root 0x8e4b48000: an earlier prune had dropped
 * one copied table and moved the later ones down, but at -Os the remapped
 * parent never reached the moved entries (a uint64_t view of the struct), so
 * the level-3 copies at index 4 and 6 named themselves as parent and the next
 * prune refused. The same eight tables here, the fourth unlinked: after the
 * prune every parent is remapped, the audit holds, and a second prune (the
 * one v55 refused) succeeds. tools/test-user-hw-walk.py also runs this
 * program built at the monitor's -Os. */
static unsigned compaction_done;
static int c_read(void *ctx,uint64_t pa,uint64_t *out){return t_read(ctx,pa,out);}
static void compaction_checks(void)
{
    for(unsigned i=0;i<CPAGES;i++)cused[i]=0;
    bad_releases=0;
    uint64_t src[8];
    for(unsigned i=0;i<8;i++){src[i]=c_alloc(2);CHECK(src[i]);}
    static const unsigned level[8]={0,1,2,3,2,3,2,3},parent[8]={0xffff,0,1,2,1,4,1,6},
        slot[8]={0,0,4,5,7,414,11,229};
    static struct hw_walk_root r;memset(&r,0,sizeof(r));
    r.entry=(struct sptm_root_cached){.root=src[0],.asid=12,.format=1,.flags=0xb,.valid=1};
    r.umprr=0x40800;r.count=8;
    uint64_t va[8];va[0]=0;
    for(unsigned i=0;i<8;i++) {
        if(i)va[i]=va[parent[i]]+(uint64_t)slot[i]*hw_walk_span(level[parent[i]]);
        r.t[i]=(struct hw_walk_table){.source=src[i],.va=va[i],.copy={hw_alloc(0),hw_alloc(0)},
            .level=(uint16_t)level[i],.parent=(uint16_t)parent[i],.slot=(uint16_t)slot[i]};
        CHECK(r.t[i].copy[0] && r.t[i].copy[1]);
        if(i && i!=3)CHECK(!t_write(0,src[parent[i]]+8UL*slot[i],src[i]|3));
    }
    struct hw_walk_ops o=ops;o.read=c_read;
    for(unsigned i=0;i<8;i++)CHECK(hw_walk_translate(&o,&r,i,0,511,0));
    EXPECT(!hw_walk_verify(&o,&r,0,0));                 /* table 3 is not linked */
    uint64_t pages[2*HW_WALK_TABLES];
    int dropped=hw_walk_prune(&o,&r,pages);
    EXPECT(dropped==2 && r.count==7);
    static const unsigned want[7]={0xffff,0,1,1,3,1,5};
    for(unsigned i=0;i<7 && i<r.count;i++) {
        EXPECT(r.t[i].parent==want[i]);
        EXPECT(!i || r.t[i].parent<i);
    }
    EXPECT(r.t[4].slot==414 && r.t[4].level==3 && r.t[6].slot==229 && r.t[6].va==va[7]);
    EXPECT(hw_walk_verify(&o,&r,0,0));
    /* What v55 refused: the next unlink's prune (table 6 unlinked now). */
    CHECK(!t_write(0,src[6]+8UL*229,0));
    dropped=hw_walk_prune(&o,&r,pages);
    EXPECT(dropped==2 && r.count==6 && hw_walk_verify(&o,&r,0,0));
    /* And the audit refuses v55's state: a copy naming itself as parent. */
    r.t[4].parent=4;EXPECT(!hw_walk_verify(&o,&r,0,0));
    EXPECT(hw_walk_prune(&o,&r,pages)<0);
    r.t[4].parent=3;EXPECT(hw_walk_verify(&o,&r,0,0));
    compaction_done=1;
}

int main(void)
{
    st=calloc(1,sizeof(*st));CHECK(st!=0);
    records();
    stage2_checks();
    switch_root_checks();
    loaded_root_checks();
    compaction_checks();
    corrupted_inputs();
    unsigned trials=24;
    for(unsigned t=0;t<trials;t++)trial(t);
    /* Part 12 over the trials: converted maps and unmaps ran, every refusal
     * left the tree unchanged, the refusals the converted events must make
     * happened, and converted commits refreshed copies on TPRO roots. */
#if SNAP_SPTM_FINE
    /* SNAP_SPTM_FINE: replacements and updates run converted; the only
     * declined replacements are the ones entering class 9. */
    EXPECT(fine_maps && fine_unmaps && fine_declined_class9 && !fine_declined_changed);
    EXPECT(fine_replaced && fine_updated && fine_declined_into9 && !fine_unexpected);
    printf("converted updates (SNAP_SPTM_FINE): %u replacements, %u region updates, %u into class 9 declined, "
           "%u invalidations skipped (AF clear)\n",fine_replaced,fine_updated,fine_declined_into9,fine_update_skips);
#else
    EXPECT(fine_maps && fine_unmaps && fine_declined_class9 && fine_declined_replace && !fine_declined_changed);
#endif
    EXPECT(fine_totals.refreshes && fine_totals.refreshed);
    printf("converted: %u maps, %u unmaps; declined %u maps (%u class 9, %u replacements), %u unmaps; "
           "%llu refreshes, %llu entries\n",fine_maps,fine_unmaps,fine_declined_maps,fine_declined_class9,
           fine_declined_replace,fine_declined_unmaps,(unsigned long long)fine_totals.refreshes,
           (unsigned long long)fine_totals.refreshed);
    EXPECT(loaded_checks_done && compaction_done && s2_presplit_done);
    EXPECT(class9_maps>10 && class9_seen>10);
    EXPECT(updates>0 && update_out_of9>0);
    EXPECT(discovered_total>0 && paths_total>0 && pruned_total>0 && detaches>0 && unnests>0 && reattaches>0);
    if(failures) {printf("FAILED: %u of %u checks\n",failures,checks);return 1;}
    printf("PASS: %u checks (%u walks compared, %u calls, %u refused, %u class9 maps, %llu paths "
           "linked, %llu discovered, %llu copies pruned, %u detaches, %u unnests, %u reattaches, %u updates, %u out of class 9)\n",
           checks,compared,ops_done,refused_ops,class9_maps,(unsigned long long)paths_total,
           (unsigned long long)discovered_total,(unsigned long long)pruned_total,detaches,unnests,reattaches,
           updates,update_out_of9);
    return 0;
}

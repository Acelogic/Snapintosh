/* SPDX-License-Identifier: MIT */
/* SNAP_KERNEL_PPERM_REUSE: a PPERM transaction that begins with the exact
 * kernel reuse snapshot current keeps it valid (repin), and skips its own
 * kernel sync when the new value differs only outside SPRR_KERNEL_VIEW_PPERM.
 * Every operation is replayed against the unchanged monitor model (invalidate,
 * full sync of that CPU) and the complete RAM image and view metadata must be
 * identical. The snapshot invariant is checked after every step. */
#define main baseline_view_tests
#include "test-sprr-view.c"
#undef main
#include "sprr-reuse.h"
#include "sprr-publish.h"

struct machine {
    struct sprr_views views;
    struct sprr_reuse_state reuse;
    struct sprr_publish_state publish;
    uint64_t pp[6];
    uint64_t skipped,synced,repinned,verified,mismatches,hits,misses;
};
static struct machine ref,cand,*active;
static unsigned char ref_ram[BYTES],cand_ram[BYTES];
static uint64_t random_state=UINT64_C(0x6a09e667f3bcc908);
static unsigned rnd(unsigned n)
{
    random_state^=random_state<<13;random_state^=random_state>>7;random_state^=random_state<<17;
    return (unsigned)(random_state%n);
}
/* kernel_table_write: identical stores are elided, changed stores mark the
 * copy page pending (the monitor's SNAP_KERNEL_DIRTY_PUBLISH contract). */
static int kwrite(void *ctx,uint64_t pa,uint64_t value)
{
    uint64_t old;
    if(rd(ctx,pa,&old))return -1;
    if(old==value)return 0;
    if(!sprr_publish_note(&active->publish,&views,pa))return -1;
    return wr(ctx,pa,value);
}
static struct shadow kshadow(void)
{
    return (struct shadow){.txsz=17,.root=BASE,.alloc=alloc,.read=rd,.write=kwrite};
}
static int publish_cpu(unsigned cpu)
{
    struct sprr_publish_state *p=&active->publish;
    if(!sprr_publish_prepare(p,&views))return 0;
    for(unsigned level=4;level--;)for(unsigned n=0;n<views.count;n++) {
        if(views.tables[n].level!=level)continue;
        p->pages++;
        if(!sprr_publish_needed(p,cpu,n)) {p->skipped++;continue;}
        if(!sprr_publish_complete(p,cpu,n))return 0;
    }
    p->publishes++;return 1;
}
static int refresh(void)
{
    struct shadow s=kshadow();struct machine *m=active;
    int match=sprr_reuse_match(&m->reuse,&views,&s,m->pp);
    if(match<0)return 0;
    if(match) {
        m->hits++;
        for(unsigned cpu=0;cpu<6;cpu++)
            if(!sprr_views_verify_cpu(&views,&s,cpu,m->pp[cpu])) {
                m->reuse.mismatches++;m->reuse.valid=0;return 0;
            }
        return 1;
    }
    m->misses++;m->reuse.valid=0;
    for(unsigned cpu=0;cpu<6;cpu++)
        if(!sprr_views_sync_cpu(&views,&s,cpu,m->pp[cpu]) || !publish_cpu(cpu))return 0;
    return sprr_reuse_save(&m->reuse,&views,&s,m->pp);
}
/* The unchanged monitor transaction. */
static int pperm_reference(unsigned cpu,uint64_t pperm)
{
    struct shadow s=kshadow();
    sprr_reuse_invalidate(&active->reuse);
    if(!sprr_views_sync_cpu(&views,&s,cpu,pperm) || !publish_cpu(cpu))return 0;
    active->pp[cpu]=pperm;return 1;
}
/* Mirrors kernel_change_pperm_impl with SNAP_KERNEL_PPERM_REUSE. */
static int pperm_candidate(unsigned cpu,uint64_t pperm)
{
    struct machine *m=active;struct shadow s=kshadow();
    int current=views.count && sprr_reuse_current(&m->reuse,&views,&s,m->pp)==1;
    sprr_reuse_invalidate(&m->reuse);
    uint64_t before=m->pp[cpu];
    const struct sprr_publish_state *ps=&m->publish;
    int skip=current && !((before^pperm)&SPRR_KERNEL_VIEW_PPERM) &&
        ps->root==views.canonical_root && ps->count==views.count &&
        !ps->pending[cpu][0] && !ps->pending[cpu][1];
    if(skip) {
        /* Soundness of the skip, checked on EVERY skip here (the monitor
         * samples 1/64): the translation under pperm equals this copy. */
        m->skipped++;m->verified++;
        if(!sprr_views_verify_cpu(&views,&s,cpu,pperm)) {m->mismatches++;return 0;}
    } else if(!sprr_views_sync_cpu(&views,&s,cpu,pperm))return 0;
    if(!skip && !publish_cpu(cpu))return 0;
    m->pp[cpu]=pperm;
    if(current) {
        if(!skip)m->synced++;
        if(!sprr_reuse_repin(&m->reuse,&views,cpu,pperm))return 0;
        m->repinned++;
    }
    return 1;
}
/* A valid snapshot must describe all six copies exactly (the reuse contract). */
static void snapshot_invariant(void)
{
    struct shadow s=kshadow();
    if(!cand.reuse.valid)return;
    CHECK(sprr_reuse_current(&cand.reuse,&views,&s,cand.pp)==1);
    for(unsigned cpu=0;cpu<6;cpu++)CHECK(sprr_views_verify_cpu(&views,&s,cpu,cand.reuse.pperm[cpu]));
    for(unsigned cpu=0;cpu<6;cpu++)CHECK(cand.reuse.pperm[cpu]==cand.pp[cpu]);
}
static struct sprr_views ref_views,cand_views;
static void enter(struct machine *m)
{
    active=m;
    if(m==&ref) {memcpy(ram,ref_ram,sizeof ram);views=ref_views;}
    else {memcpy(ram,cand_ram,sizeof ram);views=cand_views;}
}
static void leave(void)
{
    if(active==&ref) {memcpy(ref_ram,ram,sizeof ram);ref_views=views;}
    else {memcpy(cand_ram,ram,sizeof ram);cand_views=views;}
}
static void same(void)
{
    CHECK(!memcmp(ref_ram,cand_ram,sizeof ram));
    CHECK(!memcmp(&ref_views,&cand_views,sizeof ref_views) ||
          /* sync counters differ by design (skipped syncs); compare the rest */
          (ref_views.canonical_root==cand_views.canonical_root &&
           ref_views.count==cand_views.count &&
           !memcmp(ref_views.tables,cand_views.tables,sizeof ref_views.tables)));
    for(unsigned cpu=0;cpu<6;cpu++)CHECK(ref.pp[cpu]==cand.pp[cpu]);
}
/* Canonical descriptor mutation on both machines (then the caller refreshes). */
static void mutate(uint64_t table,unsigned index,uint64_t desc)
{
    enter(&ref);put(table,index,desc);leave();
    enter(&cand);put(table,index,desc);leave();
}
static void both_refresh(void)
{
    enter(&ref);CHECK(refresh());leave();
    enter(&cand);CHECK(refresh());snapshot_invariant();leave();
    same();
}
static void both_pperm(unsigned cpu,uint64_t pperm)
{
    enter(&ref);CHECK(pperm_reference(cpu,pperm));leave();
    enter(&cand);CHECK(pperm_candidate(cpu,pperm));snapshot_invariant();leave();
    same();
}
static void both_prepare(uint64_t va)
{
    /* Both machines draw the same fresh pages from the shared allocator. */
    struct shadow s;uint64_t first=next;unsigned budget=alloc_budget;
    enter(&ref);s=kshadow();CHECK(sprr_views_prepare(&views,&s,va));leave();
    next=first;alloc_budget=budget;
    enter(&cand);s=kshadow();CHECK(sprr_views_prepare(&views,&s,va));leave();
}
int main(void)
{
    CHECK(!baseline_view_tests());
    struct shadow s;setup(&s);s=kshadow();
    CHECK(sprr_views_init(&views,&s));CHECK(sprr_views_prepare(&views,&s,0));
    for(unsigned i=0;i<4;i++)put(BASE+0x3000,i,DATA+4096UL*i+3+ATTR+PT_UXN);
    memcpy(ref_ram,ram,sizeof ram);memcpy(cand_ram,ram,sizeof ram);
    ref_views=cand_views=views;
    for(unsigned cpu=0;cpu<6;cpu++)ref.pp[cpu]=cand.pp[cpu]=SPRR_PPERM_INITIAL;
    both_refresh();
    const uint64_t deltas[4]={0,0x100,SPRR_UPERM_TPRO_WRITE,0x100|SPRR_UPERM_TPRO_WRITE};
    unsigned prepared=0;
    for(unsigned round=0;round<3000;round++) {
        unsigned op=rnd(16);
        if(op<9) {
            unsigned cpu=rnd(6);both_pperm(cpu,SPRR_PPERM_INITIAL^deltas[rnd(4)]);
        } else if(op<11) {
            /* Canonical change in a copied or a shared table, then the refresh
             * the monitor performs before resuming (shadow_tlb_sync). */
            unsigned which=rnd(4);
            uint64_t table=which==0 ? BASE+0x3000 : which==1 ? BASE+0x4000 :
                           which==2 ? BASE+0x2000 : BASE+0x3000;
            unsigned index=which==2 ? 5+rnd(3) : 4+rnd(8);
            uint64_t desc=rnd(3) ? DATA+0x10000+4096UL*rnd(64)+3+ATTR+PT_UXN+PT_PXN : 0;
            if(which==2)desc=rnd(2) ? DATA+0x200000UL*(1+rnd(8))+1+ATTR+PT_UXN+PT_PXN : 0;
            if(which==3)desc=rnd(2) ? DATA+0x20000+4096UL*rnd(16)+3+ATTR+PT_UXN : 0;
            mutate(table,index,desc);both_refresh();
        } else if(op<12) {
            /* A-B-A: canonical change with PPERM transactions before its
             * refresh, then restored. The candidate must not revive a stale
             * snapshot for the copy synced from the intermediate source. */
            uint64_t old;enter(&ref);CHECK(!rd(0,BASE+0x3000+8*5,&old));leave();
            mutate(BASE+0x3000,5,DATA+0x70000+3+ATTR+PT_UXN+PT_PXN);
            both_pperm(rnd(6),SPRR_PPERM_INITIAL^deltas[rnd(4)]);
            both_pperm(rnd(6),SPRR_PPERM_INITIAL^deltas[rnd(4)]);
            mutate(BASE+0x3000,5,old);both_refresh();
        } else if(op<13 && prepared<3) {
            static const uint64_t vas[3]={0x200000,0x401000,0x600000};
            if(prepared==1) {
                mutate(BASE+0x2000,2,BASE+0x5000+3);
                mutate(BASE+0x5000,1,DATA+3+ATTR+PT_UXN+PT_PXN);
            }
            if(prepared==2) {
                mutate(BASE+0x2000,3,BASE+0x6000+3);
                mutate(BASE+0x6000,0,DATA+0x3000+3+ATTR+PT_UXN+PT_PXN);
            }
            both_prepare(vas[prepared++]);both_refresh();
        } else both_refresh();
    }
    CHECK(cand.skipped>100 && cand.synced>100 && cand.repinned==cand.skipped+cand.synced);
    CHECK(!cand.mismatches && cand.verified==cand.skipped);
    CHECK(cand.hits>ref.hits && cand.misses<ref.misses);
    printf("model: reference refresh hits %llu misses %llu; candidate hits %llu misses %llu; "
           "skipped %llu synced %llu repinned %llu\n",
           (unsigned long long)ref.hits,(unsigned long long)ref.misses,
           (unsigned long long)cand.hits,(unsigned long long)cand.misses,
           (unsigned long long)cand.skipped,(unsigned long long)cand.synced,
           (unsigned long long)cand.repinned);

    /* sprr_reuse_current is counter-free and exact. */
    enter(&cand);s=kshadow();CHECK(refresh());
    struct sprr_reuse_state saved=cand.reuse;
    CHECK(sprr_reuse_current(&cand.reuse,&views,&s,cand.pp)==1);
    CHECK(!memcmp(&saved,&cand.reuse,sizeof saved));
    for(unsigned n=0;n<views.count;n+=3)for(unsigned i=0;i<512;i+=37) {
        uint64_t pa=views.tables[n].source+8UL*i,old;
        CHECK(!rd(0,pa,&old));CHECK(!wr(0,pa,old^8));
        CHECK(sprr_reuse_current(&cand.reuse,&views,&s,cand.pp)==0);CHECK(!wr(0,pa,old));
    }
    uint64_t pp[6];memcpy(pp,cand.pp,sizeof pp);pp[2]^=SPRR_UPERM_TPRO_WRITE;
    CHECK(sprr_reuse_current(&cand.reuse,&views,&s,pp)==0);
    pp[2]=0;CHECK(sprr_reuse_current(&cand.reuse,&views,&s,pp)==-1);
    read_fail=views.tables[1].source+8;
    CHECK(sprr_reuse_current(&cand.reuse,&views,&s,cand.pp)==-1);read_fail=0;
    CHECK(!memcmp(&saved,&cand.reuse,sizeof saved));
    struct sprr_view_table keep=views.tables[1];views.tables[1].copy[3]+=4096;
    CHECK(sprr_reuse_current(&cand.reuse,&views,&s,cand.pp)==0);views.tables[1]=keep;
    /* A read failure takes the unchanged path: invalidate, full sync. */
    read_fail=views.tables[0].source+16;
    CHECK(!pperm_candidate(4,cand.pp[4]^0x100));CHECK(!cand.reuse.valid);read_fail=0;
    CHECK(pperm_candidate(4,cand.pp[4]));CHECK(!cand.reuse.valid);
    CHECK(refresh());CHECK(cand.reuse.valid);

    /* repin refuses malformed inputs and never validates a mismatched count. */
    struct sprr_reuse_state r=cand.reuse;r.valid=0;
    CHECK(!sprr_reuse_repin(&r,&views,6,SPRR_PPERM_INITIAL) && !r.valid);
    CHECK(!sprr_reuse_repin(&r,&views,0,1) && !r.valid);
    r.count--;CHECK(!sprr_reuse_repin(&r,&views,0,SPRR_PPERM_INITIAL) && !r.valid);r.count++;
    CHECK(sprr_reuse_repin(&r,&views,0,SPRR_PPERM_INITIAL|0x100) && r.valid && r.pperm[0]==(SPRR_PPERM_INITIAL|0x100));

    /* Pending publication for this CPU forces the full path even when the
     * snapshot is current (no cache maintenance is ever skipped). */
    uint64_t skipped=cand.skipped,synced=cand.synced;
    cand.publish.pending[1][0]|=1;
    CHECK(pperm_candidate(1,cand.pp[1]^SPRR_UPERM_TPRO_WRITE));
    CHECK(cand.skipped==skipped && cand.synced==synced+1 && !cand.publish.pending[1][0]);
    CHECK(cand.reuse.valid);snapshot_invariant();

    /* A corrupted copy under a current snapshot: the skip's verification
     * reports it without a store; the full refresh check also refuses it. */
    uint64_t copy=views.tables[0].copy[5],word;CHECK(!rd(0,copy,&word));
    CHECK(!wr(0,copy,word^4));unsigned saved_writes=writes;uint64_t mism=cand.mismatches;
    CHECK(!pperm_candidate(5,cand.pp[5]^SPRR_UPERM_TPRO_WRITE));
    CHECK(cand.mismatches==mism+1 && writes==saved_writes);
    CHECK(!wr(0,copy,word));
    /* TPRO toggles never change a kernel descriptor: the unchanged sync is
     * provably store-free for the fixture's selector2/fixed leaves. */
    CHECK(refresh());for(unsigned cpu=0;cpu<6;cpu++) {
        CHECK(sprr_views_verify_cpu(&views,&s,cpu,cand.pp[cpu]^SPRR_UPERM_TPRO_WRITE));
        CHECK(!sprr_views_verify_cpu(&views,&s,cpu,cand.pp[cpu]^0x100));
    }
    leave();
    printf("PPERM snapshot reuse: %u checks, %u failures\n",checks,failed);
    return failed ? 1 : 0;
}

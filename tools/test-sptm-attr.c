/* SPDX-License-Identifier: MIT */
/* SH/AttrIndx UPDATEs (options 0x10/0x20) on an active user root.
 *
 * XNU's pmap_batch_set_cache_attributes turns every mapping of a frame
 * write-combined and back through UPDATE_DISJOINT_MULTIPAGE groups with
 * options 0x130 (generation66 stopped on the first one). A user alias is
 * sptm_mac_update_user_disjoint (a kernel alias beside it makes the call
 * mixed); page ranges reach sptm_mac_update_user_region. Against a real
 * canonical hardware shadow and six private CPU views this checks that:
 *   - the source leaf, every 4K hardware leaf and every CPU view carry the new
 *     AttrIndx/SH, and PA, permissions, AF, nG and reference counts stay;
 *   - memory.clean_frame runs once per changed frame, strictly before any
 *     source, output, shadow or kernel store and any publication; without it
 *     or when it fails the call is refused and changes nothing;
 *   - the SWITCH_ROOT memo's published-store witness retires the leaf table's
 *     verdict on success and keeps it on refusal;
 *   - result 5 needs 0x100 and no leaf leaving AttrIndx 5/7;
 *   - the device window keeps its attributes (EL2 has no alias to clean).
 * cc -std=gnu11 -O1 -g -fsanitize=address,undefined -Icompat -Ishadow
 *   tools/test-sptm-attr.c compat/sptm-user.c compat/sptm-root.c compat/sptm.c
 *   compat/sptm-refs.c compat/sptm-unmap.c compat/sptm-update.c compat/txm.c
 *   compat/sptm-papt.c compat/sptm-slide.c shadow/shadow.c shadow/mmu.c
 *   shadow/sprr-view.c -o build/test-sptm-attr */
#define main tpro_lifecycle_tests
#include "test-user-tpro.c"
#undef main
#include "sptm-root-memo.h"
#include "sptm-nx-update.h"

#define IO UINT64_C(0xb0000000)
#define IO_SIZE 0x10000u
#define LIST (BASE+0x30000)
#define RW UINT64_C(0x0060000000000f43)     /* user RW NX, nG, AF, SH3 */
#define ATTRS UINT64_C(0x31c)
static struct sptm_memory mem;
static struct sptm_root_memo memo;
static unsigned cleans,refuse_clean,kernel_commits;
static uint64_t clean_pa;
static uint8_t snap_ram[SIZE],snap_hw[sizeof hw_ram];
static unsigned snap_published;
static void snapshot(void)
{memcpy(snap_ram,ram,SIZE);memcpy(snap_hw,hw_ram,sizeof hw_ram);snap_published=published;}
static int untouched(void)
{
    return !memcmp(snap_ram,ram,SIZE) && !memcmp(snap_hw,hw_ram,sizeof hw_ram) &&
        published==snap_published;
}
/* The monitor's sptm_publish: every published store is the memo's witness. */
static void attr_publish(void *ctx,uint64_t pa,uint64_t n)
{
    publish(ctx,pa,n);
    sptm_root_memo_publish(&memo,FM,BASE,BASE+SIZE,map,ctx,pa,n);
}
static int clean(void *ctx,uint64_t pa,uint64_t size)
{
    (void)ctx;
    CHECK(size==16384 && untouched() && !kernel_commits);
    cleans++;clean_pa=pa;return !refuse_clean;
}
static int prepare_update(void *ctx,uint64_t root,uint64_t va,unsigned shift,
                          uint64_t old,uint64_t next)
{
    (void)ctx;(void)old;(void)next;CHECK(root==ROOT);
    return sptm_root_prepare_unmap(&cache,&hw,live_memory,va,shift,1);
}
static int commit_update(void *ctx,uint64_t root,uint64_t va,unsigned shift,
                         uint64_t old,uint64_t next)
{
    (void)ctx;CHECK(root==ROOT);
    return sptm_root_commit_update(&cache,&hw,live_memory,va,shift,old,next) && sync_views();
}
static struct sptm_user_backend active_backend(void)
{
    return (struct sptm_user_backend){.ttbr0=ROOT,.active_refs=1,.prepare_leaf=prepare_live,
        .commit_leaf=commit_live,.prepare_unmap=prepare_remove,.commit_unmap=commit_remove,
        .prepare_update=prepare_update,.commit_update=commit_update};
}
static int resolve_active(void *ctx,uint64_t root,struct sptm_user_backend *b)
{(void)ctx;if(root!=ROOT)return 0;*b=active_backend();return 1;}
/* A mapped DEFAULT page at VA under an installed root: source, canonical
 * hardware shadow, six synchronized private views and one active reference. */
static void activate(unsigned format,uint64_t pte)
{
    mem=setup(format);mem.publish=attr_publish;mem.clean_frame=clean;live_memory=&mem;
    uint64_t result=99;struct sptm_user_backend b={0};
    CHECK(sptm_mac_map_user_page(&mem,&b,ROOT,VA,pte,1,0,&result)==SPTM_OK && !result);
    memset(hw_ram,0,sizeof hw_ram);memset(&cpu_views,0,sizeof cpu_views);
    memset(cpu_states,0,sizeof cpu_states);hw_next=HW_BASE+4096;
    hw=(struct shadow){.txsz=17,.root=HW_BASE,.alloc=hw_alloc,.read=hw_read,.write=hw_write};
    cache=(struct sptm_root_cached){.root=ROOT,.shadow=HW_BASE,.asid=get(meta(ROOT)+4,2),
        .format=format,.flags=0xa,.valid=1};
    CHECK(sptm_root_build_shadow(&mem,&hw,ROOT,format,0xa,&cache.leaves) && cache.leaves==1);
    CHECK(sprr_views_init(&cpu_views,&hw) && sprr_views_prepare_user(&cpu_views,&hw));
    for(unsigned cpu=0;cpu<6;cpu++)sprr_root_reset(&cpu_states[cpu],0xa);
    CHECK(sync_views());
    put(meta(ROOT)+6,get(meta(ROOT)+6,2)+1,2);
    memset(&memo,0,sizeof memo);cleans=refuse_clean=kernel_commits=0;clean_pa=0;
}
/* Source, every 4K hardware leaf and every CPU view of VA map DATA with the
 * attributes, permissions and XN of want. */
static void verify(unsigned format,uint64_t va,uint64_t pa,uint64_t want)
{
    uint64_t size=format ? 4096 : 16384;const uint64_t mask=PT_LEAF_ATTRS|PT_LEAF_UPPER;
    struct mmu_config src={format ? 12:14,17,ROOT};struct mmu_leaf l={0};
    CHECK(!mmu_walk(&src,va,read64,0,&l) && l.valid && l.descriptor==want);
    for(uint64_t off=0;off<size;off+=4096) {
        struct mmu_config cfg={12,17,HW_BASE};
        CHECK(!mmu_walk(&cfg,va+off,hw_read,0,&l) && l.valid && l.pa==pa+off &&
              (l.descriptor&mask)==(want&mask));
        for(unsigned cpu=0;cpu<6;cpu++) {
            struct mmu_config v={12,17,sprr_views_root(&cpu_views,cpu)};
            CHECK(!mmu_walk(&v,va+off,hw_read,0,&l) && l.valid && l.pa==pa+off &&
                  (l.descriptor&mask)==(want&mask));
        }
    }
}
static uint64_t l3_record(void)
{return sptm_root_memo_record_bytes(map(0,meta(L3),16));}
static enum sptm_result disjoint(uint64_t templ,uint64_t options,uint64_t *out)
{
    struct sptm_user_update_state st={0};
    put(LIST,ROOT,8);put(LIST+8,VA,8);put(LIST+16,templ,8);snapshot();
    return sptm_mac_update_user_disjoint(&mem,resolve_active,0,DATA,LIST,1,options,BASE,out,&st);
}
static void test_disjoint(unsigned format)
{
    const uint64_t pte=DATA|RW,wc=(pte&~ATTRS)|4;unsigned shift=format ? 12:14;
    activate(format,pte);
    uint64_t data_refs=get(meta(DATA)+8,8),table_refs=get(meta(L3)+8,2),out=99;
    sptm_root_memo_store(&memo,L3,VA,0xa,shift,l3_record());
    /* Refusals change no byte, publish nothing and keep the memo verdict:
     * no clean hook, a failed clean, nG, or bits outside the engine's set. */
    for(unsigned bad=0;bad<4;bad++) {
        mem.clean_frame=bad==0 ? 0 : clean;refuse_clean=bad==1;cleans=0;
        static const uint64_t options[]={0x130,0x130,0x134,0x330};
        enum sptm_result r=disjoint(wc,options[bad],&out);
        CHECK(r==(bad==1 ? SPTM_MEMORY_UNAVAILABLE : SPTM_UNSUPPORTED_OPTIONS));
        CHECK(untouched() && cleans==(bad==1) && out==99);
        CHECK(sptm_root_memo_find(&memo,L3,VA,0xa,shift,l3_record()));
        verify(format,VA,DATA,pte);
    }
    mem.clean_frame=clean;refuse_clean=0;cleans=0;
    /* Write-combined: one clean of DATA, before anything; then the change is
     * everywhere, the old descriptor is returned, and the memo lost it. */
    CHECK(disjoint(wc,0x130,&out)==SPTM_OK);
    CHECK(cleans==1 && clean_pa==DATA && out==5 && get(BASE,8)==pte);
    verify(format,VA,DATA,wc);
    CHECK(get(meta(DATA)+8,8)==data_refs && get(meta(L3)+8,2)==table_refs && cache.leaves==1);
    CHECK(!sptm_root_memo_find(&memo,L3,VA,0xa,shift,l3_record()) && memo.stats.invalidations==1);
    /* Back to write-back (a frame's continuation header does this). */
    CHECK(disjoint(pte,0x130,&out)==SPTM_OK && cleans==2 && out==5);
    verify(format,VA,DATA,pte);
    /* Entering posted AttrIndx 5 defers (5); leaving it does not (0). */
    CHECK(disjoint(pte|0x14,0x130,&out)==SPTM_OK && cleans==3 && out==5);
    verify(format,VA,DATA,pte|0x14);
    CHECK(disjoint(wc,0x130,&out)==SPTM_OK && cleans==4 && out==0);
    verify(format,VA,DATA,wc);
    /* Unchanged attributes need no clean; SH/AttrIndx without their option
     * are not applied; without 0x100 the result is 0. */
    CHECK(disjoint(wc,0x130,&out)==SPTM_OK && cleans==4 && out==0);
    CHECK(disjoint(pte&~PT_AF,0x108,&out)==SPTM_OK && cleans==4 && out==5);
    verify(format,VA,DATA,wc&~PT_AF);
    CHECK(disjoint(pte,0x30|0x800|8,&out)==SPTM_OK && cleans==5 && out==0);
    verify(format,VA,DATA,pte);
    CHECK(get(meta(DATA)+8,8)==data_refs && get(meta(L3)+8,2)==table_refs && cache.leaves==1);
    put(meta(ROOT)+6,get(meta(ROOT)+6,2)-1,2);
}
static void test_region(unsigned format)
{
    const uint64_t pte=DATA|RW,wc=(pte&~ATTRS)|4;
    activate(format,pte);struct sptm_user_backend b=active_backend();
    uint64_t out=99,size=format ? 4096 : 16384;struct sptm_user_update_state st={0};
    /* A second page of the same frame (format1) or a second frame: one clean
     * per distinct frame, none for the missing third leaf. */
    uint64_t second=format ? DATA+4096 : DATA+0x8000,result=99;
    if(!format)put(meta(second)+2,11,1);
    CHECK(sptm_mac_map_user_page(&mem,&b,ROOT,VA+size,second|RW,1,0,&result)==SPTM_OK && !result);
    put(LIST,wc,8);put(LIST+8,(second|RW)&~ATTRS,8);put(LIST+16,wc,8);snapshot();
    CHECK(sptm_mac_update_user_region(&mem,&b,ROOT,VA,3,LIST,0x130,BASE,&out,&st)==SPTM_OK);
    CHECK(cleans==(format ? 1u : 2u) && out==5 && get(BASE,8)==pte && get(BASE+8,8)==(second|RW));
    CHECK(!get(BASE+16,8));
    verify(format,VA,DATA,wc);verify(format,VA+size,second,(second|RW)&~ATTRS);
    /* Entering posted AttrIndx 5 defers; leaving it answers 0. */
    put(LIST,pte|0x14,8);snapshot();
    CHECK(sptm_mac_update_user_region(&mem,&b,ROOT,VA,1,LIST,0x130,BASE,&out,&st)==SPTM_OK);
    CHECK(out==5);verify(format,VA,DATA,pte|0x14);
    put(LIST,wc,8);snapshot();
    CHECK(sptm_mac_update_user_region(&mem,&b,ROOT,VA,1,LIST,0x130,BASE,&out,&st)==SPTM_OK);
    CHECK(out==0);verify(format,VA,DATA,wc);
    /* Refused without the hook, with nothing changed. */
    mem.clean_frame=0;put(LIST,pte,8);snapshot();
    CHECK(sptm_mac_update_user_region(&mem,&b,ROOT,VA,1,LIST,0x120,BASE,&out,&st)==
          SPTM_UNSUPPORTED_OPTIONS);
    CHECK(untouched());mem.clean_frame=clean;
    CHECK(sptm_mac_unmap_user_region(&mem,&b,ROOT,VA,2,1,BASE)==SPTM_OK && !cache.leaves);
    /* The device window keeps its attributes; its permissions still update. */
    mem.user_io_pa=IO;mem.user_io_size=IO_SIZE;
    const uint64_t io=IO|(RW&~ATTRS)|0x200|(1UL<<2);
    CHECK(sptm_mac_map_user_page(&mem,&b,ROOT,VA,io,1,0,&result)==SPTM_OK && !result);
    for(uint64_t o=0x10;o<=0x30;o+=0x10) {
        put(LIST,(io&~ATTRS)|0x300,8);snapshot();cleans=0;
        CHECK(sptm_mac_update_user_region(&mem,&b,ROOT,VA,1,LIST,o,BASE,&out,&st)==
              SPTM_UNSUPPORTED_OPTIONS);
        CHECK(untouched() && !cleans);
    }
    put(LIST,io|0x80,8);
    CHECK(sptm_mac_update_user_region(&mem,&b,ROOT,VA,1,LIST,0x32,BASE,&out,&st)==SPTM_OK);
    CHECK(!cleans);verify(format,VA,IO,io|0x80);
    CHECK(sptm_mac_unmap_user_region(&mem,&b,ROOT,VA,1,1,BASE)==SPTM_OK);
    put(meta(ROOT)+6,get(meta(ROOT)+6,2)-1,2);
}
/* A kernel alias beside the user one: a single clean of the target precedes
 * both the kernel commit and every user store. */
#define KROOT (BASE+0x3c000)
static struct sptm_update_workspace kernel_workspace;
static uint64_t kernel_slot;
static enum sptm_result kernel_prepare(void *ctx,uint64_t target,uint64_t va,
    uint64_t requested,uint64_t options,uint64_t scratch,uint64_t bytes,
    struct sptm_update_entry *e)
{
    (void)ctx;(void)va;(void)scratch;(void)bytes;
    *e=(struct sptm_update_entry){.guest=(volatile uint8_t *)&kernel_slot,.slot_pa=KROOT,
        .old=target|0x0060000000000603UL};
    enum sptm_result r=sptm_nx_update_pte(e->old,requested,options,&e->next,0);
    if(!r && ((e->old^e->next)&ATTRS) && !mem.clean_frame)r=SPTM_UNSUPPORTED_OPTIONS;
    return r;
}
static void kernel_commit(void *ctx,struct sptm_update_entry *e)
{
    (void)ctx;CHECK(cleans==1);kernel_commits++;kernel_slot=e->next;
}
static void test_mixed(unsigned format)
{
    const uint64_t pte=DATA|RW,wc=(pte&~ATTRS)|4,kernel=DATA|0x0060000000000603UL;
    activate(format,pte);kernel_slot=kernel;
    struct sptm_mixed_kernel_backend k={.root=KROOT,.workspace=&kernel_workspace,
        .prepare=kernel_prepare,.commit=kernel_commit};
    struct sptm_user_update_state st={0};uint64_t out=99;
    for(unsigned user_changes=0;user_changes<2;user_changes++) {
        put(LIST,KROOT,8);put(LIST+8,0xfffffe0012344000UL,8);put(LIST+16,(kernel&~ATTRS)|4,8);
        put(LIST+24,ROOT,8);put(LIST+32,VA,8);put(LIST+40,user_changes ? wc : pte,8);
        snapshot();cleans=kernel_commits=0;kernel_slot=kernel;
        CHECK(sptm_mac_update_mixed_disjoint(&mem,resolve_active,0,&k,DATA,LIST,2,0x130,BASE,
                                             &out,&st)==SPTM_OK);
        CHECK(cleans==1 && clean_pa==DATA && kernel_commits==1 && out==5);
        CHECK(kernel_slot==((kernel&~ATTRS)|4) && get(BASE,8)==kernel && get(BASE+8,8)==pte);
        verify(format,VA,DATA,user_changes ? wc : pte);
        /* Restore: the stub kernel alias is unchanged now, the user one not. */
        put(LIST+16,kernel,8);put(LIST+40,pte,8);snapshot();cleans=kernel_commits=0;
        CHECK(sptm_mac_update_mixed_disjoint(&mem,resolve_active,0,&k,DATA,LIST,2,0x130,BASE,
                                             &out,&st)==SPTM_OK);
        CHECK(cleans==user_changes && !kernel_commits && out==(user_changes ? 5u : 0u));
        verify(format,VA,DATA,pte);
    }
    put(meta(ROOT)+6,get(meta(ROOT)+6,2)-1,2);
}
int main(void)
{
    for(unsigned format=0;format<2;format++) {
        test_disjoint(format);test_region(format);test_mixed(format);
    }
    printf("SPTM attribute UPDATE: %u checks, %u failures\n",checks,failures);
    return !!failures;
}

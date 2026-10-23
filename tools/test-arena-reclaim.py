#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Table-arena pressure reclaim: the real monitor functions on the host.

table_alloc_owned, root_slot_release, arena_available, arena_reclaim,
arena_reserve and user_root_build are extracted verbatim from probes/xnuboot.c
and linked against the real compat/sptm-root.c (reclaim pick/forget) and
table-pool/private-page/view headers. The harness supplies only the context
fields they touch, a small arena of real host pages, a TLBI counter that can
be made to fail, a CPU-busy oracle and a stand-in for the shadow builder that
allocates a chosen number of tables through the real allocator.
"""
from pathlib import Path
import os
import re
import runpy
import subprocess
import tempfile
from source_text import read_source

ROOT = Path(__file__).resolve().parents[1]

HARNESS = r'''
#include "sptm-root.h"
#include "table-pool.h"
#include "sprr-view.h"
#include "sprr-private-pages.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define SNAP_ROOT_DIRTY_PUBLISH 0
#define SNAP_TXN_DIRTY_PUBLISH 0
#define SNAP_PRIVATE_VIEW_EPOCH 1
#define SNAP_KERNEL_CLASS_PROOF 0
#define SNAP_USER_VIEW_CACHE 1
#define SNAP_USER_TREE_MEMO 0
#define SNAP_NATIVE_WRITER_ADMISSION 0
#define SNAP_ARENA_RESERVE_PAGES 16u
#define ARENA_RETRY_PAGES 40u
#define SPTM_FN_SWITCH_ROOT 13
#define PAGES 64u
static unsigned checks;
#define CHECK(x) do {checks++;if(!(x)){fprintf(stderr,"FAIL %d: %s\n",__LINE__,#x);exit(1);}}while(0)
struct context;
struct user_table_owner {struct context *context; unsigned owner;};
struct context {
    uint64_t work_base,next_table,work_end,shadow_tlb_syncs,kernel_view_failed;
    struct table_pool table_pool;
    struct sprr_private_pages private_pages;
    struct sptm_root_state user_roots;
    struct sprr_views user_views[SPTM_ROOT_CACHE];
    struct sprr_view_memo user_view_memo[SPTM_ROOT_CACHE];
    struct sprr_view_proof user_view_proofs[SPTM_ROOT_CACHE];
    uint64_t user_view_epoch;
    struct user_table_owner user_table_owner[SPTM_ROOT_CACHE];
    uint64_t root_stamp[SPTM_ROOT_CACHE];
    /* ARENA_STATS */
};
static uint64_t busy_root,flush_fail,build_tables,build_fail_other,builds;
static void shadow_tlb_sync(struct context *c) {if(!flush_fail)c->shadow_tlb_syncs++;}
static int vcpu_root_busy(struct context *c,uint64_t root)
{(void)c;return root && root==busy_root;}
static int mem_read(void *ctx,uint64_t pa,uint64_t *out){(void)ctx;*out=*(volatile uint64_t *)pa;return 0;}
static int mem_write(void *ctx,uint64_t pa,uint64_t v){(void)ctx;*(volatile uint64_t *)pa=v;return 0;}
static int native_writer_admit_user(void *ctx,uint64_t va,uint64_t pa,uint64_t size,
    uint64_t low,uint64_t upper)
{(void)ctx;(void)va;(void)pa;(void)size;(void)low;(void)upper;return 1;}
static int harness_build_shadow(const struct sptm_memory *m,struct shadow *s,
    uint64_t root,unsigned format,unsigned flags,uint64_t *leaves)
{
    (void)m;(void)root;(void)format;(void)flags;builds++;
    if(build_fail_other)return 0;
    for(uint64_t n=0;n<build_tables;n++)if(!s->alloc(s->alloc_ctx))return 0;
    *leaves=build_tables;return 1;
}
/* FUNCTIONS */
static struct context c;
static uint8_t arena[(PAGES+1)*4096];
static uint32_t used(void){return (uint32_t)((c.next_table-c.work_base)/4096);}
static unsigned owned(unsigned owner)
{unsigned n=0;for(uint32_t i=0;i<used();i++)n+=c.table_pool.owner[i]==owner;return n;}
static unsigned marked(unsigned owner)
{
    unsigned n=0;
    for(uint32_t i=0;i<used();i++)
        n+=c.table_pool.owner[i]==owner && !!(c.private_pages.bitmap[i/64]&(UINT64_C(1)<<(i%64)));
    return n;
}
static int zeroed(const void *p,size_t n)
{const uint8_t *b=p;for(size_t i=0;i<n;i++)if(b[i])return 0;return 1;}
static void reset(void)
{
    memset(&c,0,sizeof c);memset(arena,0,sizeof arena);
    c.work_base=((uint64_t)(uintptr_t)arena+4095)&~UINT64_C(4095);
    c.next_table=c.work_base;c.work_end=c.work_base+PAGES*4096;
    c.table_pool.head=TABLE_POOL_MAX;
    for(unsigned i=0;i<SPTM_ROOT_CACHE;i++){c.user_table_owner[i].context=&c;c.user_table_owner[i].owner=i+1;}
    busy_root=flush_fail=build_fail_other=builds=0;build_tables=0;
}
/* A cached slot owning `pages` tables (one of them a marked private copy). */
static void cache(unsigned slot,uint64_t root,unsigned pages,unsigned valid,uint64_t stamp)
{
    uint64_t first=0;
    for(unsigned n=0;n<pages;n++) {
        uint64_t pa=n+1==pages && n ? private_table_alloc_owned(&c,slot+1) : table_alloc_owned(&c,slot+1);
        CHECK(pa);if(!n)first=pa;
    }
    c.user_roots.cache[slot]=(struct sptm_root_cached){.root=root,.shadow=first,.leaves=1,
        .asid=root ? 100+slot : 0,.valid=valid};
    c.root_stamp[slot]=stamp;
    c.user_views[slot].canonical_root=first;c.user_views[slot].count=1;
    c.user_view_memo[slot].root=first;c.user_view_proofs[slot].valid=1;
}
int main(void)
{
    uint64_t frame[31]={0};
    /* 1. Reserve at call entry: retired first, then oldest valid; never the
     *    active root, a CPU-busy root or a kernel page. */
    reset();
    for(unsigned n=0;n<4;n++)CHECK(table_alloc_owned(&c,0));        /* kernel */
    cache(0,0x100000,8,1,50);   /* valid, stamp 50 */
    cache(1,0x104000,8,1,10);   /* valid, oldest */
    cache(2,0,6,0,0);           /* retired, still holding a shadow */
    cache(3,0x10c000,8,1,5);    /* valid, older still, but active */
    cache(4,0x110000,8,1,7);    /* valid, but a CPU still holds it */
    cache(5,0x114000,8,1,30);   /* valid */
    cache(6,0x118000,8,0,40);   /* named but invalid */
    c.user_roots.active[2]=0x10c000;busy_root=0x110000;
    CHECK(arena_available(&c)==PAGES-58);
    uint64_t syncs=c.shadow_tlb_syncs;
    arena_reserve(&c,frame);
    /* 6 free -> need 24: retired slot2 (+6), invalid slot6 (+8), oldest
     * valid free slot1 (+8) = 28. */
    CHECK(arena_available(&c)==28 && c.arena_reclaim.low_water==6);
    CHECK(c.arena_reclaim.slots==3 && c.arena_reclaim.retired==1 &&
          c.arena_reclaim.invalid==1 && c.arena_reclaim.valid==1 && c.arena_reclaim.pages==22);
    CHECK(c.shadow_tlb_syncs==syncs+3 && !c.arena_reclaim.flush_failures);
    for(unsigned s=0;s<SPTM_ROOT_CACHE;s++) {
        int gone=s==1 || s==2 || s==6;
        const struct sptm_root_cached zero={0};
        if(gone) {
            CHECK(!memcmp(&c.user_roots.cache[s],&zero,sizeof zero) && !owned(s+1));
            CHECK(zeroed(&c.user_views[s],sizeof c.user_views[s]) &&
                  zeroed(&c.user_view_memo[s],sizeof c.user_view_memo[s]) && !c.user_view_proofs[s].valid);
        }
    }
    CHECK(owned(0)==4 && owned(1)==8 && !owned(2) && !owned(3) && owned(4)==8 &&
          owned(5)==8 && owned(6)==8 && !owned(7));
    CHECK(owned(4)==8 && c.user_roots.cache[3].valid && c.user_roots.cache[4].valid);
    CHECK(marked(1)==1 && marked(4)==1 && marked(5)==1);
    CHECK(c.table_pool.count==22 && owned(TABLE_POOL_FREE)==22);
    /* Reissued pages come back zeroed and unmarked to their new owner. */
    for(unsigned n=0;n<22;n++) {
        uint64_t pa=table_alloc_owned(&c,9);CHECK(pa && zeroed((void *)(uintptr_t)pa,4096));
        CHECK(!(c.private_pages.bitmap[((pa-c.work_base)/4096)/64]&(UINT64_C(1)<<(((pa-c.work_base)/4096)%64))));
    }
    CHECK(arena_available(&c)==6 && c.table_pool.count==0);
    /* 2. Above the reserve nothing is given back. */
    reset();cache(0,0x100000,8,1,1);uint64_t before=c.shadow_tlb_syncs;
    arena_reserve(&c,frame);
    CHECK(c.user_roots.cache[0].valid && owned(1)==8 && c.shadow_tlb_syncs==before && !c.arena_reclaim.reclaims);
    /* 3. SWITCH_ROOT never gives back its own target. */
    reset();
    for(unsigned s=0;s<7;s++)cache(s,0x100000+s*0x4000,8,1,s+1);     /* 8 free */
    frame[16]=SPTM_FN_SWITCH_ROOT;frame[0]=0x100000;                 /* the oldest */
    arena_reserve(&c,frame);
    CHECK(c.user_roots.cache[0].valid && owned(1)==8);
    CHECK(!c.user_roots.cache[1].valid && !owned(2) && !c.user_roots.cache[2].valid && !owned(3));
    CHECK(c.user_roots.cache[3].valid && owned(4)==8 && arena_available(&c)==24);
    frame[16]=0;frame[0]=0;
    /* 4. A TLBI that did not happen releases nothing: the slot is uncached
     *    (safe) and keeps its pages until its next build releases them. */
    reset();cache(0,0x100000,8,1,1);cache(1,0x104000,8,1,2);
    for(unsigned n=0;n<40;n++)CHECK(table_alloc_owned(&c,0));
    flush_fail=1;arena_reserve(&c,frame);
    CHECK(c.arena_reclaim.flush_failures==1 && !c.arena_reclaim.slots);
    CHECK(!c.user_roots.cache[0].root && !c.user_roots.cache[0].valid && owned(1)==8 && marked(1)==1);
    CHECK(c.user_roots.cache[1].valid && owned(2)==8);
    /* 5. A failed kernel view refresh disables reclaim entirely. */
    reset();cache(0,0x100000,8,1,1);for(unsigned n=0;n<50;n++)CHECK(table_alloc_owned(&c,0));
    c.kernel_view_failed=1;arena_reserve(&c,frame);
    CHECK(c.user_roots.cache[0].valid && owned(1)==8 && !c.arena_reclaim.reclaims);
    /* 6. A build the arena ran dry retries once after a reclaim; its own
     *    slot and partial tables are released first and rebuilt. */
    reset();
    for(unsigned s=0;s<5;s++)cache(s,0x100000+s*0x4000,10,1,s+1);  /* 50 */
    for(unsigned n=0;n<4;n++)CHECK(table_alloc_owned(&c,0));        /* 54 */
    /* Slot 5 is the SWITCH_ROOT entry: fresh, previous = 0. 30 tables + root. */
    build_tables=30;uint64_t result=0,leaves=0;
    CHECK(user_root_build(&c,0,0x200000,0,2,0,&result,&leaves)==1);
    CHECK(builds==2 && c.arena_reclaim.build_retries==1 && c.arena_reclaim.alloc_failures>=1);
    CHECK(result && owned(6)==31 && leaves==30);
    /* Oldest roots went first; the free target was ARENA_RETRY_PAGES (40). */
    CHECK(!owned(1) && !owned(2) && !owned(3) && !owned(4) && owned(5)==10 && owned(0)==4);
    /* 7. Other build failures are terminal, never retried. */
    reset();cache(0,0x100000,10,1,1);build_fail_other=1;build_tables=1;
    CHECK(user_root_build(&c,0,0x200000,0,2,0,&result,&leaves)==0);
    CHECK(builds==1 && !c.arena_reclaim.build_retries && c.user_roots.cache[0].valid);
    /* 8. A retry that still cannot fit fails terminally, after one retry. */
    reset();cache(0,0x100000,10,1,1);build_fail_other=0;build_tables=100;
    CHECK(user_root_build(&c,0,0x200000,0,2,0,&result,&leaves)==0);
    CHECK(builds==2 && c.arena_reclaim.build_retries==1 && !c.user_roots.cache[0].valid && !owned(1));
    printf("PASS: %u arena reclaim checks (monitor functions verbatim)\n",checks);
    return 0;
}
'''


def main():
    source = read_source(ROOT/'probes/xnuboot.c')
    extract = runpy.run_path(str(ROOT/'tools/test-guard-step.py'))['function']
    stats = re.search(r'    struct arena_reclaim_stats \{.*?\} arena_reclaim;', source, re.S).group(0)
    signatures = [
        'static uint64_t table_alloc_owned(struct context *c,unsigned owner)\n{',
        'static uint64_t user_table_alloc(void *ctx)\n{',
        'static uint64_t private_table_alloc_owned(struct context *c,unsigned owner)\n{',
        'static int root_slot_release(struct context *c,unsigned slot,int require_flush)\n{',
        'static uint64_t arena_available(const struct context *c)\n{',
        'static void arena_reclaim(struct context *c,uint64_t target,uint64_t exclude)\n{',
        'static void arena_reserve(struct context *c,const uint64_t *frame)\n{',
        'static int user_root_build(void *ctx,const struct sptm_memory *memory,']
    functions = '\n'.join(extract(source, s) for s in signatures)
    assert functions.count('sptm_root_build_shadow(') == 1
    functions = functions.replace('sptm_root_build_shadow(', 'harness_build_shadow(')
    program = HARNESS.replace('/* ARENA_STATS */', stats).replace('/* FUNCTIONS */', functions)
    compat = [str(p) for p in sorted((ROOT/'compat').glob('*.c'))
              if 'native' not in p.name]
    shadow = [str(ROOT/'shadow'/n) for n in ('mmu.c', 'shadow.c', 'sprr-view.c')]
    with tempfile.TemporaryDirectory(prefix='arena-reclaim-') as directory:
        src = Path(directory)/'test.c'; exe = Path(directory)/'test'
        src.write_text(program)
        subprocess.run([os.environ.get('CC', 'clang'), '-std=gnu11', '-O1', '-g',
                        '-fsanitize=address,undefined', '-Wall', '-Wextra', '-Werror',
                        '-Wno-unused-function', f'-I{ROOT/"compat"}', f'-I{ROOT/"shadow"}',
                        str(src), *compat, *shadow, '-Wl,-dead_strip', '-o', str(exe)], check=True)
        subprocess.run([str(exe)], check=True)


if __name__ == '__main__':
    main()

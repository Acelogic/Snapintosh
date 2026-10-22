/* SPDX-License-Identifier: MIT */
/* The SPTM operation x frame-type x options matrix against Apple's rules.
 *
 * tools/replay-sptm-matrix.py drives the modes below and replays Apple's own
 * UPDATE helper (sptm.t8140.release ...270fd544) over every permission cell;
 * the default mode pins the cells a GUI boot reaches:
 *   --batch    stdin "old requested options type kernel" -> "status next"
 *   --tables   the C policy bitmaps, permission rows and retype matrix
 * Default: selection, leaf policy, device-window lifecycle and retype gate. */
#define main tpro_lifecycle_tests
#include "test-user-tpro.c"
#undef main
#include <stdlib.h>
#include "sptm-nx-update.h"

#define IO UINT64_C(0xb0000000)
#define IO_SIZE 0x10000u
/* User leaves: class7 = AP 01 (0x40), class15 = AP 11 (0xc0); PXN|UXN; nG. */
#define USER_RW 0x0060000000000c43UL
#define USER_RO 0x0060000000000cc3UL

static uint64_t leaf(uint64_t pa,unsigned cls,int af)
{
    return pa|3|0x800|0x200|(af ? 0x400UL:0)|((uint64_t)(cls&12)<<4)|
        ((uint64_t)(cls&3)<<53)|((uint64_t)(cls>>4)<<59);
}
static void select_cell(unsigned type,unsigned from,unsigned to,uint64_t options,
                        enum sptm_result status,unsigned expect)
{
    uint64_t next=0,old=leaf(DATA,from,1),req=leaf(DATA,to,1);
    enum sptm_result r=sptm_mac_user_update_typed(old,req,options,type,&next);
    CHECK(r==status);
    if(r==SPTM_OK && status==SPTM_OK)CHECK(next==leaf(DATA,expect,1));
    if(r!=status || (r==SPTM_OK && next!=leaf(DATA,expect,1)))
        printf("  cell type%u %u->%u opt %llx: %u %016llx\n",type,from,to,
               (unsigned long long)options,r,(unsigned long long)next);
}
static void test_selection(void)
{
    /* Executable code write-protection (mprotect(PROT_READ) of text): row
     * 13 applies 15; the reverse is an ignored (no-op) row for type14 but a
     * policy violation for DEFAULT, whose 0x8888 lacks class 13. */
    select_cell(14,13,15,2,SPTM_OK,15);
    select_cell(14,15,13,2,SPTM_OK,15);
    select_cell(11,15,13,2,SPTM_UNSUPPORTED_OPTIONS,0);
    select_cell(14,13,7,2,SPTM_UNSUPPORTED_OPTIONS,0);
    /* TPRO (type17): write-protect/history rows 9->15/25, 25->9, 7->23/31
     * and fault restoration 31->7 with option800 only. */
    select_cell(17,9,15,2,SPTM_OK,15);
    select_cell(17,9,25,2,SPTM_OK,25);
    select_cell(17,25,9,2,SPTM_OK,9);
    select_cell(17,7,31,0x10a,SPTM_OK,31);
    select_cell(17,31,7,0xa,SPTM_OK,31);
    select_cell(17,31,7,0xc0a,SPTM_OK,7);
    select_cell(17,9,7,2,SPTM_UNSUPPORTED_OPTIONS,0);
    select_cell(17,15,9,2,SPTM_OK,15);
    /* JIT rows exist (type16 policy 0x8828) even though JIT retype is not
     * admitted yet: 5->15 and the history toggle 5->21. */
    select_cell(16,5,15,2,SPTM_OK,15);
    select_cell(16,5,21,2,SPTM_OK,21);
    select_cell(16,5,7,2,SPTM_UNSUPPORTED_OPTIONS,0);
    /* DEFAULT user rows are unchanged from the earlier NX-domain engine. */
    select_cell(11,7,15,2,SPTM_OK,15);select_cell(11,7,31,0xa,SPTM_OK,31);
    select_cell(11,15,7,2,SPTM_OK,15);select_cell(11,31,7,0x802,SPTM_OK,7);
    /* Types without a mapping policy are refused. */
    select_cell(20,7,15,2,SPTM_TYPE_MISMATCH,0);select_cell(18,7,15,2,SPTM_TYPE_MISMATCH,0);
    /* nG (option 4) stays refused here. SH (0x10) and AttrIndx (0x20) copy
     * exactly their template bits, any value, whatever the permission row
     * does (...fd5a8/fd5c0; tools/replay-sptm-matrix.py compares Apple). */
    {
        uint64_t next;
        CHECK(sptm_mac_user_update_typed(leaf(DATA,7,1),leaf(DATA,7,1),6,11,&next)==
              SPTM_UNSUPPORTED_OPTIONS);
        for(unsigned attr=0;attr<8;attr++)for(unsigned sh=0;sh<4;sh++)
        for(uint64_t o=0x10;o<=0x30;o+=0x10) {
            uint64_t old=leaf(DATA,7,1),req=(leaf(DATA,15,1)&~0x31cUL)|((uint64_t)attr<<2)|((uint64_t)sh<<8);
            uint64_t want=old;
            if(o&0x10)want=(want&~0x300UL)|((uint64_t)sh<<8);
            if(o&0x20)want=(want&~0x1cUL)|((uint64_t)attr<<2);
            CHECK(sptm_mac_user_update_typed(old,req,o,11,&next)==SPTM_OK && next==want);
            CHECK(sptm_mac_user_update_typed(old,req,o|2,11,&next)==SPTM_OK &&
                  next==((want&~0x08680000000000c0UL)|(req&0x08680000000000c0UL)));
            CHECK(sptm_nx_update_pte(leaf(DATA,3,1),(req&~0x0060000000000cc0UL)|
                  (leaf(DATA,3,1)&0x0060000000000cc0UL),o|0x100,&next,0)==SPTM_OK &&
                  ((next^leaf(DATA,3,1))&~0x31cUL)==0 && (next&0x31cUL)==(want&0x31cUL));
        }
        /* Bit5 (NS) is copied only in stage-2 tables, never here. */
        CHECK(sptm_nx_update_pte(leaf(DATA,3,1),leaf(DATA,3,1)|(1UL<<5)|(7UL<<2),0x30,&next,0)==
              SPTM_OK && next==(leaf(DATA,3,1)|(7UL<<2)));
        CHECK(sptm_mac_user_update_typed(leaf(DATA,7,1),leaf(DATA,7,1),0x100,11,&next)==
              SPTM_UNSUPPORTED_OPTIONS);
        CHECK(sptm_mac_user_update_typed(leaf(DATA,7,1),leaf(DATA,7,1),0x230,11,&next)==
              SPTM_UNSUPPORTED_OPTIONS);
    }
    /* Kernel wrapper keeps the natively enforced NX classes 3/11. Only a
     * WAS_WRITABLE toggle on an unchanged 4-bit class is newly admitted. */
    uint64_t next;
    CHECK(sptm_nx_update_pte(leaf(DATA,3,1)&~0x800UL,leaf(DATA,11,1)&~0x800UL,2,&next,0)==SPTM_OK &&
          next==(leaf(DATA,11,1)&~0x800UL));
    CHECK(sptm_nx_update_pte(leaf(DATA,3,1),leaf(DATA,7,1),2,&next,0)==SPTM_UNSUPPORTED_OPTIONS);
    CHECK(sptm_nx_update_pte(leaf(DATA,11,1),leaf(DATA,3,1),2,&next,0)==SPTM_OK &&
          next==leaf(DATA,11,1));
    CHECK(sptm_nx_update_pte(leaf(DATA,13,1),leaf(DATA,15,1),2,&next,0)==SPTM_UNSUPPORTED_OPTIONS);
    /* bit51 is never produced or accepted. */
    CHECK(sptm_mac_user_update_typed(leaf(DATA,7,1)|(1UL<<51),leaf(DATA,15,1),2,11,&next)!=SPTM_OK);
}
static void test_leaf_policy(void)
{
    for(unsigned format=0;format<2;format++) {
        struct sptm_user_geometry g;CHECK(sptm_mac_user_geometry(format,0xa,&g));
        uint64_t pa=IO,va=0x4000;
        for(unsigned type=0;type<2;type++) {
            unsigned t=type ? SPTM_MAC_IO : SPTM_MAC_DEFAULT;
            for(unsigned attr=0;attr<8;attr++)for(unsigned sh=0;sh<4;sh++)
            for(unsigned ro=0;ro<2;ro++) {
                uint64_t pte=pa|(ro ? USER_RO:USER_RW)|((uint64_t)attr<<2);
                pte=(pte&~0x300UL)|((uint64_t)sh<<8);
                CHECK(sptm_mac_user_leaf_policy(0xa,20,t,va,pte,&g)==SPTM_OK);
                CHECK(sptm_mac_user_leaf_policy(0xa,20,t,va,pte|(3UL<<58),&g)==SPTM_OK);
            }
            uint64_t pte=pa|USER_RW|(1UL<<2);
            CHECK(sptm_mac_user_leaf_policy(0xa,20,t,va,pte&~0x800UL,&g)!=SPTM_OK);   /* global */
            CHECK(sptm_mac_user_leaf_policy(0xa,20,t,va,pte&~0x40UL,&g)!=SPTM_OK);    /* class3 */
            CHECK(sptm_mac_user_leaf_policy(0xa,20,t,va,pte&~(1UL<<54),&g)!=SPTM_OK);/* UXN */
            CHECK(sptm_mac_user_leaf_policy(0xa,20,t,va,pte&~(1UL<<53),&g)!=SPTM_OK);/* PXN */
            CHECK(sptm_mac_user_leaf_policy(0xa,20,t,va,pte|(1UL<<52),&g)!=SPTM_OK); /* contiguous */
            CHECK(sptm_mac_user_leaf_policy(0xa,20,t,va,pte|(1UL<<55),&g)!=SPTM_OK);
            CHECK(sptm_mac_user_leaf_policy(0xa,20,t,va,pte|(1UL<<5),&g)!=SPTM_OK);  /* NS */
        }
        /* The device window never enters shared or commpage tables. */
        CHECK(sptm_mac_user_leaf_policy(0xa,21,SPTM_MAC_IO,va,pa|USER_RW,&g)!=SPTM_OK);
        CHECK(sptm_mac_user_leaf_policy(0xa,23,SPTM_MAC_IO,0xfffff0000UL,pa|USER_RW,&g)!=SPTM_OK);
        /* Software bits: WIRED on exec/TPRO; history on TPRO only. */
        uint64_t rx=DATA|0x0020000000000fc3UL,tpro=DATA|0x0020000000000f83UL;
        CHECK(sptm_mac_user_leaf_policy(0xa,20,14,va,rx|(1UL<<58),&g)==SPTM_OK);
        CHECK(sptm_mac_user_leaf_policy(0xa,20,14,va,rx|(1UL<<59),&g)!=SPTM_OK);
        CHECK(sptm_mac_user_leaf_policy(0xa,20,14,va,rx|(1UL<<2),&g)!=SPTM_OK);
        CHECK(sptm_mac_user_leaf_policy(0xa,20,17,va,tpro|(3UL<<58),&g)==SPTM_OK);
        CHECK(sptm_mac_user_leaf_policy(0xa,20,17,va,(DATA|USER_RO|0x300)|(3UL<<58),&g)==SPTM_OK);
        CHECK(sptm_mac_user_leaf_policy(0x2,20,17,va,tpro|(1UL<<59),&g)!=SPTM_OK);
    }
}
static int prepare_remove_update(void *ctx,uint64_t root,uint64_t va,unsigned shift,
                                 uint64_t old,uint64_t next)
{(void)ctx;(void)old;(void)next;CHECK(root==ROOT);
 return sptm_root_prepare_unmap(&cache,&hw,live_memory,va,shift,1);}
static int commit_live_update(void *ctx,uint64_t root,uint64_t va,unsigned shift,
                              uint64_t old,uint64_t next)
{(void)ctx;CHECK(root==ROOT);
 return sptm_root_commit_update(&cache,&hw,live_memory,va,shift,old,next) && sync_views();}
static void record_at(uint64_t at,uint64_t root,uint64_t va,uint64_t pte)
{put(at,root,8);put(at+8,va,8);put(at+16,pte,8);}
static int map_inactive(struct sptm_memory *m,uint64_t va,uint64_t pte,uint64_t *result)
{
    struct sptm_user_backend b={0};
    return sptm_mac_map_user_page(m,&b,ROOT,va,pte,1,0,result);
}
static void test_device_window(void)
{
    for(unsigned format=0;format<2;format++)for(unsigned active=0;active<2;active++) {
        struct sptm_memory m=setup(format);
        unsigned shift=format ? 12:14;uint64_t size=1UL<<shift,result=99;
        struct mmu_config src={shift,17,ROOT};struct mmu_leaf l;
        /* No window: an out-of-DRAM leaf is refused without mutation. */
        uint64_t wc=IO|USER_RW|(1UL<<2);   /* write-combined panel VRAM */
        memcpy(before,ram,sizeof ram);unsigned n=published;
        CHECK(map_inactive(&m,VA,wc,&result)==SPTM_BAD_ADDRESS && result==99);
        CHECK(!memcmp(before,ram,sizeof ram) && n==published);
        /* A window overlapping frame metadata is never admitted. */
        m.user_io_pa=BASE;m.user_io_size=SIZE;
        CHECK(!sptm_user_io_frame(&m,DATA,size));
        m.user_io_pa=IO;m.user_io_size=IO_SIZE;
        CHECK(sptm_user_io_frame(&m,IO,size) && !sptm_user_io_frame(&m,IO+IO_SIZE,size));
        CHECK(!sptm_user_io_frame(&m,IO+IO_SIZE-size,2*size) && !sptm_user_io_frame(&m,IO+1,size));
        m.user_io_pa=IO+0x1000;
        CHECK(!sptm_user_io_frame(&m,IO+0x4000,size));   /* window must be 16K aligned */
        m.user_io_pa=IO;
        struct sptm_user_backend b={.aperture={BASE,0xfffffe0100000000UL,SIZE}};
        if(active) {
            memset(hw_ram,0,sizeof hw_ram);memset(&cpu_views,0,sizeof cpu_views);
            memset(cpu_states,0,sizeof cpu_states);hw_next=HW_BASE+4096;live_memory=&m;
            hw=(struct shadow){.txsz=17,.root=HW_BASE,.alloc=hw_alloc,.read=hw_read,.write=hw_write};
            cache=(struct sptm_root_cached){.root=ROOT,.shadow=HW_BASE,.asid=8,.format=format,
                .flags=0xa,.valid=1};
            CHECK(sptm_root_build_shadow(&m,&hw,ROOT,format,0xa,&cache.leaves) && !cache.leaves);
            CHECK(sprr_views_init(&cpu_views,&hw) && sprr_views_prepare_user(&cpu_views,&hw));
            for(unsigned cpu=0;cpu<6;cpu++)sprr_root_reset(&cpu_states[cpu],0xa);
            CHECK(sync_views());
            b.ttbr0=ROOT;b.active_refs=6;b.prepare_leaf=prepare_live;b.commit_leaf=commit_live;
            b.prepare_unmap=prepare_remove;b.commit_unmap=commit_remove;
            put(meta(ROOT)+6,get(meta(ROOT)+6,2)+6,2);
        }
        uint64_t l3=get(meta(L3)+8,2),data_refs=get(meta(DATA)+8,8);
        CHECK(sptm_mac_map_user_page(&m,&b,ROOT,VA,wc,0,BASE,&result)==SPTM_OK && !result);
        CHECK(!mmu_walk(&src,VA,read64,0,&l) && l.valid && l.descriptor==wc);
        CHECK(get(meta(L3)+8,2)==l3+1 && get(meta(DATA)+8,8)==data_refs);
        CHECK(get(BASE,8)==0);
        CHECK(sptm_mac_map_user_page(&m,&b,ROOT,VA,wc,0,BASE,&result)==SPTM_OK && result==1);
        if(active) {
            /* Hardware and every private CPU view carry the device leaf with
             * its attributes; the monitor never dereferenced it. */
            struct mmu_config cfg={12,17,HW_BASE};
            for(uint64_t off=0;off<size;off+=4096) {
                CHECK(!mmu_walk(&cfg,VA+off,hw_read,0,&l) && l.valid && l.pa==IO+off &&
                      (l.descriptor&(PT_ATTRINDX|PT_AP|PT_PXN|PT_UXN|PT_NG))==
                      (wc&(PT_ATTRINDX|PT_AP|PT_PXN|PT_UXN|PT_NG)));
                for(unsigned cpu=0;cpu<6;cpu++) {
                    struct mmu_config v={12,17,sprr_views_root(&cpu_views,cpu)};
                    CHECK(!mmu_walk(&v,VA+off,hw_read,0,&l) && l.valid && l.pa==IO+off);
                }
            }
            CHECK(cache.leaves==1);
        } else {
            /* A later root switch rebuilds the shadow from the source. */
            struct shadow s2={.txsz=17,.root=HW_BASE,.alloc=hw_alloc,.read=hw_read,.write=hw_write};
            memset(hw_ram,0,sizeof hw_ram);hw_next=HW_BASE+4096;uint64_t leaves=0;
            CHECK(sptm_root_build_shadow(&m,&s2,ROOT,format,0xa,&leaves) && leaves==1);
        }
        /* Refusals leave the source unchanged: executable, kernel-only,
         * global, or crossing the end of the window. */
        uint64_t bad[]={(IO+size)|0x0020000000000cc3UL,(IO+size)|(USER_RW&~0x40UL),
                        (IO+size)|(USER_RW&~0x800UL),(IO+IO_SIZE)|USER_RW};
        for(unsigned i=0;i<4;i++) {
            memcpy(before,ram,sizeof ram);n=published;
            CHECK(sptm_mac_map_user_page(&m,&b,ROOT,VA+size,bad[i],1,0,&result)!=SPTM_OK);
            CHECK(!memcmp(before,ram,sizeof ram) && n==published);
        }
        /* mprotect/page aging reach UPDATE_REGION with DEFAULT's rows. */
        uint64_t templates=BASE+0x30000,out=BASE,guest=0;
        struct sptm_user_update_state st={0};
        if(active) {b.prepare_update=prepare_remove_update;b.commit_update=commit_live_update;}
        put(templates,wc&~0x400UL,8);
        CHECK(sptm_mac_update_user_region(&m,&b,ROOT,VA,1,templates,0x10a,out,&guest,&st)==SPTM_OK);
        CHECK(!mmu_walk(&src,VA,read64,0,&l) && l.descriptor==(wc&~0x400UL) && guest==5);
        CHECK(get(out,8)==wc);
        put(templates,(wc|0x80)&~0x400UL,8);
        CHECK(sptm_mac_update_user_region(&m,&b,ROOT,VA,1,templates,2,out,&guest,&st)==SPTM_OK);
        CHECK(!mmu_walk(&src,VA,read64,0,&l) && l.descriptor==((wc|0x80)&~0x400UL));
        /* A device page has no frame state for UPDATE_DISJOINT/UNMAP_DISJOINT. */
        uint64_t list=BASE+0x30000;put(list,ROOT,8);put(list+8,VA,8);put(list+16,wc,8);
        CHECK(sptm_mac_update_user_disjoint(&m,resolve_inactive,0,IO,list,1,0x10a,BASE,&out,&st)!=SPTM_OK);
        uint64_t removed=(wc|0x80)&~0x400UL;
        CHECK(sptm_mac_unmap_user_region(&m,&b,ROOT,VA,1,1,BASE)==SPTM_OK);
        CHECK(get(BASE,8)==removed && get(meta(L3)+8,2)==l3 && get(meta(DATA)+8,8)==data_refs);
        CHECK(!mmu_walk(&src,VA,read64,0,&l) && !l.valid);
        if(active) {
            struct mmu_config cfg={12,17,HW_BASE};
            CHECK(!mmu_walk(&cfg,VA,hw_read,0,&l) && !l.valid && !cache.leaves);
        }
    }
}
static void test_retype_matrix(void)
{
    unsigned supported=0;
    for(unsigned o=0;o<64;o++)for(unsigned n=0;n<64;n++)if(sptm_mac_retype_supported(o,n)) {
        supported++;CHECK(sptm_mac_apple_retype(o,n));
    }
    /* 13 DEFAULT acquisitions, 7 releases, share, shared release, reset, TXM donation. */
    CHECK(supported==24);
    CHECK(!sptm_mac_retype_supported(22,11) && !sptm_mac_apple_retype(22,11));
    struct sptm_memory m=setup(0);
    CHECK(sptm_mac_retype(&m,DATA,11,22,3)==SPTM_OK);
    reject_retype(&m,22,11,0,SPTM_UNSUPPORTED_RETYPE);
    /* Apple-admitted transitions this monitor still refuses (the retype gap
     * list in docs): JIT/debug user code, cputrace, TXM donation, IOMMU and
     * commpage/SK frames. */
    const unsigned gaps[][2]={{11,15},{11,16},{11,37},{24,11},{37,11},{15,11},
                              {16,11},{35,35}};
    for(unsigned i=0;i<sizeof gaps/sizeof*gaps;i++)
        CHECK(sptm_mac_apple_retype(gaps[i][0],gaps[i][1]) &&
              !sptm_mac_retype_supported(gaps[i][0],gaps[i][1]));
}
static void header(uint64_t at,uint64_t pa,uint64_t attr,uint32_t n,uint32_t options)
{put(at,pa,8);put(at+8,attr,8);put(at+16,n,4);put(at+20,options,4);}
static void test_multipage(void)
{
    const uint64_t ops=BASE+0x34000;
    struct sptm_memory m=setup(0);struct sptm_multipage_plan plan;
    /* phys_attribute_clear's flush-range batch: two frames, the second with
     * two mappings; a zero-mapping header contributes no group. */
    header(ops,DATA,0,1,0x10a|0x200);record_at(ops+24,ROOT,VA,0);
    header(ops+48,L1,0,0,0xa|0x200);
    header(ops+72,DATA+0x4000,0,2,0xa|0x200);
    record_at(ops+96,ROOT,VA+0x4000,0);record_at(ops+120,ROOT,VA+0x8000,0);
    CHECK(sptm_mac_multipage_plan(&m,ops,6,&plan)==SPTM_OK && plan.groups==2);
    CHECK(plan.group[0].target==DATA && plan.group[0].list==ops+24 &&
          plan.group[0].count==1 && plan.group[0].options==0x10a);
    CHECK(plan.group[1].target==DATA+0x4000 && plan.group[1].list==ops+96 &&
          plan.group[1].count==2 && plan.group[1].options==0xa);
    CHECK(!plan.group[0].aperture_flags && !plan.group[1].aperture_flags);
    /* pmap_batch_set_cache_attributes: a frame's first header (0x130, no
     * 0x200) carries the aperture step, flags 2|0x80 with AttrIndx bits4:2 of
     * its attribute word; continuations (0x330) do not. The gen66 stop was
     * the first such header of a full 64-record batch. */
    header(ops,DATA,0x0060000000000004UL,1,0x130);
    CHECK(sptm_mac_multipage_plan(&m,ops,2,&plan)==SPTM_OK && plan.groups==1);
    CHECK(plan.group[0].aperture_flags==0x82 && plan.group[0].aperture_attr==1 &&
          plan.group[0].options==0x130 && plan.group[0].count==1 && plan.group[0].list==ops+24);
    header(ops,DATA,0x40f,1,0x330);
    CHECK(sptm_mac_multipage_plan(&m,ops,2,&plan)==SPTM_OK && plan.groups==1);
    CHECK(!plan.group[0].aperture_flags && plan.group[0].options==0x130);
    const uint64_t frames[8]={DATA,BASE+0x1c000,BASE+0x20000,BASE+0x24000,
                              BASE+0x28000,BASE+0x2c000,BASE+0x38000,BASE+0x3c000};
    for(unsigned f=0;f<8;f++) {
        uint64_t at=ops+f*8*24;
        header(at,frames[f],0x0060000000000000UL|((uint64_t)f<<2),3,0x130);
        header(at+4*24,frames[f],0x0060000000000004UL,3,0x330);
        for(unsigned r=0;r<3;r++) {
            record_at(at+(1+r)*24,ROOT,VA+r*0x4000,0);record_at(at+(5+r)*24,ROOT,VA+r*0x4000,0);
        }
    }
    CHECK(sptm_mac_multipage_plan(&m,ops,64,&plan)==SPTM_OK && plan.groups==16);
    for(unsigned g=0;g<16;g++)
        CHECK(plan.group[g].target==frames[g/2] && plan.group[g].count==3 &&
              plan.group[g].options==0x130 &&
              plan.group[g].aperture_flags==(g&1 ? 0u : 0x82u) &&
              (g&1 || plan.group[g].aperture_attr==g/2));
    /* A zero-mapping header still has its aperture step; flag 0x80 alone
     * (0x100 without 0x20) is a pure deferral; no flag at all is refused. */
    header(ops,DATA,0x4,0,0x130);header(ops+24,DATA+0x4000,0,0,0x110);
    CHECK(sptm_mac_multipage_plan(&m,ops,2,&plan)==SPTM_OK && plan.groups==2);
    CHECK(!plan.group[0].count && plan.group[0].aperture_flags==0x82 &&
          !plan.group[1].count && plan.group[1].aperture_flags==0x80);
    header(ops+24,DATA+0x4000,0,0,0x10);
    CHECK(sptm_mac_multipage_plan(&m,ops,2,&plan)==SPTM_UNSUPPORTED_OPTIONS);
    header(ops+24,DATA+0x4000,0,0,0x30);
    CHECK(sptm_mac_multipage_plan(&m,ops,2,&plan)==SPTM_OK &&
          plan.group[1].aperture_flags==2);
    /* The aperture step only for a quiescent, managed DEFAULT frame. */
    header(ops,L3,0x4,0,0x130);
    CHECK(sptm_mac_multipage_plan(&m,ops,1,&plan)==SPTM_TYPE_MISMATCH);
    header(ops,BASE,0x4,0,0x130);
    CHECK(sptm_mac_multipage_plan(&m,ops,1,&plan)==SPTM_BAD_ADDRESS);
    header(ops,DATA+8,0x4,0,0x130);
    CHECK(sptm_mac_multipage_plan(&m,ops,1,&plan)==SPTM_BAD_ADDRESS);
    put(meta(DATA)+1,1,1);header(ops,DATA,0x4,0,0x130);
    CHECK(sptm_mac_multipage_plan(&m,ops,1,&plan)==SPTM_FRAME_BUSY);
    put(meta(DATA)+1,0,1);
    /* The engine's options still apply to the records: nG, an empty set and
     * bits outside it are refused. */
    header(ops,DATA,0x4,1,0x134);
    CHECK(sptm_mac_multipage_plan(&m,ops,2,&plan)==SPTM_UNSUPPORTED_OPTIONS);
    header(ops,DATA,0x4,1,0x140|0x200);
    CHECK(sptm_mac_multipage_plan(&m,ops,2,&plan)==SPTM_UNSUPPORTED_OPTIONS);
    header(ops,DATA,0,1,0x200);
    CHECK(sptm_mac_multipage_plan(&m,ops,2,&plan)==SPTM_UNSUPPORTED_OPTIONS);
    header(ops,DATA,0,2,0x10a|0x200);
    CHECK(sptm_mac_multipage_plan(&m,ops,2,&plan)==SPTM_BAD_ADDRESS);
    header(ops,DATA,0,1,0x10a|0x200);
    CHECK(sptm_mac_multipage_plan(&m,ops,0,&plan)==SPTM_BAD_ADDRESS);
    CHECK(sptm_mac_multipage_plan(&m,ops,65,&plan)==SPTM_BAD_ADDRESS);
    CHECK(sptm_mac_multipage_plan(&m,ops+0x3ff0,2,&plan)==SPTM_BAD_ADDRESS);
    CHECK(sptm_mac_multipage_plan(&m,ops+4,2,&plan)==SPTM_BAD_ADDRESS);
    /* A group is exactly one UPDATE_DISJOINT: page aging on a mapped frame. */
    struct sptm_user_backend b={0};uint64_t result=99,out=0;
    uint64_t pte=DATA|0x0060000000000f43UL;
    CHECK(sptm_mac_map_user_page(&m,&b,ROOT,VA,pte,1,0,&result)==SPTM_OK && !result);
    header(ops,DATA,0,1,0x10a|0x200);record_at(ops+24,ROOT,VA,pte&~0x400UL);
    CHECK(sptm_mac_multipage_plan(&m,ops,2,&plan)==SPTM_OK && plan.groups==1);
    struct sptm_user_update_state st={0};
    CHECK(sptm_mac_update_user_disjoint(&m,resolve_inactive,0,plan.group[0].target,
          plan.group[0].list,plan.group[0].count,plan.group[0].options,BASE,&out,&st)==SPTM_OK);
    struct mmu_config src={14,17,ROOT};struct mmu_leaf l;
    CHECK(out==5 && !mmu_walk(&src,VA,read64,0,&l) && l.descriptor==(pte&~0x400UL));
}
static int batch(void)
{
    char line[256];
    while(fgets(line,sizeof line,stdin)) {
        uint64_t old,req,opt;unsigned type,kernel;uint64_t next=0;
        if(sscanf(line,"%llx %llx %llx %x %x",(unsigned long long *)&old,
                  (unsigned long long *)&req,(unsigned long long *)&opt,&type,&kernel)!=5)return 2;
        enum sptm_result r=kernel ? sptm_nx_update_pte(old,req,opt,&next,0) :
            sptm_mac_user_update_typed(old,req,opt,type,&next);
        printf("%u %016llx\n",r,(unsigned long long)next);
    }
    return 0;
}
static void tables(void)
{
    for(unsigned t=0;t<68;t++)printf("policy %u %x\n",t,sptm_mac_type_policy(t));
    for(unsigned c=0;c<32;c++)printf("rows %u %x %x %x\n",c,sptm_update_allowed[c],
                                     sptm_update_ignored[c],sptm_update_fault[c]);
    for(unsigned o=0;o<48;o++) {
        uint64_t apple=0,mon=0;
        for(unsigned n=0;n<64;n++) {
            apple|=(uint64_t)sptm_mac_apple_retype(o,n)<<n;
            mon|=(uint64_t)sptm_mac_retype_supported(o,n)<<n;
        }
        printf("retype %u %llx %llx\n",o,(unsigned long long)apple,(unsigned long long)mon);
    }
}
int main(int argc,char **argv)
{
    if(argc==2 && !strcmp(argv[1],"--batch"))return batch();
    if(argc==2 && !strcmp(argv[1],"--tables")) {tables();return 0;}
    test_selection();test_leaf_policy();test_device_window();test_retype_matrix();
    test_multipage();
    printf("SPTM_MATRIX: %u checks, %u failures\n",checks,failures);
    return !!failures;
}

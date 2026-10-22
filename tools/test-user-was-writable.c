/* SPDX-License-Identifier: MIT */
/* Reuse typed source RAM and the real canonical/private view callbacks. */
#define main tpro_lifecycle_tests
#include "test-user-tpro.c"
#undef main
#define HISTORY (1UL<<59)

static void view_check(uint64_t va,uint64_t pa,unsigned shift,int present)
{
    for(unsigned cpu=0;cpu<7;cpu++)for(uint64_t off=0;off<(1UL<<shift);off+=4096) {
        struct mmu_config cfg={12,17,cpu==6 ? hw.root : sprr_views_root(&cpu_views,cpu)};
        struct mmu_leaf l;
        CHECK(!mmu_walk(&cfg,va+off,hw_read,0,&l) && l.valid==present);
        if(present) {
            CHECK(l.pa==pa+off);
            CHECK((l.descriptor&(PT_AP|PT_PXN|PT_UXN))==(PT_AP|PT_PXN|PT_UXN));
            CHECK(!(l.descriptor&HISTORY));
        }
    }
}

int main(void)
{
    for(unsigned format=0;format<2;format++)
    for(unsigned part=0;part<(format?4:1);part++)for(unsigned sh=2;sh<4;sh++) {
        struct sptm_memory m=setup(format);
        unsigned shift=format?12:14;uint64_t size=1UL<<shift;
        uint64_t va=VA+part*4096,pa=DATA+part*4096;
        uint64_t pte=pa|0x0060000000000cc3UL|((uint64_t)sh<<8)|HISTORY,result=99;
        struct sptm_user_backend b={.aperture={BASE,0xfffffe0100000000UL,SIZE}};
        CHECK(sptm_mac_map_user_page(&m,&b,ROOT,va,pte,0,BASE,&result)==SPTM_OK && !result);
        struct mmu_config src={shift,17,ROOT};struct mmu_leaf leaf;
        CHECK(!mmu_walk(&src,va,read64,0,&leaf) && leaf.descriptor==pte);
        CHECK(get(meta(DATA)+8,4)==0 && get(meta(DATA)+12,4)==1 && get(meta(L3)+8,2)==1);
        CHECK(get(BASE,8)==0 && get(BASE+8,8)>=b.aperture.va);
        CHECK(sptm_mac_map_user_page(&m,&b,ROOT,va,pte,0,BASE,&result)==SPTM_OK && result==1);
        CHECK(get(BASE,8)==pte && get(meta(DATA)+12,4)==1);
        /* Build a cached root from the software descriptor, then exercise
         * insertion/removal with all six private CPU views active. */
        memset(hw_ram,0,sizeof hw_ram);memset(&cpu_views,0,sizeof cpu_views);
        memset(cpu_states,0,sizeof cpu_states);hw_next=HW_BASE+4096;live_memory=&m;
        hw=(struct shadow){.txsz=17,.root=HW_BASE,.alloc=hw_alloc,.read=hw_read,.write=hw_write};
        cache=(struct sptm_root_cached){.root=ROOT,.shadow=HW_BASE,.asid=8,.format=format,.flags=0xa,.valid=1};
        CHECK(sptm_root_build_shadow(&m,&hw,ROOT,format,0xa,&cache.leaves) && cache.leaves==1);
        CHECK(sprr_views_init(&cpu_views,&hw) && sprr_views_prepare_user(&cpu_views,&hw));
        for(unsigned cpu=0;cpu<6;cpu++)sprr_root_reset(&cpu_states[cpu],0xa);
        CHECK(sync_views());view_check(va,pa,shift,1);
        struct sptm_fixed_view proof;
        CHECK(sptm_root_canonical_view(&cache,&hw,&m,&proof));
        CHECK(sptm_root_fixed_view(&cache,&hw,&m,&proof));
        b.ttbr0=ROOT;b.active_refs=6;b.prepare_leaf=prepare_live;b.commit_leaf=commit_live;
        b.prepare_unmap=prepare_remove;b.commit_unmap=commit_remove;
        put(meta(ROOT)+6,get(meta(ROOT)+6,2)+6,2);
        uint64_t alias=VA+0x8000;
        CHECK(sptm_mac_map_user_page(&m,&b,ROOT,alias,pte,1,0,&result)==SPTM_OK && !result);
        CHECK(get(meta(DATA)+12,4)==2);view_check(alias,pa,shift,1);
        CHECK(sptm_mac_map_user_page(&m,&b,ROOT,alias+size,pte&~HISTORY,1,0,&result)==SPTM_OK);
        CHECK(get(meta(DATA)+8,4)==1 && get(meta(DATA)+12,4)==2);
        CHECK(sptm_root_canonical_view(&cache,&hw,&m,&proof) && cache.leaves==3);
        view_check(alias+size,pa,shift,1);
        memcpy(before,ram,sizeof ram);unsigned n=published;
        uint64_t different=(pte&~PT_OA_MASK)|(BASE+0x20000+part*4096);
        CHECK(sptm_mac_map_user_page(&m,&b,ROOT,va,different,1,0,&result)==SPTM_OK && result==6);
        CHECK(!memcmp(before,ram,sizeof ram) && n==published);
        view_check(va,pa,shift,1);
        CHECK(sptm_mac_unmap_user_region(&m,&b,ROOT,alias,2,1,BASE)==SPTM_OK);
        CHECK(get(meta(DATA)+8,4)==0 && get(meta(DATA)+12,4)==1 && cache.leaves==1);
        view_check(alias,pa,shift,0);view_check(alias+size,pa,shift,0);
        CHECK(sptm_mac_unmap_user_region(&m,&b,ROOT,va,1,1,BASE)==SPTM_OK);
        CHECK(!get(meta(DATA)+8,8) && !get(meta(L3)+8,2) && !cache.leaves);
        view_check(va,pa,shift,0);
        CHECK(sptm_root_build_shadow(&m,&hw,ROOT,format,0xa,&cache.leaves) && !cache.leaves);
        CHECK(sptm_root_canonical_view(&cache,&hw,&m,&proof));
        for(unsigned i=0;i<16384;i++)CHECK(ram[DATA-BASE+i]==0xa5);
    }
    /* A software-history exception must not admit executable, global,
     * malformed or additional unqualified software attributes. Cases 3, 12
     * and 13 are admitted by Apple's MAP_PAGE (tools/replay-sptm-matrix.py):
     * it never inspects AttrIndx/SH, and type17's 0x8a88 policy is checked
     * on the 4-bit class, keeping WAS_WRITABLE on read-only class 15. */
    for(unsigned format=0;format<2;format++)for(unsigned bad=0;bad<14;bad++) {
        struct sptm_memory m=setup(format);struct sptm_user_backend b={0};
        uint64_t pte=DATA|0x0860000000000ec3UL,result=99;
        int admitted=bad==3 || bad==12 || bad==13;
        switch(bad) {
        case 0:pte&=~0x40UL;break; /* Supervisor-only mapping is not ordinary user data. */
        case 1:pte&=~PT_UXN;break;case 2:pte&=~PT_PXN;break;
        case 3:pte|=4;break;case 4:pte&=~(1UL<<11);break;
        case 5:pte|=1UL<<5;break;case 6:pte&=~2UL;break;
        case 7:pte|=1UL<<55;break;case 8:pte|=1UL<<51;break;
        case 9:pte|=1UL<<52;break;case 10:pte|=1UL<<60;break;
        case 11:put(meta(DATA)+2,14,1);break;
        case 12:put(meta(DATA)+2,17,1);break;
        case 13:pte=(pte&~PT_SH)|(1UL<<8);break;
        }
        memcpy(before,ram,sizeof ram);unsigned n=published;
        if(admitted) {
            struct mmu_config src={format?12:14,17,ROOT};struct mmu_leaf leaf;
            CHECK(sptm_mac_map_user_page(&m,&b,ROOT,VA,pte,1,0,&result)==SPTM_OK && !result);
            CHECK(!mmu_walk(&src,VA,read64,0,&leaf) && leaf.valid && leaf.descriptor==pte);
            continue;
        }
        CHECK(sptm_mac_map_user_page(&m,&b,ROOT,VA,pte,1,0,&result)==SPTM_UNSUPPORTED_OPTIONS);
        CHECK(result==99 && n==published && !memcmp(before,ram,sizeof ram));
    }
    printf("USER_WAS_WRITABLE: %u checks, %u failures\n",checks,failures);
    return !!failures;
}

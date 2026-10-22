/* SPDX-License-Identifier: MIT */
#define main shared_fixture_checks
#include "test-sptm-shared-root.c"
#undef main
#include "sptm-user.h"
#define USER (ROOT+PAGE)
#define USER2 (ROOT+150*PAGE)
#define START 0x180000000UL
static struct sptm_user_backend backend;
static struct sptm_user_geometry geom;
static struct sptm_root_cached cache;
static struct shadow hw;
static uint64_t next_frame,next_shadow;
static unsigned prepared,committed,fail_prepare,fail_commit;
static uint64_t word(uint64_t pa) {uint64_t x;memcpy(&x,bytes+(pa-BASE),8);return x;}
static void setword(uint64_t pa,uint64_t x) {memcpy(bytes+(pa-BASE),&x,8);}
static unsigned half(uint64_t pa,unsigned off){return meta(pa)[off]|(unsigned)meta(pa)[off+1]<<8;}
static void sethalf(uint64_t pa,unsigned off,unsigned n){meta(pa)[off]=n;meta(pa)[off+1]=n>>8;}
static int bind_shared(void *ctx,uint64_t user,uint16_t asid,uint64_t parent,
                       uint8_t slot,uint64_t start,uint64_t size)
{(void)ctx;return !txm_bind_shared(&m,&arena,&registry,user,asid,parent,slot,start,size);}
static uint64_t slot_at(uint64_t root,unsigned level,uint64_t va)
{
    uint64_t table=root;
    for(unsigned l=geom.start;l<level;l++)table=word(table+8*sptm_mac_user_index(&geom,l,va))&geom.pa_mask;
    return table+8*sptm_mac_user_index(&geom,level,va);
}
static uint64_t allocate(unsigned type,unsigned level)
{
    uint64_t pa=next_frame;next_frame+=PAGE;CHECK(next_frame<USER2);
    CHECK(!sptm_mac_retype(&m,pa,11,type,level));return pa;
}
static void parents(uint64_t root,unsigned type,uint64_t va)
{
    for(unsigned l=geom.start;l<2;l++) {
        uint64_t slot=slot_at(root,l,va);
        if(word(slot))continue;
        uint64_t aligned=va&~((uint64_t)(geom.group-1)<<(geom.shift+(3-l)*(geom.shift-3)));
        CHECK(!sptm_mac_map_user_table_live(&m,&backend,root,aligned,l,allocate(type,l+1)|3));
    }
}
static int read_hw(void *ctx,uint64_t pa,uint64_t *out)
{(void)ctx;if(!map(0,pa,8))return -1;*out=word(pa);return 0;}
static int write_hw(void *ctx,uint64_t pa,uint64_t x)
{(void)ctx;if(!map(0,pa,8))return -1;setword(pa,x);return 0;}
static uint64_t alloc_hw(void *ctx)
{(void)ctx;uint64_t pa=next_shadow;next_shadow+=4096;CHECK(next_shadow<=BASE+sizeof(bytes));memset(bytes+(pa-BASE),0,4096);return pa;}
static int prep_leaf(void *ctx,uint64_t root,uint64_t va,unsigned shift,uint64_t pte)
{(void)ctx;(void)root;(void)va;(void)shift;(void)pte;return 0;}
static int prepare(void *ctx,uint64_t root,uint64_t shared,uint64_t va,unsigned shift,uint64_t pages)
{
    (void)ctx;CHECK(root==cache.root);prepared++;
    return !fail_prepare && sptm_root_prepare_nest(&cache,&hw,&m,shared,va,shift,pages);
}
static int commit(void *ctx,uint64_t root,uint64_t shared,uint64_t va,unsigned shift,uint64_t pages)
{
    (void)ctx;CHECK(root==cache.root);committed++;
    if(fail_commit)return 0;
    int ok=sptm_root_commit_nest(&cache,&hw,&m,shared,va,shift,pages);
    if(ok)flushed++;return ok;
}
static void setup(unsigned fmt,unsigned active,unsigned groups,int populated)
{
    reset();m.alloc_high=BASE+200*PAGE;m.bind_shared_root=bind_shared;
    memset(&backend,0,sizeof(backend));next_frame=ROOT+2*PAGE;
    prepared=committed=fail_prepare=fail_commit=0;
    create(ROOT,9,fmt,2);CHECK(!sptm_mac_retype(&m,ROOT,18,19,fmt));
    uint64_t args[8]={service.stacks_pa,arena.va,START,0xe40000000UL};
    CHECK(!txm_aspace(&m,&service,&arena,&registry,37,args));
    CHECK(!sptm_mac_configure_sharedregion(&m,ROOT,START,0xe40000000UL/(fmt?4096:PAGE)));
    CHECK(sptm_mac_user_geometry(fmt,2,&geom));create(USER,10,fmt,2);
    parents(ROOT,21,START);parents(USER,20,START);
    uint64_t span=1UL<<(2*geom.shift-3);
    for(unsigned i=0;i<groups;i++) {
        uint64_t va=START+i*span*geom.group,child=allocate(21,3);
        CHECK(!sptm_mac_map_user_table_live(&m,&backend,ROOT,va,2,child|3));
        if(populated) {
            uint64_t data=next_frame;next_frame+=PAGE;
            /* Existing approved leaves are fixture input. NEST must preserve
             * their permissions and single source ownership, not add data refs. */
            for(unsigned j=0;j<geom.group;j++) {
                setword(child+j*geom.page_size, data|0x0060000000000fc3UL);
                sethalf(child,8,j+1);setword(m.frame_map_pa+((data-BASE)>>14)*16+8,j+1);
            }
        }
    }
    CHECK(!sptm_mac_set_shared_region(&m,USER,ROOT));
    next_shadow=BASE+250*PAGE;
    cache=(struct sptm_root_cached){.root=USER,.shadow=alloc_hw(0),.asid=10,.format=fmt,.flags=2,.valid=1};
    hw=(struct shadow){.txsz=17,.root=cache.shadow,.alloc=alloc_hw,.read=read_hw,.write=write_hw};
    backend.prepare_nest=prepare;backend.commit_nest=commit;
    backend.prepare_leaf=prep_leaf;backend.commit_leaf=prep_leaf;
    backend.active_refs=active;backend.ttbr0=active?USER:0;
    sethalf(USER,6,half(USER,6)+active);
    published=flushed=0;
}
static void verify(uint64_t va,uint64_t pages,unsigned count,int populated)
{
    uint64_t span=1UL<<(2*geom.shift-3),base=va&~(span-1);
    CHECK(prepared==1 && committed==1 && flushed==1);
    CHECK(half(slot_at(USER,2,base)&~(PAGE-1),8)==count);
    CHECK(half(ROOT,4)==1 && registry.bindings==1);
    for(unsigned n=0;n<count;n++) {
        uint64_t addr=base+n*span,src=word(slot_at(ROOT,2,addr));
        CHECK(word(slot_at(USER,2,addr))==src);
        CHECK(sptm_mac_nested_table(&m,USER,addr,src));
        uint64_t child=src&~(PAGE-1);unsigned occurrences=0;
        for(unsigned j=0;j<count;j++)occurrences+=(word(slot_at(ROOT,2,base+j*span))&~(PAGE-1))==child;
        CHECK(half(child,6)==1+occurrences);
        struct mmu_config cfg={12,17,cache.shadow};struct mmu_leaf leaf;
        for(unsigned off=0;off<geom.page_size;off+=4096) {
            CHECK(!mmu_walk(&cfg,addr+off,read_hw,0,&leaf));CHECK(leaf.valid==populated);
            if(populated)CHECK(leaf.pa==(word(src&geom.pa_mask)&geom.pa_mask)+off);
        }
    }
    CHECK(cache.leaves==(populated?count:0));
    snapshot();CHECK(sptm_mac_nest_region(&m,&backend,USER,ROOT,va,pages)==SPTM_TABLE_EXISTS);unchanged();
}
static int build_root(void *ctx,const struct sptm_memory *memory,uint64_t root,unsigned fmt,
                      unsigned flags,uint64_t old,uint64_t *shadow,uint64_t *leaves)
{(void)ctx;(void)old;*shadow=hw.root;return sptm_root_build_shadow(memory,&hw,root,fmt,flags,leaves);}
static void install_root(void *ctx,uint64_t shadow,uint64_t root,uint64_t asid,unsigned fmt)
{(void)ctx;(void)fmt;CHECK(shadow==hw.root && root==USER && asid==10);}
#ifndef SPTM_NEST_TEST_MAIN
#define SPTM_NEST_TEST_MAIN main
#endif
int SPTM_NEST_TEST_MAIN(int argc,char **argv)
{
    for(unsigned fmt=0;fmt<2;fmt++)for(unsigned active=0;active<=6;active++)
    for(unsigned populated=0;populated<2;populated++)for(unsigned variant=0;variant<3;variant++) {
        setup(fmt,active,3,populated);
        uint64_t span=1UL<<(2*geom.shift-3),va=START,pages=2*geom.group*span/geom.page_size;
        unsigned count=2*geom.group;
        if(variant==1){va+=geom.page_size;pages=1;count=1;}
        if(variant==2){va+=geom.group*span+geom.page_size;pages=geom.group*span/geom.page_size;count=geom.group+1;}
        CHECK(!sptm_mac_nest_region(&m,&backend,USER,ROOT,va,pages));verify(va,pages,count,populated);
    }
    for(unsigned fmt=0;fmt<2;fmt++)for(unsigned test=0;test<23;test++) {
        setup(fmt,0,3,0);uint64_t va=START,span=1UL<<(2*geom.shift-3),pages=2*geom.group*span/geom.page_size;
        uint64_t src=slot_at(ROOT,2,va),dst=slot_at(USER,2,va),child=word(src)&~(PAGE-1);
        switch(test) {
        case 0:pages=0;break;case 1:va++;break;case 2:va=0;break;
        case 3:va=1UL<<47;break;case 4:pages=UINT32_MAX;break;
        case 5:meta(USER)[8]=255;break;case 6:meta(ROOT)[12]^=1;break;
        case 7:meta(child)[2]=20;break;case 8:meta(child)[4]=2;break;
        case 9:meta(child)[0]=1;break;case 10:sethalf(child,6,0);break;
        case 11:sethalf(child,6,0xfff9);break;
        case 12:setword(src,0);break;case 13:setword(src,word(src)|4);break;
        case 14:setword(dst+8*(2*geom.group-1),3);break;
        case 15:deny=BASE;break;case 16:deny=child;break;
        case 17:fail_prepare=1;break;case 18:sethalf(dst&~(PAGE-1),8,2048);break;
        case 19:meta(ROOT)[4]=0;break;case 20:shared_regions.slots[0].state=2;break;
        case 21:pages=(1UL<<(3*geom.shift-6))/geom.page_size+1;break;
        case 22:meta(USER)[0]=1;break;
        }
        snapshot();CHECK(sptm_mac_nest_region(&m,&backend,USER,ROOT,va,pages)!=SPTM_OK);unchanged();CHECK(!committed);
    }
    /* The native ABI consumes w3; high count bits do not change the range. */
    setup(0,0,3,0);CHECK(!sptm_mac_nest_region(&m,&backend,USER,ROOT,START,(1UL<<32)|1));
    verify(START,1,1,0);
    setup(0,0,3,0);fail_commit=1;
    CHECK(sptm_mac_nest_region(&m,&backend,USER,ROOT,START,1)==SPTM_SHADOW_FAILED);
    CHECK(committed==1 && word(slot_at(USER,2,START))==word(slot_at(ROOT,2,START)));
    for(unsigned fmt=0;fmt<2;fmt++)for(unsigned corrupt=0;corrupt<2;corrupt++) {
        setup(fmt,0,3,1);uint64_t span=1UL<<(2*geom.shift-3);
        CHECK(!sptm_mac_nest_region(&m,&backend,USER,ROOT,START+geom.page_size,1));
        struct sptm_root_backend rb={.kernel_root=BASE+249*PAGE,.kernel_shadow=hw.root,
                                    .build=build_root,.install=install_root};
        if(corrupt)setword(slot_at(ROOT,2,START),word(slot_at(ROOT,2,START+geom.group*span)));
        enum sptm_result result=sptm_mac_switch_root(&m,&roots,&rb,0,USER,0,0);
        CHECK(result==(corrupt?SPTM_BAD_TABLE:SPTM_OK));
    }
    /* Adding a second consumer changes table links, not data references or
     * the first consumer's existing hardware mappings. */
    for(unsigned fmt=0;fmt<2;fmt++) {
        setup(fmt,0,3,1);uint64_t span=1UL<<(2*geom.shift-3),pages=geom.group*span/geom.page_size;
        CHECK(!sptm_mac_nest_region(&m,&backend,USER,ROOT,START+geom.page_size,pages));
        struct sptm_root_cached first_cache=cache;
        create(USER2,11,fmt,2);parents(USER2,20,START);
        CHECK(!sptm_mac_set_shared_region(&m,USER2,ROOT));
        cache=(struct sptm_root_cached){.root=USER2,.shadow=alloc_hw(0),.asid=11,.format=fmt,.flags=2,.valid=1};
        hw.root=cache.shadow;
        CHECK(!sptm_mac_nest_region(&m,&backend,USER2,ROOT,START+geom.page_size,pages));
        CHECK(cache.leaves==first_cache.leaves && cache.leaves==geom.group+1);
        CHECK(half(ROOT,4)==2 && registry.bindings==2);
        for(unsigned n=0;n<geom.group+1;n++) {
            uint64_t addr=START+n*span,pte=word(slot_at(ROOT,2,addr)),child=pte&~(PAGE-1);
            unsigned occurrences=n<geom.group?geom.group:1;
            CHECK(half(child,6)==1+2*occurrences);
            struct mmu_config a={12,17,first_cache.shadow},b={12,17,cache.shadow};
            struct mmu_leaf x,y;
            CHECK(!mmu_walk(&a,addr,read_hw,0,&x) && !mmu_walk(&b,addr,read_hw,0,&y));
            CHECK(x.valid && y.valid && x.pa==y.pa && x.descriptor==y.descriptor);
            uint64_t data=word(pte&geom.pa_mask)&0x0000ffffffffc000UL;
            CHECK(word(m.frame_map_pa+((data-BASE)>>14)*16+8)==geom.group);
        }
    }
    if(argc==3) {
        unsigned fmt=(unsigned)atoi(argv[2]);CHECK(fmt<2);setup(fmt,0,3,1);
        uint64_t span=1UL<<(2*geom.shift-3),pages=geom.group*span/geom.page_size;
        CHECK(!sptm_mac_nest_region(&m,&backend,USER,ROOT,START+geom.page_size,pages));
        FILE *f=fopen(argv[1],"wb");CHECK(f!=NULL);
        CHECK(fwrite(bytes,1,sizeof(bytes),f)==sizeof(bytes));CHECK(!fclose(f));
    }
    printf("PASS: %u nesting checks (both geometries, partial groups, 0..6 active CPUs, shadows, failures)\n",checks);
    return 0;
}

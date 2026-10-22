/* SPDX-License-Identifier: MIT */
#define main shared_fixture_checks
#include "test-sptm-shared-root.c"
#undef main
#include "sptm-user.h"
static struct sptm_user_backend backend;
static const uint8_t zero_page[PAGE];
static uint64_t value(uint64_t pa)
{uint64_t x;memcpy(&x,bytes+pa-BASE,8);return x;}
static void write_value(uint64_t pa,uint64_t x)
{memcpy(bytes+pa-BASE,&x,8);}
static struct sptm_user_geometry setup(unsigned fmt,int configured)
{
    reset();memset(&backend,0,sizeof(backend));create(ROOT,9,fmt,2);
    CHECK(!sptm_mac_retype(&m,ROOT,18,19,fmt));
    if(configured)CHECK(!sptm_mac_configure_sharedregion(&m,ROOT,0x180000000UL,0xe40000000UL/(fmt?0x1000:PAGE)));
    struct sptm_user_geometry g;CHECK(sptm_mac_user_geometry(fmt,2,&g));return g;
}
static uint64_t aligned(const struct sptm_user_geometry *g,unsigned level,uint64_t va)
{return va&~((uint64_t)(g->group-1)<<(g->shift+(3-level)*(g->shift-3)));}
static uint64_t table_slot(const struct sptm_user_geometry *g,unsigned level,uint64_t va)
{
    uint64_t table=ROOT;
    for(unsigned l=g->start;l<level;l++) {
        uint64_t pte=value(table+8*sptm_mac_user_index(g,l,va));CHECK((pte&3)==3);
        table=pte&g->pa_mask;
    }
    return table+8*sptm_mac_user_index(g,level,va);
}
int main(void)
{
    for(unsigned fmt=0;fmt<2;fmt++)for(unsigned configured=0;configured<2;configured++)
    for(unsigned where=0;where<3;where++) {
        struct sptm_user_geometry g=setup(fmt,configured);
        uint64_t va=where==0?0:where==1?0x180000000UL:(1UL<<47)-g.page_size;
        for(unsigned l=g.start;l<=2;l++) {
            uint64_t child=ROOT+(l-g.start+1)*PAGE,addr=aligned(&g,l,va);
            memset(bytes+child-BASE,0xa5,PAGE);
            CHECK(!sptm_mac_retype(&m,child,11,21,0xaabbccdd00000000UL|l+1));
            CHECK(meta(child)[2]==21 && meta(child)[4]==l+1 && !meta(child)[6] && !meta(child)[8]);
            CHECK(!memcmp(bytes+child-BASE,zero_page,PAGE));
            CHECK(!sptm_mac_map_user_table_live(&m,&backend,ROOT,addr,0x123400UL|l,child|3));
            CHECK(meta(child)[6]==1 && !meta(child)[8]);
            uint64_t slot=table_slot(&g,l,addr);
            for(unsigned n=0;n<g.group;n++)CHECK(value(slot+8*n)==((child+n*g.page_size)|3));
            uint64_t parent=slot&~(PAGE-1);CHECK(meta(parent)[l==g.start?6:8]==1);
            snapshot();CHECK(sptm_mac_retype(&m,child,21,11,0)==SPTM_FRAME_BUSY);unchanged();
        }
        uint64_t spare=ROOT+8*PAGE;CHECK(!sptm_mac_retype(&m,spare,11,21,3));
        snapshot();CHECK(sptm_mac_map_user_table_live(&m,&backend,ROOT,aligned(&g,2,va),2,spare|3)==SPTM_TABLE_EXISTS);unchanged();
        for(unsigned l=3;l-->g.start;) {
            uint64_t child=ROOT+(l-g.start+1)*PAGE;
            CHECK(!sptm_mac_unmap_user_table(&m,&backend,ROOT,aligned(&g,l,va),0x123400UL|l));
            CHECK(!meta(child)[6] && !meta(child)[8]);
            CHECK(!sptm_mac_retype(&m,child,21,11,0));
            CHECK(meta(child)[2]==11 && !meta(child)[4]);
        }
        CHECK(!meta(ROOT)[6] && !meta(ROOT)[7]);
        CHECK(shared_regions.slots[0].state==(configured?3u:1u));
    }
    for(unsigned fmt=0;fmt<2;fmt++)for(unsigned test=0;test<26;test++) {
        struct sptm_user_geometry g=setup(fmt,1);uint64_t va=0,root=ROOT,child=ROOT+PAGE,level=g.start;
        CHECK(!sptm_mac_retype(&m,child,11,21,level+1));
        enum sptm_result expected=SPTM_BAD_TABLE;
        switch(test) {
        case 0:meta(child)[2]=20;expected=SPTM_TYPE_MISMATCH;break;
        case 1:meta(child)[2]=23;expected=SPTM_TYPE_MISMATCH;break;
        case 2:meta(child)[4]=3;expected=SPTM_TYPE_MISMATCH;break;
        case 3:meta(child)[6]=1;expected=SPTM_FRAME_BUSY;break;
        case 4:meta(child)[8]=1;expected=SPTM_FRAME_BUSY;break;
        case 5:bytes[child-BASE+8]=1;break;
        case 6:meta(ROOT)[4]=1;expected=SPTM_FRAME_BUSY;break;
        case 7:backend.ttbr0=ROOT;expected=SPTM_FRAME_BUSY;break;
        case 8:backend.ttbr1=ROOT;expected=SPTM_FRAME_BUSY;break;
        case 9:meta(ROOT)[10]=2;break;
        case 10:meta(ROOT)[8]=255;break;
        case 11:shared_regions.slots[0].root=child;break;
        case 12:shared_regions.slots[0].state=2;break;
        case 13:shared_regions.slots[0].start++;break;
        case 14:m.shared_regions=0;expected=SPTM_BAD_CONFIG;break;
        case 15:va=1;expected=SPTM_BAD_ADDRESS;break;
        case 16:va=1UL<<47;expected=SPTM_BAD_ADDRESS;break;
        case 17:level=3;break;
        case 18:deny=child;expected=SPTM_MEMORY_UNAVAILABLE;break;
        case 19:meta(ROOT)[6]=g.root_groups&255;meta(ROOT)[7]=g.root_groups>>8;expected=SPTM_BAD_REFERENCE;break;
        case 20:write_value(ROOT,1);expected=SPTM_TABLE_EXISTS;break;
        case 21:write_value(ROOT,4);break;
        case 22:child=ROOT;break;
        case 23:meta(ROOT)[12]=2;break;
        case 24:meta(ROOT)[0]=1;expected=SPTM_FRAME_BUSY;break;
        case 25:create(ROOT+2*PAGE,10,fmt,2);root=ROOT+2*PAGE;expected=SPTM_TYPE_MISMATCH;break;
        }
        snapshot();CHECK(sptm_mac_map_user_table_live(&m,&backend,root,va,level,child|3)==expected);unchanged();
    }
    for(unsigned fmt=0;fmt<2;fmt++)for(unsigned test=0;test<7;test++) {
        struct sptm_user_geometry g=setup(fmt,0);
        for(unsigned l=g.start;l<=2;l++) {
            uint64_t child=ROOT+(l-g.start+1)*PAGE;
            CHECK(!sptm_mac_retype(&m,child,11,21,l+1));
            CHECK(!sptm_mac_map_user_table_live(&m,&backend,ROOT,0,l,child|3));
        }
        uint64_t child=ROOT+(3-g.start)*PAGE,parent=child-PAGE;
        enum sptm_result expected=SPTM_FRAME_BUSY;
        switch(test) {
        case 0:meta(ROOT)[4]=1;expected=SPTM_BAD_CONFIG;break;
        case 1:meta(child)[6]=2;expected=SPTM_BAD_REFERENCE;break;
        case 2:meta(child)[8]=1;break;
        case 3:bytes[child-BASE+8]=4;break;
        case 4:meta(parent)[8]=0;expected=SPTM_BAD_REFERENCE;break;
        case 5:deny=child;expected=SPTM_MEMORY_UNAVAILABLE;break;
        case 6:write_value(parent,value(parent)|4);expected=SPTM_BAD_TABLE;break;
        }
        snapshot();CHECK(sptm_mac_unmap_user_table(&m,&backend,ROOT,0,2)==expected);unchanged();
    }
    /* All four level values are constructor-valid; other low bytes are not. */
    for(unsigned level=0;level<256;level++) {
        setup(0,0);uint64_t pa=ROOT+PAGE;snapshot();
        enum sptm_result result=sptm_mac_retype(&m,pa,11,21,0xff00000000000000UL|level);
        CHECK(result==(level<4?SPTM_OK:SPTM_UNSUPPORTED_OPTIONS));
        if(level<4){CHECK(meta(pa)[4]==level);CHECK(!sptm_mac_retype(&m,pa,21,11,0));}
        else unchanged();
    }
    printf("PASS: %u shared-table lifecycle checks\n",checks);return 0;
}

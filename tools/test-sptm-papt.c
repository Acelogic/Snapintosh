/* SPDX-License-Identifier: MIT */
#include <stdio.h>
#include <string.h>
#include "sptm-papt.h"
#include "sprr-view.h"
#include "sprr.h"
#include "sptm-refs.h"
#include "sptm-user.h"
#define BASE UINT64_C(0x40000000)
#define DATA UINT64_C(0x900000000)
#define VA UINT64_C(0xfffffe0100000000)
/* SLIDE_REGION's destination window: XNU's phystokv alias of a moved frame. */
#define MOVED_VA UINT64_C(0xfffffe01fc000000)
#define MAP (BASE+0x60000)
#define ATTR (PT_AF|(3UL<<8)|PT_PXN|PT_UXN)
static unsigned char ram[1<<20],before[1<<20],payload[16384];
static struct sprr_views views;
static struct sptm_memory memory;
static struct sptm_update_backend backend;
static struct sptm_aperture aperture={DATA,VA,0x8000};
static struct shadow shadow;
static struct sptm_ref_batch refs;
static uint64_t next,pp[6],guest_slot,moved_slot;
static struct sptm_slide_region moved_regions[1];
static struct sptm_moved moved_state,*moved;
static unsigned checks,failed,publications,transitions;
static unsigned cache_syncs;
#define CHECK(x) do {checks++;if(!(x)){failed++;printf("FAIL %u: %s\n",__LINE__,#x);}} while(0)
static volatile uint8_t *map(void *ctx,uint64_t pa,uint64_t size)
{
    (void)ctx;
    if(pa==DATA && size<=sizeof(payload))return payload;
    return pa>=BASE && pa<BASE+sizeof(ram) && size<=BASE+sizeof(ram)-pa ? ram+(pa-BASE) : 0;
}
static int rd(void *ctx,uint64_t pa,uint64_t *out)
{volatile uint8_t *p=map(ctx,pa,8);if(!p)return -1;memcpy(out,(const void *)p,8);return 0;}
static int wr(void *ctx,uint64_t pa,uint64_t value)
{volatile uint8_t *p=map(ctx,pa,8);if(!p)return -1;memcpy((void *)p,&value,8);return 0;}
static uint64_t alloc(void *ctx)
{(void)ctx;if(next>=BASE+0x60000)return 0;uint64_t p=next;next+=4096;return p;}
static uint64_t get(uint64_t pa)
{uint64_t value=0;CHECK(!rd(0,pa,&value));return value;}
static void verify_alias(unsigned cpu,uint64_t va,uint64_t slot,unsigned selector,int write)
{
    struct mmu_config cfg={12,17,sprr_views_root(&views,cpu)};
    for(unsigned n=0;n<4;n++) {
        struct mmu_leaf l={0};CHECK(!mmu_walk(&cfg,va+n*4096,rd,0,&l));
        CHECK(l.valid && l.pa==DATA+n*4096);
        CHECK((l.descriptor&(PT_PXN|PT_UXN))==(PT_PXN|PT_UXN));
        CHECK(!(l.descriptor&(1UL<<6)));
        CHECK(!!(l.descriptor&(2UL<<6))==!write);
    }
    CHECK(sprr_pte_class(get(slot))==selector);
}
/* Every kernel alias of the frame: the linear one and, once SLIDE_REGION has
 * moved it, the one XNU's phystokv computes. Apple has only the latter. */
static void verify_view(unsigned cpu,unsigned selector,int write)
{
    verify_alias(cpu,VA,guest_slot,selector,write);
    if(moved)verify_alias(cpu,MOVED_VA,moved_slot,selector,write);
}
static void publish(void *ctx,uint64_t pa,uint64_t size)
{
    (void)ctx;publications++;
    CHECK(((pa==MAP || pa==MAP+16) && size==16) ||
          ((pa==guest_slot || (moved && pa==moved_slot)) && size==8));
    if(pa==MAP) {
        unsigned type=ram[MAP-BASE+2];CHECK(type==11 || type==25 || type==14 || type==17);
        if(type==14)CHECK(cache_syncs>0);
        for(unsigned cpu=0;cpu<6;cpu++)
            verify_view(cpu,type==25 ? 2 : type==14 ? 11 : 3,
                        type==11 || type==17 || (type==25 && !!(pp[cpu]&0x100)));
    }
}
static int change(void *ctx,uint64_t pa,uint64_t old,uint64_t type)
{
    (void)ctx;struct sptm_papt_change t;
    CHECK(ram[MAP-BASE+2]==old);
    if(sptm_papt_prepare(&memory,&backend,&aperture,moved,pa,old,type,&t)!=SPTM_OK)return 0;
    CHECK(t.count==(moved ? 2u : 1u));
    for(unsigned i=0;i<t.count;i++)
        if((old==25 || type==25) && !sprr_views_prepare(&views,&shadow,t.leaf[i].va))return 0;
    for(unsigned cpu=0;cpu<6;cpu++)if(!sprr_views_sync_cpu(&views,&shadow,cpu,pp[cpu]))return 0;
    sptm_papt_commit(&memory,&t);
    for(unsigned cpu=0;cpu<6;cpu++)if(!sprr_views_sync_cpu(&views,&shadow,cpu,pp[cpu]))return 0;
    if(type==14)cache_syncs++;
    CHECK(ram[MAP-BASE+2]==old);transitions++;return 1;
}
static void setup(void)
{
    memset(ram,0,sizeof(ram));memset(payload,0xa5,sizeof(payload));memset(&views,0,sizeof(views));
    next=BASE+0x20000;publications=transitions=cache_syncs=0;sptm_refs_begin(&refs);
    moved=0;moved_slot=0;
    memory=(struct sptm_memory){.frame_map_pa=MAP,.frame_low=DATA,.frame_high=DATA+0x8000,
        .alloc_low=DATA,.alloc_high=DATA+0x8000,.map=map,.publish=publish,.retype_rozone=change,
        .retype_user_exec=change,.retype_user_tpro=change,.refs=&refs};
    ram[MAP-BASE+2]=11;ram[MAP-BASE+18]=11;
    backend=(struct sptm_update_backend){.kernel_root=BASE,.shadow_root=BASE+0x10000,.map_shadow=map};
    shadow=(struct shadow){.txsz=17,.root=backend.shadow_root,.read=rd,.write=wr,.alloc=alloc};
    CHECK(!wr(0,BASE+8UL*mmu_index(14,1,VA),BASE+0x4000+3));
    CHECK(!wr(0,BASE+0x4000+8UL*mmu_index(14,2,VA),BASE+0x8000+3));
    guest_slot=BASE+0x8000+8UL*mmu_index(14,3,VA);CHECK(!wr(0,guest_slot,DATA|ATTR|3));
    for(unsigned level=0;level<3;level++)
        CHECK(!wr(0,backend.shadow_root+4096UL*level+8UL*mmu_index(12,level,VA&((1UL<<47)-1)),
                  backend.shadow_root+4096UL*(level+1)+3));
    for(unsigned n=0;n<4;n++)CHECK(!wr(0,BASE+0x13000+8UL*mmu_index(12,3,VA+n*4096),
                                     DATA+n*4096+ATTR+3));
    CHECK(sprr_views_init(&views,&shadow));
    for(unsigned cpu=0;cpu<6;cpu++) {
        pp[cpu]=SPRR_PPERM_INITIAL|(cpu&1 ? 0x100 : 0);
        CHECK(sprr_views_sync_cpu(&views,&shadow,cpu,pp[cpu]));
    }
}
/* The alias sptm_mac_slide_region leaves behind: the source VA's descriptor
 * rebuilt as NX kernel RW at the slide destination, with four matching 4K
 * shadow leaves. Uses the free 16K guest table at +0xc000 and the free 4K
 * shadow tables at +0x14000/+0x15000. The linear alias stays mapped. */
static void setup_moved(void)
{
    setup();
    uint64_t l2=BASE+0x4000,l3=BASE+0xc000,va47=MOVED_VA&((1UL<<47)-1);
    CHECK(mmu_index(14,1,MOVED_VA)==mmu_index(14,1,VA) && mmu_index(14,2,MOVED_VA)!=mmu_index(14,2,VA));
    CHECK(!wr(0,l2+8UL*mmu_index(14,2,MOVED_VA),l3+3));
    uint64_t value=DATA|3|(ATTR&(PT_LEAF_ATTRS&~0xc0UL))|(3UL<<53);
    moved_slot=l3+8UL*mmu_index(14,3,MOVED_VA);CHECK(!wr(0,moved_slot,value));
    uint64_t s1=backend.shadow_root+4096,s2=BASE+0x14000,s3=BASE+0x15000;
    CHECK(mmu_index(12,0,va47)==mmu_index(12,0,VA&((1UL<<47)-1)));
    CHECK(mmu_index(12,1,va47)!=mmu_index(12,1,VA&((1UL<<47)-1)));
    CHECK(!wr(0,s1+8UL*mmu_index(12,1,va47),s2+3));
    CHECK(!wr(0,s2+8UL*mmu_index(12,2,va47),s3+3));
    for(unsigned n=0;n<4;n++)
        CHECK(!wr(0,s3+8UL*mmu_index(12,3,va47+n*4096),(value&~PT_OA_MASK)|(DATA+n*4096)));
    moved_regions[0]=(struct sptm_slide_region){MOVED_VA,DATA,2};
    moved_state=(struct sptm_moved){moved_regions,1,MOVED_VA,MOVED_VA+0x4000000};
    moved=&moved_state;
    for(unsigned cpu=0;cpu<6;cpu++)CHECK(sprr_views_sync_cpu(&views,&shadow,cpu,pp[cpu]));
}
/* UPDATE_DISJOINT_MULTIPAGE's aperture step: every CPU's view of each alias
 * maps the frame with the requested AttrIndx and its unchanged SH, AF,
 * selector3 permissions and XN bits. */
static void verify_attr(unsigned cpu,uint64_t va,uint64_t slot,unsigned attr)
{
    struct mmu_config cfg={12,17,sprr_views_root(&views,cpu)};
    for(unsigned n=0;n<4;n++) {
        struct mmu_leaf l={0};CHECK(!mmu_walk(&cfg,va+n*4096,rd,0,&l));
        CHECK(l.valid && l.pa==DATA+n*4096 && ((l.descriptor>>2)&7)==attr);
        CHECK((l.descriptor&(PT_SH|PT_AF|PT_AP|PT_PXN|PT_UXN|PT_NS))==
              (ATTR&(PT_SH|PT_AF|PT_AP|PT_PXN|PT_UXN)));
    }
    CHECK(((get(slot)>>2)&7)==attr && sprr_pte_class(get(slot))==3 &&
          (get(slot)&~PT_ATTRINDX)==(DATA|ATTR|3));
}
static void test_attr(void)
{
    for(unsigned alias=0;alias<2;alias++)for(unsigned attr=0;attr<8;attr++) {
        if(alias)setup_moved();else setup();
        /* Also through copied private tables, as after a ROZONE round trip. */
        CHECK(sprr_views_prepare(&views,&shadow,VA));
        if(moved)CHECK(sprr_views_prepare(&views,&shadow,MOVED_VA));
        for(unsigned cpu=0;cpu<6;cpu++)CHECK(sprr_views_sync_cpu(&views,&shadow,cpu,pp[cpu]));
        memcpy(before,ram,sizeof ram);unsigned pubs=publications;
        struct sptm_papt_change t;
        CHECK(sptm_papt_prepare_attr(&memory,&backend,&aperture,moved,DATA,attr,&t)==SPTM_OK);
        CHECK(!memcmp(before,ram,sizeof ram) && publications==pubs);
        CHECK(t.count==(moved ? 2u : 1u));
        for(unsigned i=0;i<t.count;i++)
            CHECK(t.leaf[i].after==((t.leaf[i].before&~PT_ATTRINDX)|((uint64_t)attr<<2)));
        sptm_papt_commit(&memory,&t);
        CHECK(publications==pubs+t.count);
        for(unsigned n=0;n<4;n++) {
            uint64_t d=get(BASE+0x13000+8UL*mmu_index(12,3,VA+n*4096));
            CHECK(d==((DATA+n*4096+ATTR+3)&~PT_ATTRINDX)+((uint64_t)attr<<2));
        }
        /* Private copies follow only through their refresh (the monitor's
         * kernel_refresh inside shadow_tlb_sync), on every CPU. */
        for(unsigned cpu=0;cpu<6;cpu++)CHECK(sprr_views_sync_cpu(&views,&shadow,cpu,pp[cpu]));
        for(unsigned cpu=0;cpu<6;cpu++) {
            verify_attr(cpu,VA,guest_slot,attr);
            if(moved)verify_attr(cpu,MOVED_VA,moved_slot,attr);
        }
        int intact=1;
        for(unsigned n=0;n<sizeof(payload);n++)intact&=payload[n]==0xa5;
        CHECK(ram[MAP-BASE+2]==11 && intact);
    }
    /* Refusals write nothing: AttrIndx >= 8, a non-DEFAULT, busy or
     * unmanaged frame, a leaf that is not the selector3 aperture of the
     * frame, a mismatched shadow leaf, and a bad moved alias. */
    for(unsigned bad=0;bad<10;bad++) {
        if(bad>=8)setup_moved();else setup();
        unsigned attr=1;uint64_t pa=DATA;
        enum sptm_result want=SPTM_OK;
        if(bad==0){attr=8;want=SPTM_UNSUPPORTED_OPTIONS;}
        if(bad==1){ram[MAP-BASE+2]=25;want=SPTM_TYPE_MISMATCH;}
        if(bad==2){ram[MAP-BASE+2]=35;want=SPTM_TYPE_MISMATCH;}
        if(bad==3){ram[MAP-BASE+1]=1;want=SPTM_FRAME_BUSY;}
        if(bad==4){pa=DATA+0x8000;want=SPTM_BAD_ADDRESS;}
        if(bad==5){CHECK(!wr(0,guest_slot,DATA|(ATTR&~PT_UXN)|3));want=SPTM_BAD_TABLE;}
        if(bad==6){CHECK(!wr(0,guest_slot,(DATA+0x4000)|ATTR|3));want=SPTM_BAD_TABLE;}
        if(bad==7){CHECK(!wr(0,BASE+0x13000+8UL*mmu_index(12,3,VA+8192),(DATA+8192)|3));
                   want=SPTM_SHADOW_FAILED;}
        if(bad==8){CHECK(!wr(0,moved_slot,get(moved_slot)|(2UL<<6)));want=SPTM_BAD_TABLE;}
        if(bad==9){moved_regions[0].va=MOVED_VA+0x1000;want=SPTM_BAD_ADDRESS;}
        memcpy(before,ram,sizeof ram);unsigned pubs=publications;struct sptm_papt_change t;
        CHECK(sptm_papt_prepare_attr(&memory,&backend,&aperture,moved,pa,attr,&t)==want);
        CHECK(!memcmp(before,ram,sizeof ram) && publications==pubs);
    }
}
static unsigned admission_calls;
static int deny_aperture(void *ctx,uint64_t va,uint64_t pa,uint64_t size,
                         uint64_t low,uint64_t upper)
{
    admission_calls++;
    CHECK(ctx==&memory && va==(VA&((1UL<<47)-1)) && pa==DATA && size==0x4000);
    CHECK(low==(ATTR&PT_LEAF_ATTRS));
    CHECK(upper==PT_UXN); /* DEFAULT -> ROZONE requests raw selector 2. */
    return 0;
}
int main(void)
{
    setup();backend.ctx=&memory;backend.admit=deny_aperture;
    memcpy(before,ram,sizeof(ram));
    struct sptm_papt_change rejected;
    CHECK(sptm_papt_prepare(&memory,&backend,&aperture,0,DATA,11,25,&rejected)==SPTM_SHADOW_FAILED);
    CHECK(admission_calls==1 && !memcmp(before,ram,sizeof(ram)) && !publications);
    CHECK(sptm_mac_retype(&memory,DATA,11,25,0)!=SPTM_OK);
    CHECK(admission_calls==2 && !memcmp(before,ram,sizeof(ram)) && !publications);
    setup();struct sptm_papt_change t;memcpy(before,ram,sizeof(ram));
    CHECK(sptm_papt_prepare(&memory,&backend,&aperture,0,DATA,11,25,&t)==SPTM_OK);
    CHECK(t.count==1 && !memcmp(before,ram,sizeof(ram)) && !publications);
    CHECK(sptm_mac_retype(&memory,DATA,11,25,0)==SPTM_OK);
    CHECK(transitions==1 && publications==2 && ram[MAP-BASE+2]==25);
    CHECK(sptm_mac_retype(&memory,DATA,25,11,0)==SPTM_OK);
    CHECK(transitions==2 && publications==4 && ram[MAP-BASE+2]==11);
    for(unsigned n=0;n<sizeof(payload);n++)CHECK(payload[n]==0xa5);
    setup();memcpy(before,ram,sizeof ram);
    CHECK(sptm_papt_prepare(&memory,&backend,&aperture,0,DATA,11,17,&t)==SPTM_OK);
    CHECK(t.leaf[0].before==t.leaf[0].after && !memcmp(before,ram,sizeof ram) && !publications);
    CHECK(sptm_mac_retype(&memory,DATA,11,17,0)==SPTM_OK);
    CHECK(sptm_mac_retype(&memory,DATA,17,11,0)==SPTM_OK);
    CHECK(!cache_syncs && views.count==1);
    /* USER_EXEC preserves read-only references, seals the aperture on every
     * CPU, and requires cache synchronization before type publication. */
    setup();ram[MAP-BASE+8]=2;
    CHECK(sptm_mac_retype(&memory,DATA,11,14,0)==SPTM_OK);
    CHECK(views.count==1 && cache_syncs==1 && ram[MAP-BASE+8]==2);
    CHECK(sptm_mac_retype(&memory,DATA,14,11,0)==SPTM_OK);
    CHECK(ram[MAP-BASE+8]==2 && cache_syncs==1);
    for(unsigned n=0;n<sizeof(payload);n++)CHECK(payload[n]==0xa5);
    for(unsigned bad=0;bad<7;bad++) {
        setup();unsigned from=11,to=14;uint64_t options=0;
        if(bad==0)memory.retype_user_exec=0;
        if(bad==1)options=1;
        if(bad==2)ram[MAP-BASE+12]=1;
        if(bad==3)ram[MAP-BASE+4]=1;
        if(bad==4)ram[MAP-BASE+3]=1;
        if(bad==5)ram[MAP-BASE+11]=0x80;
        if(bad==6){ram[MAP-BASE+2]=14;ram[MAP-BASE+12]=1;from=14;to=11;}
        memcpy(before,ram,sizeof(ram));
        CHECK(sptm_mac_retype(&memory,DATA,from,to,options)!=SPTM_OK);
        CHECK(!memcmp(before,ram,sizeof(ram)) && !publications && !cache_syncs);
    }
    /* Executable and RO data aliases may coexist. A writable alias, DMA,
     * and release while an executable reference exists must be refused. */
    setup();CHECK(sptm_mac_retype(&memory,DATA,11,14,0)==SPTM_OK);
    ram[MAP-BASE+18]=20;ram[MAP-BASE+20]=3;
    uint64_t rx=DATA|0x0020000000000ec3UL;
    CHECK(sptm_refs_leaf(&memory,DATA+0x4000,0x4000,0,rx)==SPTM_OK);
    CHECK(sptm_refs_leaf(&memory,DATA+0x4000,0x8000,0,rx|(1UL<<54))==SPTM_OK);
    CHECK(sptm_refs_validate(&memory)==SPTM_OK);
    CHECK(refs.count==2 && refs.entries[1].other==1 && refs.entries[1].ro==1);
    sptm_refs_commit(&memory);
    CHECK(sptm_mac_retype(&memory,DATA,14,11,0)==SPTM_FRAME_BUSY);
    sptm_refs_begin(&refs);
    CHECK(sptm_refs_leaf(&memory,DATA+0x4000,0x4000,0,DATA|0x0060000000000e43UL)!=SPTM_OK);
    sptm_refs_begin(&refs);CHECK(sptm_refs_dart(&memory,DATA,1)!=SPTM_OK);
    sptm_refs_begin(&refs);CHECK(sptm_refs_leaf(&memory,DATA+0x4000,0x4000,rx,0)==SPTM_OK);
    CHECK(sptm_refs_validate(&memory)==SPTM_OK);sptm_refs_commit(&memory);
    CHECK(sptm_mac_retype(&memory,DATA,14,11,0)==SPTM_OK);
    CHECK(ram[MAP-BASE+8]==1 && !ram[MAP-BASE+12]);
    for(unsigned format=0;format<2;format++) {
        struct sptm_user_geometry g;CHECK(sptm_mac_user_geometry(format,2,&g));
        CHECK(sptm_mac_user_leaf_policy(2,20,14,0x4000,rx,&g)==SPTM_OK);
        CHECK(sptm_mac_user_leaf_policy(2,20,14,0x4000,rx|(1UL<<54),&g)==SPTM_OK);
        CHECK(sptm_mac_user_leaf_policy(2,20,11,0x4000,rx,&g)!=SPTM_OK);
        /* AF (bit 10) is free, as Apple's descriptor helper accepts page
         * aging on type14 class13 (tools/replay-user-update.py). */
        CHECK(sptm_mac_user_leaf_policy(2,20,14,0x4000,rx&~(1UL<<10),&g)==SPTM_OK);
        /* WIRED (bit58) is software state on every Apple type: mlock of code
         * reaches pmap_change_wiring's UPDATE_REGION option1. */
        CHECK(sptm_mac_user_leaf_policy(2,20,14,0x4000,rx|(1UL<<58),&g)==SPTM_OK);
        CHECK(sptm_mac_user_leaf_policy(2,20,14,0x4000,rx|(1UL<<59),&g)!=SPTM_OK);
        for(unsigned bit=0;bit<64;bit++)if(bit<12 || bit>47) {
            if(bit==8 || bit==10 || bit==54 || bit==58)continue;
            CHECK(sptm_mac_user_leaf_policy(2,20,14,0x4000,rx^(1UL<<bit),&g)!=SPTM_OK);
        }
    }
    /* Bad source/type/address/shadow inputs cannot partly update metadata,
     * payload, canonical PTEs, private copies or publication counters. */
    for(unsigned bad=0;bad<6;bad++) {
        setup();uint64_t pa=DATA;
        if(bad==0)pa++;
        if(bad==1)CHECK(!wr(0,guest_slot,(DATA+0x4000)|ATTR|3));
        if(bad==2)CHECK(!wr(0,guest_slot,DATA|PT_AF|3));
        if(bad==3)CHECK(!wr(0,BASE+0x13000+8UL*mmu_index(12,3,VA+8192),0));
        if(bad==4)backend.kernel_root+=8;
        if(bad==5)aperture.size=8192;
        memcpy(before,ram,sizeof(ram));
        CHECK(sptm_papt_prepare(&memory,&backend,&aperture,0,pa,11,25,&t)!=SPTM_OK);
        CHECK(!memcmp(before,ram,sizeof(ram)) && !publications);
        aperture.size=0x8000;
    }
    /* A SLIDE_REGION-moved frame: ROZONE and USER_EXEC must re-permission
     * the moved alias too (the one Apple re-permissions, see
     * tools/replay-papt-moved-alias.py), with private views of both. */
    setup_moved();memcpy(before,ram,sizeof ram);
    CHECK(sptm_papt_prepare(&memory,&backend,&aperture,moved,DATA,11,25,&t)==SPTM_OK);
    CHECK(t.count==2 && t.leaf[0].va==VA && t.leaf[1].va==MOVED_VA);
    CHECK(t.leaf[1].guest_pa==moved_slot && sprr_pte_class(t.leaf[1].after)==2);
    CHECK(!memcmp(before,ram,sizeof ram) && !publications);
    CHECK(sptm_mac_retype(&memory,DATA,11,25,0)==SPTM_OK);
    CHECK(transitions==1 && ram[MAP-BASE+2]==25);
    CHECK(sprr_pte_class(get(moved_slot))==2 && sprr_pte_class(get(guest_slot))==2);
    for(unsigned n=0;n<4;n++) {
        uint64_t d=get(BASE+0x15000+8UL*mmu_index(12,3,(MOVED_VA&((1UL<<47)-1))+n*4096));
        CHECK((d&PT_OA_MASK)==DATA+n*4096 && sprr_pte_class(d)==2);
    }
    for(unsigned cpu=0;cpu<6;cpu++)verify_view(cpu,2,!!(pp[cpu]&0x100));
    CHECK(sptm_mac_retype(&memory,DATA,25,11,0)==SPTM_OK);
    CHECK(sprr_pte_class(get(moved_slot))==3);
    CHECK(get(moved_slot)==(DATA|3|(ATTR&(PT_LEAF_ATTRS&~0xc0UL))|(3UL<<53)));
    for(unsigned cpu=0;cpu<6;cpu++)verify_view(cpu,3,1);
    for(unsigned n=0;n<sizeof(payload);n++)CHECK(payload[n]==0xa5);
    setup_moved();
    CHECK(sptm_mac_retype(&memory,DATA,11,14,0)==SPTM_OK);
    CHECK(cache_syncs==1 && ram[MAP-BASE+2]==14);
    CHECK(sprr_pte_class(get(moved_slot))==11 && sprr_pte_class(get(guest_slot))==11);
    for(unsigned cpu=0;cpu<6;cpu++)verify_view(cpu,11,0);
    CHECK(sptm_mac_retype(&memory,DATA,14,11,0)==SPTM_OK);
    CHECK(sprr_pte_class(get(moved_slot))==3 && ram[MAP-BASE+2]==11);
    for(unsigned cpu=0;cpu<6;cpu++)verify_view(cpu,3,1);
    /* TPRO keeps selector3 on both aliases: nothing to write. */
    setup_moved();memcpy(before,ram,sizeof ram);
    CHECK(sptm_papt_prepare(&memory,&backend,&aperture,moved,DATA,11,17,&t)==SPTM_OK);
    CHECK(t.count==2 && t.leaf[1].before==t.leaf[1].after && !memcmp(before,ram,sizeof ram));
    /* A bad moved alias refuses the whole change: the linear leaf, shadows,
     * private views and publication counters stay untouched. */
    for(unsigned bad=0;bad<5;bad++) {
        setup_moved();
        if(bad==0)CHECK(!wr(0,moved_slot,0));
        if(bad==1)CHECK(!wr(0,moved_slot,(DATA+0x4000)|(get(moved_slot)&~PT_OA_MASK)));
        if(bad==2)CHECK(!wr(0,moved_slot,get(moved_slot)|(2UL<<6)));
        if(bad==3)CHECK(!wr(0,BASE+0x15000+8UL*mmu_index(12,3,(MOVED_VA&((1UL<<47)-1))+4096),0));
        if(bad==4)moved_regions[0].va=MOVED_VA+0x1000; /* misaligned alias */
        memcpy(before,ram,sizeof ram);
        CHECK(sptm_papt_prepare(&memory,&backend,&aperture,moved,DATA,11,25,&t)!=SPTM_OK);
        CHECK(sptm_mac_retype(&memory,DATA,11,25,0)!=SPTM_OK);
        CHECK(sptm_mac_retype(&memory,DATA,11,14,0)!=SPTM_OK);
        CHECK(!memcmp(before,ram,sizeof ram) && !publications && !transitions && !cache_syncs);
    }
    /* A frame outside the moved range keeps the single linear leaf. */
    setup_moved();moved_regions[0].pa=DATA+0x4000;moved_regions[0].pages=1;
    CHECK(sptm_papt_prepare(&memory,&backend,&aperture,moved,DATA,11,25,&t)==SPTM_OK);
    CHECK(t.count==1 && t.leaf[0].va==VA);
    moved_regions[0]=(struct sptm_slide_region){MOVED_VA,DATA,2};
    test_attr();
    printf("ROZONE aperture transaction: %u checks, %u failures\n",checks,failed);
    return failed ? 1 : 0;
}

/* SPDX-License-Identifier: MIT */
#include <stdio.h>
#include <string.h>
#include "sptm-user.h"
#include "sptm-refs.h"
#include "mmu.h"
#define BASE 0x90000000UL
#define SIZE 0x40000UL
#define FM (BASE+0x4000)
#define ROOT (BASE+0x8000)
#define L2 (BASE+0xc000)
#define L3 (BASE+0x10000)
#define DATA (BASE+0x14000)
#define L1 (BASE+0x18000)
#define VA 0xfffffc000UL
#define NX 0x00600000000007c3UL
#define RX 0x00200000000007c3UL
static unsigned checks,failures,publications;
static uint8_t ram[SIZE],before[SIZE];
static uint64_t fail_pa;
static struct sptm_ref_batch refs;
static unsigned conflict_shadow_calls;
static int conflict_forbidden_leaf(void *ctx,uint64_t root,uint64_t va,unsigned shift,uint64_t pte)
{(void)ctx;(void)root;(void)va;(void)shift;(void)pte;conflict_shadow_calls++;return 0;}
static void check(int ok,const char *what)
{ checks++;if(!ok) {failures++;printf("FAIL: %s\n",what);} }
static volatile uint8_t *map(void *ctx,uint64_t pa,uint64_t n)
{
    (void)ctx;
    if(pa<BASE || pa>=BASE+SIZE || n>BASE+SIZE-pa ||
       (fail_pa>=pa && fail_pa-pa<n)) return NULL;
    return ram+(pa-BASE);
}
/* Optional observers for suites that reuse this fixture (the SWITCH_ROOT
 * memo's write witness and retype hook); NULL for this suite. */
static void (*publish_observer)(void *ctx,uint64_t pa,uint64_t n);
static struct sptm_root_memo *fixture_root_memo;
static void publish(void *ctx,uint64_t pa,uint64_t n)
{
    check(map(ctx,pa,n)!=NULL,"published owned memory");publications++;
    if(publish_observer)publish_observer(ctx,pa,n);
}
static uint64_t get(uint64_t pa,unsigned n)
{ uint64_t v=0;for(unsigned i=0;i<n;i++) v|=(uint64_t)ram[pa-BASE+i]<<(8*i);return v; }
static void put(uint64_t pa,uint64_t v,unsigned n)
{ for(unsigned i=0;i<n;i++) ram[pa-BASE+i]=(uint8_t)(v>>(8*i)); }
static uint64_t meta(uint64_t pa) {return FM+((pa-BASE)>>14)*16;}
static int read64(void *ctx,uint64_t pa,uint64_t *v)
{ if(!map(ctx,pa,8))return -1;*v=get(pa,8);return 0; }
static uint64_t slot(uint64_t va) {return L3+8*mmu_index(14,3,va);}
static int retire(void *ctx,uint64_t pa,uint16_t asid)
{ (void)ctx;return pa==ROOT && asid==2; }
static struct sptm_user_backend backend={.aperture={BASE,0xfffffe0100000000UL,SIZE}};
static struct sptm_memory reset_geometry(unsigned type,unsigned flags,uint64_t va,unsigned format)
{
    memset(ram,0,SIZE);fail_pa=0;publications=0;backend.ttbr0=backend.ttbr1=0;
    for(unsigned i=0;i<SIZE/0x4000;i++) ram[FM-BASE+i*16+2]=11;
    struct sptm_memory m={.frame_map_pa=FM,.frame_low=BASE,.frame_high=BASE+SIZE,
        .alloc_low=ROOT,.alloc_high=BASE+SIZE,.map=map,.publish=publish,.refs=&refs,
        .root_memo=fixture_root_memo};
    check(sptm_mac_retype(&m,ROOT,11,18,(2UL<<32)|((uint64_t)flags<<16)|format)==SPTM_OK,"root constructor");
    check(sptm_mac_retype(&m,L2,11,20,2)==SPTM_OK,"L2 constructor");
    check(sptm_mac_retype(&m,L3,11,23,3)==SPTM_OK,"L3 constructor");
    check(sptm_mac_retype(&m,DATA,11,type,0)==SPTM_OK,"payload constructor");
    if(format) {
        check(sptm_mac_retype(&m,L1,11,20,1)==SPTM_OK,"4K L1 allocation frame");
        check(sptm_mac_map_user_table(&m,ROOT,va&~(3UL<<39),0,L1|3)==SPTM_OK,"four L1 subtable links");
    }
    check(sptm_mac_map_user_table(&m,ROOT,format ? va&~(3UL<<30) : va,1,L2|3)==SPTM_OK,"L2 link");
    check(sptm_mac_map_user_table(&m,ROOT,format ? va&~(3UL<<21) : va,2,L3|3)==SPTM_OK,"L3 link");
    return m;
}
static struct sptm_memory reset_at(unsigned type,unsigned flags,uint64_t va)
{return reset_geometry(type,flags,va,0);}
static struct sptm_memory reset(unsigned type) {return reset_at(type,2,VA);}
int main(void)
{
    uint64_t result;
    for(unsigned type=29;type<=31;type++) {
        struct sptm_memory m=reset(type);uint64_t pte=DATA|(type==31 ? RX : NX);
        memset(ram+(DATA-BASE),0xa5,0x4000);memset(ram,0x55,16);
        check(sptm_mac_map_user_page(&m,&backend,ROOT,VA,pte,1,UINT64_MAX,&result)==SPTM_OK,
              "commpage insertion succeeds with suppressed scratch output");
        check(!result && get(BASE,8)==0x5555555555555555UL,"new mapping result and untouched output");
        check(get(meta(L3)+8,2)==1,"one valid leaf in commpage table");
        check(get(meta(DATA)+(type==31 ? 12 : 8),4)==1,"correct data permission class count");
        check(get(meta(DATA)+(type==31 ? 8 : 12),4)==0,"other permission class remains empty");
        check(get(DATA,8)==0xa5a5a5a5a5a5a5a5UL,"initialized payload preserved");
        struct mmu_config cfg={.granule_shift=14,.txsz=17,.root=ROOT};
        struct mmu_leaf leaf;
        check(!mmu_walk(&cfg,VA,read64,0,&leaf) && leaf.valid && leaf.pa==DATA,
              "independent guest walker resolves inserted payload");
        check(sptm_mac_map_user_page(&m,&backend,ROOT,VA,pte,0,BASE,&result)==SPTM_OK,
              "identical leaf accepted");
        check(result==1 && get(BASE,8)==pte,"identical leaf returns existing status and descriptor");
        check(get(BASE+8,8)==backend.aperture.va+slot(VA)-BASE,"output PTE pointer uses guest aperture");
        check(get(meta(L3)+8,2)==1 && get(meta(DATA)+(type==31 ? 12 : 8),4)==1,
              "identical mapping does not double-count");
        if(type==31) {
            check(sptm_mac_map_user_page(&m,&backend,ROOT,VA-0x4000,DATA|NX,1,0,&result)==SPTM_OK,
                  "RX payload also accepts audited NX alias");
            check(get(meta(DATA)+8,4)==1 && get(meta(DATA)+12,4)==1,"commpage mixed aliases counted");
        }
    }
    for(unsigned n=0;n<25;n++) {
        struct sptm_memory m=reset(29);
        uint64_t root=ROOT,va=VA,pte=DATA|NX,options=0,scratch=BASE;
        enum sptm_result want=SPTM_BAD_TABLE;
        switch(n) {
        case 0:backend.ttbr0=ROOT|(7UL<<48);want=SPTM_FRAME_BUSY;break;
        case 1:backend.ttbr1=ROOT;want=SPTM_FRAME_BUSY;break;
        case 2:va=1UL<<47;want=SPTM_BAD_ADDRESS;break;
        case 3:va++;want=SPTM_BAD_ADDRESS;break;
        case 4:root++;want=SPTM_BAD_ADDRESS;break;
        case 5:options=2;want=SPTM_UNSUPPORTED_OPTIONS;break;
        case 6:put(meta(ROOT)+12,2,1);break;
        case 7:put(meta(ROOT)+4,0,2);break;
        case 8:put(meta(ROOT)+10,0x10,2);break;
        case 9:put(meta(L2)+4,3,1);break;
        case 10:put(meta(L3)+6,2,2);want=SPTM_FRAME_BUSY;break;
        case 11:put(L2+8*mmu_index(14,2,VA),ROOT|3,8);break;
        case 12:put(meta(L3)+2,20,1);want=SPTM_TYPE_MISMATCH;break;
        case 13:put(meta(DATA)+2,11,1);want=SPTM_TYPE_MISMATCH;break;
        case 14:pte=DATA|RX;want=SPTM_UNSUPPORTED_OPTIONS;break;
        case 15:pte&=~(1UL<<7);want=SPTM_UNSUPPORTED_OPTIONS;break;
        case 16:pte|=1UL<<52;want=SPTM_UNSUPPORTED_OPTIONS;break;
        case 17:put(slot(VA),DATA|RX,8);want=SPTM_TABLE_EXISTS;break;
        case 18:scratch=L3;want=SPTM_BAD_ADDRESS;break;
        case 19:scratch=FM;want=SPTM_BAD_ADDRESS;break;
        case 20:fail_pa=slot(VA);want=SPTM_MEMORY_UNAVAILABLE;break;
        case 21:fail_pa=meta(DATA);want=SPTM_MEMORY_UNAVAILABLE;break;
        case 22:put(meta(DATA)+8,INT32_MAX,4);want=SPTM_BAD_REFERENCE;break;
        case 23:put(meta(L3)+8,2048,2);want=SPTM_BAD_REFERENCE;break;
        case 24:m.aperture_va=VA;m.aperture_size=0x4000;want=SPTM_BAD_CONFIG;break;
        }
        memcpy(before,ram,SIZE);unsigned old=publications;result=0x1234;
        enum sptm_result got=sptm_mac_map_user_page(&m,&backend,root,va,pte,options,scratch,&result);
        if(got!=want) printf("case %u got %u wanted %u\n",n,got,want);
        check(got==want,"precise refusal");check(!memcmp(before,ram,SIZE),"refusal changes no guest memory");
        check(old==publications && result==0x1234,"refusal publishes and acknowledges nothing");
    }
    struct sptm_memory m=reset(29);m.retire_user_root=retire;
    check(get(meta(ROOT)+6,2)==1 && get(meta(L2)+8,2)==1,"root and L2 count their child links");
    check(sptm_mac_map_user_page(&m,&backend,ROOT,VA,DATA|NX,1,0,&result)==SPTM_OK,"detach fixture leaf");
    check(sptm_mac_unmap_user_table(&m,&backend,ROOT,VA,2)==SPTM_OK,"detach populated commpage table");
    check(get(slot(VA),8)==(DATA|NX) && get(meta(L3)+8,2)==1 && get(meta(DATA)+8,4)==1,
          "detachment retains leaves and both reference counts");
    check(!get(meta(L3)+6,2) && !get(meta(L2)+8,2) && get(meta(ROOT)+6,2)==1,
          "detachment removes only direct link counts");
    check(sptm_mac_unmap_user_table(&m,&backend,ROOT,VA,1)==SPTM_OK,"detach now empty L2");
    check(!get(meta(ROOT)+6,2) && !get(meta(L2)+6,2),"temporary root is unreferenced");
    check(sptm_mac_retype(&m,L2,20,11,0)==SPTM_OK,"recycle temporary L2");
    check(sptm_mac_retype(&m,ROOT,18,11,0)==SPTM_OK,"retire temporary root ASID and recycle");
    check(get(slot(VA),8)==(DATA|NX),"retained commpage survives temporary root destruction");
    for(unsigned n=0;n<8;n++) {
        m=reset(29);unsigned level=2;enum sptm_result want=SPTM_BAD_REFERENCE;
        switch(n) {
        case 0:put(meta(L2)+8,0,2);break;
        case 1:put(meta(L3)+6,0xfffa,2);break;
        case 2:put(meta(L3)+8,1,2);break;
        case 3:level=1;want=SPTM_FRAME_BUSY;break;
        case 4:backend.ttbr0=ROOT;want=SPTM_FRAME_BUSY;break;
        case 5:level=3;want=SPTM_UNSUPPORTED_OPTIONS;break;
        case 6:put(L2+8*mmu_index(14,2,VA),0,8);want=SPTM_TABLE_MISSING;break;
        case 7:fail_pa=L3;want=SPTM_MEMORY_UNAVAILABLE;break;
        }
        memcpy(before,ram,SIZE);unsigned old=publications;
        check(sptm_mac_unmap_user_table(&m,&backend,ROOT,VA,level)==want,"precise detach refusal");
        check(!memcmp(before,ram,SIZE) && old==publications,"detach refusal is atomic");
    }
    m=reset_at(29,0x22,0xffff4000);m.retire_user_root=retire;
    check(get(meta(ROOT)+10,2)==0x22,"ARM64_32 flag preserved in root metadata");
    check(sptm_mac_map_user_page(&m,&backend,ROOT,0xffff4000,DATA|NX,1,0,&result)==SPTM_OK,
          "32-bit commpage leaf installed");
    struct mmu_config cfg32={.granule_shift=14,.txsz=17,.root=ROOT};struct mmu_leaf leaf32;
    check(!mmu_walk(&cfg32,0xffff4000,read64,0,&leaf32) && leaf32.valid && leaf32.pa==DATA,
          "32-bit commpage independently resolves in unchanged 16K geometry");
    check(sptm_mac_retype(&m,BASE+0x18000,11,20,2)==SPTM_OK,"fresh child for VA-boundary refusal");
    memcpy(before,ram,SIZE);unsigned old=publications;
    check(sptm_mac_map_user_page(&m,&backend,ROOT,0x100000000UL,DATA|NX,1,0,&result)==SPTM_BAD_ADDRESS,
          "ARM64_32 refuses VAs above four GiB");
    check(sptm_mac_map_user_table(&m,ROOT,0x100000000UL,1,(BASE+0x18000)|3)==SPTM_BAD_ADDRESS,
          "ARM64_32 table construction refuses VAs above four GiB");
    check(!memcmp(before,ram,SIZE) && old==publications,"32-bit refusal preserves existing mapping");
    check(sptm_mac_unmap_user_table(&m,&backend,ROOT,0xffff4000,2)==SPTM_OK,"detach 32-bit commpage");
    check(sptm_mac_unmap_user_table(&m,&backend,ROOT,0xffff4000,1)==SPTM_OK,"detach empty 32-bit L2");
    check(sptm_mac_retype(&m,ROOT,18,11,0)==SPTM_OK,"retire 32-bit temporary root");
    for(unsigned variant=0;variant<3;variant++) {
        unsigned flags=variant==0 ? 2 : variant==1 ? 0x22 : 6;
        uint64_t va=flags==2 ? VA : flags==6 ? 0x7fffffffc000UL : 0xffffc000UL;
        m=reset_geometry(29,flags,va,1);m.retire_user_root=retire;
        check(get(meta(ROOT)+12,1)==1,"format 1 remains in root metadata");
        check(get(meta(ROOT)+6,2)==1 && get(meta(L1)+8,2)==1 && get(meta(L2)+8,2)==1,
              "four descriptors count as one parent link group");
        struct mmu_config cfg4={.granule_shift=12,.txsz=17,.root=ROOT};
        for(unsigned n=0;n<4;n++) {
            uint64_t pte=(DATA+n*0x1000)|NX;
            check(sptm_mac_map_user_page(&m,&backend,ROOT,va+n*0x1000,pte,0,BASE,&result)==SPTM_OK,
                  "4K leaf accepts a subpage of a typed 16K payload");
            struct mmu_leaf leaf4;
            check(!mmu_walk(&cfg4,va+n*0x1000,read64,0,&leaf4) && leaf4.valid && leaf4.pa==DATA+n*0x1000,
                  "independent 4K walker resolves every physical subpage");
            uint64_t actual_slot=L3+0x3000+((va+n*0x1000)>>12&511)*8;
            check(get(BASE+8,8)==backend.aperture.va+actual_slot-BASE,"4K output points at actual subtable slot");
        }
        check(get(meta(DATA)+8,4)==4 && get(meta(L3)+8,2)==4,"4K leaves count against their shared physical frames");
        if(flags==6) {
            const uint64_t rejected_vas[]={0x7fffff800000UL,0x7fffffdff000UL,0x800000000000UL};
            memcpy(before,ram,SIZE);unsigned prior=publications;
            for(unsigned n=0;n<3;n++)
                check(sptm_mac_map_user_page(&m,&backend,ROOT,rejected_vas[n],DATA|NX,1,0,&result)==SPTM_BAD_ADDRESS,
                      "x86 leaves stay within their 2 MiB commpage window");
            check(sptm_mac_map_user_table(&m,ROOT,0x7fffff000000UL,2,L3|3)==SPTM_BAD_ADDRESS,
                  "x86 commpage group cannot start below its 8 MiB container");
            check(!memcmp(before,ram,SIZE) && publications==prior,"x86 boundary refusals preserve mapped subpages");
        }
        check(sptm_mac_unmap_user_table(&m,&backend,ROOT,va&~(3UL<<21),2)==SPTM_OK,"detach grouped 4K commpage");
        check(!get(meta(L3)+6,2) && get(meta(L3)+8,2)==4 && get(meta(DATA)+8,4)==4,
              "4K detach preserves all leaf and data counts");
        check(sptm_mac_unmap_user_table(&m,&backend,ROOT,va&~(3UL<<30),1)==SPTM_OK,"detach empty 4K L2 group");
        check(sptm_mac_unmap_user_table(&m,&backend,ROOT,va&~(3UL<<39),0)==SPTM_OK,"detach empty 4K L1 group");
        check(sptm_mac_retype(&m,ROOT,18,11,0)==SPTM_OK,"retire format-1 root");
    }
    for(unsigned n=0;n<7;n++) {
        m=reset_geometry(29,2,VA,1);uint64_t va=VA;int unmap=0;
        enum sptm_result want=SPTM_BAD_TABLE;
        switch(n) {
        case 0:put(ROOT+24,0,8);break;
        case 1:put(L1+63*8,L2|3,8);break;
        case 2:put(L2+0x3000+510*8,0,8);break;
        case 3:va++;want=SPTM_BAD_ADDRESS;break;
        case 4:unmap=1;want=SPTM_BAD_ADDRESS;break;
        case 5:unmap=1;va=VA&~(3UL<<21);put(L2+0x3000+510*8,0,8);break;
        case 6:fail_pa=L3+0x3000;want=SPTM_MEMORY_UNAVAILABLE;break;
        }
        memcpy(before,ram,SIZE);unsigned prior=publications;
        enum sptm_result got=unmap ? sptm_mac_unmap_user_table(&m,&backend,ROOT,va,2) :
            sptm_mac_map_user_page(&m,&backend,ROOT,va,DATA|NX,1,0,&result);
        if(got!=want) printf("4K refusal case %u got %u wanted %u\n",n,got,want);
        check(got==want,"4K malformed group or request refused");
        check(!memcmp(before,ram,SIZE) && prior==publications,"4K refusal is atomic across the whole group");
    }
    m=reset_geometry(29,2,VA,1);
    check(sptm_mac_unmap_user_table(&m,&backend,ROOT,VA&~(3UL<<21),2)==SPTM_OK,"group collision fixture detached");
    put(L2+0x3000+511*8,L3+0x3000+3,8);
    memcpy(before,ram,SIZE);old=publications;
    check(sptm_mac_map_user_table(&m,ROOT,VA&~(3UL<<21),2,L3|3)==SPTM_TABLE_EXISTS,
          "occupied final slot prevents entire group publication");
    check(!memcmp(before,ram,SIZE) && old==publications,"earlier group slots and counts untouched on late collision");
    m=reset_geometry(29,2,VA,0);
    put(meta(L3)+2,20,1);put(meta(DATA)+2,14,1);
    uint64_t executable=DATA|0x0020000000000ec3UL;
    check(sptm_mac_map_user_page(&m,&backend,ROOT,VA,executable,1,0,&result)==SPTM_OK,
          "USER_EXEC page installs as user read-only executable");
    check(get(slot(VA),8)==executable && get(meta(DATA)+12,4)==1,
          "executable descriptor and live reference both published");
    memcpy(before,ram,SIZE);old=publications;
    check(sptm_mac_map_user_page(&m,&backend,ROOT,VA-0x4000,DATA|0x0060000000000e43UL,1,0,&result)==SPTM_UNSUPPORTED_OPTIONS,
          "typed executable frame cannot acquire a writable user alias");
    check(!memcmp(before,ram,SIZE) && old==publications,"writable executable refusal leaves memory unchanged");
    /* Genuine status6 is a protocol response, not an in-place replacement.
     * Test both granules, output modes and every4K member of an allocation. */
    for(unsigned format=0;format<2;format++)for(unsigned part=0;part<(format?4:1);part++)
    for(unsigned options=0;options<2;options++)for(unsigned active=0;active<=6;active++) {
        uint64_t va=VA+part*0x1000,new_frame=BASE+0x20000;
        m=reset_geometry(29,2,va,format);put(meta(L3)+2,20,1);put(meta(DATA)+2,11,1);
        uint64_t initial=(DATA+part*0x1000)|0x0060000000000ec3UL;
        uint64_t wanted=(new_frame+part*0x1000)|0x0060000000000e43UL;
        check(sptm_mac_map_user_page(&m,&backend,ROOT,va,initial,1,0,&result)==SPTM_OK,
              "conflict fixture installs read-only ordinary user leaf");
        backend.active_refs=active;backend.ttbr0=active ? ROOT|(2UL<<48) : 0;
        backend.prepare_leaf=backend.commit_leaf=conflict_forbidden_leaf;
        put(meta(ROOT)+6,get(meta(ROOT)+6,2)+active,2);conflict_shadow_calls=0;
        memcpy(before,ram,SIZE);old=publications;result=0x1234;
        check(sptm_mac_map_user_page(&m,&backend,ROOT,va,wanted,options,
              options?UINT64_MAX:BASE,&result)==SPTM_OK && result==SPTM_USER_MAP_CONFLICT,
              "different frame returns native status6");
        if(!options) {
            check(get(BASE,8)==initial,"conflict reports existing descriptor");
            struct mmu_config cfg={.granule_shift=format?12:14,.txsz=17,.root=ROOT};
            struct mmu_leaf leaf;
            check(!mmu_walk(&cfg,va,read64,0,&leaf) && leaf.pa==DATA+part*0x1000,
                  "conflict keeps old translation");
            check(get(BASE+8,8)>=backend.aperture.va &&
                  get(get(BASE+8,8)-backend.aperture.va+BASE,8)==initial,
                  "conflict reports the actual guest PTE pointer");
            memcpy(ram,before,16);
        }
        check(!memcmp(before,ram,SIZE),"conflict preserves descriptors, payloads and all reference counts");
        check(publications==old+!options,"conflict publishes only requested scratch output");
        check(!conflict_shadow_calls,"conflict never mutates an active hardware shadow");
        if(!options) {
            fail_pa=BASE;result=0x1234;old=publications;
            check(sptm_mac_map_user_page(&m,&backend,ROOT,va,wanted,0,BASE,&result)==SPTM_MEMORY_UNAVAILABLE,
                  "conflict output failure is not acknowledged");
            check(result==0x1234 && old==publications && !memcmp(before,ram,SIZE),
                  "failed conflict preflight changes nothing");
        }
        backend.active_refs=0;backend.ttbr0=0;backend.prepare_leaf=backend.commit_leaf=0;
        put(meta(ROOT)+6,get(meta(ROOT)+6,2)-active,2);
        fail_pa=0;
        check(sptm_mac_unmap_user_region(&m,&backend,ROOT,va,1,0,BASE)==SPTM_OK,
              "XNU can remove the conflicting read-only mapping");
        check(sptm_mac_map_user_page(&m,&backend,ROOT,va,wanted,0,BASE,&result)==SPTM_OK && result==0,
              "XNU retry inserts the new writable frame");
        check(get(meta(DATA)+8,4)==0 && get(meta(new_frame)+12,4)==1 && get(meta(L3)+8,2)==1,
              "remove and retry transfers the reference without changing mapped-leaf count");
    }
    printf("%u checks, %u failures\n",checks,failures);return failures!=0;
}

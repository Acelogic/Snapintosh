/* SPDX-License-Identifier: MIT */
/* cc -std=gnu11 -O1 -g -fsanitize=address,undefined -fno-sanitize-recover=all \
 * -Icompat -Ishadow tools/test-sptm-table.c compat/sptm.c compat/sptm-user.c compat/sptm-unmap.c compat/sptm-refs.c shadow/mmu.c \
 * shadow/shadow.c -o build/test-sptm-table */
#include <stdio.h>
#include <string.h>
#include "sptm.h"
#include "sptm-refs.h"
#include "shadow.h"

#define BASE 0x90000000UL
#define SIZE 0x40000UL
#define ROOT BASE
#define FM (BASE + 0x4000)
#define L2 (BASE + 0x8000)
#define L3 (BASE + 0xc000)
#define VA 0xfffffe12ce018000UL
static uint8_t ram[SIZE], before[SIZE];
static unsigned checks, failures, publications;
static uint64_t next_shadow;
static struct sptm_ref_batch references;
static void check(int good, const char *label)
{
    checks++;
    if (!good) { failures++; printf("FAIL: %s\n", label); }
}
static volatile uint8_t *map(void *ctx, uint64_t pa, uint64_t size)
{
    (void)ctx;
    return pa < BASE || pa >= BASE+SIZE || size > BASE+SIZE-pa ? NULL : ram+(pa-BASE);
}
static void publish(void *ctx, uint64_t pa, uint64_t size)
{
    check(map(ctx, pa, size) != NULL, "publication within owned memory");
    publications++;
}
static int read64(void *ctx, uint64_t pa, uint64_t *v)
{
    volatile uint8_t *p = map(ctx, pa, 8);
    if (!p) return -1;
    *v=0; for (unsigned i=0;i<8;i++) *v |= (uint64_t)p[i]<<(i*8);
    return 0;
}
static int write64(void *ctx, uint64_t pa, uint64_t v)
{
    volatile uint8_t *p = map(ctx, pa, 8);
    if (!p) return -1;
    for (unsigned i=0;i<8;i++) p[i] = (uint8_t)(v>>(i*8));
    return 0;
}
static uint64_t alloc(void *ctx)
{
    (void)ctx; uint64_t pa=next_shadow; next_shadow+=0x1000;
    return next_shadow > BASE+SIZE ? 0 : pa;
}
static struct sptm_memory reset(void)
{
    memset(ram, 0, SIZE); publications=0; next_shadow=BASE+0x20000;
    for (unsigned i=0;i<SIZE/0x4000;i++) ram[0x4000+i*16+2]=11;
    return (struct sptm_memory){.frame_map_pa=FM,.frame_low=BASE,.frame_high=BASE+SIZE,
        .alloc_low=L2,.alloc_high=BASE+0x20000,.map=map,.publish=publish,.refs=&references};
}
static void retype(struct sptm_memory *m, uint64_t pa, unsigned level)
{
    check(sptm_mac_retype(m,pa,11,20,level)==SPTM_OK,"child retype succeeds");
}
static void reject(struct sptm_memory *m,uint64_t root,uint64_t va,uint64_t level,
                   uint64_t tte,enum sptm_result want)
{
    memcpy(before,ram,SIZE); unsigned old=publications;
    check(sptm_mac_map_table(m,root,va,level,tte)==want,"correct table refusal");
    check(!memcmp(before,ram,SIZE),"refused installation changed no memory");
    check(publications==old,"refused installation published nothing");
}
static void reject_user(struct sptm_memory *m,uint64_t root,uint64_t va,uint64_t level,
                        uint64_t tte,enum sptm_result want)
{
    memcpy(before,ram,SIZE);unsigned old=publications;
    enum sptm_result got=sptm_mac_map_user_table(m,root,va,level,tte);
    if(got!=want) printf("user root %llx VA %llx level %llu got %u expected %u\n",
        (unsigned long long)root,(unsigned long long)va,(unsigned long long)level,got,want);
    check(got==want,"correct user table refusal");
    check(!memcmp(before,ram,SIZE),"rejected user installation is atomic");
    check(publications==old,"rejected user installation publishes nothing");
}
int main(void)
{
    struct sptm_aperture aperture={.pa=0xda000000,.va=0xfffffe0100000000UL,
                                  .size=0x18000000};
    uint64_t ptep=sptm_aperture_pointer(&aperture,0xe4964000,8);
    check(ptep==0xfffffe010a964000UL,"MAP_PAGE returns the guest aperture pointer");
    uint64_t mask=0x9b3ffffffffffff8UL, tag=0x64c0000000000000UL;
    check(((ptep&mask)|tag)==ptep,"PTE pointer survives XNU PVH encoding");
    check(((0xe4964000UL&mask)|tag)!=ptep,"physical PTE pointer reproduces old PVH fault");
    check(sptm_aperture_pointer(&aperture,0xda000000,8)==aperture.va,"aperture lower boundary");
    check(sptm_aperture_pointer(&aperture,0xf1fffff8,8)==aperture.va+aperture.size-8,
          "last complete PTE within aperture");
    check(!sptm_aperture_pointer(&aperture,0xf1fffffc,8),"reject PTE crossing aperture end");
    check(!sptm_aperture_pointer(&aperture,0xd9ffffff,8),"reject PTE below aperture");
    aperture.va=UINT64_MAX-16;
    check(!sptm_aperture_pointer(&aperture,0xda000000,8),"reject wrapping guest aperture");
    struct sptm_memory m=reset();
    retype(&m,L2,2);
    check(sptm_mac_retype(&m,L3,11,SPTM_MAC_PAGE_TABLE_ROZONE,3)==SPTM_OK,
          "ROZONE table shares the audited table constructor");
    reject(&m,ROOT,VA,2,L3|3,SPTM_TABLE_MISSING);
    check(sptm_mac_map_table(&m,ROOT,VA,1,L2|3)==SPTM_OK,"install L2");
    check(sptm_mac_map_table(&m,ROOT,VA,2,L3|3)==SPTM_OK,"install L3");
    check(ram[0x4000+2*16+6]==1 && ram[0x4000+3*16+6]==1,"child table counts both one");
    struct mmu_config guest={.granule_shift=14,.txsz=17,.root=ROOT};
    struct mmu_leaf leaf;
    check(!mmu_walk(&guest,VA,read64,NULL,&leaf) && !leaf.valid && leaf.level==3,
          "guest walk reaches new empty leaf table");
    struct shadow s={.txsz=17,.root=alloc(NULL),.alloc=alloc,.read=read64,.write=write64};
    struct mmu_config hw={.granule_shift=12,.txsz=17,.root=s.root};
    check(!mmu_walk(&hw,VA,read64,NULL,&leaf) && !leaf.valid,"empty installation has no hardware mapping");
    uint64_t data=BASE+0x18000;
    write64(NULL,L3+8*mmu_index(14,3,VA),data|PT_VALID|PT_TABLE|PT_AF|(3UL<<8));
    check(!mmu_walk(&guest,VA,read64,NULL,&leaf) && leaf.valid,"later guest leaf resolves");
    uint64_t off=VA & ((1UL<<47)-1);
    check(!shadow_insert(&s,&leaf,off,off+0x4000),"populate shadow from guest leaf");
    for (unsigned i=0;i<0x4000;i+=0x1000) {
        struct mmu_leaf g,h;
        check(!mmu_walk(&guest,VA+i,read64,NULL,&g) &&
              !mmu_walk(&hw,VA+i,read64,NULL,&h) && g.valid && h.valid && g.pa==h.pa,
              "all four hardware pages agree with guest after table expansion");
    }
    uint64_t scratch=BASE+0x18000;
    uint64_t desc=data|PT_VALID|PT_TABLE|PT_AF|(3UL<<8);
    write64(NULL,L3+8*mmu_index(14,3,VA+0x4000),desc);
    check(!shadow_map(&s,off+0x4000,data,0x4000,PT_AF|(3UL<<8),0),"adjacent mapping installed");
    sptm_refs_begin(m.refs);
    check(sptm_refs_leaf(&m,L3,VA,0,desc)==SPTM_OK,"first alias reference");
    check(sptm_refs_leaf(&m,L3,VA+0x4000,0,desc)==SPTM_OK,"second alias reference");
    check(sptm_refs_validate(&m)==SPTM_OK,"alias counts validated");sptm_refs_commit(&m);
    memcpy(before,ram,SIZE);
    check(sptm_mac_unmap_region(&m,&s,ROOT,VA,1,0x200,scratch)==SPTM_UNSUPPORTED_OPTIONS,
          "unknown unmap options rejected");
    check(!memcmp(before,ram,SIZE),"rejected unmap changes no memory");
    check(sptm_mac_unmap_region(&m,&s,ROOT,VA,1,0x100,scratch)==SPTM_UNSUPPORTED_OPTIONS,
          "older monitor deferred-invalidation flag refused");
    check(!memcmp(before,ram,SIZE),"deferred-invalidation refusal changes no memory");
    check(sptm_mac_unmap_region(&m,&s,ROOT,VA,1,1,scratch)==SPTM_OK,"region unmap with remove-compressed option succeeds");
    uint64_t prev=0; read64(NULL,scratch,&prev);
    check(prev==desc,"scratch returns exact previous guest descriptor");
    for (unsigned i=0;i<0x4000;i+=0x1000) {
        struct mmu_leaf g,h;
        check(!mmu_walk(&guest,VA+i,read64,NULL,&g) &&
              !mmu_walk(&hw,VA+i,read64,NULL,&h) && !g.valid && !h.valid,
              "all four shadow pages and guest leaf removed");
    }
    check(!mmu_walk(&guest,VA+0x4000,read64,NULL,&leaf) && leaf.valid,
          "adjacent guest mapping preserved");
    check(!mmu_walk(&hw,VA+0x4000,read64,NULL,&leaf) && leaf.valid,
          "adjacent shadow mapping preserved");
    check(sptm_mac_unmap_region(&m,&s,ROOT,VA,1,1,scratch)==SPTM_OK,
          "unmapping a hole is harmless with remove-compressed option");
    read64(NULL,scratch,&prev); check(!prev,"hole reports previous PTE zero");
    check(!shadow_map(&s,0x200000,0x200000,0x200000,PT_AF,0),"test block mapped");
    memcpy(before,ram,SIZE);
    check(shadow_unmap(&s,0x201000,0x1000,0)!=0,"partial block removal refuses unsupported split");
    check(!memcmp(before,ram,SIZE),"partial block refusal changes no descriptor");
    check(!shadow_unmap(&s,0x200000,0x200000,0),"whole block removal succeeds");
    retype(&m,BASE+0x10000,3);
    reject(&m,ROOT,VA,2,(BASE+0x10000)|3,SPTM_TABLE_EXISTS);
    for (unsigned n=0;n<10;n++) {
        m=reset(); retype(&m,L2,2);
        switch(n) {
        case 0: reject(&m,ROOT+1,VA,1,L2|3,SPTM_BAD_TABLE); break;
        case 1: reject(&m,ROOT,VA,0,L2|3,SPTM_BAD_TABLE); break;
        case 2: reject(&m,ROOT,VA,3,L2|3,SPTM_BAD_TABLE); break;
        case 3: reject(&m,ROOT,0x123000,1,L2|3,SPTM_BAD_TABLE); break;
        case 4: reject(&m,ROOT,VA,1,L2|0x1003,SPTM_BAD_TABLE); break;
        case 5: reject(&m,ROOT,VA,1,L2|1,SPTM_BAD_TABLE); break;
        case 6: ram[L2-BASE]=1; reject(&m,ROOT,VA,1,L2|3,SPTM_BAD_TABLE); break;
        case 7: ram[0x4000+2*16+6]=1; reject(&m,ROOT,VA,1,L2|3,SPTM_FRAME_BUSY); break;
        case 8: ram[0x4000+2*16+4]=3; reject(&m,ROOT,VA,1,L2|3,SPTM_TYPE_MISMATCH); break;
        case 9: reject(&m,L2,VA,1,L2|3,SPTM_BAD_TABLE); break;
        }
    }
    const uint64_t user_root=BASE+0x10000,user_va=0xfffffc000;
    const unsigned root_meta=0x4000+4*16;
    m=reset();
    check(sptm_mac_retype(&m,user_root,11,18,(2UL<<32)|0x20000)==SPTM_OK,
          "allocate a format-zero inactive user root");
    retype(&m,L2,2);
    check(sptm_mac_retype(&m,L3,11,SPTM_MAC_PAGE_TABLE_COMMPAGE,3)==SPTM_OK,
          "commpage leaf table uses its own frame role");
    reject_user(&m,user_root,user_va,2,L3|3,SPTM_TABLE_MISSING);
    memcpy(before,ram,SIZE);
    check(sptm_mac_map_user_table(&m,user_root,user_va,1,L2|3)==SPTM_OK,
          "install an empty L2 under an inactive user root");
    uint64_t tte=L2|3;
    memcpy(before+(user_root-BASE)+8*mmu_index(14,1,user_va),&tte,8);
    before[0x4000+2*16+6]=1;
    before[root_meta+6]=1;
    check(!memcmp(before,ram,SIZE),"user table insertion changes only its slot and child count");
    check(sptm_mac_map_user_table(&m,user_root,user_va,2,L3|3)==SPTM_OK,
          "install an empty L3 through a typed user L2");
    struct mmu_config user_view={.granule_shift=14,.txsz=17,.root=user_root};
    check(!mmu_walk(&user_view,user_va,read64,NULL,&leaf) && !leaf.valid && leaf.level==3,
          "47-bit user walk reaches its reserved empty L3");
    check(ram[root_meta+4]==2 && ram[root_meta+8]==0xff && ram[root_meta+10]==2,
          "user ASID and root ownership fields are unchanged");
    m=reset();
    check(sptm_mac_retype(&m,user_root,11,18,(2UL<<32)|0x20000)==SPTM_OK,
          "high user VA fixture root");
    retype(&m,L2,2);
    check(sptm_mac_map_user_table(&m,user_root,(1UL<<47)-0x4000,1,L2|3)==SPTM_OK,
          "format zero accepts the last 16K page of its 47-bit user space");
    check(!mmu_walk(&user_view,(1UL<<47)-0x4000,read64,NULL,&leaf) &&
          !leaf.valid && leaf.level==2,"high user VA reaches its newly allocated L2");
    for(unsigned n=0;n<13;n++) {
        m=reset();
        check(sptm_mac_retype(&m,user_root,11,18,(2UL<<32)|0x20000)==SPTM_OK,"user fixture root");
        retype(&m,L2,2);
        switch(n) {
        case 0: reject_user(&m,user_root,1UL<<47,1,L2|3,SPTM_BAD_ADDRESS);break;
        case 1: reject_user(&m,user_root,VA,1,L2|3,SPTM_BAD_ADDRESS);break;
        case 2: reject_user(&m,user_root,user_va+1,1,L2|3,SPTM_BAD_ADDRESS);break;
        case 3: reject_user(&m,ROOT,user_va,1,L2|3,SPTM_BAD_ADDRESS);break;
        case 4: ram[root_meta+2]=11;reject_user(&m,user_root,user_va,1,L2|3,SPTM_BAD_TABLE);break;
        case 5: ram[root_meta+12]=2;reject_user(&m,user_root,user_va,1,L2|3,SPTM_BAD_TABLE);break;
        /* Zero is valid after address PAUTH is disabled; this 16K format
         * rejects the x86 commpage flag (bit2). */
        case 6: ram[root_meta+10]=4;reject_user(&m,user_root,user_va,1,L2|3,SPTM_BAD_TABLE);break;
        case 7: ram[root_meta+8]=0;reject_user(&m,user_root,user_va,1,L2|3,SPTM_BAD_TABLE);break;
        case 8: ram[root_meta+4]=0;reject_user(&m,user_root,user_va,1,L2|3,SPTM_BAD_TABLE);break;
        case 9: ram[root_meta]=1;reject_user(&m,user_root,user_va,1,L2|3,SPTM_FRAME_BUSY);break;
        case 10: ram[0x4000+2*16+2]=22;reject_user(&m,user_root,user_va,1,L2|3,SPTM_TYPE_MISMATCH);break;
        case 11: ram[0x4000+2*16+6]=1;reject_user(&m,user_root,user_va,1,L2|3,SPTM_FRAME_BUSY);break;
        case 12:
            check(sptm_mac_map_user_table(&m,user_root,user_va,1,L2|3)==SPTM_OK,"user L2 fixture");
            retype(&m,L3,3);ram[0x4000+2*16+4]=3;
            reject_user(&m,user_root,user_va,2,L3|3,SPTM_BAD_TABLE);break;
        }
    }
    for(unsigned flags=2;flags<=0x22;flags+=0x20) {
        m=reset();
        uint64_t top=flags==2 ? (1UL<<36) : (1UL<<32);
        uint64_t window=flags==2 ? 0x40000000UL : 0x2000000UL;
        check(sptm_mac_retype(&m,user_root,11,18,(2UL<<32)|((uint64_t)flags<<16))==SPTM_OK,
              "commpage placement root flags accepted");
        retype(&m,L2,2);
        check(sptm_mac_retype(&m,L3,11,23,3)==SPTM_OK,"placement test commpage table");
        reject_user(&m,user_root,top,2,L3|3,SPTM_BAD_ADDRESS);
        reject_user(&m,user_root,top-window-0x4000,2,L3|3,SPTM_BAD_ADDRESS);
        check(sptm_mac_map_user_table(&m,user_root,top-0x4000,1,L2|3)==SPTM_OK,"placement parent linked");
        check(sptm_mac_map_user_table(&m,user_root,top-0x4000,2,L3|3)==SPTM_OK,"last commpage VA accepted");
    }
    printf("%u checks, %u failures\n",checks,failures); return failures!=0;
}

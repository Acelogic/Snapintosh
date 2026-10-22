/* SPDX-License-Identifier: MIT */
/* cc -std=gnu11 -O1 -g -fsanitize=address,undefined -Ishadow -Icompat \
 * tools/test-native-writer.c shadow/mmu.c shadow/shadow.c -o build/test-native-writer */
#include <stdio.h>
#include <string.h>
#include "shadow.h"
#include "native-writer.h"

static unsigned checks,failed;
#define CHECK(x) do {checks++;if(!(x)){failed++;printf("FAIL line %u: %s\n",__LINE__,#x);}}while(0)
#define BASE UINT64_C(0x40000000)
#define SIZE (256u*1024u)
static unsigned char ram[SIZE];
static unsigned allocations,stores,admissions;
static uint64_t next;
static struct native_writer_mapping mapping={{UINT64_C(0x8c48ea000),UINT64_C(0x8c48eb000)}};
static enum native_writer_regime regime;
static uint64_t alloc(void *ctx)
{
    (void)ctx;if(next+4096>SIZE)return 0;
    uint64_t pa=BASE+next;next+=4096;allocations++;return pa;
}
static int read_word(void *ctx,uint64_t pa,uint64_t *value)
{
    (void)ctx;if(pa<BASE || pa>BASE+SIZE-8 || (pa&7))return -1;
    memcpy(value,ram+(pa-BASE),8);return 0;
}
static int write_word(void *ctx,uint64_t pa,uint64_t value)
{
    (void)ctx;if(pa<BASE || pa>BASE+SIZE-8 || (pa&7))return -1;
    stores++;memcpy(ram+(pa-BASE),&value,8);return 0;
}
static int admit(void *ctx,uint64_t va,uint64_t pa,uint64_t size,uint64_t low,uint64_t upper)
{
    CHECK(ctx==&mapping);admissions++;
    CHECK(!(low&~PT_LEAF_ATTRS) && !(upper&~PT_LEAF_UPPER));
    return native_writer_mapping_admit(ctx,regime,va,pa,size,low,upper);
}
static struct shadow reset(enum native_writer_regime mode)
{
    memset(ram,0,sizeof(ram));next=allocations=stores=admissions=0;regime=mode;
    struct shadow s={.txsz=17,.alloc=alloc,.read=read_word,.write=write_word,
                     .ctx=&mapping,.admit=admit};
    s.root=alloc(0);return s;
}
static struct mmu_leaf lookup(const struct shadow *s,uint64_t va)
{
    struct mmu_config cfg={12,17,s->root};struct mmu_leaf out;
    CHECK(!mmu_walk(&cfg,va,read_word,0,&out));return out;
}
static int page_oracle(enum native_writer_regime mode,uint64_t va,uint64_t pa,
                       unsigned pages,uint64_t upper)
{
    /* Deliberately enumerate pages, independently of the range-intersection
     * arithmetic used by admission. This catches interior/end boundaries. */
    for(unsigned n=0;n<pages;n++)for(unsigned w=0;w<2;w++) {
        if(pa+n*4096!=mapping.pa[w])continue;
        if((upper&(PT_PXN|PT_UXN))==(PT_PXN|PT_UXN))continue;
        if(mode==NATIVE_WRITER_KERNEL_HIGH && va+n*4096==native_writer_page_va(w))continue;
        return 0;
    }
    return 1;
}
int main(void)
{
    const uint64_t canonical=native_writer_page_va(0),alias=UINT64_C(0x7e01048ea000);
    for(unsigned mode=0;mode<3;mode++)for(unsigned attrs=0;attrs<4;attrs++)
    for(int before=-8;before<=8;before++)for(unsigned pages=1;pages<=20;pages++) {
        uint64_t pa=mapping.pa[0]+(int64_t)before*4096;
        uint64_t upper=(attrs&1?PT_PXN:0)|(attrs&2?PT_UXN:0);
        for(unsigned high=0;high<2;high++) {
            uint64_t va=(high?canonical:alias)+(int64_t)before*4096;
            CHECK(native_writer_mapping_admit(&mapping,mode,va,pa,pages*4096,0,upper)==
                  page_oracle(mode,va,pa,pages,upper));
        }
    }
    struct native_writer_mapping bad=mapping;
    bad.pa[1]=bad.pa[0];CHECK(!native_writer_mapping_valid(&bad));
    bad=mapping;bad.pa[0]++;CHECK(!native_writer_mapping_valid(&bad));
    bad=mapping;bad.pa[0]=UINT64_C(1)<<48;CHECK(!native_writer_mapping_valid(&bad));
    CHECK(!native_writer_mapping_valid(0));
    CHECK(!native_writer_mapping_admit(&mapping,-1,0,0,4096,0,0));
    CHECK(!native_writer_mapping_admit(&mapping,3,0,0,4096,0,0));
    CHECK(!native_writer_mapping_admit(&mapping,0,UINT64_C(1)<<47,0,4096,0,0));
    CHECK(!native_writer_mapping_admit(&mapping,0,(UINT64_C(1)<<47)-4096,0,8192,0,0));
    CHECK(!native_writer_mapping_admit(&mapping,0,0,(UINT64_C(1)<<48)-4096,8192,0,0));
    CHECK(!native_writer_mapping_admit(&mapping,0,0,0,UINT64_MAX-4095,0,0));
    CHECK(!native_writer_mapping_admit(&mapping,0,1,0,4096,0,0));
    CHECK(!native_writer_mapping_admit(&mapping,0,0,1,4096,0,0));
    CHECK(!native_writer_mapping_admit(&mapping,0,0,0,4097,0,0));
    CHECK(native_writer_mapping_admit(&mapping,0,0,0,0,0,0));

    struct shadow s=reset(NATIVE_WRITER_KERNEL_HIGH);
    uint64_t before_ram[SIZE/8];memcpy(before_ram,ram,SIZE);
    unsigned before_alloc=allocations,before_stores=stores;
    /* A rejected interior page cannot leave an allowed prefix published. */
    CHECK(shadow_map(&s,alias-4096,mapping.pa[0]-4096,4*4096,PT_AF,0)<0);
    CHECK(allocations==before_alloc && stores==before_stores && !memcmp(before_ram,ram,SIZE));
    CHECK(admissions==1 && !lookup(&s,alias).valid);
    CHECK(!shadow_map(&s,canonical,mapping.pa[0],8192,PT_AF,PT_UXN));
    for(unsigned i=0;i<2;i++) {
        struct mmu_leaf leaf=lookup(&s,canonical+i*4096);
        CHECK(leaf.valid && leaf.pa==mapping.pa[i] && !(leaf.descriptor&PT_PXN));
    }
    CHECK(!shadow_map(&s,alias,mapping.pa[0],8192,PT_AF,PT_PXN|PT_UXN));
    struct mmu_leaf leaf=lookup(&s,alias);
    CHECK(leaf.valid && leaf.pa==mapping.pa[0] && (leaf.descriptor&PT_PXN));
    memcpy(before_ram,ram,SIZE);before_alloc=allocations;before_stores=stores;
    CHECK(shadow_map(&s,alias,mapping.pa[0],8192,PT_AF,PT_UXN)<0);
    CHECK(allocations==before_alloc && stores==before_stores && !memcmp(before_ram,ram,SIZE));
    /* Copying a shadow for a transaction must keep admission. */
    struct shadow copy=s;
    CHECK(shadow_map(&copy,alias+0x10000,mapping.pa[0],4096,PT_AF,0)<0);
    CHECK(!memcmp(before_ram,ram,SIZE));
    s=reset(NATIVE_WRITER_USER);
    CHECK(shadow_map(&s,canonical,mapping.pa[0],4096,PT_AF,0)<0);
    CHECK(!lookup(&s,canonical).valid);
    s=reset(NATIVE_WRITER_KERNEL_LOW);
    CHECK(shadow_map(&s,canonical,mapping.pa[0],4096,PT_AF,0)<0);
    CHECK(!lookup(&s,canonical).valid);
    /* A block-sized alias must be rejected before its first table allocation. */
    s=reset(NATIVE_WRITER_KERNEL_HIGH);before_alloc=allocations;before_stores=stores;
    CHECK(shadow_map(&s,0x40000000,mapping.pa[0]&~((1UL<<30)-1),1UL<<30,PT_AF,0)<0);
    CHECK(allocations==before_alloc && stores==before_stores);
    /* Legacy/default shadows retain their existing behavior. */
    s.admit=0;CHECK(!shadow_map(&s,alias,mapping.pa[0],4096,PT_AF,0));
    CHECK(lookup(&s,alias).valid);

    uint64_t regs[31],value;int spsr;unsigned site;
    for(unsigned i=0;i<31;i++)regs[i]=UINT64_C(0xa550000000000000)+i;
    for(unsigned i=0;i<6;i++) {
        const struct native_writer_site *w=&native_writer_sites[i];
        value=0;spsr=-1;site=99;
        CHECK(native_writer_value(w->va,w->word,regs,&value,&spsr,&site));
        CHECK(value==regs[w->word&31] && site==i);
        CHECK(spsr==(i==2 || i==3 || i==5));
        for(unsigned bit=0;bit<32;bit++) {
            value=1;spsr=2;site=3;
            CHECK(!native_writer_value(w->va,w->word^(1u<<bit),regs,&value,&spsr,&site));
            CHECK(value==1 && spsr==2 && site==3);
        }
        CHECK(!native_writer_value(w->va&NATIVE_WRITER_VA_MASK,w->word,regs,&value,&spsr,&site));
        CHECK(!native_writer_value(w->va+4,w->word,regs,&value,&spsr,&site));
    }
    CHECK(!native_writer_value(native_writer_sites[0].va,native_writer_sites[0].word,
                              0,&value,&spsr,&site));
    printf("native writer admission: %u checks, %u failures\n",checks,failed);
    return failed!=0;
}

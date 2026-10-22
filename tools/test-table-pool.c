/* SPDX-License-Identifier: MIT */
#include <stdio.h>
#include <string.h>
#include "../compat/table-pool.h"
#include "../shadow/shadow.h"
#include "../shadow/sprr-view.h"

#define BASE 0x40000000UL
#define PAGES 64u
static struct table_pool pool;
static uint64_t ram[PAGES][512];
static uint32_t used;
static unsigned checks,failures;
#define CHECK(x) do {checks++;if(!(x)){failures++;printf("FAIL %u: %s\n",__LINE__,#x);}} while(0)
struct allocation {unsigned owner;};
static uint64_t allocate(void *ctx)
{
    struct allocation *a=ctx;int page=table_pool_take(&pool,&used,PAGES,a->owner);
    if(page<0)return 0;
    memset(ram[page],0,4096);return BASE+(uint64_t)page*4096;
}
static int read_word(void *ctx,uint64_t pa,uint64_t *out)
{
    if(ctx!=ram || pa<BASE || pa>=BASE+used*4096UL || (pa&7))return -1;
    *out=ram[(pa-BASE)/4096][(pa&4095)/8];return 0;
}
static int write_word(void *ctx,uint64_t pa,uint64_t value)
{
    uint64_t unused;if(read_word(ctx,pa,&unused))return -1;
    ram[(pa-BASE)/4096][(pa&4095)/8]=value;return 0;
}
static struct shadow create(struct allocation *a,uint64_t va,uint64_t pa,
                            struct sprr_views *v)
{
    struct shadow s={.txsz=17,.root=allocate(a),.alloc=allocate,
        .read=read_word,.write=write_word,.ctx=ram,.alloc_ctx=a};
    CHECK(s.root!=0);CHECK(!shadow_map(&s,va,pa,16384,0xe43,0x0060000000000000UL));
    memset(v,0,sizeof(*v));CHECK(sprr_views_init(v,&s));CHECK(sprr_views_prepare_user(v,&s));
    for(unsigned n=0;n<v->count;n++)for(unsigned cpu=0;cpu<6;cpu++)
        CHECK(pool.owner[(v->tables[n].copy[cpu]-BASE)/4096]==a->owner);
    return s;
}
static void mapping(struct shadow *s,uint64_t va,uint64_t pa)
{
    struct mmu_config cfg={12,17,s->root};
    for(unsigned part=0;part<4;part++) {
        struct mmu_leaf leaf;
        CHECK(!mmu_walk(&cfg,va+part*4096,read_word,ram,&leaf));
        CHECK(leaf.valid && leaf.pa==pa+part*4096 && (leaf.descriptor&0xfff)==0xe43);
    }
}
int main(void)
{
    pool.head=TABLE_POOL_MAX;used=4;ram[0][0]=0xfeedface;
    struct allocation a={1},b={2};struct sprr_views av,bv;
    struct shadow stable=create(&b,0x180000000,0x80000000,&bv);
    uint64_t stable_pages[PAGES][512];memcpy(stable_pages,ram,sizeof ram);
    for(unsigned cycle=0;cycle<256;cycle++) {
        uint64_t va=0x200000000UL+(uint64_t)cycle*0x40000000UL;
        struct shadow changed=create(&a,va,0x90000000,&av);
        mapping(&changed,va,0x90000000);mapping(&stable,0x180000000,0x80000000);
        for(unsigned i=0;i<used;i++)if(pool.owner[i]==2)
            CHECK(!memcmp(stable_pages[i],ram[i],4096));
        CHECK(table_pool_release(&pool,used,1)>0);
        unsigned count=pool.count;
        CHECK(!table_pool_release(&pool,used,1) && pool.count==count);
        CHECK(ram[0][0]==0xfeedface);
        CHECK(used<32); /* Repeated ASLR layouts must not exhaust a64-page arena. */
    }
    CHECK(pool.reused>2000);
    CHECK(table_pool_release(&pool,used,0)==-1);
    CHECK(table_pool_release(&pool,used,TABLE_POOL_FREE)==-1);
    while(table_pool_take(&pool,&used,PAGES,0)>=0) {}
    CHECK(used==PAGES && !pool.count);
    CHECK(table_pool_take(&pool,&used,PAGES,0)==-1 && used==PAGES);
    uint32_t before=used;
    CHECK(table_pool_take(&pool,&used,TABLE_POOL_MAX+1,0)==-1 && used==before);
    CHECK(table_pool_take(&pool,&used,PAGES,TABLE_POOL_FREE)==-1 && used==before);
    CHECK(table_pool_release(&pool,used,2)>0);
    unsigned saved=pool.count;pool.next[pool.head]=(uint16_t)pool.head;
    CHECK(table_pool_take(&pool,&used,PAGES,0)==-1 && pool.count==saved);
    /* Exercise links above the old 8192-page bound and the 16-bit sentinel. */
    memset(&pool,0,sizeof pool);pool.head=TABLE_POOL_MAX;used=0;
    for(unsigned i=0;i<TABLE_POOL_MAX;i++)
        CHECK(table_pool_take(&pool,&used,TABLE_POOL_MAX,1)==(int)i);
    CHECK(table_pool_take(&pool,&used,TABLE_POOL_MAX,1)==-1);
    CHECK(table_pool_release(&pool,used,1)==TABLE_POOL_MAX);
    for(unsigned i=0;i<TABLE_POOL_MAX;i++)
        CHECK(table_pool_take(&pool,&used,TABLE_POOL_MAX,2)==(int)(TABLE_POOL_MAX-1-i));
    CHECK(pool.head==TABLE_POOL_MAX && !pool.count && used==TABLE_POOL_MAX);
    /* Installed startup needs more than32768 pages. Exercise the real pool
     * through the240MiB boundary, including16-bit links on release/reuse.
     * The old capacity refuses the first allocation and fails this replay. */
    const uint32_t installed_pages=61440;
    memset(&pool,0,sizeof pool);pool.head=TABLE_POOL_MAX;used=0;
    int first=table_pool_take(&pool,&used,installed_pages,1);
    CHECK(first==0);
    if(first==0) {
        for(uint32_t i=1;i<installed_pages;i++)
            CHECK(table_pool_take(&pool,&used,installed_pages,1)==(int)i);
        CHECK(table_pool_take(&pool,&used,installed_pages,1)==-1);
        CHECK(table_pool_release(&pool,used,1)==(int)installed_pages);
        for(uint32_t i=0;i<installed_pages;i++)
            CHECK(table_pool_take(&pool,&used,installed_pages,2)==(int)(installed_pages-1-i));
        CHECK(pool.head==TABLE_POOL_MAX && !pool.count && used==installed_pages);
    }
    printf("TABLE_POOL: %u checks, %u failures; high-water %u pages, reused %llu\n",
        checks,failures,used,(unsigned long long)pool.reused);
    return !!failures;
}

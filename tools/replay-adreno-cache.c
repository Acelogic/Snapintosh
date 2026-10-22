/* SPDX-License-Identifier: MIT */
/* CPU cache -> production mapper/SMMU -> CP write -> CPU visibility.
 * Includes the existing noncoherent integration model; no XNU or hardware. */
#define main adreno_existing_model_main
#include "test-adreno.c"
#undef main

static unsigned invalidates;
static void invalidate(void *ctx, uint64_t pa, uint64_t size)
{
    (void)ctx; invalidates++;
    CHECK(size && !((pa|size)&63));
    uint64_t off=ram_offset(pa,size);
    for(uint64_t line=off/64;line<(off+size)/64;line++) {
        dirty[line]=0;cached[line]=0;
    }
}
static int cache_request(uint64_t op,uint64_t va,uint64_t size,uint64_t direction)
{
    struct adreno_ops cache_ops=ops;cache_ops.invalidate=invalidate;
    uint64_t regs[4]={op,va,size,direction};
    unsigned mmio=nlog;
    int e=adreno_guest_cache(&cache_ops,&P,&S,regs,dart_leaf,0,MEM_LOW,MEM_HIGH);
    CHECK((int64_t)regs[0]==e && regs[1]==(e?0:size) && regs[2]==0 && regs[3]==S.wptr);
    CHECK(nlog==mmio); /* Cache maintenance must not submit or modify GPU MMIO. */
    return e;
}
static int sync_range(uint64_t va,uint64_t size,uint64_t direction)
{
    return cache_request(ADRENO_GUEST_CACHE,va,size,direction);
}
static void cp_write(uint64_t va,uint32_t value)
{
    uint64_t at=P.ring_pa+4*S.wptr;
    m_wr(0,at,ADRENO_PKT7_MEM_WRITE3);m_wr(0,at+4,(uint32_t)va);
    m_wr(0,at+8,(uint32_t)(va>>32));m_wr(0,at+12,value);
    m_clean(0,at,16);S.wptr+=4;m_wr(0,ADRENO_CP_RB_WPTR,(uint32_t)S.wptr);
    CHECK(r.rptr==r.wptr && !r.fsr);
}
int main(void)
{
    dram=calloc(1,RAM_SIZE);cache=calloc(1,RAM_SIZE);
    if(!dram || !cache) return 2;
    resource_setup(0);
    struct adreno_resource resource={0};
    CHECK(adreno_resource_reserve(&resource,&resource_ops,resource_model.logical)==0);
    CHECK(adreno_resource_commit(&resource,&resource_ops)==0);
    uint64_t va=resource.address,pa=GUEST_PAGE;
    unsigned first=(unsigned)((va-ADRENO_WINDOW_BASE)>>14);
    uint64_t original[2]={dart[first],dart[first+1]};
    m_wr(0,pa,0x11112222);m_wr(0,pa+0x4080,0x33334444);
    CHECK((uint32_t)dev_rd64(pa)==0 && (uint32_t)dev_rd64(pa+0x4080)==0);
    CHECK(sync_range(va,0x8000,ADRENO_CACHE_TO_DEVICE)==0);
    CHECK((uint32_t)dev_rd64(pa)==0x11112222 && (uint32_t)dev_rd64(pa+0x4080)==0x33334444);
    CHECK((smmu_walk(va+0x4080,1)&ADRENO_PTE_ADDR)==pa+0x4000);
    CHECK(m_rd(0,pa+0x4080)==0x33334444); /* a clean speculative CPU read */
    cp_write(va+0x4080,0x55556666);
    CHECK(m_rd(0,pa+0x4080)==0x33334444);
    CHECK(sync_range(va+0x4000,0x100,ADRENO_CACHE_FROM_DEVICE)==0);
    CHECK(m_rd(0,pa+0x4080)==0x55556666);
    /* Deliberate ownership violation distinguishes invalidate from the old
     * clean+invalidate helper. It is not an admitted concurrent CPU writer. */
    m_wr(0,pa+0x4080,0x77778888);cp_write(va+0x4080,0x9999aaaa);
    CHECK(sync_range(va+0x4080,64,ADRENO_CACHE_FROM_DEVICE)==0);
    CHECK(m_rd(0,pa+0x4080)==0x9999aaaa && (uint32_t)dev_rd64(pa+0x4080)==0x9999aaaa);
    unsigned before_clean=cleans,before_inval=invalidates;
    for(unsigned which=0;which<8;which++) {
        uint64_t bad=which==0 ? 0 : which==1 ? dart_desc(pa+0x4000,0x40,0x4000,0,0) :
            which==2 ? dart_desc(pa+0x4000,0,0x3fc0,0,0) :
            which==3 ? dart_desc(pa+0x4000,0,0x4000,0,1) :
            which==4 ? dart_desc(MEM_LOW-0x4000,0,0x4000,0,0) :
            which==5 ? dart_desc(MEM_HIGH,0,0x4000,0,0) :
            which==6 ? dart_desc(ARENA,0,0x4000,0,0) :
                       dart_desc(pa+0x8000,0,0x4000,0,0);
        dart[first+1]=bad;
        CHECK(sync_range(va,0x8000,ADRENO_CACHE_TO_DEVICE)==ADRENO_E_TARGET);
        CHECK(cleans==before_clean && invalidates==before_inval);
    }
    dart[first+1]=original[1];
    uint64_t slot=POOL+ADRENO_L3_OFFSET+((va+0x4000-ADRENO_WINDOW_BASE)>>12)*8;
    uint64_t saved=m_rd64(0,slot);m_wr64(0,slot,saved^0x1000);
    CHECK(sync_range(va,0x8000,ADRENO_CACHE_TO_DEVICE)==ADRENO_E_TARGET && cleans==before_clean);
    m_wr64(0,slot,saved);
    const uint64_t bad_ranges[][2]={{va,0},{va+1,64},{va,63},{ADRENO_WINDOW_BASE-64,64},
        {ADRENO_WINDOW_END,64},{ADRENO_WINDOW_END-64,128},{va,UINT64_MAX},
        {va,ADRENO_CACHE_MAX_BYTES+64}};
    for(unsigned i=0;i<sizeof bad_ranges/sizeof bad_ranges[0];i++)
        CHECK(sync_range(bad_ranges[i][0],bad_ranges[i][1],ADRENO_CACHE_TO_DEVICE)==ADRENO_E_WINDOW);
    CHECK(cache_request(ADRENO_GUEST_CACHE+1,va,64,ADRENO_CACHE_TO_DEVICE)==ADRENO_E_PARAMS);
    CHECK(sync_range(va,64,0)==ADRENO_E_PARAMS);
    CHECK(sync_range(va,64,3)==ADRENO_E_PARAMS);
    CHECK(cleans==before_clean && invalidates==before_inval);
    /* Subpage native byte bounds are enforced even inside present mirror pages. */
    dart[first]=dart_desc(pa,64,0x3fc0,0,0);
    CHECK(sync_range(va,64,ADRENO_CACHE_TO_DEVICE)==ADRENO_E_TARGET);
    CHECK(sync_range(va+64,64,ADRENO_CACHE_TO_DEVICE)==0);
    CHECK(sync_range(va+0x3fc0,64,ADRENO_CACHE_TO_DEVICE)==ADRENO_E_TARGET);
    dart[first]=original[0];
    /* A read-only GPU input may be cleaned, never admitted as a GPU output. */
    dart[first]=dart_desc(pa,0,0x4000,1,0);CHECK(mirror(va,0x4000)==0);
    CHECK(sync_range(va,64,ADRENO_CACHE_TO_DEVICE)==0);
    CHECK(sync_range(va,64,ADRENO_CACHE_FROM_DEVICE)==ADRENO_E_TARGET);
    dart[first]=original[0];CHECK(mirror(va,0x4000)==0);
    uint64_t status=S.status,flags=P.flags;
    const uint64_t bad_status[]={0,ADRENO_S_ADOPTED,status|ADRENO_S_QUIESCED,status|ADRENO_S_HIJACKED};
    for(unsigned i=0;i<sizeof bad_status/sizeof bad_status[0];i++) {
        S.status=bad_status[i];CHECK(sync_range(va,64,ADRENO_CACHE_TO_DEVICE)==ADRENO_E_PARAMS);
    }
    S.status=status;P.flags|=ADRENO_F_RING;
    CHECK(sync_range(va,64,ADRENO_CACHE_TO_DEVICE)==ADRENO_E_PARAMS);P.flags=flags;
    struct adreno_ops missing=ops;uint64_t regs[4]={ADRENO_GUEST_CACHE,va,64,ADRENO_CACHE_FROM_DEVICE};
    CHECK(adreno_guest_cache(&missing,&P,&S,regs,dart_leaf,0,MEM_LOW,MEM_HIGH)==ADRENO_E_PARAMS);
    CHECK(adreno_resource_free(&resource,&resource_ops)==0 && !resource_model.pins);
    free(cache);free(dram);
    printf("%s: %u cache/mapper/SMMU/CP checks; modeled cache and GPU\n",failures?"FAIL":"PASS",checks);
    return failures!=0;
}

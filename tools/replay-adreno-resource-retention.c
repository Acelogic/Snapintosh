/* SPDX-License-Identifier: MIT */
/* Resource-list -> production fence decoder -> noncoherent SMMU/CP replay.
 * The native namespace callbacks are substituted; no XNU or hardware runs. */
#define main adreno_existing_model_main
#include "test-adreno.c"
#undef main
#include "adreno-resource-list.h"

struct namespace_model {
    unsigned refs[8], calls, releases, order[8]; uint8_t *shared;
    unsigned preparations, prepare_calls, completes, fail_prepare, bad_token;
    unsigned sync_checks, sync_to, sync_from, fail_check, fail_to, fail_from;
    unsigned gpu_calls; int gpu_result;
    unsigned chunks, fail_chunk;
    struct adreno_resource mapping;
};
static void *retain_id(void *context, uint32_t id)
{
    struct namespace_model *ns = context;
    ns->calls++;
    /* Mutation after snapshot must not redirect any subsequent lookup. */
    if (ns->shared) { memset(ns->shared, 0xff, 160); ns->shared = NULL; }
    if (!id || id >= 8 || id == 7) return NULL;
    ns->refs[id]++;
    return &ns->refs[id];
}
static void release_id(void *context, void *resource)
{
    struct namespace_model *ns = context;
    unsigned *ref = resource;
    CHECK(ns->preparations==0);
    CHECK(ref >= ns->refs && ref < ns->refs+8 && *ref > 0);
    ns->order[ns->releases++] = (unsigned)(ref-ns->refs);
    --*ref;
}
static int prepare_id(void *context, void *resource, void **token)
{
    struct namespace_model *ns=context;
    CHECK(resource>= (void *)ns->refs && resource< (void *)(ns->refs+8));
    ns->prepare_calls++;
    if(ns->fail_prepare==ns->prepare_calls) return -1;
    if(!ns->preparations && adreno_resource_commit(&ns->mapping,&resource_ops)) return -1;
    ns->preparations++;
    if(ns->bad_token==1) return 0;
    *token=&ns->mapping;
    return ns->bad_token==2 ? -1 : 0;
}
static void complete_id(void *context, void *token)
{
    struct namespace_model *ns=context;
    CHECK(token==&ns->mapping && ns->preparations>0);
    ns->preparations--;ns->completes++;
    /* Native completeMemory drops preparation ownership. The scheduler may
     * unwire later; final map release remains a separate operation. */
}
static void cache_invalidate(void *ctx, uint64_t pa, uint64_t size)
{
    (void)ctx;uint64_t off=ram_offset(pa,size);
    CHECK(!((pa|size)&63));
    for(uint64_t line=off/64;line<(off+size)/64;line++) { dirty[line]=0;cached[line]=0; }
}
static int maintain_id(void *context,uint64_t address,uint64_t bytes,unsigned direction)
{
    struct namespace_model *ns=context;ns->chunks++;
    CHECK(bytes && bytes<=ADRENO_CACHE_MAX_BYTES && !((address|bytes)&63));
    if(ns->chunks==ns->fail_chunk) return -1;
    struct adreno_ops cache_ops=ops;cache_ops.invalidate=cache_invalidate;
    uint64_t regs[4]={ADRENO_GUEST_CACHE,address,bytes,direction};
    return adreno_guest_cache(&cache_ops,&P,&S,regs,dart_leaf,0,MEM_LOW,MEM_HIGH);
}
static int sync_id(void *context,void *token,unsigned direction)
{
    struct namespace_model *ns=context;
    CHECK(token==&ns->mapping && ns->preparations==3);
    unsigned count=direction==0 ? ++ns->sync_checks : direction==ADRENO_CACHE_TO_DEVICE ? ++ns->sync_to : ++ns->sync_from;
    if((direction==0 && count==ns->fail_check) ||
       (direction==ADRENO_CACHE_TO_DEVICE && count==ns->fail_to) ||
       (direction==ADRENO_CACHE_FROM_DEVICE && count==ns->fail_from)) return -1;
    return adreno_resource_cache(&ns->mapping,direction,maintain_id,ns);
}
static uint64_t aliased_physical(void *ctx,uint64_t offset,uint64_t *length)
{
    (void)ctx;CHECK(resource_model.pins);*length=resource_model.logical-offset;
    return GUEST_PAGE+(offset&0x3fff);
}
static int large_free(void *ctx,uint64_t va,uint64_t length)
{
    (void)ctx;CHECK(resource_model.pins && resource_model.reserved);
    if(guest_unmap(va,length)) return -1;
    resource_model.reserved=0;resource_model.free_calls++;return 0;
}
static int submitted_work(void *context)
{
    struct namespace_model *ns=context;ns->gpu_calls++;
    CHECK(ns->sync_checks==3 && ns->sync_to==3 && ns->sync_from==0 && ns->preparations==3);
    CHECK((uint32_t)dev_rd64(GUEST_PAGE+0x80)==0xabcdef01);
    if(ns->gpu_result) return ns->gpu_result;
    CHECK(m_rd(0,GUEST_PAGE+0x80)==0xabcdef01); /* clean CPU alias can be stale after DMA */
    uint64_t va=ns->mapping.address+0x80,at=P.ring_pa+4*S.wptr;
    m_wr(0,at,ADRENO_PKT7_MEM_WRITE3);m_wr(0,at+4,(uint32_t)va);
    m_wr(0,at+8,(uint32_t)(va>>32));m_wr(0,at+12,0xabcdef02);
    m_clean(0,at,16);S.wptr+=4;m_wr(0,ADRENO_CP_RB_WPTR,(uint32_t)S.wptr);
    CHECK(r.rptr==r.wptr && !r.fsr && m_rd(0,GUEST_PAGE+0x80)==0xabcdef01);
    return 0;
}
static void put16(uint8_t *p, uint16_t v) { p[0]=v; p[1]=v>>8; }
static void put32(uint8_t *p, uint32_t v) { for(unsigned i=0;i<4;i++) p[i]=(uint8_t)(v>>(i*8)); }
static void input(uint8_t *bytes)
{
    memset(bytes,0,160); put32(bytes+28,2);
    put32(bytes+32,1); put32(bytes+36,2); put16(bytes+80,1); put16(bytes+82,3); put16(bytes+94,2);
    put32(bytes+96,1); put16(bytes+144,0x11); put16(bytes+158,1);
}
int main(void)
{
    uint8_t shared[160], snapshot[160];
    struct adreno_resource_entry entries[12];
    struct adreno_resource_list list = {0};
    struct namespace_model first = {0}, second = {0};
    struct adreno_resource_list_ops ops = {&first,retain_id,release_id,prepare_id,complete_id,sync_id};
    uint64_t bytes=0,capacity=0;
    dram=calloc(1,RAM_SIZE); cache=calloc(1,RAM_SIZE);
    if(!dram || !cache) return 2;
    guest_fence_setup();
    input(shared); first.shared=shared;
    CHECK(adreno_resource_list_measure(shared,sizeof shared,&bytes,&capacity)==0 && bytes==160 && capacity==12);
    CHECK(adreno_resource_list_acquire(&list,shared,sizeof shared,snapshot,sizeof snapshot,entries,12,&ops)==0);
    CHECK(list.count==3 && first.refs[1]==2 && first.refs[2]==1 && second.refs[1]==0);
    CHECK(entries[0].id==1 && entries[1].id==2 && entries[2].id==1 && entries[2].usage==0x11);
    CHECK(adreno_resource_list_acquire(&list,shared,sizeof shared,snapshot,sizeof snapshot,entries,12,&ops)==ADRENO_LIST_E_BUSY);
    struct adreno_submit_header command={ADRENO_KCMD_FENCE,8}; uint32_t value=0x534e7001;
    CHECK(adreno_submit_command(&command,8,submit_fence,&value)==0);
    CHECK(S.fences==1 && r.rptr==r.wptr && m_rd(0,GUEST_PAGE+0x200)==value);
    CHECK(first.refs[1]==2 && first.refs[2]==1);
    CHECK(adreno_resource_list_release(&list,&ops)==0);
    CHECK(first.refs[1]==0 && first.refs[2]==0 && first.releases==3);
    CHECK(first.order[0]==1 && first.order[1]==2 && first.order[2]==1);
    CHECK(adreno_resource_list_release(&list,&ops)==0 && first.releases==3);
    /* Same IDs in a different device must resolve to different objects. */
    input(shared); ops.context=&second;
    CHECK(adreno_resource_list_acquire(&list,shared,160,snapshot,160,entries,12,&ops)==0);
    CHECK(entries[0].resource==&second.refs[1] && second.refs[1]==2 && first.refs[1]==0);
    CHECK(adreno_resource_list_release(&list,&ops)==0 && second.refs[1]==0);
    /* A missing late ID rolls back only the successful earlier lookups. */
    memset(&first,0,sizeof first); ops.context=&first; input(shared); put32(shared+96,7);
    CHECK(adreno_resource_list_acquire(&list,shared,160,snapshot,160,entries,12,&ops)==ADRENO_LIST_E_RESOURCE);
    CHECK(!list.ready && first.calls==3 && first.releases==2 && first.order[0]==2 && first.order[1]==1);
    CHECK(first.refs[1]==0 && first.refs[2]==0);
    unsigned calls=first.calls;
    for(unsigned n=0;n<160;n++) {
        input(shared);
        CHECK(adreno_resource_list_acquire(&list,shared,n,snapshot,160,entries,12,&ops)!=0);
        CHECK(first.calls==calls && !list.ready);
    }
    input(shared); put16(shared+158,7);
    CHECK(adreno_resource_list_acquire(&list,shared,160,snapshot,160,entries,12,&ops)==ADRENO_LIST_E_FORMAT && first.calls==calls);
    input(shared); put32(shared+96,0);
    CHECK(adreno_resource_list_acquire(&list,shared,160,snapshot,160,entries,12,&ops)==ADRENO_LIST_E_FORMAT && first.calls==calls);
    input(shared);
    CHECK(adreno_resource_list_acquire(&list,shared,160,snapshot,159,entries,12,&ops)==ADRENO_LIST_E_CAPACITY);
    CHECK(adreno_resource_list_acquire(&list,shared,160,snapshot,160,entries,2,&ops)==ADRENO_LIST_E_CAPACITY && first.calls==calls);
    put32(shared+28,ADRENO_LIST_MAX_GROUPS+1);
    CHECK(adreno_resource_list_measure(shared,UINT64_MAX,&bytes,&capacity)==ADRENO_LIST_E_FORMAT);
    input(shared); put32(shared+28,0);
    CHECK(adreno_resource_list_acquire(&list,shared,32,snapshot,32,NULL,0,&ops)==0 && list.ready && list.count==0);
    CHECK(adreno_resource_list_prepare(&list,&ops)==0 && first.prepare_calls==0);
    CHECK(adreno_resource_list_prepare(&list,&ops)==ADRENO_LIST_E_BUSY);
    CHECK(adreno_resource_list_release(&list,&ops)==0);
    CHECK(adreno_resource_list_measure(NULL,32,&bytes,&capacity)==ADRENO_LIST_E_ARGUMENT);
    CHECK(adreno_resource_list_acquire(NULL,shared,32,snapshot,32,NULL,0,&ops)==ADRENO_LIST_E_ARGUMENT);
    /* Three references/IDs alias one mapping; each owns a preparation count. */
    memset(&first,0,sizeof first);resource_setup(0);input(shared);
    CHECK(adreno_resource_reserve(&first.mapping,&resource_ops,resource_model.logical)==0);
    CHECK(adreno_resource_list_acquire(&list,shared,160,snapshot,160,entries,12,&ops)==0);
    CHECK(adreno_resource_list_prepare(&list,&ops)==0 && first.preparations==3 && resource_model.pins==1);
    CHECK(adreno_resource_list_prepare(&list,&ops)==ADRENO_LIST_E_BUSY && first.prepare_calls==3);
    CHECK(guest_fence(first.mapping.address+0x4080,0x534e7002)==0 && r.rptr==r.wptr);
    CHECK(m_rd(0,GUEST_PAGE+0x4080)==0x534e7002 && first.preparations==3);
    CHECK(adreno_resource_list_release(&list,&ops)==0);
    CHECK(first.preparations==0 && first.completes==3 && first.releases==3);
    CHECK(adreno_resource_free(&first.mapping,&resource_ops)==0 && !resource_model.pins);
    /* Failure on the second preparation undoes only the first successful one. */
    memset(&first,0,sizeof first);resource_setup(0);input(shared);first.fail_prepare=2;
    CHECK(adreno_resource_reserve(&first.mapping,&resource_ops,resource_model.logical)==0);
    CHECK(adreno_resource_list_acquire(&list,shared,160,snapshot,160,entries,12,&ops)==0);
    CHECK(adreno_resource_list_prepare(&list,&ops)==ADRENO_LIST_E_PREPARE);
    CHECK(first.preparations==0 && first.completes==1 && first.releases==0 && first.refs[1]==2);
    CHECK(adreno_resource_list_release(&list,&ops)==0 && first.releases==3);
    CHECK(adreno_resource_free(&first.mapping,&resource_ops)==0);
    /* Production range splitter: a >1 MiB mapping has real mirrored leaves,
     * aliased to the model's small physical arena. Reject partial CPU lines. */
    memset(&first,0,sizeof first);resource_setup(0);
    resource_model.logical=ADRENO_CACHE_MAX_BYTES+64;
    struct adreno_resource_ops large_ops=resource_ops;
    large_ops.physical=aliased_physical;large_ops.free=large_free;
    CHECK(adreno_resource_reserve(&first.mapping,&large_ops,resource_model.logical)==0);
    CHECK(adreno_resource_commit(&first.mapping,&large_ops)==0);
    CHECK(adreno_resource_cache(&first.mapping,0,maintain_id,&first)==0 && first.chunks==0);
    CHECK(adreno_resource_cache(&first.mapping,ADRENO_CACHE_TO_DEVICE,maintain_id,&first)==0 && first.chunks==2);
    first.chunks=0;first.fail_chunk=2;
    CHECK(adreno_resource_cache(&first.mapping,ADRENO_CACHE_TO_DEVICE,maintain_id,&first)==ADRENO_RESOURCE_E_CACHE);
    CHECK(first.chunks==2 && resource_model.pins);
    first.mapping.logical_length++;
    CHECK(adreno_resource_cache(&first.mapping,0,maintain_id,&first)==ADRENO_RESOURCE_E_RANGE && first.chunks==2);
    first.mapping.logical_length--;
    CHECK(adreno_resource_cache(&first.mapping,ADRENO_CACHE_TO_DEVICE,NULL,&first)==ADRENO_RESOURCE_E_STATE);
    CHECK(adreno_resource_free(&first.mapping,&large_ops)==0);
    /* Resource ownership spans preflight, clean, CP execution and invalidate. */
    for(unsigned fault=0;fault<6;fault++) {
        memset(&list,0,sizeof list);memset(&first,0,sizeof first);resource_setup(0);input(shared);
        CHECK(adreno_resource_reserve(&first.mapping,&resource_ops,resource_model.logical)==0);
        CHECK(adreno_resource_list_acquire(&list,shared,160,snapshot,160,entries,12,&ops)==0);
        CHECK(adreno_resource_list_prepare(&list,&ops)==0);
        m_wr(0,GUEST_PAGE+0x80,0xabcdef01);
        if(fault==1) first.fail_check=3;
        if(fault==2) first.fail_to=2;
        if(fault==3) first.gpu_result=ADRENO_SUBMIT_E_UNCERTAIN;
        if(fault==4) first.fail_from=1;   /* the Write entry's invalidate: the only FROM_DEVICE (design 3.5) */
        if(fault==5) first.gpu_result=ADRENO_SUBMIT_E_INACTIVE;
        int status=adreno_resource_list_submit(&list,&ops,submitted_work,&first);
        if(!fault) {
            /* Usages 1, 3, 0x11: only the Write-usage entry (3) is invalidated; it aliases the mapping the
             * GPU wrote, so the CPU still reads the GPU's value. */
            CHECK(status==0 && first.sync_from==1 && m_rd(0,GUEST_PAGE+0x80)==0xabcdef02);
        } else if(fault<3) {
            CHECK(status==ADRENO_LIST_E_CACHE && first.gpu_calls==0 && first.sync_from==0);
            if(fault==1) CHECK(first.sync_to==0);
        } else if(fault==3 || fault==4) {
            CHECK(status==(fault==3?ADRENO_SUBMIT_E_UNCERTAIN:ADRENO_LIST_E_VISIBILITY));
            CHECK(adreno_resource_list_release(&list,&ops)==ADRENO_LIST_E_BUSY);
            CHECK(first.preparations==3 && first.refs[1]==2 && first.completes==0 && resource_model.pins);
            unsigned before=first.sync_checks;
            CHECK(adreno_resource_list_submit(&list,&ops,submitted_work,&first)==ADRENO_LIST_E_BUSY);
            CHECK(first.sync_checks==before && first.gpu_calls==1);
            continue; /* only the following model reset discards frozen state */
        } else CHECK(status==ADRENO_SUBMIT_E_INACTIVE && !(list.ready&ADRENO_LIST_FROZEN));
        CHECK(adreno_resource_list_release(&list,&ops)==0 && first.preparations==0);
        CHECK(adreno_resource_free(&first.mapping,&resource_ops)==0);
    }
    /* Inconsistent callback ownership freezes; each following setup explicitly
     * resets the modeled machine instead of completing an unknown token. */
    for(unsigned bad=1;bad<=2;bad++) {
        memset(&list,0,sizeof list);memset(&first,0,sizeof first);resource_setup(0);input(shared);first.bad_token=bad;
        CHECK(adreno_resource_reserve(&first.mapping,&resource_ops,resource_model.logical)==0);
        CHECK(adreno_resource_list_acquire(&list,shared,160,snapshot,160,entries,12,&ops)==0);
        CHECK(adreno_resource_list_prepare(&list,&ops)==ADRENO_LIST_E_STATE);
        CHECK(adreno_resource_list_release(&list,&ops)==ADRENO_LIST_E_BUSY);
        CHECK(first.preparations==1 && first.completes==0 && first.releases==0 && resource_model.pins==1);
    }
    memset(&list,0,sizeof list);
    /* No resource preparation can be released after uncertain GPU retirement. */
    memset(&first,0,sizeof first);resource_setup(0);input(shared);
    CHECK(adreno_resource_reserve(&first.mapping,&resource_ops,resource_model.logical)==0);
    CHECK(adreno_resource_list_acquire(&list,shared,160,snapshot,160,entries,12,&ops)==0);
    CHECK(adreno_resource_list_prepare(&list,&ops)==0);
    clean_disabled=1;
    CHECK(guest_fence(first.mapping.address+0x4080,0x534e7003)==ADRENO_E_FENCE);
    adreno_resource_list_freeze(&list);
    CHECK(adreno_resource_list_release(&list,&ops)==ADRENO_LIST_E_BUSY);
    CHECK(adreno_resource_list_complete(&list,&ops)==ADRENO_LIST_E_BUSY);
    CHECK(first.preparations==3 && first.completes==0 && first.releases==0 && resource_model.pins==1);
    CHECK(adreno_resource_list_release(&list,&ops)==ADRENO_LIST_E_BUSY && first.refs[1]==2);
    /* Ending this model process represents reset; the frozen state is not
     * unwound under an assumption that the timed-out GPU has stopped. */
    printf("%s: %u resource ownership/decoder/SMMU/CP checks; native namespace substituted\n",failures?"FAILED":"PASS",checks);
    free(dram);free(cache);return failures?1:0;
}

/* SPDX-License-Identifier: MIT */
#include "txm.h"
#include "sptm-access.h"
#if SNAP_ROOT_INDEX
#include "root-index.h"
#endif

/* 8-byte fields: one single-copy-atomic access (compat/sptm-access.h, v67). */
static void store64(volatile uint8_t *p, uint64_t value) {sptm_put64(p, value);}
static uint64_t load64(volatile uint8_t *p) {return sptm_get64(p);}
/* The shared-region object's binding count at +0x68 is a u32 in the pinned
 * firmware: the binder adds with `ldadd w` (1703679c..67a8) and TXM36's
 * destructor subtracts with `ldaddal w` (170363f4..63fc), panicking on a
 * zero old value. The registry now admits 511 users, so a byte would wrap
 * at 256 bound address spaces and the next unbind would be refused. */
#define TXM_SHARED_REFS 0x68u
static uint32_t load32(const volatile uint8_t *p)
{
    uint32_t v=0;for(unsigned n=0;n<4;n++) v|=(uint32_t)p[n]<<(n*8);return v;
}
static void store32(volatile uint8_t *p,uint32_t value)
{
    for(unsigned n=0;n<4;n++) p[n]=(uint8_t)(value>>(n*8));
}

static void empty_object(uint8_t out[TXM_ASPACE_STRIDE],uint64_t va,
                         unsigned id,unsigned shared)
{
    for(unsigned i=0;i<TXM_ASPACE_STRIDE;i++)out[i]=0;
    out[0x11]=out[0x91]=1;
    out[0x22]=(uint8_t)id;out[0x23]=(uint8_t)(id>>8);
    out[0x24]=(uint8_t)shared;
    store64(out+0x38,va+0x80);
}

/* Reconstruct the entire issued object from host-owned state. Unsupported
 * signing/tree mutations stay visible instead of being overwritten. */
static int object_view(const struct txm_arena *a,const struct txm_registry *r,
                      unsigned slot,uint8_t out[TXM_ASPACE_STRIDE])
{
    if(r->count>TXM_ASPACE_LIMIT || slot>=r->count || !r->root[slot] ||
       r->shared[slot]>1)return 0;
    unsigned refs=0,parent=TXM_ASPACE_LIMIT;
    for(unsigned i=0;i<r->count;i++) {
        if(!r->root[i]) {if(r->bound_shared[i])return 0;continue;}
        if(r->bound_shared[i]==r->root[slot])refs++;
        if(r->root[i]==r->bound_shared[slot]) {
            if(parent!=TXM_ASPACE_LIMIT)return 0;
            parent=i;
        }
    }
    if((refs && !r->shared[slot]) ||
       (r->bound_shared[slot] && (r->shared[slot] || parent==TXM_ASPACE_LIMIT ||
        r->shared[parent]!=1 || !r->region_start[parent] ||
        r->region_end[parent]<=r->region_start[parent])))return 0;
    uint64_t va=a->va+slot*TXM_ASPACE_STRIDE;
    empty_object(out,va,r->asid[slot],r->shared[slot]);
    store64(out+0x58,r->region_start[slot]);store64(out+0x60,r->region_end[slot]);
    /* The native reference is u32 (TXM_SHARED_REFS); keep all four bytes. */
    store32(out+TXM_SHARED_REFS,refs);
    if(r->bound_shared[slot]) {
        store64(out+0x28,va+0x80);store64(out+0x38,0);store64(out+0x48,va+0x80);
        out[0x92]=1;
        store64(out+0x98,a->va+parent*TXM_ASPACE_STRIDE);
        store64(out+0xa8,r->region_start[parent]);store64(out+0xb0,r->region_end[parent]);
        /* Empty-tree insertion gives a black root: children and parent/color
         * +b8/+c0/+c8 remain zero (native1703541c..444). */
    }
    return 1;
}
static int object_matches(volatile uint8_t *object,const uint8_t *expected)
{
    for(unsigned i=0;i<TXM_ASPACE_STRIDE;i++)if(object[i]!=expected[i])return 0;
    return 1;
}

enum sptm_result txm_bind_shared(const struct sptm_memory *m,
    const struct txm_arena *a,struct txm_registry *r,uint64_t user_root,
    uint16_t asid,uint64_t shared_root,uint8_t shared_slot,uint64_t start,uint64_t size)
{
    if(!m || !m->map || !m->publish || !a || !r || r->count>TXM_ASPACE_LIMIT ||
       !a->va || ((a->pa|a->va)&0x3fff) || a->pa>UINT64_MAX-TXM_ASPACE_SIZE ||
       a->va>UINT64_MAX-TXM_ASPACE_SIZE || r->bindings==UINT64_MAX)return SPTM_BAD_CONFIG;
    if(!asid || shared_slot>=SPTM_MAC_SHARED_ROOT_LIMIT || user_root==shared_root ||
       !sptm_managed_frame(m,user_root) || !sptm_managed_frame(m,shared_root) ||
       !size || ((start|size)&0x3fff) || size>UINT64_MAX-start)return SPTM_BAD_ADDRESS;
    unsigned user=TXM_ASPACE_LIMIT,parent=TXM_ASPACE_LIMIT;
    for(unsigned i=0;i<r->count;i++) {
        if(r->shared[i]>1 || (!r->root[i] && r->bound_shared[i]))return SPTM_BAD_CONFIG;
        if(!r->root[i])continue;
        if(r->root[i]==user_root || (!r->shared[i] && r->asid[i]==asid)) {
            if(r->root[i]!=user_root || r->shared[i] || r->asid[i]!=asid ||
               user!=TXM_ASPACE_LIMIT)return SPTM_TYPE_MISMATCH;
            user=i;
        }
        if(r->root[i]==shared_root || (r->shared[i] && r->asid[i]==shared_slot)) {
            if(r->root[i]!=shared_root || !r->shared[i] || r->asid[i]!=shared_slot ||
               parent!=TXM_ASPACE_LIMIT)return SPTM_TYPE_MISMATCH;
            parent=i;
        }
    }
    if(user==TXM_ASPACE_LIMIT || parent==TXM_ASPACE_LIMIT)return SPTM_TABLE_MISSING;
    if(r->bound_shared[user] || r->region_start[user] || r->region_end[user])return SPTM_FRAME_BUSY;
    if(!r->region_start[parent] || r->region_start[parent]>start ||
       r->region_end[parent]<start+size)return SPTM_BAD_ADDRESS;
    uint8_t uview[256],pview[256];
    if(!object_view(a,r,user,uview) || !object_view(a,r,parent,pview))return SPTM_BAD_CONFIG;
    uint64_t upa=a->pa+user*256,ppa=a->pa+parent*256,uva=a->va+user*256;
    volatile uint8_t *u=m->map(m->ctx,upa,256),*p=m->map(m->ctx,ppa,256);
    if(!u || !p)return SPTM_MEMORY_UNAVAILABLE;
    if(!object_matches(u,uview) || !object_matches(p,pview))return SPTM_FRAME_BUSY;
    /* 170367b4..c0 refuses an increment from the u32 ceiling. */
    if(load32(pview+TXM_SHARED_REFS)==UINT32_MAX)return SPTM_BAD_REFERENCE;
    /* All fallible work precedes the first write. This is the native binding
     * of the preallocated node, not a new mapping or a trust grant. */
    store64(u+0x28,uva+0x80);store64(u+0x38,0);store64(u+0x48,uva+0x80);
    u[0x92]=1;store64(u+0x98,a->va+parent*256);
    store64(u+0xa8,r->region_start[parent]);store64(u+0xb0,r->region_end[parent]);
    store32(p+TXM_SHARED_REFS,load32(p+TXM_SHARED_REFS)+1);
    m->publish(m->ctx,upa,256);m->publish(m->ctx,ppa+TXM_SHARED_REFS,4);
    r->bound_shared[user]=shared_root;r->bindings++;
    return SPTM_OK;
}

enum sptm_result txm_share_prepare(const struct sptm_memory *m,
    const struct txm_arena *a,const struct txm_registry *r,uint64_t root,
    uint16_t asid,uint8_t shared_slot,struct txm_share_plan *plan)
{
    if(!m || !m->map || !m->publish || !a || !r || !plan ||
       r->count>TXM_ASPACE_LIMIT || !a->va ||
       ((a->pa|a->va)&0x3fff) || a->pa>UINT64_MAX-TXM_ASPACE_SIZE ||
       a->va>UINT64_MAX-TXM_ASPACE_SIZE)return SPTM_BAD_CONFIG;
    if(!asid || shared_slot>=SPTM_MAC_SHARED_ROOT_LIMIT ||
       !sptm_managed_frame(m,root))return SPTM_BAD_ADDRESS;
    unsigned slot=TXM_ASPACE_LIMIT;
    for(unsigned i=0;i<r->count;i++) {
        if(r->shared[i]>1)return SPTM_BAD_CONFIG;
        if(!r->root[i])continue;
        if(r->shared[i] && r->asid[i]==shared_slot)return SPTM_FRAME_BUSY;
        if(r->root[i]==root || (!r->shared[i] && r->asid[i]==asid)) {
            if(r->root[i]!=root || r->asid[i]!=asid || r->shared[i] ||
               slot!=TXM_ASPACE_LIMIT)return SPTM_TYPE_MISMATCH;
            slot=i;
        }
    }
    if(slot==TXM_ASPACE_LIMIT)return SPTM_TABLE_MISSING;
    if(r->region_start[slot] || r->region_end[slot] || r->bound_shared[slot])return SPTM_FRAME_BUSY;
    uint64_t off=slot*TXM_ASPACE_STRIDE;
    volatile uint8_t *object=m->map(m->ctx,a->pa+off,TXM_ASPACE_STRIDE);
    if(!object)return SPTM_MEMORY_UNAVAILABLE;
    /* 170365e4..5f8 rejects signing state, attached subordinate mappings
     * and flags before moving the same object from ASID to shared registry.
     * This backend has only issued empty objects; validate their whole
     * representation so unsupported policy mutations cannot be hidden. */
    uint8_t expected[TXM_ASPACE_STRIDE];empty_object(expected,a->va+off,asid,0);
    for(unsigned i=0;i<TXM_ASPACE_STRIDE;i++)
        if(object[i]!=expected[i])return SPTM_FRAME_BUSY;
    *plan=(struct txm_share_plan){object,a->pa+off,slot,shared_slot};
    return SPTM_OK;
}

void txm_share_commit(const struct sptm_memory *m,struct txm_registry *r,
                       const struct txm_share_plan *p)
{
    /* 17036618 changes the packed u16 id/u16 class and preserves the handle,
     * mapping object and all other bytes. The service lock excludes reuse. */
    p->object[0x22]=(uint8_t)p->shared_slot;p->object[0x23]=0;
    p->object[0x24]=1;p->object[0x25]=0;
    m->publish(m->ctx,p->object_pa+0x22,4);
    r->asid[p->registry_slot]=(uint16_t)p->shared_slot;
    r->shared[p->registry_slot]=1;
}

static void reply_status(const struct sptm_memory *m, uint64_t stack_pa,
                        volatile uint8_t *stack, const uint64_t words[6], unsigned count,
                        uint64_t status)
{
    volatile uint8_t *reply = stack + 0x3c00;
    store64(reply + 0x08, status);
    reply[0x10] = 0;
    store64(reply + 0x18, count);
    for (unsigned n = 0; n < 6; n++) store64(reply + 0x20 + 8 * n, words[n]);
    m->publish(m->ctx, stack_pa + 0x3c00, 0x50);
}

static void reply_words(const struct sptm_memory *m,uint64_t stack_pa,
                        volatile uint8_t *stack,const uint64_t words[6],unsigned count)
{
    reply_status(m,stack_pa,stack,words,count,0);
}

enum sptm_result txm_trust_query_empty(const struct sptm_memory *m,
    const struct txm_service *s,uint64_t selector,const uint64_t args[8],
    uint64_t *status)
{
    const uint64_t page=SPTM_MAC_FRAME_SIZE;
    if(selector!=14) return SPTM_UNSUPPORTED_OPTIONS;
    if(!m || !m->map || !m->publish || !s || !args || !status ||
       !s->stack_count || s->stack_count>256 || (s->stacks_pa&(page-1)) ||
       s->stacks_pa>UINT64_MAX-s->stack_count*page)
        return SPTM_BAD_CONFIG;
    if((args[0]&(page-1)) || args[0]<s->stacks_pa ||
       args[0]>=s->stacks_pa+s->stack_count*page)
        return SPTM_BAD_ADDRESS;
    if(args[1]>3) return SPTM_UNSUPPORTED_OPTIONS;
    for(unsigned n=4;n<8;n++) if(args[n]) return SPTM_UNSUPPORTED_OPTIONS;
    uint64_t size=args[3] ? args[3] : 20;
    if(!args[2] || args[2]>UINT64_MAX-size) return SPTM_BAD_ADDRESS;
    volatile uint8_t *stack=m->map(m->ctx,args[0],page);
    if(!stack) return SPTM_MEMORY_UNAVAILABLE;
    /* Pinned TXM ...17046524 initializes 0x12411 and returns it immediately
     * when the list is empty. All-lists search ...17046624 returns 0x12412.
     * Neither path reads the hash or writes a token. ...1703fa64/88 packs
     * the library result in high32 with error domain3, leaving count zero.
     * Match this negative result; do not fabricate signature verification. */
    *status=args[1] ? TXM_TRUST_CACHE_MISS : TXM_TRUST_CACHE_ALL_MISS;
    const uint64_t words[6]={0};
    reply_status(m,args[0],stack,words,0,*status);
    return SPTM_OK;
}

static uint32_t trust_u32(const volatile uint8_t *p)
{
    return (uint32_t)p[0]|(uint32_t)p[1]<<8|(uint32_t)p[2]<<16|(uint32_t)p[3]<<24;
}

static enum sptm_result trust_view(const struct sptm_memory *m,
    const struct txm_trust_cache *tc,volatile uint8_t **view,uint64_t *span)
{
    const uint64_t page=SPTM_MAC_FRAME_SIZE;
    if(!m || !m->map || !m->publish || !tc || !tc->pa || !tc->va ||
       ((tc->pa|tc->va)&(page-1)) || tc->size<24 || tc->size>TXM_TRUST_MAX_BYTES)
        return SPTM_BAD_CONFIG;
    *span=page+((tc->size+page-1)&~(page-1));
    if(tc->pa>UINT64_MAX-*span || tc->va>UINT64_MAX-*span ||
       (tc->pa<m->alloc_high && tc->pa+*span>m->alloc_low))return SPTM_BAD_ADDRESS;
    *view=m->map(m->ctx,tc->pa,*span);
    if(!*view)return SPTM_MEMORY_UNAVAILABLE;
    const volatile uint8_t *payload=*view+page;
    if(trust_u32(payload)!=2 || tc->size!=24+24UL*trust_u32(payload+20))
        return SPTM_BAD_CONFIG;
    return SPTM_OK;
}

static int trust_compare(const volatile uint8_t *a,const uint8_t *b)
{
    for(unsigned n=0;n<20;n++)if(a[n]!=b[n])return a[n]<b[n] ? -1 : 1;
    return 0;
}

enum sptm_result txm_trust_bootstrap(const struct sptm_memory *m,
    const struct txm_service *s,const struct txm_trust_cache *tc,struct txm_trust_state *state)
{
    if(!tc || !state || !s || state->initialized)return SPTM_BAD_CONFIG;
    if(!tc->pa)return tc->va || tc->size ? SPTM_BAD_CONFIG : SPTM_OK;
    volatile uint8_t *view;
    uint64_t span;
    enum sptm_result result=trust_view(m,tc,&view,&span);
    if(result)return result;
    const uint64_t page=SPTM_MAC_FRAME_SIZE;
    if(!s->stack_count || s->stack_count>256 || s->stacks_pa>UINT64_MAX-s->stack_count*page)
        return SPTM_BAD_CONFIG;
    const uint64_t starts[]={s->stacks_pa,s->log_pa,s->rw_pa,s->ro_pa};
    const uint64_t lengths[]={s->stack_count*page,page,page,page};
    for(unsigned n=0;n<4;n++)if(starts[n] &&
       (starts[n]>UINT64_MAX-lengths[n] ||
        (tc->pa<starts[n]+lengths[n] && tc->pa+span>starts[n])))return SPTM_BAD_ADDRESS;
    unsigned count=trust_u32(view+page+20);
    for(unsigned i=1;i<count;i++) {
        uint8_t next[20];
        for(unsigned j=0;j<20;j++)next[j]=view[page+24+i*24+j];
        if(trust_compare(view+page+24+(i-1)*24,next)>0)return SPTM_BAD_CONFIG;
    }
    /* TXM ...46944 saves length/payload at +16/+24 of the 32-byte module;
     * ...46aa8 sets static type0. One static list; dynamic lists stay empty.
     * The same module and original entry bytes are read directly by AMFI. */
    for(unsigned n=0;n<page;n++)view[n]=0;
    store64(view+0x10,tc->va+0x100);
    store64(view+0x20,tc->va+0x80);
    store64(view+0x110,tc->size);
    store64(view+0x118,tc->va+page);
    m->publish(m->ctx,tc->pa,page);
    state->entries=count;
    state->initialized=1;
    return SPTM_OK;
}

/* Slots are allocated oldest first; native list order is newest first. */
static unsigned trust_dynamic_count(const struct txm_trust_cache *tc,volatile uint8_t *view)
{
    uint64_t head=load64(view+0x80);
    return head ? (unsigned)((head-tc->va-TXM_DYNAMIC_MODULE)/32+1):0;
}

static enum sptm_result trust_ready(const struct sptm_memory *m,
    const struct txm_trust_cache *tc,const struct txm_trust_state *state,
    volatile uint8_t **view)
{
    if(!state || state->initialized!=1)return SPTM_BAD_CONFIG;
    uint64_t span;
    enum sptm_result result=trust_view(m,tc,view,&span);
    if(result)return result;
    if(state->entries!=trust_u32(*view+SPTM_MAC_FRAME_SIZE+20) ||
       load64(*view+0x10)!=tc->va+0x100 || load64(*view+0x18) ||
       load64(*view+0x20)!=tc->va+0x80 || load64(*view+0x100) ||
       load64(*view+0x108) || load64(*view+0x110)!=tc->size ||
       load64(*view+0x118)!=tc->va+SPTM_MAC_FRAME_SIZE || load64(*view+0x88))return SPTM_BAD_CONFIG;
    uint64_t head=load64(*view+0x80),at=TXM_DYNAMIC_PAYLOAD;
    if(head && (head<tc->va+TXM_DYNAMIC_MODULE ||
       head>=tc->va+TXM_DYNAMIC_MODULE+32*TXM_DYNAMIC_COUNT ||
       (head-tc->va-TXM_DYNAMIC_MODULE)%32))return SPTM_BAD_CONFIG;
    unsigned count=trust_dynamic_count(tc,*view);
    for(unsigned i=0;i<TXM_DYNAMIC_COUNT;i++) {
        uint64_t mod=TXM_DYNAMIC_MODULE+32*i;
        if(i>=count) {
            for(unsigned n=0;n<32;n++)if((*view)[mod+n])return SPTM_BAD_CONFIG;
            continue;
        }
        uint64_t size=load64(*view+mod+16),type=load64(*view+mod+8);
        if(load64(*view+mod)!=(i ? tc->va+mod-32:0) || (type!=13 && type!=14 && type!=27) ||
           load64(*view+mod+24)!=tc->va+at || size<24 || at>SPTM_MAC_FRAME_SIZE ||
           size>SPTM_MAC_FRAME_SIZE-at || trust_u32(*view+at)!=2 ||
           24+24UL*trust_u32(*view+at+20)>size)return SPTM_BAD_CONFIG;
        at=(at+size+15)&~15UL;
    }
    return SPTM_OK;
}

enum sptm_result txm_trust_load(const struct sptm_memory *m,const struct txm_service *s,
    const struct txm_trust_cache *tc,const struct txm_trust_state *state,
    struct txm_load_state *audit,const struct txm_load_ops *ops,const uint64_t args[8],uint64_t *status)
{
    const uint64_t page=SPTM_MAC_FRAME_SIZE;
    if(!m || !m->map || !m->publish || !s || !audit || !ops || !ops->prepare ||
       !ops->stage || !ops->authenticate || !args || !status || !s->stack_count ||
       s->stack_count>256 || (s->stacks_pa&(page-1)) ||
       s->stacks_pa>UINT64_MAX-s->stack_count*page)return SPTM_BAD_CONFIG;
    if((args[0]&(page-1)) || args[0]<s->stacks_pa ||
       args[0]-s->stacks_pa>=s->stack_count*page)return SPTM_BAD_ADDRESS;
    if((args[1]!=13 && args[1]!=14 && args[1]!=27) || !args[3] || args[3]>TXM_NATIVE_COPY_MAX || !args[5] ||
       args[5]>page || args[6] || args[7])return SPTM_UNSUPPORTED_OPTIONS;
    volatile uint8_t *view;
    enum sptm_result r=trust_ready(m,tc,state,&view);
    if(r)return r;
    unsigned dynamic_count=trust_dynamic_count(tc,view);
    uint64_t retained_at=TXM_DYNAMIC_PAYLOAD;
    if(dynamic_count) {
        uint64_t last=TXM_DYNAMIC_MODULE+32*(dynamic_count-1);
        retained_at=(load64(view+last+24)-tc->va+load64(view+last+16)+15)&~15UL;
    }
    /* Reserve the entire input length before ownership changes; the native
     * inner payload cannot exceed it. Full slots still admit duplicate checks,
     * but a successful new UUID stops without replacing any live cache. */
    if(dynamic_count<TXM_DYNAMIC_COUNT && args[3]>page-retained_at)
        return SPTM_UNSUPPORTED_OPTIONS;
    volatile uint8_t *stack=m->map(m->ctx,args[0],page);
    if(!stack)return SPTM_MEMORY_UNAVAILABLE;
    uint64_t pa[2];r=ops->prepare(ops->ctx,args,pa);
    if(r)return r;
    if(pa[0]==pa[1])return SPTM_BAD_ADDRESS;
    for(unsigned i=0;i<2;i++) {
        r=sptm_txm_retype_check(m,pa[i],SPTM_MAC_TXM_DEFAULT,SPTM_MAC_TXM_OWNED);
        if(r)return r;
    }
    volatile uint8_t *payload=m->map(m->ctx,pa[0],args[3]),*manifest=m->map(m->ctx,pa[1],args[5]);
    if(!payload || !manifest)return SPTM_MEMORY_UNAVAILABLE;
    /* Both guest pages and publication plans have passed before any mutation.
     * The private copy survives release of the caller's original payload. */
    if(ops->stage(ops->ctx,(const uint8_t *)payload,args[3],(const uint8_t *)manifest,args[5]))
        return SPTM_MEMORY_UNAVAILABLE;
    audit->calls++;audit->payload_pa=pa[0];audit->manifest_pa=pa[1];
    for(unsigned i=0;i<2;i++) {
        r=sptm_txm_retype(m,pa[i],SPTM_MAC_TXM_DEFAULT,SPTM_MAC_TXM_OWNED);
        if(r)return r; /* A publication failure is fatal; never resume half a transfer. */
    }
    r=sptm_txm_retype(m,pa[0],SPTM_MAC_TXM_OWNED,SPTM_MAC_DEFAULT);
    if(r)return r;
    struct txm_native_cache boot={0,(const uint8_t *)view+page,tc->size};
    struct txm_native_cache dynamic[TXM_DYNAMIC_COUNT];
    for(unsigned i=0;i<dynamic_count;i++) {
        uint64_t mod=TXM_DYNAMIC_MODULE+32*(dynamic_count-1-i);
        dynamic[i]=(struct txm_native_cache){load64(view+mod+8),
            (const uint8_t *)view+(load64(view+mod+24)-tc->va),load64(view+mod+16)};
    }
    struct txm_native_result native={0};
    int error=ops->authenticate(ops->ctx,args[1],&boot,dynamic,dynamic_count,&native);
    r=sptm_txm_retype(m,pa[1],SPTM_MAC_TXM_OWNED,SPTM_MAC_DEFAULT);
    if(r)return r;
    if(error)return SPTM_BAD_CONFIG;
    uint64_t words[6]={0};unsigned count=0;
    uint64_t answer=native.status<<32 | (native.status==1 ? 0:3);
    audit->last_status=answer;
    if(native.status==1) {
        /* Native duplicate detection runs even when our bounded storage is full.
         * An additional distinct cache needs a larger protected reservation;
         * stop visibly instead of replacing a live cache or inventing status. */
        if(dynamic_count==TXM_DYNAMIC_COUNT)return SPTM_UNSUPPORTED_OPTIONS;
        if(!native.payload || native.size<24 || native.size>TXM_NATIVE_COPY_MAX ||
           native.size>page-retained_at ||
           trust_u32(native.payload)!=2 || 24+24UL*trust_u32(native.payload+20)>native.size)
            return SPTM_BAD_CONFIG;
        uint64_t mod=TXM_DYNAMIC_MODULE+32*dynamic_count;
        for(uint64_t i=0;i<native.size;i++)view[retained_at+i]=native.payload[i];
        store64(view+mod,load64(view+0x80));store64(view+mod+8,args[1]);
        store64(view+mod+16,native.size);store64(view+mod+24,tc->va+retained_at);
        /* Publish data and module before exposing the head to guest readers. */
        m->publish(m->ctx,tc->pa,page);
        store64(view+0x80,tc->va+mod);m->publish(m->ctx,tc->pa+0x80,8);
        words[0]=1;count=1;audit->successes++;audit->copied_bytes+=native.size;
    } else audit->failures++;
    reply_status(m,args[0],stack,words,count,answer);*status=answer;
    return SPTM_OK;
}

enum sptm_result txm_trust_uuid(const struct sptm_memory *m,
    const struct txm_service *s,const struct txm_trust_cache *tc,const struct txm_trust_state *state,
    txm_copyin_fn copyin,void *copy_ctx,uint64_t selector,const uint64_t args[8],uint64_t *status)
{
    const uint64_t page=SPTM_MAC_FRAME_SIZE;
    if(selector!=16)return SPTM_UNSUPPORTED_OPTIONS;
    if(!m || !m->map || !m->publish || !s || !tc || !state || !args || !status || !copyin ||
       !s->stack_count || s->stack_count>256 || (s->stacks_pa&(page-1)) ||
       s->stacks_pa>UINT64_MAX-s->stack_count*page)return SPTM_BAD_CONFIG;
    if((args[0]&(page-1)) || args[0]<s->stacks_pa ||
       args[0]-s->stacks_pa>=s->stack_count*page ||
       !args[1] || args[1]>UINT64_MAX-16)return SPTM_BAD_ADDRESS;
    for(unsigned n=2;n<8;n++)if(args[n])return SPTM_UNSUPPORTED_OPTIONS;
    volatile uint8_t *view=0;
    if(tc->pa) {
        enum sptm_result result=trust_ready(m,tc,state,&view);
        if(result)return result;
    } else if(tc->va || tc->size || state->initialized || state->entries)return SPTM_BAD_CONFIG;
    uint8_t uuid[16];
    if(!copyin(copy_ctx,args[1],uuid,sizeof(uuid)))return SPTM_MEMORY_UNAVAILABLE;
    volatile uint8_t *stack=m->map(m->ctx,args[0],page);
    if(!stack)return SPTM_MEMORY_UNAVAILABLE;
    unsigned different=0;
    if(view)for(unsigned n=0;n<16;n++)different|=uuid[n]^view[page+4+n];
    uint64_t answer=view && !different ? TXM_TRUST_UUID_HIT : TXM_TRUST_UUID_MISS;
    if(view && answer==TXM_TRUST_UUID_MISS) {
        for(unsigned i=0;i<trust_dynamic_count(tc,view);i++) {
            uint64_t payload=load64(view+TXM_DYNAMIC_MODULE+32*i+24)-tc->va;
            different=0;
            for(unsigned n=0;n<16;n++)different|=uuid[n]^view[payload+4+n];
            if(!different)answer=TXM_TRUST_UUID_HIT;
        }
    }
    /* Native ...463dc -> ...46844 checks all loaded lists. trust_ready binds
     * the protected static/dynamic modules; this does not load or
     * approve any cache. ...3fc2c packs the library result without a token. */
    const uint64_t words[6]={0};
    reply_status(m,args[0],stack,words,0,answer);
    *status=answer;
    return SPTM_OK;
}

enum sptm_result txm_trust_query(const struct sptm_memory *m,
    const struct txm_service *s,const struct txm_trust_cache *tc,struct txm_trust_state *state,
    txm_copyin_fn copyin,void *copy_ctx,uint64_t selector,const uint64_t args[8],uint64_t *status)
{
    if(!tc)return SPTM_BAD_CONFIG;
    if(!tc->pa) {
        if(tc->va || tc->size)return SPTM_BAD_CONFIG;
        return txm_trust_query_empty(m,s,selector,args,status);
    }
    const uint64_t page=SPTM_MAC_FRAME_SIZE;
    if(selector!=14)return SPTM_UNSUPPORTED_OPTIONS;
    if(!m || !m->map || !m->publish || !s || !args || !status || !copyin ||
       !s->stack_count || s->stack_count>256 || (s->stacks_pa&(page-1)) ||
       s->stacks_pa>UINT64_MAX-s->stack_count*page)return SPTM_BAD_CONFIG;
    if((args[0]&(page-1)) || args[0]<s->stacks_pa ||
       args[0]>=s->stacks_pa+s->stack_count*page)return SPTM_BAD_ADDRESS;
    if(args[1]>3)return SPTM_UNSUPPORTED_OPTIONS;
    for(unsigned n=4;n<8;n++)if(args[n])return SPTM_UNSUPPORTED_OPTIONS;
    uint64_t size=args[3] ? args[3] : 20;
    if(!args[2] || args[2]>UINT64_MAX-size)return SPTM_BAD_ADDRESS;
    volatile uint8_t *view;
    enum sptm_result result=trust_ready(m,tc,state,&view);
    if(result)return result;
    volatile uint8_t *stack=m->map(m->ctx,args[0],page);
    if(!stack)return SPTM_MEMORY_UNAVAILABLE;
    uint64_t words[6]={0},answer=args[1] ? TXM_TRUST_CACHE_MISS : TXM_TRUST_CACHE_ALL_MISS;
    uint8_t hash[24]={0};
    unsigned dynamic_count=trust_dynamic_count(tc,view);
    if((args[1]<2 && state->entries) || ((args[1]==0 || args[1]==2) && dynamic_count)) {
        /* Version2 compares the first20 bytes even when XNU supplies a full
         * 32-byte SHA256. Native ...462e0 requires at least20 bytes. */
        if(size<20)return SPTM_UNSUPPORTED_OPTIONS;
        if(!copyin(copy_ctx,args[2],hash,20))return SPTM_MEMORY_UNAVAILABLE;
        for(unsigned list=0;list<=dynamic_count && answer!=TXM_TRUST_CACHE_HIT;list++) {
        if(list ? (args[1]!=0 && args[1]!=2) : args[1]>=2)continue;
        uint64_t module=list ? TXM_DYNAMIC_MODULE+32*(dynamic_count-list):0x100;
        uint64_t payload=load64(view+module+24)-tc->va;
        int low=0,high=(int)trust_u32(view+payload+20)-1;
        while(low<=high) {
            int mid=low+(high-low)/2;
            uint64_t offset=payload+24+24UL*(unsigned)mid;
            int order=trust_compare(view+offset,hash);
            if(!order) {
                words[0]=tc->va+module;words[1]=tc->va+offset;
                answer=TXM_TRUST_CACHE_HIT;break;
            }
            if(order<0)low=mid+1;else high=mid-1;
        }
        }
    }
    /* ...4671c returns library success16; ...3fa74..a98 packs domain0,
     * status16<<32 and two token words. A miss has no token or output words. */
    reply_status(m,args[0],stack,words,answer==TXM_TRUST_CACHE_HIT ? 2 : 0,answer);
    *status=answer;
    state->queries++;
    if(answer==TXM_TRUST_CACHE_HIT) {
        state->hits++;
        unsigned index=(unsigned)((words[1]-tc->va-page-24)/24);
        if(words[0]==tc->va+0x100 && index<64*64)state->matched[index/64]|=1UL<<(index%64);
    } else state->misses++;
    state->last_kind=args[1];state->last_length=size;state->last_status=answer;
    for(unsigned n=0;n<24;n++)state->last_hash[n]=hash[n];
    state->last_module=words[0];state->last_entry=words[1];
    return SPTM_OK;
}

enum sptm_result txm_compilation_match_empty(const struct sptm_memory *m,
    const struct txm_service *s,txm_copyin_fn copyin,void *copy_ctx,
    uint64_t selector,const uint64_t args[8],uint64_t *status)
{
    const uint64_t page=SPTM_MAC_FRAME_SIZE;
    if(selector!=30) return SPTM_UNSUPPORTED_OPTIONS;
    if(!m || !m->map || !m->publish || !s || !args || !status || !copyin ||
       !s->stack_count || s->stack_count>256 || (s->stacks_pa&(page-1)) ||
       s->stacks_pa>UINT64_MAX-s->stack_count*page)
        return SPTM_BAD_CONFIG;
    if((args[0]&(page-1)) || args[0]<s->stacks_pa ||
       args[0]>=s->stacks_pa+s->stack_count*page)
        return SPTM_BAD_ADDRESS;
    for(unsigned n=3;n<8;n++) if(args[n]) return SPTM_UNSUPPORTED_OPTIONS;
    uint64_t size=args[2] ? args[2] : 20;
    if(size<20 || size>64) return SPTM_UNSUPPORTED_OPTIONS;
    if(!args[1] || args[1]>UINT64_MAX-size) return SPTM_BAD_ADDRESS;
    volatile uint8_t *stack=m->map(m->ctx,args[0],page);
    if(!stack) return SPTM_MEMORY_UNAVAILABLE;
    uint8_t input[64];
    int copied=copyin(copy_ctx,args[1],input,size);
    for(unsigned n=0;n<sizeof(input);n++)((volatile uint8_t *)input)[n]=0;
    if(!copied) return SPTM_BAD_ADDRESS;
    /* ...170398e8 compares the normalized size to the stored size (initially
     * zero). Without an admitted setter it cannot match any valid20..64 input.
     * ...1704035c returns status8 and leaves the output count zero. */
    *status=8;
    const uint64_t words[6]={0};
    reply_status(m,args[0],stack,words,0,*status);
    return SPTM_OK;
}

enum sptm_result txm_image4_nonce_digest(const struct sptm_memory *m,
    const struct txm_service *s,struct txm_nonce_digest_registry *registry,
    txm_copyin_fn copyin,void *copy_ctx,uint64_t selector,const uint64_t args[8])
{
    const uint64_t page=SPTM_MAC_FRAME_SIZE;
    if(selector!=52)return SPTM_UNSUPPORTED_OPTIONS;
    if(!m || !m->map || !m->publish || !s || !args || !registry || !copyin ||
       !s->stack_count || s->stack_count>256 || (s->stacks_pa&(page-1)) ||
       s->stacks_pa>UINT64_MAX-s->stack_count*page)return SPTM_BAD_CONFIG;
    if((args[0]&(page-1)) || args[0]<s->stacks_pa ||
       args[0]>=s->stacks_pa+s->stack_count*page)return SPTM_BAD_ADDRESS;
    /* The shipped setter takes its domain in w0, then indexes with w21. */
    uint32_t domain=(uint32_t)args[1];
    if(domain>=TXM_NONCE_DIGEST_DOMAINS || !args[3] || args[3]>48)
        return SPTM_UNSUPPORTED_OPTIONS;
    for(unsigned n=4;n<8;n++)if(args[n])return SPTM_UNSUPPORTED_OPTIONS;
    if(!args[2] || args[2]>UINT64_MAX-args[3])return SPTM_BAD_ADDRESS;
    struct txm_nonce_digest *entry=&registry->entries[domain];
    /* ...170790f4 rejects a second set even when its material is identical.
     * Match that fatal refusal rather than silently overwriting boot state. */
    if(entry->length)return SPTM_FRAME_BUSY;
    volatile uint8_t *stack=m->map(m->ctx,args[0],page);
    if(!stack)return SPTM_MEMORY_UNAVAILABLE;
    uint8_t input[48]={0};int copied=copyin(copy_ctx,args[2],input,args[3]);
    if(copied) {
        for(unsigned n=0;n<48;n++)entry->bytes[n]=input[n];
        entry->length=args[3];registry->sets++;
    }
    for(unsigned n=0;n<48;n++)((volatile uint8_t *)input)[n]=0;
    if(!copied)return SPTM_BAD_ADDRESS;
    const uint64_t words[6]={0};reply_words(m,args[0],stack,words,0);
    return SPTM_OK;
}

static enum sptm_result image4_stack(const struct sptm_memory *m,
    const struct txm_service *s,uint64_t selector,const uint64_t args[8])
{
    const uint64_t page=SPTM_MAC_FRAME_SIZE;
    if (selector!=45) return SPTM_UNSUPPORTED_OPTIONS;
    if (!m || !m->map || !m->publish || !s || !args || !s->stack_count ||
        s->stack_count>256 || (s->stacks_pa&(page-1)) ||
        s->stacks_pa>UINT64_MAX-s->stack_count*page)
        return SPTM_BAD_CONFIG;
    if ((args[0]&(page-1)) || args[0]<s->stacks_pa ||
        args[0]>=s->stacks_pa+s->stack_count*page)
        return SPTM_BAD_ADDRESS;
    return SPTM_OK;
}

enum sptm_result txm_image4(const struct sptm_memory *m,
    const struct txm_service *s,uint64_t selector,const uint64_t args[8])
{
    enum sptm_result check=image4_stack(m,s,selector,args);
    if(check!=SPTM_OK)return check;
    if (args[1]!=6 || args[3]!=16) return SPTM_UNSUPPORTED_OPTIONS;
    for (unsigned i=4;i<8;i++) if (args[i]) return SPTM_UNSUPPORTED_OPTIONS;
    if (!args[2] || args[2]>UINT64_MAX-16) return SPTM_BAD_ADDRESS;
    volatile uint8_t *stack=m->map(m->ctx,args[0],SPTM_MAC_FRAME_SIZE);
    if (!stack) return SPTM_MEMORY_UNAVAILABLE;
    /* 26A428 TXM ...1704119c initializes {domain5,errno78}; op6 takes
     * ...170411e0 -> ...170413b0 without reading input or changing policy.
     * XNU unpacks the reply at ...befcbc8 and returns errno at ...befed00.
     * Serve that negative contract so Apple's own fallback can execute. */
    const uint64_t words[6]={0};
    reply_status(m,args[0],stack,words,0,TXM_IMAGE4_UUID_UNAVAILABLE);
    return SPTM_OK;
}

enum sptm_result txm_image4_release_type(const struct sptm_memory *m,
    const struct txm_service *s,struct txm_release_type *state,
    txm_copyin_fn copyin,void *copy_ctx,uint64_t selector,
    const uint64_t args[8],uint64_t *status)
{
    enum sptm_result check=image4_stack(m,s,selector,args);
    if(check!=SPTM_OK)return check;
    if(!state || !copyin || !status || state->sets>1)return SPTM_BAD_CONFIG;
    if(args[1] || args[3]!=64)return SPTM_UNSUPPORTED_OPTIONS;
    for(unsigned i=4;i<8;i++)if(args[i])return SPTM_UNSUPPORTED_OPTIONS;
    if(!args[2] || args[2]>UINT64_MAX-64)return SPTM_BAD_ADDRESS;
    volatile uint8_t *stack=m->map(m->ctx,args[0],SPTM_MAC_FRAME_SIZE);
    if(!stack)return SPTM_MEMORY_UNAVAILABLE;
    uint8_t input[64];
    if(!copyin(copy_ctx,args[2],input,sizeof(input)))return SPTM_BAD_ADDRESS;
    /* ...1706cf88 copies64 bytes and forces byte62 to NUL. Its setter
     * ...1706dd3c stores one bounded string and rejects a second set with37.
     * The caller serializes this state under the monitor's service lock. */
    unsigned error=state->sets ? 37 : 0;
    if(!error) {
        for(unsigned i=0;i<64;i++)state->input[i]=input[i];
        input[62]=0;
        unsigned length=0;while(input[length])length++;
        for(unsigned i=0;i<64;i++)state->value[i]=i<length ? input[i] : 0;
        state->length=length;state->sets=1;
    } else state->rejections++;
    for(unsigned i=0;i<64;i++)((volatile uint8_t *)input)[i]=0;
    *status=error ? ((uint64_t)error<<32)|5 : 0;
    state->calls++;state->last_status=*status;
    state->input_va=args[2];state->stack_pa=args[0];
    const uint64_t words[6]={0};
    reply_status(m,args[0],stack,words,0,*status);
    return SPTM_OK;
}

enum sptm_result txm_image4_nonce(const struct sptm_memory *m,
    const struct txm_service *s,struct txm_nonce_registry *registry,
    txm_copyin_fn copyin,void *copy_ctx,uint64_t selector,
    const uint64_t args[8],uint64_t *status)
{
    enum sptm_result check=image4_stack(m,s,selector,args);
    if(check!=SPTM_OK)return check;
    if(!registry || !copyin || !status)return SPTM_BAD_CONFIG;
    if(args[1]!=3 || args[3]!=44)return SPTM_UNSUPPORTED_OPTIONS;
    for(unsigned i=4;i<8;i++)if(args[i])return SPTM_UNSUPPORTED_OPTIONS;
    if(!args[2] || args[2]>UINT64_MAX-44)return SPTM_BAD_ADDRESS;
    volatile uint8_t *stack=m->map(m->ctx,args[0],SPTM_MAC_FRAME_SIZE);
    if(!stack)return SPTM_MEMORY_UNAVAILABLE;
    uint8_t input[44];
    if(!copyin(copy_ctx,args[2],input,sizeof(input)))return SPTM_BAD_ADDRESS;
    uint64_t domain=0;
    uint32_t flags=0;
    for(unsigned i=0;i<8;i++)domain|=(uint64_t)input[i]<<(8*i);
    for(unsigned i=0;i<4;i++)flags|=(uint32_t)input[8+i]<<(8*i);
    /* TXM ...1706e0a8 builds this exact registry from ...170901f8.
     * Handler ...1706d0b0 rejects wide IDs, unknown IDs and a second set. */
    static const uint32_t domains[TXM_NONCE_DOMAINS]={
        0x70646d67,0x63707478,0x64766469,0x63316274,0x63316162,0x6331676e,
        0x6331736d,0x64316d61,0x63316765,0x63316572,0x63316169,0x6331616c};
    unsigned index=TXM_NONCE_DOMAINS;
    for(unsigned i=0;i<TXM_NONCE_DOMAINS;i++)if(domain==domains[i])index=i;
    unsigned error=domain>>32 ? 84 : index==TXM_NONCE_DOMAINS ? 2 :
        registry->entries[index].initialized ? 37 : 0;
    if(!error) {
        struct txm_nonce *entry=&registry->entries[index];
        entry->domain=domain;entry->flags=flags&0x7f;
        for(unsigned i=0;i<16;i++) {
            entry->first[i]=input[12+i];entry->second[i]=input[28+i];
        }
        entry->initialized=1;
        registry->sets++;
    } else registry->rejections++;
    /* Erase temporary material after the owned record has been committed. */
    for(unsigned i=0;i<sizeof(input);i++)((volatile uint8_t *)input)[i]=0;
    *status=error ? ((uint64_t)error<<32)|5 : 0;
    const uint64_t words[6]={0};
    reply_status(m,args[0],stack,words,0,*status);
    return SPTM_OK;
}

enum sptm_result txm_set_local_key(const struct sptm_memory *m,
    const struct txm_service *s,struct txm_local_key *state,
    txm_copyin_fn copyin,void *copy_ctx,uint64_t selector,const uint64_t args[8])
{
    const uint64_t page=SPTM_MAC_FRAME_SIZE;
    if(selector!=26)return SPTM_UNSUPPORTED_OPTIONS;
    if(!m || !m->map || !m->publish || !s || !state || !copyin || !args ||
       !s->stack_count || s->stack_count>256 || (s->stacks_pa&(page-1)) ||
       s->stacks_pa>UINT64_MAX-s->stack_count*page || state->sets>1)
        return SPTM_BAD_CONFIG;
    if((args[0]&(page-1)) || args[0]<s->stacks_pa ||
       args[0]>=s->stacks_pa+s->stack_count*page ||
       !args[1] || args[1]>UINT64_MAX-TXM_LOCAL_KEY_BYTES)
        return SPTM_BAD_ADDRESS;
    for(unsigned i=2;i<8;i++)if(args[i])return SPTM_UNSUPPORTED_OPTIONS;
    /* Native ...17039560 claims a one-time byte, then copies exactly97
     * bytes. A duplicate panics with0x55: stop without publishing success. */
    if(state->sets)return SPTM_FRAME_BUSY;
    volatile uint8_t *stack=m->map(m->ctx,args[0],page);
    if(!stack)return SPTM_MEMORY_UNAVAILABLE;
    uint8_t value[TXM_LOCAL_KEY_BYTES];
    if(!copyin(copy_ctx,args[1],value,sizeof(value)))return SPTM_BAD_ADDRESS;
    for(unsigned i=0;i<sizeof(value);i++)state->value[i]=value[i];
    state->input_va=args[1];state->stack_pa=args[0];state->sets=1;
    /* The runtime service lock serializes publication with other CPUs. */
    const uint64_t words[6]={0};
    reply_words(m,args[0],stack,words,0);
    return SPTM_OK;
}

enum sptm_result txm_sep_channel_unavailable(const struct sptm_memory *m,
    const struct txm_service *s,uint64_t selector,const uint64_t args[8])
{
    const uint64_t page=SPTM_MAC_FRAME_SIZE;
    if(selector!=7)return SPTM_UNSUPPORTED_OPTIONS;
    if(!m || !m->map || !m->publish || !s || !args ||
       !s->stack_count || s->stack_count>256 || !s->ro_pa ||
       ((s->stacks_pa|s->ro_pa)&(page-1)) ||
       s->stacks_pa>UINT64_MAX-s->stack_count*page ||
       s->ro_pa>UINT64_MAX-page ||
       (s->ro_pa>=s->stacks_pa && s->ro_pa<s->stacks_pa+s->stack_count*page))
        return SPTM_BAD_CONFIG;
    if((args[0]&(page-1)) || args[0]<s->stacks_pa ||
       args[0]>=s->stacks_pa+s->stack_count*page)return SPTM_BAD_ADDRESS;
    for(unsigned i=1;i<8;i++)if(args[i])return SPTM_UNSUPPORTED_OPTIONS;
    volatile uint8_t *info=m->map(m->ctx,s->ro_pa,page);
    if(!info)return SPTM_MEMORY_UNAVAILABLE;
    /* Native initializer ...17037778..798 excludes platform class0.
     * Enforce the loader's explicit absent capability, including the empty
     * three-word descriptor. Never hide a configured/partially owned channel. */
    if(info[0xa] || load64(info+0x38) || load64(info+0x40) || load64(info+0x48))
        return SPTM_BAD_CONFIG;
    volatile uint8_t *stack=m->map(m->ctx,args[0],page);
    if(!stack)return SPTM_MEMORY_UNAVAILABLE;
    const uint64_t words[6]={0};
    reply_status(m,args[0],stack,words,0,TXM_SEP_CHANNEL_UNAVAILABLE);
    return SPTM_OK;
}

enum sptm_result txm_developer_mode(const struct sptm_memory *m,
    const struct txm_service *s, uint64_t selector, const uint64_t args[8])
{
    const uint64_t page = SPTM_MAC_FRAME_SIZE;
    if (selector != 31) return SPTM_UNSUPPORTED_OPTIONS;
    if (!m || !m->map || !m->publish || !s || !args || !s->stack_count ||
        s->stack_count > 256 || (s->stacks_pa & (page-1)) ||
        s->stacks_pa > UINT64_MAX - s->stack_count*page)
        return SPTM_BAD_CONFIG;
    if ((args[0] & (page-1)) || args[0] < s->stacks_pa ||
        args[0] >= s->stacks_pa + s->stack_count*page)
        return SPTM_BAD_ADDRESS;
    if (args[1] > 1) return SPTM_UNSUPPORTED_OPTIONS;
    for (unsigned n=2; n<8; n++)
        if (args[n]) return SPTM_UNSUPPORTED_OPTIONS;
    volatile uint8_t *stack = m->map(m->ctx, args[0], page);
    if (!stack) return SPTM_MEMORY_UNAVAILABLE;
    /* TXM 26A428 switch slot 30 goes directly to ...1703f4f4: status 0,
     * result count 0, synchronous return. No developer/CSM policy write. */
    const uint64_t words[6] = {0};
    reply_words(m, args[0], stack, words, 0);
    return SPTM_OK;
}

enum sptm_result txm_info_with_trust(const struct sptm_memory *m,
    const struct txm_service *s,const struct txm_trust_cache *tc,
    const struct txm_trust_state *state,uint64_t selector,const uint64_t args[8])
{
    const uint64_t page = SPTM_MAC_FRAME_SIZE;
    if (selector != 1 && selector != 2 && selector != 3) return SPTM_UNSUPPORTED_OPTIONS;
    if (!m || !m->map || !m->publish || !s || !args || !s->stack_count ||
        s->stack_count > 256 || (s->stacks_pa | s->log_pa | s->log_va) & (page - 1) ||
        s->stacks_pa > UINT64_MAX - s->stack_count * page ||
        s->log_pa > UINT64_MAX - page || s->log_va > UINT64_MAX - page ||
        (s->log_pa >= s->stacks_pa && s->log_pa < s->stacks_pa + s->stack_count * page))
        return SPTM_BAD_CONFIG;
    if ((args[0] & (page - 1)) || args[0] < s->stacks_pa ||
        args[0] >= s->stacks_pa + s->stack_count * page)
        return SPTM_BAD_ADDRESS;
    for (unsigned n = 1; n < 8; n++)
        if (args[n]) return SPTM_UNSUPPORTED_OPTIONS;
    if (selector == 2) {
        if (!s->rw_va || !s->ro_va ||
            ((s->rw_pa | s->rw_va | s->ro_pa | s->ro_va) & (page - 1)) ||
            s->rw_pa > UINT64_MAX-page || s->ro_pa > UINT64_MAX-page ||
            s->rw_va > UINT64_MAX-page || s->ro_va > UINT64_MAX-page ||
            s->rw_pa == s->ro_pa || s->rw_pa == s->log_pa || s->ro_pa == s->log_pa ||
            (s->rw_pa >= s->stacks_pa && s->rw_pa < s->stacks_pa+s->stack_count*page) ||
            (s->ro_pa >= s->stacks_pa && s->ro_pa < s->stacks_pa+s->stack_count*page))
            return SPTM_BAD_CONFIG;
        if (!m->map(m->ctx, s->rw_pa, page) || !m->map(m->ctx, s->ro_pa, page))
            return SPTM_MEMORY_UNAVAILABLE;
    }
    volatile uint8_t *stack = m->map(m->ctx, args[0], page);
    volatile uint8_t *log = m->map(m->ctx, s->log_pa, page);
    if (!stack || !log) return SPTM_MEMORY_UNAVAILABLE;
    /* The producer has no records. Loader zeroes the log and its head/sync
     * words; this operation never resets state shared with the consumer. */
    uint64_t words[6] = {s->log_va, s->log_va + 0x3ff0, s->log_va + 0x3ff8, 0, 0, 0};
    if (selector == 2) {
        words[0] = s->rw_va; words[1] = s->ro_va + 0x3ff0;
        words[2] = 0; words[5] = s->ro_va;
    } else if (selector == 3) {
        /* GetTrustCacheInfo: runtime, static count, capabilities of each
         * static cache. Native version2 capability table ...1700c3f0 is7.
         * No second static cache or dynamically installed cache is present. */
        for (unsigned n = 0; n < 6; n++) words[n] = 0;
        if(tc && tc->pa) {
            volatile uint8_t *view;
            enum sptm_result result=trust_ready(m,tc,state,&view);
            if(result)return result;
            words[0]=tc->va;words[1]=1;words[2]=7;
        } else if(tc && (tc->va || tc->size))return SPTM_BAD_CONFIG;
    }
    reply_words(m, args[0], stack, words, selector == 1 ? 3 : selector == 2 ? 6 : 4);
    return SPTM_OK;
}

enum sptm_result txm_info(const struct sptm_memory *m,const struct txm_service *s,
    uint64_t selector,const uint64_t args[8])
{
    return txm_info_with_trust(m,s,0,0,selector,args);
}

enum sptm_result txm_aspace(const struct sptm_memory *m,
    const struct txm_service *s, const struct txm_arena *a,
    struct txm_registry *r, uint64_t selector, const uint64_t args[8])
{
    const uint64_t page = SPTM_MAC_FRAME_SIZE;
    if (selector != 35 && selector != 36 && selector != 37) return SPTM_UNSUPPORTED_OPTIONS;
    if (!m || !m->map || !m->publish || !s || !a || !r || !args || !sptm_boot_memory_valid(m) ||
        !s->stack_count || s->stack_count > 256 || !a->va ||
        ((s->stacks_pa | a->pa | a->va | m->frame_low | m->frame_high |
          m->alloc_low | m->alloc_high) & (page - 1)) || (m->frame_map_pa & 15) ||
        s->stacks_pa > UINT64_MAX - s->stack_count * page ||
        a->pa > UINT64_MAX - TXM_ASPACE_SIZE || a->va > UINT64_MAX - TXM_ASPACE_SIZE ||
        m->frame_low >= m->frame_high || m->alloc_low >= m->alloc_high ||
        m->alloc_low < m->frame_low || m->alloc_high > m->frame_high ||
        r->count > TXM_ASPACE_LIMIT)
        return SPTM_BAD_CONFIG;
    uint64_t map_size = ((m->frame_high - m->frame_low) / page) * 16;
    const uint64_t arena_end = a->pa + TXM_ASPACE_SIZE, arena_va_end = a->va + TXM_ASPACE_SIZE;
    if (m->frame_map_pa > UINT64_MAX - map_size ||
        (a->pa < m->frame_map_pa + map_size && arena_end > m->frame_map_pa) ||
        (a->pa < s->stacks_pa + s->stack_count * page && arena_end > s->stacks_pa) ||
        (s->log_pa >= a->pa && s->log_pa < arena_end) ||
        (s->rw_pa >= a->pa && s->rw_pa < arena_end) ||
        (s->ro_pa >= a->pa && s->ro_pa < arena_end) ||
        (s->log_va >= a->va && s->log_va < arena_va_end) ||
        (s->rw_va >= a->va && s->rw_va < arena_va_end) ||
        (s->ro_va >= a->va && s->ro_va < arena_va_end))
        return SPTM_BAD_CONFIG;
    for (uint64_t pa = a->pa; pa < arena_end; pa += page)
        if (sptm_managed_frame(m, pa)) return SPTM_BAD_CONFIG;
    if ((args[0] & (page - 1)) || args[0] < s->stacks_pa ||
        args[0] >= s->stacks_pa + s->stack_count * page)
        return SPTM_BAD_ADDRESS;
    for (unsigned n = selector==37 ? 4 : 2; n < 8; n++)
        if (args[n]) return SPTM_UNSUPPORTED_OPTIONS;
    uint64_t region_start=0,region_end=0;
    if(selector==37) {
        /* Native 1703669c..6bc treats these as scalar VA bounds, not
         * pointers to copy. Do not restrict them to physical guest RAM. */
        if((args[2]|args[3])&(page-1) || !args[2] || !args[3] ||
           args[3]>UINT64_MAX-args[2])return SPTM_BAD_ADDRESS;
        region_start=args[2];region_end=args[2]+args[3];
    }
    unsigned slot = r->count;
    uint64_t asid = args[1];
    unsigned shared=0;
    if (selector == 35) {
        if (!asid || asid > 0xffff) return SPTM_UNSUPPORTED_OPTIONS;
        for (unsigned n = 0; n < r->count; n++) {
            if (!r->shared[n] && r->asid[n] == asid) return SPTM_FRAME_BUSY;
            if (!r->root[n] && slot == r->count) slot = n;
        }
        if (slot == TXM_ASPACE_LIMIT) return SPTM_MEMORY_UNAVAILABLE;
    } else {
        if (args[1] < a->va || args[1] - a->va >= TXM_ASPACE_SIZE ||
            ((args[1] - a->va) % TXM_ASPACE_STRIDE)) return SPTM_BAD_ADDRESS;
        slot = (unsigned)((args[1] - a->va) / TXM_ASPACE_STRIDE);
        if (slot >= r->count || !r->root[slot] || r->shared[slot]>1 ||
            (!r->shared[slot] && !r->asid[slot]))
            return SPTM_BAD_ADDRESS;
        asid = r->asid[slot];
        shared=r->shared[slot];
    }
    uint64_t prior_start=r->region_start[slot],prior_end=r->region_end[slot];
    if(selector==35 && r->bound_shared[slot])return SPTM_BAD_CONFIG;
    if((prior_start || prior_end) && (!shared || !prior_start ||
       prior_end<=prior_start || ((prior_start|prior_end)&(page-1))))return SPTM_BAD_CONFIG;
    if(shared && asid>=SPTM_MAC_SHARED_ROOT_LIMIT)return SPTM_BAD_TABLE;
    if(selector==37) {
        if(!shared)return SPTM_TYPE_MISMATCH;
        if(prior_end)return SPTM_FRAME_BUSY;
        if(r->region_sets==UINT64_MAX)return SPTM_BAD_CONFIG;
    }

    volatile uint8_t *frames = m->map(m->ctx, m->frame_map_pa, map_size);
    if (!frames) return SPTM_MEMORY_UNAVAILABLE;
    uint64_t root = 0;struct sptm_user_geometry geometry;
#if SNAP_ROOT_INDEX
    /* compat/root-index.h: visit only the records the scan's first test
     * admits (type and key), in its order; -1 walks every frame as before. */
    uint64_t listed[SPTM_ROOT_INDEX_LIST];unsigned item=0;
    int count=sptm_root_index_candidates(m->root_index,m,
        shared ? SPTM_ROOT_KEY_SHARED(asid) : SPTM_ROOT_KEY_USER(asid),1,listed);
    for (uint64_t pa=count>=0 ? (count ? listed[0] : m->alloc_high) : sptm_next_frame(m,0); pa<m->alloc_high;
         pa=count>=0 ? (++item<(unsigned)count ? listed[item] : m->alloc_high) : sptm_next_frame(m,pa+page)) {
#else
    for (uint64_t pa=sptm_next_frame(m,0); pa<m->alloc_high; pa=sptm_next_frame(m,pa+page)) {
#endif
        volatile uint8_t *f = frames + ((pa - m->frame_low) / page) * 16;
        if(shared) {
            if(f[2]!=SPTM_MAC_SHARED_ROOT_TABLE || f[8]!=asid)continue;
            if(selector==36 && (f[4] || f[5]))return SPTM_FRAME_BUSY;
            if(f[10] || !sptm_mac_user_geometry(f[12],SPTM_MAC_ROOT_FLAGS_USER,&geometry))
                return SPTM_BAD_TABLE;
        } else {
            if (f[2] != SPTM_MAC_USER_ROOT_TABLE ||
                ((unsigned)f[4] | (unsigned)f[5] << 8) != asid) continue;
            if(!sptm_mac_user_binding_valid(m,f) || (selector==35 && f[8]!=0xff) ||
               !sptm_mac_user_geometry(f[12],f[10],&geometry))
                return SPTM_BAD_TABLE;
            if(selector!=35 && ((f[8]==255)!=(!r->bound_shared[slot]) ||
               (f[8]!=255 && m->shared_regions->slots[f[8]].root!=r->bound_shared[slot])))
                return SPTM_TYPE_MISMATCH;
        }
        if (root) return SPTM_FRAME_BUSY;
        if (f[0] || f[1] || (selector==35 && (f[6] || f[7])) || f[9] || f[11] ||
            f[13] || f[14] || f[15]) return SPTM_BAD_TABLE;
        root = pa;
    }
    if (!root) return SPTM_TABLE_MISSING;
    if(selector!=35 && root!=r->root[slot])return SPTM_TYPE_MISMATCH;
    /* Native17036370..652c destroys the TXM policy object, not its SPTM
     * hierarchy. Retained commpages and other source mappings may remain.
     * Validate our issued policy view below; do not walk, unmap or release
     * PTEs here. The later SPTM lifecycle owns those references. */
    uint64_t offset = slot * TXM_ASPACE_STRIDE;
    volatile uint8_t *object = m->map(m->ctx, a->pa + offset, TXM_ASPACE_STRIDE);
    volatile uint8_t *stack = m->map(m->ctx, args[0], page);
    if (!object || !stack) return SPTM_MEMORY_UNAVAILABLE;
    /* Constructor 1703629c: flags +18=0, packed ASID/type +22,
     * empty mapping object +38. Allocators use sizes 70 and 50 and mark
     * each object's allocated byte +11. Locks and list links start empty.
     * No signing/trust policy or address-space activation is implied. */
    uint8_t expected[TXM_ASPACE_STRIDE];
    empty_object(expected,a->va+offset,(unsigned)asid,shared);
    if(selector!=35 && !object_view(a,r,slot,expected))return SPTM_BAD_CONFIG;
    if(selector!=35 && !object_matches(object,expected))return SPTM_FRAME_BUSY;
    if(selector==36 && shared && load32(expected+TXM_SHARED_REFS))return SPTM_FRAME_BUSY;
    volatile uint8_t *parent_object=0;uint64_t parent_pa=0;
    if(selector==36 && r->bound_shared[slot]) {
        if(r->unbindings==UINT64_MAX)return SPTM_BAD_CONFIG;
        unsigned parent=TXM_ASPACE_LIMIT;
        for(unsigned i=0;i<r->count;i++)if(r->root[i]==r->bound_shared[slot]) {
            if(parent!=TXM_ASPACE_LIMIT)return SPTM_BAD_CONFIG;
            parent=i;
        }
        uint8_t parent_view[256];
        if(parent==TXM_ASPACE_LIMIT || !object_view(a,r,parent,parent_view) ||
           !load32(parent_view+TXM_SHARED_REFS))
            return SPTM_BAD_REFERENCE;
        parent_pa=a->pa+parent*256;parent_object=m->map(m->ctx,parent_pa,256);
        if(!parent_object)return SPTM_MEMORY_UNAVAILABLE;
        if(!object_matches(parent_object,parent_view))return SPTM_FRAME_BUSY;
    }
    if(selector==37) {
        /* 170366e4: preserve identity and mapping pointer, publish only
         * the range, then return zero outputs. All fallible reads precede
         * this commit; callers hold the shared service token throughout. */
        store64(object+0x58,region_start);store64(object+0x60,region_end);
        m->publish(m->ctx,a->pa+offset+0x58,16);
        r->region_start[slot]=region_start;r->region_end[slot]=region_end;
        r->region_sets++;
        uint64_t words[6]={0};reply_words(m,args[0],stack,words,0);
        return SPTM_OK;
    }
    if(parent_object) {
        /* Native170363fc releases only the TXM object's reference. SPTM
         * retains its slot until the later root destructor. */
        store32(parent_object+TXM_SHARED_REFS,load32(parent_object+TXM_SHARED_REFS)-1);
        m->publish(m->ctx,parent_pa+TXM_SHARED_REFS,4);r->unbindings++;
    }
    for (unsigned n = 0; n < TXM_ASPACE_STRIDE; n++)
        object[n] = selector == 35 ? expected[n] : 0;
    m->publish(m->ctx, a->pa + offset, TXM_ASPACE_STRIDE);
    r->root[slot] = selector == 35 ? root : 0;
    r->asid[slot] = selector == 35 ? (uint16_t)asid : 0;
    r->shared[slot]=0;
    r->region_start[slot]=r->region_end[slot]=0;
    r->bound_shared[slot]=0;
    if (slot == r->count) r->count++;
    uint64_t words[6] = {selector == 35 ? a->va + offset : 0, 0, 0, 0, 0, 0};
    reply_words(m, args[0], stack, words, selector == 35 ? 1 : 0);
    return SPTM_OK;
}

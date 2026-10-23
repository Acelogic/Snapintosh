/* SPDX-License-Identifier: MIT */
/* Field accessors, TXM object views, shared-region binding and the trust-cache
 * calls.
 * Part of compat/txm.c's translation unit, included in order; not compiled on its own. */
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


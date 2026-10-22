/* SPDX-License-Identifier: MIT */
#include "txm-native.h"

static int valid(const struct txm_native_params *p)
{
    return p && p->image>=0x20000000 && p->image<=0xf0000000 &&
        p->work && !((p->image|p->work)&0x3fff) && p->size==TXM_NATIVE_BYTES &&
        p->work<(1UL<<36)-TXM_NATIVE_BYTES && p->tree_size && p->tree_size<=0x100000 &&
        (p->work+TXM_NATIVE_BYTES<=p->image || p->image+TXM_NATIVE_IMAGE_BYTES<=p->work);
}
static void zero(uint64_t at,uint64_t size)
{for(uint64_t i=0;i<size;i++)((volatile uint8_t *)at)[i]=0;}
static void put(uint64_t at,uint64_t value)
{*(volatile uint64_t *)at=value;}
static uint64_t get(uint64_t at)
{return *(volatile uint64_t *)at;}

static int invoke(const struct txm_native_params *p,struct txm_native_state *s,
                  uint64_t entry,const uint64_t args[8])
{
    volatile uint64_t *call=(volatile uint64_t *)p->work;
    call[0]=p->image;call[1]=p->work+TXM_NATIVE_STACK;call[2]=p->image+entry;
    for(unsigned i=0;i<8;i++)call[3+i]=args[i];
    for(unsigned i=11;i<16;i++)call[i]=0;
    uint64_t (*bridge)(volatile uint64_t *)=(void *)(p->image+0x100000);
    uint64_t status=bridge(call);
    s->calls++;s->last_entry=entry;s->last_status=status;
    s->panic_code=call[12];s->panic_arg=call[13];
    if(call[15]!=1 || call[14]!=status ||
       *(volatile uint8_t *)(p->work+TXM_NATIVE_STACK+0x78)) {
        s->phase=4;return -1;
    }
    return 0;
}

int txm_native_init(const struct txm_native_params *p,struct txm_native_state *s,
                    uint64_t guest_pfr0,uint64_t guest_pfr1)
{
    if(!valid(p) || !s || s->phase)return -1;
    /* The A16 implements SVE/SME, but the monitor's id_forge hides both.
     * Require that effective guest contract. A future guest exposing either
     * extension needs its complete scalable/streaming state saved first. */
    if(((guest_pfr0>>32)&15) || ((guest_pfr1>>24)&15))return -1;
    zero(p->work,TXM_NATIVE_TREE); /* The loader's exact tree copy survives. */
    put(p->image+0x203e0,p->work+TXM_NATIVE_TREE);
    put(p->image+0x203e8,p->tree_size);
    *(volatile uint8_t *)(p->image+0x203f0)=1;
    uint64_t stack=p->work+TXM_NATIVE_STACK;
    *(volatile uint8_t *)stack=1;
    put(stack+0x60,p->work+0x100000);put(stack+0x68,0x100000);put(stack+0x70,0x100000);
    const uint64_t args[8]={0};
    if(invoke(p,s,0x791a0,args))return -1;
    s->phase=1;
    return 0;
}

int txm_native_stage(const struct txm_native_params *p,struct txm_native_state *s,
    const uint8_t *payload,uint64_t size,const uint8_t *manifest,uint64_t manifest_size)
{
    if(!valid(p) || !s || s->phase!=1 || !payload || !manifest ||
       !size || size>TXM_NATIVE_COPY_MAX || !manifest_size || manifest_size>0x4000 ||
       (uint64_t)payload>UINT64_MAX-size || (uint64_t)manifest>UINT64_MAX-manifest_size)
        return -1;
    /* Guest input ownership is checked by the caller before staging. Refuse
     * aliases of private workspace so initialization/copy cannot self-clobber. */
    if(((uint64_t)payload<p->work+p->size && p->work<(uint64_t)payload+size) ||
       ((uint64_t)manifest<p->work+p->size && p->work<(uint64_t)manifest+manifest_size))return -1;
    zero(p->work+TXM_NATIVE_PAYLOAD,0x8000);
    for(uint64_t i=0;i<size;i++)((volatile uint8_t *)(p->work+TXM_NATIVE_PAYLOAD))[i]=payload[i];
    for(uint64_t i=0;i<manifest_size;i++)((volatile uint8_t *)(p->work+TXM_NATIVE_MANIFEST))[i]=manifest[i];
    s->payload_size=size;s->manifest_size=manifest_size;s->phase=2;
    return 0;
}

static int cache_valid(const struct txm_native_params *p,const struct txm_native_cache *c,
                       uint64_t type)
{
    if(!c)return 1;
    return c->type==type && c->payload && c->size>=24 && c->size<=0x100000 &&
        (uint64_t)c->payload<=UINT64_MAX-c->size &&
        ((uint64_t)c->payload+c->size<=p->work || p->work+p->size<=(uint64_t)c->payload);
}
static void module(uint64_t at,const struct txm_native_cache *c)
{
    zero(at,32);
    if(c) {put(at+8,c->type);put(at+16,c->size);put(at+24,(uint64_t)c->payload);}
}

int txm_native_load(const struct txm_native_params *p,struct txm_native_state *s,uint64_t type,
    const struct txm_native_cache *boot,const struct txm_native_cache *dynamic,
    struct txm_native_result *out)
{
    return txm_native_load_caches(p,s,type,boot,dynamic,dynamic ? 1:0,out);
}

int txm_native_load_caches(const struct txm_native_params *p,struct txm_native_state *s,uint64_t type,
    const struct txm_native_cache *boot,const struct txm_native_cache *dynamic,unsigned count,
    struct txm_native_result *out)
{
    if(!valid(p) || !s || s->phase!=2 || (type!=13 && type!=14 && type!=27) || !out ||
       !cache_valid(p,boot,0) || count>TXM_NATIVE_CACHE_MAX || (count && !dynamic))return -1;
    for(unsigned i=0;i<count;i++)
        if((dynamic[i].type!=13 && dynamic[i].type!=14 && dynamic[i].type!=27) ||
           !cache_valid(p,&dynamic[i],dynamic[i].type))return -1;
    *out=(struct txm_native_result){0};
    uint64_t runtime=p->image+0x20400,old_static=p->work+0xc000,
        old_dynamic=p->work+0xc100,pending=p->work+0xc200,heads=p->work+0x10000;
    const uint64_t existing[TXM_NATIVE_CACHE_MAX]={old_dynamic,p->work+0xc300,p->work+0xc400};
    /* Rebuild private pointer views from caller-owned protected cache copies.
     * Native library code performs both authentication and duplicate lookup. */
    zero(runtime,0x30);zero(heads,16);zero(p->work+0x14000,0x100);
    module(old_static,boot);module(pending,0);
    for(unsigned i=0;i<TXM_NATIVE_CACHE_MAX;i++) {
        module(existing[i],i<count ? &dynamic[i]:0);
        if(i+1<count)put(existing[i],existing[i+1]);
    }
    put(runtime,p->work+0x14000);put(runtime+0x20,heads);
    if(boot)put(runtime+0x10,old_static);
    if(count)put(heads,old_dynamic);
    uint64_t args[8]={runtime,type,pending,p->work+TXM_NATIVE_PAYLOAD,s->payload_size,
                      p->work+TXM_NATIVE_MANIFEST,s->manifest_size,0};
    s->phase=3;
    if(invoke(p,s,0x46ac8,args))return -1;
    s->loads++;s->phase=1;out->status=s->last_status;
    if(s->last_status!=1) {s->auth_failures++;return 0;}
    uint64_t payload=get(pending+24),length=get(pending+16),start=p->work+TXM_NATIVE_PAYLOAD;
    if(get(heads)!=pending || get(pending)!=(count ? old_dynamic:0) || get(pending+8)!=type ||
       !length || payload<start || payload-start>s->payload_size ||
       length>s->payload_size-(payload-start)) {s->phase=4;return -1;}
    out->payload=(const uint8_t *)payload;out->size=length;
    return 0;
}

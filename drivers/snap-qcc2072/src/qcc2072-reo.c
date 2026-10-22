/* SPDX-License-Identifier: MIT */
/* Independent implementation from pinned register/descriptor facts. Source and
 * license provenance: re/reo-provider/FAILURES-AND-REPLAY.md. */
#include "qcc2072-reo.h"

struct geometry { uint32_t base,r2,id,entries,dwords,destination; };
static const struct geometry rings[QCC2072_REO_RING_COUNT] = {
    {0xa38500,0xa3b048,1,2048,8,1}, {0xa38578,0xa3b050,2,2048,8,1},
    {0xa385f0,0xa3b058,3,2048,8,1}, {0xa38668,0xa3b060,4,2048,8,1},
    {0xa386e0,0xa3b068,5,2048,8,1}, {0xa38758,0xa3b070,6,2048,8,1},
    {0xa387d0,0xa3b078,7,2048,8,1}, {0xa38848,0xa3b080,8,2048,8,1},
    {0xa38320,0xa3b028,16,32,8,0}, {0xa388c0,0xa3b088,0,128,8,1},
    {0xa382a8,0xa3b020,20,256,10,0}, {0xa38aa0,0xa3b0a8,21,2048,28,1}
};
static void zero(void *v,size_t n)
{
    uint8_t *p=v;for(size_t i=0;i<n;i++)p[i]=0;
}
static void put32(uint8_t *p,uint32_t v)
{
    for(unsigned i=0;i<4;i++)p[i]=(uint8_t)(v>>(8*i));
}
static int overlap(uint64_t a,uint64_t n,uint64_t b,uint64_t m)
{
    return n && m && (a>UINT64_MAX-n || b>UINT64_MAX-m || (a<b+m && b<a+n));
}
static int fail(struct qcc2072_reo *r,int reason)
{
    r->quarantined=1;r->quarantine_reason=reason;return reason;
}
static int owner(struct qcc2072_reo *r)
{
    if(r->ops.validate_owner(r->ops.context,r->admission->generation,
                             r->admission->owner_cookie))
        return fail(r,QCC2072_SESSION_STALE);
    return 0;
}
static int allowed(uint32_t target)
{
    for(unsigned i=0;i<QCC2072_REO_RING_COUNT;i++) {
        const struct geometry *g=&rings[i];
        if(target==g->r2 || target==g->r2+4)return 1;
        if(target<g->base)continue;
        switch(target-g->base) {
        case 0:case 4:case 8:case 0x10:case 0x4c:return 1;
        case 0x14:case 0x18:case 0x24:if(g->destination)return 1;break;
        case 0x1c:case 0x20:case 0x30:case 0x34:if(!g->destination)return 1;break;
        default:break;
        }
    }
    return 0;
}
/* Every operation rechecks ownership. No cached window assumption crosses a
 * callback; CE and REO share the selector on the same serialized owner queue. */
static int access32(struct qcc2072_reo *r,uint32_t target,uint32_t *value,int write)
{
    uint32_t old,selected,back;int rc;
    if(!allowed(target))return fail(r,QCC2072_BAD_REGISTER);
    if((rc=owner(r)))return rc;
    if(r->ops.read32(r->ops.context,0x3278,&old) || old==UINT32_MAX)
        return fail(r,QCC2072_RUNTIME_IO);
    selected=(old&0xffffffc0U)|0x40000000U|((target>>19)&63);
    if(old!=selected && (r->ops.write32(r->ops.context,0x3278,selected) ||
        r->ops.read32(r->ops.context,0x3278,&back) || back!=selected))
        return fail(r,QCC2072_RUNTIME_IO);
    if((rc=owner(r)))return rc;
    uint32_t offset=0x80000+(target&0x7ffff);
    rc=write?r->ops.write32(r->ops.context,offset,*value):
             r->ops.read32(r->ops.context,offset,value);
    return rc?fail(r,QCC2072_RUNTIME_IO):0;
}
static int checked_write(struct qcc2072_reo *r,uint32_t address,uint32_t value,uint32_t mask)
{
    uint32_t back;int rc=access32(r,address,&value,1);
    if(!rc)rc=access32(r,address,&back,0);
    if(!rc && (back&mask)!=(value&mask))rc=fail(r,QCC2072_RUNTIME_IO);
    return rc;
}
static int stage_ring(struct qcc2072_reo *r,unsigned index)
{
    const struct geometry *g=&rings[index];
    uint32_t base=g->base,addr=(uint32_t)(r->arena.iova+r->ring_offset[index]);
    uint32_t wb=(uint32_t)(r->arena.iova+index*64);int rc;
#define WRITE(a,v,m) do { rc=checked_write(r,(a),(v),(m));if(rc)return rc; } while(0)
    WRITE(base+0x10,0,0x40); /* enable only: other MISC bits include status */
    WRITE(base+0x4c,0,0x1ff);
    WRITE(base,addr,UINT32_MAX);
    WRITE(base+4,g->entries*g->dwords<<8,UINT32_MAX);
    WRITE(base+8,g->dwords|(g->destination?g->id<<8:0),0xffff);
    if(g->destination) {
        WRITE(base+0x24,0,UINT32_MAX);WRITE(base+0x14,wb,UINT32_MAX);
        WRITE(base+0x18,0,0xff);
    } else {
        WRITE(base+0x30,0,UINT32_MAX);WRITE(base+0x34,0,UINT32_MAX);
        WRITE(base+0x1c,wb,UINT32_MAX);WRITE(base+0x20,0,0xff);
    }
    WRITE(g->r2,0,UINT32_MAX);WRITE(g->r2+4,0,UINT32_MAX);
#undef WRITE
    return 0;
}
int qcc2072_reo_init(struct qcc2072_reo *r,const struct qcc2072_reo_ops *ops,
    const struct qcc2072_dma_admission *a,const struct qcc2072_dma_buffer *arena,
    const struct qcc2072_dma_buffer *protected,uint32_t count,uint32_t bar_bytes)
{
    if(!r || !ops || !a || !arena || !protected || !count || count>128 ||
       !ops->validate_owner || !ops->read32 || !ops->write32 || !ops->sync ||
       bar_bytes<0x100000)return QCC2072_INVALID_ARGUMENT;
    int rc=qcc2072_dma_validate(a,a->generation,a->owner_cookie);if(rc)return rc;
    if((rc=qcc2072_dma_buffer_validate(a,arena,QCC2072_REO_ARENA_BYTES,4096)))return rc;
    if(arena->iova>UINT32_MAX || QCC2072_REO_ARENA_BYTES-1>UINT32_MAX-arena->iova ||
       overlap((uintptr_t)arena->cpu,QCC2072_REO_ARENA_BYTES,(uintptr_t)r,sizeof(*r)))
        return QCC2072_DMA_INVALID;
    int writable=0;
    for(uint32_t i=0;i<a->map_count;i++) {
        const struct qcc2072_dma_map *m=&a->maps[i];
        if((m->permissions&3)==3 && arena->iova>=m->iova &&
           arena->iova-m->iova<=m->length &&
           QCC2072_REO_ARENA_BYTES<=m->length-(arena->iova-m->iova))writable=1;
    }
    if(!writable)return QCC2072_DMA_INVALID;
    for(uint32_t i=0;i<count;i++) {
        const struct qcc2072_dma_buffer *b=&protected[i];
        if((rc=qcc2072_dma_buffer_validate(a,b,b->capacity,4)))return rc;
        if(overlap((uintptr_t)arena->cpu,QCC2072_REO_ARENA_BYTES,(uintptr_t)b->cpu,b->capacity) ||
           overlap(arena->physical,QCC2072_REO_ARENA_BYTES,b->physical,b->capacity) ||
           overlap(arena->iova,QCC2072_REO_ARENA_BYTES,b->iova,b->capacity))return QCC2072_DMA_INVALID;
    }
    if(ops->validate_owner(ops->context,a->generation,a->owner_cookie))return QCC2072_SESSION_STALE;
    struct qcc2072_reo_ops saved_ops=*ops;struct qcc2072_dma_buffer saved_arena=*arena;
    zero(r,sizeof(*r));r->ops=saved_ops;r->arena=saved_arena;r->admission=a;
    uint32_t offset=4096;
    for(unsigned i=0;i<QCC2072_REO_RING_COUNT;i++) {
        offset=(offset+4095)&~4095U;r->ring_offset[i]=offset;
        uint32_t bytes=rings[i].entries*rings[i].dwords*4;
        if(offset>QCC2072_REO_ARENA_BYTES || bytes>QCC2072_REO_ARENA_BYTES-offset)
            return fail(r,QCC2072_DMA_INVALID);
        offset+=bytes;
    }
    zero(r->arena.cpu,QCC2072_REO_ARENA_BYTES);
    /* TLV32 header is 4 bytes; payload starts with the 16-bit command number. */
    for(unsigned i=0;i<256;i++)put32(r->arena.cpu+r->ring_offset[10]+i*40+4,i+1);
    r->initialized=1;return 0;
}
int qcc2072_reo_stage(struct qcc2072_reo *r)
{
    if(!r || !r->initialized || r->in_call || r->staged)return QCC2072_BAD_STATE;
    if(r->quarantined)return QCC2072_QUARANTINED;
    r->in_call=1;int rc=owner(r);
    /* Check every engine before any REO geometry write. Never reset a busy ring. */
    for(unsigned i=0;!rc && i<QCC2072_REO_RING_COUNT;i++) {
        uint32_t misc;rc=access32(r,rings[i].base+0x10,&misc,0);
        if(!rc && (misc&0x40))rc=fail(r,QCC2072_DEVICE_NOT_QUIESCENT);
    }
    if(!rc && r->ops.sync(r->ops.context,&r->arena,0,QCC2072_REO_ARENA_BYTES,QCC2072_SYNC_DEVICE))
        rc=fail(r,QCC2072_RUNTIME_IO);
    for(unsigned i=0;!rc && i<QCC2072_REO_RING_COUNT;i++)rc=stage_ring(r,i);
    if(!rc)r->staged=1;
    r->in_call=0;return rc;
}
int qcc2072_reo_activate(struct qcc2072_reo *r)
{
    if(!r || !r->initialized || r->in_call || !r->staged || r->activated)
        return QCC2072_BAD_STATE;
    if(r->quarantined)return QCC2072_QUARANTINED;
    r->in_call=1;int rc=owner(r);
    for(unsigned i=0;!rc && i<QCC2072_REO_RING_COUNT;i++) {
        uint32_t misc;rc=access32(r,rings[i].base+0x10,&misc,0);
        if(!rc && (misc&0x40))rc=fail(r,QCC2072_DEVICE_NOT_QUIESCENT);
    }
    if(!rc && r->ops.sync(r->ops.context,&r->arena,0,QCC2072_REO_ARENA_BYTES,QCC2072_SYNC_DEVICE))
        rc=fail(r,QCC2072_RUNTIME_IO);
    for(unsigned i=0;!rc && i<QCC2072_REO_RING_COUNT;i++)
        rc=checked_write(r,rings[i].base+0x10,rings[i].destination?0x40:0x42,0x43);
    if(!rc)r->activated=1;r->in_call=0;return rc;
}
int qcc2072_reo_abort(struct qcc2072_reo *r,int reason)
{
    if(!r || !r->initialized || r->in_call)return QCC2072_BAD_STATE;
    return fail(r,reason?reason:QCC2072_QUARANTINED);
}

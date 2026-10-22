/* SPDX-License-Identifier: MIT */
/* Independent QCC2072 common SRNG and cookie implementation. Exact source pins
 * and pre-code failure inventory live in re/datapath-provider. */
#include "qcc2072-datapath.h"
struct ring_spec {uint32_t base,r2,id,count,dwords,dest;};
static const struct ring_spec rings[QCC2072_DATAPATH_COMMON_RINGS]={
    {0xa34d3c,0xa370b8,120,32768,2,0}, /* WBM idle descriptor list */
    {0xa3437c,0xa37010,121,64,8,0},
    {0xa44918,0xa46000,24,512,8,0},
    {0xa44990,0xa46008,25,512,8,0},
    {0xa44a08,0xa46010,26,512,8,0},
    {0xa34e08,0xa370c8,128,32768,8,1},
    {0xa34ef8,0xa370d8,130,32768,8,1},
    {0xa34fe8,0xa370e8,132,32768,8,1},
    {0xa34f70,0xa370e0,131,16384,8,1}
};
static void zero(void*v,size_t n){uint8_t*p=v;for(size_t i=0;i<n;i++)p[i]=0;}
static void put32(uint8_t*p,uint32_t v){for(unsigned i=0;i<4;i++)p[i]=(uint8_t)(v>>(8*i));}
static void put64(uint8_t*p,uint64_t v){for(unsigned i=0;i<8;i++)p[i]=(uint8_t)(v>>(8*i));}
static uint32_t get32(const uint8_t*p){return (uint32_t)p[0]|(uint32_t)p[1]<<8|(uint32_t)p[2]<<16|(uint32_t)p[3]<<24;}
static int overlap(uint64_t a,uint64_t n,uint64_t b,uint64_t m){return n&&m&&(a>UINT64_MAX-n||b>UINT64_MAX-m||(a<b+m&&b<a+n));}
static int fail(struct qcc2072_datapath*d,int rc){d->quarantined=1;d->quarantine_reason=rc;return rc;}
static int owner(struct qcc2072_datapath*d){return d->ops.validate_owner(d->ops.context,d->admission->generation,d->admission->owner_cookie)?fail(d,QCC2072_SESSION_STALE):0;}
static int allowed(struct qcc2072_datapath*d,uint32_t a){
    if((a&3)==0&&d->cmem&&a>=d->cmem&&a-d->cmem<280*4)return 1;
    static const uint32_t globals[]={0xa38000,0xa38ba0,0xa38b2c,0xa38b30,0xa38b34,0xa38b38,0xa3800c,0xa38010,0xa3806c,0xa38070,0xa34040,0xa34044,0xa34090,0xa34094};
    for(unsigned i=0;i<sizeof(globals)/sizeof(globals[0]);i++)if(a==globals[i])return 1;
    for(unsigned i=0;i<QCC2072_DATAPATH_COMMON_RINGS;i++){
        const struct ring_spec*g=&rings[i];if(a==g->r2||a==g->r2+4)return 1;
        if(a<g->base)continue;
        switch(a-g->base){case 0:case 4:case 8:case 0x10:case 0x4c:return 1;
        case 0x14:case 0x18:case 0x24:if(g->dest)return 1;break;
        case 0x1c:case 0x20:case 0x30:case 0x34:if(!g->dest)return 1;break;default:break;}
    }return 0;
}
static int access32(struct qcc2072_datapath*d,uint32_t a,uint32_t*v,int write){
    uint32_t old,selection,back;int rc;if(!allowed(d,a))return fail(d,QCC2072_BAD_REGISTER);
    if((rc=owner(d)))return rc;
    if(d->ops.read32(d->ops.context,0x3278,&old)||old==UINT32_MAX)return fail(d,QCC2072_RUNTIME_IO);
    selection=(old&0xffffffc0U)|0x40000000U|((a>>19)&63);
    if(old!=selection&&(d->ops.write32(d->ops.context,0x3278,selection)||d->ops.read32(d->ops.context,0x3278,&back)||back!=selection))return fail(d,QCC2072_RUNTIME_IO);
    if((rc=owner(d)))return rc;uint32_t off=0x80000+(a&0x7ffff);
    rc=write?d->ops.write32(d->ops.context,off,*v):d->ops.read32(d->ops.context,off,v);
    return rc?fail(d,QCC2072_RUNTIME_IO):0;
}
static int wr(struct qcc2072_datapath*d,uint32_t a,uint32_t v,uint32_t mask){
    uint32_t back=0;int rc=access32(d,a,&v,1);if(!rc)rc=access32(d,a,&back,0);
    return rc?rc:((back&mask)!=(v&mask)?fail(d,QCC2072_RUNTIME_IO):0);
}
static int rmw(struct qcc2072_datapath*d,uint32_t a,uint32_t clear,uint32_t set){uint32_t v;int rc=access32(d,a,&v,0);return rc?rc:wr(d,a,(v&~clear)|set,UINT32_MAX);}
static int enter(struct qcc2072_datapath*d){if(!d||!d->initialized||d->in_call)return QCC2072_BAD_STATE;if(d->quarantined)return QCC2072_QUARANTINED;d->in_call=1;int rc=owner(d);if(rc)d->in_call=0;return rc;}
static int leave(struct qcc2072_datapath*d,int rc){d->in_call=0;return rc;}
int qcc2072_datapath_init(struct qcc2072_datapath*d,const struct qcc2072_reo_ops*ops,
 const struct qcc2072_dma_admission*a,const struct qcc2072_dma_buffer*arena,
 const struct qcc2072_dma_buffer*protected,uint32_t count){
 if(!d||!ops||!a||!arena||!protected||!count||count>128||!ops->validate_owner||!ops->read32||!ops->write32||!ops->sync)return QCC2072_INVALID_ARGUMENT;
 int rc=qcc2072_dma_validate(a,a->generation,a->owner_cookie);if(rc)return rc;
 if((rc=qcc2072_dma_buffer_validate(a,arena,QCC2072_DATAPATH_ARENA_BYTES,4096)))return rc;
 if(arena->iova>UINT32_MAX-QCC2072_DATAPATH_ARENA_BYTES+1||overlap((uintptr_t)arena->cpu,QCC2072_DATAPATH_ARENA_BYTES,(uintptr_t)d,sizeof(*d)))return QCC2072_DMA_INVALID;
 int rw=0;for(uint32_t i=0;i<a->map_count;i++){const struct qcc2072_dma_map*m=&a->maps[i];if((m->permissions&3)==3&&arena->iova>=m->iova&&arena->iova-m->iova<=m->length&&QCC2072_DATAPATH_ARENA_BYTES<=m->length-(arena->iova-m->iova))rw=1;}if(!rw)return QCC2072_DMA_INVALID;
 for(uint32_t i=0;i<count;i++){const struct qcc2072_dma_buffer*b=&protected[i];if((rc=qcc2072_dma_buffer_validate(a,b,b->capacity,4)))return rc;if(overlap((uintptr_t)arena->cpu,QCC2072_DATAPATH_ARENA_BYTES,(uintptr_t)b->cpu,b->capacity)||overlap(arena->physical,QCC2072_DATAPATH_ARENA_BYTES,b->physical,b->capacity)||overlap(arena->iova,QCC2072_DATAPATH_ARENA_BYTES,b->iova,b->capacity))return QCC2072_DMA_INVALID;}
 if(ops->validate_owner(ops->context,a->generation,a->owner_cookie))return QCC2072_SESSION_STALE;
 struct qcc2072_reo_ops saved=*ops;struct qcc2072_dma_buffer mem=*arena;zero(d,sizeof(*d));d->ops=saved;d->admission=a;d->arena=mem;
 zero(d->arena.cpu,QCC2072_DATAPATH_ARENA_BYTES);
 for(unsigned i=0;i<280*512;i++){
    put64(d->arena.cpu+0x1000+i*8,(uintptr_t)d->arena.cpu+0x120000+i*32);
    uint8_t*p=d->arena.cpu+0x120000+i*32;put32(p,i);put32(p+4,0x2072cc01);put64(p+8,a->generation);
 }
 d->offsets[0]=0xa00000;uint32_t offset=0xa40000;
 for(unsigned i=1;i<QCC2072_DATAPATH_COMMON_RINGS;i++){offset=(offset+4095)&~4095U;d->offsets[i]=offset;offset+=rings[i].count*rings[i].dwords*4;}
 if(offset>0xe00000)return fail(d,QCC2072_DMA_INVALID);
 /* Logical link banks use the upstream <2MiB bank geometry, even though this
  * admitted allocation is contiguous. Return cookie is opaque to hardware. */
 for(unsigned i=0;i<32768;i++){
    unsigned bank=i/16383,slot=i%16383,remaining=(bank==2?2:16383)-slot;
    uint32_t cookie=((remaining+0x4000)<<3)|bank;
    uint8_t*p=d->arena.cpu+0xa00000+i*8;put32(p,(uint32_t)(arena->iova+0x600000+i*128));put32(p+4,(1U<<8)|(cookie<<12));
 }
 d->initialized=1;return 0;
}
static int ring_stage(struct qcc2072_datapath*d,unsigned i){
 const struct ring_spec*g=&rings[i];uint32_t base=g->base,addr=(uint32_t)d->arena.iova+d->offsets[i],wb=(uint32_t)d->arena.iova+i*64;int rc;
#define W(a,v,m) do{rc=wr(d,a,v,m);if(rc)return rc;}while(0)
 W(base+0x10,0,0x40);W(base+0x4c,0,0x1ff);W(base,addr,UINT32_MAX);W(base+4,g->count*g->dwords<<8,UINT32_MAX);W(base+8,g->dwords|(g->dest?g->id<<8:0),0xffff);
 if(g->dest){W(base+0x24,0,UINT32_MAX);W(base+0x14,wb,UINT32_MAX);W(base+0x18,0,0xff);}
 else{W(base+0x30,0,UINT32_MAX);W(base+0x34,0,UINT32_MAX);if(i){W(base+0x1c,wb,UINT32_MAX);W(base+0x20,0,0xff);}}
 W(g->r2,0,UINT32_MAX);W(g->r2+4,0,UINT32_MAX);
#undef W
 return 0;
}
int qcc2072_datapath_begin(struct qcc2072_datapath*d,const struct qcc2072_qmi_session*q){
 int rc=enter(d);if(rc)return rc;if(d->active)return leave(d,QCC2072_BAD_STATE);
 if(!q||q->generation!=d->admission->generation||q->owner_cookie!=d->admission->owner_cookie||!q->device_memory_observed)return leave(d,fail(d,QCC2072_IDENTITY_UNKNOWN));
 uint64_t base=q->device_memory[0].start,size=q->device_memory[0].size;
 /* Firmware supplies CMEM, not an arbitrary host physical address. Restrict its
  * bounded PPT prefix to the endpoint's windowed device-memory address space,
  * excluding UMAC and CE/reset register banks. No host address translation. */
 if((base&3)||base<0x80000||base>=0x1b00000||size<280*4||size>0x2000000-base||overlap(base,280*4,0xa00000,0x100000))return leave(d,fail(d,QCC2072_BAD_REGISTER));
 d->cmem=(uint32_t)base;
 for(unsigned i=0;!rc&&i<QCC2072_DATAPATH_COMMON_RINGS;i++){uint32_t v;rc=access32(d,rings[i].base+0x10,&v,0);if(!rc&&(v&0x40))rc=fail(d,QCC2072_DEVICE_NOT_QUIESCENT);}
 if(!rc&&d->ops.sync(d->ops.context,&d->arena,0,QCC2072_DATAPATH_ARENA_BYTES,QCC2072_SYNC_DEVICE))rc=fail(d,QCC2072_RUNTIME_IO);
 for(unsigned i=0;!rc&&i<QCC2072_DATAPATH_COMMON_RINGS;i++)rc=ring_stage(d,i);
 for(unsigned i=0;!rc&&i<280;i++)rc=wr(d,d->cmem+i*4,(uint32_t)((d->arena.iova+0x1000+i*4096)>>12),UINT32_MAX);
 if(!rc)rc=wr(d,0xa3806c,d->cmem,UINT32_MAX);
 if(!rc)rc=wr(d,0xa38070,0x1d1310,UINT32_MAX);
 if(!rc)rc=wr(d,0xa34040,d->cmem,UINT32_MAX);
 if(!rc)rc=wr(d,0xa34044,0x51310,UINT32_MAX);
 if(!rc)rc=rmw(d,0xa34090,0,0xb);
 if(!rc)rc=rmw(d,0xa34094,0,0x13a);
 if(!rc)rc=rmw(d,0xa38000,0,0xc);
 if(!rc)rc=rmw(d,0xa38ba0,0x1fe0000,0);
 for(unsigned i=0;!rc&&i<4;i++)rc=wr(d,0xa38b2c+i*4,i==3?40000:100000,UINT32_MAX);
 if(!rc)rc=wr(d,0xa3800c,0x43214321,UINT32_MAX);
 if(!rc)rc=wr(d,0xa38010,0x43214321,UINT32_MAX);
 /* Enable common engines only after all tables/rings/routing were published. */
 for(unsigned i=0;!rc&&i<QCC2072_DATAPATH_COMMON_RINGS;i++)rc=wr(d,rings[i].base+0x10,rings[i].dest?0x40:i?0x42:0x43,0x43);
 /* Hardware may consume immediately; do not require a stable HP readback. */
 if(!rc){uint32_t hp=32767*2;rc=access32(d,rings[0].r2,&hp,1);}
 if(!rc)d->active=1;return leave(d,rc);
}
int qcc2072_datapath_poll(struct qcc2072_datapath*d){
 int rc=enter(d);if(rc)return rc;if(!d->active)return leave(d,QCC2072_BAD_STATE);
 if(d->ops.sync(d->ops.context,&d->arena,0,9*64,QCC2072_SYNC_CPU))return leave(d,fail(d,QCC2072_RUNTIME_IO));
 /* Without an attached qcc2072-dp-io owner no data packet exists: detect
  * unexpected completion rather than invent ownership or discard a buffer.
  * With it attached, that module consumes these rings; indices stay checked. */
 for(unsigned i=1;i<9;i++){uint32_t v=get32(d->arena.cpu+i*64);if(v>=rings[i].count*rings[i].dwords||v%rings[i].dwords)return leave(d,fail(d,QCC2072_RUNTIME_RING));if(v&&!d->io_attached)return leave(d,fail(d,QCC2072_RUNTIME_UNSUPPORTED));}
 if(d->rx_prepared){
  if(d->ops.sync(d->ops.context,&d->arena,0x400,6*128,QCC2072_SYNC_CPU))return leave(d,fail(d,QCC2072_RUNTIME_IO));
  for(unsigned i=0;i<6;i++){
   unsigned step=i==3?8:2,entries=i<3?4096:1024;
   uint32_t v=get32(d->arena.cpu+0x400+i*128+(i==3?0:64));
   if(v>=entries*step||v%step)return leave(d,fail(d,QCC2072_RUNTIME_RING));
   /* RXDMA destination completion requires exact descriptor/link ownership. */
   if(i==3&&v)return leave(d,fail(d,QCC2072_RUNTIME_UNSUPPORTED));
  }
 }
 return leave(d,0);
}
int qcc2072_datapath_abort(struct qcc2072_datapath*d,int why){if(!d||!d->initialized||d->in_call)return QCC2072_BAD_STATE;return fail(d,why?why:QCC2072_QUARANTINED);}

/* LMAC pointers are admitted shared DMA words: firmware owns the opposite end.
 * Exact common/PMAC source geometry from hal_wcn7850 override selected by QCC2072.
 * PDEV ids1/2 correspond to MACs0/1; shared host-to-FW refill uses pdev0. */
struct rx_spec {uint32_t offset,count,dwords,type,id,pdev;};
static const struct rx_spec rx_rings[6]={
 {0xdd0000,4096,2,2,5,0},{0xdd8000,4096,2,1,0,1},
 {0xde0000,4096,2,1,0,2},{0xde8000,1024,8,0,7,1},
 {0xdf0000,1024,2,1,1,1},{0xdf2000,1024,2,1,1,2}
};
int qcc2072_datapath_rx_prepare(struct qcc2072_datapath*d){
 int rc=enter(d);if(rc)return rc;
 if(!d->active||d->rx_prepared)return leave(d,QCC2072_BAD_STATE);
 /* No reuse: these slots are posted once until a validated completion path
  * returns their owned descriptor. SPT entries stay immutable this generation. */
 for(unsigned i=0;i<4095;i++){
  uint32_t cookie=131072+i,address=(uint32_t)d->arena.iova+0xe00000+i*2048;
  uint8_t*p=d->arena.cpu+0xdd0000+i*8;put32(p,address);put32(p+4,(6U<<8)|(cookie<<12));
  p=d->arena.cpu+0x120000+cookie*32;put32(p+16,address);put32(p+20,2048);put32(p+24,1);
 }
 for(unsigned mac=0;mac<2;mac++)for(unsigned i=0;i<1023;i++){
  uint8_t*p=d->arena.cpu+0xdf0000+mac*0x2000+i*8;
  put32(p,(uint32_t)d->arena.iova+0x1600000+mac*0x200000+i*2048);put32(p+4,(6U<<8)|(i<<12));
 }
 /* Publish all descriptors/buffers before the shared source head words. */
 if(d->ops.sync(d->ops.context,&d->arena,0,QCC2072_DATAPATH_ARENA_BYTES,QCC2072_SYNC_DEVICE))return leave(d,fail(d,QCC2072_RUNTIME_IO));
 put32(d->arena.cpu+0x400,4095*2);
 put32(d->arena.cpu+0x400+4*128,1023*2);put32(d->arena.cpu+0x400+5*128,1023*2);
 if(d->ops.sync(d->ops.context,&d->arena,0x400,6*128,QCC2072_SYNC_DEVICE))return leave(d,fail(d,QCC2072_RUNTIME_IO));
 d->rx_prepared=1;return leave(d,0);
}
int qcc2072_datapath_htt_command(struct qcc2072_datapath*d,unsigned index,void*out,size_t cap,size_t*length){
 if(!out||!length)return QCC2072_INVALID_ARGUMENT;*length=0;
 int rc=enter(d);if(rc)return rc;
 if(!d->active||!d->rx_prepared||index>=8)return leave(d,QCC2072_BAD_STATE);
 size_t n=index<6?52:68;if(cap<n)return leave(d,QCC2072_TOO_LARGE);
 uint8_t*p=out;zero(p,n);
 if(index<6){
  const struct rx_spec*r=&rx_rings[index];uint32_t hp=(uint32_t)d->arena.iova+0x400+index*128;
  put32(p,11|(r->pdev<<8)|(r->id<<16)|(r->type<<24));put32(p+4,(uint32_t)d->arena.iova+r->offset);
  put32(p+12,r->count*r->dwords|(r->dwords<<16)|(r->type==1?1U<<25:0));
  put32(p+16,hp);put32(p+24,hp+64);
  /* MSI disabled; polled completions. No unsupported response-required bit:
   * pinned upstream submits without requesting SRING_SETUP confirmation. */
 }else{
  /* QCC2072 full descriptor offsets independently compiled from pinned header:
   * size392, packet-header264, MPDU-tag140, MSDU-tag0. */
  put32(p,0x1400000c|((index-5)<<8));put32(p+4,2048);
  put32(p+16,1U<<24);put32(p+20,(1U<<18)|(1U<<21)|(1U<<24));
  put32(p+24,13);put32(p+28,392|(264U<<16));put32(p+32,140U<<16);
 }
 *length=n;return leave(d,0);
}

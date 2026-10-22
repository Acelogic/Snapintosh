/* SPDX-License-Identifier: MIT */
/* Independent bounded QCC2072 CE/SRNG engine. Wire facts pinned in sources.json. */
#include "qcc2072-ce.h"
static uint32_t u32(const uint8_t*p){return (uint32_t)p[0]|(uint32_t)p[1]<<8|(uint32_t)p[2]<<16|(uint32_t)p[3]<<24;}
static void p32(uint8_t*p,uint32_t v){for(unsigned i=0;i<4;i++)p[i]=(uint8_t)(v>>(8*i));}
static void clear(void*v,size_t n){uint8_t*p=v;for(size_t i=0;i<n;i++)p[i]=0;}
static int overlap(uint64_t a,uint64_t n,uint64_t b,uint64_t m){return n&&m&&(a>UINT64_MAX-n||b>UINT64_MAX-m||(a<b+m&&b<a+n));}
static int fail(struct qcc2072_ce*c,int x){c->quarantined=1;c->quarantine_reason=x;return x;}
static int enter(struct qcc2072_ce*c){if(!c||c->in_call)return QCC2072_BAD_STATE;if(c->quarantined)return QCC2072_QUARANTINED;
 if(c->ops.validate_owner(c->ops.context,c->admission->generation,c->admission->owner_cookie))return fail(c,QCC2072_SESSION_STALE);
 uint64_t now=c->ops.now_ms(c->ops.context);if(now<c->last_ms||now>UINT64_MAX-c->timeout_ms)return fail(c,QCC2072_SESSION_STALE);c->last_ms=now;c->in_call=1;return 0;}
static int leave(struct qcc2072_ce*c,int x){c->in_call=0;return x;}
static int syncmem(struct qcc2072_ce*c,size_t o,size_t n,uint32_t d){if(o>c->arena.capacity||n>c->arena.capacity-o||c->ops.sync(c->ops.context,&c->arena,o,n,d))return fail(c,QCC2072_RUNTIME_IO);return 0;}
static int access(struct qcc2072_ce*c,uint32_t target,uint32_t*v,int write){
 uint32_t old,selected,back;if((target&3)||target<0x1b80000||target>=0x1b90000||c->bar_bytes<0x100000)return fail(c,QCC2072_RUNTIME_IO);
 if(c->ops.validate_owner(c->ops.context,c->admission->generation,c->admission->owner_cookie))return fail(c,QCC2072_SESSION_STALE);
 if(c->ops.read32(c->ops.context,0x3278,&old)||old==UINT32_MAX)return fail(c,QCC2072_RUNTIME_IO);
 selected=(old&0xffffffc0U)|0x40000000U|((target>>19)&63);
 if(old!=selected&&(c->ops.write32(c->ops.context,0x3278,selected)||c->ops.read32(c->ops.context,0x3278,&back)||back!=selected))return fail(c,QCC2072_RUNTIME_IO);
 uint32_t off=0x80000+(target&0x7ffff);int x=write?c->ops.write32(c->ops.context,off,*v):c->ops.read32(c->ops.context,off,v);
 return x?fail(c,QCC2072_RUNTIME_IO):0;
}
static int wr(struct qcc2072_ce*c,uint32_t o,uint32_t v){return access(c,o,&v,1);}
static int ring_setup(struct qcc2072_ce*c,struct qcc2072_ce_ring*r){
 uint64_t addr=c->arena.iova+r->offset,wb=c->arena.iova+r->writeback;uint32_t b=r->base;int x;
 /* Explicitly disable stale MSI and ring enable before publishing new geometry. */
 if((x=wr(c,b+0x10,0))||(x=wr(c,b+0x4c,0))||(x=wr(c,b,(uint32_t)addr))||
 (x=wr(c,b+4,(uint32_t)(addr>>32)|(r->entries*r->entry_dwords<<8)))||
 (x=wr(c,b+8,r->entry_dwords|(r->status?r->id<<8:0))))return x;
 if(r->status){if((x=wr(c,b+0x24,0))||(x=wr(c,b+0x14,(uint32_t)wb))||(x=wr(c,b+0x18,(uint32_t)(wb>>32))))return x;}
 else if((x=wr(c,b+0x30,0))||(x=wr(c,b+0x34,0))||(x=wr(c,b+0x1c,(uint32_t)wb))||(x=wr(c,b+0x20,(uint32_t)(wb>>32))))return x;
 if((x=wr(c,r->r2,0))||(x=wr(c,r->r2+4,0))||(x=wr(c,b+0x10,r->status?0x40:0x42)))return x;return 0;
}
int qcc2072_ce_init(struct qcc2072_ce*c,const struct qcc2072_ce_ops*ops,const struct qcc2072_dma_admission*a,const struct qcc2072_dma_buffer*arena,const struct qcc2072_dma_buffer*protected,uint32_t count,uint32_t bar,uint32_t timeout){
 if(!c||!ops||!a||!arena||!protected||!count||count>128||!ops->validate_owner||!ops->read32||!ops->write32||!ops->sync||!ops->now_ms||!ops->receive||bar<0x100000||!timeout||timeout>120000)return QCC2072_INVALID_ARGUMENT;
 int x=qcc2072_dma_buffer_validate(a,arena,QCC2072_CE_ARENA_BYTES,4096);if(x)return x;
 int rw=0;for(uint32_t i=0;i<a->map_count;i++){const struct qcc2072_dma_map*m=&a->maps[i];if((m->permissions&3)==3&&arena->iova>=m->iova&&arena->iova-m->iova<=m->length&&QCC2072_CE_ARENA_BYTES<=m->length-(arena->iova-m->iova))rw=1;}if(!rw)return QCC2072_DMA_INVALID;
 if(overlap((uintptr_t)arena->cpu,QCC2072_CE_ARENA_BYTES,(uintptr_t)c,sizeof(*c)))return QCC2072_DMA_INVALID;
 for(uint32_t i=0;i<count;i++){const struct qcc2072_dma_buffer*b=&protected[i];if((x=qcc2072_dma_buffer_validate(a,b,b->capacity,4)))return x;
  if(overlap((uintptr_t)arena->cpu,QCC2072_CE_ARENA_BYTES,(uintptr_t)b->cpu,b->capacity)||overlap(arena->physical,QCC2072_CE_ARENA_BYTES,b->physical,b->capacity)||overlap(arena->iova,QCC2072_CE_ARENA_BYTES,b->iova,b->capacity))return QCC2072_DMA_INVALID;}
 struct qcc2072_ce_ops o=*ops;struct qcc2072_dma_buffer ar=*arena;clear(c,sizeof(*c));c->ops=o;c->arena=ar;c->admission=a;c->bar_bytes=bar;c->timeout_ms=timeout;
 if((x=enter(c)))return x;
 static const uint32_t spec[7][7]={{0,0,16,4,0,0x20000,64},{1,0x1000,512,2,0,0xb8000,82},{1,0x2000,512,4,1,0,101},{2,0x4000,64,2,0,0x1b8000,83},{2,0x5000,64,4,1,0,102},{3,0x6000,32,4,0,0x28000,67},{4,0x8000,2048,4,0,0x38000,68}};
 for(unsigned i=0;i<7;i++){struct qcc2072_ce_ring*r=&c->rings[i];r->pipe=spec[i][0];r->offset=spec[i][1];r->entries=spec[i][2];r->entry_dwords=spec[i][3];r->status=(uint8_t)spec[i][4];r->data_offset=spec[i][5];r->id=spec[i][6];r->writeback=0x10000+i*64;
  int rx=r->pipe==1||r->pipe==2;r->base=0x1b80000+r->pipe*0x2000+(rx?0x1000:0)+(r->status?0x58:0);r->r2=0x1b80000+r->pipe*0x2000+(rx?0x1000:0)+0x400+(r->status?8:0);}
 clear(c->arena.cpu,QCC2072_CE_ARENA_BYTES);return leave(c,0);
}
static int post_rx(struct qcc2072_ce*c,unsigned which,unsigned slot){
 struct qcc2072_ce_ring*r=&c->rings[which?3:1];unsigned head=r->head,next=(head+1)%r->entries;
 if(r->pending>=r->entries-1)return fail(c,QCC2072_RUNTIME_RING);
 uint64_t addr=c->arena.iova+r->data_offset+slot*2048;uint8_t*p=c->arena.cpu+r->offset+head*8;
 p32(p,(uint32_t)addr);p32(p+4,(uint32_t)(addr>>32));c->rx_slots[which][head]=(uint16_t)slot;
 int x;if((x=syncmem(c,r->data_offset+slot*2048,2048,QCC2072_SYNC_DEVICE))||(x=syncmem(c,r->offset+head*8,8,QCC2072_SYNC_DEVICE)))return x;
 r->head=next;r->pending++;return wr(c,r->r2,next*2);
}
int qcc2072_ce_begin(struct qcc2072_ce*c){int x=enter(c);if(x)return x;if(c->begun)return leave(c,QCC2072_BAD_STATE);
 if((x=syncmem(c,0,QCC2072_CE_ARENA_BYTES,QCC2072_SYNC_DEVICE)))return leave(c,x);
 for(unsigned i=0;i<7;i++)if((x=ring_setup(c,&c->rings[i])))return leave(c,x);
 for(unsigned j=0;j<2;j++){struct qcc2072_ce_ring*r=&c->rings[j?3:1];uint32_t v;
  if((x=access(c,r->base+0xb0,&v,0))||(x=wr(c,r->base+0xb0,(v&0xffff0000U)|2048)))return leave(c,x);
  for(unsigned i=0;i<r->entries-1;i++)if((x=post_rx(c,j,i)))return leave(c,x);}
 c->begun=1;return leave(c,0);
}
static int refresh(struct qcc2072_ce*c,unsigned idx){
 struct qcc2072_ce_ring*r=&c->rings[idx];int x=syncmem(c,r->writeback,4,QCC2072_SYNC_CPU);if(x)return x;
 uint32_t p=u32(c->arena.cpu+r->writeback);if(p>=r->entries*r->entry_dwords||p%r->entry_dwords)return fail(c,QCC2072_RUNTIME_RING);
 p/=r->entry_dwords;if(r->status){r->head=p;return 0;}
 unsigned delta=(p+r->entries-r->tail)%r->entries;if(delta>r->pending)return fail(c,QCC2072_RUNTIME_RING);
 r->tail=p;r->pending-=delta;r->completed+=delta;return 0;
}
int qcc2072_ce_poll(struct qcc2072_ce*c,uint32_t budget){if(!budget||budget>1024)return QCC2072_INVALID_ARGUMENT;int x=enter(c);if(x)return x;if(!c->begun)return leave(c,QCC2072_BAD_STATE);
 for(unsigned i=0;i<7;i++)if((x=refresh(c,i)))return leave(c,x);
 for(unsigned t=0;t<3;t++){struct qcc2072_ce_ring*r=&c->rings[t==0?0:t==1?5:6];if(r->pending&&c->last_ms>=c->tx_deadline[t][r->tail])return leave(c,fail(c,QCC2072_DEADLINE));}
 for(unsigned which=0;which<2;which++){struct qcc2072_ce_ring*d=&c->rings[which?3:1],*r=d+1;
  while(budget&&r->tail!=r->head){
   /* The status producer is the authoritative completion. Re-sample buffer
    * consumer to tolerate independent DMA publication ordering; defer if lagging. */
   if(c->rx_consumed[which]==d->completed){if((x=refresh(c,which?3:1)))return leave(c,x);if(c->rx_consumed[which]==d->completed)break;}
   unsigned index=r->tail,slot=c->rx_slots[which][c->rx_read[which]];size_t off=r->offset+index*16;
   if((x=syncmem(c,off,16,QCC2072_SYNC_CPU)))return leave(c,x);uint32_t flags=u32(c->arena.cpu+off),n=flags>>16;
   if(!n||n>2048||(flags&(1U<<11)))return leave(c,fail(c,QCC2072_BAD_WIRE));
   size_t data=d->data_offset+slot*2048;if((x=syncmem(c,data,n,QCC2072_SYNC_CPU)))return leave(c,x);
   if(c->ops.receive(c->ops.context,d->pipe,c->arena.cpu+data,n))return leave(c,fail(c,QCC2072_PEER_FAILED));
   p32(c->arena.cpu+off,flags&0xffff);if((x=syncmem(c,off,16,QCC2072_SYNC_DEVICE)))return leave(c,x);
   r->tail=(index+1)%r->entries;c->rx_read[which]=(c->rx_read[which]+1)%d->entries;c->rx_consumed[which]++;budget--;
   if((x=wr(c,r->r2+4,r->tail*4))||(x=post_rx(c,which,slot)))return leave(c,x);
  }
 }
 return leave(c,0);
}
int qcc2072_ce_send(struct qcc2072_ce*c,uint32_t pipe,const void*bytes,size_t n){
 if(!bytes||!n||(pipe!=0&&pipe!=3&&pipe!=4)||n>(pipe==4?256U:2048U))return QCC2072_INVALID_ARGUMENT;
 int x=enter(c);if(x)return x;if(!c->begun)return leave(c,QCC2072_BAD_STATE);
 if(overlap((uintptr_t)bytes,n,(uintptr_t)c->arena.cpu,QCC2072_CE_ARENA_BYTES))return leave(c,QCC2072_INVALID_ARGUMENT);
 unsigned idx=pipe==0?0:pipe==3?5:6,t=pipe==0?0:pipe==3?1:2;struct qcc2072_ce_ring*r=&c->rings[idx];if((x=refresh(c,idx)))return leave(c,x);
 if(r->pending>=r->entries-1)return leave(c,QCC2072_RUNTIME_FULL);
 unsigned head=r->head;size_t data=r->data_offset+head*(pipe==4?256U:2048U),desc=r->offset+head*16;uint64_t addr=c->arena.iova+data;
 for(size_t i=0;i<n;i++)c->arena.cpu[data+i]=((const uint8_t*)bytes)[i];p32(c->arena.cpu+desc,(uint32_t)addr);p32(c->arena.cpu+desc+4,(uint32_t)(addr>>32)|((uint32_t)n<<16));p32(c->arena.cpu+desc+8,head);p32(c->arena.cpu+desc+12,0);
 if((x=syncmem(c,data,n,QCC2072_SYNC_DEVICE))||(x=syncmem(c,desc,16,QCC2072_SYNC_DEVICE)))return leave(c,x);
 c->tx_deadline[t][head]=c->last_ms+c->timeout_ms;r->head=(head+1)%r->entries;r->pending++;
 if((x=wr(c,r->r2,r->head*4)))return leave(c,x);return leave(c,0);
}
int qcc2072_ce_abort(struct qcc2072_ce*c,int why){if(!c||c->in_call)return QCC2072_BAD_STATE;return fail(c,why?why:QCC2072_QUARANTINED);}

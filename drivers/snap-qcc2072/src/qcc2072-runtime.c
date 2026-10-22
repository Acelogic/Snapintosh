/* SPDX-License-Identifier: MIT */
/* Independent bounded MHI host implementation from the pinned wire contracts.
 * Reference facts and copyright boundaries: re/backend/RUNTIME-FAILURES-AND-REPLAY.md.
 * No Linux helper bodies are incorporated. Provider callbacks perform all I/O. */
#include "qcc2072-runtime.h"
#define CHCTX 0x0000U
#define EVCTX 0x2000U
#define CMDCTX 0x3000U
#define CMDRING 0x4000U
#define EV0RING 0x5000U
#define EV1RING 0x6000U
#define TXRING 0x7000U
#define RXRING 0x8000U
#define RXDATA 0x10000U
#define TXDATA 0x90000U
#define CTXSZ 44U
#define CH_TX 20U
#define CH_RX 21U
static uint32_t rd32(const uint8_t *p) { return (uint32_t)p[0]|(uint32_t)p[1]<<8|(uint32_t)p[2]<<16|(uint32_t)p[3]<<24; }
static uint64_t rd64(const uint8_t *p) { return rd32(p)|(uint64_t)rd32(p+4)<<32; }
static void wr32(uint8_t *p,uint32_t x) { for(unsigned i=0;i<4;i++)p[i]=(uint8_t)(x>>(8*i)); }
static void wr64(uint8_t *p,uint64_t x) { for(unsigned i=0;i<8;i++)p[i]=(uint8_t)(x>>(8*i)); }
static void zero(void *p,size_t n) { uint8_t *b=p;for(size_t i=0;i<n;i++)b[i]=0; }
static int overlap(uint64_t a,uint64_t n,uint64_t b,uint64_t m) { return n&&m&&a<b+m&&b<a+n; }
static uint8_t *mem(struct qcc2072_runtime *r,uint32_t off) { return r->boot.arena.cpu+off; }
static uint64_t addr(struct qcc2072_runtime *r,uint32_t off) { return r->boot.arena.iova+off; }
static int fail(struct qcc2072_runtime *r,int why) {
    r->quarantine_reason=why;r->state=QCC2072_RUNTIME_QUARANTINE;
    if(r->ops.state_changed)r->ops.state_changed(r->ops.context,r->state,why);
    return why;
}
static void state(struct qcc2072_runtime *r,enum qcc2072_runtime_state s) {
    r->state=s;if(r->ops.state_changed)r->ops.state_changed(r->ops.context,s,0);
}
static int readreg(struct qcc2072_runtime *r,uint32_t off,uint32_t *v) {
    if((off&3)||off>r->boot.bar_bytes-4)return fail(r,QCC2072_BAD_REGISTER);
    if(r->ops.read32(r->ops.context,off,v))return fail(r,QCC2072_RUNTIME_IO);
    if(*v==0xffffffffU||*v==0xdeadbeefU)return fail(r,QCC2072_BAD_REGISTER);
    return 0;
}
static int writereg(struct qcc2072_runtime *r,uint32_t off,uint32_t v) {
    if((off&3)||off>r->boot.bar_bytes-4)return fail(r,QCC2072_BAD_REGISTER);
    if(r->ops.write32(r->ops.context,off,v))return fail(r,QCC2072_RUNTIME_IO);
    return 0;
}
static int write64(struct qcc2072_runtime *r,uint32_t off,uint64_t v) {
    int x=writereg(r,off+4,(uint32_t)(v>>32));return x?x:writereg(r,off,(uint32_t)v);
}
static int syncbuf(struct qcc2072_runtime *r,const struct qcc2072_dma_buffer *b,size_t off,size_t n,uint32_t direction) {
    if(off>b->capacity||n>b->capacity-off)return fail(r,QCC2072_DMA_INVALID);
    if(r->ops.sync(r->ops.context,b,off,n,direction))return fail(r,QCC2072_RUNTIME_IO);
    return 0;
}
static int syncarena(struct qcc2072_runtime *r,size_t off,size_t n,uint32_t direction) { return syncbuf(r,&r->boot.arena,off,n,direction); }
static int enter(struct qcc2072_runtime *r) {
    uint64_t now;
    if(!r||r->in_call)return QCC2072_BAD_STATE;
    if(r->state==QCC2072_RUNTIME_QUARANTINE)return QCC2072_QUARANTINED;
    r->in_call=1;
    if(r->ops.validate_owner(r->ops.context,r->generation,r->owner_cookie)){r->in_call=0;return fail(r,QCC2072_SESSION_STALE);}
    now=r->ops.now_ms(r->ops.context);
    if(now<r->last_ms||(r->deadline_ms&&now>=r->deadline_ms)){r->in_call=0;return fail(r,QCC2072_DEADLINE);}
    r->last_ms=now;return 0;
}
static int leave(struct qcc2072_runtime *r,int result) { r->in_call=0;return result; }
static int writable(const struct qcc2072_dma_admission *a,const struct qcc2072_dma_buffer *b,size_t n) {
    for(uint32_t i=0;i<a->map_count;i++) {
        const struct qcc2072_dma_map *m=&a->maps[i];
        if(b->iova>=m->iova&&b->iova-m->iova<=m->length&&n<=m->length-(b->iova-m->iova)&&
           (m->permissions&(QCC2072_DMA_READ|QCC2072_DMA_WRITE))==(QCC2072_DMA_READ|QCC2072_DMA_WRITE))return 1;
    }return 0;
}
static int disjoint(const struct qcc2072_dma_buffer *a,size_t an,const struct qcc2072_dma_buffer *b,size_t bn) {
    return !overlap((uintptr_t)a->cpu,an,(uintptr_t)b->cpu,bn)&&!overlap(a->iova,an,b->iova,bn)&&!overlap(a->physical,an,b->physical,bn);
}
static void context(struct qcc2072_runtime *r,uint32_t c,uint32_t ring,uint32_t n) {
    wr64(mem(r,c+12),addr(r,ring));wr64(mem(r,c+20),n*16U);
    wr64(mem(r,c+28),addr(r,ring));wr64(mem(r,c+36),addr(r,ring));
}
int qcc2072_runtime_init(struct qcc2072_runtime *r,const struct qcc2072_runtime_ops *ops,
                         const struct qcc2072_dma_admission *a,const struct qcc2072_runtime_boot *b) {
    int x;size_t total=0;
    if(!r||!ops||!a||!b||!ops->validate_owner||!ops->enable_dma||!ops->read32||!ops->write32||!ops->sync||!ops->now_ms||!ops->receive)return QCC2072_INVALID_ARGUMENT;
    if(b->bar_bytes<0x1000||b->bar_bytes>0x100000||b->timeout_ms<100||b->timeout_ms>120000||!b->sequence||b->sequence>0x3fffffffU||
       !b->segment_count||b->segment_count>QCC2072_MHI_MAX_SEGMENTS||!b->segments||b->image.vector_count!=b->segment_count||
       b->image.vector_bytes!=b->segment_count*16U||b->image.bhi_bytes!=QCC2072_MHI_CHUNK||
       b->image.bhi_iova!=b->sbl.iova||b->image.bhie_vectors_iova!=b->vectors.iova||b->event_msi[0]>255||b->event_msi[1]>255)return QCC2072_INVALID_ARGUMENT;
    if((x=qcc2072_dma_validate(a,a->generation,a->owner_cookie)))return x;
    if((x=qcc2072_dma_buffer_validate(a,&b->arena,QCC2072_RUNTIME_ARENA_BYTES,4096)))return x;
    if(!writable(a,&b->arena,QCC2072_RUNTIME_ARENA_BYTES))return QCC2072_DMA_INVALID;
    if((x=qcc2072_dma_buffer_validate(a,&b->sbl,b->image.bhi_bytes,4))||
       (x=qcc2072_dma_buffer_validate(a,&b->vectors,b->image.vector_bytes,16)))return x;
    if(!disjoint(&b->arena,QCC2072_RUNTIME_ARENA_BYTES,&b->sbl,b->image.bhi_bytes)||
       !disjoint(&b->arena,QCC2072_RUNTIME_ARENA_BYTES,&b->vectors,b->image.vector_bytes)||
       !disjoint(&b->sbl,b->image.bhi_bytes,&b->vectors,b->image.vector_bytes))return QCC2072_DMA_INVALID;
    if(overlap((uintptr_t)r,sizeof(*r),(uintptr_t)b->arena.cpu,QCC2072_RUNTIME_ARENA_BYTES)||
       overlap((uintptr_t)ops,sizeof(*ops),(uintptr_t)b->arena.cpu,QCC2072_RUNTIME_ARENA_BYTES)||
       overlap((uintptr_t)b,sizeof(*b),(uintptr_t)b->arena.cpu,QCC2072_RUNTIME_ARENA_BYTES)||
       overlap((uintptr_t)a,sizeof(*a),(uintptr_t)b->arena.cpu,QCC2072_RUNTIME_ARENA_BYTES)||
       overlap((uintptr_t)a->maps,a->map_count*sizeof(*a->maps),(uintptr_t)b->arena.cpu,QCC2072_RUNTIME_ARENA_BYTES)||
       overlap((uintptr_t)b->segments,b->segment_count*sizeof(*b->segments),(uintptr_t)b->arena.cpu,QCC2072_RUNTIME_ARENA_BYTES))return QCC2072_DMA_INVALID;
    for(uint32_t i=0;i<b->segment_count;i++) {
        uint64_t n=rd64(b->vectors.cpu+i*16+8);
        if(rd64(b->vectors.cpu+i*16)!=b->segments[i].iova||!n||n>QCC2072_MHI_CHUNK||
           (i+1<b->segment_count&&n!=QCC2072_MHI_CHUNK))return QCC2072_BAD_WIRE;
        if((x=qcc2072_dma_buffer_validate(a,&b->segments[i],(size_t)n,4)))return x;
        if(!disjoint(&b->arena,QCC2072_RUNTIME_ARENA_BYTES,&b->segments[i],(size_t)n)||
           !disjoint(&b->vectors,b->image.vector_bytes,&b->segments[i],(size_t)n)||
           !disjoint(&b->sbl,b->image.bhi_bytes,&b->segments[i],(size_t)n))return QCC2072_DMA_INVALID;
        for(uint32_t j=0;j<i;j++)if(!disjoint(&b->segments[i],(size_t)n,&b->segments[j],(size_t)rd64(b->vectors.cpu+j*16+8)))return QCC2072_DMA_INVALID;
        total+=(size_t)n;
    }
    if(total!=b->image.bhie_bytes)return QCC2072_BAD_WIRE;
    zero(r,sizeof(*r));r->ops=*ops;r->admission=a;r->boot=*b;
    /* MHI remains confined to direct BAR space even when CE aperture is mapped. */
    if(r->boot.bar_bytes>0x80000)r->boot.bar_bytes=0x80000;
    r->generation=a->generation;r->owner_cookie=a->owner_cookie;
    r->last_ms=ops->now_ms(ops->context);r->state=QCC2072_RUNTIME_PREPARED;
    zero(b->arena.cpu,QCC2072_RUNTIME_ARENA_BYTES);
    context(r,CMDCTX,CMDRING,128);context(r,EVCTX,EV0RING,32);context(r,EVCTX+CTXSZ,EV1RING,256);
    for(unsigned e=0;e<2;e++) {
        uint32_t c=EVCTX+e*CTXSZ;wr32(mem(r,c),e?1U<<16:0);wr32(mem(r,c+4),1);wr32(mem(r,c+8),b->event_msi[e]);
        r->event_write[e]=e?255:31;wr64(mem(r,c+36),addr(r,(e?EV1RING:EV0RING)+r->event_write[e]*16));
    }
    for(unsigned c=CH_TX;c<=CH_RX;c++) {
        uint32_t off=CHCTX+c*CTXSZ;wr32(mem(r,off),1U|(2U<<8));wr32(mem(r,off+4),c==CH_TX?1:2);wr32(mem(r,off+8),1);
        context(r,off,c==CH_TX?TXRING:RXRING,64);
    }return 0;
}
static int block_offset(struct qcc2072_runtime *r,uint32_t off,uint32_t bytes) {
    return off>=0x100&&!(off&3)&&off<=r->boot.bar_bytes-bytes;
}
int qcc2072_runtime_begin(struct qcc2072_runtime *r) {
    int x=enter(r);uint32_t st,ctl;
    if(x)return x;
    if(r->state!=QCC2072_RUNTIME_PREPARED)return leave(r,QCC2072_BAD_STATE);
    if((x=readreg(r,0x28,&r->bhi))||(x=readreg(r,0x2c,&r->bhie)))return leave(r,x);
    if(!block_offset(r,r->bhi,0x48)||!block_offset(r,r->bhie,0x7c)||overlap(r->bhi,0x48,r->bhie,0x7c))return leave(r,fail(r,QCC2072_BAD_REGISTER));
    if((x=readreg(r,r->bhi+0x28,&r->ee))||(x=readreg(r,0x38,&ctl))||(x=readreg(r,0x48,&st)))return leave(r,x);
    if((r->ee!=0&&r->ee!=6)||(ctl&2)||(st&4))return leave(r,fail(r,QCC2072_DEVICE_NOT_QUIESCENT));
    if((x=syncarena(r,0,QCC2072_RUNTIME_ARENA_BYTES,QCC2072_SYNC_DEVICE))||
       (x=syncbuf(r,&r->boot.sbl,0,r->boot.image.bhi_bytes,QCC2072_SYNC_DEVICE)))return leave(r,x);
    for(uint32_t i=0;i<r->boot.segment_count;i++)if((x=syncbuf(r,&r->boot.segments[i],0,(size_t)rd64(r->boot.vectors.cpu+i*16+8),QCC2072_SYNC_DEVICE)))return leave(r,x);
    if((x=syncbuf(r,&r->boot.vectors,0,r->boot.image.vector_bytes,QCC2072_SYNC_DEVICE)))return leave(r,x);
    if(r->ops.enable_dma(r->ops.context,r->generation,r->owner_cookie))return leave(r,fail(r,QCC2072_RUNTIME_IO));
    r->active=1;r->deadline_ms=r->last_ms+r->boot.timeout_ms;
    if(r->deadline_ms<r->last_ms)return leave(r,fail(r,QCC2072_DEADLINE));
    if((x=writereg(r,r->bhi+0x2c,0))||(x=write64(r,r->bhi+8,r->boot.image.bhi_iova))||
       (x=writereg(r,r->bhi+0x10,r->boot.image.bhi_bytes))||(x=writereg(r,r->bhi+0x18,r->boot.sequence)))return leave(r,x);
    state(r,QCC2072_RUNTIME_BOOTING);return leave(r,0);
}
static int publish_contexts(struct qcc2072_runtime *r,uint32_t ctl) {
    int x;uint32_t cfg;uint64_t lo=0xffffffffU,hi=0;
    if((x=readreg(r,0,&r->reglen))||(x=readreg(r,0x18,&r->chdb))||(x=readreg(r,0x20,&r->erdb))||(x=readreg(r,0x10,&cfg)))return x;
    if(r->reglen>r->boot.bar_bytes||r->reglen<0xa8||!block_offset(r,r->chdb,128*8)||!block_offset(r,r->erdb,2*8)||
       overlap(r->chdb,128*8,r->erdb,16)||
       overlap(r->chdb,128*8,r->bhi,0x48)||overlap(r->chdb,128*8,r->bhie,0x7c)||
       overlap(r->erdb,16,r->bhi,0x48)||overlap(r->erdb,16,r->bhie,0x7c))return fail(r,QCC2072_BAD_REGISTER);
    for(uint32_t i=0;i<r->admission->map_count;i++) {
        const struct qcc2072_dma_map *m=&r->admission->maps[i];
        if(m->iova<lo)lo=m->iova;if(m->iova+m->length-1>hi)hi=m->iova+m->length-1;
    }
    if((x=write64(r,0x58,addr(r,CHCTX)))||(x=write64(r,0x60,addr(r,EVCTX)))||(x=write64(r,0x68,addr(r,CMDCTX)))||
       (x=write64(r,0x80,lo))||(x=write64(r,0x98,lo))||(x=write64(r,0x88,hi))||(x=write64(r,0xa0,hi))||
       (x=writereg(r,0x10,(cfg&0xffffU)|(2U<<16)))||
       (x=write64(r,r->erdb,addr(r,EV0RING+31*16)))||(x=write64(r,r->erdb+8,addr(r,EV1RING+255*16)))||
       (x=writereg(r,0x38,(ctl&~0xff00U)|(2U<<8))))return x;
    r->context_published=1;return 0;
}
static int start_channel(struct qcc2072_runtime *r,uint32_t ch) {
    uint32_t off=CMDRING+r->cmd_write*16U;int x;
    if(r->cmd_read!=r->cmd_write)return fail(r,QCC2072_RUNTIME_RING);
    wr64(mem(r,off),0);wr32(mem(r,off+8),0);wr32(mem(r,off+12),(ch<<24)|(18U<<16));
    r->cmd_channel=ch;r->cmd_write=(r->cmd_write+1)%128;
    wr64(mem(r,CMDCTX+36),addr(r,CMDRING+r->cmd_write*16));
    if((x=syncarena(r,off,16,QCC2072_SYNC_DEVICE))||(x=syncarena(r,CMDCTX+36,8,QCC2072_SYNC_DEVICE))||
       (x=write64(r,0x70,addr(r,CMDRING+r->cmd_write*16))))return x;
    state(r,ch==CH_TX?QCC2072_RUNTIME_START_TX:QCC2072_RUNTIME_START_RX);return 0;
}
static int post_rx(struct qcc2072_runtime *r,uint32_t slot) {
    uint32_t i=r->rx_write,off=RXRING+i*16;int x;
    if((i+1)%64==r->rx_read||slot>=64)return fail(r,QCC2072_RUNTIME_RING);
    if((x=syncarena(r,RXDATA+slot*8192,8192,QCC2072_SYNC_DEVICE)))return x;
    wr64(mem(r,off),addr(r,RXDATA+slot*8192));wr32(mem(r,off+8),8192);wr32(mem(r,off+12),(2U<<16)|(1U<<9));
    r->rx_buffer_slot[i]=(uint8_t)slot;r->rx_write=(i+1)%64;
    wr64(mem(r,CHCTX+CH_RX*CTXSZ+36),addr(r,RXRING+r->rx_write*16));
    if((x=syncarena(r,off,16,QCC2072_SYNC_DEVICE))||(x=syncarena(r,CHCTX+CH_RX*CTXSZ+36,8,QCC2072_SYNC_DEVICE)))return x;
    return 0;
}
static int handle_event(struct qcc2072_runtime *r,uint32_t e,const uint8_t *p) {
    uint64_t ptr=rd64(p);uint32_t d0=rd32(p+8),d1=rd32(p+12),type=(d1>>16)&255,code=d0>>24,ch=d1>>24,len=d0&65535;int x;
    if(type==0x20&&e==0) {
        if(code==8)return fail(r,QCC2072_PEER_FAILED);
        if(code!=2&&code!=3&&code!=4)return fail(r,QCC2072_RUNTIME_UNSUPPORTED);
        r->mhi_state=code;
        /* Hold wake asserted while this bounded bootstrap/IPCR engine is active. */
        if(code!=2)return writereg(r,0x38,2U<<8);
        return 0;
    }
    if(type==0x40&&e==0) {
        if(code==3)return fail(r,QCC2072_PEER_FAILED);
        if(code!=1&&code!=2&&code!=4)return fail(r,QCC2072_RUNTIME_UNSUPPORTED);
        r->ee=code;return 0;
    }
    if(type==0x21&&e==0) {
        if(r->cmd_read==r->cmd_write||ptr!=addr(r,CMDRING+r->cmd_read*16)||code!=1)return fail(r,QCC2072_RUNTIME_RING);
        r->cmd_read=(r->cmd_read+1)%128;
        if(r->cmd_channel==CH_TX&&r->state==QCC2072_RUNTIME_START_TX){r->tx_started=1;return start_channel(r,CH_RX);}
        if(r->cmd_channel!=CH_RX||r->state!=QCC2072_RUNTIME_START_RX)return fail(r,QCC2072_RUNTIME_RING);
        r->rx_started=1;
        for(unsigned i=0;i<63;i++)if((x=post_rx(r,i)))return x;
        if((x=write64(r,r->chdb+CH_RX*8,addr(r,RXRING+r->rx_write*16))))return x;
        r->deadline_ms=0;state(r,QCC2072_RUNTIME_IPCR);return 0;
    }
    if(type!=0x22||e!=1||(ch!=CH_TX&&ch!=CH_RX)||r->state!=QCC2072_RUNTIME_IPCR)return fail(r,QCC2072_RUNTIME_UNSUPPORTED);
    if(code==5||code==6)return write64(r,r->chdb+ch*8,addr(r,(ch==CH_TX?TXRING+r->tx_write*16:RXRING+r->rx_write*16)));
    if(code!=2)return fail(r,QCC2072_RUNTIME_RING);
    if(ch==CH_TX) {
        if(r->tx_read==r->tx_write||ptr!=addr(r,TXRING+r->tx_read*16)||len>r->tx_length[r->tx_read])return fail(r,QCC2072_RUNTIME_RING);
        r->tx_length[r->tx_read]=0;r->tx_deadline[r->tx_read]=0;r->tx_read=(r->tx_read+1)%64;return 0;
    }
    if(r->rx_read==r->rx_write||ptr!=addr(r,RXRING+r->rx_read*16)||!len||len>8192)return fail(r,QCC2072_RUNTIME_RING);
    uint32_t slot=r->rx_buffer_slot[r->rx_read];
    if((x=syncarena(r,RXDATA+slot*8192,len,QCC2072_SYNC_CPU)))return x;
    if(r->ops.receive(r->ops.context,mem(r,RXDATA+slot*8192),len))return fail(r,QCC2072_BAD_WIRE);
    r->rx_read=(r->rx_read+1)%64;
    if((x=post_rx(r,slot)))return x;
    return write64(r,r->chdb+CH_RX*8,addr(r,RXRING+r->rx_write*16));
}
static int events(struct qcc2072_runtime *r,uint32_t *budget) {
    int x;
    for(unsigned e=0;e<2;e++) {
        uint32_t count=e?256:32,base=e?EV1RING:EV0RING,c=EVCTX+e*CTXSZ;uint64_t rp;
        if((x=syncarena(r,c+28,8,QCC2072_SYNC_CPU)))return x;
        rp=rd64(mem(r,c+28));
        if(rp<addr(r,base)||rp>=addr(r,base+count*16)||(rp-addr(r,base))%16)return fail(r,QCC2072_RUNTIME_RING);
        uint32_t end=(uint32_t)((rp-addr(r,base))/16),processed=0;
        while(r->event_read[e]!=end&&*budget) {
            uint32_t off=base+r->event_read[e]*16;
            if((x=syncarena(r,off,16,QCC2072_SYNC_CPU)))return x;
            if((x=handle_event(r,e,mem(r,off))))return x;
            r->event_read[e]=(r->event_read[e]+1)%count;r->event_write[e]=(r->event_write[e]+1)%count;
            (*budget)--;processed++;
        }
        if(processed) {
            wr64(mem(r,c+36),addr(r,base+r->event_write[e]*16));
            if((x=syncarena(r,c+36,8,QCC2072_SYNC_DEVICE))||(x=write64(r,r->erdb+e*8,addr(r,base+r->event_write[e]*16))))return x;
        }
    }return 0;
}
int qcc2072_runtime_poll(struct qcc2072_runtime *r,uint32_t budget) {
    int x;uint32_t st,ctl,bstatus=0,bestatus=0;
    if(!budget||budget>1024)return QCC2072_INVALID_ARGUMENT;
    if((x=enter(r)))return x;
    if(!r->active)return leave(r,QCC2072_BAD_STATE);
    if((x=readreg(r,0x48,&st))||(x=readreg(r,0x38,&ctl))||(x=readreg(r,r->bhi+0x28,&r->ee)))return leave(r,x);
    r->mhi_state=(st>>8)&255;
    if((st&4)||(ctl&2)||r->ee==3||r->mhi_state==8)return leave(r,fail(r,QCC2072_PEER_FAILED));
    if(r->ee>6)return leave(r,fail(r,QCC2072_RUNTIME_UNSUPPORTED));
    if(!r->bhi_done) {
        if((x=readreg(r,r->bhi+0x2c,&bstatus)))return leave(r,x);
        if((bstatus>>30)==3)return leave(r,fail(r,QCC2072_PEER_FAILED));
        if((bstatus>>30)==2||r->ee==1||r->ee==2||r->ee==4)r->bhi_done=1;
    }
    if(!r->context_published&&(st&1))if((x=publish_contexts(r,ctl)))return leave(r,x);
    if(r->bhi_done&&!r->bhie_sent&&(r->ee==1)) {
        if((x=write64(r,r->bhie+0x2c,r->boot.image.bhie_vectors_iova))||
           (x=writereg(r,r->bhie+0x34,r->boot.image.vector_bytes))||
           (x=writereg(r,r->bhie+0x3c,r->boot.sequence)))return leave(r,x);
        r->bhie_sent=1;
    }
    if(r->bhie_sent&&!r->bhie_done) {
        if((x=readreg(r,r->bhie+0x44,&bestatus)))return leave(r,x);
        if((bestatus>>30)==3)return leave(r,fail(r,QCC2072_PEER_FAILED));
        if((bestatus>>30)==2)r->bhie_done=1;
    }
    if(r->context_published)if((x=events(r,&budget)))return leave(r,x);
    if(r->context_published&&r->bhi_done&&r->bhie_done&&r->ee==2&&r->mhi_state==2&&r->state==QCC2072_RUNTIME_BOOTING) {
        if((x=write64(r,r->chdb+127*8,1))||(x=start_channel(r,CH_TX)))return leave(r,x);
    }
    if(r->state==QCC2072_RUNTIME_IPCR&&r->mhi_state!=2) {
        if(r->mhi_state!=3&&r->mhi_state!=4)return leave(r,fail(r,QCC2072_RUNTIME_UNSUPPORTED));
        if((x=write64(r,r->chdb+127*8,1))||(x=writereg(r,0x38,(ctl&~0xff00U)|(2U<<8))))return leave(r,x);
    }
    if(r->tx_read!=r->tx_write&&r->last_ms>=r->tx_deadline[r->tx_read])return leave(r,fail(r,QCC2072_DEADLINE));
    return leave(r,0);
}
int qcc2072_runtime_send(struct qcc2072_runtime *r,const void *bytes,size_t n) {
    int x;if(!bytes||!n||n>8192)return QCC2072_INVALID_ARGUMENT;
    if((x=enter(r)))return x;
    if(r->state!=QCC2072_RUNTIME_IPCR||r->mhi_state!=2)return leave(r,QCC2072_BAD_STATE);
    uint32_t i=r->tx_write,off=TXRING+i*16,buf=TXDATA+i*8192;
    if((i+1)%64==r->tx_read)return leave(r,QCC2072_RUNTIME_FULL);
    if(overlap((uintptr_t)bytes,n,(uintptr_t)r,sizeof(*r))||overlap((uintptr_t)bytes,n,(uintptr_t)r->boot.arena.cpu,QCC2072_RUNTIME_ARENA_BYTES))return leave(r,QCC2072_DMA_INVALID);
    const uint8_t *src=bytes;for(size_t j=0;j<n;j++)mem(r,buf)[j]=src[j];
    wr64(mem(r,off),addr(r,buf));wr32(mem(r,off+8),(uint32_t)n);wr32(mem(r,off+12),(2U<<16)|(1U<<9));
    r->tx_length[i]=(uint32_t)n;r->tx_deadline[i]=r->last_ms+r->boot.timeout_ms;
    if(r->tx_deadline[i]<r->last_ms)return leave(r,fail(r,QCC2072_DEADLINE));
    r->tx_write=(i+1)%64;wr64(mem(r,CHCTX+CH_TX*CTXSZ+36),addr(r,TXRING+r->tx_write*16));
    if((x=syncarena(r,buf,n,QCC2072_SYNC_DEVICE))||(x=syncarena(r,off,16,QCC2072_SYNC_DEVICE))||
       (x=syncarena(r,CHCTX+CH_TX*CTXSZ+36,8,QCC2072_SYNC_DEVICE))||
       (x=write64(r,r->chdb+CH_TX*8,addr(r,TXRING+r->tx_write*16))))return leave(r,x);
    return leave(r,0);
}
int qcc2072_runtime_abort(struct qcc2072_runtime *r,int reason) {
    if(!r||r->in_call)return QCC2072_BAD_STATE;
    if(r->state==QCC2072_RUNTIME_QUARANTINE)return QCC2072_QUARANTINED;
    r->in_call=1;int x=fail(r,reason?reason:QCC2072_QUARANTINED);return leave(r,x);
}

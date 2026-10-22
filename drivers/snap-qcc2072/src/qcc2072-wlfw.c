/* SPDX-License-Identifier: MIT */
/* Bounded WLFW bring-up, distinct from HTC/WMI and native Wi-Fi readiness. */
#include "qcc2072-wlfw.h"
static uint16_t u16(const uint8_t*p){return (uint16_t)(p[0]|(uint16_t)p[1]<<8);}
static uint32_t u32(const uint8_t*p){return u16(p)|(uint32_t)u16(p+2)<<16;}
static void p16(uint8_t*p,uint16_t v){p[0]=(uint8_t)v;p[1]=(uint8_t)(v>>8);}
static void p32(uint8_t*p,uint32_t v){for(unsigned i=0;i<4;i++)p[i]=(uint8_t)(v>>(8*i));}
static void p64(uint8_t*p,uint64_t v){for(unsigned i=0;i<8;i++)p[i]=(uint8_t)(v>>(8*i));}
static void clear(void*v,size_t n){uint8_t*p=v;for(size_t i=0;i<n;i++)p[i]=0;}
static int same(const uint8_t*a,const uint8_t*b,size_t n){for(size_t i=0;i<n;i++)if(a[i]!=b[i])return 0;return 1;}
static int overlap(uint64_t a,uint64_t n,uint64_t b,uint64_t m){return n&&m&&a<b+m&&b<a+n;}
static int disjoint(const struct qcc2072_dma_buffer*a,size_t an,const struct qcc2072_dma_buffer*b,size_t bn){return
 !overlap((uintptr_t)a->cpu,an,(uintptr_t)b->cpu,bn)&&!overlap(a->iova,an,b->iova,bn)&&!overlap(a->physical,an,b->physical,bn);}
static int fail(struct qcc2072_wlfw*s,int why){s->state=QCC2072_WLFW_QUARANTINE;s->quarantine_reason=why;return why;}
static int enter(struct qcc2072_wlfw*s,uint64_t now){
 if(!s||s->in_call)return QCC2072_BAD_STATE;
 if(s->state==QCC2072_WLFW_QUARANTINE)return QCC2072_QUARANTINED;
 if(now<s->last_ms||now>UINT64_MAX-s->config.timeout_ms)return fail(s,QCC2072_SESSION_STALE);
 if(s->state!=QCC2072_WLFW_FW_READY&&s->state!=QCC2072_WLFW_WLAN_ENABLED&&now>=s->deadline_ms)return fail(s,QCC2072_DEADLINE);
 s->in_call=1;if(s->ops.validate_owner(s->ops.context,s->generation,s->owner_cookie)){s->in_call=0;return fail(s,QCC2072_SESSION_STALE);}s->last_ms=now;return 0;
}
static int leave(struct qcc2072_wlfw*s,int x){s->in_call=0;return x;}
static size_t scalar(uint8_t*p,uint8_t tag,uint64_t v,unsigned width){p[0]=tag;p16(p+1,(uint16_t)width);for(unsigned i=0;i<width;i++)p[3+i]=(uint8_t)(v>>(i*8));return 3+width;}
static int request(struct qcc2072_wlfw*s,uint8_t*p,size_t n,uint16_t id,enum qcc2072_wlfw_state next,size_t*written){
 if(!s->transaction||n<7||n>8192)return fail(s,QCC2072_STALE_TRANSACTION);
 p[0]=0;p16(p+1,s->transaction);p16(p+3,id);p16(p+5,(uint16_t)(n-7));
 s->pending_transaction=s->transaction++;s->pending_message=id;s->deadline_ms=s->last_ms+s->config.timeout_ms;s->state=next;*written=n;return 0;
}
static int rwbuf(const struct qcc2072_dma_admission*a,const struct qcc2072_dma_buffer*b,size_t n){
 int x=qcc2072_dma_buffer_validate(a,b,n,4096);if(x)return x;
 for(uint32_t i=0;i<a->map_count;i++){const struct qcc2072_dma_map*m=&a->maps[i];if((m->permissions&3)==3&&b->iova>=m->iova&&b->iova-m->iova<=m->length&&n<=m->length-(b->iova-m->iova))return 0;}
 return QCC2072_DMA_INVALID;
}
int qcc2072_wlfw_init(struct qcc2072_wlfw*s,const struct qcc2072_wlfw_ops*ops,const struct qcc2072_wlfw_config*c,uint32_t node,uint32_t port,uint64_t now){
 int x;if(!s||!ops||!c||!c->admission||!ops->allocate||!ops->sync||!ops->validate_owner||node>=0xfffffffeU||!port||port>=0xfffffffeU||
 !c->board.bytes||!c->regdb.bytes||!c->m3_image.bytes||!c->aux_image.bytes||!c->board.length||!c->regdb.length||!c->m3_image.length||!c->aux_image.length||
 c->board.length>QCC2072_MAX_BOARD_BYTES||c->regdb.length>QCC2072_MAX_BOARD_BYTES||c->m3_image.length>0x100000||c->aux_image.length>0x100000||
 !c->memory_budget_bytes||c->memory_budget_bytes>128U*1024*1024||!c->timeout_ms||c->timeout_ms>120000||now>UINT64_MAX-c->timeout_ms||c->supports_global_reset>1||
 c->protected_count>64||!c->protected_count||!c->protected_buffers)return QCC2072_INVALID_ARGUMENT;
 if(c->exact_inputs_verified!=1)return QCC2072_IDENTITY_UNKNOWN;
 if((x=qcc2072_dma_validate(c->admission,c->admission->generation,c->admission->owner_cookie))||
 (x=qcc2072_dma_buffer_validate(c->admission,&c->m3,c->m3_image.length,4096))||
 (x=qcc2072_dma_buffer_validate(c->admission,&c->aux,c->aux_image.length,4096)))return x;
 if(!disjoint(&c->m3,c->m3_image.length,&c->aux,c->aux_image.length))return QCC2072_DMA_INVALID;
 for(uint32_t i=0;i<c->protected_count;i++){
  const struct qcc2072_dma_buffer*b=&c->protected_buffers[i];
  if((x=qcc2072_dma_buffer_validate(c->admission,b,b->capacity,4)))return x;
  if(!disjoint(&c->m3,c->m3_image.length,b,b->capacity)||!disjoint(&c->aux,c->aux_image.length,b,b->capacity))return QCC2072_DMA_INVALID;
 }
 if(!same(c->m3.cpu,c->m3_image.bytes,c->m3_image.length)||!same(c->aux.cpu,c->aux_image.bytes,c->aux_image.length))return QCC2072_BAD_CONTAINER;
 clear(s,sizeof(*s));s->ops=*ops;s->config=*c;s->node=node;s->port=port;s->generation=c->admission->generation;s->owner_cookie=c->admission->owner_cookie;
 s->transaction=1;s->last_ms=now;s->deadline_ms=now+c->timeout_ms;s->state=QCC2072_WLFW_NEW;return 0;
}
static int memory_allocate(struct qcc2072_wlfw*s){
 for(uint32_t i=0;i<s->memory_count;i++){
  struct qcc2072_dma_buffer*b=&s->memory[i];size_t n=s->requested[i].bytes;int x;
  if(s->ops.allocate(s->ops.context,&s->requested[i],b))return fail(s,QCC2072_DMA_INVALID);
  if((x=rwbuf(s->config.admission,b,n)))return fail(s,x);
  if(!disjoint(b,n,&s->config.m3,s->config.m3_image.length)||!disjoint(b,n,&s->config.aux,s->config.aux_image.length)||
    overlap((uintptr_t)b->cpu,n,(uintptr_t)s,sizeof(*s)))return fail(s,QCC2072_DMA_INVALID);
  for(uint32_t j=0;j<s->config.protected_count;j++)if(!disjoint(b,n,&s->config.protected_buffers[j],s->config.protected_buffers[j].capacity))return fail(s,QCC2072_DMA_INVALID);
  for(uint32_t j=0;j<i;j++)if(!disjoint(b,n,&s->memory[j],s->requested[j].bytes))return fail(s,QCC2072_DMA_INVALID);
 }
 /* No allocation is zeroed until all returned ranges pass the complete batch. */
 for(uint32_t i=0;i<s->memory_count;i++){
  clear(s->memory[i].cpu,s->requested[i].bytes);
  if(s->ops.sync(s->ops.context,&s->memory[i],0,s->requested[i].bytes,QCC2072_SYNC_DEVICE))return fail(s,QCC2072_RUNTIME_IO);
 }
 return 0;
}
/* Exact QCC2072 hw.c selects this WCN7850 target/host pipe map. These are
 * independently encoded wire facts, not sibling calibration data. Shadow TLVs
 * are omitted because this provider uses direct R2 MMIO, with polling MSI off. */
static size_t wlan_config(uint8_t*p){
 static const uint32_t target[9][5]={{0,2,32,2048,0},{1,1,32,2048,0},{2,1,32,2048,0},{3,2,32,2048,0},{4,2,256,256,8},{5,1,32,2048,0},{6,3,32,16384,0},{7,4,0,0,8},{8,3,32,16384,0}};
 static const uint32_t services[7]={0x104,0x102,0x101,0x103,0x100,1,0x300};
 const char version[]="Snapintosh-QCC";size_t n=0;p[n++]=0x10;p16(p+n,sizeof(version)-1);n+=2;for(size_t i=0;i<sizeof(version)-1;i++)p[n++]=(uint8_t)version[i];
 p[n++]=0x11;p16(p+n,181);n+=2;p[n++]=9;for(unsigned i=0;i<9;i++)for(unsigned j=0;j<5;j++){p32(p+n,target[i][j]);n+=4;}
 p[n++]=0x12;p16(p+n,169);n+=2;p[n++]=14;
 for(unsigned i=0;i<7;i++)for(unsigned dir=2;dir;dir--){p32(p+n,services[i]);p32(p+n+4,dir);p32(p+n+8,dir==2?(i==5?0:i==6?4:3):(i==6?1:2));n+=12;}return n;
}
int qcc2072_wlfw_enable(struct qcc2072_wlfw*s,uint64_t now){int x=enter(s,now);if(x)return x;if(s->state!=QCC2072_WLFW_FW_READY||!s->fw_ready_seen)return leave(s,QCC2072_BAD_STATE);s->state=QCC2072_WLFW_INI_NEXT;s->deadline_ms=now+s->config.timeout_ms;return leave(s,0);}
int qcc2072_wlfw_next(struct qcc2072_wlfw*s,uint64_t now,void*packet,size_t cap,size_t*written){
 uint8_t*p=packet;size_t n=7;int x;if(!p||!written)return QCC2072_INVALID_ARGUMENT;*written=0;if((x=enter(s,now)))return x;
 /* A bounded maximum avoids mutating allocation/protocol state on short output. */
 if(cap<QCC2072_QMI_REQUEST_MAX)return leave(s,QCC2072_OUTPUT_TOO_SMALL);
 switch(s->state){
 case QCC2072_WLFW_INI_NEXT:
  n+=scalar(p+n,0x10,1,1);return leave(s,request(s,p,n,0x2f,QCC2072_WLFW_WAIT_INI,written));
 case QCC2072_WLFW_CONFIG_NEXT:
  n+=wlan_config(p+n);return leave(s,request(s,p,n,0x23,QCC2072_WLFW_WAIT_CONFIG,written));
 case QCC2072_WLFW_MODE_NEXT:
  n+=scalar(p+n,1,0,4);n+=scalar(p+n,0x10,0,1);return leave(s,request(s,p,n,0x22,QCC2072_WLFW_WAIT_MODE,written));
 case QCC2072_WLFW_NEW:
  n+=scalar(p+n,0x10,1,1);n+=scalar(p+n,0x15,0x4b4e454c,4);n+=scalar(p+n,0x16,1,1);n+=scalar(p+n,0x17,1,1);n+=scalar(p+n,0x18,1,1);
  return leave(s,request(s,p,n,0x20,QCC2072_WLFW_WAIT_IND,written));
 case QCC2072_WLFW_IND_DONE:
  n+=scalar(p+n,0x10,1,4);n+=scalar(p+n,0x13,6U|(s->config.supports_global_reset?8U:0U),1);
  n+=scalar(p+n,0x14,1,1);n+=scalar(p+n,0x16,1,1);n+=scalar(p+n,0x17,1,1);n+=scalar(p+n,0x1a,0,1);n+=scalar(p+n,0x1c,0,1);n+=scalar(p+n,0x27,0x58,8);
  return leave(s,request(s,p,n,0x34,QCC2072_WLFW_WAIT_HOST,written));
 case QCC2072_WLFW_MEMORY_REQUESTED:
  if((x=memory_allocate(s)))return leave(s,x);
  p[n]=1;p16(p+n+1,(uint16_t)(1+s->memory_count*17));p[n+3]=(uint8_t)s->memory_count;n+=4;
  for(uint32_t i=0;i<s->memory_count;i++){p64(p+n,s->memory[i].iova);p32(p+n+8,s->requested[i].bytes);p32(p+n+12,s->requested[i].type);p[n+16]=0;n+=17;}
  return leave(s,request(s,p,n,0x36,QCC2072_WLFW_WAIT_MEMORY_ACK,written));
 case QCC2072_WLFW_MEM_READY:
  if((x=qcc2072_qmi_cap_request(&s->qmi,now,p,cap,written)))return leave(s,fail(s,x));
  s->state=QCC2072_WLFW_WAIT_CAP;s->deadline_ms=now+s->config.timeout_ms;return leave(s,0);
 case QCC2072_WLFW_CAP_DONE:
  if((x=qcc2072_qmi_regdb_begin(&s->qmi,s->config.regdb.bytes,s->config.regdb.length,1)))return leave(s,fail(s,x));
  s->state=QCC2072_WLFW_REGDB;break;
 case QCC2072_WLFW_BOARD_NEXT:
  if((x=qcc2072_qmi_board_begin(&s->qmi,s->config.board.bytes,s->config.board.length,0x111217cb,0xe14f105b,1)))return leave(s,fail(s,x));
  s->state=QCC2072_WLFW_BOARD;break;
 case QCC2072_WLFW_REGDB:case QCC2072_WLFW_BOARD:break;
 case QCC2072_WLFW_M3_NEXT:case QCC2072_WLFW_AUX_NEXT:{
  int aux=s->state==QCC2072_WLFW_AUX_NEXT;const struct qcc2072_dma_buffer*b=aux?&s->config.aux:&s->config.m3;size_t z=aux?s->config.aux_image.length:s->config.m3_image.length;
  if(s->ops.sync(s->ops.context,b,0,z,QCC2072_SYNC_DEVICE))return leave(s,fail(s,QCC2072_RUNTIME_IO));
  n+=scalar(p+n,1,b->iova,8);n+=scalar(p+n,2,z,4);
  return leave(s,request(s,p,n,aux?0x5a:0x3c,aux?QCC2072_WLFW_WAIT_AUX:QCC2072_WLFW_WAIT_M3,written));}
 default:return leave(s,0);
 }
 if(s->qmi.state!=QCC2072_QMI_BDF_NEXT)return leave(s,0);
 x=qcc2072_qmi_board_request(&s->qmi,now,p,cap,written);if(x)return leave(s,fail(s,x));s->deadline_ms=now+s->config.timeout_ms;return leave(s,0);
}
static int memory_request(struct qcc2072_wlfw*s,const uint8_t*p,size_t n){
 struct qcc2072_wlfw_memory_request requests[52];uint32_t count,total=0;size_t off=1;
 if(!n||!(count=p[0])||count>52)return QCC2072_BAD_WIRE;
 for(uint32_t i=0;i<count;i++){
  if(n-off<9)return QCC2072_BAD_WIRE;
  uint32_t z=u32(p+off),type=u32(p+off+4);unsigned cfg=p[off+8];off+=9;
  if(cfg>2||n-off<cfg*13U)return QCC2072_BAD_WIRE;
  if(cfg)return QCC2072_RUNTIME_UNSUPPORTED;
  if(!z||z>s->config.memory_budget_bytes-total)return QCC2072_TOO_LARGE;
  /* ath12k HOST_DDR, BDF, M3_DUMP, CALDB, PAGEABLE, LPASS_SHARED_V01 (0xb: the
   * QCC2072 asks for 1 MiB of it on the A16). MLO_GLOBAL (8) stays refused. */
  if(type!=1&&type!=2&&type!=3&&type!=4&&type!=9&&type!=0xb)return QCC2072_RUNTIME_UNSUPPORTED;
  requests[i]=(struct qcc2072_wlfw_memory_request){z,type};total+=z;
 }
 if(off!=n)return QCC2072_BAD_WIRE;
 for(uint32_t i=0;i<count;i++)s->requested[i]=requests[i];s->memory_count=count;s->memory_bytes=total;return 0;
}
static int memory_ready(struct qcc2072_wlfw*s,uint64_t now){
 uint8_t packet[7]={4,0,0,0x37,0,0,0};int x=qcc2072_qmi_init(&s->qmi,s->node,s->port,s->generation,s->owner_cookie,now,s->config.timeout_ms);
 if(x)return fail(s,x);s->qmi.next_transaction=s->transaction;
 x=qcc2072_qmi_receive(&s->qmi,s->node,s->port,s->generation,s->owner_cookie,now,packet,7);
 /* This reconstruction is invoked only after the real received indication was
  * validated and retained as memory_ready_seen; it does not fabricate a receipt. */
 if(x)return fail(s,x);s->state=QCC2072_WLFW_MEM_READY;s->deadline_ms=now+s->config.timeout_ms;return 0;
}
int qcc2072_wlfw_receive(struct qcc2072_wlfw*s,uint32_t node,uint32_t port,uint64_t gen,uint64_t owner,uint64_t now,const void*packet,size_t length){
 const uint8_t*p=packet,*mem=NULL;size_t memlen=0,off=7;uint32_t seen[8]={0};uint16_t id,tx,result=0,error=0;int have_result=0,x;
 if(!s||!p)return QCC2072_INVALID_ARGUMENT;
 if(node!=s->node||port!=s->port)return QCC2072_FOREIGN_PEER;
 if(gen!=s->generation||owner!=s->owner_cookie)return QCC2072_SESSION_STALE;
 if((x=enter(s,now)))return x;
 if(length<7||length>8192||u16(p+5)!=length-7)return leave(s,fail(s,QCC2072_BAD_WIRE));
 id=u16(p+3);tx=u16(p+1);
 while(off<length){if(length-off<3)return leave(s,fail(s,QCC2072_BAD_WIRE));uint8_t tag=p[off];size_t z=u16(p+off+1);off+=3;
  if(z>length-off||(seen[tag/32]&(1U<<(tag%32))))return leave(s,fail(s,QCC2072_BAD_WIRE));seen[tag/32]|=1U<<(tag%32);
  if(tag==2&&p[0]==2){if(z!=4)return leave(s,fail(s,QCC2072_BAD_WIRE));result=u16(p+off);error=u16(p+off+2);have_result=1;}
  if(tag==1&&id==0x35){mem=p+off;memlen=z;}off+=z;
 }
 if(p[0]==4){
  /* Indications carry no transaction: the A16's firmware sends REQUEST_MEM with
   * txn 1, and Linux's QMI core dispatches indications without checking it. */
  if(id==0x35){
   if(!mem||s->memory_count||(s->state!=QCC2072_WLFW_WAIT_HOST&&s->state!=QCC2072_WLFW_WAIT_MEMORY))return leave(s,fail(s,QCC2072_BAD_STATE));
   if((x=memory_request(s,mem,memlen)))return leave(s,fail(s,x));
   if(s->state==QCC2072_WLFW_WAIT_MEMORY)s->state=QCC2072_WLFW_MEMORY_REQUESTED;return leave(s,0);
  }
  if(id==0x37){
   if(length!=7||s->memory_ready_seen||(s->state!=QCC2072_WLFW_WAIT_MEMORY_ACK&&s->state!=QCC2072_WLFW_WAIT_MEM_READY))return leave(s,fail(s,QCC2072_BAD_STATE));
   s->memory_ready_seen=1;if(s->state==QCC2072_WLFW_WAIT_MEM_READY)return leave(s,memory_ready(s,now));return leave(s,0);
  }
  if(id==0x38){
   /* The A16's firmware reports FW_READY (with an optional TLV 0x12) as soon as M3 is
    * acknowledged, before AUX is offered; Linux handles it as an independent event. */
   if(s->fw_ready_seen||s->state<QCC2072_WLFW_WAIT_M3||s->state>QCC2072_WLFW_WAIT_FW_READY)return leave(s,fail(s,QCC2072_BAD_STATE));
   s->fw_ready_seen=1;if(s->state==QCC2072_WLFW_WAIT_FW_READY)s->state=QCC2072_WLFW_FW_READY;return leave(s,0);
  }
  return leave(s,fail(s,QCC2072_RUNTIME_UNSUPPORTED));
 }
 if(p[0]!=2||!have_result)return leave(s,fail(s,QCC2072_BAD_WIRE));
 if(s->state==QCC2072_WLFW_WAIT_CAP||s->state==QCC2072_WLFW_REGDB||s->state==QCC2072_WLFW_BOARD){
  x=qcc2072_qmi_receive(&s->qmi,node,port,gen,owner,now,p,length);if(x)return leave(s,fail(s,x));
  if(s->qmi.state==QCC2072_QMI_CAP_OBSERVED)s->state=QCC2072_WLFW_CAP_DONE;
  if(s->qmi.state==QCC2072_QMI_BDF_ACKED){s->state=s->state==QCC2072_WLFW_REGDB?QCC2072_WLFW_BOARD_NEXT:QCC2072_WLFW_M3_NEXT;s->transaction=s->qmi.next_transaction;}
  return leave(s,0);
 }
 if(!tx||tx!=s->pending_transaction||id!=s->pending_message)return leave(s,QCC2072_STALE_TRANSACTION);
 if(result||error)return leave(s,fail(s,QCC2072_PEER_FAILED));
 switch(s->state){
 case QCC2072_WLFW_WAIT_INI:s->state=QCC2072_WLFW_CONFIG_NEXT;break;
 case QCC2072_WLFW_WAIT_CONFIG:s->state=QCC2072_WLFW_MODE_NEXT;break;
 case QCC2072_WLFW_WAIT_MODE:s->state=QCC2072_WLFW_WLAN_ENABLED;break;
 case QCC2072_WLFW_WAIT_IND:s->state=QCC2072_WLFW_IND_DONE;break;
 case QCC2072_WLFW_WAIT_HOST:s->state=s->memory_count?QCC2072_WLFW_MEMORY_REQUESTED:QCC2072_WLFW_WAIT_MEMORY;break;
 case QCC2072_WLFW_WAIT_MEMORY_ACK:
  s->state=QCC2072_WLFW_WAIT_MEM_READY;if(s->memory_ready_seen)x=memory_ready(s,now);break;
 case QCC2072_WLFW_WAIT_M3:s->state=QCC2072_WLFW_AUX_NEXT;break;
 case QCC2072_WLFW_WAIT_AUX:s->state=s->fw_ready_seen?QCC2072_WLFW_FW_READY:QCC2072_WLFW_WAIT_FW_READY;break;
 default:return leave(s,QCC2072_STALE_TRANSACTION);
 }
 s->pending_transaction=s->pending_message=0;s->deadline_ms=now+s->config.timeout_ms;return leave(s,x);
}
int qcc2072_wlfw_abort(struct qcc2072_wlfw*s,int reason){if(!s||s->in_call)return QCC2072_BAD_STATE;return fail(s,reason?reason:QCC2072_QUARANTINED);}

/* SPDX-License-Identifier: MIT */
/* Production callback orchestration; no synthetic peer or ready-state setter. */
#include "qcc2072-service.h"
static void clear(void*v,size_t n){uint8_t*p=v;for(size_t i=0;i<n;i++)p[i]=0;}
static int owner(void*v,uint64_t g,uint64_t c){struct qcc2072_service*s=v;return s->config.io.validate_owner(s->config.io.context,g,c);}
static int enable(void*v,uint64_t g,uint64_t c){struct qcc2072_service*s=v;return s->config.io.enable_dma(s->config.io.context,g,c);}
static int read32(void*v,uint32_t o,uint32_t*x){struct qcc2072_service*s=v;return s->config.io.read32(s->config.io.context,o,x);}
static int write32(void*v,uint32_t o,uint32_t x){struct qcc2072_service*s=v;return s->config.io.write32(s->config.io.context,o,x);}
static int syncmem(void*v,const struct qcc2072_dma_buffer*b,size_t o,size_t n,uint32_t d){struct qcc2072_service*s=v;return s->config.io.sync(s->config.io.context,b,o,n,d);}
static uint64_t nowms(void*v){struct qcc2072_service*s=v;return s->config.io.now_ms(s->config.io.context);}
static int receive(void*v,const uint8_t*p,size_t n){
 struct qcc2072_service*s=v;if(!s->in_call||!p||!n||n>QCC2072_RUNTIME_MTU||s->rx_count==QCC2072_SERVICE_RX_SLOTS)return QCC2072_RUNTIME_FULL;
 for(size_t i=0;i<n;i++)s->rx[s->rx_write][i]=p[i];s->rx_length[s->rx_write]=(uint16_t)n;
 s->rx_write=(s->rx_write+1)%QCC2072_SERVICE_RX_SLOTS;s->rx_count++;return 0;
}
static int fail(struct qcc2072_service*s,int why){
 s->state=QCC2072_SERVICE_QUARANTINE;s->quarantine_reason=why?why:QCC2072_QUARANTINED;s->qrtr.quarantined=1;
 if(s->ce_initialized){qcc2072_ce_abort(&s->ce,s->quarantine_reason);qcc2072_htc_abort(&s->htc,s->quarantine_reason);}
 if(s->wlfw_initialized)qcc2072_wlfw_abort(&s->wlfw,s->quarantine_reason);
 qcc2072_runtime_abort(&s->runtime,s->quarantine_reason);return s->quarantine_reason;
}
static int leave(struct qcc2072_service*s,int x){
 if(s->state!=s->reported_state){s->reported_state=s->state;if(s->config.state_changed)s->config.state_changed(s->config.event_context,s->state,s->quarantine_reason);}
 s->in_call=0;return x;
}
static int enter(struct qcc2072_service*s){
 if(!s||s->in_call)return QCC2072_BAD_STATE;if(s->state==QCC2072_SERVICE_QUARANTINE)return QCC2072_QUARANTINED;
 s->in_call=1;uint64_t now=nowms(s);if(now<s->last_ms||owner(s,s->runtime.generation,s->runtime.owner_cookie))return leave(s,fail(s,QCC2072_SESSION_STALE));s->last_ms=now;return 0;
}
int qcc2072_service_init(struct qcc2072_service*s,const struct qcc2072_service_config*c){
 if(!s||!c||!c->io.validate_owner||!c->io.enable_dma||!c->io.read32||!c->io.write32||!c->io.sync||!c->io.now_ms||
 !c->memory.validate_owner||!c->memory.allocate||!c->memory.sync||!c->firmware.admission||
 !c->discovery_timeout_ms||c->discovery_timeout_ms>120000)return QCC2072_INVALID_ARGUMENT;
 struct qcc2072_service_config cfg=*c;clear(s,sizeof(*s));s->config=cfg;s->last_ms=nowms(s);
 if(s->last_ms>UINT64_MAX-cfg.discovery_timeout_ms)return QCC2072_INVALID_ARGUMENT;
 struct qcc2072_runtime_ops ops={s,owner,enable,read32,write32,syncmem,nowms,receive,0};
 int x=qcc2072_runtime_init(&s->runtime,&ops,cfg.firmware.admission,&cfg.boot);if(x)return fail(s,x);
 x=qcc2072_qrtr_init(&s->qrtr,cfg.local_node,cfg.local_port,s->runtime.generation,s->runtime.owner_cookie);if(x)return fail(s,x);
 /* Validate all WLFW buffers before any DMA enable. The temporary endpoint is
  * never used on wire; actual discovery reinitializes before first request. */
 x=qcc2072_wlfw_init(&s->wlfw,&cfg.memory,&cfg.firmware,0,1,s->last_ms);if(x)return fail(s,x);
 s->state=s->reported_state=QCC2072_SERVICE_PREPARED;return 0;
}
static int ce_receive(void*v,uint32_t pipe,const uint8_t*p,size_t n){struct qcc2072_service*s=v;
 if(!s->in_call||!p||!n||n>2048||s->ce_rx_count>=32)return QCC2072_RUNTIME_FULL;unsigned k=s->ce_rx_count++;
 for(size_t i=0;i<n;i++)s->ce_rx[k][i]=p[i];s->ce_rx_length[k]=(uint16_t)n;s->ce_rx_pipe[k]=(uint8_t)pipe;return 0;}
int qcc2072_service_enable_wlan(struct qcc2072_service*s,const struct qcc2072_dma_buffer*arena){int x=enter(s);if(x)return x;
 if(!arena||s->state!=QCC2072_SERVICE_FW_READY||s->ce_initialized||s->runtime.state!=QCC2072_RUNTIME_IPCR||s->runtime.mhi_state!=2)return leave(s,QCC2072_BAD_STATE);
 struct qcc2072_dma_buffer guard[128];unsigned n=0;for(unsigned i=0;i<s->config.firmware.protected_count;i++){const struct qcc2072_dma_buffer*b=&s->config.firmware.protected_buffers[i];
  if(b->cpu==arena->cpu&&b->iova==arena->iova&&b->physical==arena->physical&&b->capacity==arena->capacity)continue;guard[n++]=*b;}
 guard[n++]=s->config.firmware.m3;guard[n++]=s->config.firmware.aux;for(unsigned i=0;i<s->wlfw.memory_count;i++)guard[n++]=s->wlfw.memory[i];
 struct qcc2072_ce_ops ops={s,owner,read32,write32,syncmem,nowms,ce_receive};
 x=qcc2072_ce_init(&s->ce,&ops,s->config.firmware.admission,arena,guard,n,s->config.boot.bar_bytes,s->config.firmware.timeout_ms);if(x)return leave(s,fail(s,x));s->ce_initialized=1;
 if((x=qcc2072_ce_begin(&s->ce))||(x=qcc2072_htc_init(&s->htc,s->runtime.generation,s->runtime.owner_cookie,s->last_ms,s->config.firmware.timeout_ms))||(x=qcc2072_wlfw_enable(&s->wlfw,s->last_ms)))return leave(s,fail(s,x));
 s->state=QCC2072_SERVICE_WLAN_CONFIG;return leave(s,0);
}
static int ce_progress(struct qcc2072_service*s,uint32_t budget){int x=qcc2072_ce_poll(&s->ce,budget);if(x)return fail(s,x);
 for(unsigned i=0;i<s->ce_rx_count;i++){struct qcc2072_htc_message msg;
  x=qcc2072_htc_receive(&s->htc,s->runtime.generation,s->runtime.owner_cookie,s->last_ms,s->ce_rx_pipe[i],s->ce_rx[i],s->ce_rx_length[i],&msg);if(x)return fail(s,x);
  if(msg.payload.length&&(!s->config.firmware_event||s->config.firmware_event(s->config.event_context,msg.service,msg.payload.bytes,msg.payload.length)))return fail(s,QCC2072_RUNTIME_UNSUPPORTED);
 }s->ce_rx_count=0;
 if(s->ce_pending_length){x=qcc2072_ce_send(&s->ce,s->ce_pending_pipe,s->ce_pending,s->ce_pending_length);if(x==QCC2072_RUNTIME_FULL)return 0;if(x)return fail(s,x);s->ce_pending_length=0;}
 /* Firmware mode response gates outbound HTC negotiation; actual READY may race
  * that response and is retained, never manufactured. */
 if(s->wlfw.state==QCC2072_WLFW_WLAN_ENABLED){
  if(s->state==QCC2072_SERVICE_WLAN_CONFIG)s->htc.deadline_ms=s->last_ms+s->htc.timeout_ms;
  x=qcc2072_htc_next(&s->htc,s->last_ms,s->ce_pending,sizeof(s->ce_pending),&s->ce_pending_length,&s->ce_pending_pipe);if(x)return fail(s,x);
  if(s->ce_pending_length){x=qcc2072_ce_send(&s->ce,s->ce_pending_pipe,s->ce_pending,s->ce_pending_length);if(x&&x!=QCC2072_RUNTIME_FULL)return fail(s,x);if(!x)s->ce_pending_length=0;}
  s->state=s->htc.state==QCC2072_HTC_SETUP_SENT?QCC2072_SERVICE_HTC_SETUP:QCC2072_SERVICE_HTC;
 }return 0;
}
int qcc2072_service_begin(struct qcc2072_service*s){int x=enter(s);if(x)return x;
 if(s->state!=QCC2072_SERVICE_PREPARED)return leave(s,QCC2072_BAD_STATE);
 x=qcc2072_runtime_begin(&s->runtime);if(x)return leave(s,fail(s,x));s->state=QCC2072_SERVICE_BOOTING;return leave(s,0);
}
static int flush(struct qcc2072_service*s){
 if(!s->pending_length)return 0;int x=qcc2072_runtime_send(&s->runtime,s->pending,s->pending_length);
 if(x==QCC2072_RUNTIME_FULL)return x;if(x)return fail(s,x);s->pending_length=0;return 0;
}
int qcc2072_service_poll(struct qcc2072_service*s,uint32_t budget){
 if(!budget||budget>32)return QCC2072_INVALID_ARGUMENT;int x=enter(s);if(x)return x;
 if(s->state==QCC2072_SERVICE_PREPARED)return leave(s,QCC2072_BAD_STATE);
 if((x=qcc2072_runtime_poll(&s->runtime,budget)))return leave(s,fail(s,x));
 if(s->state==QCC2072_SERVICE_BOOTING&&s->runtime.state==QCC2072_RUNTIME_IPCR){
  if(s->last_ms>UINT64_MAX-s->config.discovery_timeout_ms)return leave(s,fail(s,QCC2072_DEADLINE));
  s->discovery_deadline=s->last_ms+s->config.discovery_timeout_ms;s->state=QCC2072_SERVICE_DISCOVERY;
  if((x=qcc2072_qrtr_hello(&s->qrtr,s->pending,sizeof(s->pending),&s->pending_length)))return leave(s,fail(s,x));
 }
 if(s->state==QCC2072_SERVICE_DISCOVERY&&s->last_ms>=s->discovery_deadline)return leave(s,fail(s,QCC2072_DEADLINE));
 if(s->wlfw_initialized&&s->wlfw.state!=QCC2072_WLFW_FW_READY&&s->wlfw.state!=QCC2072_WLFW_WLAN_ENABLED&&s->last_ms>=s->wlfw.deadline_ms)return leave(s,fail(s,QCC2072_DEADLINE));
 if((x=flush(s))){if(x==QCC2072_RUNTIME_FULL)goto finish;return leave(s,x);}
 for(uint32_t i=0;i<budget&&s->rx_count;i++){
  struct qcc2072_qrtr_message msg;
  x=qcc2072_qrtr_receive(&s->qrtr,s->runtime.generation,s->runtime.owner_cookie,s->rx[s->rx_read],s->rx_length[s->rx_read],&msg);
  if(x)return leave(s,fail(s,x));
  if(msg.service_arrived){
   if(s->wlfw_initialized)return leave(s,fail(s,QCC2072_DUPLICATE));
   x=qcc2072_wlfw_init(&s->wlfw,&s->config.memory,&s->config.firmware,s->qrtr.remote_node,s->qrtr.remote_port,s->last_ms);
   if(x)return leave(s,fail(s,x));s->wlfw_initialized=1;s->state=QCC2072_SERVICE_WLFW;
  }
  if(msg.data.length){
   if(!s->wlfw_initialized)return leave(s,fail(s,QCC2072_BAD_STATE));
   x=qcc2072_wlfw_receive(&s->wlfw,msg.node,msg.port,s->runtime.generation,s->runtime.owner_cookie,s->last_ms,msg.data.bytes,msg.data.length);
   if(x)return leave(s,fail(s,x));
  }
  if(msg.reply_length){for(size_t j=0;j<msg.reply_length;j++)s->pending[j]=msg.reply[j];s->pending_length=msg.reply_length;}
  s->rx_read=(s->rx_read+1)%QCC2072_SERVICE_RX_SLOTS;s->rx_count--;
  if((x=flush(s))){if(x==QCC2072_RUNTIME_FULL)goto finish;return leave(s,x);}
 }
 if(s->wlfw_initialized&&s->qrtr.pending_tx<10){
  size_t n=0;x=qcc2072_wlfw_next(&s->wlfw,s->last_ms,s->qmi,sizeof(s->qmi),&n);if(x)return leave(s,fail(s,x));
  if(n){x=qcc2072_qrtr_send(&s->qrtr,s->qmi,n,s->pending,sizeof(s->pending),&s->pending_length);if(x)return leave(s,fail(s,x));
   x=flush(s);if(x&&x!=QCC2072_RUNTIME_FULL)return leave(s,x);}
 }
 finish:
 if(s->wlfw_initialized&&s->wlfw.state==QCC2072_WLFW_FW_READY)s->state=QCC2072_SERVICE_FW_READY;
 if(s->ce_initialized&&(x=ce_progress(s,budget)))return leave(s,x);
 return leave(s,0);
}
int qcc2072_service_abort(struct qcc2072_service*s,int reason){if(!s||s->in_call)return QCC2072_BAD_STATE;s->in_call=1;return leave(s,fail(s,reason));}

int qcc2072_service_send_wmi(struct qcc2072_service*s,const void*payload,size_t n){
 int x=enter(s);if(x)return x;
 if(!s->ce_initialized||s->state!=QCC2072_SERVICE_HTC_SETUP||s->htc.state!=QCC2072_HTC_SETUP_SENT)return leave(s,QCC2072_BAD_STATE);
 if(s->ce_pending_length)return leave(s,QCC2072_RUNTIME_FULL);
 x=qcc2072_htc_wmi(&s->htc,s->last_ms,payload,n,s->ce_pending,sizeof(s->ce_pending),&s->ce_pending_length);
 if(x)return leave(s,x);s->ce_pending_pipe=3;
 x=qcc2072_ce_send(&s->ce,3,s->ce_pending,s->ce_pending_length);
 if(x==QCC2072_RUNTIME_FULL)return leave(s,0); /* copied ownership accepted */
 if(x)return leave(s,fail(s,x));s->ce_pending_length=0;return leave(s,0);
}

int qcc2072_service_send_htt(struct qcc2072_service*s,const void*payload,size_t n){
 int x=enter(s);if(x)return x;
 if(!s->ce_initialized||s->state!=QCC2072_SERVICE_HTC_SETUP||s->htc.state!=QCC2072_HTC_SETUP_SENT)return leave(s,QCC2072_BAD_STATE);
 if(s->ce_pending_length)return leave(s,QCC2072_RUNTIME_FULL);
 x=qcc2072_htc_htt(&s->htc,s->last_ms,payload,n,s->ce_pending,sizeof(s->ce_pending),&s->ce_pending_length);
 if(x)return leave(s,x);s->ce_pending_pipe=4;
 x=qcc2072_ce_send(&s->ce,4,s->ce_pending,s->ce_pending_length);
 if(x==QCC2072_RUNTIME_FULL)return leave(s,0);
 if(x)return leave(s,fail(s,x));s->ce_pending_length=0;return leave(s,0);
}

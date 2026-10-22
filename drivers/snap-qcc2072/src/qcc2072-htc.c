/* SPDX-License-Identifier: MIT */
/* Bounded HTC control and credit protocol; actual RX establishes all endpoints. */
#include "qcc2072-htc.h"
static uint32_t u32(const uint8_t*p){return (uint32_t)p[0]|(uint32_t)p[1]<<8|(uint32_t)p[2]<<16|(uint32_t)p[3]<<24;}
static void p32(uint8_t*p,uint32_t v){for(unsigned i=0;i<4;i++)p[i]=(uint8_t)(v>>(8*i));}
static void clear(void*v,size_t n){uint8_t*p=v;for(size_t i=0;i<n;i++)p[i]=0;}
static int fail(struct qcc2072_htc*h,int x){h->state=QCC2072_HTC_QUARANTINE;h->quarantine_reason=x;return x;}
static int enter(struct qcc2072_htc*h,uint64_t now){if(!h)return QCC2072_INVALID_ARGUMENT;if(h->state==QCC2072_HTC_QUARANTINE)return QCC2072_QUARANTINED;
 if(now<h->last_ms||now>UINT64_MAX-h->timeout_ms)return fail(h,QCC2072_SESSION_STALE);
 if(h->state!=QCC2072_HTC_SETUP_SENT&&now>=h->deadline_ms)return fail(h,QCC2072_DEADLINE);h->last_ms=now;return 0;}
int qcc2072_htc_init(struct qcc2072_htc*h,uint64_t g,uint64_t owner,uint64_t now,uint32_t timeout){
 if(!h||!g||!owner||!timeout||timeout>120000||now>UINT64_MAX-timeout)return QCC2072_INVALID_ARGUMENT;clear(h,sizeof(*h));h->generation=g;h->owner_cookie=owner;h->last_ms=now;h->timeout_ms=timeout;h->deadline_ms=now+timeout;return 0;}
static int header(struct qcc2072_htc*h,uint8_t ep,uint8_t flags,const uint8_t*data,size_t n,uint8_t*out,size_t cap,size_t*written){
 if(!out||!written||!data||!n||n>2040||ep>=9)return QCC2072_INVALID_ARGUMENT;
 if(cap<n+8)return QCC2072_OUTPUT_TOO_SMALL;uintptr_t a=(uintptr_t)data,b=(uintptr_t)out;
 if(a>UINTPTR_MAX-n||b>UINTPTR_MAX-n-8||(a<b+n+8&&b<a+n))return QCC2072_INVALID_ARGUMENT;
 p32(out,ep|((uint32_t)flags<<8)|((uint32_t)n<<16));p32(out+4,(uint32_t)h->sequence[ep]++<<8);for(size_t i=0;i<n;i++)out[8+i]=data[i];*written=n+8;return 0;
}
int qcc2072_htc_next(struct qcc2072_htc*h,uint64_t now,void*out,size_t cap,size_t*n,uint32_t*pipe){
 if(!n||!pipe)return QCC2072_INVALID_ARGUMENT;*n=0;*pipe=0;int x=enter(h,now);if(x)return x;uint8_t body[12]={0};size_t z=8;enum qcc2072_htc_state next;
 if(h->state==QCC2072_HTC_READY){p32(body,2|(0x100U<<16));p32(body+4,(uint32_t)h->allocation<<8);next=QCC2072_HTC_WAIT_WMI;}
 else if(h->state==QCC2072_HTC_WMI_CONNECTED){p32(body,2|(0x300U<<16));p32(body+4,8);next=QCC2072_HTC_WAIT_HTT;}
 else if(h->state==QCC2072_HTC_HTT_CONNECTED){p32(body,5);z=12;next=QCC2072_HTC_SETUP_SENT;}else return 0;
 x=header(h,0,0,body,z,out,cap,n);if(x)return x;h->state=next;h->deadline_ms=now+h->timeout_ms;return 0;
}
int qcc2072_htc_wmi(struct qcc2072_htc*h,uint64_t now,const void*data,size_t n,void*out,size_t cap,size_t*written){
 if(!written)return QCC2072_INVALID_ARGUMENT;*written=0;int x=enter(h,now);if(x)return x;if(h->state!=QCC2072_HTC_SETUP_SENT||!h->wmi_endpoint)return QCC2072_BAD_STATE;
 if(n>h->wmi_max||n>2040)return QCC2072_TOO_LARGE;unsigned credits=(unsigned)((n+8+h->credit_size-1)/h->credit_size);if(credits>h->credits)return QCC2072_RUNTIME_FULL;
 x=header(h,h->wmi_endpoint,1,data,n,out,cap,written);if(!x)h->credits=(uint16_t)(h->credits-credits);return x;
}
int qcc2072_htc_htt(struct qcc2072_htc*h,uint64_t now,const void*data,size_t n,void*out,size_t cap,size_t*written){
 if(!written)return QCC2072_INVALID_ARGUMENT;*written=0;int x=enter(h,now);if(x)return x;
 if(h->state!=QCC2072_HTC_SETUP_SENT||!h->htt_endpoint)return QCC2072_BAD_STATE;
 if(!n||n>h->htt_max||n>248)return QCC2072_TOO_LARGE;
 return header(h,h->htt_endpoint,0,data,n,out,cap,written);
}
int qcc2072_htc_receive(struct qcc2072_htc*h,uint64_t gen,uint64_t owner,uint64_t now,uint32_t pipe,const void*bytes,size_t length,struct qcc2072_htc_message*msg){
 if(!h||!bytes||!msg)return QCC2072_INVALID_ARGUMENT;int x=enter(h,now);if(x)return x;if(gen!=h->generation||owner!=h->owner_cookie)return fail(h,QCC2072_SESSION_STALE);clear(msg,sizeof(*msg));
 const uint8_t*p=bytes;if(length<8||length>2048||(pipe!=1&&pipe!=2))return fail(h,QCC2072_BAD_WIRE);
 uint32_t a=u32(p),b=u32(p+4);unsigned ep=a&255,flags=(a>>8)&255,n=a>>16,trailer=flags&2?b&255:0;
 if(ep>=9||(ep&&(ep!=h->wmi_endpoint&&ep!=h->htt_endpoint))||flags&~2U||n>length-8||length-8-n>3||trailer>n||((flags&2)&&trailer<4))return fail(h,QCC2072_BAD_WIRE);
 for(size_t i=8+n;i<length;i++)if(p[i])return fail(h,QCC2072_BAD_WIRE);
 if(ep&&((ep==h->wmi_endpoint&&pipe!=2)||(ep==h->htt_endpoint&&pipe!=1)))return fail(h,QCC2072_FOREIGN_PEER);
 unsigned grants=0;size_t end=8+n,off=end-trailer;
 while(off<end){if(end-off<4)return fail(h,QCC2072_BAD_WIRE);unsigned id=p[off],z=p[off+1];off+=4;if(z>end-off)return fail(h,QCC2072_BAD_WIRE);
  if(id==1){if(!z||(z&3))return fail(h,QCC2072_BAD_WIRE);for(unsigned i=0;i<z;i+=4){unsigned eid=p[off+i];if(eid>=9||eid>=h->max_endpoints)return fail(h,QCC2072_BAD_WIRE);if(eid==h->wmi_endpoint&&eid)grants+=p[off+i+1];}}
  off+=z;
 }
 if(grants>h->allocation-h->credits)return fail(h,QCC2072_BAD_WIRE);
 n-=trailer;p+=8;
 if(!n){h->credits=(uint16_t)(h->credits+grants);return 0;}
 if(ep){h->credits=(uint16_t)(h->credits+grants);msg->endpoint=(uint8_t)ep;msg->service=ep==h->wmi_endpoint?0x100:0x300;msg->payload.bytes=p;msg->payload.length=n;return 0;}
 if(n<8)return fail(h,QCC2072_BAD_WIRE);unsigned id=u32(p)&0xffff,service=u32(p)>>16;
 if(id==1){
  if(h->state!=QCC2072_HTC_WAIT_READY||h->ready_seen||(n!=8&&n!=12))return fail(h,QCC2072_BAD_STATE);
  unsigned credits=service,size=u32(p+4)&0xffff,max=(u32(p+4)>>16)&255;
  /* The A16's firmware grants 2 credits of 2176 bytes over 5 endpoints. Host sends stay
   * within 2040 bytes regardless; the credit size only scales the credit count. */
  if(!credits||credits>255||!size||size>4096||max<3||max>9)return fail(h,QCC2072_BAD_WIRE);
  h->allocation=h->credits=(uint16_t)credits;h->credit_size=(uint16_t)size;h->max_endpoints=(uint8_t)max;h->ready_seen=1;h->state=QCC2072_HTC_READY;
 }else if(id==3){
  int wmi=h->state==QCC2072_HTC_WAIT_WMI;if(!wmi&&h->state!=QCC2072_HTC_WAIT_HTT)return fail(h,QCC2072_BAD_STATE);
  if(n<12||service!=(wmi?0x100:0x300))return fail(h,QCC2072_BAD_WIRE);unsigned status=p[4],eid=p[5],max=u32(p+4)>>16,meta=p[8];
  if(status)return fail(h,QCC2072_PEER_FAILED);if(!eid||eid>=h->max_endpoints||eid==h->wmi_endpoint||eid==h->htt_endpoint||!max||meta!=n-12)return fail(h,QCC2072_BAD_WIRE);
  if(wmi){h->wmi_endpoint=(uint8_t)eid;h->wmi_max=(uint16_t)max;h->state=QCC2072_HTC_WMI_CONNECTED;}
  else {h->htt_endpoint=(uint8_t)eid;h->htt_max=(uint16_t)max;h->state=QCC2072_HTC_HTT_CONNECTED;}
 }else return fail(h,QCC2072_RUNTIME_UNSUPPORTED);
 h->credits=(uint16_t)(h->credits+grants);h->deadline_ms=now+h->timeout_ms;return 0;
}
int qcc2072_htc_abort(struct qcc2072_htc*h,int why){if(!h)return QCC2072_INVALID_ARGUMENT;return fail(h,why?why:QCC2072_QUARANTINED);}

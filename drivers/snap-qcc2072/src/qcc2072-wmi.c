/* SPDX-License-Identifier: MIT */
/* Independently implemented bounded WMI wire handling. Wire facts pinned in
 * re/backend/WMI-FAILURES-AND-REPLAY.md; no Linux helper code is incorporated. */
#include "qcc2072-wmi.h"
static uint32_t le32(const uint8_t *p){return (uint32_t)p[0]|(uint32_t)p[1]<<8|(uint32_t)p[2]<<16|(uint32_t)p[3]<<24;}
static uint16_t le16(const uint8_t *p){return (uint16_t)(p[0]|(uint16_t)p[1]<<8);}
static void put32(uint8_t *p,uint32_t x){for(unsigned i=0;i<4;i++)p[i]=(uint8_t)(x>>(8*i));}
static void zero(void *v,size_t n){uint8_t *p=v;for(size_t i=0;i<n;i++)p[i]=0;}
static void copy(void *v,const void *b,size_t n){uint8_t *p=v;const uint8_t *q=b;for(size_t i=0;i<n;i++)p[i]=q[i];}
static int overlap(const void *a,size_t an,const void *b,size_t bn){uintptr_t x=(uintptr_t)a,y=(uintptr_t)b;return x>UINTPTR_MAX-an||y>UINTPTR_MAX-bn||(x<y+bn&&y<x+an);}
static int fail(struct qcc2072_wmi *w,int why){w->state=QCC2072_WMI_QUARANTINE;w->quarantine_reason=why;return why;}
static int check(struct qcc2072_wmi *w,uint64_t now){
 if(!w)return QCC2072_INVALID_ARGUMENT;
 if(w->state==QCC2072_WMI_QUARANTINE)return QCC2072_QUARANTINED;
 if(now<w->last_ms||now>UINT64_MAX-w->timeout_ms||w->config.validate_owner(w->config.context,w->generation,w->owner_cookie))return fail(w,QCC2072_SESSION_STALE);
 if(w->state!=QCC2072_WMI_READY&&now>=w->deadline_ms)return fail(w,QCC2072_DEADLINE);
 w->last_ms=now;return 0;
}
static int bit(const struct qcc2072_wmi *w,unsigned n){return !!(w->services[n/32]&(1U<<(n%32)));}
static void progress(struct qcc2072_wmi *w){
 if(!w->service_seen||w->state>=QCC2072_WMI_WAIT_READY)return;
 w->state=((bit(w,77)&&!w->ext_seen)||(bit(w,220)&&!w->ext2_seen))?QCC2072_WMI_WAIT_EXT:QCC2072_WMI_INIT_ELIGIBLE;
}
int qcc2072_wmi_init(struct qcc2072_wmi *w,const struct qcc2072_wmi_config *c,uint64_t g,uint64_t owner,uint64_t now,uint32_t timeout){
 if(!w||!c||!g||!owner||!timeout||timeout>120000||now>UINT64_MAX-timeout||!c->validate_owner||!c->admit_datapath)return QCC2072_INVALID_ARGUMENT;
 struct qcc2072_wmi_config cfg=*c;zero(w,sizeof(*w));w->config=cfg;w->generation=g;w->owner_cookie=owner;w->timeout_ms=timeout;w->last_ms=now;w->deadline_ms=now+timeout;
 return check(w,now);
}
struct slice {const uint8_t *p;size_t n;};
struct parsed {struct slice fixed,bitmap,bytes,rules;unsigned fixed_tag,count;};
/* Only a known event's mandatory fixed field is interpreted. All ARRAY_STRUCT
 * envelopes are recursively bounded before any caller-visible state changes. */
static int walk(struct parsed *v,const uint8_t *p,size_t n,unsigned depth){
 if(depth>3)return QCC2072_BAD_WIRE;
 while(n){
  if(n<4||++v->count>256)return QCC2072_BAD_WIRE;
  unsigned tag=le32(p)>>16,z=le32(p)&0xffff;p+=4;n-=4;
  if(z>n)return QCC2072_BAD_WIRE;
  struct slice *dst=0;
  if(!depth&&tag==v->fixed_tag)dst=&v->fixed;
  /* SERVICE_READY carries a second top-level ARRAY_UINT32 (the DBS hw-mode list) after
   * the service bitmap; ath12k takes them in order. Only the first is the bitmap. */
  else if(!depth&&tag==16&&!v->bitmap.p)dst=&v->bitmap;
  else if(!depth&&tag==16)dst=0;
  else if(!depth&&tag==17)dst=&v->bytes;
  if(dst){if(dst->p)return QCC2072_DUPLICATE;dst->p=p;dst->n=z;}
  if(tag==18){
   if((v->fixed_tag==938||v->fixed_tag==609)&&!depth){if(v->rules.p)return QCC2072_DUPLICATE;v->rules.p=p;v->rules.n=z;}
   int x=walk(v,p,z,depth+1);if(x)return x;
  }
  p+=z;n-=z;
 }return 0;
}
static int alpha2(uint8_t a,uint8_t b){return (a=='0'&&b=='0')||(a>='A'&&a<='Z'&&b>='A'&&b<='Z');}
static int valid_mac(const uint8_t *p){unsigned x=0;for(unsigned i=0;i<6;i++)x|=p[i];return x&&!(p[0]&1);}
static int regulatory(struct qcc2072_wmi *w,const struct parsed *v){
 const uint8_t *p=v->fixed.p;if(v->fixed.n<312||!v->rules.p)return QCC2072_BAD_WIRE;
 if(le32(p))return QCC2072_PEER_FAILED;
 if(!alpha2(p[8],p[9])||le32(p+8)>0xffff||le32(p+12)!=1)return QCC2072_RUNTIME_UNSUPPORTED;
 unsigned n2=le32(p+48),n5=le32(p+52),total=n2+n5;
 if(n2>10||n5>10||!total)return QCC2072_BAD_WIRE;
 for(unsigned i=252;i<312;i+=4){unsigned z=le32(p+i);if(z>5)return QCC2072_BAD_WIRE;total+=z;}
 if(v->rules.n!=(size_t)total*20)return QCC2072_BAD_WIRE;
 struct qcc2072_wmi_reg_rule rules[20];zero(rules,sizeof(rules));
 for(unsigned i=0;i<total;i++){
  const uint8_t *r=v->rules.p+i*20;
  if(le32(r)!=(937U<<16|16U))return QCC2072_BAD_WIRE;
  unsigned start=le32(r+4)&0xffff,end=le32(r+4)>>16,bw=le32(r+8)&0xffff;
  if(start>=end||start<2300||end>7200||!bw||bw>320)return QCC2072_BAD_WIRE;
  if(i<n2+n5){rules[i].start_mhz=(uint16_t)start;rules[i].end_mhz=(uint16_t)end;rules[i].max_bw_mhz=(uint16_t)bw;
   rules[i].flags=(uint16_t)le32(r+12);rules[i].power_dbm=(uint8_t)(le32(r+8)>>16);rules[i].antenna_gain=(uint8_t)(le32(r+8)>>24);}
 }
 copy(w->reg_rules,rules,sizeof(rules));w->reg_rule_count=n2+n5;w->reg_phy_id=le32(p+4);w->country[0]=p[8];w->country[1]=p[9];w->reg_seen=1;w->reg_revision++;return 0;
}
/* WMI_REG_CHAN_LIST_CC_EVENT (0x3a001, tag 609), the form the A16's firmware sends:
 * 14 fixed words, then WMI_TAG_REGULATORY_RULE_STRUCT (608) rules of 16 bytes:
 * freq start|end<<16, max_bw|power<<16|gain<<24, flags (NO_IR 2, RADAR 8). */
static int regulatory_cc(struct qcc2072_wmi *w,const struct parsed *v){
 const uint8_t *p=v->fixed.p;if(v->fixed.n<56||!v->rules.p)return QCC2072_BAD_WIRE;
 if(le32(p))return QCC2072_PEER_FAILED;
 if(!alpha2(p[8],p[9])||le32(p+8)>0xffff||le32(p+12)!=1)return QCC2072_RUNTIME_UNSUPPORTED;
 unsigned n2=le32(p+48),n5=le32(p+52),total=n2+n5;
 if(n2>10||n5>10||!total||v->rules.n!=(size_t)total*16)return QCC2072_BAD_WIRE;
 struct qcc2072_wmi_reg_rule rules[20];zero(rules,sizeof(rules));
 for(unsigned i=0;i<total;i++){
  const uint8_t *r=v->rules.p+i*16;
  if(le32(r)!=(608U<<16|12U))return QCC2072_BAD_WIRE;
  unsigned start=le32(r+4)&0xffff,end=le32(r+4)>>16,bw=le32(r+8)&0xffff;
  if(start>=end||start<2300||end>7200||!bw||bw>320)return QCC2072_BAD_WIRE;
  rules[i].start_mhz=(uint16_t)start;rules[i].end_mhz=(uint16_t)end;rules[i].max_bw_mhz=(uint16_t)bw;
  rules[i].flags=(uint16_t)le32(r+12);rules[i].power_dbm=(uint8_t)(le32(r+8)>>16);rules[i].antenna_gain=(uint8_t)(le32(r+8)>>24);
 }
 copy(w->reg_rules,rules,sizeof(rules));w->reg_rule_count=total;w->reg_phy_id=le32(p+4);w->country[0]=p[8];w->country[1]=p[9];w->reg_seen=1;w->reg_revision++;return 0;
}
static int management(const struct parsed *v,struct qcc2072_wmi_event *out){
 const uint8_t *h=v->fixed.p,*p=v->bytes.p;if(v->fixed.n<68||!p)return QCC2072_BAD_WIRE;
 unsigned n=le32(h+16),status=le32(h+20),channel=le32(h),freq=le32(h+64);
 if(n>v->bytes.n||v->bytes.n-n>3)return QCC2072_BAD_WIRE;
 /* The 0-3 alignment bytes after the frame are not zeroed by the A16's firmware (ath12k
  * ignores them), so only the length is checked. */
 if(status||n<24){out->kind=QCC2072_WMI_EVENT_NONE;return 0;} /* damaged air frame, not a transport failure */
 unsigned fc=le16(p),sub=fc&0x00fc;
 /* Connect-path frames (auth, (re)assoc response, deauth, disassoc) are surfaced whole for
  * qcc2072_assoc_wmi_event (re/assoc); the consumer checks addresses and subtype rules. */
 if(sub==0xb0||sub==0x10||sub==0x30||sub==0xc0||sub==0xa0){
  out->kind=QCC2072_WMI_EVENT_MGMT;out->mgmt_subtype=sub;out->frame_length=n;
  out->snr=le32(h+4);out->rate=le32(h+8);out->raw_rssi=(int32_t)le32(h+44);out->flags=le32(h+40);out->pdev_id=le32(h+60);
  return 0;
 }
 if((fc&0x00fc)!=0x80&&(fc&0x00fc)!=0x50){out->kind=QCC2072_WMI_EVENT_NONE;return 0;}
 if((fc&0xc703)||n<36||(le16(p+22)&15)||!valid_mac(p+16))return 0;
 unsigned expected=channel==14?2484:channel>=1&&channel<=13?2407+channel*5:channel>=36&&channel<=177?5000+channel*5:0;
 if(!expected||freq!=expected)return 0;
 struct snap_station_bss *b=&out->bss;size_t z=n-36;if(z>sizeof(b->ies))return 0;
 unsigned ssids=0;for(size_t i=36;i<n;){if(n-i<2||p[i+1]>n-i-2)return 0;
  unsigned id=p[i],len=p[i+1];i+=2;
  if(!id){if(++ssids!=1||len>32)return 0;b->ssid_length=(uint8_t)len;copy(b->ssid,p+i,len);}
  if(id==3&&(len!=1||p[i]!=channel))return 0;
  i+=len;
 }
 if(ssids!=1)return 0;
 copy(b->bssid,p+16,6);b->frequency_mhz=(uint16_t)freq;b->beacon_interval_tu=le16(p+32);b->capability=le16(p+34);
 b->observed=SNAP_STATION_BSS_INTERVAL|SNAP_STATION_BSS_CAPABILITY;b->ie_length=(uint16_t)z;copy(b->ies,p+36,z);
 out->snr=le32(h+4);out->rate=le32(h+8);out->raw_rssi=(int32_t)le32(h+44);out->flags=le32(h+40);out->pdev_id=le32(h+60);
 out->beacon_tsf=(uint64_t)le32(p+24)|(uint64_t)le32(p+28)<<32;out->kind=QCC2072_WMI_EVENT_BSS;return 0;
}
int qcc2072_wmi_receive(struct qcc2072_wmi *w,uint64_t g,uint64_t owner,uint64_t now,uint16_t service,const void *bytes,size_t n,struct qcc2072_wmi_event *out){
 if(!w||!bytes||!out||overlap(w,sizeof(*w),bytes,n)||overlap(w,sizeof(*w),out,sizeof(*out))||overlap(bytes,n,out,sizeof(*out)))return QCC2072_INVALID_ARGUMENT;
 zero(out,sizeof(*out));int x=check(w,now);if(x)return x;
 if(g!=w->generation||owner!=w->owner_cookie)return fail(w,QCC2072_SESSION_STALE);
 if(service!=0x100)return fail(w,QCC2072_FOREIGN_PEER);
 const uint8_t *p=bytes;if(n<4||n>2040||le32(p)&0xff000000U)return fail(w,QCC2072_BAD_WIRE);
 unsigned id=le32(p),tag=0;
 switch(id){case 1:tag=32;break;case 2:tag=35;break;case 3:tag=559;break;case 0x4009:tag=428;break;case 0x4022:tag=820;break;case 0x3a003:tag=938;break;case 0x3a001:tag=609;break;case 0x7001:tag=44;break;case 0x3001:tag=36;break;
  /* connect path (re/assoc): VDEV_START_RESP, VDEV_STOPPED, INSTALL_KEY_COMPLETE, PEER_STA_KICKOUT,
   * PEER_ASSOC_CONF, PEER_DELETE_RESP, MGMT_TX_COMPLETION, ROAM */
  case 0x5001:tag=40;break;case 0x5002:tag=41;break;case 0x5003:tag=42;break;case 0x6001:tag=43;break;
  case 0x6006:tag=434;break;case 0x6007:tag=451;break;case 0x7006:tag=423;break;case 0xb001:tag=48;break;default:break;}
 struct parsed v={0};v.fixed_tag=tag;x=walk(&v,p+4,n-4,0);if(x)return fail(w,x);out->id=id;
 if(!tag){w->unknown_events++;out->kind=QCC2072_WMI_EVENT_UNKNOWN;return 0;}
 if(!v.fixed.p)return fail(w,QCC2072_BAD_WIRE);p=v.fixed.p;
 switch(id){
 case 1:
  if(w->service_seen||w->state>=QCC2072_WMI_WAIT_READY)return fail(w,QCC2072_BAD_STATE);
  if(v.fixed.n<128||v.bitmap.n!=128||!v.bitmap.p)return fail(w,QCC2072_BAD_WIRE);
  if(le32(p+72))return fail(w,QCC2072_RUNTIME_UNSUPPORTED);
  if(!le32(p+36)||le32(p+36)>4||!le32(p+76)||le32(p+76)>512)return fail(w,QCC2072_BAD_WIRE);
  for(unsigned i=0;i<32;i++)if(le32(v.bitmap.p+i*4)&~15U)return fail(w,QCC2072_BAD_WIRE);
  for(unsigned i=0;i<128;i++)if(le32(v.bitmap.p+(i/4)*4)&(1U<<(i%4)))w->services[i/32]|=1U<<(i%32);
  w->fw_build=le32(p);w->rf_chains=le32(p+36);w->max_scan_channels=le32(p+76);w->default_hw_mode=le32(p+120);w->service_seen=1;progress(w);break;
 case 3:{
  if(v.fixed.n!=20||w->state>=QCC2072_WMI_WAIT_READY)return fail(w,QCC2072_BAD_STATE);
  unsigned off=le32(p);if(off<128||off>384||off%128)return fail(w,QCC2072_BAD_WIRE);
  unsigned segment=1U<<(off/128);if(w->available_segments&segment)return fail(w,QCC2072_DUPLICATE);
  for(unsigned i=0;i<4;i++)w->services[off/32+i]=le32(p+4+i*4);w->available_segments|=segment;progress(w);break;}
 case 0x4009:
  if(!w->service_seen||w->ext_seen||w->state>=QCC2072_WMI_WAIT_READY||!bit(w,77))return fail(w,QCC2072_BAD_STATE);
  if(v.fixed.n<76)return fail(w,QCC2072_BAD_WIRE);w->ext_seen=1;progress(w);break;
 case 0x4022:
  if(!w->ext_seen||w->ext2_seen||w->state>=QCC2072_WMI_WAIT_READY||!bit(w,220))return fail(w,QCC2072_BAD_STATE);
  if(v.fixed.n<52)return fail(w,QCC2072_BAD_WIRE);w->peer_metadata_version=le32(p+28)&3;w->ext2_seen=1;progress(w);break;
 case 2:
  if(w->state!=QCC2072_WMI_WAIT_READY||w->ready_seen)return fail(w,QCC2072_BAD_STATE);
  if(v.fixed.n<52)return fail(w,QCC2072_BAD_WIRE);if(le32(p+32))return fail(w,QCC2072_PEER_FAILED);
  if(!valid_mac(p+24))return fail(w,QCC2072_BAD_WIRE);copy(w->mac,p+24,6);w->ready_seen=1;w->state=QCC2072_WMI_READY;break;
 case 0x3a003:
  if(!w->service_seen)return fail(w,QCC2072_BAD_STATE);x=regulatory(w,&v);if(x)return fail(w,x);out->kind=QCC2072_WMI_EVENT_REGULATORY;return 0;
 case 0x3a001:
  if(!w->service_seen)return fail(w,QCC2072_BAD_STATE);x=regulatory_cc(w,&v);if(x)return fail(w,x);out->kind=QCC2072_WMI_EVENT_REGULATORY;return 0;
 case 0x7001:
  if(w->state!=QCC2072_WMI_READY)return fail(w,QCC2072_BAD_STATE);x=management(&v,out);if(x)return fail(w,x);
  if(out->kind==QCC2072_WMI_EVENT_MGMT)out->frame_offset=(uint32_t)(v.bytes.p-(const uint8_t *)bytes);
  return 0;
 case 0x5001:case 0x5002:case 0x5003:case 0x6001:case 0x6006:case 0x6007:case 0x7006:case 0xb001:{
  /* ath12k min_len of each fixed TLV; the payload is decoded by qcc2072_assoc_wmi_event. */
  unsigned need=id==0x5001?40:id==0x5002?4:id==0x5003?24:id==0x6001?16:id==0x7006?20:12;
  if(w->state!=QCC2072_WMI_READY)return fail(w,QCC2072_BAD_STATE);
  if(v.fixed.n<need)return fail(w,QCC2072_BAD_WIRE);
  out->kind=QCC2072_WMI_EVENT_STATION;out->vdev_id=id==0x6001||id==0x7006?0xffffffffU:le32(p);return 0;}
 case 0x3001:
  if(w->state!=QCC2072_WMI_READY||v.fixed.n<28)return fail(w,QCC2072_BAD_STATE);
  out->kind=QCC2072_WMI_EVENT_SCAN;out->scan_type=le32(p);out->scan_reason=le32(p+4);out->scan_frequency=le32(p+8);out->scan_request_id=le32(p+12);out->scan_id=le32(p+16);out->vdev_id=le32(p+20);out->scan_tsf=le32(p+24);return 0;
 default:return fail(w,QCC2072_BAD_STATE);
 }
 out->kind=QCC2072_WMI_EVENT_BOOT;return 0;
}
int qcc2072_wmi_init_command(struct qcc2072_wmi *w,uint64_t now,void *out,size_t cap,size_t *n){
 if(!n||!w||overlap(w,sizeof(*w),n,sizeof(*n)))return QCC2072_INVALID_ARGUMENT;*n=0;int x=check(w,now);if(x)return x;
 if(w->state!=QCC2072_WMI_INIT_ELIGIBLE)return QCC2072_BAD_STATE;
 if(w->config.admit_datapath(w->config.context,w->generation,w->owner_cookie))return QCC2072_BAD_STATE;
 if(!out||overlap(w,sizeof(*w),out,cap)||overlap(n,sizeof(*n),out,cap))return QCC2072_INVALID_ARGUMENT;
 if(cap<332)return QCC2072_OUTPUT_TOO_SMALL;
 uint8_t *p=out;zero(p,332);put32(p,1);put32(p+4,74U<<16|28U);uint8_t *r=p+36;put32(r,75U<<16|288U);
 static const uint16_t values[][2]={{4,4},{8,16},{12,3},{16,3},{20,2},{24,32},{28,16},{40,100},{44,100},{48,100},{52,40},{56,1},{60,4},{64,3},{68,3},{72,8},{88,1024},{112,2},{116,1024},{120,10},{124,1},{128,8},{132,2},{136,32},{140,22},{216,1},{228,1}};
 for(unsigned i=0;i<sizeof(values)/sizeof(values[0]);i++)put32(r+values[i][0],values[i][1]);
 put32(r+32,(1U<<w->rf_chains)-1);put32(r+36,(1U<<w->rf_chains)-1);put32(r+176,(1U<<5)|(1U<<18));
 unsigned metadata=bit(w,365)?2:w->peer_metadata_version;
 put32(r+272,metadata<<4|(1U<<9)|(1U<<18)|(bit(w,421)?1U<<22:0));put32(r+276,bit(w,281)?1U<<4:0);
 put32(p+328,18U<<16);*n=332;w->state=QCC2072_WMI_WAIT_READY;w->deadline_ms=now+w->timeout_ms;return 0;
}
int qcc2072_wmi_poll(struct qcc2072_wmi *w,uint64_t now){return check(w,now);}
int qcc2072_wmi_snapshot(const struct qcc2072_wmi *w,struct snap_station_ready *out){
 if(!w||!out||overlap(w,sizeof(*w),out,sizeof(*out)))return QCC2072_INVALID_ARGUMENT;zero(out,sizeof(*out));
 if(w->state==QCC2072_WMI_QUARANTINE)return QCC2072_QUARANTINED;
 if(w->config.validate_owner(w->config.context,w->generation,w->owner_cookie))return QCC2072_SESSION_STALE;
 out->generation=w->generation;
 if(w->service_seen&&(!bit(w,77)||w->ext_seen)&&(!bit(w,220)||w->ext2_seen))out->observed|=SNAP_STATION_READY_SERVICE;
 if(w->ready_seen){out->observed|=SNAP_STATION_READY_WMI_READY|SNAP_STATION_READY_MAC;copy(out->mac,w->mac,6);}
 if(w->reg_seen){out->observed|=SNAP_STATION_READY_REGULATORY;copy(out->country,w->country,2);}return 0;
}
int qcc2072_wmi_abort(struct qcc2072_wmi *w,int reason){if(!w)return QCC2072_INVALID_ARGUMENT;return fail(w,reason?reason:QCC2072_QUARANTINED);}

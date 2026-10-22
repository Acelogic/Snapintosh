/* SPDX-License-Identifier: MIT */
/* Independent QRTR framing and exact WLFW discovery; no Linux implementation copied. */
#include "qcc2072-qrtr.h"
static uint32_t u32(const uint8_t *p){return (uint32_t)p[0]|(uint32_t)p[1]<<8|(uint32_t)p[2]<<16|(uint32_t)p[3]<<24;}
static uint32_t u16(const uint8_t *p){return (uint32_t)p[0]|(uint32_t)p[1]<<8;}
static void put(uint8_t *p,uint32_t x){for(unsigned i=0;i<4;i++)p[i]=(uint8_t)(x>>(8*i));}
static void clear(void *v,size_t n){uint8_t *p=v;for(size_t i=0;i<n;i++)p[i]=0;}
static int fail(struct qcc2072_qrtr *q,int why){q->quarantined=1;return why;}
static int frame(uint32_t type,uint32_t sn,uint32_t sp,uint32_t dn,uint32_t dp,uint32_t confirm,
                 const uint8_t *data,size_t n,uint8_t *out,size_t cap,size_t *written){
    size_t pad=(n+3U)&~(size_t)3;
    if(!out||!written||!data||!n||n>8192-32)return QCC2072_INVALID_ARGUMENT;
    if(cap<32+pad)return QCC2072_OUTPUT_TOO_SMALL;
    uintptr_t a=(uintptr_t)data,b=(uintptr_t)out;
    if(a>UINTPTR_MAX-n||b>UINTPTR_MAX-(32+pad)||(a<b+32+pad&&b<a+n))return QCC2072_INVALID_ARGUMENT;
    put(out,1);put(out+4,type);put(out+8,sn);put(out+12,sp);put(out+16,confirm);put(out+20,(uint32_t)n);put(out+24,dn);put(out+28,dp);
    for(size_t i=0;i<n;i++)out[32+i]=data[i];for(size_t i=n;i<pad;i++)out[32+i]=0;*written=32+pad;return 0;
}
int qcc2072_qrtr_init(struct qcc2072_qrtr *q,uint32_t node,uint32_t port,uint64_t gen,uint64_t owner){
    if(!q||node>=QCC2072_QRTR_CTRL||!port||port>=0xffffU||!gen||!owner)return QCC2072_INVALID_ARGUMENT;
    clear(q,sizeof(*q));q->local_node=node;q->local_port=port;q->generation=gen;q->owner_cookie=owner;return 0;
}
int qcc2072_qrtr_hello(struct qcc2072_qrtr *q,void *out,size_t cap,size_t *written){
    uint8_t body[20]={0};int x;
    if(!q||q->quarantined||q->hello_sent)return QCC2072_BAD_STATE;
    put(body,2);x=frame(2,q->local_node,QCC2072_QRTR_CTRL,QCC2072_QRTR_BROADCAST,QCC2072_QRTR_CTRL,0,body,20,out,cap,written);
    if(!x)q->hello_sent=1;return x;
}
int qcc2072_qrtr_send(struct qcc2072_qrtr *q,const void *data,size_t n,void *out,size_t cap,size_t *written){
    if(!q||q->quarantined||!q->hello_sent||!q->service_present)return QCC2072_BAD_STATE;
    if(q->pending_tx>=10)return QCC2072_RUNTIME_FULL;
    int x=frame(1,q->local_node,q->local_port,q->remote_node,q->remote_port,q->pending_tx==4,data,n,out,cap,written);
    if(!x)q->pending_tx++;return x;
}
int qcc2072_qrtr_receive(struct qcc2072_qrtr *q,uint64_t gen,uint64_t owner,
                         const void *bytes,size_t len,struct qcc2072_qrtr_message *out){
    const uint8_t *p=bytes,*body;size_t hdr,n;uint32_t type,sn,sp,dn,dp,confirm;int x;
    if(!q||!p||!out)return QCC2072_INVALID_ARGUMENT;
    if(q->quarantined)return QCC2072_QUARANTINED;
    if(gen!=q->generation||owner!=q->owner_cookie)return fail(q,QCC2072_SESSION_STALE);
    if(!q->hello_sent)return QCC2072_BAD_STATE;
    if(!len||len>8192||(len&3))return fail(q,QCC2072_BAD_WIRE);
    if(p[0]==1){
        if(len<32||u32(p)!=1)return fail(q,QCC2072_BAD_WIRE);
        hdr=32;type=u32(p+4);sn=u32(p+8);sp=u32(p+12);confirm=u32(p+16);n=u32(p+20);dn=u32(p+24);dp=u32(p+28);
        if(confirm>1)return fail(q,QCC2072_BAD_WIRE);
    }else if(p[0]==3){
        if(len<16||(p[2]&~1U))return fail(q,QCC2072_BAD_WIRE);
        hdr=16U+p[3];type=p[1];confirm=p[2]&1;n=u32(p+4);sn=u16(p+8);sp=u16(p+10);dn=u16(p+12);dp=u16(p+14);
        if(sp==0xfffeU)sp=QCC2072_QRTR_CTRL;if(dp==0xfffeU)dp=QCC2072_QRTR_CTRL;
        if(dn==0xffffU)dn=QCC2072_QRTR_BROADCAST;
    }else return fail(q,QCC2072_BAD_WIRE);
    if(dp==0xffffU)dp=QCC2072_QRTR_CTRL;
    if(!n||hdr>len||n>len-hdr||((n+3)&~(size_t)3)!=len-hdr)return fail(q,QCC2072_BAD_WIRE);
    if(sn>=QCC2072_QRTR_CTRL||sn==q->local_node||(dn!=q->local_node&&dn!=QCC2072_QRTR_BROADCAST))return QCC2072_FOREIGN_PEER;
    if(q->remote_known&&sn!=q->remote_node)return QCC2072_FOREIGN_PEER;
    body=p+hdr;clear(out,sizeof(*out));out->node=sn;out->port=sp;
    if(type==1){
        if(!q->service_present||sp!=q->remote_port||dn!=q->local_node||dp!=q->local_port)return QCC2072_FOREIGN_PEER;
        if(confirm){
            uint8_t reply[20]={0};put(reply,7);put(reply+4,q->local_node);put(reply+8,q->local_port);
            x=frame(7,q->local_node,q->local_port,sn,sp,0,reply,20,out->reply,sizeof(out->reply),&out->reply_length);
            if(x)return fail(q,x);
        }
        out->data.bytes=body;out->data.length=n;return 0;
    }
    if(type==7){
        /* RESUME_TX is keyed by its body's client, as in Linux qrtr_tx_resume. The A16's
         * firmware sends it control port to control port; Linux peers use the data ports. */
        int ports=(sp==q->remote_port&&dp==q->local_port)||(sp==QCC2072_QRTR_CTRL&&dp==QCC2072_QRTR_CTRL);
        if(!q->service_present||!ports||n!=20||u32(body)!=7||u32(body+4)!=q->remote_node||u32(body+8)!=q->remote_port)return QCC2072_FOREIGN_PEER;
        q->pending_tx=0;return 0;
    }
    if(sp!=QCC2072_QRTR_CTRL||dp!=QCC2072_QRTR_CTRL||confirm||n!=20||u32(body)!=type)return fail(q,QCC2072_BAD_WIRE);
    if(type==2){q->remote_node=sn;q->remote_known=1;return 0;}
    if(type==4){
        if(u32(body+4)!=QCC2072_QRTR_WLFW||u32(body+8)!=QCC2072_QRTR_WLFW_INSTANCE)return 0;
        uint32_t node=u32(body+12),port=u32(body+16);
        if(node!=sn||!port||port>=QCC2072_QRTR_CTRL)return fail(q,QCC2072_BAD_WIRE);
        if(q->service_present){if(q->remote_port==port)return 0;return fail(q,QCC2072_DUPLICATE);}
        q->remote_node=node;q->remote_port=port;q->remote_known=q->service_present=1;out->service_arrived=1;return 0;
    }
    if(type==5){
        if(u32(body+4)==QCC2072_QRTR_WLFW&&u32(body+8)==QCC2072_QRTR_WLFW_INSTANCE&&
           u32(body+12)==q->remote_node&&u32(body+16)==q->remote_port&&q->service_present){q->service_present=0;out->service_departed=1;return fail(q,QCC2072_PEER_FAILED);}
        return 0;
    }
    if(type==3||type==8){out->service_departed=q->service_present;q->service_present=0;return fail(q,QCC2072_PEER_FAILED);}
    if(type==6||type==9||type==10||type==11)return 0;
    return fail(q,QCC2072_RUNTIME_UNSUPPORTED);
}

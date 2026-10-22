/* SPDX-License-Identifier: MIT */
#include "sep-sks-endpoint.h"

static void copy_state(struct sep_sks_endpoint *to,const struct sep_sks_endpoint *from)
{
    volatile uint8_t *out=(volatile uint8_t *)to;
    const uint8_t *in=(const uint8_t *)from;
    for(unsigned i=0;i<sizeof(*to);i++)out[i]=in[i];
}
static int equal_wire(const struct sep_sks_wire_state *a,const struct sep_sks_wire_state *b)
{
    const uint8_t *x=(const uint8_t *)a,*y=(const uint8_t *)b;
    for(unsigned i=0;i<sizeof(*a);i++)if(x[i]!=y[i])return 0;
    return 1;
}
static int address(uint64_t value)
{
    return value && !(value&0x3fff) && value<(1UL<<44) &&
           SEP_SKS_BUFFER_BYTES<=(1UL<<44)-value;
}
static int query(uint64_t request)
{
    /* Query byte1 is a seven-bit command plus reply bit; byte2 is the
     * eight-bit sequence. Control negotiation uses a different layout. */
    return (request&0xff)==SEP_SKS_ENDPOINT && !(request&0x8000) &&
           !((request>>24)&0xffffff);
}
static int wire_valid(const struct sep_sks_wire_state *wire)
{
    if(wire->environment_valid>1 || (!!wire->updates)!=wire->environment_valid)return 0;
    if(!wire->environment_valid)return 1;
    const uint8_t *p=wire->environment;
    return p[0]==1 && !p[1] && !p[2] && !p[3] &&
           (p[8]==4 || p[8]==6) && !p[9] && !p[10] && !p[11];
}
static int pages_valid(const struct sep_sks_endpoint *s)
{
    uint64_t seen[2*SEP_SKS_PAGES];unsigned count=0;
    for(unsigned d=0;d<2;d++)for(unsigned i=0;i<SEP_SKS_PAGES;i++) {
        uint64_t pa=s->physical[d][i];
        if(s->stage[d]!=2) {if(pa)return 0;continue;}
        if(!pa || (pa&0x3fff))return 0;
        for(unsigned j=0;j<count;j++)if(seen[j]==pa)return 0;
        seen[count++]=pa;
    }
    return 1;
}
static int reply_shape(uint64_t request,uint64_t reply)
{
    if((reply&0xffffff)!=((request&0xffffff)|0x8000) || ((reply>>32)&0xffff))return 0;
    unsigned status=(reply>>24)&255,length=reply>>48,command=(request>>8)&127;
    if(status>SEP_SKS_BAD_STATE)return 0;
    if(status)return length==0;
    return command==SEP_SKS_GET_CAPABILITIES ? length==92 || length==100 :
        command==SEP_SKS_SET_ENVIRONMENT && (length==80 || length==88);
}
int sep_sks_endpoint_valid(const struct sep_sks_endpoint *s)
{
    if(!s || s->ready>1 || s->advertisements!=2*s->ready || !wire_valid(&s->wire))return 0;
    if(s->wire.updates>s->queries)return 0;
    if(!s->ready && (s->negotiations || s->queries || s->last_request || s->last_reply))return 0;
    for(unsigned d=0;d<2;d++) {
        if(s->stage[d]>2 || (!s->ready && s->stage[d]))return 0;
        if(s->size[d]!=(s->stage[d] ? SEP_SKS_BUFFER_BYTES : 0))return 0;
        if(s->stage[d]==2 ? !address(s->iova[d]) : !!s->iova[d])return 0;
    }
    if(!pages_valid(s) || s->negotiations<s->stage[0]+s->stage[1])return 0;
    if(s->stage[0]==2 && s->stage[1]==2 &&
       s->iova[0]<s->iova[1]+SEP_SKS_BUFFER_BYTES && s->iova[1]<s->iova[0]+SEP_SKS_BUFFER_BYTES)return 0;
    if(s->queries && (s->stage[0]!=2 || s->stage[1]!=2))return 0;
    if(!s->negotiations && !s->queries)return !s->last_request && !s->last_reply;
    uint64_t request=s->last_request;
    if(query(request))return s->queries && request>>48<=SEP_SKS_BUFFER_BYTES && reply_shape(request,s->last_reply);
    unsigned op=(request>>16)&255,d=op&1;
    if((request&0xff0000ffUL)!=((uint64_t)SEP_SKS_ENDPOINT<<24) || !(request&0xff00) ||
       op<2 || op>5 || !s->negotiations || s->last_reply!=(request&~0xff000000UL))return 0;
    return op>=4 ? s->stage[d]>=1 && request>>32==SEP_SKS_BUFFER_BYTES :
        s->stage[d]==2 && (request>>32)<<12==s->iova[d];
}
enum sep_sks_endpoint_result sep_sks_endpoint_step(struct sep_sks_endpoint *s,
    const struct sep_sks_endpoint_io *io,uint64_t request,uint64_t *reply)
{
    if(!reply || !sep_sks_endpoint_valid(s) || !s->ready)return SEP_SKS_ENDPOINT_BAD_STATE;
    struct sep_sks_endpoint next;copy_state(&next,s);
    if(query(request)) {
        if(s->stage[0]!=2 || s->stage[1]!=2 || s->queries==UINT64_MAX ||
           request>>48>SEP_SKS_BUFFER_BYTES)return SEP_SKS_ENDPOINT_BAD_REQUEST;
        if(!io || !io->prepare || !io->publish)return SEP_SKS_ENDPOINT_RESOURCE;
        uint8_t payload[SEP_SKS_REPLY_BYTES],status=255;
        uint16_t length=UINT16_MAX;
        unsigned command=(request>>8)&127;
        if(!io->prepare(io->context,s,command,request>>48,&next.wire,payload,&length,&status))
            return SEP_SKS_ENDPOINT_RESOURCE;
        next.queries++;next.last_request=request;
        next.last_reply=(request&0xffffff)|0x8000|((uint64_t)status<<24)|((uint64_t)length<<48);
        if(length>SEP_SKS_REPLY_BYTES || !reply_shape(request,next.last_reply))return SEP_SKS_ENDPOINT_RESOURCE;
        if(status || command==SEP_SKS_GET_CAPABILITIES) {
            if(!equal_wire(&s->wire,&next.wire))return SEP_SKS_ENDPOINT_RESOURCE;
        } else if(s->wire.updates==UINT64_MAX || next.wire.updates!=s->wire.updates+1)
            return SEP_SKS_ENDPOINT_RESOURCE;
        if(!sep_sks_endpoint_valid(&next))return SEP_SKS_ENDPOINT_RESOURCE;
        if(!io->publish(io->context,s,payload,length))return SEP_SKS_ENDPOINT_RESOURCE;
        copy_state(s,&next);*reply=next.last_reply;return SEP_SKS_ENDPOINT_OK;
    }
    unsigned op=(request>>16)&255,d=op&1;
    if((request&0xff0000ffUL)!=((uint64_t)SEP_SKS_ENDPOINT<<24) ||
       !(request&0xff00) || op<2 || op>5)return SEP_SKS_ENDPOINT_UNKNOWN;
    if(s->negotiations==UINT64_MAX)return SEP_SKS_ENDPOINT_BAD_REQUEST;
    if(op>=4) {
        if(request>>32!=SEP_SKS_BUFFER_BYTES)return SEP_SKS_ENDPOINT_BAD_REQUEST;
        next.size[d]=SEP_SKS_BUFFER_BYTES;
        if(!next.stage[d])next.stage[d]=1;
    } else {
        uint64_t iova=(request>>32)<<12;
        if(!s->stage[d] || !address(iova) || (s->stage[d]==2 && iova!=s->iova[d]))
            return SEP_SKS_ENDPOINT_BAD_REQUEST;
        unsigned other=d^1;
        if(s->stage[other]==2 && iova<s->iova[other]+SEP_SKS_BUFFER_BYTES &&
           s->iova[other]<iova+SEP_SKS_BUFFER_BYTES)return SEP_SKS_ENDPOINT_BAD_REQUEST;
        if(!io || !io->bind || !io->bind(io->context,s,d,iova,SEP_SKS_BUFFER_BYTES,next.physical[d]))
            return SEP_SKS_ENDPOINT_RESOURCE;
        next.iova[d]=iova;next.stage[d]=2;
        if(!pages_valid(&next))return SEP_SKS_ENDPOINT_RESOURCE;
        if(s->stage[d]==2)for(unsigned i=0;i<SEP_SKS_PAGES;i++)
            if(next.physical[d][i]!=s->physical[d][i])return SEP_SKS_ENDPOINT_RESOURCE;
    }
    next.negotiations++;next.last_request=request;next.last_reply=request&~0xff000000UL;
    copy_state(s,&next);*reply=next.last_reply;return SEP_SKS_ENDPOINT_OK;
}

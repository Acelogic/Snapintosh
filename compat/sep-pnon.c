/* SPDX-License-Identifier: MIT */
#include "sep-pnon.h"

static uint64_t extent(unsigned direction){return direction ? 0x14000 : 0x1c000;}
static void copy_state(struct sep_pnon *dst,const struct sep_pnon *src)
{
    /* Volatile byte stores keep this bounded copy freestanding: a large
     * structure assignment may be lowered to an unavailable libc memcpy. */
    volatile uint8_t *out=(volatile uint8_t *)dst;
    const uint8_t *in=(const uint8_t *)src;
    for(unsigned i=0;i<sizeof(*dst);i++)out[i]=in[i];
}
static int address(uint64_t va,uint64_t size)
{
    return va && !(va&0x3fff) && va<(1UL<<44) && size<=(1UL<<44)-va;
}
static int pages_valid(const struct sep_pnon *s)
{
    uint64_t seen[2*SEP_PNON_PAGES];unsigned count=0;
    for(unsigned d=0;d<2;d++)for(unsigned n=0;n<SEP_PNON_PAGES;n++) {
        uint64_t pa=s->physical[d][n];
        if(s->stage[d]!=2 || n>=s->size[d]/0x4000) {if(pa)return 0;continue;}
        if(!pa || (pa&0x3fff))return 0;
        for(unsigned j=0;j<count;j++)if(seen[j]==pa)return 0;
        seen[count++]=pa;
    }
    return 1;
}
int sep_pnon_valid(const struct sep_pnon *s)
{
    if(!s || s->ready>1 || s->advertisements!=2*s->ready)return 0;
    if(!s->ready && (s->negotiations || s->queries || s->last_request || s->last_reply))return 0;
    for(unsigned d=0;d<2;d++) {
        if(s->stage[d]>2 || (!s->ready && s->stage[d]))return 0;
        if(s->size[d]!=(s->stage[d] ? extent(d) : 0))return 0;
        if(s->stage[d]==2 ? !address(s->iova[d],s->size[d]) : !!s->iova[d])return 0;
    }
    if(!pages_valid(s) || s->negotiations<s->stage[0]+s->stage[1])return 0;
    if(s->stage[0]==2 && s->stage[1]==2 &&
       s->iova[0]<s->iova[1]+s->size[1] && s->iova[1]<s->iova[0]+s->size[0])return 0;
    if(s->queries && (s->stage[0]!=2 || s->stage[1]!=2))return 0;
    if(!s->negotiations && !s->queries)return !s->last_request && !s->last_reply;
    if(sep_pnon_command(s->last_request))
        return s->queries && (s->last_reply==SEP_PNON_REFUSED ||
            (s->last_request==SEP_PNON_QUERY && s->last_reply==SEP_PNON_REPLY));
    uint64_t req=s->last_request,op=(req>>16)&255;
    if((req&0xff0000ff)!=0x01000000 || !(req&0xff00) || op<2 || op>5 ||
       s->last_reply!=(req&~0xff000000UL) || !s->negotiations)return 0;
    unsigned direction=(unsigned)op&1;
    return op>=4 ? s->stage[direction]>=1 && (req>>32)==s->size[direction] :
        s->stage[direction]==2 && (req>>32)<<12==s->iova[direction];
}
enum sep_pnon_result sep_pnon_step(struct sep_pnon *s,const struct sep_pnon_io *io,
                                  uint64_t request,uint64_t *reply)
{
    if(!reply || !sep_pnon_valid(s) || !s->ready)return SEP_PNON_BAD_STATE;
    if(sep_pnon_command(request)) {
        if(s->stage[0]!=2 || s->stage[1]!=2 || s->queries==UINT64_MAX)return SEP_PNON_BAD_REQUEST;
        int length=io && io->query ? io->query(io->ctx,s,request>>32) : 0;
        /* Only an exact 32-byte request may carry the 36-byte OS-type reply. */
        if(length!=32 && (length!=36 || request!=SEP_PNON_QUERY))return SEP_PNON_RESOURCE;
        uint64_t word=length==36 ? SEP_PNON_REPLY : SEP_PNON_REFUSED;
        s->queries++;s->last_request=request;s->last_reply=word;
        *reply=word;return SEP_PNON_OK;
    }
    unsigned op=(unsigned)(request>>16)&255,direction=op&1;
    if((request&0xff0000ff)!=0x01000000 || !(request&0xff00) || op<2 || op>5)
        return SEP_PNON_UNKNOWN;
    if(s->negotiations==UINT64_MAX)return SEP_PNON_BAD_REQUEST;
    struct sep_pnon next;copy_state(&next,s);
    if(op>=4) {
        if(request>>32!=extent(direction))return SEP_PNON_BAD_REQUEST;
        next.size[direction]=extent(direction);
        if(!next.stage[direction])next.stage[direction]=1;
    } else {
        uint64_t iova=(request>>32)<<12,size=s->size[direction];
        if(!s->stage[direction] || !address(iova,size) ||
           (s->stage[direction]==2 && iova!=s->iova[direction]))return SEP_PNON_BAD_REQUEST;
        unsigned other=direction^1;
        if(s->stage[other]==2 && iova<s->iova[other]+s->size[other] &&
           s->iova[other]<iova+size)return SEP_PNON_BAD_REQUEST;
        if(!io || !io->bind || !io->bind(io->ctx,s,direction,iova,size,next.physical[direction]))
            return SEP_PNON_RESOURCE;
        next.iova[direction]=iova;next.stage[direction]=2;
        if(!pages_valid(&next))return SEP_PNON_RESOURCE;
        if(s->stage[direction]==2)for(unsigned n=0;n<SEP_PNON_PAGES;n++)
            if(next.physical[direction][n]!=s->physical[direction][n])return SEP_PNON_RESOURCE;
    }
    /* Request PARAM selects endpoint1; reply PARAM is transaction status.
     * The native _cmsgSend decoder rejects an echoed endpoint as error 1. */
    next.negotiations++;next.last_request=request;next.last_reply=request&~0xff000000UL;
    copy_state(s,&next);*reply=next.last_reply;return SEP_PNON_OK;
}
int sep_pnon_os_type(const uint8_t request[32],uint8_t reply[36])
{
    if(!request || !reply)return 0;
    const uint8_t header[8]={0x68,0x63,0x50,0x42,0x3e,0,0,0};
    for(unsigned i=0;i<32;i++)if(request[i]!=(i<8 ? header[i] : 0))return 0;
    /* 26A428 libbootpolicy requires response magic 0x42507268, status zero,
     * exact length 0x24 and the OS type byte at +0x20. This virtual boot is
     * ordinary recoveryOS (2), not physical-presence/one-true-recovery (1). */
    for(unsigned i=0;i<36;i++)reply[i]=0;
    reply[0]=0x68;reply[1]=0x72;reply[2]=0x50;reply[3]=0x42;
    reply[32]=SEP_PNON_OS_TYPE;return 1;
}
static int not_supported(const uint8_t request[32],uint8_t reply[36])
{
    /* __sep_command writes the magic and the command word, then zeroes 24
     * bytes; any body follows these 32 bytes and is never read here. */
    const uint8_t magic[4]={0x68,0x63,0x50,0x42};
    for(unsigned i=0;i<4;i++)if(request[i]!=magic[i])return 0;
    uint32_t command=(uint32_t)request[4]|(uint32_t)request[5]<<8|
        (uint32_t)request[6]<<16|(uint32_t)request[7]<<24;
    if(!command || command>0xff)return 0;
    for(unsigned i=8;i<32;i++)if(request[i])return 0;
    for(unsigned i=0;i<36;i++)reply[i]=0;
    reply[0]=0x68;reply[1]=0x72;reply[2]=0x50;reply[3]=0x42;
    reply[4]=SEP_PNON_NOT_SUPPORTED;return 32;
}
int sep_pnon_reply(const uint8_t request[32],uint8_t reply[36])
{
    if(!request || !reply)return 0;
    if(sep_pnon_os_type(request,reply))return 36;
    return not_supported(request,reply);
}
int sep_pnon_command(uint64_t request)
{
    uint64_t length=request>>32;
    return (request&0xffffffffUL)==SEP_PNON_COMMAND_KIND &&
        length>=SEP_PNON_REQUEST_MIN && length<=SEP_PNON_REQUEST_MAX;
}
int sep_pnon_reply_sized(const uint8_t request[32],uint64_t length,uint8_t reply[36])
{
    if(!request || !reply || length<SEP_PNON_REQUEST_MIN || length>SEP_PNON_REQUEST_MAX)return 0;
    if(length==SEP_PNON_REQUEST_MIN)return sep_pnon_reply(request,reply);
    /* A body follows the header. No command with a body is implemented, so
     * even command 0x3e gets only the not-supported header here. */
    return not_supported(request,reply);
}
int sep_pnon_refuse_sized(const uint8_t request[32],uint64_t length,uint8_t reply[36])
{
    if(!request || !reply || length<SEP_PNON_REQUEST_MIN || length>SEP_PNON_REQUEST_MAX)return 0;
    return not_supported(request,reply);
}

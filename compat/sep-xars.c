/* SPDX-License-Identifier: MIT */
#include "sep-xars.h"

static void copy_state(struct sep_xars *out, const struct sep_xars *in)
{
    volatile uint8_t *dst=(volatile uint8_t *)out;
    const uint8_t *src=(const uint8_t *)in;
    for(unsigned i=0;i<sizeof(*out);i++)dst[i]=src[i];
}
static int address(uint64_t va)
{
    return va && !(va&0x3fff) && va<(1UL<<44) && SEP_XARS_SIZE<=(1UL<<44)-va;
}
static int query(uint64_t request)
{
    /* Pinned Lynx get-CPSN, get-public-key and get-app-hash builders contain
     * only the opcode; native transport supplies endpoint and nonzero tag. */
    unsigned op=(unsigned)(request>>16)&255;
    return (request&~0xffff00UL)==SEP_XARS_ENDPOINT && (request&0xff00) &&
        (op==0x0a || op==0x0b || op==0x20);
}
static uint64_t refusal(uint64_t request)
{
    return (request&0xffffUL)|((uint64_t)SEP_XARS_STATUS_REFUSED<<16);
}
static int slot_query(uint64_t request)
{
    /* Pinned get_ap_slot_info builder: opcode byte2, slot byte6, nothing else.
     * AppleMobileApNonce iterates only slots 0 and 1; others stay unsupported. */
    return (request&~0x0100000000ff00UL)==((uint64_t)SEP_XARS_SLOT_INFO<<16|SEP_XARS_ENDPOINT) &&
        (request&0xff00);
}
static uint64_t slot_reply(uint64_t request)
{
    return (request&0xffffUL)|((uint64_t)SEP_XARS_SLOT_BYTES<<24)|
        ((uint64_t)SEP_XARS_SLOT_EMPTY<<48);
}
static int epochs_query(uint64_t request)
{
    /* Pinned getFullEpochs builder: opcode byte2 and nothing else. */
    return (request&~0xff00UL)==((uint64_t)SEP_XARS_EPOCHS<<16|SEP_XARS_ENDPOINT) &&
        (request&0xff00);
}
static uint64_t epochs_reply(uint64_t request)
{
    return (request&0xffffUL)|((uint64_t)SEP_XARS_EPOCH_BYTES<<24);
}
static int pages_valid(const struct sep_xars *s)
{
    uint64_t seen[2*SEP_XARS_PAGES];unsigned count=0;
    for(unsigned d=0;d<2;d++)for(unsigned i=0;i<SEP_XARS_PAGES;i++) {
        uint64_t pa=s->physical[d][i];
        if(s->stage[d]!=2) {if(pa)return 0;continue;}
        if(!pa || (pa&0x3fff))return 0;
        for(unsigned n=0;n<count;n++)if(seen[n]==pa)return 0;
        seen[count++]=pa;
    }
    return 1;
}
int sep_xars_valid(const struct sep_xars *s)
{
    if(!s || s->ready>1 || s->advertisements!=2*s->ready)return 0;
    if(!s->ready && (s->negotiations || s->queries || s->last_request || s->last_reply))return 0;
    for(unsigned d=0;d<2;d++) {
        if(s->stage[d]>2 || (!s->ready && s->stage[d]))return 0;
        if(s->size[d]!=(s->stage[d] ? SEP_XARS_SIZE : 0))return 0;
        if(s->stage[d]==2 ? !address(s->iova[d]) : !!s->iova[d])return 0;
    }
    if(!pages_valid(s) || s->negotiations<s->stage[0]+s->stage[1])return 0;
    if(s->stage[0]==2 && s->stage[1]==2 &&
       s->iova[0]<s->iova[1]+SEP_XARS_SIZE && s->iova[1]<s->iova[0]+SEP_XARS_SIZE)return 0;
    if(s->queries && (s->stage[0]!=2 || s->stage[1]!=2))return 0;
    if(!s->negotiations && !s->queries)return !s->last_request && !s->last_reply;
    uint64_t req=s->last_request;
    if(query(req))return s->queries && s->last_reply==refusal(req);
    if(slot_query(req))return s->queries && s->last_reply==slot_reply(req);
    if(epochs_query(req))return s->queries && s->last_reply==epochs_reply(req);
    unsigned op=(unsigned)(req>>16)&255, d=op&1;
    if((req&0xff0000ffUL)!=((uint64_t)SEP_XARS_ENDPOINT<<24) || !(req&0xff00) ||
       op<2 || op>5 || !s->negotiations || s->last_reply!=(req&~0xff000000UL))return 0;
    return op>=4 ? s->stage[d]>=1 && req>>32==SEP_XARS_SIZE :
        s->stage[d]==2 && (req>>32)<<12==s->iova[d];
}
enum sep_xars_result sep_xars_step(struct sep_xars *s,const struct sep_xars_io *io,
                                  uint64_t request,uint64_t *reply)
{
    if(!reply || !sep_xars_valid(s) || !s->ready)return SEP_XARS_BAD_STATE;
    if(query(request)) {
        if(s->stage[0]!=2 || s->stage[1]!=2 || s->queries==UINT64_MAX)return SEP_XARS_BAD_REQUEST;
        if(!io || !io->validate || !io->validate(io->ctx,s))return SEP_XARS_RESOURCE;
        s->queries++;s->last_request=request;s->last_reply=refusal(request);
        *reply=s->last_reply;return SEP_XARS_OK;
    }
    if(slot_query(request) || epochs_query(request)) {
        int slot=slot_query(request);
        if(s->stage[0]!=2 || s->stage[1]!=2 || s->queries==UINT64_MAX)return SEP_XARS_BAD_REQUEST;
        if(!io || !io->slot ||
           !io->slot(io->ctx,s,slot ? SEP_XARS_SLOT_BYTES : SEP_XARS_EPOCH_BYTES))return SEP_XARS_RESOURCE;
        s->queries++;s->last_request=request;
        s->last_reply=slot ? slot_reply(request) : epochs_reply(request);
        *reply=s->last_reply;return SEP_XARS_OK;
    }
    unsigned op=(unsigned)(request>>16)&255,d=op&1;
    if((request&0xff0000ffUL)!=((uint64_t)SEP_XARS_ENDPOINT<<24) ||
       !(request&0xff00) || op<2 || op>5)return SEP_XARS_UNKNOWN;
    if(s->negotiations==UINT64_MAX)return SEP_XARS_BAD_REQUEST;
    struct sep_xars next;copy_state(&next,s);
    if(op>=4) {
        if(request>>32!=SEP_XARS_SIZE)return SEP_XARS_BAD_REQUEST;
        next.size[d]=SEP_XARS_SIZE;
        if(!next.stage[d])next.stage[d]=1;
    } else {
        uint64_t iova=(request>>32)<<12;
        if(!s->stage[d] || !address(iova) || (s->stage[d]==2 && iova!=s->iova[d]))
            return SEP_XARS_BAD_REQUEST;
        unsigned other=d^1;
        if(s->stage[other]==2 && iova<s->iova[other]+SEP_XARS_SIZE &&
           s->iova[other]<iova+SEP_XARS_SIZE)return SEP_XARS_BAD_REQUEST;
        if(!io || !io->bind || !io->bind(io->ctx,s,d,iova,SEP_XARS_SIZE,next.physical[d]))
            return SEP_XARS_RESOURCE;
        next.iova[d]=iova;next.stage[d]=2;
        if(!pages_valid(&next))return SEP_XARS_RESOURCE;
        if(s->stage[d]==2)for(unsigned i=0;i<SEP_XARS_PAGES;i++)
            if(next.physical[d][i]!=s->physical[d][i])return SEP_XARS_RESOURCE;
    }
    next.negotiations++;next.last_request=request;next.last_reply=request&~0xff000000UL;
    copy_state(s,&next);*reply=next.last_reply;return SEP_XARS_OK;
}

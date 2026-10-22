/* SPDX-License-Identifier: MIT */
#include "aes-engine.h"

void aes_engine_init(struct aes_engine *s)
{ if (s) { aes_clear(s,sizeof(*s));s->ready=1; } }
static uint32_t key_bytes(uint32_t header)
{ return 16+8*((header>>22)&3); }
static void bytes_be(uint8_t *out,const uint32_t *words,unsigned n)
{ for (unsigned i=0;i<n;i++) out[i]=(uint8_t)(words[i/4]>>(24-8*(i&3))); }
struct span { volatile uint8_t *p;size_t n; };
#define SPANS (AES_TRANSFER_MAX/0x4000+1)
static int overlap(uintptr_t a,size_t an,uintptr_t b,size_t bn)
{ return a<b+bn && b<a+an; }
static int maps(const struct aes_dma *m,const struct aes_engine *s,uint64_t iova,size_t n,
                int write,struct span *out,unsigned *count)
{
    if (!m || !m->map || !m->publish || !n || iova>=(1UL<<42) || n>(1UL<<42)-iova) return 0;
    *count=0;
    while (n) {
        size_t take=0x4000-(iova&0x3fff);if (take>n) take=n;
        volatile uint8_t *p=m->map(m->ctx,iova,take,write);
        uintptr_t a=(uintptr_t)p,b=(uintptr_t)s;
        if (!p || a>UINTPTR_MAX-take || b>UINTPTR_MAX-sizeof(*s) ||
            overlap(a,take,b,sizeof(*s)) || *count>=SPANS) return 0;
        out[(*count)++]=(struct span){p,take};iova+=take;n-=take;
    }
    return 1;
}
static uint8_t get_byte(const struct span *s,size_t offset)
{ while (offset>=s->n) { offset-=s->n;s++; }return s->p[offset]; }
static void put_byte(const struct span *s,size_t offset,uint8_t value)
{ while (offset>=s->n) { offset-=s->n;s++; }s->p[offset]=value; }
static enum aes_result crypt(struct aes_engine *s,const struct aes_dma *m,uint32_t h,const uint32_t *w)
{
    unsigned ks=(h>>27)&1,is=(h>>25)&3;size_t n=h&0x1ffffff;
    const struct aes_slot *key=&s->keys[ks];
    if (!n || (n&15) || n>AES_TRANSFER_MAX || !key->valid ||
        (key->key.rounds!=10 && key->key.rounds!=12 && key->key.rounds!=14) ||
        key->encrypt>1 || key->mode>2 || (key->mode && !(s->iv_valid&(1U<<is)))) return AES_BAD_STATE;
    /* J700 26A428 _pushCommandBuffer, 0xfffffe00099351c4..51f8:
     * the first low address (source) has its high bits in [25:16]. */
    if (w[0]&~0x03ff03ffU) return AES_UNSUPPORTED;
    uint64_t src=((uint64_t)((w[0]>>16)&0x3ff)<<32)|w[1];
    uint64_t dst=((uint64_t)(w[0]&0x3ff)<<32)|w[2];
    struct span in[SPANS],out[SPANS];unsigned ni,no;
    if (!maps(m,s,src,n,0,in,&ni) || !maps(m,s,dst,n,1,out,&no)) return AES_DMA_REFUSED;
    /* Exact physical in-place is supported even through different IOVAs.
     * Partial overlap or output aliases must not clobber future input. */
    size_t aoff=0;
    for (unsigned a=0;a<no;a++) {
        for (unsigned b=0;b<a;b++)
            if (overlap((uintptr_t)out[a].p,out[a].n,(uintptr_t)out[b].p,out[b].n)) return AES_DMA_REFUSED;
        size_t boff=0;
        for (unsigned b=0;b<ni;b++) {
            if (overlap((uintptr_t)out[a].p,out[a].n,(uintptr_t)in[b].p,in[b].n) &&
                (uintptr_t)out[a].p-aoff!=(uintptr_t)in[b].p-boff) return AES_DMA_REFUSED;
            boff+=in[b].n;
        }
        aoff+=out[a].n;
    }
    uint8_t iv[16],input[16],block[16];
    for (unsigned j=0;j<16;j++) iv[j]=s->iv[is][j];
    for (size_t off=0;off<n;off+=16) {
        for (unsigned j=0;j<16;j++) input[j]=get_byte(in,off+j);
        if (key->mode==2) {
            (void)aes_block(&key->key,iv,block,0);
            for (unsigned j=0;j<16;j++) block[j]^=input[j];
            for (unsigned j=16;j>0;j--) if (++iv[j-1]) break;
        } else {
            for (unsigned j=0;j<16;j++) block[j]=input[j]^((key->mode && key->encrypt) ? iv[j] : 0);
            (void)aes_block(&key->key,block,block,!key->encrypt);
            if (key->mode) for (unsigned j=0;j<16;j++) {
                if (!key->encrypt) block[j]^=iv[j];
                iv[j]=key->encrypt ? block[j] : input[j];
            }
        }
        for (unsigned j=0;j<16;j++) put_byte(out,off+j,block[j]);
    }
    for (unsigned i=0;i<no;i++) m->publish(m->ctx,out[i].p,out[i].n);
    if (key->mode) for (unsigned j=0;j<16;j++) s->iv[is][j]=iv[j];
    s->transfers++;s->bytes+=n;
    aes_clear(iv,sizeof(iv));aes_clear(input,sizeof(input));aes_clear(block,sizeof(block));
    return AES_OK;
}
static enum aes_result get_iv(struct aes_engine *s,const struct aes_dma *m,uint32_t h,uint32_t low)
{
    /* The shipped version-5 driver exports slot zero, 9934e30..9934e60.
     * Other GET_IV encodings remain unsupported until established. */
    if (!(s->iv_valid&1)) return AES_BAD_STATE;
    uint64_t dst=((uint64_t)(h&0x3ff)<<32)|low;
    struct span out[SPANS];unsigned count;
    if (!maps(m,s,dst,16,1,out,&count)) return AES_DMA_REFUSED;
    for (unsigned i=1;i<count;i++)
        if (overlap((uintptr_t)out[0].p,out[0].n,(uintptr_t)out[i].p,out[i].n)) return AES_DMA_REFUSED;
    for (unsigned i=0;i<16;i++) put_byte(out,i,s->iv[0][i]);
    for (unsigned i=0;i<count;i++) m->publish(m->ctx,out[i].p,out[i].n);
    s->iv_exports++;return AES_OK;
}
static unsigned payload_words(uint32_t v)
{
    switch (v>>28) {
    case 1:
        if ((v&~0x18d30000U) || ((v>>22)&3)>2 || ((v>>16)&3)>2) return 0;
        return key_bytes(v)/4;
    case 2:return (v&~0x2c000000U) ? 0 : 4;
    case 5:return (!(v&0x1ffffff) || (v&15) || (v&0x1ffffff)>AES_TRANSFER_MAX) ? 0 : 3;
    case 6:return (v&~0x600003ffU) ? 0 : 1;
    default:return 0;
    }
}
static enum aes_result word(struct aes_engine *s,const struct aes_dma *m,uint32_t v)
{
    if (!s->running) return AES_BAD_STATE;
    if (!s->need) {
        unsigned op=v>>28,need=payload_words(v);
        switch (op) {
        case 1:case 2:case 6:
            if (!need) return AES_UNSUPPORTED;
            break;
        case 5:
            if (!need) return AES_BAD_VALUE;
            break;
        case 8:
            /* performAESQuantum 9934d9c..9934db4 inserts this exact
             * synchronization command before GET_IV. DMA is synchronous
             * and already published, so no work remains to drain. It must
             * not raise FLAG or replace the completion tag. */
            if (v==0x80000100U) {s->commands++;s->barriers++;return AES_OK;}
            if (v&~0x880000ffU) return AES_UNSUPPORTED;
            s->completed_tag=v&0xff;
            if (v&(1U<<27)) s->irq_status|=1U<<5;
            s->commands++;s->barriers++;return AES_OK;
        default:return AES_UNSUPPORTED;
        }
        s->header=v;s->need=need;s->used=0;return AES_OK;
    }
    if (s->used+1<s->need) { s->words[s->used++]=v;return AES_OK; }
    uint32_t words[8];for (unsigned i=0;i<s->used;i++) words[i]=s->words[i];words[s->used]=v;
    enum aes_result result=AES_OK;unsigned op=s->header>>28;
    if (op==1) {
        uint8_t bytes[32];unsigned n=key_bytes(s->header),slot=(s->header>>27)&1;
        bytes_be(bytes,words,n);(void)aes_expand(&s->keys[slot].key,bytes,n);
        s->keys[slot].valid=1;s->keys[slot].encrypt=(s->header>>20)&1;
        s->keys[slot].mode=(s->header>>16)&3;aes_clear(bytes,sizeof(bytes));
    } else if (op==2) {
        unsigned slot=(s->header>>26)&3;bytes_be(s->iv[slot],words,16);s->iv_valid|=1U<<slot;
    } else if (op==5) result=crypt(s,m,s->header,words);
    else if (op==6) result=get_iv(s,m,s->header,words[0]);
    else result=AES_BAD_STATE;
    aes_clear(words,sizeof(words));
    if (result!=AES_OK) return result;
    aes_clear(s->words,sizeof(s->words));s->header=s->need=s->used=0;s->commands++;return AES_OK;
}
enum aes_result aes_engine_access(struct aes_engine *s,const struct aes_dma *m,
    uint64_t off,unsigned width,int write,uint64_t *value)
{
    if (!s || !value || s->ready!=1 || s->running>1 || s->need>8 || s->used>=8 ||
        (s->need && (s->used>=s->need || s->need!=payload_words(s->header) || !s->running)) ||
        (!s->need && (s->used || s->header)) || s->iv_valid>15 || s->completed_tag>255 ||
        (s->irq_status&~0x20U) || (s->irq_enable&~0x3efffU) ||
        (s->threshold && s->threshold!=64)) return AES_BAD_STATE;
    if (width!=4 || (off&3)) return AES_BAD_WIDTH;
    if (write) {
        if (*value>UINT32_MAX) return AES_BAD_VALUE;
        uint32_t v=(uint32_t)*value;
        switch (off) {
        case 8:
            if (v!=1 && v!=2) return AES_UNSUPPORTED;
            if (s->need) return AES_BAD_STATE;
            s->running=v==1;return AES_OK;
        case 0x18:
            if (v&~0x3efffU) return AES_BAD_VALUE;
            s->irq_status&=~v;return AES_OK;
        case 0x1c:
            if (v&~0x3efffU) return AES_BAD_VALUE;
            s->irq_enable=v;return AES_OK;
        case 0x20:
            if (v!=64) return AES_BAD_VALUE;
            s->threshold=v;return AES_OK;
        case 0x200:return word(s,m,v);
        default:return AES_UNKNOWN_REGISTER;
        }
    }
    switch (off) {
    case 0x0c:*value=s->need ? 0 : 0x3f80;return AES_OK;
    case 0x18:*value=s->irq_status;return AES_OK;
    case 0x1c:*value=s->irq_enable;return AES_OK;
    case 0x24:*value=2;return AES_OK; /* FIFO words are synchronously consumed. */
    case 0x30:*value=s->completed_tag;return AES_OK;
    default:return AES_UNKNOWN_REGISTER;
    }
}
int aes_engine_irq(const struct aes_engine *s)
{ return s && s->ready==1 && (s->irq_status&s->irq_enable)!=0; }

/* SPDX-License-Identifier: MIT */
#ifndef SEP_CALLBACKS_H
#define SEP_CALLBACKS_H

#include <stdint.h>
#include <stddef.h>

/* SEP ROM, AES DMA, and SKS mailbox / transport DMA callbacks */
struct sep_rom_dma_context {
    struct context *c;enum sptm_result refusal;
    unsigned index,pnon_refusal;uint64_t shared_iova,shared_size;
    const struct device_sep_asc *asc;
    uint64_t sks_translations;
    unsigned sks_prepared;
};
static int sep_rom_admit(void *opaque,unsigned kind,uint64_t iova,uint64_t size)
{
    struct sep_rom_dma_context *a=opaque;struct context *c=a->c;unsigned index;
    if(device_dart_admit_frame(c->params->models,c->model_state,
       (unsigned)c->params->model_count,5,20,0,1,&index)!=DEVICE_OK) {
        a->refusal=SPTM_BAD_CONFIG;return 0;
    }
    struct sptm_memory memory=sptm_context_memory(c);
    a->refusal=sptm_sep_rom_buffer(&memory,&c->model_state[index].dart,kind,iova,size);
    return a->refusal==SPTM_OK;
}
static int sep_bootstrap_read(void *opaque,uint32_t offset,size_t size,void *out)
{
    struct sep_rom_dma_context *a=opaque;struct context *c=a->c;
    if(!size || size>64 || offset>a->shared_size || size>a->shared_size-offset ||
       (offset&0x3fff)+size>0x4000) {a->refusal=SPTM_BAD_ADDRESS;return 0;}
    struct sptm_memory memory=sptm_context_memory(c);uint64_t pa;
    a->refusal=sptm_dart_dma_translate(&memory,&c->model_state[a->index].dart,
        20,0,a->shared_iova+offset,size,0,&pa);
    if(a->refusal)return 0;
    const volatile uint8_t *source=memory.map(memory.ctx,pa,size);
    if(!source){a->refusal=SPTM_MEMORY_UNAVAILABLE;return 0;}
    uint8_t *target=out;for(size_t i=0;i<size;i++)target[i]=source[i];
    return 1;
}
static int sep_rom_bootstrap(void *opaque,uint64_t iova,uint64_t size,struct sep_bootstrap *out)
{
    struct sep_rom_dma_context *a=opaque;struct context *c=a->c;
    if(size!=0x14000 || device_dart_admit_frame(c->params->models,c->model_state,
       (unsigned)c->params->model_count,5,20,0,1,&a->index)!=DEVICE_OK) {
        a->refusal=SPTM_BAD_CONFIG;return 0;
    }
    struct dart_state *dart=&c->model_state[a->index].dart;
    uint64_t before=dart->translations;
    if(before>UINT64_MAX-14){a->refusal=SPTM_BAD_CONFIG;return 0;}
    struct sptm_memory memory=sptm_context_memory(c);
    a->refusal=sptm_sep_rom_buffer(&memory,dart,1,iova,size);
    if(a->refusal)return 0;
    a->shared_iova=iova;a->shared_size=size;
    const struct sep_bootstrap_reader reader={a,sep_bootstrap_read};
    if(sep_bootstrap_parse(&reader,size,out)!=SEP_BOOTSTRAP_OK ||
       out->panic_offset!=0x4000 || out->panic_size!=0x8000 ||
       out->flags_offset!=0xc000 || out->scot_offset!=0x10000) {
        if(!a->refusal)a->refusal=SPTM_BAD_CONFIG;
        dart->translations=before;return 0;
    }
    return 1;
}
static int sep_service_admit(struct sep_rom_dma_context *a,unsigned owner,
    unsigned candidate,uint64_t iova,uint64_t size,uint64_t physical[SPTM_SEP_ALL_PAGES],
    unsigned positions[2])
{
    struct context *c=a->c;
    if(owner>2 || candidate>2 || !a->asc || !sep_pnon_valid(&a->asc->pnon) ||
       !sep_xars_valid(&a->asc->xars) || !sep_sks_endpoint_valid(&a->asc->sks) ||
       a->shared_size!=0x14000 ||
       device_dart_admit_frame(c->params->models,c->model_state,
       (unsigned)c->params->model_count,5,20,0,1,&a->index)!=DEVICE_OK) {
        a->refusal=SPTM_BAD_CONFIG;return 0;
    }
    struct sptm_sep_span spans[7]={{a->shared_iova,a->shared_size,0}};
    unsigned count=1,pages=5;
    for(unsigned endpoint=0;endpoint<3;endpoint++)for(unsigned d=0;d<2;d++) {
        unsigned replace=endpoint==owner && d==candidate;
        uint64_t stage=endpoint==2 ? a->asc->sks.stage[d] : endpoint ? a->asc->xars.stage[d] : a->asc->pnon.stage[d];
        uint64_t old_iova=endpoint==2 ? a->asc->sks.iova[d] : endpoint ? a->asc->xars.iova[d] : a->asc->pnon.iova[d];
        uint64_t old_size=endpoint==2 ? a->asc->sks.size[d] : endpoint ? a->asc->xars.size[d] : a->asc->pnon.size[d];
        const uint64_t *old_physical=endpoint==2 ? a->asc->sks.physical[d] : endpoint ? a->asc->xars.physical[d] : a->asc->pnon.physical[d];
        if(endpoint==owner)positions[d]=pages;
        if(!replace && stage!=2)continue;
        spans[count++]=(struct sptm_sep_span){replace ? iova : old_iova,
            replace ? size : old_size,stage==2 ? old_physical : 0};
        pages+=(unsigned)(spans[count-1].size/0x4000);
    }
    struct sptm_memory memory=sptm_context_memory(c);
    a->refusal=sptm_sep_all_buffers(&memory,&c->model_state[a->index].dart,spans,count,physical);
    return a->refusal==SPTM_OK;
}
static int sep_pnon_bind(void *opaque,const struct sep_pnon *s,unsigned direction,
                        uint64_t iova,uint64_t size,uint64_t out[SEP_PNON_PAGES])
{
    struct sep_rom_dma_context *a=opaque;uint64_t pages[SPTM_SEP_ALL_PAGES];unsigned positions[2];
    if(direction>1 || !a->asc || s!=&a->asc->pnon ||
       !sep_service_admit(a,0,direction,iova,size,pages,positions))return 0;
    for(unsigned i=0;i<SEP_PNON_PAGES;i++)out[i]=i<size/0x4000 ? pages[positions[direction]+i] : 0;
    return 1;
}
static int sep_pnon_query(void *opaque,const struct sep_pnon *s,uint64_t request_length)
{
    struct sep_rom_dma_context *a=opaque;struct context *c=a->c;unsigned index;
    if(device_dart_admit_frame(c->params->models,c->model_state,
       (unsigned)c->params->model_count,5,20,0,1,&index)!=DEVICE_OK) {
        a->refusal=SPTM_BAD_CONFIG;return 0;
    }
    uint64_t before=c->model_state[index].dart.translations;
    uint64_t pages[SPTM_SEP_ALL_PAGES];unsigned positions[2];
    if(!a->asc || s!=&a->asc->pnon || !sep_service_admit(a,0,2,0,0,pages,positions))return 0;
    struct sptm_memory memory=sptm_context_memory(c);
    const volatile uint8_t *source=memory.map(memory.ctx,pages[positions[0]],32);
    volatile uint8_t *target=memory.map(memory.ctx,pages[positions[1]],36);
    uint8_t request[32],reply[36];int length=0;
    if(source && target) {
        for(unsigned i=0;i<32;i++)request[i]=source[i];
        /* Only the 32-byte header is read; a longer command's body stays
         * in the send buffer unread and gets the not-supported reply. */
        length=a->pnon_refusal ? sep_pnon_refuse_sized(request,request_length,reply) :
            sep_pnon_reply_sized(request,request_length,reply);
    } else a->refusal=SPTM_MEMORY_UNAVAILABLE;
    if(length) {
        for(int i=0;i<length;i++)target[i]=reply[i];
        sptm_publish(c,(uint64_t)target,(uint64_t)length);
    } else c->model_state[index].dart.translations=before;
    aes_clear(request,sizeof(request));aes_clear(reply,sizeof(reply));return length;
}
static int sep_xars_bind(void *opaque,const struct sep_xars *s,unsigned direction,
                        uint64_t iova,uint64_t size,uint64_t out[SEP_XARS_PAGES])
{
    struct sep_rom_dma_context *a=opaque;uint64_t pages[SPTM_SEP_ALL_PAGES];unsigned positions[2];
    if(direction>1 || !a->asc || s!=&a->asc->xars ||
       !sep_service_admit(a,1,direction,iova,size,pages,positions))return 0;
    for(unsigned i=0;i<SEP_XARS_PAGES;i++)out[i]=pages[positions[direction]+i];
    return 1;
}
static int sep_xars_validate(void *opaque,const struct sep_xars *s)
{
    struct sep_rom_dma_context *a=opaque;uint64_t pages[SPTM_SEP_ALL_PAGES];unsigned positions[2];
    return a->asc && s==&a->asc->xars && sep_service_admit(a,1,2,0,0,pages,positions);
}
static int sep_xars_slot(void *opaque,const struct sep_xars *s,unsigned bytes)
{
    if(bytes!=SEP_XARS_SLOT_BYTES && bytes!=SEP_XARS_EPOCH_BYTES)return 0;
    struct sep_rom_dma_context *a=opaque;struct context *c=a->c;unsigned index;
    if(device_dart_admit_frame(c->params->models,c->model_state,
       (unsigned)c->params->model_count,5,20,0,1,&index)!=DEVICE_OK) {
        a->refusal=SPTM_BAD_CONFIG;return 0;
    }
    uint64_t before=c->model_state[index].dart.translations;
    uint64_t pages[SPTM_SEP_ALL_PAGES];unsigned positions[2];
    if(!a->asc || s!=&a->asc->xars || !sep_service_admit(a,1,2,0,0,pages,positions))return 0;
    struct sptm_memory memory=sptm_context_memory(c);
    volatile uint8_t *target=memory.map(memory.ctx,pages[positions[1]],bytes);
    if(!target) {
        a->refusal=SPTM_MEMORY_UNAVAILABLE;
        c->model_state[index].dart.translations=before;return 0;
    }
    /* Empty virtual state at the receive-buffer start: a zero BNCN and commit
     * hash for an AP-nonce slot, or eight empty epoch slots. */
    for(unsigned i=0;i<bytes;i++)target[i]=0;
    sptm_publish(c,(uint64_t)target,bytes);
    return 1;
}
static int sep_sks_bind(void *opaque,const struct sep_sks_endpoint *s,unsigned direction,
                        uint64_t iova,uint64_t size,uint64_t out[SEP_SKS_PAGES])
{
    struct sep_rom_dma_context *a=opaque;uint64_t pages[SPTM_SEP_ALL_PAGES];unsigned positions[2];
    if(direction>1 || !a->asc || s!=&a->asc->sks ||
       !sep_service_admit(a,2,direction,iova,size,pages,positions))return 0;
    for(unsigned i=0;i<SEP_SKS_PAGES;i++)out[i]=pages[positions[direction]+i];
    return 1;
}
static int sep_sks_prepare(void *opaque,const struct sep_sks_endpoint *s,unsigned command,
    unsigned length,struct sep_sks_wire_state *staged,uint8_t reply[SEP_SKS_REPLY_BYTES],
    uint16_t *reply_bytes,uint8_t *status)
{
    /* runtime_enter holds the guest service lock through preparation/publication.
     * A bounded shared scratch avoids a16KiB request on each EL2 stack. */
    struct sep_rom_dma_context *a=opaque;struct context *c=a->c;unsigned index;
    uint8_t *request=c->sep_sks_request;
    a->sks_prepared=0;
    if(!a->asc || s!=&a->asc->sks || device_dart_admit_frame(c->params->models,c->model_state,
       (unsigned)c->params->model_count,5,20,0,1,&index)!=DEVICE_OK) {
        a->refusal=SPTM_BAD_CONFIG;return 0;
    }
    a->sks_translations=c->model_state[index].dart.translations;
    uint64_t pages[SPTM_SEP_ALL_PAGES];unsigned positions[2];
    if(!sep_service_admit(a,2,2,0,0,pages,positions))return 0;
    if(length>SEP_SKS_WIRE_MAX) {
        *reply_bytes=0;*status=SEP_SKS_MALFORMED;a->sks_prepared=1;return 1;
    }
    struct sptm_memory memory=sptm_context_memory(c);
    const volatile uint8_t *source=length ? memory.map(memory.ctx,pages[positions[0]],length) : 0;
    if(length && !source) {
        a->refusal=SPTM_MEMORY_UNAVAILABLE;
        c->model_state[index].dart.translations=a->sks_translations;return 0;
    }
    for(unsigned i=0;i<length;i++)request[i]=source[i];
    uint32_t result_bytes=0;
    *status=sep_sks_wire(staged,command,request,length,reply,SEP_SKS_REPLY_BYTES,&result_bytes);
    aes_clear(request,length);
    *reply_bytes=(uint16_t)result_bytes;a->sks_prepared=1;return 1;
}
static int sep_sks_publish(void *opaque,const struct sep_sks_endpoint *s,
                           const uint8_t *reply,uint16_t bytes)
{
    struct sep_rom_dma_context *a=opaque;struct context *c=a->c;
    if(!a->sks_prepared || !a->asc || s!=&a->asc->sks || bytes>SEP_SKS_REPLY_BYTES) {
        a->refusal=SPTM_BAD_CONFIG;return 0;
    }
    uint64_t pages[SPTM_SEP_ALL_PAGES];unsigned positions[2];
    unsigned index=a->index;
    if(!sep_service_admit(a,2,2,0,0,pages,positions)) {
        c->model_state[index].dart.translations=a->sks_translations;return 0;
    }
    struct sptm_memory memory=sptm_context_memory(c);
    volatile uint8_t *target=bytes ? memory.map(memory.ctx,pages[positions[1]],bytes) : 0;
    if(bytes && !target) {
        a->refusal=SPTM_MEMORY_UNAVAILABLE;
        c->model_state[index].dart.translations=a->sks_translations;return 0;
    }
    for(unsigned i=0;i<bytes;i++)target[i]=reply[i];
    if(bytes)sptm_publish(c,(uint64_t)target,bytes);
    a->sks_prepared=0;return 1;
}
static int sep_entropy32(void *opaque,uint32_t *out)
{
    (void)opaque;
    uint64_t isar0,word=0;
    __asm__ volatile("mrs %0,id_aa64isar0_el1":"=r"(isar0));
    if((isar0>>60)!=1)return 0;
    /* Independent RNDR output, never the boot seed or private PAC seed.
     * As in pauth_domain_prepare, NE records RNDR's architected success.
     * Exhaustion stops the service; no deterministic/unavailable fallback. */
    for(unsigned retry=0;retry<64;retry++) {
        unsigned ok;
        __asm__ volatile("mrs %0,s3_3_c2_c4_0; cset %w1,ne"
                         :"=r"(word),"=r"(ok)::"cc");
        if(ok){*out=(uint32_t)word;aes_clear(&word,sizeof(word));return 1;}
    }
    aes_clear(&word,sizeof(word));return 0;
}

#endif /* SEP_CALLBACKS_H */

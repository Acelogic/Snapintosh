/* SPDX-License-Identifier: MIT */
#include "pauth-batch.h"

static enum sptm_result fail(struct pauth_batch_state *s,enum sptm_result r)
{s->failures++;return r;}

enum sptm_result pauth_batch_sign(const struct sptm_memory *m,struct pauth_batch_state *s,
    uint64_t input,uint64_t count,uint64_t scratch,uint64_t scratch_va,
    uint64_t tbi,uint64_t tbid,pauth_batch_sign_fn sign,void *ctx)
{
    if(!s)return SPTM_BAD_CONFIG;
    s->attempts++;s->input_pa=input;s->count=count;s->scratch_pa=scratch;
    s->result_va=0;s->tbi=tbi;s->tbid=tbid;s->input_type=0;
    s->failed_index=UINT64_MAX;s->sign_calls=s->restored_calls=0;
    if(!m || !m->map || !m->publish || !sign || !count || count>64 ||
       tbi>1 || tbid>1 || (scratch&16383) || (scratch_va&16383) ||
       !scratch_va || scratch_va>UINT64_MAX-2048 ||
       m->frame_low>=m->frame_high || ((m->frame_low|m->frame_high)&16383))
        return fail(s,SPTM_BAD_CONFIG);
    uint64_t bytes=count*24;
    /* Pinned copy helper permits one16K source frame, including unaligned
     * input, and only role-table types11/35 with an available reader lock. */
    if(input<m->frame_low || input>=m->frame_high ||
       bytes>m->frame_high-input || (input&16383)+bytes>16384)
        return fail(s,SPTM_BAD_ADDRESS);
    uint64_t index=(input-m->frame_low)>>14;
    if(index>(UINT64_MAX-m->frame_map_pa)/16)return fail(s,SPTM_BAD_ADDRESS);
    volatile uint8_t *meta=m->map(m->ctx,m->frame_map_pa+index*16,16);
    if(!meta)return fail(s,SPTM_MEMORY_UNAVAILABLE);
    unsigned lock=meta[0]|((unsigned)meta[1]<<8);s->input_type=meta[2];
    if((lock&1) || lock>0xfff1)return fail(s,SPTM_FRAME_BUSY);
    if(meta[2]!=SPTM_MAC_DEFAULT && meta[2]!=SPTM_MAC_KERNEL_RESTRICTED)
        return fail(s,SPTM_TYPE_MISMATCH);
    volatile uint8_t *src=m->map(m->ctx,input,bytes);
    volatile uint8_t *dst=m->map(m->ctx,scratch,512+bytes);
    if(!src || !dst)return fail(s,SPTM_MEMORY_UNAVAILABLE);
    uint8_t *copy=(uint8_t *)s->input;
    for(uint64_t i=0;i<bytes;i++)copy[i]=src[i];
    for(uint64_t i=0;i<count;i++) {
        const struct pauth_batch_entry *e=&s->input[i];
        if(e->key!=0 && e->key!=2) {s->failed_index=i;return fail(s,SPTM_BAD_CONFIG);}
        /* The native helper accepts lower47-bit addresses. Preserve tags
         * only when TBI applies to the selected instruction/data class. */
        uint64_t upper=tbi && (e->key==2 || !tbid) ?
            (e->pointer>>47)&511 : e->pointer>>47;
        if(upper) {s->failed_index=i;return fail(s,SPTM_BAD_ADDRESS);}
    }
    for(uint64_t i=0;i<count;i++) {
        s->sign_calls++;
        if(!sign(ctx,&s->input[i],tbi,tbid,&s->output[i])) {
            s->failed_index=i;return fail(s,SPTM_SHADOW_FAILED);
        }
        s->restored_calls++;
    }
    /* No guest stores until all records and native restorations pass.
     * Output[0..512) and the copied records[512..2048) do not overlap. */
    for(uint64_t i=0;i<bytes;i++)dst[512+i]=copy[i];
    const uint8_t *output=(const uint8_t *)s->output;
    for(uint64_t i=0;i<count*8;i++)dst[i]=output[i];
    m->publish(m->ctx,scratch,512+bytes);
    s->result_va=scratch_va+512;s->calls++;s->records+=count;
    return SPTM_OK;
}

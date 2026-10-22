/* SPDX-License-Identifier: MIT */
#include "pauth-pointer.h"

static enum sptm_result fail(struct pauth_pointer_state *s,enum sptm_result r)
{s->failures++;return r;}

enum sptm_result pauth_pointer(uint64_t pointer,uint64_t key,uint64_t modifier,
    uint64_t authenticate,uint64_t tbi,uint64_t tbid,pauth_batch_sign_fn sign,
    void *ctx,struct pauth_pointer_state *s)
{
    if(!s)return SPTM_BAD_CONFIG;
    s->attempts++;s->pointer=pointer;s->key=key;s->modifier=modifier;
    s->authenticate=authenticate;s->tbi=tbi;s->tbid=tbid;
    s->stripped=s->computed=s->result=0;
    if(!sign || authenticate>1 || tbi>1 || tbid>1 ||
       ((uint32_t)key!=0 && (uint32_t)key!=2))return fail(s,SPTM_BAD_CONFIG);
    uint64_t tagged=tbi && ((uint32_t)key==2 || !tbid);
    uint64_t raw=pointer;
    if(authenticate) {
        /* XPAC restores PAC bits from address bit55. Our current user
         * geometry supports only canonical lower47-bit addresses. Upper
         * addresses are explicitly unsupported, never silently normalized. */
        if(pointer&(1ULL<<55))return fail(s,SPTM_BAD_ADDRESS);
        raw=pointer&((1ULL<<47)-1);
        if(tagged)raw|=pointer&0xff00000000000000ULL;
    }
    /* The original scalar SIGN service forwards every input bit to PAC.
     * The callback must be sign-only; noncanonical values need not round-trip. */
    s->stripped=raw;
    struct pauth_batch_entry entry={raw,modifier,(uint32_t)key,0};
    s->native_calls++;
    if(!sign(ctx,&entry,tbi,tbid,&s->computed))return fail(s,SPTM_SHADOW_FAILED);
    s->native_restores++;
    if(authenticate) {
        s->auths++;
        if(s->computed==pointer) {s->valid++;s->result=raw;}
        else {s->invalid++;s->result=UINT64_MAX;}
    } else {s->signs++;s->result=s->computed;}
    s->calls++;return SPTM_OK;
}

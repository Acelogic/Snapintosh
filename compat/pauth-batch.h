/* SPDX-License-Identifier: MIT */
#pragma once
#include "sptm.h"
#define PAUTH_BATCH_MAX 64
struct pauth_batch_entry { uint64_t pointer,modifier; uint32_t key,padding; };
_Static_assert(sizeof(struct pauth_batch_entry)==24,"SPTM sign record stride");
struct pauth_batch_state {
    uint64_t attempts,calls,records,failures,input_pa,count,scratch_pa,result_va;
    uint64_t tbi,tbid,input_type,failed_index,sign_calls,restored_calls;
    struct pauth_batch_entry input[PAUTH_BATCH_MAX];
    uint64_t output[PAUTH_BATCH_MAX];
};
/* sign returns1 only when signing succeeded and all host state is restored. */
typedef int (*pauth_batch_sign_fn)(void *,const struct pauth_batch_entry *,
                                  uint64_t,uint64_t,uint64_t *);
enum sptm_result pauth_batch_sign(const struct sptm_memory *,struct pauth_batch_state *,
    uint64_t input_pa,uint64_t count,uint64_t scratch_pa,uint64_t scratch_va,
    uint64_t tbi,uint64_t tbid,pauth_batch_sign_fn,void *);

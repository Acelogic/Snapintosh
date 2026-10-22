/* SPDX-License-Identifier: MIT */
#pragma once
#include "pauth-batch.h"
struct pauth_pointer_state {
    uint64_t attempts,calls,signs,auths,valid,invalid,failures;
    uint64_t pointer,modifier,key,authenticate,tbi,tbid,stripped,computed,result;
    uint64_t native_calls,native_restores;
};
/* SIGN forwards all64 input bits to a sign-only native backend; it must not
 * require an AUT round trip. A mismatched signature is a successful service call returning UINT64_MAX.
 * Backend/configuration failures stop the guest without supplying a result. */
enum sptm_result pauth_pointer(const uint64_t pointer,uint64_t key,uint64_t modifier,
    uint64_t authenticate,uint64_t tbi,uint64_t tbid,pauth_batch_sign_fn,void *,
    struct pauth_pointer_state *);

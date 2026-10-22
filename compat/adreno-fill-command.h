/* SPDX-License-Identifier: MIT */
#pragma once
#include "adreno-submit.h"
#include "adreno-resource.h"
#include "adreno-resource-list.h"
#include "adreno-fill.h"

#define ADRENO_KCMD_FILL32 (ADRENO_KCMD_VENDOR_BASE + 1u)
/* Wire32 bytes: u32 type,size,resourceID,pattern; u64 offset,bytes. */
struct adreno_fill32_request { uint32_t resource_id, pattern; uint64_t offset, bytes; };
#ifdef __cplusplus
extern "C" {
#endif
int adreno_fill32_decode(const void *command,uint64_t available,struct adreno_fill32_request *);
int adreno_fill32_resource_range(const struct adreno_resource *,uint64_t offset,
                                 uint64_t bytes,uint64_t *address);
/* Caller holds accelerator submission serialization throughout. resolve checks
 * the native map under its lock; native preparation remains owned by list.
 * transfer returns0 only for complete GPU retirement and the exact byte count;
 * every post-doorbell ambiguity returns ADRENO_FILL32_E_UNCERTAIN. Other errors
 * mean preflight refusal before DMA. Failed FROM_DEVICE also freezes the list. */
int adreno_fill32_submit(struct adreno_resource_list *,const struct adreno_resource_list_ops *,
    const struct adreno_fill32_request *,
    int (*resolve)(void *,void *resource,void *preparation,uint64_t,uint64_t,uint64_t *),
    int (*transfer)(void *,uint64_t,uint64_t,uint32_t),void *context);
#ifdef __cplusplus
}
#endif

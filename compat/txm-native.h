/* SPDX-License-Identifier: MIT */
#pragma once
#include <stdint.h>

/* Pinned J700 26A428 Image4 library, invoked through the EL2 bridge. The
 * loader verifies/relocates the image and owns these physical reservations.
 * All calls require the monitor service lock. No guest VA is a host pointer.
 * This adapter performs native authentication; TXM12 owns guest transfers,
 * protected publication and the kernel reply separately. */
#define TXM_NATIVE_BYTES 0x300000UL
#define TXM_NATIVE_IMAGE_BYTES 0x100308UL
#define TXM_NATIVE_PAYLOAD 0x4000UL
#define TXM_NATIVE_MANIFEST 0x8000UL
#define TXM_NATIVE_STACK 0x43c00UL
#define TXM_NATIVE_TREE 0x200000UL
#define TXM_NATIVE_COPY_MAX 8192UL
#define TXM_NATIVE_CACHE_MAX 3u
struct txm_native_params {uint64_t image,work,size,tree_size;};
struct txm_native_state {
    uint64_t phase,calls,loads,auth_failures,last_entry,last_status;
    uint64_t panic_code,panic_arg,payload_size,manifest_size;
};
struct txm_native_cache {uint64_t type;const uint8_t *payload;uint64_t size;};
struct txm_native_result {uint64_t status;const uint8_t *payload;uint64_t size;};
_Static_assert(sizeof(struct txm_native_params)==32,"native loader ABI");
_Static_assert(sizeof(struct txm_native_state)==80,"native audit ABI");
/* Zero on transport success, including an Image4 rejection in result.status.
 * Nonzero means invalid state/configuration or a native panic: do not resume
 * the guest as if authentication returned normally. */
/* Pass the effective guest-visible ID registers, after the monitor's feature
 * mask. Physical SVE/SME presence alone does not imply live guest state. */
int txm_native_init(const struct txm_native_params *,struct txm_native_state *,
                    uint64_t guest_pfr0,uint64_t guest_pfr1);
int txm_native_stage(const struct txm_native_params *,struct txm_native_state *,
    const uint8_t *payload,uint64_t payload_size,const uint8_t *manifest,uint64_t manifest_size);
int txm_native_load(const struct txm_native_params *,struct txm_native_state *,uint64_t type,
    const struct txm_native_cache *boot,const struct txm_native_cache *dynamic,
    struct txm_native_result *);
/* Dynamic descriptors are ordered newest first, matching the native list.
 * The caller retains their payloads outside this adapter's workspace. */
int txm_native_load_caches(const struct txm_native_params *,struct txm_native_state *,uint64_t type,
    const struct txm_native_cache *boot,const struct txm_native_cache *dynamic,unsigned count,
    struct txm_native_result *);

/* SPDX-License-Identifier: MIT */
#pragma once
#include "sptm.h"
#include "txm-native.h"

/* sptm-mac-v1 TXM_XNU transport. Stack pages are dedicated loader reserves,
 * never arbitrary caller-provided RAM. Log, development information,
 * boot-loaded static trust-cache lookup, developer-mode notification and bounded
 * address-space registration/shared-region bounds and the Image4 boot-UUID negative reply are
 * the currently implemented services. No signature verification is implied. */
struct txm_service {
    uint64_t stacks_pa, stack_count, log_pa, log_va;
    uint64_t rw_pa, rw_va, ro_pa, ro_va;
};
enum sptm_result txm_info(const struct sptm_memory *m,
                             const struct txm_service *service,
                             uint64_t selector, const uint64_t args[8]);
/* Fallback when no boot cache was supplied. Never produces a successful
 * trust token. Dynamic cache installation remains unsupported. */
#define TXM_TRUST_CACHE_MISS ((0x12411UL<<32)|3UL)
#define TXM_TRUST_CACHE_ALL_MISS ((0x12412UL<<32)|3UL)
enum sptm_result txm_trust_query_empty(const struct sptm_memory *m,
    const struct txm_service *service,uint64_t selector,const uint64_t args[8],
    uint64_t *status);
/* Selected macOS TXM selector 31 acknowledges a boolean developer-mode
 * notification with no return values. Its firmware handler makes no policy
 * mutation. Preserve the loader's declared development environment, and do
 * not treat this notification as Image4 or code-signature verification. */
enum sptm_result txm_developer_mode(const struct sptm_memory *m,
    const struct txm_service *service, uint64_t selector, const uint64_t args[8]);

/* Pinned TXM7 returns 0x29 when its SEP channel capability is absent.
 * The virtual platform publishes class0 and no channel descriptor in its
 * read-only information page. This implements only that negative reply;
 * an enabled channel requires separately owned backing and a real backend. */
#define TXM_SEP_CHANNEL_UNAVAILABLE 0x29UL
enum sptm_result txm_sep_channel_unavailable(const struct sptm_memory *,
    const struct txm_service *,uint64_t selector,const uint64_t args[8]);

/* Pinned macOS TXM endpoint45/op6 validates length16, then returns errno78
 * in error domain5. It does not read or register the supplied UUID. */
#define TXM_IMAGE4_UUID_UNAVAILABLE ((78UL<<32)|5UL)
enum sptm_result txm_image4(const struct sptm_memory *m,
    const struct txm_service *service,uint64_t selector,const uint64_t args[8]);

/* Selected TXM's twelve nonce domains. Host-owned and zero-initialized per
 * boot; callers serialize this state together with guest page-table services.
 * Material is retained for subsequent Image4 operations, never logged. */
#define TXM_NONCE_DOMAINS 12u
struct txm_nonce {
    uint64_t domain;
    uint32_t flags, initialized;
    uint8_t first[16], second[16];
};
struct txm_nonce_registry {
    struct txm_nonce entries[TXM_NONCE_DOMAINS];
    uint64_t sets, rejections;
};
_Static_assert(sizeof(struct txm_nonce)==48,"nonce audit header stride");
_Static_assert(__builtin_offsetof(struct txm_nonce_registry,sets)==576,
               "nonce audit counters offset");
typedef int (*txm_copyin_fn)(void *,uint64_t,uint8_t *,uint64_t);
/* TXM26 copies one97-byte local-signing public-key record per boot. The
 * pinned firmware panics on duplicate initialization. This owns the record;
 * it does not validate signatures or implement the separate getter. */
#define TXM_LOCAL_KEY_BYTES 97u
struct txm_local_key {
    uint64_t sets,input_va,stack_pa;
    uint8_t value[TXM_LOCAL_KEY_BYTES];
};
_Static_assert(sizeof(struct txm_local_key)==128,"local key audit layout");
enum sptm_result txm_set_local_key(const struct sptm_memory *,
    const struct txm_service *,struct txm_local_key *,txm_copyin_fn,void *,
    uint64_t selector,const uint64_t args[8]);
/* Image4 operation0 sets the release-type string once per boot. The native
 * input is64 bytes, truncated at byte62 before copying into owned storage.
 * Subsequent attempts preserve the value and return domain5/errno37. */
struct txm_release_type {
    uint64_t calls,sets,rejections,last_status,input_va,stack_pa,length;
    uint8_t input[64],value[64];
};
_Static_assert(sizeof(struct txm_release_type)==184,"release type audit layout");
enum sptm_result txm_image4_release_type(const struct sptm_memory *,
    const struct txm_service *,struct txm_release_type *,txm_copyin_fn,void *,
    uint64_t selector,const uint64_t args[8],uint64_t *status);
/* One loader-pinned version-2 static cache. The first reserved 16K page
 * holds its runtime/module view; the original payload starts at +16K.
 * All pages must be read-only to every guest CPU before entering XNU. */
struct txm_trust_cache { uint64_t pa, va, size; };
/* The payload bound: BaseSystem's cache is 26,496 bytes, the installed OS's static cache
 * (Firmware/043-70867-635.dmg.aea.trustcache, IM4P trst) about 441 KB. */
#define TXM_TRUST_MAX_BYTES 0x100000UL
struct txm_trust_state {
    uint64_t initialized, entries, queries, hits, misses;
    uint64_t last_kind, last_length, last_status;
    uint8_t last_hash[24];
    uint64_t last_module, last_entry;
    uint64_t matched[64]; /* Bitmap of the first 4096 entries (the audit's; later hits are counted only). */
};
_Static_assert(sizeof(struct txm_trust_state)==616,"trust query audit layout");
#define TXM_TRUST_CACHE_HIT (0x10UL<<32)
/* TXM16 UUID lookup: library success5 or not-found0x32405, no output words. */
#define TXM_TRUST_UUID_HIT (5UL<<32)
#define TXM_TRUST_UUID_MISS ((0x32405UL<<32)|3UL)
enum sptm_result txm_trust_bootstrap(const struct sptm_memory *,
    const struct txm_service *,const struct txm_trust_cache *,struct txm_trust_state *);
enum sptm_result txm_trust_query(const struct sptm_memory *,
    const struct txm_service *,const struct txm_trust_cache *,struct txm_trust_state *,
    txm_copyin_fn,void *,uint64_t selector,const uint64_t args[8],uint64_t *status);
enum sptm_result txm_trust_uuid(const struct sptm_memory *,
    const struct txm_service *,const struct txm_trust_cache *,const struct txm_trust_state *,
    txm_copyin_fn,void *,uint64_t selector,const uint64_t args[8],uint64_t *status);
/* Observed copied type13/14/27 paths. Three modules and up to8KiB of retained
 * payload fit in the existing first16K metadata page; larger paths remain explicit
 * stops. Native authentication is mandatory before any guest publication. */
#define TXM_DYNAMIC_MODULE 0x200UL
#define TXM_DYNAMIC_PAYLOAD 0x2000UL
#define TXM_DYNAMIC_COUNT TXM_NATIVE_CACHE_MAX
struct txm_load_ops {
    void *ctx;
    enum sptm_result (*prepare)(void *,const uint64_t args[8],uint64_t pa[2]);
    int (*stage)(void *,const uint8_t *,uint64_t,const uint8_t *,uint64_t);
    int (*authenticate)(void *,uint64_t,const struct txm_native_cache *,
                        const struct txm_native_cache *,unsigned,struct txm_native_result *);
};
struct txm_load_state {
    uint64_t calls,successes,failures,last_status,payload_pa,manifest_pa,copied_bytes;
};
enum sptm_result txm_trust_load(const struct sptm_memory *,const struct txm_service *,
    const struct txm_trust_cache *,const struct txm_trust_state *,
    struct txm_load_state *,const struct txm_load_ops *,const uint64_t args[8],uint64_t *status);
enum sptm_result txm_info_with_trust(const struct sptm_memory *,
    const struct txm_service *,const struct txm_trust_cache *,const struct txm_trust_state *,
    uint64_t selector,const uint64_t args[8]);
/* Image4 v2 endpoint52: one digest of1..48 bytes for each of17 domains.
 * State is host-owned, zeroed per boot, and shared under the service lock.
 * This stores nonce material; it does not authenticate an executable. */
#define TXM_NONCE_DIGEST_DOMAINS 17u
struct txm_nonce_digest { uint8_t bytes[48]; uint64_t length; };
struct txm_nonce_digest_registry {
    struct txm_nonce_digest entries[TXM_NONCE_DIGEST_DOMAINS];
    uint64_t sets;
};
_Static_assert(sizeof(struct txm_nonce_digest)==56,"digest audit stride");
_Static_assert(__builtin_offsetof(struct txm_nonce_digest_registry,sets)==952,"digest audit count offset");
enum sptm_result txm_image4_nonce_digest(const struct sptm_memory *,
    const struct txm_service *,struct txm_nonce_digest_registry *,
    txm_copyin_fn,void *,uint64_t selector,const uint64_t args[8]);
/* No compilation-service cdhash has been installed by this backend. Setter
 * calls remain unsupported. Endpoint30 therefore returns the native no-match
 * status8 after validating/copying its bounded input; no privilege is granted. */
enum sptm_result txm_compilation_match_empty(const struct sptm_memory *m,
    const struct txm_service *service,txm_copyin_fn copyin,void *copy_ctx,
    uint64_t selector,const uint64_t args[8],uint64_t *status);
enum sptm_result txm_image4_nonce(const struct sptm_memory *m,
    const struct txm_service *service,struct txm_nonce_registry *registry,
    txm_copyin_fn copyin,void *copy_ctx,uint64_t selector,
    const uint64_t args[8],uint64_t *status);

/* Map callback must admit only guest RAM, including every table read. This
 * copy helper supports the selected16K TTBR1 regime and at most97 bytes. */
struct txm_kernel_memory {
    const struct sptm_memory *memory;
    uint64_t root, tcr;
};
int txm_copy_kernel_input(void *ctx,uint64_t va,uint8_t *out,uint64_t size);
int txm_resolve_kernel_page(void *ctx,uint64_t va,uint64_t size,uint64_t *pa);

/* macOS 27 26A428 TXM object ABI. This is an adapter for the hash-pinned
 * firmware, not a portable definition of Apple's internal object types.
 * A contiguous reserved arena holds one 256-byte object per address space.
 * Eight 16 KiB pages give 512: a six-CPU BaseSystem boot filled the earlier
 * single page (63 processes plus the shared region) within 91 guest seconds.
 * Keep the registry in host-owned memory: guest-visible objects are not
 * allocation authority.
 *
 * SNAP_TXM_ASPACE_WIDE (opt-in, default 0): 64 pages, 4096 objects. Run v47
 * filled all 512 slots about 15 minutes after the first login (TXM35 ASID
 * 0x1552 refused): 4 shared regions plus 508 live address spaces, 506 of them
 * bound to a shared region, with 2,603 TXM36 unbinds already done and XNU's
 * monotonic ASIDs at 0x1551. That is concurrency, not a leak: TXM36 frees its
 * slot itself, RETYPE of a still-registered root is refused, and a logged-in
 * desktop holds about 500 processes. 26A428's
 * bsd_scale_setup gives an 8 GiB guest kern.maxproc 1000*2 = 2000; 4096
 * covers that twice over (exec briefly holds two maps per process).
 * Failure modes, written before the code:
 *  A1 Growing the arena must not change one lifecycle rule (create, share,
 *     bind, TXM36 release, RETYPE refusal of a registered root).
 *  A2 Loader and monitor must agree. A wide monitor with the 8-page layout
 *     would write objects over UAT, the trust window and the panic page:
 *     xnuboot_prepare refuses unless UAT starts right after the whole arena
 *     (probes/xnuboot.py configure_txm_arena, SNAP_TXM_ASPACE_WIDE=1). The
 *     other mismatch, a narrow monitor on the wide layout, uses 8 of 64 pages.
 *  A3 Define-free host readers (MonitorLayout(), run.py's table_start,
 *     capture-console-tail.py, retire) keep every struct context offset and
 *     its page count, so the 143 KiB registry lives in monitor arena pages
 *     after the context (after root_ext under SNAP_ROOT_CACHE_WIDE). The
 *     context keeps a 512-slot twin at offset 8, refreshed at the stop.
 *  A4 Those pages are written without a table-store note: excluded from
 *     SNAP_TXN_DIRTY_PUBLISH sentinels, or the next TXM35 is a hash mismatch.
 *  A5 Zeroed before the first TXM call; below next_table, never a table.
 *  A6 Objects stay in guest RAM in the physical aperture (XNU reads them),
 *     below avail_start and outside the managed frames.
 *  A7 Scans run to the high-water count, not to the limit.
 *  A8 u16 ASIDs, u8 class and the u32 shared count all hold 4096 slots.
 *  A9 Native exhaustion is returnCode 7: XNU's txm_kernel_call (26A428
 *     0xfffffe00079b0c70..0cc8) then donates a TXM_DEFAULT page through
 *     selector 10 (pmap_txm_allocate_page: RETYPE 11->42) and retries. This
 *     backend implements neither, so a full arena is still a monitor stop. */
#ifndef SNAP_TXM_ASPACE_WIDE
#define SNAP_TXM_ASPACE_WIDE 0
#endif
#if SNAP_TXM_ASPACE_WIDE
#define TXM_ASPACE_PAGES 64u
#else
#define TXM_ASPACE_PAGES 8u
#endif
#define TXM_ASPACE_SIZE ((uint64_t)TXM_ASPACE_PAGES*0x4000u)
#define TXM_ASPACE_STRIDE 0x100u
#define TXM_ASPACE_LIMIT (TXM_ASPACE_PAGES*0x4000u/TXM_ASPACE_STRIDE)
struct txm_arena { uint64_t pa, va; };
struct txm_registry {
    uint64_t root[TXM_ASPACE_LIMIT];
    uint16_t asid[TXM_ASPACE_LIMIT];
    unsigned count;
    /* Identity class: 0=ASID, 1=shared slot. The asid[] field holds the
     * class-specific identifier; shared slot zero is valid. */
    uint8_t shared[TXM_ASPACE_LIMIT];
    /* TXM37: exclusive shared-region bounds; zero/zero means unset.
     * Guest-visible objects are checked views, not allocation authority. */
    uint64_t region_start[TXM_ASPACE_LIMIT],region_end[TXM_ASPACE_LIMIT];
    uint64_t region_sets;
    /* Internal table1/endpoint5 association. Cleared by TXM36, independently
     * of the SPTM root reference released later by RETYPE. */
    uint64_t bound_shared[TXM_ASPACE_LIMIT];
    uint64_t bindings, unbindings;
};
#if SNAP_TXM_ASPACE_WIDE
/* The define-free registry (512 slots), field for field: struct context's
 * twin for host readers (A3). count may exceed 512 in a wide run; slots 512
 * and above are only in the live registry. */
#define TXM_ASPACE_LIMIT_COMPAT 512u
struct txm_registry_compat {
    uint64_t root[TXM_ASPACE_LIMIT_COMPAT];
    uint16_t asid[TXM_ASPACE_LIMIT_COMPAT];
    unsigned count;
    uint8_t shared[TXM_ASPACE_LIMIT_COMPAT];
    uint64_t region_start[TXM_ASPACE_LIMIT_COMPAT],region_end[TXM_ASPACE_LIMIT_COMPAT];
    uint64_t region_sets;
    uint64_t bound_shared[TXM_ASPACE_LIMIT_COMPAT];
    uint64_t bindings, unbindings;
};
_Static_assert(sizeof(struct txm_registry_compat)==17952,"define-free TXM registry size");
_Static_assert(TXM_ASPACE_LIMIT<=4096,"A8: u16 ASIDs and the u32 shared count");
#endif
struct txm_share_plan {
    volatile uint8_t *object;
    uint64_t object_pa;
    unsigned registry_slot,shared_slot;
};
/* Internal TXM table1/endpoint4; not a synthetic kernel-visible service.
 * Prepare and commit run under the same service lock, with the all-CPU
 * translation retirement between them. Commit cannot allocate or fail. */
enum sptm_result txm_share_prepare(const struct sptm_memory *,
    const struct txm_arena *,const struct txm_registry *,uint64_t root,
    uint16_t asid,uint8_t shared_slot,struct txm_share_plan *);
void txm_share_commit(const struct sptm_memory *,struct txm_registry *,
    const struct txm_share_plan *);
enum sptm_result txm_bind_shared(const struct sptm_memory *,
    const struct txm_arena *,struct txm_registry *,uint64_t user_root,
    uint16_t asid,uint64_t shared_root,uint8_t shared_slot,
    uint64_t start,uint64_t size);
enum sptm_result txm_aspace(const struct sptm_memory *m,
    const struct txm_service *service, const struct txm_arena *arena,
    struct txm_registry *registry, uint64_t selector, const uint64_t args[8]);

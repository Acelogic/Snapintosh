/* SPDX-License-Identifier: MIT */
#pragma once
#include <stdint.h>

#define ADRENO_LIST_MAX_GROUPS 4096u
enum { ADRENO_LIST_E_ARGUMENT=-110, ADRENO_LIST_E_FORMAT=-111,
       ADRENO_LIST_E_CAPACITY=-112, ADRENO_LIST_E_RESOURCE=-113,
       ADRENO_LIST_E_BUSY=-114, ADRENO_LIST_E_PREPARE=-115, ADRENO_LIST_E_STATE=-116,
       ADRENO_LIST_E_CACHE=-117, ADRENO_LIST_E_VISIBILITY=-118 };
#define ADRENO_LIST_READY 1u
#define ADRENO_LIST_PREPARED 2u
#define ADRENO_LIST_FROZEN 4u
/* Sparse cache ownership (agents/cache-maint FAILURE-MODES.md C1-C15), opt-in: each kernel command maintains only
 * what it lets the GPU touch, each map once per ownership interval. FENCE: nothing (validation only). FILL32: its
 * target range. IB: every distinct map cleaned once per list (prepare to complete), every distinct Write map
 * invalidated once per IB. Off (0): every kernel command cleans every entry and invalidates every Write entry. */
#ifndef ADRENO_CACHE_SPARSE
#define ADRENO_CACHE_SPARSE 0
#endif
#if ADRENO_CACHE_SPARSE
/* Per map, owned by the map and zero when its backing changes; read and written only under the caller's submission
 * serialization. cleaned: the epoch of the list that last cleaned the whole logical extent (TO_DEVICE); invalidated:
 * the list submission that last invalidated it (FROM_DEVICE). Epochs come from one counter and are never 0. */
struct adreno_cache_mark { uint64_t cleaned, invalidated; };
/* The kext's per-map callbacks, hung on the list (null: every entry maintained whole every time, as unsparse).
 * mark: the preparation's map's marks. sync_range: sync over [offset, offset + bytes) of the logical extent, rounded
 * out to whole lines (null: the whole map). Both get the list ops' context. */
struct adreno_cache_ops {
    struct adreno_cache_mark *(*mark)(void *, void *preparation);
    int (*sync_range)(void *, void *preparation, unsigned direction, uint64_t offset, uint64_t bytes);
};
/* What one kernel command lets the GPU reach. ALL: every entry (IB). NONE: no entry (FENCE: its write is the kext's
 * stamp page). RANGE: [offset, offset + bytes) of the entries prepared as `preparation` (FILL32). */
enum { ADRENO_CACHE_SCOPE_ALL = 0, ADRENO_CACHE_SCOPE_NONE = 1, ADRENO_CACHE_SCOPE_RANGE = 2 };
struct adreno_cache_scope { unsigned kind; const void *preparation; uint64_t offset, bytes; };
/* Cumulative counters (relaxed): list submissions by scope; whole-map cleans done/skipped; invalidates done/skipped. */
enum { ADRENO_CACHE_N_ALL, ADRENO_CACHE_N_NONE, ADRENO_CACHE_N_RANGE, ADRENO_CACHE_N_TO, ADRENO_CACHE_N_TO_SKIPPED,
       ADRENO_CACHE_N_FROM, ADRENO_CACHE_N_FROM_SKIPPED, ADRENO_CACHE_COUNTERS };
/* C12: a unit built without the define still imports the old names, which nothing defines in a sparse kext (kmutil
 * refuses the collection). */
#define adreno_resource_list_submit adreno_resource_list_submit_sparse
#define adreno_resource_list_prepare adreno_resource_list_prepare_sparse
#endif
struct adreno_resource_entry { uint32_t id; uint16_t usage, reserved; void *resource, *preparation; };
struct adreno_resource_list {
    struct adreno_resource_entry *entries; uint64_t count;
    uint32_t ready, prepared_count;
#if ADRENO_CACHE_SPARSE
    uint64_t epoch;                   /* set by each successful prepare */
    const struct adreno_cache_ops *cache;   /* set by the owner before prepare; kept by acquire/release */
#endif
};
struct adreno_resource_list_ops {
    void *context;
    void *(*retain)(void *, uint32_t);
    void (*release)(void *, void *);
    /* Success returns zero plus one owned token. Failure must leave token
     * null and undo any speculative native preparation itself. */
    int (*prepare)(void *, void *, void **);
    void (*complete)(void *, void *);
    /* 0 checks eligibility without maintenance; 1/2 follow the guest cache ABI. */
    int (*sync)(void *, void *, unsigned);
};
#ifdef __cplusplus
extern "C" {
#endif
/* The input extent must be a valid kernel mapping. Measurement is advisory:
 * acquire copies into separate caller-owned storage and validates that copy
 * before invoking any namespace callback. No pointer into input is retained. */
int adreno_resource_list_measure(const void *input, uint64_t available,
                                 uint64_t *snapshot_bytes, uint64_t *entry_capacity);
int adreno_resource_list_acquire(struct adreno_resource_list *, const void *input,
    uint64_t available, void *snapshot, uint64_t snapshot_capacity,
    struct adreno_resource_entry *entries, uint64_t entry_capacity,
    const struct adreno_resource_list_ops *);
/* Release references in reverse order. Arrays and snapshot storage belong to
 * the caller; repeated IDs have distinct balanced native references. */
int adreno_resource_list_release(struct adreno_resource_list *, const struct adreno_resource_list_ops *);
int adreno_resource_list_prepare(struct adreno_resource_list *, const struct adreno_resource_list_ops *);
int adreno_resource_list_complete(struct adreno_resource_list *, const struct adreno_resource_list_ops *);
/* After uncertain GPU retirement, retain references and preparation until
 * reset. There is intentionally no thaw based on elapsed time. */
void adreno_resource_list_freeze(struct adreno_resource_list *);
/* Caller serializes this entire interval across queues. submit returns 0,
 * INACTIVE (no new DMA), or UNCERTAIN; unknown errors are also uncertain.
 * Timeout or failed post-DMA visibility freezes preparation ownership. */
int adreno_resource_list_submit(struct adreno_resource_list *, const struct adreno_resource_list_ops *,
                                int (*submit)(void *), void *);
#if ADRENO_CACHE_SPARSE
/* adreno_resource_list_submit with an explicit scope; adreno_resource_list_submit itself is scope ALL. RANGE needs
 * an entry prepared as scope->preparation (else ADRENO_LIST_E_ARGUMENT) and invalidates only if one such entry has
 * Write usage. Every entry is still validated (direction 0) first. Same results and freezing as unscoped. */
int adreno_resource_list_submit_scope(struct adreno_resource_list *, const struct adreno_resource_list_ops *,
                                      int (*submit)(void *), void *, const struct adreno_cache_scope *);
void adreno_cache_sparse_counters(uint64_t v[ADRENO_CACHE_COUNTERS]);
#endif
#ifndef ADRENO_PIPELINE
#define ADRENO_PIPELINE 0
#endif
#if ADRENO_PIPELINE
/* --pipeline (agents/gpu-pipeline FAILURE-MODES.md R1): adreno_resource_list_submit split at the doorbell, so the work
 * can end after the call returns. begin is everything submit does before calling its work (state checks, direction 0
 * on every entry, TO_DEVICE); end is everything after it, given the work's result (0: the GPU retired it;
 * ADRENO_SUBMIT_E_INACTIVE: refused before any ring write; anything else: uncertain, the list freezes). submit is
 * begin, work, end, and returns exactly what it returned before. `pending` is the caller's, from begin to end; begin
 * arms it only on success, end disarms it. validate is begin's checks without maintenance (a FENCE folded into a
 * flight: nothing reaches the GPU for it). */
struct adreno_list_pending {
    uint64_t submission;              /* sparse: this submission's epoch */
    uint64_t offset, bytes;           /* sparse RANGE: the scope */
    const void *target;               /* sparse RANGE: the entry's preparation */
    uint32_t armed, kind, target_usage, reserved;
};
#if ADRENO_CACHE_SPARSE
#define adreno_resource_list_begin adreno_resource_list_begin_sparse
#define adreno_resource_list_end adreno_resource_list_end_sparse
#define adreno_resource_list_validate adreno_resource_list_validate_sparse
int adreno_resource_list_begin_scope(struct adreno_resource_list *, const struct adreno_resource_list_ops *,
                                     const struct adreno_cache_scope *, struct adreno_list_pending *);
#endif
int adreno_resource_list_begin(struct adreno_resource_list *, const struct adreno_resource_list_ops *,
                               struct adreno_list_pending *);
int adreno_resource_list_end(struct adreno_resource_list *, const struct adreno_resource_list_ops *,
                             struct adreno_list_pending *, int result);
int adreno_resource_list_validate(struct adreno_resource_list *, const struct adreno_resource_list_ops *);
#endif
#ifdef __cplusplus
}
#endif

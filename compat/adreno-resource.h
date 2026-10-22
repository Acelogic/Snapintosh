/* SPDX-License-Identifier: MIT */
#pragma once
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define ADRENO_RESOURCE_RESERVED 1u
#define ADRENO_RESOURCE_PINNED   2u
#define ADRENO_RESOURCE_FAILED   4u
/* Complete, pinned translations kept across a native unwire (adreno_resource_unwire).
 * Submissions, cache maintenance and resolution refuse it: they require exactly
 * RESERVED|PINNED, which only the native rewire restores. */
#define ADRENO_RESOURCE_RESIDENT 8u

/* Commit option: one insert per physically contiguous run (at most 64 pages, within
 * one 32 MiB leaf table) instead of one per page. */
#define ADRENO_COMMIT_RUNS 1u

struct adreno_resource {
    uint64_t address, length, logical_length, mapped_length;
    unsigned flags;
};
/* Bytes of RESIDENT mappings, shared by every resource of one owner and changed
 * atomically. bytes equals the sum of RESIDENT lengths, including frozen ones,
 * and never exceeds budget; budget 0 never retains. The rest are counters. */
struct adreno_residency {
    uint64_t budget, bytes;
    uint64_t retained, reused, evicted, refused;
};
/* The caller serializes operations and owns the descriptor selected by ctx.
 * pin/unpin include retaining/releasing that descriptor. All callbacks return
 * zero on success except physical, which returns a physical address or zero.
 * free requires fully mapped, pinned backing and must complete native unmap
 * plus mirror invalidation before returning success. Failed cleanup freezes
 * the state: its owner must retain it until reset. */
struct adreno_resource_ops {
    void *ctx;
    int (*reserve)(void *, uint64_t, uint64_t *, uint64_t *);
    int (*free)(void *, uint64_t, uint64_t);
    int (*pin)(void *);
    int (*unpin)(void *);
    uint64_t (*physical)(void *, uint64_t, uint64_t *);
    int (*insert)(void *, uint64_t, uint64_t, uint64_t, uint64_t);
    int (*clear)(void *, uint64_t, uint64_t);
};
enum {
    ADRENO_RESOURCE_E_STATE = -80, ADRENO_RESOURCE_E_RANGE = -81,
    ADRENO_RESOURCE_E_RESERVE = -82, ADRENO_RESOURCE_E_PIN = -83,
    ADRENO_RESOURCE_E_SEGMENT = -84, ADRENO_RESOURCE_E_INSERT = -85,
    ADRENO_RESOURCE_E_CLEAR = -86, ADRENO_RESOURCE_E_UNPIN = -87,
    ADRENO_RESOURCE_E_FREE = -88, ADRENO_RESOURCE_E_CACHE = -89,
    ADRENO_RESOURCE_E_BIND = -90     /* adreno_resource_bind: the native bind refused every address */
};

int adreno_resource_reserve(struct adreno_resource *, const struct adreno_resource_ops *, uint64_t);
int adreno_resource_commit(struct adreno_resource *, const struct adreno_resource_ops *);
/* Translation retirement only: caller first completes GPU work using the VA. */
int adreno_resource_release(struct adreno_resource *, const struct adreno_resource_ops *);
int adreno_resource_free(struct adreno_resource *, const struct adreno_resource_ops *);
/* Residency (docs/ADRENO-GPU-MAP-RESIDENCY-20261017.md). The old entry points above
 * insert page by page and never retain.
 *
 * Native unwire. keep is the owner's verdict that the pinned descriptor is still the
 * native one and was pinned in its own direction (not a read-only fallback). Within
 * the budget, a complete pinned mapping then stays mapped and pinned (RESIDENT): no
 * clear, no unpin, no TLB invalidation. Anything else is adreno_resource_release. */
int adreno_resource_unwire(struct adreno_resource *, const struct adreno_resource_ops *,
                           struct adreno_residency *, int keep);
/* Native wire. same: no descriptor is pinned or the pinned one is the native one.
 * RESIDENT and same reuses the mapping untouched. RESIDENT and not same releases the
 * stale mapping first (the GPU has not used it since the native unwire), then
 * commits. Otherwise this is adreno_resource_commit (refused when not same). */
int adreno_resource_rewire(struct adreno_resource *, const struct adreno_resource_ops *,
                           struct adreno_residency *, int same, unsigned options);
/* adreno_resource_free that accounts a RESIDENT mapping (its complete pinned PTEs are
 * what strict native free needs) and commits with options when it must recommit. */
int adreno_resource_free_with(struct adreno_resource *, const struct adreno_resource_ops *,
                              struct adreno_residency *, unsigned options);
/* direction 0 validates ownership/range only; 1/2 use the guest cache ABI.
 * Caller holds preparation and map serialization. Partial cache lines are
 * unsupported; callback receives bounded chunks of the logical extent. */
int adreno_resource_cache(const struct adreno_resource *, unsigned direction,
                         int (*maintain)(void *, uint64_t, uint64_t, unsigned), void *);
#ifndef ADRENO_CACHE_SPARSE
#define ADRENO_CACHE_SPARSE 0
#endif
#if ADRENO_CACHE_SPARSE
/* adreno_resource_cache over [offset, offset + bytes) of the logical extent (agents/cache-maint FAILURE-MODES.md
 * C14): the same state rules, then E_RANGE for an empty, overflowing or out-of-extent range; the range is rounded
 * out to whole 64-byte lines (the extent is line-aligned) and sent in chunks of at most ADRENO_CACHE_MAX_BYTES. */
int adreno_resource_cache_range(const struct adreno_resource *, unsigned direction, uint64_t offset, uint64_t bytes,
                                int (*maintain)(void *, uint64_t, uint64_t, unsigned), void *);
#endif

#if ADRENO_POOL_ARENA && !ADRENO_RESOURCE_POOL
#error "ADRENO_POOL_ARENA is a class of ADRENO_RESOURCE_POOL's pool"
#endif
#if ADRENO_VA_RECLAIM && !ADRENO_RESOURCE_POOL
#error "ADRENO_VA_RECLAIM drains ADRENO_RESOURCE_POOL's pool"
#endif
#if ADRENO_RESOURCE_POOL
/* Kext batch 8 (FAILURES-AND-DESIGN.md 2026-10-20, V1-V7, D1-D12): native bind and final release in one
 * place, with a pool of empty DART reservations.
 *
 * Release order (V1): the native CB0 range (IOGPUMemoryMap::freeGPUVirtualAddress) is freed before the
 * DART reservation can reach anyone else, so a map created concurrently can never be handed a DART range
 * the shared CB0 allocator still holds. Final release (D2): a reservation of at most max_span is cleared
 * and unpinned when pinned (nothing when not) and kept, empty, in the pool instead of being recommitted for
 * a strict native unmap; the next map of the same span takes it without a DART call. A full pool, or a
 * larger span, takes the strict path (recommit, native unmap, unpin) as before. Pooled reservations have no
 * valid leaf, are free in CB0 (except parked collisions, below), belong to no map and are never freed. */
#if ADRENO_POOL_ARENA
/* Kext batch 9 (batch9/dart FAILURES-AND-DESIGN.md K1-K12, opt-in): an arena class. installed-fresh-20261020-v9
 * refused 13,257 puts of the plug-in's 1 MiB UBO staging arenas (each then recommitted 64 pages and strict-freed)
 * because spans whose maps are never re-created filled limit_bytes for good (pooled entries are never evicted).
 * Non-suspect entries of exactly arena_span are admitted against arena_limit alone (at most
 * ADRENO_VA_POOL_ARENA_ENTRIES), outside limit_bytes, the per-span cap and the general slots; every other entry
 * keeps batch 8's rules over the other entries. bytes stays the sum of every pooled span. */
#define ADRENO_VA_POOL_GENERAL 256u
#define ADRENO_VA_POOL_ARENA_ENTRIES 256u
#define ADRENO_VA_POOL_SLOTS (ADRENO_VA_POOL_GENERAL + ADRENO_VA_POOL_ARENA_ENTRIES)
#else
#define ADRENO_VA_POOL_SLOTS 256u
#endif
#define ADRENO_VA_POOL_PER_SPAN 32u  /* entries of one span at most: no span monopolizes the pool */
#define ADRENO_VA_POOL_SUSPECT 1u     /* parked after a CB0 collision (V3): never handed out */
#define ADRENO_BIND_ATTEMPTS 3u
#if ADRENO_VA_RECLAIM
/* agents/gpu-va (FAILURE-MODES.md G1-G17, opt-in): the DART's 3 GiB ran out on the desktop (b11v1 15,427, b12v4 3,222,
 * b12v5 1,273 "VM exhausted" / "Map request failed") while the pool parked up to 384 MiB of empty reservations and a
 * strict free that could not re-pin a vanished backing froze its range for good (b11v1: 47).
 * Filler: pinned, physically contiguous kext memory mapped read-only (G4) at a reservation that holds no leaf (G3), so
 * a strict native free finds every leaf present (G2) without the backing. An unpinned reservation's strict free uses
 * it instead of re-pinning and recommitting the backing (G5). A refused reserve drains the pool through filled frees
 * and retries, at most ADRENO_VA_RECLAIM_ROUNDS times (G6, G7), and refuses the next ADRENO_VA_PRESSURE_PUTS puts
 * (G9). A NULL filler leaves every path as without the define (G12). */
#define ADRENO_VA_RECLAIM_ROUNDS 3u
#define ADRENO_VA_DRAIN_FLOOR (64ull << 20)   /* bytes a drain returns at least (or the span, when larger) */
#define ADRENO_VA_PRESSURE_PUTS 4096u
struct adreno_va_filler {
    void *ctx;
    /* ops.insert's contract (page i of [address + offset, + size) -> pa + i * page), read-only leaves */
    int (*insert)(void *, uint64_t address, uint64_t offset, uint64_t pa, uint64_t size);
    /* ops.free's: the strict native free of [address, + length), every leaf present */
    int (*free)(void *, uint64_t address, uint64_t length);
    uint64_t pa, bytes;                       /* 16 KiB aligned; a page multiple of at most 1 MiB */
};
#endif
struct adreno_va_pool {
    uint64_t address[ADRENO_VA_POOL_SLOTS], span[ADRENO_VA_POOL_SLOTS], order[ADRENO_VA_POOL_SLOTS];
    unsigned flags[ADRENO_VA_POOL_SLOTS];
    unsigned count;
    uint64_t bytes, next;                /* pooled bytes; insertion order */
    uint64_t limit_bytes, max_span;      /* admission limits; 0 admits nothing */
    void (*lock)(void *), (*unlock)(void *);
    void *lock_ctx;
    /* Counters, changed atomically. */
    uint64_t puts, takes, refused, suspects, collisions, retried, unbound, gave_up;
    uint64_t strict, recommit_pages;     /* strict native frees from retire, pages recommitted for them */
#if ADRENO_POOL_ARENA
    uint64_t arena_span, arena_limit;    /* the class: exact span (0: none) and its entry limit */
    uint64_t arena_count;                /* its entries (under the lock) */
#endif
#if ADRENO_VA_RECLAIM
    const struct adreno_va_filler *filler;   /* NULL: no filled free, no reclaim, no pressure (G12) */
    uint64_t pressure;                       /* puts still to refuse (under the lock) */
    /* Counters, changed atomically: refused reserves; reclaims that then reserved / did not; entries drained and their
     * bytes; puts refused for pressure; filled strict frees; reservations lost to a failed fill (never freed, G2). */
    uint64_t exhausted, reclaimed, reclaim_failed, drained, drained_bytes, pressure_refused, filled, lost, lost_bytes;
#endif
};
/* Native bind at exactly (address, length): 0 bound; 1 refused before the native allocation (the address
 * is in use natively, or misaligned): retry elsewhere; 2 natively allocated but not admitted (the commit
 * add_mapping ran failed): no retry. */
typedef int (*adreno_bind_fn)(void *ctx, uint64_t address, uint64_t length);
/* Native unbind: frees the CB0 range when (and only when) the native side holds it. */
typedef void (*adreno_unbind_fn)(void *ctx);
/* Take over an empty reservation (address, span) for a map of length bytes; the checks of
 * adreno_resource_reserve. */
int adreno_resource_adopt(struct adreno_resource *, uint64_t length, uint64_t address, uint64_t span);
/* allocGPUVirtualAddress: at most ADRENO_BIND_ATTEMPTS attempts. Only the first may take a pooled
 * reservation; later ones reserve fresh from the DART while the colliding reservation is parked (V3).
 * The bind callback may commit (add_mapping on wired memory) into r. Nonzero on failure, r empty or
 * frozen. */
int adreno_resource_bind(struct adreno_resource *, const struct adreno_resource_ops *, uint64_t length,
                         struct adreno_va_pool *, adreno_bind_fn, adreno_unbind_fn, void *ctx,
                         struct adreno_residency *, unsigned options);
/* Final release (releaseAddress): unbind first (V1), then pool or strict free (D2). A failure freezes r
 * (FAILED, retained until reset) with the CB0 range already free; the DART keeps the range. */
int adreno_resource_retire(struct adreno_resource *, const struct adreno_resource_ops *,
                           struct adreno_residency *, unsigned options, struct adreno_va_pool *,
                           adreno_unbind_fn, void *ctx);
#endif

#ifdef __cplusplus
}
#endif

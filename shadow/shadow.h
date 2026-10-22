/* SPDX-License-Identifier: MIT */
/* Emit a 4K translation equivalent to a guest's 16K one.
 *
 * The guest's tables are never given to the MMU. q1n1 walks them in software
 * (mmu.c) and builds a parallel set of 4K tables that resolve the same virtual
 * addresses to the same physical addresses with the same permissions. The
 * hardware walks the shadow; the guest believes it is walking its own.
 *
 * The two granules do not nest, so this is a re-translation rather than a
 * rewrite: 16K indexes 11 bits per level and 4K indexes 9, so a guest level-2
 * block (32M) becomes sixteen 4K-regime level-2 blocks (2M each), and a guest
 * level-3 page (16K) becomes four level-3 pages. The emitter always uses the
 * largest 4K descriptor that alignment and size allow, so a guest block does
 * not explode into thousands of leaves.
 *
 * The correctness property this is built around: walking the shadow must give
 * the same answer as walking the guest, for every address in the range. That is
 * checkable directly with the same walker, and is what tools/test-shadow.c does
 * rather than comparing against hand-written expectations.
 */
#pragma once
#include "mmu.h"

struct shadow {
    uint32_t txsz;            /* same VA width as the guest regime */
    uint64_t root;            /* 4K root table PA, already zeroed */

    /* A zeroed, 4K-aligned table, or 0 when none is left. The shadow grows as
     * mappings are inserted, so this is called during a build. */
    uint64_t (*alloc)(void *ctx);
    int (*read)(void *ctx, uint64_t pa, uint64_t *out);
    int (*write)(void *ctx, uint64_t pa, uint64_t value);
    void *ctx;
    /* Optional independent context for allocation ownership/lifetime. */
    void *alloc_ctx;

    /* Optional mapping admission, before allocating or storing any descriptor.
     * Receives the whole normalized range, including block mappings. Return
     * nonzero to admit it. Copies used for preflight must retain this callback.
     * This does not cover callers that mutate existing descriptors directly. */
    int (*admit)(void *ctx, uint64_t va, uint64_t pa, uint64_t size,
                 uint64_t low, uint64_t upper);
};

static inline uint64_t shadow_alloc_page(const struct shadow *s)
{return s->alloc(s->alloc_ctx ? s->alloc_ctx:s->ctx);}

/* Map [va, va+size) -> pa carrying `low` and `upper` attribute bits.
 * `va`, `pa` and `size` must be 4K aligned. */
int shadow_map(struct shadow *s, uint64_t va, uint64_t pa, uint64_t size,
               uint64_t low, uint64_t upper);

/* Reserve empty L3 tables before guest entry. Never installs valid leaves;
 * an existing block or leaf is an error. Allocation failure is terminal to
 * the boot preparation, not a transaction on a running guest. */
int shadow_reserve(struct shadow *s, uint64_t va, uint64_t size);

/* The table holding va's entry at `level`, creating missing tables on the
 * way through s->alloc (an allocator returning 0 forbids that). An existing
 * block on the way is an error. */
int shadow_table(struct shadow *s, uint32_t level, uint64_t va, uint64_t *table);

/* Remove a range without allocating. Partial block removal is rejected until
 * block splitting is implemented. check_only validates without mutations. */
int shadow_unmap(struct shadow *s, uint64_t va, uint64_t size, int check_only);
#if SNAP_DETACH_FAST
/* compat/nest-fast.h: 1 when [va, va+size) holds no valid 4K leaf, reading
 * each table on the way and each level-3 table's entries once; 0 when one
 * does; -1 when shadow_unmap would refuse the arguments, a read fails or a
 * block is on the way (the caller then takes shadow_unmap's own path). */
int shadow_range_empty(const struct shadow *s, uint64_t va, uint64_t size);
#endif

/* Insert one guest leaf, clipped to [clip_start, clip_end).
 *
 * Returns 0 when a mapping was written, SHADOW_NOTHING when there was nothing
 * to write, and negative on failure. The middle case is separate on purpose: it
 * used to return 0 as well, so a caller that asked for a leaf to be shadowed
 * and got "success, nothing inserted" had been told something false. It cost a
 * run where five MAP_PAGE calls reported success and the MMU had none of them,
 * because the clip arrived in a different address space from the leaf and every
 * insert collapsed to an empty range.
 *
 * `clip_start` and `clip_end` must be in the same space as `leaf->base`, which
 * mmu_walk reports masked into the regime. */
#define SHADOW_NOTHING 1
int shadow_insert(struct shadow *s, const struct mmu_leaf *leaf,
                  uint64_t clip_start, uint64_t clip_end);

/* Walk `guest` across [start, end) and shadow everything mapped there.
 * Returns the number of leaves inserted, or negative on failure. A hole in the
 * guest is not a failure -- it is simply left unmapped, so a fault on it
 * reaches the guest as the guest's own translation fault. */
long shadow_build(struct shadow *s, const struct mmu_config *guest,
                  uint64_t start, uint64_t end, mmu_read_fn guest_read, void *guest_ctx);

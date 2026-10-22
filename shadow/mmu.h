/* SPDX-License-Identifier: MIT */
/* Software AArch64 stage-1 walker and 4K shadow emitter.
 *
 * The A16's MMU walks 4K and 64K tables but not 16K. XNU asks for 16K. So q1n1
 * keeps the guest's 16K tables out of the hardware entirely: it walks them in
 * software and emits an equivalent 4K translation that the hardware can use.
 * The guest reads back its own values (TVM/TRVM) and an ID register that claims
 * 16K (TID3), so from EL1 nothing is unusual.
 *
 * This header is granule-agnostic on purpose. The same walker handles the 16K
 * guest side and the 4K shadow side, which means the shadow emitter can be
 * checked by walking what it produced and comparing against the source -- a
 * property test rather than a hand-built expectation.
 *
 * Nothing here touches hardware or EL2 state: reads go through a callback, so
 * the whole thing runs natively under sanitizers in tools/test-shadow.c.
 */
#pragma once
#include <stdint.h>

/* Descriptor bits shared by every level and granule. */
#define PT_VALID      (1UL << 0)
#define PT_TABLE      (1UL << 1)     /* at levels 0-2; at level 3 means "page" */
#define PT_ATTRINDX   (7UL << 2)
#define PT_NS         (1UL << 5)
#define PT_AP         (3UL << 6)
#define PT_SH         (3UL << 8)
#define PT_AF         (1UL << 10)
#define PT_NG         (1UL << 11)
#define PT_CONTIG     (1UL << 52)
#define PT_PXN        (1UL << 53)
#define PT_UXN        (1UL << 54)

/* The low attributes a leaf carries down to its shadow copies unchanged. */
#define PT_LEAF_ATTRS (PT_ATTRINDX | PT_NS | PT_AP | PT_SH | PT_AF | PT_NG)
#define PT_LEAF_UPPER (PT_PXN | PT_UXN)

/* Output address field. 48-bit PA; 52-bit output is a separate encoding and is
 * rejected rather than mis-decoded. */
#define PT_OA_MASK 0x0000fffffffff000UL

struct mmu_config {
    uint32_t granule_shift;   /* 12, 14 or 16 */
    uint32_t txsz;            /* T0SZ or T1SZ */
    uint64_t root;            /* table base PA */
};

struct mmu_leaf {
    uint64_t descriptor;      /* the leaf as found */
    uint64_t pa;              /* resolved output address for `va` */
    uint64_t base;            /* start of the mapped region */
    uint64_t size;            /* region size: page or block */
    uint32_t level;           /* level the leaf was found at */
    int valid;
};

/* Read 8 bytes of guest physical memory. Returning non-zero aborts the walk,
 * which is how a shadow build reports an unreadable guest table rather than
 * fabricating a mapping. */
typedef int (*mmu_read_fn)(void *ctx, uint64_t pa, uint64_t *out);

/* Levels the architecture permits a block descriptor at, per granule. */
int mmu_block_allowed(uint32_t granule_shift, uint32_t level);

/* The level a walk starts at, from granule and TxSZ. */
int mmu_start_level(uint32_t granule_shift, uint32_t txsz);

/* Index into the table at `level` for `va`. */
uint32_t mmu_index(uint32_t granule_shift, uint32_t level, uint64_t va);

/* Bytes one entry at `level` maps. */
uint64_t mmu_level_size(uint32_t granule_shift, uint32_t level);

/* Walk `va` through the table described by `cfg`.
 *
 * Returns 0 and fills `out` whether or not the mapping exists -- `out->valid`
 * says which. A negative return means the walk could not be performed at all
 * (unreadable memory, malformed configuration), which is not the same thing as
 * an unmapped address and must not be treated as one. */
int mmu_walk(const struct mmu_config *cfg, uint64_t va, mmu_read_fn read, void *ctx,
             struct mmu_leaf *out);

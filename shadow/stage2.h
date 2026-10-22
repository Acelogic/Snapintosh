/* SPDX-License-Identifier: MIT */
/* The stage-2 map: exactly the ranges we own, and nothing else.
 *
 * Stage 2 is the hypervisor's own translation underneath the guest's. Every
 * address the kernel resolves through its stage-1 tables is an intermediate
 * address, and stage 2 says which of those exist. The map is an identity over
 * a short list of ranges -- the DRAM we declared with the reserve above it,
 * the panel when it is handed over, the probe's own work area read-only -- and
 * everything else is absent. A guest touch of an absent page is a stage-2
 * fault at EL2 carrying the address, which is the question to answer next,
 * rather than a silent pass-through to whatever the SoC keeps at that
 * physical address.
 *
 * The descriptors are written by the emitter that builds the 4K shadow
 * (shadow_map): a stage-2 leaf keeps its permission, shareability and access
 * bits in the positions the stage-1 fields occupy, and the emitter masks with
 * those positions, so it writes them unchanged. What this file adds is the
 * list's validation -- nothing is written unless every range is aligned,
 * inside the IPA width and disjoint from the others, because shadow_map
 * overwrites a leaf it lands on rather than noticing the collision -- and the
 * split that lets one page of a range be guarded on its own.
 *
 * Nothing here touches hardware: reads, writes and allocations go through the
 * shadow's callbacks, so the whole thing runs natively under sanitizers in
 * tools/test-stage2.c, where the produced map is walked page by page and
 * compared against the list it was built from.
 */
#pragma once
#include "shadow.h"

/* Stage-2 leaf bits. S2AP and MemAttr replace stage 1's AP and AttrIndx/NS at
 * the same positions; SH, AF and XN sit where they sit at stage 1. */
#define S2_MEMATTR_NORMAL (0xfUL << 2)   /* normal write-back; stage 1 can only tighten it */
#define S2_SH_INNER       (3UL << 8)
#define S2_AF             (1UL << 10)
#define S2_AP_RO          (1UL << 6)     /* S2AP 0b01: read, never write */
#define S2_AP_RW          (3UL << 6)     /* S2AP 0b11 */
#define S2_XN             (1UL << 54)    /* no execution, with or without FEAT_XNX */
#define S2_ATTRS          (S2_MEMATTR_NORMAL | S2_SH_INNER | S2_AF)
/* Device-nGnRE (MemAttr 0b0001): the Adreno register windows the guest reaches
 * directly (compat/adreno.h). Stage 2 wins over any stage-1 Normal attribute,
 * so a guest mapping of a GPU register page is always a device access. */
#define S2_MEMATTR_DEVICE_nGnRE (1UL << 2)
#define S2_ATTRS_DEVICE   (S2_MEMATTR_DEVICE_nGnRE | S2_SH_INNER | S2_AF)

struct stage2_range {
    uint64_t lo, hi;          /* [lo, hi), 4K aligned, mapped to itself */
    uint64_t low, upper;      /* the leaf's low bits (S2_AP_* | S2_ATTRS) and
                               * its upper bits (S2_XN or 0) */
};

/* A range that is empty, unaligned, past the IPA width `s->txsz` describes,
 * or overlapping another; also an empty list. Nothing has been written. */
#define STAGE2_BAD_RANGES (-2)

/* Validate the list, then map every range over itself in `s`. Returns 0,
 * STAGE2_BAD_RANGES, or -1 when a table could not be allocated or written. */
int stage2_build(struct shadow *s, const struct stage2_range *ranges, unsigned count);

/* Seal an existing identity range without allocating or widening coverage.
 * Split the two boundary pages before guest entry. validate_only performs the
 * same complete walk with no writes. No descriptor is changed on validation
 * failure; a backend write failure is fatal and may leave partial protection.
 * The caller publishes descriptors and invalidates all affected VMIDs. */
int stage2_readonly(struct shadow *s, uint64_t lo, uint64_t hi, int validate_only);

/* Split the block covering `ipa` down to 4K pages, every piece keeping the
 * block's address and attributes, so one page can be changed on its own.
 * Returns the level-3 table holding `ipa`'s entry, or 0 when `ipa` is not
 * mapped -- an absent page has nothing to split and stays absent -- or when no
 * table is left. Idempotent: a page already at level 3 returns its table. */
uint64_t stage2_split(struct shadow *s, uint64_t ipa);

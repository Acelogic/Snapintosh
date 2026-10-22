/* SPDX-License-Identifier: MIT */
#pragma once
/* SNAP_UPDATE_DISJOINT_FAST: two exact cuts in user-root UPDATE_DISJOINT
 * (endpoint 6), opt-in, default 0, default builds unchanged.
 *
 * Why (installed-fresh-20261017-v33, 1800 s desktop): 6,734,021 calls, all
 * user-only and nearly all one record, hold the service lock 339 s, 50.4 us
 * each, against 10.8 us for MAP_PAGE, which does the same leaf commit,
 * variant stores and 16K invalidation in all six VMIDs. The records are
 * XNU's reference/modify emulation: one call clears AF and write-protects a
 * page (...e43 -> ...ac3, options 0xa), the next sets them back on the fault
 * (...ac3 -> ...e43, options 0xc0a). The extra cost is
 *  - every 64th call re-derives all six CPUs' kernel permission copies (57
 *    tables x 512 entries x 6) read-only (user_update_kernel_skip): ~0.8-1.1
 *    ms each (host: 1.1 ms at -Os), 105,219 times, ~15 us per call;
 *  - the transaction publication (97 runtime pages, dirty bitmap, sentinel);
 * not variant or shared-region re-syncs (variants follow each store; no
 * record named a shared-region root).
 *
 * What changes, nothing else:
 *  1. A user leaf update whose old leaf has AF clear skips its 16K TLBI in
 *     every VMID. Every regime that walks a user leaf runs with TCR.HA clear
 *     (SPTM_ROOT_TCR_*), so an AF=0 descriptor raises an Access flag fault,
 *     and Arm does not permit a TLB to cache a descriptor that would fault:
 *     no TLB holds the old translation. The commit's earlier proof that the
 *     cached shadow equals the old guest leaf (prepare_update) means its 4K
 *     leaves and variant copies have AF clear as well. Leaves with AF set, all
 *     other update kinds, shared-region roots and kernel records keep theirs.
 *  2. The sampled kernel-copy verification checks all six CPUs in one pass
 *     over the tables, reading each source word once
 *     (sprr_views_verify_all), with exactly sprr_views_verify_cpu's verdict
 *     for every CPU. Same call sites, same 1-in-64 rate, same counters.
 *
 * Failure modes, written before the code; tools/test-update-disjoint-fast.c
 * checks each and tools/test-update-disjoint-fast.py requires a mutant of
 * each guard to fail it:
 *  A1 a TLBI skipped while a TLB may hold the old translation: only a valid
 *     old leaf with AF clear qualifies, never AF set, and never under a regime
 *     with hardware AF updates (static assert on SPTM_ROOT_TCR_* bit 39).
 *  A2 the skip applied because of the NEW leaf (an AF-set target) rather than
 *     the old one: an old AF-set translation would stay cached.
 *  A3 a stale translation from an earlier state that was never invalidated:
 *     every transition away from a cacheable leaf keeps its TLBI (the model
 *     test checks no cached translation ever outlives its leaf).
 *  A4 the skip reaching another path (unmap, map replacement, shared-region
 *     or kernel updates): it is one call site, user_commit_update.
 *  V1 the single pass accepts what a per-CPU verification refuses, or refuses
 *     what it accepts (differential over random views and corruptions).
 *  V2 a CPU's copy is skipped, misaligned or missing copies are admitted, or
 *     a CPU's entries are decoded with another CPU's PPERM or child copy.
 *  V3 the verification rate or counters change (kernel_ops_perf.py requires
 *     verified == skipped // 64 for user_update_skip).
 *  V4 a default build changes: the define-off source is token-identical. */
#include <stdint.h>
#include "../shadow/mmu.h"
#include "sptm-root.h"

_Static_assert(!(SPTM_ROOT_TCR_16K&(UINT64_C(1)<<39)) && !(SPTM_ROOT_TCR_4K&(UINT64_C(1)<<39)),
               "user regimes keep hardware Access flag updates off");

/* A committed user leaf update needs no TLBI when its old leaf could not be
 * cached: valid and Access flag clear (A1, A2). */
static inline int update_fast_uncached(uint64_t old)
{
    return (old&3)==3 && !(old&PT_AF);
}

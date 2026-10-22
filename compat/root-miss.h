/* SPDX-License-Identifier: MIT */
#pragma once
/* SNAP_ROOT_MISS_FAST: a cheaper SWITCH_ROOT miss for the 64-slot user-root
 * cache (compat/sptm-root.c), opt-in, default 0, default builds unchanged.
 *
 * Why (installed-fresh-20261017-v27 fast, stopped context): 616,962 user
 * switches, 50,341 builds after 50,142 evictions from a full cache, no arena
 * reclaim (low water 42,992 free pages). SWITCH_ROOT holds the service lock
 * for 426 s of 726 s; self time per build is at most 8.2 ms. Every build
 * walks the incoming tree twice (the switch's word walk, then the build's
 * byte walk), about 224 tables and 20K leaves each, and about 221 of those
 * tables are nested shared-region level-3 tables a 16K build links, never
 * copies (SNAP_NATIVE_SHARED). The victim of a full cache is taken round
 * robin by build count, so a root installed a moment ago is as likely to go
 * as one idle for seconds.
 *
 * What changes, nothing else:
 *  1. A full cache gives up the least recently installed inactive root
 *     (sptm_root_reclaim_pick's order: a named invalid slot first, then the
 *     oldest root_stamp) instead of the next one round robin. A cached shadow
 *     is derived state; which inactive root loses it never affects a
 *     translation, only how soon it is rebuilt.
 *  2. On a miss, the switch's walk and the linked build's walk answer a
 *     SHARED level-3 table from the retained verdicts of SNAP_ROOT_VALIDATE_
 *     MEMO, exactly as a cache hit already does. Such a table never reaches
 *     hardware through the build: the build links the shared group, whose
 *     content native-shared.c keeps per store, so the verdict is a tripwire
 *     here just as on a hit. Every other table (private and commpage level-3
 *     tables, whose leaves the build copies; all tables of a 4K-format root)
 *     is still scanned in full by both walks.
 *
 * Failure modes, written before the code; tools/test-root-miss.c checks each
 * and tools/test-root-miss.py requires a mutant of each guard to fail it:
 *  E1 an active root (installed on any CPU) is evicted: its tables would be
 *     released under a running walker.
 *  E2 the victim is the incoming root, or two slots come to name one root
 *     (cache_hit and the alias masks assume at most one).
 *  E3 a valid shadow is given up while an invalidated slot is available.
 *  E4 no victim although an inactive slot exists: a spurious
 *     SPTM_MEMORY_UNAVAILABLE stops the guest.
 *  E5 eviction accounting changes: each eviction is one eviction and one
 *     invalidation, each build one build (kernel_ops_perf and the audits
 *     relate builds, invalidations and syncs).
 *  E6 no stamps (NULL) must keep the round robin; stamps only order inactive
 *     victims and never admit an active one.
 *  M1 a retained verdict answers a table whose leaves the build copies: a
 *     since-changed private, commpage or 4K-format table would reach hardware
 *     unchecked.
 *  M2 the walk and the linked build disagree about which level-2 entries name
 *     shared tables (a validated SHARED child copied, or a copied child
 *     answered by a verdict). Both require attrs 3, type SHARED and level 3.
 *  M3 a verdict outlives a store to its table page, a change of its frame
 *     record bytes0..5 or a mapped frame's type change: sptm-root-memo.h's
 *     witness (unchanged) retires it. Misses and builds record a verdict only
 *     after a full scan passed, as hits do.
 *  M4 decoder relations break (tools/kernel_ops_perf.py): root_memo.calls
 *     counts only cache-hit validations; records == misses; sampled <=
 *     root_validate.sampled; root_validate.validations is unchanged.
 *  M5 the 1-in-64 memo-free reference walk stops covering misses.
 *  M6 a miss skips the root header, the refcount identity, the level-1/2
 *     structure, a child's frame record or a nested-link proof: the verdict
 *     answers only the level-3 descriptor scan, after all of those.
 *  M7 verdicts used without their write witness (SNAP_ROOT_VALIDATE_MEMO),
 *     without the sampled walk (SNAP_ROOT_VALIDATE_WORDS) or without linked
 *     builds (SNAP_NATIVE_SHARED): probes/xnuboot.c asserts all three.
 *  M8 a default build changes: the define-off source is token-identical.
 * Unchanged by construction: user_root_install (with the shared-slot flush
 * of user_shared_slot), the per-CPU kernel PPERM variants, the TPRO variant
 * trees (shared groups never hold selector 9), arena reserve and reclaim
 * (sptm_root_reclaim_pick is reused read-only), and struct context (no field
 * is added; the cache stays 64 slots). */
#include "sptm-root.h"

/* A level-3 table this walk may answer from a retained verdict. A cache hit
 * walk answers any (shared_only 0); a miss or a linked build only a SHARED
 * one, the only kind sptm_root_build_linked links instead of copying. */
static inline int root_miss_memo_table(int shared_only,unsigned type)
{
    return !shared_only || type==SPTM_MAC_PAGE_TABLE_SHARED;
}

/* A linked build may keep a verdict for a SHARED child only when that child's
 * group already exists (grouped != 0): the build then links it and copies
 * nothing. A group the build creates is filled from the child's leaves, so
 * that child is scanned in full first (M1). */
static inline int root_miss_linked_only(int grouped)
{
    return grouped!=0;
}

/* The slot a full cache gives up for `root`: never an active root (E1),
 * never one naming `root` or none (E2), an invalidated slot before a valid
 * one (E3), the least recently installed valid one otherwise. NULL when no
 * slot qualifies; the caller then refuses as before (E4). */
static inline struct sptm_root_cached *root_miss_victim(struct sptm_root_state *s,
    const uint64_t stamp[SPTM_ROOT_CACHE],uint64_t root)
{
    unsigned i=sptm_root_reclaim_pick(s,stamp,SPTM_ROOT_MASK_NONE);
    if(i>=SPTM_ROOT_CACHE || !s->cache[i].root || s->cache[i].root==root)return 0;
    return &s->cache[i];
}

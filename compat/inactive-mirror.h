/* SPDX-License-Identifier: MIT */
#pragma once
#include <stdint.h>
#include "sprr.h"
/* SNAP_INACTIVE_MIRROR (SWITCH_ROOT step B, docs/SWITCH-ROOT-COST-20260928.md):
 * MAP_PAGE and MAP_TABLE on a user root that no CPU has installed keep that
 * root's cached shadow whenever the shadow still equals the guest tree
 * afterwards, instead of discarding it for a full rebuild on the next switch.
 *
 *  - A fresh leaf goes through the same prepare_leaf/commit_leaf pair as on an
 *    active root: commit re-walks the published guest leaf and checks it
 *    against the root's leaf policy, refreshes every private view and
 *    completes the all-VMID TLBI. At most INACTIVE_MIRROR_BUDGET fresh leaves
 *    per cache slot between installs (about the cost of one rebuild); past
 *    that, and for every TPRO (class9) leaf, the shadow is discarded as before.
 *  - A leaf that was already present needs no insertion: a same-PA
 *    replacement reaches every cached root through the update callbacks, and
 *    an identical request stores nothing.
 *  - MAP_TABLE links an empty table (no mapping) or a commpage table whose
 *    leaves the attach callbacks already copy into every cached root.
 * Anything else (an uncached root, CONFIGURE_ROOT, retirement) is unchanged. */
#define INACTIVE_MIRROR_BUDGET 64u
/* One leaf needs at most three new 4K shadow tables. Mirror only with room to
 * spare, so a mirror never meets an exhausted arena (a failed prepare stops
 * the guest); without it the shadow is discarded as before. */
#define INACTIVE_MIRROR_ARENA_PAGES 16u
/* leaves: fresh leaves committed into an inactive cached shadow; present:
 * inactive MAP_PAGE over a present or identical leaf, shadow kept; tables:
 * inactive MAP_TABLE, shadow kept; tpro, budget, arena: fresh leaves that
 * discarded a valid cached shadow (TPRO, slot budget spent, arena short);
 * configured: valid cached shadows discarded by CONFIGURE_ROOT. */
struct inactive_mirror_stats {
    uint64_t leaves,present,tables,tpro,budget,arena,configured;
};
_Static_assert(sizeof(struct inactive_mirror_stats)==56,"inactive mirror record");
/* A fresh MAP_PAGE leaf may be committed into the cached shadow of a root no
 * CPU has installed: the entry is valid, the leaf is not TPRO, the slot has
 * budget left and the arena has room. */
static inline int inactive_mirror_admit(unsigned active_refs,int cached,uint64_t pte,uint64_t used,
                                        uint64_t free_pages)
{
    return !active_refs && cached && sprr_pte_class(pte)!=9 && used<INACTIVE_MIRROR_BUDGET &&
           free_pages>=INACTIVE_MIRROR_ARENA_PAGES;
}
/* After an accepted, non-conflicting MAP_PAGE on a root no CPU has installed.
 * status is the guest answer (sptm_mac_map_page_status): 1 when the slot held
 * a present or identical leaf, 0 when a fresh leaf was inserted. The cached
 * shadow still equals the guest tree only if the leaf was present (its
 * replacement, if any, was already mirrored) or the fresh leaf was committed
 * into it; otherwise the caller must invalidate it. */
static inline int inactive_mirror_keep(int cached,uint64_t status,int committed)
{return cached && (status==1 || committed);}

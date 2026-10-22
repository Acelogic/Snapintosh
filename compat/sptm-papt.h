/* SPDX-License-Identifier: MIT */
#pragma once
#include "sptm.h"

/* ROZONE's privileged aperture mapping, separate from counted object aliases.
 * Preparation changes no bytes. Keep all mapped pointers valid through commit.
 * The caller first installs private CPU paths for every leaf, then commits
 * these canonical descriptors, refreshes/publishes private views and
 * completes TLBI before publishing the frame type.
 *
 * Apple keeps one aperture alias per frame and re-permissions the one its
 * physical-to-virtual table names, which after SLIDE_REGION is the moved
 * alias (tools/replay-papt-moved-alias.py). The monitor also keeps the
 * linear alias, so a moved frame has two leaves: leaf[0] is always the linear
 * one and leaf[1] the moved one XNU's phystokv uses. Both change together. */
struct sptm_papt_leaf {
    uint64_t va, guest_pa, before, after;
    volatile uint8_t *guest, *shadow[4];
};
struct sptm_papt_change {
    unsigned count;
    struct sptm_papt_leaf leaf[2];
};
/* moved may be NULL (no SLIDE_REGION state): only the linear leaf changes. */
enum sptm_result sptm_papt_prepare(const struct sptm_memory *,
    const struct sptm_update_backend *,const struct sptm_aperture *,
    const struct sptm_moved *,uint64_t pa,uint64_t old_type,uint64_t new_type,
    struct sptm_papt_change *);
/* UPDATE_DISJOINT_MULTIPAGE's aperture step (...270dfb1c flag 2): AttrIndx
 * of both aliases := attr (0..7), SH and permissions unchanged, for a
 * quiescent DEFAULT frame (selector3). The caller cleans the frame to PoC
 * before commit, then publishes, refreshes private views and completes TLBI.
 * The selector is unchanged, so no private CPU path needs preparing. */
enum sptm_result sptm_papt_prepare_attr(const struct sptm_memory *,
    const struct sptm_update_backend *,const struct sptm_aperture *,
    const struct sptm_moved *,uint64_t pa,unsigned attr,struct sptm_papt_change *);
void sptm_papt_commit(const struct sptm_memory *,const struct sptm_papt_change *);

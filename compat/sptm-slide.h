/* SPDX-License-Identifier: MIT */
#pragma once
#include "sptm.h"

#define SPTM_SLIDE_INPUTS 8u
#define SPTM_SLIDE_REGIONS 50u
/* Loader-owned initial source allowlist and reserved destination window.
 * All fields are u64 to keep the Python/C boot-parameter ABI explicit. */
struct sptm_slide_config {
    uint64_t table_low, table_high, map_pa, begin, end, count;
    struct sptm_slide_region regions[SPTM_SLIDE_INPUTS];
};
struct sptm_slide_state {
    uint64_t cursor, count, calls, pages;
    struct sptm_slide_region regions[SPTM_SLIDE_REGIONS];
};

/* What XNU's phystokv now reflects: every region SLIDE_REGION published, and
 * only destinations inside the loader's reserved window. MAP_PAGE and the
 * other PTE-pointer replies pass this to sptm_published_pointer. */
static inline struct sptm_moved sptm_slide_moved(const struct sptm_slide_state *s,
    const struct sptm_slide_config *config)
{
    return (struct sptm_moved){s->count ? s->regions : 0,s->count,
        config->begin,config->end};
}

/* mac17p SLIDE_REGION: move an owned, disposable bootstrap VA range to a
 * reserved NX kernel-RW alias; preserve the physical bytes. Split and publish
 * the 24-byte physical-to-virtual entries consumed by XNU. The existing full
 * physical aperture remains mapped so cached bootstrap pointers stay valid.
 * Bootstrap tables/data only; allocator mappings and post-lockdown calls are
 * refused. The guest must be quiescent, map callbacks stable through the call,
 * and the caller must publish shadows/TLBI before resuming. */
enum sptm_result sptm_mac_slide_region(const struct sptm_memory *m,
    const struct sptm_update_backend *b, const struct sptm_slide_config *config,
    struct sptm_slide_state *state, uint64_t va, uint64_t count, int locked);

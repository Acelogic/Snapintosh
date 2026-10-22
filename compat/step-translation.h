/* SPDX-License-Identifier: MIT */
#ifndef SNAP_STEP_TRANSLATION_H
#define SNAP_STEP_TRANSLATION_H
#include <stdint.h>

/* One private, short-lived code translation, never a general guest TLB.
 * Access is serialized by the same service lock as shadow-table updates. */
struct step_translation {
    uint64_t valid, va_page, pa_page, generation, guard;
    uint64_t hits, misses, invalidations, verified, mismatches;
};

static inline void step_translation_clear(struct step_translation *t)
{
    t->invalidations += !!t->valid;
    t->valid = 0;
}

static inline int step_translation_match(const struct step_translation *t,
                                         uint64_t va, uint64_t generation)
{
    return t->valid && !(va & 3) && va >= UINT64_C(0xffff800000000000) &&
           t->va_page == (va & ~UINT64_C(0xfff)) && t->generation == generation;
}
#endif

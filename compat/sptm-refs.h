/* SPDX-License-Identifier: MIT */
#pragma once
#include "sptm.h"

/* A 2048-page contiguous unmap can touch 2048 data frames and three L3
 * tables. Updates have at most 64 entries; MAP_PAGE changes one mapping.
 * All deltas are accumulated and validated before metadata is published. */
#define SPTM_REF_MAX 2052u
struct sptm_ref_entry {
    uint64_t pa;
    volatile uint8_t *entry;
    int64_t ro, other;
    unsigned type;
};
struct sptm_ref_batch { unsigned count; struct sptm_ref_entry entries[SPTM_REF_MAX]; };
void sptm_refs_begin(struct sptm_ref_batch *b);
enum sptm_result sptm_refs_leaf(const struct sptm_memory *m,uint64_t table,
                               uint64_t va,uint64_t old,uint64_t next);
enum sptm_result sptm_refs_validate(const struct sptm_memory *m);
/* A new DART data leaf shares the ordinary data counters at +8/+12.
 * The DART caller separately validates ownership, type and descriptor state. */
enum sptm_result sptm_refs_dart(const struct sptm_memory *m,uint64_t pa,int readonly);
/* Remove exactly one admitted DART leaf reference; CPU aliases remain. */
enum sptm_result sptm_refs_dart_remove(const struct sptm_memory *m,uint64_t pa,int readonly);
/* Stream-scoped entry also accounts for the separately reserved SEP payload. */
enum sptm_result sptm_refs_dart_stream(const struct sptm_memory *m,
    uint64_t id,uint64_t sid,uint64_t pa,int readonly,int remove);
void sptm_refs_commit(const struct sptm_memory *m);
#if SNAP_FINE_LOCKS
/* SNAP_FINE_LOCKS (docs/FINE-LOCKS-20261017.md F1-F3, F11). A converted call
 * takes its batch from this CPU (sptm_memory.refs) and sets
 * sptm_memory.fine. Every first touch then
 *  - admits only an ordinary PAGE_TABLE (20) table or a DEFAULT (11) or
 *    USER_EXEC (14) data frame: frame types change only on the token path, so
 *    a type read here cannot change before commit (F3); every other type,
 *    and its mixed-alias rule, stays on the token path (F2);
 *  - loads the counts with single-copy atomic loads and keeps the snapshot;
 *  - refuses a data count within SPTM_REF_FINE_MARGIN of INT32_MAX, so the
 *    deltas of concurrent calls (at most 6 CPUs x 2,052 entries) cannot carry
 *    a count the snapshot admitted past a bound (F2). A table's counts change
 *    only under its root's stripe, so its snapshot is exact.
 * Commit adds (count - snapshot) atomically instead of storing the absolute
 * value, so concurrent calls on other roots never lose a delta (F1). A
 * decrement removes one of this call's own root's leaves, which its stripe
 * holds, so the count it lowers always includes it. Any refusal here is a
 * decline: the caller repeats the call on the token path. */
#define SPTM_REF_FINE_MARGIN (UINT32_C(1)<<20)
#if SNAP_SPTM_FINE_RETYPE
/* SNAP_SPTM_FINE_RETYPE (compat/sptm-frame-lock.h): a converted RETYPE can
 * change a frame's type while the gate is shared, so a first touch holds the
 * frame shared (held, this CPU's list) before it reads the type and counts,
 * and the caller releases the list after its last TLBI (S3, S5). */
#include "sptm-frame-lock.h"
_Static_assert(SPTM_FRAME_HELD >= SPTM_REF_MAX + 2, "every first touch and the input frames fit the held list");
struct sptm_ref_fine { int64_t ro[SPTM_REF_MAX], other[SPTM_REF_MAX]; struct sptm_frame_held *held; };
#else
struct sptm_ref_fine { int64_t ro[SPTM_REF_MAX], other[SPTM_REF_MAX]; };
#endif
#endif

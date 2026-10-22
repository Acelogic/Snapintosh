/* SPDX-License-Identifier: MIT */
#pragma once
#include <stdint.h>
/* SNAP_NEST_FAST and SNAP_DETACH_FAST: cheaper NEST_REGION, UNNEST_REGION and
 * UNMAP_TABLE for 16K user roots (docs/TOKEN-COSTS-20261018.md). Opt-in,
 * default 0; off, every file is token-identical to the code without them.
 *
 * Why (installed-fresh-20261018-v54, 1,800 s, stopped context):
 *   NEST_REGION    29,336 calls, 71.0 s held, 2.42 ms each, 45.6 level-2
 *                  descriptors each (nest_state.descriptors);
 *   UNNEST_REGION  48,887 calls, 16.3 s, 334 us each, 25.2 descriptors and
 *                  5,826 leaves each (unnest_descriptors, unnest_leaves);
 *   UNMAP_TABLE    83,883 calls (user_detach_calls), 21.5 s, 256 us each.
 * The cost is walking, not copying (SNAP_NATIVE_SHARED links groups):
 *  - sptm_root_prepare_nest_linked checks the source's leaves with one full
 *    3-level byte-assembled walk per 16K address of the range, empty slots
 *    included: 45.6 x 2048 = 93K walks per call, to admit about 10.6K leaves
 *    that SWITCH_ROOT validation has usually proved already.
 *  - sptm_mac_unnest_region assembles every descriptor of every unnested
 *    table from eight byte loads and checks each leaf's frame record.
 *  - sptm_root_prepare_detach walks both trees one 4K page at a time through
 *    the (empty) 32 MiB of a level-3 table, and shadow_unmap does the same
 *    three more times: about 33K walks to prove nothing is mapped.
 *
 * SNAP_NEST_FAST (requires the SWITCH_ROOT memo's write witness,
 * SNAP_ROOT_VALIDATE_MEMO, and SNAP_ROOT_VALIDATE_WORDS' sampled walk in the
 * monitor build; probes/xnuboot.c asserts both):
 *  1. NEST's source check runs per level-2 entry instead of per 16K address.
 *     An entry naming a SHARED level-3 table (attrs 3, type 21, level 3:
 *     shared_child) is answered by a retained validate_table verdict for that
 *     table, base and root flags (sptm-root-memo.h), or scanned once with
 *     word loads, applying the same leaf checks; any other entry, or an
 *     unmappable table, takes the original per-address loop for its 32 MiB.
 *  2. UNNEST answers a SHARED table from the same verdict, counting valid
 *     page descriptors as leaves and skipping pure bits63:61 compressed
 *     markers, just as validate_table does. Other invalid descriptors fall
 *     back to the checked loop (docs/UNNEST-COMPRESSED-20261018.md).
 *  A verdict is stored only after validate_table's own level-3 scan passed
 *  (run without the memo), so every stored verdict is one SWITCH_ROOT could
 *  have stored; the memo then counts the lookup as a miss and the store as a
 *  record (records == misses, tools/kernel_ops_perf.py). Every 64th answered
 *  table is rescanned without the memo; a disagreement fails the call (the
 *  monitor stops) and counts a mismatch.
 * SNAP_DETACH_FAST: UNMAP_TABLE of an empty level-3 table (no leaf removed)
 *  proves both trees empty by reading the guest table and each existing 4K
 *  shadow level-3 table once (shadow_range_empty) instead of walking every
 *  page, and skips shadow_unmap's walks when nothing can be removed; any
 *  other case, or anything unusual on the way (a block, an unreadable
 *  table), takes the original path. The ordinary-table emptiness check
 *  reads words instead of bytes.
 *
 * Failure modes (tools/test-token-costs.c checks each; each guard has a
 * mutant that must fail it, tools/test-token-costs.py):
 *  N1 a verdict answers a table that changed since it was recorded: the
 *     witness (sptm_root_memo_publish) or the mapped-frame retype epoch must
 *     have retired it; the key includes the frame record bytes0..5.
 *  N2 a verdict recorded without validate_table's full scan, or under other
 *     root flags or another base: a later SWITCH_ROOT hit would trust it.
 *  N3 per-entry decomposition differs from the per-address loop: a non-table,
 *     non-shared, attrs-7 or unmappable entry must take the original loop.
 *  N4 UNNEST counts compressed markers as leaves or admits an invalid
 *     nonzero descriptor that is not a pure bits63:61 marker.
 *  N5 the sampled rescan stops covering answered tables, or a mismatch is
 *     not fatal.
 *  N6 memo accounting breaks (records != misses, a hit not counted).
 *  D1 a detach proves emptiness while either tree maps a page, or skips the
 *     shadow removal when there was something to remove.
 *  D2 a removed leaf count other than zero, a level-1 detach, a block or an
 *     unreadable entry takes the fast path.
 *  D3 shadow_unmap's argument refusals are lost (the fast path must refuse
 *     exactly what it refuses).
 *  M  a default build changes: tools/test-token-costs.py compares the
 *     define-off text and the monitor hashes.
 *
 * 3. SNAP_UNNEST_4K_FAST (needs SNAP_NEST_FAST; docs/UNNEST-4K-FAST-20261020.md):
 *  the same UNNEST answer for 4K (format 1) roots, the installed route's
 *  kernel-user-4k roots, which item 2 leaves to the checked loop (shift 14
 *  only). installed-fresh-20261020-v5: 923,675 UNNESTs held the token
 *  122.9 s, 54.2 tables and 4,963 leaves each, all walked. A 4K table is
 *  answered by a retained verdict at shift 12, or validate_table's 4K level-3
 *  scan is run and recorded (sptm_root_shared_proof_4k). The verdict also
 *  carries the table's mapped-leaf count once a proved table has been
 *  counted (sptm_root_shared_count_4k; compat/sptm-root-memo.h record bits
 *  63:48), and a hit with a count skips the scan too: that count describes
 *  the table content the verdict describes, which no published store has
 *  changed since. Every 64th answered table is still rescanned and, for 4K,
 *  recounted; a different count is a mismatch (fatal). A 4K table's
 *  verdicts take their own 8-entry window of the frame's 32, so a frame's
 *  four tables under several root flags do not evict each other. Failure
 *  modes U1-U11 (the document, tools/test-unnest-4k-fast.c).
 *  installed-fresh-20261020-v6 hit 8 %: every exit unnests the whole shared
 *  region (~3,450 tables under its flags), and 2,048 entries evicted a live
 *  verdict on 99.6 % of records. With the define the memo holds 32,768
 *  entries, and a per-frame-index count lets the write witness skip frames
 *  without verdicts after one byte (compat/sptm-root-memo.h; C1-C8 of the
 *  batch-7 note in docs/UNNEST-4K-FAST-20261020.md). */
#ifndef SNAP_NEST_FAST
#define SNAP_NEST_FAST 0
#endif
#ifndef SNAP_DETACH_FAST
#define SNAP_DETACH_FAST 0
#endif
#ifndef SNAP_UNNEST_4K_FAST
#define SNAP_UNNEST_4K_FAST 0
#endif
#if SNAP_UNNEST_4K_FAST && !SNAP_NEST_FAST
#error "SNAP_UNNEST_4K_FAST extends SNAP_NEST_FAST's UNNEST answer: build with SNAP_NEST_FAST"
#endif
#if SNAP_NEST_FAST || SNAP_DETACH_FAST
/* 1 in (mask+1) memo-answered tables is rescanned without the memo. */
#ifndef SPTM_NEST_FAST_SAMPLE
#define SPTM_NEST_FAST_SAMPLE 63u
#endif
/* nest_*: NEST level-2 entries naming a shared table (tables), answered by a
 * verdict (hits), scanned (scans), verdicts stored (records), other entries
 * walked per address (walked). unnest_*: the same for UNNEST tables (walked:
 * the original loop). sampled/mismatches: rescans of answered tables and
 * disagreements (must stay 0). detach_*: level-3 detaches proved empty
 * (their commits skip shadow_unmap on the same proof), and those that took
 * the original walk. unnest_counted (item 3): 4K hits answered with their
 * verdict's leaf count, without the scan. */
struct sptm_nest_fast_stats {
    uint64_t nest_tables, nest_hits, nest_scans, nest_records, nest_walked;
    uint64_t unnest_tables, unnest_hits, unnest_scans, unnest_records, unnest_walked;
    uint64_t sampled, mismatches;
#if SNAP_UNNEST_4K_FAST
    uint64_t detach_fast, detach_slow, unnest_counted, reserved;
#else
    uint64_t detach_fast, detach_slow, reserved[2];
#endif
};
_Static_assert(sizeof(struct sptm_nest_fast_stats)==128,"nest-fast stats stride");
#endif
#if SNAP_NEST_FAST
#include "sptm.h"
/* UNNEST's verdict for the shared level-3 table `table` at `base` of a root
 * of `format` and `flags` (sptm-root.c): 1 proved (a retained verdict, or
 * validate_table's level-3 scan just passed and was recorded), 0 not proved
 * (the caller runs its own check), -1 a sampled rescan disagreed (fatal). */
int sptm_root_shared_proof(const struct sptm_memory *m,uint64_t table,uint64_t base,
                           unsigned format,unsigned flags);
#endif
#if SNAP_UNNEST_4K_FAST
/* Item 3, for a 4K root's shared table: sptm_root_shared_proof at shift 12.
 * On a hit that is not sampled, *known is the leaf count the verdict carries
 * (UINT64_MAX: none yet); otherwise UINT64_MAX and the caller counts. */
int sptm_root_shared_proof_4k(const struct sptm_memory *m,uint64_t table,uint64_t base,
                              unsigned format,unsigned flags,uint64_t *known);
/* After the caller counted a table sptm_root_shared_proof_4k proved: its
 * verdict carries `leaves`. 1 recorded, 0 no verdict to carry it, -1 the
 * verdict already carried another count (a sampled recount disagreed: fatal,
 * a mismatch). */
int sptm_root_shared_count_4k(const struct sptm_memory *m,uint64_t table,uint64_t base,
                              unsigned format,unsigned flags,uint64_t leaves);
#endif

/* SPDX-License-Identifier: MIT */
#pragma once
/* SNAP_ROOT_CACHE_WIDE: 192 cached user roots instead of 64, opt-in, default
 * 0, default builds unchanged.
 *
 * Why (installed-fresh-20261017-v34): SWITCH_ROOT held the service lock 420.7
 * s of 576 s; 49,783 builds followed 49,661 evictions from the full 64-slot
 * cache at about 8.1 ms each, and every one of the 64 cached roots had been
 * installed within the last 366 installs: more than 64 roots are in use within
 * about 0.4 s. A cached shadow is derived state, so a larger cache changes
 * nothing but how often one is rebuilt. The arena kept 42,792 pages free at its
 * low water; a root's shadow and copies take about 91 pages.
 *
 * Shape. SPTM_ROOT_CACHE is 192: compat/sptm-root.c, the root policy helpers,
 * shadow/native-shared.c and every slot loop of probes/xnuboot.c see 192 slots.
 * Their state lives in struct root_ext, monitor arena pages taken first at
 * setup; struct context keeps every define-free field at its offset (64-slot
 * twins: sptm_root_state_compat, native_shared_compat, the 64-entry arrays),
 * refreshed from the live state at the stop (root_ext_mirror).
 *
 * Failure modes, written before the code; tools/test-root-wide.c checks each
 * and tools/test-root-wide.py requires a mutant of each guard to fail it:
 *  W1 a slot of 64 or more reaches a 64-slot structure: a mask bit, link bit,
 *     stamp, budget, view, proof, memo or owner record lost or out of range.
 *     Every per-slot record is SPTM_ROOT_CACHE long; masks and link bits are
 *     SPTM_ROOT_CACHE bits.
 *  W2 two slots share a table-pool owner: owner = slot + 1 <= 192, below
 *     NATIVE_SHARED_OWNER (200) and TABLE_POOL_FREE (255), asserted.
 *  W3 two slots share a hardware ASID, or one overflows: native_asid is
 *     0x100 + 4 slot + 2 w + k <= 0x403, within the 16-bit ASIDs user
 *     regimes select (TCR.AS, SPTM_ROOT_TCR_*), asserted.
 *  W4 a define-free reader sees a moved field or a moved table arena: twins
 *     keep every offset, the one new field is appended in the context's last
 *     page (asserted beside the exit profile's), tools/test-root-wide.py
 *     compares every define-free offset.
 *  W5 the state's pages handed out as tables: they precede next_table and keep
 *     table-pool owner 0, which nothing releases.
 *  W6 the transaction coverage sentinel arms a state page, whose stores carry
 *     no dirty note, and stops the run: those pages are excluded.
 *  W7 the guest writes the state: it stays in the stage-2 read-only arena (it
 *     can read root and table addresses there, as it can read the tables).
 *  W8 host readers at the stop see the twins stale: root_ext_mirror refreshes
 *     slots 0-63, counters, CPU records and native-shared groups after every
 *     executor quiesced (slots 64 and above are visible nowhere else).
 *  W9 a group linked by a slot of 64 or more is freed, or grows without that
 *     slot's link: link bits are NATIVE_SHARED_SLOTS (192) wide.
 *  W10 a default build changes: the define-off source is token-identical.
 * Unchanged: SWITCH_ROOT's protocol, installation, shared-slot flushes,
 * kernel PPERM variants, TPRO trees, arena reserve and reclaim (now over 192
 * slots), SNAP_ROOT_MISS_FAST and SNAP_UPDATE_DISJOINT_FAST. */
#include "sptm-root.h"
#include "../shadow/native-shared.h"

_Static_assert(SPTM_ROOT_CACHE%64u==0 && SPTM_ROOT_CACHE<=NATIVE_SHARED_SLOTS,
               "a mask word and a link bit for every slot");
_Static_assert(0x100u+4u*SPTM_ROOT_CACHE<=0x10000u,"native ASIDs stay within 16 bits");
_Static_assert(((SPTM_ROOT_TCR_16K&SPTM_ROOT_TCR_4K)>>36)&1,
               "user regimes select 16-bit ASIDs");

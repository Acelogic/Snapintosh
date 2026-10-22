/* SPDX-License-Identifier: MIT */
#ifndef SNAP_DART_CONVERTED_H
#define SNAP_DART_CONVERTED_H
#include <stdint.h>
#include "cpu.h"
#include "fine-lock.h"

/* SNAP_DART_CONVERTED (opt-in, default 0; batch9/dart FAILURES-AND-DESIGN.md
 * A1-A19): the Adreno DART's MAP and UNMAP (native table 3, endpoints 2 and 3,
 * the virtual DART SPTM_DART_ADRENO stream 0, with ADRENO_F_DART) as converted
 * calls, without the service token: batch 5's SNAP_TOKEN_TRIM part B on its
 * own, which never ran on hardware (installed-fresh-20261020-v4 stopped in
 * part A first). installed-fresh-20261020-v9: 3.85M such MAPs held the token
 * 49.3 s and waited 87.7 s for it, and every token hold delays the converted
 * calls at the gate as well.
 *
 * The gate shared, no stripe (the call names no root), then this device lock
 * (FIFO), then the token path's body on a fine memory: device_dart_admit_frame,
 * sptm_dart_map/unmap with this CPU's reference batch (atomic deltas beside
 * converted user calls on the same frames) and the DART memo, a publish that
 * feeds the DART memo's witness and then the SWITCH_ROOT memo's (under aux),
 * and the SMMU CB0 mirror, whose UNMAP returns only after the SMMU TLB
 * invalidation completed (probes/xnuboot.c fine_dart_call). Every other
 * writer of what it touches holds the token, which drains the gate first.
 *
 * Lock order: gate (shared) < stripes < device < aux. DART calls take no
 * stripe, user calls never take the device lock, the token holder neither;
 * nothing waits for the gate or the token while holding or waiting for it.
 *
 * No report record of its own: the fine profile's dart_map and dart_unmap
 * buckets (header bit 2) carry entries, gate wait, device-lock wait (as stripe
 * wait), hold and contention; the token costs' other.dart_map the declined
 * rest; the GPU counters the mirror's maps, unmaps and TLB invalidations. */
#ifndef SNAP_DART_CONVERTED
#define SNAP_DART_CONVERTED 0
#endif
#if SNAP_DART_CONVERTED
struct dart_converted_state {
    struct fine_ticket device;                 /* the Adreno DART, the DART memo and the SMMU CB0 mirror */
    uint64_t device_wait[GUEST_CPU_COUNT][2];  /* this CPU's current call: device-lock wait ticks, waited */
} __attribute__((aligned(64)));
#endif
#endif

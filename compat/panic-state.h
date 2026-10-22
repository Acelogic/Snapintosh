/* SPDX-License-Identifier: MIT */
#pragma once
#include <stdint.h>

#define SPTM_PANIC_PAGE_SIZE 0x4000UL
#define SPTM_PANIC_HANDOFF_OFFSET 0x198UL
#define SPTM_PANIC_NO_OWNER 0x8000UL
/* Access is serialized by the monitor's global service token. The owner is
 * the logical guest CPU, not MPIDR affinity or the CPU making a later call. */
struct sptm_panic_state {
    uint64_t triggered, owner, phase, entries, rejected;
    uint64_t cpu_entries[6];
};
_Static_assert(sizeof(struct sptm_panic_state)==88,"panic-state audit layout");
void sptm_panic_init(struct sptm_panic_state *);
int sptm_panic_enter(struct sptm_panic_state *, unsigned cpu);
/* The panic-only dispatch/diagnostic return protocol is not implemented yet.
 * Refuse it explicitly instead of processing ordinary services after panic.
 * Repeated exact PANIC_ENTRY remains admitted, as in the native dispatcher. */
int sptm_panic_dispatch(struct sptm_panic_state *, unsigned cpu, uint64_t x16);

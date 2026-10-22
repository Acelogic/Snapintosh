/* SPDX-License-Identifier: MIT */
#ifndef SNAP_SECONDARY_H
#define SNAP_SECONDARY_H
#include <stdint.h>
#define SECONDARY_MAGIC UINT64_C(0x31504d5350414e53) /* SNAPSMP1 */
struct secondary_config {
    uint64_t magic, size, boot_affinity, mask;
    uint64_t regime[4]; /* SCTLR, TCR, TTBR0, MAIR: host-verified EL2 mappings */
    uint64_t affinity[6], redistributor[6];
};
/* First 88 bytes are shared with secondary.S. Records occupy separate pages.
 * Immutable launch data is published before CPU_ON; each CPU owns its report. */
struct secondary {
    uint64_t regime[4], cpu, stack, affinity, redistributor;
    uint64_t vectors, callback, stop_callback;
    uint64_t phase, error, observed_affinity, observed_sp;
    uint64_t group, priority, waker, gic_saved, cleanup;
    uint64_t on_result, off_result, affinity_result;
    uint64_t prepare_result, entered, finish_result;
    uint64_t observed_regime[4], active_vncr, active_vmpidr, active_vttbr;
    uint64_t initial_cpacr, initial_cptr, final_cpacr, final_cptr;
};
_Static_assert(sizeof(struct secondary_config)==160,"secondary host ABI");
_Static_assert(sizeof(struct secondary)==37*8,"secondary report ABI");
_Static_assert(__builtin_offsetof(struct secondary,stack)==40,"secondary stack ABI");
_Static_assert(__builtin_offsetof(struct secondary,vectors)==64,"secondary vector ABI");
_Static_assert(__builtin_offsetof(struct secondary,callback)==72,"secondary callback ABI");
_Static_assert(__builtin_offsetof(struct secondary,stop_callback)==80,"secondary stop ABI");
_Static_assert(__builtin_offsetof(struct secondary,phase)==88,"secondary phase ABI");
int64_t secondary_psci(uint64_t fn, uint64_t a, uint64_t b, uint64_t c);
void secondary_entry(void);
void secondary_guest_enter(uint64_t entry, uint64_t out) __attribute__((noreturn));
int secondary_gic_start(struct secondary *s);
int secondary_gic_stop(struct secondary *s);
void secondary_power_off(struct secondary *s) __attribute__((noreturn));
#endif

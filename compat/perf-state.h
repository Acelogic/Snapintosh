/* SPDX-License-Identifier: MIT */
/* The monitor's appended performance state (probes/xnuboot.c, struct
 * context.perf), present in every build so host layout readers see one
 * context size; its counters stay zero unless SNAP_FAST_VCPU_TRAPS,
 * SNAP_SYSREG_CENSUS, SNAP_INCREMENTAL_PUBLISH, SNAP_CANONICAL_VIEW_FAST,
 * SNAP_VECTOR_BRANCH or SNAP_FAST_CROSSINGS is on. (struct exit_profile,
 * below, is the one opt-in exception: see its comment.)
 * tools/perf_counters.py decodes it from the bytes at
 * context + offsetof(context, perf). */
#pragma once
#include "cpu.h"
#include "fast-trap.h"
#include "service-profile.h"
#include "sptm-root.h"
#include "../shadow/root-publish-index.h"

struct canonical_view_perf {
    struct sptm_view_mapped_stats mapped;
    uint64_t sampled,mismatches;   /* reference re-walks (1 in 64); must stay 0 */
};
struct perf_state {
    struct fast_trap_cpu fast[GUEST_CPU_COUNT];
    struct sysreg_census_cpu census[GUEST_CPU_COUNT];
    struct root_publish_index root_index;
    struct canonical_view_perf canonical;
};

/* The exit profile: appended after every other field of struct context, and
 * only when SNAP_FAST_EL0_SYSREG or SNAP_SERVICE_SUBCLASS is on. It fits in
 * the context's last page, before the 4K-aligned table arena, and
 * probes/xnuboot.c asserts that the arena does not move, so define-free
 * layout readers (tools/monitor_layout.py, probes/run.py's arena base) still
 * agree on every offset; tools/perf_counters.py decode_exit_profile reads it
 * with the build defines. Zero unless its define is on.
 *
 * Per lock-free exit class, timing[] holds (exits << FAST_EXIT_COUNT_SHIFT) +
 * the CNTPCT ticks from the end of sync_lower's register save to the end of
 * xnuboot_pauth_resume (the EL0 key reload included; the hardware exception,
 * the register save/restore and the ERET excluded). Slots 0..10 are the
 * fast-trap classes 1..11 (compat/fast-trap.h), slots 11..17 the boundary
 * classes 1..7 (compat/fast-vector.h, 7 = the EL0 emulation). One add per
 * exit: the 36-bit tick field holds over 59 minutes of 19.2 MHz exits per
 * class and CPU, the 28-bit count 268 million; an exit of 2^32 ticks or
 * more is counted in slow instead. */
#define FAST_EXIT_CLASSES 18u
#define FAST_EXIT_TRAP_SLOT(cls) ((cls) - 1u)
#define FAST_EXIT_CROSS_SLOT(cls) ((cls) + 10u)
#define FAST_EXIT_COUNT_SHIFT 36
#define FAST_EXIT_TICK_LIMIT (UINT64_C(1) << 32)
struct fast_exit_cpu {
    uint64_t el0[4];    /* SNAP_FAST_EL0_SYSREG: emulated counter, emulated UPERM,
                         * declined other word, declined by a guard */
    uint64_t timing[FAST_EXIT_CLASSES];   /* SNAP_SERVICE_SUBCLASS, see above */
    uint64_t slow;      /* ...exits of FAST_EXIT_TICK_LIMIT ticks or more */
    uint64_t max;       /* ...the longest exit charged, in ticks */
} __attribute__((aligned(64)));
_Static_assert(sizeof(struct fast_exit_cpu) == 192, "three cache lines per CPU");
struct exit_profile {
    struct service_sub_profile sub;          /* SNAP_SERVICE_SUBCLASS, under the lock */
    struct fast_exit_cpu cpu[GUEST_CPU_COUNT];  /* written by that CPU only */
};
/* One lock-free exit, charged by its own CPU; mark is frame slot 31: the
 * class slot + 1 in the top byte over the start tick. */
static inline void fast_exit_charge(struct fast_exit_cpu *p, uint64_t mark, uint64_t now)
{
    uint64_t slot = mark >> 56, ticks = (now - mark) & ((UINT64_C(1) << 56) - 1);
    if (!slot || slot > FAST_EXIT_CLASSES) return;
    if (ticks >= FAST_EXIT_TICK_LIMIT) { p->slow++; return; }
    p->timing[slot - 1] += (UINT64_C(1) << FAST_EXIT_COUNT_SHIFT) + ticks;
    if (ticks > p->max) p->max = ticks;
}
static inline uint64_t fast_exit_mark(uint64_t start, unsigned slot)
{
    return (start & ((UINT64_C(1) << 56) - 1)) | ((uint64_t)(slot + 1) << 56);
}

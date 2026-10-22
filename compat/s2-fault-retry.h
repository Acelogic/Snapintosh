/* SPDX-License-Identifier: MIT */
/* SNAP_S2_FAULT_RETRY (probes/xnuboot.c s2_fault_retry): a guest stage-2
 * TRANSLATION fault that would stop the run is retried instead, when the
 * address the hardware names (HPFAR_EL2) is guest RAM that this CPU's own
 * stage-2 tree maps. SNAP_S2_FAULT_RETRY_STAGE1 (which needs it) also
 * retries a fault whose hardware IPA is not mapped but whose stage-1
 * re-walk's is; without it that case stops, because the hardware's stage-1
 * translation was not the tables' and a translation like it that did not
 * fault may already have written the wrong page (the guest writes the real
 * install's disk).
 *
 * Why (docs/USER-HW-WALK-20261017.md "v65"). v62, v63 and v65 stopped on a user
 * store pair with a stage-2 translation fault (levels 2, 2 and 1) on what the
 * stop reported as mapped guest RAM. That reported IPA is the stage-1 re-walk
 * (AT S1E1R) done while handling the fault, not HPFAR_EL2, so the address the
 * hardware actually faulted on was never recorded. A translation fault is
 * never cached, so at that moment the walker read an invalid descriptor:
 * either for that IPA (a different stage-2 root or VTCR, or a torn table) or
 * for another IPA (a stage-1 translation, stale or torn, that differs from the
 * tables as they are now). This retries such a fault, bounded, and keeps a
 * snapshot of each one that tells those cases apart.
 *
 * What is recorded for every stage-2 translation fault that reaches the stop
 * (a device window, model or guard answered earlier is not one), retried or
 * not: VTTBR, VTCR and HCR as they are now and as this vCPU set them; ESR,
 * FAR, HPFAR, ELR, SPSR; TTBR0_EL1 and TCR_EL1; the CPU (MPIDR, slot) and
 * CNTPCT; HPFAR's IPA and the stage-1 re-walk's IPA, each with the three
 * descriptors of its walk through the tree VTTBR names now.
 *
 * Eligibility (else the run stops exactly as before, snapshot kept):
 *  - EC 0x24 or 0x20 with FSC 0b0001LL (translation fault, level LL); access
 *    flag and permission faults (an S2RO frame written: an XNU bug) are not;
 *  - VTTBR is this vCPU's, the VTCR fields the monitor sets (T0SZ, SL0, IRGN0,
 *    ORGN0, SH0, TG0, PS, VS) are its own, and HCR_EL2.VM is set. A register
 *    that is wrong now is a monitor bug, not a transient, and stops;
 *  - HPFAR's IPA is guest RAM [mem_low, mem_high) mapped to itself in that
 *    tree (S2_RETRY_MAPPED). If it is not but the re-walk's IPA is
 *    (S2_RETRY_STAGE1: the hardware's stage-1 translation was not the
 *    tables' now), the fault is recorded and stops (S2_RETRY_STOP_STAGE1)
 *    unless SNAP_S2_FAULT_RETRY_STAGE1 asks for that retry too.
 * Bounds, per vCPU: the same access (PC and FAR) faulting S2_RETRY_REPEAT_MAX
 * times in a row stops (two retries did not help), and more than
 * S2_RETRY_RATE_MAX retries in one second (CNTFRQ ticks) stops.
 * A retry invalidates this CPU's stage 1 and stage 2 for its VMID (TLBI
 * VMALLS12E1) and returns to the faulting instruction.
 *
 * The state is one monitor arena page (owner 0, taken at setup, stored without
 * a note, excluded from the coverage sentinel), named by context.s2_retry;
 * tools/s2-retry-dump.py decodes it from a run's work dump.
 *
 * Failure inventory: a permission or access-flag fault retried; a fault on an
 * IPA outside guest RAM retried (a device the tree names without a model must
 * still stop); a STAGE1 fault retried without SNAP_S2_FAULT_RETRY_STAGE1, or
 * a MAPPED one stopped; a retry with a wrong VTTBR, VTCR or VM bit; an unbounded retry
 * loop (the same access, or a storm); a retry without the invalidation; a
 * snapshot that misses HPFAR or names the re-walk's IPA as the hardware's; a
 * default build that changes. */
#pragma once
#include <stdint.h>

#define S2_RETRY_RING 16u
#define S2_RETRY_CPUS 6u
#define S2_RETRY_RATE_MAX 1000u        /* retries per vCPU per second */
#define S2_RETRY_REPEAT_MAX 3u         /* the same access this many times in a row stops */

enum s2_retry_kind {
    S2_RETRY_NONE = 0,
    S2_RETRY_MAPPED = 1,               /* HPFAR's IPA: guest RAM, mapped in the current tree */
    S2_RETRY_STAGE1 = 2,               /* HPFAR's is not; the stage-1 re-walk's IPA is */
};
enum s2_retry_verdict {
    S2_RETRY_RESUME = 0,
    S2_RETRY_STOP_REGISTERS = 1,       /* VTTBR, VTCR or HCR_EL2.VM not this vCPU's now */
    S2_RETRY_STOP_UNMAPPED = 2,        /* neither IPA is mapped guest RAM */
    S2_RETRY_STOP_REPEAT = 3,          /* the same access again: retrying did not help */
    S2_RETRY_STOP_RATE = 4,            /* more than S2_RETRY_RATE_MAX in a second */
    S2_RETRY_STOP_STAGE1 = 5,          /* STAGE1, and SNAP_S2_FAULT_RETRY_STAGE1 is off */
};

struct s2_retry_entry {
    uint64_t seq;                      /* 1-based; written last */
    uint64_t counter, mpidr;
    uint64_t info;                     /* slot | level << 8 | kind << 16 | verdict << 24 */
    uint64_t esr, far, hpfar, elr, spsr;
    uint64_t vttbr, vttbr_expected, vtcr, vtcr_expected, hcr;
    uint64_t ttbr0, tcr;
    uint64_t ipa_hw, ipa_at;           /* HPFAR's IPA; the AT S1E1R re-walk's (0: none) */
    uint64_t d_hw[3], d_at[3];         /* level 1, 2, 3 descriptors as read now (0: not read) */
};
struct s2_retry_cpu {
    uint64_t last_pc, last_far, repeats;
    uint64_t window_start, window_count;
    uint64_t resumed, stopped;
};
struct s2_retry_state {
    uint64_t next;                     /* entries written (ring index source) */
    uint64_t faults, resumed, stopped, mapped, stage1;
    struct s2_retry_cpu cpu[S2_RETRY_CPUS];
    struct s2_retry_entry ring[S2_RETRY_RING];
};
_Static_assert(sizeof(struct s2_retry_state) <= 4096, "one arena page");
#define S2_RETRY_PAGES 1u

/* The level of a translation fault (0-3), or -1 for anything else. */
static inline int s2_retry_translation(uint64_t esr)
{
    unsigned ec = (unsigned)(esr >> 26) & 63, fsc = (unsigned)esr & 63;
    if (ec != 0x24 && ec != 0x20) return -1;
    return (fsc & 0x3c) == 0x04 ? (int)(fsc & 3) : -1;
}

/* HPFAR_EL2.FIPA (IPA[47:12]) plus FAR's page offset, which is not the
 * faulting address's when the stage-1 walk faulted (S1PTW: a table page). */
static inline uint64_t s2_retry_hpfar_ipa(uint64_t hpfar, uint64_t far, uint64_t esr)
{
    uint64_t page = ((hpfar & UINT64_C(0x00000ffffffffff0)) >> 4) << 12;
    return page | (((esr >> 7) & 1) ? 0 : (far & 0xfff));
}

/* The VTCR_EL2 the monitor programs (probes/xnuboot.c vcpu_arch_prepare), and
 * the fields of it compared: T0SZ, SL0, IRGN0, ORGN0, SH0, TG0, PS and VS.
 * RES1 bit 31 and the feature fields above are not the monitor's. */
#define S2_RETRY_VTCR_FIELDS UINT64_C(0xfffff)
static inline uint64_t s2_retry_vtcr(uint64_t txsz, uint64_t parange)
{
    return txsz | (UINT64_C(1) << 6) | (UINT64_C(1) << 8) | (UINT64_C(1) << 10)
         | (UINT64_C(3) << 12) | (UINT64_C(0) << 14) | (parange << 16);
}
static inline int s2_retry_registers_ok(uint64_t vttbr, uint64_t vttbr_expected,
                                        uint64_t vtcr, uint64_t vtcr_expected, uint64_t hcr)
{
    return vttbr == vttbr_expected &&
           (vtcr & S2_RETRY_VTCR_FIELDS) == (vtcr_expected & S2_RETRY_VTCR_FIELDS) && (hcr & 1);
}

/* Walk ipa through the stage-2 tree at root as the hardware would with the
 * monitor's VTCR (4K granule, T0SZ txsz, start level 1). d[] gets each
 * descriptor read (0 where none was). Nonzero when ipa reaches a valid leaf
 * (a page, or a 1G/2M block) that maps it to itself. */
static inline int s2_retry_walk(int (*read)(void *, uint64_t, uint64_t *), void *ctx,
                                uint64_t root, uint64_t txsz, uint64_t ipa, uint64_t d[3])
{
    d[0] = d[1] = d[2] = 0;
    if (txsz < 25 || txsz > 33 || (ipa >> (64 - txsz))) return 0;
    uint64_t table = root & UINT64_C(0x0000fffffffff000);
    for (unsigned level = 1; level <= 3; level++) {
        unsigned shift = 12 + 9 * (3 - level);
        uint64_t e;
        if (read(ctx, table + 8 * ((ipa >> shift) & 511), &e)) return 0;
        d[level - 1] = e;
        if (!(e & 1)) return 0;
        uint64_t oa = e & UINT64_C(0x0000fffffffff000);
        if (level == 3 || !(e & 2)) {
            if (level == 3 && !(e & 2)) return 0;    /* reserved at level 3 */
            uint64_t span = UINT64_C(1) << shift;
            return (oa & ~(span - 1)) == (ipa & ~(span - 1) & UINT64_C(0x0000fffffffff000));
        }
        table = oa;
    }
    return 0;
}

static inline int s2_retry_dram(uint64_t ipa, uint64_t lo, uint64_t hi)
{
    return ipa >= lo && ipa < hi;
}

/* The bounds, for an eligible fault on vCPU cpu at CNTPCT now (hz ticks a
 * second): RESUME, STOP_REPEAT or STOP_RATE; counts it either way. */
static inline enum s2_retry_verdict s2_retry_decide(struct s2_retry_cpu *cpu, uint64_t now, uint64_t hz,
                                                    uint64_t pc, uint64_t far)
{
    if (cpu->repeats && pc == cpu->last_pc && far == cpu->last_far) cpu->repeats++;
    else {cpu->last_pc = pc; cpu->last_far = far; cpu->repeats = 1;}
    if (cpu->repeats >= S2_RETRY_REPEAT_MAX) return S2_RETRY_STOP_REPEAT;
    if (!cpu->window_count || now - cpu->window_start >= hz) {cpu->window_start = now; cpu->window_count = 0;}
    if (++cpu->window_count > S2_RETRY_RATE_MAX) return S2_RETRY_STOP_RATE;
    return S2_RETRY_RESUME;
}

/* One fault's verdict from what was read: the registers, then which IPA (if
 * either) is mapped guest RAM, STAGE1 only when stage1_retry
 * (SNAP_S2_FAULT_RETRY_STAGE1), then the bounds. kind gets the IPA's kind. */
static inline enum s2_retry_verdict s2_retry_judge(struct s2_retry_cpu *cpu, int registers_ok,
                                                   int hw_mapped, int at_mapped, int stage1_retry,
                                                   uint64_t now, uint64_t hz, uint64_t pc, uint64_t far,
                                                   enum s2_retry_kind *kind)
{
    *kind = hw_mapped ? S2_RETRY_MAPPED : at_mapped ? S2_RETRY_STAGE1 : S2_RETRY_NONE;
    if (!registers_ok) return S2_RETRY_STOP_REGISTERS;
    if (*kind == S2_RETRY_NONE) return S2_RETRY_STOP_UNMAPPED;
    if (*kind == S2_RETRY_STAGE1 && !stage1_retry) return S2_RETRY_STOP_STAGE1;
    return s2_retry_decide(cpu, now, hz, pc, far);
}

/* Keep e in the ring (the oldest goes); seq last, so a reader skips a slot
 * being written. Counts the fault and its outcome. */
static inline void s2_retry_note(struct s2_retry_state *s, struct s2_retry_entry *e, unsigned slot,
                                 int level, enum s2_retry_kind kind, enum s2_retry_verdict verdict)
{
    uint64_t n = __atomic_fetch_add(&s->next, 1, __ATOMIC_RELAXED);
    e->info = (uint64_t)slot | ((uint64_t)(level & 0xff) << 8) | ((uint64_t)kind << 16) |
              ((uint64_t)verdict << 24);
    struct s2_retry_entry *dst = &s->ring[n % S2_RETRY_RING];
    __atomic_store_n(&dst->seq, 0, __ATOMIC_RELAXED);
    /* Word by word (every field is a uint64_t): no memcpy in the monitor. */
    const uint64_t *from = (const uint64_t *)e;
    volatile uint64_t *to = (volatile uint64_t *)dst;
    for (unsigned w = 1; w < sizeof(*e) / 8; w++) to[w] = from[w];
    __atomic_store_n(&dst->seq, n + 1, __ATOMIC_RELEASE);
    __atomic_fetch_add(&s->faults, 1, __ATOMIC_RELAXED);
    if (slot < S2_RETRY_CPUS) {
        if (verdict == S2_RETRY_RESUME) s->cpu[slot].resumed++; else s->cpu[slot].stopped++;
    }
    if (verdict == S2_RETRY_RESUME) {
        __atomic_fetch_add(&s->resumed, 1, __ATOMIC_RELAXED);
        __atomic_fetch_add(kind == S2_RETRY_MAPPED ? &s->mapped : &s->stage1, 1, __ATOMIC_RELAXED);
    } else __atomic_fetch_add(&s->stopped, 1, __ATOMIC_RELAXED);
}

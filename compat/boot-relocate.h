/* SPDX-License-Identifier: MIT */
/* SNAP_BOOT_RELOCATE (probes/xnuboot.c): vCPU 0, the guest's boot CPU, runs on
 * a physical CPU other than the one inside q1n1's P_CALL, so all six vCPUs can
 * share one cluster that is not q1n1's: on the A16, Prime cluster 1 (MPIDR
 * 0x10000-0x10500, MADT efficiency class 1) instead of cluster 0 (0x0-0x500,
 * class 0), where q1n1 runs.
 *
 * Why one cluster (v26, 2026-10-17). The monitor's service lock is a single
 * test-and-set word taken with LDAXR/STXR (compat/service-lock.c; the monitor
 * is built without LSE, so there is no CAS and no queue). v26 put vCPU 0 on
 * cluster 0 and vCPU 1 on Prime cluster 1. vCPU 1 spun in XNU's
 * hw_lck_ticket_contended, whose WFE traps (HCR_EL2.TWE) took the service lock
 * 915,111 times in 1.39 s, on a ticket lock vCPU 0 held in thread_select. vCPU
 * 0's next trap then waited the full second for the service lock
 * (max_wait_ticks 19,200,004 at 19.2 MHz) and stopped the run with
 * SERVICE_TIMEOUT: the "6" in "faults (6, 0, 0, 0, 0, 0)" is that enum value,
 * not a count. Across 26 single-cluster runs the longest wait was 115 ms. A
 * waiter in another cluster loses nearly every race against a releaser that
 * re-acquires from its own L1, so placement across clusters needs a fair
 * (queued) lock first. Until then every vCPU shares one cluster, and moving
 * vCPU 0 off q1n1's CPU is what lets that cluster be a Prime one. XNU starts
 * its secondaries one at a time, so v26's other four records stayed unlaunched
 * (on_result UINT64_MAX): a consequence, not a second failure.
 *
 * Protocol:
 *  - the host sets secondary_config.mask bit 0 and affinity[0] and
 *    redistributor[0] (tools/secondary-runtime.py, SNAP_SMP_PRIME=1). A monitor
 *    built without this define refuses bit 0 (secondary_prepare_records), so a
 *    mismatched build never runs the guest on q1n1's CPU by accident;
 *  - q1n1's CPU runs the shared preparation (xnuboot_prepare without
 *    vcpu_arch_prepare), routes the Adreno SPI to the target, records its own
 *    EL1/EL2 state and ID registers, and CPU_ONs the target through
 *    secondary_entry with record page 0;
 *  - the target compares the ID registers the shared preparation used and its
 *    clock (the guest clock is CNTVCT_EL0 read at EL2, so CNTVOFF_EL2, which the
 *    monitor never programs, and CNTFRQ_EL0 must equal q1n1's CPU's), starts
 *    its GIC timer PPI, installs vCPU 0's per-CPU state (vcpu_arch_prepare), arms
 *    its watchdog and enters the guest as the boot CPU (x0 = 0);
 *  - q1n1's CPU only serves the relay meanwhile: q1n1's call service runs only
 *    on the CPU inside the P_CALL (q1n1 platform/uefi/main.c), so vCPU 0's host
 *    polls (early_stop_host_call) are posted here and run by q1n1's CPU;
 *  - the target ends as an executor (xnuboot_relocated_stop: its own debug,
 *    timer and GIC state, guest_service_finish, CPU_OFF); q1n1's CPU waits for
 *    phase 4 and PSCI OFF, puts its own saved registers back into vCPU 0's
 *    record and runs the unchanged report and return.
 *
 * Failure inventory: a default build that changes; bit 0 accepted without the
 * define; a target equal to q1n1's CPU or a secondary's, an aliased or
 * out-of-range redistributor, or a layout spanning clusters; the q1n1 call
 * service run from the target; the target's exit unwinding as q1n1, or on
 * q1n1's stack; q1n1's report restoring the target's registers onto q1n1's CPU
 * (VTTBR, VMPIDR, CNTHCTL, MDCR, debug banks, EL2 timer); the Adreno SPI left
 * routed to q1n1's CPU; q1n1's CPU returning while the target may still run
 * monitor code (no arrival, no finish, CPU_OFF failed); ID registers the shared
 * preparation read on q1n1's CPU, or its CNTVOFF_EL2 or CNTFRQ_EL0, differing on
 * the target; a relayed call whose caller gave up having the late answer
 * written into its stack; any system register read or written on either CPU
 * that is not an architecturally allocated, A16-implemented encoding (v48 read
 * the whole ID group through probes/idregs.h and faulted on S3_0_C0_C0_1:
 * BOOT_RELOCATE_ID_REGS below; tools/test-boot-relocate.py checks every MRS and
 * MSR the define adds against an allowlist); bit 0 read as a releasable
 * secondary, or a release refused because of it (v51:
 * boot_relocate_release_mask). */
#pragma once

#define BOOT_RELOCATE_MASK 1                 /* secondary_config.mask bit 0 */
/* struct boot_relocation (probes/xnuboot.c) and struct context offsets the
 * exit path reads in assembly; both are asserted there. */
#define BOOT_RELOCATE_ARMED 296              /* after struct secondary */
#define CONTEXT_SECONDARY_BASE 1802088
/* Prepare results (OUT_STATUS) of a relocation that never entered the guest. */
#define BOOT_RELOCATE_E_CPU_ON (-80)         /* AFFINITY_INFO not OFF, or CPU_ON refused */
#define BOOT_RELOCATE_E_ARRIVAL (-81)        /* the target turned OFF without reaching the monitor */
#define BOOT_RELOCATE_E_TARGET (-82)         /* the target stopped before guest entry (record error) */
/* Record 0 errors: secondary_run's 0x100-0x106, plus this one. */
#define BOOT_RELOCATE_ERROR_ID 0x107         /* an ID register the shared preparation used differs */
#define BOOT_RELOCATE_ERROR_CLOCK 0x108      /* CNTVOFF_EL2 or CNTFRQ_EL0 differs from q1n1's CPU */

#ifndef __ASSEMBLER__
#include <stdint.h>

#define BOOT_RELOCATE_AFFINITY UINT64_C(0xff00ffffff)
#define BOOT_RELOCATE_CLUSTER UINT64_C(0xff00ff0000)    /* Aff3 and Aff2 */
#define BOOT_RELOCATE_GICR_FIRST UINT64_C(0x17080000)
#define BOOT_RELOCATE_GICR_END UINT64_C(0x17500000)
#define BOOT_RELOCATE_GICR_STRIDE UINT64_C(0x40000)
/* The ID registers both CPUs read and compare, as X(name, op1, CRn, CRm, op2,
 * shared) with op0 = 3. Only architecturally allocated encodings (Arm ARM,
 * DDI 0487, "ID registers" / the op0=3, op1=0, CRn=0 space), and only ones
 * this monitor already reads natively on the A16 at EL2: MIDR, PFR0, PFR1 and
 * MMFR2 in vcpu_arch_prepare's ID log, ISAR0-2 and PFR0/1 in
 * pauth_domain_prepare, MMFR0 in xnuboot_prepare, MMFR1 for PAN and DFR0 for
 * the writer breakpoints. Never the whole ID group: CRm=0's op2 1-4 and 7 are
 * unallocated and UNDEFINED, and with FEAT_IDST the Oryon reports the read as
 * a trap (v48: ESR 0x62320001, MRS S3_0_C0_C0_1 from probes/idregs.h's
 * id_register, an EL2 fault before the guest ran). shared = 1: the shared
 * preparation read it on q1n1's CPU and relies on it for every vCPU (PFR0/1:
 * pauth_domain_prepare and txm_native_init's forged pair; ISAR0-2:
 * pauth_domain_prepare; MMFR0: the counter/ECV check). The rest is evidence. */
#define BOOT_RELOCATE_ID_REGS(X) \
    X(MIDR_EL1,         0, 0, 0, 0, 0) \
    X(ID_AA64PFR0_EL1,  0, 0, 4, 0, 1) \
    X(ID_AA64PFR1_EL1,  0, 0, 4, 1, 1) \
    X(ID_AA64DFR0_EL1,  0, 0, 5, 0, 0) \
    X(ID_AA64ISAR0_EL1, 0, 0, 6, 0, 1) \
    X(ID_AA64ISAR1_EL1, 0, 0, 6, 1, 1) \
    X(ID_AA64ISAR2_EL1, 0, 0, 6, 2, 1) \
    X(ID_AA64MMFR0_EL1, 0, 0, 7, 0, 1) \
    X(ID_AA64MMFR1_EL1, 0, 0, 7, 1, 0) \
    X(ID_AA64MMFR2_EL1, 0, 0, 7, 2, 0)
enum boot_relocate_id {
#define BOOT_ID_INDEX(name, op1, crn, crm, op2, shared) BOOT_ID_##name,
    BOOT_RELOCATE_ID_REGS(BOOT_ID_INDEX)
#undef BOOT_ID_INDEX
    BOOT_ID_COUNT
};
#define BOOT_ID_SHARED_BIT(name, op1, crn, crm, op2, shared) | ((uint64_t)(shared) << BOOT_ID_##name)
#define BOOT_RELOCATE_ID_SHARED (UINT64_C(0) BOOT_RELOCATE_ID_REGS(BOOT_ID_SHARED_BIT))
_Static_assert(BOOT_ID_COUNT <= 64, "one mismatch bit per register");

static inline int boot_relocate_gicr_valid(uint64_t r)
{
    return r >= BOOT_RELOCATE_GICR_FIRST && r < BOOT_RELOCATE_GICR_END &&
           !((r - BOOT_RELOCATE_GICR_FIRST) % BOOT_RELOCATE_GICR_STRIDE);
}

/* The monitor's check of a relocation request (mask bit 0), in addition to
 * secondary_prepare_records' existing per-secondary checks: a well-formed
 * target that is neither q1n1's CPU nor a secondary's, a redistributor of its
 * own, and every enabled vCPU in the target's cluster. */
static inline int boot_relocate_layout_valid(uint64_t boot, uint64_t mask,
                                             const uint64_t affinity[6],
                                             const uint64_t redistributor[6])
{
    if (!(mask & BOOT_RELOCATE_MASK)) return 1;
    uint64_t target = affinity[0];
    if ((target & ~BOOT_RELOCATE_AFFINITY) || target == boot ||
        !boot_relocate_gicr_valid(redistributor[0])) return 0;
    for (unsigned i = 1; i < 6; i++) {
        if (!(mask & (1u << i))) continue;
        if (affinity[i] == target || redistributor[i] == redistributor[0] ||
            (affinity[i] & BOOT_RELOCATE_CLUSTER) != (target & BOOT_RELOCATE_CLUSTER)) return 0;
    }
    return 1;
}

/* The secondaries the guest may release through the PMGR CPU-start block
 * (compat/cpu-release.h): the host mask without bit 0, which asks for vCPU 0's
 * relocation and is not a release bit. v51 passed 0x3f, so
 * guest_cpu_release_write refused XNU's first CPU-start write (ApplePMGR's
 * register-write helper, PMGR reg 24 +0x4004, the global core mask, value 0x2
 * for CPU 1). That write fell through to stage 2 and stopped the run (exit 6)
 * before any secondary started. */
static inline uint64_t boot_relocate_release_mask(uint64_t mask)
{
    return mask & ~(uint64_t)BOOT_RELOCATE_MASK;
}

/* Which shared-preparation ID registers differ between q1n1's CPU and the
 * target, one bit per BOOT_RELOCATE_ID_REGS row; zero when the target may run
 * vCPU 0. */
static inline uint64_t boot_relocate_id_mismatch(const uint64_t boot[BOOT_ID_COUNT],
                                                 const uint64_t target[BOOT_ID_COUNT])
{
    uint64_t mismatch = 0;
    for (unsigned n = 0; n < BOOT_ID_COUNT; n++)
        if (((BOOT_RELOCATE_ID_SHARED >> n) & 1) && boot[n] != target[n])
            mismatch |= UINT64_C(1) << n;
    return mismatch;
}

/* q1n1's CPU while the target runs vCPU 0. */
enum boot_wait_action {
    BOOT_WAIT_SERVE,      /* keep serving the relay and polling */
    BOOT_WAIT_STOP,       /* request a fault stop, then keep waiting */
    BOOT_WAIT_HANDBACK,   /* the target can no longer run monitor code: report */
    BOOT_WAIT_QUARANTINE  /* CPU_OFF returned: the target spins in monitor text forever */
};
struct boot_wait {
    uint64_t phase;       /* record.phase, loaded with acquire */
    int64_t off;          /* last AFFINITY_INFO of the target: 1 OFF, 0 ON, 2 ON_PENDING, <0 error */
    uint64_t now, launched;               /* CNTPCT */
    uint64_t arrival, session;            /* ticks after launch */
    int stopped;          /* the run's sticky stop word is set */
};
static inline enum boot_wait_action boot_relocate_wait(const struct boot_wait *w)
{
    if (w->phase >= 5) return BOOT_WAIT_QUARANTINE;
    /* Phase 4 is stored just before CPU_OFF: only OFF proves it completed. */
    if (w->phase == 4) return w->off == 1 ? BOOT_WAIT_HANDBACK : BOOT_WAIT_SERVE;
    uint64_t elapsed = w->now - w->launched;
    if (!w->phase) {
        if (elapsed < w->arrival) return BOOT_WAIT_SERVE;
        /* OFF without phase 1: secondary_entry's early_off (wrong EL or MPIDR)
         * powered it down before any monitor C code. A late arrival is not
         * possible from OFF; ON or ON_PENDING may still arrive, so it only
         * closes admission (guest_service_boot then refuses) and waits. */
        if (w->off == 1) return BOOT_WAIT_HANDBACK;
        return w->stopped ? BOOT_WAIT_SERVE : BOOT_WAIT_STOP;
    }
    /* Running: its own watchdog ends the run; past that plus a margin it is
     * stuck at EL2. Asking is all that is safe: it may still be executing. */
    if (elapsed >= w->session && !w->stopped) return BOOT_WAIT_STOP;
    return BOOT_WAIT_SERVE;
}

/* One-slot relay from the target (vCPU 0, the only caller of the q1n1 call
 * service) to q1n1's CPU. `request` is written only by the target and `done`
 * only by q1n1's CPU; request == done means idle. A caller that gives up sets
 * `abandoned` and never posts again, so a late answer only ever writes this
 * page; POLL's latch is copied through `buffer` for the same reason. */
#define BOOT_RELAY_FAILED UINT64_MAX
struct boot_relay {
    uint64_t request, done;
    uint64_t op, a1, a2, a3, result;
    uint64_t abandoned, in_call, served, refused, max_ticks;
    uint64_t buffer[16];
} __attribute__((aligned(64)));

/* The caller may fill `buffer` only while this holds: q1n1's CPU then owns
 * nothing of the page until the next post. */
static inline int boot_relay_idle(const struct boot_relay *r)
{
    return !__atomic_load_n(&r->abandoned, __ATOMIC_RELAXED) &&
           __atomic_load_n(&r->done, __ATOMIC_ACQUIRE) == __atomic_load_n(&r->request, __ATOMIC_RELAXED);
}
static inline int boot_relay_post(struct boot_relay *r, uint64_t op, uint64_t a1,
                                  uint64_t a2, uint64_t a3, uint64_t *ticket)
{
    if (!boot_relay_idle(r)) return 0;
    uint64_t request = __atomic_load_n(&r->request, __ATOMIC_RELAXED);
    r->op = op; r->a1 = a1; r->a2 = a2; r->a3 = a3;
    *ticket = request + 1;
    __atomic_store_n(&r->request, *ticket, __ATOMIC_RELEASE);
    return 1;
}
static inline int boot_relay_take(const struct boot_relay *r, uint64_t *ticket)
{
    uint64_t request = __atomic_load_n(&r->request, __ATOMIC_ACQUIRE);
    if (request == __atomic_load_n(&r->done, __ATOMIC_RELAXED)) return 0;
    *ticket = request;
    return 1;
}
static inline void boot_relay_answer(struct boot_relay *r, uint64_t ticket, uint64_t result)
{
    r->result = result;
    __atomic_store_n(&r->done, ticket, __ATOMIC_RELEASE);
}
static inline int boot_relay_answered(const struct boot_relay *r, uint64_t ticket, uint64_t *result)
{
    if (__atomic_load_n(&r->done, __ATOMIC_ACQUIRE) != ticket) return 0;
    *result = r->result;
    return 1;
}
#endif

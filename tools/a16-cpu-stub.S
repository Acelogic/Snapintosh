/* SPDX-License-Identifier: MIT */
/* EL2 helper stub for tools/measure-a16-cpu-clock.py and tools/a16-cpu-perf.py.
 *
 * Uploaded as a flat .text blob to a 2 KiB-aligned scratch address in q1n1's
 * heap and entered through P_CALL at one of four fixed offsets:
 *
 *   +0x0  measure(report, windows, ticks)          on the calling (boot) CPU
 *   +0x4  start_secondary(result, mpidr, report)   PSCI CPU_ON into secondary_entry
 *   +0x8  affinity(result, mpidr)                  PSCI AFFINITY_INFO_64, level 0
 *   +0xc  sync(address, length, op)                DSB SY; op 1 = DC CVAC, 2 = DC CIVAC
 *   +0x10 start_hold(result, mpidr, report)        PSCI CPU_ON into hold_entry
 *
 * hold_entry keeps its CPU busy measuring window after window (at most 240)
 * into a 4 KiB report, publishing the count at R_PROGRESS after each window,
 * until the host sets the 64-bit stop word at report + 4096; then it powers
 * itself off like secondary_entry. It holds a cluster active for as long as a
 * host experiment needs.
 *
 * Refuses, before writing anything, when PMINTENSET_EL1 is non-zero.
 * Writes outside the caller's report buffers and the stack: PMCR_EL0 (E set,
 * D and DP clear), PMCNTENSET_EL0 bit 31, PMCCFILTR_EL0.NSH, and MDCR_EL2
 * HCCD/HPMD clear only when set. Each is restored from the value read before
 * it; PMCCNTR_EL0 itself is never reset (P and C read as zero, so writing the
 * saved PMCR_EL0 back resets nothing). The secondary path also sets VBAR_EL2 on
 * the started CPU, which then powers itself off. No MMIO, no guest memory.
 *
 * tools/test-measure-a16-cpu-clock.py audits the assembled instructions:
 * every MSR target, every SMC, and every store base register. */

#define MAX_WINDOWS     16
#define HOLD_WINDOWS    240         /* (4096 - R_SAMPLES) / 16 */
#define HOLD_BYTES      4096        /* the stop word follows the report */

#define R_MAGIC         0
#define R_STATUS        8
#define R_EL            16
#define R_MPIDR         24
#define R_MIDR          32
#define R_CNTFRQ        40
#define R_DFR0          48
#define R_PMCR0         56          /* PMCR_EL0, PMCNTENSET_EL0 before */
#define R_PMCCFILTR0    72          /* PMCCFILTR_EL0, MDCR_EL2 before */
#define R_PMCR_RUN      88
#define R_MDCR_RUN      96
#define R_PMCR1         104         /* PMCR_EL0, PMCNTENSET_EL0 after restore */
#define R_PMCCFILTR1    120         /* PMCCFILTR_EL0, MDCR_EL2 after restore */
#define R_WINDOWS       136
#define R_TICKS         144
#define R_ESR           152
#define R_OFF           160
#define R_DONE          168
#define R_PMCCFILTR_RUN 176
#define R_PMINTEN       184         /* PMINTENSET_EL1, read before any write */
#define R_PROGRESS      192         /* windows completed so far (hold) */
#define R_WDONE         200         /* windows completed */
#define R_SAMPLES       256         /* MAX_WINDOWS x (CNTPCT delta, PMCCNTR delta) */

#define ST_OK           0
#define ST_NOT_EL2      1
#define ST_NO_PMU       2
#define ST_BAD_ARGS     3
#define ST_PMU_IRQ      4
#define ST_FAULT        0xee

.text
.global _start
_start:
    b measure
    b start_secondary
    b affinity
    b sync
    b start_hold

/* x0 report (512 bytes), x1 windows (1..16), x2 CNTPCT ticks per window. */
measure:
    stp x29, x30, [sp, #-112]!
    mov x29, sp
    stp x19, x20, [sp, #16]
    stp x21, x22, [sp, #32]
    stp x23, x24, [sp, #48]
    stp x25, x26, [sp, #64]
    stp x27, x28, [sp, #80]
    str x18, [sp, #96]
    mov x19, x0
    mov x20, x1
    mov x21, x2
    mov x16, #0
    mov x17, #0
    mov x18, #MAX_WINDOWS
    bl pmu_measure
    ldr x18, [sp, #96]
    ldp x27, x28, [sp, #80]
    ldp x25, x26, [sp, #64]
    ldp x23, x24, [sp, #48]
    ldp x21, x22, [sp, #32]
    ldp x19, x20, [sp, #16]
    ldp x29, x30, [sp], #112
    ret

/* Shared by all paths. In: x19 report, x20 windows, x21 ticks, x18 the most
 * windows allowed, x17 progress word (0: none), x16 stop word (0: none; a
 * non-zero value ends the run after the current window). Out: x0 status.
 * Uses x0-x15 and x22-x28; no stack and no calls, so it runs on a secondary
 * that has neither a stack nor its MMU on. Interrupts are not masked here:
 * neither counter stops in an EL2 handler, so the ratio is unaffected, and the
 * boot CPU's tick keeps q1n1's USB link serviced. */
pmu_measure:
    str x20, [x19, #R_WINDOWS]
    str x21, [x19, #R_TICKS]
    mrs x0, CurrentEL
    str x0, [x19, #R_EL]
    mrs x1, mpidr_el1
    str x1, [x19, #R_MPIDR]
    mrs x1, midr_el1
    str x1, [x19, #R_MIDR]
    mrs x1, cntfrq_el0
    str x1, [x19, #R_CNTFRQ]
    cmp x0, #8
    b.ne .Lnot_el2
    str xzr, [x19, #R_WDONE]
    cbz x20, .Lbad_args
    cmp x20, x18
    b.hi .Lbad_args
    cbz x21, .Lbad_args
    lsr x0, x21, #32
    cbnz x0, .Lbad_args
    mrs x0, id_aa64dfr0_el1
    str x0, [x19, #R_DFR0]
    ubfx x1, x0, #8, #4             /* PMUVer */
    cbz x1, .Lno_pmu
    cmp x1, #15                     /* IMPLEMENTATION DEFINED, not PMUv3 */
    b.eq .Lno_pmu
    /* All-ones sentinels: if EL3 traps these and q1n1's handler skips the
     * instruction, the report shows it instead of a plausible value. */
    mov x23, #-1
    mov x24, #-1
    mov x25, #-1
    mov x26, #-1
    mrs x23, pmcr_el0
    mrs x24, pmcntenset_el0
    mrs x25, pmccfiltr_el0
    mrs x26, mdcr_el2
    stp x23, x24, [x19, #R_PMCR0]
    stp x25, x26, [x19, #R_PMCCFILTR0]
    /* Overflow interrupts enabled (by whoever ran last): setting PMCR_EL0.E
     * could start counters that interrupt this CPU. Refuse before any write. */
    mov x0, #-1
    mrs x0, pmintenset_el1
    str x0, [x19, #R_PMINTEN]
    cbnz x0, .Lpmu_irq
    /* MDCR_EL2.HCCD (23) and .HPMD (17, with PMCR_EL0.DP) stop PMCCNTR at EL2. */
    mov x0, #(1 << 23)
    orr x0, x0, #(1 << 17)
    bic x27, x26, x0
    cmp x27, x26
    b.eq 1f
    msr mdcr_el2, x27
1:  /* PMCCFILTR_EL0.NSH (27): count cycles in Non-secure EL2 (off at reset). */
    orr x28, x25, #(1 << 27)
    cmp x28, x25
    b.eq 2f
    msr pmccfiltr_el0, x28
2:  /* PMCR_EL0: E (0) on; P/C (1,2) never written; D (3, /64) and DP (5) off. */
    orr x0, x23, #1
    bic x0, x0, #0x6
    bic x0, x0, #0x8
    bic x0, x0, #0x20
    msr pmcr_el0, x0
    mov x1, #0x80000000
    msr pmcntenset_el0, x1
    isb
    mrs x0, pmcr_el0
    str x0, [x19, #R_PMCR_RUN]
    mrs x0, mdcr_el2
    str x0, [x19, #R_MDCR_RUN]
    mrs x0, pmccfiltr_el0
    str x0, [x19, #R_PMCCFILTR_RUN]
    mov x22, #0
.Lwindow:
    isb
    mrs x9, cntpct_el0
    mrs x10, pmccntr_el0
    add x11, x9, x21
.Lspin:
    mrs x12, cntpct_el0
    cmp x12, x11
    b.lo .Lspin
    isb
    mrs x13, pmccntr_el0
    mrs x14, cntpct_el0
    sub x14, x14, x9
    sub x13, x13, x10
    add x15, x19, #R_SAMPLES
    add x15, x15, x22, lsl #4
    stp x14, x13, [x15]
    add x22, x22, #1
    str x22, [x19, #R_WDONE]
    cbz x17, 6f
    str x22, [x17]
6:  cbz x16, 7f
    ldr x0, [x16]
    cbnz x0, 8f
7:  cmp x22, x20
    b.lo .Lwindow
8:
    /* Restore what was read, in reverse. */
    tbnz x24, #31, 3f
    mov x1, #0x80000000
    msr pmcntenclr_el0, x1
3:  msr pmcr_el0, x23
    cmp x28, x25
    b.eq 4f
    msr pmccfiltr_el0, x25
4:  cmp x27, x26
    b.eq 5f
    msr mdcr_el2, x26
5:  isb
    mrs x0, pmcr_el0
    mrs x1, pmcntenset_el0
    stp x0, x1, [x19, #R_PMCR1]
    mrs x0, pmccfiltr_el0
    mrs x1, mdcr_el2
    stp x0, x1, [x19, #R_PMCCFILTR1]
    mov x0, #ST_OK
    b .Lstatus
.Lnot_el2:
    mov x0, #ST_NOT_EL2
    b .Lstatus
.Lno_pmu:
    mov x0, #ST_NO_PMU
    b .Lstatus
.Lbad_args:
    mov x0, #ST_BAD_ARGS
    b .Lstatus
.Lpmu_irq:
    mov x0, #ST_PMU_IRQ
.Lstatus:
    str x0, [x19, #R_STATUS]
    movz x1, #0x5043                /* "CPUCLK01" little-endian */
    movk x1, #0x4355, lsl #16
    movk x1, #0x4b4c, lsl #32
    movk x1, #0x3130, lsl #48
    str x1, [x19, #R_MAGIC]
    dsb sy
    ret

/* x0 result (64 bytes), x1 target MPIDR (affinity bits only), x2 the
 * secondary's report (512 bytes; hold: 4096 and the stop word), already holding
 * windows and ticks and cleaned to PoC. Refuses the executing CPU. Result:
 * [0] PSCI return, [8] CurrentEL, [16] target, [24] report, [32] entry, [40] done. */
start_secondary:
    adr x6, secondary_entry
    b start_common
start_hold:
    adr x6, hold_entry
start_common:
    stp x19, x30, [sp, #-16]!
    mov x19, x0
    str x1, [x19, #16]
    str x2, [x19, #24]
    mrs x4, CurrentEL
    str x4, [x19, #8]
    cmp x4, #8
    b.ne .Lrefuse
    mov x5, #0xffffff
    movk x5, #0xff, lsl #32
    bics xzr, x1, x5
    b.ne .Lrefuse
    mrs x4, mpidr_el1
    and x4, x4, x5
    cmp x1, x4
    b.eq .Lrefuse
    str x6, [x19, #32]
    mov x3, x2                      /* context id: the report */
    mov x2, x6
    mov w0, #3
    movk w0, #0xc400, lsl #16       /* CPU_ON 64 */
    smc #0
    b .Lstarted
.Lrefuse:
    mov x0, #-2                     /* PSCI INVALID_PARAMETERS, nothing issued */
.Lstarted:
    str x0, [x19]
    mov x4, #1
    str x4, [x19, #40]
    ldp x19, x30, [sp], #16
    ret

/* x0 result (64 bytes), x1 target MPIDR. [0] PSCI return, [16] target, [40] done. */
affinity:
    stp x19, x30, [sp, #-16]!
    mov x19, x0
    str x1, [x19, #16]
    mov w0, #4
    movk w0, #0xc400, lsl #16       /* AFFINITY_INFO 64 */
    mov x2, #0
    smc #0
    str x0, [x19]
    mov x4, #1
    str x4, [x19, #40]
    ldp x19, x30, [sp], #16
    ret

/* x0 address, x1 length, x2 op: 0 barrier only, 1 clean, 2 clean+invalidate,
 * each by VA to PoC and completed with DSB SY. Returns 0x5c. */
sync:
    dsb sy
    cbz x2, 9f
    cmp x2, #2
    b.hi 9f
    mrs x3, ctr_el0
    ubfx x3, x3, #16, #4
    mov x4, #4
    lsl x4, x4, x3                  /* smallest data cache line */
    sub x5, x4, #1
    bic x6, x0, x5
    add x7, x0, x1
6:  cmp x2, #1
    b.ne 7f
    dc cvac, x6
    b 8f
7:  dc civac, x6
8:  add x6, x6, x4
    cmp x6, x7
    b.lo 6b
    dsb sy
9:  mov x0, #0x5c
    ret

/* PSCI CPU_ON targets: MMU and caches off, no stack, x0 = its report. */
.balign 64
secondary_entry:
    msr daifset, #15
    mov x19, x0
    adr x1, secondary_vectors
    msr vbar_el2, x1
    isb
    ldr x20, [x19, #R_WINDOWS]
    ldr x21, [x19, #R_TICKS]
    mov x16, #0
    mov x17, #0
    mov x18, #MAX_WINDOWS
    bl pmu_measure
    mov x20, #512
    b .Lsecondary_off

/* PSCI CPU_ON target for a hold: as secondary_entry, until the stop word. */
.balign 64
hold_entry:
    msr daifset, #15
    mov x19, x0
    adr x1, secondary_vectors
    msr vbar_el2, x1
    isb
    ldr x20, [x19, #R_WINDOWS]
    ldr x21, [x19, #R_TICKS]
    add x16, x19, #HOLD_BYTES
    add x17, x19, #R_PROGRESS
    mov x18, #HOLD_WINDOWS
    bl pmu_measure
    mov x20, #HOLD_BYTES
/* x19 report, x20 its size: mark done, clean it to PoC, CPU_OFF. */
.Lsecondary_off:
    mov x1, #1
    str x1, [x19, #R_DONE]
    dsb sy
    mrs x3, ctr_el0
    ubfx x3, x3, #16, #4
    mov x4, #4
    lsl x4, x4, x3
    mov x1, x19
    add x2, x19, x20
10: dc cvac, x1
    add x1, x1, x4
    cmp x1, x2
    b.lo 10b
    dsb sy
    mov w0, #2
    movk w0, #0x8400, lsl #16       /* CPU_OFF */
    mov x1, #0
    mov x2, #0
    mov x3, #0
    smc #0
    /* CPU_OFF must not return. Keep the evidence and never run anything else. */
    str x0, [x19, #R_OFF]
    mov x1, #3
    str x1, [x19, #R_DONE]
    dc cvac, x19
    dsb sy
.Lpark:
    wfe
    b .Lpark

secondary_fault:
    mrs x1, esr_el2
    str x1, [x19, #R_ESR]
    mov x1, #ST_FAULT
    str x1, [x19, #R_STATUS]
    mov x20, #HOLD_BYTES
    b .Lsecondary_off

.balign 2048
secondary_vectors:
.rept 16
    b secondary_fault
    .balign 128
.endr

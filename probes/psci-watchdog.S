/* SPDX-License-Identifier: MIT */
/* Bounded physical-secondary watchdog proof. WARM_ENTRY adds a read-only
 * stock entry-stub boundary probe; neither mode completes XNU CPU startup.
 * Primary ABI matches psci-roundtrip. Secondary report is 32 u64 words;
 * inputs [8]=its GICR base, [9]=affinity-only MPIDR. All secondary handlers
 * are stackless. The secondary runs a masked EL1 loop for at most one second;
 * a 100 ms EL2 timer must interrupt it. Only this CPU's PPI26 is changed. */
.text
.global _start
_start:
    stp x19, x30, [sp, #-16]!
#ifdef COHERENT
    stp x20, x21, [sp, #-16]!
    stp x22, x23, [sp, #-16]!
    stp x24, x25, [sp, #-16]!
#endif
    mov x19, x0
    mrs x4, CurrentEL
    str x4, [x19, #8]
    str x1, [x19, #16]
    cmp x4, #8
    b.ne refused
    mrs x4, mpidr_el1
    mov x5, #0xffffff
    movk x5, #0xff, lsl #32
    and x4, x4, x5
    cmp x1, x4
    b.eq refused
    adr x2, secondary
    str x2, [x19, #24]
    add x3, x19, #4096
#ifdef COHERENT
    /* Publish the actual primary regime, not a host-side stale snapshot. */
    mrs x4, sctlr_el2
    mrs x5, tcr_el2
    stp x4, x5, [x3, #256]
    mrs x4, ttbr0_el2
    mrs x5, mair_el2
    stp x4, x5, [x3, #272]
    /* Refuse before CPU_ON if the regime changed since the host page walk. */
    ldp x6, x7, [x3, #400]
    cmp x4, x6
    b.ne refused
    cmp x5, x7
    b.ne refused
    ldp x4, x5, [x3, #256]
    ldp x6, x7, [x3, #384]
    cmp x4, x6
    b.ne refused
    cmp x5, x7
    b.ne refused
    add x4, x3, #256
    dc cvac, x4
    dsb sy
#endif
    mov w0, #3
    movk w0, #0xc400, lsl #16
    smc #0
    b primary_done
refused:
    mov x0, #-2
primary_done:
    str x0, [x19]
#ifdef COHERENT
    cbnz x0, primary_coherence_done
    add x20, x19, #4096
    ldp x21, x22, [x20, #320] /* shared block, required increments */
    mrs x24, cntpct_el0
    mrs x0, cntfrq_el0
    add x24, x24, x0
    add x25, x21, #8
primary_wait_ready:
    ldar x0, [x25]
    cbnz x0, primary_ready
    mrs x0, cntpct_el0
    cmp x0, x24
    b.lo primary_wait_ready
    b primary_coherence_done
primary_ready:
    mov x0, #1
    str x0, [x19, #40]
    add x25, x21, #16
    stlr x0, [x25]
    mov x23, #0
primary_increment:
    ldaxr x0, [x21]
    add x0, x0, #1
    stlxr w1, x0, [x21]
    cbnz w1, primary_retry
    add x23, x23, #1
    cmp x23, x22
    b.eq primary_increments_done
primary_retry:
    mrs x0, cntpct_el0
    cmp x0, x24
    b.lo primary_increment
primary_increments_done:
    clrex
    str x23, [x19, #56]
    cmp x23, x22
    b.ne primary_coherence_done
    add x25, x21, #32
    mov x0, #1
    stlr x0, [x25]
    ldar x0, [x21]
    str x0, [x19, #48]
    dc cvac, x21
    dsb sy
primary_coherence_done:
#endif
    mov x4, #1
    str x4, [x19, #32]
#ifdef COHERENT
    ldp x24, x25, [sp], #16
    ldp x22, x23, [sp], #16
    ldp x20, x21, [sp], #16
#endif
    ldp x19, x30, [sp], #16
    ret

.balign 64
secondary:
    msr daifset, #15
    mov x19, x0
    mov x20, #0
    mrs x1, CurrentEL
    mrs x2, mpidr_el1
    stp x1, x2, [x19, #8]
    mov x0, #6
    str x0, [x19]
    cmp x1, #8
    b.ne raw_off
#ifdef WARM_ENTRY
    msr tpidr_el2, x19
#endif
    adr x1, vectors
    msr vbar_el2, x1
    isb
    mrs x1, sctlr_el2
    mrs x2, hcr_el2
    stp x1, x2, [x19, #24]
    mrs x1, midr_el1
    str x1, [x19, #40]
    ldp x20, x3, [x19, #64]
    mov x5, #0xffffff
    movk x5, #0xff, lsl #32
    mrs x2, mpidr_el1
    and x2, x2, x5
    cmp x2, x3
    b.ne stop
    /* GIC affinity puts MPIDR Aff3 in bits31:24. */
    and x2, x2, #0xffffff
    lsr x3, x3, #32
    orr x2, x2, x3, lsl #24
    ldr x1, [x20, #8]
    str x1, [x19, #144]
    lsr x1, x1, #32
    cmp x1, x2
    b.ne stop
    add x21, x20, #0x10, lsl #12
    ldr w1, [x20, #0x14]
    str x1, [x19, #152]
    ldr w2, [x21, #0x80]
    str x2, [x19, #160]
    ldrb w2, [x21, #0x41a]
    str x2, [x19, #168]
    ldr w2, [x21, #0x100]
    str x2, [x19, #176]
    /* No other enabled interrupt or active/pending timer may be disturbed. */
    cbnz w2, stop
    ldr w2, [x21, #0x200]
    tbnz w2, #26, stop
    ldr w2, [x21, #0x300]
    tbnz w2, #26, stop
    ldr w2, [x21, #0xc04]
    tbnz w2, #21, stop  /* PPI26 must already be level-triggered. */
    mov x2, #2
    str x2, [x19, #240] /* snapshots valid, cleanup now required */
    bic w1, w1, #2
    str w1, [x20, #0x14]
    dsb sy
    mov w3, #0xffff
wake_wait:
    ldr w1, [x20, #0x14]
    tbz w1, #2, awake
    subs w3, w3, #1
    b.ne wake_wait
    b stop
awake:
    mov w1, #0x4000000
    ldr w2, [x21, #0x80]
    orr w2, w2, w1
    str w2, [x21, #0x80]
    mov w2, #0x80
    strb w2, [x21, #0x41a]
    str w1, [x21, #0x280]
    str w1, [x21, #0x100]
    dsb sy
    mov w3, #0xffff
enable_wait:
    ldr w1, [x20]
    tbz w1, #3, enabled
    subs w3, w3, #1
    b.ne enable_wait
    b stop
enabled:
    mrs x1, icc_sre_el2
    orr x1, x1, #1
    msr icc_sre_el2, x1
    isb
    mrs x1, icc_sre_el2
    str x1, [x19, #184]
    tbz x1, #0, stop
    mov x1, #0xf0
    msr icc_pmr_el1, x1
    msr icc_bpr1_el1, xzr
    mov x1, #1
    msr icc_igrpen1_el1, x1
    mrs x1, icc_ctlr_el1
    str x1, [x19, #192]
    mov x1, #0x80000000
    orr x1, x1, #0x10 /* RW, IMO: physical IRQ routed to EL2. */
    msr hcr_el2, x1
    str x1, [x19, #200]
#ifdef COHERENT
    /* Host admission walked these immutable firmware tables and checked
     * identity mappings: normal inner-shareable WB RAM, Device GIC pages.
     * Primary and secondary must use the same attributes for atomic data. */
    ldp x1, x2, [x19, #256]
    ldp x3, x4, [x19, #272]
    msr mair_el2, x4
    msr tcr_el2, x2
    msr ttbr0_el2, x3
    dsb sy
    tlbi alle2
    ic iallu
    dsb sy
    isb
    msr sctlr_el2, x1
    isb
    mrs x1, sctlr_el2
    mrs x2, tcr_el2
    stp x1, x2, [x19, #288]
    mrs x1, ttbr0_el2
    mrs x2, mair_el2
    stp x1, x2, [x19, #304]
    /* Bound the concurrent EL2 phase too; an IRQ here fails the EL1 witness. */
    mrs x1, cntfrq_el0
    mrs x2, cntpct_el0
    add x27, x2, x1
    mov x3, #10
    udiv x3, x1, x3
    add x2, x2, x3
    msr cnthp_cval_el2, x2
    mov x1, #1
    msr cnthp_ctl_el2, x1
    isb
    msr daifclr, #2
    ldp x23, x24, [x19, #320]
    ldar x0, [x23]
    str x0, [x19, #352]
    add x26, x23, #8
    stlr x1, [x26] /* ready */
    add x26, x23, #16
secondary_wait_go:
    ldar x0, [x26]
    cbnz x0, secondary_go
    mrs x0, cntpct_el0
    cmp x0, x27
    b.lo secondary_wait_go
    b stop
secondary_go:
    mov x25, #0
secondary_increment:
    ldaxr x0, [x23]
    add x0, x0, #1
    stlxr w1, x0, [x23]
    cbnz w1, secondary_retry
    add x25, x25, #1
    cmp x25, x24
    b.eq secondary_increments_done
secondary_retry:
    mrs x0, cntpct_el0
    cmp x0, x27
    b.lo secondary_increment
secondary_increments_done:
    clrex
    str x25, [x19, #336]
    cmp x25, x24
    b.ne stop
    add x26, x23, #24
    mov x0, #1
    stlr x0, [x26]
    ldar x0, [x23]
    str x0, [x19, #360]
    msr daifset, #2
#endif
    mov x1, #1
    msr cnthctl_el2, x1 /* permit EL1 physical counter for timeout fallback */
    mov x1, #0x800
    movk x1, #0x30d0, lsl #16
    msr sctlr_el1, x1 /* MMU and caches off; EL1 loop is physical code */
    adr x1, el1_vectors
    msr vbar_el1, x1
    isb
    mrs x1, cntfrq_el0
    str x1, [x19, #80]
    cbz x1, stop
    mrs x2, cntpct_el0
    str x2, [x19, #88]
    add x22, x2, x1 /* one-second cooperative fallback */
    mov x3, #10
    udiv x3, x1, x3
    cbz x3, stop
    add x2, x2, x3
    str x2, [x19, #96]
    msr cnthp_cval_el2, x2
    mov x1, #1
    msr cnthp_ctl_el2, x1
    adr x1, el1_loop
    str x1, [x19, #208]
    msr elr_el2, x1
    mov x1, #0x3c5 /* EL1h, all DAIF masked */
    msr spsr_el2, x1
    mov x1, #3
    str x1, [x19, #240]
#ifdef WARM_ENTRY
    /* x19-x28 are the guest's registers. Recover our report and GIC pointers
     * from a private EL2 thread pointer in every exception path. */
    msr tpidr_el2, x19
    add x18, x19, #512
    ldp x1, x2, [x18, #24] /* private guest TTBR1/TTBR0 */
    msr ttbr1_el1, x1
    msr ttbr0_el1, x2
    ldp x1, x2, [x18, #40] /* TCR, MAIR */
    msr tcr_el1, x1
    msr mair_el1, x2
    ldp x1, x2, [x18, #64] /* VTTBR, VTCR */
    msr vtcr_el2, x2
    msr vttbr_el2, x1
    ldr x1, [x19, #528]
    msr vmpidr_el2, x1
    ldr x1, [x19, #592]
    msr vbar_el1, x1
    mrs x1, hcr_el2
    orr x1, x1, #1
    msr hcr_el2, x1
    dsb ish
    tlbi vmalls12e1is
    dsb ish
    isb
    ldr x1, [x19, #568]
    msr sctlr_el1, x1
    msr esr_el1, xzr
    msr far_el1, xzr
    ldr x1, [x19, #512]
    msr elr_el2, x1
    ldr x0, [x19, #520] /* selected equivalent warm-path selector */
    mov x1, #0
    mov x2, #0
    mov x3, #0 /* no hibernation arguments */
#endif
    isb
    eret
el1_loop:
#ifdef COHERENT
    /* Do not alias cached EL2 report RAM through an uncached EL1 data access. */
    nop
    nop
#else
    mov x0, #4
    str x0, [x19, #240]
#endif
1:
    mrs x0, cntpct_el0
    cmp x0, x22
    b.lo 1b
    hvc #1
    b .

irq:
#ifdef WARM_ENTRY
    adr x17, warm_irq_ready
    b warm_snapshot
warm_irq_ready:
#endif
    msr daifset, #15
    mrs x1, cntpct_el0
    str x1, [x19, #104]
    mrs x1, icc_iar1_el1
    dsb sy
    str x1, [x19, #112]
    mrs x2, cnthp_ctl_el2
    str x2, [x19, #120]
    mrs x3, elr_el2
    mrs x4, spsr_el2
    stp x3, x4, [x19, #128]
    msr cnthp_ctl_el2, xzr
    isb
    cmp x1, #1020
    b.hs stop
    msr icc_eoir1_el1, x1
    isb
    ldr x3, [x19, #192]
    tbz x3, #1, eoi_done
    msr icc_dir_el1, x1
    isb
eoi_done:
    cmp x1, #26
    b.ne stop
    mov x3, #5
    and x2, x2, x3
    cmp x2, #5
    b.ne stop
    and x4, x4, #15
    cmp x4, #5
    b.ne stop
    mov x1, #2
    str x1, [x19]
    b stop

fault:
#ifdef WARM_ENTRY
    adr x17, warm_fault_ready
    b warm_snapshot
warm_fault_ready:
#endif
    msr daifset, #15
    mrs x1, esr_el2
    str x1, [x19, #56]
    mrs x1, elr_el2
    mrs x2, spsr_el2
    stp x1, x2, [x19, #128]
    mov x1, #4
    str x1, [x19]
#ifdef WARM_ENTRY
    b stop
warm_snapshot:
    mrs x16, tpidr_el2
    add x16, x16, #640
    stp x0, x1, [x16]
    stp x2, x3, [x16, #16]
    stp x4, x15, [x16, #32]
    stp x19, x20, [x16, #48]
    stp x21, x30, [x16, #64]
    mrs x0, sp_el0
    mrs x1, sp_el1
    stp x0, x1, [x16, #80]
    mrs x0, esr_el1
    mrs x1, far_el1
    stp x0, x1, [x16, #96]
    mrs x0, elr_el1
    mrs x1, far_el2
    stp x0, x1, [x16, #112]
    mrs x0, hpfar_el2
    mrs x1, vmpidr_el2
    stp x0, x1, [x16, #128]
    mrs x0, vttbr_el2
    mrs x1, ttbr1_el1
    stp x0, x1, [x16, #144]
    mrs x0, tcr_el1
    mrs x1, sctlr_el1
    stp x0, x1, [x16, #160]
    sub x19, x16, #640
    ldr x20, [x19, #64]
    add x21, x20, #0x10000
    br x17
#endif
stop:
    msr daifset, #15
    msr cnthp_ctl_el2, xzr
    isb
    ldr x1, [x19, #240]
    cmp x1, #2
    b.lo raw_off
    mov w1, #0x4000000
    str w1, [x21, #0x180]
    str w1, [x21, #0x280]
    dsb sy
    mov w3, #0xffff
disable_wait:
    ldr w1, [x20]
    tbz w1, #3, disabled
    subs w3, w3, #1
    b.ne disable_wait
disabled:
    str x1, [x19, #224]
    ldr w1, [x19, #160]
    str w1, [x21, #0x80]
    ldr w1, [x19, #168]
    strb w1, [x21, #0x41a]
    ldr w1, [x19, #152]
    str w1, [x20, #0x14]
    dsb sy
    ldr w1, [x20, #0x14]
    str x1, [x19, #216]
    mov x1, #6
    str x1, [x19, #240]
raw_off:
    /* Publish all four report cache lines before powering down. */
    dc cvac, x19
    add x1, x19, #64
    dc cvac, x1
    add x1, x19, #128
    dc cvac, x1
    add x1, x19, #192
    dc cvac, x1
#ifdef COHERENT
    add x1, x19, #256
    dc cvac, x1
    add x1, x19, #320
    dc cvac, x1
    add x1, x19, #384
    dc cvac, x1
    add x1, x19, #448
    dc cvac, x1
#ifdef WARM_ENTRY
    add x1, x19, #512
    add x2, x19, #1024
warm_publish:
    dc cvac, x1
    add x1, x1, #64
    cmp x1, x2
    b.lo warm_publish
#endif
    ldr x1, [x19, #320]
    dc cvac, x1
#endif
    dsb sy
    mov w0, #2
    movk w0, #0x8400, lsl #16
    mov x1, #0
    mov x2, #0
    mov x3, #0
    smc #0
    str x0, [x19, #48]
    mov x1, #3
    str x1, [x19]
    dc cvac, x19
    dsb sy
park:
    wfe
    b park

.balign 2048
vectors:
.rept 4
    b fault
    .balign 128
    b irq
    .balign 128
    b fault
    .balign 128
    b fault
    .balign 128
.endr
.balign 2048
el1_vectors:
.rept 16
    hvc #2
    b .
    .balign 128
.endr

/* SPDX-License-Identifier: MIT */
/* One physical-core round trip; no guest entry and no MMIO.
 * Primary: x0=64-byte report, x1=target MPIDR. Secondary report at x0+4096.
 * The secondary has no stack, records entry state and issues CPU_OFF.
 * Scratch/report must be clean to PoC before entry on a cache-off CPU. */
.text
.global _start
_start:
    stp x19, x30, [sp, #-16]!
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
    mov w0, #3
    movk w0, #0xc400, lsl #16
    smc #0
    b primary_done
refused:
    mov x0, #-2
primary_done:
    str x0, [x19]
    mov x4, #1
    str x4, [x19, #32]
    ldp x19, x30, [sp], #16
    ret

.balign 64
secondary:
    msr daifset, #15
    mov x19, x0
    mrs x1, CurrentEL
    mrs x2, mpidr_el1
    stp x1, x2, [x19, #8]
    cmp x1, #8
    b.ne off
    adr x1, vectors
    msr vbar_el2, x1
    isb
    mrs x1, sctlr_el2
    mrs x2, hcr_el2
    stp x1, x2, [x19, #24]
    mrs x1, midr_el1
    str x1, [x19, #40]
off:
    mov x1, #2
    str x1, [x19]
    dc cvac, x19
    dsb sy
    mov w0, #2
    movk w0, #0x8400, lsl #16
    mov x1, #0
    mov x2, #0
    mov x3, #0
    smc #0
    /* CPU_OFF must not return. Preserve evidence and never run random code. */
    str x0, [x19, #48]
    mov x1, #3
    str x1, [x19]
    dc cvac, x19
    dsb sy
park:
    wfe
    b park

fault:
    mrs x1, esr_el2
    str x1, [x19, #56]
    b off

.balign 2048
vectors:
.rept 16
    b fault
    .balign 128
.endr

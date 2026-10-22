/* SPDX-License-Identifier: MIT */
/* Read-only primary EL2 memory-regime inventory. x0 = 128-byte report. */
.text
.global _start
_start:
begin:
    mrs x1, CurrentEL
    str x1, [x0]
    cmp x1, #8
    b.ne 1f
    mrs x1, mpidr_el1
    str x1, [x0, #8]
    mrs x1, sctlr_el2
    str x1, [x0, #16]
    mrs x1, tcr_el2
    str x1, [x0, #24]
    mrs x1, ttbr0_el2
    str x1, [x0, #32]
    mrs x1, mair_el2
    str x1, [x0, #40]
    mrs x1, hcr_el2
    str x1, [x0, #48]
    mrs x1, cnthctl_el2
    str x1, [x0, #56]
    mrs x1, cntfrq_el0
    str x1, [x0, #64]
    mrs x1, vbar_el2
    str x1, [x0, #72]
    mov x1, sp
    str x1, [x0, #80]
    adr x1, begin
    str x1, [x0, #88]
    mov x1, #1
    str x1, [x0, #96]
1:
    ret

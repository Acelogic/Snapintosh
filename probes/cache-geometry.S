// SPDX-License-Identifier: MIT
// Inspect physical zero-block geometry; zero one bounded scratch block at EL2.
.text
.globl _start
_start:
    mrs x1, currentel
    str x1, [x0, #0]
    cmp x1, #8
    b.ne .Lrefuse
    mrs x1, dczid_el0
    str x1, [x0, #8]
    mrs x2, ctr_el0
    str x2, [x0, #16]
    mrs x2, hcr_el2
    str x2, [x0, #24]
    mrs x2, sctlr_el1
    str x2, [x0, #32]
    mrs x2, sctlr_el2
    str x2, [x0, #40]
    // Only the observed 64-byte contract has scratch storage reserved here.
    cmp x1, #4
    b.ne .Lrefuse
    tst x0, #63
    b.ne .Lrefuse
    add x2, x0, #0x100
    dc zva, x2
    dsb sy
    mov x0, #0
    ret
.Lrefuse:
    mov x0, #1
    ret

/* SPDX-License-Identifier: MIT */
/* Read-only SMC queries. x0=64-byte report, x1=operation, x2=argument.
 * No CPU_ON/OFF, suspend, reset or vendor calls are dispatched here. */
.text
.global _start
_start:
    stp x19, x20, [sp, #-32]!
    str x30, [sp, #16]
    mov x19, x0
    mov x20, x1
    mrs x3, CurrentEL
    mrs x4, mpidr_el1
    stp x3, x4, [x19]
    stp x1, x2, [x19, #16]
    mov x3, #0
    str x3, [x19, #40]
    cmp x1, #0
    b.eq version
    cmp x1, #1
    b.eq features
    cmp x1, #2
    b.eq affinity
    mov x0, #-2
    b result
version:
    mov x0, #0x84000000
    mov x1, #0
    b query
features:
    /* Only allow the three CPU APIs needed to assess a future backend. */
    mov w3, #3
    movk w3, #0xc400, lsl #16
    cmp x2, x3
    b.eq feature_ok
    mov w3, #4
    movk w3, #0xc400, lsl #16
    cmp x2, x3
    b.eq feature_ok
    mov w3, #2
    movk w3, #0x8400, lsl #16
    cmp x2, x3
    b.ne invalid
feature_ok:
    mov w0, #10
    movk w0, #0x8400, lsl #16
    mov x1, x2
    b query
affinity:
    mov w0, #4
    movk w0, #0xc400, lsl #16
    mov x1, x2
query:
    mov x2, #0
    mov x3, #0
    smc #0
    b result
invalid:
    mov x0, #-2
result:
    str x0, [x19, #32]
    mov x3, #1
    str x3, [x19, #40]
    mrs x3, CurrentEL
    mrs x4, mpidr_el1
    stp x3, x4, [x19, #48]
    ldr x30, [sp, #16]
    ldp x19, x20, [sp], #32
    ret

/* SPDX-License-Identifier: MIT
 * Seed every full SIMD register around the production C adapter transaction,
 * save the observed values in record+0x400, then restore q1n1's own state. */
.section .text.entry,"ax"
.global txm_native_probe_entry
txm_native_probe_entry:
    sub sp, sp, #544
    stp x19, x30, [sp]
    mrs x9, cptr_el2
    str x9, [sp, #16]
    bic x9, x9, #0x400
    msr cptr_el2, x9
    isb
    mov x19, x0
.macro pair op, a, b, off
    \op q\a, q\b, [sp, #\off]
.endm
    pair stp, 0, 1, 32
    pair stp, 2, 3, 64
    pair stp, 4, 5, 96
    pair stp, 6, 7, 128
    pair stp, 8, 9, 160
    pair stp, 10, 11, 192
    pair stp, 12, 13, 224
    pair stp, 14, 15, 256
    pair stp, 16, 17, 288
    pair stp, 18, 19, 320
    pair stp, 20, 21, 352
    pair stp, 22, 23, 384
    pair stp, 24, 25, 416
    pair stp, 26, 27, 448
    pair stp, 28, 29, 480
    pair stp, 30, 31, 512
.macro patterns op, a, b, off
    \op q\a, q\b, [x9, #\off]
.endm
    add x9, x19, #0x200
    patterns ldp, 0, 1, 0
    patterns ldp, 2, 3, 32
    patterns ldp, 4, 5, 64
    patterns ldp, 6, 7, 96
    patterns ldp, 8, 9, 128
    patterns ldp, 10, 11, 160
    patterns ldp, 12, 13, 192
    patterns ldp, 14, 15, 224
    patterns ldp, 16, 17, 256
    patterns ldp, 18, 19, 288
    patterns ldp, 20, 21, 320
    patterns ldp, 22, 23, 352
    patterns ldp, 24, 25, 384
    patterns ldp, 26, 27, 416
    patterns ldp, 28, 29, 448
    patterns ldp, 30, 31, 480
    bl txm_native_probe
    add x9, x19, #0x400
    patterns stp, 0, 1, 0
    patterns stp, 2, 3, 32
    patterns stp, 4, 5, 64
    patterns stp, 6, 7, 96
    patterns stp, 8, 9, 128
    patterns stp, 10, 11, 160
    patterns stp, 12, 13, 192
    patterns stp, 14, 15, 224
    patterns stp, 16, 17, 256
    patterns stp, 18, 19, 288
    patterns stp, 20, 21, 320
    patterns stp, 22, 23, 352
    patterns stp, 24, 25, 384
    patterns stp, 26, 27, 416
    patterns stp, 28, 29, 448
    patterns stp, 30, 31, 480
    pair ldp, 0, 1, 32
    pair ldp, 2, 3, 64
    pair ldp, 4, 5, 96
    pair ldp, 6, 7, 128
    pair ldp, 8, 9, 160
    pair ldp, 10, 11, 192
    pair ldp, 12, 13, 224
    pair ldp, 14, 15, 256
    pair ldp, 16, 17, 288
    pair ldp, 18, 19, 320
    pair ldp, 20, 21, 352
    pair ldp, 22, 23, 384
    pair ldp, 24, 25, 416
    pair ldp, 26, 27, 448
    pair ldp, 28, 29, 480
    pair ldp, 30, 31, 512
    ldr x9, [sp, #16]
    msr cptr_el2, x9
    isb
    ldp x19, x30, [sp]
    add sp, sp, #544
    ret

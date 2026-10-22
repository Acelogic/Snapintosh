/* SPDX-License-Identifier: MIT
 * Single-caller bridge for the pinned, relocated native Image4 helper.
 * x0: 16 u64 words: image base, native SP, entry, x0..x7, saved SP,
 * panic code, panic argument, returned x0, normal-return flag.
 * Failure contract and native replay: docs/TXM-TRUST-LOAD-20260925.md.
 */
.section .text.entry,"ax"
.global txm_image4_bridge
.global txm_image4_panic
.global txm_image4_active
.balign 16
txm_image4_bridge:
    sub sp, sp, #640
    stp x19, x20, [sp, #0]
    stp x21, x22, [sp, #16]
    stp x23, x24, [sp, #32]
    stp x25, x26, [sp, #48]
    stp x27, x28, [sp, #64]
    stp x29, x30, [sp, #80]
    mrs x9, cptr_el2
    str x9, [sp, #608]
    bic x10, x9, #0x400
    msr cptr_el2, x10
    isb
    mrs x9, fpcr
    mrs x10, fpsr
    str x9, [sp, #616]
    str x10, [sp, #624]
    /* The monitor keeps live guest SIMD state in the physical registers.
     * Preserve all of it, not only the ordinary C ABI's low d8..d15. */
    stp q0, q1, [sp, #96]
    stp q2, q3, [sp, #128]
    stp q4, q5, [sp, #160]
    stp q6, q7, [sp, #192]
    stp q8, q9, [sp, #224]
    stp q10, q11, [sp, #256]
    stp q12, q13, [sp, #288]
    stp q14, q15, [sp, #320]
    stp q16, q17, [sp, #352]
    stp q18, q19, [sp, #384]
    stp q20, q21, [sp, #416]
    stp q22, q23, [sp, #448]
    stp q24, q25, [sp, #480]
    stp q26, q27, [sp, #512]
    stp q28, q29, [sp, #544]
    stp q30, q31, [sp, #576]
    adr x9, txm_image4_active
    str x0, [x9]
    mov x9, sp
    str x9, [x0, #88]
    stp xzr, xzr, [x0, #96]
    stp xzr, xzr, [x0, #112]
    mov x9, x0
    ldp x17, x16, [x9, #8]
    mov sp, x17
    ldp x0, x1, [x9, #24]
    ldp x2, x3, [x9, #40]
    ldp x4, x5, [x9, #56]
    ldp x6, x7, [x9, #72]
    blr x16
    adr x9, txm_image4_active
    ldr x9, [x9]
    str x0, [x9, #112]
    mov x10, #1
    str x10, [x9, #120]
    b .Lrestore
.org 0x200
txm_image4_panic:
    adr x9, txm_image4_active
    ldr x9, [x9]
    stp x0, x1, [x9, #96]
    mov x0, #-1
    str x0, [x9, #112]
.Lrestore:
    ldr x10, [x9, #88]
    mov sp, x10
    ldp q0, q1, [sp, #96]
    ldp q2, q3, [sp, #128]
    ldp q4, q5, [sp, #160]
    ldp q6, q7, [sp, #192]
    ldp q8, q9, [sp, #224]
    ldp q10, q11, [sp, #256]
    ldp q12, q13, [sp, #288]
    ldp q14, q15, [sp, #320]
    ldp q16, q17, [sp, #352]
    ldp q18, q19, [sp, #384]
    ldp q20, q21, [sp, #416]
    ldp q22, q23, [sp, #448]
    ldp q24, q25, [sp, #480]
    ldp q26, q27, [sp, #512]
    ldp q28, q29, [sp, #544]
    ldp q30, q31, [sp, #576]
    ldr x9, [sp, #616]
    ldr x10, [sp, #624]
    msr fpcr, x9
    msr fpsr, x10
    ldr x9, [sp, #608]
    msr cptr_el2, x9
    isb
    ldp x19, x20, [sp, #0]
    ldp x21, x22, [sp, #16]
    ldp x23, x24, [sp, #32]
    ldp x25, x26, [sp, #48]
    ldp x27, x28, [sp, #64]
    ldp x29, x30, [sp, #80]
    add sp, sp, #640
    ret
.org 0x300
txm_image4_active:
    .quad 0

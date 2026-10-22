// SPDX-License-Identifier: MIT
// PA configuration inventory; optional synthetic-key primitive exercise.
// No host key material is exported.
.section .text.entry,"ax"
.globl _start
_start:
    mov x2,x1
    mrs x1, currentel;        str x1, [x0, #0]
    mrs x1, id_aa64isar1_el1; str x1, [x0, #8]
    mrs x1, id_aa64isar2_el1; str x1, [x0, #16]
    mrs x1, sctlr_el2;        str x1, [x0, #24]
    mrs x1, tcr_el2;          str x1, [x0, #32]
    mrs x1, hcr_el2;          str x1, [x0, #40]
    mrs x1, sctlr_el1;        str x1, [x0, #48]
    mrs x1, tcr_el1;          str x1, [x0, #56]
    mrs x1, id_aa64mmfr0_el1; str x1, [x0, #64]
    mrs x1, id_aa64isar0_el1; str x1, [x0, #72]
    cbz x2,.Linspect_only
    add x1,x0,#0x180
    add x0,x0,#0x100
#if PAUTH_PROBE_SIGN_ONLY
    b pauth_native_sign_user
#else
    b pauth_native_user
#endif
.Linspect_only:
    mov x0, #0
    ret

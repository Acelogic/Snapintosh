/* SPDX-License-Identifier: MIT */
/* PSCI x0 points to a published, page-aligned secondary record. No stack or
 * C code is used before the admitted primary EL2 mapping regime is installed. */
.text
.global secondary_entry
secondary_entry:
    msr daifset, #15
    mov x19, x0
    mrs x1, CurrentEL
    cmp x1, #8
    b.ne early_off
    mrs x1, mpidr_el1
    mov x2, #0xffffff
    movk x2, #0xff, lsl #32
    and x1, x1, x2
    ldr x2, [x19, #48]
    cmp x1, x2
    b.ne early_off
    /* Faults before the common stack/vector switch can only power this CPU
     * off. The unresolved lifecycle reservation then prevents RAM reuse. */
    adr x1, early_vectors
    msr vbar_el2, x1
    mov x1, #0x80000000
    msr hcr_el2, x1
    ldp x1, x2, [x19]
    ldp x3, x4, [x19, #16]
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
    msr spsel, #1
    ldr x1, [x19, #40]
    mov sp, x1
    ldr x1, [x19, #32]
    msr tpidr_el2, x1
    ldr x1, [x19, #64]
    msr vbar_el2, x1
    isb
    mov x0, x19
    ldr x1, [x19, #72]
    blr x1
    /* The callback should enter the guest or finish this executor. */
    mov x0, x19
    ldr x1, [x19, #80]
    blr x1
early_off:
    msr daifset, #15
    mov w0, #2
    movk w0, #0x8400, lsl #16
    mov x1, #0
    mov x2, #0
    mov x3, #0
    smc #0
1:  wfe
    b 1b

.global secondary_guest_enter
secondary_guest_enter:
    msr elr_el2, x0
    mov x2, #0x3c5
    msr spsr_el2, x2
    mov x2, #1
    str x2, [x1, #8]
    mov x0, #1 /* exact stock warm path; no hibernation arguments */
    mov x1, #0
    mov x2, #0
    mov x3, #0
    isb
    eret

#if SNAP_BOOT_RELOCATE
/* vCPU 0 on a relocated CPU (compat/boot-relocate.h): _start's cold entry,
 * not the warm path above. x0 = entry, x1 = out, x2/x3 = params x1/x2. */
.global boot_guest_enter
boot_guest_enter:
    msr elr_el2, x0
    mov x4, #0x3c5                      /* EL1h, DAIF masked */
    msr spsr_el2, x4
    mov x4, #1
    str x4, [x1, #8]                    /* OUT_ENTERED */
    mov x0, #0                          /* boot CPU */
    mov x1, x2
    mov x2, x3
    isb
    eret
#endif

.balign 2048
early_vectors:
.rept 16
    b early_off
    .balign 128
.endr

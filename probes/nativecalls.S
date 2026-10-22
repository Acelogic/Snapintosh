/* SPDX-License-Identifier: MIT */
/* Bounded native execution / undefined Apple-call exception probe.
 * x0: 256-byte report; x1: zeroed, 4K-aligned scratch; x2: scratch size;
 * x3: bit0 NV2, bit1 EL1t (otherwise EL1h).
 *
 * The EL1 vector contains only HVC. This observes hardware exception entry
 * without executing a guest handler; the production vector execute guard
 * must be qualified separately. No stage-1/stage-2 translation is exercised.
 * Every changed architectural register and host callee-saved GPR is restored.
 */
.text
.globl _start
_start:
    stp x29, x30, [sp, #-16]!
    stp x27, x28, [sp, #-16]!
    stp x25, x26, [sp, #-16]!
    stp x23, x24, [sp, #-16]!
    stp x21, x22, [sp, #-16]!
    stp x19, x20, [sp, #-16]!
    sub sp, sp, #192
    stp x0, x3, [sp]
    mov x19, x0
    mov x20, x1
    mov x21, x3
    mov x4, #0
1:  str xzr, [x19, x4]
    add x4, x4, #8
    cmp x4, #256
    b.lo 1b
    ldr x4, =0x4e43414c4c533031
    str x4, [x19]
    mov x4, #1
    str x4, [x19, #8]
    str x3, [x19, #24]
    mov x4, #64
    str x4, [x19, #32]
    mrs x4, daif
    str x4, [sp, #32]
    msr daifset, #0xf

.macro save reg, offset
    mrs x4, \reg
    str x4, [sp, #\offset]
.endm
    save sp_el0, 16
    save sp_el1, 24
    save hcr_el2, 40
    save vbar_el2, 48
    save sctlr_el1, 56
    save vbar_el1, 64
    save elr_el1, 72
    save spsr_el1, 80
    save esr_el1, 88
    save far_el1, 96
    save mdscr_el1, 104
    save elr_el2, 112
    save spsr_el2, 120
    mrs x4, id_aa64mmfr2_el1
    str x4, [x19, #224]
    ubfx x4, x4, #24, #4
    cmp x4, #2
    b.lo unsupported
    save s3_4_c2_c2_0, 128             /* VNCR_EL2 */
    cmp x2, #0x4000
    b.lo unsupported
    tst x1, #0xfff
    b.ne unsupported
    cmp x3, #3
    b.hi unsupported

    adr x4, el2_vectors
    msr vbar_el2, x4
    mov x4, #(1 << 31)                /* RW; VM, TGE and HCD clear */
    tbz x21, #0, 2f
    msr s3_4_c2_c2_0, x20
    orr x4, x4, #(1 << 42)
    orr x4, x4, #(1 << 45)
2:  msr hcr_el2, x4
    str x4, [x19, #240]
    ldr x4, [sp, #40]
    str x4, [x19, #232]
    isb
    msr sctlr_el1, xzr
    msr mdscr_el1, xzr
    adr x4, el1_vectors
    msr vbar_el1, x4
    add x4, x20, #0x4000
    msr sp_el1, x4
    sub x4, x4, #0x1000
    msr sp_el0, x4
    mov x4, #0x3c5
    tbz x21, #1, 3f
    mov x4, #0x3c4
3:  msr spsr_el2, x4
    adr x4, guest
    msr elr_el2, x4
    mrs x4, cntfrq_el0
    str x4, [x19, #216]
    isb
    mrs x4, cntpct_el0
    str x4, [x19, #200]
    eret

unsupported:
    mov x4, #4
    str x4, [x19, #16]
    /* VNCR was not changed; initialize its saved slot even on this path. */
    b initialize_restore

/* Native computation and register/flags checks around each intercepted call. */
.macro prepare
    ldr x0, =0x11223344
    ldr x1, =0x55667788
    ldr x2, =0x9900aabb
    ldr x3, =0xccddeeff
    mov x6, #32
1:  add x5, x5, #1
    sub x6, x6, #1
    cbnz x6, 1b
    mov x7, #0xa0000000
    msr nzcv, x7
.endm
.macro check
    mrs x7, nzcv
    str x7, [x19, #176]
    mov x8, #0xa0000000
    cmp x7, x8
    b.ne guest_failed
    ldr x8, =0x11223345
    cmp x0, x8
    b.ne guest_failed
    ldr x8, =0x55667788
    cmp x1, x8
    b.ne guest_failed
    ldr x8, =0x9900aabb
    cmp x2, x8
    b.ne guest_failed
    ldr x8, =0xccddeeff
    cmp x3, x8
    b.ne guest_failed
    mov x8, sp
    cmp x8, x9
    b.ne guest_failed
    ldr x8, [sp]
    ldr x10, =0x13579bdf2468ace0
    cmp x8, x10
    b.ne guest_failed
.endm
guest:
    sub sp, sp, #16
    mov x9, sp
    str x9, [x19, #248]
    ldr x10, =0x13579bdf2468ace0
    str x10, [sp]
    mov x4, #64
    mov x5, #0
guest_loop:
    prepare
genter_site:
    .inst 0x00201420
    check
    prepare
alternate_site:
    .inst 0xd4e00000
    check
    sub x4, x4, #1
    cbnz x4, guest_loop
    str x5, [x19, #184]
    add sp, sp, #16
    hvc #0xff
    b guest_failed
guest_failed:
    hvc #0xfe
    b guest_failed

/* The HVC shim preserves all GPRs and exposes the hardware EL1 saved state. */
.balign 2048
el1_vectors:
    hvc #0x91                         /* current EL, SP0, synchronous */
    b guest_failed
    .balign 128
    hvc #0xe1
    b guest_failed
    .balign 128
    hvc #0xe2
    b guest_failed
    .balign 128
    hvc #0xe3
    b guest_failed
    .balign 128
    hvc #0x92                         /* current EL, SPx, synchronous */
    b guest_failed
    .balign 128
    hvc #0xe5
    b guest_failed
    .balign 128
    hvc #0xe6
    b guest_failed
    .balign 128
    hvc #0xe7
    b guest_failed
    .rept 8
    .balign 128
    hvc #0xef
    b guest_failed
    .endr

.balign 2048
el2_vectors:
    .rept 16
    b exception
    .balign 128
    .endr

exception:
    sub sp, sp, #256
    stp x0, x1, [sp]
    stp x2, x3, [sp, #16]
    stp x4, x5, [sp, #32]
    stp x6, x7, [sp, #48]
    stp x8, x9, [sp, #64]
    stp x10, x11, [sp, #80]
    stp x12, x13, [sp, #96]
    stp x14, x15, [sp, #112]
    stp x16, x17, [sp, #128]
    stp x18, x19, [sp, #144]
    stp x20, x21, [sp, #160]
    stp x22, x23, [sp, #176]
    stp x24, x25, [sp, #192]
    stp x26, x27, [sp, #208]
    stp x28, x29, [sp, #224]
    str x30, [sp, #240]
    ldr x19, [sp, #256]
    mrs x0, esr_el2
    mrs x1, elr_el2
    mrs x2, spsr_el2
    stp x0, x1, [x19, #128]
    str x2, [x19, #144]
    ubfx x3, x0, #26, #6
    cmp x3, #0x16
    b.ne bad_exception
    ldr x3, [x19, #56]
    add x3, x3, #1
    str x3, [x19, #56]
    and x3, x0, #0xffff
    cmp x3, #0xff
    b.eq completed
    cmp x3, #0xfe
    b.eq check_failed
    ldr x3, [sp, #264]                /* saved mode */
    mov x4, #0x92
    tbz x3, #1, 4f
    mov x4, #0x91
4:  and x3, x0, #0xffff
    cmp x3, x4
    b.ne bad_exception
    mrs x0, esr_el1
    mrs x1, elr_el1
    mrs x2, spsr_el1
    mrs x3, far_el1
    ubfx x4, x0, #26, #6
    cbnz x4, bad_exception
    adr x4, genter_site
    cmp x1, x4
    b.eq genter_exception
    adr x4, alternate_site
    cmp x1, x4
    b.ne bad_exception
    stp x0, x1, [x19, #96]
    stp x2, x3, [x19, #112]
    ldr x4, [x19, #48]
    add x4, x4, #1
    str x4, [x19, #48]
    b resume_guest
genter_exception:
    stp x0, x1, [x19, #64]
    stp x2, x3, [x19, #80]
    ldr x4, [x19, #40]
    add x4, x4, #1
    str x4, [x19, #40]
resume_guest:
    /* With HCR.NV, hardware SPSR_EL1 describes the virtual EL2 mode. ERET
     * from the real EL2 must target physical EL1, never the saved EL2 mode. */
    ldr x4, [sp, #264]
    mov x5, #5
    tbz x4, #1, 5f
    mov x5, #4
5:  tbz x4, #0, 6f
    add x5, x5, #4
6:  and x6, x2, #31
    cmp x5, x6
    b.ne bad_exception
    tbz x4, #0, 7f
    sub x2, x2, #4
7:
    /* Emulated call reply; every other guest register stays unchanged. */
    ldr x4, [sp]
    add x4, x4, #1
    str x4, [sp]
    add x1, x1, #4
    msr elr_el2, x1
    msr spsr_el2, x2
    ldp x0, x1, [sp]
    ldp x2, x3, [sp, #16]
    ldp x4, x5, [sp, #32]
    ldp x6, x7, [sp, #48]
    ldp x8, x9, [sp, #64]
    ldp x10, x11, [sp, #80]
    ldp x12, x13, [sp, #96]
    ldp x14, x15, [sp, #112]
    ldp x16, x17, [sp, #128]
    ldp x18, x19, [sp, #144]
    ldp x20, x21, [sp, #160]
    ldp x22, x23, [sp, #176]
    ldp x24, x25, [sp, #192]
    ldp x26, x27, [sp, #208]
    ldp x28, x29, [sp, #224]
    ldr x30, [sp, #240]
    add sp, sp, #256
    eret
completed:
    mov x4, #1
    b finish_exception
check_failed:
    mov x4, #3
    b finish_exception
bad_exception:
    mov x4, #2
    mrs x0, esr_el2
    mrs x1, elr_el2
    mrs x2, far_el2
    stp x0, x1, [x19, #152]
    str x2, [x19, #168]
finish_exception:
    str x4, [x19, #16]
    isb
    mrs x4, cntpct_el0
    str x4, [x19, #208]
    add sp, sp, #256
    mov x12, #0
    ldr x4, [sp, #128]
    msr s3_4_c2_c2_0, x4
    isb
    mrs x5, s3_4_c2_c2_0
    cmp x4, x5
    b.eq restore_registers
    mov x12, #(1 << 13)
    b restore_registers
initialize_restore:
    mov x12, #0
restore_registers:
.macro restore reg, offset, bit
    ldr x10, [sp, #\offset]
    msr \reg, x10
    isb
    mrs x11, \reg
    cmp x10, x11
    b.eq 1f
    orr x12, x12, #(1 << \bit)
1:
.endm
    restore sp_el0, 16, 0
    restore sp_el1, 24, 1
    restore sctlr_el1, 56, 2
    restore vbar_el1, 64, 3
    restore elr_el1, 72, 4
    restore spsr_el1, 80, 5
    restore esr_el1, 88, 6
    restore far_el1, 96, 7
    restore mdscr_el1, 104, 8
    restore elr_el2, 112, 9
    restore spsr_el2, 120, 10
    restore hcr_el2, 40, 11
    restore vbar_el2, 48, 12
    str x12, [x19, #192]
    ldr x4, [sp, #32]
    msr daif, x4
    isb
    mov x0, #0
    add sp, sp, #192
    ldp x19, x20, [sp], #16
    ldp x21, x22, [sp], #16
    ldp x23, x24, [sp], #16
    ldp x25, x26, [sp], #16
    ldp x27, x28, [sp], #16
    ldp x29, x30, [sp], #16
    ret
    .ltorg

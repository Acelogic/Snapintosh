// SPDX-License-Identifier: MIT
.arch_extension pauth
.text
.balign 4
#ifndef PAUTH_NATIVE_NAME
#define PAUTH_NATIVE_NAME pauth_native_user
#endif
.globl PAUTH_NATIVE_NAME
PAUTH_NATIVE_NAME:
    stp x29,x30,[sp,#-96]!
    stp x19,x20,[sp,#16]
    stp x21,x22,[sp,#32]
    stp x23,x24,[sp,#48]
    stp x25,x26,[sp,#64]
    stp x27,x28,[sp,#80]
    mov x19,x0
    mov x20,x1
    mov w0,#1
    cbz x19,.Lreturn
    cbz x20,.Lreturn
    mrs x9,CurrentEL
    cmp x9,#8
    b.ne .Lreturn
    mrs x9,hcr_el2
    tbnz x9,#34,.Lreturn       // only the non-VHE EL2 regime
    mrs x22,sctlr_el2
    tbz x22,#0,.Lreturn
    mrs x23,tcr_el2
    ubfx x9,x23,#14,#2
    cbnz x9,.Lreturn          // 4K EL2 translation only
    and x9,x23,#63
    cmp x9,#17
    b.lo .Lreturn
    cmp x9,#24
    b.hi .Lreturn            // preserve the existing L0 table geometry
    mrs x9,id_aa64isar1_el1
    ubfx x10,x9,#4,#8
    mrs x9,id_aa64isar2_el1
    ubfx x9,x9,#12,#4
    orr x9,x9,x10
    cbz x9,.Lreturn
    ldr x26,[x19,#32]
    cmp x26,#3
    b.hi .Lreturn
    ldp x10,x11,[x19,#40]
    orr x9,x10,x11
    cmp x9,#1
    b.hi .Lreturn
#if !PAUTH_NATIVE_RAW_SIGN
    // Only canonical lower 47-bit pointers can round-trip through AUT.
    // A top-byte tag is legal only when TBI applies to this key class.
    cmp x26,#2
    cset x12,hs
    eor x13,x11,#1
    orr x12,x12,x13
    and x12,x12,x10
    ldr x13,[x19]
    cbnz x12,.Ltagged_pointer
    lsr x13,x13,#47
    b .Lcheck_pointer
.Ltagged_pointer:
    ubfx x13,x13,#47,#9
.Lcheck_pointer:
    cbnz x13,.Lreturn
#endif
    // Expanding T0SZ within L0 preserves all currently mapped EL2 VAs.
    // TBI/TBID affect PAC composition; the executing identity mappings are
    // untagged. Scope the changes to this PE and flush its EL2 TLB both ways.
    mov x9,x23
    mov x12,#17
    bfi x9,x12,#0,#6
    bfi x9,x10,#20,#1
    bfi x9,x11,#29,#1
    mrs x21,daif
    msr daifset,#15
    dsb sy
    msr tcr_el2,x9
    isb
    tlbi alle2
    dsb sy
    isb
    mov x9,#0x2000
    movk x9,#0xc800,lsl #16
    orr x9,x22,x9
    msr sctlr_el2,x9
    isb
    ldp x27,x28,[x19,#16]
    cbz x26,.Lia_save
    cmp x26,#1
    b.eq .Lib_save
    cmp x26,#2
    b.eq .Lda_save
    mrs x24,s3_0_c2_c2_2
    mrs x25,s3_0_c2_c2_3
    msr s3_0_c2_c2_2,x27
    msr s3_0_c2_c2_3,x28
    b .Loperate
.Lia_save:
    mrs x24,s3_0_c2_c1_0
    mrs x25,s3_0_c2_c1_1
    msr s3_0_c2_c1_0,x27
    msr s3_0_c2_c1_1,x28
    b .Loperate
.Lib_save:
    mrs x24,s3_0_c2_c1_2
    mrs x25,s3_0_c2_c1_3
    msr s3_0_c2_c1_2,x27
    msr s3_0_c2_c1_3,x28
    b .Loperate
.Lda_save:
    mrs x24,s3_0_c2_c2_0
    mrs x25,s3_0_c2_c2_1
    msr s3_0_c2_c2_0,x27
    msr s3_0_c2_c2_1,x28
.Loperate:
    isb
    ldp x8,x9,[x19]
    cbz x26,.Lia_op
    cmp x26,#1
    b.eq .Lib_op
    cmp x26,#2
    b.eq .Lda_op
    pacdb x8,x9
#if PAUTH_NATIVE_RAW_SIGN
    mov x10,xzr
#else
    mov x10,x8
    autdb x10,x9
#endif
    msr s3_0_c2_c2_2,x24
    msr s3_0_c2_c2_3,x25
    isb
    mrs x11,s3_0_c2_c2_2
    mrs x12,s3_0_c2_c2_3
    b .Lrestore
.Lia_op:
    pacia x8,x9
#if PAUTH_NATIVE_RAW_SIGN
    mov x10,xzr
#else
    mov x10,x8
    autia x10,x9
#endif
    msr s3_0_c2_c1_0,x24
    msr s3_0_c2_c1_1,x25
    isb
    mrs x11,s3_0_c2_c1_0
    mrs x12,s3_0_c2_c1_1
    b .Lrestore
.Lib_op:
    pacib x8,x9
#if PAUTH_NATIVE_RAW_SIGN
    mov x10,xzr
#else
    mov x10,x8
    autib x10,x9
#endif
    msr s3_0_c2_c1_2,x24
    msr s3_0_c2_c1_3,x25
    isb
    mrs x11,s3_0_c2_c1_2
    mrs x12,s3_0_c2_c1_3
    b .Lrestore
.Lda_op:
    pacda x8,x9
#if PAUTH_NATIVE_RAW_SIGN
    mov x10,xzr
#else
    mov x10,x8
    autda x10,x9
#endif
    msr s3_0_c2_c2_0,x24
    msr s3_0_c2_c2_1,x25
    isb
    mrs x11,s3_0_c2_c2_0
    mrs x12,s3_0_c2_c2_1
.Lrestore:
    cmp x11,x24
    ccmp x12,x25,#0,eq
    cset x16,eq
    dsb sy
    msr tcr_el2,x23
    isb
    tlbi alle2
    dsb sy
    isb
    msr sctlr_el2,x22
    isb
    mrs x11,tcr_el2
    cmp x11,x23
    cset x12,eq
    orr x16,x16,x12,lsl #1
    mrs x11,sctlr_el2
    cmp x11,x22
    cset x12,eq
    orr x16,x16,x12,lsl #2
    msr daif,x21
    mrs x11,daif
    cmp x11,x21
    cset x12,eq
    orr x16,x16,x12,lsl #3
    stp x8,x10,[x20]
    str x16,[x20,#16]
    cmp x16,#15
    cset w0,ne
.Lreturn:
    ldp x19,x20,[sp,#16]
    ldp x21,x22,[sp,#32]
    ldp x23,x24,[sp,#48]
    ldp x25,x26,[sp,#64]
    ldp x27,x28,[sp,#80]
    ldp x29,x30,[sp],#96
    ret

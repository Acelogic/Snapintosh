/* SPDX-License-Identifier: MIT */
/* Make a guest believe in a page size the hardware does not have.
 *
 * Shadow paging keeps the guest's 16K tables away from the MMU, but that only
 * works if the guest thinks 16K exists in the first place. XNU reads
 * ID_AA64MMFR0_EL1; on this machine TGran16 reads 0. HCR_EL2.TID3 traps reads
 * of the ID group to EL2, so the value the guest sees is whatever we hand it.
 *
 * This probe proves the mechanism end to end with no hypervisor around it:
 * install our own EL2 vectors, drop to EL1, have the guest read the register,
 * trap it, substitute a forged value, and return. Everything is restored before
 * the probe returns, so it is safe to run against a live q1n1.
 *
 * Deliberately self-contained: it runs as a P_CALL blob rather than needing
 * guest-entry support in q1n1, so the trap path can be tested before any of the
 * hypervisor exists.
 *
 * x0 = out buffer.
 */

/* ID_AA64MMFR0_EL1 is op0=3 op1=0 CRn=0 CRm=7 op2=0. The ESR ISS for a trapped
 * MSR/MRS packs those as Op0[21:20] Op2[19:17] Op1[16:14] CRn[13:10] Rt[9:5]
 * CRm[4:1] Direction[0]. Matching on everything but Rt identifies the register. */
#define ISS_MMFR0   ((3 << 20) | (0 << 17) | (0 << 14) | (0 << 10) | (7 << 1) | 1)
#define ISS_MASK    ((3 << 20) | (7 << 17) | (7 << 14) | (15 << 10) | (15 << 1) | 1)

#define OUT_REAL_MMFR0   0
#define OUT_GUEST_MMFR0  8
#define OUT_GUEST_ISAR2  16
#define OUT_TRAPS        24
#define OUT_BAD_ESR      32
#define OUT_BAD_ELR      40

.text
.globl _start
_start:
    stp x29, x30, [sp, #-16]!
    stp x19, x20, [sp, #-16]!
    stp x21, x22, [sp, #-16]!
    stp x23, x24, [sp, #-16]!
    mov x19, x0                         /* out buffer */

    /* Save every piece of EL2/EL1 state this probe disturbs. */
    mrs x20, vbar_el2
    mrs x21, hcr_el2
    mrs x22, spsr_el2
    mrs x23, elr_el2
    mrs x24, sctlr_el1

    /* Scratch state lives after the caller's buffer: trap counter, saved SP,
     * and the guest stack. Keeping it here avoids needing writable globals in
     * a position-independent blob. */
    add x9, x19, #64
    str xzr, [x9, #0]                   /* trap count */
    mov x10, sp
    str x10, [x9, #8]                   /* EL2 SP, for the HVC exit path */
    str xzr, [x19, #OUT_BAD_ESR]
    str xzr, [x19, #OUT_BAD_ELR]
    str x19, [x9, #16]                  /* out buffer, for the handler */

    /* The real value, read at EL2 where TID3 does not apply. */
    mrs x11, id_aa64mmfr0_el1
    str x11, [x19, #OUT_REAL_MMFR0]

    adr x12, vectors
    msr vbar_el2, x12
    isb

    /* TID3 traps the ID group. RW makes EL1 AArch64. TGE must be clear or
     * there is no EL1 to drop into; VM off keeps stage 2 out of this test. */
    mov x13, #(1 << 31)                 /* RW */
    orr x13, x13, #(1 << 18)            /* TID3 */
    msr hcr_el2, x13
    isb

    msr sctlr_el1, xzr                  /* guest runs with its MMU off */
    add x14, x9, #(16 * 8)              /* guest stack, above the scratch */
    msr sp_el1, x14
    mov x15, #0x3c5                     /* EL1h, DAIF masked */
    msr spsr_el2, x15
    adr x16, guest
    msr elr_el2, x16
    isb
    eret

/* --- the guest, at EL1 --- */
guest:
    mrs x10, id_aa64mmfr0_el1           /* traps; we substitute the answer */
    mrs x11, id_aa64isar2_el1           /* traps too, passed through unaltered */
    hvc #0                              /* back to EL2 */
    b .

/* --- EL2 vectors; only "synchronous, lower EL, AArch64" is ever taken --- */
.balign 2048
vectors:
.balign 128
    b bad                               /* current EL, SP0, sync */
.balign 128
    b bad
.balign 128
    b bad
.balign 128
    b bad
.balign 128
    b bad                               /* current EL, SPx, sync */
.balign 128
    b bad
.balign 128
    b bad
.balign 128
    b bad
.balign 128
    b sync_lower                        /* lower EL, AArch64, sync */
.balign 128
    b bad
.balign 128
    b bad
.balign 128
    b bad
.balign 128
    b bad                               /* lower EL, AArch32 */
.balign 128
    b bad
.balign 128
    b bad
.balign 128
    b bad

sync_lower:
    /* Frame the guest's registers so the trapped read can be delivered into
     * whichever Xt it named, without a jump table. */
    sub sp, sp, #(32 * 8)
    stp x0, x1, [sp, #(0 * 8)]
    stp x2, x3, [sp, #(2 * 8)]
    stp x4, x5, [sp, #(4 * 8)]
    stp x6, x7, [sp, #(6 * 8)]
    stp x8, x9, [sp, #(8 * 8)]
    stp x10, x11, [sp, #(10 * 8)]
    stp x12, x13, [sp, #(12 * 8)]
    stp x14, x15, [sp, #(14 * 8)]
    stp x16, x17, [sp, #(16 * 8)]
    stp x18, x19, [sp, #(18 * 8)]
    stp x20, x21, [sp, #(20 * 8)]
    stp x22, x23, [sp, #(22 * 8)]
    stp x24, x25, [sp, #(24 * 8)]
    stp x26, x27, [sp, #(26 * 8)]
    stp x28, x29, [sp, #(28 * 8)]
    str x30, [sp, #(30 * 8)]

    mrs x0, esr_el2
    lsr x1, x0, #26                     /* EC */
    cmp x1, #0x16                       /* HVC64: the guest is done */
    b.eq exit_guest
    cmp x1, #0x18                       /* trapped MSR/MRS */
    b.ne unexpected

    /* Count it, then decide whether this is the register we forge. */
    add x9, x19, #64
    ldr x2, [x9, #0]
    add x2, x2, #1
    str x2, [x9, #0]

    and x3, x0, #0x1ffffff              /* ISS */
    ubfx x4, x3, #5, #5                 /* Rt */
    movz x5, #64543
    movk x5, #63, lsl #16
    bic x6, x3, #(31 << 5)              /* clear Rt before matching */
    and x6, x6, x5
    movz x7, #15
    movk x7, #48, lsl #16
    cmp x6, x7
    b.ne pass_through

    /* Forge TGran16 = 0b0010 (16K supported) and TGran16_2 = 0b0010, leaving
     * every other field as the hardware reports it. This is the entire lie. */
    mrs x8, id_aa64mmfr0_el1
    mov x10, #0xf
    lsl x11, x10, #20
    bic x8, x8, x11                     /* clear TGran16 */
    mov x12, #2
    lsl x13, x12, #20
    orr x8, x8, x13
    lsl x11, x10, #32
    bic x8, x8, x11                     /* clear TGran16_2 */
    lsl x13, x12, #32
    orr x8, x8, x13
    b deliver

pass_through:
    /* The only other register this guest reads. A real hypervisor would decode
     * the full ID group here; the point of the probe is that the untouched
     * registers come back exactly as the hardware reports them. */
    mrs x8, id_aa64isar2_el1

deliver:
    /* Write the result into the guest's Xt slot in the frame. x31 is XZR and
     * is discarded rather than written. */
    cmp x4, #31
    b.eq skip_write
    add x14, sp, x4, lsl #3
    str x8, [x14]
skip_write:
    /* Step over the trapped instruction. */
    mrs x15, elr_el2
    add x15, x15, #4
    msr elr_el2, x15
    b restore_and_eret

unexpected:
    str x0, [x19, #OUT_BAD_ESR]
    mrs x1, elr_el2
    str x1, [x19, #OUT_BAD_ELR]
    /* Fall through: unwind to the caller rather than looping in the guest. */

exit_guest:
    /* Record what the guest saw, then return to the EL2 caller directly --
     * there is no guest left to ERET into. */
    ldr x10, [sp, #(10 * 8)]
    ldr x11, [sp, #(11 * 8)]
    str x10, [x19, #OUT_GUEST_MMFR0]
    str x11, [x19, #OUT_GUEST_ISAR2]
    add x9, x19, #64
    ldr x2, [x9, #0]
    str x2, [x19, #OUT_TRAPS]
    ldr x3, [x9, #8]
    mov sp, x3                          /* the EL2 stack we entered on */

    msr vbar_el2, x20
    msr hcr_el2, x21
    msr spsr_el2, x22
    msr elr_el2, x23
    msr sctlr_el1, x24
    isb

    mov x0, #0
    ldp x23, x24, [sp], #16
    ldp x21, x22, [sp], #16
    ldp x19, x20, [sp], #16
    ldp x29, x30, [sp], #16
    ret

restore_and_eret:
    ldp x0, x1, [sp, #(0 * 8)]
    ldp x2, x3, [sp, #(2 * 8)]
    ldp x4, x5, [sp, #(4 * 8)]
    ldp x6, x7, [sp, #(6 * 8)]
    ldp x8, x9, [sp, #(8 * 8)]
    ldp x10, x11, [sp, #(10 * 8)]
    ldp x12, x13, [sp, #(12 * 8)]
    ldp x14, x15, [sp, #(14 * 8)]
    ldp x16, x17, [sp, #(16 * 8)]
    ldp x18, x19, [sp, #(18 * 8)]
    ldp x20, x21, [sp, #(20 * 8)]
    ldp x22, x23, [sp, #(22 * 8)]
    ldp x24, x25, [sp, #(24 * 8)]
    ldp x26, x27, [sp, #(26 * 8)]
    ldp x28, x29, [sp, #(28 * 8)]
    ldr x30, [sp, #(30 * 8)]
    add sp, sp, #(32 * 8)
    eret

bad:
    /* Anything else is a bug in this probe, not a result. */
    mrs x0, esr_el2
    str x0, [x19, #OUT_BAD_ESR]
    b exit_guest

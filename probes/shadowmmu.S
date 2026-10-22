/* SPDX-License-Identifier: MIT */
/* Entry stub, EL2 vectors and the guest for the shadowed-MMU probe.
 * Every decision lives in shadowmmu.c; this is the plumbing around them.
 *
 * x0 = out buffer, x1 = work area, x2 = work size.
 *
 * The exception frame is pushed on the EL2 stack, which is the same stack the
 * entry stub is using, so popping the frame on the way out restores the entry
 * stub's SP exactly. And x19-x26 survive the guest untouched -- it only uses
 * x0-x4, x10 and x11 -- so the saved EL2 state round-trips through the frame
 * without needing anywhere else to live.
 */

#define OUT_MAGIC     0        /* what the guest read through its own VA */
#define OUT_TTBR_BACK 8        /* what the guest read back from TTBR0_EL1 */
#define OUT_REPORT    16       /* 8 words from shadowmmu_report */
#define OUT_EXPECT    80
#define OUT_TEST_VA   88
#define OUT_ENTERED   96

#define FRAME (34 * 8)

.section .text.entry, "ax"
.globl _start
_start:
    stp x29, x30, [sp, #-16]!
    stp x19, x20, [sp, #-16]!
    stp x21, x22, [sp, #-16]!
    stp x23, x24, [sp, #-16]!
    stp x25, x26, [sp, #-16]!
    sub sp, sp, #80                     /* scratch for shadowmmu_prepare */
    mov x19, x0                         /* out */
    mov x20, x1                         /* work */
    mov x27, x2                         /* work size */

    /* q1n1 takes a 1 kHz timer interrupt at EL2. This probe replaces VBAR_EL2,
     * so any tick that lands while it runs would be delivered to vectors that
     * only know how to abort -- and the build below takes milliseconds, so one
     * would. Mask for the duration; the guest already runs with DAIF set. */
    mrs x28, daif
    msr daifset, #0xf

    mrs x21, vbar_el2
    mrs x22, hcr_el2
    mrs x23, tpidr_el2
    mrs x24, sctlr_el1
    mrs x25, tcr_el1
    mrs x26, ttbr0_el1

    mov x10, #0
    mov x11, #0
    str xzr, [x19, #OUT_ENTERED]
    /* The fault slots are only written when the fault path runs, so clear them
     * or the caller reports whatever heap fill was there (0xaf on this target,
     * which decodes as a convincing-looking ESR). */
    str xzr, [x19, #104]
    str xzr, [x19, #112]
    str xzr, [x19, #120]

    mov x0, x20
    mov x1, x27
    str x3, [sp, #72]                   /* stage: past the 8 words prepare() fills */
    mov x2, x3
    mov x3, x19                         /* out, for the fault path */
    bl shadowmmu_setup
    mov x1, sp
    str x1, [x20]                       /* context.el2_sp, offset 0 */

    /* Stage 0 never leaves EL2, so a failure here is readable instead of a
     * hang. The guest path is only worth entering once this passes. */
    adr x0, _start
    bl shadowmmu_selftest
    str x0, [x19, #OUT_ENTERED]         /* selftest verdict, overwritten below */
    ldr x3, [sp, #72]
    cbz x3, exit

    /* Guest tables are built around this blob's own address, so the identity
     * mapping covers the code that will be executing when the MMU comes on. */
    adr x0, _start
    mov x1, sp
    bl shadowmmu_prepare
    cbz x0, exit                        /* no room: report zeros */

    ldr x5, [sp, #24]                   /* test VA */
    ldr x6, [sp, #32]                   /* magic */
    str x6, [x19, #OUT_EXPECT]
    str x5, [x19, #OUT_TEST_VA]

    /* Stage 5 and up run the guest with stage 2 active. Built before HCR is
     * written so VTTBR/VTCR are valid the moment VM is set. */
    mov x17, #0                         /* HCR_EL2.VM, off unless stage >= 5 */
    ldr x3, [sp, #72]
    cmp x3, #5
    b.lt 2f
    bl shadowmmu_stage2
    cbz x0, exit
    mov x17, #1
2:
    adr x7, vectors
    msr vbar_el2, x7
    /* RW: AArch64 guest. TVM/TRVM: the guest's MMU registers never reach the
     * hardware, in either direction. TID3: it must believe 16K exists before it
     * will ask for it. */
    mov x8, #(1 << 31)
    orr x8, x8, #(1 << 26)              /* TVM  */
    orr x8, x8, #(1 << 30)              /* TRVM */
    orr x8, x8, #(1 << 18)              /* TID3 */
    orr x8, x8, x17                     /* VM, when stage 2 is in play */
    msr hcr_el2, x8
    isb

    msr sctlr_el1, xzr                  /* guest starts with translation off */
    add x9, x20, x27
    and x9, x9, #~15
    msr sp_el1, x9
    mov x12, #0x3c5                     /* EL1h, DAIF masked */
    msr spsr_el2, x12
    adr x13, guest
    msr elr_el2, x13

    ldr x16, [sp, #72]                  /* stage, for the guest to branch on */
    ldp x0, x1, [sp, #0]                /* guest ttbr0, tcr */
    ldr x2, [sp, #16]                   /* guest mair */
    ldr x6, [sp, #40]                   /* guest ttbr1, 0 below stage 8 */
    ldr x7, [sp, #48]                   /* the kernel-half VA to load through */
    mov x3, #1                          /* SCTLR_EL1.M */
    mov x4, x5                          /* test VA */
    mov x5, x16
    mov x14, #1
    str x14, [x19, #OUT_ENTERED]
    isb
    eret

/* Reached with the guest gone: x10/x11 hold what it saw, x19-x26 the saved
 * state, and SP back where the entry stub left it. */
exit:
    str x10, [x19, #OUT_MAGIC]
    str x11, [x19, #OUT_TTBR_BACK]
    add x0, x19, #OUT_REPORT
    bl shadowmmu_report                 /* reads TPIDR_EL2, so before restoring it */

    msr vbar_el2, x21
    msr hcr_el2, x22
    msr tpidr_el2, x23
    msr sctlr_el1, x24
    msr tcr_el1, x25
    msr ttbr0_el1, x26
    msr daif, x28
    isb

    mov x0, #0
    add sp, sp, #80
    ldp x25, x26, [sp], #16
    ldp x23, x24, [sp], #16
    ldp x21, x22, [sp], #16
    ldp x19, x20, [sp], #16
    ldp x29, x30, [sp], #16
    ret

/* --- the guest, at EL1 --- */
/* Stages, so a hang can be bisected: 1 enters and leaves, 2 also programs the
 * MMU registers (proving TVM traps them), 3 enables translation and loads. */
guest:
    cmp x5, #1
    b.eq guest_done
    /* Its own EL1 vectors first. A fault in the guest goes to EL1, not EL2 --
     * there is no bit that routes only stage-1 faults up -- so without this a
     * mistake in the shadow is an indistinguishable hang instead of a report. */
    adr x15, guest_vectors
    msr vbar_el1, x15                   /* not trapped by TVM */
    isb
    msr ttbr0_el1, x0                   /* trapped: recorded, never programmed */
    msr tcr_el1, x1                     /* trapped: a 16K granule the HW lacks */
    msr mair_el1, x2                    /* trapped */
    msr ttbr1_el1, x6                   /* trapped; zero until stage 8 */
    isb
    cmp x5, #2
    b.eq guest_done
    /* Stage 20 writes SCTLR with M clear: it proves the write traps without
     * risking an MMU enable, which is the one step that cannot be undone from
     * inside the guest. */
    cmp x5, #20
    b.ne 1f
    mov x3, #0
1:
    msr sctlr_el1, x3
    cmp x5, #20
    b.eq guest_done
    mov x13, x5                         /* the stage survives the clamp below */
    cmp x5, #5
    csel x5, xzr, x5, ge                /* stage >= 5 runs the full guest */                   /* trapped: EL2 builds the shadow here */
    isb
    ldr x10, [x4]                       /* only resolvable through the shadow */
    mrs x11, ttbr0_el1                  /* TRVM: must read back the guest's value */
    cmp x13, #6
    b.lt guest_done
    /* A call into a page EL2 marked execute-never at stage 2. Nothing in
     * `guest_stub` runs: the fetch faults to EL2, which answers in x0 and
     * returns past the call. This is how XNU's monitor-call stubs have to be
     * caught, since their `genter` is an undefined encoding here and an
     * undefined instruction at EL1 is delivered to EL1, never to EL2. */
    mov x0, #0x5150
    bl guest_stub
    mov x12, x0
    cmp x13, #8
    b.lt 3f
    /* The upper half, through the guest's own 16K TTBR1 regime. This is the
     * address family the kernelcache is linked for, so resolving it is the last
     * translation mechanism XNU needs that was not yet proven. */
    ldr x9, [x7]
3:
    cmp x13, #7
    b.lt guest_done
    /* And ordinary code on that same protected page, which has to run rather
     * than be answered. In the kernelcache this is whatever function happens to
     * share a page with the call stubs. */
    mov x0, #0x1234
    bl guest_neighbour
    mov x14, x0
guest_done:
    hvc #0
    b .

/* Any exception the guest takes itself: hand EL2 the reason and stop. */
.balign 2048
guest_vectors:
.rept 16
.balign 128
    hvc #1
.endr

.balign 2048
vectors:
.balign 128
    b bad
.balign 128
    b bad
.balign 128
    b bad
.balign 128
    b bad
.balign 128
    b bad
.balign 128
    b bad
.balign 128
    b bad
.balign 128
    b bad
.balign 128
    b sync_lower                        /* lower EL, AArch64, synchronous */
.balign 128
    b bad
.balign 128
    b bad
.balign 128
    b bad
.balign 128
    b bad
.balign 128
    b bad
.balign 128
    b bad
.balign 128
    b bad

sync_lower:
    sub sp, sp, #FRAME
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

    mrs x1, esr_el2
    mrs x2, elr_el2
    str x2, [sp, #(32 * 8)]
    mov x0, sp
    add x2, sp, #(32 * 8)               /* &elr, so the handler can step over */
    bl shadowmmu_trap
    str x0, [sp, #(33 * 8)]             /* verdict, past the register restore */

    ldr x2, [sp, #(32 * 8)]
    msr elr_el2, x2
    ldp x0, x1, [sp, #(0 * 8)]
    ldp x2, x3, [sp, #(2 * 8)]
    ldp x4, x5, [sp, #(4 * 8)]
    ldp x6, x7, [sp, #(6 * 8)]
    ldp x8, x9, [sp, #(8 * 8)]
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

    ldr x11, [sp, #(33 * 8)]
    cbnz x11, done                      /* 1 = HVC, negative = unhandled */
    ldp x10, x11, [sp, #(10 * 8)]       /* resume: the guest's own x10/x11 */
    add sp, sp, #FRAME
    eret

done:
    /* Guest's results out of the frame, then pop it so SP matches the entry
     * stub, and x19-x26 are the values it saved. */
    ldp x10, x11, [sp, #(10 * 8)]
    ldp x19, x20, [sp, #(19 * 8)]
    ldp x21, x22, [sp, #(21 * 8)]
    ldp x23, x24, [sp, #(23 * 8)]
    ldp x25, x26, [sp, #(25 * 8)]
    ldp x27, x28, [sp, #(27 * 8)]
    add sp, sp, #FRAME
    b exit

bad:
    /* Any vector but the guest's synchronous one. This can fire in the middle of
     * the trap handler, with a frame pushed and registers holding compiler
     * temporaries, so nothing is assumed: the stack and the out buffer both come
     * back from the context via TPIDR_EL2. Without this an EL2 fault here
     * unwinds through a corrupted SP and hangs, which is indistinguishable from
     * the guest never returning. */
    mrs x9, tpidr_el2
    ldr x10, [x9, #0]                   /* context.el2_sp */
    mov sp, x10
    ldr x19, [x9, #8]                   /* context.out_ptr */
    mrs x0, esr_el2
    str x0, [x19, #104]
    mrs x0, elr_el2
    str x0, [x19, #112]
    mrs x0, far_el2
    str x0, [x19, #120]
    mov x10, #0
    mov x11, #0
    b exit

/* The stub the guest calls into, alone on a 4K page so that making the page
 * execute-never at stage 2 traps the call and nothing else. It is also the
 * negative control: if the page ever does execute, x0 comes back as zero
 * instead of EL2's answer, and the run reports a wrong result rather than
 * passing quietly. The trailing alignment keeps the C objects off this page. */
.balign 4096
.globl guest_stub
guest_stub:
    mov x0, #0
    ret

/* Ordinary code, on the same protected page. EL2 has to let this run: it
 * unprotects the page, software-steps one instruction, and protects it again,
 * twice over for the two instructions here. */
.balign 256
.globl guest_neighbour
guest_neighbour:
    add x0, x0, #1
    ret
.balign 4096

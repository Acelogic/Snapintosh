/* SPDX-License-Identifier: MIT */
/* Entry stub and EL2 vectors for the XNU entry probe. Every decision lives in
 * xnuboot.c; this is the plumbing.
 *
 * x0 = out buffer, x1 = work area, x2 = work size, x3 = params (physical),
 * x4 = optional host secondary configuration (zero disables physical launch).
 *
 * There is no guest here: the guest is the stock kernelcache, already in memory
 * with its page tables built by the host. This sets EL1 up and ERETs into it.
 */

#define OUT_STATUS   0         /* 0 entered and returned, negative = prepare failed */
#define OUT_ENTERED  8
#define OUT_REPORT   16        /* 8 words, then the event log, the console, the
                                * register snapshots and the counters; the full
                                * map is in xnuboot.c above OUT_GUEST_REGS */

/* Where the `bad` vector leaves ELR_EL2 and FAR_EL2. Byte offsets into the
 * private vCPU, asserted on the other side by _Static_assert in xnuboot.c, because
 * a field inserted above them there would move them silently here. */
#define CTX_BAD_ELR  16
#define CTX_BAD_FAR  24

#define FRAME (34 * 8)
/* SNAP_SERVICE_SUBCLASS (xnuboot.c): sync_lower stamps CNTPCT into the
 * otherwise unused frame slot 31; a lock-free exit marks its class in the
 * top byte and xnuboot_pauth_resume charges the round trip. */
#ifndef SNAP_SERVICE_SUBCLASS
#define SNAP_SERVICE_SUBCLASS 0
#endif
/* SNAP_PAUTH_EL0_LIVE (xnuboot.c el0_live_trap): sync_lower leaves the EL0 PAC
 * bank installed for an entry that may be an EL0 read answered lock-free. */
#ifndef SNAP_PAUTH_EL0_LIVE
#define SNAP_PAUTH_EL0_LIVE 0
#endif
#include "../compat/pauth-switch.h"
/* vCPU 0 on another physical CPU (compat/boot-relocate.h, probes/xnuboot.c). */
#ifndef SNAP_BOOT_RELOCATE
#define SNAP_BOOT_RELOCATE 0
#endif
#if SNAP_BOOT_RELOCATE
#include "../compat/boot-relocate.h"
#endif
.macro pauth_bank_pointer
    mrs x0,tpidr_el2
    ldr x9,[x0,#32]
    ldr x0,[x0,#40]
    add x0,x9,x0,lsl #8
    movz x10,#(PAUTH_BANK_CONTEXT & 65535)
    movk x10,#(PAUTH_BANK_CONTEXT >> 16),lsl #16
    add x0,x0,x10
.endm

/* Which asynchronous vector an exception arrived at, mirrored in xnuboot.c.
 *
 * This exists because IRQ and FIQ do not write ESR_EL2 at all -- only the
 * SError vector does. Reading ESR_EL2 after an IRQ therefore returns the
 * syndrome of some earlier synchronous trap, so the register cannot be what
 * tells the three apart. The vector can, and it is the one fact available at
 * no cost. */
#define ASYNC_IRQ    0
#define ASYNC_FIQ    1
#define ASYNC_SERROR 2

.section .text.entry, "ax"
.globl _start
_start:
    stp x29, x30, [sp, #-16]!
    stp x19, x20, [sp, #-16]!
    stp x21, x22, [sp, #-16]!
    stp x23, x24, [sp, #-16]!
    stp x25, x26, [sp, #-16]!
    stp x27, x28, [sp, #-16]!
    mov x19, x0                         /* out */
    mov x20, x1                         /* work */
    mov x27, x2                         /* work size */
    mov x21, x3                         /* params */

    /* q1n1 takes a 1 kHz timer interrupt at EL2, and this replaces VBAR_EL2, so
     * a tick landing mid-build would be delivered to vectors that only abort. */
    mrs x28, daif
    msr daifset, #0xf

    mrs x22, vbar_el2
    mrs x23, hcr_el2
    mrs x24, tpidr_el2
    mrs x25, sctlr_el1
    mrs x26, tcr_el1

    str xzr, [x19, #OUT_STATUS]
    str xzr, [x19, #OUT_ENTERED]

    mov x0, x20
    mov x1, x27
    mov x2, x21
    mov x3, x19
    bl xnuboot_setup
    mov x1, sp
    mrs x9, tpidr_el2
    str x1, [x9]                        /* private vcpu.el2_sp, offset 0 */

    /* The saved EL2 state goes in the private CPU record. The guest here
     * is a stock kernel: it will use x19-x28 as it pleases, so nothing that has
     * to survive the ERET can live in one. */
    mov x0, x22
    mov x1, x23
    mov x2, x24
    mov x3, x25
    mov x4, x26
    mov x5, x28
    bl xnuboot_save

    /* Vectors first: xnuboot_prepare enables EL1 translation and probes it, and
     * a fault during that has to land somewhere that can report. */
    adr x7, vectors
    msr vbar_el2, x7
    /* RW: AArch64 guest. TVM/TRVM: XNU's MMU registers never reach the hardware
     * in either direction. VM: stage 2.
     *
     * TIDCP is the one that makes Apple's silicon emulable at all. XNU reads
     * Apple IMPDEF system registers -- the first is `mrs x8, S3_6_C15_C2_7`, 12
     * events in -- and those encodings are simply undefined here, which at EL1
     * is delivered to EL1, not to us. TIDCP traps the whole IMPDEF encoding
     * space (CRn 9, 10, 11 and 15) to EL2 in preference to that undefined
     * exception, so every one of them becomes ours to answer.
     *
     * TID3 traps the ID group. It was dropped once, because this handler used to
     * answer anything it did not decode with zero -- which told XNU it was
     * running on a CPU with no features at all. probes/idregs.h now reads every
     * allocated encoding for real (the rest read as zero, never as an MRS), so
     * the answers are the truth with only the features this hypervisor cannot
     * stand behind removed. */
    mov x8, #(1 << 31)
    orr x8, x8, #(1 << 26)              /* TVM   */
    orr x8, x8, #(1 << 30)              /* TRVM  */
    orr x8, x8, #(1 << 20)              /* TIDCP */
    orr x8, x8, #(1 << 18)              /* TID3: the ID group, so features the
                                         * hypervisor cannot support can be
                                         * denied rather than discovered */
    orr x8, x8, #1                      /* VM    */
    orr x8, x8, #(1 << 14)              /* TWE: virtual event stream */
    msr hcr_el2, x8
    isb

    bl xnuboot_prepare
    str x0, [x19, #OUT_STATUS]
    cbnz x0, exit                       /* negative: the step is in OUT_STATUS */
#if SNAP_BOOT_RELOCATE
    /* Relocated: another CPU runs vCPU 0 and this one serves its q1n1 calls
     * until that CPU is OFF; then the report, exactly as below. */
    bl xnuboot_boot_relocate
    cbnz x0, exit
#endif

    /* SP_EL1 is XNU's business -- its entry stub sets both stacks itself from
     * fixed addresses -- so it is left at whatever the shadow maps rather than
     * guessed at here. */
    mov x12, #0x3c5                     /* EL1h, DAIF masked */
    msr spsr_el2, x12
    ldr x13, [x21, #24]                 /* params.entry */
    msr elr_el2, x13

    /* A bounded slice of guest, then control comes back whatever it is doing.
     * Without this a guest that never returns wedges EL2 inside the proxy call
     * and the machine needs a power cycle.
     *
     * Two seconds was plenty while every run ended on the first fault. It is not
     * enough now that faults resume into XNU's own handler: the panic path walks
     * a lot of state before it emits its first character, and cutting it off
     * mid-way looks exactly like a kernel that printed nothing. The budget comes
     * from the host so a long look does not need a rebuild. */
    ldr x0, [x21, #192]                 /* params.watchdog_seconds */
    bl xnuboot_watchdog
    mrs x8, hcr_el2
    orr x8, x8, #(1 << 4)               /* IMO: IRQs to EL2, EL1 cannot mask */
    orr x8, x8, #(1 << 3)               /* FMO: and FIQs */
    msr hcr_el2, x8
    isb

    mov x14, #1
    str x14, [x19, #OUT_ENTERED]
    ldr x1, [x21, #32]                  /* params.x1 */
    ldr x2, [x21, #40]                  /* params.x2 */
    mov x0, #0                          /* boot CPU */
    isb
    eret

/* Reached from anywhere, with nothing assumed about the registers or the stack:
 * both come back from the private CPU record through TPIDR_EL2. */
exit:
    pauth_bank_pointer
    bl pauth_switch_leave
    mrs x9, tpidr_el2
#if SNAP_BOOT_RELOCATE
    /* vCPU 0's relocated CPU shares vcpu 0 with q1n1's CPU but never its
     * stack or its return: it finishes on the stack it was started with.
     * Record page 0 is armed only for a relocation; its affinity says which
     * physical CPU that is. */
    ldr x10, [x9, #40]                  /* vcpu.slot */
    cbnz x10, 1f
    ldr x11, [x9, #32]                  /* vcpu.context */
    movz x12, #(CONTEXT_SECONDARY_BASE & 65535)
    movk x12, #(CONTEXT_SECONDARY_BASE >> 16), lsl #16
    ldr x11, [x11, x12]                 /* record page 0 */
    cbz x11, 1f
    ldr x12, [x11, #BOOT_RELOCATE_ARMED]
    cbz x12, 1f
    mrs x13, mpidr_el1
    mov x14, #0xffffff
    movk x14, #0xff, lsl #32
    and x13, x13, x14
    ldr x12, [x11, #48]                 /* record.affinity */
    cmp x13, x12
    b.ne 1f
    ldr x10, [x11, #40]                 /* record.stack */
    mov sp, x10
    b xnuboot_relocated_stop
1:
#endif
    ldr x10, [x9, #0]                   /* vcpu.el2_sp */
    mov sp, x10
    ldr x10, [x9, #40]                  /* vcpu.slot */
    cbnz x10, xnuboot_secondary_stop    /* never unwind a secondary as q1n1 */
    ldr x19, [x9, #8]                   /* vcpu.out_ptr */
    add x0, x19, #OUT_REPORT
    bl xnuboot_report                   /* restores EL2; x0 is the terminal ownership result */

    /* Preserve nonzero quarantine: the host must not read or reclaim RAM. */
    ldp x27, x28, [sp], #16
    ldp x25, x26, [sp], #16
    ldp x23, x24, [sp], #16
    ldp x21, x22, [sp], #16
    ldp x19, x20, [sp], #16
    ldp x29, x30, [sp], #16
    ret

.balign 2048
.global xnuboot_vectors
xnuboot_vectors:
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
    b async_irq                         /* lower EL, AArch64, IRQ */
.balign 128
    b async_fiq                         /* lower EL, AArch64, FIQ */
.balign 128
    b async_serror                      /* lower EL, AArch64, SError */
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
#if SNAP_SERVICE_SUBCLASS
    mrs x9, cntpct_el0                  /* exception entry synchronized the context */
    str x9, [sp, #(31 * 8)]             /* exit timing start; class 0 in the top byte */
#endif

    pauth_bank_pointer
#if SNAP_PAUTH_EL0_LIVE
    bl pauth_switch_live
#else
    bl pauth_switch_leave
#endif
    cbnz x0,pauth_failed
    mrs x1, esr_el2
    mrs x2, elr_el2
    str x2, [sp, #(32 * 8)]
    mov x0, sp
    add x2, sp, #(32 * 8)               /* &elr, so the handler can step over */
    bl xnuboot_trap
    str x0, [sp, #(33 * 8)]

resume_lower:
    ldr x0,[sp,#(33 * 8)]
    cbnz x0,done
    mov x0,sp
    bl xnuboot_pauth_resume
    cbnz x0,done
    ldr x2, [sp, #(32 * 8)]
    msr elr_el2, x2
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

    ldr x16, [sp, #(33 * 8)]
    cbnz x16, done
    ldp x16, x17, [sp, #(16 * 8)]       /* resume: the guest's own x16/x17 */
    add sp, sp, #FRAME
    eret

done:
    /* No register recovery here: `exit` rebuilds the stack and the out pointer
     * from the context, which is the only state a stock kernel cannot have
     * clobbered. */
    b exit

/* The watchdog, an SError, or anything else asynchronous while the guest runs.
 *
 * All three used to arrive here anonymously and be recorded as the watchdog,
 * which made a bus error from the guest -- a peripheral that does not answer --
 * read as a healthy kernel that merely needed more time. They are opposite
 * findings. The vector carries which one it was in x1 and xnuboot_async()
 * reads ESR_EL2 only on the SError path, where the architecture guarantees it
 * holds this exception's syndrome.
 *
 * The original x0/x1 are saved first, then the common path saves the remaining
 * registers, so a watchdog snapshot belongs to the guest rather than to C. */
async_irq:
    stp x0, x1, [sp, #-FRAME]!
    mov x1, #ASYNC_IRQ
    b async_lower
async_fiq:
    stp x0, x1, [sp, #-FRAME]!
    mov x1, #ASYNC_FIQ
    b async_lower
async_serror:
    stp x0, x1, [sp, #-FRAME]!
    mov x1, #ASYNC_SERROR
    b async_lower

async_lower:
    /* As with sync_lower, SP_EL2 is the private monitor stack. Preserve all
     * guest registers before borrowing any; exit restores the host stack. */
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
    str x1,[sp,#(31 * 8)]             /* vector kind survives the leaf helper */
    pauth_bank_pointer
    bl pauth_switch_leave
    cbnz x0,pauth_failed
    ldr x1,[sp,#(31 * 8)]
    mrs x0, elr_el2
    str x0, [sp, #(32 * 8)]
    mov x2, sp
    bl xnuboot_async
    str x0, [sp, #(33 * 8)]
    b resume_lower

pauth_failed:
    mrs x9,elr_el2
    str x9,[sp,#(32 * 8)]
    mov x0,sp
    bl xnuboot_pauth_failed
    b done

bad:
    /* Any vector but the guest's synchronous one. Nothing is assumed: the stack
     * and the out buffer both come back from the private CPU record through TPIDR_EL2,
     * because this can fire with a frame pushed and registers holding compiler
     * temporaries. */
    mrs x9, tpidr_el2
    ldr x19, [x9, #8]                   /* vcpu.out_ptr */
    mrs x0, esr_el2
    str x0, [x19, #OUT_STATUS]
    /* ESR alone says an EL2 fault happened and what kind. ELR says where in
     * this file, and FAR what address it was reaching for -- the difference
     * between "the monitor faulted" and a line and an address. They go in the
     * private CPU record because this vector cannot call anything;
     * xnuboot_report, which runs next through `exit`, copies them out. */
    mrs x1, elr_el2
    mrs x2, far_el2
    stp x1, x2, [x9, #CTX_BAD_ELR]
    b exit

/* SPDX-License-Identifier: MIT */
/* EL2 memory-bandwidth stub for tools/measure-a16-memory-bandwidth.py (agents/dvfs lever 1: the probe that runs
 * before and after the DDR vote).
 *
 * Entered through P_CALL on q1n1's boot CPU, with q1n1's EL2 MMU and caches on, at offset 0:
 *
 *   a16_bw(report, base, bytes, passes | kernels << 16)
 *
 * base: two buffers of `bytes` each, A = base and B = base + bytes, write-back cacheable at EL2 (the host walks
 * q1n1's tables first). bytes: a power of two, at least 4 KiB. passes: 1..16. kernels: bit 0 READ (A), bit 1
 * WRITE (B), bit 2 COPY (A to B), bit 3 CHASE (a dependent-load cycle over every 64-byte line of A, in the order
 * of a full-period LCG, so no stride is regular; built by the stub, then walked once).
 * Every pass is timed with ISB; CNTPCT_EL0 (CNTVCT_EL0 in the host build); WRITE and COPY end in DSB SY so the
 * time includes draining the stores. General-purpose LDP/STP only (no FP/SIMD state, no CPTR_EL2 trap).
 * Uses x0-x17 only, no stack, no calls, no system-register writes, no MMIO; writes only the report and the two
 * buffers. Interrupts stay unmasked (q1n1's tick services USB): a pass that an interrupt lengthens shows as an
 * outlier, which the host refuses against the median.
 *
 * -DBW_HOST builds the same code as a Mach-O function for this Mac (tools/test-a16-bw.c runs it at EL0). */

#define R_MAGIC     0
#define R_STATUS    8
#define R_EL        16
#define R_CNTFRQ    24
#define R_BYTES     32
#define R_PASSES    40
#define R_KERNELS   48
#define R_SUM       56
#define R_STEPS     64
#define R_END       72
#define R_DONE      80
#define R_READ      128         /* 16 passes x CNTPCT delta */
#define R_WRITE     256
#define R_COPY      384
#define R_CHASE     512         /* build ticks, walk ticks */
#define REPORT      640

#define ST_OK       0
#define ST_NOT_EL2  1
#define ST_BAD_ARGS 3

#ifdef BW_HOST
#define TIMER cntvct_el0
    .text
    .globl _a16_bw
    .p2align 2
_a16_bw:
#else
#define TIMER cntpct_el0
    .text
    .global _start
_start:
#endif
    mov x9, x0                              /* report */
    movz x10, #0x3141                       /* "A16BW001", little-endian */
    movk x10, #0x4236, lsl #16
    movk x10, #0x3057, lsl #32
    movk x10, #0x3130, lsl #48
    str x10, [x9, #R_MAGIC]
    mov x10, #-1
    str x10, [x9, #R_STATUS]
    str xzr, [x9, #R_DONE]
#ifdef BW_HOST
    mov x10, #0
#else
    mrs x10, CurrentEL
    lsr x10, x10, #2
#endif
    str x10, [x9, #R_EL]
    mrs x10, cntfrq_el0
    str x10, [x9, #R_CNTFRQ]
    str x2, [x9, #R_BYTES]
    and x11, x3, #0xffff                    /* passes */
    ubfx x12, x3, #16, #8                   /* kernels */
    str x11, [x9, #R_PASSES]
    str x12, [x9, #R_KERNELS]
#ifndef BW_HOST
    ldr x10, [x9, #R_EL]
    cmp x10, #2
    b.ne .Lnot_el2
#endif
    cbz x11, .Lbad
    cmp x11, #16
    b.hi .Lbad
    cmp x2, #4096
    b.lo .Lbad
    sub x13, x2, #1
    tst x2, x13
    b.ne .Lbad
    cbz x1, .Lbad
    tst x1, #63
    b.ne .Lbad
    mov x15, #0                             /* checksum of the read data */
    add x16, x1, x2                         /* B */

    /* READ: two lines per iteration. */
    tbz x12, #0, .Lread_done
    mov x17, #0
.Lread_pass:
    isb
    mrs x4, TIMER
    mov x5, x1
    add x6, x1, x2
.Lread_loop:
    ldp x7, x8, [x5]
    ldp x7, x8, [x5, #16]
    ldp x7, x8, [x5, #32]
    ldp x7, x8, [x5, #48]
    ldp x7, x8, [x5, #64]
    ldp x7, x8, [x5, #80]
    ldp x7, x8, [x5, #96]
    ldp x7, x8, [x5, #112]
    add x5, x5, #128
    cmp x5, x6
    b.lo .Lread_loop
    eor x15, x15, x7
    eor x15, x15, x8
    isb
    mrs x13, TIMER
    sub x13, x13, x4
    add x14, x9, #R_READ
    str x13, [x14, x17, lsl #3]
    add x17, x17, #1
    cmp x17, x11
    b.lo .Lread_pass
.Lread_done:

    /* WRITE: zeros over B, drained. */
    tbz x12, #1, .Lwrite_done
    mov x17, #0
.Lwrite_pass:
    isb
    mrs x4, TIMER
    mov x5, x16
    add x6, x16, x2
.Lwrite_loop:
    stp xzr, xzr, [x5]
    stp xzr, xzr, [x5, #16]
    stp xzr, xzr, [x5, #32]
    stp xzr, xzr, [x5, #48]
    stp xzr, xzr, [x5, #64]
    stp xzr, xzr, [x5, #80]
    stp xzr, xzr, [x5, #96]
    stp xzr, xzr, [x5, #112]
    add x5, x5, #128
    cmp x5, x6
    b.lo .Lwrite_loop
    dsb sy
    isb
    mrs x13, TIMER
    sub x13, x13, x4
    add x14, x9, #R_WRITE
    str x13, [x14, x17, lsl #3]
    add x17, x17, #1
    cmp x17, x11
    b.lo .Lwrite_pass
.Lwrite_done:

    /* COPY: A to B, drained. */
    tbz x12, #2, .Lcopy_done
    mov x17, #0
.Lcopy_pass:
    isb
    mrs x4, TIMER
    mov x5, x1
    mov x6, x16
    add x10, x1, x2
.Lcopy_loop:
    ldp x7, x8, [x5]
    stp x7, x8, [x6]
    ldp x7, x8, [x5, #16]
    stp x7, x8, [x6, #16]
    ldp x7, x8, [x5, #32]
    stp x7, x8, [x6, #32]
    ldp x7, x8, [x5, #48]
    stp x7, x8, [x6, #48]
    add x5, x5, #64
    add x6, x6, #64
    cmp x5, x10
    b.lo .Lcopy_loop
    dsb sy
    isb
    mrs x13, TIMER
    sub x13, x13, x4
    add x14, x9, #R_COPY
    str x13, [x14, x17, lsl #3]
    add x17, x17, #1
    cmp x17, x11
    b.lo .Lcopy_pass
.Lcopy_done:

    /* CHASE: line k holds the address of line LCG(k); a = 0x5851f42d4c957f2d (= 1 mod 4), c = 0x14057b7ef767814f
     * (odd), modulo the line count (a power of two): one cycle through every line (Hull-Dobell). */
    tbz x12, #3, .Lchase_done
    lsr x3, x2, #6                          /* lines (x3's argument is no longer needed) */
    sub x13, x3, #1                         /* mask */
    movz x7, #0x7f2d
    movk x7, #0x4c95, lsl #16
    movk x7, #0xf42d, lsl #32
    movk x7, #0x5851, lsl #48
    movz x8, #0x814f
    movk x8, #0xf767, lsl #16
    movk x8, #0x7b7e, lsl #32
    movk x8, #0x1405, lsl #48
    isb
    mrs x4, TIMER
    mov x5, #0                              /* index */
    mov x6, x3                              /* lines to link */
.Lchase_build:
    madd x14, x5, x7, x8
    and x14, x14, x13                       /* next */
    add x17, x1, x14, lsl #6                /* &line[next] */
    add x10, x1, x5, lsl #6                 /* &line[index] */
    str x17, [x10]
    mov x5, x14
    subs x6, x6, #1
    b.ne .Lchase_build
    dsb sy
    isb
    mrs x14, TIMER
    sub x14, x14, x4
    str x14, [x9, #R_CHASE]
    isb
    mrs x4, TIMER
    mov x5, x1
    mov x6, x3
.Lchase_walk:
    ldr x5, [x5]
    subs x6, x6, #1
    b.ne .Lchase_walk
    isb
    mrs x14, TIMER
    sub x14, x14, x4
    str x14, [x9, #R_CHASE + 8]
    str x3, [x9, #R_STEPS]
    str x5, [x9, #R_END]                    /* one full cycle returns to A */
.Lchase_done:

    str x15, [x9, #R_SUM]
    mov x0, #ST_OK
    b .Lout
.Lnot_el2:
    mov x0, #ST_NOT_EL2
    b .Lout
.Lbad:
    mov x0, #ST_BAD_ARGS
.Lout:
    str x0, [x9, #R_STATUS]
    mov x10, #1
    str x10, [x9, #R_DONE]
    dsb sy
    ret

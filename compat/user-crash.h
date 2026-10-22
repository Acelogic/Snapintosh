/* SPDX-License-Identifier: MIT */
#ifndef USER_CRASH_H
#define USER_CRASH_H

#include <stdint.h>

/* EL0 crash evidence, taken where the monitor already sees every lower-EL
 * AArch64 synchronous exception: at XNU's vector entry, before XNU acts.
 *
 * A process that crashes leaves nothing behind once launchd has reaped it:
 * the kernel message buffer is circular, the corpse is released as soon as
 * ReportCrash has read it, and the crash report sits in guest files. What
 * can be kept cheaply is the one instruction that decided the death:
 *
 *   - abort() is pthread_kill(self, SIGABRT): SVC #0x80, x16 = 328;
 *   - kill(pid, sig) with a core-dumping signal: x16 = 37;
 *   - abort_with_payload (521), terminate_with_payload (520) and the
 *     non-fatal os_fault_with_payload (529), which carry a reason string;
 *   - the exception classes XNU turns into the task's own signal: BRK64,
 *     unknown, illegal state, FPAC, PC and SP alignment;
 *   - an EL0 abort at an address no 64-bit process maps (the 4 GiB page
 *     zero, or at/above 2^47 such as a pointer with PAC error bits).
 *
 * Syscall numbers and argument registers are from 26A428
 * libsystem_kernel: ___pthread_kill mov x16,#0x148; ___kill #0x25;
 * ___terminate_with_payload #0x208; ___abort_with_payload #0x209;
 * _os_fault_with_payload #0x211. The core-dumping signals are XNU's SA_CORE
 * set. Recording is diagnostic only; it never changes delivery.
 *
 * Header-only and freestanding: no libc, no struct copies (no memcpy). */

enum user_crash_kind {
    USER_CRASH_NONE = 0,
    USER_CRASH_SELF_SIGNAL = 1,     /* __pthread_kill(thread, core signal) */
    USER_CRASH_KILL = 2,            /* kill(pid, core signal) */
    USER_CRASH_ABORT_PAYLOAD = 3,
    USER_CRASH_TERMINATE_PAYLOAD = 4,
    USER_CRASH_OS_FAULT = 5,        /* simulated crash: a report, not a death */
    USER_CRASH_EXCEPTION = 6,       /* fatal EL0 exception class */
    USER_CRASH_WILD_ABORT = 7,      /* EL0 abort outside [4 GiB, 2^47) */
    USER_CRASH_TRAP = 8,            /* SNAP_USER_CRASH_WIDE: an EL0 trap class below */
};

/* SNAP_USER_CRASH_WIDE: the EL0 synchronous classes the list in
 * user_crash_classify misses, each of which 26A428's sleh_synchronous
 * (jump table at sleh_synchronous+3424, kernel.release.t8140) turns into a
 * signal or a panic and none of which this monitor answers for EL0:
 *   0x01 WFI/WFE      handle_wf_trap: EXC_BAD_INSTRUCTION (SIGILL)
 *   0x07 SIMD/FP      handle_simd_trap: EXC_BAD_INSTRUCTION (SIGILL)
 *   0x18 MSR/MRS/SYS  handle_msr_trap (inlined): EXC_BAD_INSTRUCTION (SIGILL)
 *   0x09 PAC trap, 0x19 SVE: handle_uncategorized, as EC 0 (SIGILL)
 *   0x0d BTI          handle_bti_fail: panic, also for EL0
 *   0x1d SME          lazy SME state, else EXC_BAD_INSTRUCTION (SIGILL)
 *   0x2c FP exception handle_fp_trap: EXC_ARITHMETIC (SIGFPE)
 * launchd's four recorded deaths were 0x01 and left no row. The same build
 * also keeps the faulting instruction word of every exception-class row
 * (kinds 6 and 8) in text[0] (meta words 1 and the word's byte offset), read
 * like the frame records; an unreadable word leaves no text. */
#if defined(SNAP_USER_CRASH_WIDE) && SNAP_USER_CRASH_WIDE
#define USER_CRASH_WIDE 1
#else
#define USER_CRASH_WIDE 0
#endif
static inline int user_crash_wide_class(unsigned ec)
{
    return ec == 0x01 || ec == 0x07 || ec == 0x09 || ec == 0x0d || ec == 0x18 ||
           ec == 0x19 || ec == 0x1d || ec == 0x2c;
}

#define USER_CRASH_ROWS 8
#define USER_CRASH_FRAMES 4
#define USER_CRASH_TEXT_WORDS 8
#define USER_CRASH_STACK_SPAN (UINT64_C(8) << 20)

#define USER_SYS_KILL 37
#define USER_SYS_PTHREAD_KILL 328
#define USER_SYS_TERMINATE_PAYLOAD 520
#define USER_SYS_ABORT_PAYLOAD 521
#define USER_SYS_OS_FAULT_PAYLOAD 529

/* meta: kind [7:0], cpu [15:8], ec [21:16], frames [26:24],
 * text words [31:28], reason-string byte offset in text[0] [34:32]. */
struct user_crash_record {
    uint64_t seq, guest_count, raw_count, meta;
    uint64_t esr, elr, far, x0, x1, x2, x16, fp, lr, sp;
    uint64_t ttbr0, tpidr_el1, tpidrro_el0;
    uint64_t frames[USER_CRASH_FRAMES];
    uint64_t text[USER_CRASH_TEXT_WORDS];
};

struct user_crash_ring {
    uint64_t recorded, walk_reads, walk_refusals, text_refusals;
    struct user_crash_record rows[USER_CRASH_ROWS];
};

_Static_assert(sizeof(struct user_crash_record) == 29 * 8, "crash record ABI");
_Static_assert(sizeof(struct user_crash_ring) == 4 * 8 + USER_CRASH_ROWS * 29 * 8,
               "crash ring ABI");

/* Reads one aligned guest user word at va through the current user root.
 * Returns 1 only for ordinary RAM; never touches device memory. */
typedef int (*user_crash_reader)(void *ctx, uint64_t va, uint64_t *out);

static inline int user_crash_core_signal(uint64_t sig)
{
    /* SIGQUIT SIGILL SIGTRAP SIGABRT SIGEMT SIGFPE SIGBUS SIGSEGV SIGSYS */
    return (sig >= 3 && sig <= 8) || (sig >= 10 && sig <= 12);
}

static inline unsigned user_crash_classify(uint64_t esr, uint64_t far,
                                           uint64_t x16, uint64_t x1)
{
    unsigned ec = (unsigned)(esr >> 26) & 63;
    if (ec == 0x15) {
        if ((esr & 0xffff) != 0x80) return USER_CRASH_NONE;
        switch (x16) {
        case USER_SYS_PTHREAD_KILL:
            return user_crash_core_signal(x1) ? USER_CRASH_SELF_SIGNAL : USER_CRASH_NONE;
        case USER_SYS_KILL:
            return user_crash_core_signal(x1) ? USER_CRASH_KILL : USER_CRASH_NONE;
        case USER_SYS_ABORT_PAYLOAD: return USER_CRASH_ABORT_PAYLOAD;
        case USER_SYS_TERMINATE_PAYLOAD: return USER_CRASH_TERMINATE_PAYLOAD;
        case USER_SYS_OS_FAULT_PAYLOAD: return USER_CRASH_OS_FAULT;
        default: return USER_CRASH_NONE;
        }
    }
    if (ec == 0x3c || ec == 0x00 || ec == 0x0e || ec == 0x1c || ec == 0x22 || ec == 0x26)
        return USER_CRASH_EXCEPTION;
    if (USER_CRASH_WIDE && user_crash_wide_class(ec))
        return USER_CRASH_TRAP;
    if (ec == 0x20 || ec == 0x24) {
        uint64_t address = far & ((UINT64_C(1) << 56) - 1);  /* TBI0 tag byte */
        if (address < (UINT64_C(1) << 32) || address >= (UINT64_C(1) << 47))
            return USER_CRASH_WILD_ABORT;
    }
    return USER_CRASH_NONE;
}

/* The user string argument of a payload call, or zero. */
static inline uint64_t user_crash_reason(unsigned kind, const uint64_t *x)
{
    if (kind == USER_CRASH_ABORT_PAYLOAD || kind == USER_CRASH_OS_FAULT) return x[4];
    if (kind == USER_CRASH_TERMINATE_PAYLOAD) return x[5];
    return 0;
}

/* x: the trapped EL0 registers x0..x30. Every field is written one by one. */
static inline void user_crash_record(struct user_crash_ring *ring, unsigned kind,
    unsigned cpu, uint64_t guest_count, uint64_t raw_count, uint64_t esr,
    uint64_t elr, uint64_t far, const uint64_t *x, uint64_t sp, uint64_t ttbr0,
    uint64_t tpidr_el1, uint64_t tpidrro_el0, user_crash_reader read, void *ctx)
{
    uint64_t seq = ++ring->recorded;
    struct user_crash_record *r = &ring->rows[(seq - 1) % USER_CRASH_ROWS];
    unsigned frames = 0, words = 0, i;
    uint64_t fp = x[29], low = sp, reason = user_crash_reason(kind, x);

    r->seq = 0;                     /* incomplete until the last store */
    r->guest_count = guest_count; r->raw_count = raw_count;
    r->esr = esr; r->elr = elr; r->far = far;
    r->x0 = x[0]; r->x1 = x[1]; r->x2 = x[2]; r->x16 = x[16];
    r->fp = x[29]; r->lr = x[30]; r->sp = sp;
    r->ttbr0 = ttbr0; r->tpidr_el1 = tpidr_el1; r->tpidrro_el0 = tpidrro_el0;
    for (i = 0; i < USER_CRASH_FRAMES; i++) r->frames[i] = 0;
    for (i = 0; i < USER_CRASH_TEXT_WORDS; i++) r->text[i] = 0;

    /* Frame records live on the trapping thread's own stack: 16-byte
     * aligned, above SP, strictly increasing, within one stack span. */
    while (read && frames < USER_CRASH_FRAMES && fp && !(fp & 15) && fp >= low &&
           fp - sp < USER_CRASH_STACK_SPAN && fp < (UINT64_C(1) << 47)) {
        uint64_t next, lr;
        if (!read(ctx, fp, &next) || !read(ctx, fp + 8, &lr)) {
            ring->walk_refusals++;
            break;
        }
        ring->walk_reads += 2;
        r->frames[frames++] = lr;
        if (next <= fp) break;
        low = fp + 16;
        fp = next;
    }
    /* The reason string, as aligned words up to and including its NUL. */
    if (read && reason && reason < (UINT64_C(1) << 47)) {
        uint64_t va = reason & ~UINT64_C(7);
        while (words < USER_CRASH_TEXT_WORDS) {
            uint64_t word;
            unsigned b, end = 0;
            if (!read(ctx, va + 8 * words, &word)) {
                ring->text_refusals++;
                break;
            }
            r->text[words++] = word;
            for (b = words == 1 ? (unsigned)(reason & 7) : 0; b < 8; b++)
                if (!((word >> (8 * b)) & 0xff)) { end = 1; break; }
            if (end) break;
        }
    }
    uint64_t text_offset = reason & 7;
#if USER_CRASH_WIDE
    /* The faulting instruction of an exception-class row (no reason string
     * shares text[]): the aligned word holding ELR, offset 0 or 4. */
    if (read && !reason && (kind == USER_CRASH_EXCEPTION || kind == USER_CRASH_TRAP) &&
        !(elr & 3) && elr < (UINT64_C(1) << 47)) {
        uint64_t word;
        if (read(ctx, elr & ~UINT64_C(7), &word)) {
            r->text[0] = word;
            words = 1;
            text_offset = elr & 7;
        } else {
            ring->text_refusals++;
        }
    }
#endif
    r->meta = (uint64_t)(kind & 0xff) | (uint64_t)(cpu & 0xff) << 8 |
              (uint64_t)((esr >> 26) & 63) << 16 | (uint64_t)frames << 24 |
              (uint64_t)words << 28 | text_offset << 32;
    r->seq = seq;
}

#endif

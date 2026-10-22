/* SPDX-License-Identifier: MIT */
/* Run a guest with 16K page tables on hardware that has no 16K granule.
 *
 * The guest writes TTBR0_EL1, TCR_EL1, MAIR_EL1 and SCTLR_EL1 as it normally
 * would. HCR_EL2.TVM traps every one of those, so none of them reach the MMU.
 * EL2 records what the guest asked for, and when the guest enables its MMU we
 * walk its 16K tables in software, emit an equivalent 4K translation, and
 * program the hardware with that instead. TRVM sends reads back through us too,
 * so the guest reads back its own 16K values and never sees the substitution.
 *
 * If the guest then loads through one of its own virtual addresses and gets the
 * right data, the illusion is complete: XNU's page size, running on silicon
 * that cannot walk it.
 *
 * Paired with probes/shadowmmu.S, which holds the entry stub, the EL2 vectors
 * and the guest itself.
 */
#include "shadow.h"

/* Laid out at the base of the caller's work area. The guest's tables, the
 * shadow's tables and this context all live there, so the probe needs no
 * writable sections of its own. */
struct context {
    /* Offsets 0 and 8, relied on by the fault vector in shadowmmu.S: an EL2
     * fault has to recover a usable stack and the out buffer before it can
     * report anything, and it cannot assume any register survived. */
    uint64_t el2_sp;
    uint64_t out_ptr;
    uint64_t guest_ttbr0, guest_tcr, guest_mair, guest_sctlr;
    uint64_t shadow_root, next_table, work_base, work_end;
    uint64_t traps, builds, leaves;
    /* The upper half. XNU lives at 0xfffffe00_......, so nothing of it can be
     * entered until TTBR1 is shadowed too. */
    uint64_t guest_ttbr1, shadow_root1, leaves1, par_test1;
    uint64_t kernel_result, kernel_expect;
    uint64_t fault_esr, fault_far;
    uint64_t par_code, par_test;
    uint64_t stage, progress, stage2_root;
    /* The monitor-call stub: a page EL2 made non-executable at stage 2 so the
     * guest's call into it arrives here instead of running. */
    uint64_t stub_pa, stub_calls, stub_result, stub_arg;
    /* The rest of that page. Real call stubs share their pages with ordinary
     * kernel code, so anything that is not a call site has to be allowed to
     * execute: unprotect, step one instruction, protect again. */
    uint64_t stub_l3, steps, aborts, neighbour_result;
    uint64_t save_mdcr, save_mdscr, step_d;
    uint64_t dbg_oslsr, dbg_mdcr, dbg_mdscr;
};

#define SCTLR_M 1UL
#define TEST_VA 0x10000000UL      /* index 8 of the guest 16K level-2 table */
/* The upper half, at the address family XNU actually uses. With T1SZ 23 the
 * regime covers 2^41 bytes ending at the top of the address space, so
 * 0xfffffe00_00000000 is offset 0 in it -- which is also where the kernelcache
 * is linked. */
#define KERNEL_TXSZ 23
#define KERNEL_VA   0xfffffe0010000000UL

/* What EL2 adds to the guest's argument when it answers a stub call. Arbitrary,
 * but it has to be something the stub itself cannot produce: `guest_stub`
 * returns zero, so a run where the page was executed instead of trapped reports
 * the wrong answer rather than passing by accident. */
#define STUB_REPLY 0x504d0000UL
extern char guest_stub[];
/* Ordinary code sharing the stub's page: it must run, not be emulated. */
extern char guest_neighbour[];

/* EL2 here runs with a flat view of physical memory, which is what lets the
 * walker dereference guest tables directly. */
static int mem_read(void *ctx, uint64_t pa, uint64_t *out)
{
    (void)ctx;
    *out = *(volatile uint64_t *)pa;
    return 0;
}

static int mem_write(void *ctx, uint64_t pa, uint64_t value)
{
    (void)ctx;
    *(volatile uint64_t *)pa = value;
    return 0;
}

/* The context pointer lives in TPIDR_EL2, not a static: this blob has no
 * writable sections (see probe.ld), and EL2's scratch register is exactly what
 * that hole is for. The entry stub saves and restores it. */
static struct context *context_of(void)
{
    uint64_t p;
    __asm__ volatile("mrs %0, tpidr_el2" : "=r"(p));
    return (struct context *)p;
}

static uint64_t table_alloc(void *ctx)
{
    struct context *c = ctx;
    if (c->next_table + 0x1000 > c->work_end) return 0;
    uint64_t table = c->next_table;
    c->next_table += 0x1000;
    for (unsigned n = 0; n < 0x1000 / 8; n++) *(volatile uint64_t *)(table + 8UL * n) = 0;
    return table;
}

/* TCR_EL1 for the shadow: the guest's, with each granule forced to 4K. T0SZ and
 * T1SZ are carried across unchanged, so the shadow covers exactly the VA widths
 * the guest asked for.
 *
 * TG1 is not TG0. The field at [31:30] encodes 0b01 = 16K, 0b10 = 4K, 0b11 =
 * 64K, while TG0 at [15:14] encodes 0b00 = 4K, 0b01 = 64K, 0b10 = 16K. Reading
 * both with one table gives a shadow that is correct in one half and silently
 * wrong in the other, which is the hardest kind of wrong to find. */
static uint64_t shadow_tcr(uint64_t guest_tcr, int upper)
{
    uint64_t tcr = guest_tcr & ~(3UL << 14);        /* TG0 = 0b00, 4K */
    if (upper) {
        tcr = (tcr & ~(3UL << 30)) | (2UL << 30);   /* TG1 = 0b10, also 4K */
        tcr &= ~(1UL << 23);                        /* EPD1 clear: walk TTBR1 */
    } else {
        tcr |= 1UL << 23;                           /* nothing up there to walk */
    }
    return tcr;
}

/* Make table writes visible to the hardware table walker.
 *
 * The walker is a separate observer from the core's stores. Whether EL2 here
 * runs with its MMU off (stores go straight to memory) or on (stores are
 * cacheable), the tables have to be cleaned to the point of coherency and the
 * write ordered before the walker is pointed at them -- otherwise the walker
 * reads whatever was in memory before, which presents as a translation fault on
 * an entry software can plainly see is valid. */
static void publish_tables(uint64_t start, uint64_t end)
{
    for (uint64_t line = start & ~63UL; line < end; line += 64)
        __asm__ volatile("dc civac, %0" :: "r"(line) : "memory");
    __asm__ volatile("dsb ish" ::: "memory");
}

/* Ask the hardware walker whether it can resolve `va` in the EL1 regime we just
 * programmed. PAR_EL1 bit 0 set means it faulted. This is the same instruction
 * probes/tgran16.c uses, and it is what turns "the guest vanished" into a
 * reportable answer. */
static uint64_t probe_translation(uint64_t va)
{
    uint64_t par;
    __asm__ volatile("at s1e1r, %0" :: "r"(va));
    __asm__ volatile("isb");
    __asm__ volatile("mrs %0, par_el1" : "=r"(par));
    return par;
}

/* Build the shadow and put it behind the guest's MMU enable. */
#define STOP(n) do { if (c->stage == 30u + (n)) { c->progress = (n); return 0; } } while (0)

/* One translation regime: walk the guest's 16K tables and emit 4K ones.
 *
 * Both halves are built the same way because the walker works in offsets within
 * a regime rather than in whole virtual addresses -- TTBR1's top bits are the
 * caller's business, and picking the root is exactly that choice. */
static int build_regime(struct context *c, uint64_t ttbr, uint32_t txsz,
                        uint64_t *root_out, uint64_t *leaves_out)
{
    struct mmu_config guest = {.granule_shift = 14, .txsz = txsz, .root = ttbr};
    struct shadow shadow = {.txsz = txsz, .alloc = table_alloc, .read = mem_read,
                            .write = mem_write, .ctx = c};
    shadow.root = table_alloc(c);
    if (!shadow.root) return -1;

    long leaves = shadow_build(&shadow, &guest, 0, 1UL << (64 - txsz), mem_read, c);
    if (leaves < 0) return -1;

    *root_out = shadow.root;
    *leaves_out = (uint64_t)leaves;
    return 0;
}

static int install(struct context *c, uint64_t guest_pc)
{
    c->progress = 0;
    STOP(0);
    uint32_t t0sz = (uint32_t)(c->guest_tcr & 0x3f);
    uint32_t t1sz = (uint32_t)((c->guest_tcr >> 16) & 0x3f);

    if (build_regime(c, c->guest_ttbr0, t0sz, &c->shadow_root, &c->leaves)) return -1;
    STOP(1);
    if (c->guest_ttbr1 &&
        build_regime(c, c->guest_ttbr1, t1sz, &c->shadow_root1, &c->leaves1))
        return -1;

    STOP(2);
    c->builds++;

    /* Everything handed out by table_alloc, guest tables included: all of it is
     * about to be walked by hardware. */
    publish_tables(c->work_base, c->next_table);
    STOP(3);

    /* The guest's ASID travels with its TTBR; the shadow reuses it so the
     * guest's own TLB maintenance keeps meaning what it meant. */
    uint64_t asid = c->guest_ttbr0 & 0xffff000000000000UL;
    __asm__ volatile("msr mair_el1, %0" :: "r"(c->guest_mair));
    __asm__ volatile("msr tcr_el1, %0"
                     :: "r"(shadow_tcr(c->guest_tcr, c->guest_ttbr1 != 0)));
    STOP(4);
    __asm__ volatile("msr ttbr0_el1, %0" :: "r"(c->shadow_root | asid));
    if (c->guest_ttbr1)
        __asm__ volatile("msr ttbr1_el1, %0" :: "r"(c->shadow_root1));
    /* Nothing may survive from whatever used this translation regime before.
     * Earlier probes on this machine enabled SCTLR_EL1.M with their own tables,
     * so stale EL1 entries are not hypothetical here. */
    __asm__ volatile("dsb ish; tlbi vmalle1is; dsb ish; isb");

    /* Translation has to be ON for AT S1E1R to walk anything: with SCTLR_EL1.M
     * clear the instruction reports PA == VA and never faults, which is a check
     * that always passes and means nothing. So enable first, then ask. */
    STOP(5);
    __asm__ volatile("msr sctlr_el1, %0" :: "r"(c->guest_sctlr));
    __asm__ volatile("isb");
    STOP(6);

    /* Enabling the MMU into a shadow that does not map the guest's PC is an
     * unrecoverable hang with nothing left to report it. Check, and back out
     * while backing out is still possible. */
    c->par_code = probe_translation(guest_pc);
    c->par_test = probe_translation(TEST_VA);
    if (c->guest_ttbr1) c->par_test1 = probe_translation(KERNEL_VA);
    if (c->par_code & 1) {
        __asm__ volatile("msr sctlr_el1, xzr; isb");
        return -2;
    }
    return 0;
}

/* Stage-2 execute-never. Bit 54 alone, not the XN[1:0] pair: with FEAT_XNX the
 * field is [54:53] and 0b10 means "not executable at EL1 or EL0"; without it
 * bit 54 is the whole field and bit 53 is RES0. Writing only bit 54 is correct
 * either way, so nothing has to read ID_AA64MMFR1_EL1.XNX to be right. */
#define S2_XN (1UL << 54)

/* Flip execute permission on the one protected page. The descriptor is reached
 * directly rather than re-walked: EL2 built this table and kept the address. */
static void stub_page_exec(struct context *c, int allow)
{
    volatile uint64_t *slot =
        (volatile uint64_t *)(c->stub_l3 + 8UL * ((c->stub_pa >> 12) & 0x1ff));
    if (allow) *slot &= ~S2_XN;
    else       *slot |= S2_XN;
    __asm__ volatile("dc civac, %0" :: "r"((uint64_t)slot) : "memory");
    __asm__ volatile("dsb ish; tlbi vmalls12e1is; dsb ish; isb");
}

/* Software step, driven from EL2.
 *
 * MDCR_EL2.TDE (set once, when the page is first protected) routes the guest's
 * debug exceptions here instead of to its own vectors. MDSCR_EL1.SS and
 * SPSR_EL2.SS together mean "execute one instruction, then except". PSTATE.D
 * masks debug exceptions and this guest runs with all of DAIF set, so D is
 * cleared for the duration and put back exactly as it was. */
static void step_arm(struct context *c, int on)
{
    uint64_t mdscr, spsr;
    __asm__ volatile("mrs %0, mdscr_el1" : "=r"(mdscr));
    __asm__ volatile("mrs %0, spsr_el2" : "=r"(spsr));
    if (on) {
        c->step_d = (spsr >> 9) & 1;
        mdscr |= 1UL;
        spsr = (spsr | (1UL << 21)) & ~(1UL << 9);
    } else {
        mdscr &= ~1UL;
        spsr = (spsr & ~(1UL << 21)) | (c->step_d << 9);
    }
    __asm__ volatile("msr mdscr_el1, %0" :: "r"(mdscr));
    __asm__ volatile("msr spsr_el2, %0" :: "r"(spsr));
    __asm__ volatile("isb");
    if (on) __asm__ volatile("mrs %0, mdscr_el1" : "=r"(c->dbg_mdscr));
}

/* ISS layout for a trapped MSR/MRS: Op0[21:20] Op2[19:17] Op1[16:14]
 * CRn[13:10] Rt[9:5] CRm[4:1] Direction[0]. */
#define SYSREG(op0, op1, crn, crm, op2) \
    (((op0) << 20) | ((op2) << 17) | ((op1) << 14) | ((crn) << 10) | ((crm) << 1))
#define ISS_REG(iss) ((iss) & ~((0x1fUL << 5) | 1UL))
#define ISS_RT(iss)  (((iss) >> 5) & 0x1f)
#define ISS_READ(iss) ((iss) & 1)

#define SR_SCTLR_EL1 SYSREG(3, 0, 1, 0, 0)
#define SR_TTBR0_EL1 SYSREG(3, 0, 2, 0, 0)
#define SR_TTBR1_EL1 SYSREG(3, 0, 2, 0, 1)
#define SR_TCR_EL1   SYSREG(3, 0, 2, 0, 2)
#define SR_MAIR_EL1  SYSREG(3, 0, 10, 2, 0)
#define SR_MMFR0_EL1 SYSREG(3, 0, 0, 7, 0)

/* Returns 1 when the guest is finished, 0 to resume it, negative on a trap we
 * do not understand -- which is recorded rather than guessed at. */
int shadowmmu_trap(uint64_t *frame, uint64_t esr, uint64_t *elr);
int shadowmmu_trap(uint64_t *frame, uint64_t esr, uint64_t *elr)
{
    struct context *c = context_of();
    uint64_t ec = esr >> 26, iss = esr & 0x1ffffff;

    if (ec == 0x16) {
        /* imm 1 is the guest's own vectors reporting a fault it took at EL1 --
         * a shadow that does not map what the guest expects shows up here. */
        if ((iss & 0xffff) == 1) {
            __asm__ volatile("mrs %0, esr_el1" : "=r"(c->fault_esr));
            __asm__ volatile("mrs %0, far_el1" : "=r"(c->fault_far));
        }
        c->stub_result = frame[12];
        c->neighbour_result = frame[14];
        c->kernel_result = frame[9];
        return 1;
    }

    /* Instruction abort from EL1. With the stub page marked execute-never at
     * stage 2, the guest's `bl` into it never runs an instruction: the fetch
     * itself arrives here, with x30 already holding the return address. EL2
     * answers in the guest's registers and returns past the call.
     *
     * This is the shape XNU's monitor calls have to be caught in. Its `genter`
     * stubs are an undefined encoding on this silicon, and an undefined
     * instruction at EL1 is delivered to EL1 -- there is no HCR bit that routes
     * it to EL2. A stage-2 execute permission fault is the one mechanism that
     * does, and because every call site in the kernelcache lives in a handful of
     * pages, it costs nothing anywhere else. */
    if (ec == 0x20) {
        if (c->stub_pa && *elr == c->stub_pa) {
            c->stub_calls++;
            c->stub_arg = frame[0];
            frame[0] = frame[0] + STUB_REPLY;
            *elr = frame[30];                       /* what the stub's ret would do */
            return 0;
        }
        /* Some other address in the protected page. In the kernelcache this is
         * ordinary code that happens to share a page with the call stubs, and it
         * has to run. Lift the protection for exactly one instruction. */
        if (c->stub_pa && (*elr & ~0xfffUL) == c->stub_pa) {
            c->aborts++;
            stub_page_exec(c, 1);
            step_arm(c, 1);
            return 0;
        }
        c->fault_esr = esr;
        __asm__ volatile("mrs %0, far_el2" : "=r"(c->fault_far));
        return -1;
    }

    /* The instruction we unprotected the page for has retired. */
    if (ec == 0x32) {
        c->steps++;
        step_arm(c, 0);
        stub_page_exec(c, 0);
        return 0;
    }

    if (ec != 0x18) {                               /* not a sysreg trap */
        c->fault_esr = esr;
        __asm__ volatile("mrs %0, far_el2" : "=r"(c->fault_far));
        return -1;
    }

    c->traps++;
    uint64_t reg = ISS_REG(iss), rt = ISS_RT(iss);
    uint64_t value = (rt == 31) ? 0 : frame[rt];
    int is_read = ISS_READ(iss);

    switch (reg) {
    case SR_TTBR0_EL1:
        if (is_read) value = c->guest_ttbr0; else c->guest_ttbr0 = value;
        break;
    case SR_TTBR1_EL1:
        if (is_read) value = c->guest_ttbr1; else c->guest_ttbr1 = value;
        break;
    case SR_TCR_EL1:
        if (is_read) value = c->guest_tcr; else c->guest_tcr = value;
        break;
    case SR_MAIR_EL1:
        if (is_read) value = c->guest_mair; else c->guest_mair = value;
        break;
    case SR_SCTLR_EL1:
        if (is_read) {
            value = c->guest_sctlr;
        } else {
            uint64_t was = c->guest_sctlr;
            c->guest_sctlr = value;
            /* The moment the guest turns translation on is the moment its
             * tables have to exist in a form the hardware can walk. */
            /* Stage 21: leave the guest straight from an MSR trap, touching
             * nothing. Isolates the exit path itself from anything install()
             * does, since the HVC exit is the only one proven so far. */
            if (c->stage == 21) return 1;
            if ((value & SCTLR_M) && !(was & SCTLR_M)) {
                /* Stage 22 takes this branch but calls nothing, which separates
                 * "entering the branch hangs" from "install() hangs" -- the two
                 * the stop points could not tell apart. */
                if (c->stage == 22) return 1;
                uint64_t pc;
                __asm__ volatile("mrs %0, elr_el2" : "=r"(pc));
                /* install() performs the enable itself, so the translation it
                 * checks is the one the guest will actually run under. */
                if (install(c, pc)) return -1;
                /* Stage 3 stops here: the shadow is installed and the hardware
                 * has confirmed it, but we never return to the guest. That
                 * separates "install fails inside the handler" from "the return
                 * into a translating guest fails". */
                if (c->stage == 3) return 1;
            } else {
                __asm__ volatile("msr sctlr_el1, %0" :: "r"(value));
                __asm__ volatile("isb");
            }
        }
        break;
    case SR_MMFR0_EL1: {
        /* The same forgery probes/tid3.S proves on its own: claim 16K so the
         * guest is willing to ask for it. */
        uint64_t real;
        __asm__ volatile("mrs %0, id_aa64mmfr0_el1" : "=r"(real));
        value = (real & ~((0xfUL << 20) | (0xfUL << 32))) | (2UL << 20) | (2UL << 32);
        break;
    }
    default:
        if (is_read) {
            value = 0;
        } else {
            c->fault_esr = esr;
            return -1;
        }
        break;
    }

    if (is_read && rt != 31) frame[rt] = value;
    *elr += 4;
    return 0;
}

void shadowmmu_setup(uint64_t work, uint64_t size, uint64_t stage, uint64_t out);
void shadowmmu_setup(uint64_t work, uint64_t size, uint64_t stage, uint64_t out)
{
    __asm__ volatile("msr tpidr_el2, %0" :: "r"(work));
    struct context *c = (struct context *)work;
    for (unsigned n = 0; n < sizeof(*c) / 8; n++) ((uint64_t *)c)[n] = 0;
    /* Tables start after the context, 16K aligned so the guest's root is legal
     * for a 16K regime as well as the shadow's 4K ones. */
    c->next_table = (work + sizeof(*c) + 0x3fff) & ~0x3fffUL;
    c->work_base = c->next_table;
    c->work_end = work + size;
    c->stage = stage;
    c->out_ptr = out;
}

uint64_t shadowmmu_report(uint64_t *out);
uint64_t shadowmmu_report(uint64_t *out)
{
    struct context *c = context_of();
    out[0] = c->guest_ttbr0;
    out[1] = c->guest_tcr;
    out[2] = c->shadow_root;
    out[3] = c->traps;
    out[4] = c->builds;
    out[5] = c->leaves;
    out[6] = c->par_code;
    out[7] = c->par_test;
    /* progress rides in the high half of `leaves`, which is small, rather
     * than displacing the trap count the way an earlier version did. */
    out[5] = c->leaves | (c->progress << 32);
    /* A fault the guest took at EL1 lands in out[4]'s high half; `builds`
     * is a small count and leaves room. */
    out[4] = c->builds | ((c->fault_esr & 0xffffffffUL) << 32);
    /* Past the fault slots the entry stub owns (out[6]..out[13] here), so the
     * stub report can grow without moving anything the runner already reads. */
    out[14] = c->stub_pa;
    out[15] = c->stub_calls;
    out[16] = c->stub_result;
    out[17] = c->stub_arg;
    out[18] = c->aborts | (c->steps << 32);
    out[19] = c->neighbour_result;
    out[20] = c->dbg_oslsr;
    out[21] = c->dbg_mdcr;
    out[22] = c->dbg_mdscr;
    out[23] = c->shadow_root1;
    out[24] = c->leaves1;
    out[25] = c->par_test1;
    out[26] = c->kernel_result;
    out[27] = c->kernel_expect;
    if (c->stub_pa) {
        __asm__ volatile("msr mdcr_el2, %0" :: "r"(c->save_mdcr));
        __asm__ volatile("msr mdscr_el1, %0" :: "r"(c->save_mdscr));
        /* Put the OS Lock back if this probe was the one that opened it. */
        if (c->dbg_oslsr & (1UL << 1)) {
            uint64_t one = 1;
            __asm__ volatile("msr oslar_el1, %0" :: "r"(one));
        }
        __asm__ volatile("isb");
    }
    return c->next_table;
}

/* --- the guest's own 16K tables, built before it runs ---
 *
 * A real guest builds these itself; here EL2 lays them out so the probe stays
 * small. What matters is that they are genuine 16K-granule tables that the
 * hardware cannot walk, so the load the guest performs can only succeed through
 * the shadow. */

#define GUEST_TXSZ   28
/* AP = 0b00: read/write at EL1, no EL0 access, and PXN/UXN left clear so the
 * guest can execute from it. AP[1] was set here originally, which marks the
 * region EL0-accessible -- wrong for what is effectively a kernel identity map,
 * and a way to lose EL1 execute permission. AT S1E1R checks read, not execute,
 * so install()'s check passed and the guest still died on its next fetch. */
#define GUEST_LEAF   (PT_VALID | PT_AF | (3UL << 8))
#define GUEST_PAGE   (GUEST_LEAF | PT_TABLE)
#define TEST_MAGIC   0x5EED5EED5EED5EEDUL
#define KERNEL_MAGIC 0xC0FFEEC0FFEEC0FFUL

static uint64_t guest_table(struct context *c)
{
    c->next_table = (c->next_table + 0x3fff) & ~0x3fffUL;   /* 16K tables */
    if (c->next_table + 0x4000 > c->work_end) return 0;
    uint64_t table = c->next_table;
    c->next_table += 0x4000;
    for (unsigned n = 0; n < 0x4000 / 8; n++) *(volatile uint64_t *)(table + 8UL * n) = 0;
    return table;
}

uint64_t shadowmmu_prepare(uint64_t code, uint64_t *out);
uint64_t shadowmmu_prepare(uint64_t code, uint64_t *out)
{
    struct context *c = context_of();
    uint64_t root = guest_table(c);
    if (!root) return 0;

    /* Identity-map the 1GB containing the blob and the work area with 32M
     * blocks. Without this the guest's PC stops translating the instant it
     * enables its MMU, and the failure looks like a shadow bug rather than a
     * missing mapping. */
    uint64_t region = code & ~((1UL << 30) - 1);
    for (unsigned n = 0; n < (1U << 30) / (32U << 20); n++) {
        uint64_t va = region + (uint64_t)n * (32UL << 20);
        *(volatile uint64_t *)(root + 8UL * mmu_index(14, 2, va)) = va | GUEST_LEAF;
    }

    /* The mapping under test: a 16K page at a VA that is nowhere near the
     * identity region, so resolving it proves the shadow and not luck. */
    uint64_t l3 = guest_table(c);
    uint64_t data = guest_table(c);
    if (!l3 || !data) return 0;
    *(volatile uint64_t *)data = TEST_MAGIC;
    *(volatile uint64_t *)(root + 8UL * mmu_index(14, 2, TEST_VA)) = l3 | PT_VALID | PT_TABLE;
    *(volatile uint64_t *)(l3 + 8UL * mmu_index(14, 3, TEST_VA)) = data | GUEST_PAGE;

    out[0] = root;
    /* T0SZ 28, IRGN/ORGN write-back, inner shareable, TG0 = 0b10 (16K). */
    uint64_t tcr = GUEST_TXSZ | (1UL << 8) | (1UL << 10) | (3UL << 12) | (2UL << 14);
    out[2] = 0xffUL;                       /* MAIR attr0: normal write-back */
    out[3] = TEST_VA;
    out[4] = TEST_MAGIC;
    out[5] = 0;
    out[6] = KERNEL_VA;
    out[7] = KERNEL_MAGIC;
    c->kernel_expect = KERNEL_MAGIC;

    /* Stage 8 adds the upper half: a 16K TTBR1 regime at the address family the
     * kernelcache is linked for. Three levels, since T1SZ 23 makes the top level
     * a truncated level-1 table rather than a full one -- the same shape XNU's
     * own regime has, and a place where an off-by-one level is easy. */
    if (c->stage >= 8) {
        uint64_t root1 = guest_table(c);
        uint64_t l2 = guest_table(c);
        uint64_t l3k = guest_table(c);
        uint64_t kdata = guest_table(c);
        if (!root1 || !l2 || !l3k || !kdata) return 0;
        *(volatile uint64_t *)kdata = KERNEL_MAGIC;

        uint64_t off = KERNEL_VA & ((1UL << (64 - KERNEL_TXSZ)) - 1);
        *(volatile uint64_t *)(root1 + 8UL * mmu_index(14, 1, off)) = l2 | PT_VALID | PT_TABLE;
        *(volatile uint64_t *)(l2 + 8UL * mmu_index(14, 2, off)) = l3k | PT_VALID | PT_TABLE;
        *(volatile uint64_t *)(l3k + 8UL * mmu_index(14, 3, off)) = kdata | GUEST_PAGE;

        out[5] = root1;
        /* T1SZ, IRGN1/ORGN1 write-back, SH1 inner shareable, TG1 = 0b01 (16K). */
        tcr |= ((uint64_t)KERNEL_TXSZ << 16) | (1UL << 24) | (1UL << 26)
             | (3UL << 28) | (1UL << 30);
    } else {
        tcr |= 1UL << 23;                  /* EPD1: nothing in the upper half */
    }
    out[1] = tcr;
    return root;
}

/* Everything except the guest, run at EL2.
 *
 * When the guest hangs there is nothing to read, because the proxy is blocked
 * inside the P_CALL that started it. So the pieces get a path that never leaves
 * EL2: build the guest's 16K tables, build the shadow from them, and walk the
 * shadow in software to confirm it resolves what the guest would ask for. No
 * MMU register is touched, so this cannot wedge the machine.
 *
 * Returns 0 on success, or a negative code identifying the step that failed.
 */
int shadowmmu_selftest(uint64_t code);
int shadowmmu_selftest(uint64_t code)
{
    struct context *c = context_of();
    uint64_t prepared[8];
    if (!shadowmmu_prepare(code, prepared)) return -1;

    c->guest_ttbr0 = prepared[0];
    c->guest_tcr = prepared[1];
    c->guest_mair = prepared[2];

    struct mmu_config guest = {
        .granule_shift = 14,
        .txsz = (uint32_t)(c->guest_tcr & 0x3f),
        .root = c->guest_ttbr0,
    };
    struct shadow shadow = {.txsz = guest.txsz, .alloc = table_alloc,
                            .read = mem_read, .write = mem_write, .ctx = c};
    shadow.root = table_alloc(c);
    if (!shadow.root) return -2;

    long leaves = shadow_build(&shadow, &guest, 0, 1UL << (64 - guest.txsz), mem_read, c);
    if (leaves < 0) return -3;
    c->shadow_root = shadow.root;
    c->leaves = (uint64_t)leaves;
    c->builds++;

    /* Everything handed out by table_alloc, guest tables included: all of it is
     * about to be walked by hardware. */
    publish_tables(c->work_base, c->next_table);

    /* The address the guest will load through, resolved the way the hardware
     * would resolve it once the shadow is installed. */
    struct mmu_config shadow_cfg = {.granule_shift = 12, .txsz = guest.txsz,
                                    .root = shadow.root};
    struct mmu_leaf leaf;
    if (mmu_walk(&shadow_cfg, prepared[3], mem_read, c, &leaf) < 0) return -4;
    if (!leaf.valid) return -5;
    if (*(volatile uint64_t *)leaf.pa != prepared[4]) return -6;

    /* And the code the guest executes from, which must stay mapped across the
     * MMU enable or the guest dies on its next instruction. */
    if (mmu_walk(&shadow_cfg, code, mem_read, c, &leaf) < 0) return -7;
    if (!leaf.valid || leaf.pa != code) return -8;

    /* Now the same thing the trap handler does, at EL2 where a failure is still
     * reportable: program the hardware with the shadow, enable translation, and
     * ask the hardware walker. Everything is put back before returning, so this
     * leaves the machine exactly as it was found. */
    /* AT S1E1R only walks the EL1&0 regime when that regime is live. q1n1 runs
     * with HCR_EL2.TGE set, which disables it -- the same precondition
     * probes/tgran16.c documents, and forgetting it here made both walks report
     * failures that said nothing about the shadow. The guest path clears TGE
     * before entering EL1; this path has to do it explicitly. */
    uint64_t save_hcr;
    __asm__ volatile("mrs %0, hcr_el2" : "=r"(save_hcr));
    __asm__ volatile("msr hcr_el2, %0; isb"
                     :: "r"((save_hcr & ~((1UL << 27) | 1UL)) | (1UL << 31)));

    uint64_t save_sctlr, save_tcr, save_ttbr, save_mair;
    __asm__ volatile("mrs %0, sctlr_el1" : "=r"(save_sctlr));
    __asm__ volatile("mrs %0, tcr_el1" : "=r"(save_tcr));
    __asm__ volatile("mrs %0, ttbr0_el1" : "=r"(save_ttbr));
    __asm__ volatile("mrs %0, mair_el1" : "=r"(save_mair));

    c->guest_sctlr = SCTLR_M | (1UL << 11) | (1UL << 20) | (1UL << 22) |
                     (1UL << 23) | (1UL << 28) | (1UL << 29);
    int rc = install(c, code);

    __asm__ volatile("msr sctlr_el1, xzr; isb");
    __asm__ volatile("msr tcr_el1, %0" :: "r"(save_tcr));
    __asm__ volatile("msr ttbr0_el1, %0" :: "r"(save_ttbr));
    __asm__ volatile("msr mair_el1, %0" :: "r"(save_mair));
    __asm__ volatile("msr sctlr_el1, %0" :: "r"(save_sctlr));
    __asm__ volatile("dsb ish; tlbi vmalle1is; dsb ish; isb");
    __asm__ volatile("msr hcr_el2, %0; isb" :: "r"(save_hcr));

    /* Put back everything the selftest pretended to be the guest.
     *
     * Leaving guest_sctlr with M set made the trap handler believe the guest's
     * MMU was already enabled, so it skipped building the shadow and enabled
     * translation with the guest's own 16K tables -- an unrecoverable fault loop
     * with no mapped vectors, which presented as "install() hangs" when
     * install() was never reached. */
    c->guest_sctlr = 0;
    c->guest_ttbr0 = 0;
    c->guest_ttbr1 = 0;
    c->guest_tcr = 0;
    c->guest_mair = 0;
    if (rc) return -9;
    if (c->par_test & 1) return -10;
    return 0;
}

/* --- stage 2 ---
 *
 * Shadow paging only stays correct if q1n1 learns when the guest edits its own
 * page tables. Nothing traps a plain store, so the tables have to be made
 * read-only to the guest, and the only mechanism that can do that without the
 * guest noticing is stage 2: it translates what stage 1 produced, and the guest
 * cannot see or change it.
 *
 * This builds the permissive half first -- an identity map of intermediate
 * physical addresses to physical addresses -- so the guest runs unchanged with
 * stage 2 active. Write-protecting individual table pages is a later change on
 * top of a mechanism already known to work.
 */

/* Stage-2 descriptors are their own format: S2AP at [7:6] rather than stage 1's
 * AP, and MemAttr at [5:2] instead of an index into MAIR. */
#define S2_AF      (1UL << 10)
#define S2_SH_IS   (3UL << 8)
#define S2_RW      (3UL << 6)     /* S2AP: read and write */
#define S2_RO      (1UL << 6)     /* S2AP: read only -- the write-protect case */
#define S2_NORMAL  (0xfUL << 2)   /* MemAttr: normal, write-back cacheable */
#define S2_BLOCK   (S2_AF | S2_SH_IS | S2_NORMAL | PT_VALID)

#define S2_TXSZ 28u               /* 36-bit IPA: one 64-entry level-1 table */

/* Replace the 1GB block covering `pa` with a table, a table, and 512 pages, so
 * exactly one 4K page can be given different permissions. Everything else in
 * that gigabyte keeps the mapping it had. */
static int s2_split(struct context *c, uint64_t root, uint64_t pa, uint64_t leaf_extra)
{
    uint64_t l2 = table_alloc(c);
    uint64_t l3 = table_alloc(c);
    if (!l2 || !l3) return -1;

    uint64_t base1 = pa & ~((1UL << 30) - 1);
    for (unsigned n = 0; n < 512; n++)
        *(volatile uint64_t *)(l2 + 8UL * n) =
            (base1 + ((uint64_t)n << 21)) | S2_RW | S2_BLOCK;

    uint64_t base2 = pa & ~((1UL << 21) - 1);
    for (unsigned n = 0; n < 512; n++)
        *(volatile uint64_t *)(l3 + 8UL * n) =
            (base2 + ((uint64_t)n << 12)) | S2_RW | S2_BLOCK | PT_TABLE;
    *(volatile uint64_t *)(l3 + 8UL * ((pa >> 12) & 0x1ff)) |= leaf_extra;

    c->stub_l3 = l3;
    *(volatile uint64_t *)(l2 + 8UL * ((pa >> 21) & 0x1ff)) = l3 | PT_VALID | PT_TABLE;
    /* The root is published last: until its entry changes, the walker keeps
     * using the 1GB block and never sees a half-built table. */
    publish_tables(l3, l3 + 0x1000);
    publish_tables(l2, l2 + 0x1000);
    *(volatile uint64_t *)(root + 8UL * ((pa >> 30) & 0x3f)) = l2 | PT_VALID | PT_TABLE;
    publish_tables(root, root + 0x1000);
    return 0;
}

uint64_t shadowmmu_stage2(void);
uint64_t shadowmmu_stage2(void)
{
    struct context *c = context_of();
    uint64_t root = table_alloc(c);
    if (!root) return 0;

    /* 1GB blocks across the whole 36-bit IPA space. Identity, so every address
     * the guest can name through stage 1 resolves to itself. */
    for (unsigned n = 0; n < 64; n++)
        *(volatile uint64_t *)(root + 8UL * n) = ((uint64_t)n << 30) | S2_RW | S2_BLOCK;
    publish_tables(root, root + 0x1000);

    /* PS must describe a physical range the hardware actually implements, so it
     * comes from PARange rather than a guess. */
    uint64_t parange;
    __asm__ volatile("mrs %0, id_aa64mmfr0_el1" : "=r"(parange));
    parange &= 0xf;
    if (parange > 5) parange = 5;

    uint64_t vtcr = S2_TXSZ | (1UL << 6)          /* SL0 = 1: start at level 1 */
                  | (1UL << 8) | (1UL << 10)      /* IRGN0/ORGN0 write-back */
                  | (3UL << 12)                   /* SH0 inner shareable */
                  | (0UL << 14)                   /* TG0 = 4K */
                  | (parange << 16);
    __asm__ volatile("msr vtcr_el2, %0" :: "r"(vtcr));
    __asm__ volatile("msr vttbr_el2, %0" :: "r"(root));
    /* Stage 6 and up arm the interception: one page of this blob is made
     * non-executable so the guest's call into it faults to EL2. Done after
     * VTTBR/VTCR are set but before HCR_EL2.VM, so the guest never observes the
     * permissive map. */
    if (c->stage >= 6) {
        c->stub_pa = (uint64_t)(unsigned long)guest_stub;
        /* The stub has to own its page, or the guest's ordinary code would
         * fault too and there would be nothing sensible to do with it. The
         * linker aligns it; this catches a blob that was not loaded on a page
         * boundary, which the linker cannot know about. */
        if (c->stub_pa & 0xfff) {
            c->progress = 90;
            c->stub_pa = 0;
            return 0;
        }
        if (s2_split(c, root, c->stub_pa, S2_XN)) {
            c->progress = 91;
            c->stub_pa = 0;
            return 0;
        }
        /* Debug exceptions have to arrive at EL2 rather than at the guest's own
         * vectors, or the single-step fallback steps the guest into its own
         * handler. Saved here and put back by shadowmmu_report, which runs on
         * every exit including the EL2 fault path. */
        __asm__ volatile("mrs %0, mdcr_el2" : "=r"(c->save_mdcr));
        __asm__ volatile("mrs %0, mdscr_el1" : "=r"(c->save_mdscr));
        __asm__ volatile("msr mdcr_el2, %0; isb" :: "r"(c->save_mdcr | (1UL << 8)));
        /* Self-hosted debug, software step included, is disabled outright while
         * the OS Lock is held. Firmware can leave it locked, and a locked lock
         * looks exactly like a step that silently never fires. */
        __asm__ volatile("mrs %0, oslsr_el1" : "=r"(c->dbg_oslsr));
        if (c->dbg_oslsr & (1UL << 1))
            __asm__ volatile("msr oslar_el1, xzr; isb");
        __asm__ volatile("mrs %0, mdcr_el2" : "=r"(c->dbg_mdcr));
    }

    __asm__ volatile("dsb ish; tlbi vmalls12e1is; dsb ish; isb");
    c->stage2_root = root;
    return root;
}

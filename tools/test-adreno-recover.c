/* SPDX-License-Identifier: MIT */
/* GPU hang recovery, the monitor side (SNAP_ADRENO_RECOVER; agents/gpu-recovery FAILURE-MODES.md, written before the
 * code; the M-numbers below are its tests). The monitor's own entry points, in probes/xnuboot.c's dispatch order
 * (POLL then adreno_recover_final; RECOVER; the DEAD gate; the in-flight admission; START through
 * adreno_recover_start), over tools/test-adreno-ring.c's CP, extended here with what a reset touches:
 *  - CP_SQE_CNTL (3 halts the SQE: no progress; 1 starts it), RBBM_SW_RESET_CMD (the GX side back to reset values:
 *    SQE off, ring pointers 0, CP_RB_CNTL 0, the register file, the CCU, RBBM_GBIF_HALT, sticky bits, SECVID secure;
 *    the IB in progress is gone), the CX GBIF halt and its acknowledgement, RBBM_INT_CLEAR_CMD, SECVID;
 *  - a DMA engine: while a hung IB "runs", every step of model time writes its work page until GX or CX GBIF halts;
 *  - dirty UCHE lines the hung IB left: CACHE_CLEAN writes them back, CACHE_INVALIDATE7 drops them, and the reset drops
 *    them unless `caches_survive` (R2: INFERRED for the A16, so tested both ways);
 *  - CP_ME_INIT on the ring (q1n1's C4 words), every other GX register as a plain register file.
 * After a recovery the test hands the guilty pages back (a CPU sentinel) and keeps the GPU busy: any GPU write into them
 * afterwards is counted (R1, R2). Injected failures cover every proof (R4-R12, R25).
 *
 *   clang -std=gnu11 -Icompat -Ishadow -O1 -g -fsanitize=address,undefined -Wall -Wextra -Werror \
 *     -DSNAP_ADRENO_IB_ASYNC=1 -DSNAP_ADRENO_RECOVER=2 [-DADRENO_IB_POLL_DIVISOR=1u] tools/test-adreno-recover.c \
 *     compat/adreno-ib.c compat/adreno-fill.c compat/adreno-submit.c compat/adreno-resource.c compat/adreno.c \
 *     compat/irq-forward.c shadow/stage2.c shadow/shadow.c shadow/mmu.c -o build/test-adreno-recover \
 *     && build/test-adreno-recover
 * Run from the tree root. No hardware client. */
#define ADRENO_RING_NO_MAIN 1
#define ADRENO_RING_HOOKS 1
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunused-function"   /* S2 needs the draw-plan fixture: not run here */
#include "test-adreno-ring.c"
#pragma clang diagnostic pop
#if !SNAP_ADRENO_IB_ASYNC
#error "build with -DSNAP_ADRENO_IB_ASYNC=1"
#endif
#if !defined(ADRENO_RECOVER_NO_MAIN) && SNAP_ADRENO_RECOVER != 2
#error "build with -DSNAP_ADRENO_RECOVER=2 (level 1 runs inside, as rs.level = 1)"
#endif
#if SNAP_ADRENO_RECOVER
#include "adreno-recover-table.h"
#else
/* tools/test-adreno-recover-e2e.c's skew variant: a monitor without the define (the model still knows the registers). */
#define ADRENO_RBBM_INT_CLEAR_CMD 0x03d00184UL
#define ADRENO_RBBM_SW_RESET_CMD 0x03d001ccUL
#define ADRENO_GBIF_HALT 0x03d0f114UL
#define ADRENO_GBIF_HALT_ACK 0x03d0f118UL
#define ADRENO_RECOVER_SQE_BELOW_RING 0x20000UL
#define ADRENO_RECOVER_SQE_BYTES 0x20000UL
#define ADRENO_IB_HARD_TICKS(hz) ((hz) / ADRENO_IB_POLL_DIVISOR)
#define ADRENO_IB_SOFT_TICKS(hz) ((hz) / ADRENO_IB_POLL_DIVISOR)
#endif

#define SQE_PA (RING - ADRENO_RECOVER_SQE_BELOW_RING)
#define WORK2_VA FILL_B_VA
#define WORK2_PA FILL_B_PA
#define HARD ADRENO_IB_HARD_TICKS(ring_ops.hz)
#define SOFT ADRENO_IB_SOFT_TICKS(ring_ops.hz)
#define HUNG (1ull << 50)                             /* a latency the model never reaches: a hung IB */
#define RBBM_HANG_DETECT (1u << 23)
#define UCHE_OOB (1u << 24)
#define SECVID_PA 0x03d3d000UL                        /* RBBM_SECVID_TRUST_CNTL (q1n1 adreno_x2) */
#define SQE_BASE_PA (ADRENO_PA + 4 * 0x816UL)         /* CP_SQE_INSTR_BASE */

static struct {
    /* injected behaviour */
    int caches_survive, invalidate_ignored, cx_halt_stuck, reset_ignored, sqe_wont_start, me_init_stalls;
    int secvid_secure, cb0_moved_by_reset, sticky_after_reset;
    uint32_t rptr_after_reset;
    unsigned gx_off_after;                            /* GX power goes off after this many register-file writes */
    uint64_t evidence_at; uint32_t evidence_bits;     /* an error bit appears at this model time (0: never) */
    /* GX-side state the base model does not have */
    uint32_t gbif_halt, gbif_ack, sw_reset, secvid;
    uint32_t file[0x10000]; uint8_t set[0x10000];
    unsigned resets, file_writes, me_inits, invalidates, doorbells_sqe_off, base_under_sqe;
    /* the hung IB's DMA and its dirty cache lines */
    int dma; uint64_t dma_pa; uint32_t dma_value; unsigned dma_writes;
    struct { uint64_t pa; uint32_t v; } stale[8]; unsigned nstale, stale_landed;
    /* the guest's view: pages handed back after the final answer */
    uint64_t freed_lo, freed_hi; unsigned writes_into_freed;
    /* every MMIO write the monitor made since `watch` was set, outside the allowed set */
    int watch; unsigned stray_writes; uint64_t first_stray;
} gm;
#if SNAP_ADRENO_RECOVER
static struct adreno_recover_state RS;
#endif
static struct adreno_ops rec_ops;

static int passthrough(uint64_t pa)
{
    return (pa >= ADRENO_PA && pa < ADRENO_PASS0_END) || (pa >= ADRENO_PASS1_PA && pa < ADRENO_PASS1_END);
}
static int freed(uint64_t pa) { return pa >= gm.freed_lo && pa < gm.freed_hi; }
static void dma_step(void)
{
    if (gm.dma && !(r.halt_ack & 1) && !(gm.gbif_ack & 1)) {
        dev_wr32(gm.dma_pa, ++gm.dma_value);
        gm.dma_writes++;
        if (freed(gm.dma_pa)) gm.writes_into_freed++;
    }
    if (gm.evidence_at && (int64_t)(clock_now - gm.evidence_at) >= 0) { cp.int0 |= gm.evidence_bits; gm.evidence_at = 0; }
}
static void model_reset(void)
{
    gm.resets++;
    r.sqe = 0;
    r.rptr = r.wptr = gm.rptr_after_reset;
    cp.halt = cp.stall = cp.pending = 0;
    cp.latency = 0;                                    /* what runs next runs at its doorbell */
    cp.busy_polls = cp.busy_forever = 0;
    if (!gm.sticky_after_reset) { cp.int0 = 0; cp.cp_global = 0; }
    cp.int0_in_ib = cp.cp_global_in_ib = 0;
    cp.fault_in_ib = 0;
    cp.rb_cntl = r.rb_cntl = 0;
    memset(cp.reg, 0, sizeof cp.reg);
    memset(gm.file, 0, sizeof gm.file);
    memset(gm.set, 0, sizeof gm.set);
    gm.secvid = 1;                                     /* secure out of reset: C5 must make it 0 */
    r.halt = r.halt_ack = 0;                           /* RBBM_GBIF_HALT is a GX register */
    gm.dma = 0;                                        /* the IB in progress is gone */
    nccu = 0;
    if (!gm.caches_survive) gm.nstale = 0;
    if (gm.cb0_moved_by_reset) r.ttbr_lo ^= 0x1000;
}
static uint32_t rec_rd(void *ctx, uint64_t pa)
{
    dma_step();
    switch (pa) {
    case ADRENO_GBIF_HALT: return gm.gbif_halt;
    case ADRENO_GBIF_HALT_ACK: return gm.gbif_ack;
    case ADRENO_RBBM_SW_RESET_CMD: return gm.sw_reset;
    case ADRENO_RBBM_GBIF_HALT: return r.halt;
    case SECVID_PA: return gm.secvid;
    case ADRENO_RBBM_STATUS: case ADRENO_RBBM_INT_0_STATUS: case ADRENO_CP_INTERRUPT_STATUS_GLOBAL:
    case ADRENO_CP_RB_CNTL: case ADRENO_CP_RB_RPTR: case ADRENO_CP_RB_WPTR: case ADRENO_CP_SQE_CNTL:
    case ADRENO_RBBM_GBIF_HALT_ACK:
        return ring_rd(ctx, pa);
    }
    if (passthrough(pa)) return gm.file[(pa - ADRENO_PA) / 4];
    return ring_rd(ctx, pa);
}
static int allowed_write(uint64_t pa)
{
    if (passthrough(pa)) return 1;                     /* GX registers and the CX GBIF halt (R7) */
    if (pa == ADRENO_CB0 + ADRENO_CB_FSR || pa == ADRENO_SMMU_SGFSR) return 1;   /* fault W1C (R5) */
    if (pa >= RING && pa < RING + 8192 * 4) return 1;  /* the ring (R3) */
    if (pa >= MEMPTRS && pa < MEMPTRS + 0x1000) return 1;   /* RPTR shadows and fence slots */
    return 0;
}
static void rec_wr(void *ctx, uint64_t pa, uint32_t v)
{
    dma_step();
    if (gm.watch && !allowed_write(pa)) { if (!gm.stray_writes++) gm.first_stray = pa; }
    if (passthrough(pa)) {
        gm.file[(pa - ADRENO_PA) / 4] = v;
        gm.set[(pa - ADRENO_PA) / 4] = 1;
    }
    switch (pa) {
    case ADRENO_CP_RB_WPTR:
        if (!(r.sqe & 1) || r.sqe == 3) { gm.doorbells_sqe_off++; r.wptr = v; return; }   /* nobody fetches */
        ring_wr(ctx, pa, v);
        return;
    case ADRENO_CP_SQE_CNTL:
        if (v == 3) { r.sqe = 3; cp.halt = 1; return; }
        if (v == 1) { r.sqe = gm.sqe_wont_start ? 0 : 1; cp.halt = 0; return; }
        r.sqe = v;
        return;
    case ADRENO_GBIF_HALT:
        gm.gbif_halt = v;
        gm.gbif_ack = gm.cx_halt_stuck ? 0 : (v & 3);
        return;
    case ADRENO_RBBM_GBIF_HALT: m_wr(ctx, pa, v); return;
    case ADRENO_RBBM_SW_RESET_CMD:
        gm.sw_reset = v;
        if (v && !gm.reset_ignored) model_reset();
        return;
    case ADRENO_RBBM_INT_CLEAR_CMD: if (!gm.sticky_after_reset) cp.int0 &= ~v; return;
    case SECVID_PA: gm.secvid = gm.secvid_secure ? 1 : v; return;
    case ADRENO_CP_RB_CNTL: cp.rb_cntl = r.rb_cntl = v; return;
    case SQE_BASE_PA: if (r.sqe & 1) gm.base_under_sqe++; return;
    }
    if (passthrough(pa)) {
        if (++gm.file_writes == gm.gx_off_after) r.pwr = 3;
        return;
    }
    ring_wr(ctx, pa, v);
}
static void rec_inval(void *ctx, uint64_t pa, uint64_t size)
{
    (void)ctx;
    uint64_t off = ram_offset(pa, size);
    for (uint64_t line = off / 64; line <= (off + size - 1) / 64; line++) { dirty[line] = 0; cached[line] = 0; }
}
static void ring_event_hook(uint32_t ev)
{
    if (ev == EV_CACHE_CLEAN || ev == EV_CACHE_FLUSH_TS) {
        for (unsigned i = 0; i < gm.nstale; i++) {
            dev_wr32(gm.stale[i].pa, gm.stale[i].v);
            gm.stale_landed++;
            if (freed(gm.stale[i].pa)) gm.writes_into_freed++;
        }
        gm.nstale = 0;
    }
    if (ev == A8XX_E_CACHE_INVALIDATE7) { gm.invalidates++; if (!gm.invalidate_ignored) gm.nstale = 0; }
}
static int ring_extra_op(uint32_t op, const uint32_t *b, uint32_t count)
{
    (void)b;
    if (op != A8XX_E_CP_ME_INIT) return 0;
    if (count != 7) { violation("CP_ME_INIT count %u", count); return 1; }
    gm.me_inits++;
    if (gm.me_init_stalls) cp.stall = 1;
    return 1;
}

/* --- the dispatch (probes/xnuboot.c with SNAP_ADRENO_RECOVER) ----------------------------------------------------- */
static unsigned events;                               /* EV_GPU_RECOVER the dispatch would record */
#if SNAP_ADRENO_RECOVER
static int mon_call(uint64_t x[4])
{
    const uint64_t before = RS.attempts;
    int e;
    if (x[0] == ADRENO_GUEST_IB_POLL) {
        const uint64_t active = F.active;
        e = adreno_guest_ib_poll(&rec_ops, &P, &S, &F, x);
        if (active && !F.active) e = adreno_recover_final(&rec_ops, &P, &S, &F, &RS, e, 1, x);
    } else if (x[0] == ADRENO_GUEST_RECOVER) {
        e = adreno_guest_recover(&rec_ops, &P, &S, &F, &RS, x);
    } else if ((e = adreno_recover_refuse(&RS, &S, x)) || (e = adreno_ib_flight_refuse(&S, &F, x))) {
    } else switch (x[0]) {
    case ADRENO_GUEST_IB_START:
        e = adreno_recover_start(&rec_ops, &P, &S, &F, &RS, x, dart_leaf, 0, MEM_LOW, MEM_HIGH); break;
    case ADRENO_GUEST_IB: e = adreno_guest_ib(&rec_ops, &P, &S, x, dart_leaf, 0, MEM_LOW, MEM_HIGH); break;
    case ADRENO_GUEST_FILL32: e = adreno_guest_fill32(&rec_ops, &P, &S, x, dart_leaf, 0, MEM_LOW, MEM_HIGH); break;
    case ADRENO_GUEST_UNMAP:
        e = adreno_guest_unmap(&rec_ops, &P, &S, x, dart_leaf, s3_native_unmap, 0, MEM_LOW, MEM_HIGH); break;
    default: e = adreno_guest_fence(&rec_ops, &P, &S, x, dart_leaf, 0, MEM_LOW, MEM_HIGH);
    }
    events += RS.attempts != before;
    return e;
}
static int mon_tick(void)
{
    int final;
    const uint64_t before = RS.attempts;
    int idle = adreno_ib_flight_tick(&rec_ops, &P, &S, &F, ADRENO_IB_FLIGHT_GRACE_SECONDS * ring_ops.hz, &final);
    if (final != ADRENO_IB_PENDING) final = adreno_recover_final(&rec_ops, &P, &S, &F, &RS, final, 1, 0);
    if (idle) adreno_fault_poll(&rec_ops, &S);
    events += RS.attempts != before;
    return final;
}
#else
/* A monitor without SNAP_ADRENO_RECOVER (probes/xnuboot.c today): RECOVER goes to the fence handler, which refuses it. */
static int mon_call(uint64_t x[4])
{
    int e;
    if (x[0] == ADRENO_GUEST_IB_POLL) return adreno_guest_ib_poll(&rec_ops, &P, &S, &F, x);
    if ((e = adreno_ib_flight_refuse(&S, &F, x))) return e;
    switch (x[0]) {
    case ADRENO_GUEST_IB_START: return adreno_guest_ib_start(&rec_ops, &P, &S, &F, x, dart_leaf, 0, MEM_LOW, MEM_HIGH);
    case ADRENO_GUEST_IB: return adreno_guest_ib(&rec_ops, &P, &S, x, dart_leaf, 0, MEM_LOW, MEM_HIGH);
    case ADRENO_GUEST_FILL32: return adreno_guest_fill32(&rec_ops, &P, &S, x, dart_leaf, 0, MEM_LOW, MEM_HIGH);
    case ADRENO_GUEST_UNMAP: return adreno_guest_unmap(&rec_ops, &P, &S, x, dart_leaf, s3_native_unmap, 0, MEM_LOW, MEM_HIGH);
    }
    return adreno_guest_fence(&rec_ops, &P, &S, x, dart_leaf, 0, MEM_LOW, MEM_HIGH);
}
#endif

/* --- fixtures -------------------------------------------------------------------------------------------------- */
static void rec_setup(int level)
{
    s3_setup(22, 0);
    map(WORK2_VA, WORK2_PA, 0x4000, 0);
    memset(&gm, 0, sizeof gm);
    for (uint64_t off = 0; off < ADRENO_RECOVER_SQE_BYTES; off += 4)    /* q1n1's C2: the SQE image */
        dev_wr32(SQE_PA + off, 0x5e5e0000u ^ (uint32_t)(off * 2654435761u));
    rec_ops = ring_ops;
    rec_ops.rd = rec_rd;
    rec_ops.wr = rec_wr;
    rec_ops.invalidate = rec_inval;
#if SNAP_ADRENO_RECOVER
    memset(&RS, 0, sizeof RS);
    adreno_recover_init(&rec_ops, &P, &S, &RS);
    if (level == 1) RS.level = 1;
#else
    (void)level;
#endif
    events = 0;
    nlog = 0;
}
static void package(uint64_t va_of_work, uint32_t value)
{
    const uint32_t w[4] = {pkt7(OP_MEM_WRITE, 3), (uint32_t)va_of_work, (uint32_t)(va_of_work >> 32), value};
    put_package(PKG_PA, w, 4, 64);
}
static int start(uint64_t x[4])
{
    x[0] = ADRENO_GUEST_IB_START; x[1] = PKG_VA; x[2] = 4; x[3] = 64;
    return mon_call(x);
}
/* The kext's loop: POLLs with its backoff until a final answer. */
static int poll_final(uint64_t marker, uint64_t x[4], unsigned *polls)
{
    uint64_t delay = 10;
    unsigned n = 0;
    int e;
    for (;;) {
        x[0] = ADRENO_GUEST_IB_POLL; x[1] = marker; x[2] = x[3] = 0;
        e = mon_call(x);
        if (e != ADRENO_IB_PENDING || ++n > 200000) break;
        clock_now += delay;
        delay = delay * 2 > 200 ? 200 : delay * 2;
    }
    if (polls) *polls = n;
    return e;
}
/* A hung IB: the CP never finishes it, its shader keeps writing the work page and left a dirty UCHE line there. */
static int hang(uint64_t x[4])
{
    package(WORK_VA, 0xa5a5dead);
    cp.latency = HUNG;
    gm.dma = 1; gm.dma_pa = WORK_PA + 0x40;
    gm.stale[0].pa = WORK_PA + 0x100; gm.stale[0].v = 0xbad0bad0; gm.nstale = 1;
    return start(x);
}
/* A normal IB that writes `value` into WORK2 and finishes after `latency`. */
static int work(uint32_t value, uint64_t latency)
{
    uint64_t x[4];
    package(WORK2_VA, value);
    cp.latency = latency;
    int e = start(x);
    if (e == ADRENO_IB_PENDING) e = poll_final(x[1], x, 0);
    return e;
}
/* The guest gets the guilty pages back: a CPU sentinel, written to memory. */
static void give_back(void)
{
    gm.freed_lo = WORK_PA; gm.freed_hi = WORK_PA + 0x4000;
    for (uint64_t off = 0; off < 0x4000; off += 4) dev_wr32(WORK_PA + off, 0x5e171e1u);
}
static unsigned freed_changed(void) { return words_not(WORK_PA, 0x4000, 0x5e171e1u); }
static int ring_has_ib_word(void)
{
    for (uint32_t i = 0; i < 8192; i++) if (ring_word(i) == pkt7(OP_IB, 3)) return 1;
    return 0;
}

#ifndef ADRENO_RECOVER_NO_MAIN
/* --- M: the scenarios ------------------------------------------------------------------------------------------- */
/* M1 (R1) M3 (R3, R16) M9 (R9): hang -> hard limit -> RESET; no GPU write after; the guilty IB never comes back. */
static void test_m1_m3_m9_reset(void)
{
    uint64_t x[4];
    unsigned polls;
    rec_setup(2);
    CHECK(RS.level == 2 && !RS.init_refused && RS.sqe_pa == SQE_PA && RS.sqe_sum);
    CHECK(work(0x11110001, 400) == 0 && dev_rd32(WORK2_PA) == 0x11110001);
    gm.file[(ADRENO_GBIF_SCACHE_CNTL0 - ADRENO_PA) / 4] = 0x0d34d300u;   /* q1n1 llcc-gpu's SCIDs (SCID 13, say) */
    gm.file[(ADRENO_GBIF_SCACHE_CNTL1 - ADRENO_PA) / 4] = 0x0d34d34du;
    CHECK(hang(x) == ADRENO_IB_PENDING);
    const uint64_t m = x[1], t0 = clock_now;
    gm.watch = 1;
    int e = poll_final(m, x, &polls);
    gm.watch = 0;
    if (e != ADRENO_IB_E_RESET)
        printf("M1 debug: e=%d dead=%#llx attempts=%llu resets=%u me_inits=%u sqe=%u rptr=%u wptr=%u swptr=%llu int0=%#x fsr=%#x stray=%u first=%#llx viol=%u '%s'\n",
               e, (unsigned long long)RS.dead, (unsigned long long)RS.attempts, gm.resets, gm.me_inits, r.sqe, r.rptr, r.wptr,
               (unsigned long long)S.wptr, cp.int0, r.fsr, gm.stray_writes, (unsigned long long)gm.first_stray, cp.violations, cp.first);
    CHECK(e == ADRENO_IB_E_RESET && x[1] == 0 && x[3] == S.wptr);
    CHECK(clock_now - t0 >= HARD && clock_now - t0 < HARD + ring_ops.hz / 10);   /* R22, R23: the hard limit */
    CHECK(F.last_status == ADRENO_IB_E_RESET && !F.active && F.uncertain == 1 && F.reserved[0] == 1);
    CHECK(RS.epoch == 1 && F.reserved[2] == 1 && !RS.dead && RS.last_cause == ADRENO_RECOVER_HARD && events == 1);
    CHECK(gm.resets == 1 && gm.me_inits == 1 && gm.invalidates == 1 && r.sqe == 1 && cp.violations == 0);
    CHECK(gm.stray_writes == 0 && gm.doorbells_sqe_off == 0 && gm.base_under_sqe == 0);   /* M7 (R7) */
    CHECK(gm.secvid == 0 && !cp.int0 && !cp.cp_global && !r.fsr && r.halt == 0 && gm.gbif_halt == 8);
    CHECK(!ring_has_ib_word() && r.rptr == S.wptr && r.wptr == S.wptr);              /* M3: zeroed ring */
    CHECK(dev_rd32(MEMPTRS + 0x80) == (0x534e8000u | 1u));                           /* the proving fence */
    CHECK(gm.file[(ADRENO_GBIF_SCACHE_CNTL0 - ADRENO_PA) / 4] == 0x0d34d300u &&       /* the LLCC SCIDs kept */
          gm.file[(ADRENO_GBIF_SCACHE_CNTL1 - ADRENO_PA) / 4] == 0x0d34d34du);
    /* M9: the register file holds the table's last value of every register it writes */
    unsigned wrong = 0;
    const struct adreno_recover_op *sets[3] = {adreno_recover_hw_init, adreno_recover_sqe_start, adreno_recover_secvid};
    const unsigned counts[3] = {sizeof adreno_recover_hw_init / sizeof adreno_recover_hw_init[0], 1,
                                sizeof adreno_recover_secvid / sizeof adreno_recover_secvid[0]};
    uint32_t want[0x10000]; uint8_t wset[0x10000];
    memset(wset, 0, sizeof wset);
    for (unsigned s = 0; s < 3; s++)
        for (unsigned i = 0; i < counts[s]; i++)
            if (sets[s][i].op == ADRENO_RT_WRITE) { want[sets[s][i].reg] = sets[s][i].value; wset[sets[s][i].reg] = 1; }
    for (unsigned reg = 0; reg < 0x10000; reg++)
        if (wset[reg] && (!gm.set[reg] || gm.file[reg] != want[reg])) wrong++;
    CHECK(wrong == 0);
    CHECK(tz.calls == 1 && tz.last[0] == ADRENO_SMC_CP_APERTURE);                  /* R10: the aperture SMC */
    /* R1: give the pages back; the DMA stopped at the halt; 200 IBs (CACHE_CLEAN each) and fences later, intact */
    const unsigned dma = gm.dma_writes;
    give_back();
    unsigned ok = 0;
    for (unsigned i = 0; i < 200; i++) ok += work(0x22220000u + i, i % 3 ? 300 : 0) == 0;
    uint64_t f[4] = {ADRENO_GUEST_FENCE, FENCE_VA + 0x300, 0x5a5a1001, 0};
    CHECK(ok == 200 && mon_call(f) == 0 && dev_rd32(FENCE_PA + 0x300) == 0x5a5a1001);
    CHECK(dev_rd32(WORK2_PA) == 0x22220000u + 199 && gm.dma_writes == dma && freed_changed() == 0 &&
          gm.writes_into_freed == 0 && cp.violations == 0);
    /* R16: markers keep counting; the guilty one is never answered again */
    package(WORK2_VA, 0x22220999);
    cp.latency = 300;
    CHECK(start(x) == ADRENO_IB_PENDING && x[1] == (ADRENO_IB_MARKER_BASE ^ (uint32_t)S.ib_submits) && x[1] != m);
    CHECK(poll_final(x[1], x, 0) == 0 && dev_rd32(WORK2_PA) == 0x22220999);
    /* the IBASYNC1 record as the stop reports it (probes/xnuboot.c OUT_IB_ASYNC), for tools/perf_counters.py */
    uint64_t rec[2 + ADRENO_IB_FLIGHT_WORDS];
    rec[0] = 0x31434e5953414249ull;
    rec[1] = (uint64_t)sizeof F << 32 | ADRENO_IB_POLL_DIVISOR;
    memcpy(&rec[2], &F, sizeof F);
    save("ib-async-recover-record.bin", rec, sizeof rec);
    printf("RECOVER_M1 reset after %llu ticks (hard %llu), %u polls, %u table writes, epoch %llu\n",
           (unsigned long long)(clock_now - t0), (unsigned long long)HARD, polls, gm.file_writes,
           (unsigned long long)RS.epoch);
}

/* M1 (R1): the halt is never acknowledged: DMA cannot be excluded -> DEAD, UNCERTAIN, nothing reset. */
static void test_m1_halt_stuck(void)
{
    uint64_t x[4];
    for (int which = 0; which < 2; which++) {
        rec_setup(2);
        if (which) gm.cx_halt_stuck = 1; else r.halt_stuck = 1;
        CHECK(hang(x) == ADRENO_IB_PENDING);
        CHECK(poll_final(x[1], x, 0) == ADRENO_IB_E_UNCERTAIN && x[1] == 0);
        CHECK(RS.dead == ((uint64_t)ADRENO_RECOVER_HARD << 8 |
                          (which ? ADRENO_RECOVER_STEP_HALT_CX : ADRENO_RECOVER_STEP_HALT_GX)));
        CHECK(gm.resets == 0 && gm.sw_reset == 0 && RS.epoch == 0 && RS.failures == 1);
        const unsigned doorbells = cp.doorbells, writes = nlog;
        CHECK(work(1, 0) == ADRENO_E_PARAMS && cp.doorbells == doorbells && nlog == writes);   /* M17: DEAD gate */
    }
}

/* M2 (R2): dirty UCHE lines survive the reset in this model: the scrub's CACHE_INVALIDATE7 drops them. Negative
 * control: if the hardware ignored the invalidate, the next IB's CACHE_CLEAN would write into the freed page, and this
 * test sees it (so it would see it on the guard's failure too). */
static void test_m2_stale_lines(void)
{
    uint64_t x[4];
    for (int ignored = 0; ignored < 2; ignored++) {
        rec_setup(2);
        gm.caches_survive = 1;
        gm.invalidate_ignored = ignored;
        CHECK(hang(x) == ADRENO_IB_PENDING);
        CHECK(poll_final(x[1], x, 0) == ADRENO_IB_E_RESET);
        give_back();
        CHECK(work(0x33330001, 200) == 0);
        if (!ignored) CHECK(gm.writes_into_freed == 0 && freed_changed() == 0 && gm.stale_landed == 0);
        else CHECK(gm.writes_into_freed == 1 && freed_changed() == 1);   /* the hazard is visible to the test */
    }
}

/* M4 (R4): CB0 changed before -> DEAD, nothing written; changed by the reset -> DEAD after it. */
static void test_m4_cb0(void)
{
    uint64_t x[4];
    rec_setup(2);
    CHECK(hang(x) == ADRENO_IB_PENDING);
    const uint64_t m = x[1];
    clock_now += HARD;
    r.ttbr_lo ^= 0x1000;
    gm.watch = 1;
    const unsigned writes = nlog;
    CHECK(poll_final(m, x, 0) == ADRENO_IB_E_UNCERTAIN);
    CHECK(RS.dead == ((uint64_t)ADRENO_RECOVER_HARD << 8 | ADRENO_RECOVER_STEP_CB0) && gm.sw_reset == 0 &&
          gm.resets == 0 && nlog == writes && gm.gbif_halt == 0);
    rec_setup(2);
    gm.cb0_moved_by_reset = 1;
    CHECK(hang(x) == ADRENO_IB_PENDING);
    CHECK(poll_final(x[1], x, 0) == ADRENO_IB_E_UNCERTAIN && RS.dead &&
          (RS.dead & 0xff) == ADRENO_RECOVER_STEP_AFTER && gm.resets == 1);
}

/* M5 (R5): a CB0 fault while the IB runs: level 1 UNCERTAIN (as today); level 2 RESET_FAULT, fault recorded, cleared. */
static void test_m5_fault(void)
{
    uint64_t x[4];
    for (int level = 1; level <= 2; level++) {
        rec_setup(level);
        package(WORK_VA, 1);
        cp.latency = 400;
        cp.fault_in_ib = 1;
        CHECK(start(x) == ADRENO_IB_PENDING);
        int e = poll_final(x[1], x, 0);
        if (level == 1) CHECK(e == ADRENO_IB_E_UNCERTAIN && r.fsr && RS.epoch == 0 && gm.resets == 0);
        else CHECK(e == ADRENO_IB_E_RESET_FAULT && !r.fsr && S.faults == 1 && RS.epoch == 1 &&
                   RS.last_cause == ADRENO_RECOVER_FAULT && work(0x55550001, 100) == 0);
    }
}

/* M6 (R6): GX off at the hang -> DEAD, nothing written; GX goes off during the replay -> DEAD. */
static void test_m6_power(void)
{
    uint64_t x[4];
    rec_setup(2);
    CHECK(hang(x) == ADRENO_IB_PENDING);
    const uint64_t m = x[1];
    clock_now += HARD;
    r.pwr = 3;
    CHECK(poll_final(m, x, 0) == ADRENO_IB_E_UNCERTAIN && (RS.dead & 0xff) == ADRENO_RECOVER_STEP_POWER &&
          gm.sw_reset == 0 && gm.gbif_halt == 0);
    rec_setup(2);
    gm.gx_off_after = 60;
    CHECK(hang(x) == ADRENO_IB_PENDING);
    CHECK(poll_final(x[1], x, 0) == ADRENO_IB_E_UNCERTAIN && RS.dead && gm.resets == 1 && gm.me_inits == 0);
}

/* M8 (R8): the SQE image changed -> DEAD before anything is written. */
static void test_m8_sqe_image(void)
{
    uint64_t x[4];
    rec_setup(2);
    CHECK(hang(x) == ADRENO_IB_PENDING);
    dev_wr32(SQE_PA + 0x1234 * 4, dev_rd32(SQE_PA + 0x1234 * 4) ^ 0x100);
    CHECK(poll_final(x[1], x, 0) == ADRENO_IB_E_UNCERTAIN &&
          (RS.dead & 0xff) == ADRENO_RECOVER_STEP_SQE_IMAGE && gm.sw_reset == 0 && gm.gbif_halt == 0 && gm.resets == 0);
}

/* M10 (R10): TrustZone traps -> DEAD; interrupted twice -> resumed, recovered; a nonzero answer -> recovered. */
static void test_m10_smc(void)
{
    uint64_t x[4];
    for (int k = 0; k < 3; k++) {
        rec_setup(2);
        if (k == 0) tz.trap = 1;
        if (k == 1) { tz.interrupts = 2; tz.session = 0x77; }
        if (k == 2) tz.final = (uint64_t)-22;
        CHECK(hang(x) == ADRENO_IB_PENDING);
        int e = poll_final(x[1], x, 0);
        if (k == 0) CHECK(e == ADRENO_IB_E_UNCERTAIN && (RS.dead & 0xff) == ADRENO_RECOVER_STEP_SMC && gm.me_inits == 0);
        else CHECK(e == ADRENO_IB_E_RESET && RS.epoch == 1 && work(0x10100000u + (unsigned)k, 0) == 0);
        if (k == 1) CHECK(tz.calls == 3 && tz.resumed_x6 == 0x77);
    }
}

/* M11 (R11): the SQE does not start, or CP_ME_INIT stalls -> DEAD. */
static void test_m11_me_init(void)
{
    uint64_t x[4];
    for (int k = 0; k < 2; k++) {
        rec_setup(2);
        if (k) gm.me_init_stalls = 1; else gm.sqe_wont_start = 1;
        CHECK(hang(x) == ADRENO_IB_PENDING);
        CHECK(poll_final(x[1], x, 0) == ADRENO_IB_E_UNCERTAIN && (RS.dead & 0xff) == ADRENO_RECOVER_STEP_ME_INIT);
    }
    rec_setup(2);                                       /* C5: SECVID stays secure -> DEAD */
    gm.secvid_secure = 1;
    CHECK(hang(x) == ADRENO_IB_PENDING);
    CHECK(poll_final(x[1], x, 0) == ADRENO_IB_E_UNCERTAIN && (RS.dead & 0xff) == ADRENO_RECOVER_STEP_SECVID);
    rec_setup(2);                                       /* sticky bits survive the reset -> DEAD */
    gm.sticky_after_reset = 1;
    package(WORK_VA, 1);
    cp.latency = 300;
    cp.int0_in_ib = UCHE_OOB;
    CHECK(start(x) == ADRENO_IB_PENDING);
    CHECK(poll_final(x[1], x, 0) == ADRENO_IB_E_GPU_ERROR && (RS.dead & 0xff) == ADRENO_RECOVER_STEP_STICKY);
}

/* M12 (R12): the CP keeps a nonzero RPTR after the reset -> DEAD; a reset ring wraps normally later. */
static void test_m12_ring(void)
{
    uint64_t x[4];
    rec_setup(2);
    gm.rptr_after_reset = 7;
    CHECK(hang(x) == ADRENO_IB_PENDING);
    CHECK(poll_final(x[1], x, 0) == ADRENO_IB_E_UNCERTAIN && (RS.dead & 0xff) == ADRENO_RECOVER_STEP_RING);
    rec_setup(2);
    CHECK(hang(x) == ADRENO_IB_PENDING && poll_final(x[1], x, 0) == ADRENO_IB_E_RESET);
    unsigned ok = 0;
    const uint64_t wraps = S.ring_wraps;
    for (unsigned i = 0; i < 300; i++) ok += work(0x12120000u + i, 0) == 0;
    CHECK(ok == 300 && S.ring_wraps == wraps + 1 && cp.violations == 0 && dev_rd32(WORK2_PA) == 0x12120000u + 299);
}

/* M13 (R20): an abandoned hung flight is reset by the tick; the late POLL gets RESET. The stop never resets. */
static void test_m13_tick_and_stop(void)
{
    uint64_t x[4];
    rec_setup(2);
    CHECK(hang(x) == ADRENO_IB_PENDING);
    const uint64_t m = x[1];
    clock_now += HARD;
    CHECK(mon_tick() == ADRENO_IB_PENDING && F.active);                 /* within hard + grace */
    clock_now += ADRENO_IB_FLIGHT_GRACE_SECONDS * ring_ops.hz;
    CHECK(mon_tick() == ADRENO_IB_E_RESET && !F.active && F.abandoned == 1 && RS.epoch == 1);
    x[0] = ADRENO_GUEST_IB_POLL; x[1] = m; x[2] = x[3] = 0;
    CHECK(mon_call(x) == ADRENO_IB_E_RESET && x[1] == 0);
    CHECK(work(0x13130001, 100) == 0);
    rec_setup(2);
    CHECK(hang(x) == ADRENO_IB_PENDING);
    int final = 0;
    CHECK(adreno_ib_flight_drain(&rec_ops, &P, &S, &F, ring_ops.hz / 100, &final) == 1 &&
          final == ADRENO_IB_E_UNCERTAIN && gm.resets == 0 && gm.sw_reset == 0);
    adreno_quiesce(&rec_ops, &P, &S);
    CHECK((S.status & ADRENO_S_QUIESCED) && S.quiesce);
}

/* M14 (R21, R27): SETTLE and QUERY. */
static void test_m14_settle(void)
{
    uint64_t x[4], q[4];
    rec_setup(2);
    q[0] = ADRENO_GUEST_RECOVER; q[1] = ADRENO_RECOVER_QUERY; q[2] = q[3] = 0;
    CHECK(mon_call(q) == 0 && q[1] == (ADRENO_RECOVER_ABI | 2u << 8 | ADRENO_IB_HARD_SECONDS << 16) && q[2] == 0 &&
          q[3] == ADRENO_RECOVER_STATE_READY && RS.queries == 1);
    q[0] = ADRENO_GUEST_RECOVER; q[1] = ADRENO_RECOVER_SETTLE; q[2] = q[3] = 0;   /* idle: settled, no reset */
    CHECK(mon_call(q) == 0 && q[2] == 0 && gm.resets == 0 && RS.settles == 1);
    package(WORK_VA, 0x14140001);
    cp.latency = 5000;
    CHECK(start(x) == ADRENO_IB_PENDING);
    const unsigned writes = nlog;
    q[0] = ADRENO_GUEST_RECOVER; q[1] = ADRENO_RECOVER_SETTLE; q[2] = q[3] = 0;   /* a flight: BUSY, nothing */
    CHECK(mon_call(q) == ADRENO_IB_E_BUSY && nlog == writes && gm.resets == 0 && F.active);
    q[0] = ADRENO_GUEST_RECOVER; q[1] = ADRENO_RECOVER_QUERY; q[2] = q[3] = 0;
    CHECK(mon_call(q) == 0 && q[3] == ADRENO_RECOVER_STATE_FLIGHT);
    CHECK(poll_final(x[1], x, 0) == 0 && dev_rd32(WORK_PA) == 0x14140001);
    q[0] = ADRENO_GUEST_RECOVER; q[1] = 7; q[2] = q[3] = 0;                         /* malformed */
    CHECK(mon_call(q) == ADRENO_E_PARAMS);
    /* The CP is wedged outside any flight (e.g. a FILL32 the kext saw time out): level 1 cannot settle, level 2 resets. */
    for (int level = 1; level <= 2; level++) {
        rec_setup(level);
        uint64_t fl[4] = {ADRENO_GUEST_FILL32, FILL_A_VA, 0x40, 0x77777777};
        map(FILL_A_VA, FILL_A_PA, 0x4000, 0);
        cp.halt = 1;                                    /* the CP stops consuming: the fill times out */
        CHECK(mon_call(fl) != 0);
        q[0] = ADRENO_GUEST_RECOVER; q[1] = ADRENO_RECOVER_SETTLE; q[2] = q[3] = 0;
        int e = mon_call(q);
        if (level == 1) CHECK(e == ADRENO_IB_E_UNCERTAIN && gm.resets == 0);
        else CHECK(e == 0 && q[2] == 1 && q[1] == 1 && RS.settle_resets == 1 && work(0x14140002, 0) == 0);
    }
}

/* M15 (R22): a 2.5 s job completes (soft budget, overdue counted) at both levels; HANG_DETECT ends it early. */
static void test_m15_budget(void)
{
    uint64_t x[4];
    for (int level = 1; level <= 2; level++) {
        rec_setup(level);
        package(WORK_VA, 0x15150001);
        cp.latency = 2500000;
        CHECK(start(x) == ADRENO_IB_PENDING);
        CHECK(poll_final(x[1], x, 0) == 0 && dev_rd32(WORK_PA) == 0x15150001 && F.reserved[0] == 1 &&
              F.reserved[1] == 0 && gm.resets == 0);
        rec_setup(level);
        package(WORK_VA, 1);
        cp.latency = HUNG;
        const uint64_t t0 = clock_now;
        gm.evidence_at = t0 + SOFT + 200000; gm.evidence_bits = RBBM_HANG_DETECT;
        CHECK(start(x) == ADRENO_IB_PENDING);
        int e = poll_final(x[1], x, 0);
        CHECK(clock_now - t0 < SOFT + 200000 + ring_ops.hz / 100 && F.reserved[1] == 1);
        if (level == 1) CHECK(e == ADRENO_IB_E_UNCERTAIN && gm.resets == 0);
        else CHECK(e == ADRENO_IB_E_RESET && RS.last_cause == ADRENO_RECOVER_EVIDENCE && !cp.int0);
        printf("RECOVER_M15 level %d: 2.5 s job completed; HANG_DETECT after soft+0.2 s ended at %llu ticks -> %d\n",
               level, (unsigned long long)(clock_now - t0), e);
    }
}

/* M16 (R24): give-up policy: four resets in 60 s, the fifth gives up; spaced hangs: sixteen per boot. */
static void test_m16_policy(void)
{
    uint64_t x[4];
    rec_setup(2);
    unsigned resets = 0;
    for (unsigned i = 0; i < 4; i++) { CHECK(hang(x) == ADRENO_IB_PENDING); resets += poll_final(x[1], x, 0) == ADRENO_IB_E_RESET; }
    CHECK(resets == 4 && RS.epoch == 4);
    CHECK(hang(x) == ADRENO_IB_PENDING && poll_final(x[1], x, 0) == ADRENO_IB_E_UNCERTAIN);
    CHECK(RS.dead == ((uint64_t)ADRENO_RECOVER_HARD << 8 | ADRENO_RECOVER_STEP_POLICY) && gm.resets == 4);
    uint64_t q[4] = {ADRENO_GUEST_RECOVER, ADRENO_RECOVER_QUERY, 0, 0};
    CHECK(mon_call(q) == 0 && q[3] == ADRENO_RECOVER_STATE_DEAD && q[2] == 4);
    q[0] = ADRENO_GUEST_RECOVER; q[1] = ADRENO_RECOVER_SETTLE; q[2] = q[3] = 0;
    CHECK(mon_call(q) == ADRENO_RECOVER_E_DEAD);
    rec_setup(2);
    resets = 0;
    for (unsigned i = 0; i < 17; i++) {
        clock_now += (uint64_t)(ADRENO_RECOVER_WINDOW_SECONDS + 1) * ring_ops.hz;
        CHECK(hang(x) == ADRENO_IB_PENDING);
        resets += poll_final(x[1], x, 0) == ADRENO_IB_E_RESET;
    }
    CHECK(resets == ADRENO_RECOVER_MAX && RS.epoch == ADRENO_RECOVER_MAX && (RS.dead & 0xff) == ADRENO_RECOVER_STEP_POLICY);
    printf("RECOVER_M16 burst: 4 resets then DEAD; spaced: %u resets then DEAD\n", resets);
}

/* M17 (R25): after DEAD every ring user is refused before any write; UNMAP and CACHE still work; quiesce works. */
static void test_m17_dead(void)
{
    uint64_t x[4];
    rec_setup(2);
    gm.reset_ignored = 1;                               /* the pulse does nothing: SQE_CNTL still reads 3 */
    CHECK(hang(x) == ADRENO_IB_PENDING);
    CHECK(poll_final(x[1], x, 0) == ADRENO_IB_E_UNCERTAIN && (RS.dead & 0xff) == ADRENO_RECOVER_STEP_RESET);
    const unsigned writes = nlog, cleans_before = cleans, doorbells = cp.doorbells;
    uint64_t f[4] = {ADRENO_GUEST_FENCE, FENCE_VA + 0x200, 0x5a5a0099, 0};
    uint64_t fl[4] = {ADRENO_GUEST_FILL32, FILL_A_VA, 0x40, 0x11223344};
    uint64_t ib[4] = {ADRENO_GUEST_IB, PKG_VA, 4, 64};
    CHECK(mon_call(f) == ADRENO_E_PARAMS && mon_call(fl) == ADRENO_E_PARAMS && mon_call(ib) == ADRENO_E_PARAMS &&
          start(x) == ADRENO_E_PARAMS && x[1] == 0);
    CHECK(nlog == writes && cleans == cleans_before && cp.doorbells == doorbells);
    uint64_t u[4] = {ADRENO_GUEST_UNMAP, WORK2_VA, 0x4000, 0};
    CHECK(mon_call(u) == 0 && u[1] == 0x4000);
    adreno_quiesce(&rec_ops, &P, &S);
    CHECK(S.quiesce != 0);
}

/* M18 (R5, sticky): a START refused STICKY (an earlier FILL32 raised UCHE_OOB): level 2 resets and starts the IB. */
static void test_m18_sticky_start(void)
{
    uint64_t x[4];
    for (int level = 1; level <= 2; level++) {
        rec_setup(level);
        cp.int0 = UCHE_OOB;
        package(WORK_VA, 0x18180001);
        cp.latency = 0;
        int e = start(x);
        if (level == 1) CHECK(e == ADRENO_IB_E_STICKY && gm.resets == 0);
        else CHECK(e == 0 && RS.start_resets == 1 && RS.epoch == 1 && dev_rd32(WORK_PA) == 0x18180001);
    }
}

/* M19: GPU_ERROR at retirement: level 1 unchanged; level 2 resets (sticky bits gone) and answers RESET. */
static void test_m19_gpu_error(void)
{
    uint64_t x[4];
    for (int level = 1; level <= 2; level++) {
        rec_setup(level);
        package(WORK_VA, 0x19190001);
        cp.latency = 500;
        cp.int0_in_ib = UCHE_OOB;
        CHECK(start(x) == ADRENO_IB_PENDING);
        int e = poll_final(x[1], x, 0);
        if (level == 1) CHECK(e == ADRENO_IB_E_GPU_ERROR && cp.int0 == UCHE_OOB);
        else CHECK(e == ADRENO_IB_E_RESET && !cp.int0 && RS.last_cause == ADRENO_RECOVER_GPU_ERROR &&
                   work(0x19190002, 0) == 0);
    }
}

/* Level 1 at the hard limit: UNCERTAIN as today (only later), no reset; init refuses level 2 without the SQE region. */
static void test_level1_and_init(void)
{
    uint64_t x[4];
    rec_setup(1);
    CHECK(hang(x) == ADRENO_IB_PENDING);
    const uint64_t t0 = clock_now;
    CHECK(poll_final(x[1], x, 0) == ADRENO_IB_E_UNCERTAIN && clock_now - t0 >= HARD && gm.resets == 0 && !RS.dead);
    rec_setup(2);
    P.ring_pa = ARENA + 0x10000;                         /* an SQE region below the arena: level 2 is not armed */
    memset(&RS, 0, sizeof RS);
    adreno_recover_init(&rec_ops, &P, &S, &RS);
    CHECK(RS.level == 1 && RS.init_refused == ADRENO_RECOVER_STEP_INIT);
    P.ring_pa = RING;
}

/* M20: START itself ends UNCERTAIN (its doorbell dropped twice, async-ib A20): level 2 resets, answers RESET. */
static void test_m20_start_uncertain(void)
{
    uint64_t x[4];
    rec_setup(2);
    package(WORK_VA, 1);
    cp.latency = 300;
    r.drop_writes = 2;
    int e0 = start(x);
    if (e0 != ADRENO_IB_E_RESET) printf("M20 debug: e=%d dead=%#llx attempts=%llu epoch=%llu\n", e0,
                                        (unsigned long long)RS.dead, (unsigned long long)RS.attempts, (unsigned long long)RS.epoch);
    CHECK(e0 == ADRENO_IB_E_RESET && x[1] == 0 && !F.active && RS.epoch == 1 && F.flights == 0);
    CHECK(work(0x20200001, 0) == 0 && dev_rd32(WORK2_PA) == 0x20200001);
}

int main(void)
{
    dram = calloc(1, RAM_SIZE);
    cache = calloc(1, RAM_SIZE);
    if (!dram || !cache) return 2;
    test_m1_m3_m9_reset();
    test_m1_halt_stuck();
    test_m2_stale_lines();
    test_m4_cb0();
    test_m5_fault();
    test_m6_power();
    test_m8_sqe_image();
    test_m10_smc();
    test_m11_me_init();
    test_m12_ring();
    test_m13_tick_and_stop();
    test_m14_settle();
    test_m15_budget();
    test_m16_policy();
    test_m17_dead();
    test_m18_sticky_start();
    test_m19_gpu_error();
    test_level1_and_init();
    test_m20_start_uncertain();
    free(dram);
    free(cache);
    if (failures) { printf("FAIL: %u of %u recovery checks\n", failures, checks); return 1; }
    printf("PASS: %u recovery checks (soft budget %llu ticks, hard %llu): reset, DMA drain, stale lines, CB0, fault, "
           "power, SQE image, SMC, ME_INIT, SECVID, sticky, ring, tick, stop, settle, budget, policy, DEAD gate, "
           "sticky START, GPU_ERROR, level 1, START UNCERTAIN\n", checks, (unsigned long long)(1000000 / ADRENO_IB_POLL_DIVISOR),
           (unsigned long long)(1000000ull * ADRENO_IB_HARD_SECONDS));
    return 0;
}
#endif

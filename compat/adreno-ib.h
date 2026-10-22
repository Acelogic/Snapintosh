/* SPDX-License-Identifier: MIT */
/* ADRENO_GUEST_IB, the monitor side (design S2, docs 4.3). The ABI (arguments, results, placement rule and
 * refusal order) is compat/adreno-guest.h; this is the implementation the HVC #0xad16 dispatch calls.
 *
 * The kext copies, relocates and validates a package (IB + data) into its GPU-read-only arena and asks the
 * monitor to run the IB. The monitor never parses the IB. It proves the package cannot change under the CP
 * (every page a readable, GPU-no-write DART leaf in guest RAM outside the arena, mirrored into CB0 as exactly
 * pa | LEAF | RDONLY), that the GPU is powered, attached, idle and error-free, then cleans the package to PoC
 * and runs q1n1's hardware-proven ring sequence (a16gpu_p6p7.ring_words, a7xx_submit: CP_INDIRECT_BUFFER,
 * CCU invalidates, a BV CACHE_CLEAN fence, CP_WAIT_TIMESTAMP, a BR CACHE_CLEAN fence) on the monitor-owned
 * ring, which wraps (compat/adreno.h adreno_ring_reserve). It returns after completion: both fences equal
 * the marker, CP_RB_RPTR == WPTR and RBBM idle (a shader or IB write into memptrs cannot fake the last two).
 *
 * Privilege (design 4.1/4.4-4.6, INFERRED until hardware proofs H1-H3): the ring runs privileged (q1n1
 * hw_init: CP_APRIV_CNTL_PIPE RBPRIVLEVEL on every pipe), IB1 unprivileged under the 52 CP_PROTECT_GLOBAL
 * entries. The monitor neither writes nor re-reads CP_PROTECT/APRIV (q1n1 only ever writes them; their
 * readback is unproven on the A16), so IB-level protection rests on H1/H2 and on the kext's allowlist.
 * The BV fence is a BV-thread write, and only the BR pipe has APRIV CDWRITE: memptrs must stay UNPRIV_RW
 * (q1n1 cp-fence's mapping) or the BV fence faults (review R6). The guest keeps its stage-2 passthrough to
 * the CP registers (design 4.4: the monitor's checks guard against accidents, not a hostile guest kernel).
 */
#pragma once
#include "adreno.h"

/* Caller holds the service lock across the placement walk, the ring emission and the bounded poll (DART
 * and mirror stay stable). regs[0..3] = x0..x3 in, results out (compat/adreno-guest.h). `leaf` is the
 * committed DART stream-0 descriptor of a 16 KiB IOVA page, as for FILL32. Returns regs[0]. */
int adreno_guest_ib(const struct adreno_ops *o, const struct adreno_params *p, struct adreno_state *s,
                    uint64_t regs[4], uint64_t (*leaf)(void *ctx, uint64_t iova), void *leaf_ctx,
                    uint64_t mem_low, uint64_t mem_high);

/* The ADRENO_IB_RING_WORDS words the monitor emits for one IB (equal to q1n1 a16gpu_p6p7.ring_words(ib_va,
 * dwords, br_va, bv_va, marker)); exported for the host oracle. Returns the count written. */
unsigned adreno_ib_ring_words(uint32_t w[ADRENO_IB_RING_WORDS], uint64_t ib_va, uint32_t dwords,
                              uint64_t br_va, uint64_t bv_va, uint32_t marker);

#ifndef SNAP_ADRENO_IB_ASYNC
#define SNAP_ADRENO_IB_ASYNC 0
#endif
#if SNAP_ADRENO_IB_ASYNC
/* ---- SNAP_ADRENO_IB_ASYNC: ADRENO_GUEST_IB_START / ADRENO_GUEST_IB_POLL (ABI compat/adreno-guest.h) ------------
 * ADRENO_GUEST_IB holds the service token for the whole GPU execution: every guest HVC is taken under it
 * (probes/xnuboot.c xnuboot_trap -> runtime_enter), and no fast path takes EC 0x16. START and POLL make that
 * hold short: START is ADRENO_GUEST_IB's checks, clean and doorbell plus a spin of at most
 * hz / ADRENO_IB_START_SPIN_DIVISOR; POLL is one completion pass. The guest waits between them, off the token.
 * Failure modes and their tests: agents/async-ib/FAILURE-MODES.md (A0-A22).
 *
 * The flight is one IB between START's doorbell and its final status. One per monitor (any vCPU may poll it:
 * a thread migrates), keyed by its marker, timed by the system counter from the doorbell. It lives in a monitor
 * arena page (probes/xnuboot.c c->ib_flight), not in struct context or struct adreno_state, so no decoded layout
 * moves; every access is under the service token, like the rest of the GPU state. Its words, as they stand at
 * the stop, are the report's "IBASYNC1" record (tools/perf_counters.py decode_ib_async). */
struct adreno_ib_flight {
    /* The IB in flight (active), as START rang it; tlbi bases are adreno_state's at the doorbell. */
    uint64_t active, marker, start, va, dwords, bytes, wptr, reads, tlbi_base, tlbi_timeout_base;
    /* The last flight's final reply, answered again to a POLL of its marker (never to marker 0). */
    uint64_t last_marker;
    int64_t last_status;
    uint64_t last_ticks, last_wptr;
    /* Counters. starts: START calls; flights: STARTs that answered PENDING. Every flight ends once: finished (by
     * POLL), abandoned (by the tick, no POLL for budget + grace) or stopped (drained at the stop); and as ok,
     * gpu_errors or uncertain. polls = poll_pending + finished + idle + mismatched + poll_refused (idle includes
     * the stored last reply). refused: ring users and package UNMAPs refused while in flight. tlbi and
     * tlbi_timeouts: SMMU invalidations (and their 1 ms timeouts) while a flight was active. max_ticks,
     * sum_ticks: doorbell to final status; max_reads: completion passes of one flight. */
    uint64_t starts, flights, polls, poll_pending, finished, abandoned, stopped, ok, gpu_errors, uncertain;
    uint64_t idle, mismatched, poll_refused, refused, tlbi, tlbi_timeouts, max_ticks, sum_ticks, max_reads;
    uint64_t reserved[3];
};
#define ADRENO_IB_FLIGHT_WORDS 36
_Static_assert(sizeof(struct adreno_ib_flight) == 8 * ADRENO_IB_FLIGHT_WORDS, "IBASYNC1 words (perf_counters.py)");
#define ADRENO_IB_FLIGHT_GRACE_SECONDS 1u   /* the tick finalizes a flight nobody polled for budget + this */

/* START: regs[0] = ADRENO_GUEST_IB_START, the rest and every refusal as adreno_guest_ib (ADRENO_IB_E_BUSY while a
 * flight is active). A final status is answered exactly as adreno_guest_ib's; otherwise the flight begins and
 * regs = {ADRENO_IB_PENDING, marker, ticks, WPTR}. Caller holds the service lock, as for adreno_guest_ib. */
int adreno_guest_ib_start(const struct adreno_ops *o, const struct adreno_params *p, struct adreno_state *s,
                          struct adreno_ib_flight *f, uint64_t regs[4],
                          uint64_t (*leaf)(void *ctx, uint64_t iova), void *leaf_ctx,
                          uint64_t mem_low, uint64_t mem_high);
/* POLL: regs = {ADRENO_GUEST_IB_POLL, marker, 0, 0}; one completion pass of the flight (compat/adreno-guest.h).
 * Writes nothing but the fence-slot cleans; a final status ends the flight. */
int adreno_guest_ib_poll(const struct adreno_ops *o, const struct adreno_params *p, struct adreno_state *s,
                         struct adreno_ib_flight *f, uint64_t regs[4]);
/* The dispatch's admission while a flight is active, before the call runs: 0 admits; otherwise the refusal status
 * (nothing written; regs hold the call's own refusal reply): ADRENO_GUEST_IB and IB_START ADRENO_IB_E_BUSY, FENCE
 * and FILL32 ADRENO_E_PARAMS, an UNMAP overlapping the in-flight package ADRENO_IB_E_BUSY. */
int adreno_ib_flight_refuse(struct adreno_state *s, struct adreno_ib_flight *f, uint64_t regs[4]);
/* vCPU 0's tick: 1 when it may poll CB0 faults and make the run fence (no flight), 0 while a flight is active. A
 * flight without a final status hz / ADRENO_IB_POLL_DIVISOR + grace ticks after its doorbell is finalized here
 * first (abandoned: one last pass, retired -> 0 or GPU_ERROR, else UNCERTAIN); *final gets that status, or
 * ADRENO_IB_PENDING when nothing ended. */
int adreno_ib_flight_tick(const struct adreno_ops *o, const struct adreno_params *p, struct adreno_state *s,
                          struct adreno_ib_flight *f, uint64_t grace, int *final);
/* The stop (every executor drained, before adreno_quiesce): poll an active flight until its final status, at most
 * `bound` ticks and never past its budget; then UNCERTAIN (stopped). 1 and *final when one was drained, else 0. */
int adreno_ib_flight_drain(const struct adreno_ops *o, const struct adreno_params *p, struct adreno_state *s,
                           struct adreno_ib_flight *f, uint64_t bound, int *final);

#ifndef SNAP_ADRENO_RECOVER
#define SNAP_ADRENO_RECOVER 0
#endif
#if SNAP_ADRENO_RECOVER
/* ---- SNAP_ADRENO_RECOVER: GPU hang recovery (agents/gpu-recovery FAILURE-MODES.md R1-R30; ABI adreno-guest.h) ------
 * 1: the flight's budget hz / ADRENO_IB_POLL_DIVISOR becomes soft (past it the flight is counted overdue and, after two
 *    passes, ended early only on hang evidence: an RBBM_INT_0 error bit, HANG_DETECT included, or a CP global fault);
 *    the flight ends UNCERTAIN at the hard limit ADRENO_IB_HARD_SECONDS; ADRENO_GUEST_RECOVER QUERY/SETTLE answer.
 * 2: also the CP soft reset (adreno_recover): a flight that ends UNCERTAIN or GPU_ERROR, a START refused with STICKY or
 *    RING, and a SETTLE that finds the CP busy reset the CP at EL2, and the flight's answer becomes ADRENO_IB_E_RESET
 *    (ADRENO_IB_E_RESET_FAULT after a CB0 fault). Every step proves itself; any failed proof gives up for the boot
 *    (DEAD: ring users refused before any write, flights answer as level 1 would), never worse than without it.
 * The flight's reserved words count: [0] flights that passed the soft budget, [1] flights ended by hang evidence,
 * [2] resets (the epoch); they ride in the IBASYNC1 record (tools/perf_counters.py decode_ib_async recover=True).
 * The rest of the state is struct adreno_recover_state, in root_ext after the flight (probes/xnuboot.c), under the
 * service token like everything here. */
#if SNAP_ADRENO_RECOVER != 1 && SNAP_ADRENO_RECOVER != 2
#error "SNAP_ADRENO_RECOVER is 1 (soft budget, settle) or 2 (also the CP soft reset)"
#endif
#ifndef ADRENO_IB_HARD_SECONDS
#define ADRENO_IB_HARD_SECONDS 3u
#endif
_Static_assert(ADRENO_IB_HARD_SECONDS >= 1 && ADRENO_IB_HARD_SECONDS <= ADRENO_IB_HARD_SECONDS_MAX,
               "the hard limit stays under IOGPU's 5 s waitForGPUTimeoutSeconds (R23)");
_Static_assert(ADRENO_IB_POLL_DIVISOR >= 1, "the soft budget is at most 1 s, under the hard limit");
#define ADRENO_IB_SOFT_TICKS(hz) ((hz) / ADRENO_IB_POLL_DIVISOR)
#define ADRENO_IB_HARD_TICKS(hz) ((hz) * (uint64_t)ADRENO_IB_HARD_SECONDS)
#define ADRENO_IB_FLIGHT_OVERDUE 2u          /* f->active bit: the flight passed the soft budget (counted once) */
#define ADRENO_RECOVER_BURST 4u              /* resets allowed within ADRENO_RECOVER_WINDOW_SECONDS (R24) */
#define ADRENO_RECOVER_WINDOW_SECONDS 60u
#define ADRENO_RECOVER_MAX 16u               /* resets per boot */
/* A8XX registers only the reset uses (Mesa a6xx.xml; tools/test-gen-adreno-recover-table.py checks the offsets). */
#define ADRENO_RBBM_INT_CLEAR_CMD 0x03d00184UL   /* A8XX_RBBM_INT_CLEAR_CMD 0x061 (W1C of RBBM_INT_0_STATUS) */
#define ADRENO_RBBM_SW_RESET_CMD 0x03d001ccUL    /* A8XX_RBBM_SW_RESET_CMD 0x073 */
#define ADRENO_GBIF_HALT 0x03d0f114UL            /* A6XX_GBIF_HALT 0x3c45 (CX GBIF: client 1, arbiter 2) */
#define ADRENO_GBIF_HALT_ACK 0x03d0f118UL        /* A6XX_GBIF_HALT_ACK 0x3c46 */
#define ADRENO_GBIF_SCACHE_CNTL0 0x03d0f004UL    /* q1n1 llcc-gpu (a8xx_llc_activate): the GPU's LLCC SCIDs, kept */
#define ADRENO_GBIF_SCACHE_CNTL1 0x03d0f008UL    /* across the reset (snapshot before, restored after the replay) */
#define ADRENO_RECOVER_SQE_BELOW_RING 0x20000UL  /* q1n1 ARENA_LAYOUT: cp_rb 0x140000 - cp_sqe 0x120000 */
#define ADRENO_RECOVER_SQE_BYTES 0x20000UL       /* cp_sqe size */
/* Causes (what started a recovery) and steps (where one gave up: dead = cause << 8 | step). */
enum { ADRENO_RECOVER_HARD = 1, ADRENO_RECOVER_EVIDENCE, ADRENO_RECOVER_FAULT, ADRENO_RECOVER_GPU_ERROR,
       ADRENO_RECOVER_STICKY, ADRENO_RECOVER_SETTLE_BUSY, ADRENO_RECOVER_UNCERTAIN };
enum { ADRENO_RECOVER_STEP_POLICY = 1, ADRENO_RECOVER_STEP_INIT, ADRENO_RECOVER_STEP_POWER, ADRENO_RECOVER_STEP_CB0,
       ADRENO_RECOVER_STEP_SQE_IMAGE, ADRENO_RECOVER_STEP_HALT_GX, ADRENO_RECOVER_STEP_HALT_CX,
       ADRENO_RECOVER_STEP_RESET, ADRENO_RECOVER_STEP_TABLE, ADRENO_RECOVER_STEP_SMC, ADRENO_RECOVER_STEP_RING,
       ADRENO_RECOVER_STEP_ME_INIT, ADRENO_RECOVER_STEP_SECVID, ADRENO_RECOVER_STEP_SCRUB, ADRENO_RECOVER_STEP_STICKY,
       ADRENO_RECOVER_STEP_AFTER, ADRENO_RECOVER_STEP_FENCE };
struct adreno_recover_state {
    uint64_t level;                         /* SNAP_ADRENO_RECOVER, or 1 when adreno_recover_init refused the reset */
    uint64_t init_refused;                  /* 0, or the step that kept level 2 from being armed */
    uint64_t epoch;                         /* successful resets */
    uint64_t dead;                          /* 0, or cause << 8 | step of the recovery that gave up */
    uint64_t attempts, failures, queries, settles, settle_resets, start_resets;
    uint64_t sqe_pa, sqe_sum;               /* q1n1's SQE image and its FNV-1a sum at prepare (R8) */
    uint64_t times[ADRENO_RECOVER_BURST];   /* counter value of the last resets, a ring indexed by epoch */
    uint64_t last_cause, last_ticks;        /* the last recovery: its cause and its own duration */
    uint64_t snap[8];                       /* before it: RBBM_STATUS, INT_0, CP_GLOBAL, RPTR, WPTR, FSR, sGFSR, SQE */
};
/* gpu_prepare, after adreno_adopt: level, the SQE region and its sum (level 2). */
void adreno_recover_init(const struct adreno_ops *o, const struct adreno_params *p, const struct adreno_state *s,
                         struct adreno_recover_state *rs);
/* The CP soft reset (level 2, not DEAD, no flight active). 0: reset, ring idle at the new WPTR, proving fence landed;
 * ADRENO_IB_E_UNCERTAIN at level 1; ADRENO_E_PARAMS when not adopted or quiesced (nothing written); otherwise
 * ADRENO_RECOVER_E_DEAD (rs->dead set). f, when given, gets the epoch in reserved[2]. */
int adreno_recover(const struct adreno_ops *o, const struct adreno_params *p, struct adreno_state *s,
                   struct adreno_ib_flight *f, struct adreno_recover_state *rs, int cause);
/* After a flight (POLL, tick) or START ended with final status e: at level 2, UNCERTAIN or GPU_ERROR become a reset
 * and ADRENO_IB_E_RESET(_FAULT); regs (the reply, may be NULL) and, for a flight, its stored reply follow. Returns the
 * status to answer. */
int adreno_recover_final(const struct adreno_ops *o, const struct adreno_params *p, struct adreno_state *s,
                         struct adreno_ib_flight *f, struct adreno_recover_state *rs, int e, int was_flight,
                         uint64_t regs[4]);
/* The dispatch's admission while DEAD (before any other check): IB, IB_START, FENCE and FILL32 are refused with
 * ADRENO_E_PARAMS before any write (regs hold the refusal); 0 admits. */
int adreno_recover_refuse(const struct adreno_recover_state *rs, struct adreno_state *s, uint64_t regs[4]);
/* IB_START with recovery: adreno_guest_ib_start, and at level 2 a START refused with STICKY or RING (no flight)
 * resets and is tried once more; a final UNCERTAIN/GPU_ERROR goes through adreno_recover_final. */
int adreno_recover_start(const struct adreno_ops *o, const struct adreno_params *p, struct adreno_state *s,
                         struct adreno_ib_flight *f, struct adreno_recover_state *rs, uint64_t regs[4],
                         uint64_t (*leaf)(void *ctx, uint64_t iova), void *leaf_ctx,
                         uint64_t mem_low, uint64_t mem_high);
/* ADRENO_GUEST_RECOVER (QUERY, SETTLE). */
int adreno_guest_recover(const struct adreno_ops *o, const struct adreno_params *p, struct adreno_state *s,
                         struct adreno_ib_flight *f, struct adreno_recover_state *rs, uint64_t regs[4]);
#endif
#endif
#if !SNAP_ADRENO_IB_ASYNC && defined(SNAP_ADRENO_RECOVER) && SNAP_ADRENO_RECOVER
#error "SNAP_ADRENO_RECOVER needs SNAP_ADRENO_IB_ASYNC (it ends asynchronous flights)"
#endif

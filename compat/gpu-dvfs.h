/* SPDX-License-Identifier: MIT */
/* SNAP_GPU_DVFS (probes/xnuboot.c): an opt-in Adreno X2-90 frequency governor
 * in the monitor (agents/dvfs FAILURE-MODES.md section 3).
 *
 * Why the monitor. The guest cannot reach the GMU (every GMU block is a trapped
 * class, compat/adreno.h), so any vote is sent by the monitor whoever decides
 * it. The monitor also owns the exact load signal: every guest IB, fence and
 * FILL32 is synchronous on its ring (adreno_guest_ib returns the completion
 * ticks in regs[2]); with SNAP_ADRENO_IB_ASYNC the monitor also knows the
 * flight in progress (its doorbell tick) under the service lock that the vCPU 0
 * tick also holds. The thermal guard lives here and
 * can clamp the GPU before the 95 C stop without a guest round trip, and the
 * stop path can restore the lowest OPP before gpu_quiesce. A kext-side
 * governor would need a new guest call that only asks the monitor to do the
 * same, plus an AuxKC relink, and would let the guest request any OPP.
 *
 * Mechanism (q1n1 tools/a16gpu_stage3.py hfi_send/hfi_wait_ack, Linux
 * a6xx_hfi_set_freq): HFI H2F GX_BW_PERF_VOTE {ack_type 1, perf index, bw
 * index} on the command queue in the GMU arena, doorbell GMU_HOST2GMU_INTR_SET,
 * acknowledged on the response queue (GMU2HOST_INTR_INFO.MSGQ). The perf and
 * bandwidth tables are the ones q1n1's hfi step sent: with --gpu-dvfs that step
 * runs --max-opps N --perf-opp 1 (N from cycle.py --gpu-dvfs-ceiling, default
 * 11 = 1700 MHz) and records N in the arena host record (hfi_opps, word 21);
 * the governor reads it at start and never votes a perf index past it (ABI 4,
 * agents/dvfs FAILURE-MODES.md section 9). The user approved every OPP up to
 * the chip maximum on 2026-10-21; 1850 MHz (RPMh 456) is not in the table
 * because the A16's mx.lvl tops out at 452 (q1n1 rail_refusal: refused rather
 * than an under-voted MX). SNAP_GPU_DVFS_MAX_OPP (a hard build cap) is at most
 * 11.
 *
 * Exceptions to adreno.h's "never writes the GMU", only under this define and
 * only these: GMU_HOST2GMU_INTR_SET, GMU_GMU2HOST_INTR_CLR, the HFI command and
 * response queues and their indices, and the host record's hfi_seq word (so
 * q1n1's next HFI message after the run continues the sequence).
 *
 * Policy (ABI 3, interactive; agents/dvfs FAILURE-MODES.md section 8). With
 * present-sync the GPU time of each frame sets the frame rate, so:
 *  - the first IB of a burst runs at the ceiling: the HVC path calls
 *    gpu_dvfs_kick just before the IB's or START's doorbell (no flight active),
 *    which votes the clamped ceiling when the clock is below it;
 *  - any GPU activity (an IB, START, fence or FILL32, or an IB still in flight)
 *    holds the ceiling for SNAP_GPU_DVFS_HOLD_MS (1.5 s) after it, so a short
 *    pause in a drag keeps 915 MHz; the tick also raises on activity it sees
 *    first (votes may land under a running CP, A8: as Linux's devfreq and
 *    present-deadline boosts do);
 *  - otherwise, every 50 ms window (Linux msm_gpu devfreq polls at 50 ms): busy
 *    = the completion ticks in the window; busy >= 90 % the ceiling, else the
 *    lowest OPP whose MHz covers busy x current MHz / 70 %; up at once, down
 *    after 3 windows in a row with no flight at the window's end;
 *  - thermal (G20): the ceiling falls 75 -> 85 C on the hottest sensor outside
 *    the CPU-core banks (die) and 88 -> 93 C on the hottest of all (hotspot,
 *    in practice the busiest Prime core), at once, 3 C hysteresis each.
 * A send that fails or times out latches the governor: no further HFI in this
 * run.
 *
 * Nothing here touches hardware; struct gpu_dvfs_io supplies MMIO and DRAM
 * words (the monitor: q1n1's EL2 identity map, as compat/adreno.c ADRENO_DIRECT)
 * and gpu_dvfs_address_allowed refuses anything else. tools/test-dvfs.c runs
 * this code against a GMU model that follows hfi_wait_ack's rules. */
#pragma once
#include <stddef.h>
#include <stdint.h>

#ifndef SNAP_GPU_DVFS_MAX_OPP
#define SNAP_GPU_DVFS_MAX_OPP 11
#endif
_Static_assert(SNAP_GPU_DVFS_MAX_OPP >= 1 && SNAP_GPU_DVFS_MAX_OPP <= 11,
               "OPP 11 = 1700 MHz (TURBO_L4) is the highest every A16 rail can carry; 1850 MHz has no MX corner");
#ifndef DVFS_WARM_MC
#define DVFS_WARM_MC 75000
#endif
#ifndef DVFS_HOT_MC
#define DVFS_HOT_MC 85000
#endif
#ifndef DVFS_HYST_MC
#define DVFS_HYST_MC 3000
#endif

#define GPU_DVFS_MAGIC UINT64_C(0x3153564644555047) /* GPUDVFS1 */
#define GPU_DVFS_ABI 4u
#define GPU_DVFS_OPPS 11u
#define GPU_DVFS_LEGACY_OPPS 6u        /* a host record without hfi_opps (q1n1 before ABI 4): --max-opps was 6 */
#define GPU_DVFS_WINDOW_MS 50u
#define GPU_DVFS_DOWN_WINDOWS 3u
#define GPU_DVFS_HISPEED_PCT 90u
#define GPU_DVFS_TARGET_PCT 70u
#define GPU_DVFS_SEND_MS 10u
#define GPU_DVFS_RACE_US 2000u      /* an IB this long counts as long (report only since ABI 3) */
/* G19: the ceiling is held this long after the last GPU activity (cycle.py --gpu-dvfs-hold). */
#ifndef SNAP_GPU_DVFS_HOLD_MS
#define SNAP_GPU_DVFS_HOLD_MS 1500
#endif
_Static_assert(SNAP_GPU_DVFS_HOLD_MS >= 300 && SNAP_GPU_DVFS_HOLD_MS <= 5000, "hold 300..5000 ms");
/* G20: two clamps. die: every valid sensor outside the CPU-core banks (tsens0/2/4); hotspot: all 92. */
#ifndef GPU_DVFS_DIE_WARM_MC
#define GPU_DVFS_DIE_WARM_MC 75000
#endif
#ifndef GPU_DVFS_DIE_HOT_MC
#define GPU_DVFS_DIE_HOT_MC 85000
#endif
#ifndef GPU_DVFS_SPOT_WARM_MC
#define GPU_DVFS_SPOT_WARM_MC 88000
#endif
#ifndef GPU_DVFS_SPOT_HOT_MC
#define GPU_DVFS_SPOT_HOT_MC 93000
#endif
_Static_assert(GPU_DVFS_DIE_WARM_MC < GPU_DVFS_DIE_HOT_MC && GPU_DVFS_SPOT_WARM_MC < GPU_DVFS_SPOT_HOT_MC &&
               GPU_DVFS_DIE_HOT_MC <= GPU_DVFS_SPOT_HOT_MC && GPU_DVFS_SPOT_HOT_MC < 95000,
               "both clamps reach OPP 1 below the thermal guard's 95 C stop");
/* 1: a vote may land while an IB is in flight (A8). 0: b12v4's rule, a change waits for the flight to end. */
#ifndef SNAP_GPU_DVFS_MIDFLIGHT
#define SNAP_GPU_DVFS_MIDFLIGHT 1
#endif

/* q1n1 adreno_x2.py GPU_OPPS rows 1..11 (glymur.dtsi gpu_opp_table; speed bin 1 allows all of them, RPMh levels
 * 56..452) and their peak bandwidths. The bw index of each GX_BW_PERF_VOTE is computed at start the way
 * a16gpu_stage3.perf_vote does it over the table q1n1 sent (O5): 1 + the distinct lower bandwidths among its OPPs. */
static const uint32_t GPU_DVFS_MHZ[GPU_DVFS_OPPS] = {310, 410, 572, 760, 820, 915, 1070, 1185, 1350, 1550, 1700};
static const uint32_t GPU_DVFS_LEVEL[GPU_DVFS_OPPS] = {56, 64, 128, 192, 224, 256, 320, 384, 416, 448, 452};
static const uint32_t GPU_DVFS_KBPS[GPU_DVFS_OPPS] = {2136719, 6074219, 12449219, 12449219, 16500000, 16500000,
                                                      16500000, 16500000, 18597657, 18597657, 18597657};

/* The arena (q1n1 adreno_x2.py ARENA_LAYOUT) and the GMU registers. */
#define GPU_DVFS_STATE_OFF  0x0100000u    /* host record ('state') */
#define GPU_DVFS_HFI_OFF    0x0114000u    /* 'gmu_hfi', 16 KiB */
#define GPU_DVFS_HFI_BYTES  0x0004000u
#define GPU_DVFS_HOST_MAGIC UINT64_C(0x3353363141314151)   /* "QA1A16S3" */
#define GPU_DVFS_HOST_SEQ   (7u * 8u)     /* HOST_FIELDS index 7: hfi_seq */
#define GPU_DVFS_HOST_BOOT  (5u * 8u)     /* index 5: boot_token (this GMU boot) */
#define GPU_DVFS_HOST_HFI   (6u * 8u)     /* index 6: hfi_token (the GMU boot whose HFI START was acked) */
#define GPU_DVFS_HOST_OPPS  (21u * 8u)    /* index 21: hfi_opps (O4; 0 in a record from q1n1 before ABI 4) */
#define GPU_DVFS_Q_HDR(q)   (24u + 48u * (q))
#define GPU_DVFS_Q_DATA(q)  (4096u * ((q) + 1u))
#define GPU_DVFS_Q_SIZE     3u            /* header word indices */
#define GPU_DVFS_Q_READ     10u
#define GPU_DVFS_Q_WRITE    11u
#define GPU_DVFS_Q_DWORDS   1024u
#define GPU_DVFS_GMU_INTR_CLR  0x03d7e644u   /* GMU_GMU2HOST_INTR_CLR (0x1f991) */
#define GPU_DVFS_GMU_INTR_INFO 0x03d7e648u   /* GMU_GMU2HOST_INTR_INFO (0x1f992), bit 0 MSGQ */
#define GPU_DVFS_GMU_DOORBELL  0x03d7e650u   /* GMU_HOST2GMU_INTR_SET (0x1f994) */
#define GPU_DVFS_MSGQ 1u
#define GPU_DVFS_MSG_VOTE 30u                /* HFI_H2F_MSG_GX_BW_PERF_VOTE */
#define GPU_DVFS_F2H_ACK 126u
#define GPU_DVFS_F2H_ERROR 100u
#define GPU_DVFS_TYPE_ACK 1u

struct gpu_dvfs_io {
    void *ctx;
    uint32_t (*rd32)(void *ctx, uint64_t pa);
    void (*wr32)(void *ctx, uint64_t pa, uint32_t value);
    void (*clean)(void *ctx, uint64_t pa, uint64_t size);   /* DC CIVAC by line, then DSB SY */
    uint64_t (*now)(void *ctx);                             /* CNTPCT */
    uint64_t hz;
};

enum gpu_dvfs_status { GPU_DVFS_OFF, GPU_DVFS_RUNNING, GPU_DVFS_LATCHED, GPU_DVFS_STOPPED };
enum gpu_dvfs_error {
    GPU_DVFS_OK, GPU_DVFS_E_RANGE = 1, GPU_DVFS_E_HOST = 2, GPU_DVFS_E_QUEUE = 3, GPU_DVFS_E_BUSY = 4,
    GPU_DVFS_E_TIMEOUT = 5, GPU_DVFS_E_NACK = 6, GPU_DVFS_E_RSP = 7, GPU_DVFS_E_ADDRESS = 8
};

struct gpu_dvfs_state {
    uint64_t magic, abi, status, reason;
    uint64_t hz, arena, window_ticks, next_window, windows;
    uint64_t opp, ceiling, below, below_target;
    uint64_t busy_ticks, last_busy_pct, submissions, window_submissions;
    uint64_t votes, acks, errors, last_error, last_seq, skipped_messages;
    uint64_t send_ticks_max, send_ticks_total, thermal_clamp, hispeed, restores;
    uint64_t pending, deferred, flight_ticks_seen;   /* a change waiting for the GPU to go idle (async IB) */
    int64_t thermal_eff_mc;                          /* hotspot as the clamp used: rises at once, falls past 3 C */
    uint64_t residency_ms[GPU_DVFS_OPPS + 1];   /* ms at each OPP (index 1..11; ABI <= 3: 1..6), at the window's end */
    /* ABI 2, race to idle. top: the thermally clamped ceiling of the last window; hot_until: CNTPCT; race_long /
     * race_burst: raises to the ceiling by a long IB / a burst; midflight_votes: votes sent with an IB in flight;
     * hot_ms: time held at the ceiling by a trigger; idle_downs: steps down to OPP 1; long_flights: IBs of
     * GPU_DVFS_RACE_US or more; flight_max_seen: the longest flight (ticks) that ended at one tick; started: CNTPCT
     * at the start. */
    uint64_t top, hot_until, race_long, race_burst, midflight_votes, hot_ms, idle_downs;
    uint64_t flights_seen, ended_seen, long_flights, flight_max_seen, started;
    /* ABI 3. race_first: raises by gpu_dvfs_kick before a doorbell; kicks: its calls; hold_ms: the build's hold;
     * die_mc / spot_mc: the last readings; die_eff_mc: die as the clamp used; clamp_die_ms / clamp_spot_ms: time
     * each clamp held the ceiling below SNAP_GPU_DVFS_MAX_OPP. (ABI 3 counts race_long for any raise the tick
     * makes on activity; race_burst stays 0: the per-IB kick replaced the burst rule.) */
    uint64_t race_first, kicks, hold_ms;
    int64_t die_mc, spot_mc, die_eff_mc;
    uint64_t clamp_die_ms, clamp_spot_ms;
    /* ABI 4. hfi_opps: the host record's word as read (0: none); bw_rows: the bw table's rows past the off row;
     * opp_flights[k]: flights that started and ended at OPP k with no vote between (bits 63..32: count, 31..0:
     * summed microseconds, saturating) -- the effective clock check of O10. */
    uint64_t hfi_opps, bw_rows;
    uint64_t opp_flights[GPU_DVFS_OPPS + 1];
    struct gpu_dvfs_private {
        uint64_t events_seen;
        uint64_t track, track_opp, track_votes;   /* the flight in progress as the tick first saw it */
        uint8_t bw[GPU_DVFS_OPPS + 1];
        uint8_t pad[(8 - (GPU_DVFS_OPPS + 1) % 8) % 8];
    } priv;                                  /* not reported */
};
#define GPU_DVFS_REPORT_WORDS (offsetof(struct gpu_dvfs_state, priv) / 8)
_Static_assert(offsetof(struct gpu_dvfs_state, priv) % 8 == 0, "report is whole words");

static inline int gpu_dvfs_address_allowed(const struct gpu_dvfs_state *s, uint64_t pa, int write)
{
    if (pa == GPU_DVFS_GMU_DOORBELL || pa == GPU_DVFS_GMU_INTR_CLR) return write;
    if (pa == GPU_DVFS_GMU_INTR_INFO) return !write;
    if (!s->arena || pa & 3) return 0;
    if (pa >= s->arena + GPU_DVFS_HFI_OFF && pa < s->arena + GPU_DVFS_HFI_OFF + GPU_DVFS_HFI_BYTES) return 1;
    return pa >= s->arena + GPU_DVFS_STATE_OFF && pa < s->arena + GPU_DVFS_STATE_OFF + 0x100 &&
           (!write || pa == s->arena + GPU_DVFS_STATE_OFF + GPU_DVFS_HOST_SEQ ||
            pa == s->arena + GPU_DVFS_STATE_OFF + GPU_DVFS_HOST_SEQ + 4);
}

static inline uint32_t gpu_dvfs_rd(struct gpu_dvfs_state *s, const struct gpu_dvfs_io *io, uint64_t pa)
{
    if (!gpu_dvfs_address_allowed(s, pa, 0)) { s->last_error = GPU_DVFS_E_ADDRESS; return 0xffffffffu; }
    return io->rd32(io->ctx, pa);
}

static inline int gpu_dvfs_wr(struct gpu_dvfs_state *s, const struct gpu_dvfs_io *io, uint64_t pa, uint32_t v)
{
    if (!gpu_dvfs_address_allowed(s, pa, 1)) { s->last_error = GPU_DVFS_E_ADDRESS; return -1; }
    io->wr32(io->ctx, pa, v);
    return 0;
}

/* A DRAM word the GMU shares a line with: CIVAC, store, CIVAC (q1n1 GPU_STORE32). */
static inline int gpu_dvfs_store(struct gpu_dvfs_state *s, const struct gpu_dvfs_io *io, uint64_t pa, uint32_t v)
{
    if (!gpu_dvfs_address_allowed(s, pa, 1)) { s->last_error = GPU_DVFS_E_ADDRESS; return -1; }
    io->clean(io->ctx, pa & ~UINT64_C(63), 64);
    io->wr32(io->ctx, pa, v);
    io->clean(io->ctx, pa & ~UINT64_C(63), 64);
    return 0;
}

/* Fresh view of a queue header (drop any line fetched before the GMU wrote). */
static inline void gpu_dvfs_header(struct gpu_dvfs_state *s, const struct gpu_dvfs_io *io, unsigned q,
                                   uint32_t *size, uint32_t *read, uint32_t *write)
{
    uint64_t h = s->arena + GPU_DVFS_HFI_OFF + GPU_DVFS_Q_HDR(q);
    io->clean(io->ctx, h & ~UINT64_C(63), (h & 63) + 48);
    *size = gpu_dvfs_rd(s, io, h + 4 * GPU_DVFS_Q_SIZE);
    *read = gpu_dvfs_rd(s, io, h + 4 * GPU_DVFS_Q_READ);
    *write = gpu_dvfs_rd(s, io, h + 4 * GPU_DVFS_Q_WRITE);
}

static inline int gpu_dvfs_queue_sane(uint32_t size, uint32_t read, uint32_t write)
{
    return size == GPU_DVFS_Q_DWORDS && read < size && write < size && !(read & 3) && !(write & 3);
}

/* Wait (bounded) for the command queue to drain: the GMU has taken every
 * command, so it no longer writes the line shared with the indices. */
static inline int gpu_dvfs_drained(struct gpu_dvfs_state *s, const struct gpu_dvfs_io *io, uint64_t deadline)
{
    for (unsigned n = 0;; n++) {
        uint32_t size, read, write;
        gpu_dvfs_header(s, io, 0, &size, &read, &write);
        if (!gpu_dvfs_queue_sane(size, read, write)) return GPU_DVFS_E_QUEUE;
        if (read == write) return 0;
        if (n >= 2 && (int64_t)(io->now(io->ctx) - deadline) > 0) return GPU_DVFS_E_BUSY;
    }
}

/* Consume response messages until the ack for (seq, msg). 1: matched (*status
 * = its error word), 0: queue empty without it, <0: corrupt queue. */
static inline int gpu_dvfs_responses(struct gpu_dvfs_state *s, const struct gpu_dvfs_io *io, uint32_t seq,
                                     uint32_t msg, uint32_t *status, uint64_t deadline)
{
    uint64_t data = s->arena + GPU_DVFS_HFI_OFF + GPU_DVFS_Q_DATA(1);
    uint64_t hdr = s->arena + GPU_DVFS_HFI_OFF + GPU_DVFS_Q_HDR(1);
    for (unsigned m = 0; m < GPU_DVFS_Q_DWORDS / 4 + 1; m++) {
        uint32_t size, read, write;
        gpu_dvfs_header(s, io, 1, &size, &read, &write);
        if (read == write) return 0;
        if (size != GPU_DVFS_Q_DWORDS || read >= size || write >= size) return -GPU_DVFS_E_RSP;
        io->clean(io->ctx, data + 4 * read - ((data + 4 * read) & 63), 128);
        uint32_t first = gpu_dvfs_rd(s, io, data + 4 * read);
        uint32_t dwords = first >> 8 & 0xff;
        if (dwords < 1 || dwords > 19) return -GPU_DVFS_E_RSP;
        uint32_t words[3] = {first, 0, 0}, at = read;
        for (uint32_t n = 0; n < dwords; n++) {
            if (n) {
                uint64_t pa = data + 4 * at;
                io->clean(io->ctx, pa & ~UINT64_C(63), 64);
                uint32_t w = gpu_dvfs_rd(s, io, pa);
                if (n < 3) words[n] = w;
            }
            at = (at + 1) % size;
        }
        at = ((at + 3) & ~3u) % size;
        /* The cmd read_index shares this line: let the GMU finish with it first. */
        int e = gpu_dvfs_drained(s, io, deadline);
        if (e) return -e;
        if (gpu_dvfs_store(s, io, hdr + 4 * GPU_DVFS_Q_READ, at)) return -GPU_DVFS_E_ADDRESS;
        uint32_t ident = words[0] & 0xff, kind = words[0] >> 16 & 0xf;
        int ack = ident == GPU_DVFS_F2H_ACK || (kind == GPU_DVFS_TYPE_ACK && ident == msg);
        if (ident == GPU_DVFS_F2H_ERROR || !ack || dwords < 3 || (words[1] >> 20 & 0xfff) != seq ||
            (words[1] & 0xff) != msg) {
            s->skipped_messages++;
            continue;
        }
        *status = words[2];
        return 1;
    }
    return -GPU_DVFS_E_RSP;
}

/* a6xx_hfi_send_msg for GX_BW_PERF_VOTE, bounded by GPU_DVFS_SEND_MS. 0 or an error. */
static inline int gpu_dvfs_send(struct gpu_dvfs_state *s, const struct gpu_dvfs_io *io, uint32_t perf, uint32_t bw)
{
    if (perf < 1 || perf > s->ceiling || perf > SNAP_GPU_DVFS_MAX_OPP || bw < 1 || bw > s->bw_rows)
        return GPU_DVFS_E_RANGE;
    uint64_t start = io->now(io->ctx), deadline = start + io->hz / 1000 * GPU_DVFS_SEND_MS;
    uint64_t host = s->arena + GPU_DVFS_STATE_OFF;
    io->clean(io->ctx, host, 64);
    uint64_t magic = gpu_dvfs_rd(s, io, host) | (uint64_t)gpu_dvfs_rd(s, io, host + 4) << 32;
    uint64_t arena = gpu_dvfs_rd(s, io, host + 16) | (uint64_t)gpu_dvfs_rd(s, io, host + 20) << 32;
    if (magic != GPU_DVFS_HOST_MAGIC || arena != s->arena) return GPU_DVFS_E_HOST;
    uint32_t size, read, write;
    gpu_dvfs_header(s, io, 0, &size, &read, &write);
    if (!gpu_dvfs_queue_sane(size, read, write)) return GPU_DVFS_E_QUEUE;
    if (read != write) return GPU_DVFS_E_BUSY;           /* G3: one command in flight, ever */
    io->clean(io->ctx, host + GPU_DVFS_HOST_SEQ, 8);
    uint32_t seq = (gpu_dvfs_rd(s, io, host + GPU_DVFS_HOST_SEQ) + 1) % 0xfff;
    const uint32_t words[4] = {(seq & 0xfff) << 20 | 4u << 8 | GPU_DVFS_MSG_VOTE, 1, perf, bw};
    uint64_t data = s->arena + GPU_DVFS_HFI_OFF + GPU_DVFS_Q_DATA(0);
    uint32_t at = write;
    for (unsigned n = 0; n < 4; n++) {
        if (gpu_dvfs_wr(s, io, data + 4 * at, words[n])) return GPU_DVFS_E_ADDRESS;
        io->clean(io->ctx, (data + 4 * at) & ~UINT64_C(63), 64);
        at = (at + 1) % size;
    }
    /* G6: the sequence is the host record's; written before the doorbell. */
    if (gpu_dvfs_wr(s, io, host + GPU_DVFS_HOST_SEQ, seq) || gpu_dvfs_wr(s, io, host + GPU_DVFS_HOST_SEQ + 4, 0))
        return GPU_DVFS_E_ADDRESS;
    io->clean(io->ctx, host + GPU_DVFS_HOST_SEQ, 8);
    s->last_seq = seq;
    uint64_t cmd = s->arena + GPU_DVFS_HFI_OFF + GPU_DVFS_Q_HDR(0);
    if (gpu_dvfs_store(s, io, cmd + 4 * GPU_DVFS_Q_WRITE, at)) return GPU_DVFS_E_ADDRESS;
    gpu_dvfs_wr(s, io, GPU_DVFS_GMU_DOORBELL, 1);
    s->votes++;
    for (;;) {
        if (gpu_dvfs_rd(s, io, GPU_DVFS_GMU_INTR_INFO) & GPU_DVFS_MSGQ) {
            gpu_dvfs_wr(s, io, GPU_DVFS_GMU_INTR_CLR, GPU_DVFS_MSGQ);
            uint32_t status = 0;
            int r = gpu_dvfs_responses(s, io, seq, GPU_DVFS_MSG_VOTE, &status, deadline);
            if (r < 0) return -r;
            if (r > 0) {
                uint64_t t = io->now(io->ctx) - start;
                s->send_ticks_total += t;
                if (t > s->send_ticks_max) s->send_ticks_max = t;
                if (status) return GPU_DVFS_E_NACK;
                s->acks++;
                return 0;
            }
        }
        if ((int64_t)(io->now(io->ctx) - deadline) > 0) return GPU_DVFS_E_TIMEOUT;
    }
}

static inline int gpu_dvfs_set(struct gpu_dvfs_state *s, const struct gpu_dvfs_io *io, uint32_t opp)
{
    if (s->status != GPU_DVFS_RUNNING || opp < 1 || opp > s->ceiling) return -1;
    int e = gpu_dvfs_send(s, io, opp, s->priv.bw[opp]);
    if (e) {
        /* G5: never send again in this run; a timeout leaves the GMU's state unknown. */
        s->errors++;
        s->last_error = (uint64_t)e;
        s->status = GPU_DVFS_LATCHED;
        return e;
    }
    s->opp = opp;
    return 0;
}

/* What the monitor knows of the GPU's work at a tick (SNAP_ADRENO_IB_ASYNC: struct adreno_ib_flight; all zero
 * with synchronous IBs, whose completions arrive through gpu_dvfs_busy). Counters are monotonic. */
struct gpu_dvfs_load {
    uint64_t active;       /* an IB is in flight */
    uint64_t start;        /* its doorbell, CNTPCT */
    uint64_t flights;      /* STARTs that went in flight */
    uint64_t ended;        /* flights that ended: finished + abandoned + stopped */
    uint64_t sum_ticks;    /* doorbell to final status, summed over ended flights */
};

/* G20: the thermal guard's last poll, two ways. spot_mc: the hottest of all sensors (A16 runs: a Prime core of the
 * vCPU cluster); die_mc: the hottest valid sensor outside the CPU-core banks, INT64_MIN when none. ready: a valid
 * poll and no trip (as cpu-dvfs.h). */
struct gpu_dvfs_thermal {
    int64_t spot_mc, die_mc;
    int ready;
};

/* O4/O5: the table q1n1 sent for this GMU boot (host record), the ceiling it allows, and each OPP's bw row.
 * 0 when usable; else the off reason (4: no HFI START recorded for this GMU boot, 5: host record of another arena). */
static inline unsigned gpu_dvfs_table(struct gpu_dvfs_state *s, const struct gpu_dvfs_io *io)
{
    uint64_t host = s->arena + GPU_DVFS_STATE_OFF;
    io->clean(io->ctx, host, 0x100);
    uint64_t magic = gpu_dvfs_rd(s, io, host) | (uint64_t)gpu_dvfs_rd(s, io, host + 4) << 32;
    uint64_t arena = gpu_dvfs_rd(s, io, host + 16) | (uint64_t)gpu_dvfs_rd(s, io, host + 20) << 32;
    if (magic != GPU_DVFS_HOST_MAGIC || arena != s->arena) return 5;
    uint64_t boot = gpu_dvfs_rd(s, io, host + GPU_DVFS_HOST_BOOT) |
                    (uint64_t)gpu_dvfs_rd(s, io, host + GPU_DVFS_HOST_BOOT + 4) << 32;
    uint64_t hfi = gpu_dvfs_rd(s, io, host + GPU_DVFS_HOST_HFI) |
                   (uint64_t)gpu_dvfs_rd(s, io, host + GPU_DVFS_HOST_HFI + 4) << 32;
    if (!boot || boot != hfi) return 4;
    s->hfi_opps = gpu_dvfs_rd(s, io, host + GPU_DVFS_HOST_OPPS) |
                  (uint64_t)gpu_dvfs_rd(s, io, host + GPU_DVFS_HOST_OPPS + 4) << 32;
    uint64_t n = s->hfi_opps ? s->hfi_opps : GPU_DVFS_LEGACY_OPPS;
    if (n > GPU_DVFS_OPPS) n = GPU_DVFS_OPPS;    /* a longer table only adds OPPs this monitor never votes */
    s->ceiling = n < SNAP_GPU_DVFS_MAX_OPP ? n : SNAP_GPU_DVFS_MAX_OPP;
    /* a16gpu_stage3.perf_vote: bws = [0] + sorted distinct bandwidths of the table's OPPs; index of each. */
    s->bw_rows = 0;
    for (unsigned k = 0; k < n; k++) {
        unsigned below = 0, seen = 0;
        for (unsigned j = 0; j < n; j++) {
            if (GPU_DVFS_KBPS[j] >= GPU_DVFS_KBPS[k]) continue;
            unsigned dup = 0;
            for (unsigned i = 0; i < j; i++) dup |= GPU_DVFS_KBPS[i] == GPU_DVFS_KBPS[j];
            if (!dup) below++;
        }
        for (unsigned i = 0; i < k; i++) seen |= GPU_DVFS_KBPS[i] == GPU_DVFS_KBPS[k];
        if (!seen) s->bw_rows++;
        s->priv.bw[k + 1] = (uint8_t)(1 + below);
    }
    return 0;
}

/* arena: q1n1's GPU arena (adreno_params.arena_base). The hfi step left the
 * GMU at OPP 1 (GX_BW_PERF_VOTE [1, 1, 1]); the governor starts there. io: reads the host record (O4). */
static inline void gpu_dvfs_start(struct gpu_dvfs_state *s, uint64_t hz, uint64_t arena, int thermal, uint64_t now,
                                  const struct gpu_dvfs_load *load, const struct gpu_dvfs_io *io)
{
    *s = (struct gpu_dvfs_state){.magic = GPU_DVFS_MAGIC, .abi = GPU_DVFS_ABI, .hz = hz, .arena = arena,
                                 .opp = 1, .ceiling = SNAP_GPU_DVFS_MAX_OPP, .top = 1,
                                 .flight_ticks_seen = load ? load->sum_ticks : 0,
                                 .flights_seen = load ? load->flights : 0, .ended_seen = load ? load->ended : 0,
                                 .thermal_eff_mc = INT64_MIN, .die_eff_mc = INT64_MIN, .die_mc = INT64_MIN,
                                 .spot_mc = INT64_MIN, .hold_ms = SNAP_GPU_DVFS_HOLD_MS};
    s->priv.events_seen = s->flights_seen;
    if (!thermal) { s->reason = 1; return; }
    if (!hz || !arena || arena & 0xfff || !io) { s->reason = 2; return; }
    unsigned why = gpu_dvfs_table(s, io);
    if (why) { s->reason = why; return; }
    s->window_ticks = hz / 1000 * GPU_DVFS_WINDOW_MS;
    s->next_window = now + s->window_ticks;
    s->started = now;
    s->status = GPU_DVFS_RUNNING;
}

/* From the guest IB/fence/FILL32 path (and a START that completed in its spin): the completion ticks of one
 * submission. Activity: the next tick holds (and if need be raises) the ceiling. */
static inline void gpu_dvfs_busy(struct gpu_dvfs_state *s, uint64_t ticks)
{
    if (s->status != GPU_DVFS_RUNNING) return;
    s->busy_ticks += ticks;
    s->submissions++;
    s->window_submissions++;
    if (ticks >= s->hz / 1000000u * GPU_DVFS_RACE_US) s->long_flights++;
}

/* G18: from the HVC path, just before an IB's or a START's doorbell, with no flight active and the service lock
 * held (as the vCPU 0 tick holds it). Holds the ceiling and, when the clock is below it, votes it now, so the first
 * IB of a burst runs at the ceiling. Returns 1 when a vote was sent and acknowledged. */
static inline int gpu_dvfs_kick(struct gpu_dvfs_state *s, const struct gpu_dvfs_io *io, uint64_t now)
{
    if (s->status != GPU_DVFS_RUNNING) return 0;
    s->kicks++;
    s->hot_until = now + s->hz / 1000u * SNAP_GPU_DVFS_HOLD_MS;
    if (s->opp >= s->top) return 0;
    s->race_first++;
    s->below = 0;
    s->pending = 0;
    return !gpu_dvfs_set(s, io, (uint32_t)s->top);
}

static inline int gpu_dvfs_due(const struct gpu_dvfs_state *s, uint64_t now)
{
    return s->status == GPU_DVFS_RUNNING && (int64_t)(now - s->next_window) >= 0;
}

static inline int64_t gpu_dvfs_thermal_effective(int64_t previous, int64_t mc)
{
    if (mc == INT64_MIN || previous == INT64_MIN || mc >= previous) return mc;
    return mc + DVFS_HYST_MC < previous ? mc + DVFS_HYST_MC : previous;
}

/* The ceiling one clamp allows: SNAP_GPU_DVFS_MAX_OPP up to warm, OPP 1 from hot, linear between. */
static inline uint32_t gpu_dvfs_clamp(uint32_t ceiling, int64_t t, int64_t warm, int64_t hot)
{
    if (t == INT64_MIN || t >= hot) return 1;
    if (t <= warm) return ceiling;
    uint64_t span = ceiling - 1u;
    uint64_t cut = ((uint64_t)(t - warm) * span + (uint64_t)(hot - warm - 1)) / (uint64_t)(hot - warm);
    return cut >= span ? 1u : (uint32_t)(ceiling - cut);
}

/* G7/A8: a vote while an IB is in flight. Linux votes whenever devfreq or a missed present deadline asks
 * (msm_gpu_devfreq.c msm_devfreq_target -> a6xx_gmu.c a6xx_gmu_set_freq -> a6xx_hfi_set_freq, and
 * msm_fence.c deadline_work -> msm_devfreq_boost while the fence is not signalled), so the GMU switches the
 * clock under a running CP. SNAP_GPU_DVFS_MIDFLIGHT 0 restores b12v4's rule: wait for the flight to end. */
static inline int gpu_dvfs_change(struct gpu_dvfs_state *s, const struct gpu_dvfs_io *io, uint32_t target,
                                  int gpu_active)
{
    if (gpu_active && !SNAP_GPU_DVFS_MIDFLIGHT) {
        if (s->pending != target) s->deferred++;   /* each decision once, however long the flight */
        s->pending = target;
        return 0;
    }
    s->pending = 0;
    if (gpu_active) s->midflight_votes++;
    return !gpu_dvfs_set(s, io, target);
}

/* Every locked tick of vCPU 0 (~1 kHz):
 *  - activity (a submission since the last tick, an IB in flight, a flight that ended) holds the ceiling for
 *    SNAP_GPU_DVFS_HOLD_MS and raises it now when the kick did not (a fence or FILL32, a synchronous IB);
 *  - every 50 ms window: the two thermal clamps (at once), then the hold keeps the ceiling, else the busy-fraction
 *    rule, down only after GPU_DVFS_DOWN_WINDOWS windows below and never while an IB is in flight; the clock thus
 *    leaves the ceiling SNAP_GPU_DVFS_HOLD_MS + 150 ms after the last activity at the earliest.
 * Returns 1 when a vote was sent and acknowledged. */
static inline int gpu_dvfs_tick(struct gpu_dvfs_state *s, const struct gpu_dvfs_io *io, uint64_t now,
                                const struct gpu_dvfs_thermal *th, const struct gpu_dvfs_load *load)
{
    if (s->status != GPU_DVFS_RUNNING || !load || !th) return 0;
    int active = load->active != 0;
    /* Flights that ended since the last tick count as busy in this window (G9). */
    uint64_t ended = load->ended - s->ended_seen, sum = load->sum_ticks - s->flight_ticks_seen;
    s->ended_seen = load->ended;
    s->flight_ticks_seen = load->sum_ticks;
    s->flights_seen = load->flights;
    s->busy_ticks += sum;
    if (ended) {
        uint64_t per = sum / ended;
        if (per >= s->hz / 1000000u * GPU_DVFS_RACE_US) s->long_flights += ended;
        if (per > s->flight_max_seen) s->flight_max_seen = per;
    }
    /* O10: a flight the tick saw in progress at one OPP, which ended with no vote since, counts for that OPP (flights
     * run one at a time; only the tick votes while one is in flight, the kick only before a doorbell). */
    if (ended == 1 && s->priv.track && s->votes == s->priv.track_votes && s->priv.track_opp <= GPU_DVFS_OPPS) {
        uint64_t w = s->opp_flights[s->priv.track_opp], us = sum * 1000000u / s->hz;
        uint64_t n = (w >> 32) + 1, t = (w & 0xffffffffu) + us;
        if (n <= 0xffffffffu) s->opp_flights[s->priv.track_opp] = n << 32 | (t > 0xffffffffu ? 0xffffffffu : t);
    }
    if (ended) s->priv.track = 0;
    if (active && !s->priv.track) {
        s->priv.track = load->flights;
        s->priv.track_opp = s->opp;
        s->priv.track_votes = s->votes;
    }
    uint64_t events = load->flights + s->submissions;
    int activity = events != s->priv.events_seen || active || ended;
    s->priv.events_seen = events;
    if (activity) {
        s->hot_until = now + s->hz / 1000u * SNAP_GPU_DVFS_HOLD_MS;
        if (s->opp < s->top && s->pending != s->top) {
            s->race_long++;
            s->below = 0;
            return gpu_dvfs_change(s, io, (uint32_t)s->top, active);
        }
    }
    if (s->pending && !active && !gpu_dvfs_due(s, now)) {
        uint32_t t = (uint32_t)s->pending;
        s->pending = 0;
        return !gpu_dvfs_set(s, io, t);
    }
    if (!gpu_dvfs_due(s, now)) return 0;
    uint64_t span = now - (s->next_window - s->window_ticks);
    if (!span) span = 1;
    s->windows++;
    s->next_window = now + s->window_ticks;
    uint64_t span_ms = span * 1000u / s->hz;
    if (s->opp <= GPU_DVFS_OPPS) s->residency_ms[s->opp] += span_ms;
    uint64_t busy = s->busy_ticks > span ? span : s->busy_ticks;   /* G9 */
    uint32_t pct = (uint32_t)(busy * 100u / span);
    s->busy_ticks = 0;
    s->window_submissions = 0;
    s->last_busy_pct = pct;
    /* G20: hotspot and die, each with its own hysteresis; no die reading -> the hotspot under the die's limits. */
    s->spot_mc = th->spot_mc;
    s->die_mc = th->die_mc;
    s->thermal_eff_mc = th->ready ? gpu_dvfs_thermal_effective(s->thermal_eff_mc, th->spot_mc) : INT64_MIN;
    int64_t die = th->die_mc != INT64_MIN ? th->die_mc : th->spot_mc;
    s->die_eff_mc = th->ready ? gpu_dvfs_thermal_effective(s->die_eff_mc, die) : INT64_MIN;
    uint32_t by_spot = gpu_dvfs_clamp((uint32_t)s->ceiling, s->thermal_eff_mc, GPU_DVFS_SPOT_WARM_MC,
                                      GPU_DVFS_SPOT_HOT_MC);
    uint32_t by_die = gpu_dvfs_clamp((uint32_t)s->ceiling, s->die_eff_mc, GPU_DVFS_DIE_WARM_MC, GPU_DVFS_DIE_HOT_MC);
    uint32_t ceiling = by_spot < by_die ? by_spot : by_die;
    if (by_spot < s->ceiling) s->clamp_spot_ms += span_ms;
    if (by_die < s->ceiling) s->clamp_die_ms += span_ms;
    s->top = ceiling;
    s->thermal_clamp = ceiling < s->ceiling ? s->thermal_clamp + 1 : 0;
    int hot = (int64_t)(s->hot_until - now) > 0;
    if (hot) s->hot_ms += span_ms;
    if (s->opp > ceiling) {                         /* C4/G20: at once */
        s->below = 0;
        return gpu_dvfs_change(s, io, ceiling, active);
    }
    uint32_t target;
    if (hot || pct >= GPU_DVFS_HISPEED_PCT) {
        target = ceiling;
        if (ceiling > s->opp && !hot) s->hispeed++;
    } else {
        uint64_t want = (uint64_t)GPU_DVFS_MHZ[s->opp - 1] * pct / GPU_DVFS_TARGET_PCT;
        target = ceiling;
        for (uint32_t o = 1; o <= ceiling; o++)
            if (GPU_DVFS_MHZ[o - 1] >= want) { target = o; break; }
    }
    if (target > ceiling) target = ceiling;
    if (target > s->opp) {
        s->below = 0;
        if (hot && s->pending != target) s->race_long++;   /* a hold raise the trigger made before the ceiling was known */
        return gpu_dvfs_change(s, io, target, active);
    }
    if (target < s->opp && !active) {
        if (!s->below || target > s->below_target) s->below_target = target;
        if (++s->below >= GPU_DVFS_DOWN_WINDOWS) {
            s->below = 0;
            if (s->below_target == 1) s->idle_downs++;
            return gpu_dvfs_change(s, io, (uint32_t)s->below_target, active);
        }
        return 0;
    }
    s->below = 0;
    if (target == s->opp) s->pending = 0;
    return 0;
}

/* G11: back to OPP 1 before gpu_quiesce; a latched governor sends nothing. */
static inline int gpu_dvfs_stop(struct gpu_dvfs_state *s, const struct gpu_dvfs_io *io)
{
    int e = 0;
    s->pending = 0;
    if (s->status == GPU_DVFS_RUNNING && s->opp != 1) e = gpu_dvfs_set(s, io, 1);
    if (s->status == GPU_DVFS_RUNNING) s->status = GPU_DVFS_STOPPED;
    s->restores++;
    return e;
}

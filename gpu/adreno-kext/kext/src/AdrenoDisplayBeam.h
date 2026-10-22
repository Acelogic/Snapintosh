/* SPDX-License-Identifier: MIT */
/* AdrenoDisplayBeam.h - the eDP interface's real scanout position (DPU INTF_5 LINE_COUNT/FRAME_COUNT) and a race-ahead
 * publication against it (--present-beam, -DADRENO_BEAM=1; agents/tear-free/FAILURE-MODES.md A-E). Header-only C shared
 * by AdrenoDisplay.cpp and tools/replay-adreno-presentation.c; every hardware access goes through adreno_beam_io, so the
 * replay drives the same decisions against a simulated scanout.
 *
 * Positions are absolute line counts ("pos"): frame F's line L is F * vtotal + L, L counted from the vsync start as the
 * timing engine counts (0-based after removing the counter's own base). Row r of frame F leaves the interface at line
 * F * vtotal + a0 + r; the DPU fetches it no earlier than `margin` lines before that (C4).
 *
 * One rule decides every write (C3): rows [y0, y1) of a present that targets frame T (row0 = T * vtotal + a0) may be
 * written once frame T-1 has output row y1-1 (pos >= row0 - vtotal + y1: wait, bounded) and while frame T has not begun
 * fetching row y0 (pos + margin < row0 + y0: else an overtake, counted). A present started a little before the vblank
 * therefore writes the rows the beam has passed at once, follows the beam over the last rows of frame T-1, and then runs
 * ahead of frame T; the copy is faster than the scan, so it stays ahead unless it stalls. Nothing here writes the DPU. */
#pragma once
#include <stdint.h>
#include <string.h>
#ifdef KERNEL
#include <libkern/libkern.h>     /* snprintf */
#else
#include <stdio.h>
#endif
#include "../../../../compat/dpu-intf.h"

/* --present-latch (agents/input-latency FAILURE-MODES.md L1-L9): -DADRENO_LATCH=1 aims the fire late in the blank, `slack`
 * before row 0 of the targeted frame leaves (less the margin and a slow copy's excess), instead of `lead` before the
 * vblank start; an overtake or a LATE fire doubles the slack (up to the whole blank, which is today's aim) and clean GOs
 * decay it back. Slack 0 is today's arithmetic. Off by default; without it this header compiles as before. */
#ifndef ADRENO_LATCH
#define ADRENO_LATCH 0
#endif

enum { ADRENO_BEAM_OFF = 0, ADRENO_BEAM_REFUSED = 1, ADRENO_BEAM_UNCAL = 2, ADRENO_BEAM_LOCKED = 3, ADRENO_BEAM_STALLED = 4 };
enum {
    ADRENO_BEAM_R_NONE = 0, ADRENO_BEAM_R_PROPERTY = 1, ADRENO_BEAM_R_ADDRESS = 2, ADRENO_BEAM_R_MAP = 3,
    ADRENO_BEAM_R_ATTR = 4, ADRENO_BEAM_R_ENGINE = 5, ADRENO_BEAM_R_HTOTAL = 6, ADRENO_BEAM_R_VTOTAL = 7,
    ADRENO_BEAM_R_HEIGHT = 8, ADRENO_BEAM_R_AVR = 9, ADRENO_BEAM_R_FROZEN = 10, ADRENO_BEAM_R_MODULUS = 11,
    ADRENO_BEAM_R_PERIOD = 12, ADRENO_BEAM_R_INCONSISTENT = 13, ADRENO_BEAM_R_RETRIES = 14, ADRENO_BEAM_R_STALL = 15,
    ADRENO_BEAM_R_DRIFT = 16
};
/* adreno_beam_fire outcomes */
enum { ADRENO_BEAM_GO = 0, ADRENO_BEAM_EARLY = 1, ADRENO_BEAM_LATE = 2, ADRENO_BEAM_FORCED = 3, ADRENO_BEAM_UNARMED = 4,
       ADRENO_BEAM_FAILED = 5 };

#define ADRENO_BEAM_MARGIN 32u               /* lines: fetch lead (Linux x1e prog fetch worst case 24) + write slack */
#define ADRENO_BEAM_TICK_NS 16666667ull      /* WindowServer keeps the published 60 Hz: vblanks per tick n */
#define ADRENO_BEAM_RETRIES 4u               /* failed recalibrations before REFUSED for the session (D4) */
#define ADRENO_BEAM_STALL_TICKS 64u          /* timer-path ticks before a stalled beam recalibrates (D4) */

_Static_assert(DPU_INTF_LAST_READ < DPU_INTF_PAGE, "every beam read stays inside the one mapped page (A1)");
_Static_assert(DPU_INTF_PA == 0x0AE3A000ULL, "INTF_5 = mdp 0x0ae01000 + 0x34000 + 5 * 0x1000 (A1)");

struct adreno_beam_io {
    uint32_t (*read)(void *ctx, uint32_t offset);   /* one 32-bit read of the INTF page; never a write (A3) */
    uint64_t (*now)(void *ctx);                      /* the timebase (mach_absolute_time in the kext) */
    void *ctx;
};

struct adreno_beam_regs {
    uint32_t engine, config, hsync_ctl, vsync_period, disp_v_start, disp_v_end, act_v_start, act_v_end;
    uint32_t disp_hctl, act_hctl, config2, count_en, status, avr;
};
static inline void adreno_beam_read_regs(const struct adreno_beam_io *io, struct adreno_beam_regs *r)
{
    r->engine = io->read(io->ctx, DPU_INTF_TIMING_ENGINE_EN);
    r->config = io->read(io->ctx, DPU_INTF_CONFIG);
    r->hsync_ctl = io->read(io->ctx, DPU_INTF_HSYNC_CTL);
    r->vsync_period = io->read(io->ctx, DPU_INTF_VSYNC_PERIOD_F0);
    r->disp_v_start = io->read(io->ctx, DPU_INTF_DISPLAY_V_START_F0);
    r->disp_v_end = io->read(io->ctx, DPU_INTF_DISPLAY_V_END_F0);
    r->act_v_start = io->read(io->ctx, DPU_INTF_ACTIVE_V_START_F0);
    r->act_v_end = io->read(io->ctx, DPU_INTF_ACTIVE_V_END_F0);
    r->disp_hctl = io->read(io->ctx, DPU_INTF_DISPLAY_HCTL);
    r->act_hctl = io->read(io->ctx, DPU_INTF_ACTIVE_HCTL);
    r->config2 = io->read(io->ctx, DPU_INTF_CONFIG2);
    r->count_en = io->read(io->ctx, DPU_INTF_FRAME_LINE_COUNT_EN);
    r->status = io->read(io->ctx, DPU_INTF_STATUS);
    r->avr = io->read(io->ctx, DPU_INTF_AVR_CONTROL);
}

struct adreno_beam_timing {
    uint32_t htotal, vtotal;                 /* pixel clocks per line, lines per frame */
    uint32_t a0, a1;                         /* first and last active line */
    uint32_t width, wide, width_ok;          /* active width as programmed (pixel pairs with widebus), recorded only */
};

/* B1: the timing the engine runs, from the registers, or a refusal reason. Linux dpu_hw_intf_setup_timing_engine:
 * VSYNC_PERIOD_F0 = vtotal * htotal; DISPLAY_V_START/END_F0 bound the active lines in pixel clocks (DP adds a pixel
 * offset inside the line, so a floor division gives the line); ACTIVE_V_* replace them when INTF_CONFIG bit 30 is set. */
static inline int adreno_beam_decode(const struct adreno_beam_regs *r, uint32_t width, uint32_t height,
                                     struct adreno_beam_timing *t)
{
    memset(t, 0, sizeof *t);
    if (!(r->status & 1u) && !(r->engine & 1u)) return ADRENO_BEAM_R_ENGINE;
    if (r->avr) return ADRENO_BEAM_R_AVR;
    const uint32_t ht = r->hsync_ctl >> 16;
    if (ht < 16) return ADRENO_BEAM_R_HTOTAL;
    /* vtotal from the registers themselves: VSYNC_PERIOD_F0 is a whole number of lines, longer than the active height.
     * No CVT range: the A16's eDP panel runs 60 Hz on a 120 Hz-class pixel clock by a 2040-line blank (vtotal 3840,
     * survey 2026-10-21); the calibrated frame period (4..50 ms) bounds the rest. */
    const uint32_t vt = r->vsync_period / ht;
    if (!height || r->vsync_period % ht || vt <= height || vt > 8 * height) return ADRENO_BEAM_R_VTOTAL;
    uint32_t vs = r->disp_v_start, ve = r->disp_v_end;
    if ((r->config & DPU_INTF_CFG_ACTIVE_V_EN) && r->act_v_end > r->act_v_start) { vs = r->act_v_start; ve = r->act_v_end; }
    /* The active span starts inside line vs / ht (DP: hsync + back porch pixels in) and covers ceil(span / ht) lines;
     * Linux's DP ACTIVE_V_END runs hpw + hbp pixels past the frame's last pixel clock, so the end is not divided. */
    if (ve < vs) return ADRENO_BEAM_R_HEIGHT;
    const uint32_t a0 = vs / ht, lines = (uint32_t)(((uint64_t)ve - vs + ht) / ht), a1 = a0 + lines - 1;
    if (lines != height || a1 >= vt) return ADRENO_BEAM_R_HEIGHT;
    const uint32_t hctl = ((r->config & (1u << 29)) && r->act_hctl) ? r->act_hctl : r->disp_hctl;
    const uint32_t hs = hctl & 0xffffu, he = hctl >> 16;
    t->htotal = ht; t->vtotal = vt; t->a0 = a0; t->a1 = a1;
    t->width = he >= hs ? he - hs + 1 : 0;
    t->wide = r->config2 & DPU_INTF_CFG2_WIDEN;
    t->width_ok = t->width == width || (t->wide && 2 * t->width == width);
    return ADRENO_BEAM_R_NONE;
}

/* D3: the GPU node's two properties, as the kext finds them (raw bytes, little-endian). */
static inline int adreno_beam_check_property(const void *abi, uint64_t abi_len, const void *pa, uint64_t pa_len)
{
    uint32_t a = 0; uint64_t p = 0;
    if (!abi || abi_len != sizeof a || !pa || pa_len != sizeof p) return ADRENO_BEAM_R_PROPERTY;
    memcpy(&a, abi, sizeof a); memcpy(&p, pa, sizeof p);
    if (a != DPU_INTF_ABI) return ADRENO_BEAM_R_PROPERTY;
    if (p != DPU_INTF_PA) return ADRENO_BEAM_R_ADDRESS;
    return ADRENO_BEAM_R_NONE;
}
/* A4: PAR_EL1.ATTR of the kernel mapping (or 0x100 | FST on a fault) is a Device encoding: 0b0000dd00, or with FEAT_XS
 * 0b0000dd01 (the same Device type, XS=0). SPTM 26A428's MAIR_EL1 is 0x00000000010000ff, so XNU's I/O index 3 reads
 * 0x01: Device-nGnRnE (b12v4 refused it as 0x1). Normal (upper nibble set), the reserved dd1x and faults are refused. */
static inline int adreno_beam_attr_ok(uint64_t attr) { return attr < 0x10 && !(attr & 0x2); }

struct adreno_beam {
    uint32_t state, reason;
    struct adreno_beam_timing t;
    uint32_t height, margin, n, line_base, fc_ok, fc_line, recal_failures, drift_n, early_n;
    uint64_t tpms;                           /* timebase ticks per millisecond */
    uint64_t frame, line_fp;                 /* ticks per frame; ticks per line << 16 */
    /* the last sample: time, position, raw line and frame counter */
    uint64_t s_t, s_pos, fc_hi;
    uint32_t s_line, s_fc;
    /* the tick */
    uint64_t target;                         /* the armed vblank start (pos of frame T-1's last active line + 1); 0 none */
    uint64_t last_tick;                      /* the last GO's vblank start */
    uint64_t armed_fire;                     /* the time the fire was meant for */
    uint32_t deferrals;                      /* consecutive late re-targets (C1) */
    uint64_t go_row0;                        /* the frame a GO chose for its layer-0 present (adreno_beam_begin takes it) */
    uint64_t row0;                           /* the present's frame: pos where its row 0 leaves; 0 = choose at the first gate */
    uint64_t band_lo, band_hi;               /* rows a dynamic present may write (C7) */
    uint64_t spin_budget;                    /* lines the current present may still wait */
    uint32_t cursor;                         /* the current present is cursor-only (C7 counters) */
    uint32_t stalled_ticks;
    uint64_t lead, late_hi, maint, copy_hi;  /* ticks: fire lead, decaying maxima of fire lateness and of the layer-0 copy,
                                              * and the maintenance estimate */
    uint64_t copy_last;                      /* the previous copy, so one stalled copy alone does not raise copy_hi */
    /* this window (the perf beam line) */
    uint64_t go, late, forced, early, unarmed, ovt, ovt_row, spins, spin_lines, spin_max, cur_waits, cur_capped;
    uint64_t stalls, glitches, fc_bad, recal, phase_max, gates, capped;
#if ADRENO_LATCH
    /* L1-L9: the latch. slack_base 0 = today's aim. latch_off: lines from the targeted vblank start to the fire point,
     * fixed when the target is chosen (adreno_beam_target, a LATE re-target). present_ovt: overtakes of the present
     * running now. This window: the slack's peak, raises by overtake and by LATE, lines of the last offset. */
    uint64_t slack_base, slack, slack_peak;
    uint64_t latch_off;
    uint32_t present_ovt;
    uint64_t slack_ovt, slack_late;
#endif
};

static inline uint64_t adreno_beam_lines(const struct adreno_beam *b, uint64_t ticks)
{
    return b->line_fp ? (ticks << 16) / b->line_fp : 0;      /* ticks < 2^47 here */
}
static inline uint64_t adreno_beam_ticks(const struct adreno_beam *b, uint64_t lines) { return (lines * b->line_fp) >> 16; }

static inline void adreno_beam_init(struct adreno_beam *b, uint64_t tpms, uint32_t height)
{
    memset(b, 0, sizeof *b);
    b->tpms = tpms ? tpms : 1; b->height = height; b->margin = ADRENO_BEAM_MARGIN; b->n = 1;
    b->state = ADRENO_BEAM_OFF;
}
static inline void adreno_beam_refuse(struct adreno_beam *b, uint32_t reason) { b->state = ADRENO_BEAM_REFUSED; b->reason = reason; }
/* D1 D2: a stop, restart or mode set: the next arm recalibrates; nothing armed, no frame chosen. */
static inline void adreno_beam_reset(struct adreno_beam *b)
{
    if (b->state == ADRENO_BEAM_LOCKED || b->state == ADRENO_BEAM_STALLED) b->state = ADRENO_BEAM_UNCAL;
    b->target = b->last_tick = b->armed_fire = b->row0 = b->go_row0 = 0; b->deferrals = 0;
}

/* B6: one LINE_COUNT read, 0-based, or -1 after a second implausible read (counted). A value one line outside the
 * counter's range (0 or vtotal + 1 against a 1-based counter, vtotal against a 0-based one) is clamped to its edge. */
static inline int64_t adreno_beam_line(struct adreno_beam *b, const struct adreno_beam_io *io)
{
    for (unsigned i = 0; i < 2; i++) {
        uint32_t l = io->read(io->ctx, DPU_INTF_LINE_COUNT);
        if (l + 1 >= b->line_base && l <= b->line_base + b->t.vtotal) {
            const int64_t x = (int64_t)l - (int64_t)b->line_base;
            return x < 0 ? 0 : x >= (int64_t)b->t.vtotal ? (int64_t)b->t.vtotal - 1 : x;
        }
    }
    b->glitches++;
    return -1;
}
/* The position from FRAME_COUNT and LINE_COUNT (fc_ok). FRAME_COUNT advances at line fc_line, so lines before it belong
 * to the frame it will count next. A pair is taken only when FRAME_COUNT read the same before and after LINE_COUNT and
 * the line is more than 2 lines from fc_line (the turn's jitter, and calibration's +-1): within ~5 lines of re-reads.
 * 0 = glitch (B6). */
static inline uint64_t adreno_beam_pos_fc(struct adreno_beam *b, const struct adreno_beam_io *io)
{
    const uint32_t vt = b->t.vtotal;
    uint32_t f1 = 0, f2 = 1; int64_t l = -1;
    for (unsigned tries = 0; tries < 256; tries++) {
        f1 = io->read(io->ctx, DPU_INTF_FRAME_COUNT);
        l = adreno_beam_line(b, io);
        f2 = io->read(io->ctx, DPU_INTF_FRAME_COUNT);
        if (l < 0 || f1 != f2) continue;
        const uint32_t dd = ((uint32_t)l + vt - b->fc_line) % vt;
        if (dd <= 2 || vt - dd <= 2) continue;
        break;
    }
    if (l < 0 || f1 != f2) { b->glitches++; return 0; }
    uint32_t d = f1 - b->s_fc;
    if (d > 0x7fffffffu) { b->glitches++; return 0; }            /* backwards */
    uint64_t f = b->fc_hi + d + ((uint64_t)l < b->fc_line ? 1 : 0);
    b->s_fc = f1; b->fc_hi += d;
    return f * b->t.vtotal + (uint64_t)l;
}

/* A timed sample: the position and the time (B3 B4 B5). Without a usable FRAME_COUNT the wraps since the last sample
 * come from the elapsed time; after a very long gap the position re-anchors (whole frames from the time, no drift
 * check). Two phase errors over 8 lines in a row, each over at least a quarter frame, mark the timing for
 * recalibration (a rate change, a frozen counter). */
static inline uint64_t adreno_beam_sample(struct adreno_beam *b, const struct adreno_beam_io *io, uint64_t *now_out)
{
    const uint64_t vt = b->t.vtotal;
    uint64_t pos, l;
    if (b->fc_ok) {
        pos = adreno_beam_pos_fc(b, io);
        if (!pos) return 0;
        l = pos % vt;
    } else {
        int64_t r = adreno_beam_line(b, io);
        if (r < 0) return 0;
        l = (uint64_t)r; pos = 0;
    }
    const uint64_t t = io->now(io->ctx), dt = t - b->s_t;
    const int near = dt < (b->frame << 10);
    const uint64_t exp = near ? adreno_beam_lines(b, dt) : 0;
    if (!b->fc_ok) {
        const uint64_t dl = (l + vt - b->s_line) % vt;
        uint64_t k;
        if (near) k = exp >= dl ? (exp - dl + vt / 2) / vt : 0;
        else k = dt / (b->frame ? b->frame : 1);
        pos = b->s_pos + k * vt + dl;
    }
    if (near && dt >= b->frame / 4 && b->state == ADRENO_BEAM_LOCKED) {
        const uint64_t got = pos - b->s_pos;
        const uint64_t err = got > exp ? got - exp : exp - got;
        if (err > b->phase_max) b->phase_max = err;
        if (err > 8) {
            if (++b->drift_n >= 2) { b->state = ADRENO_BEAM_UNCAL; b->reason = ADRENO_BEAM_R_DRIFT; b->recal++; b->drift_n = 0; }
        } else b->drift_n = 0;
    }
    b->s_t = t; b->s_pos = pos; b->s_line = (uint32_t)l;
    if (now_out) *now_out = t;
    return pos;
}

/* B2 B3: three to five wraps of LINE_COUNT, bounded by iterations and by 250 ms of the timebase. Sets the line time,
 * the counter's base and modulus, whether FRAME_COUNT tracks the wraps (and at which line it turns), n, and the anchor.
 * Returns a reason (0 = LOCKED). Reads only LINE_COUNT and FRAME_COUNT, plus the timebase at each wrap. */
static inline int adreno_beam_calibrate(struct adreno_beam *b, const struct adreno_beam_io *io)
{
    const uint32_t vt = b->t.vtotal;
    if (!vt) return ADRENO_BEAM_R_VTOTAL;
    uint32_t fprev = io->read(io->ctx, DPU_INTF_FRAME_COUNT), prev = io->read(io->ctx, DPU_INTF_LINE_COUNT);
    uint32_t lmin = prev, lmax = prev, fc_line = UINT32_MAX, fc_line_bad = 0, fc_changes = 0;
    uint64_t t_wrap[6]; uint32_t l_wrap[6], f_wrap[6]; unsigned wraps = 0;
    const uint64_t t0 = io->now(io->ctx), limit = 250 * b->tpms;
    for (uint64_t iter = 1; wraps < 6 && iter < 8000000; iter++) {
        if (!(iter & 1023) && io->now(io->ctx) - t0 > limit) break;
        /* FRAME_COUNT before and after the line: a turn between the two reads leaves the line ambiguous by one, so it
         * is noted by the next pair, whose line is past the turn */
        const uint32_t f = io->read(io->ctx, DPU_INTF_FRAME_COUNT), l = io->read(io->ctx, DPU_INTF_LINE_COUNT);
        const uint32_t f2 = io->read(io->ctx, DPU_INTF_FRAME_COUNT);
        if (l > 2 * vt + 2) { b->glitches++; continue; }
        if (l < lmin) lmin = l;
        if (l > lmax) lmax = l;
        if (f == f2 && f != fprev) {
            fc_changes++;
            if (fc_line == UINT32_MAX) fc_line = l;
            else {
                const uint32_t dd = (l + vt - fc_line % vt) % vt;     /* circular distance to the first turn's line */
                if (dd > 2 && vt - dd > 2) fc_line_bad++;
            }
            fprev = f;
        }
        if (l + vt / 2 < prev) {
            t_wrap[wraps] = io->now(io->ctx); l_wrap[wraps] = l; f_wrap[wraps] = f2; wraps++;
        }
        prev = l;
    }
    if (wraps < 3) return lmax == lmin ? ADRENO_BEAM_R_FROZEN : ADRENO_BEAM_R_PERIOD;
    /* the counter's range: 0..vt-1 or 1..vt (the A16: 1..3840); a few lines missed at the wrap are tolerated */
    const uint32_t base = lmax >= vt ? 1u : 0u;
    if (lmax > vt || lmax + 8 < vt || lmin > base + 8) return ADRENO_BEAM_R_MODULUS;
    /* ticks per frame from each pair of consecutive wraps; a median, and at least two intervals within 0.5% of it */
    uint64_t fr[5]; unsigned m = 0;
    for (unsigned i = 0; i + 1 < wraps; i++) {
        const uint64_t lines = (uint64_t)vt + l_wrap[i + 1] - l_wrap[i];
        fr[m++] = (t_wrap[i + 1] - t_wrap[i]) * vt / (lines ? lines : 1);
    }
    for (unsigned i = 1; i < m; i++) for (unsigned j = i; j && fr[j] < fr[j - 1]; j--) { uint64_t x = fr[j]; fr[j] = fr[j - 1]; fr[j - 1] = x; }
    const uint64_t frame = fr[m / 2];
    unsigned close = 0;
    for (unsigned i = 0; i < m; i++) if ((fr[i] > frame ? fr[i] - frame : frame - fr[i]) * 200 <= frame) close++;
    if (close < 2) return ADRENO_BEAM_R_INCONSISTENT;
    if (frame < 4 * b->tpms || frame > 50 * b->tpms) return ADRENO_BEAM_R_PERIOD;
    b->line_base = base;
    b->frame = frame;
    b->line_fp = (frame << 16) / vt;
    /* FRAME_COUNT: one step per wrap at one line, or it is only counted (fc_bad) and the time resolves the wraps */
    int fc = fc_line != UINT32_MAX && !fc_line_bad && fc_line - base < vt;
    for (unsigned i = 0; fc && i + 1 < wraps; i++) if (f_wrap[i + 1] - f_wrap[i] != 1) fc = 0;
    if (!fc && fc_changes) b->fc_bad++;
    b->fc_ok = (uint32_t)fc;
    b->fc_line = fc ? fc_line - base : 0;
    const uint64_t floor_ticks = b->tpms * ADRENO_BEAM_TICK_NS * 3 / 4 / 1000000u;     /* 12.5 ms */
    uint64_t n = (floor_ticks + frame - 1) / frame;
    b->n = n < 1 ? 1 : n > 4 ? 4 : (uint32_t)n;
    /* the anchor: the last wrap, 64 frames in, so a position is never 0 */
    const uint32_t la = l_wrap[wraps - 1] - base;
    b->s_t = t_wrap[wraps - 1]; b->s_line = la; b->s_pos = 64ull * vt + la;
    b->s_fc = f_wrap[wraps - 1]; b->fc_hi = 64 - (fc && la < b->fc_line ? 1 : 0);
    b->drift_n = 0;
    b->target = b->last_tick = b->armed_fire = b->row0 = b->go_row0 = 0; b->deferrals = 0;   /* positions renumbered */
    if (!b->lead) b->lead = b->tpms * 3 / 2;
    b->state = ADRENO_BEAM_LOCKED; b->reason = ADRENO_BEAM_R_NONE;
    return ADRENO_BEAM_R_NONE;
}

/* C3 C5: a layer-0 copy took `ticks`. A copy slower than the scan of the active rows is started earlier by the
 * difference: it then follows frame T-1's beam (the gate's wait) and stays ahead of frame T's. */
static inline void adreno_beam_copied(struct adreno_beam *b, uint64_t ticks)
{
    const uint64_t two = ticks < b->copy_last ? ticks : b->copy_last;      /* the smaller of the last two copies */
    b->copy_last = ticks;
    b->copy_hi = two > b->copy_hi ? two : b->copy_hi - b->copy_hi / 64;    /* a slow animation is remembered ~1 s */
}
static inline uint64_t adreno_beam_excess(const struct adreno_beam *b)
{
    const uint64_t scan = adreno_beam_ticks(b, b->height), excess = b->copy_hi > scan ? b->copy_hi - scan : 0;
    return excess < 5 * b->tpms ? excess : 5 * b->tpms;
}
/* The first vblank start (frame F's last active line + 1) after pos. */
static inline uint64_t adreno_beam_next_vblank(const struct adreno_beam *b, uint64_t pos)
{
    const uint64_t vt = b->t.vtotal;
    uint64_t v = pos / vt * vt + b->t.a1 + 1;
    while (v <= pos) v += vt;
    return v;
}
/* Lines a present needs before the vblank: its maintenance pass, and a slow copy's excess over the scan. */
static inline uint64_t adreno_beam_head(const struct adreno_beam *b)
{
    return adreno_beam_lines(b, b->maint + adreno_beam_excess(b)) + 4;
}
#if ADRENO_LATCH
/* L3 L8 L9: lines from a vblank start to the latch point: its frame's row 0 (vt - a1 - 1 + a0 lines on) less the margin,
 * 2, a slow copy's excess and the slack. 0 when the slack is off or does not fit: today's aim. */
static inline uint64_t adreno_beam_latch_lines(const struct adreno_beam *b)
{
    if (!b->slack || !b->t.vtotal) return 0;
    const uint64_t gap = (uint64_t)b->t.vtotal - b->t.a1 - 1 + b->t.a0;
    const uint64_t back = (uint64_t)b->margin + 2 + adreno_beam_lines(b, adreno_beam_excess(b) + b->slack);
    return gap > back ? gap - back : 0;
}
/* L9: the slack (ticks) at which the offset is 0, the cap. */
static inline uint64_t adreno_beam_slack_cap(const struct adreno_beam *b)
{
    return adreno_beam_ticks(b, (uint64_t)b->t.vtotal - b->t.a1 - 1 + b->t.a0);
}
/* L1 L2: an overtake or a LATE fire doubles the slack, up to the cap; a clean layer-0 present decays it by 1/64 toward
 * its base. */
static inline void adreno_beam_slack_raise(struct adreno_beam *b)
{
    if (!b->slack_base) return;
    const uint64_t cap = adreno_beam_slack_cap(b);
    b->slack = b->slack >= cap / 2 ? cap : 2 * b->slack;
    if (b->slack > b->slack_peak) b->slack_peak = b->slack;
}
static inline void adreno_beam_slack_decay(struct adreno_beam *b)
{
    if (b->slack > b->slack_base) b->slack -= (b->slack - b->slack_base + 63) / 64;
}
/* The latch's base slack in ticks (0 = off, today's aim): the kext at start, the replay per scenario. */
static inline void adreno_beam_latch(struct adreno_beam *b, uint64_t slack)
{
    b->slack_base = b->slack = b->slack_peak = slack;
    b->latch_off = 0;
}
#endif
/* The vblank to arm for at pos (C1 C6): from a GO, n frames after it, skipping frames already too close; otherwise the
 * first vblank at least the present's head start away, and never sooner than n frames after the last GO. */
static inline uint64_t adreno_beam_target(struct adreno_beam *b, uint64_t pos, int in_tick)
{
    const uint64_t vt = b->t.vtotal, nv = (uint64_t)b->n * vt, min = adreno_beam_head(b);
    uint64_t target;
#if ADRENO_LATCH
    /* L3 L4: the first vblank whose latch point (off lines on) is at least the head start away: a vblank already passed
     * still qualifies while its frame's blank has room. Never sooner than n frames after the last GO. off 0 is the
     * code below. */
    const uint64_t off = adreno_beam_latch_lines(b);
    b->latch_off = off;
    if (in_tick && b->last_tick) {
        target = b->last_tick + nv;
        while (target + off < pos + min) target += vt;
    } else {
        target = adreno_beam_next_vblank(b, pos + min > off ? pos + min - off : 0);
        if (b->last_tick && target < b->last_tick + nv) target = b->last_tick + nv;
    }
#else
    if (in_tick && b->last_tick) {
        target = b->last_tick + nv;
        while (target < pos + min) target += vt;
    } else {
        target = adreno_beam_next_vblank(b, pos + min);
        if (b->last_tick && target < b->last_tick + nv) target = b->last_tick + nv;
    }
#endif
    b->target = target;
    return target;
}
/* When the timer should fire for b->target, from the sample (now, pos): lead ticks before the vblank, never past. */
static inline uint64_t adreno_beam_fire_time(struct adreno_beam *b, uint64_t now, uint64_t pos)
{
#if ADRENO_LATCH
    const uint64_t aim = b->target + b->latch_off;     /* L3: the latch point, lead ticks before it */
    const uint64_t at = now + adreno_beam_ticks(b, aim > pos ? aim - pos : 0);
#else
    const uint64_t at = now + adreno_beam_ticks(b, b->target > pos ? b->target - pos : 0);
#endif
    const uint64_t fire = at > now + b->lead ? at - b->lead : now;
    b->armed_fire = fire;
    return fire;
}
/* The frame a GO publishes into: the one after the targeted vblank. */
static inline uint64_t adreno_beam_row0(const struct adreno_beam *b, uint64_t target)
{
    return target - b->t.a1 - 1 + b->t.vtotal + b->t.a0;
}

/* C1 C2: the timer fired at now with the beam at pos. Adapts the lead: the decaying maximum of the fire lateness, the
 * maintenance estimate, a slow copy's excess over the scan, and 250 us (0.4 ms .. 3 ms plus the excess). EARLY and LATE
 * leave b->target armed-for (the caller re-arms for it); GO and FORCED choose the present's frame (FORCED and UNARMED:
 * at its first gate). */
static inline int adreno_beam_fire(struct adreno_beam *b, uint64_t now, uint64_t pos)
{
    if (!pos) { b->target = 0; b->go_row0 = 0; return ADRENO_BEAM_FAILED; }   /* B6: no decision; an ordinary tick */
    const uint64_t ms = b->tpms;
    if (b->armed_fire) {
        const uint64_t late = now > b->armed_fire ? now - b->armed_fire : 0;
        b->late_hi = late > b->late_hi ? late : b->late_hi - b->late_hi / 16;
        const uint64_t excess = adreno_beam_excess(b), lead = b->late_hi + b->maint + excess + ms / 4;
        b->lead = lead < ms * 2 / 5 ? ms * 2 / 5 : lead > 3 * ms + excess ? 3 * ms + excess : lead;
        b->armed_fire = 0;
    }
    if (!b->target) { b->unarmed++; b->go_row0 = 0; return ADRENO_BEAM_UNARMED; }
    /* the last position a race can start from: frame T's fetch of row 0, less the margin, less a slow copy's excess */
    const uint64_t row0 = adreno_beam_row0(b, b->target), back = b->margin + 2 + adreno_beam_lines(b, adreno_beam_excess(b));
    const uint64_t limit = row0 > back ? row0 - back : 0;
#if ADRENO_LATCH
    if (pos + adreno_beam_lines(b, (b->lead > 2 * ms ? b->lead + ms : 3 * ms)) < b->target + b->latch_off) {
#else
    if (pos + adreno_beam_lines(b, (b->lead > 2 * ms ? b->lead + ms : 3 * ms)) < b->target) {
#endif
        b->early++;
        if (++b->early_n < 3) return ADRENO_BEAM_EARLY;
        /* D4: three early fires in a row: the beam does not advance as predicted; the timer path takes over */
        b->early_n = 0; b->stalls++; b->state = ADRENO_BEAM_STALLED; b->reason = ADRENO_BEAM_R_STALL; b->stalled_ticks = 0;
        b->target = 0; b->go_row0 = 0;
        return ADRENO_BEAM_FAILED;
    }
    b->early_n = 0;
    if (pos >= limit) {
        if (b->deferrals < 2) {
            b->deferrals++; b->late++;
#if ADRENO_LATCH
            if (b->slack_base) { adreno_beam_slack_raise(b); b->slack_late++; }     /* L1: start earlier from now on */
            {
                const uint64_t off = adreno_beam_latch_lines(b), head = adreno_beam_head(b);
                b->latch_off = off;
                b->target = adreno_beam_next_vblank(b, pos + head > off ? pos + head - off : 0);
            }
#else
            b->target = adreno_beam_next_vblank(b, pos + adreno_beam_head(b));
#endif
            return ADRENO_BEAM_LATE;
        }
        b->forced++; b->deferrals = 0; b->last_tick = b->target; b->target = 0; b->go_row0 = 0;
        return ADRENO_BEAM_FORCED;
    }
    b->go++; b->deferrals = 0; b->last_tick = b->target; b->target = 0; b->go_row0 = row0;
    return ADRENO_BEAM_GO;
}

/* Before a present: its spin allowance, its frame (a layer-0 present takes the GO's, once; a cursor-only one, and a
 * layer-0 one after FORCED or UNARMED, choose at the first gate) and the rows it may write. */
static inline void adreno_beam_begin(struct adreno_beam *b, int cursor_only, uint64_t band_lo, uint64_t band_hi)
{
    b->cursor = (uint32_t)cursor_only;
    const uint64_t layer0 = b->lead + b->tpms > 3 * b->tpms ? b->lead + b->tpms : 3 * b->tpms;
    b->spin_budget = adreno_beam_lines(b, cursor_only ? b->tpms : layer0);
    b->band_lo = band_lo; b->band_hi = band_hi;
    b->row0 = cursor_only ? 0 : b->go_row0;
    if (!cursor_only) b->go_row0 = 0;
#if ADRENO_LATCH
    b->present_ovt = 0;
#endif
}
#if ADRENO_LATCH
/* L2: after a layer-0 present, an overtake raises the slack and a clean one decays it. */
static inline void adreno_beam_end(struct adreno_beam *b)
{
    if (!b->cursor && b->slack_base) {
        if (b->present_ovt) { adreno_beam_slack_raise(b); b->slack_ovt++; }
        else adreno_beam_slack_decay(b);
    }
    b->row0 = 0; b->cursor = 0; b->present_ovt = 0;
}
#else
static inline void adreno_beam_end(struct adreno_beam *b) { b->row0 = 0; b->cursor = 0; }
#endif

/* Wait until pos >= need, reading LINE_COUNT only (no timebase trap per read): forward steps under half a frame, a
 * bounded number of lines and of reads, and a timebase check every 4096 reads. A counter that does not move is a stall
 * (D4). Returns the position reached; 0 after a stall. */
static inline uint64_t adreno_beam_spin(struct adreno_beam *b, const struct adreno_beam_io *io, uint64_t pos, uint64_t need)
{
    const uint64_t vt = b->t.vtotal, start = pos, budget = b->spin_budget;
    const uint64_t cap = 4000 * (budget + 4) + 100000;      /* a backstop only: the timebase check below ends a stall */
    uint64_t prev = pos % vt, t0 = 0;
    for (uint64_t iter = 1; pos < need; iter++) {
        if (pos - start >= budget) { b->capped++; if (b->cursor) b->cur_capped++; break; }
        if (iter > cap) goto stall;
        if (!(iter & 4095)) {
            const uint64_t t = io->now(io->ctx);
            if (!t0) t0 = t;
            else if (t - t0 > adreno_beam_ticks(b, budget + 8) + b->tpms) goto stall;
        }
        const int64_t l = adreno_beam_line(b, io);
        if (l < 0) continue;
        const uint64_t d = ((uint64_t)l + vt - prev) % vt;
        if (d > vt / 2) { b->glitches++; continue; }
        pos += d; prev = (uint64_t)l;
    }
    {
        const uint64_t spun = pos - start;
        b->spins++; b->spin_lines += spun; if (spun > b->spin_max) b->spin_max = spun;
        b->spin_budget = spun < budget ? budget - spun : 0;
        if (b->cursor) b->cur_waits++;
    }
    return pos;
stall:
    b->stalls++; b->state = ADRENO_BEAM_STALLED; b->reason = ADRENO_BEAM_R_STALL; b->stalled_ticks = 0;
    return 0;
}

/* C3 C7: before the first write into rows [y0, y1) of the present. */
static inline void adreno_beam_gate(struct adreno_beam *b, const struct adreno_beam_io *io, uint64_t y0, uint64_t y1)
{
    if (b->state != ADRENO_BEAM_LOCKED) return;
    b->gates++;
    uint64_t pos = b->fc_ok ? adreno_beam_pos_fc(b, io) : adreno_beam_sample(b, io, 0);
    if (!pos) return;
    const uint64_t vt = b->t.vtotal;
    if (!b->row0) {
        /* the frame for the whole band: this frame's, while the beam is still above it, else the next one's */
        const uint64_t here = pos / vt * vt + b->t.a0;
        b->row0 = pos + b->margin + 2 < here + b->band_lo ? here : here + vt;
    }
    const uint64_t need = b->row0 - vt + y1;
    if (pos < need) {
        pos = adreno_beam_spin(b, io, pos, need);
        if (!pos) return;
    }
    if (pos + b->margin >= b->row0 + y0) {
        if (!b->ovt) b->ovt_row = y0;
        b->ovt++;
#if ADRENO_LATCH
        b->present_ovt++;
#endif
    }
}

/* ---- the perf beam line (E4) ---- */
struct adreno_beam_summary {
    uint64_t state, reason, frame_ns, vtotal, a0, a1, n, fc, lead_us, spin_us, spin_max_us, go, late, forced, early;
    uint64_t ovt, ovt_row, cur_waits, cur_capped, stalls, glitches, recal, phase_max;
};
static inline void adreno_beam_summarize(const struct adreno_beam *b, uint64_t (*to_ns)(uint64_t), struct adreno_beam_summary *s)
{
    memset(s, 0, sizeof *s);
    s->state = b->state; s->reason = b->reason; s->frame_ns = to_ns(b->frame); s->vtotal = b->t.vtotal;
    s->a0 = b->t.a0; s->a1 = b->t.a1; s->n = b->n; s->fc = b->fc_ok;
    s->lead_us = to_ns(b->lead) / 1000u;
    s->spin_us = b->spins ? to_ns(adreno_beam_ticks(b, b->spin_lines / b->spins)) / 1000u : 0;
    s->spin_max_us = to_ns(adreno_beam_ticks(b, b->spin_max)) / 1000u;
    s->go = b->go; s->late = b->late; s->forced = b->forced; s->early = b->early; s->ovt = b->ovt; s->ovt_row = b->ovt_row;
    s->cur_waits = b->cur_waits; s->cur_capped = b->cur_capped; s->stalls = b->stalls; s->glitches = b->glitches;
    s->recal = b->recal; s->phase_max = b->phase_max;
}
static inline void adreno_beam_next_window(struct adreno_beam *b)
{
    b->go = b->late = b->forced = b->early = b->unarmed = b->ovt = b->ovt_row = b->spins = b->spin_lines = b->spin_max = 0;
    b->cur_waits = b->cur_capped = b->stalls = b->glitches = b->fc_bad = b->recal = b->phase_max = 0;
    b->gates = b->capped = 0;
#if ADRENO_LATCH
    b->slack_peak = b->slack; b->slack_ovt = b->slack_late = 0;
#endif
}
#ifndef ADRENO_PERF_CAP
#define ADRENO_PERF_CAP 999999999ull
#endif
static inline unsigned long long adreno_beam_cap(uint64_t v, uint64_t cap) { return (unsigned long long)(v < cap ? v : cap); }
/* E4: at most ADRENO_PERF_LINE_MAX bytes with every field at its cap (the replay checks it): counts at 999999999, the
 * bounded fields (state, reason, vtotal, n, us of lead and spin, rows, lines) at caps of their own. */
static inline int adreno_perf_line_beam(char *buf, size_t size, uint64_t seq, const struct adreno_beam_summary *s)
{
    const uint64_t C = ADRENO_PERF_CAP;
    return snprintf(buf, size, "AdrenoDisplay: perf beam s=%llu st=%llu/%llu fr=%llu vt=%llu n=%llu lead=%llu "
                    "spin=%llu/%llu tk=%llu/%llu/%llu/%llu ovt=%llu/%llu cur=%llu/%llu stall=%llu gl=%llu rs=%llu ph=%llu",
                    adreno_beam_cap(seq, C), adreno_beam_cap(s->state, 9), adreno_beam_cap(s->reason, 99),
                    adreno_beam_cap(s->frame_ns, C), adreno_beam_cap(s->vtotal, 99999), adreno_beam_cap(s->n, 9),
                    adreno_beam_cap(s->lead_us, 99999), adreno_beam_cap(s->spin_us, 99999), adreno_beam_cap(s->spin_max_us, 99999),
                    adreno_beam_cap(s->go, C), adreno_beam_cap(s->late, C), adreno_beam_cap(s->forced, C), adreno_beam_cap(s->early, C),
                    adreno_beam_cap(s->ovt, C), adreno_beam_cap(s->ovt_row, 9999), adreno_beam_cap(s->cur_waits, C),
                    adreno_beam_cap(s->cur_capped, C), adreno_beam_cap(s->stalls, C), adreno_beam_cap(s->glitches, C),
                    adreno_beam_cap(s->recal, C), adreno_beam_cap(s->phase_max, 99999));
}

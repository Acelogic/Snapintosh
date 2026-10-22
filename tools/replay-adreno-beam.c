/* SPDX-License-Identifier: MIT */
/* --present-beam (agents/tear-free FAILURE-MODES.md, written before the code): included by
 * tools/replay-adreno-presentation.c when built with -DADRENO_BEAM=1.
 *
 * A scanout model (an eDP timing engine: a line counter, a frame counter, the DPU fetching each row of each frame at its
 * line minus a fetch lead) runs against the production presentation path: AdrenoDisplayPresent.h's
 * adreno_display_present on 1800-row surfaces, with AdrenoDisplayBeam.h's gate, and a model of AdrenoDisplay.cpp's frame
 * path (swap_begin_gated, armFrameTimerGated, vsyncGated, presentGated) under two policies: GRID, the deployed
 * --present-vsync60 tick (16,666,667 ns grid, off-tick copies on arrival), and BEAM. Simulated time advances with every
 * register read, timebase read, maintained row, read/hashed chunk and written span, at the A16's measured per-row costs
 * (installed-fresh-desktop-20261021-b11v1 perf split: maint 0.22, read 0.5, hash 0.9 ms per 1800 rows).
 *
 * Every row a present writes is logged with its time and content version; every frame the DPU scans is rebuilt row by
 * row from those logs at each row's fetch time. A frame is torn when it is not exactly the image of one swap. */
#include <math.h>
#include "../gpu/adreno-kext/kext/src/AdrenoDisplayBeam.h"
#if ADRENO_PRESENT_SYNC
#include "../gpu/adreno-kext/kext/src/AdrenoDisplaySync.h"
#endif

enum { BW = 16, BH = 1800, BROW = BW * 4, BRING = 8 };
enum { GRID = 0, BEAM = 1 };
#define US 1000ull

struct scan {
    uint64_t line_ps, line_ps2, change_at;    /* ps per line; from change_at (ns) on, line_ps2 */
    uint32_t vt, a0, a1, base, fc_line, fetch_lead, modulus;
    uint64_t freeze_from, freeze_until;       /* the counters hold still (ns) */
    uint32_t garbage_every;                   /* every Nth LINE_COUNT read returns garbage */
    int fc_off, counts_off;
    uint32_t fc_start;
    struct adreno_beam_regs regs;
};
static uint64_t scan_pos(const struct scan *s, uint64_t t)
{
    if (!s->change_at || t <= s->change_at) return t * 1000 / s->line_ps;
    return s->change_at * 1000 / s->line_ps + (t - s->change_at) * 1000 / s->line_ps2;
}
static uint64_t scan_time(const struct scan *s, uint64_t pos)
{
    const uint64_t pc = s->change_at ? s->change_at * 1000 / s->line_ps : UINT64_MAX;
    if (pos <= pc) return (pos * s->line_ps + 999) / 1000;
    return s->change_at + ((pos - pc) * s->line_ps2 + 999) / 1000;
}
/* Registers as Linux dpu_hw_intf_setup_timing_engine programs a DP interface with widebus (B1): the vertical front
 * porch folded into the back porch, horizontal values in pixel pairs, ACTIVE_H/V enabled. */
static struct adreno_beam_regs dp_regs(uint32_t width, uint32_t height, uint32_t vt, int wide)
{
    struct adreno_beam_regs r; memset(&r, 0, sizeof r);
    const uint32_t div = wide ? 2 : 1, w = width / div, hfp = 8 / div, hpw = 32 / div, hbp = 40 / div;
    const uint32_t ht = w + hfp + hpw + hbp, vpw = 6, vbp = vt - height - vpw;
    r.engine = 1; r.status = 1; r.hsync_ctl = ht << 16 | hpw; r.vsync_period = vt * ht;
    r.disp_v_start = (vpw + vbp) * ht + hpw + hbp; r.disp_v_end = vt * ht - 1 - hfp;
    r.act_v_start = r.disp_v_start; r.act_v_end = r.act_v_start + height * ht - 1;
    r.disp_hctl = r.act_hctl = (hpw + hbp + w - 1) << 16 | (hpw + hbp);
    r.config = 1u << 29 | DPU_INTF_CFG_ACTIVE_V_EN; r.config2 = wide ? DPU_INTF_CFG2_WIDEN : 0; r.count_en = 3;
    return r;
}
/* The A16, as surveyed on 2026-10-21 (operator-20261021-wifi/dpu-intf-survey-20261021.json): widebus, no ACTIVE_V,
 * htotal 1540 pixel pairs, vtotal 3840, active lines 2040..3839, 59.51 Hz, LINE_COUNT 1..3840, AVR off. */
static struct adreno_beam_regs a16_regs(void)
{
    struct adreno_beam_regs r; memset(&r, 0, sizeof r);
    r.engine = 1; r.status = 1; r.config = 0; r.hsync_ctl = 0x6040010; r.vsync_period = 0x5a3c00;
    r.disp_v_start = 0x2ff044; r.disp_v_end = 0x5a3bff; r.disp_hctl = 0x6030064; r.config2 = 0x101; r.count_en = 0;
    return r;
}
static void scan_init(struct scan *s, double hz, uint32_t vt)
{
    memset(s, 0, sizeof *s);
    s->vt = vt; s->a0 = vt - BH; s->a1 = vt - 1; s->modulus = vt; s->fetch_lead = 24;
    s->line_ps = (uint64_t)(1e12 / (hz * vt) + 0.5);
    s->regs = dp_regs(2880, BH, vt, 1);
}

struct rowlog { uint64_t t[BRING]; uint32_t v[BRING]; uint8_t head; };
struct bworld {
    struct scan s;
    int policy, margin_zero, maint_slow;
    struct adreno_beam b; struct adreno_vsync v; struct ktimer k;
    uint64_t rng, now, tb_off; int tb24;
    /* the frame path (AdrenoDisplay) */
    int current, presented, armed, in_tick, queued; uint64_t fire_at, ready_at, queued_at, render_min, render_max;
    unsigned swap, swaps;
    /* stalls: per present, and heavy timer tails */
    unsigned stall_pct, tail_pct; uint64_t stall_min, stall_max, tail_min, tail_max; int stall_chunk; uint64_t stall_ns;
    unsigned full_every; uint64_t write_ns; uint64_t last_copy_t, min_copy_gap;
    uint64_t reset_at; int reset_done;
    /* the present's clock phases */
    unsigned clocks, clock_base; uint64_t first_row;
    /* content */
    uint32_t ver[BH]; uint32_t chg[BH][BRING]; uint8_t chg_head[BH]; struct rowlog log[BH];
    uint64_t ready_time[4096], shown_time[4096]; unsigned shown_next;
    /* results */
    uint64_t frames, torn, eval_frame, presents, off_tick, lat_sum, lat_n, lat_max, min_gap, last_fire, fires, spins_ns;
    uint64_t first_present_t, last_present_t, unknown;
    struct adreno_display_damage dmg; struct adreno_display_present_workspace ws; uint8_t *src, *dst;
#if ADRENO_PRESENT_SYNC
    /* present sync (agents/present-sync K1 K4): gpu_pct of the swaps arrive while their GPU write still runs
     * gpu_min..gpu_max; sg is AdrenoDisplay's gate (off unless initialised); unfinished: copies that started before it ended */
    unsigned gpu_pct; uint64_t gpu_min, gpu_max, gpu_end, unfinished; struct adreno_sync_gate sg;
#endif
};
static uint64_t brnd(struct bworld *w) { return vrnd(&w->rng); }
static uint64_t tb(const struct bworld *w, uint64_t t) { return w->tb_off + (w->tb24 ? t * 24 / 1000 : t); }
static uint64_t tb_ns(const struct bworld *w, uint64_t x) { x -= w->tb_off; return w->tb24 ? x * 1000 / 24 : x; }
static uint64_t tb_ms(const struct bworld *w) { return w->tb24 ? 24000 : 1000000; }

/* ---- the hardware: one read costs 150 ns, one timebase read (a monitor trap in the guest) 700 ns ---- */
static uint32_t b_read(void *ctx, uint32_t off)
{
    struct bworld *w = ctx;
    w->now += 150;
    const struct scan *s = &w->s;
    uint64_t t = w->now;
    if (s->freeze_until && t >= s->freeze_from && t < s->freeze_until) t = s->freeze_from;
    const uint64_t pos = scan_pos(s, t);
    switch (off) {
    case DPU_INTF_LINE_COUNT:
        if (s->counts_off) return 0;
        if (s->garbage_every && !(brnd(w) % s->garbage_every)) return 0xffffffffu;
        return (uint32_t)(pos % s->modulus) + s->base;
    case DPU_INTF_FRAME_COUNT:
        if (s->counts_off || s->fc_off) return 0;
        return s->fc_start + (uint32_t)((pos + s->vt - s->fc_line) / s->vt);
    case DPU_INTF_TIMING_ENGINE_EN: return s->regs.engine;
    case DPU_INTF_CONFIG: return s->regs.config;
    case DPU_INTF_HSYNC_CTL: return s->regs.hsync_ctl;
    case DPU_INTF_VSYNC_PERIOD_F0: return s->regs.vsync_period;
    case DPU_INTF_DISPLAY_V_START_F0: return s->regs.disp_v_start;
    case DPU_INTF_DISPLAY_V_END_F0: return s->regs.disp_v_end;
    case DPU_INTF_ACTIVE_V_START_F0: return s->regs.act_v_start;
    case DPU_INTF_ACTIVE_V_END_F0: return s->regs.act_v_end;
    case DPU_INTF_DISPLAY_HCTL: return s->regs.disp_hctl;
    case DPU_INTF_ACTIVE_HCTL: return s->regs.act_hctl;
    case DPU_INTF_CONFIG2: return s->regs.config2;
    case DPU_INTF_FRAME_LINE_COUNT_EN: return s->regs.count_en;
    case DPU_INTF_STATUS: return s->regs.status;
    case DPU_INTF_AVR_CONTROL: return s->regs.avr;
    default: CHECK(!"a read outside the allow-listed registers"); return 0;   /* A1 */
    }
}
static uint64_t b_now(void *ctx) { struct bworld *w = ctx; w->now += 700; return tb(w, w->now); }
static const struct adreno_beam_io *bio(struct bworld *w)
{
    static struct adreno_beam_io io; io.read = b_read; io.now = b_now; io.ctx = w; return &io;
}

/* ---- the display: rebuild each scanned frame from the row logs ---- */
static void log_write(struct bworld *w, uint64_t y, uint32_t v)
{
    struct rowlog *l = &w->log[y];
    l->head = (uint8_t)((l->head + 1) % BRING); l->t[l->head] = w->now; l->v[l->head] = v;
}
static int visible_at(const struct bworld *w, uint64_t y, uint64_t t, uint32_t *v)
{
    const struct rowlog *l = &w->log[y];
    for (unsigned i = 0; i < BRING; i++) {
        unsigned k = (l->head + BRING - i) % BRING;
        if (l->t[k] <= t && (l->t[k] || l->v[k] == 0)) { *v = l->v[k]; return 1; }
    }
    return 0;
}
/* the content of swap p in row y: its last change at or before p */
static int version_of(const struct bworld *w, uint64_t y, uint32_t p, uint32_t *v)
{
    uint32_t best = 0; int found = 0;
    for (unsigned i = 0; i < BRING; i++) {
        uint32_t c = w->chg[y][i];
        if (c <= p && c >= best) { best = c; found = 1; }
    }
    *v = best; return found;
}
static void evaluate_frames(struct bworld *w)
{
    const struct scan *s = &w->s;
    for (;;) {
        const uint64_t f = w->eval_frame, row0 = f * s->vt + s->a0;
        const uint64_t last = scan_time(s, row0 + BH - 1 - (row0 + BH - 1 >= s->fetch_lead ? s->fetch_lead : 0));
        if (last >= w->now) return;
        static uint32_t vis[BH]; uint32_t p = 0; int ok = 1;
        for (uint64_t y = 0; y < BH; y++) {
            const uint64_t pos = row0 + y >= s->fetch_lead ? row0 + y - s->fetch_lead : 0;
            if (!visible_at(w, y, scan_time(s, pos), &vis[y])) { ok = 0; break; }
            if (vis[y] > p) p = vis[y];
        }
        w->eval_frame++;
        if (!ok) { w->unknown++; continue; }
        if (!w->first_present_t || scan_time(s, row0) < w->first_present_t || scan_time(s, row0) > w->last_present_t) continue;
        int consistent = 1;
        for (uint64_t y = 0; y < BH && consistent; y++) {
            uint32_t want;
            if (version_of(w, y, p, &want) && want != vis[y]) consistent = 0;
        }
        w->frames++;
        if (!consistent) w->torn++;
        /* latency: the newest swap q whose content every row shows (or newer content), torn frame or not */
        uint32_t q = p;
        for (; q >= w->shown_next && q; q--) {
            int all = 1;
            for (uint64_t y = 0; y < BH && all; y++) { uint32_t want; if (version_of(w, y, q, &want) && vis[y] < want) all = 0; }
            if (all) break;
        }
        while (w->shown_next <= q && w->shown_next < w->swaps && w->shown_next < 4096) {
            const uint64_t rt = w->ready_time[w->shown_next], lat = last > rt ? last - rt : 0;   /* until fully scanned */
            w->lat_sum += lat; w->lat_n++; if (lat > w->lat_max) w->lat_max = lat;
            w->shown_next++;
        }
    }
}

/* ---- the present's callbacks (AdrenoDisplay's maintainSourceRange, presentBarrier, presentClock; observe) ---- */
static void b_maintain(void *ctx, const void *p, uint64_t n) { struct bworld *w = ctx; (void)p; (void)n; w->now += w->maint_slow ? 2200 : 122; }
static void b_barrier(void *ctx) { struct bworld *w = ctx; w->now += 1 * US; }
static uint64_t b_clock(void *ctx)
{
    struct bworld *w = ctx;
    const unsigned k = ++w->clocks;
    if (k > w->clock_base + 1) {                 /* after ta: th, tb, tc per chunk */
        const unsigned j = (k - w->clock_base - 2) / 3, phase = (k - w->clock_base - 2) % 3;
        const uint64_t y0 = w->first_row + (uint64_t)j * ADRENO_DISPLAY_STAGE_ROWS;
        const uint64_t rows = y0 >= BH ? 0 : BH - y0 < ADRENO_DISPLAY_STAGE_ROWS ? BH - y0 : ADRENO_DISPLAY_STAGE_ROWS;
        if (w->clock_base && phase == 0) {
            w->now += rows * 278;                /* read and convert */
            if ((int)j == w->stall_chunk) w->now += w->stall_ns;
        }
        if (w->clock_base && phase == 1) w->now += rows * 500;    /* signatures */
    }
    return tb(w, w->now);
}
static uint32_t cur_version;
static void b_observe(void *ctx, uint64_t x, uint64_t y, uint64_t width)
{
    struct bworld *w = ctx; (void)x;
    w->now += (w->write_ns ? w->write_ns : 2000) * width / BW;   /* 2 us per full row: the A16's quiet-window rate */
    log_write(w, y, w->src ? w->ver[y] : cur_version);
}
static void b_gate(void *ctx, uint64_t x, uint64_t y0, uint64_t y1)
{
    struct bworld *w = ctx; (void)x;
    if (w->margin_zero) w->b.margin = 0;
    const uint64_t t0 = w->now;
    adreno_beam_gate(&w->b, bio(w), y0, y1);
    w->spins_ns += w->now - t0;
}

/* ---- the producer: a 600-row window dragged down 9 rows a frame; every 200th swap changes every row ---- */
static void produce(struct bworld *w, unsigned i)
{
    uint64_t lo, hi;
    if (i && !(i % (w->full_every ? w->full_every : 200))) { lo = 0; hi = BH; }
    else { const uint64_t top = 50 + (uint64_t)i * 9 % (BH - 700); lo = top >= 9 ? top - 9 : 0; hi = top + 600; }
    for (uint64_t y = lo; y < hi; y++) {
        w->ver[y] = i;
        w->chg_head[y] = (uint8_t)((w->chg_head[y] + 1) % BRING); w->chg[y][w->chg_head[y]] = i;
        uint32_t *px = (uint32_t *)(void *)(w->src + y * BROW);
        for (unsigned xx = 0; xx < BW; xx++) px[xx] = i * 2654435761u + (uint32_t)y;
    }
}
static void present_swap(struct bworld *w)
{
#if ADRENO_PRESENT_SYNC
    if (w->gpu_end > w->now) w->unfinished++;
#endif
    produce(w, w->swap);
    struct adreno_display_cursor c; memset(&c, 0, sizeof c);
    struct adreno_display_scanout d = {w->dst, (uint64_t)BH * BROW, BROW, BW, BH};
    struct adreno_display_surface s = {w->src, (uint64_t)BH * BROW, 0, BROW, BW, BH, ADRENO_DISPLAY_FORMAT_BGRA};
    const int beam = w->policy == BEAM && w->b.state == ADRENO_BEAM_LOCKED;
    if (beam) adreno_beam_begin(&w->b, 0, 0, BH);
    struct adreno_display_present_ops ops = {b_maintain, b_barrier, b_clock, w, b_observe, w, beam ? b_gate : NULL, w};
    struct adreno_display_present_result r;
    w->stall_chunk = -1;
    if (w->stall_pct && brnd(w) % 100 < w->stall_pct) {
        w->stall_chunk = (int)(brnd(w) % 113);
        w->stall_ns = w->stall_min + brnd(w) % (w->stall_max - w->stall_min + 1);
    }
    w->clocks = 0; w->clock_base = 3; w->first_row = 0;
    if (!w->first_present_t) w->first_present_t = w->now;
    if (w->last_copy_t && w->now - w->last_copy_t < w->min_copy_gap) w->min_copy_gap = w->now - w->last_copy_t;
    w->last_copy_t = w->now;
    const uint64_t started = tb(w, w->now);
    const int error = adreno_display_present(&c, &d, &s, &w->ws, &ops, &r);
    CHECK(error == 0);
    if (beam) {
        w->b.maint = w->b.maint - w->b.maint / 8 + (r.maint_ticks + r.barrier_ticks) / 8;
        adreno_beam_copied(&w->b, tb(w, w->now) - started);
        adreno_beam_end(&w->b);
    }
    w->presents++;
    w->last_present_t = w->now;
    if (w->swap < 4096) w->ready_time[w->swap] = w->queued_at;
    w->swap++;
    w->ready_at = w->now + w->render_min + brnd(w) % (w->render_max - w->render_min + 1);
}

/* ---- the frame path: AdrenoDisplay.cpp ---- */
static uint64_t bfire(struct bworld *w, uint64_t armed, uint64_t x)
{
    uint64_t slop = x > armed ? (x - armed) >> w->k.shift : 0;
    if (slop > w->k.cap) slop = w->k.cap;
    uint64_t fire = x + slop;
    if (w->k.noise) fire += brnd(w) % w->k.noise;
    if (w->tail_pct && brnd(w) % 100 < w->tail_pct) fire += w->tail_min + brnd(w) % (w->tail_max - w->tail_min + 1);
    return fire < armed ? armed : fire;
}
static int beam_calibrate(struct bworld *w)          /* beamCalibrateGated */
{
    const int locked_before = w->b.frame != 0;
    const int reason = adreno_beam_calibrate(&w->b, bio(w));
    if (!reason) w->b.recal_failures = 0;
    else if (!locked_before || ++w->b.recal_failures >= ADRENO_BEAM_RETRIES)
        adreno_beam_refuse(&w->b, locked_before ? ADRENO_BEAM_R_RETRIES : (uint32_t)reason);
    else { w->b.state = ADRENO_BEAM_STALLED; w->b.reason = (uint32_t)reason; w->b.stalled_ticks = 0; w->b.stalls++; }
    return !reason;
}
static int beam_arm(struct bworld *w)                /* beamArmGated */
{
    struct adreno_beam *b = &w->b;
    if (b->state == ADRENO_BEAM_STALLED && ++b->stalled_ticks >= ADRENO_BEAM_STALL_TICKS) b->state = ADRENO_BEAM_UNCAL;
    if (b->state == ADRENO_BEAM_UNCAL && !beam_calibrate(w)) return 0;
    if (b->state != ADRENO_BEAM_LOCKED) return 0;
    uint64_t now = 0;
    const uint64_t pos = adreno_beam_sample(b, bio(w), &now);
    if (!pos || b->state != ADRENO_BEAM_LOCKED) { b->target = 0; return 0; }
    if (!b->target) adreno_beam_target(b, pos, w->in_tick);
    const uint64_t fire = adreno_beam_fire_time(b, now, pos);
    const uint64_t at = adreno_vsync_arm_time(&w->v, now, fire);
    w->v.deadline = fire; w->v.arms++;
    w->armed = 1; w->fire_at = bfire(w, w->now, tb_ns(w, at));
    return 1;
}
static void b_arm(struct bworld *w)                  /* armFrameTimerGated */
{
    if (w->armed || (!w->current && !w->queued)) return;
    if (w->policy == BEAM && beam_arm(w)) return;
    const uint64_t now = tb(w, w->now);
    const uint64_t at = adreno_vsync_arm_time(&w->v, now, adreno_vsync_target(&w->v, now, w->in_tick));
    w->armed = 1; w->fire_at = bfire(w, w->now, tb_ns(w, at));
}
static void b_swap_begin(struct bworld *w)           /* swap_begin_gated */
{
    if (w->policy == BEAM && !w->in_tick && !w->current && w->b.state == ADRENO_BEAM_LOCKED && w->queued) {
        b_arm(w); return;                            /* C6 */
    }
    if (!w->current && w->queued) {
#if ADRENO_PRESENT_SYNC
        if (w->sg.max_wait && adreno_sync_decide(&w->sg, (const void *)(uintptr_t)(w->swap + 1u), w->swap, w->gpu_end > w->now,
                                                 w->queued_at, w->now) == ADRENO_SYNC_WAIT) {
            b_arm(w); return;                        /* K1 K4: stays queued, nothing written */
        }
#endif
        w->current = 1; w->queued = 0;
        if (!w->in_tick) w->off_tick++;
        b_arm(w);
        present_swap(w);
        w->presented = 1;
        return;
    }
    b_arm(w);
}
static void b_tick(struct bworld *w)                 /* vsyncGated */
{
    w->armed = 0; w->fires++;
    if (w->last_fire && w->now - w->last_fire < w->min_gap) w->min_gap = w->now - w->last_fire;
    w->last_fire = w->now;
    adreno_vsync_fired(&w->v, tb(w, w->now));
    if (w->policy == BEAM && w->b.state == ADRENO_BEAM_LOCKED && (w->b.target || w->b.armed_fire)) {
        uint64_t now = 0;
        const uint64_t pos = adreno_beam_sample(&w->b, bio(w), &now);
        const int r = adreno_beam_fire(&w->b, now, pos);
        if (r == ADRENO_BEAM_EARLY || r == ADRENO_BEAM_LATE) { b_arm(w); return; }
    }
    if (w->current && w->presented) { w->current = 0; w->presented = 0; }
    w->in_tick = 1; b_swap_begin(w); w->b.go_row0 = 0; w->in_tick = 0;
}
static void bworld_init(struct bworld *w, int policy, double hz, uint64_t seed)
{
    uint8_t *src = w->src, *dst = w->dst; uint64_t *sig = w->dmg.sig; uint8_t *known = w->dmg.known, *stage = w->ws.stage;
    memset(w, 0, sizeof *w);
    w->src = src ? src : malloc((size_t)BH * BROW); w->dst = dst ? dst : malloc((size_t)BH * BROW);
    memset(w->src, 0, (size_t)BH * BROW); memset(w->dst, 0, (size_t)BH * BROW);
    w->dmg.sig = sig ? sig : calloc(2 * BH, 8); w->dmg.known = known ? known : calloc(BH, 1);
    memset(w->dmg.sig, 0, 2 * BH * 8); memset(w->dmg.known, 0, BH);
    w->dmg.rows = BH; w->dmg.refresh_period = ADRENO_DISPLAY_REFRESH_PERIOD;
    w->ws.stage = stage ? stage : malloc((size_t)ADRENO_DISPLAY_STAGE_ROWS * BROW); w->ws.stage_row_bytes = BROW;
    w->ws.damage = &w->dmg;
    w->policy = policy; w->rng = seed * 0x9e3779b97f4a7c15ull | 1;
    scan_init(&w->s, hz, 1852);
    w->k = (struct ktimer){3, 1000000, 0, 300000, 0, 0};
    w->render_min = 3000000; w->render_max = 12000000; w->min_gap = w->min_copy_gap = UINT64_MAX;
    w->now = 1000 * MS;
    w->swap = w->shown_next = 1;                 /* version 0 is the content before the first swap */
}
static void bworld_start(struct bworld *w)
{
    const uint64_t ms = tb_ms(w);
    adreno_vsync_init(&w->v, ms * 16666667 / 1000000, ms, 4 * (ms * 16666667 / 1000000));
    adreno_beam_init(&w->b, ms, BH);
    if (w->policy == BEAM) {
        struct adreno_beam_regs r; adreno_beam_read_regs(bio(w), &r);
        int reason = adreno_beam_decode(&r, 2880, BH, &w->b.t);
        if (reason) adreno_beam_refuse(&w->b, (uint32_t)reason);
        else { w->b.state = ADRENO_BEAM_UNCAL; beam_calibrate(w); }
    }
    w->ready_at = w->now + 2 * MS;
}
static void bworld_run(struct bworld *w, unsigned swaps)
{
    w->swaps = swaps;
    while (w->swap < swaps) {
        const uint64_t t_tick = w->armed ? w->fire_at : UINT64_MAX;
        const uint64_t t_swap = w->ready_at && !w->queued ? w->ready_at : UINT64_MAX;
        uint64_t t = t_tick < t_swap ? t_tick : t_swap;
        if (t == UINT64_MAX) { CHECK(!"the world stopped with swaps left"); return; }
        if (t > w->now) w->now = t;
        evaluate_frames(w);
        if (w->reset_at && !w->reset_done && w->now >= w->reset_at) {     /* D1: stop_hardware_gated + start */
            w->reset_done = 1; adreno_vsync_reset(&w->v); adreno_beam_reset(&w->b); w->armed = 0;
        }
        if (t_tick <= t_swap) b_tick(w);
        else {
            w->queued = 1; w->queued_at = w->now; w->ready_at = 0;
#if ADRENO_PRESENT_SYNC
            if (w->gpu_pct) w->gpu_end = brnd(w) % 100 < w->gpu_pct ? w->now + w->gpu_min + brnd(w) % (w->gpu_max - w->gpu_min + 1) : 0;
#endif
            b_swap_begin(w);
        }
    }
    w->now += 100 * MS;
    evaluate_frames(w);
}
struct bres { uint64_t frames, torn, pps_x10, lat_us, lat_max_us, spin_us, ovt, late, forced, early, stalls, glitches, recal,
              n, state, fc, off_tick, min_gap_us, go; };
static struct bres bsummary(struct bworld *w)
{
    struct bres r; memset(&r, 0, sizeof r);
    r.frames = w->frames; r.torn = w->torn;
    const uint64_t span = w->last_present_t - w->first_present_t;
    r.pps_x10 = span ? (w->presents - 1) * 10000000000ull / span : 0;
    r.lat_us = w->lat_n ? w->lat_sum / w->lat_n / 1000 : 0; r.lat_max_us = w->lat_max / 1000;
    r.spin_us = w->b.go + w->b.forced ? w->spins_ns / (w->b.go + w->b.forced) / 1000 : 0;
    r.ovt = w->b.ovt; r.late = w->b.late; r.forced = w->b.forced; r.early = w->b.early; r.stalls = w->b.stalls;
    r.glitches = w->b.glitches; r.recal = w->b.recal; r.n = w->b.n; r.state = w->b.state; r.fc = w->b.fc_ok;
    r.off_tick = w->off_tick; r.min_gap_us = w->min_copy_gap == UINT64_MAX ? 0 : w->min_copy_gap / 1000; r.go = w->b.go;
    return r;
}
static FILE *BJ; static int bfirst;
static void breport(const char *name, const struct bres *r)
{
    fprintf(BJ, "%s\"%s\":{\"frames\":%llu,\"torn\":%llu,\"pps_x10\":%llu,\"latency_us\":%llu,\"latency_max_us\":%llu,"
            "\"spin_us_per_tick\":%llu,\"overtakes\":%llu,\"late\":%llu,\"forced\":%llu,\"early\":%llu,\"stalls\":%llu,"
            "\"glitches\":%llu,\"recal\":%llu,\"n\":%llu,\"state\":%llu,\"fc\":%llu,\"off_tick\":%llu,\"min_gap_us\":%llu,\"go\":%llu}",
            bfirst++ ? "," : "", name, (unsigned long long)r->frames, (unsigned long long)r->torn,
            (unsigned long long)r->pps_x10, (unsigned long long)r->lat_us, (unsigned long long)r->lat_max_us,
            (unsigned long long)r->spin_us, (unsigned long long)r->ovt, (unsigned long long)r->late,
            (unsigned long long)r->forced, (unsigned long long)r->early, (unsigned long long)r->stalls,
            (unsigned long long)r->glitches, (unsigned long long)r->recal, (unsigned long long)r->n,
            (unsigned long long)r->state, (unsigned long long)r->fc, (unsigned long long)r->off_tick,
            (unsigned long long)r->min_gap_us, (unsigned long long)r->go);
    printf("beam %-28s frames %5llu torn %5llu (%5.1f%%) pps %3llu.%llu lat %6llu us (max %7llu) spin %4llu us ovt %llu "
           "late %llu forced %llu early %llu stall %llu gl %llu rs %llu n %llu off %llu\n", name,
           (unsigned long long)r->frames, (unsigned long long)r->torn, r->frames ? 100.0 * r->torn / r->frames : 0.0,
           (unsigned long long)r->pps_x10 / 10, (unsigned long long)r->pps_x10 % 10, (unsigned long long)r->lat_us,
           (unsigned long long)r->lat_max_us, (unsigned long long)r->spin_us, (unsigned long long)r->ovt,
           (unsigned long long)r->late, (unsigned long long)r->forced, (unsigned long long)r->early,
           (unsigned long long)r->stalls, (unsigned long long)r->glitches, (unsigned long long)r->recal,
           (unsigned long long)r->n, (unsigned long long)r->off_tick);
}
static struct bres bscenario(struct bworld *w, const char *name, unsigned swaps)
{
    bworld_start(w); bworld_run(w, swaps);
    struct bres r = bsummary(w); breport(name, &r); return r;
}

/* ---- unit checks: address, decode, property, attribute, calibration, perf line ---- */
static void beam_units(void)
{
    /* A1: three derivations of one page */
    CHECK(DPU_INTF_PA == 0x0AE3A000ull && DPU_INTF_PA == 0x0AE01000ull + 0x39000ull &&
          DPU_INTF_PA == DPU_MDP_PA + 0x34000ull + 0x1000ull * 5);
    CHECK(DPU_INTF_LAST_READ + 4 <= DPU_INTF_PAGE);
    /* B1: decode */
    struct adreno_beam_timing t;
    struct adreno_beam_regs r = dp_regs(2880, 1800, 1852, 1);
    CHECK(adreno_beam_decode(&r, 2880, 1800, &t) == 0 && t.vtotal == 1852 && t.a0 == 52 && t.a1 == 1851 && t.width_ok &&
          t.htotal == 1480);
    r = dp_regs(2880, 1800, 1852, 0);
    CHECK(adreno_beam_decode(&r, 2880, 1800, &t) == 0 && t.a0 == 52 && t.a1 == 1851 && t.width_ok && t.htotal == 2960);
    {   /* a non-DP engine: blank split around the active lines, no ACTIVE_V */
        struct adreno_beam_regs n = r; const uint32_t ht = 2960;
        n.config = 0; n.disp_v_start = 24 * ht + 10; n.disp_v_end = (1852 - 28) * ht - 1;
        CHECK(adreno_beam_decode(&n, 2880, 1800, &t) == 0 && t.a0 == 24 && t.a1 == 1823);
        n.act_v_start = n.act_v_end = 0; n.config = DPU_INTF_CFG_ACTIVE_V_EN;    /* ACTIVE_V_EN without values */
        CHECK(adreno_beam_decode(&n, 2880, 1800, &t) == 0 && t.a0 == 24);
    }
    struct adreno_beam_regs bad = r; bad.engine = 0; bad.status = 0;
    CHECK(adreno_beam_decode(&bad, 2880, 1800, &t) == ADRENO_BEAM_R_ENGINE);
    bad = r; bad.hsync_ctl = 0; CHECK(adreno_beam_decode(&bad, 2880, 1800, &t) == ADRENO_BEAM_R_HTOTAL);
    bad = r; bad.vsync_period = 1000 * 2960; CHECK(adreno_beam_decode(&bad, 2880, 1800, &t) == ADRENO_BEAM_R_VTOTAL);
    bad = r; bad.vsync_period = 20000u * 2960; CHECK(adreno_beam_decode(&bad, 2880, 1800, &t) == ADRENO_BEAM_R_VTOTAL);
    bad = r; bad.vsync_period = 1852u * 2960 + 7; CHECK(adreno_beam_decode(&bad, 2880, 1800, &t) == ADRENO_BEAM_R_VTOTAL);
    {   /* the A16's own registers: accepted, the long blank first */
        struct adreno_beam_regs a = a16_regs();
        CHECK(adreno_beam_decode(&a, 2880, 1800, &t) == 0 && t.htotal == 1540 && t.vtotal == 3840 && t.a0 == 2040 &&
              t.a1 == 3839 && t.width == 1440 && t.wide && t.width_ok);
        a.avr = 1; CHECK(adreno_beam_decode(&a, 2880, 1800, &t) == ADRENO_BEAM_R_AVR);
    }
    bad = dp_regs(1920, 1080, 1125, 0); CHECK(adreno_beam_decode(&bad, 2880, 1800, &t) == ADRENO_BEAM_R_VTOTAL);
    bad = dp_regs(2880, 1080, 1852, 0); CHECK(adreno_beam_decode(&bad, 2880, 1800, &t) == ADRENO_BEAM_R_HEIGHT);
    bad = r; bad.avr = 1; CHECK(adreno_beam_decode(&bad, 2880, 1800, &t) == ADRENO_BEAM_R_AVR);
    bad = dp_regs(2560, 1800, 1852, 0); CHECK(adreno_beam_decode(&bad, 2880, 1800, &t) == 0 && !t.width_ok);
    /* D3: the GPU node's properties */
    const uint32_t abi = 1, abi2 = 2; const uint64_t pa = DPU_INTF_PA, pa2 = DPU_INTF_PA + 0x1000;
    CHECK(adreno_beam_check_property(NULL, 0, NULL, 0) == ADRENO_BEAM_R_PROPERTY);
    CHECK(adreno_beam_check_property(&abi, 4, &pa, 4) == ADRENO_BEAM_R_PROPERTY);
    CHECK(adreno_beam_check_property(&abi2, 4, &pa, 8) == ADRENO_BEAM_R_PROPERTY);
    CHECK(adreno_beam_check_property(&abi, 4, &pa2, 8) == ADRENO_BEAM_R_ADDRESS);
    CHECK(adreno_beam_check_property(&abi, 4, &pa, 8) == 0);
    /* A4: Device encodings only */
    CHECK(adreno_beam_attr_ok(0x00) && adreno_beam_attr_ok(0x04) && adreno_beam_attr_ok(0x08) && adreno_beam_attr_ok(0x0c));
    /* FEAT_XS: 0b0000dd01; b12v4's mapping read 0x01 (SPTM MAIR_EL1 0x00000000010000ff, index 3) */
    CHECK(adreno_beam_attr_ok(0x01) && adreno_beam_attr_ok(0x05) && adreno_beam_attr_ok(0x09) && adreno_beam_attr_ok(0x0d));
    CHECK(!adreno_beam_attr_ok(0x44) && !adreno_beam_attr_ok(0xff) && !adreno_beam_attr_ok(0x107) && !adreno_beam_attr_ok(0x101));
    CHECK(!adreno_beam_attr_ok(0x02) && !adreno_beam_attr_ok(0x03) && !adreno_beam_attr_ok(0x40) && !adreno_beam_attr_ok(0x10));
    /* B2 B3: calibration, against the scanout model */
    static struct bworld w;
    struct { const char *what; double hz; int counts_off, fc_off; uint32_t base, modulus, fc_line, freeze; int want; uint32_t n; } cal[] = {
        {"60hz", 60.02, 0, 0, 0, 0, 0, 0, 0, 1},
        {"120hz", 120.0, 0, 0, 0, 0, 0, 0, 0, 2},
        {"144hz", 144.0, 0, 0, 0, 0, 0, 0, 0, 2},
        {"90hz", 90.0, 0, 0, 0, 0, 0, 0, 0, 2},
        {"165hz", 165.0, 0, 0, 0, 0, 0, 0, 0, 3},
        {"48hz", 48.0, 0, 0, 0, 0, 0, 0, 0, 1},
        {"30hz", 30.0, 0, 0, 0, 0, 0, 0, 0, 1},
        {"one-based", 60.0, 0, 0, 1, 0, 0, 0, 0, 1},
        {"a16-3840", 59.51, 0, 0, 1, 0, 0, 0, 0, 1},
        {"fc-at-500", 60.0, 0, 0, 0, 0, 500, 0, 0, 1},
        {"fc-off", 60.0, 0, 1, 0, 0, 0, 0, 0, 1},
        {"counts-off", 60.0, 1, 0, 0, 0, 0, 0, ADRENO_BEAM_R_FROZEN, 0},
        {"frozen-mid", 60.0, 0, 0, 0, 0, 0, 1, ADRENO_BEAM_R_FROZEN, 0},
        {"modulus", 60.0, 0, 0, 0, 1700, 0, 0, ADRENO_BEAM_R_MODULUS, 0},
        {"400hz", 400.0, 0, 0, 0, 0, 0, 0, ADRENO_BEAM_R_PERIOD, 0},
        {"3hz", 3.0, 0, 0, 0, 0, 0, 0, ADRENO_BEAM_R_PERIOD, 0},
    };
    for (unsigned i = 0; i < sizeof cal / sizeof cal[0]; i++) {
        bworld_init(&w, BEAM, cal[i].hz, 100 + i);
        if (!strcmp(cal[i].what, "a16-3840")) { scan_init(&w.s, cal[i].hz, 3840); w.s.regs = a16_regs(); }
        w.s.counts_off = cal[i].counts_off; w.s.fc_off = cal[i].fc_off; w.s.base = cal[i].base;
        if (cal[i].modulus) w.s.modulus = cal[i].modulus;
        w.s.fc_line = cal[i].fc_line;
        if (cal[i].freeze) { w.s.freeze_from = w.now; w.s.freeze_until = UINT64_MAX; }
        adreno_beam_init(&w.b, tb_ms(&w), BH);
        struct adreno_beam_regs rr; adreno_beam_read_regs(bio(&w), &rr);
        CHECK(adreno_beam_decode(&rr, 2880, BH, &w.b.t) == 0);
        const uint64_t t0 = w.now;
        const int got = adreno_beam_calibrate(&w.b, bio(&w));
        const double frame_ms = 1e3 / cal[i].hz;
        const int ok = got == cal[i].want && (got || (w.b.n == cal[i].n && w.b.line_base == cal[i].base &&
                      w.b.fc_ok == (uint32_t)!cal[i].fc_off && w.b.fc_line == cal[i].fc_line &&
                      fabs((double)w.b.frame / 1e6 - frame_ms) < frame_ms * 0.002));
        CHECK(ok);
        CHECK(w.now - t0 < 300 * MS);                                     /* bounded (B2) */
        printf("beam calibrate %-10s -> %d (want %d) frame %.4f ms n %u base %u fc %u/%u in %.1f ms\n", cal[i].what, got,
               cal[i].want, (double)w.b.frame / 1e6, w.b.n, w.b.line_base, w.b.fc_ok, w.b.fc_line, (double)(w.now - t0) / 1e6);
    }
    /* E4: the perf beam line within 250 bytes at the caps, and it parses back */
    char line[512]; struct adreno_beam_summary big; memset(&big, 0xff, sizeof big);
    int n = adreno_perf_line_beam(line, sizeof line, ~0ull, &big);
    CHECK(n > 0 && n <= ADRENO_PERF_LINE_MAX);
    printf("beam perf line at caps: %d bytes\n", n);
    struct adreno_beam_summary sm; memset(&sm, 0, sizeof sm); sm.state = 3; sm.vtotal = 1852; sm.a0 = 52; sm.a1 = 1851; sm.ovt = 7;
    n = adreno_perf_line_beam(line, sizeof line, 9, &sm);
    CHECK(!strncmp(line, "AdrenoDisplay: perf beam s=9 st=3/0 ", 36) && strstr(line, " vt=1852 n=0 ") && strstr(line, " ovt=7/0 "));
    printf("%s\n", line);
}

/* ---- C7: cursor-only presents at any phase ---- */
static void beam_cursor(int gated, struct bres *out)
{
    static struct bworld w;
    bworld_init(&w, BEAM, 60.02, gated ? 41 : 42);
    bworld_start(&w);
    enum { CW = 32 };
    static uint8_t img[ADRENO_DISPLAY_CURSOR_BYTES], save[ADRENO_DISPLAY_CURSOR_BYTES], save2[ADRENO_DISPLAY_CURSOR_BYTES];
    static uint8_t row[BROW];
    for (unsigned i = 0; i < CW * CW; i++) { img[i * 4] = 200; img[i * 4 + 3] = 255; }
    struct adreno_display_cursor c; memset(&c, 0, sizeof c);
    c.image = img; c.save = save; c.width = c.height = CW; c.x = 0; c.y = 100; c.visible = 1;
    w.ws.row = row; w.ws.row_bytes = BROW; w.ws.next_save = save2;
    struct adreno_display_scanout d = {w.dst, (uint64_t)BH * BROW, BROW, BW, BH};
    uint8_t *keep = w.src; w.src = NULL;            /* b_observe logs cur_version */
    w.swaps = 4096;
    for (unsigned i = 1; i <= 1500; i++) {
        w.now += 1500 * US + brnd(&w) % (9000 * US);      /* mouse events at any phase */
        evaluate_frames(&w);
        const uint64_t old_lo = c.drawn ? c.sy : BH, old_hi = c.drawn ? c.sy + c.sh : 0;
        static int dir = 1;
        int32_t ny = c.y + dir * (int32_t)(1 + brnd(&w) % 40);
        if (ny < 0 || ny > BH - CW) { dir = -dir; ny = c.y + dir * 20; }
        c.y = ny;
        const uint64_t lo = (uint64_t)c.y < old_lo ? (uint64_t)c.y : old_lo, hi = (uint64_t)c.y + CW > old_hi ? (uint64_t)c.y + CW : old_hi;
        for (uint64_t y = lo; y < hi; y++)                /* the rows this move changes: the old and the new rectangle */
            if ((y >= old_lo && y < old_hi) || (y >= (uint64_t)c.y && y < (uint64_t)c.y + CW)) {
                w.chg_head[y] = (uint8_t)((w.chg_head[y] + 1) % BRING); w.chg[y][w.chg_head[y]] = i;
            }
        cur_version = i;
        if (gated && w.b.state == ADRENO_BEAM_LOCKED) adreno_beam_begin(&w.b, 1, lo, hi);
        struct adreno_display_present_ops ops = {b_maintain, b_barrier, b_clock, &w, b_observe, &w,
                                                 gated ? b_gate : NULL, &w};
        w.clocks = 0; w.clock_base = 0; w.first_row = lo;
        if (!w.first_present_t) w.first_present_t = w.now;
        struct adreno_display_present_result r;
        CHECK(adreno_display_present(&c, &d, NULL, &w.ws, &ops, &r) == 0);
        if (gated) adreno_beam_end(&w.b);
        w.last_present_t = w.now; w.presents++;
        if (i < 4096) w.ready_time[i] = w.now;
    }
    w.now += 100 * MS; evaluate_frames(&w);
    w.src = keep;
    *out = bsummary(&w);
    out->ovt = w.b.cur_capped; out->spin_us = w.b.cur_waits ? w.spins_ns / w.b.cur_waits / 1000 : 0;
}

static void beam_scenarios(const char *dir)
{
    unsigned c0 = checks, f0 = failures, cc0 = cost_checks, cf0 = cost_failures;
    char path[4096]; snprintf(path, sizeof path, "%s/beam.json", dir);
    BJ = fopen(path, "w"); assert(BJ);
    fprintf(BJ, "{\"scenarios\":{");
    beam_units();
    static struct bworld w; struct bres r, base;
    /* the A16 as surveyed: vtotal 3840, a 2040-line blank first, 59.51 Hz, LINE_COUNT 1..3840 */
    bworld_init(&w, GRID, 59.51, 50); scan_init(&w.s, 59.51, 3840); w.s.regs = a16_regs(); w.s.base = 1;
    base = bscenario(&w, "grid_a16_survey", 1200);
    bworld_init(&w, BEAM, 59.51, 50); scan_init(&w.s, 59.51, 3840); w.s.regs = a16_regs(); w.s.base = 1;
    r = bscenario(&w, "beam_a16_survey", 1200);
    CHECK(r.state == ADRENO_BEAM_LOCKED && r.n == 1 && r.torn <= r.ovt + r.forced);
    COST(r.torn == 0 && base.torn > 0);
    bworld_init(&w, BEAM, 59.51, 51); scan_init(&w.s, 59.51, 3840); w.s.regs = a16_regs(); w.s.base = 1;
    w.stall_pct = 2; w.stall_min = 3 * MS; w.stall_max = 30 * MS; w.tail_pct = 2; w.tail_min = 2 * MS; w.tail_max = 40 * MS;
    r = bscenario(&w, "beam_a16_survey_stalls", 1200);
    CHECK(r.state == ADRENO_BEAM_LOCKED && r.torn <= r.ovt + r.forced);
    /* C3 C6: the deployed grid tick against the beam, a 60 Hz panel (60.02 Hz: the grid drifts through it) */
    bworld_init(&w, GRID, 60.02, 1); base = bscenario(&w, "grid_60", 1200);
    COST(base.torn * 100 >= base.frames * 25);                  /* the deployed path tears a quarter of the frames */
    bworld_init(&w, BEAM, 60.02, 1); r = bscenario(&w, "beam_60", 1200);
    CHECK(r.state == ADRENO_BEAM_LOCKED && r.n == 1 && r.fc == 1);
    COST(r.torn == 0 && r.ovt == 0 && r.forced == 0);
    CHECK(r.pps_x10 >= 550 && r.spin_us <= 1500 && r.off_tick == 0);
    /* C1 C3: stalls inside 2% of the copies (3-30 ms) and 2% of fires 2-40 ms late (monitor token holds) */
    bworld_init(&w, GRID, 60.02, 2); w.stall_pct = 2; w.stall_min = 3 * MS; w.stall_max = 30 * MS;
    w.tail_pct = 2; w.tail_min = 2 * MS; w.tail_max = 40 * MS; base = bscenario(&w, "grid_60_stalls", 1200);
    bworld_init(&w, BEAM, 60.02, 2); w.stall_pct = 2; w.stall_min = 3 * MS; w.stall_max = 30 * MS;
    w.tail_pct = 2; w.tail_min = 2 * MS; w.tail_max = 40 * MS; r = bscenario(&w, "beam_60_stalls", 1200);
    CHECK(r.torn <= r.ovt + r.forced);                          /* every torn frame is a counted overtake or forced copy */
    COST(r.torn * 20 <= base.torn);                             /* at least 20x fewer than the grid under the same stalls */
    /* B3: other panel rates */
    const struct { const char *name; double hz; uint64_t n; } rates[] = {
        {"beam_120", 120.0, 2}, {"beam_144", 144.0, 2}, {"beam_90", 90.0, 2}, {"beam_48", 48.0, 1}};
    for (unsigned i = 0; i < 4; i++) {
        bworld_init(&w, BEAM, rates[i].hz, 10 + i); r = bscenario(&w, rates[i].name, 900);
        CHECK(r.state == ADRENO_BEAM_LOCKED && r.n == rates[i].n);
        COST(r.torn == 0 && r.ovt == 0);
    }
    bworld_init(&w, GRID, 120.0, 10); base = bscenario(&w, "grid_120", 900);
    /* B3: the rate doubles midway (60 -> 120 Hz): a recalibration, no burst of ticks */
    bworld_init(&w, BEAM, 60.0, 20); w.s.change_at = 1000 * MS + 8000 * MS; w.s.line_ps2 = w.s.line_ps / 2;
    r = bscenario(&w, "beam_rate_change", 1200);
    CHECK(r.recal >= 1 && r.state == ADRENO_BEAM_LOCKED && r.n == 2 && r.min_gap_us >= 4000);
    CHECK(r.torn <= r.ovt + r.forced + 2);
    /* C4: the DPU fetching 24 lines ahead. Steady state stays far ahead of it; under stalls the 32-line margin makes every
     * tear a counted overtake, and without the margin tears go uncounted. */
    bworld_init(&w, BEAM, 60.02, 21); w.s.fetch_lead = 24; r = bscenario(&w, "beam_fetch_lead_24", 900);
    CHECK(r.torn == 0);
    bworld_init(&w, BEAM, 60.02, 29); w.s.fetch_lead = 24; w.stall_pct = 20; w.stall_min = 2 * MS; w.stall_max = 15 * MS;
    r = bscenario(&w, "beam_fetch_lead_24_stalls", 900);
    CHECK(r.torn <= r.ovt + r.forced);
    {   /* C4 deterministic: the gate counts a chunk whose row the DPU may already be fetching (fetch lead 24 < M 32), and
         * would not without the margin */
        static struct bworld g; bworld_init(&g, BEAM, 60.0, 30); bworld_start(&g);
        const uint64_t vt = g.b.t.vtotal;
        for (int margin = 32; margin >= 0; margin -= 32) {
            const uint64_t pos = adreno_beam_sample(&g.b, bio(&g), 0), off = pos - scan_pos(&g.s, g.now);  /* numberings */
            const uint64_t row0 = (pos / vt + 2) * vt + g.b.t.a0, y0 = 160;
            g.b.row0 = row0; g.b.margin = (uint32_t)margin; g.b.spin_budget = 0; g.b.ovt = 0;
            /* move the scanout to 10 lines before row y0 of the frame (inside a 24-line fetch lead) */
            g.now = scan_time(&g.s, row0 + y0 - 10 - off) + 1;
            adreno_beam_gate(&g.b, bio(&g), y0, y0 + 16);
            CHECK(margin ? g.b.ovt == 1 : g.b.ovt == 0);
            /* and, a frame on, 40 lines before it: outside both */
            g.b.ovt = 0; g.b.row0 = row0 + vt; g.now = scan_time(&g.s, row0 + vt + y0 - 40 - off) + 1;
            adreno_beam_gate(&g.b, bio(&g), y0, y0 + 16);
            CHECK(g.b.ovt == 0);
        }
    }
    /* C3: a 120 Hz panel, every swap a full-frame change written at 4.6 us a row (the A16's busy-window rate): the copy
     * (~10 ms) is slower than one scan (8.3 ms), so the race is overtaken near the bottom; every tear is counted */
    bworld_init(&w, BEAM, 120.0, 31); w.full_every = 1; w.write_ns = 4600; r = bscenario(&w, "beam_120_full_frame_slow_writes", 600);
    CHECK(r.torn <= r.ovt + r.forced);
    struct bres slow = r;
    bworld_init(&w, GRID, 120.0, 31); w.full_every = 1; w.write_ns = 4600; base = bscenario(&w, "grid_120_full_frame_slow_writes", 600);
    COST(slow.torn * 4 <= base.torn);                           /* the slow copy starts early enough to stay ahead */
    /* D4 B2: the counters freeze for 2 s: bounded spins, the grid meanwhile, recalibration after */
    bworld_init(&w, BEAM, 60.02, 22); w.s.freeze_from = 1000 * MS + 5000 * MS; w.s.freeze_until = w.s.freeze_from + 2000 * MS;
    r = bscenario(&w, "beam_freeze_2s", 1200);
    CHECK(r.stalls >= 1 && r.state == ADRENO_BEAM_LOCKED && r.pps_x10 >= 500);
    /* B6: one LINE_COUNT read in 1000 is garbage */
    bworld_init(&w, BEAM, 60.02, 23); w.s.garbage_every = 1000; r = bscenario(&w, "beam_garbage_reads", 900);
    CHECK(r.glitches > 0 && r.state == ADRENO_BEAM_LOCKED && r.torn <= r.ovt + r.forced);
    /* C6: an irregular producer (3-30 ms): no copy at a random phase */
    bworld_init(&w, BEAM, 60.02, 24); w.render_min = 3 * MS; w.render_max = 30 * MS; r = bscenario(&w, "beam_irregular", 900);
    CHECK(r.torn == 0 && r.off_tick == 0);
    bworld_init(&w, GRID, 60.02, 24); w.render_min = 3 * MS; w.render_max = 30 * MS; base = bscenario(&w, "grid_irregular", 900);
    /* B5: a 24 MHz timebase near 2^63, FRAME_COUNT about to wrap; and FRAME_COUNT not counting */
    bworld_init(&w, BEAM, 60.02, 25); w.tb24 = 1; w.tb_off = (1ull << 63) - 5000000; w.s.fc_start = 0xfffffffbu;
    r = bscenario(&w, "beam_24mhz_wrap", 900);
    CHECK(r.state == ADRENO_BEAM_LOCKED && r.torn == 0 && r.fc == 1);
    bworld_init(&w, BEAM, 60.02, 26); w.s.fc_off = 1; r = bscenario(&w, "beam_no_frame_count", 900);
    CHECK(r.state == ADRENO_BEAM_LOCKED && r.fc == 0 && r.torn == 0);
    /* C8: a maintenance pass of 4 ms (longer than any lead): nothing hangs; torn frames are counted ones */
    bworld_init(&w, BEAM, 60.02, 27); w.maint_slow = 1; r = bscenario(&w, "beam_maint_4ms", 600);
    CHECK(r.torn <= r.ovt + r.forced && r.pps_x10 >= 200);
    /* D1: a stop and start mid-run */
    bworld_init(&w, BEAM, 60.02, 28); w.reset_at = 1000 * MS + 6000 * MS; r = bscenario(&w, "beam_reset", 900);
    CHECK(r.state == ADRENO_BEAM_LOCKED && r.torn <= r.ovt + r.forced + 1);
    /* C7: cursor-only presents at random phases, gated and not */
    beam_cursor(0, &base); breport("cursor_ungated", &base);
    beam_cursor(1, &r); breport("cursor_gated", &r);
    COST(base.torn > 0);
    CHECK(r.torn <= r.ovt);                                     /* ovt here: capped cursor waits */
    COST(r.torn == 0);
#if ADRENO_PRESENT_SYNC
    {   /* agents/present-sync K1 K4: 40% of the swaps arrive while their GPU write runs 1-40 ms more, on the A16's beam
         * and on the grid; the gate (50 ms bound) defers them: no unfinished copy but a counted forced one, no tear */
        const struct { int policy; double hz; uint32_t vt; const char *off, *on; } g[] = {
            {BEAM, 59.51, 3840, "beam_a16_gpulag", "beam_a16_gpulag_sync"}, {GRID, 60.02, 1852, "grid_60_gpulag", "grid_60_gpulag_sync"}};
        for (unsigned i = 0; i < 2; i++) {
            uint64_t unfinished[2], forced[2]; struct bres rr[2];
            for (int on = 0; on < 2; on++) {
                bworld_init(&w, g[i].policy, g[i].hz, 61 + i);
                if (g[i].vt == 3840) { scan_init(&w.s, g[i].hz, 3840); w.s.regs = a16_regs(); w.s.base = 1; }
                w.gpu_pct = 40; w.gpu_min = 1 * MS; w.gpu_max = 40 * MS;
                if (on) adreno_sync_gate_init(&w.sg, 50 * MS, 2000 * MS);
                rr[on] = bscenario(&w, on ? g[i].on : g[i].off, 900);
                unfinished[on] = w.unfinished; forced[on] = w.sg.forced;
            }
            printf("beam present sync %s: unfinished copies %llu without the gate, %llu with it (forced %llu); pps %llu.%llu -> %llu.%llu\n",
                   g[i].off, (unsigned long long)unfinished[0], (unsigned long long)unfinished[1], (unsigned long long)forced[1],
                   (unsigned long long)rr[0].pps_x10 / 10, (unsigned long long)rr[0].pps_x10 % 10,
                   (unsigned long long)rr[1].pps_x10 / 10, (unsigned long long)rr[1].pps_x10 % 10);
            COST(unfinished[0] > 0);
            CHECK(unfinished[1] <= forced[1]);                  /* only a copy at the bound may be unfinished */
            if (g[i].policy == BEAM) CHECK(rr[1].torn <= rr[1].ovt + rr[1].forced && rr[1].off_tick == 0);
            CHECK(rr[1].pps_x10 >= 200);
        }
    }
#if ADRENO_PIPELINE
    {   /* agents/gpu-pipeline D1 D2 D4: pipelined, every swap arrives right after its IB started and its write runs a whole
         * IB more (b12v12: 9-18 ms; heavy: 20-108 ms); the gate's pipeline bound (1.1 s) holds each until it ended: no
         * unfinished copy, nothing forced, no tear, the beam stays locked */
        const struct { int policy; double hz; uint32_t vt; uint64_t lo, hi; const char *name; } g[] = {
            {BEAM, 59.51, 3840, 9 * MS, 18 * MS, "beam_a16_pipe"}, {BEAM, 59.51, 3840, 20 * MS, 108 * MS, "beam_a16_pipe_heavy"},
            {GRID, 60.02, 1852, 9 * MS, 18 * MS, "grid_60_pipe"}};
        for (unsigned i = 0; i < 3; i++) {
            bworld_init(&w, g[i].policy, g[i].hz, 71 + i);
            if (g[i].vt == 3840) { scan_init(&w.s, g[i].hz, 3840); w.s.regs = a16_regs(); w.s.base = 1; }
            w.gpu_pct = 100; w.gpu_min = g[i].lo; w.gpu_max = g[i].hi;
            adreno_sync_gate_init(&w.sg, 1100 * MS, 2000 * MS);
            const struct bres rr = bscenario(&w, g[i].name, 900);
            printf("beam pipeline %s: unfinished copies %llu (forced %llu, deferrals %llu, longest wait %llu us); pps %llu.%llu; "
                   "torn %llu ovt %llu\n", g[i].name, (unsigned long long)w.unfinished, (unsigned long long)w.sg.forced,
                   (unsigned long long)w.sg.defer, (unsigned long long)w.sg.max_waited / 1000,
                   (unsigned long long)rr.pps_x10 / 10, (unsigned long long)rr.pps_x10 % 10, (unsigned long long)rr.torn,
                   (unsigned long long)rr.ovt);
            CHECK(w.unfinished == 0 && w.sg.forced == 0);
            if (g[i].policy == BEAM) CHECK(rr.torn <= rr.ovt && rr.off_tick == 0);
            CHECK(rr.pps_x10 >= 50);
        }
    }
#endif
#endif
    fprintf(BJ, "},\"checks\":%u,\"failures\":%u,\"cost_checks\":%u,\"cost_failures\":%u}\n", checks - c0, failures - f0,
            cost_checks - cc0, cost_failures - cf0);
    fclose(BJ);
    printf("{\"beam_checks\":%u,\"beam_failures\":%u,\"beam_cost_checks\":%u,\"beam_cost_failures\":%u}\n", checks - c0,
           failures - f0, cost_checks - cc0, cost_failures - cf0);
}

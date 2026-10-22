/* SPDX-License-Identifier: MIT */
/* SNAP_CPU_DVFS (probes/xnuboot.c): an opt-in CPU frequency governor for the
 * A16's SCMI performance domains (agents/dvfs FAILURE-MODES.md section 4).
 *
 * Mechanism (docs/A16-CPU-CLOCKS-20261018.md, build/cpu-clock-records): the
 * X2E has no cpufreq-hw block; the PDP firmware takes SCMI PERF levels. For the
 * Prime domains the pdp0 message route is ignored and only the domain's own
 * LEVEL_SET fastchannel applies (gen1-v50-prime-hold-fc.json): write the level
 * index to the fastchannel's data word in the domain's own PDP transmit block,
 * then 0xf to its doorbell (channel 3, pcc_core0; db_preserve 0), as Linux's
 * __scmi_perf_level_set does. LEVEL_GET is a fastchannel in the shared receive
 * block. A request outlives the cluster's power-off; a cold boot resets it.
 *
 * What the firmware grants is what counts (ABI 2, after b12v4: PDP1 was asked
 * for 19 with six busy Prime cores, LEVEL_GET stayed 13, and ABI 1 still
 * counted 195 s "at 19"). Every window reads LEVEL_GET: the residency, the
 * level the policy scales from and the reported level are LEVEL_GET's, never
 * the request's. A request LEVEL_GET has not shown after CPU_DVFS_REFUSE_WINDOWS
 * (one re-assert on the way) is refused: the governor then walks down one level
 * per refusal period until LEVEL_GET follows or it reaches the granted level,
 * and caps itself at the highest level the firmware granted (refused_mask has a
 * bit per refused level). While demand stays at hispeed it re-asks the ceiling
 * every CPU_DVFS_REPROBE_WINDOWS, at most CPU_DVFS_REPROBES times (a limit that
 * depends on load or on the number of active cores can lift). LIMITS_GET (a
 * 4-byte fastchannel next to LEVEL_GET, format unknown, read only) is kept raw
 * at the start and whenever it changes. Optionally (io->khz) vCPU 0's own core
 * times a dependent-add chain once a second: a clock measured independently of
 * what LEVEL_GET means.
 *
 * Load signal: guest WFI runs natively (HCR_EL2.TWI is never set), so there is
 * no WFI trap residency. The EL2 tick (~1 kHz per vCPU, timer_arm's IPI-poll
 * cap) already classifies the interrupted guest PC for SNAP_WFI_RESUME
 * (compat/wfi-resume.h): WFI_DECLINE_BUSY means the vCPU was running; RESUME,
 * IPI, TIMER, LINE and WAKE all found it at WFI+4 (idle); STATE and TEXT are
 * unknown and ignored. Those per-vCPU counters (perf.fast[slot].wfi) are a
 * 1 kHz busy sampler; this governor only reads their deltas.
 *
 * Policy, once per window (20 ms) on vCPU 0's locked tick, per domain:
 *  - demand = the highest busy fraction among the vCPUs on that domain, each
 *    averaged with its previous window's estimate (one busy vCPU keeps a
 *    shared cluster fast); a vCPU with fewer than CPU_DVFS_MIN_SAMPLES
 *    classified ticks keeps its last value, and one with none for
 *    CPU_DVFS_STALE_WINDOWS drops out;
 *  - hispeed: demand >= 90 % asks for the ceiling; otherwise the lowest level
 *    whose kHz >= 1.25 x demand x the granted level's kHz (schedutil's
 *    headroom on a non-invariant utilisation), within [floor, ceiling];
 *  - ceiling = min(sustained level, thermal clamp, the firmware cap found);
 *  - up at once; down only when the target is at least two levels lower for
 *    CPU_DVFS_DOWN_WINDOWS consecutive windows, to one level above the highest
 *    of those targets (a one-level dead band against step-down/step-up cycles);
 *  - thermal clamp below the monitor's 95 C guard: from DVFS_WARM_MC the
 *    ceiling falls linearly to the floor at DVFS_HOT_MC, 3 C hysteresis; no
 *    valid reading clamps to the floor; the clamp acts at once, even while a
 *    request is being verified;
 *  - levels 0 and 255 are never written (SCMI 0 means "no request"), nor any
 *    boost level; the same level is not written twice in a row except the one
 *    re-assert and a reprobe.
 * One writer (vCPU 0), at most one LEVEL_SET per domain per window. A domain
 * whose LEVEL_GET is not a level index for CPU_DVFS_VERIFY_LATCH windows after
 * a request latches (no more writes). Restore writes the level LEVEL_GET showed
 * at start when it was a valid index, else the boot level; idempotent.
 *
 * Nothing here touches hardware: the monitor supplies the MMIO through struct
 * cpu_dvfs_io and refuses any address cpu_dvfs_*_allowed rejects.
 * tools/test-dvfs.c runs this exact code natively against recorded traces. */
#pragma once
#include <stddef.h>
#include <stdint.h>

#define CPU_DVFS_MAGIC UINT64_C(0x3153564644555043) /* CPUDVFS1 */
#define CPU_DVFS_ABI 2u
#define CPU_DVFS_DOMAINS 3u
#define CPU_DVFS_LEVELS 22u
#define CPU_DVFS_SLOTS 6u
#define CPU_DVFS_WINDOW_MS 20u
#define CPU_DVFS_DOWN_WINDOWS 5u
#define CPU_DVFS_MIN_SAMPLES 5u
#define CPU_DVFS_STALE_WINDOWS 10u
#define CPU_DVFS_HISPEED_PCT 90u
#define CPU_DVFS_HEADROOM_PCT 125u
#define CPU_DVFS_VERIFY_RETRY 2u       /* LEVEL_GET still not the request: write it once more */
#define CPU_DVFS_REFUSE_WINDOWS 4u     /* still not: refused (80 ms; gen1 applied within one 20 ms window) */
#define CPU_DVFS_VERIFY_LATCH 8u       /* LEVEL_GET no level index this long after a request: latched */
#define CPU_DVFS_REPROBE_WINDOWS 250u  /* 5 s between re-asks of the ceiling above a firmware cap */
#define CPU_DVFS_REPROBES 12u
#define CPU_DVFS_MEASURE_WINDOWS 50u   /* io->khz once a second */
#ifndef DVFS_WARM_MC
#define DVFS_WARM_MC 75000
#endif
#ifndef DVFS_HOT_MC
#define DVFS_HOT_MC 85000
#endif
#ifndef DVFS_HYST_MC
#define DVFS_HYST_MC 3000
#endif
_Static_assert(DVFS_WARM_MC < DVFS_HOT_MC && DVFS_HOT_MC < 95000, "clamp below the thermal guard's stop");
_Static_assert(CPU_DVFS_VERIFY_RETRY < CPU_DVFS_REFUSE_WINDOWS && CPU_DVFS_REFUSE_WINDOWS < CPU_DVFS_VERIFY_LATCH,
               "re-assert, then refuse, then latch");

/* 0: each domain's sustained level. A smaller index caps every domain lower. */
#ifndef SNAP_CPU_DVFS_CEILING
#define SNAP_CPU_DVFS_CEILING 0
#endif
/* 0: each domain's firmware boot level (PDP0 16, PDP1/2 13). */
#ifndef SNAP_CPU_DVFS_FLOOR
#define SNAP_CPU_DVFS_FLOOR 0
#endif

/* wfi-resume.h enum order: RESUME, STATE, BUSY, TEXT, IPI, TIMER, LINE, WAKE. */
#define CPU_DVFS_WFI_BUSY 2u
#define CPU_DVFS_WFI_IDLE_MASK ((1u << 0) | (1u << 4) | (1u << 5) | (1u << 6) | (1u << 7))

struct cpu_dvfs_domain_desc {
    uint64_t level_set, doorbell, level_get, limits_get;   /* fastchannels (gen1-v50-query-pdp0-2.json) */
    uint32_t doorbell_set;                     /* db_set; db_preserve is 0 */
    uint32_t levels, sustained, boot;          /* boot: what firmware ran before any request */
    uint32_t khz[CPU_DVFS_LEVELS];             /* PERF_DESCRIBE_LEVELS (gen1-query-2.json) */
};

static const struct cpu_dvfs_domain_desc CPU_DVFS_DOMAIN[CPU_DVFS_DOMAINS] = {
    {0x19980118u, 0x1998011cu, 0x17610148u, 0x17610160u, 0xfu, 21u, 20u, 16u,
     {355200, 902400, 1056000, 1209600, 1363200, 1516800, 1651200, 1785600, 1939200, 2073600, 2208000,
      2342400, 2496000, 2630400, 2764800, 2918400, 3072000, 3225600, 3398400, 3552000, 3609600, 0}},
    {0x1a980118u, 0x1a98011cu, 0x17610150u, 0x17610168u, 0xfu, 22u, 19u, 13u,
     {355200, 883200, 1132800, 1382400, 1593600, 1785600, 1996800, 2188800, 2400000, 2611200, 2822400,
      3033600, 3225600, 3436800, 3628800, 3801600, 3955200, 4128000, 4281600, 4454400, 4800000, 5011200}},
    {0x1b980118u, 0x1b98011cu, 0x17610158u, 0x17610170u, 0xfu, 22u, 19u, 13u,
     {355200, 883200, 1132800, 1382400, 1593600, 1785600, 1996800, 2188800, 2400000, 2611200, 2822400,
      3033600, 3225600, 3436800, 3628800, 3801600, 3955200, 4128000, 4281600, 4454400, 4800000, 5011200}},
};
_Static_assert(SNAP_CPU_DVFS_CEILING >= 0 && SNAP_CPU_DVFS_CEILING < 22, "ceiling is a level index");
_Static_assert(SNAP_CPU_DVFS_FLOOR >= 0 && SNAP_CPU_DVFS_FLOOR < 22, "floor is a level index");

struct cpu_dvfs_io {
    void *ctx;
    uint32_t (*rd32)(void *ctx, uint64_t pa);
    void (*wr32)(void *ctx, uint64_t pa, uint32_t value);   /* device store, then DSB SY */
    uint32_t (*khz)(void *ctx);   /* optional: the calling core's clock, timed by the caller (0 = no reading) */
};

enum cpu_dvfs_status {
    CPU_DVFS_OFF,          /* not started: no thermal guard, or no governed domain */
    CPU_DVFS_RUNNING,
    CPU_DVFS_STOPPED,      /* restored */
};

/* One governed domain: the reported words. Every level here is an SCMI level index. */
struct cpu_dvfs_domain {
    uint64_t slots;                        /* vCPU slot mask on this domain; 0 = not governed */
    uint32_t level;                        /* granted: the last LEVEL_GET that was a level index (0: none yet) */
    uint32_t requested;                    /* the last LEVEL_SET written (0: none) */
    uint32_t floor, ceiling;               /* ceiling: the sustained level or SNAP_CPU_DVFS_CEILING */
    uint32_t restore, initial_get;
    uint32_t cap;                          /* the highest level the firmware granted after a refusal (else ceiling) */
    uint32_t walk;                         /* 1 while walking down from a refused level */
    uint32_t writes, refusals;             /* refusals: requests LEVEL_GET never showed */
    uint32_t mismatches, latched;          /* latched: 0x80000000 | the LEVEL_GET word */
    uint32_t verify, settled;              /* verify: the request awaiting LEVEL_GET; settled: window of the last cap */
    uint32_t below, below_target;
    uint32_t clamped_windows, last_demand_pct;
    uint32_t limits_start, limits_last;    /* LIMITS_GET word, raw */
    uint32_t limits_changes, refused_mask; /* refused_mask: bit n = level n was refused at least once */
    uint32_t granted_max, unknown_ms;      /* unknown: time whose LEVEL_GET was not a level index */
    uint32_t reprobes, accepted;           /* accepted: requests LEVEL_GET confirmed */
    uint32_t residency_ms[CPU_DVFS_LEVELS];   /* ms at each GRANTED level (LEVEL_GET at the window's end) */
};

struct cpu_dvfs_private {
    uint32_t last_busy[CPU_DVFS_SLOTS], last_idle[CPU_DVFS_SLOTS];
    uint32_t util_pct[CPU_DVFS_SLOTS], stale[CPU_DVFS_SLOTS];
    uint64_t slot_domain[CPU_DVFS_SLOTS];  /* 0..2, or ~0 for no vCPU in the slot */
};

struct cpu_dvfs_state {
    uint64_t magic, abi, status, reason;
    uint64_t hz, window_ticks, next_window, windows;
    uint64_t thermal_mc, thermal_clamp, hispeed, restores;
    int64_t thermal_eff_mc;                /* the reading the clamp used: rises at once, falls past 3 C */
    /* CNTPCT at the start and at the last window: windows end at the first tick past 20 ms, so time is measured,
     * not counted (b12v4: 9775 windows were 247 s, not 195.5). */
    uint64_t started, last_window;
    /* io->khz on vCPU 0's core (the domain of slot 0): count, sum of MHz, min/max/last kHz, LEVEL_GET then. */
    uint64_t meas_count, meas_mhz_sum;
    uint32_t meas_khz_min, meas_khz_max, meas_khz_last, meas_get_last;
    struct cpu_dvfs_domain domain[CPU_DVFS_DOMAINS];
    struct cpu_dvfs_private priv;          /* not reported */
};
#define CPU_DVFS_REPORT_WORDS (offsetof(struct cpu_dvfs_state, priv) / 8)
_Static_assert(offsetof(struct cpu_dvfs_state, priv) % 8 == 0, "report is whole words");
_Static_assert(sizeof(struct cpu_dvfs_domain) % 8 == 0, "domain is whole words");

static inline int cpu_dvfs_write_allowed(uint64_t pa)
{
    for (unsigned d = 0; d < CPU_DVFS_DOMAINS; d++)
        if (pa == CPU_DVFS_DOMAIN[d].level_set || pa == CPU_DVFS_DOMAIN[d].doorbell) return 1;
    return 0;
}

static inline int cpu_dvfs_read_allowed(uint64_t pa)
{
    for (unsigned d = 0; d < CPU_DVFS_DOMAINS; d++)
        if (pa == CPU_DVFS_DOMAIN[d].level_get || pa == CPU_DVFS_DOMAIN[d].limits_get) return 1;
    return 0;
}

static inline uint32_t cpu_dvfs_rd(const struct cpu_dvfs_io *io, uint64_t pa)
{
    return cpu_dvfs_read_allowed(pa) ? io->rd32(io->ctx, pa) : UINT32_C(0xffffffff);
}

/* LEVEL_GET 0 is "no request" and 255 "not published"; only 1..levels-1 is a level the firmware runs. */
static inline int cpu_dvfs_valid(unsigned d, uint32_t get)
{
    return get >= 1 && get < CPU_DVFS_DOMAIN[d].levels;
}

static inline unsigned cpu_dvfs_request(struct cpu_dvfs_state *s, const struct cpu_dvfs_io *io, unsigned d,
                                        uint32_t level, int again)
{
    const struct cpu_dvfs_domain_desc *k = &CPU_DVFS_DOMAIN[d];
    struct cpu_dvfs_domain *g = &s->domain[d];
    /* Never 0 (no request) or a boost level: the floor/ceiling already keep
     * level inside [1, sustained]; this is the last line. */
    if (!level || level > k->sustained || g->latched) return 0;
    if (!cpu_dvfs_write_allowed(k->level_set) || !cpu_dvfs_write_allowed(k->doorbell)) return 0;
    io->wr32(io->ctx, k->level_set, level);   /* the level before the doorbell (wr32 ends in DSB SY) */
    io->wr32(io->ctx, k->doorbell, k->doorbell_set);
    if (!again) g->mismatches = 0;
    g->requested = level;
    g->verify = level;
    g->writes++;
    return 1;
}

/* hz: CNTPCT frequency. affinity[slot]: physical MPIDR affinity of the CPU
 * that runs vCPU slot, ~0 for none. thermal: nonzero when the launch has the
 * thermal guard (EARLY_STOP_F_THERMAL); without it nothing is ever written. */
static inline void cpu_dvfs_start(struct cpu_dvfs_state *s, const struct cpu_dvfs_io *io, uint64_t hz,
                                  const uint64_t affinity[CPU_DVFS_SLOTS], int thermal, uint64_t now)
{
    *s = (struct cpu_dvfs_state){.magic = CPU_DVFS_MAGIC, .abi = CPU_DVFS_ABI, .hz = hz,
                                 .thermal_eff_mc = INT64_MIN, .meas_khz_min = UINT32_MAX};
    for (unsigned n = 0; n < CPU_DVFS_SLOTS; n++) {
        uint64_t d = affinity[n] == ~UINT64_C(0) ? ~UINT64_C(0) : (affinity[n] >> 16) & 0xff;
        s->priv.slot_domain[n] = d < CPU_DVFS_DOMAINS ? d : ~UINT64_C(0);
        s->priv.stale[n] = CPU_DVFS_STALE_WINDOWS;
        if (s->priv.slot_domain[n] != ~UINT64_C(0)) s->domain[d].slots |= UINT64_C(1) << n;
    }
    if (!thermal) { s->reason = 1; return; }          /* C3: no thermal guard */
    if (!hz) { s->reason = 2; return; }
    unsigned governed = 0;
    for (unsigned d = 0; d < CPU_DVFS_DOMAINS; d++) {
        struct cpu_dvfs_domain *g = &s->domain[d];
        const struct cpu_dvfs_domain_desc *k = &CPU_DVFS_DOMAIN[d];
        if (!g->slots) continue;
        governed++;
        uint32_t get = cpu_dvfs_rd(io, k->level_get);
        g->initial_get = get;
        g->limits_start = g->limits_last = cpu_dvfs_rd(io, k->limits_get);
        g->ceiling = SNAP_CPU_DVFS_CEILING && SNAP_CPU_DVFS_CEILING < k->sustained ?
                     SNAP_CPU_DVFS_CEILING : k->sustained;
        g->floor = SNAP_CPU_DVFS_FLOOR ? SNAP_CPU_DVFS_FLOOR : k->boot;
        if (g->floor > g->ceiling) g->floor = g->ceiling;
        if (!g->floor) g->floor = 1;
        g->cap = g->ceiling;
        /* U2: LEVEL_GET 0 = no request, 255 = not published; restore those to the boot level. */
        g->restore = get >= 1 && get <= k->sustained ? get : k->boot;
        g->level = cpu_dvfs_valid(d, get) ? get : 0;
        if (g->level > g->granted_max) g->granted_max = g->level;
    }
    if (!governed) { s->reason = 3; return; }
    s->window_ticks = hz / 1000 * CPU_DVFS_WINDOW_MS;
    s->next_window = now + s->window_ticks;
    s->started = s->last_window = now;
    s->status = CPU_DVFS_RUNNING;
}

static inline int cpu_dvfs_due(const struct cpu_dvfs_state *s, uint64_t now)
{
    return s->status == CPU_DVFS_RUNNING && (int64_t)(now - s->next_window) >= 0;
}

/* The reading the clamp acts on (C4): a rise at once, a fall only past the hysteresis, so a reading that
 * hovers at a step boundary does not toggle the level. */
static inline int64_t dvfs_thermal_effective(int64_t previous, int64_t mc)
{
    if (mc == INT64_MIN || previous == INT64_MIN || mc >= previous) return mc;
    return mc + DVFS_HYST_MC < previous ? mc + DVFS_HYST_MC : previous;
}

/* The effective ceiling under the thermal clamp (C4). */
static inline uint32_t cpu_dvfs_thermal_ceiling(uint32_t floor, uint32_t ceiling, int64_t t, int ready)
{
    if (!ready || t == INT64_MIN) return floor;
    if (t >= DVFS_HOT_MC) return floor;
    if (t <= DVFS_WARM_MC) return ceiling;
    uint64_t span = (uint64_t)(ceiling - floor);
    uint64_t cut = ((uint64_t)(t - DVFS_WARM_MC) * span + (DVFS_HOT_MC - DVFS_WARM_MC - 1)) /
                   (DVFS_HOT_MC - DVFS_WARM_MC);
    return cut >= span ? floor : (uint32_t)(ceiling - cut);
}

/* U5/U13: LEVEL_GET against the outstanding request. Returns the writes made (the re-assert or a walk step). */
static inline unsigned cpu_dvfs_verify(struct cpu_dvfs_state *s, const struct cpu_dvfs_io *io, unsigned d,
                                       uint32_t get, int valid)
{
    struct cpu_dvfs_domain *g = &s->domain[d];
    uint32_t want = g->verify;
    if (valid && get == want) {
        g->verify = 0;
        g->mismatches = 0;
        g->accepted++;
        if (g->walk || want > g->cap) {        /* the walk (or a reprobe) found a level the firmware grants */
            g->walk = 0;
            g->cap = want;
            g->settled = (uint32_t)s->windows;
        }
        return 0;
    }
    g->mismatches++;
    if (!valid) {                              /* nothing published: only a latch, never a cap */
        if (g->mismatches >= CPU_DVFS_VERIFY_LATCH) {
            g->latched = UINT32_C(0x80000000) | get;
            g->verify = 0;
            g->walk = 0;
        } else if (g->mismatches == CPU_DVFS_VERIFY_RETRY) {
            return cpu_dvfs_request(s, io, d, want, 1);
        }
        return 0;
    }
    if (g->mismatches == CPU_DVFS_VERIFY_RETRY && !g->walk) return cpu_dvfs_request(s, io, d, want, 1);
    if (g->mismatches < CPU_DVFS_REFUSE_WINDOWS) return 0;
    g->verify = 0;
    g->mismatches = 0;
    if (get > want) {
        /* The firmware runs above the request: a lower request it keeps above (nothing learnt), or, mid-walk, a
         * higher request of this walk granted late; either way the granted level is grantable. */
        if (g->walk) { g->cap = get; g->settled = (uint32_t)s->windows; }
        g->walk = 0;
        return 0;
    }
    /* Refused: the firmware runs `get`, below `want`. */
    g->refusals++;
    if (want < 32) g->refused_mask |= UINT32_C(1) << want;
    uint32_t next = want - 1;
    uint32_t base = get > g->floor ? get : (uint32_t)g->floor;
    if (next > base) {                          /* walk: one level lower, verified the same way */
        g->walk = 1;
        g->cap = next;
        return cpu_dvfs_request(s, io, d, next, 0);
    }
    g->walk = 0;
    g->cap = base;                              /* nothing above the granted level was granted */
    g->settled = (uint32_t)s->windows;
    return 0;
}

/* One window. wfi[slot] points at that vCPU's eight perf.fast[slot].wfi
 * counters (read relaxed; another CPU may be incrementing them). mc/ready: the
 * thermal guard's latest maximum (current_mc) and whether it is ready.
 * Returns the number of LEVEL_SET writes made. */
static inline unsigned cpu_dvfs_tick(struct cpu_dvfs_state *s, const struct cpu_dvfs_io *io, uint64_t now,
                                     const volatile uint32_t *const wfi[CPU_DVFS_SLOTS], int64_t mc, int ready)
{
    if (!cpu_dvfs_due(s, now)) return 0;
    s->windows++;
    /* Catch up without bursts: the next window is one window from now. */
    s->next_window = now + s->window_ticks;
    uint32_t span_ms = (uint32_t)((now - s->last_window) * 1000u / s->hz);
    s->last_window = now;
    s->thermal_mc = (uint64_t)mc;
    s->thermal_eff_mc = ready ? dvfs_thermal_effective(s->thermal_eff_mc, mc) : INT64_MIN;
    struct cpu_dvfs_private *p = &s->priv;
    for (unsigned n = 0; n < CPU_DVFS_SLOTS; n++) {
        if (p->slot_domain[n] == ~UINT64_C(0) || !wfi[n]) continue;
        uint32_t busy = wfi[n][CPU_DVFS_WFI_BUSY], idle = 0;
        for (unsigned r = 0; r < 8; r++)
            if (CPU_DVFS_WFI_IDLE_MASK & (1u << r)) idle += wfi[n][r];
        uint32_t db = busy - p->last_busy[n], di = idle - p->last_idle[n];   /* U9: wrap-safe */
        p->last_busy[n] = busy;
        p->last_idle[n] = idle;
        if (db + di >= CPU_DVFS_MIN_SAMPLES) {
            /* U8: one window holds only ~20 samples per vCPU; average with the previous estimate (a 20 ms
             * half-life, PELT-like) so a single noisy window neither jumps to the ceiling nor drops. */
            uint32_t now_pct = (uint32_t)((uint64_t)db * 100u / (db + di));
            p->util_pct[n] = p->stale[n] >= CPU_DVFS_STALE_WINDOWS ? now_pct : (p->util_pct[n] + now_pct + 1) / 2;
            p->stale[n] = 0;
        } else if (p->stale[n] < CPU_DVFS_STALE_WINDOWS) {
            p->stale[n]++;
        }
    }
    unsigned writes = 0;
    for (unsigned d = 0; d < CPU_DVFS_DOMAINS; d++) {
        struct cpu_dvfs_domain *g = &s->domain[d];
        const struct cpu_dvfs_domain_desc *k = &CPU_DVFS_DOMAIN[d];
        if (!g->slots) continue;
        /* U13: what the firmware runs, every window. */
        uint32_t get = cpu_dvfs_rd(io, k->level_get);
        int valid = cpu_dvfs_valid(d, get);
        if (valid) {
            g->level = get;
            g->residency_ms[get] += span_ms;
            if (get > g->granted_max) g->granted_max = get;
        } else {
            g->unknown_ms += span_ms;
        }
        uint32_t limits = cpu_dvfs_rd(io, k->limits_get);
        if (limits != g->limits_last) { g->limits_last = limits; g->limits_changes++; }
        if (g->latched) continue;
        uint32_t cur = g->level ? g->level : (uint32_t)g->restore;
        uint32_t ceiling = cpu_dvfs_thermal_ceiling(g->floor, g->ceiling, s->thermal_eff_mc, ready);
        if (ceiling < g->ceiling) g->clamped_windows++;
        if (cur > ceiling && g->requested != ceiling) {
            /* C4: the clamp acts at once, whatever is being verified (once per clamp level: a firmware that keeps
             * a higher level is verified and re-asserted like any request, not written every window). */
            g->below = 0;
            g->walk = 0;
            writes += cpu_dvfs_request(s, io, d, ceiling, 0);
            continue;
        }
        if (g->verify) {
            writes += cpu_dvfs_verify(s, io, d, get, valid);
            if (g->verify || g->latched) continue;     /* one request outstanding at a time */
            cur = g->level ? g->level : (uint32_t)g->restore;
        }
        uint32_t demand = 0;
        for (unsigned n = 0; n < CPU_DVFS_SLOTS; n++)
            if ((g->slots >> n & 1) && p->stale[n] < CPU_DVFS_STALE_WINDOWS && p->util_pct[n] > demand)
                demand = p->util_pct[n];
        g->last_demand_pct = demand;
        /* U13: re-ask the ceiling above a firmware cap now and then, while the demand is there. */
        if (demand >= CPU_DVFS_HISPEED_PCT && g->cap < ceiling && cur < ceiling && g->reprobes < CPU_DVFS_REPROBES &&
            (uint32_t)s->windows - g->settled >= CPU_DVFS_REPROBE_WINDOWS) {
            g->reprobes++;
            g->cap = ceiling;
            g->below = 0;
            writes += cpu_dvfs_request(s, io, d, ceiling, 0);
            continue;
        }
        uint32_t top = ceiling < g->cap ? ceiling : g->cap;
        if (top < g->floor) top = g->floor;
        uint32_t target;
        if (demand >= CPU_DVFS_HISPEED_PCT) {
            target = top;
            if (top > cur) s->hispeed++;
        } else {
            uint64_t want = (uint64_t)k->khz[cur < k->levels ? cur : k->sustained] * demand *
                            CPU_DVFS_HEADROOM_PCT / 10000u;
            target = top;
            for (uint32_t l = g->floor; l <= top; l++)
                if (k->khz[l] >= want) { target = l; break; }
        }
        if (target < g->floor) target = g->floor;
        if (target > top) target = top;
        if (target == g->requested) {
            /* Asked already; LEVEL_GET says what the firmware made of it. */
            if (target >= cur) g->below = 0;
            continue;
        }
        if (target > cur && (target >= cur + 2 || demand >= CPU_DVFS_HISPEED_PCT || target == top)) {
            /* Up at once; a one-level step only when it reaches the ceiling or on hispeed (dead band). */
            g->below = 0;
            writes += cpu_dvfs_request(s, io, d, target, 0);
        } else if (target >= cur) {
            g->below = 0;
        } else if (target + 1 < cur) {
            /* U8: down only past a one-level dead band, after CPU_DVFS_DOWN_WINDOWS windows, to one level above
             * the highest target seen meanwhile (so the next window does not step straight back up). */
            if (!g->below || target > g->below_target) g->below_target = target;
            if (++g->below >= CPU_DVFS_DOWN_WINDOWS) {
                uint32_t to = g->below_target <= g->floor ? g->floor : g->below_target + 1;
                g->below = 0;
                if (to < cur && to != g->requested) writes += cpu_dvfs_request(s, io, d, to, 0);
            }
        } else {
            g->below = 0;
        }
    }
    /* Consecutive windows with any domain under the clamp. */
    {
        int any = 0;
        for (unsigned d = 0; d < CPU_DVFS_DOMAINS; d++)
            if (s->domain[d].slots &&
                cpu_dvfs_thermal_ceiling(s->domain[d].floor, s->domain[d].ceiling, s->thermal_eff_mc, ready) <
                    s->domain[d].ceiling)
                any = 1;
        s->thermal_clamp = any ? s->thermal_clamp + 1 : 0;
    }
    /* U14: the clock vCPU 0's core runs, timed independently of LEVEL_GET (once a second). */
    if (io->khz && s->windows % CPU_DVFS_MEASURE_WINDOWS == 1 && p->slot_domain[0] < CPU_DVFS_DOMAINS) {
        uint32_t khz = io->khz(io->ctx);
        if (khz) {
            s->meas_count++;
            s->meas_mhz_sum += khz / 1000u;
            s->meas_khz_last = khz;
            if (khz < s->meas_khz_min) s->meas_khz_min = khz;
            if (khz > s->meas_khz_max) s->meas_khz_max = khz;
            s->meas_get_last = s->domain[p->slot_domain[0]].level;
        }
    }
    return writes;
}

/* C5/U10: restore every governed domain that was written; idempotent. */
static inline unsigned cpu_dvfs_stop(struct cpu_dvfs_state *s, const struct cpu_dvfs_io *io)
{
    if (s->status != CPU_DVFS_RUNNING) return 0;
    unsigned writes = 0;
    for (unsigned d = 0; d < CPU_DVFS_DOMAINS; d++) {
        struct cpu_dvfs_domain *g = &s->domain[d];
        if (!g->slots || !g->writes) continue;
        uint32_t latched = g->latched;
        g->latched = 0;                          /* a latched domain is still restored once */
        writes += cpu_dvfs_request(s, io, d, g->restore, 0);
        g->latched = latched;
    }
    s->restores++;
    s->status = CPU_DVFS_STOPPED;
    return writes;
}

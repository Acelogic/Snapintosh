/* SPDX-License-Identifier: MIT */
/* agents/dvfs: the CPU and GPU governors (compat/cpu-dvfs.h, compat/gpu-dvfs.h), the exact code the monitor
 * links, run natively against
 *  - an SCMI PERF fastchannel model (LEVEL_SET + doorbell -> LEVEL_GET, LIMITS_GET, per PDP domain) whose
 *    firmware accepts, clamps to a limit, rejects above a limit (b12v4: PDP1 kept 13 under six busy cores),
 *    or never publishes;
 *  - a GMU model that serves the HFI command queue in a GPU-arena image the way q1n1's hfi_send /
 *    hfi_wait_ack expect (ack with the command's id and seq, F2H errors, NACK, silence, a stuck queue);
 *  - an async-IB flight model (struct gpu_dvfs_load: doorbell tick, flights, ended, sum_ticks);
 *  - a first-order thermal model of the A16 (calibrated on v78: 61.0 C after 393 s of desktop load);
 *  - recorded load traces (agents/dvfs/work/traces, converted by tests/sim-governors.py).
 * Failure modes: agents/dvfs FAILURE-MODES.md (C, G, U). No hardware.
 *
 *   clang -std=gnu11 -O1 -g -fsanitize=address,undefined -fno-sanitize-recover=all -Wall -Wextra -Werror \
 *     tools/test-dvfs.c -o /tmp/test-dvfs -lm && /tmp/test-dvfs [replay.txt [summary.json [block.bin]]]
 * Add -DSNAP_GPU_DVFS_MIDFLIGHT=0 for the deferring variant (the checks follow the define).
 */
#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../compat/cpu-dvfs.h"
#include "../compat/gpu-dvfs.h"

static unsigned checks, failures;
#define CHECK(cond, ...)                                                                   \
    do {                                                                                   \
        checks++;                                                                          \
        if (!(cond)) {                                                                     \
            failures++;                                                                    \
            fprintf(stderr, "FAIL %s:%d: ", __FILE__, __LINE__);                           \
            fprintf(stderr, __VA_ARGS__);                                                  \
            fputc('\n', stderr);                                                           \
        }                                                                                  \
    } while (0)

#define HZ 19200000ull
#define MS (HZ / 1000)

/* ---------------------------------------------------------------- SCMI fastchannel model */
enum fw_mode {
    FW_ACCEPT,     /* LEVEL_GET follows every request (gen1 with one Prime core held) */
    FW_CLAMP,      /* LEVEL_GET = min(request, cap) */
    FW_REJECT,     /* a request above cap leaves LEVEL_GET as it was (b12v4's PDP1: 13 kept) */
    FW_SILENT,     /* nothing published (LEVEL_GET keeps its word, e.g. 255) */
};
struct scmi {
    uint32_t set[3], get[3], cap[3], limits[3];
    enum fw_mode mode[3];
    unsigned writes, doorbells, foreign, zero, boost, limits_reads;
    uint32_t max[3];
};
static int scmi_dom(uint64_t pa, int *kind)
{
    for (int d = 0; d < 3; d++) {
        if (pa == CPU_DVFS_DOMAIN[d].level_set) { *kind = 0; return d; }
        if (pa == CPU_DVFS_DOMAIN[d].doorbell) { *kind = 1; return d; }
        if (pa == CPU_DVFS_DOMAIN[d].level_get) { *kind = 2; return d; }
        if (pa == CPU_DVFS_DOMAIN[d].limits_get) { *kind = 3; return d; }
    }
    return -1;
}
static uint32_t scmi_rd(void *ctx, uint64_t pa)
{
    struct scmi *m = ctx;
    int k, d = scmi_dom(pa, &k);
    if (d < 0 || k < 2) { m->foreign++; return 0xffffffffu; }
    if (k == 3) { m->limits_reads++; return m->limits[d]; }
    return m->get[d];
}
static void scmi_wr(void *ctx, uint64_t pa, uint32_t v)
{
    struct scmi *m = ctx;
    int k, d = scmi_dom(pa, &k);
    if (d < 0 || k >= 2) { m->foreign++; return; }
    if (k == 0) {
        m->set[d] = v;
        m->writes++;
        if (!v) m->zero++;
        if (v > CPU_DVFS_DOMAIN[d].sustained) m->boost++;
        if (v > m->max[d]) m->max[d] = v;
        return;
    }
    if (v != CPU_DVFS_DOMAIN[d].doorbell_set) { m->foreign++; return; }
    m->doorbells++;
    uint32_t want = m->set[d];
    switch (m->mode[d]) {
    case FW_ACCEPT: m->get[d] = want; break;
    case FW_CLAMP: m->get[d] = m->cap[d] && want > m->cap[d] ? m->cap[d] : want; break;
    case FW_REJECT: if (!m->cap[d] || want <= m->cap[d]) m->get[d] = want; break;
    case FW_SILENT: break;
    }
}
/* io->khz: the clock of vCPU 0's domain as the firmware runs it (domain chosen by the scenario). */
static unsigned khz_domain = 1;
static uint32_t scmi_khz(void *ctx)
{
    struct scmi *m = ctx;
    uint32_t get = m->get[khz_domain];
    return cpu_dvfs_valid(khz_domain, get) ? CPU_DVFS_DOMAIN[khz_domain].khz[get] : 0;
}

/* ---------------------------------------------------------------- GMU / HFI model */
#define ARENA 0x96000000ull
#define ARENA_BYTES 0x120000u
enum gmu_mode { GMU_ACK, GMU_NACK, GMU_SILENT, GMU_STUCK, GMU_ERROR_FIRST, GMU_NACK_ABOVE };
struct gmu {
    uint8_t *mem;
    uint32_t intr;
    enum gmu_mode mode;
    unsigned doorbells, votes, acks, foreign, bad_msgs, discipline;
    uint32_t perf, bw, last_seq, nack_above;
    uint64_t clock, clean_line, store_line;
    int expect_clean;
};
static uint32_t *gw(struct gmu *g, uint64_t pa) { return (uint32_t *)(g->mem + (pa - ARENA)); }
static int in_arena(uint64_t pa) { return pa >= ARENA && pa + 4 <= ARENA + ARENA_BYTES; }
static uint64_t hdr(unsigned q, unsigned word) { return ARENA + GPU_DVFS_HFI_OFF + GPU_DVFS_Q_HDR(q) + 4 * word; }
static uint64_t qdata(unsigned q, unsigned index) { return ARENA + GPU_DVFS_HFI_OFF + GPU_DVFS_Q_DATA(q) + 4 * index; }
static void gmu_post(struct gmu *g, const uint32_t *w, unsigned n)
{
    uint32_t write = *gw(g, hdr(1, GPU_DVFS_Q_WRITE));
    for (unsigned i = 0; i < n; i++) { *gw(g, qdata(1, write)) = w[i]; write = (write + 1) % GPU_DVFS_Q_DWORDS; }
    write = (write + 3) & ~3u;
    *gw(g, hdr(1, GPU_DVFS_Q_WRITE)) = write % GPU_DVFS_Q_DWORDS;
    g->intr |= 1;
}
static void gmu_doorbell(struct gmu *g)
{
    g->doorbells++;
    if (g->mode == GMU_STUCK) return;
    uint32_t read = *gw(g, hdr(0, GPU_DVFS_Q_READ)), write = *gw(g, hdr(0, GPU_DVFS_Q_WRITE));
    while (read != write) {
        uint32_t h = *gw(g, qdata(0, read)), n = h >> 8 & 0xff, w[8] = {0};
        for (unsigned i = 0; i < n && i < 8; i++) w[i] = *gw(g, qdata(0, (read + i) % GPU_DVFS_Q_DWORDS));
        read = ((read + n + 3) & ~3u) % GPU_DVFS_Q_DWORDS;
        if ((h & 0xff) != GPU_DVFS_MSG_VOTE || n != 4 || w[1] != 1) { g->bad_msgs++; continue; }
        g->votes++;
        g->last_seq = h >> 20;
        if (g->mode == GMU_ERROR_FIRST) {
            uint32_t err[4] = {GPU_DVFS_F2H_ERROR | 4u << 8, 0xdead, 0, 0};
            gmu_post(g, err, 4);
        }
        if (g->mode == GMU_SILENT) continue;
        uint32_t status = g->mode == GMU_NACK || (g->mode == GMU_NACK_ABOVE && w[2] > g->nack_above) ? 1 : 0;
        if (!status) { g->perf = w[2]; g->bw = w[3]; }
        uint32_t ack[4] = {GPU_DVFS_MSG_VOTE | GPU_DVFS_TYPE_ACK << 16 | 4u << 8, h, status, 0};
        gmu_post(g, ack, 4);
        g->acks++;
    }
    *gw(g, hdr(0, GPU_DVFS_Q_READ)) = read;
}
static uint32_t gmu_rd(void *ctx, uint64_t pa)
{
    struct gmu *g = ctx;
    g->clock += 64;
    if (pa == GPU_DVFS_GMU_INTR_INFO) return g->intr;
    if (in_arena(pa)) return *gw(g, pa);
    g->foreign++;
    return 0xffffffffu;
}
static int index_word(uint64_t pa)
{
    return pa == hdr(0, GPU_DVFS_Q_WRITE) || pa == hdr(1, GPU_DVFS_Q_READ);
}
static void gmu_wr(void *ctx, uint64_t pa, uint32_t v)
{
    struct gmu *g = ctx;
    g->clock += 64;
    if (pa == GPU_DVFS_GMU_DOORBELL) { if (v == 1) gmu_doorbell(g); return; }
    if (pa == GPU_DVFS_GMU_INTR_CLR) { g->intr &= ~v; return; }
    if (!in_arena(pa)) { g->foreign++; return; }
    if (index_word(pa)) {
        /* G4: an index word is stored right after a clean of its line, and cleaned again right after. */
        if (g->clean_line != (pa & ~63ull)) g->discipline++;
        g->expect_clean = 1;
        g->store_line = pa & ~63ull;
    }
    *gw(g, pa) = v;
}
static void gmu_clean(void *ctx, uint64_t pa, uint64_t size)
{
    struct gmu *g = ctx;
    (void)size;
    g->clock += 32;
    if (g->expect_clean) {
        if ((pa & ~63ull) != g->store_line) g->discipline++;
        g->expect_clean = 0;
    }
    g->clean_line = pa & ~63ull;
}
static uint64_t gmu_now(void *ctx) { return ((struct gmu *)ctx)->clock += 16; }
/* O4: the host record as q1n1's hfi step leaves it: boot_token = hfi_token (START acked this GMU boot) and
 * hfi_opps = the table size it sent (0: q1n1 before ABI 4). */
static unsigned gmu_hfi_opps = 11;
#define TOP ((uint64_t)((gmu_hfi_opps ? gmu_hfi_opps : 6) < SNAP_GPU_DVFS_MAX_OPP ? (gmu_hfi_opps ? gmu_hfi_opps : 6) \
                                                                           : SNAP_GPU_DVFS_MAX_OPP))
static void gmu_init(struct gmu *g, enum gmu_mode mode, uint32_t seq, uint32_t start_index)
{
    memset(g, 0, sizeof *g);
    g->mem = calloc(1, ARENA_BYTES);
    g->mode = mode;
    g->clean_line = ~0ull;
    uint64_t host = ARENA + GPU_DVFS_STATE_OFF;
    *gw(g, host) = (uint32_t)GPU_DVFS_HOST_MAGIC;
    *gw(g, host + 4) = (uint32_t)(GPU_DVFS_HOST_MAGIC >> 32);
    *gw(g, host + 16) = (uint32_t)ARENA;
    *gw(g, host + 20) = (uint32_t)(ARENA >> 32);
    *gw(g, host + GPU_DVFS_HOST_SEQ) = seq;
    *gw(g, host + GPU_DVFS_HOST_BOOT) = 7;
    *gw(g, host + GPU_DVFS_HOST_HFI) = 7;
    *gw(g, host + GPU_DVFS_HOST_OPPS) = gmu_hfi_opps;
    for (unsigned q = 0; q < 3; q++) {
        *gw(g, hdr(q, GPU_DVFS_Q_SIZE)) = GPU_DVFS_Q_DWORDS;
        *gw(g, hdr(q, GPU_DVFS_Q_READ)) = start_index;
        *gw(g, hdr(q, GPU_DVFS_Q_WRITE)) = start_index;
    }
}
static struct gpu_dvfs_io gmu_io(struct gmu *g)
{
    return (struct gpu_dvfs_io){g, gmu_rd, gmu_wr, gmu_clean, gmu_now, HZ};
}

/* ---------------------------------------------------------------- scenarios (failure modes) */
static void wfi_feed(uint32_t wfi[6][8], const double busy[6], unsigned ticks, uint64_t *rng)
{
    for (unsigned n = 0; n < 6; n++)
        for (unsigned t = 0; t < ticks; t++) {
            *rng = *rng * 6364136223846793005ull + 1442695040888963407ull;
            double r = (double)(*rng >> 11) / 9007199254740992.0;
            if (busy[n] < 0) continue;            /* no vCPU in this slot */
            wfi[n][r < busy[n] ? CPU_DVFS_WFI_BUSY : 0]++;
        }
}
static unsigned cpu_run(struct cpu_dvfs_state *s, struct scmi *m, uint32_t wfi[6][8], const double busy[6],
                        unsigned windows, int64_t mc, uint64_t *now, uint64_t *rng)
{
    struct cpu_dvfs_io io = {m, scmi_rd, scmi_wr, scmi_khz};
    const volatile uint32_t *p[6];
    for (unsigned n = 0; n < 6; n++) p[n] = wfi[n];
    unsigned writes = 0;
    for (unsigned w = 0; w < windows; w++)
        for (unsigned ms = 0; ms < CPU_DVFS_WINDOW_MS; ms++) {
            wfi_feed(wfi, busy, 1, rng);
            *now += MS;
            writes += cpu_dvfs_tick(s, &io, *now, p, mc, mc != INT64_MIN);
        }
    return writes;
}
static const uint64_t PRIME6[6] = {0x10000, 0x10100, 0x10200, 0x10300, 0x10400, 0x10500};
static const uint64_t PERF6[6] = {0x0, 0x100, 0x200, 0x300, 0x400, 0x500};   /* no --prime-secondaries */

/* Windows (of 20 ms: the model ticks exactly every ms) at or above a level. */
static uint32_t residency_above(const struct cpu_dvfs_domain *g, uint32_t level)
{
    uint32_t n = 0;
    for (uint32_t l = level + 1; l < CPU_DVFS_LEVELS; l++) n += g->residency_ms[l];
    return n / CPU_DVFS_WINDOW_MS;
}
static uint32_t residency_total(const struct cpu_dvfs_domain *g)
{
    return residency_above(g, 0) + g->residency_ms[0] / CPU_DVFS_WINDOW_MS;
}
#define AT(g, l) ((g)->residency_ms[l] / CPU_DVFS_WINDOW_MS)

static void scenario_cpu(void)
{
    struct scmi m;
    struct cpu_dvfs_state s;
    uint32_t wfi[6][8];
    uint64_t now = 1000, rng = 1;
    double idle[6] = {0.02, 0.02, 0.02, 0.02, 0.02, 0.02}, busy[6] = {1, 1, 1, 1, 1, 1};
    double one[6] = {1.0, 0.02, 0.02, 0.02, 0.02, 0.02};
    struct cpu_dvfs_io io = {&m, scmi_rd, scmi_wr, scmi_khz};
    khz_domain = 1;

    /* C3: no thermal guard -> never starts, no MMIO. */
    memset(&m, 0, sizeof m); memset(wfi, 0, sizeof wfi);
    m.get[1] = 255;
    cpu_dvfs_start(&s, &io, HZ, PRIME6, 0, now);
    cpu_run(&s, &m, wfi, busy, 50, 50000, &now, &rng);
    CHECK(s.status == CPU_DVFS_OFF && m.writes == 0 && m.doorbells == 0, "C3: no thermal guard, nothing written");
    CHECK(cpu_dvfs_stop(&s, &io) == 0 && m.writes == 0, "C3: stop writes nothing");

    /* U2/U6/U1: all six vCPUs on PDP1 (prime); LEVEL_GET 255 at start -> restore = boot level 13. */
    memset(&m, 0, sizeof m); memset(wfi, 0, sizeof wfi);
    m.get[1] = 255;
    m.limits[1] = 0x00160000u;
    cpu_dvfs_start(&s, &io, HZ, PRIME6, 1, now);
    CHECK(s.status == CPU_DVFS_RUNNING && s.domain[1].slots == 0x3f && !s.domain[0].slots && !s.domain[2].slots,
          "U6: six vCPUs on PDP1 only");
    CHECK(s.domain[1].restore == 13 && s.domain[1].floor == 13 && s.domain[1].ceiling == 19 && s.domain[1].level == 0,
          "U2/U1: restore 13 (boot), floor 13, ceiling 19 (sustained), nothing granted yet, got %u/%u/%u/%u",
          s.domain[1].restore, s.domain[1].floor, s.domain[1].ceiling, s.domain[1].level);
    CHECK(s.domain[1].limits_start == 0x00160000u, "U13: LIMITS_GET kept raw at the start");
    cpu_run(&s, &m, wfi, one, 10, 50000, &now, &rng);
    CHECK(m.max[1] == 19 && m.get[1] == 19 && s.domain[1].level == 19 && s.domain[1].accepted >= 1,
          "U6/hispeed: one busy vCPU drives the shared domain to 19, LEVEL_GET confirms (got %u)", m.max[1]);
    CHECK(!m.boost && !m.zero && !m.foreign, "U1/U2/U3: no boost, no 0, no foreign address");
    CHECK(s.domain[1].unknown_ms >= 20 && residency_total(&s.domain[1]) + s.domain[1].unknown_ms / 20 == 10,
          "U13: the windows before LEVEL_GET published count as unknown, not as a level");
    unsigned before = m.writes;
    cpu_run(&s, &m, wfi, idle, 4, 50000, &now, &rng);
    CHECK(m.writes == before, "U8: no step down before %u windows", CPU_DVFS_DOWN_WINDOWS);
    cpu_run(&s, &m, wfi, idle, 4, 50000, &now, &rng);
    CHECK(m.get[1] == 13, "U8: back to the floor after the down delay (got %u)", m.get[1]);
    CHECK(m.writes - before == 1, "U8: one write for the step down (got %u)", m.writes - before);

    /* C4: thermal clamp. 80 C halves the span, 85 C forces the floor, INT64_MIN forces the floor. */
    cpu_run(&s, &m, wfi, busy, 3, 80000, &now, &rng);
    CHECK(m.get[1] == 16, "C4: 80 C caps at 16 (19 - ceil(5/10*6)) (got %u)", m.get[1]);
    cpu_run(&s, &m, wfi, busy, 2, 85000, &now, &rng);
    CHECK(m.get[1] == 13, "C4: 85 C -> floor at once (got %u)", m.get[1]);
    cpu_run(&s, &m, wfi, busy, 2, 83000, &now, &rng);
    CHECK(m.get[1] == 13, "C4: hysteresis: falling to 83 C keeps the 85 C clamp (got %u)", m.get[1]);
    cpu_run(&s, &m, wfi, busy, 2, 80000, &now, &rng);
    CHECK(m.get[1] == 14, "C4: falling to 80 C acts as 83 C: cap 19 - ceil(8/10 x 6) = 14 (got %u)", m.get[1]);
    cpu_run(&s, &m, wfi, busy, 2, 70000, &now, &rng);
    CHECK(m.get[1] == 19, "C4: cool again -> ceiling (got %u)", m.get[1]);
    cpu_run(&s, &m, wfi, busy, 2, INT64_MIN, &now, &rng);
    CHECK(m.get[1] == 13, "C4: no valid reading -> floor (got %u)", m.get[1]);
    CHECK(s.meas_count >= 1 && s.meas_khz_min >= 3436800 && s.meas_khz_max == 4454400,
          "U14: io->khz sampled once a second (count %llu, min %u, max %u)", (unsigned long long)s.meas_count,
          s.meas_khz_min, s.meas_khz_max);
    CHECK(cpu_dvfs_stop(&s, &io) == 1 && m.set[1] == 13, "C5: stop restores 13");

    /* U13 / b12v4: six busy Prime cores, LEVEL_GET 13 from the start, the firmware keeps 13 whatever is asked.
     * ABI 1 latched after 8 windows and reported 195 s "at 19". Now: one re-assert, refusal, a walk down to 14,
     * cap 13, every window at 13 in the residency, a bounded number of reprobes. */
    memset(&m, 0, sizeof m); memset(wfi, 0, sizeof wfi);
    m.get[1] = 13; m.mode[1] = FW_REJECT; m.cap[1] = 13;
    cpu_dvfs_start(&s, &io, HZ, PRIME6, 1, now);
    CHECK(s.domain[1].level == 13 && s.domain[1].restore == 13 && s.domain[1].initial_get == 13,
          "b12v4: LEVEL_GET 13 at start is the granted level and the restore");
    unsigned w0 = m.writes;
    cpu_run(&s, &m, wfi, busy, 40, 50000, &now, &rng);
    const struct cpu_dvfs_domain *g = &s.domain[1];
    CHECK(m.writes - w0 == 7 && g->refusals == 6 && g->refused_mask == 0xfc000u && g->cap == 13 && !g->walk,
          "U13: 19 (+1 re-assert), then 18..14 refused one by one; cap 13 (writes %u refusals %u mask %#x cap %u)",
          m.writes - w0, g->refusals, g->refused_mask, g->cap);
    CHECK(!g->latched, "U13: a firmware that answers with a level is not an error: not latched");
    CHECK(AT(g, 13) == 40 && residency_above(g, 13) == 0,
          "U13: the residency follows LEVEL_GET: 40 windows at 13, none above (%u at 13)", AT(g, 13));
    before = m.writes;
    cpu_run(&s, &m, wfi, busy, 200, 50000, &now, &rng);
    CHECK(m.writes == before, "U13: settled at the cap: no write while the reprobe delay runs");
    cpu_run(&s, &m, wfi, busy, CPU_DVFS_REPROBE_WINDOWS * (CPU_DVFS_REPROBES + 4), 50000, &now, &rng);
    CHECK(g->reprobes == CPU_DVFS_REPROBES && m.writes - before == CPU_DVFS_REPROBES * 7,
          "U13: %u reprobes of the ceiling, 7 writes each, then none (reprobes %u writes %u)", CPU_DVFS_REPROBES,
          g->reprobes, m.writes - before);
    CHECK(residency_above(g, 13) == 0 && g->granted_max == 13 && s.meas_khz_max == 3436800,
          "U13/U14: never reported above 13; measured clock 3.437 GHz");
    CHECK(cpu_dvfs_stop(&s, &io) == 1 && m.set[1] == 13, "C5: restore 13 (LEVEL_GET at start)");

    /* U13: a firmware that clamps to 16 (LEVEL_GET = min(request, 16)): the walk settles at 16, the residency is
     * at 16 from the first window after the request, and later requests stay at or below 16. */
    memset(&m, 0, sizeof m); memset(wfi, 0, sizeof wfi);
    m.get[1] = 13; m.mode[1] = FW_CLAMP; m.cap[1] = 16;
    cpu_dvfs_start(&s, &io, HZ, PRIME6, 1, now);
    w0 = m.writes;
    cpu_run(&s, &m, wfi, busy, 30, 50000, &now, &rng);
    CHECK(g->cap == 16 && m.writes - w0 == 4 && AT(g, 16) >= 28 && residency_above(g, 16) == 0,
          "U13: clamp at 16 found with 19, 19, 18, 17 (writes %u, cap %u, at 16 %u)", m.writes - w0, g->cap,
          AT(g, 16));
    cpu_run(&s, &m, wfi, idle, 10, 50000, &now, &rng);
    CHECK(m.get[1] == 13, "U13: down to the floor from the clamp (got %u)", m.get[1]);
    w0 = m.writes;
    cpu_run(&s, &m, wfi, busy, 5, 50000, &now, &rng);
    CHECK(m.set[1] == 16 && m.get[1] == 16 && m.writes - w0 == 1, "U13: hispeed asks the cap (16), not 19");
    cpu_dvfs_stop(&s, &io);

    /* U13: a limit that lifts (load-dependent): REJECT above 13 with six busy cores, then none; one busy vCPU
     * keeps hispeed; the next reprobe gets 19 and the residency shows it from then on. */
    memset(&m, 0, sizeof m); memset(wfi, 0, sizeof wfi);
    m.get[1] = 13; m.mode[1] = FW_REJECT; m.cap[1] = 13;
    cpu_dvfs_start(&s, &io, HZ, PRIME6, 1, now);
    cpu_run(&s, &m, wfi, busy, 40, 50000, &now, &rng);
    m.cap[1] = 0;
    cpu_run(&s, &m, wfi, one, CPU_DVFS_REPROBE_WINDOWS + 10, 50000, &now, &rng);
    CHECK(m.get[1] == 19 && g->cap == 19 && g->reprobes == 1 && AT(g, 19) >= 1 && AT(g, 19) <= 40,
          "U13: the reprobe finds 19 once the limit lifts (get %u cap %u reprobes %u at 19 %u)", m.get[1], g->cap,
          g->reprobes, AT(g, 19));
    cpu_dvfs_stop(&s, &io);

    /* U13: a late grant mid-walk (the firmware applies 19 while the walk asks 18): cap 19, not a refusal of 18. */
    memset(&m, 0, sizeof m); memset(wfi, 0, sizeof wfi);
    m.get[1] = 13; m.mode[1] = FW_REJECT; m.cap[1] = 13;
    cpu_dvfs_start(&s, &io, HZ, PRIME6, 1, now);
    cpu_run(&s, &m, wfi, busy, 5, 50000, &now, &rng);   /* 19 refused, the walk asks 18 */
    CHECK(g->walk && m.set[1] == 18, "U13: walking at 18 (set %u)", m.set[1]);
    m.get[1] = 19;                                     /* the firmware applies the earlier 19 late */
    cpu_run(&s, &m, wfi, busy, 6, 50000, &now, &rng);
    CHECK(!g->walk && g->cap == 19 && !(g->refused_mask >> 18 & 1) && m.get[1] == 19,
          "U13: late grant -> cap 19, 18 not marked refused (cap %u mask %#x)", g->cap, g->refused_mask);
    cpu_dvfs_stop(&s, &io);

    /* U5: LEVEL_GET never publishes a level (255): one re-assert, latched at 8, nothing more; no residency. */
    memset(&m, 0, sizeof m); memset(wfi, 0, sizeof wfi);
    m.get[1] = 255; m.mode[1] = FW_SILENT;
    cpu_dvfs_start(&s, &io, HZ, PRIME6, 1, now);
    cpu_run(&s, &m, wfi, busy, 12, 50000, &now, &rng);
    CHECK(g->latched == (0x80000000u | 255) && m.writes == 2 && residency_total(g) == 0 && g->unknown_ms == 240,
          "U5: unpublished LEVEL_GET -> latched after one re-assert, 0 windows at any level (writes %u latched %#x)",
          m.writes, g->latched);
    before = m.writes;
    cpu_run(&s, &m, wfi, idle, 20, 50000, &now, &rng);
    CHECK(m.writes == before, "U5: a latched domain is not written again");
    CHECK(cpu_dvfs_stop(&s, &io) == 1 && m.set[1] == 13 && s.status == CPU_DVFS_STOPPED,
          "C5: stop restores the latched domain once, to 13");
    CHECK(cpu_dvfs_stop(&s, &io) == 0, "C5: restore is idempotent");

    /* C4 while a walk is in progress: the clamp writes at once and the walk stops. */
    memset(&m, 0, sizeof m); memset(wfi, 0, sizeof wfi);
    m.get[1] = 13; m.mode[1] = FW_REJECT; m.cap[1] = 13;
    m.get[1] = 19;                                   /* an earlier request left 19 running */
    cpu_dvfs_start(&s, &io, HZ, PRIME6, 1, now);
    cpu_run(&s, &m, wfi, busy, 1, 86000, &now, &rng);
    CHECK(m.set[1] == 13 && m.get[1] == 13 && !g->walk, "C4: 86 C writes the floor in the first window");
    cpu_dvfs_stop(&s, &io);
    CHECK(m.set[1] == 19, "U2: restore = the valid level LEVEL_GET showed at start (got %u)", m.set[1]);

    /* No --prime-secondaries: all six vCPUs on the Performance cluster (PDP0, boot CPU 0x0): floor 16 (3.072
     * GHz), ceiling 20 (3.610 GHz); LEVEL_GET 255 at start. */
    khz_domain = 0;
    memset(&m, 0, sizeof m); memset(wfi, 0, sizeof wfi);
    m.get[0] = 255;
    cpu_dvfs_start(&s, &io, HZ, PERF6, 1, now);
    CHECK(s.domain[0].slots == 0x3f && !s.domain[1].slots && s.domain[0].ceiling == 20 && s.domain[0].floor == 16 &&
          s.domain[0].restore == 16, "PDP0 topology: one domain, floor 16, ceiling 20, restore 16");
    cpu_run(&s, &m, wfi, busy, 60, 50000, &now, &rng);
    CHECK(m.get[0] == 20 && AT(&s.domain[0], 20) >= 58 && s.meas_khz_max == 3609600,
          "PDP0: busy -> 20 (3.61 GHz), granted and measured (at 20: %u)", AT(&s.domain[0], 20));
    cpu_dvfs_stop(&s, &io);
    CHECK(m.set[0] == 16, "PDP0: restore 16 (got %u)", m.set[0]);
    khz_domain = 1;

    /* Mixed clusters: vCPU 0-3 on PDP0 (0x0..0x300), 4-5 on PDP1. */
    const uint64_t mixed[6] = {0x0, 0x100, 0x200, 0x300, 0x10000, 0x10100};
    double mid[6] = {0.85, 0.85, 0.85, 0.85, 0.05, 0.05}, sixty[6] = {0.6, 0.6, 0.6, 0.6, 0.05, 0.05};
    memset(&m, 0, sizeof m); memset(wfi, 0, sizeof wfi);
    m.get[0] = 0; m.get[1] = 0;
    cpu_dvfs_start(&s, &io, HZ, mixed, 1, now);
    CHECK(s.domain[0].slots == 0xf && s.domain[1].slots == 0x30 && s.domain[0].ceiling == 20 &&
          s.domain[0].floor == 16 && s.domain[0].restore == 16, "U6: two domains, PDP0 floor 16 ceiling 20");
    cpu_run(&s, &m, wfi, sixty, 10, 50000, &now, &rng);
    CHECK(m.writes == 0, "60 %% at the boot level: 1.25 x 0.6 x 3072 MHz is below the floor's clock, no write");
    cpu_run(&s, &m, wfi, mid, 10, 50000, &now, &rng);
    CHECK(m.get[0] >= 18 && m.get[0] <= 20 && m.get[1] == 0,
          "schedutil headroom: 85 %% raises PDP0 to 3.40 GHz or, on a >= 90 %% window, 3.61 (got %u); PDP1 untouched",
          m.get[0]);
    cpu_dvfs_stop(&s, &io);
    CHECK(m.set[0] == 16, "restore PDP0 to its boot level 16 (got %u)", m.set[0]);

    /* U9: counter wrap. */
    memset(&m, 0, sizeof m); memset(wfi, 0, sizeof wfi);
    for (unsigned n = 0; n < 6; n++) wfi[n][CPU_DVFS_WFI_BUSY] = 0xfffffff0u;
    cpu_dvfs_start(&s, &io, HZ, PRIME6, 1, now);
    for (unsigned n = 0; n < 6; n++) s.priv.last_busy[n] = 0xfffffff0u;
    cpu_run(&s, &m, wfi, busy, 3, 50000, &now, &rng);
    CHECK(m.get[1] == 19, "U9: busy counters that wrap still read busy (got %u)", m.get[1]);
    CHECK(!cpu_dvfs_write_allowed(0x19980000) && !cpu_dvfs_write_allowed(0x1998010c) &&
          cpu_dvfs_write_allowed(0x1a98011c) && !cpu_dvfs_write_allowed(0x17610150) &&
          !cpu_dvfs_write_allowed(0x17610168) && cpu_dvfs_read_allowed(0x17610168) &&
          !cpu_dvfs_read_allowed(0x1a980120), "U3: allow-lists: writes only LEVEL_SET/doorbell, reads only GETs");
    CHECK(m.limits_reads > 0 && !m.foreign, "U13: LIMITS_GET read, nothing foreign");
}

/* ---------------------------------------------------------------- GPU: race to idle */
struct flight_model {
    struct gpu_dvfs_load load;
    uint64_t end;          /* the tick the flight in progress completes */
};
static void flight_begin(struct flight_model *f, uint64_t now, uint64_t ticks)
{
    f->load.active = 1;
    f->load.start = now;
    f->load.flights++;
    f->end = now + ticks;
}
static void flight_step(struct flight_model *f, uint64_t now)
{
    if (f->load.active && (int64_t)(now - f->end) >= 0) {
        f->load.active = 0;
        f->load.ended++;
        f->load.sum_ticks += f->end - f->load.start;
    }
}
/* ms ticks of vCPU 0 with the flight model and the guard's two readings (G20); returns the votes sent. */
static int64_t die_offset = -12000;   /* die = hotspot - 12 C unless a scenario sets it (b12v12: 60.3 vs 72.6) */
static unsigned gpu_ms(struct gpu_dvfs_state *s, struct gpu_dvfs_io *io, struct flight_model *f, unsigned ms,
                       int64_t mc, uint64_t *now)
{
    unsigned v0 = (unsigned)s->votes;
    for (unsigned n = 0; n < ms; n++) {
        *now += MS;
        flight_step(f, *now);
        const struct gpu_dvfs_thermal th = {mc, mc == INT64_MIN || die_offset == INT64_MIN ? INT64_MIN : mc + die_offset,
                                            mc != INT64_MIN};
        gpu_dvfs_tick(s, io, *now, &th, &f->load);
    }
    return (unsigned)s->votes - v0;
}
/* The HVC path's G18 kick before a START's doorbell, then the flight. */
static void start_ib(struct gpu_dvfs_state *s, struct gpu_dvfs_io *io, struct flight_model *f, uint64_t now,
                     uint64_t ticks)
{
    if (!f->load.active) gpu_dvfs_kick(s, io, now);
    flight_begin(f, now, ticks);
}
static double hold_ms = SNAP_GPU_DVFS_HOLD_MS;

static void scenario_gpu(void)
{
    struct gmu g;
    struct gpu_dvfs_state s;
    struct gpu_dvfs_io io;
    struct flight_model f;
    uint64_t now = 1000;

    gmu_init(&g, GMU_ACK, 41, 8);
    io = gmu_io(&g);
    memset(&f, 0, sizeof f);
    gpu_dvfs_start(&s, HZ, ARENA, 0, now, &f.load, &io);
    CHECK(s.status == GPU_DVFS_OFF, "C3: GPU governor off without the thermal guard");
    CHECK(gpu_dvfs_kick(&s, &io, now) == 0 && !s.kicks && !g.doorbells, "G18: a kick before the start does nothing");
    gpu_dvfs_start(&s, HZ, ARENA, 1, now, &f.load, &io);
    CHECK(gpu_ms(&s, &io, &f, 60, 50000, &now) == 0 && s.opp == 1 && s.top == TOP && s.hold_ms == SNAP_GPU_DVFS_HOLD_MS,
          "idle start: no vote, the first window sets the ceiling (top %llu)", (unsigned long long)s.top);

    /* G18: the first IB of a burst: OPP 6 before its doorbell, no in-flight vote needed. */
    start_ib(&s, &io, &f, now, 12 * MS);
    CHECK(s.opp == TOP && g.perf == TOP && g.bw == s.priv.bw[TOP] && s.race_first == 1 && !s.midflight_votes &&
          g.votes == 1, "G18/O4: the ceiling (OPP %llu, %u MHz, bw %u) before the first IB's doorbell (opp %llu)",
          (unsigned long long)TOP, GPU_DVFS_MHZ[TOP - 1], g.bw, (unsigned long long)s.opp);
    CHECK(g.last_seq == 42 && *gw(&g, ARENA + GPU_DVFS_STATE_OFF + GPU_DVFS_HOST_SEQ) == 42,
          "G6: seq 42 = host hfi_seq + 1, written back");
    CHECK(!g.discipline && !g.foreign && !g.bad_msgs, "G4/G12: index stores bracketed by cleans, no foreign access");
    gpu_ms(&s, &io, &f, 20, 50000, &now);
    start_ib(&s, &io, &f, now, 5 * MS);
    CHECK(g.votes == 1 && s.kicks == 2 && s.race_first == 1, "G18: at the ceiling already: a kick votes nothing");

    /* G19: a drag with pauses up to 0.8 x the hold (1.2 s by default) keeps 915 throughout. */
    for (unsigned k = 0; k < 6; k++) {
        gpu_ms(&s, &io, &f, k & 1 ? (unsigned)(hold_ms * 0.8) : (unsigned)(hold_ms * 0.2), 50000, &now);
        start_ib(&s, &io, &f, now, 8 * MS);
    }
    CHECK(g.votes == 1 && s.opp == TOP, "G19: pauses up to 0.8 x the hold keep the ceiling (votes %u opp %llu)", g.votes,
          (unsigned long long)s.opp);
    /* Idle: back to OPP 1 between the hold and the hold + 200 ms after the last activity (the flight's end). */
    uint64_t ended_at = now + 8 * MS;
    unsigned ms = 0;
    while (s.opp == TOP && ms < 6000) { gpu_ms(&s, &io, &f, 1, 50000, &now); ms++; }
    double idle_ms = (double)(now - ended_at) / MS;
    CHECK(s.opp == 1 && idle_ms >= hold_ms && idle_ms <= hold_ms + 200 && s.idle_downs == 1,
          "G19: back to OPP 1 after %.0f ms idle (want %.0f-%.0f)", idle_ms, hold_ms, hold_ms + 200);
    CHECK(g.votes == 2, "G8: two votes for one burst (up, down) (got %u)", g.votes);

    /* A fence or synchronous submission (no kick) raises at the next tick. */
    gpu_dvfs_busy(&s, 1 * MS);
    gpu_ms(&s, &io, &f, 1, 50000, &now);
    CHECK(s.opp == TOP && s.race_long == 1, "G19: a synchronous submission -> the ceiling at the next tick (race_long %llu)",
          (unsigned long long)s.race_long);
    gpu_ms(&s, &io, &f, (unsigned)hold_ms + 400, 50000, &now);
    CHECK(s.opp == 1, "G19: and back to 1 when idle");

    /* G20: the hotspot (a Prime core) at 80 C with the die at 60 C clamps nothing: a burst gets 915. */
    die_offset = -20000;
    gpu_ms(&s, &io, &f, 60, 80000, &now);
    start_ib(&s, &io, &f, now, 5 * MS);
    CHECK(s.top == TOP && s.opp == TOP && !s.clamp_spot_ms && !s.clamp_die_ms,
          "G20: hotspot 80 C / die 60 C -> no clamp (the b12 runs' case), top %llu", (unsigned long long)s.top);
    /* Hotspot 90 C: TOP - ceil(2/5 x (TOP - 1)) (11 -> 7, 6 -> 4), at once. */
    gpu_ms(&s, &io, &f, 60, 90000, &now);
    uint64_t at90 = TOP - (2 * (TOP - 1) + 4) / 5;
    CHECK(s.top == at90 && s.opp == at90 && s.clamp_spot_ms > 0, "G20: hotspot 90 C -> OPP %llu at once (opp %llu)",
          (unsigned long long)at90, (unsigned long long)s.opp);
    gpu_ms(&s, &io, &f, 60, 93000, &now);
    CHECK(s.opp == 1 && s.top == 1, "G20: hotspot 93 C -> OPP 1 (opp %llu)", (unsigned long long)s.opp);
    start_ib(&s, &io, &f, now, 5 * MS);
    CHECK(s.opp == 1, "G20: a kick cannot lift the clamp");
    /* The die at 80 C (hotspot 80): TOP - ceil(5/10 x (TOP - 1)) (11 -> 6, 6 -> 3). */
    uint64_t at80 = TOP - (5 * (TOP - 1) + 9) / 10;
    die_offset = 0;
    gpu_ms(&s, &io, &f, (unsigned)hold_ms + 2000, 70000, &now);
    gpu_ms(&s, &io, &f, 60, 80000, &now);
    start_ib(&s, &io, &f, now, 5 * MS);
    CHECK(s.top == at80 && s.opp == at80 && s.clamp_die_ms > 0, "G20: die 80 C -> OPP %llu (opp %llu)",
          (unsigned long long)at80, (unsigned long long)s.opp);
    /* No die reading: the hotspot under the die's limits (80 C -> 3). */
    die_offset = INT64_MIN;
    gpu_ms(&s, &io, &f, 60, 80000, &now);
    CHECK(s.top == at80 && s.die_mc == INT64_MIN, "G20b: no die reading -> the hotspot with the die thresholds (top %llu)",
          (unsigned long long)s.top);
    /* A8: the clamp lifts while a long IB runs: raised under the CP, or (MIDFLIGHT 0) when it ends. */
    die_offset = -20000;
    gpu_ms(&s, &io, &f, 60, 93000, &now);
    start_ib(&s, &io, &f, now, 200 * MS);
    unsigned mid0 = (unsigned)s.midflight_votes;
    gpu_ms(&s, &io, &f, 2, 93000, &now);
    gpu_ms(&s, &io, &f, 60, 50000, &now);
#if SNAP_GPU_DVFS_MIDFLIGHT
    CHECK(s.opp == TOP && s.midflight_votes > mid0, "A8: cooled mid-flight -> the ceiling under the running CP (opp %llu)",
          (unsigned long long)s.opp);
#else
    CHECK(s.opp == 1 && s.pending == TOP && s.midflight_votes == mid0, "G7: cooled mid-flight -> deferred (opp %llu)",
          (unsigned long long)s.opp);
    unsigned d0 = (unsigned)s.deferred;
    gpu_ms(&s, &io, &f, 200, 50000, &now);
    CHECK(s.opp == TOP && !s.pending && s.deferred == d0, "G7: sent when the flight ended, one deferral (opp %llu)",
          (unsigned long long)s.opp);
#endif
    die_offset = -12000;
    gpu_ms(&s, &io, &f, (unsigned)hold_ms + 3000, 50000, &now);
    CHECK(s.opp == 1, "idle again -> OPP 1");

    /* G11: stop at OPP 1 sends nothing; from a raised clock it sends OPP 1. */
    unsigned votes = g.votes;
    gpu_dvfs_stop(&s, &io);
    CHECK(g.votes == votes && s.status == GPU_DVFS_STOPPED, "G11: stop at OPP 1 sends nothing");
    free(g.mem);

    gmu_init(&g, GMU_ACK, 0xffe, 1020);   /* seq wraps to 0 at 0xfff; the queue wraps at 1024 */
    io = gmu_io(&g);
    memset(&f, 0, sizeof f);
    gpu_dvfs_start(&s, HZ, ARENA, 1, now, &f.load, &io);
    gpu_dvfs_busy(&s, HZ / 20);
    gpu_ms(&s, &io, &f, 60, 50000, &now);
    CHECK(s.opp == TOP && g.last_seq == 0 && *gw(&g, hdr(0, GPU_DVFS_Q_WRITE)) == 0,
          "G6: seq wraps mod 0xfff, the message wraps the queue (seq %u)", g.last_seq);
    gpu_dvfs_stop(&s, &io);
    CHECK(g.perf == 1 && g.bw == 1, "G11: stop -> OPP 1");
    CHECK(!g.discipline && !g.foreign, "wrapped queue: discipline kept");
    free(g.mem);

    /* G5: NACK, silence, error message first, stuck queue, corrupt header, wrong host record. */
    const struct { enum gmu_mode mode; int corrupt, host; uint64_t want; const char *what; } cases[] = {
        {GMU_NACK, 0, 0, GPU_DVFS_E_NACK, "NACK"},
        {GMU_SILENT, 0, 0, GPU_DVFS_E_TIMEOUT, "no ack"},
        {GMU_STUCK, 0, 0, GPU_DVFS_E_TIMEOUT, "stuck queue"},
        {GMU_ERROR_FIRST, 0, 0, 0, "F2H error before the ack (skipped)"},
        {GMU_ACK, 1, 0, GPU_DVFS_E_QUEUE, "corrupt header"},
        {GMU_ACK, 0, 1, GPU_DVFS_E_HOST, "host record of another arena"},
    };
    for (unsigned i = 0; i < sizeof cases / sizeof *cases; i++) {
        gmu_init(&g, cases[i].mode, 5, 0);
        io = gmu_io(&g);
        memset(&f, 0, sizeof f);
        if (cases[i].corrupt) *gw(&g, hdr(0, GPU_DVFS_Q_SIZE)) = 512;
        gpu_dvfs_start(&s, HZ, ARENA, 1, now, &f.load, &io);
        /* After the start (which checks the record too, O4): the send's own check of every message. */
        if (cases[i].host) *gw(&g, ARENA + GPU_DVFS_STATE_OFF + 16) = 0x1000;
        gpu_dvfs_busy(&s, HZ / 20);
        gpu_ms(&s, &io, &f, 50, 50000, &now);
        if (!cases[i].want) {
            CHECK(s.status == GPU_DVFS_RUNNING && s.opp == TOP && s.skipped_messages == 1, "G5: %s", cases[i].what);
        } else {
            CHECK(s.status == GPU_DVFS_LATCHED && s.last_error == cases[i].want,
                  "G5: %s -> latched with %llu (got status %llu error %llu)", cases[i].what,
                  (unsigned long long)cases[i].want, (unsigned long long)s.status, (unsigned long long)s.last_error);
            unsigned d = g.doorbells;
            gpu_dvfs_busy(&s, HZ / 20);
            flight_begin(&f, now, 30 * MS);
            gpu_ms(&s, &io, &f, 100, 50000, &now);
            gpu_dvfs_stop(&s, &io);
            CHECK(g.doorbells == d, "G5: %s: nothing sent after the latch, not even at the stop", cases[i].what);
        }
        CHECK(!g.foreign, "G12: %s: no foreign address", cases[i].what);
        free(g.mem);
    }
    /* The busy queue: read != write when the governor wants to send -> E_BUSY, latched. */
    gmu_init(&g, GMU_ACK, 5, 0);
    io = gmu_io(&g);
    memset(&f, 0, sizeof f);
    *gw(&g, hdr(0, GPU_DVFS_Q_WRITE)) = 4;
    gpu_dvfs_start(&s, HZ, ARENA, 1, now, &f.load, &io);
    gpu_dvfs_busy(&s, HZ / 20);
    gpu_ms(&s, &io, &f, 50, 50000, &now);
    CHECK(s.status == GPU_DVFS_LATCHED && s.last_error == GPU_DVFS_E_BUSY && !g.doorbells,
          "G3: undrained command queue: latched, no doorbell");
    CHECK(gpu_dvfs_address_allowed(&s, GPU_DVFS_GMU_DOORBELL, 1) && !gpu_dvfs_address_allowed(&s, GPU_DVFS_GMU_INTR_INFO, 1) &&
          !gpu_dvfs_address_allowed(&s, 0x03d7e000, 1) && !gpu_dvfs_address_allowed(&s, ARENA + GPU_DVFS_STATE_OFF + 8, 1) &&
          !gpu_dvfs_address_allowed(&s, ARENA + 0x140000, 0),
          "G12: allow-list: doorbell/clear writes, INFO read, HFI region and hfi_seq only");
    free(g.mem);
}

/* ---------------------------------------------------------------- GPU: the table q1n1 sent (section 9, O4/O5/O9/O10) */
/* q1n1 tools/test-a16gpu-opps.py bw_index_table(): the bw row of each OPP for a table of N OPPs. */
static const uint8_t BW_ROWS_Q1N1[12][12] = {
    {0}, {0, 1}, {0, 1, 2}, {0, 1, 2, 3}, {0, 1, 2, 3, 3}, {0, 1, 2, 3, 3, 4}, {0, 1, 2, 3, 3, 4, 4},
    {0, 1, 2, 3, 3, 4, 4, 4}, {0, 1, 2, 3, 3, 4, 4, 4, 4}, {0, 1, 2, 3, 3, 4, 4, 4, 4, 5},
    {0, 1, 2, 3, 3, 4, 4, 4, 4, 5, 5}, {0, 1, 2, 3, 3, 4, 4, 4, 4, 5, 5, 5}};

static void scenario_gpu_table(void)
{
    struct gmu g;
    struct gpu_dvfs_state s;
    struct gpu_dvfs_io io;
    struct flight_model f;
    uint64_t now = 1000;
    unsigned saved = gmu_hfi_opps;

    /* O4/O5: every table size, and a record without the field (0 -> 6, the b12 invariant). */
    for (unsigned n = 0; n <= 11; n++) {
        gmu_hfi_opps = n;
        gmu_init(&g, GMU_ACK, 1, 0);
        io = gmu_io(&g);
        memset(&f, 0, sizeof f);
        gpu_dvfs_start(&s, HZ, ARENA, 1, now, &f.load, &io);
        unsigned want = n ? n : 6, rows = want >= 9 ? 5 : want >= 5 ? 4 : want >= 3 ? 3 : want;
        if (want > SNAP_GPU_DVFS_MAX_OPP) want = SNAP_GPU_DVFS_MAX_OPP;
        int same = 1;
        for (unsigned k = 1; k <= (n ? n : 6); k++) same &= s.priv.bw[k] == BW_ROWS_Q1N1[n ? n : 6][k];
        CHECK(s.status == GPU_DVFS_RUNNING && s.ceiling == want && s.hfi_opps == n && s.bw_rows == rows && same,
              "O4/O5: hfi_opps %u -> ceiling %llu (want %u), %llu bw rows, bw indices as q1n1's", n,
              (unsigned long long)s.ceiling, want, (unsigned long long)s.bw_rows);
        free(g.mem);
    }
    /* O4: the table of another GMU boot (no START acked since this boot) or another arena keeps the governor off. */
    gmu_hfi_opps = 11;
    gmu_init(&g, GMU_ACK, 1, 0);
    io = gmu_io(&g);
    *gw(&g, ARENA + GPU_DVFS_STATE_OFF + GPU_DVFS_HOST_HFI) = 6;
    gpu_dvfs_start(&s, HZ, ARENA, 1, now, &f.load, &io);
    gpu_dvfs_busy(&s, HZ / 20);
    gpu_ms(&s, &io, &f, 100, 50000, &now);
    CHECK(s.status == GPU_DVFS_OFF && s.reason == 4 && !g.doorbells, "O4: hfi_token != boot_token -> off, nothing sent");
    free(g.mem);
    gmu_init(&g, GMU_ACK, 1, 0);
    io = gmu_io(&g);
    *gw(&g, ARENA + GPU_DVFS_STATE_OFF + 16) = 0x1000;
    gpu_dvfs_start(&s, HZ, ARENA, 1, now, &f.load, &io);
    CHECK(s.status == GPU_DVFS_OFF && s.reason == 5, "O4: a host record of another arena -> off");
    free(g.mem);
    /* A table of one OPP: the governor never votes. */
    gmu_hfi_opps = 1;
    gmu_init(&g, GMU_ACK, 1, 0);
    io = gmu_io(&g);
    memset(&f, 0, sizeof f);
    gpu_dvfs_start(&s, HZ, ARENA, 1, now, &f.load, &io);
    gpu_ms(&s, &io, &f, 60, 50000, &now);
    start_ib(&s, &io, &f, now, 20 * MS);
    gpu_ms(&s, &io, &f, 200, 50000, &now);
    CHECK(s.status == GPU_DVFS_RUNNING && !g.doorbells && s.opp == 1, "O4: hfi_opps 1 -> no vote at all");
    free(g.mem);
    /* O9: the GMU refuses the top three perf indices: the race to the top is NACKed, the governor latches at OPP 1. */
    gmu_hfi_opps = 11;
    gmu_init(&g, GMU_NACK_ABOVE, 1, 0);
    g.nack_above = (uint32_t)TOP - 3;
    io = gmu_io(&g);
    memset(&f, 0, sizeof f);
    gpu_dvfs_start(&s, HZ, ARENA, 1, now, &f.load, &io);
    gpu_ms(&s, &io, &f, 60, 50000, &now);
    start_ib(&s, &io, &f, now, 20 * MS);
    unsigned d = g.doorbells;
    gpu_ms(&s, &io, &f, 3000, 50000, &now);
    gpu_dvfs_stop(&s, &io);
    CHECK(s.status == GPU_DVFS_LATCHED && s.last_error == GPU_DVFS_E_NACK && s.opp == 1 && g.doorbells == d,
          "O9: a NACK at the new top latches at the last good OPP, nothing sent after (status %llu opp %llu)",
          (unsigned long long)s.status, (unsigned long long)s.opp);
    free(g.mem);
    /* O10: flights that ran entirely at one OPP count for it; one with a vote mid-flight counts nowhere. */
    gmu_hfi_opps = 11;
    gmu_init(&g, GMU_ACK, 1, 0);
    io = gmu_io(&g);
    memset(&f, 0, sizeof f);
    gpu_dvfs_start(&s, HZ, ARENA, 1, now, &f.load, &io);
    gpu_ms(&s, &io, &f, 60, 50000, &now);
    for (unsigned k = 0; k < 3; k++) { start_ib(&s, &io, &f, now, 10 * MS); gpu_ms(&s, &io, &f, 20, 50000, &now); }
    uint64_t w = s.opp_flights[TOP];
    CHECK(w >> 32 == 3 && (w & 0xffffffffu) >= 29900 && (w & 0xffffffffu) <= 30100,
          "O10: three 10 ms flights at the ceiling: count %llu, %llu us", (unsigned long long)(w >> 32),
          (unsigned long long)(w & 0xffffffffu));
    gpu_ms(&s, &io, &f, 2000, 93000, &now);           /* hot: clamped to OPP 1 */
    start_ib(&s, &io, &f, now, 200 * MS);
    gpu_ms(&s, &io, &f, 30, 93000, &now);
    gpu_ms(&s, &io, &f, 250, 50000, &now);            /* cools mid-flight: raised under the CP (or deferred) */
    uint64_t total = 0;
    for (unsigned k = 1; k <= GPU_DVFS_OPPS; k++) total += s.opp_flights[k] >> 32;
#if SNAP_GPU_DVFS_MIDFLIGHT
    CHECK(total == 3, "O10: the flight with a vote mid-flight is not attributed (%llu)", (unsigned long long)total);
#else
    CHECK(total == 4 && s.opp_flights[1] >> 32 == 1, "O10: deferred: the long flight ran at OPP 1 and counts there (%llu)",
          (unsigned long long)total);
#endif
    free(g.mem);
    gmu_hfi_opps = saved;
}

/* ---------------------------------------------------------------- trace replay */
/* Thermal model: dT/dt = (T_amb + K * load - T) / TAU. v78 reached 61.0 C after 393 s of desktop load with the
 * Prime cluster at its boot level (13) and the GPU at 310 MHz. With TAU 300 s, T_amb 33 C and that run's load
 * taken as 0.8 (mean busy of six vCPUs, as the recorded desktops), the rise is 47.9 C per unit load (1.0 = six
 * busy cores at level 13). One calibration point: a model, not a measurement. */
#define T_AMB 33.0
#define TAU_S 300.0
#define K_RISE 47.9   /* load 0.8 (a desktop's mean busy) at level 13 reaches 61.0 C at 393 s, as v78 did */
/* PDP1 PERF_DESCRIBE_LEVELS power column (gen1-query-2.json), relative units. */
static const double PDP1_POWER[22] = {16234, 40367, 57952, 78683, 99138, 119516, 141775, 168315, 199272, 235860,
                                      273666, 318025, 361184, 417571, 472809, 534328, 593280, 669726, 738051,
                                      826209, 1143072, 1200956};
static double cpu_power(unsigned level) { return PDP1_POWER[level < 22 ? level : 13]; }
/* GPU (section 9, O8): power relative to OPP 6 (915 MHz, NOM) ~ f x V^2. The rail voltages are ASSUMED typical
 * Qualcomm corners (none is published for this part): LOW_SVS_D1 0.56 V ... NOM 0.78 ... TURBO_L4 0.97. GPU_LOAD_915:
 * a fully busy GPU at 915 MHz adds 5.2 C at steady state (0.109 x K_RISE), from b12v6-v12: +1.4 +- 0.6 C on the die
 * sensors per unit of time at 915 with b12v12's ~27 % busy. */
#define GPU_LOAD_915 0.109
static const double GPU_VOLT[GPU_DVFS_OPPS] = {0.56, 0.60, 0.66, 0.71, 0.74, 0.78, 0.83, 0.88, 0.91, 0.95, 0.97};
static double gpu_rel_power(uint64_t opp)
{
    unsigned k = opp >= 1 && opp <= GPU_DVFS_OPPS ? (unsigned)opp - 1 : 0;
    return GPU_DVFS_MHZ[k] / 915.0 * (GPU_VOLT[k] / 0.78) * (GPU_VOLT[k] / 0.78);
}

struct seg { double dur_s, busy[6], gpu_frac, ib_hz; };
struct run_stats {
    double seconds, cpu_mhz_sum, gpu_mhz_sum, t_max, t_end, busy_sum;
    unsigned windows, gpu_windows, cpu_writes, gpu_votes, clamp_windows, max_level, max_opp;
    double cpu_res[22], gpu_res[GPU_DVFS_OPPS + 1];
};

static const char *dump_path;   /* argv[3]: the last replay's DVFSREP1 block, as the monitor's stop writes it */

static void dump_block(const struct cpu_dvfs_state *cs, const struct gpu_dvfs_state *gs)
{
    FILE *f = fopen(dump_path, "wb");
    if (!f) return;
    uint64_t head[2] = {UINT64_C(0x3150455253465644), 1u | 2u | (uint64_t)CPU_DVFS_REPORT_WORDS << 16 |
                                                      (uint64_t)GPU_DVFS_REPORT_WORDS << 32};
    fwrite(head, 8, 2, f);
    fwrite(cs, 8, CPU_DVFS_REPORT_WORDS, f);
    fwrite(gs, 8, GPU_DVFS_REPORT_WORDS, f);
    fclose(f);
}

static void replay(const char *name, const struct seg *seg, unsigned nseg, FILE *json, int first)
{
    struct scmi m;
    struct gmu g;
    struct cpu_dvfs_state cs;
    struct gpu_dvfs_state gs;
    uint32_t wfi[6][8];
    memset(&m, 0, sizeof m); memset(wfi, 0, sizeof wfi);
    m.get[1] = 255;
    gmu_init(&g, GMU_ACK, 1, 0);
    struct cpu_dvfs_io cio = {&m, scmi_rd, scmi_wr, scmi_khz};
    static const struct gpu_dvfs_load idle_gpu;   /* synchronous IBs: completions through gpu_dvfs_busy */
    struct gpu_dvfs_io gio = gmu_io(&g);
    uint64_t now = HZ, rng = 7;
    double temp = 34.0;
    cpu_dvfs_start(&cs, &cio, HZ, PRIME6, 1, now);
    khz_domain = 1;
    gpu_dvfs_start(&gs, HZ, ARENA, 1, now, &idle_gpu, &gio);
    struct run_stats r;
    memset(&r, 0, sizeof r);
    int state[6] = {0};
    double ib_carry = 0;
    const volatile uint32_t *p[6];
    for (unsigned n = 0; n < 6; n++) p[n] = wfi[n];
    for (unsigned k = 0; k < nseg; k++) {
        unsigned ms_total = (unsigned)(seg[k].dur_s * 1000.0 + 0.5);
        for (unsigned ms = 0; ms < ms_total; ms++) {
            now += HZ / 1000;
            unsigned level = m.get[1] <= 21 ? m.get[1] : 13;
            if (!level) level = 13;
            double speed = (double)CPU_DVFS_DOMAIN[1].khz[level] / CPU_DVFS_DOMAIN[1].khz[13];
            /* Busy at the boot level becomes busy / speed at a higher level (CPU-bound work finishes sooner). */
            for (unsigned n = 0; n < 6; n++) {
                double b = seg[k].busy[n] / speed;
                if (b > 0.995) b = 0.995;
                /* Two-state chain with 5 ms mean bursts and the segment's busy fraction. */
                rng = rng * 6364136223846793005ull + 1442695040888963407ull;
                double u = (double)(rng >> 11) / 9007199254740992.0;
                double leave = state[n] ? (1.0 - b) / 5.0 / (b > 0 ? b : 1) : b / 5.0 / (1.0 - b);
                if (leave > 1) leave = 1;
                if (u < leave) state[n] = !state[n];
                wfi[n][state[n] ? CPU_DVFS_WFI_BUSY : 0]++;
                r.busy_sum += state[n] ? 1.0 / 6 : 0;
            }
            /* GPU: IBs at ib_hz, each lasting gpu_frac / ib_hz at 310 MHz, scaled by 310 / MHz. */
            ib_carry += seg[k].ib_hz / 1000.0;
            while (ib_carry >= 1.0 && seg[k].ib_hz > 0) {
                ib_carry -= 1.0;
                double mhz = GPU_DVFS_MHZ[(gs.opp ? gs.opp : 1) - 1];
                double ticks = seg[k].gpu_frac / seg[k].ib_hz * HZ * 310.0 / mhz;
                gpu_dvfs_busy(&gs, (uint64_t)ticks);
            }
            int64_t mc = (int64_t)(temp * 1000.0);
            unsigned w0 = cs.windows, gw0 = gs.windows, votes0 = gs.votes;
            r.cpu_writes += cpu_dvfs_tick(&cs, &cio, now, p, mc, 1);
            const struct gpu_dvfs_thermal th = {mc, mc - 12000, 1};
            gpu_dvfs_tick(&gs, &gio, now, &th, &idle_gpu);
            if (gs.votes != votes0) r.gpu_votes++;
            if (cs.windows != w0) {
                r.windows++;
                level = m.get[1] <= 21 && m.get[1] ? m.get[1] : 13;
                r.cpu_res[level] += CPU_DVFS_WINDOW_MS / 1000.0;
                r.cpu_mhz_sum += CPU_DVFS_DOMAIN[1].khz[level] / 1000.0 * CPU_DVFS_WINDOW_MS / 1000.0;
                if (level > r.max_level) r.max_level = level;
                if (cs.thermal_clamp) r.clamp_windows++;
            }
            if (gs.windows != gw0) {
                r.gpu_windows++;
                r.gpu_res[gs.opp] += GPU_DVFS_WINDOW_MS / 1000.0;
                r.gpu_mhz_sum += GPU_DVFS_MHZ[gs.opp - 1] * GPU_DVFS_WINDOW_MS / 1000.0;
                if (gs.opp > r.max_opp) r.max_opp = (unsigned)gs.opp;
            }
            /* Thermal: load = mean busy x level power relative to level 13, plus the GPU (OPP 6 adds 15 %). */
            double cpu_load = 0;
            for (unsigned n = 0; n < 6; n++) cpu_load += state[n] / 6.0;
            double load = cpu_load * cpu_power(level) / cpu_power(13) +
                          GPU_LOAD_915 * gpu_rel_power(gs.opp) * (seg[k].gpu_frac > 1 ? 1 : seg[k].gpu_frac);
            temp += (T_AMB + K_RISE * load - temp) / (TAU_S * 1000.0);
            if (temp > r.t_max) r.t_max = temp;
            r.seconds += 0.001;
        }
    }
    /* Invariants over the whole replay. */
    CHECK(!m.boost && !m.zero && !m.foreign && m.max[1] <= 19, "%s: CPU never boost, never 0, PDP1 only", name);
    CHECK(r.max_opp <= SNAP_GPU_DVFS_MAX_OPP && !g.foreign && !g.discipline && !g.bad_msgs, "%s: GPU <= OPP 6, clean HFI", name);
    CHECK(r.t_max < 95.0, "%s: the governors keep the model below the guard's 95 C (max %.1f)", name, r.t_max);
    CHECK(r.cpu_writes <= r.windows + 1, "%s: at most one LEVEL_SET per window", name);
    CHECK(r.gpu_votes <= r.seconds * 10 + 2, "%s: at most 10 GPU votes a second (G8: %u in %.0f s)", name, r.gpu_votes,
          r.seconds);
    CHECK(gs.status == GPU_DVFS_RUNNING && cs.status == CPU_DVFS_RUNNING, "%s: neither governor latched", name);
    cpu_dvfs_stop(&cs, &cio);
    gpu_dvfs_stop(&gs, &gio);
    if (dump_path) dump_block(&cs, &gs);
    CHECK((!m.writes || m.set[1] == 13) && (!gs.votes || g.perf == 1), "%s: stop restores 13 and OPP 1", name);
    r.t_end = temp;
    if (json) {
        fprintf(json, "%s  \"%s\": {\"seconds\": %.1f, \"cpu_writes\": %u, \"gpu_votes\": %u, \"cpu_mean_mhz\": %.0f, "
                      "\"gpu_mean_mhz\": %.0f, \"max_level\": %u, \"max_opp\": %u, \"clamp_seconds\": %.1f, "
                      "\"t_max_c\": %.1f, \"mean_busy_at_boot_level\": %.3f, \"cpu_seconds_at_level\": {",
                first ? "" : ",\n", name, r.seconds, r.cpu_writes, r.gpu_votes, r.cpu_mhz_sum / (r.windows * 0.02 + 1e-9),
                r.gpu_mhz_sum / (r.gpu_windows * 0.05 + 1e-9), r.max_level, r.max_opp,
                r.clamp_windows * 0.02, r.t_max, r.busy_sum / (r.seconds * 1000 + 1e-9));
        int c = 0;
        for (unsigned l = 0; l < 22; l++)
            if (r.cpu_res[l] > 0) fprintf(json, "%s\"%u\": %.1f", c++ ? ", " : "", l, r.cpu_res[l]);
        fprintf(json, "}, \"gpu_seconds_at_opp\": {");
        c = 0;
        for (unsigned o = 1; o <= GPU_DVFS_OPPS; o++)
            if (r.gpu_res[o] > 0) fprintf(json, "%s\"%u\": %.1f", c++ ? ", " : "", o, r.gpu_res[o]);
        fprintf(json, "}}");
    }
    printf("%-40s %7.0fs cpu %4.0f MHz (max lvl %2u, %5u writes) gpu %4.0f MHz (max opp %u, %4u votes) "
           "clamp %6.1fs Tmax %.1f C\n", name, r.seconds, r.cpu_mhz_sum / (r.windows * 0.02 + 1e-9), r.max_level,
           r.cpu_writes, r.gpu_mhz_sum / (r.gpu_windows * 0.05 + 1e-9), r.max_opp, r.gpu_votes, r.clamp_windows * 0.02,
           r.t_max);
    free(g.mem);
}

static void replay_file(const char *path, const char *json_path)
{
    FILE *f = fopen(path, "r");
    CHECK(f != NULL, "open %s", path);
    if (!f) return;
    FILE *json = json_path ? fopen(json_path, "w") : NULL;
    if (json) fprintf(json, "{\n");
    char line[1024], name[256] = "";
    struct seg *seg = NULL;
    unsigned n = 0, cap = 0;
    int first = 1;
    while (fgets(line, sizeof line, f)) {
        if (!strncmp(line, "run ", 4) || !strncmp(line, "end", 3)) {
            if (n) { replay(name, seg, n, json, first); first = 0; }
            n = 0;
            if (!strncmp(line, "run ", 4)) sscanf(line + 4, "%255s", name);
            continue;
        }
        struct seg s;
        if (sscanf(line, "seg %lf %lf %lf %lf %lf %lf %lf %lf %lf", &s.dur_s, &s.busy[0], &s.busy[1], &s.busy[2],
                   &s.busy[3], &s.busy[4], &s.busy[5], &s.gpu_frac, &s.ib_hz) == 9) {
            if (n == cap) { cap = cap ? 2 * cap : 256; seg = realloc(seg, cap * sizeof *seg); }
            seg[n++] = s;
        }
    }
    if (n) replay(name, seg, n, json, first);
    if (json) { fprintf(json, "\n}\n"); fclose(json); }
    free(seg);
    fclose(f);
}

/* U14: the monitor's clock measurement (probes/xnuboot.c dvfs_cpu_khz), the same chain, on this Mac's core
 * timed by CLOCK_UPTIME_RAW (EL0 CNTVCT is not usable here): a sanity check that a dependent ADD costs one
 * cycle (an M3 Max P-core reads 3.7-4.05 GHz), not a measurement of the A16. */
#if defined(__aarch64__) && defined(__APPLE__)
#include <time.h>
#endif
static void native_khz(void)
{
#if defined(__aarch64__) && defined(__APPLE__)
    uint64_t best = 0;
    for (unsigned k = 0; k < 2000; k++) {
        uint64_t n = 512 * 8, x = 0;
        uint64_t t0 = clock_gettime_nsec_np(CLOCK_UPTIME_RAW);
        __asm__ volatile("1:\n\t.rept 64\n\tadd %0, %0, #1\n\t.endr\n\tsubs %1, %1, #1\n\tb.ne 1b"
                         : "+r"(x), "+r"(n) :: "cc");
        uint64_t t1 = clock_gettime_nsec_np(CLOCK_UPTIME_RAW);
        uint64_t khz = t1 > t0 && x == 512 * 8 * 64 ? UINT64_C(512) * 8 * 64 * 1000000 / (t1 - t0) : 0;
        if (khz > best) best = khz;
    }
    printf("U14 method on this host: dependent-ADD chain at %.3f GHz (best of 2000)\n", best / 1e6);
    CHECK(best > 600000 && best < 6500000, "U14: the ADD chain times a plausible clock (%llu kHz)",
          (unsigned long long)best);
#endif
}

int main(int argc, char **argv)
{
    native_khz();
    scenario_cpu();
    scenario_gpu();
    scenario_gpu_table();
    gmu_hfi_opps = 6;      /* the b12-era table: the same scenarios at 915 MHz */
    scenario_gpu();
    gmu_hfi_opps = 11;
    dump_path = argc > 3 ? argv[3] : NULL;
    if (argc > 1) replay_file(argv[1], argc > 2 ? argv[2] : NULL);
    printf("%s: %u checks, %u failures (cpu report %zu words, gpu report %zu words)\n", failures ? "FAIL" : "PASS",
           checks, failures, (size_t)CPU_DVFS_REPORT_WORDS, (size_t)GPU_DVFS_REPORT_WORDS);
    return failures ? 1 : 0;
}

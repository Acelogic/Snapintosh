/* SPDX-License-Identifier: MIT */
/* compat/nvme-host.c against a controller model.
 *   clang -std=gnu11 -O1 -g -fsanitize=address,undefined -Wall -Wextra -Werror \
 *     -Icompat tools/test-nvme-host.c compat/nvme-host.c compat/ans-window.c -o build/test-nvme-host && build/test-nvme-host
 *
 * What it protects:
 *  - reads never leave the window: an out-of-window or oversized read is refused before any
 *    queue entry or doorbell is written (a regression here would read other partitions);
 *  - adoption refuses a DMA window inside guest memory, a controller that is not
 *    enabled-and-ready, and admin queue registers that are not the adopted ones;
 *  - data lands where the PRPs say for 1, 2 and >2 pages (the PRP list), at the right real LBA;
 *  - the queue survives phase wrap (more commands than entries);
 *  - a lost completion is a bounded timeout that stops the queue, and an error completion is
 *    reported without desynchronising it.
 * M7 failure inventory: docs/GUEST-WRITEBACK-M7-20260926.md. These pre-implementation
 * additions protect write/flush failure handling that a normal hardware boot cannot provoke. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "nvme-host.h"
#include "ans-window.h"

#define BAR 0x7a000000ull
#define DMA 0xae9300000ull
#define FIRST 1000ull
#define LAST 1999ull
#define DISK_LBAS 32768ull

static uint8_t dma[NVMEH_WINDOW_BYTES];
static uint8_t disk[DISK_LBAS * 512];
static uint32_t regs[0x2000 / 4];
static unsigned doorbells, cq_tail, cq_phase = 1, drop, fail_status, wrong_cid, wrong_sqid;
#if SNAP_ANS_ASYNC
/* agents/nvme-async: with defer set the controller only latches the SQ tail; controller_run executes later. */
static unsigned defer, latched;
#endif
static unsigned fail_nth;
static uint64_t controller_last = LAST;
static uint64_t clock_now;
static int failures;

#define CHECK(c) do { if (!(c)) { printf("FAIL %s:%d %s\n", __FILE__, __LINE__, #c); failures++; } } while (0)

static uint8_t *mem(uint64_t pa)
{
    if (pa >= DMA && pa < DMA + sizeof dma) return dma + (pa - DMA);
    return 0;
}
static uint64_t get64(const uint8_t *b) { uint64_t v; memcpy(&v, b, 8); return v; }

/* The controller: on the I/O SQ tail doorbell, execute every new entry. */
static unsigned sq_head;
static void controller(unsigned tail)
{
    while (sq_head != tail) {
        uint8_t *e = mem(DMA + NVMEH_IOSQ + sq_head * 64);
        sq_head = (sq_head + 1) % NVMEH_IO_ENTRIES;
        uint32_t cdw0; memcpy(&cdw0, e, 4);
        uint64_t prp1 = get64(e + 24), prp2 = get64(e + 32);
        uint64_t lba = get64(e + 40);
        uint32_t nlb; memcpy(&nlb, e + 48, 4);
        uint32_t n = (nlb & 0xffff) + 1, status = 0;
        unsigned op = cdw0 & 0xff;
        CHECK(op <= 2);
        if (op) CHECK(lba >= FIRST && lba + n - 1 <= controller_last);
        else CHECK(!prp1 && !prp2 && !lba && !nlb);           /* Flush has no data payload */
        if (op == 1) CHECK(nlb & (1u << 30));               /* every physical write uses FUA */
        if (drop) { drop--; continue; }                      /* a lost command: no completion */
        if (fail_nth && !--fail_nth) fail_status = 0x280;
        if (fail_status) { status = fail_status; fail_status = 0; }
        else if (op) {
            uint64_t bytes = n * 512ull, pages = (bytes + 4095) / 4096;
            for (uint64_t pg = 0; pg < pages; pg++) {
                uint64_t pa = pg == 0 ? prp1 : pages == 2 ? prp2 : get64(mem(prp2) + 8 * (pg - 1));
                uint64_t len = bytes - pg * 4096 < 4096 ? bytes - pg * 4096 : 4096;
                if (op == 2) memcpy(mem(pa), disk + lba * 512 + pg * 4096, len);
                else memcpy(disk + lba * 512 + pg * 4096, mem(pa), len);
            }
        }
        uint8_t *c = mem(DMA + NVMEH_IOCQ + cq_tail * 16);
        uint32_t dw3 = ((cdw0 >> 16) ^ wrong_cid) | cq_phase << 16 | status << 17;
        uint32_t dw2 = sq_head | (wrong_sqid ? 2u : 1u) << 16;
        memset(c, 0, 16);
        memcpy(c + 8, &dw2, 4);
        memcpy(c + 12, &dw3, 4);
        cq_tail = (cq_tail + 1) % NVMEH_IO_ENTRIES;
        if (!cq_tail) cq_phase ^= 1;
    }
}

static uint32_t rd(void *ctx, uint64_t pa)
{
    (void)ctx;
    if (pa >= BAR && pa < BAR + sizeof regs) return regs[(pa - BAR) / 4];
    uint8_t *m = mem(pa);
    if (!m) { printf("FAIL read of unmapped %#llx\n", (unsigned long long)pa); failures++; return 0; }
    uint32_t v; memcpy(&v, m, 4); return v;
}
static void wr(void *ctx, uint64_t pa, uint32_t v)
{
    (void)ctx;
    if (pa >= BAR && pa < BAR + sizeof regs) {
        regs[(pa - BAR) / 4] = v;
#if SNAP_ANS_ASYNC
        if (pa == BAR + 0x1008 && defer) { doorbells++; latched = v; return; }
#endif
        if (pa == BAR + 0x1008) { doorbells++; controller(v); }   /* SQ 1 tail (DSTRD 0) */
        return;
    }
    uint8_t *m = mem(pa);
    if (!m) { printf("FAIL write to unmapped %#llx\n", (unsigned long long)pa); failures++; return; }
    memcpy(m, &v, 4);
}
static void clean(void *ctx, uint64_t pa, uint64_t size) { (void)ctx; (void)pa; (void)size; }
static uint64_t now(void *ctx) { (void)ctx; return clock_now += 10; }

static const struct nvmeh_ops ops = {0, rd, wr, clean, now};

static struct nvmeh_params params(void)
{
    struct nvmeh_params p = {0};
    p.flags = NVMEH_F_ENABLE; p.bar = BAR; p.stride = 0; p.dma_base = DMA;
    p.io_tail = 3; p.io_head = 3; p.io_phase = 1; p.io_next_cid = 9;
    p.lba_bytes = 512; p.first_lba = FIRST; p.last_lba = LAST;
    p.max_transfer = 128 * 1024; p.timeout_ticks = 100000;
    return p;
}
static void controller_ready(void)
{
    memset(regs, 0, sizeof regs);
    regs[0x14 / 4] = 0x460001; regs[0x1c / 4] = 1;
    regs[0x24 / 4] = (NVMEH_ADMIN_ENTRIES - 1) << 16 | (NVMEH_ADMIN_ENTRIES - 1);
    regs[0x28 / 4] = (uint32_t)(DMA + NVMEH_ASQ); regs[0x2c / 4] = (uint32_t)((DMA + NVMEH_ASQ) >> 32);
    regs[0x30 / 4] = (uint32_t)(DMA + NVMEH_ACQ); regs[0x34 / 4] = (uint32_t)((DMA + NVMEH_ACQ) >> 32);
    sq_head = 3; cq_tail = 3; cq_phase = 1; doorbells = 0;
}

static int data_is(uint64_t lba, uint32_t count, uint32_t at)
{
    return !memcmp(dma + NVMEH_DATA + at, disk + lba * 512, count * 512ull);
}

/* Written before the1MiB implementation: exercise production chunking with
 * the real NVMe command builder, including errors a normal A16 boot cannot
 * intentionally provoke. No mirrored chunking algorithm in the test. */
static void large_window(void)
{
    static uint8_t head[1 << 20], tail[1 << 20], stage[(1 << 20) + 4096];
    struct nvmeh_params p = params(); struct nvmeh_state s = {0};
    p.flags |= NVMEH_F_WRITE; p.last_lba = FIRST + 8192 - 1;
    p.write_first_lba = FIRST + 2048; p.write_last_lba = p.last_lba - 2048;
    controller_last = p.last_lba; controller_ready(); memset(dma, 0, sizeof dma);
    CHECK(!nvmeh_adopt(&ops, &p, &s, 0, 0x1000));
    struct ans_window_backend b = {1024, head, tail, stage, dma + NVMEH_DATA, &ops, &p, &s
#if SNAP_ANS_ASYNC
                                   , 0
#endif
                                   };
    memset(head, 0x12, sizeof head); memset(tail, 0x34, sizeof tail);
    memset(stage + (1 << 20), 0xa7, 4096);
    volatile uint8_t *data = NULL;
    CHECK(!ans_window_read_blocks(&b, 128, 256, &data) && data == stage);
    CHECK(!memcmp(stage, head, 128 * 4096));
    CHECK(!memcmp(stage + 128 * 4096, disk + (FIRST + 2048) * 512, 128 * 4096));
    CHECK(!ans_window_read_blocks(&b, 640, 256, &data));
    CHECK(!memcmp(stage, disk + (FIRST + 640 * 8) * 512, 128 * 4096));
    CHECK(!memcmp(stage + 128 * 4096, tail, 128 * 4096));
    unsigned before = doorbells;
    CHECK(ans_window_prepare_write(&b, 255, 2, &data) == 0x20);
    CHECK(ans_window_prepare_write(&b, 767, 2, &data) == 0x20);
    CHECK(ans_window_prepare_write(&b, 256, 257, &data) == 0x20);
    CHECK(ans_window_read_blocks(&b, UINT64_MAX, 256, &data));
    CHECK(doorbells == before);
    CHECK(!ans_window_prepare_write(&b, 256, 256, &data) && data == stage);
    for (unsigned i = 0; i < 1 << 20; i++) stage[i] = (uint8_t)(i / 4096 + i);
    CHECK(!ans_window_write_blocks(&b, 256, 256));
    CHECK(doorbells == before + 8 && s.writes == 8);
    CHECK(!memcmp(stage, disk + (FIRST + 2048) * 512, 1 << 20));
    memset(stage, 0, 1 << 20);
    CHECK(!ans_window_read_blocks(&b, 256, 256, &data));
    CHECK(!memcmp(stage, disk + (FIRST + 2048) * 512, 1 << 20));
    CHECK(!nvmeh_flush(&ops, &p, &s));
    /* The third failed chunk terminates immediately; successful earlier chunks
     * remain on media and the guest whole-request result must be failure. */
    memset(stage, 0xb9, 1 << 20); before = doorbells; uint64_t writes = s.writes;
    uint8_t original_third = disk[(FIRST + 2048 + 512) * 512]; fail_nth = 3;
    CHECK(ans_window_write_blocks(&b, 256, 256));
    CHECK(doorbells == before + 3 && s.writes == writes + 2);
    CHECK(disk[(FIRST + 2048) * 512] == 0xb9);
    CHECK(disk[(FIRST + 2048 + 512) * 512] == original_third);
    fail_nth = 3; before = doorbells;
    CHECK(ans_window_read_blocks(&b, 256, 256, &data) && doorbells == before + 3);
    p.flags &= ~NVMEH_F_WRITE; before = doorbells;
    CHECK(ans_window_prepare_write(&b, 256, 256, &data) == 0x20 && doorbells == before);
    for (unsigned i = 1 << 20; i < sizeof stage; i++) CHECK(stage[i] == 0xa7);
    printf("1MiB production window: eight-command write/read, both synthetic crossings, middle-chunk errors; %d failures\n", failures);
}

#if SNAP_ANS_ASYNC
/* SNAP_ANS_ASYNC (agents/nvme-async/FAILURE-MODES.md N5, N6, N10, N17), built with -DSNAP_ANS_ASYNC=1:
 *  - submit/reap against the synchronous command on the same script and controller (a differential): every
 *    result and every nvmeh_state word but the tick sums equal, and the same disk and data buffer;
 *  - a pending reap changes nothing; ready() is read-only and true exactly when the completion is there;
 *  - busy, timeout from the submit's timestamp, dead queue, identity mismatch;
 *  - the async window backend: the 1 MiB production window scenarios of large_window() through start/poll with
 *    every physical command deferred, edge-only reads done at start, the stop's quiesce with a completed and with
 *    a lost command. */
static uint8_t disk0[sizeof disk];
static void controller_run(void) { unsigned d = defer; defer = 0; controller(latched); defer = d; }
/* The adopted queue's slots before the head hold this lap's completions (phase 1), as a real controller left
 * them; a zeroed slot would read as the next lap's entry once the head wraps, which only a poll can see. */
static void cq_lap(void) { for (unsigned i = 0; i < 3; i++) dma[NVMEH_IOCQ + 16 * i + 14] |= 1; }
static struct nvmeh_flight flight;
static unsigned async_pending_max;
static int async_cmd(const struct nvmeh_params *p, struct nvmeh_state *s, unsigned op, uint64_t wlba,
                     uint32_t count, uint32_t at)
{
    defer = 1;
    unsigned before_bells = doorbells;
    int r = nvmeh_submit(&ops, p, s, &flight, op, wlba, count, at);
    if (r) { defer = 0; CHECK(!flight.active); return r; }
    CHECK(doorbells == before_bells + 1 && flight.active);
    CHECK(nvmeh_submit(&ops, p, s, &flight, op, wlba, count, at) == NVMEH_E_BUSY && doorbells == before_bells + 1);
    unsigned n = 0, ran = 0;
    for (;;) {
        struct nvmeh_state before = *s;
        int ready = nvmeh_ready(&ops, p, s);
        CHECK(!memcmp(&before, s, sizeof before));
        r = nvmeh_reap(&ops, p, s, &flight);
        if (r != NVMEH_PENDING) break;
        CHECK(!ready);
        CHECK(!memcmp(&before, s, sizeof before));        /* a pending reap changes nothing */
        if (++n == 2) { controller_run(); ran = 1; }
    }
    CHECK(ran || r == NVMEH_E_TIMEOUT);
    CHECK(!flight.active);
    if (n > async_pending_max) async_pending_max = n;
    defer = 0;
    return r;
}
static int sync_cmd(const struct nvmeh_params *p, struct nvmeh_state *s, unsigned op, uint64_t wlba,
                    uint32_t count, uint32_t at)
{
    return op == 2 ? nvmeh_read(&ops, p, s, wlba, count, at) : op == 1 ? nvmeh_write(&ops, p, s, wlba, count, at) :
           nvmeh_flush(&ops, p, s);
}
typedef int (*cmd_fn)(const struct nvmeh_params *, struct nvmeh_state *, unsigned, uint64_t, uint32_t, uint32_t);
/* main()'s sequence, through either half. */
static unsigned script(cmd_fn run, struct nvmeh_state *s, int *results)
{
    unsigned k = 0;
    struct nvmeh_params p = params();
    memcpy(disk, disk0, sizeof disk);
    controller_last = LAST; controller_ready(); memset(s, 0, sizeof *s); memset(dma, 0, sizeof dma); cq_lap();
    clock_now = 0; drop = fail_status = fail_nth = wrong_cid = wrong_sqid = 0;
    results[k++] = nvmeh_adopt(&ops, &p, s, 0, 0x1000);
    results[k++] = run(&p, s, 2, LAST - FIRST + 1, 1, 0);
    results[k++] = run(&p, s, 2, 0, 257, 0);
    results[k++] = run(&p, s, 2, 0, 8, 0x800);
    results[k++] = run(&p, s, 2, 0, 8, 0);
    results[k++] = run(&p, s, 2, 17, 16, 0x1000);
    results[k++] = run(&p, s, 2, 100, 256, 0);
    for (unsigned i = 0; i < 3 * NVMEH_IO_ENTRIES; i++) results[k++] = run(&p, s, 2, (i * 37) % (LAST - FIRST - 8), 8, 0);
    results[k++] = run(&p, s, 1, 10, 8, 0);                  /* read-only */
    p.flags |= NVMEH_F_WRITE; p.write_first_lba = FIRST + 10; p.write_last_lba = LAST - 10;
    results[k++] = run(&p, s, 1, 9, 8, 0);
    results[k++] = run(&p, s, 1, 10, 257, 0);
    const unsigned counts[] = {8, 16, 256};
    for (unsigned i = 0; i < 2 * NVMEH_IO_ENTRIES; i++) {
        memset(dma + NVMEH_DATA, (int)(0x55 ^ i), counts[i % 3] * 512u);
        results[k++] = run(&p, s, 1, 100, counts[i % 3], 0);
        results[k++] = run(&p, s, 0, 0, 0, 0);
        results[k++] = run(&p, s, 2, 100, counts[i % 3], 0);
    }
    fail_status = 0x0280; results[k++] = run(&p, s, 1, 100, 8, 0);
    fail_status = 6; results[k++] = run(&p, s, 0, 0, 0, 0);
    fail_status = 0x0281; results[k++] = run(&p, s, 2, 5, 8, 0);
    results[k++] = run(&p, s, 2, 6, 8, 0);
    drop = 1; results[k++] = run(&p, s, 2, 7, 8, 0);       /* lost: timeout, queue closed */
    results[k++] = run(&p, s, 2, 8, 8, 0);
    results[k++] = run(&p, s, 1, 100, 8, 0);
    results[k++] = run(&p, s, 0, 0, 0, 0);
    drop = 0;
    return k;
}
static void identity(cmd_fn run, struct nvmeh_state *s, int *results, unsigned bad)
{
    struct nvmeh_params p = params();
    controller_ready(); memset(s, 0, sizeof *s); memset(dma, 0, sizeof dma); cq_lap(); clock_now = 0;
    results[0] = nvmeh_adopt(&ops, &p, s, 0, 0x1000);
    wrong_cid = bad == 0; wrong_sqid = bad == 1;
    results[1] = run(&p, s, 0, 0, 0, 0);
    wrong_cid = wrong_sqid = 0;
    p.flags |= NVMEH_F_WRITE; p.write_first_lba = FIRST + 10; p.write_last_lba = LAST - 10;
    results[2] = run(&p, s, 1, 100, 8, 0);
}
static int same_state(const struct nvmeh_state *a, const struct nvmeh_state *b)
{
    struct nvmeh_state x = *a, y = *b;
    x.max_ticks = y.max_ticks = x.total_ticks = y.total_ticks = 0;
    return !memcmp(&x, &y, sizeof x);
}
static int win_run(const struct ans_window_backend *b, unsigned op, uint64_t lba, uint64_t n, volatile uint8_t **data)
{
    defer = 1;
    int r = ans_window_start(b, op, lba, n);
    unsigned polls = 0;
    while (r == ANS_WINDOW_PENDING) {
        if (++polls % 2 == 0) controller_run();
        r = ans_window_poll(b, data);
    }
    if (!r && op == 2 && !polls) r = ans_window_poll(b, data);   /* done at start: the poll hands the data */
    defer = 0;
    return r;
}
static void large_window_async(void)
{
    static uint8_t head[1 << 20], tail[1 << 20], stage[(1 << 20) + 4096];
    static struct ans_window_flight w;
    struct nvmeh_params p = params(); struct nvmeh_state s = {0};
    p.flags |= NVMEH_F_WRITE; p.last_lba = FIRST + 8192 - 1;
    p.write_first_lba = FIRST + 2048; p.write_last_lba = p.last_lba - 2048;
    controller_last = p.last_lba; controller_ready(); memset(dma, 0, sizeof dma); cq_lap(); clock_now = 0;
    CHECK(!nvmeh_adopt(&ops, &p, &s, 0, 0x1000));
    struct ans_window_backend b = {1024, head, tail, stage, dma + NVMEH_DATA, &ops, &p, &s, &w};
    memset(head, 0x12, sizeof head); memset(tail, 0x34, sizeof tail);
    memset(stage + (1 << 20), 0xa7, 4096);
    volatile uint8_t *data = NULL;
    unsigned before = doorbells;
    CHECK(!win_run(&b, 2, 0, 16, &data) && data == stage && doorbells == before);   /* edge only: no command */
    CHECK(!memcmp(stage, head, 16 * 4096));
    data = NULL;
    CHECK(!win_run(&b, 2, 128, 256, &data) && data == stage);
    CHECK(!memcmp(stage, head, 128 * 4096));
    CHECK(!memcmp(stage + 128 * 4096, disk + (FIRST + 2048) * 512, 128 * 4096));
    CHECK(!win_run(&b, 2, 640, 256, &data));
    CHECK(!memcmp(stage, disk + (FIRST + 640 * 8) * 512, 128 * 4096));
    CHECK(!memcmp(stage + 128 * 4096, tail, 128 * 4096));
    before = doorbells;
    CHECK(win_run(&b, 1, 255, 2, &data) == 1 && win_run(&b, 1, 767, 2, &data) == 1);
    CHECK(win_run(&b, 1, 256, 257, &data) == 1 && win_run(&b, 2, UINT64_MAX, 256, &data) == 1);
    CHECK(doorbells == before);
    for (unsigned i = 0; i < 1 << 20; i++) stage[i] = (uint8_t)(i / 4096 + i);
    CHECK(!win_run(&b, 1, 256, 256, &data));
    CHECK(doorbells == before + 8 && s.writes == 8);
    CHECK(!memcmp(stage, disk + (FIRST + 2048) * 512, 1 << 20));
    memset(stage, 0, 1 << 20);
    CHECK(!win_run(&b, 2, 256, 256, &data));
    CHECK(!memcmp(stage, disk + (FIRST + 2048) * 512, 1 << 20));
    before = doorbells;
    CHECK(!win_run(&b, 0, 0, 0, &data) && doorbells == before + 1 && s.flushes == 1);
    memset(stage, 0xb9, 1 << 20); before = doorbells; uint64_t writes = s.writes;
    uint8_t original_third = disk[(FIRST + 2048 + 512) * 512]; fail_nth = 3;
    CHECK(win_run(&b, 1, 256, 256, &data) == 1);
    CHECK(doorbells == before + 3 && s.writes == writes + 2);
    CHECK(disk[(FIRST + 2048) * 512] == 0xb9 && disk[(FIRST + 2048 + 512) * 512] == original_third);
    fail_nth = 3; before = doorbells;
    CHECK(win_run(&b, 2, 256, 256, &data) == 1 && doorbells == before + 3);
    /* Busy: a start while a command is in flight sends nothing. */
    defer = 1; before = doorbells;
    CHECK(ans_window_start(&b, 2, 256, 32) == ANS_WINDOW_PENDING && doorbells == before + 1);
    CHECK(ans_window_ready(&b) == 0);
    CHECK(ans_window_start(&b, 2, 256, 32) == 1 && doorbells == before + 1);
    /* The stop's quiesce: a completed command is reaped (counted), the flight ends. */
    controller_run();
    CHECK(ans_window_ready(&b) == 1);
    uint64_t reads = s.reads;
    CHECK(ans_window_quiesce(&b) == 1 && !w.phys && !w.f.active && s.reads == reads + 1 && !(s.status & NVMEH_S_FAILED));
    CHECK(ans_window_quiesce(&b) == 0);
    /* ... and a lost one is bounded by its timeout and closes the queue. */
    CHECK(ans_window_start(&b, 2, 256, 32) == ANS_WINDOW_PENDING);
    uint64_t t0 = clock_now;
    CHECK(ans_window_quiesce(&b) == 1 && s.timeouts == 1 && (s.status & NVMEH_S_FAILED));
    CHECK(clock_now - t0 > p.timeout_ticks);
    defer = 0; before = doorbells;
    CHECK(win_run(&b, 2, 256, 32, &data) == 1 && doorbells == before);       /* dead */
    p.flags &= ~NVMEH_F_WRITE;
    CHECK(win_run(&b, 1, 256, 256, &data) == 1 && doorbells == before);
    for (unsigned i = 1 << 20; i < sizeof stage; i++) CHECK(stage[i] == 0xa7);
}
static void async_suite(void)
{
    static int a[2048], b[2048];
    static uint8_t dma_a[sizeof dma], disk_a[sizeof disk];
    struct nvmeh_state sa, sb;
    int before = failures;
    memcpy(disk0, disk, sizeof disk);
    unsigned na = script(sync_cmd, &sa, a);
    memcpy(dma_a, dma, sizeof dma); memcpy(disk_a, disk, sizeof disk);
    unsigned nb = script(async_cmd, &sb, b);
    CHECK(na == nb && !memcmp(a, b, na * sizeof a[0]));
    CHECK(same_state(&sa, &sb));
    CHECK(!memcmp(dma_a + NVMEH_DATA, dma + NVMEH_DATA, NVMEH_DATA_BYTES) && !memcmp(disk_a, disk, sizeof disk));
    CHECK(sb.timeouts == 1 && (sb.status & NVMEH_S_FAILED) && sb.errors == 3 && sb.writes == 2 * NVMEH_IO_ENTRIES);
    for (unsigned bad = 0; bad < 2; bad++) {
        identity(sync_cmd, &sa, a, bad);
        identity(async_cmd, &sb, b, bad);
        CHECK(!memcmp(a, b, 3 * sizeof a[0]) && a[1] == NVMEH_E_STATUS && a[2] == NVMEH_E_DEAD && same_state(&sa, &sb));
    }
    memcpy(disk, disk0, sizeof disk);
    large_window_async();
    printf("async: %u-command differential, window start/poll, quiesce; at most %u pending reaps; %d failures\n",
           na, async_pending_max, failures - before);
}
#endif

int main(void)
{
    for (size_t i = 0; i < sizeof disk; i++) disk[i] = (uint8_t)(i * 2654435761u >> 13);
    struct nvmeh_params p = params();
    struct nvmeh_state s;

    /* Adoption refusals. */
    controller_ready(); memset(&s, 0, sizeof s);
    CHECK(nvmeh_adopt(&ops, &p, &s, DMA - 0x1000, DMA + 0x1000) == NVMEH_E_GUEST);
    regs[0x1c / 4] = 0; memset(&s, 0, sizeof s);
    CHECK(nvmeh_adopt(&ops, &p, &s, 0, 0x1000) == NVMEH_E_CTRL);
    controller_ready(); regs[0x28 / 4] += 0x1000; memset(&s, 0, sizeof s);
    CHECK(nvmeh_adopt(&ops, &p, &s, 0, 0x1000) == NVMEH_E_QUEUES);
    struct nvmeh_params bad = p; bad.dma_base = DMA + 0x1000;
    controller_ready(); memset(&s, 0, sizeof s);
    CHECK(nvmeh_adopt(&ops, &bad, &s, 0, 0x1000) == NVMEH_E_PARAMS);
    CHECK(nvmeh_read(&ops, &p, &s, 0, 8, 0) == NVMEH_E_DEAD);    /* not adopted: nothing is sent */
    CHECK(doorbells == 0);

    controller_ready(); memset(&s, 0, sizeof s);
    CHECK(nvmeh_adopt(&ops, &p, &s, 0, 0x1000) == 0);

    /* Confinement: refused before any doorbell. */
    unsigned before = doorbells;
    CHECK(nvmeh_read(&ops, &p, &s, LAST - FIRST + 1, 1, 0) == NVMEH_E_RANGE);    /* first LBA past the end */
    CHECK(nvmeh_read(&ops, &p, &s, LAST - FIRST, 2, 0) == NVMEH_E_RANGE);        /* runs past the end */
    CHECK(nvmeh_read(&ops, &p, &s, 0, 257, 0) == NVMEH_E_RANGE);                 /* over max_transfer */
    CHECK(nvmeh_read(&ops, &p, &s, 0, 16, 0x1f000) == NVMEH_E_RANGE);            /* past the data buffer */
    CHECK(nvmeh_read(&ops, &p, &s, 0, 8, 0x800) == NVMEH_E_RANGE);               /* unaligned */
    CHECK(doorbells == before && s.refused == 5);

    /* Data for 1, 2 and >2 pages, at the real LBA first + wlba. */
    CHECK(nvmeh_read(&ops, &p, &s, 0, 8, 0) == 0 && data_is(FIRST, 8, 0));
    CHECK(nvmeh_read(&ops, &p, &s, 17, 16, 0x1000) == 0 && data_is(FIRST + 17, 16, 0x1000));
    CHECK(nvmeh_read(&ops, &p, &s, 100, 256, 0) == 0 && data_is(FIRST + 100, 256, 0));
    CHECK(nvmeh_read(&ops, &p, &s, LAST - FIRST, 1, 0) == 0 && data_is(LAST, 1, 0));

    /* Phase wrap: more commands than entries. */
    int ok = 1;
    for (unsigned i = 0; i < 3 * NVMEH_IO_ENTRIES; i++) {
        uint64_t w = (i * 37) % (LAST - FIRST - 8);
        ok &= nvmeh_read(&ops, &p, &s, w, 8, 0) == 0 && data_is(FIRST + w, 8, 0);
    }
    CHECK(ok);

    /* Read-only is the default; no queue/data mutation on disabled or invalid writes. */
    before = doorbells;
    CHECK(nvmeh_write(&ops, &p, &s, 10, 8, 0) == NVMEH_E_READONLY);
    CHECK(doorbells == before && s.writes == 0);
    p.flags |= NVMEH_F_WRITE;
    p.write_first_lba = FIRST + 10; p.write_last_lba = LAST - 10;
    CHECK(nvmeh_write(&ops, &p, &s, 9, 8, 0) == NVMEH_E_RANGE);
    CHECK(nvmeh_write(&ops, &p, &s, LAST-FIRST-10, 2, 0) == NVMEH_E_RANGE);
    CHECK(nvmeh_write(&ops, &p, &s, 10, 0, 0) == NVMEH_E_RANGE);
    CHECK(nvmeh_write(&ops, &p, &s, 10, 257, 0) == NVMEH_E_RANGE);
    CHECK(nvmeh_write(&ops, &p, &s, 10, 16, 0x1f000) == NVMEH_E_RANGE);
    CHECK(doorbells == before);
    /* The data differs from the old disk for one, two and32 pages and wraps the queue. */
    const unsigned counts[] = {8, 16, 256};
    for (unsigned i = 0; i < 2 * NVMEH_IO_ENTRIES; i++) {
        unsigned count = counts[i % 3];
        memset(dma + NVMEH_DATA, (int)(0x55 ^ i), count * 512u);
        CHECK(nvmeh_write(&ops, &p, &s, 100, count, 0) == 0);
        CHECK(data_is(FIRST + 100, count, 0));
        CHECK(nvmeh_flush(&ops, &p, &s) == 0);
        memset(dma + NVMEH_DATA, 0, count * 512u);
        CHECK(nvmeh_read(&ops, &p, &s, 100, count, 0) == 0);
        CHECK(dma[NVMEH_DATA] == (uint8_t)(0x55 ^ i));
    }
    CHECK(s.writes == 2 * NVMEH_IO_ENTRIES && s.flushes == s.writes);
    uint64_t writes = s.writes, flushes = s.flushes;
    fail_status = 0x0280;
    CHECK(nvmeh_write(&ops, &p, &s, 100, 8, 0) == NVMEH_E_STATUS && s.writes == writes);
    fail_status = 6;
    CHECK(nvmeh_flush(&ops, &p, &s) == NVMEH_E_STATUS && s.flushes == flushes);
    CHECK(nvmeh_flush(&ops, &p, &s) == 0 && s.flushes == flushes + 1);

    /* An error completion: reported, and the queue stays usable. */
    fail_status = 0x0281;                                    /* media error */
    CHECK(nvmeh_read(&ops, &p, &s, 5, 8, 0) == NVMEH_E_STATUS && s.errors == 3 && (s.last_status >> 16) == 0x0281);
    CHECK(nvmeh_read(&ops, &p, &s, 6, 8, 0) == 0 && data_is(FIRST + 6, 8, 0));

    /* A lost completion: bounded timeout, then the queue is closed. */
    drop = 1;
    CHECK(nvmeh_read(&ops, &p, &s, 7, 8, 0) == NVMEH_E_TIMEOUT && s.timeouts == 1 && (s.status & NVMEH_S_FAILED));
    before = doorbells;
    CHECK(nvmeh_read(&ops, &p, &s, 8, 8, 0) == NVMEH_E_DEAD && doorbells == before);
    CHECK(nvmeh_write(&ops, &p, &s, 100, 8, 0) == NVMEH_E_DEAD && doorbells == before);
    CHECK(nvmeh_flush(&ops, &p, &s) == NVMEH_E_DEAD && doorbells == before);

    for (unsigned bad_identity = 0; bad_identity < 2; bad_identity++) {
        controller_ready(); memset(&s, 0, sizeof s); memset(dma, 0, sizeof dma);
        CHECK(nvmeh_adopt(&ops, &p, &s, 0, 0x1000) == 0);
        wrong_cid = bad_identity == 0; wrong_sqid = bad_identity == 1;
        CHECK(nvmeh_flush(&ops, &p, &s) == NVMEH_E_STATUS && (s.status & NVMEH_S_FAILED));
        wrong_cid = wrong_sqid = 0;
        before = doorbells;
        CHECK(nvmeh_write(&ops, &p, &s, 100, 8, 0) == NVMEH_E_DEAD && doorbells == before);
    }

    large_window();
#if SNAP_ANS_ASYNC
    async_suite();
#endif
    printf("%s: %llu reads, %d failures\n", failures ? "FAIL" : "ok", (unsigned long long)s.reads, failures);
    return failures != 0;
}

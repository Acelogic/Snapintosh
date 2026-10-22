/* SPDX-License-Identifier: MIT */
/* Fix 2, asynchronous IB completion, end to end: the kext's START/POLL loop (compat/adreno-ib-async.h, the code
 * AdrenoX2.cpp ibRing runs when built with ADRENO_IB_ASYNC) drives the monitor's HVC #0xad16 dispatch in the order
 * probes/xnuboot.c has with SNAP_ADRENO_IB_ASYNC (POLL first, then the in-flight admission, then the call) over
 * tools/test-adreno-ring.c's CP, which here takes model time to execute an IB. The failure modes this was written
 * against are agents/async-ib/FAILURE-MODES.md (A-numbers below), written before the code. It also runs
 * test-adreno-ring.c's S1 (the ring itself) and S3 (the monitor's calls alone), and needs no draw-plan fixture.
 *
 *   clang -std=gnu11 -Icompat -Ishadow -O1 -g -fsanitize=address,undefined -Wall -Wextra -Werror \
 *     -DSNAP_ADRENO_IB_ASYNC=1 [-DADRENO_IB_POLL_DIVISOR=1u] tools/test-adreno-ib-async.c \
 *     compat/adreno-ib-command.c compat/adreno-ib.c compat/adreno-fill-command.c compat/adreno-fill.c \
 *     compat/adreno-submit.c compat/adreno-resource.c compat/adreno-resource-list.c compat/adreno.c \
 *     compat/irq-forward.c shadow/stage2.c shadow/shadow.c shadow/mmu.c -o build/test-adreno-ib-async \
 *     && build/test-adreno-ib-async
 * Run from the tree root. SNAP_RING_ARTIFACT_DIR, when set, receives ib-async-record.bin, the IBASYNC1 report record
 * (probes/xnuboot.c OUT_IB_ASYNC) of the last scenario, which tools/perf_counters.py decode_ib_async must decode, and
 * ib-async-token.json, the model's monitor-call hold times for one long IB, synchronous against asynchronous.
 * No hardware client. */
#define ADRENO_RING_NO_MAIN 1
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunused-function"   /* S2 needs the draw-plan fixture: not run here */
#include "test-adreno-ring.c"
#pragma clang diagnostic pop
#include "adreno-ib-async.h"
#include "adreno-ib-command.h"
#if !SNAP_ADRENO_IB_ASYNC
#error "build with -DSNAP_ADRENO_IB_ASYNC=1"
#endif

/* --- the monitor: probes/xnuboot.c's dispatch for HVC #0xad16 --------------------------------------------------- */
static int monitor_async = 1;                   /* 0: a monitor without the define (or older): no START/POLL */
static const struct adreno_ops *cpu = &ring_ops; /* the vCPU that takes this HVC (A4) */
static unsigned hvcs, starts_sent, polls_sent, ib_records, migrate;
static uint64_t held_total, held_max;            /* model ticks inside monitor calls: the token's hold */
static void monitor_hvc(void *ctx, uint64_t x[4])
{
    (void)ctx;
    const uint64_t request = x[0], t0 = clock_now;
    hvcs++;
    starts_sent += request == ADRENO_GUEST_IB_START;
    polls_sent += request == ADRENO_GUEST_IB_POLL;
    if (monitor_async && request == ADRENO_GUEST_IB_POLL) {   /* gpu_ib_poll_hvc */
        const uint64_t active = F.active;
        adreno_guest_ib_poll(cpu, &P, &S, &F, x);
        ib_records += active && !F.active;                    /* one EV_GPU_IB per IB (A18) */
    } else {
        int e = monitor_async ? adreno_ib_flight_refuse(&S, &F, x) : 0;
        if (!e) switch (request) {
        case ADRENO_GUEST_UNMAP:
            e = adreno_guest_unmap(cpu, &P, &S, x, dart_leaf, s3_native_unmap, 0, MEM_LOW, MEM_HIGH); break;
        case ADRENO_GUEST_CACHE: e = adreno_guest_cache(cpu, &P, &S, x, dart_leaf, 0, MEM_LOW, MEM_HIGH); break;
        case ADRENO_GUEST_FILL32: e = adreno_guest_fill32(cpu, &P, &S, x, dart_leaf, 0, MEM_LOW, MEM_HIGH); break;
        case ADRENO_GUEST_IB: e = adreno_guest_ib(cpu, &P, &S, x, dart_leaf, 0, MEM_LOW, MEM_HIGH); break;
        default:
            if (monitor_async && request == ADRENO_GUEST_IB_START)
                e = adreno_guest_ib_start(cpu, &P, &S, &F, x, dart_leaf, 0, MEM_LOW, MEM_HIGH);
            else
                e = adreno_guest_fence(cpu, &P, &S, x, dart_leaf, 0, MEM_LOW, MEM_HIGH);
        }
        ib_records += request == ADRENO_GUEST_IB ||
                      (monitor_async && request == ADRENO_GUEST_IB_START && e != ADRENO_IB_PENDING);
    }
    const uint64_t held = clock_now - t0;
    held_total += held;
    if (held > held_max) held_max = held;
}

/* --- the kext: AdrenoX2 configureGuestIB's discovery and ibRing ------------------------------------------------- */
static uint64_t waited_us;
static void kext_delay(void *ctx, uint32_t us)  /* IODelay: guest time passes, off the monitor */
{
    (void)ctx;
    clock_now += us;
    waited_us += us;
    if (migrate) cpu = cpu == &ring_ops ? &cpu_b : &ring_ops;   /* the thread resumes on the other vCPU */
}
static const struct adreno_ib_async_ops kext = {0, monitor_hvc, kext_delay};
static int kext_async;                           /* gAdrenoIBAsync */
static struct adreno_ib_async_stats kext_stats;
static struct adreno_ib_reply kext_ib(uint64_t va, uint64_t dwords, uint64_t bytes)
{
    uint64_t out[4];
    if (kext_async) adreno_ib_async_run(&kext, va, dwords, bytes, out, &kext_stats);
    else { out[0] = ADRENO_GUEST_IB; out[1] = va; out[2] = dwords; out[3] = bytes; monitor_hvc(0, out); }
    return (struct adreno_ib_reply){(int64_t)out[0], out[1], out[2], out[3]};
}
static void e2e_setup(uint64_t latency)
{
    s3_setup(22, latency);
    cpu = &ring_ops;
    cpu_b = ring_ops;
    cpu_b.ctx = &cpu_b;
    cpu_b.rd = cpu_b_rd;
    cpu_b_reads = 0;
    hvcs = starts_sent = polls_sent = ib_records = migrate = 0;
    held_total = held_max = waited_us = 0;
    memset(&kext_stats, 0, sizeof kext_stats);
    monitor_async = 1;
    kext_async = adreno_ib_async_probe(&kext);
}

/* A11: discovery, on both monitors, and the synchronous fallback. */
static void test_discovery(void)
{
    e2e_setup(0);
    unsigned writes = nlog, cleans_before = cleans;
    CHECK(kext_async == 1 && polls_sent == 1 && F.idle == 1 && nlog == writes && cleans == cleans_before);
    e2e_setup(800);
    monitor_async = 0;                                  /* the define-off build: the fence handler refuses POLL */
    S.fence_error = 0;
    kext_async = adreno_ib_async_probe(&kext);
    CHECK(kext_async == 0 && (int64_t)S.fence_error == ADRENO_E_PARAMS && F.polls == 1 && !cp.doorbells);   /* F: setup's probe */
    s3_package(0xa5a5b001);
    struct adreno_ib_reply reply = kext_ib(PKG_VA, 4, 64);
    CHECK(adreno_ib_classify(&reply) == 0 && starts_sent == 0 && dev_rd32(WORK_PA) == 0xa5a5b001);
    CHECK(held_max >= 800);                             /* the synchronous IB held the monitor the whole time */
}

/* START -> several POLLs -> completion through the kext's loop; the token's hold, synchronous against async. */
static void test_complete_and_hold(void)
{
    e2e_setup(1500);
    s3_package(0xa5a5b002);
    struct adreno_ib_reply reply = kext_ib(PKG_VA, 4, 64);
    CHECK(adreno_ib_classify(&reply) == 0 && reply.marker == (ADRENO_IB_MARKER_BASE ^ 1u) && reply.ticks >= 1500);
    CHECK(kext_stats.pending == 1 && kext_stats.polls >= 3 && ib_records == 1 && dev_rd32(WORK_PA) == 0xa5a5b002);
    CHECK(F.finished == 1 && F.ok == 1 && !F.active && S.ib_dwords == 4 && S.ib_errors == 0);
    /* One long IB (30 ms of GPU time, a drag frame's worth): how long the monitor is held per call. */
    const uint64_t latency = 30000;
    uint64_t sync_max, sync_total, async_max, async_total;
    unsigned sync_calls, async_calls;
    e2e_setup(latency);
    s3_package(0xa5a5b003);
    kext_async = 0;
    reply = kext_ib(PKG_VA, 4, 64);
    CHECK(reply.status == 0 && dev_rd32(WORK_PA) == 0xa5a5b003);
    sync_max = held_max; sync_total = held_total; sync_calls = hvcs - 1;     /* minus the discovery POLL */
    e2e_setup(latency);
    s3_package(0xa5a5b004);
    reply = kext_ib(PKG_VA, 4, 64);
    CHECK(reply.status == 0 && dev_rd32(WORK_PA) == 0xa5a5b004 && reply.ticks >= latency);
    async_max = held_max; async_total = held_total; async_calls = hvcs - 1;
    /* The model charges 50 ticks per counter read, so a POLL costs 50 ticks against a 200-tick wait; on the A16 a
     * POLL is a few microseconds. What other vCPUs feel is the longest single hold. */
    CHECK(sync_max >= latency && async_max < 1000 && async_total < latency / 4);
    CHECK(async_calls == kext_stats.polls + 1 && kext_stats.polls <= 5 + latency / 200 + 2);
    printf("RING_ASYNC_TOKEN gpu=%llu ticks: synchronous %u call(s), longest hold %llu, total %llu; asynchronous %u "
           "calls, longest hold %llu, total %llu, guest wait %llu\n", (unsigned long long)latency, sync_calls,
           (unsigned long long)sync_max, (unsigned long long)sync_total, async_calls, (unsigned long long)async_max,
           (unsigned long long)async_total, (unsigned long long)waited_us);
    char json[512];
    int n = snprintf(json, sizeof json, "{\"gpu_ticks\": %llu, \"sync\": {\"calls\": %u, \"max_hold\": %llu, "
                     "\"held\": %llu}, \"async\": {\"calls\": %u, \"max_hold\": %llu, \"held\": %llu, \"waited\": %llu}}\n",
                     (unsigned long long)latency, sync_calls, (unsigned long long)sync_max,
                     (unsigned long long)sync_total, async_calls, (unsigned long long)async_max,
                     (unsigned long long)async_total, (unsigned long long)waited_us);
    CHECK(n > 0 && (size_t)n < sizeof json);
    save("ib-async-token.json", json, (size_t)n);
}

/* Final outcomes through the loop: GPU error, a fault, the budget; A4: the thread migrating every wait. */
static void test_outcomes_and_migration(void)
{
    e2e_setup(900);
    s3_package(1);
    cp.int0_in_ib = 1u << 24;
    struct adreno_ib_reply reply = kext_ib(PKG_VA, 4, 64);
    CHECK(reply.status == ADRENO_IB_E_GPU_ERROR && !reply.marker && adreno_ib_classify(&reply) == ADRENO_IB_E_GPU_ERROR);
    e2e_setup(900);
    s3_package(1);
    cp.fault_in_ib = 1;
    reply = kext_ib(PKG_VA, 4, 64);
    CHECK(reply.status == ADRENO_IB_E_UNCERTAIN && adreno_ib_classify(&reply) == ADRENO_SUBMIT_E_UNCERTAIN);
    e2e_setup(1);
    s3_package(1);
    cp.halt = 1;
    reply = kext_ib(PKG_VA, 4, 64);
    CHECK(reply.status == ADRENO_IB_E_UNCERTAIN && reply.ticks > BUDGET && !reply.marker);
    CHECK(adreno_ib_classify(&reply) == ADRENO_SUBMIT_E_UNCERTAIN && kext_stats.polls <= BUDGET / 200 + 8);
    CHECK(waited_us < BUDGET + 400 && !F.active && F.uncertain == 1);
    e2e_setup(2500);                                    /* A4 */
    s3_package(0xa5a5b005);
    migrate = 1;
    reply = kext_ib(PKG_VA, 4, 64);
    CHECK(reply.status == 0 && dev_rd32(WORK_PA) == 0xa5a5b005 && cpu_b_reads > 0 && kext_stats.polls >= 3);
}

/* A9, A10: the kext's reading of what comes back after PENDING. A scripted monitor answers START with PENDING and
 * then the given POLL reply (or PENDING forever). */
static struct { int64_t start_status; uint64_t start_marker; int64_t status; uint64_t marker; int forever; } script;
static unsigned script_polls;
static void scripted_hvc(void *ctx, uint64_t x[4])
{
    (void)ctx;
    if (x[0] == ADRENO_GUEST_IB_START) { x[0] = (uint64_t)script.start_status; x[1] = script.start_marker; x[2] = 7; x[3] = 57; return; }
    CHECK(x[0] == ADRENO_GUEST_IB_POLL && x[1] == script.start_marker && !x[2] && !x[3]);
    script_polls++;
    if (script.forever) { x[0] = (uint64_t)(int64_t)ADRENO_IB_PENDING; x[1] = script.start_marker; x[2] = 9; x[3] = 57; return; }
    x[0] = (uint64_t)script.status; x[1] = script.marker; x[2] = 11; x[3] = 57;
}
static void scripted_delay(void *ctx, uint32_t us) { (void)ctx; waited_us += us; }
static void test_kext_reading(void)
{
    const struct adreno_ib_async_ops ops = {0, scripted_hvc, scripted_delay};
    const uint64_t M = ADRENO_IB_MARKER_BASE ^ 5u;
    const struct { int64_t status; uint64_t marker; int64_t want; } cases[] = {
        {0, M, 0}, {ADRENO_IB_E_GPU_ERROR, 0, ADRENO_IB_E_GPU_ERROR}, {ADRENO_IB_E_UNCERTAIN, 0, ADRENO_IB_E_UNCERTAIN},
        {ADRENO_E_PARAMS, 0, ADRENO_IB_E_UNCERTAIN},    /* a define-off monitor's refusal after the doorbell */
        {ADRENO_IB_E_BUSY, 0, ADRENO_IB_E_UNCERTAIN}, {ADRENO_IB_IDLE, 0, ADRENO_IB_E_UNCERTAIN},
        {ADRENO_E_WINDOW, 0, ADRENO_IB_E_UNCERTAIN}, {ADRENO_E_RING, 0, ADRENO_IB_E_UNCERTAIN},
        {ADRENO_IB_PENDING, M ^ 1, ADRENO_IB_E_UNCERTAIN}, {0, M ^ 1, ADRENO_IB_E_UNCERTAIN},
        {0, 0, ADRENO_IB_E_UNCERTAIN}, {ADRENO_IB_E_GPU_ERROR, M, ADRENO_IB_E_UNCERTAIN},
        {ADRENO_IB_E_UNCERTAIN, M, ADRENO_IB_E_UNCERTAIN}, {-1234, 0, ADRENO_IB_E_UNCERTAIN}};
    unsigned right = 0;
    for (unsigned k = 0; k < sizeof cases / sizeof cases[0]; k++) {
        script = (typeof(script)){ADRENO_IB_PENDING, M, cases[k].status, cases[k].marker, 0};
        uint64_t out[4];
        adreno_ib_async_run(&ops, PKG_VA, 4, 64, out, 0);
        struct adreno_ib_reply reply = {(int64_t)out[0], out[1], out[2], out[3]};
        int ok = (int64_t)out[0] == cases[k].want && out[1] == (cases[k].want ? 0 : M) && out[2] == 11 && out[3] == 57 &&
                 (cases[k].want != ADRENO_IB_E_UNCERTAIN || adreno_ib_classify(&reply) == ADRENO_SUBMIT_E_UNCERTAIN);
        if (!ok) printf("FAIL kext reading case %u: got %lld\n", k, (long long)(int64_t)out[0]);
        CHECK(ok);
        right += ok;
    }
    /* START's own replies: final ones pass through untouched; PENDING without a usable marker is UNCERTAIN. */
    uint64_t out[4];
    script = (typeof(script)){ADRENO_IB_E_BUSY, 0, 0, 0, 0};
    script_polls = 0;
    adreno_ib_async_run(&ops, PKG_VA, 4, 64, out, 0);
    struct adreno_ib_reply refused = {(int64_t)out[0], out[1], out[2], out[3]};
    CHECK((int64_t)out[0] == ADRENO_IB_E_BUSY && !script_polls && adreno_ib_classify(&refused) == ADRENO_SUBMIT_E_INACTIVE);
    script = (typeof(script)){ADRENO_IB_PENDING, 0, 0, 0, 0};
    adreno_ib_async_run(&ops, PKG_VA, 4, 64, out, 0);
    CHECK((int64_t)out[0] == ADRENO_IB_E_UNCERTAIN && !out[1] && !script_polls);
    script = (typeof(script)){ADRENO_IB_PENDING, 1ull << 32, 0, 0, 0};
    adreno_ib_async_run(&ops, PKG_VA, 4, 64, out, 0);
    CHECK((int64_t)out[0] == ADRENO_IB_E_UNCERTAIN && !out[1] && !script_polls);
    /* A10: PENDING forever: UNCERTAIN once the kext's own bound is spent, and no sooner. */
    script = (typeof(script)){ADRENO_IB_PENDING, M, 0, 0, 1};
    script_polls = 0;
    waited_us = 0;
    struct adreno_ib_async_stats stats = {0};
    adreno_ib_async_run(&ops, PKG_VA, 4, 64, out, &stats);
    CHECK((int64_t)out[0] == ADRENO_IB_E_UNCERTAIN && !out[1] && waited_us >= ADRENO_IB_ASYNC_LIMIT_US &&
          waited_us < ADRENO_IB_ASYNC_LIMIT_US + ADRENO_IB_ASYNC_DELAY_MAX_US &&
          script_polls <= ADRENO_IB_ASYNC_LIMIT_US / ADRENO_IB_ASYNC_DELAY_MAX_US + 6 && stats.polls == script_polls);
    printf("RING_ASYNC_KEXT_READING %u/%u; PENDING forever: %u polls, %llu us\n", right,
           (unsigned)(sizeof cases / sizeof cases[0]), script_polls, (unsigned long long)waited_us);
}

/* A7: the kext's own classifiers read each in-flight refusal as "refused before any ring write". */
static int fill_pre_doorbell(int64_t status, uint64_t x1)  /* AdrenoX2::fillWork's mapping, re-stated */
{
    if (x1) return 0;
    switch (status) {
    case ADRENO_E_PARAMS: case ADRENO_E_WINDOW: case ADRENO_E_TARGET: case ADRENO_E_CX: case ADRENO_E_GX:
    case ADRENO_E_HALT: case ADRENO_E_CB0: case ADRENO_E_FAULT: case ADRENO_E_SQE: case ADRENO_E_RING: return 1;
    }
    return 0;
}
static void test_refusals_classified(void)
{
    e2e_setup(4000);
    s3_package(0xa5a5b006);
    map(FILL_A_VA, FILL_A_PA, 0x4000, 0);
    uint64_t x[4] = {ADRENO_GUEST_IB_START, PKG_VA, 4, 64};
    monitor_hvc(0, x);
    CHECK((int64_t)x[0] == ADRENO_IB_PENDING && F.active);
    const uint64_t marker = x[1];
    const uint32_t value = 0x5a5ab007;
    m_wr(0, FENCE_PA + 0x200, ~value);                  /* the kext's probeGuestFence seeds ~value */
    uint64_t f[4] = {ADRENO_GUEST_FENCE, FENCE_VA + 0x200, value, 0};
    monitor_hvc(0, f);
    CHECK(adreno_fence_classify((int64_t)f[0], f[1], value, m_rd(0, FENCE_PA + 0x200)) == ADRENO_SUBMIT_E_INACTIVE);
    uint64_t l[4] = {ADRENO_GUEST_FILL32, FILL_A_VA, 0x40, 0x11223344};
    monitor_hvc(0, l);
    CHECK(fill_pre_doorbell((int64_t)l[0], l[1]));
    uint64_t i[4] = {ADRENO_GUEST_IB, PKG_VA, 4, 64};
    monitor_hvc(0, i);
    struct adreno_ib_reply ib_reply = {(int64_t)i[0], i[1], i[2], i[3]};
    CHECK(adreno_ib_classify(&ib_reply) == ADRENO_SUBMIT_E_INACTIVE && F.refused == 3);
    /* The flight goes on and completes, as the kext's loop would see it. */
    unsigned polls;
    CHECK(s3_poll_until_final(&ring_ops, marker, x, &polls, 0) == 0 && dev_rd32(WORK_PA) == 0xa5a5b006);
}

/* The report record: several flights of every kind in one monitor's life, as the stop leaves it. */
static void test_record(void)
{
    e2e_setup(1200);
    struct adreno_ib_reply reply;
    for (unsigned n = 0; n < 5; n++) {                  /* retired after POLLs */
        s3_package(0xa5a5c000 + n);
        reply = kext_ib(PKG_VA, 4, 64);
        CHECK(reply.status == 0);
    }
    cp.latency = 0;                                     /* retired within START's spin: no flight */
    reply = kext_ib(PKG_VA, 4, 64);
    CHECK(reply.status == 0);
    cp.latency = 900;                                   /* GPU error */
    cp.int0_in_ib = 1u << 24;
    reply = kext_ib(PKG_VA, 4, 64);
    CHECK(reply.status == ADRENO_IB_E_GPU_ERROR);
    cp.int0 = cp.int0_in_ib = 0;
    uint64_t x[4] = {ADRENO_GUEST_IB_START, PKG_VA, 4, 64};  /* abandoned: started, never polled */
    monitor_hvc(0, x);
    CHECK((int64_t)x[0] == ADRENO_IB_PENDING);
    clock_now += BUDGET + GRACE + 1;
    CHECK(s3_tick() == 0 && F.abandoned == 1);
    x[0] = ADRENO_GUEST_IB_START; x[1] = PKG_VA; x[2] = 4; x[3] = 64;   /* in flight at the stop */
    monitor_hvc(0, x);
    CHECK((int64_t)x[0] == ADRENO_IB_PENDING);
    int final;
    CHECK(adreno_ib_flight_drain(&ring_ops, &P, &S, &F, ring_ops.hz / 10, &final) == 1 && final == 0);
    adreno_quiesce(&ring_ops, &P, &S);
    CHECK((S.status & ADRENO_S_QUIESCED) != 0);
    CHECK(F.starts == 9 && F.flights == 8 && F.finished == 6 && F.abandoned == 1 && F.stopped == 1);
    CHECK(F.ok == 7 && F.gpu_errors == 1 && F.uncertain == 0 && !F.active);
    CHECK(F.polls == F.poll_pending + F.finished + F.idle + F.mismatched + F.poll_refused);
    uint64_t record[2 + ADRENO_IB_FLIGHT_WORDS];
    record[0] = UINT64_C(0x31434e5953414249);           /* "IBASYNC1", probes/xnuboot.c IB_ASYNC_MAGIC */
    record[1] = (uint64_t)sizeof(struct adreno_ib_flight) << 32 | ADRENO_IB_POLL_DIVISOR;
    memcpy(record + 2, &F, sizeof F);
    save("ib-async-record.bin", record, sizeof record);
    printf("RING_ASYNC_RECORD starts=%llu flights=%llu polls=%llu pending=%llu finished=%llu abandoned=%llu "
           "stopped=%llu ok=%llu gpu_errors=%llu max_ticks=%llu max_reads=%llu\n",
           (unsigned long long)F.starts, (unsigned long long)F.flights, (unsigned long long)F.polls,
           (unsigned long long)F.poll_pending, (unsigned long long)F.finished, (unsigned long long)F.abandoned,
           (unsigned long long)F.stopped, (unsigned long long)F.ok, (unsigned long long)F.gpu_errors,
           (unsigned long long)F.max_ticks, (unsigned long long)F.max_reads);
}

int main(void)
{
    dram = calloc(1, RAM_SIZE);
    cache = calloc(1, RAM_SIZE);
    if (!dram || !cache) return 2;
    test_s1_capacity();
    test_s1_edges();
    test_s1_nop_split();
    test_s3();
    unsigned before = failures;
    test_discovery();
    test_complete_and_hold();
    test_outcomes_and_migration();
    test_kext_reading();
    test_refusals_classified();
    test_record();
    printf("RING_ASYNC_E2E %s\n", failures == before ? "ok" : "FAILED");
    free(dram);
    free(cache);
    if (failures) { printf("FAIL: %u of %u asynchronous IB checks\n", failures, checks); return 1; }
    printf("PASS: %u asynchronous IB checks (divisor %u); ring S1, monitor S3, kext loop end to end: discovery and "
           "fallback, completion, token hold, outcomes, budget, migration, kext reading, refusals, record\n",
           checks, (unsigned)ADRENO_IB_POLL_DIVISOR);
    return 0;
}

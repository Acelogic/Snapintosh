/* SPDX-License-Identifier: MIT */
/* The kext's IB pipeline (compat/adreno-ib-pipeline.h, -DADRENO_PIPELINE=1) end to end against async-ib's monitor
 * model: the engine AdrenoX2.cpp runs under fSubmitLock drives the monitor's HVC #0xad16 dispatch (START/POLL with
 * SNAP_ADRENO_IB_ASYNC, in probes/xnuboot.c's order) over tools/test-adreno-ring.c's CP, which takes model time per
 * IB (cp.latency). The kext side is real: adreno_ib_submit_begin/ring/finish (stage, relocate, validate, TO_DEVICE,
 * START, FROM_DEVICE), the two package slots, and present-sync's write table (AdrenoDisplaySync.h). Resource lists are
 * recorded fixtures; IOGPU's event machine is a stamp word and per-command-buffer completion values.
 * Failure modes: agents/gpu-pipeline/FAILURE-MODES.md (written before the code); the letters below are its entries.
 *
 *   clang -std=gnu11 -Icompat -Ishadow -O1 -g -fsanitize=address,undefined -Wall -Wextra -Werror \
 *     -DSNAP_ADRENO_IB_ASYNC=1 -DADRENO_PIPELINE=1 tools/test-adreno-ib-pipeline.c compat/adreno-ib-command.c \
 *     compat/adreno-ib.c compat/adreno-fill-command.c compat/adreno-fill.c compat/adreno-submit.c \
 *     compat/adreno-resource.c compat/adreno-resource-list.c compat/adreno.c compat/irq-forward.c shadow/stage2.c \
 *     shadow/shadow.c shadow/mmu.c -o build/test-adreno-ib-pipeline && build/test-adreno-ib-pipeline
 * Run from the model tree's root (agents/gpu-pipeline/tests/setup-model-tree.sh). SNAP_PIPE_JSON, when set, receives
 * the throughput rows (pipelined and synchronous) as JSON. No hardware client. */
#define ADRENO_RING_NO_MAIN 1
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunused-function"   /* S2 needs the draw-plan fixture: not run here */
#include "test-adreno-ring.c"
#pragma clang diagnostic pop
#include "adreno-ib-pipeline.h"
#include "../gpu/adreno-kext/kext/src/AdrenoDisplaySync.h"
#if !SNAP_ADRENO_IB_ASYNC || !ADRENO_PIPELINE
#error "build with -DSNAP_ADRENO_IB_ASYNC=1 -DADRENO_PIPELINE=1"
#endif

/* --- the monitor: probes/xnuboot.c's dispatch for HVC #0xad16 (as tools/test-adreno-ib-async.c) ------------------ */
static int monitor_async = 1;
static unsigned hvcs, starts_sent, polls_sent, busy_refused, params_refused, fences_rung, fills_rung;
static void start_hook(const uint64_t x[4]);
static void monitor_hvc(void *ctx, uint64_t x[4])
{
    (void)ctx;
    const uint64_t request = x[0];
    hvcs++;
    if (monitor_async && request == ADRENO_GUEST_IB_POLL) {
        polls_sent++;
        adreno_guest_ib_poll(&ring_ops, &P, &S, &F, x);
        return;
    }
    if (request == ADRENO_GUEST_IB_START) { starts_sent++; start_hook(x); }
    int e = monitor_async ? adreno_ib_flight_refuse(&S, &F, x) : 0;
    if (e == ADRENO_IB_E_BUSY) busy_refused++;
    if (e == ADRENO_E_PARAMS) params_refused++;
    if (!e) switch (request) {
    case ADRENO_GUEST_FILL32: fills_rung++; adreno_guest_fill32(&ring_ops, &P, &S, x, dart_leaf, 0, MEM_LOW, MEM_HIGH); break;
    case ADRENO_GUEST_IB: adreno_guest_ib(&ring_ops, &P, &S, x, dart_leaf, 0, MEM_LOW, MEM_HIGH); break;
    default:
        if (monitor_async && request == ADRENO_GUEST_IB_START)
            adreno_guest_ib_start(&ring_ops, &P, &S, &F, x, dart_leaf, 0, MEM_LOW, MEM_HIGH);
        else { fences_rung++; adreno_guest_fence(&ring_ops, &P, &S, x, dart_leaf, 0, MEM_LOW, MEM_HIGH); }
    }
}

/* --- the kext: two package slots in the doubled arena (CPU view: host memory; GPU view: read-only guest pages) -- */
#define SLOT_VA(s) (0x40800000ull + (uint64_t)(s) * ADRENO_PIPE_SLOT_BYTES)
#define SLOT_PA(s) (GUEST_PAGE + 0x300000ull + (uint64_t)(s) * 0x8000ull)   /* zero page, then the package page */
static struct adreno_ib_tables tables;
static struct adreno_ib_work slotw[2];
static uint8_t *slot_arena[2];
static struct adreno_ib_reloc slot_relocs[2][8];
static uint16_t slot_order[2][8];
static uint8_t slot_used[2][8];
static uint64_t slot_targets[2][ADRENO_IB_TARGET_WORDS];
static struct adreno_pipe pipe;
static uint32_t REG;                                  /* an allowlisted, non-address register the IBs write */
static uint64_t probe_ticks;

/* The kext's stores sit in its cacheable view until the monitor cleans the package (START): copy the staged bytes
 * into guest RAM through the CPU cache model, dirty. Record what the CP will run. */
static uint64_t started_at[4096], due_at[4096], start_sum[4096];
static unsigned start_slot[4096], nstarts, start_order_errors;
static uint32_t prev_value;
static uint64_t gpu_latency;                          /* the next IB's GPU time */
static uint32_t int0_next, fault_next, halt_next;
static uint64_t package_sum(unsigned s, uint64_t bytes)
{
    uint64_t h = 1469598103934665603ull;
    for (uint64_t i = 0; i < bytes; i++) h = (h ^ slot_arena[s][ADRENO_IB_PACKAGE_AT + i]) * 1099511628211ull;
    return h;
}
static void start_hook(const uint64_t x[4])
{
    const unsigned s = x[1] == SLOT_VA(1) + ADRENO_IB_PACKAGE_AT;
    CHECK(x[1] == SLOT_VA(s) + ADRENO_IB_PACKAGE_AT);
    for (uint64_t off = 0; off < x[3]; off += 4) {
        uint32_t v; memcpy(&v, slot_arena[s] + ADRENO_IB_PACKAGE_AT + off, 4);
        m_wr(0, SLOT_PA(s) + 0x4000 + off, v);
    }
    /* Q1: the previous IB ran to its end before this doorbell (it wrote REG last), unless it failed */
    if (nstarts && prev_value && cp.reg[REG] != prev_value && !r.fsr && !cp.halt && !cp.int0) start_order_errors++;
    uint32_t value; memcpy(&value, slot_arena[s] + ADRENO_IB_PACKAGE_AT + 4, 4);
    prev_value = value;
    cp.latency = gpu_latency;
    cp.int0_in_ib = int0_next; cp.fault_in_ib = fault_next; cp.halt = halt_next;
    if (nstarts < 4096) {
        started_at[nstarts] = clock_now; due_at[nstarts] = clock_now + gpu_latency;
        start_sum[nstarts] = package_sum(s, x[3]); start_slot[nstarts] = s;
    }
    nstarts++;
}

/* --- resource lists: recorded fixtures (the kext's AdrenoSegmentList callbacks) --------------------------------- */
static uint64_t to_cost;                              /* extra model time per TO_DEVICE entry (agents/present-pacing EP3) */
#define LMAXE 4
struct fx_list {
    struct adreno_resource_list list;
    struct adreno_resource_entry e[LMAXE];
    unsigned id, to_n, from_n, completed, released, validated;
    uint64_t last_to, first_from, last_from;
};
static struct fx_list *fx_of(void *preparation) { return *(struct fx_list **)preparation; }
static void *fx_retain(void *c, uint32_t id) { (void)c; (void)id; return 0; }
static void fx_release(void *c, void *r) { (void)c; (void)r; }
static int fx_prepare(void *c, void *r, void **t) { (void)c; *t = r; return 0; }
static void fx_complete(void *c, void *t) { (void)c; fx_of(t)->completed++; }
static int fx_sync(void *c, void *t, unsigned direction)
{
    (void)c;
    struct fx_list *l = fx_of(t);
    if (direction == ADRENO_CACHE_TO_DEVICE) { l->to_n++; l->last_to = clock_now; clock_now += to_cost; }
    if (direction == ADRENO_CACHE_FROM_DEVICE) { if (!l->from_n) l->first_from = clock_now; l->from_n++; l->last_from = clock_now; }
    if (direction == 0) l->validated++;
    clock_now += 2;                                   /* maintenance takes time */
    return 0;
}
static const struct adreno_resource_list_ops fx_ops = {0, fx_retain, fx_release, fx_prepare, fx_complete, fx_sync};
static int fx_resolve(void *c, void *r, void *t, uint64_t o, uint64_t b, uint64_t *a) { (void)c; (void)r; (void)t; (void)o; (void)b; *a = 0; return -1; }
static struct fx_list *fx_new(unsigned id)
{
    struct fx_list *l = calloc(1, sizeof *l);
    l->id = id;
    for (unsigned i = 0; i < LMAXE; i++) {
        /* resource and preparation both point at a cell holding the list: fx_of() finds it from either */
        struct fx_list **cell = malloc(sizeof *cell); *cell = l;
        l->e[i] = (struct adreno_resource_entry){100 + i, (uint16_t)(i ? ADRENO_USAGE_WRITE | ADRENO_USAGE_READ : ADRENO_USAGE_READ), 0, cell, cell};
    }
    l->list.entries = l->e; l->list.count = LMAXE; l->list.prepared_count = LMAXE;
    l->list.ready = ADRENO_LIST_READY | ADRENO_LIST_PREPARED;
    return l;
}
static void fx_free(struct fx_list *l)
{
    adreno_resource_list_complete(&l->list, &fx_ops);
    for (unsigned i = 0; i < LMAXE; i++) free(l->e[i].resource);
    free(l);
}

/* --- the IB command: one PKT4 of REG = value (validated like any draw package) ----------------------------------- */
static uint8_t command[256];
static uint64_t make_command(uint32_t value)
{
    struct adreno_ib_command c;
    memset(&c, 0, sizeof c);
    c.header.type = ADRENO_KCMD_IB; c.version = ADRENO_IB_COMMAND_VERSION; c.ib_dwords = 2;
    c.header.size = (uint32_t)adreno_ib_command_bytes(2, 0, 0);
    memset(command, 0, sizeof command);
    memcpy(command, &c, sizeof c);
    const uint32_t w[2] = {a8xx_pkt4_hdr(REG, 1), value};
    memcpy(command + sizeof c, w, sizeof w);
    return c.header.size;
}

/* --- IOGPU and the kext glue: stamps, command buffers, marks, the lock ------------------------------------------- */
static uint32_t stamp_word, stamp_counter;            /* the stamp page's word; getCurrentStamp */
struct cb {                                           /* one command buffer's kernel-side record (the flight's owner) */
    unsigned k;                                       /* its IB's value */
    struct fx_list *l;
    uint32_t value;                                   /* its completion event's stamp (0: none) */
    uint32_t surface;                                 /* the IOSurface it writes (present-sync) */
    int result, retired, released, start_index;
    uint64_t retired_at;
    int early_unmarked; uint64_t unmarked_at;         /* agents/present-pacing EP1: released at the finish */
};
static int locked;                                    /* fSubmitLock */
static struct adreno_sync_table marks;
static struct cb *post[8];                            /* retired under the lock; signalled and released after it */
static unsigned npost, order_errors, stamp_regressions, sum_mismatch, lock_violations;
static uint32_t last_retired_k;
static uint64_t kext_us(void *c) { (void)c; return clock_now; }
static void kext_delay(void *c, uint32_t us) { (void)c; clock_now += us; }
static uint32_t kext_stamp(void *c, void *owner)
{
    (void)c;
    CHECK(locked);
    struct cb *cb = owner;
    stamp_counter += 0x100;                           /* incrementStamp, then setEventStamp into the queue event */
    cb->value = stamp_counter;
    return stamp_counter;
}
#if ADRENO_PRESENT_RELATCH
static struct adreno_pipe_early early_cfg;            /* agents/present-pacing: AdrenoX2's gAdrenoPipeEarly */
#endif
static void kext_retired(void *c, void *owner, int result, const struct adreno_ib_reply *final, uint32_t stamp)
{
    (void)c; (void)final;
    if (!locked) lock_violations++;
    struct cb *cb = owner;
    CHECK(stamp == cb->value);
    /* C1 R1: the CP ran it, and FROM_DEVICE is done, before its stamp is written (retired or GPU_ERROR: the list's
     * FROM_DEVICE runs; UNCERTAIN: it must not) */
    if (result == 0 || result == ADRENO_IB_E_GPU_ERROR)
        CHECK(clock_now >= due_at[cb->start_index] && cb->l->from_n > 0 && cb->l->last_from >= due_at[cb->start_index]);
    if (!result && cb->k <= last_retired_k && last_retired_k) order_errors++;   /* Q1: retired in submission order */
    if (!result) last_retired_k = cb->k;
    /* Q2: the slot it ran from was not restaged while it flew */
    const unsigned slot = start_slot[cb->start_index];
    if (package_sum(slot, slotw[slot].package_bytes) != start_sum[cb->start_index]) sum_mismatch++;
    if ((int32_t)(stamp - stamp_word) <= 0) stamp_regressions++;
    stamp_word = stamp;                               /* written under the lock, in retirement order (C3) */
    cb->result = result; cb->retired = 1; cb->retired_at = clock_now;
#if ADRENO_PRESENT_RELATCH
    if (early_cfg.on && cb->surface) {                /* EP1: under the lock, after this flight's FROM_DEVICE */
        adreno_sync_unmark(&marks, cb->surface);
        cb->early_unmarked = 1; cb->unmarked_at = clock_now; early_cfg.unmarks++;
    }
#endif
    post[npost++] = cb;
}
static const struct adreno_pipe_ops kext = {0, monitor_hvc, kext_delay, kext_us, kext_stamp, kext_retired};
static void post_work(void)                           /* after the unlock: unmark, signal IOGPU, release the list */
{
    CHECK(!locked);
    for (unsigned i = 0; i < npost; i++) {
        struct cb *cb = post[i];
        if (cb->surface && !cb->early_unmarked) { adreno_sync_unmark(&marks, cb->surface); cb->unmarked_at = clock_now; }
        cb->released = 1;
    }
    npost = 0;
}
static int cb_complete(const struct cb *cb) { return !cb->value || (int32_t)(cb->value - stamp_word) <= 0; }  /* testEvent */

/* submitIB: marks before the lock, the engine under it, the post work after it. */
static int kext_ib(struct cb *cb, int pipelined, int *in_flight)
{
    if (cb->surface) adreno_sync_mark(&marks, cb->surface, clock_now);
    const uint64_t bytes = make_command(cb->k);
    locked = 1;
#if ADRENO_PRESENT_RELATCH
    if (early_cfg.on && pipe.flight.active && adreno_pipe_try_finish(&pipe, &kext)) early_cfg.pre++;   /* EP2 */
    cb->start_index = (int)nstarts;
    int e = adreno_pipe_submit(&pipe, &kext, &cb->l->list, &fx_ops, command, bytes, fx_resolve, 0, cb, pipelined, in_flight,
                               &early_cfg);
#else
    cb->start_index = (int)nstarts;
    int e = adreno_pipe_submit(&pipe, &kext, &cb->l->list, &fx_ops, command, bytes, fx_resolve, 0, cb, pipelined, in_flight);
#endif
    locked = 0;
    post_work();
    if (!*in_flight && cb->surface) adreno_sync_unmark(&marks, cb->surface);   /* the RAII path: not handed over */
    if (!*in_flight) { cb->retired = 1; cb->result = e; }
    return e;
}
/* submitFence: folds into a flight; otherwise rings the fence (FENCE_VA's probe slot). */
static int kext_fence(struct cb *cb)
{
    locked = 1;
    int e;
    if (adreno_pipe_fold(&pipe)) e = adreno_resource_list_validate(&cb->l->list, &fx_ops);
    else {
        m_wr(0, FENCE_PA + 0x200, ~0x534e5001u);
        uint64_t x[4] = {ADRENO_GUEST_FENCE, FENCE_VA + 0x200, 0x534e5001u, 0};
        cp.latency = 20;                              /* a CP_MEM_WRITE: microseconds (the model times every doorbell) */
        monitor_hvc(0, x);
        e = adreno_fence_classify((int64_t)x[0], x[1], 0x534e5001u, m_rd(0, FENCE_PA + 0x200));
    }
    locked = 0;
    post_work();
    return e;
}
/* submitFill: the flight first, then the synchronous FILL32. */
static int kext_fill(uint32_t pattern)
{
    locked = 1;
    adreno_pipe_complete(&pipe, &kext);
    pipe.stats.drains++;
    uint64_t x[4] = {ADRENO_GUEST_FILL32, FILL_A_VA, 0x40, pattern};
    cp.latency = 20;
    monitor_hvc(0, x);
    locked = 0;
    post_work();
    return (int)(int64_t)x[0];
}
/* the completion timer: one POLL */
static int kext_timer(void)
{
    locked = 1;
    const int active = adreno_pipe_poll(&pipe, &kext);
    locked = 0;
    post_work();
    return active;
}

static void world(uint64_t latency)
{
    s3_setup(22, latency);
    for (unsigned s = 0; s < 2; s++) map(SLOT_VA(s), SLOT_PA(s), 0x8000, 1);
    for (unsigned s = 0; s < 2; s++) {
        memset(slot_arena[s], 0, ADRENO_PIPE_SLOT_BYTES);
        CHECK(adreno_ib_work_init(&slotw[s], &tables, slot_arena[s], SLOT_VA(s), ADRENO_PIPE_SLOT_BYTES, slot_relocs[s], slot_order[s],
                                  slot_used[s], 8, slot_targets[s]) == 0);
    }
    adreno_pipe_init(&pipe, &slotw[0], &slotw[1]);
    memset(&marks, 0, sizeof marks);
    nstarts = 0; gpu_latency = latency; int0_next = fault_next = halt_next = 0;
    hvcs = starts_sent = polls_sent = busy_refused = params_refused = fences_rung = fills_rung = 0;
    stamp_word = stamp_counter = 0; npost = 0; order_errors = stamp_regressions = sum_mismatch = lock_violations = 0;
    last_retired_k = 0; locked = 0; start_order_errors = 0; prev_value = 0;
    const struct adreno_ib_async_ops probe = {0, monitor_hvc, kext_delay};
    CHECK(adreno_ib_async_probe(&probe) == 1);         /* O1: the kext pipelines only on a monitor with IB_POLL */
    (void)probe_ticks;
}

/* Q1 Q3 C1 C3 R1 R2 D1, and the throughput: WindowServer's frames, CPU then GPU, pipelined against synchronous. */
struct run { uint64_t frames, span_us, gap_us, gap_max_us, flights, overlapped, folded, spin_us, idle_us, idle_max_us; double fps; };
static struct run frames_run(unsigned n, uint64_t cpu_us, uint64_t gpu_us, int pipelined, unsigned jitter_pct)
{
    world(gpu_us);
    struct cb *cbs = calloc(n, sizeof *cbs);
    uint64_t rng = 0x9e3779b97f4a7c15ull, first_swap = 0, last_swap = 0;
    unsigned fence_errors = 0, unfinished_swaps = 0, marked_during = 0;
    for (unsigned i = 0; i < n; i++) {
        /* WindowServer's CPU part of frame i; the kext's completion timer polls every 500 us meanwhile */
        const uint64_t until = clock_now + cpu_us;
        while (clock_now + 500 <= until) { clock_now += 500; if (pipe.flight.active) kext_timer(); }
        clock_now = until;
        rng = rng * 6364136223846793005ull + 1442695040888963407ull;
        gpu_latency = gpu_us - gpu_us * jitter_pct / 200 + (jitter_pct ? (rng >> 33) % (gpu_us * jitter_pct / 100 + 1) : 0);
        struct cb *cb = &cbs[i];
        cb->k = i + 1; cb->l = fx_new(i + 1); cb->surface = 7;   /* every frame writes layer 0's surface */
        int in_flight = 0;
        const int e = kext_ib(cb, pipelined, &in_flight);
        CHECK(e == 0);
        CHECK(in_flight == pipelined);
        if (kext_fence(cb)) fence_errors++;           /* Q3: the command buffer's FENCE */
        /* the syscall returned: commitAndWaitUntilSubmitted returns, WindowServer swaps. D1: its surface is marked
         * until the IB retired (or it already has). */
        uint64_t oldest = 0;
        const uint32_t writers = adreno_sync_query(&marks, 7, &oldest);
        if (!cb->retired && !writers) unfinished_swaps++;
        if (writers) marked_during++;
        if (!first_swap) first_swap = clock_now;
        last_swap = clock_now;
        /* C1: IOGPU completion only after retirement */
        CHECK(cb_complete(cb) == cb->retired);
    }
    /* the tail: no successor, the timer finishes the last flight (C5) */
    unsigned timer_ticks = 0;
    while (kext_timer()) { clock_now += 500; timer_ticks++; if (timer_ticks > 100000) break; }
    const uint64_t end = clock_now;
    unsigned all_retired = 1, completes_ok = 1, released = 1;
    for (unsigned i = 0; i < n; i++) {
        all_retired &= cbs[i].retired && cbs[i].result == 0;
        completes_ok &= cb_complete(&cbs[i]);
        if (pipelined) released &= cbs[i].released;
        /* R1: TO_DEVICE before its START, FROM_DEVICE after the CP ran it; R2: the list completes after that */
        CHECK(cbs[i].l->to_n == LMAXE && cbs[i].l->last_to <= started_at[i]);
        CHECK(cbs[i].l->from_n == LMAXE - 1 && cbs[i].l->first_from >= due_at[i]);
        CHECK(cbs[i].l->completed == 0);
        fx_free(cbs[i].l);
    }
    uint64_t oldest = 0;
    CHECK(all_retired && completes_ok && released && adreno_sync_query(&marks, 7, &oldest) == 0 && marks.unmatched == 0);
    CHECK(order_errors == 0 && start_order_errors == 0 && stamp_regressions == 0 && sum_mismatch == 0 && lock_violations == 0);
    CHECK(busy_refused == 0 && params_refused == 0 && fence_errors == 0 && unfinished_swaps == 0);
    CHECK(nstarts == n && F.flights == (pipelined ? n : F.flights));
    if (pipelined) CHECK(pipe.stats.folded >= n - 1 && fences_rung <= 1 && marked_during == n);
    /* the GPU's idle time between one IB's end (due) and the next doorbell, when the next was already waiting */
    uint64_t idle = 0, idle_max = 0, idle_n = 0;
    for (unsigned i = 0; i + 1 < n && i + 1 < 4096; i++) {
        if (started_at[i + 1] <= due_at[i]) continue;
        const uint64_t d = started_at[i + 1] - due_at[i];
        if (d > cpu_us) continue;                     /* the GPU waited for the CPU: not a pipeline gap */
        idle += d; idle_n++; if (d > idle_max) idle_max = d;
    }
    struct run r = {n, last_swap - first_swap, pipe.stats.gap_n ? pipe.stats.gap_us / pipe.stats.gap_n : 0,
                    pipe.stats.gap_max_us, pipe.stats.flights, pipe.stats.overlapped, pipe.stats.folded, pipe.stats.spin_us,
                    idle_n ? idle / idle_n : 0, idle_max, 0};
    r.fps = r.span_us ? (double)(n - 1) * 1e6 / (double)r.span_us : 0;
    printf("PIPE_FRAMES %s cpu=%llu gpu=%llu jitter=%u%%: %u frames, %.1f per second (swap to swap), GPU idle between "
           "IBs mean %llu us max %llu us, flights %llu overlapped %llu folded %llu spin %llu us, tail %u timer ticks, "
           "end %llu us\n",
           pipelined ? "pipelined" : "synchronous", (unsigned long long)cpu_us, (unsigned long long)gpu_us, jitter_pct, n,
           r.fps, (unsigned long long)r.idle_us, (unsigned long long)r.idle_max_us, (unsigned long long)r.flights,
           (unsigned long long)r.overlapped, (unsigned long long)r.folded, (unsigned long long)r.spin_us, timer_ticks,
           (unsigned long long)end);
    free(cbs);
    return r;
}

/* R4 Q1: a synchronous client's IB while WindowServer's flight runs: the flight retires first, the client's IB
 * retires before its submission returns. Q4: a FILL32 during a flight. Q5: three IBs of one command buffer. */
static void test_mixed(void)
{
    world(3000);
    struct cb ws = {.k = 1, .l = fx_new(1), .surface = 7}, app = {.k = 2, .l = fx_new(2)}, ws2 = {.k = 3, .l = fx_new(3), .surface = 7};
    int fl = 0;
    CHECK(kext_ib(&ws, 1, &fl) == 0 && fl == 1);
    clock_now += 500;
    CHECK(kext_ib(&app, 0, &fl) == 0 && fl == 0);
    CHECK(ws.retired && ws.result == 0 && app.retired && cp.reg[REG] == 2 && ws.retired_at <= clock_now);
    CHECK(app.l->first_from >= due_at[1] && ws.l->first_from >= due_at[0] && busy_refused == 0);
    CHECK(pipe.stats.sync_ibs == 1 && !pipe.flight.active);
    CHECK(kext_ib(&ws2, 1, &fl) == 0 && fl == 1);
    const unsigned fills = fills_rung;
    CHECK(kext_fill(0x11223344) == 0);                /* Q4 */
    CHECK(ws2.retired && fills_rung == fills + 1 && params_refused == 0 && dev_rd32(FILL_A_PA) == 0x11223344);
    /* Q5: one list, three IBs */
    struct cb a = {.k = 10, .l = fx_new(10)};
    struct cb b = {.k = 11, .l = a.l}, c = {.k = 12, .l = a.l};
    CHECK(kext_ib(&a, 1, &fl) == 0 && fl && kext_ib(&b, 1, &fl) == 0 && fl && kext_ib(&c, 1, &fl) == 0 && fl);
    CHECK(a.retired && b.retired && !c.retired && a.l->from_n == 2 * (LMAXE - 1));
    while (kext_timer()) clock_now += 500;
    CHECK(c.retired && a.l->from_n == 3 * (LMAXE - 1) && a.l->to_n == 3 * LMAXE && a.l->completed == 0);
    CHECK(order_errors == 0 && busy_refused == 0 && stamp_regressions == 0 && last_retired_k == 12);
    uint64_t oldest;
    CHECK(adreno_sync_query(&marks, 7, &oldest) == 0 && marks.unmatched == 0);
    fx_free(ws.l); fx_free(app.l); fx_free(ws2.l); fx_free(a.l);
    printf("PIPE_MIXED ok: synchronous client behind a flight, FILL32 during a flight, three IBs of one list\n");
}

/* C4: failures after the submission returned, and the next submission refused (fail-fast as today). */
static void test_async_failures(void)
{
    const struct { const char *name; uint32_t int0, fault, halt; int want; } k[] = {
        {"gpu_error", 1u << 24, 0, 0, ADRENO_IB_E_GPU_ERROR},
        {"fault", 0, 1, 0, ADRENO_SUBMIT_E_UNCERTAIN},
        {"budget", 0, 0, 1, ADRENO_SUBMIT_E_UNCERTAIN}};
    for (unsigned i = 0; i < 3; i++) {
        world(900);
        struct cb x = {.k = 1, .l = fx_new(1), .surface = 7}, y = {.k = 2, .l = fx_new(2), .surface = 7};
        int fl = 0;
        int0_next = k[i].int0; fault_next = k[i].fault; halt_next = k[i].halt;
        CHECK(kext_ib(&x, 1, &fl) == 0 && fl == 1);
        int0_next = fault_next = halt_next = 0;
        unsigned ticks = 0;
        while (kext_timer()) { clock_now += 500; if (++ticks > 20000) break; }
        CHECK(x.retired && x.result == k[i].want && cb_complete(&x));        /* the stamp is written all the same */
        CHECK((slotw[0].state & slotw[1].state & (ADRENO_IB_STATE_DISABLED | ADRENO_IB_STATE_UNCERTAIN)) != 0);
        if (k[i].want == ADRENO_SUBMIT_E_UNCERTAIN) CHECK(x.l->list.ready & ADRENO_LIST_FROZEN);
        cp.halt = 0; cp.int0 = 0; cp.cp_global = 0; r.fsr = 0;
        const unsigned starts = starts_sent;
        CHECK(kext_ib(&y, 1, &fl) == ADRENO_SUBMIT_E_INACTIVE && fl == 0 && starts_sent == starts);
        uint64_t oldest;
        CHECK(adreno_sync_query(&marks, 7, &oldest) == 0 && marks.unmatched == 0);
        printf("PIPE_FAILURE %s: finished %d after %u timer ticks, stamp written, next IB refused before any ring write\n",
               k[i].name, x.result, ticks);
        if (!(x.l->list.ready & ADRENO_LIST_FROZEN)) fx_free(x.l);
        fx_free(y.l);
    }
}

/* C5 (A10): a monitor that answers PENDING forever: the kext's own bound ends the flight as UNCERTAIN at 4 s. */
static unsigned scripted;
static void forever_hvc(void *c, uint64_t x[4])
{
    (void)c;
    scripted++;
    if (x[0] == ADRENO_GUEST_IB_START) { x[0] = (uint64_t)(int64_t)ADRENO_IB_PENDING; x[1] = ADRENO_IB_MARKER_BASE ^ 9u; x[2] = 1; x[3] = 50; return; }
    x[0] = (uint64_t)(int64_t)ADRENO_IB_PENDING; x[1] = ADRENO_IB_MARKER_BASE ^ 9u; x[2] = 2; x[3] = 50;
}
static void test_pending_forever(void)
{
    world(0);
    const struct adreno_pipe_ops forever = {0, forever_hvc, kext_delay, kext_us, kext_stamp, kext_retired};
    struct cb x = {.k = 1, .l = fx_new(1), .surface = 7};
    adreno_sync_mark(&marks, 7, clock_now);
    int fl = 0;
    locked = 1;
    nstarts = 1; due_at[0] = 0; started_at[0] = clock_now;
    const uint64_t t0 = clock_now;
#if ADRENO_PRESENT_RELATCH
    CHECK(adreno_pipe_submit(&pipe, &forever, &x.l->list, &fx_ops, command, make_command(1), fx_resolve, 0, &x, 1, &fl, 0) == 0 && fl);
#else
    CHECK(adreno_pipe_submit(&pipe, &forever, &x.l->list, &fx_ops, command, make_command(1), fx_resolve, 0, &x, 1, &fl) == 0 && fl);
#endif
    locked = 0;
    unsigned ticks = 0;
    for (;;) {
        locked = 1;
        const int active = adreno_pipe_poll(&pipe, &forever);
        locked = 0;
        post_work();
        if (!active) break;
        clock_now += 500;
        if (++ticks > 20000) break;
    }
    CHECK(x.retired && x.result == ADRENO_SUBMIT_E_UNCERTAIN && clock_now - t0 >= ADRENO_IB_ASYNC_LIMIT_US &&
          clock_now - t0 < ADRENO_IB_ASYNC_LIMIT_US + 1000 && cb_complete(&x));
    printf("PIPE_PENDING_FOREVER UNCERTAIN after %llu us (%u timer ticks), stamp written\n",
           (unsigned long long)(clock_now - t0), ticks);
}

/* C3: 4,096 IBs: stamps strictly increase, the word is always the newest retired value. */
static void test_stamps(void)
{
    enum { N = 4096 };
    world(400);
    struct cb *cbs = calloc(N, sizeof *cbs);
    unsigned bad = 0;
    for (unsigned i = 0; i < N; i++) {
        cbs[i].k = i + 1; cbs[i].l = fx_new(i + 1);
        int fl = 0;
        if (kext_ib(&cbs[i], 1, &fl) || !fl) bad++;
        clock_now += 100;
    }
    while (kext_timer()) clock_now += 500;
    unsigned complete = 0;
    for (unsigned i = 0; i < N; i++) { complete += cb_complete(&cbs[i]) && cbs[i].retired; fx_free(cbs[i].l); }
    CHECK(bad == 0 && complete == N && stamp_regressions == 0 && stamp_word == stamp_counter &&
          stamp_counter == N * 0x100u && order_errors == 0 && sum_mismatch == 0 && busy_refused == 0);
    printf("PIPE_STAMPS %u IBs: every one in flight, stamps strictly increase, last %#x, all command buffers complete\n",
           N, stamp_word);
    free(cbs);
}

#if ADRENO_PRESENT_RELATCH
/* agents/present-pacing EP1-EP3: the early release against the monitor model. */
static void test_early(void)
{
    int fl = 0;
    /* EP3: a flight that completes during the next submission's long TO_DEVICE is finished there, before that START;
     * its marks go at its FROM_DEVICE (EP1); order, slots and the stamps as always */
    world(300);
    memset(&early_cfg, 0, sizeof early_cfg); early_cfg.on = 1; early_cfg.assist_us = 50;
    to_cost = 150;                                    /* 4 entries: 600 us of TO_DEVICE, the flight runs 300 us */
    struct cb a = {.k = 1, .l = fx_new(1), .surface = 7}, b = {.k = 2, .l = fx_new(2), .surface = 8};
    CHECK(kext_ib(&a, 1, &fl) == 0 && fl == 1);
    const unsigned bi = nstarts;
    CHECK(kext_ib(&b, 1, &fl) == 0 && fl == 1);
    CHECK(a.retired && a.result == 0 && a.early_unmarked && early_cfg.assisted == 1 && early_cfg.pre == 0);
    CHECK(a.unmarked_at < started_at[bi] && a.unmarked_at >= due_at[bi - 1]);
    CHECK(pipe.stats.overlapped == 0);               /* nothing left to wait for after the TO_DEVICE */
    uint64_t oldest;
    CHECK(adreno_sync_query(&marks, 7, &oldest) == 0 && adreno_sync_query(&marks, 8, &oldest) == 1);
    while (kext_timer()) clock_now += 500;
    CHECK(b.retired && b.result == 0 && adreno_sync_query(&marks, 8, &oldest) == 0 && marks.unmatched == 0);
    CHECK(order_errors == 0 && sum_mismatch == 0 && start_order_errors == 0 && busy_refused == 0 && stamp_regressions == 0);
    const uint64_t assist_gain = started_at[bi] - a.unmarked_at, early_wait = a.unmarked_at - due_at[bi - 1];
    /* EP2: a flight already final when the next submission takes the lock is finished before its TO_DEVICE */
    struct cb c = {.k = 3, .l = fx_new(3), .surface = 9}, d = {.k = 4, .l = fx_new(4), .surface = 10};
    CHECK(kext_ib(&c, 1, &fl) == 0 && fl == 1);
    clock_now += 1000;                                /* done on the GPU; the timer has not polled */
    const unsigned di = nstarts;
    CHECK(kext_ib(&d, 1, &fl) == 0 && fl == 1);
    CHECK(c.retired && early_cfg.pre == 1 && c.unmarked_at + LMAXE * to_cost <= started_at[di] && c.l->last_from < d.l->last_to);
    while (kext_timer()) clock_now += 500;
    /* today's order with the switch off: the same flight is finished after the next START (its marks at the post) */
    world(300);
    memset(&early_cfg, 0, sizeof early_cfg);
    struct cb e = {.k = 5, .l = fx_new(5), .surface = 11}, f = {.k = 6, .l = fx_new(6), .surface = 12};
    CHECK(kext_ib(&e, 1, &fl) == 0 && fl == 1);
    const unsigned fi = nstarts;
    CHECK(kext_ib(&f, 1, &fl) == 0 && fl == 1);
    CHECK(e.retired && !e.early_unmarked && e.unmarked_at > started_at[fi] && pipe.stats.overlapped == 1);
    const uint64_t today_wait = e.unmarked_at - due_at[fi - 1];
    while (kext_timer()) clock_now += 500;
    /* EP3 and C4: the assisted flight failed (GPU error): its state spreads, the new IB is refused after its begin */
    world(300);
    memset(&early_cfg, 0, sizeof early_cfg); early_cfg.on = 1; early_cfg.assist_us = 50;
    struct cb g = {.k = 7, .l = fx_new(7), .surface = 13}, h = {.k = 8, .l = fx_new(8), .surface = 14};
    int0_next = 1u << 24;
    CHECK(kext_ib(&g, 1, &fl) == 0 && fl == 1);
    int0_next = 0;
    const unsigned starts = starts_sent;
    CHECK(kext_ib(&h, 1, &fl) == ADRENO_SUBMIT_E_INACTIVE && fl == 0 && starts_sent == starts);
    CHECK(g.retired && g.result == ADRENO_IB_E_GPU_ERROR && early_cfg.assisted == 1 &&
          (slotw[0].state & slotw[1].state & ADRENO_IB_STATE_DISABLED));
    CHECK(adreno_sync_query(&marks, 13, &oldest) == 0 && adreno_sync_query(&marks, 14, &oldest) == 0 && marks.unmatched == 0);
    cp.halt = 0; cp.int0 = 0; cp.cp_global = 0; r.fsr = 0;
    to_cost = 0; memset(&early_cfg, 0, sizeof early_cfg);
    printf("PIPE_EARLY ok: assisted finish %llu us before the next START (marks released %llu us after the GPU end, "
           "today %llu us), a final flight finished before TO_DEVICE, a failed assisted flight refuses the next IB\n",
           (unsigned long long)assist_gain, (unsigned long long)early_wait, (unsigned long long)today_wait);
    fx_free(a.l); fx_free(b.l); fx_free(c.l); fx_free(d.l); fx_free(e.l); fx_free(f.l); fx_free(h.l);
}
#endif

static void json_row(FILE *j, const char *name, const struct run *r, int first)
{
    fprintf(j, "%s\"%s\":{\"frames\":%llu,\"fps\":%.2f,\"span_us\":%llu,\"gpu_idle_mean_us\":%llu,"
            "\"gpu_idle_max_us\":%llu,\"flights\":%llu,\"overlapped\":%llu,\"folded\":%llu,\"spin_us\":%llu}",
            first ? "" : ",", name, (unsigned long long)r->frames, r->fps, (unsigned long long)r->span_us,
            (unsigned long long)r->idle_us, (unsigned long long)r->idle_max_us, (unsigned long long)r->flights,
            (unsigned long long)r->overlapped, (unsigned long long)r->folded, (unsigned long long)r->spin_us);
}

int main(void)
{
    dram = calloc(1, RAM_SIZE);
    cache = calloc(1, RAM_SIZE);
    for (unsigned s = 0; s < 2; s++) if (posix_memalign((void **)&slot_arena[s], 64, ADRENO_PIPE_SLOT_BYTES)) return 2;
    if (!dram || !cache) return 2;
    CHECK(adreno_ib_tables_init(&tables) == 0);
    for (uint32_t off = 0x800; off < ADRENO_IB_REG_LIMIT && !REG; off++)
        if ((tables.allowed[off / 64] >> (off % 64) & 1) && !(tables.address[off / 64] >> (off % 64) & 1)) REG = off;
    CHECK(REG != 0);
    printf("PIPE register %#x\n", REG);
    /* the b12v12 shape: 13.4 ms GPU, 5 ms CPU per frame (model ticks are microseconds) */
    const struct run sync = frames_run(300, 5000, 13400, 0, 0);
    const struct run pipe1 = frames_run(300, 5000, 13400, 1, 0);
    const struct run pipej = frames_run(300, 5000, 13400, 1, 40);
    const struct run cpub = frames_run(300, 16000, 13400, 1, 0);       /* CPU-bound: 16 ms CPU */
    const double ideal = 1e6 / 13400.0, serial = 1e6 / (13400.0 + 5000.0), ideal_cpu = 1e6 / 16000.0;
    CHECK(sync.fps < serial * 1.01);
    CHECK(pipe1.fps > ideal * 0.97 && pipe1.fps <= ideal * 1.001);  /* overlap: within 3% of 1000/max(gpu, cpu) */
    CHECK(pipej.fps > ideal * 0.95);
    CHECK(cpub.fps > ideal_cpu * 0.97 && cpub.overlapped < cpub.flights / 10);   /* nothing to wait for */
    printf("PIPE_THROUGHPUT b12v12 shape: synchronous %.1f/s (serial bound %.1f), pipelined %.1f/s (bound %.1f), "
           "jittered %.1f/s; CPU-bound %.1f/s (bound %.1f)\n", sync.fps, serial, pipe1.fps, ideal, pipej.fps, cpub.fps,
           ideal_cpu);
    test_mixed();
    test_async_failures();
    test_pending_forever();
    test_stamps();
#if ADRENO_PRESENT_RELATCH
    test_early();
#endif
    const char *jp = getenv("SNAP_PIPE_JSON");
    if (jp) {
        FILE *j = fopen(jp, "w");
        if (j) {
            fprintf(j, "{\"model_us_per_tick\":1,\"rows\":{");
            json_row(j, "sync_cpu5_gpu13.4", &sync, 1);
            json_row(j, "pipelined_cpu5_gpu13.4", &pipe1, 0);
            json_row(j, "pipelined_cpu5_gpu13.4_jitter40", &pipej, 0);
            json_row(j, "pipelined_cpu16_gpu13.4", &cpub, 0);
            fprintf(j, "},\"checks\":%u,\"failures\":%u}\n", checks, failures);
            fclose(j);
        }
    }
    for (unsigned s = 0; s < 2; s++) free(slot_arena[s]);
    free(dram);
    free(cache);
    if (failures) { printf("FAIL: %u of %u pipeline checks\n", failures, checks); return 1; }
    printf("PASS: %u pipeline checks: order, one flight, folded fences, FROM_DEVICE after retirement, stamps after it, "
           "marks until it, mixed clients, FILL32, three IBs per list, asynchronous failures, PENDING forever, 4,096 stamps\n",
           checks);
    return 0;
}

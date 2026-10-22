/* SPDX-License-Identifier: MIT */
/* GPU hang recovery end to end (agents/gpu-recovery FAILURE-MODES.md, written before the code; the E-numbers below).
 * The kext's real submission code -- adreno_ib_submit (synchronous) or the pipeline engine (-DADRENO_PIPELINE=1:
 * adreno_ib_submit_begin/ring/finish, two package slots), the async loop (adreno-ib-async.h), the fail-fast gate
 * (adreno_submit_gated), and with -DADRENO_GPU_RECOVER=1 the un-latch and the IOGPU status words
 * (adreno-recover-guest.h), in AdrenoX2.cpp's order -- against the monitor's HVC dispatch with SNAP_ADRENO_RECOVER
 * (tools/test-adreno-recover.c: test-adreno-ring.c's CP plus the reset registers, a DMA engine that keeps writing while
 * an IB hangs, dirty cache lines). Resource lists are recorded fixtures with one written page each: after an IB's
 * list completes, the page is "handed back" (a CPU sentinel) and no GPU write may reach it again.
 * Variants (run them all): recovering kext + monitor (sync and pipeline); an older kext (-DADRENO_GPU_RECOVER=0) on a
 * recovering monitor; a recovering kext on an older monitor (-DSNAP_ADRENO_RECOVER=0).
 *
 *   clang -std=gnu11 -Icompat -Ishadow -O1 -g -fsanitize=address,undefined -Wall -Wextra -Werror \
 *     -DSNAP_ADRENO_IB_ASYNC=1 -DSNAP_ADRENO_RECOVER=2 -DADRENO_GPU_RECOVER=1 [-DADRENO_PIPELINE=1] \
 *     tools/test-adreno-recover-e2e.c compat/adreno-ib-command.c compat/adreno-ib.c compat/adreno-fill-command.c \
 *     compat/adreno-fill.c compat/adreno-submit.c compat/adreno-resource.c compat/adreno-resource-list.c compat/adreno.c \
 *     compat/irq-forward.c shadow/stage2.c shadow/shadow.c shadow/mmu.c -o build/test-adreno-recover-e2e \
 *     && build/test-adreno-recover-e2e
 * Run from the model tree's root (agents/gpu-recovery/tests/setup-model-tree.sh). No hardware client. */
#define ADRENO_RECOVER_NO_MAIN 1
#ifndef ADRENO_PIPELINE
#define ADRENO_PIPELINE 0
#endif
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunused-function"
#include "test-adreno-recover.c"
#pragma clang diagnostic pop
#pragma clang diagnostic ignored "-Wunused-function"   /* each variant uses its own subset of the helpers below */
#include "adreno-ib-command.h"
#include "adreno-ib-async.h"
#if ADRENO_PIPELINE
#include "adreno-ib-pipeline.h"
#endif
#if ADRENO_GPU_RECOVER
#include "adreno-recover-guest.h"
#endif

#define SLOT_BYTES ((uint64_t)ADRENO_IB_PACKAGE_AT + ADRENO_IB_MAX_PACKAGE)
#define SLOT_VA(s) (0x40800000ull + (uint64_t)(s) * SLOT_BYTES)
#define SLOT_PA(s) (GUEST_PAGE + 0x300000ull + (uint64_t)(s) * 0x8000ull)
#define LIST_PA(i) (GUEST_PAGE + 0x320000ull + (uint64_t)(i) * 0x4000ull)   /* each list's page the GPU writes */
#define SENTINEL 0x5e171e1du

/* --- the kext <-> monitor HVC ----------------------------------------------------------------------------------- */
static unsigned hvcs, settles_sent;
static int pending_forever;                           /* E6: a broken monitor that keeps answering PENDING */
static void start_hook(const uint64_t x[4]);
static void kext_hvc(void *ctx, uint64_t x[4])
{
    (void)ctx;
    hvcs++;
    const uint64_t request = x[0], marker = x[1];
    if (request == ADRENO_GUEST_IB_START) start_hook(x);
    if (request == ADRENO_GUEST_RECOVER && x[1] == 1) settles_sent++;
    mon_call(x);
    if (pending_forever && request == ADRENO_GUEST_IB_POLL && marker) { x[0] = (uint64_t)(int64_t)ADRENO_IB_PENDING; x[1] = marker; }
}
static void kext_delay(void *ctx, uint32_t us) { (void)ctx; clock_now += us; }

/* --- the kext's package slots: CPU view in host memory, GPU view read-only guest pages ---------------------------- */
static struct adreno_ib_tables tables;
static struct adreno_ib_work slotw[2];
static uint8_t *slot_arena[2];
static struct adreno_ib_reloc slot_relocs[2][8];
static uint16_t slot_order[2][8];
static uint8_t slot_used[2][8];
static uint64_t slot_targets[2][ADRENO_IB_TARGET_WORDS];
static uint32_t REG;
/* What the next START runs: model latency, a hang that writes `hang_page`, a CB0 fault. */
static uint64_t next_latency;
static int next_hang, next_fault;
static unsigned next_page;
static void start_hook(const uint64_t x[4])
{
    const unsigned s = x[1] == SLOT_VA(1) + ADRENO_IB_PACKAGE_AT;
    CHECK(x[1] == SLOT_VA(s) + ADRENO_IB_PACKAGE_AT);
    for (uint64_t off = 0; off < x[3]; off += 4) {      /* the kext's stores, dirty in its cacheable view */
        uint32_t v; memcpy(&v, slot_arena[s] + ADRENO_IB_PACKAGE_AT + off, 4);
        m_wr(0, SLOT_PA(s) + 0x4000 + off, v);
    }
    cp.latency = next_hang ? HUNG : next_latency;
    if (next_hang) {
        gm.dma = 1; gm.dma_pa = LIST_PA(next_page) + 0x40;
        gm.stale[0].pa = LIST_PA(next_page) + 0x100; gm.stale[0].v = 0xbad0bad0; gm.nstale = 1;
    }
    cp.fault_in_ib = next_fault;
    next_hang = next_fault = 0;
}

/* --- resource lists: recorded fixtures (AdrenoSegmentList's callbacks), one page each ---------------------------- */
#define LMAXE 2
struct fx_list {
    struct adreno_resource_list list;
    struct adreno_resource_entry e[LMAXE];
    unsigned page, to_n, from_n, completed;
    uint64_t last_from;
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
    if (direction == ADRENO_CACHE_TO_DEVICE) l->to_n++;
    if (direction == ADRENO_CACHE_FROM_DEVICE) { l->from_n++; l->last_from = clock_now; }
    return 0;
}
static const struct adreno_resource_list_ops fx_ops = {0, fx_retain, fx_release, fx_prepare, fx_complete, fx_sync};
static int fx_resolve(void *c, void *r, void *t, uint64_t o, uint64_t b, uint64_t *a)
{ (void)c; (void)r; (void)t; (void)o; (void)b; *a = 0; return -1; }
static struct fx_list *fx_new(unsigned page)
{
    struct fx_list *l = calloc(1, sizeof *l);
    l->page = page;
    for (unsigned i = 0; i < LMAXE; i++) {
        struct fx_list **cell = malloc(sizeof *cell); *cell = l;
        l->e[i] = (struct adreno_resource_entry){100 + i, (uint16_t)(i ? ADRENO_USAGE_WRITE | ADRENO_USAGE_READ : ADRENO_USAGE_READ),
                                                 0, cell, cell};
    }
    l->list.entries = l->e; l->list.count = LMAXE; l->list.prepared_count = LMAXE;
    l->list.ready = ADRENO_LIST_READY | ADRENO_LIST_PREPARED;
    return l;
}
static int frozen(const struct fx_list *l) { return !!(l->list.ready & ADRENO_LIST_FROZEN); }
/* The list completed (IOGPU drops it): its page goes back to the guest. */
static void hand_back(struct fx_list *l)
{
    for (uint64_t off = 0; off < 0x4000; off += 4) dev_wr32(LIST_PA(l->page) + off, SENTINEL);
    if (!gm.freed_hi) { gm.freed_lo = LIST_PA(l->page); gm.freed_hi = gm.freed_lo + 0x4000; }
}
static unsigned page_changed(const struct fx_list *l) { return words_not(LIST_PA(l->page), 0x4000, SENTINEL); }

/* --- the command: one PKT4 of REG = value ------------------------------------------------------------------------ */
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

/* --- AdrenoX2: the latch, the recovery client, the status word ---------------------------------------------------- */
static uint8_t latch;                                 /* fStampCleanupFailed */
static int dma_ok = 1;                                /* fStampDMAActive && fIBDMAActive */
#if ADRENO_GPU_RECOVER
static struct adreno_recover_guest G;
static const struct adreno_recover_ops rops = {0, kext_hvc};
#endif
static uint64_t kext_limit(void)
{
#if ADRENO_GPU_RECOVER
    return adreno_recover_guest_limit_us(&G);
#else
    return 0;
#endif
}
static uint32_t status_of(int result)                 /* processSegmentKernelCommand / pipeRetired */
{
    if (!result) return 0;
#if ADRENO_GPU_RECOVER
    return adreno_recover_guest_status(result, latch || G.dead);
#else
    return 0xa;
#endif
}
static void unlatch(void)                             /* at the top of submitFence/Fill/IB, under fSubmitLock */
{
#if ADRENO_GPU_RECOVER
    struct adreno_ib_work *ws[2] = {&slotw[0], &slotw[1]};
    adreno_recover_guest_unlatch(&rops, &G, clock_now, &latch, ws, 2, dma_ok);
#endif
}
struct cb { unsigned k; struct fx_list *l; int result, retired; uint32_t status, stamp; };

#if !ADRENO_PIPELINE
/* ibRing with ADRENO_IB_ASYNC: START, POLLs with backoff, the kext's bound from the monitor's hard limit. */
static int ring_cb(void *c, uint64_t package, uint64_t dwords, uint64_t bytes, struct adreno_ib_reply *reply)
{
    (void)c;
#if ADRENO_GPU_RECOVER
    const struct adreno_ib_async_ops ops = {0, kext_hvc, kext_delay, kext_limit()};
#else
    const struct adreno_ib_async_ops ops = {0, kext_hvc, kext_delay};
#endif
    uint64_t out[4];
    adreno_ib_async_run(&ops, package, dwords, bytes, out, 0);
    reply->status = (int64_t)out[0]; reply->marker = out[1]; reply->ticks = out[2]; reply->wptr = out[3];
    return 0;
}
struct gated { struct cb *cb; uint64_t bytes; };
static int ib_work(void *c)
{
    struct gated *g = c;
    return adreno_ib_submit(&slotw[0], &g->cb->l->list, &fx_ops, command, g->bytes, fx_resolve, ring_cb, 0);
}
static int submit(struct cb *cb)
{
    unlatch();
    struct gated g = {cb, make_command(cb->k)};
    const int e = adreno_submit_gated(&latch, ib_work, &g);
    cb->result = e; cb->retired = 1; cb->status = status_of(e);
    return e;
}
static int idle_kext(void) { return 1; }
#else
static struct adreno_pipe pipe;
static uint32_t stamp_counter, stamp_word;
static uint64_t kext_us(void *c) { (void)c; return clock_now; }
static uint32_t kext_stamp(void *c, void *owner)
{
    (void)c;
    struct cb *cb = owner;
    stamp_counter += 0x100;
    cb->stamp = stamp_counter;
    return stamp_counter;
}
static void kext_retired(void *c, void *owner, int result, const struct adreno_ib_reply *final, uint32_t stamp)
{
    (void)c; (void)final;
    struct cb *cb = owner;
    if (result == ADRENO_SUBMIT_E_UNCERTAIN || result == ADRENO_LIST_E_VISIBILITY) latch = 1;
    cb->result = result; cb->retired = 1; cb->status = status_of(result);   /* the fence's status, then the stamp */
    CHECK(stamp == cb->stamp);
    stamp_word = stamp;
}
static struct adreno_pipe_ops pops = {0, kext_hvc, kext_delay, kext_us, kext_stamp, kext_retired
#if ADRENO_GPU_RECOVER
    , 0
#endif
};
/* submitIB with the pipeline (every IB pipelined: a WindowServer client). */
static int submit(struct cb *cb)
{
    unlatch();
    if (latch) { cb->result = ADRENO_SUBMIT_E_INACTIVE; cb->retired = 1; cb->status = status_of(cb->result); return cb->result; }
    int in_flight = 0;
    const int e = adreno_pipe_submit(&pipe, &pops, &cb->l->list, &fx_ops, command, make_command(cb->k), fx_resolve, 0, cb,
                                     1, &in_flight);
    if (e == ADRENO_SUBMIT_E_UNCERTAIN || e == ADRENO_LIST_E_VISIBILITY) latch = 1;
    if (!in_flight) { cb->result = e; cb->retired = 1; cb->status = status_of(e); }
    return e;
}
/* The completion timer until nothing is in flight. */
static int idle_kext(void)
{
    unsigned n = 0;
    while (pipe.flight.active && n++ < 1000000) { clock_now += 500; adreno_pipe_poll(&pipe, &pops); }
    return !pipe.flight.active;
}
#endif

static void world(int level)
{
    rec_setup(level);
    for (unsigned s = 0; s < 2; s++) map(SLOT_VA(s), SLOT_PA(s), 0x8000, 1);
    for (unsigned s = 0; s < 2; s++) {
        memset(slot_arena[s], 0, SLOT_BYTES);
        CHECK(adreno_ib_work_init(&slotw[s], &tables, slot_arena[s], SLOT_VA(s), SLOT_BYTES, slot_relocs[s], slot_order[s],
                                  slot_used[s], 8, slot_targets[s]) == 0);
    }
    latch = 0; dma_ok = 1; pending_forever = 0; hvcs = settles_sent = 0;
    next_latency = 0; next_hang = next_fault = 0;
#if ADRENO_GPU_RECOVER
    const struct adreno_ib_async_ops probe = {0, kext_hvc, kext_delay, 0};
#else
    const struct adreno_ib_async_ops probe = {0, kext_hvc, kext_delay};
#endif
    CHECK(adreno_ib_async_probe(&probe) == 1);
#if ADRENO_GPU_RECOVER
    const int has = adreno_recover_guest_probe(&rops, &G);
    CHECK(has == (SNAP_ADRENO_RECOVER != 0));
#endif
#if ADRENO_PIPELINE
    adreno_pipe_init(&pipe, &slotw[0], &slotw[1]);
    stamp_counter = stamp_word = 0;
#if ADRENO_GPU_RECOVER
    pops.limit_us = kext_limit();
#endif
#endif
}
static int cmd_ib(struct cb *cb, unsigned k, struct fx_list *l, uint64_t latency)
{
    cb->k = k; cb->l = l; cb->retired = 0;
    next_latency = latency;
    const int e = submit(cb);
    idle_kext();
    return e;
}

#if ADRENO_GPU_RECOVER && SNAP_ADRENO_RECOVER
/* E1 E2 E3 E4 E7 (R14 R15 R17 R18 R26, R1 end to end): a hang between good IBs. */
static void test_e1_reset(void)
{
    world(2);
    CHECK(G.abi == 1 && G.level == 2 && G.hard_s == ADRENO_IB_HARD_SECONDS &&
          kext_limit() == ADRENO_IB_HARD_SECONDS * 1000000ull + ADRENO_RECOVER_MARGIN_US);
    struct fx_list *la = fx_new(0), *lb = fx_new(1), *lc = fx_new(2);
    struct cb a = {0}, b = {0}, c = {0};
    CHECK(cmd_ib(&a, 0x1001, la, 300) == 0 && a.status == 0 && cp.reg[REG] == 0x1001 && la->from_n && !frozen(la));
    /* the guilty IB: hangs, keeps writing lb's page */
    next_hang = 1; next_page = lb->page;
    b.k = 0x1002; b.l = lb;
    const uint64_t t0 = clock_now;
    int e = submit(&b);
#if ADRENO_PIPELINE
    CHECK(e == 0 && !b.retired && pipe.flight.active);                    /* in flight: the submission returned */
    /* the next frame's IB is staged while the guilty one hangs, then waits for its final reply (Q1) */
    next_latency = 300;
    c.k = 0x1003; c.l = lc;
    e = submit(&c);
    CHECK(e == 0 && b.retired && lc->to_n > 0);
    idle_kext();
    CHECK(c.retired && c.result == 0 && c.status == 0 && cp.reg[REG] == 0x1003);   /* R15: the innocent ran */
#else
    CHECK(e == ADRENO_IB_E_RESET && b.retired);
    (void)lc; (void)c;
#endif
    CHECK(b.result == ADRENO_IB_E_RESET && b.status == ADRENO_IOGPU_STATUS_HANG);      /* R14, R26 */
    CHECK(b.l->from_n == 1 && !frozen(lb) && latch == 0 && RS.epoch == 1 && G.dead == 0);   /* R18 */
    CHECK(clock_now - t0 >= HARD && slotw[0].resets + slotw[1].resets == 1);
    CHECK(!(slotw[0].state & (ADRENO_IB_STATE_UNCERTAIN | ADRENO_IB_STATE_DISABLED)) &&
          !(slotw[1].state & (ADRENO_IB_STATE_UNCERTAIN | ADRENO_IB_STATE_DISABLED)));
    /* E3 (R1, R2): lb's page goes back to the guest; 100 IBs later nothing has written it */
    hand_back(lb);
    unsigned ok = 0;
    for (unsigned i = 0; i < 100; i++) { struct cb x = {0}; ok += cmd_ib(&x, 0x2000 + i, la, i % 2 ? 250 : 0) == 0 && x.status == 0; }
    CHECK(ok == 100 && page_changed(lb) == 0 && gm.writes_into_freed == 0 && cp.violations == 0);
    /* E4: FILL32 and FENCE after the reset */
    uint64_t f[4] = {ADRENO_GUEST_FENCE, FENCE_VA + 0x300, 0x5a5a2001, 0};
    uint64_t fl[4] = {ADRENO_GUEST_FILL32, FILL_A_VA, 0x40, 0x31313131};
    map(FILL_A_VA, FILL_A_PA, 0x4000, 0);
    CHECK(mon_call(f) == 0 && dev_rd32(FENCE_PA + 0x300) == 0x5a5a2001 && mon_call(fl) == 0 &&
          dev_rd32(FILL_A_PA) == 0x31313131);
    /* E7: a CB0 fault: RESET_FAULT, status 0xb */
    struct cb d = {0};
    next_fault = 1;
    e = cmd_ib(&d, 0x1004, la, 300);
    CHECK(d.result == ADRENO_IB_E_RESET_FAULT && d.status == ADRENO_IOGPU_STATUS_PAGE_FAULT && RS.epoch == 2 && !latch);
    struct cb z = {0};
    CHECK(cmd_ib(&z, 0x1005, la, 0) == 0 && z.status == 0 && cp.reg[REG] == 0x1005);
    printf("RECOVER_E1 %s: guilty RESET status %u after %llu ticks, innocent ok, 100 IBs after, sentinel intact, "
           "fault -> %#x\n", ADRENO_PIPELINE ? "pipeline" : "synchronous", b.status,
           (unsigned long long)(clock_now - t0), d.status);
}

/* E5 E7 (R27 R28 R26): level 1: a long IB outlives the hard limit; the kext latches; SETTLE un-latches once the GPU is
 * idle, at most once per 100 ms; a teardown latch is never cleared. */
static void test_e5_unlatch(void)
{
    world(1);
    struct fx_list *la = fx_new(0), *lb = fx_new(1);
    struct cb b = {0};
    next_latency = HARD + 500000;                                       /* 3.5 s */
    b.k = 0x5001; b.l = lb;
    const uint64_t t0 = clock_now;
    int e = submit(&b);
    idle_kext();
    CHECK(b.retired && b.result == ADRENO_SUBMIT_E_UNCERTAIN && b.status == ADRENO_IOGPU_STATUS_TIMEOUT && latch);
    CHECK(frozen(lb) && b.l->from_n == 0 && RS.epoch == 0);             /* retained as today */
    (void)e;
    /* at once: SETTLE finds the CP still busy -> still latched; the command buffer is a victim (5) */
    clock_now += 10;
    struct cb c = {0};
    CHECK(cmd_ib(&c, 0x5002, la, 0) == ADRENO_SUBMIT_E_INACTIVE && c.status == ADRENO_IOGPU_STATUS_VICTIM && latch);
    CHECK(G.settles == 1 && G.refused == 1 && settles_sent == 1);
    /* R28: 1,000 latched submissions within 50 ms make no further SETTLE */
    unsigned victims = 0;
    for (unsigned i = 0; i < 1000; i++) {
        clock_now += 50;
        struct cb x = {0};
        victims += cmd_ib(&x, 0x5100 + i, la, 0) == ADRENO_SUBMIT_E_INACTIVE && x.status == ADRENO_IOGPU_STATUS_VICTIM;
    }
    CHECK(victims == 1000 && G.settles == 1 && settles_sent == 1);
    /* the long IB finishes at 3.5 s; the next SETTLE proves the CP idle: un-latched, the IB runs */
    clock_now = t0 + HARD + 500000 + 200000;
    struct cb d = {0};
    CHECK(cmd_ib(&d, 0x5003, la, 300) == 0 && d.status == 0 && !latch && cp.reg[REG] == 0x5003);
    CHECK(G.unlatched == 1 && G.settled == 1 && G.settle_resets == 0 && frozen(lb));   /* R18: lb stays retained */
    /* a latch from a failed DMA completion (teardown) is never cleared */
    latch = 1; dma_ok = 0;
    clock_now += 1000000;
    const uint64_t sent = settles_sent;
    struct cb x = {0};
    CHECK(cmd_ib(&x, 0x5004, la, 0) == ADRENO_SUBMIT_E_INACTIVE && latch && settles_sent == sent);
    printf("RECOVER_E5 %s: latched at %llu ticks, 1 SETTLE refused, 1000 victims, un-latched by SETTLE at %llu\n",
           ADRENO_PIPELINE ? "pipeline" : "synchronous", (unsigned long long)HARD, (unsigned long long)(HARD + 700000));
}

/* E6 (R19, R23): the kext waits through PENDING to the monitor's RESET at the hard limit, under 4.1 s; a monitor that
 * answers PENDING forever is cut at hard + 2 s; then SETTLE (the GPU was reset meanwhile) un-latches. */
static void test_e6_bound(void)
{
    world(2);
    struct fx_list *la = fx_new(0), *lb = fx_new(1), *lc = fx_new(2);
    struct cb b = {0};
    next_hang = 1; next_page = lb->page;
    const uint64_t t0 = clock_now;
    b.k = 0x6001; b.l = lb;
    submit(&b);
    idle_kext();
    CHECK(b.result == ADRENO_IB_E_RESET && clock_now - t0 >= HARD && clock_now - t0 < 4100000);
    pending_forever = 1;
    struct cb c = {0};
    next_hang = 1; next_page = lc->page;
    const uint64_t t1 = clock_now;
    c.k = 0x6002; c.l = lc;
    submit(&c);
    idle_kext();
    /* the synchronous loop counts its IODelay time only (async-ib A10), the pipeline the clock: each POLL's own time
     * (here ~50 model ticks of monitor work) comes on top of the synchronous bound */
    CHECK(c.result == ADRENO_SUBMIT_E_UNCERTAIN && latch && clock_now - t1 >= kext_limit() &&
          clock_now - t1 < kext_limit() + (ADRENO_PIPELINE ? 100000 : 1000000) && RS.epoch == 2);
    pending_forever = 0;
    clock_now += 200000;
    struct cb d = {0};
    CHECK(cmd_ib(&d, 0x6003, la, 0) == 0 && !latch && G.unlatched == 1);
    printf("RECOVER_E6 %s: RESET at %llu ticks; PENDING forever cut at %llu (limit %llu)\n",
           ADRENO_PIPELINE ? "pipeline" : "synchronous", (unsigned long long)HARD, (unsigned long long)(clock_now - t1),
           (unsigned long long)kext_limit());
}
#endif

#if !ADRENO_GPU_RECOVER && SNAP_ADRENO_RECOVER
/* E8 (R29): today's kext on a recovering monitor: RESET reads as UNCERTAIN, the kext latches as today; the GPU itself
 * was reset (and the monitor would serve a SETTLE no one sends). */
static void test_e8_old_kext(void)
{
    world(2);
    struct fx_list *la = fx_new(0), *lb = fx_new(1);
    struct cb b = {0};
    next_hang = 1; next_page = lb->page;
    b.k = 0x8001; b.l = lb;
    submit(&b);
    idle_kext();
    CHECK(b.result == ADRENO_SUBMIT_E_UNCERTAIN && b.status == 0xa && latch && frozen(lb) && RS.epoch == 1);
    struct cb c = {0};
    CHECK(cmd_ib(&c, 0x8002, la, 0) == ADRENO_SUBMIT_E_INACTIVE && latch);
    printf("RECOVER_E8 old kext, recovering monitor: latched as today, GPU reset (epoch %llu)\n", (unsigned long long)RS.epoch);
}
#endif
#if ADRENO_GPU_RECOVER && !SNAP_ADRENO_RECOVER
/* E8 (R29): a recovering kext on today's monitor: QUERY refused, 4 s bound, latched for the boot, no SETTLE. */
static void test_e8_old_monitor(void)
{
    world(2);
    CHECK(G.abi == 0 && kext_limit() == 0);
    struct fx_list *la = fx_new(0), *lb = fx_new(1);
    struct cb b = {0};
    next_hang = 1; next_page = lb->page;
    b.k = 0x8101; b.l = lb;
    submit(&b);
    idle_kext();
    CHECK(b.result == ADRENO_SUBMIT_E_UNCERTAIN && latch && frozen(lb));
    clock_now += 1000000;
    struct cb c = {0};
    CHECK(cmd_ib(&c, 0x8102, la, 0) == ADRENO_SUBMIT_E_INACTIVE && latch && settles_sent == 0 && G.settles == 0);
    printf("RECOVER_E8 recovering kext, old monitor: QUERY refused, latched as today, no SETTLE\n");
}
#endif

int main(void)
{
    dram = calloc(1, RAM_SIZE);
    cache = calloc(1, RAM_SIZE);
    for (unsigned s = 0; s < 2; s++) if (posix_memalign((void **)&slot_arena[s], 64, SLOT_BYTES)) return 2;
    if (!dram || !cache) return 2;
    CHECK(adreno_ib_tables_init(&tables) == 0);
    for (uint32_t off = 0x800; off < ADRENO_IB_REG_LIMIT && !REG; off++)
        if ((tables.allowed[off / 64] >> (off % 64) & 1) && !(tables.address[off / 64] >> (off % 64) & 1)) REG = off;
    CHECK(REG != 0);
#if ADRENO_GPU_RECOVER && SNAP_ADRENO_RECOVER
    test_e1_reset();
    test_e5_unlatch();
    test_e6_bound();
#elif SNAP_ADRENO_RECOVER
    test_e8_old_kext();
#else
    test_e8_old_monitor();
#endif
    if (failures) { printf("FAIL: %u of %u end-to-end recovery checks\n", failures, checks); return 1; }
    printf("PASS: %u end-to-end recovery checks (%s, kext recovery %d, monitor recovery %d)\n", checks,
           ADRENO_PIPELINE ? "pipeline" : "synchronous", ADRENO_GPU_RECOVER, SNAP_ADRENO_RECOVER);
    return 0;
}

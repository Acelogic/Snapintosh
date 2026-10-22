/* SPDX-License-Identifier: MIT */
/* compat/early-stop.c against the real compat/service-lock.c: HVC admission
 * and refusal, reason recording, delay bounds, host latch admission, the poll
 * rate limit, and stop idempotence when an early stop races the watchdog.
 *
 *   clang -std=gnu11 -O1 -g -pthread -fsanitize=address,undefined \
 *     -fno-sanitize-recover=all -Wall -Wextra -Werror -Icompat -Ishadow \
 *     tools/test-early-stop.c compat/early-stop.c compat/service-lock.c \
 *     -o build/test-early-stop && build/test-early-stop
 *
 * tools/test-early-stop.py runs this and the Python-side decoders. */
#include <pthread.h>
#include <sched.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "early-stop.h"
#include "adreno-guest.h"
#include "auxkc-observe.h"
#include "service-lock.h"

static unsigned checks;
#define CHECK(x) do { checks++; if (!(x)) { fprintf(stderr, "line %d: %s\n", __LINE__, #x); exit(1); } } while (0)

#define HVC_AD16 0xd415a2c2u      /* hvc #0xad16, assembled by hand */
#define HZ 24000000ull
#define NORMAL(cpu) (((uint64_t)SERVICE_STOP_NORMAL << 32) | ((cpu) + 1))

static const struct auxkc_range KC = {
    .va_base = 0xfffffe0010280000ull, .va_end = 0xfffffe00102c8000ull,
    .pa_base = 0x8e6a80000ull, .pa_end = 0x8e6ac8000ull,
};

static struct early_stop_params params(uint64_t flags)
{
    return (struct early_stop_params){.flags = flags, .max_delay_s = 120, .host_call = 0xb0012340,
                                      .host_state = 0xb0400000, .host_poll_ms = 200,
                                      .session = 0x5eed5eed12345678ull};
}

static void layout(void)
{
    CHECK(sizeof(struct early_stop_params) == 8 * EARLY_STOP_PARAMS_WORDS);
    CHECK(sizeof(struct early_stop_state) == 8 * EARLY_STOP_STATE_WORDS);
    CHECK(sizeof(struct early_stop_host_request) == 8 * EARLY_STOP_HOST_REQUEST_WORDS);
    /* tools/early_stop.py FIELDS order: spot-check both ends and the middle. */
    CHECK(offsetof(struct early_stop_state, state) == 0);
    CHECK(offsetof(struct early_stop_state, deadline) == 7 * 8);
    CHECK(offsetof(struct early_stop_state, fire_cpu) == 11 * 8);
    CHECK(offsetof(struct early_stop_state, host_in_call) == 20 * 8);
    CHECK(offsetof(struct early_stop_state, outcome) == 21 * 8);
    CHECK(offsetof(struct early_stop_state, text) == 22 * 8);
    CHECK(offsetof(struct early_stop_host_request, text) == 6 * 8);
    CHECK(EARLY_STOP_E_DISABLED == -60);           /* ADRENO_E_PARAMS */
    CHECK(ADRENO_GUEST_STOP == 0x00010006 && ADRENO_GUEST_HVC == 0xad16);
}

static void caller_admission(void)
{
    const uint64_t va = KC.va_base + 0x1a2c4, pa = KC.pa_base + 0x1a2c4;
    CHECK(early_stop_guest_caller(&KC, va, pa, HVC_AD16, 0x3c5) == 0);        /* EL1h */
    CHECK(early_stop_guest_caller(&KC, va, pa, HVC_AD16, 0x3c4) == 0);        /* EL1t */
    CHECK(early_stop_guest_caller(&KC, KC.va_base, KC.pa_base, HVC_AD16, 5) == 0);
    CHECK(early_stop_guest_caller(&KC, KC.va_end - 4, KC.pa_end - 4, HVC_AD16, 5) == 0);
    /* EL0 cannot issue HVC; EL2 and AArch32 modes are never a guest kext. */
    for (uint64_t mode = 0; mode < 32; mode++)
        if (mode != 4 && mode != 5)
            CHECK(early_stop_guest_caller(&KC, va, pa, HVC_AD16, mode) == EARLY_STOP_E_CALLER);
    /* Outside the AuxKC, in either space, or aliased within it. */
    CHECK(early_stop_guest_caller(&KC, KC.va_base - 4, KC.pa_base - 4, HVC_AD16, 5) == EARLY_STOP_E_CALLER);
    CHECK(early_stop_guest_caller(&KC, KC.va_end, KC.pa_end, HVC_AD16, 5) == EARLY_STOP_E_CALLER);
    CHECK(early_stop_guest_caller(&KC, KC.va_end - 3, KC.pa_end - 3, HVC_AD16, 5) == EARLY_STOP_E_CALLER);
    CHECK(early_stop_guest_caller(&KC, va + 2, pa + 2, HVC_AD16, 5) == EARLY_STOP_E_CALLER);
    CHECK(early_stop_guest_caller(&KC, 0xfffffe0007004000ull, 0x8c1000000ull, HVC_AD16, 5) == EARLY_STOP_E_CALLER);
    CHECK(early_stop_guest_caller(&KC, va, 0, HVC_AD16, 5) == EARLY_STOP_E_CALLER);   /* AT faulted */
    CHECK(early_stop_guest_caller(&KC, va, pa + 0x4000, HVC_AD16, 5) == EARLY_STOP_E_CALLER);
    CHECK(early_stop_guest_caller(&KC, va + 0x4000, pa, HVC_AD16, 5) == EARLY_STOP_E_CALLER);
    /* The bytes must be this exact instruction. */
    CHECK(early_stop_guest_caller(&KC, va, pa, 0xd4000002u, 5) == EARLY_STOP_E_CALLER);   /* hvc #0 */
    CHECK(early_stop_guest_caller(&KC, va, pa, 0xd415a2e2u, 5) == EARLY_STOP_E_CALLER);   /* hvc #0xad17 */
    CHECK(early_stop_guest_caller(&KC, va, pa, 0xd415a2c3u, 5) == EARLY_STOP_E_CALLER);   /* smc #0xad16 */
    CHECK(early_stop_guest_caller(&KC, va, pa, 0, 5) == EARLY_STOP_E_CALLER);
    /* No AuxKC, a degenerate one, or inverted ranges admit nothing. */
    struct auxkc_range none = {0}, tiny = {KC.va_base, KC.va_base + 2, KC.pa_base, KC.pa_base + 2};
    struct auxkc_range inverted = {KC.va_end, KC.va_base, KC.pa_end, KC.pa_base};
    CHECK(early_stop_guest_caller(NULL, va, pa, HVC_AD16, 5) == EARLY_STOP_E_CALLER);
    CHECK(early_stop_guest_caller(&none, 0, 0, HVC_AD16, 5) == EARLY_STOP_E_CALLER);
    CHECK(early_stop_guest_caller(&tiny, KC.va_base, KC.pa_base, HVC_AD16, 5) == EARLY_STOP_E_CALLER);
    CHECK(early_stop_guest_caller(&inverted, va, pa, HVC_AD16, 5) == EARLY_STOP_E_CALLER);
    /* A range touching the top of the address space does not wrap. */
    struct auxkc_range top = {UINT64_MAX - 0x3fff, UINT64_MAX, KC.pa_base, KC.pa_base + 0x3fff};
    CHECK(early_stop_guest_caller(&top, UINT64_MAX - 3, KC.pa_base + 0x3ffc, HVC_AD16, 5) == EARLY_STOP_E_CALLER);
    CHECK(early_stop_guest_caller(&top, UINT64_MAX - 0x3fff, KC.pa_base, HVC_AD16, 5) == 0);
}

static void guest_admission(void)
{
    const uint64_t va = KC.va_base + 0x800, pa = KC.pa_base + 0x800;
    uint64_t accepted = 77;
    struct early_stop_params off = params(0), host = params(EARLY_STOP_F_HOST);
    struct early_stop_params guest = params(EARLY_STOP_F_GUEST);
    CHECK(early_stop_guest_admit(&off, &KC, va, pa, HVC_AD16, 5, 1, 20, &accepted) == EARLY_STOP_E_DISABLED);
    CHECK(early_stop_guest_admit(&host, &KC, va, pa, HVC_AD16, 5, 1, 20, &accepted) == EARLY_STOP_E_DISABLED);
    CHECK(early_stop_guest_admit(NULL, &KC, va, pa, HVC_AD16, 5, 1, 20, &accepted) == EARLY_STOP_E_DISABLED);
    CHECK(accepted == 77);
    CHECK(early_stop_guest_admit(&guest, &KC, va, pa, HVC_AD16, 0, 1, 20, &accepted) == EARLY_STOP_E_CALLER);
    CHECK(early_stop_guest_admit(&guest, &KC, va, pa, 0xd4000002u, 5, 1, 20, &accepted) == EARLY_STOP_E_CALLER);
    CHECK(early_stop_guest_admit(&guest, &KC, va, pa, HVC_AD16, 5, 0, 20, &accepted) == EARLY_STOP_E_REASON);
    CHECK(early_stop_guest_admit(&guest, &KC, va, pa, HVC_AD16, 5, EARLY_STOP_GUEST_REASON_MAX + 1, 20, &accepted) ==
          EARLY_STOP_E_REASON);
    CHECK(early_stop_guest_admit(&guest, &KC, va, pa, HVC_AD16, 5, UINT64_MAX, 20, &accepted) == EARLY_STOP_E_REASON);
    CHECK(accepted == 77);
    CHECK(early_stop_guest_admit(&guest, &KC, va, pa, HVC_AD16, 5, EARLY_STOP_REASON_PRESENT, 20, &accepted) == 0);
    CHECK(accepted == 20);
    CHECK(early_stop_guest_admit(&guest, &KC, va, pa, HVC_AD16, 5, EARLY_STOP_REASON_PLUGIN_FAILURE, 0, &accepted) == 0);
    CHECK(accepted == 0);
    CHECK(early_stop_guest_admit(&guest, &KC, va, pa, HVC_AD16, 5, EARLY_STOP_REASON_CLIENT_DIED, 20, &accepted) == 0 &&
          accepted == 20 && EARLY_STOP_REASON_CLIENT_DIED == 3 && EARLY_STOP_GUEST_REASON_MAX == 3);
    /* Both enabled is still admission-checked per source. */
    struct early_stop_params both = params(EARLY_STOP_F_ALL);
    CHECK(early_stop_guest_admit(&both, &KC, va, pa, HVC_AD16, 5, 2, 20, &accepted) == 0);
}

static void delay_bounds(void)
{
    struct early_stop_params p = params(EARLY_STOP_F_GUEST);
    uint64_t accepted = 0;
    CHECK(early_stop_delay(&p, 0, &accepted) == 0 && accepted == 0);
    CHECK(early_stop_delay(&p, 20, &accepted) == 0 && accepted == 20);
    CHECK(early_stop_delay(&p, 120, &accepted) == 0 && accepted == 120);
    CHECK(early_stop_delay(&p, 121, &accepted) == 0 && accepted == 120);     /* clamped */
    CHECK(early_stop_delay(&p, EARLY_STOP_DELAY_LIMIT, &accepted) == 0 && accepted == 120);
    accepted = 5;
    CHECK(early_stop_delay(&p, EARLY_STOP_DELAY_LIMIT + 1, &accepted) == EARLY_STOP_E_DELAY && accepted == 5);
    CHECK(early_stop_delay(&p, UINT64_MAX, &accepted) == EARLY_STOP_E_DELAY);
    CHECK(early_stop_delay(&p, 1ull << 32, &accepted) == EARLY_STOP_E_DELAY);
    p.max_delay_s = 0;                               /* stop at the next tick */
    CHECK(early_stop_delay(&p, 20, &accepted) == 0 && accepted == 0);
    p.max_delay_s = EARLY_STOP_DELAY_LIMIT + 1;      /* a params blob the host must never write */
    CHECK(early_stop_delay(&p, 20, &accepted) == EARLY_STOP_E_DELAY);
    CHECK(early_stop_delay(NULL, 20, &accepted) == EARLY_STOP_E_DELAY);
    CHECK(early_stop_delay(&p, 20, NULL) == EARLY_STOP_E_DELAY);
    /* The armed deadline is accepted * hz after the request, never the ask. */
    struct early_stop_state s = {0};
    const uint64_t now = 0x1234567890ull;
    CHECK(early_stop_request(&s, EARLY_STOP_SOURCE_GUEST, 1, 0, 500, 120, now, HZ, 0, 0, NULL) == 0);
    CHECK(s.deadline == now + 120 * HZ && s.requested_delay == 500 && s.accepted_delay == 120);
    struct early_stop_state z = {0};
    CHECK(early_stop_request(&z, EARLY_STOP_SOURCE_GUEST, 1, 0, 9, 9, now, 0, 0, 0, NULL) == 0);
    CHECK(z.deadline == now);                        /* no rate: never later than now */
    struct early_stop_state w = {0};                 /* counter wrap */
    CHECK(early_stop_request(&w, EARLY_STOP_SOURCE_GUEST, 1, 0, 1, 1, UINT64_MAX - 5, HZ, 0, 0, NULL) == 0);
    CHECK(w.deadline == UINT64_MAX - 5 + HZ);
    CHECK(early_stop_deadline(&w, UINT64_MAX - 5 + 2 * HZ) == w.deadline);
    CHECK(early_stop_deadline(&w, UINT64_MAX - 5 + HZ / 2) == UINT64_MAX - 5 + HZ / 2);
    CHECK(!early_stop_fire(&w, UINT64_MAX, UINT64_MAX - 5 + 2 * HZ, 1));
    CHECK(early_stop_fire(&w, UINT64_MAX - 5 + HZ, UINT64_MAX - 5 + 2 * HZ, 1));
}

static void recording(void)
{
    struct early_stop_state s = {0};
    const uint64_t now = 1000000, budget = now + 2400 * HZ, pc = KC.va_base + 0x1a2c4;
    CHECK(early_stop_deadline(&s, budget) == budget);             /* idle: the budget */
    CHECK(!early_stop_fire(&s, budget + 1, budget, 0));           /* idle never fires */
    early_stop_refuse(&s, EARLY_STOP_E_CALLER);
    early_stop_refuse(&s, EARLY_STOP_E_REASON);
    CHECK(s.refusals == 2 && (int64_t)s.last_refusal == EARLY_STOP_E_REASON && s.state == EARLY_STOP_IDLE);
    CHECK(early_stop_request(&s, EARLY_STOP_SOURCE_GUEST, EARLY_STOP_REASON_PRESENT, 0x2a00000007ull,
                             20, 20, now, HZ, 3, pc, NULL) == EARLY_STOP_ACCEPTED);
    CHECK(s.state == EARLY_STOP_PENDING && s.source == EARLY_STOP_SOURCE_GUEST &&
          s.reason == EARLY_STOP_REASON_PRESENT && s.detail == 0x2a00000007ull &&
          s.requested_delay == 20 && s.accepted_delay == 20 && s.request_ticks == now &&
          s.deadline == now + 20 * HZ && s.request_cpu == 4 && s.request_pc == pc &&
          !s.fire_cpu && !s.fire_ticks && !s.text[0]);
    struct early_stop_state before;
    memcpy(&before, &s, sizeof s);
    const uint64_t text[8] = {0x6f74617265706f, 0};             /* "operato" */
    CHECK(early_stop_request(&s, EARLY_STOP_SOURCE_HOST, 1, 99, 20, 20, now + 5, HZ, 0, 0, text) ==
          EARLY_STOP_DUPLICATE);
    CHECK(early_stop_request(&s, EARLY_STOP_SOURCE_GUEST, 2, 1, 0, 0, now + 6, HZ, 1, pc, NULL) ==
          EARLY_STOP_DUPLICATE);
    CHECK(s.duplicates == 2);
    before.duplicates = 2;
    CHECK(!memcmp(&before, &s, sizeof s));                       /* the first request stands */
    CHECK(early_stop_deadline(&s, budget) == now + 20 * HZ);
    CHECK(early_stop_deadline(&s, now + 10 * HZ) == now + 10 * HZ);  /* budget first */
    CHECK(!early_stop_fire(&s, now + 20 * HZ - 1, budget, 2));
    CHECK(early_stop_fire(&s, now + 20 * HZ, budget, 2));
    CHECK(s.state == EARLY_STOP_FIRED && s.fire_cpu == 3 && s.fire_ticks == now + 20 * HZ);
    CHECK(early_stop_fire(&s, now + 21 * HZ, budget, 5));         /* a peer stops too... */
    CHECK(s.fire_cpu == 3 && s.fire_ticks == now + 20 * HZ);      /* ...but the first is kept */
    CHECK(early_stop_deadline(&s, budget) == now + 20 * HZ);      /* still bounds every timer */
    early_stop_finish(&s, NORMAL(2));
    CHECK(s.outcome == EARLY_STOP_OUTCOME_STOPPED);
    early_stop_finish(&s, NORMAL(0));
    CHECK(s.outcome == EARLY_STOP_OUTCOME_CONCURRENT);
    early_stop_finish(&s, ((uint64_t)SERVICE_STOP_FAULT << 32) | 3);
    CHECK(s.outcome == EARLY_STOP_OUTCOME_CONCURRENT);
    /* A tie with the budget belongs to the watchdog. */
    struct early_stop_state t = {0};
    CHECK(early_stop_request(&t, EARLY_STOP_SOURCE_GUEST, 1, 0, 20, 20, now, HZ, 0, 0, NULL) == 0);
    CHECK(!early_stop_fire(&t, now + 20 * HZ, now + 20 * HZ, 0));
    CHECK(!early_stop_fire(&t, now + 30 * HZ, now + 10 * HZ, 0));
    early_stop_finish(&t, NORMAL(0));
    CHECK(t.outcome == EARLY_STOP_OUTCOME_SUPERSEDED && t.state == EARLY_STOP_PENDING);
    struct early_stop_state idle = {0};
    early_stop_finish(&idle, NORMAL(0));
    CHECK(idle.outcome == EARLY_STOP_OUTCOME_NONE);
    /* A host request keeps its text and marks CPU0 without a guest PC. */
    struct early_stop_state h = {0};
    const uint64_t words[8] = {0x2074736f68206f6eull, 0x6572, 0, 0, 0, 0, 0, 0};
    CHECK(early_stop_request(&h, EARLY_STOP_SOURCE_HOST, EARLY_STOP_REASON_OPERATOR, 0xabcdef, 0, 0,
                             now, HZ, 0, 0, words) == EARLY_STOP_ACCEPTED);
    CHECK(h.source == EARLY_STOP_SOURCE_HOST && h.request_cpu == 1 && !h.request_pc &&
          h.deadline == now && !memcmp(h.text, words, sizeof words) && h.detail == 0xabcdef);
    CHECK(early_stop_fire(&h, now, budget, 0) && h.fire_cpu == 1);
}

static void host_admission(void)
{
    struct early_stop_params p = params(EARLY_STOP_F_HOST);
    struct early_stop_host_request r = {EARLY_STOP_HOST_MAGIC, p.session, 0x1122334455667788ull,
                                        EARLY_STOP_REASON_OPERATOR, 0, 0x99,
                                        {0x6e776f6420747570ull, 0, 0, 0, 0, 0, 0, 0}};
    uint64_t accepted = 55;
    CHECK(early_stop_host_admit(&p, &r, &accepted) == 0 && accepted == 0);
    r.delay_s = 30;
    CHECK(early_stop_host_admit(&p, &r, &accepted) == 0 && accepted == 30);
    r.delay_s = 3000;
    CHECK(early_stop_host_admit(&p, &r, &accepted) == 0 && accepted == 120);
    r.delay_s = EARLY_STOP_DELAY_LIMIT + 1;
    CHECK(early_stop_host_admit(&p, &r, &accepted) == EARLY_STOP_E_DELAY);
    r.delay_s = 0;
    struct early_stop_host_request bad = r;
    bad.magic ^= 1;
    CHECK(early_stop_host_admit(&p, &bad, &accepted) == EARLY_STOP_E_HOST);
    bad = r; bad.session ^= 1;                   /* a previous run's datagram */
    CHECK(early_stop_host_admit(&p, &bad, &accepted) == EARLY_STOP_E_HOST);
    bad = r; bad.reason = 0;
    CHECK(early_stop_host_admit(&p, &bad, &accepted) == EARLY_STOP_E_REASON);
    bad = r; bad.reason = 0x10000;
    CHECK(early_stop_host_admit(&p, &bad, &accepted) == EARLY_STOP_E_REASON);
    bad = r; bad.text[7] = 0x4100000000000000ull;   /* not NUL terminated */
    CHECK(early_stop_host_admit(&p, &bad, &accepted) == EARLY_STOP_E_HOST);
    struct early_stop_params guest_only = params(EARLY_STOP_F_GUEST);
    CHECK(early_stop_host_admit(&guest_only, &r, &accepted) == EARLY_STOP_E_DISABLED);
    struct early_stop_params unsessioned = p;
    unsessioned.session = 0;
    bad = r; bad.session = 0;
    CHECK(early_stop_host_admit(&unsessioned, &bad, &accepted) == EARLY_STOP_E_HOST);
    CHECK(early_stop_host_admit(&p, NULL, &accepted) == EARLY_STOP_E_DISABLED);
}

static void poll_rate(void)
{
    struct early_stop_params p = params(EARLY_STOP_F_HOST);
    const uint64_t period = HZ / 1000 * 200;
    for (unsigned wrap = 0; wrap < 2; wrap++) {
        struct early_stop_state s = {0};
        uint64_t t = wrap ? UINT64_MAX - period / 2 : 5000;
        CHECK(early_stop_host_due(&s, &p, t, HZ) == 1 && s.host_polls == 1);
        CHECK(early_stop_host_due(&s, &p, t + 1, HZ) == 0);
        CHECK(early_stop_host_due(&s, &p, t + period - 1, HZ) == 0);
        CHECK(early_stop_host_due(&s, &p, t + period, HZ) == 1 && s.host_polls == 2);
        CHECK(early_stop_host_due(&s, &p, t + period + 3, HZ) == 0);
    }
    struct early_stop_state s = {0};
    struct early_stop_params q = p;
    q.flags = EARLY_STOP_F_GUEST;
    CHECK(!early_stop_host_due(&s, &q, 1, HZ));
    q = p; q.host_call = 0;
    CHECK(!early_stop_host_due(&s, &q, 1, HZ));
    q = p; q.session = 0;
    CHECK(!early_stop_host_due(&s, &q, 1, HZ));
    q = p; q.host_poll_ms = EARLY_STOP_POLL_MIN_MS - 1;
    CHECK(!early_stop_host_due(&s, &q, 1, HZ));
    q = p; q.host_poll_ms = EARLY_STOP_POLL_MAX_MS + 1;
    CHECK(!early_stop_host_due(&s, &q, 1, HZ));
    CHECK(!early_stop_host_due(&s, &p, 1, 0));
    CHECK(!early_stop_host_due(&s, NULL, 1, HZ));
    CHECK(s.host_polls == 0);
}

/* ---- idempotence against a concurrent watchdog stop ------------------------
 * Three CPUs start together. W takes the budget stop, E finds the accepted
 * early deadline expired, D keeps asking for another early stop. Whatever the
 * interleaving: one stop word, set once and never replaced; one fire record;
 * the outcome says whether the early stop is what set the word. */
struct race {
    struct guest_service_lock lock;
    struct early_stop_state stop;
    volatile int go;
    int early_fired, duplicates;
};

static void wait_go(struct race *r) { while (!__atomic_load_n(&r->go, __ATOMIC_ACQUIRE)) sched_yield(); }

static void *watchdog_cpu(void *opaque)
{
    struct race *r = opaque;
    wait_go(r);
    guest_service_stop(&r->lock, 1, SERVICE_STOP_NORMAL);
    return NULL;
}

static void *early_cpu(void *opaque)
{
    struct race *r = opaque;
    wait_go(r);
    if (early_stop_fire(&r->stop, 2000, 10000, 2)) {
        r->early_fired = 1;
        guest_service_stop(&r->lock, 2, SERVICE_STOP_NORMAL);
    }
    return NULL;
}

static void *duplicate_cpu(void *opaque)
{
    struct race *r = opaque;
    wait_go(r);
    for (int n = 0; n < 4; n++)
        r->duplicates += early_stop_request(&r->stop, EARLY_STOP_SOURCE_HOST, 1, n, 0, 0, 1500, 1,
                                            3, 0, NULL) == EARLY_STOP_DUPLICATE;
    if (early_stop_fire(&r->stop, 2100, 10000, 3)) guest_service_stop(&r->lock, 3, SERVICE_STOP_NORMAL);
    return NULL;
}

static void races(void)
{
    unsigned won[4] = {0};
    for (unsigned round = 0; round < 3000; round++) {
        struct race *r = calloc(1, sizeof *r);
        CHECK(r && guest_service_boot(&r->lock) == SERVICE_OK);
        CHECK(early_stop_request(&r->stop, EARLY_STOP_SOURCE_GUEST, 2, round, 1, 1, 1000, 1000,
                                 0, 0, NULL) == EARLY_STOP_ACCEPTED);        /* deadline 2000 */
        pthread_t t[3];
        CHECK(!pthread_create(&t[0], NULL, watchdog_cpu, r));
        CHECK(!pthread_create(&t[1], NULL, early_cpu, r));
        CHECK(!pthread_create(&t[2], NULL, duplicate_cpu, r));
        __atomic_store_n(&r->go, 1, __ATOMIC_RELEASE);
        for (int n = 0; n < 3; n++) CHECK(!pthread_join(t[n], NULL));
        uint64_t word = guest_service_stopped(&r->lock);
        CHECK(word == NORMAL(1) || word == NORMAL(2) || word == NORMAL(3));
        CHECK(guest_service_lifecycle(&r->lock) & SERVICE_ADMISSION_CLOSED);
        CHECK(r->duplicates >= 3 && r->duplicates <= 4 && r->stop.duplicates == (uint64_t)r->duplicates);
        CHECK(r->stop.state == EARLY_STOP_FIRED && (r->stop.fire_cpu == 3 || r->stop.fire_cpu == 4));
        if (r->stop.source == EARLY_STOP_SOURCE_GUEST)
            CHECK(r->stop.reason == 2 && r->stop.detail == round && r->stop.deadline == 2000);
        else
            CHECK(r->stop.source == EARLY_STOP_SOURCE_HOST && r->stop.reason == 1 &&
                  r->stop.deadline == 1500 && r->duplicates == 3);
        early_stop_finish(&r->stop, word);
        CHECK(r->stop.outcome == (word == ((uint64_t)SERVICE_STOP_NORMAL << 32 | r->stop.fire_cpu) ?
                                  EARLY_STOP_OUTCOME_STOPPED : EARLY_STOP_OUTCOME_CONCURRENT));
        /* A later stop of either kind leaves the word alone. */
        guest_service_stop(&r->lock, 4, SERVICE_STOP_FAULT);
        guest_service_stop(&r->lock, 0, SERVICE_STOP_NORMAL);
        CHECK(guest_service_stopped(&r->lock) == word);
        won[word & 3]++;
        free(r);
    }
    printf("race winners: watchdog %u, early %u, early peer %u\n", won[2], won[3], won[0]);
    /* Deterministic orders, both ways. */
    struct guest_service_lock lock = {0};
    struct early_stop_state s = {0};
    CHECK(guest_service_boot(&lock) == SERVICE_OK);
    CHECK(early_stop_request(&s, EARLY_STOP_SOURCE_HOST, 1, 0, 0, 0, 10, HZ, 0, 0, NULL) == 0);
    guest_service_stop(&lock, 4, SERVICE_STOP_NORMAL);           /* watchdog on CPU4 first */
    CHECK(early_stop_fire(&s, 11, 1000, 0));
    guest_service_stop(&lock, 0, SERVICE_STOP_NORMAL);
    early_stop_finish(&s, guest_service_stopped(&lock));
    CHECK(guest_service_stopped(&lock) == NORMAL(4) && s.outcome == EARLY_STOP_OUTCOME_CONCURRENT);
    struct guest_service_lock lock2 = {0};
    struct early_stop_state s2 = {0};
    CHECK(guest_service_boot(&lock2) == SERVICE_OK);
    CHECK(early_stop_request(&s2, EARLY_STOP_SOURCE_GUEST, 1, 0, 0, 0, 10, HZ, 5, 0, NULL) == 0);
    CHECK(early_stop_fire(&s2, 11, 1000, 5));
    guest_service_stop(&lock2, 5, SERVICE_STOP_NORMAL);           /* early stop first */
    guest_service_stop(&lock2, 1, SERVICE_STOP_NORMAL);           /* then the watchdog */
    early_stop_finish(&s2, guest_service_stopped(&lock2));
    CHECK(guest_service_stopped(&lock2) == NORMAL(5) && s2.outcome == EARLY_STOP_OUTCOME_STOPPED);
}

int main(void)
{
    layout();
    caller_admission();
    guest_admission();
    delay_bounds();
    recording();
    host_admission();
    poll_rate();
    races();
    printf("PASS: early stop, %u checks\n", checks);
    return 0;
}

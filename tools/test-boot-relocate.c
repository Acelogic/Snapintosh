/* SPDX-License-Identifier: MIT */
/* compat/boot-relocate.h, natively: the layout check, the ID comparison, q1n1's
 * CPU's wait decision against an independent oracle over its whole input grid,
 * and the relay between two real threads, including a caller that gives up.
 *
 *   cc -std=gnu11 -O1 -g -Wall -Wextra -Werror -fsanitize=address,undefined \
 *      -Icompat tools/test-boot-relocate.c compat/cpu-release.c -o /tmp/test-boot-relocate -lpthread
 *   (tools/test-boot-relocate.py also builds it with -fsanitize=thread)
 */
#include <pthread.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "boot-relocate.h"
#include "cpu-release.h"

static unsigned long checks;
#define CHECK(x) do { checks++; if (!(x)) { \
    fprintf(stderr, "%s:%d: CHECK(%s) failed\n", __FILE__, __LINE__, #x); exit(1); } } while (0)

/* --- the monitor's layout check ------------------------------------------ */
static int layout(uint64_t boot, uint64_t mask, const uint64_t a[6], const uint64_t r[6])
{
    return boot_relocate_layout_valid(boot, mask, a, r);
}
static void test_layout(void)
{
    const uint64_t gicr = 0x17080000, s = 0x40000;
    /* The A16: cluster 0 is GICR 0..5, cluster 1 GICR 6..11, cluster 2 GICR 12..17. */
    uint64_t prime[6] = {0x10000, 0x10100, 0x10200, 0x10300, 0x10400, 0x10500};
    uint64_t prime_r[6] = {gicr + 6*s, gicr + 7*s, gicr + 8*s, gicr + 9*s, gicr + 10*s, gicr + 11*s};
    CHECK(layout(0, 0x3f, prime, prime_r));
    CHECK(layout(0, 0x01, prime, prime_r));          /* vCPU 0 alone */
    CHECK(layout(0, 0x07, prime, prime_r));
    /* Without bit 0 the existing per-secondary checks decide; this adds nothing. */
    uint64_t zero[6] = {0}, zero_r[6] = {0};
    CHECK(layout(0, 0x3e, zero, zero_r));
    /* The target cannot be q1n1's CPU. */
    uint64_t a[6], r[6];
    memcpy(a, prime, sizeof a); memcpy(r, prime_r, sizeof r);
    CHECK(!layout(0x10000, 0x3f, a, r));
    /* Malformed affinity: MT/U/RES1 bits or Aff3's neighbours. */
    for (uint64_t bad = 1; bad; bad <<= 1) {
        if (bad & BOOT_RELOCATE_AFFINITY) continue;
        a[0] = prime[0] | bad;
        CHECK(!layout(0, 0x3f, a, r));
    }
    a[0] = prime[0];
    /* Redistributor: out of range, misaligned, or a secondary's. */
    const uint64_t bad_r[] = {0, gicr - s, 0x17500000, gicr + 1, gicr + s / 2, prime_r[3]};
    for (unsigned i = 0; i < sizeof bad_r / sizeof bad_r[0]; i++) {
        r[0] = bad_r[i];
        CHECK(!layout(0, 0x3f, a, r));
        CHECK(layout(0, 0x37, a, r) == (bad_r[i] == prime_r[3]));   /* slot 3 disabled */
    }
    r[0] = prime_r[0];
    /* A secondary on the target's CPU, or in any other cluster. */
    for (unsigned slot = 1; slot < 6; slot++) {
        uint64_t keep = a[slot], keep_r = r[slot];
        a[slot] = prime[0];
        CHECK(!layout(0, 0x3f, a, r));
        CHECK(layout(0, 0x3f & ~(1u << slot), a, r));
        const uint64_t other[] = {slot * 0x100, 0x20000 + slot * 0x100, 0x100010000 + slot * 0x100};
        for (unsigned k = 0; k < 3; k++) {
            a[slot] = other[k];
            r[slot] = gicr + (k == 1 ? 12 + slot : slot) * s;
            CHECK(!layout(0, 0x3f, a, r));
            CHECK(layout(0, 0x3f & ~(1u << slot), a, r));
        }
        a[slot] = keep; r[slot] = keep_r;
    }
    CHECK(layout(0, 0x3f, a, r));
}

/* --- ID registers ------------------------------------------------------------ */
static void test_ids(void)
{
    /* The rows the shared preparation relies on, named independently of the table. */
    const unsigned shared[] = {BOOT_ID_ID_AA64PFR0_EL1, BOOT_ID_ID_AA64PFR1_EL1, BOOT_ID_ID_AA64ISAR0_EL1,
                               BOOT_ID_ID_AA64ISAR1_EL1, BOOT_ID_ID_AA64ISAR2_EL1, BOOT_ID_ID_AA64MMFR0_EL1};
    CHECK(BOOT_ID_COUNT == 10 && BOOT_ID_MIDR_EL1 == 0);
    uint64_t boot[BOOT_ID_COUNT], target[BOOT_ID_COUNT];
    for (unsigned n = 0; n < BOOT_ID_COUNT; n++) boot[n] = target[n] = 0x1111111111111111ull * (n + 1);
    CHECK(!boot_relocate_id_mismatch(boot, target));
    /* MIDR, DFR0, MMFR1 and MMFR2: evidence only (Prime and Performance MIDRs differ). */
    for (unsigned n = 0; n < BOOT_ID_COUNT; n++) {
        uint64_t keep = target[n];
        int is_shared = 0;
        for (unsigned k = 0; k < sizeof shared / sizeof shared[0]; k++) is_shared |= shared[k] == n;
        for (unsigned bit = 0; bit < 64; bit += 7) {
            target[n] = keep ^ (1ull << bit);
            CHECK(boot_relocate_id_mismatch(boot, target) == (is_shared ? 1ull << n : 0));
        }
        target[n] = keep;
    }
    target[BOOT_ID_ID_AA64PFR1_EL1] ^= 2; target[BOOT_ID_ID_AA64MMFR0_EL1] ^= 4;
    CHECK(boot_relocate_id_mismatch(boot, target) ==
          ((1ull << BOOT_ID_ID_AA64PFR1_EL1) | (1ull << BOOT_ID_ID_AA64MMFR0_EL1)));
}

/* --- releasing secondaries (compat/cpu-release.c, linked) ------------------- */
static unsigned launched[8], launches;
static int launch_ok(void *context, unsigned slot)
{
    (void)context;
    launched[launches++ % 8] = slot;
    return 1;
}
/* XNU's CPU start through ApplePMGR, as v50 and v51 issued it: the global core
 * mask at +4 (v51: value 0x2 for CPU 1), then the cluster register (+8 E-local
 * bits 0-3, +12 P-local bits 0-1). Returns how many writes were accepted. */
static unsigned start_all(struct guest_cpu_release *s, uint64_t allowed)
{
    unsigned accepted = 0;
    for (unsigned cpu = 1; cpu < 6; cpu++) {
        accepted += (unsigned)guest_cpu_release_write(s, allowed, 4, 4, 1u << cpu, launch_ok, 0);
        if (cpu < 4) accepted += (unsigned)guest_cpu_release_write(s, allowed, 8, 4, 1u << cpu, launch_ok, 0);
        else accepted += (unsigned)guest_cpu_release_write(s, allowed, 12, 4, 1u << (cpu - 4), launch_ok, 0);
    }
    return accepted;
}
static void test_release(void)
{
    const uint64_t prime = 0x3f, plain = 0x3e;   /* SNAP_SMP_PRIME=1's mask, and the default one */
    struct guest_cpu_release s = {0};
    /* v51: the relocation bit went into the release allowance; the first write was refused. */
    launches = 0;
    CHECK(!guest_cpu_release_write(&s, prime, 4, 4, 0x2, launch_ok, 0));
    CHECK(start_all(&s, prime) == 0 && !launches && !s.armed && !s.issued);
    /* The fix: the allowance never carries bit 0, for every mask the host can send. */
    for (uint64_t mask = 1; mask < 0x40; mask++) {
        uint64_t allowed = boot_relocate_release_mask(mask);
        CHECK(!(allowed & BOOT_RELOCATE_MASK) && (allowed | (mask & BOOT_RELOCATE_MASK)) == mask);
    }
    CHECK(boot_relocate_release_mask(plain) == plain);
    memset(&s, 0, sizeof s);
    launches = 0;
    CHECK(start_all(&s, boot_relocate_release_mask(prime)) == 10);
    CHECK(launches == 5 && s.armed == 0x3e && s.issued == 0x3e);
    for (unsigned n = 0; n < 5; n++) CHECK(launched[n] == n + 1);
    /* No second launch of a CPU, and the same sequence on the default mask (v50) is unchanged. */
    CHECK(!guest_cpu_release_write(&s, boot_relocate_release_mask(prime), 8, 4, 0x2, launch_ok, 0));
    struct guest_cpu_release v50 = {0};
    launches = 0;
    CHECK(start_all(&v50, plain) == 10 && launches == 5 && v50.armed == 0x3e && v50.issued == 0x3e);
    /* A partial relocation request (vCPU 0 and CPU 1 only) releases only CPU 1. */
    struct guest_cpu_release partial = {0};
    launches = 0;
    CHECK(start_all(&partial, boot_relocate_release_mask(0x3)) == 2 && launches == 1 && launched[0] == 1);
}

/* --- q1n1's CPU's decision ------------------------------------------------- */
static enum boot_wait_action oracle(uint64_t phase, int64_t off, uint64_t elapsed,
                                    uint64_t arrival, uint64_t session, int stopped)
{
    /* Written from the protocol, not from the header:
     *  - CPU_OFF came back (phase 5+): the CPU spins in monitor text forever;
     *  - finished (phase 4): only PSCI OFF proves CPU_OFF completed;
     *  - not arrived (phase 0): wait a full arrival window; then OFF means it
     *    left through early_off and cannot come back; anything else may still
     *    arrive, so close admission once and keep waiting;
     *  - running (1-3): ask once after the session window, else wait. */
    if (phase > 4) return BOOT_WAIT_QUARANTINE;
    if (phase == 4) return off == 1 ? BOOT_WAIT_HANDBACK : BOOT_WAIT_SERVE;
    if (phase == 0) {
        if (elapsed < arrival) return BOOT_WAIT_SERVE;
        if (off == 1) return BOOT_WAIT_HANDBACK;
        return stopped ? BOOT_WAIT_SERVE : BOOT_WAIT_STOP;
    }
    if (elapsed < session) return BOOT_WAIT_SERVE;
    return stopped ? BOOT_WAIT_SERVE : BOOT_WAIT_STOP;
}
static void test_wait(void)
{
    const uint64_t hz = 19200000, arrival = hz, session = 1860 * hz;
    const uint64_t launches[] = {0, 12345, UINT64_MAX - hz / 2};   /* the counter may wrap */
    const uint64_t elapsed[] = {0, 1, arrival - 1, arrival, arrival + 1, session - 1, session,
                                session + 1, UINT64_MAX / 2};
    const int64_t offs[] = {-9, -1, 0, 1, 2, 3};
    unsigned counts[4] = {0};
    for (uint64_t phase = 0; phase < 8; phase++)
        for (unsigned o = 0; o < sizeof offs / sizeof offs[0]; o++)
            for (unsigned e = 0; e < sizeof elapsed / sizeof elapsed[0]; e++)
                for (unsigned l = 0; l < 3; l++)
                    for (int stopped = 0; stopped < 2; stopped++) {
                        struct boot_wait w = {.phase = phase, .off = offs[o],
                            .now = launches[l] + elapsed[e], .launched = launches[l],
                            .arrival = arrival, .session = session, .stopped = stopped};
                        enum boot_wait_action got = boot_relocate_wait(&w);
                        CHECK(got == oracle(phase, offs[o], elapsed[e], arrival, session, stopped));
                        counts[got]++;
                    }
    /* Named rows, the failure inventory's cases. */
    struct boot_wait w = {.arrival = arrival, .session = session};
    w.phase = 4; w.off = 0; CHECK(boot_relocate_wait(&w) == BOOT_WAIT_SERVE);       /* CPU_OFF pending */
    w.off = 1; CHECK(boot_relocate_wait(&w) == BOOT_WAIT_HANDBACK);
    w.phase = 5; CHECK(boot_relocate_wait(&w) == BOOT_WAIT_QUARANTINE);              /* CPU_OFF failed */
    w.phase = 0; w.off = 1; w.now = arrival - 1; CHECK(boot_relocate_wait(&w) == BOOT_WAIT_SERVE);
    w.now = arrival; CHECK(boot_relocate_wait(&w) == BOOT_WAIT_HANDBACK);           /* early_off */
    w.off = 2; CHECK(boot_relocate_wait(&w) == BOOT_WAIT_STOP);                      /* may arrive */
    w.stopped = 1; CHECK(boot_relocate_wait(&w) == BOOT_WAIT_SERVE);
    w.phase = 3; w.stopped = 0; w.now = session - 1; CHECK(boot_relocate_wait(&w) == BOOT_WAIT_SERVE);
    w.now = session; CHECK(boot_relocate_wait(&w) == BOOT_WAIT_STOP);                 /* stuck at EL2 */
    w.off = 1; CHECK(boot_relocate_wait(&w) == BOOT_WAIT_STOP);   /* running: OFF is never trusted */
    printf("wait grid: SERVE=%u STOP=%u HANDBACK=%u QUARANTINE=%u\n",
           counts[0], counts[1], counts[2], counts[3]);
    CHECK(counts[0] && counts[1] && counts[2] && counts[3]);
}

/* --- the relay, between two threads ----------------------------------------- */
static struct boot_relay relay;
static volatile int server_stop, server_delay_ms;
static uint64_t answer_of(uint64_t op, uint64_t a1, uint64_t a2, uint64_t a3)
{
    return op * 1000003u ^ a1 ^ (a2 << 7) ^ (a3 << 17);
}
static uint64_t service(uint64_t op, uint64_t a1, uint64_t a2, uint64_t a3)
{
    if (op == 2 && a1) {                              /* POLL: fill the latch */
        uint64_t *latch = (uint64_t *)(uintptr_t)a1;
        for (uint64_t n = 0; n < a2 / 8; n++) latch[n] = latch[n] * 3 + n;
    }
    return answer_of(op, a1, a2, a3);
}
static void *server(void *unused)
{
    (void)unused;
    uint64_t seen = 0;
    while (!__atomic_load_n(&server_stop, __ATOMIC_ACQUIRE)) {
        uint64_t ticket;
        if (!boot_relay_take(&relay, &ticket)) { sched_yield(); continue; }
        if (ticket != seen + 1) { fprintf(stderr, "ticket %llu after %llu\n",
            (unsigned long long)ticket, (unsigned long long)seen); exit(1); }
        seen = ticket;
        int delay = __atomic_load_n(&server_delay_ms, __ATOMIC_ACQUIRE);
        if (delay) { struct timespec t = {0, delay * 1000000L}; nanosleep(&t, 0); }
        uint64_t result = service(relay.op, relay.a1, relay.a2, relay.a3);
        __atomic_fetch_add(&relay.served, 1, __ATOMIC_RELAXED);
        boot_relay_answer(&relay, ticket, result);
    }
    return 0;
}
/* The monitor's client (boot_relay_call) with a host clock. */
static uint64_t call(uint64_t op, uint64_t a1, uint64_t a2, uint64_t a3, unsigned timeout_ms)
{
    int latch = op == 2;
    uint64_t *caller = (uint64_t *)(uintptr_t)a1;
    if (!boot_relay_idle(&relay)) return BOOT_RELAY_FAILED;
    if (latch) for (uint64_t n = 0; n < a2 / 8; n++) relay.buffer[n] = caller[n];
    uint64_t ticket, result;
    if (!boot_relay_post(&relay, op, latch ? (uintptr_t)relay.buffer : a1, a2, a3, &ticket))
        return BOOT_RELAY_FAILED;
    struct timespec start, now;
    clock_gettime(CLOCK_MONOTONIC, &start);
    while (!boot_relay_answered(&relay, ticket, &result)) {
        clock_gettime(CLOCK_MONOTONIC, &now);
        if ((now.tv_sec - start.tv_sec) * 1000 + (now.tv_nsec - start.tv_nsec) / 1000000 >= timeout_ms) {
            __atomic_store_n(&relay.abandoned, 1, __ATOMIC_RELEASE);
            return BOOT_RELAY_FAILED;
        }
        sched_yield();
    }
    if (latch) for (uint64_t n = 0; n < a2 / 8; n++) caller[n] = relay.buffer[n];
    return result;
}
static void test_relay(void)
{
    pthread_t t;
    CHECK(!pthread_create(&t, 0, server, 0));
    for (uint64_t i = 1; i <= 20000; i++) {
        uint64_t op = 1 + i % 3, latch[14] = {0};
        for (unsigned n = 0; n < 14; n++) latch[n] = i + n;
        uint64_t a1 = op == 2 ? (uintptr_t)latch : i, a2 = op == 2 ? sizeof latch : i & 7, a3 = i * 5;
        uint64_t expect = answer_of(op, op == 2 ? (uintptr_t)relay.buffer : a1, a2, a3);
        CHECK(call(op, a1, a2, a3, 10000) == expect);
        if (op == 2) for (unsigned n = 0; n < 14; n++) CHECK(latch[n] == (i + n) * 3 + n);
    }
    CHECK(__atomic_load_n(&relay.served, __ATOMIC_RELAXED) == 20000 && relay.request == 20000 &&
          __atomic_load_n(&relay.done, __ATOMIC_ACQUIRE) == 20000);
    /* A slow server: the caller gives up, later posts are refused, and the late
     * answer lands only in the relay page (the caller's latch is untouched). */
    __atomic_store_n(&server_delay_ms, 200, __ATOMIC_RELEASE);
    uint64_t latch[14];
    for (unsigned n = 0; n < 14; n++) latch[n] = 7;
    CHECK(call(2, (uintptr_t)latch, sizeof latch, 0, 20) == BOOT_RELAY_FAILED);
    CHECK(__atomic_load_n(&relay.abandoned, __ATOMIC_RELAXED));
    uint64_t ticket;
    CHECK(!boot_relay_post(&relay, 1, 0, 0, 0, &ticket));
    struct timespec wait = {0, 400 * 1000000L};
    nanosleep(&wait, 0);
    CHECK(__atomic_load_n(&relay.done, __ATOMIC_ACQUIRE) == relay.request &&
          __atomic_load_n(&relay.served, __ATOMIC_RELAXED) == 20001);
    for (unsigned n = 0; n < 14; n++) CHECK(latch[n] == 7);
    CHECK(!boot_relay_post(&relay, 1, 0, 0, 0, &ticket));
    __atomic_store_n(&server_stop, 1, __ATOMIC_RELEASE);
    CHECK(!pthread_join(t, 0));
    /* Single-threaded protocol edges. */
    struct boot_relay q;
    memset(&q, 0, sizeof q);
    CHECK(!boot_relay_take(&q, &ticket));
    CHECK(boot_relay_post(&q, 3, 1, 2, 3, &ticket) && ticket == 1);
    uint64_t second;
    CHECK(!boot_relay_post(&q, 3, 1, 2, 3, &second));     /* one slot */
    uint64_t result;
    CHECK(!boot_relay_answered(&q, ticket, &result));
    uint64_t taken;
    CHECK(boot_relay_take(&q, &taken) && taken == 1 && q.op == 3 && q.a3 == 3);
    boot_relay_answer(&q, taken, 99);
    CHECK(!boot_relay_take(&q, &taken));
    CHECK(boot_relay_answered(&q, ticket, &result) && result == 99);
    CHECK(!boot_relay_answered(&q, ticket + 1, &result));
    CHECK(boot_relay_post(&q, 1, 0, 0, 0, &ticket) && ticket == 2);
}

int main(void)
{
    test_layout();
    test_ids();
    test_release();
    test_wait();
    test_relay();
    printf("%lu checks\nPASS\n", checks);
    return 0;
}

/* SPDX-License-Identifier: MIT */
/* The plug-in's UBO staging-arena pool policy (gpu/adreno-kext/plugin/AdrenoMetal/AdrenoStagingPolicy.h), on the host.
 *
 * The policy is pure C: no lock, no Metal, no clock; the plug-in calls it under its lock with its own time and releases
 * the victims after unlocking. Failure modes and their tests: docs/PLUGIN-ARENA-TRIM-20261021.md (A1-A19); this file is
 * the U column: size classes, LIFO takes of the exact class and device, duplicate puts, the idle trim (300 ms), the idle
 * cap (16 MiB older than 100 ms), the hot cap (96 MiB), the slot limit, the pressure drain and its window, time that
 * runs backwards, a randomized ownership model (every pooled item comes back exactly once, a taken item never comes back
 * from a trim), and the steady-state frame model (no new arenas at 60 fps with up to 3 frames in flight).
 *
 *     xcrun clang -std=c11 -O1 -Wall -Wextra -Werror -o OUT/test-adreno-staging-pool tools/test-adreno-staging-pool.c && OUT/test-adreno-staging-pool
 */
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../gpu/adreno-kext/plugin/AdrenoMetal/AdrenoStagingPolicy.h"

#define KiB(n) ((uint64_t)(n) << 10)
#define MiB(n) ((uint64_t)(n) << 20)
#define MS(n) ((uint64_t)(n) * 1000000ull)

static unsigned checks, failures;
#define CHECK(cond, ...) do { checks++; if (!(cond)) { failures++; printf("FAIL %s:%d: ", __FILE__, __LINE__); \
    printf(__VA_ARGS__); printf("\n"); } } while (0)

/* Items: each knows how many references the pool holds (0 or 1) and how often it came back. */
typedef struct { int id; int pooled; int returned; uint64_t bytes; } Item;
static Item items[4096];
static int nitems;
static Item *fresh(uint64_t bytes) { Item *i = &items[nitems]; *i = (Item){nitems, 0, 0, bytes}; nitems++; return i; }

static AdrenoStagingLimits defaults(void) { return adreno_staging_default_limits(); }

static int victims_contain(const AdrenoStagingVictims *v, const void *item) {
    for (unsigned i = 0; i < v->count; i++) if (v->item[i] == item) return 1;
    return 0;
}
/* Invariants after every operation (A3, A5, A6). */
static void invariants(const AdrenoStagingPool *p, const char *what) {
    uint64_t sum = 0;
    for (unsigned i = 0; i < p->count; i++) {
        sum += p->entry[i].bytes;
        if (i) CHECK(p->entry[i - 1].since <= p->entry[i].since, "%s: entries out of age order at %u", what, i);
        CHECK(adreno_staging_poolable(p->entry[i].bytes), "%s: unpoolable entry of %" PRIu64 " bytes", what, p->entry[i].bytes);
        for (unsigned j = 0; j < i; j++) CHECK(p->entry[j].item != p->entry[i].item, "%s: item pooled twice", what);
    }
    CHECK(p->count <= ADRENO_STAGING_SLOTS, "%s: %u entries", what, p->count);
    CHECK(sum == p->bytes, "%s: bytes %" PRIu64 " != sum %" PRIu64, what, p->bytes, sum);
}
/* After a trim at `now`: no entry is older than idle, the idle prefix fits the idle cap, the pool fits the hot cap. */
static void trimmed(const AdrenoStagingPool *p, uint64_t now, const char *what) {
    uint64_t idle = 0;
    for (unsigned i = 0; i < p->count; i++) {
        uint64_t age = now - p->entry[i].since;
        CHECK(age < p->limits.idleNs, "%s: entry %u aged %" PRIu64 " ns survived the trim", what, i, age);
        if (age >= p->limits.hotNs) idle += p->entry[i].bytes;
    }
    CHECK(idle <= p->limits.idleMax, "%s: %" PRIu64 " idle bytes over the idle cap", what, idle);
    CHECK(p->bytes <= p->limits.hotMax, "%s: %" PRIu64 " bytes over the hot cap", what, p->bytes);
}

static void test_classes(void) {
    struct { uint64_t need, previous, want; } cases[] = {
        {0, 0, KiB(64)}, {1, 0, KiB(64)}, {KiB(64), 0, KiB(64)}, {KiB(64) + 1, 0, KiB(256)}, {KiB(256), 0, KiB(256)},
        {KiB(256) + 64, 0, MiB(1)}, {261856, 0, KiB(256)}, {524272, 0, MiB(1)}, {MiB(1), 0, MiB(1)},
        {16, KiB(64), KiB(256)}, {16, KiB(256), MiB(1)}, {16, MiB(1), MiB(1)}, {KiB(300), KiB(64), MiB(1)},
        {16, MiB(2), MiB(1)}, {16, KiB(16), KiB(64)},
        {MiB(1) + 1, 0, MiB(1) + KiB(16)}, {MiB(1) + KiB(20), KiB(64), MiB(1) + KiB(32)},
    };
    for (unsigned i = 0; i < sizeof cases / sizeof *cases; i++) {
        uint64_t got = adreno_staging_class(cases[i].need, cases[i].previous);
        CHECK(got == cases[i].want, "class(need %" PRIu64 ", previous %" PRIu64 ") = %" PRIu64 ", want %" PRIu64,
              cases[i].need, cases[i].previous, got, cases[i].want);
        CHECK(got >= ((cases[i].need + 63) & ~63ull), "class %" PRIu64 " below the 64-byte aligned need", got);
        CHECK(!(got & (KiB(16) - 1)), "class %" PRIu64 " not a whole number of 16 KiB pages", got);
    }
    for (uint64_t need = 0; need <= MiB(2); need += 4096 + 48) {
        uint64_t prev[] = {0, KiB(64), KiB(256), MiB(1)};
        for (unsigned k = 0; k < 4; k++) {
            uint64_t got = adreno_staging_class(need, prev[k]);
            CHECK(got >= ((need + 63) & ~63ull) && (need > MiB(1) || adreno_staging_poolable(got)),
                  "class(%" PRIu64 ", %" PRIu64 ") = %" PRIu64, need, prev[k], got);
            CHECK(!prev[k] || got >= (prev[k] * 4 < MiB(1) ? prev[k] * 4 : MiB(1)), "no growth after %" PRIu64, prev[k]);
        }
    }
    CHECK(adreno_staging_poolable(KiB(64)) && adreno_staging_poolable(KiB(256)) && adreno_staging_poolable(MiB(1)),
          "class sizes are poolable");
    CHECK(!adreno_staging_poolable(0) && !adreno_staging_poolable(KiB(128)) && !adreno_staging_poolable(MiB(2)) &&
          !adreno_staging_poolable(MiB(1) + KiB(16)), "other sizes are not poolable");
}

static void test_lifo_owner_class(void) {
    AdrenoStagingPool p; adreno_staging_init(&p, defaults());
    AdrenoStagingVictims v = {0};
    int X = 0, Y = 0;
    Item *a = fresh(MiB(1)), *b = fresh(MiB(1)), *c = fresh(KiB(256)), *d = fresh(MiB(1));
    CHECK(adreno_staging_put(&p, a, &X, MiB(1), MS(0), &v) == 1, "put a");
    CHECK(adreno_staging_put(&p, b, &X, MiB(1), MS(1), &v) == 1, "put b");
    CHECK(adreno_staging_put(&p, c, &X, KiB(256), MS(2), &v) == 1, "put c");
    CHECK(adreno_staging_put(&p, d, &Y, MiB(1), MS(3), &v) == 1, "put d");
    CHECK(v.count == 0, "no victims (%u)", v.count);
    invariants(&p, "lifo");
    CHECK(adreno_staging_take(&p, &X, MiB(1), MS(4)) == b, "LIFO: the most recent 1 MiB arena of X first");
    CHECK(adreno_staging_take(&p, &X, MiB(1), MS(4)) == a, "then the older one");
    CHECK(adreno_staging_take(&p, &X, MiB(1), MS(4)) == NULL, "X has no third 1 MiB arena (Y's is not X's)");
    CHECK(adreno_staging_take(&p, &X, KiB(64), MS(4)) == NULL, "no 64 KiB arena: no other class is handed out");
    CHECK(adreno_staging_take(&p, &X, KiB(256), MS(4)) == c, "the 256 KiB arena of X");
    CHECK(adreno_staging_take(&p, &Y, MiB(1), MS(4)) == d, "Y's arena");
    CHECK(p.count == 0 && p.bytes == 0, "empty after the takes");
    CHECK(p.takes == 4, "takes counted (%" PRIu64 ")", p.takes);
    invariants(&p, "lifo end");
}

static void test_duplicate_and_unpoolable(void) {
    AdrenoStagingPool p; adreno_staging_init(&p, defaults());
    AdrenoStagingVictims v = {0};
    int X = 0;
    Item *a = fresh(MiB(1)), *big = fresh(MiB(2));
    CHECK(adreno_staging_put(&p, a, &X, MiB(1), MS(0), &v) == 1, "put a");
    CHECK(adreno_staging_put(&p, a, &X, MiB(1), MS(1), &v) == 0, "a second put of a is refused");
    CHECK(v.count == 1 && v.item[0] == a, "the refused put comes back as a victim (the caller's reference)");
    CHECK(p.count == 1 && p.bytes == MiB(1), "still one entry");
    v.count = 0;
    CHECK(adreno_staging_put(&p, big, &X, MiB(2), MS(1), &v) == 0 && v.count == 1 && v.item[0] == big,
          "an unpoolable size is refused and returned");
    v.count = 0;
    CHECK(adreno_staging_put(&p, NULL, &X, MiB(1), MS(1), &v) == 0 && v.count == 0, "NULL is ignored");
    invariants(&p, "duplicate");
}

static void test_idle_trim(void) {
    AdrenoStagingPool p; adreno_staging_init(&p, defaults());
    AdrenoStagingVictims v = {0};
    int X = 0; Item *it[5];
    for (int i = 0; i < 5; i++) { it[i] = fresh(MiB(1)); adreno_staging_put(&p, it[i], &X, MiB(1), MS(0), &v); }
    adreno_staging_trim(&p, MS(299), &v);
    CHECK(v.count == 0 && p.count == 5, "nothing released before 300 ms (%u victims)", v.count);
    trimmed(&p, MS(299), "idle 299");
    adreno_staging_trim(&p, MS(300), &v);
    CHECK(v.count == 5 && p.count == 0 && p.bytes == 0, "everything released at 300 ms idle (%u)", v.count);
    for (int i = 0; i < 5; i++) CHECK(victims_contain(&v, it[i]), "victim %d", i);
    CHECK(p.aged == 5, "aged counted (%" PRIu64 ")", p.aged);
    CHECK(!adreno_staging_wants_timer(&p), "an empty pool needs no timer");
}

static void test_idle_cap(void) {
    AdrenoStagingPool p; adreno_staging_init(&p, defaults());
    AdrenoStagingVictims v = {0};
    int X = 0; Item *it[20];
    for (int i = 0; i < 20; i++) { it[i] = fresh(MiB(1)); adreno_staging_put(&p, it[i], &X, MiB(1), MS(i), &v); }
    CHECK(v.count == 0 && adreno_staging_wants_timer(&p), "20 hot arenas kept, timer wanted");
    adreno_staging_trim(&p, MS(50), &v);
    CHECK(v.count == 0, "all hot at 50 ms");
    adreno_staging_trim(&p, MS(110), &v);
    CHECK(v.count == 0, "11 idle MiB fit the 16 MiB idle cap at 110 ms (%u)", v.count);
    adreno_staging_trim(&p, MS(119), &v);
    CHECK(v.count == 4 && p.count == 16, "20 idle MiB at 119 ms: the 4 oldest go (%u victims, %u left)", v.count, p.count);
    for (int i = 0; i < 4; i++) CHECK(v.item[i] == it[i], "oldest first: victim %d", i);
    trimmed(&p, MS(119), "idle cap");
    CHECK(p.capped == 4, "capped counted");
    /* A take of a hot arena while idle ones exist: LIFO still takes the newest. */
    CHECK(adreno_staging_take(&p, &X, MiB(1), MS(120)) == it[19], "LIFO after the cap");
}

static void test_hot_cap_and_slots(void) {
    AdrenoStagingPool p; adreno_staging_init(&p, defaults());
    AdrenoStagingVictims v = {0};
    int X = 0; Item *it[100];
    for (int i = 0; i < 100; i++) { it[i] = fresh(MiB(1)); adreno_staging_put(&p, it[i], &X, MiB(1), MS(0), &v); }
    CHECK(p.count == 96 && p.bytes == MiB(96), "96 MiB hot cap (%u entries)", p.count);
    CHECK(v.count == 4 && v.item[0] == it[0] && v.item[3] == it[3], "the 4 oldest went (%u)", v.count);
    invariants(&p, "hot cap");
    AdrenoStagingLimits l = defaults(); l.hotMax = MiB(1024); l.idleMax = MiB(1024);
    adreno_staging_init(&p, l); v.count = 0;
    Item *s[300];
    for (int i = 0; i < 300; i++) { s[i] = fresh(KiB(64)); adreno_staging_put(&p, s[i], &X, KiB(64), MS(0), &v); }
    CHECK(p.count == ADRENO_STAGING_SLOTS && v.count == 300 - ADRENO_STAGING_SLOTS, "slot limit %u (%u victims)",
          p.count, v.count);
    CHECK(v.item[0] == s[0] && !victims_contain(&v, s[299]), "slots: oldest evicted, newest kept");
    invariants(&p, "slots");
}

static void test_pressure(void) {
    AdrenoStagingPool p; adreno_staging_init(&p, defaults());
    AdrenoStagingVictims v = {0};
    int X = 0; Item *it[10];
    for (int i = 0; i < 10; i++) { it[i] = fresh(KiB(256)); adreno_staging_put(&p, it[i], &X, KiB(256), MS(10), &v); }
    uint64_t released = adreno_staging_drain(&p, MS(20), &v);
    CHECK(released == KiB(2560) && v.count == 10 && p.count == 0 && p.bytes == 0, "drain returns everything (%u)", v.count);
    CHECK(p.drains == 1 && p.drained == 10, "drain counted");
    v.count = 0;
    Item *a = fresh(KiB(256)), *b = fresh(KiB(256));
    CHECK(adreno_staging_put(&p, a, &X, KiB(256), MS(20) + p.limits.pressureNs - 1, &v) == 0 && v.count == 1,
          "a put inside the pressure window is refused");
    CHECK(adreno_staging_put(&p, b, &X, KiB(256), MS(20) + p.limits.pressureNs, &v) == 1, "pooling resumes after it");
    CHECK(adreno_staging_drain(&p, MS(1000), &v) == KiB(256), "a second drain");
    CHECK(adreno_staging_drain(&p, MS(1001), &v) == 0, "a drain of an empty pool releases nothing");
    CHECK(p.pressureUntil == MS(1001) + p.limits.pressureNs, "every drain extends the window");
    invariants(&p, "pressure");
}

static void test_time_backwards(void) {
    AdrenoStagingPool p; adreno_staging_init(&p, defaults());
    AdrenoStagingVictims v = {0};
    int X = 0; Item *a = fresh(MiB(1)), *b = fresh(MiB(1));
    adreno_staging_put(&p, a, &X, MiB(1), MS(100), &v);
    adreno_staging_put(&p, b, &X, MiB(1), MS(50), &v);         /* another thread's older clock read */
    invariants(&p, "backwards");
    CHECK(p.entry[1].since == MS(100), "a time that runs backwards is clamped (%" PRIu64 ")", p.entry[1].since);
    adreno_staging_trim(&p, MS(80), &v);                        /* also clamped: nothing is negative-aged */
    CHECK(v.count == 0, "trim at an older time releases nothing");
    adreno_staging_trim(&p, MS(399), &v);
    CHECK(v.count == 0, "299 ms after the clamped time: kept");
    adreno_staging_trim(&p, MS(400), &v);
    CHECK(v.count == 2, "300 ms after: both released");
}

/* Randomized ownership model (A1, A2, A3): the set of items the pool owns is tracked beside it; every take and every
 * victim must be owned at that moment, and leaves the set; refused puts come straight back. */
static uint64_t rng = 0x9e3779b97f4a7c15ull;
static uint64_t next(void) { rng ^= rng << 13; rng ^= rng >> 7; rng ^= rng << 17; return rng; }
static void test_model(void) {
    AdrenoStagingLimits l = defaults();
    l.hotMax = MiB(24); l.idleMax = MiB(4);                      /* small caps so every rule fires often */
    AdrenoStagingPool p; adreno_staging_init(&p, l);
    int owners[2] = {0, 0};
    const uint64_t sizes[] = {KiB(64), KiB(256), MiB(1)};
    Item *outside[512]; int nout = 0;                             /* items the caller holds (taken or new) */
    uint64_t now = 0; unsigned ops = 0, takes = 0, puts = 0, victimsSeen = 0;
    for (int step = 0; step < 200000; step++) {
        now += next() % MS(30);
        if (next() % 97 == 0 && now > MS(5)) now -= MS(5);       /* a racing thread's clock */
        AdrenoStagingVictims v = {0};
        unsigned op = next() % 100;
        if (op < 45) {                                           /* put: a held item, or a new one */
            Item *it;
            if (nout && next() % 3) { int k = (int)(next() % (unsigned)nout); it = outside[k]; outside[k] = outside[--nout]; }
            else {
                if (nitems >= 4000) continue;
                it = fresh(sizes[next() % 3]);
            }
            CHECK(!it->pooled, "model: putting an item the pool owns");
            int got = adreno_staging_put(&p, it, &owners[it->id & 1], it->bytes, now, &v);
            it->pooled = 1; puts++;
            (void)got;
        } else if (op < 85) {                                    /* take */
            const void *owner = &owners[next() & 1];
            uint64_t bytes = sizes[next() % 3];
            Item *it = adreno_staging_take(&p, owner, bytes, now);
            if (it) {
                CHECK(it->pooled, "model: take returned an item the pool does not own");
                CHECK(it->bytes == bytes && &owners[it->id & 1] == owner, "model: take of the wrong class or owner");
                it->pooled = 0; it->returned++; takes++;
                if (nout < 512) outside[nout++] = it;
            }
        } else if (op < 98) {
            adreno_staging_trim(&p, now, &v);
            if (now >= p.last) trimmed(&p, now, "model trim");
        } else {
            adreno_staging_drain(&p, now, &v);
        }
        for (unsigned i = 0; i < v.count; i++) {
            Item *it = v.item[i];
            CHECK(it->pooled, "model: a victim the pool did not own (released twice)");
            CHECK(v.bytes[i] == it->bytes, "model: victim bytes");
            it->pooled = 0; it->returned++; victimsSeen++;
        }
        invariants(&p, "model");
        ops++;
        if (failures > 20) break;
    }
    AdrenoStagingVictims v = {0};
    adreno_staging_drain(&p, now, &v);
    for (unsigned i = 0; i < v.count; i++) { Item *it = v.item[i]; CHECK(it->pooled, "final drain"); it->pooled = 0; it->returned++; }
    for (int i = 0; i < nitems; i++) CHECK(!items[i].pooled, "item %d still owned after the final drain", i);
    printf("model: %u ops, %u puts, %u takes, %u victims, %" PRIu64 " aged, %" PRIu64 " capped, %" PRIu64 " drained\n",
           ops, puts, takes, victimsSeen, p.aged, p.capped, p.drained);
    CHECK(p.aged && p.capped && p.drained && takes, "every rule fired in the model");
}

/* Steady state (A5): every frame takes `per` arenas (allocating what the pool lacks); the GPU completes frame f at
 * f * frameNs + lag * 16 ms (its arenas return to the pool then); the timer trims every 100 ms. Events run in time
 * order before each frame's takes. Count new arenas after the first `warm` frames. */
static unsigned steady(uint64_t frameNs, unsigned per, unsigned lag, unsigned frames, unsigned warm, uint64_t *heldMax) {
    AdrenoStagingPool p; adreno_staging_init(&p, defaults());
    int X = 0;
    Item *flight[64][256] = {{0}};
    unsigned created = 0, done = 0; uint64_t now = 0, tick = MS(100);
    *heldMax = 0;
    nitems = 0;
    for (unsigned f = 0; f < frames; f++, now += frameNs) {
        AdrenoStagingVictims v = {0};
        for (;;) {                                               /* completions and timer ticks up to now, in order */
            uint64_t completion = done < f ? (uint64_t)done * frameNs + lag * MS(16) : UINT64_MAX;
            if (completion > now && tick > now) break;
            if (completion <= tick) {
                for (unsigned i = 0; i < per; i++) adreno_staging_put(&p, flight[done % 64][i], &X, MiB(1), completion, &v);
                done++;
            } else { adreno_staging_trim(&p, tick, &v); tick += MS(100); }
        }
        if (f - done >= 63) { printf("steady: more than 63 frames in flight\n"); failures++; return 0; }
        for (unsigned i = 0; i < per; i++) {
            Item *it = adreno_staging_take(&p, &X, MiB(1), now);
            if (!it) { it = fresh(MiB(1)); if (f >= warm) created++; if (nitems >= 4000) nitems = 0; }
            flight[f % 64][i] = it;
        }
        uint64_t held = p.bytes + (uint64_t)per * (f + 1 - done) * MiB(1);
        if (held > *heldMax) *heldMax = held;
    }
    return created;
}
static void test_steady_state(void) {
    uint64_t held;
    CHECK(steady(MS(16), 24, 1, 600, 10, &held) == 0, "60 fps, 24 arenas per frame, 1 in flight: no new arenas");
    CHECK(steady(MS(16), 24, 3, 600, 10, &held) == 0, "60 fps, 3 in flight: no new arenas");
    CHECK(steady(MS(16), 74, 3, 600, 10, &held) == 0, "60 fps, 74 arenas per frame (scroll-list): no new arenas");
    CHECK(steady(MS(33), 47, 2, 300, 10, &held) == 0, "30 fps, 47 per frame (blurfull), 2 in flight: no new arenas");
    CHECK(steady(MS(50), 24, 3, 200, 10, &held) == 0, "20 fps, 24 per frame: no new arenas");
    unsigned slow = steady(MS(200), 24, 1, 50, 5, &held);
    CHECK(slow > 0, "5 fps: arenas idle between frames are capped (%u new)", slow);
    unsigned rare = steady(MS(1000), 24, 1, 20, 2, &held);
    CHECK(rare == 24 * 18, "1 fps: every arena is released between frames (%u new)", rare);
    printf("steady: 5 fps with 24 arenas per frame allocates %u arenas in 45 frames; 1 fps allocates %u in 18\n", slow, rare);
}

int main(void) {
    test_classes();
    test_lifo_owner_class();
    test_duplicate_and_unpoolable();
    test_idle_trim();
    test_idle_cap();
    test_hot_cap_and_slots();
    test_pressure();
    test_time_backwards();
    nitems = 0;
    test_model();
    test_steady_state();
    if (failures) { printf("FAIL: %u of %u checks\n", failures, checks); return 1; }
    printf("PASS: %u checks\n", checks);
    return 0;
}

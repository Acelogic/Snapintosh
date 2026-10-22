/* SPDX-License-Identifier: MIT */
// UBO staging-arena pool policy (docs/PLUGIN-ARENA-TRIM-20261021.md, failure modes A1-A19). Pure C: no lock, no Metal,
// no clock. The plug-in (AdrenoDrawCommands.m) calls it under its lock with its own monotonic time and releases the
// victims after unlocking; tools/test-adreno-staging-pool.c tests it on the host.
//
// Ownership: a pooled item is one +1 reference the pool owns. It leaves the pool exactly once: from a take (to the
// caller), or as a victim (an aged, capped, drained or refused item) that the caller releases after its unlock.
//
// Every GPU mapping of every process shares one 3 GiB GPU address window; an idle arena holds its address range. So:
//   - a process that renders keeps its working set: arenas returned within hotNs, up to hotMax bytes in all;
//   - arenas unused for hotNs are idle: at most idleMax bytes of them stay; idle for idleNs, they are released;
//   - a drain (memory pressure, a failed allocation) releases everything and refuses puts for pressureNs.
#ifndef ADRENO_STAGING_POLICY_H
#define ADRENO_STAGING_POLICY_H
#include <stdint.h>
#include <string.h>

#define ADRENO_STAGING_SLOTS 256u
#define ADRENO_STAGING_CLASS_MIN (64ull << 10)      // 64 KiB, 256 KiB, 1 MiB: each a whole number of 16 KiB pages
#define ADRENO_STAGING_CLASS_MAX (1ull << 20)
#define ADRENO_STAGING_PAGE (16ull << 10)

typedef struct {
    uint64_t hotMax;        // bytes the pool may hold in all (the working set of a rendering process)
    uint64_t idleMax;       // bytes of entries unused for at least hotNs (the idle cap)
    uint64_t hotNs;         // an entry this old is idle
    uint64_t idleNs;        // an entry this old is released
    uint64_t pressureNs;    // puts refused for this long after a drain
} AdrenoStagingLimits;

typedef struct {
    void *item;             // the pool's +1 reference
    const void *owner;      // the device the arena belongs to
    uint64_t bytes, since;  // its length; when it entered the pool (clamped monotonic ns)
} AdrenoStagingEntry;

typedef struct {
    AdrenoStagingEntry entry[ADRENO_STAGING_SLOTS];  // oldest first (since non-decreasing)
    unsigned count;
    uint64_t bytes;                                  // sum of entry bytes
    uint64_t last;                                   // the latest time seen: times never run backwards
    uint64_t pressureUntil;                          // puts before this time are refused
    AdrenoStagingLimits limits;
    uint64_t puts, pooled, refused, takes, aged, capped, drained, drains;
} AdrenoStagingPool;

typedef struct {
    void *item[ADRENO_STAGING_SLOTS + 1];
    uint64_t bytes[ADRENO_STAGING_SLOTS + 1];
    unsigned count;
} AdrenoStagingVictims;

static inline AdrenoStagingLimits adreno_staging_default_limits(void) {
    return (AdrenoStagingLimits){.hotMax = 96ull << 20, .idleMax = 16ull << 20, .hotNs = 100000000ull,
                                 .idleNs = 300000000ull, .pressureNs = 500000000ull};
}
static inline void adreno_staging_init(AdrenoStagingPool *p, AdrenoStagingLimits limits) {
    memset(p, 0, sizeof *p);
    p->limits = limits;
}
static inline int adreno_staging_poolable(uint64_t bytes) {
    return bytes == ADRENO_STAGING_CLASS_MIN || bytes == ADRENO_STAGING_CLASS_MIN * 4 || bytes == ADRENO_STAGING_CLASS_MAX;
}
// The arena length for a copy of `need` bytes when the chain's previous arena (0: none) is full: the smallest class
// that holds max(need, 4 x previous) (capped at 1 MiB); above 1 MiB, the 64-byte aligned need in whole pages (an arena
// of its own that is never pooled).
static inline uint64_t adreno_staging_class(uint64_t need, uint64_t previous) {
    uint64_t aligned = (need + 63) & ~63ull;
    if (aligned > ADRENO_STAGING_CLASS_MAX) return (aligned + ADRENO_STAGING_PAGE - 1) & ~(ADRENO_STAGING_PAGE - 1);
    uint64_t want = previous ? (previous >= ADRENO_STAGING_CLASS_MAX / 4 ? ADRENO_STAGING_CLASS_MAX : previous * 4) : 0;
    if (aligned > want) want = aligned;
    for (uint64_t c = ADRENO_STAGING_CLASS_MIN; c < ADRENO_STAGING_CLASS_MAX; c *= 4)
        if (want <= c) return c;
    return ADRENO_STAGING_CLASS_MAX;
}
static inline uint64_t adreno_staging_clock(AdrenoStagingPool *p, uint64_t now) {
    if (now > p->last) p->last = now;
    return p->last;
}
static inline void adreno_staging_victim(AdrenoStagingVictims *v, void *item, uint64_t bytes) {
    if (v->count < ADRENO_STAGING_SLOTS + 1) { v->item[v->count] = item; v->bytes[v->count] = bytes; v->count++; }
}
// Remove the k oldest entries into v.
static inline void adreno_staging_drop_front(AdrenoStagingPool *p, unsigned k, AdrenoStagingVictims *v) {
    if (!k) return;
    for (unsigned i = 0; i < k; i++) {
        adreno_staging_victim(v, p->entry[i].item, p->entry[i].bytes);
        p->bytes -= p->entry[i].bytes;
    }
    memmove(&p->entry[0], &p->entry[k], (p->count - k) * sizeof p->entry[0]);
    p->count -= k;
}
// Age, idle-cap and hot-cap rules, oldest entries first.
static inline void adreno_staging_trim(AdrenoStagingPool *p, uint64_t now, AdrenoStagingVictims *v) {
    now = adreno_staging_clock(p, now);
    unsigned k = 0;
    while (k < p->count && now - p->entry[k].since >= p->limits.idleNs) k++;
    p->aged += k;
    adreno_staging_drop_front(p, k, v);
    // The idle entries are a prefix (age order); keep at most idleMax bytes of them, the youngest.
    uint64_t idle = 0; unsigned n = 0;
    while (n < p->count && now - p->entry[n].since >= p->limits.hotNs) idle += p->entry[n++].bytes;
    k = 0;
    while (k < n && idle > p->limits.idleMax) idle -= p->entry[k++].bytes;
    uint64_t bytes = p->bytes;
    for (unsigned i = 0; i < k; i++) bytes -= p->entry[i].bytes;
    while (k < p->count && bytes > p->limits.hotMax) bytes -= p->entry[k++].bytes;
    p->capped += k;
    adreno_staging_drop_front(p, k, v);
}
// Pool `item` (the caller's +1 reference). 1: pooled (and still pooled after the trim this put runs); 0: refused, the
// item is in v (pressure window, unpoolable size, already pooled) or was trimmed at once.
static inline int adreno_staging_put(AdrenoStagingPool *p, void *item, const void *owner, uint64_t bytes, uint64_t now,
                                     AdrenoStagingVictims *v) {
    if (!item) return 0;
    now = adreno_staging_clock(p, now);
    p->puts++;
    int duplicate = 0;
    for (unsigned i = 0; i < p->count && !duplicate; i++) duplicate = p->entry[i].item == item;
    if (duplicate || !adreno_staging_poolable(bytes) || now < p->pressureUntil) {
        p->refused++;
        adreno_staging_victim(v, item, bytes);
        return 0;
    }
    if (p->count == ADRENO_STAGING_SLOTS) { p->capped++; adreno_staging_drop_front(p, 1, v); }
    p->entry[p->count++] = (AdrenoStagingEntry){item, owner, bytes, now};
    p->bytes += bytes;
    p->pooled++;
    adreno_staging_trim(p, now, v);
    return p->count && p->entry[p->count - 1].item == item;
}
// The most recently pooled entry of exactly this owner and length (LIFO keeps the working set warm), or NULL.
static inline void *adreno_staging_take(AdrenoStagingPool *p, const void *owner, uint64_t bytes, uint64_t now) {
    (void)adreno_staging_clock(p, now);
    for (unsigned i = p->count; i-- > 0;) {
        if (p->entry[i].owner != owner || p->entry[i].bytes != bytes) continue;
        void *item = p->entry[i].item;
        p->bytes -= bytes;
        memmove(&p->entry[i], &p->entry[i + 1], (p->count - i - 1) * sizeof p->entry[0]);
        p->count--;
        p->takes++;
        return item;
    }
    return NULL;
}
// Everything into v; puts refused for pressureNs. Returns the bytes released.
static inline uint64_t adreno_staging_drain(AdrenoStagingPool *p, uint64_t now, AdrenoStagingVictims *v) {
    now = adreno_staging_clock(p, now);
    uint64_t bytes = p->bytes;
    p->drained += p->count;
    p->drains++;
    adreno_staging_drop_front(p, p->count, v);
    p->pressureUntil = now + p->limits.pressureNs;
    return bytes;
}
static inline int adreno_staging_wants_timer(const AdrenoStagingPool *p) { return p->count != 0; }
#endif

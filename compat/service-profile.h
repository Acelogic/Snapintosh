/* SPDX-License-Identifier: MIT */
#pragma once
#include <stdint.h>

/* EC 0..63, followed by IRQ, FIQ, SError and secondary bootstrap. Each CPU
 * owns its record, including while waiting outside the shared service lock. */
#define SERVICE_PROFILE_BUCKETS 68
#define SERVICE_PROFILE_ASYNC 64
#define SERVICE_PROFILE_BOOT 67
struct service_profile_bucket { uint64_t entries, wait_ticks, hold_ticks; };
struct service_profile {
    uint64_t attempts, acquired, cancelled, contended;
    uint64_t wait_ticks, hold_ticks, max_wait_ticks, max_hold_ticks;
    uint64_t first_tick, last_tick, enter_tick, acquire_tick;
    uint64_t category, stage, errors;
    struct service_profile_bucket buckets[SERVICE_PROFILE_BUCKETS];
} __attribute__((aligned(64)));

static inline void service_profile_begin(struct service_profile *p,
                                         uint64_t now, unsigned category)
{
    if (p->stage || category >= SERVICE_PROFILE_BUCKETS) { p->errors++; return; }
    if (!p->attempts) p->first_tick = now;
    p->attempts++; p->buckets[category].entries++;
    p->category = category; p->enter_tick = p->last_tick = now; p->stage = 1;
}

static inline void service_profile_wait_done(struct service_profile *p,
                                             uint64_t now, int acquired,
                                             int contended)
{
    if (p->stage != 1) { p->errors++; return; }
    uint64_t ticks = now - p->enter_tick;
    p->wait_ticks += ticks; p->buckets[p->category].wait_ticks += ticks;
    if (ticks > p->max_wait_ticks) p->max_wait_ticks = ticks;
    p->contended += !!contended; p->last_tick = now;
    if (acquired) {
        p->acquired++; p->acquire_tick = now; p->stage = 2;
    } else { p->cancelled++; p->stage = 0; }
}

static inline void service_profile_end(struct service_profile *p, uint64_t now)
{
    if (p->stage != 2) { p->errors++; return; }
    uint64_t ticks = now - p->acquire_tick;
    p->hold_ticks += ticks; p->buckets[p->category].hold_ticks += ticks;
    if (ticks > p->max_hold_ticks) p->max_hold_ticks = ticks;
    p->last_tick = now; p->stage = 0;
}

/* SNAP_SERVICE_SUBCLASS (probes/xnuboot.c): the locked instruction aborts
 * (EC 0x20, the category holding most of the lock) split by what the handler
 * decoded each one to be. The handler tags its entry (service_sub_tag);
 * runtime_leave, after service_profile_end and before the release, charges
 * the entry's own wait and hold to that tag (service_sub_charge) and clears
 * it. The buckets are shared by every CPU and written only under the service
 * lock; current[cpu] is written only by that CPU, under the lock. Each
 * completed EC 0x20 entry lands in exactly one bucket, so over all CPUs the
 * buckets sum to buckets[0x20] of the per-CPU profiles: hold exactly, entries
 * and wait less only the acquisitions a stop cancelled (they never complete).
 * The bucket count is fixed so the host decoders need no build defines. */
#define SERVICE_SUB_CATEGORY 0x20u
enum service_sub {
    SERVICE_SUB_OTHER,          /* untagged: guard and call-page aborts, a vector step */
    SERVICE_SUB_VECTOR,         /* a vector-page entry continued into XNU (or stopped) */
    SERVICE_SUB_EL0_CLOCK,      /* user_sysreg_access: the ordered counter alias */
    SERVICE_SUB_EL0_UPERM,      /* user_sysreg_access: the SPRR_UPERM read */
    SERVICE_SUB_EL0_UPERM_WRITE,/* user_sysreg_access: the SPRR_UPERM write */
    SERVICE_SUB_CALL_OTHER,     /* a native call that is not an SPTM endpoint below 32 */
    SERVICE_SUB_ENDPOINT        /* + the SPTM endpoint number, 0..SERVICE_SUB_ENDPOINTS-1 */
};
#define SERVICE_SUB_ENDPOINTS 32u
#define SERVICE_SUB_BUCKETS (SERVICE_SUB_ENDPOINT + SERVICE_SUB_ENDPOINTS)
#define SERVICE_SUB_CPUS 8u
struct service_sub_profile {
    struct service_profile_bucket buckets[SERVICE_SUB_BUCKETS];
    uint8_t current[SERVICE_SUB_CPUS];   /* per CPU: its entry's tag so far */
} __attribute__((aligned(64)));

/* A native call's tag from x16, split exactly as monitor_call_impl counts
 * endpoint_calls: the endpoint command, domain 0, table 0, endpoint below the
 * bucket count; everything else is SERVICE_SUB_CALL_OTHER. */
static inline unsigned service_sub_call(uint64_t x16, unsigned endpoint_command)
{
    uint32_t cmd = (uint32_t)((x16 >> 56) & 0xff), domain = (uint32_t)((x16 >> 48) & 0xff);
    uint32_t table = (uint32_t)((x16 >> 32) & 0xffff), endpoint = (uint32_t)x16;
    return cmd == endpoint_command && !domain && !table && endpoint < SERVICE_SUB_ENDPOINTS ?
           SERVICE_SUB_ENDPOINT + endpoint : SERVICE_SUB_CALL_OTHER;
}

static inline void service_sub_tag(struct service_sub_profile *s, unsigned cpu, unsigned sub)
{
    if (cpu < SERVICE_SUB_CPUS && sub < SERVICE_SUB_BUCKETS) s->current[cpu] = (uint8_t)sub;
}

/* After service_profile_end: completed says that end closed an acquired
 * entry (its stage was 2). Only an EC 0x20 entry is charged; the tag is
 * cleared either way, so none outlives its entry. */
static inline void service_sub_charge(struct service_sub_profile *s, unsigned cpu,
                                      const struct service_profile *p, int completed)
{
    if (cpu >= SERVICE_SUB_CPUS) return;
    unsigned sub = s->current[cpu];
    s->current[cpu] = SERVICE_SUB_OTHER;
    if (!completed || p->category != SERVICE_SUB_CATEGORY || p->stage || sub >= SERVICE_SUB_BUCKETS)
        return;
    struct service_profile_bucket *b = &s->buckets[sub];
    b->entries++;
    b->wait_ticks += p->acquire_tick - p->enter_tick;
    b->hold_ticks += p->last_tick - p->acquire_tick;
}

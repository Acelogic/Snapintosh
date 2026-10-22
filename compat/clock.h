/* SPDX-License-Identifier: MIT */
#ifndef SNAP_COMPAT_CLOCK_H
#define SNAP_COMPAT_CLOCK_H
#include <stdint.h>

/* ESR sysreg identifiers, without Rt or direction. These are guest ABI, not
 * host register numbers. The backend counter must use the frequency declared
 * in the guest device tree; it must advance with elapsed time, not accesses. */
#define CLOCK_SYSREG(o0,o1,n,m,o2) \
    (((o0)<<20)|((o2)<<17)|((o1)<<14)|((n)<<10)|((m)<<1))
#define CLOCK_CNTVCTSS CLOCK_SYSREG(3,4,15,10,6)
#define CLOCK_CNTVCT   CLOCK_SYSREG(3,4,15,11,7)
#define CLOCK_CNTKCTL  CLOCK_SYSREG(3,4,15,9,6)
#define CLOCK_CNTV_CTL CLOCK_SYSREG(3,1,15,0,5)
#define CLOCK_CNTV_TVAL CLOCK_SYSREG(3,1,15,15,4)
#define CLOCK_ARCH_CNTVCT CLOCK_SYSREG(3,3,14,0,2)
#define CLOCK_ARCH_CNTVCTSS CLOCK_SYSREG(3,3,14,0,6)
#define CLOCK_ARCH_CNTP_CTL CLOCK_SYSREG(3,3,14,2,1)

/* All rates are Hz. Conversion uses quotient/remainder arithmetic so the
 * freestanding host does not need a compiler 128-bit division runtime. */
struct clock_rate { uint32_t host_hz, guest_hz; };
int clock_rate_init(struct clock_rate *rate, uint64_t host_hz, uint64_t guest_hz);
uint64_t clock_rate_sample(const struct clock_rate *rate, uint64_t host_count);
/* Earliest physical tick reaching guest_deadline, bounded by host_budget.
 * Accounts for the fractional phase discarded by the sampled guest count. */
uint64_t clock_rate_wait(const struct clock_rate *rate, uint64_t host_now,
                         uint64_t guest_deadline, uint64_t host_budget);

/* The nearest power of two between the rates, round(log2(host/guest)),
 * clamped to [-15, 15]; 0 for an invalid rate. */
int clock_event_shift(uint64_t host_hz, uint64_t guest_hz);
/* A guest CNTKCTL (bits 7:0) for the hardware counter's event stream: EVNTI
 * moved by clock_event_shift and clamped to 0..15, so the native stream keeps
 * the guest's period within a factor of sqrt(2); every other bit unchanged. */
uint64_t clock_event_host_control(uint64_t control, uint64_t host_hz, uint64_t guest_hz);

/* Software event-stream state. Events coalesce into one pending bit. This
 * permits a WFE trap backend without interrupting the host every few ticks. */
struct guest_event { uint64_t control, next, pending; };
void guest_event_configure(struct guest_event *event, uint64_t control, uint64_t now);
uint64_t guest_event_wait(struct guest_event *event, uint64_t now, uint64_t budget);
int guest_event_consume(struct guest_event *event, uint64_t now);

enum clock_result {
    CLOCK_UNHANDLED, CLOCK_OK, CLOCK_READ_ONLY, CLOCK_CONTROL_UNSUPPORTED,
    CLOCK_TIMER_UNSUPPORTED, CLOCK_BACKEND_FAILED
};
struct guest_clock {
    uint64_t reads, first, last, writes, cntkctl;
};
struct clock_backend {
    void *ctx;
    uint64_t (*counter)(void *ctx);
    /* Apply the complete guest CNTKCTL value. Return zero on success; failure
     * must leave hardware unchanged. The host adapter owns save/restore. */
    int (*control)(void *ctx, uint64_t value);
};
enum clock_result guest_clock_access(struct guest_clock *clock,
    const struct clock_backend *backend, uint64_t reg, int read, uint64_t *value);
/* Exact Apple EL0 ordered-counter MRS. The caller validates exception origin
 * and executable memory; unknown encodings and disabled EL0 access stay strict. */
enum clock_result guest_clock_user_read(struct guest_clock *clock,
    const struct clock_backend *backend, uint32_t instruction, uint64_t regs[31]);

/* One CPU's Apple kernel deadline timer. Its time domain is the counter above.
 * The host adapter schedules a physical wakeup and drives a level FIQ from
 * guest_timer_pending(); servicing an interrupt does not acknowledge it. */
struct guest_timer {
    uint64_t cval, ctl, reads, writes;
};
enum clock_result guest_timer_access(struct guest_timer *timer, uint64_t reg,
                                    int read, uint64_t *value, uint64_t now);
/* An unused timer domain can be disabled and its mask read back. Enabling it
 * requires a separately implemented counter and interrupt-delivery contract. */
enum clock_result guest_timer_idle_access(struct guest_timer *timer, uint64_t reg,
                                         int read, uint64_t *value);
uint64_t guest_timer_control(const struct guest_timer *timer, uint64_t now);
int guest_timer_pending(const struct guest_timer *timer, uint64_t now);
/* Next wake interval, capped by the independent watchdog's remaining budget.
 * An already pending level needs no repeat physical interrupt. */
uint64_t guest_timer_wait(const struct guest_timer *timer, uint64_t now,
                          uint64_t budget);
#endif

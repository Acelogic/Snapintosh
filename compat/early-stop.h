/* SPDX-License-Identifier: MIT */
#ifndef SNAP_EARLY_STOP_H
#define SNAP_EARLY_STOP_H
#include <stdint.h>

/* Early stop: two opt-in ways to end a run before its watchdog budget, both
 * through the watchdog's own path (the timer expiry in xnuboot_async_locked,
 * then runtime_leave -> guest_service_stop(SERVICE_STOP_NORMAL)), so every CPU
 * quiesces exactly as it does at a budget stop and RAM stays collectable.
 *
 *  - Guest milestone: our Adreno kext issues HVC #0xad16 with
 *    x0 = ADRENO_GUEST_STOP (compat/adreno-guest.h). Admitted only when the
 *    launch enabled it, from EL1, and only for an HVC whose instruction bytes
 *    are the loader-supplied AuxKC's (whose sole bundle is our kext).
 *  - Host abort: the Mac sends a stop datagram to q1n1 while the P_CALL runs;
 *    CPU0 polls q1n1's call service (q1n1 platform/uefi/call-service.h) on
 *    its timer tick, at a bounded rate.
 *
 * Neither stops the run directly. An accepted request arms a deadline no
 * later than the budget; the first CPU whose timer finds it expired records
 * EV_EARLY_STOP and stops. An earlier host deadline can supersede a pending
 * guest/host request. Fired records and later deadlines remain unchanged.
 * With params.early_stop all zero (an ordinary launch) nothing here runs and
 * the effective deadline is the watchdog's. docs/EARLY-STOP-20260928.md. */

#define EARLY_STOP_F_GUEST 1u          /* admit ADRENO_GUEST_STOP */
#define EARLY_STOP_F_HOST  2u          /* poll q1n1's call service on CPU0 */
#define EARLY_STOP_F_THERMAL 8u      /* A16 physical TSENS policy, opt-in */
#define EARLY_STOP_F_ALL   (EARLY_STOP_F_GUEST | EARLY_STOP_F_HOST)
/* Two-way console over the same poll (compat/console-link.h). Only with
 * EARLY_STOP_F_HOST, whose poll carries it; not a stop trigger, so not in
 * EARLY_STOP_F_ALL. */
#define EARLY_STOP_F_CONSOLE 4u
/* The guest network over the same poll (compat/guest-net-link.h,
 * docs/GUEST-NETWORK-20261019.md). Only with EARLY_STOP_F_HOST, and only in a
 * monitor built with SNAP_GUEST_NET, which alone lets its poll run below
 * EARLY_STOP_POLL_MIN_MS; not a stop trigger, so not in EARLY_STOP_F_ALL. */
#define EARLY_STOP_F_NET 16u
#ifndef SNAP_GUEST_NET
#define SNAP_GUEST_NET 0
#endif

#define EARLY_STOP_SOURCE_GUEST 1u
#define EARLY_STOP_SOURCE_HOST  2u
#define EARLY_STOP_SOURCE_THERMAL 3u

/* Guest reason codes (x1 of ADRENO_GUEST_STOP). */
#define EARLY_STOP_REASON_PRESENT        1u  /* first AdrenoDisplay present shown */
#define EARLY_STOP_REASON_PLUGIN_FAILURE 2u  /* AdrenoMetal, just before it raises */
#define EARLY_STOP_REASON_CLIENT_DIED    3u  /* WindowServer's GPU task torn down after it allocated */
#define EARLY_STOP_GUEST_REASON_MAX      3u
/* Host reason code carried by the stop datagram (tools/request-stop.py). */
#define EARLY_STOP_REASON_OPERATOR       1u
#define EARLY_STOP_HOST_REASON_MAX       0xffffu

/* Seconds. A request above the hard limit is malformed and refused; anything
 * else is clamped to params.max_delay_s, which the host keeps <= the limit. */
#define EARLY_STOP_DELAY_LIMIT 3600u
#define EARLY_STOP_POLL_MIN_MS 20u
#define EARLY_STOP_POLL_MAX_MS 5000u
#define EARLY_STOP_POLL_MIN_NET_MS 2u
#if SNAP_GUEST_NET
#define EARLY_STOP_POLL_FLOOR(p) (((p)->flags & EARLY_STOP_F_NET) ? EARLY_STOP_POLL_MIN_NET_MS : EARLY_STOP_POLL_MIN_MS)
#else
#define EARLY_STOP_POLL_FLOOR(p) EARLY_STOP_POLL_MIN_MS
#endif

/* Results in x0 (and in EV_EARLY_STOP_REQUEST). Disabled is ADRENO_E_PARAMS,
 * the answer an older monitor's fence handler gives an unknown request. */
#define EARLY_STOP_ACCEPTED   0
#define EARLY_STOP_DUPLICATE  1        /* valid, but did not shorten a pending deadline */
#define EARLY_STOP_E_DISABLED (-60)
#define EARLY_STOP_E_CALLER   (-80)    /* not EL1, or not the AuxKC's own HVC */
#define EARLY_STOP_E_REASON   (-81)
#define EARLY_STOP_E_DELAY    (-82)
#define EARLY_STOP_E_HOST     (-83)    /* a malformed q1n1 latch record */

enum early_stop_phase { EARLY_STOP_IDLE, EARLY_STOP_ARMING, EARLY_STOP_PENDING, EARLY_STOP_FIRED, EARLY_STOP_UPDATING };
enum early_stop_outcome {
    EARLY_STOP_OUTCOME_NONE,           /* nothing accepted */
    EARLY_STOP_OUTCOME_STOPPED,        /* fired, and its CPU owns the stop word */
    EARLY_STOP_OUTCOME_CONCURRENT,     /* fired, but another stop set the word first */
    EARLY_STOP_OUTCOME_SUPERSEDED,     /* accepted, the run stopped before its deadline */
};

/* Appended to struct params (probes/xnuboot.py writes the same six words). */
struct early_stop_params {
    uint64_t flags;                    /* EARLY_STOP_F_*; zero on ordinary launches */
    uint64_t max_delay_s;              /* <= EARLY_STOP_DELAY_LIMIT */
    uint64_t host_call;                /* q1n1 bootinfo call_service entry, or 0 */
    uint64_t host_state;               /* q1n1 bootinfo call_service_state, informational */
    uint64_t host_poll_ms;             /* [EARLY_STOP_POLL_MIN_MS, EARLY_STOP_POLL_MAX_MS] */
    uint64_t session;                  /* per-launch nonce armed into q1n1, nonzero */
};
#define EARLY_STOP_PARAMS_WORDS 6

/* q1n1's call service (platform/uefi/call-service.h), called only from CPU0,
 * which is the CPU inside the P_CALL: x0 = op, x1..x3 arguments. */
#define EARLY_STOP_HOST_ARM    1u      /* x1 = session: clears any latch */
#define EARLY_STOP_HOST_POLL   2u      /* x1 = struct early_stop_host_request *, x2 = size */
#define EARLY_STOP_HOST_DISARM 3u
#define EARLY_STOP_HOST_MAGIC  UINT64_C(0x3154414c52533151)   /* "Q1SRLAT1" */
struct early_stop_host_request {       /* POLL returns 1 and fills this once */
    uint64_t magic, session, nonce, reason, delay_s, latched_ticks;
    uint64_t text[8];                  /* reason text, NUL padded */
};
#define EARLY_STOP_HOST_REQUEST_WORDS 14

/* Appended to struct context. Every word is written under the service lock;
 * state and deadline are also read by the timer paths of other CPUs.
 * tools/early_stop.py decodes it in this order (tools/test-early-stop.c pins
 * the layout); OUT_EARLY_STOP copies it into the report. */
struct early_stop_state {
    uint64_t state;                    /* enum early_stop_phase */
    uint64_t source, reason, detail;
    uint64_t requested_delay, accepted_delay;      /* seconds */
    uint64_t request_ticks, deadline, fire_ticks;  /* physical counter */
    uint64_t request_cpu, request_pc, fire_cpu;    /* CPU slot + 1; 0 = none */
    uint64_t refusals, last_refusal, duplicates;
    uint64_t host_polls, host_next_poll, host_armed, host_status, host_errors, host_in_call;
    uint64_t outcome;                  /* enum early_stop_outcome, set by the report */
    uint64_t text[8];                  /* host reason text, NUL padded */
};
#define EARLY_STOP_STATE_WORDS 30

struct auxkc_range;

/* Pure checks, in admission order. 0 admits; otherwise an EARLY_STOP_E_*. */
int early_stop_guest_caller(const struct auxkc_range *kc, uint64_t hvc_va,
                            uint64_t hvc_pa, uint32_t word, uint64_t spsr);
int early_stop_delay(const struct early_stop_params *p, uint64_t requested,
                     uint64_t *accepted);
int early_stop_guest_admit(const struct early_stop_params *p, const struct auxkc_range *kc,
                           uint64_t hvc_va, uint64_t hvc_pa, uint32_t word, uint64_t spsr,
                           uint64_t reason, uint64_t requested, uint64_t *accepted);

/* Arm now + accepted * hz. A host may shorten a pending deadline; later
 * guest requests and fired records are immutable. Effective winner replaces
 * this record; EV_EARLY_STOP_REQUEST retains earlier requests independently.
 * Call under the service lock, as fire/finish. The phase claim also excludes
 * a concurrent update/fire. Returns ACCEPTED or DUPLICATE; text may be NULL. */
int early_stop_request(struct early_stop_state *s, unsigned source, uint64_t reason,
                       uint64_t detail, uint64_t requested, uint64_t accepted,
                       uint64_t now, uint64_t hz, unsigned cpu, uint64_t pc,
                       const uint64_t *text);
void early_stop_refuse(struct early_stop_state *s, int code);

/* The deadline the timer must honour: the budget's, or an earlier accepted one. */
uint64_t early_stop_deadline(const struct early_stop_state *s, uint64_t budget);
/* 1 when an accepted deadline strictly before the budget has passed: the
 * calling CPU records EV_EARLY_STOP and stops. The first caller is recorded. */
int early_stop_fire(struct early_stop_state *s, uint64_t now, uint64_t budget, unsigned cpu);
/* After every executor has quiesced: classify against the service stop word. */
void early_stop_finish(struct early_stop_state *s, uint64_t stop_word);
/* Rate limit for CPU0's host poll: 1 when a poll is due (and schedules the next). */
int early_stop_host_due(struct early_stop_state *s, const struct early_stop_params *p,
                        uint64_t now, uint64_t hz);
/* Validate q1n1's latch record for this session; 0 or EARLY_STOP_E_HOST/_DELAY. */
int early_stop_host_admit(const struct early_stop_params *p,
                          const struct early_stop_host_request *r, uint64_t *accepted);
#endif

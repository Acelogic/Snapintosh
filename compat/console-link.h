/* SPDX-License-Identifier: MIT */
/* Two-way console over q1n1's call service (docs/GUEST-SHELL-DESIGN-20261016.md).
 *
 * Output is the console the monitor already keeps: console_tail, counted by
 * console_tail_bytes. Before each host poll CPU0 describes that ring in a view
 * and passes it to q1n1's POLL (a3). q1n1 answers the Mac's console requests
 * from it and appends the Mac's keystrokes to the view's staging buffer. After
 * the poll they move into the DockChannel receive ring, which XNU's
 * serial_keyboard_poll drains every 16 ms. CPU0 does all of it under the
 * service lock, which also serializes console_put and the trapped UART. The
 * monitor never waits for the Mac: a host that falls behind sees a gap, and
 * input that does not fit is not accepted (q1n1 reports how much was).
 *
 * Opt-in per launch: EARLY_STOP_F_CONSOLE (SNAP_EARLY_STOP=console). Without
 * it nothing is passed to q1n1 and the UART answers exactly as before.
 *
 * Header-only and freestanding, so the monitor and the host loopback test
 * (tools/test-console-link.c) compile the same code. */
#ifndef SNAP_CONSOLE_LINK_H
#define SNAP_CONSOLE_LINK_H
#include <stdint.h>
#include "../shadow/dockchannel.h"

/* q1n1 platform/uefi/call-service.h struct q1n1_console_view, word for word.
 * The monitor fills magic..in_fill before each POLL; q1n1 keeps the rest. */
#define CONSOLE_LINK_VIEW_MAGIC UINT64_C(0x3156534e4f433151)   /* "Q1CONSV1" */
#define CONSOLE_LINK_VIEW_VERSION 1u
struct console_link_view {
    uint64_t magic, version;
    uint64_t out_base, out_size, out_produced;
    uint64_t in_base, in_size, in_room, in_fill;
    uint64_t in_held;
    uint64_t owner, owner_changes;
    uint64_t requests, refused, in_duplicate, in_gaps, in_overflow, out_served, out_gaps;
    uint64_t polls_seen;
};
#define CONSOLE_LINK_VIEW_WORDS 20
_Static_assert(sizeof(struct console_link_view) == 8 * CONSOLE_LINK_VIEW_WORDS,
               "q1n1 call-service.h struct q1n1_console_view layout");

/* At least q1n1's Q1N1_CONSOLE_IN_MAX, so one request's input always fits. */
#define CONSOLE_LINK_STAGING 1024u

/* XNU's _serial_getc (KDK 0xfffffe00075031ac) enters the debugger with
 * "Automatic NMI" once these 32 bytes arrive in a row (string at KDK
 * 0xfffffe0007d368c0). Its matcher advances on a match and resets to zero on
 * any other byte; console_link_drain runs the same automaton over the bytes it
 * delivers and drops the one that would complete it. */
#define CONSOLE_LINK_NMI "afDIGHr84A84jh19Kphgp428DNPdnapq"
#define CONSOLE_LINK_NMI_LENGTH 32u

struct console_link {
    struct console_link_view view;
    struct dc_rx rx;
    uint64_t nmi_match;                       /* XNU's matcher state over delivered bytes */
    uint64_t polls, call_ticks, call_ticks_max;   /* host polls; CNTPCT ticks inside q1n1 */
    uint64_t staged, delivered, nmi_dropped, rx_refused;
    uint8_t staging[CONSOLE_LINK_STAGING];
};

/* Before a POLL: what q1n1 may read, and how much input it may stage. */
static inline void console_link_prepare(struct console_link *l, const uint8_t *ring,
                                        uint64_t ring_size, uint64_t produced)
{
    struct console_link_view *v = &l->view;
    unsigned room = dc_rx_free(&l->rx);
    v->magic = CONSOLE_LINK_VIEW_MAGIC;
    v->version = CONSOLE_LINK_VIEW_VERSION;
    v->out_base = (uint64_t)(uintptr_t)ring;
    v->out_size = ring_size;
    v->out_produced = produced;
    v->in_base = (uint64_t)(uintptr_t)l->staging;
    v->in_size = CONSOLE_LINK_STAGING;
    v->in_room = room < CONSOLE_LINK_STAGING ? room : CONSOLE_LINK_STAGING;
    v->in_fill = 0;
}

/* After it: move what q1n1 staged into the receive ring. Never more than the
 * room offered, whatever in_fill says. */
static inline void console_link_drain(struct console_link *l)
{
    uint64_t fill = l->view.in_fill < l->view.in_room ? l->view.in_fill : l->view.in_room;
    l->staged += fill;
    for (uint64_t n = 0; n < fill; n++) {
        uint8_t c = l->staging[n];
        uint64_t next = c == (uint8_t)CONSOLE_LINK_NMI[l->nmi_match] ? l->nmi_match + 1 : 0;
        if (next == CONSOLE_LINK_NMI_LENGTH) {
            l->nmi_dropped++;
            continue;
        }
        if (dc_rx_push(&l->rx, c)) {
            l->rx_refused++;
            continue;
        }
        l->nmi_match = next;
        l->delivered++;
    }
    l->view.in_fill = 0;
}

/* One POLL's cost, with or without the console. */
static inline void console_link_account(struct console_link *l, uint64_t ticks)
{
    l->polls++;
    l->call_ticks += ticks;
    if (ticks > l->call_ticks_max) l->call_ticks_max = ticks;
}

#endif /* SNAP_CONSOLE_LINK_H */

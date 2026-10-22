/* SPDX-License-Identifier: MIT */
#include "qcc2072-connect.h"
#include "native-wpa2-crypto.h"
#include <string.h>

static void note(struct qcc2072_connect *e, unsigned code, int64_t a, int64_t b)
{
    if (e->ops.note) e->ops.note(e->ops.context, code, a, b);
}
static int same(const uint8_t *a, const uint8_t *b, size_t n) { return !memcmp(a, b, n); }
/* snap_wpa2 transmit: tag the frame so dp-io's completion finds its way back. */
static int wpa_transmit(void *context, uint64_t generation, uint64_t transaction, const uint8_t *frame, size_t length)
{
    struct qcc2072_connect *e = (struct qcc2072_connect *)context;
    (void)generation;
    if (length < 14 || frame[12] != 0x88 || frame[13] != 0x8e) return SNAP_STATION_INVALID;
    if (e->ops.eapol_admit(e->ops.context, frame, length, 1)) return SNAP_STATION_INVALID;
    uint64_t tag = QCC2072_CONNECT_TAG | (uint64_t)(++e->tx_sequence);
    int rc = e->ops.transmit(e->ops.context, frame, length, tag);
    /* message 2 or 4 (key info MIC + secure) for the log */
    note(e, QCC2072_CONNECT_N_TX, (frame[19] & 0x02) ? 4 : 2, rc);   /* key info secure bit */
    if (rc) return rc;
    e->tx_tag = tag; e->tx_transaction = transaction;
    return 0;
}
static int wpa_random(void *context, uint8_t *out, size_t length)
{
    struct qcc2072_connect *e = (struct qcc2072_connect *)context;
    return e->ops.random(e->ops.context, out, length);
}
void qcc2072_connect_init(struct qcc2072_connect *e, struct snap_station *station, const struct qcc2072_connect_ops *ops)
{
    if (!e) return;
    snap_wpa2_clear(e, sizeof(*e));
    e->station = station;
    if (ops) e->ops = *ops;
    e->initialized = station && ops && ops->transmit && ops->random && ops->eapol_admit &&
                     ops->link_security && ops->disconnect;
}
static void wipe_queues(struct qcc2072_connect *e)
{
    snap_wpa2_clear(e->rx, sizeof(e->rx)); e->rx_count = 0;
    snap_wpa2_clear(e->done, sizeof(e->done)); e->done_count = 0;
    snap_wpa2_clear(e->events, sizeof(e->events)); e->event_count = 0;
}
void qcc2072_connect_abort(struct qcc2072_connect *e)
{
    if (!e) return;
    if (e->wpa.phase) (void)snap_wpa2_abort(&e->wpa, 1);   /* transmit copied every frame: quiesced */
    snap_wpa2_clear(&e->wpa, sizeof(e->wpa));
    snap_wpa2_clear(e->pmk, sizeof(e->pmk)); e->has_pmk = 0;
    wipe_queues(e);
    e->state = QCC2072_CONNECT_IDLE; e->disconnect_due = 0; e->transaction = e->link = 0;
}
int qcc2072_connect_arm(struct qcc2072_connect *e, uint64_t transaction, const uint8_t bssid[6],
                        const uint8_t own[6], const uint8_t pmk[32])
{
    if (!e || !e->initialized || !transaction || !bssid || !own || !pmk) return SNAP_STATION_INVALID;
    if (e->in_service) return SNAP_STATION_BUSY;
    qcc2072_connect_abort(e);
    e->reason = 0;
    memcpy(e->pmk, pmk, 32); e->has_pmk = 1;
    memcpy(e->bssid, bssid, 6); memcpy(e->own, own, 6);
    e->transaction = transaction; e->state = QCC2072_CONNECT_ARMED;
    note(e, QCC2072_CONNECT_N_ARMED, (int64_t)transaction, 0);
    return SNAP_STATION_OK;
}
void qcc2072_connect_station_event(struct qcc2072_connect *e, const struct snap_station_event *v)
{
    if (!e || !v || e->state == QCC2072_CONNECT_IDLE) return;
    if (v->type == SNAP_STATION_BSS || v->type == SNAP_STATION_SCAN_DONE) return;
    if (e->event_count >= sizeof(e->events) / sizeof(e->events[0])) { e->events_dropped++; return; }
    struct qcc2072_connect_event *c = &e->events[e->event_count++];
    c->generation = v->generation; c->transaction = v->transaction; c->link_transaction = v->link_transaction;
    c->type = v->type; c->status = v->status;
}
int qcc2072_connect_rx(struct qcc2072_connect *e, const uint8_t *f, size_t n)
{
    if (!e || !f || n < 14 || f[12] != 0x88 || f[13] != 0x8e) return 0;
    if (e->state != QCC2072_CONNECT_ARMED && e->state != QCC2072_CONNECT_HANDSHAKE &&
        e->state != QCC2072_CONNECT_CONNECTED) { e->foreign++; return 1; }
    if (!same(f, e->own, 6) || !same(f + 6, e->bssid, 6) || n > SNAP_WPA2_MAX_FRAME) { e->foreign++; return 1; }
    if (e->rx_count == QCC2072_CONNECT_RX_SLOTS) {     /* keep the newest: the AP retransmits */
        memmove(&e->rx[0], &e->rx[1], sizeof(e->rx[0]) * (QCC2072_CONNECT_RX_SLOTS - 1));
        e->rx_count--; e->rx_dropped++;
    }
    e->rx[e->rx_count].length = (uint16_t)n; memcpy(e->rx[e->rx_count].frame, f, n); e->rx_count++;
    return 1;
}
int qcc2072_connect_tx_done(struct qcc2072_connect *e, uint64_t tag, int status)
{
    if (!e || (tag & QCC2072_CONNECT_TAG_MASK) != QCC2072_CONNECT_TAG) return 0;
    if (e->done_count >= sizeof(e->done) / sizeof(e->done[0])) { e->done_dropped++; return 1; }
    e->done[e->done_count].tag = tag; e->done[e->done_count].status = status; e->done_count++;
    return 1;
}
/* IEEE 802.11 reason codes for a supplicant-side teardown (wpa_supplicant's choices). */
static uint16_t deauth_reason(unsigned why)
{
    if (why == SNAP_WPA2_R_RSNE || why == SNAP_WPA2_R_RSNXE || why == SNAP_WPA2_R_RSNE2) return 17;
    if (why == SNAP_WPA2_R_TIMEOUT) return 15;
    return 1;
}
static void ended(struct qcc2072_connect *e, unsigned state, int request_disconnect)
{
    unsigned why = e->wpa.reason;
    if (request_disconnect && e->link) { e->disconnect_due = 1; e->disconnect_reason = deauth_reason(why); }
    if (e->wpa.phase) (void)snap_wpa2_abort(&e->wpa, 1);
    snap_wpa2_clear(&e->wpa, sizeof(e->wpa));
    snap_wpa2_clear(e->pmk, sizeof(e->pmk)); e->has_pmk = 0;
    snap_wpa2_clear(e->rx, sizeof(e->rx)); e->rx_count = 0;
    e->reason = (uint8_t)why; e->state = (uint8_t)state;
}
static void handle(struct qcc2072_connect *e, const struct qcc2072_connect_event *v)
{
    if (!e->station || v->generation != e->station->generation) return;
    switch (v->type) {
    case SNAP_STATION_ASSOCIATED: {
        if (e->state != QCC2072_CONNECT_ARMED || v->transaction != e->transaction) return;
        e->link = v->transaction;
        note(e, QCC2072_CONNECT_N_ASSOCIATED, (int64_t)v->transaction, 0);
        struct snap_wpa2_ap ap;
        memset(&ap, 0, sizeof(ap));
        int rc = e->ops.link_security(e->ops.context, &ap);
        if (!rc) {
            static const struct snap_wpa2_ops wops = {wpa_transmit, wpa_random};
            rc = snap_wpa2_start(&e->wpa, e->station, &wops, e, e->pmk, &ap, e->now_ms);
        }
        snap_wpa2_clear(e->pmk, sizeof(e->pmk)); e->has_pmk = 0;   /* snap_wpa2 holds it now */
        note(e, QCC2072_CONNECT_N_START, rc, ap.rsn_length | (int64_t)ap.rsnxe_length << 8);
        if (rc) { e->wpa.reason = SNAP_WPA2_R_AP_RSN; ended(e, QCC2072_CONNECT_FAILED, 1); note(e, QCC2072_CONNECT_N_FAILED, rc, e->reason); }
        else e->state = QCC2072_CONNECT_HANDSHAKE;
        return;
    }
    case SNAP_STATION_CONTROL_DONE: {
        if (e->state != QCC2072_CONNECT_HANDSHAKE || !e->wpa.phase || v->link_transaction != e->link) return;
        struct snap_station_event *x = &e->scratch;
        memset(x, 0, sizeof(*x));
        x->generation = v->generation; x->transaction = v->transaction; x->link_transaction = v->link_transaction;
        x->type = v->type; x->status = v->status;
        int rc = snap_wpa2_control_done(&e->wpa, x);
        note(e, QCC2072_CONNECT_N_CONTROL_DONE, v->status, rc);
        return;
    }
    case SNAP_STATION_CONNECTED:
        if (v->transaction != e->link || e->state != QCC2072_CONNECT_HANDSHAKE) return;
        e->state = QCC2072_CONNECT_CONNECTED;
        note(e, QCC2072_CONNECT_N_CONNECTED, (int64_t)v->transaction, 0);
        return;
    case SNAP_STATION_ERROR: case SNAP_STATION_CANCEL_ACK:
        if (v->transaction != e->transaction || e->state == QCC2072_CONNECT_FAILED ||
            e->state == QCC2072_CONNECT_DISCONNECTED || e->state == QCC2072_CONNECT_IDLE) return;
        /* snap_wpa2 failed while the radio link is still up: tear it down at the provider */
        ended(e, QCC2072_CONNECT_FAILED, e->wpa.phase == SNAP_WPA2_FAILED);
        note(e, QCC2072_CONNECT_N_FAILED, v->status, e->reason);
        return;
    case SNAP_STATION_DISCONNECTED:
        if (!e->link || v->transaction != e->link || e->state == QCC2072_CONNECT_DISCONNECTED ||
            e->state == QCC2072_CONNECT_IDLE) return;
        ended(e, QCC2072_CONNECT_DISCONNECTED, e->wpa.phase == SNAP_WPA2_FAILED);
        note(e, QCC2072_CONNECT_N_DISCONNECTED, v->status, e->reason);
        return;
    default:
        return;
    }
}
static void drain_events(struct qcc2072_connect *e)
{
    for (unsigned guard = 0; e->event_count && guard < 64; guard++) {
        struct qcc2072_connect_event v = e->events[0];
        e->event_count--;
        memmove(&e->events[0], &e->events[1], sizeof(e->events[0]) * e->event_count);
        handle(e, &v);
    }
}
int qcc2072_connect_service(struct qcc2072_connect *e, uint64_t now_ms)
{
    if (!e || !e->initialized) return SNAP_STATION_INVALID;
    if (e->in_service) return SNAP_STATION_BUSY;
    e->in_service = 1; e->now_ms = now_ms;
    /* 1. TX completions first: an M3 can then be taken right after M2's ACK */
    for (unsigned i = 0; i < e->done_count; i++) {
        int status = e->done[i].status, rc = SNAP_STATION_STALE;
        if (e->wpa.phase && e->wpa.tx_pending && e->done[i].tag == e->tx_tag)
            rc = snap_wpa2_tx_done(&e->wpa, e->wpa.generation, e->tx_transaction, status ? SNAP_STATION_NOT_READY : 0);
        note(e, QCC2072_CONNECT_N_TX_DONE, status, rc);
    }
    e->done_count = 0;
    /* 2. station events (ASSOCIATED starts snap_wpa2, CONTROL_DONE continues it) */
    drain_events(e);
    /* 3. EAPOL in arrival order once snap_wpa2 runs */
    while (e->rx_count) {
        if (!e->wpa.phase) {
            if (e->state == QCC2072_CONNECT_ARMED) break;          /* before ASSOCIATED: keep */
            snap_wpa2_clear(e->rx, sizeof(e->rx)); e->rx_count = 0;
            break;
        }
        int admit = e->ops.eapol_admit(e->ops.context, e->rx[0].frame, e->rx[0].length, 0);
        int rc = SNAP_STATION_INVALID, kind = 0;
        if (!admit) {
            e->admitted++;
            kind = (e->rx[0].frame[19] & 0x01) ? 3 : 1;           /* key info MIC bit */
            rc = snap_wpa2_receive(&e->wpa, e->rx[0].frame, e->rx[0].length, now_ms);
        } else e->foreign++;
        if (admit) note(e, QCC2072_CONNECT_N_FOREIGN, admit, 0);
        else note(e, QCC2072_CONNECT_N_RX, kind * 100 + e->wpa.reason, rc);
        snap_wpa2_clear(e->rx[0].frame, e->rx[0].length);
        e->rx_count--;
        memmove(&e->rx[0], &e->rx[1], sizeof(e->rx[0]) * e->rx_count);
        drain_events(e);
    }
    /* 4. deadlines */
    if (e->wpa.phase && e->wpa.phase != SNAP_WPA2_FAILED) (void)snap_wpa2_tick(&e->wpa, now_ms);
    drain_events(e);
    /* 5. provider teardown of a link snap_station already dropped */
    if (e->disconnect_due) {
        int rc = e->ops.disconnect(e->ops.context, e->link, e->disconnect_reason);
        if (rc != SNAP_STATION_BUSY) { e->disconnect_due = 0; note(e, QCC2072_CONNECT_N_DISCONNECT, e->disconnect_reason, rc); }
    }
    e->in_service = 0;
    return e->state;
}
const char *qcc2072_connect_note_name(unsigned code)
{
    /* a, b: ARMED (transaction), ASSOCIATED (transaction), START (rc, rsn|rsnxe<<8 lengths),
     * RX (message 1/3 * 100 + snap_wpa2 reason, rc), TX (message 2/4, transport rc), TX_DONE (dp-io status, rc),
     * CONTROL_DONE (status, rc), CONNECTED (transaction), FAILED (status, wpa reason),
     * DISCONNECTED (status, wpa reason), DISCONNECT (802.11 reason, rc), FOREIGN (admit rc),
     * DROPPED (count) */
    static const char *const names[QCC2072_CONNECT_N_COUNT] = {
        "?", "armed", "associated", "wpa2-start", "eapol-rx", "eapol-tx", "eapol-tx-done", "control-done",
        "connected", "failed", "disconnected", "provider-disconnect", "eapol-foreign", "eapol-dropped"};
    return code < QCC2072_CONNECT_N_COUNT ? names[code] : "?";
}
const char *qcc2072_connect_state_name(unsigned state)
{
    static const char *const names[] = {"idle", "armed", "handshake", "connected", "failed", "disconnected"};
    return state < sizeof(names) / sizeof(names[0]) ? names[state] : "?";
}

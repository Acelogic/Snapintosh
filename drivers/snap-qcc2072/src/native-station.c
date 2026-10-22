/* SPDX-License-Identifier: MIT */
#include "native-station.h"

static void zero(void *buffer, unsigned long size)
{
    uint8_t *p = (uint8_t *)buffer;
    while (size--) *p++ = 0;
}
static int unicast(const uint8_t *mac)
{
    return !(mac[0] & 1) && (mac[0] | mac[1] | mac[2] | mac[3] | mac[4] | mac[5]);
}
static int frequency(uint16_t mhz)
{
    /* Basic encoding bound only; backend enforces observed regulatory rules. */
    return mhz >= 2300 && mhz <= 7125;
}
static int ies_valid(const uint8_t *ies, uint16_t length)
{
    unsigned at = 0;
    if (length > SNAP_STATION_MAX_IE) return 0;
    while (at < length) {
        if (length - at < 2 || ies[at + 1] > length - at - 2) return 0;
        at += 2 + ies[at + 1];
    }
    return 1;
}
static int equal(const uint8_t *a, const uint8_t *b, unsigned size)
{
    while (size--) if (*a++ != *b++) return 0;
    return 1;
}
static int security(const uint8_t *ies, unsigned length)
{
    unsigned at = 0;
    int rsn = 0;
    const uint8_t ccmp_psk[] = {1, 0, 0, 15, 172, 4, 1, 0,
                              0, 15, 172, 4, 1, 0, 0, 15, 172, 2};
    while (at < length) {
        unsigned bytes = ies[at + 1];
        if (ies[at] == 48) {
            if (rsn || (bytes != 18 && bytes != 20) ||
                !equal(ies + at + 2, ccmp_psk, sizeof(ccmp_psk)) ||
                (bytes == 20 && (ies[at + 20] || ies[at + 21])))
                return SNAP_STATION_UNSUPPORTED;
            rsn = 1;
        } else if (ies[at] == 221 && bytes >= 4 &&
                   ies[at + 2] == 0 && ies[at + 3] == 80 &&
                   ies[at + 4] == 242 && ies[at + 5] == 1) {
            return SNAP_STATION_UNSUPPORTED;
        }
        at += bytes + 2;
    }
    return rsn;
}
static void clear_control(struct snap_station *s)
{
    volatile uint8_t *p = (volatile uint8_t *)&s->control;
    unsigned size = sizeof(s->control);
    while (size--) *p++ = 0;
}
static void clear_link(struct snap_station *s)
{
    s->connected = s->associated = s->secure = s->pairwise_key = 0;
    s->group_keys = s->authorized = 0;
    s->link_transaction = 0;
    zero(s->peer, sizeof(s->peer));
}
static void deliver(struct snap_station *s, const struct snap_station_event *e)
{
    s->in_callback = 1;
    s->ops.event(s->context, e);
    s->in_callback = 0;
}
static void clear_pending(struct snap_station *s)
{
    zero(&s->pending, sizeof(s->pending));
    s->cancelling = 0;
}
void snap_station_init(struct snap_station *s, const struct snap_station_ops *ops,
                       void *context)
{
    if (!s) return;
    zero(s, sizeof(*s));
    if (ops) s->ops = *ops;
    s->context = context;
}
int snap_station_admit(struct snap_station *s, const struct snap_station_ready *r)
{
    if (!s || !r) return SNAP_STATION_INVALID;
    if (s->in_callback || s->admitted || s->quarantined) return SNAP_STATION_BUSY;
    if (!s->ops.submit || !s->ops.cancel || !s->ops.stop || !s->ops.event)
        return SNAP_STATION_NOT_READY;
    /* "00" is the world regulatory domain the QCC2072 firmware reports before a country is
     * set (REG_CHAN_LIST_CC on the A16); the backend's channel set still comes from its rules. */
    if (!r->generation || !unicast(r->mac) ||
        !((r->country[0] >= 'A' && r->country[0] <= 'Z' && r->country[1] >= 'A' && r->country[1] <= 'Z') ||
          (r->country[0] == '0' && r->country[1] == '0')) ||
        (r->capabilities & ~(uint32_t)(SNAP_STATION_CAP_SCAN | SNAP_STATION_CAP_CONNECT |
                                        SNAP_STATION_CAP_PRIVATE_SCAN)))
        return SNAP_STATION_INVALID;
    if ((r->observed & SNAP_STATION_READY_ALL) != SNAP_STATION_READY_ALL)
        return SNAP_STATION_NOT_READY;
    if (r->generation <= s->generation) return SNAP_STATION_STALE;
    s->generation = r->generation;
    s->ready = *r;
    s->last_transaction = s->link_transaction = 0;
    s->admitted = 1;
    return SNAP_STATION_OK;
}
int snap_station_submit(struct snap_station *s, const struct snap_station_request *r)
{
    unsigned i;
    int status;
    if (!s || !r) return SNAP_STATION_INVALID;
    if (s->in_callback) return SNAP_STATION_BUSY;
    if (!s->admitted || s->quarantined) return SNAP_STATION_NOT_READY;
    if (s->pending.type || s->control.type) return SNAP_STATION_BUSY;
    if (!r->transaction || r->ssid_length > 32 ||
        r->channel_count > SNAP_STATION_MAX_CHANNELS ||
        !ies_valid(r->ies, r->ie_length))
        return SNAP_STATION_INVALID;
    if (r->transaction <= s->last_transaction) return SNAP_STATION_STALE;
    if (r->type != SNAP_STATION_SCAN && r->type != SNAP_STATION_CONNECT)
        return SNAP_STATION_UNSUPPORTED;
    if (!(s->ready.capabilities & r->type)) return SNAP_STATION_UNSUPPORTED;
    if (r->scan.private_mac > 1) return SNAP_STATION_INVALID;
    if (r->type == SNAP_STATION_SCAN && r->scan.private_mac &&
        !(s->ready.capabilities & SNAP_STATION_CAP_PRIVATE_SCAN))
        return SNAP_STATION_UNSUPPORTED;
    if (r->type == SNAP_STATION_CONNECT &&
        (!r->ssid_length || !unicast(r->bssid) || s->connected))
        return SNAP_STATION_INVALID;
    for (i = 0; i < r->channel_count; ++i)
        if (!frequency(r->channels_mhz[i])) return SNAP_STATION_INVALID;
    if (r->type == SNAP_STATION_CONNECT) {
        status = security(r->ies, r->ie_length);
        if (status < 0) return status;
        if (status && !s->ops.control) return SNAP_STATION_UNSUPPORTED;
        s->secure = (uint8_t)status;
        for (i = 0; i < sizeof(s->peer); ++i) s->peer[i] = r->bssid[i];
    }
    s->pending = *r;
    s->pending.generation = s->generation;
    s->last_transaction = r->transaction;
    s->in_callback = 1;
    status = s->ops.submit(s->context, &s->pending);
    s->in_callback = 0;
    if (status != SNAP_STATION_OK) {
        clear_pending(s);
        if (r->type == SNAP_STATION_CONNECT) clear_link(s);
    }
    return status;
}
int snap_station_control_submit(struct snap_station *s, const struct snap_station_control *r)
{
    int status;
    if (!s || !r) return SNAP_STATION_INVALID;
    if (s->in_callback || s->control.type) return SNAP_STATION_BUSY;
    if (!s->admitted || s->quarantined || !s->associated) return SNAP_STATION_NOT_READY;
    if (!s->ops.control) return SNAP_STATION_UNSUPPORTED;
    if (r->generation != s->generation || r->link_transaction != s->link_transaction ||
        !r->transaction || r->transaction <= s->last_transaction)
        return SNAP_STATION_STALE;
    if (r->type == SNAP_STATION_KEY_INSTALL || r->type == SNAP_STATION_KEY_REMOVE) {
        const uint8_t group[6] = {255, 255, 255, 255, 255, 255};
        if (!s->secure || s->connected) return SNAP_STATION_UNSUPPORTED;
        if (r->cipher != SNAP_STATION_CIPHER_CCMP128) return SNAP_STATION_UNSUPPORTED;
        if (r->pairwise > 1 || r->index > 3 || (r->pairwise && r->index) ||
            !equal(r->peer, r->pairwise ? s->peer : group, sizeof(s->peer)) ||
            r->key_length != (r->type == SNAP_STATION_KEY_INSTALL ? 16 : 0))
            return SNAP_STATION_INVALID;
    } else if (r->type == SNAP_STATION_PORT_AUTHORIZE) {
        if (s->secure && (!s->pairwise_key || !s->group_keys)) return SNAP_STATION_NOT_READY;
        if (s->authorized || s->connected) return SNAP_STATION_STALE;
    } else if (r->type != SNAP_STATION_LINK_DISCONNECT) {
        return SNAP_STATION_UNSUPPORTED;
    }
    if (r->type >= SNAP_STATION_PORT_AUTHORIZE && r->key_length)
        return SNAP_STATION_INVALID;
    s->control = *r;
    s->last_transaction = r->transaction;
    s->in_callback = 1;
    status = s->ops.control(s->context, &s->control);
    s->in_callback = 0;
    if (status != SNAP_STATION_OK) clear_control(s);
    return status;
}
static int control_done(struct snap_station *s, const struct snap_station_event *e)
{
    unsigned type, pairwise, index;
    if (!s->control.type || e->transaction != s->control.transaction ||
        e->link_transaction != s->control.link_transaction) return SNAP_STATION_STALE;
    type = s->control.type; pairwise = s->control.pairwise; index = s->control.index;
    clear_control(s);
    if (!s->associated || e->link_transaction != s->link_transaction)
        return SNAP_STATION_STALE;
    if (!e->status) {
        if (type == SNAP_STATION_KEY_INSTALL) {
            if (pairwise) s->pairwise_key = 1;
            else s->group_keys |= (uint8_t)(1U << index);
        } else if (type == SNAP_STATION_KEY_REMOVE) {
            if (pairwise) s->pairwise_key = 0;
            else s->group_keys &= (uint8_t)~(1U << index);
            s->authorized = 0;
        } else if (type == SNAP_STATION_PORT_AUTHORIZE) {
            s->authorized = 1;
        }
    }
    deliver(s, e);
    return SNAP_STATION_OK;
}
int snap_station_cancel(struct snap_station *s, uint64_t transaction)
{
    int status;
    if (!s) return SNAP_STATION_INVALID;
    if (s->in_callback) return SNAP_STATION_BUSY;
    if (!s->admitted || s->quarantined) return SNAP_STATION_NOT_READY;
    if (!s->pending.type || transaction != s->pending.transaction)
        return SNAP_STATION_STALE;
    if (s->cancelling) return SNAP_STATION_BUSY;
    s->in_callback = 1;
    status = s->ops.cancel(s->context, s->generation, transaction);
    s->in_callback = 0;
    if (status == SNAP_STATION_OK) s->cancelling = 1;
    return status;
}
int snap_station_event(struct snap_station *s, const struct snap_station_event *e)
{
    int terminal = 0;
    if (!s || !e) return SNAP_STATION_INVALID;
    if (s->in_callback) return SNAP_STATION_BUSY;
    if (e->generation != s->generation || !e->transaction)
        return SNAP_STATION_STALE;
    if (!s->admitted || s->quarantined) return SNAP_STATION_NOT_READY;
    if (e->type == SNAP_STATION_CONTROL_DONE) return control_done(s, e);
    if (e->type == SNAP_STATION_DISCONNECTED) {
        if (!s->associated || e->transaction != s->link_transaction)
            return SNAP_STATION_STALE;
        if (s->pending.type == SNAP_STATION_CONNECT &&
            s->pending.transaction == e->transaction) clear_pending(s);
        clear_link(s);
        deliver(s, e);
        return SNAP_STATION_OK;
    }
    if (!s->pending.type || e->transaction != s->pending.transaction)
        return SNAP_STATION_STALE;
    if (e->type == SNAP_STATION_CANCEL_ACK) {
        if (!s->cancelling || e->status) return SNAP_STATION_INVALID;
        terminal = 1;
    } else if (e->type == SNAP_STATION_ERROR) {
        if (!e->status) return SNAP_STATION_INVALID;
        terminal = 1;
    } else if (s->cancelling) {
        return e->type == SNAP_STATION_BSS ? SNAP_STATION_CANCELLED : SNAP_STATION_INVALID;
    } else if (e->status) {
        return SNAP_STATION_INVALID;
    } else if (s->pending.type == SNAP_STATION_SCAN) {
        if (e->type == SNAP_STATION_SCAN_DONE) terminal = 1;
        else if (e->type != SNAP_STATION_BSS || !unicast(e->bss.bssid) ||
                 e->bss.ssid_length > 32 || !frequency(e->bss.frequency_mhz) ||
                 e->bss.rssi_dbm > 0 || e->bss.rssi_dbm < -127 ||
                 !ies_valid(e->bss.ies, e->bss.ie_length))
            return SNAP_STATION_INVALID;
    } else if (e->type == SNAP_STATION_ASSOCIATED) {
        if (s->associated) return SNAP_STATION_STALE;
        s->associated = 1;
        s->link_transaction = e->transaction;
    } else if (e->type == SNAP_STATION_CONNECTED) {
        if (!s->associated || (s->secure &&
            (!s->pairwise_key || !s->group_keys || !s->authorized)))
            return SNAP_STATION_INVALID;
        s->connected = 1;
        s->link_transaction = e->transaction;
        terminal = 1;
    } else {
        return SNAP_STATION_INVALID;
    }
    /* A backend's terminal event releases its borrow before callback delivery. */
    if (terminal) {
        if (s->pending.type == SNAP_STATION_CONNECT && e->type != SNAP_STATION_CONNECTED)
            clear_link(s);
        clear_pending(s);
    }
    deliver(s, e);
    return SNAP_STATION_OK;
}
int snap_station_stop(struct snap_station *s)
{
    struct snap_station_event e;
    int status;
    if (!s) return SNAP_STATION_INVALID;
    if (s->in_callback) return SNAP_STATION_BUSY;
    if (!s->admitted && !s->quarantined) return SNAP_STATION_OK;
    s->admitted = 0;
    s->quarantined = 1;
    s->in_callback = 1;
    status = s->ops.stop(s->context, s->generation);
    s->in_callback = 0;
    if (status != SNAP_STATION_OK) return status;
    zero(&e, sizeof(e));
    e.generation = s->generation;
    if (s->pending.type) {
        e.transaction = s->pending.transaction;
        e.type = SNAP_STATION_ERROR;
        e.status = SNAP_STATION_CANCELLED;
        clear_pending(s);
        deliver(s, &e);
    }
    if (s->associated) {
        e.transaction = s->link_transaction;
        e.type = SNAP_STATION_DISCONNECTED;
        e.status = SNAP_STATION_CANCELLED;
        clear_link(s);
        deliver(s, &e);
    }
    clear_control(s);
    clear_link(s);
    s->quarantined = 0;
    zero(&s->ready, sizeof(s->ready));
    return SNAP_STATION_OK;
}

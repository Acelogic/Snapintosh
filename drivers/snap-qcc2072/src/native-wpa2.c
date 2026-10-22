/* SPDX-License-Identifier: MIT */
#include "native-wpa2.h"
#include "native-wpa2-crypto.h"
#include <string.h>

/* WPA2-PSK supplicant, CCMP-128, no PMF. Interoperability rules follow wpa_supplicant
 * (re/connect/FAILURES.md 7-25): M2 carries our own RSN element, M3 must carry
 * the AP's beacon RSN element (and RSNXE) unchanged, unknown KDEs are ignored, retransmitted
 * M1/M3 with new replay counters are answered, unacknowledged EAPOL does not end the
 * handshake (the AP retransmits), and keys are never installed twice. */
static uint16_t be16(const uint8_t *p) { return (uint16_t)((uint16_t)p[0] << 8 | p[1]); }
static void put16(uint8_t *p, uint16_t v) { p[0] = (uint8_t)(v >> 8); p[1] = (uint8_t)v; }
static int equal(const uint8_t *a, const uint8_t *b, size_t n)
{
    unsigned different = 0;
    for (size_t i = 0; i < n; ++i) different |= a[i] ^ b[i];
    return !different;
}
static int zero(const uint8_t *p, size_t n)
{
    unsigned value = 0;
    for (size_t i = 0; i < n; ++i) value |= p[i];
    return !value;
}
static void clear_keys(struct snap_wpa2 *s)
{
    snap_wpa2_clear(s->pmk, sizeof(s->pmk));
    snap_wpa2_clear(s->ptk, sizeof(s->ptk));
    snap_wpa2_clear(s->gtk, sizeof(s->gtk));
    snap_wpa2_clear(s->kck, sizeof(s->kck));
    s->kck_valid = 0;
}
static int ignore(struct snap_wpa2 *s, int status, unsigned reason)
{
    s->reason = (uint8_t)reason; s->ignored++;
    return status;
}
static int fail(struct snap_wpa2 *s, int status, unsigned reason)
{
    s->phase = SNAP_WPA2_FAILED; s->reason = (uint8_t)reason; s->m4_wanted = 0;
    clear_keys(s);
    if (!s->tx_pending) snap_wpa2_clear(s->tx, sizeof(s->tx));
    if (s->station && s->station->generation == s->generation) {
        struct snap_station_event e;
        memset(&e, 0, sizeof(e));
        e.generation = s->generation; e.transaction = s->link; e.status = status;
        e.type = s->station->connected ? SNAP_STATION_DISCONNECTED : SNAP_STATION_ERROR;
        snap_station_event(s->station, &e);
    }
    return status;
}
static int current(const struct snap_wpa2 *s)
{
    return s && s->station && s->generation == s->station->generation &&
           s->link == s->station->link_transaction && s->station->associated &&
           !s->station->quarantined;
}
/* A transmit the transport refuses is a lost frame: the authenticator retransmits. */
static int send_frame(struct snap_wpa2 *s)
{
    if (s->tx_pending) return SNAP_STATION_BUSY;
    if (s->station->last_transaction == UINT64_MAX) return fail(s, SNAP_STATION_INVALID, SNAP_WPA2_R_STATION);
    s->tx_transaction = ++s->station->last_transaction;
    s->tx_pending = 1; s->in_callback = 1;
    int result = s->ops.transmit(s->context, s->generation, s->tx_transaction, s->tx, s->tx_length);
    s->in_callback = 0;
    if (result) { s->tx_pending = 0; s->tx_failures++; s->reason = SNAP_WPA2_R_TX; return SNAP_STATION_OK; }
    if (s->tx_is_m4) s->m4_sent++; else s->m2_sent++;
    return SNAP_STATION_OK;
}
static void mic(const uint8_t kck[16], const uint8_t *p, size_t n, uint8_t out[16])
{
    uint8_t copy[SNAP_WPA2_MAX_FRAME], digest[20];
    memcpy(copy, p, n); memset(copy + 95, 0, 16);
    snap_wpa2_hmac(kck, 16, copy + 14, n - 14, digest);
    memcpy(out, digest, 16);
    snap_wpa2_clear(copy, sizeof(copy)); snap_wpa2_clear(digest, sizeof(digest));
}
static int mic_ok(const uint8_t kck[16], const uint8_t *p, size_t n)
{
    uint8_t want[16];
    mic(kck, p, n, want);
    int ok = equal(want, p + 95, 16);
    snap_wpa2_clear(want, sizeof(want));
    return ok;
}
static int make_frame(struct snap_wpa2 *s, int fourth)
{
    if (s->tx_pending) return SNAP_STATION_BUSY;
    memset(s->tx, 0, sizeof(s->tx));
    memcpy(s->tx, s->station->peer, 6); memcpy(s->tx + 6, s->station->ready.mac, 6);
    put16(s->tx + 12, 0x888e); s->tx[14] = 2; s->tx[15] = 3;
    put16(s->tx + 16, (uint16_t)(95 + (fourth ? 0 : s->rsn_length)));
    s->tx[18] = 2; put16(s->tx + 19, fourth ? 0x30a : 0x10a);
    memcpy(s->tx + 23, s->replay, 8);
    if (!fourth) {
        memcpy(s->tx + 31, s->snonce, 32); put16(s->tx + 111, s->rsn_length);
        memcpy(s->tx + 113, s->rsn, s->rsn_length);
    }
    s->tx_length = (uint16_t)(113 + (fourth ? 0 : s->rsn_length));
    uint8_t value[16];
    mic(fourth ? s->kck : s->ptk, s->tx, s->tx_length, value);
    memcpy(s->tx + 95, value, 16); snap_wpa2_clear(value, sizeof(value));
    s->tx_is_m4 = (uint8_t)fourth;
    return send_frame(s);
}
static void derive(struct snap_wpa2 *s)
{
    uint8_t input[100], digest[20];
    static const uint8_t label[] = "Pairwise key expansion";
    memcpy(input, label, sizeof(label));
    const uint8_t *a = s->station->peer, *b = s->station->ready.mac;
    if (memcmp(a, b, 6) > 0) { const uint8_t *t = a; a = b; b = t; }
    memcpy(input + sizeof(label), a, 6); memcpy(input + sizeof(label) + 6, b, 6);
    a = s->anonce; b = s->snonce;
    if (memcmp(a, b, 32) > 0) { const uint8_t *t = a; a = b; b = t; }
    memcpy(input + sizeof(label) + 12, a, 32); memcpy(input + sizeof(label) + 44, b, 32);
    for (unsigned i = 0; i < 3; ++i) {
        input[sizeof(label) + 76] = (uint8_t)i;
        snap_wpa2_hmac(s->pmk, 32, input, sizeof(label) + 77, digest);
        memcpy(s->ptk + 20 * i, digest, i == 2 ? 8 : 20);
    }
    snap_wpa2_clear(input, sizeof(input)); snap_wpa2_clear(digest, sizeof(digest));
}
static int submit_control(struct snap_wpa2 *s, unsigned phase)
{
    struct snap_station_control r;
    memset(&r, 0, sizeof(r));
    if (s->station->last_transaction == UINT64_MAX) return fail(s, SNAP_STATION_INVALID, SNAP_WPA2_R_STATION);
    r.generation = s->generation; r.link_transaction = s->link;
    r.transaction = s->station->last_transaction + 1;
    if (phase == SNAP_WPA2_AUTHORIZE) r.type = SNAP_STATION_PORT_AUTHORIZE;
    else {
        r.type = SNAP_STATION_KEY_INSTALL; r.cipher = SNAP_STATION_CIPHER_CCMP128;
        r.key_length = 16; r.pairwise = phase == SNAP_WPA2_PTK;
        r.index = r.pairwise ? 0 : s->key_index;
        if (r.pairwise) { memcpy(r.peer, s->station->peer, 6); memcpy(r.key, s->ptk + 32, 16); }
        else { memset(r.peer, 255, 6); memcpy(r.key, s->gtk, 16); memcpy(r.rx_pn, s->pn, 6); }
    }
    s->phase = (uint8_t)phase; s->control_transaction = r.transaction;
    s->in_callback = 1;
    int result = snap_station_control_submit(s->station, &r);
    s->in_callback = 0;
    snap_wpa2_clear(&r, sizeof(r));
    return result ? fail(s, result, SNAP_WPA2_R_CONTROL) : SNAP_STATION_OK;
}
int snap_wpa2_start(struct snap_wpa2 *s, struct snap_station *station,
                   const struct snap_wpa2_ops *ops, void *context,
                   const uint8_t pmk[32], const struct snap_wpa2_ap *ap, uint64_t now_ms)
{
    if (!s || !station || !ops || !ops->transmit || !ops->random || !pmk || !ap ||
        !station->associated || !station->secure || station->connected ||
        station->pending.type != SNAP_STATION_CONNECT || !station->ops.control ||
        !snap_rsn_is_own(station->pending.ies, station->pending.ie_length) || now_ms > UINT64_MAX - 15000)
        return SNAP_STATION_INVALID;
    if (ap->rsn_length > SNAP_RSN_MAX_ELEMENT || ap->rsnxe_length > SNAP_RSN_MAX_RSNXE ||
        snap_rsn_ap_policy(ap->rsn, ap->rsn_length, 0) ||
        (ap->rsnxe_length && (ap->rsnxe_length < 3 || ap->rsnxe[0] != 244 || ap->rsnxe[1] + 2U != ap->rsnxe_length)))
        return SNAP_STATION_UNSUPPORTED;
    if (s->tx_pending || (s->phase && s->phase != SNAP_WPA2_FAILED)) return SNAP_STATION_BUSY;
    memset(s, 0, sizeof(*s));
    s->station = station; s->ops = *ops; s->context = context;
    s->generation = station->generation; s->link = station->link_transaction;
    s->deadline_ms = now_ms + 15000; s->rsn_length = SNAP_RSN_OWN_LENGTH;
    memcpy(s->rsn, station->pending.ies, SNAP_RSN_OWN_LENGTH); memcpy(s->pmk, pmk, 32); s->ap = *ap;
    s->in_callback = 1;
    int result = s->ops.random(context, s->snonce, 32);
    s->in_callback = 0;
    if (result || zero(s->snonce, 32)) return fail(s, SNAP_STATION_NOT_READY, SNAP_WPA2_R_RANDOM);
    s->phase = SNAP_WPA2_WAIT_M1;
    return SNAP_STATION_OK;
}
/* Message 1: first, a retransmission (hostapd increments the replay counter) or a new ANonce. */
static int message1(struct snap_wpa2 *s, const uint8_t *p)
{
    const uint8_t *counter = p + 23, *nonce = p + 31;
    if (zero(nonce, 32)) return ignore(s, SNAP_STATION_INVALID, SNAP_WPA2_R_ANONCE);
    if (s->phase == SNAP_WPA2_WAIT_M1) {
        s->m1_received++;
        memcpy(s->anonce, nonce, 32); memcpy(s->m1_replay, counter, 8); memcpy(s->replay, counter, 8);
        derive(s); s->phase = SNAP_WPA2_WAIT_M3;
        return make_frame(s, 0);
    }
    /* After an authentic M3 a new M1 would be a rekey: not supported, ignored. */
    if (s->phase != SNAP_WPA2_WAIT_M3) return ignore(s, SNAP_STATION_STALE, SNAP_WPA2_R_STALE);
    int order = memcmp(counter, s->m1_replay, 8);
    if (order < 0) return ignore(s, SNAP_STATION_STALE, SNAP_WPA2_R_REPLAY);
    if (!order && !equal(nonce, s->anonce, 32)) return ignore(s, SNAP_STATION_INVALID, SNAP_WPA2_R_REPLAY);
    if (s->tx_pending) return ignore(s, SNAP_STATION_BUSY, SNAP_WPA2_R_STALE);
    s->m1_received++;
    if (!equal(nonce, s->anonce, 32)) { memcpy(s->anonce, nonce, 32); derive(s); }
    memcpy(s->m1_replay, counter, 8); memcpy(s->replay, counter, 8);
    return make_frame(s, 0);   /* the same SNonce, the new counter */
}
/* M3 again after the keys were installed: authenticate with the kept KCK, answer with M4,
 * never reinstall a key or reset a packet number. */
static int message3_again(struct snap_wpa2 *s, const uint8_t *p, size_t n)
{
    if (!s->kck_valid) return ignore(s, SNAP_STATION_STALE, SNAP_WPA2_R_STALE);
    if (!equal(p + 31, s->anonce, 32)) return ignore(s, SNAP_STATION_INVALID, SNAP_WPA2_R_ANONCE);
    if (memcmp(p + 23, s->m3_replay, 8) < 0) return ignore(s, SNAP_STATION_STALE, SNAP_WPA2_R_REPLAY);
    if (!mic_ok(s->kck, p, n)) return ignore(s, SNAP_STATION_INVALID, SNAP_WPA2_R_MIC);
    if (s->tx_pending || s->m4_wanted) return ignore(s, SNAP_STATION_BUSY, SNAP_WPA2_R_STALE);
    s->m3_received++;
    memcpy(s->m3_replay, p + 23, 8); memcpy(s->replay, p + 23, 8);
    return make_frame(s, 1);
}
static int message3(struct snap_wpa2 *s, const uint8_t *p, size_t n)
{
    if (s->phase == SNAP_WPA2_PTK || s->phase == SNAP_WPA2_GTK)
        return ignore(s, SNAP_STATION_BUSY, SNAP_WPA2_R_STALE);          /* never install twice */
    if (s->phase == SNAP_WPA2_M4 || s->phase == SNAP_WPA2_AUTHORIZE || s->phase == SNAP_WPA2_CONNECTED)
        return message3_again(s, p, n);
    if (s->phase != SNAP_WPA2_WAIT_M3) return ignore(s, SNAP_STATION_STALE, SNAP_WPA2_R_STALE);
    if (be16(p + 21) != 16) return ignore(s, SNAP_STATION_INVALID, SNAP_WPA2_R_KEY_LENGTH);
    if (!equal(p + 31, s->anonce, 32)) return ignore(s, SNAP_STATION_INVALID, SNAP_WPA2_R_ANONCE);
    if (memcmp(p + 23, s->m1_replay, 8) <= 0) return ignore(s, SNAP_STATION_INVALID, SNAP_WPA2_R_REPLAY);
    if (!mic_ok(s->ptk, p, n)) return ignore(s, SNAP_STATION_INVALID, SNAP_WPA2_R_MIC);
    /* Authentic from here: a bad element is the AP's (or a downgrade), so the handshake ends. */
    unsigned wrapped = be16(p + 111);
    uint8_t plain[256];
    if (!snap_wpa2_unwrap(s->ptk + 16, p + 113, wrapped, plain))
        return fail(s, SNAP_STATION_INVALID, SNAP_WPA2_R_WRAP);
    unsigned bad = 0, rsn = 0, rsn2 = 0, rsnxe = 0, gtk = 0, offset = 0, length = wrapped - 8;
    while (offset < length) {
        if (plain[offset] == 0xdd && zero(plain + offset + 1, length - offset - 1)) break;   /* padding */
        if (length - offset < 2 || (unsigned)plain[offset + 1] + 2 > length - offset) { bad = SNAP_WPA2_R_GTK; break; }
        const uint8_t *ie = plain + offset;
        unsigned bytes = (unsigned)ie[1] + 2;
        if (ie[0] == 48 && !rsn) {
            rsn = 1;
            if (bytes != s->ap.rsn_length || !equal(ie, s->ap.rsn, bytes)) { bad = SNAP_WPA2_R_RSNE; break; }
        } else if (ie[0] == 48) {
            struct snap_rsn assigned;   /* the pairwise suite the AP assigns: must be ours */
            if (rsn2++ || snap_rsn_parse(ie, bytes, &assigned) || assigned.pairwise_count != 1 ||
                !assigned.pairwise_ccmp) { bad = SNAP_WPA2_R_RSNE2; break; }
        } else if (ie[0] == 244 && !rsnxe) {
            rsnxe = 1;
            if (bytes != s->ap.rsnxe_length || !equal(ie, s->ap.rsnxe, bytes)) { bad = SNAP_WPA2_R_RSNXE; break; }
        } else if (ie[0] == 221 && bytes >= 6 && ie[2] == 0 && ie[3] == 15 && ie[4] == 172 && ie[5] == 1) {
            /* GTK KDE: key id in bits 0-1; the Tx bit and reserved bits are ignored (wpa_supplicant) */
            if (gtk || bytes != 24 || !(ie[6] & 3)) { bad = SNAP_WPA2_R_GTK; break; }
            gtk = 1; s->key_index = (uint8_t)(ie[6] & 3); memcpy(s->gtk, ie + 8, 16);
        }
        /* any other element or KDE (IGTK, transition disable, vendor) is ignored */
        offset += bytes;
    }
    snap_wpa2_clear(plain, sizeof(plain));
    if (!bad && !rsn) bad = SNAP_WPA2_R_RSNE;
    if (!bad && s->ap.rsnxe_length && !rsnxe) bad = SNAP_WPA2_R_RSNXE;
    if (!bad && !gtk) bad = SNAP_WPA2_R_GTK;
    if (bad) return fail(s, SNAP_STATION_UNSUPPORTED, bad);
    s->m3_received++;
    memcpy(s->pn, p + 79, 6); memcpy(s->replay, p + 23, 8); memcpy(s->m3_replay, p + 23, 8);
    memcpy(s->kck, s->ptk, 16); s->kck_valid = 1;
    return submit_control(s, SNAP_WPA2_PTK);
}
int snap_wpa2_receive(struct snap_wpa2 *s, const uint8_t *p, size_t n, uint64_t now_ms)
{
    if (!s || s->in_callback) return SNAP_STATION_BUSY;
    if (!current(s)) return SNAP_STATION_STALE;
    if (s->phase == SNAP_WPA2_FAILED) return SNAP_STATION_NOT_READY;
    if (s->phase != SNAP_WPA2_CONNECTED && now_ms >= s->deadline_ms)
        return fail(s, SNAP_STATION_NOT_READY, SNAP_WPA2_R_TIMEOUT);
    if (!p || n < 113 || n > SNAP_WPA2_MAX_FRAME ||
        !equal(p, s->station->ready.mac, 6) || !equal(p + 6, s->station->peer, 6) ||
        be16(p + 12) != 0x888e || p[14] < 1 || p[14] > 3 || p[15] != 3 ||
        (size_t)be16(p + 16) + 18 != n || p[18] != 2 || (size_t)be16(p + 111) + 113 != n)
        return ignore(s, SNAP_STATION_INVALID, SNAP_WPA2_R_MALFORMED);
    unsigned info = be16(p + 19);
    if (info == 0x8a) return message1(s, p);   /* key data (e.g. a PMKID KDE) is ignored for PSK */
    if (info == 0x13ca) return message3(s, p, n);
    return ignore(s, SNAP_STATION_UNSUPPORTED, SNAP_WPA2_R_KEY_INFO);
}
int snap_wpa2_tx_done(struct snap_wpa2 *s, uint64_t generation, uint64_t transaction, int status)
{
    if (!s || s->in_callback) return SNAP_STATION_BUSY;
    if (!s->tx_pending || generation != s->generation || transaction != s->tx_transaction)
        return SNAP_STATION_STALE;
    s->tx_pending = 0;
    if (s->phase == SNAP_WPA2_FAILED) { snap_wpa2_clear(s->tx, sizeof(s->tx)); return SNAP_STATION_NOT_READY; }
    if (!current(s)) return fail(s, SNAP_STATION_STALE, SNAP_WPA2_R_STATION);
    if (status) { s->tx_failures++; s->reason = SNAP_WPA2_R_TX; }
    if (s->phase == SNAP_WPA2_M4 && s->m4_wanted) {        /* M2's buffer is free now */
        s->m4_wanted = 0; memcpy(s->replay, s->m3_replay, 8);
        return make_frame(s, 1);
    }
    /* An unacknowledged M4 still authorizes: the AP resends M3 if it lacked M4 (19, 20). */
    if (s->tx_is_m4 && s->phase == SNAP_WPA2_M4) return submit_control(s, SNAP_WPA2_AUTHORIZE);
    return SNAP_STATION_OK;
}
int snap_wpa2_control_done(struct snap_wpa2 *s, const struct snap_station_event *e)
{
    if (!s || s->in_callback) return SNAP_STATION_BUSY;
    if (!e || !current(s) || e->type != SNAP_STATION_CONTROL_DONE ||
        e->generation != s->generation || e->transaction != s->control_transaction ||
        e->link_transaction != s->link || s->station->control.type)
        return SNAP_STATION_STALE;
    if (s->phase != SNAP_WPA2_PTK && s->phase != SNAP_WPA2_GTK && s->phase != SNAP_WPA2_AUTHORIZE)
        return SNAP_STATION_STALE;
    if (e->status) return fail(s, e->status, SNAP_WPA2_R_CONTROL);
    if (s->phase == SNAP_WPA2_PTK) return submit_control(s, SNAP_WPA2_GTK);
    if (s->phase == SNAP_WPA2_GTK) {
        s->phase = SNAP_WPA2_M4;
        if (s->tx_pending) { s->m4_wanted = 1; return SNAP_STATION_OK; }
        memcpy(s->replay, s->m3_replay, 8);
        return make_frame(s, 1);
    }
    struct snap_station_event connected;
    memset(&connected, 0, sizeof(connected));
    connected.generation = s->generation; connected.transaction = s->link;
    connected.type = SNAP_STATION_CONNECTED;
    int result = snap_station_event(s->station, &connected);
    if (result) return fail(s, result, SNAP_WPA2_R_STATION);
    s->phase = SNAP_WPA2_CONNECTED;
    /* The KCK stays until the handshake deadline to answer a retransmitted M3 (19). */
    snap_wpa2_clear(s->pmk, sizeof(s->pmk)); snap_wpa2_clear(s->ptk, sizeof(s->ptk));
    snap_wpa2_clear(s->gtk, sizeof(s->gtk));
    return SNAP_STATION_OK;
}
int snap_wpa2_tick(struct snap_wpa2 *s, uint64_t now_ms)
{
    if (!s || s->in_callback) return SNAP_STATION_BUSY;
    if (!s->phase) return SNAP_STATION_OK;
    if (s->phase == SNAP_WPA2_CONNECTED) {
        if (s->kck_valid && now_ms >= s->deadline_ms) { snap_wpa2_clear(s->kck, sizeof(s->kck)); s->kck_valid = 0; }
        return SNAP_STATION_OK;
    }
    if (s->phase == SNAP_WPA2_FAILED) return SNAP_STATION_NOT_READY;
    if (!current(s)) return fail(s, SNAP_STATION_NOT_READY, SNAP_WPA2_R_STATION);
    if (now_ms >= s->deadline_ms) return fail(s, SNAP_STATION_NOT_READY, SNAP_WPA2_R_TIMEOUT);
    return SNAP_STATION_OK;
}
int snap_wpa2_abort(struct snap_wpa2 *s, int quiesced)
{
    if (!s || s->in_callback) return SNAP_STATION_BUSY;
    if (s->phase) fail(s, SNAP_STATION_CANCELLED, SNAP_WPA2_R_ABORT);
    if (s->tx_pending && !quiesced) return SNAP_STATION_BUSY;
    snap_wpa2_clear(s, sizeof(*s));
    return SNAP_STATION_OK;
}
static int hex(uint8_t c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}
int snap_wpa2_pmk(const uint8_t *pw, size_t n, const uint8_t *ssid, size_t ssid_length, uint8_t pmk[32])
{
    if (!pw || !ssid || !pmk || !ssid_length || ssid_length > 32) return SNAP_STATION_INVALID;
    if (n == 64) {                       /* a raw PSK (wpa_supplicant psk=<64 hex>) */
        uint8_t raw[32];
        for (unsigned i = 0; i < 32; i++) {
            int hi = hex(pw[2 * i]), lo = hex(pw[2 * i + 1]);
            if (hi < 0 || lo < 0) { snap_wpa2_clear(raw, sizeof(raw)); return SNAP_STATION_INVALID; }
            raw[i] = (uint8_t)(hi << 4 | lo);
        }
        memcpy(pmk, raw, 32); snap_wpa2_clear(raw, sizeof(raw));
        return SNAP_STATION_OK;
    }
    if (n < 8 || n > 63) return SNAP_STATION_INVALID;
    for (size_t i = 0; i < n; i++) if (pw[i] < 32 || pw[i] > 126) return SNAP_STATION_INVALID;
    uint8_t salt[36], u[20], t[20], out[40];
    for (unsigned block = 1; block <= 2; block++) {   /* PBKDF2-HMAC-SHA1, 4096 iterations */
        memcpy(salt, ssid, ssid_length);
        salt[ssid_length] = 0; salt[ssid_length + 1] = 0; salt[ssid_length + 2] = 0;
        salt[ssid_length + 3] = (uint8_t)block;
        snap_wpa2_hmac(pw, n, salt, ssid_length + 4, u);
        memcpy(t, u, 20);
        for (unsigned i = 1; i < 4096; i++) {
            snap_wpa2_hmac(pw, n, u, 20, u);
            for (unsigned k = 0; k < 20; k++) t[k] ^= u[k];
        }
        memcpy(out + 20 * (block - 1), t, 20);
    }
    memcpy(pmk, out, 32);
    snap_wpa2_clear(salt, sizeof(salt)); snap_wpa2_clear(u, sizeof(u));
    snap_wpa2_clear(t, sizeof(t)); snap_wpa2_clear(out, sizeof(out));
    return SNAP_STATION_OK;
}
const char *snap_wpa2_reason(unsigned reason)
{
    static const char *const names[SNAP_WPA2_R_COUNT] = {
        "none", "handshake deadline (15 s)", "malformed EAPOL-Key frame", "unsupported key information",
        "stale or out-of-order message", "ANonce mismatch", "replay counter not newer", "MIC mismatch",
        "AES key unwrap failed", "M3 RSN element differs from the beacon's", "M3 RSNXE differs from the beacon's",
        "M3 second RSN element assigns a cipher other than CCMP", "GTK KDE missing or invalid",
        "key length is not 16", "EAPOL transmit not acknowledged", "key or authorize control failed",
        "station link changed", "random source failed", "AP RSN element not joinable", "aborted"};
    return reason < SNAP_WPA2_R_COUNT ? names[reason] : "unknown";
}

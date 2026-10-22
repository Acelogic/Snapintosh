/* SPDX-License-Identifier: MIT */
#ifndef SNAP_NATIVE_WPA2_H
#define SNAP_NATIVE_WPA2_H
#include "native-station.h"
#include "native-rsn.h"
#include <stddef.h>
#ifdef __cplusplus
extern "C" {
#endif
enum { SNAP_WPA2_MAX_FRAME = 512, SNAP_WPA2_WAIT_M1 = 1,
    SNAP_WPA2_WAIT_M3, SNAP_WPA2_PTK, SNAP_WPA2_GTK, SNAP_WPA2_M4,
    SNAP_WPA2_AUTHORIZE, SNAP_WPA2_CONNECTED, SNAP_WPA2_FAILED };
/* Why the last frame was refused or the handshake failed (logs; never key material). */
enum { SNAP_WPA2_R_NONE, SNAP_WPA2_R_TIMEOUT, SNAP_WPA2_R_MALFORMED, SNAP_WPA2_R_KEY_INFO,
    SNAP_WPA2_R_STALE, SNAP_WPA2_R_ANONCE, SNAP_WPA2_R_REPLAY, SNAP_WPA2_R_MIC, SNAP_WPA2_R_WRAP,
    SNAP_WPA2_R_RSNE, SNAP_WPA2_R_RSNXE, SNAP_WPA2_R_RSNE2, SNAP_WPA2_R_GTK, SNAP_WPA2_R_KEY_LENGTH,
    SNAP_WPA2_R_TX, SNAP_WPA2_R_CONTROL, SNAP_WPA2_R_STATION, SNAP_WPA2_R_RANDOM, SNAP_WPA2_R_AP_RSN,
    SNAP_WPA2_R_ABORT, SNAP_WPA2_R_COUNT };
struct snap_wpa2_ops {
    /* Both callbacks are serialized, non-reentrant. Accepted TX borrows the
     * immutable frame until tx_done or caller-proven transport quiescence.
     * A non-zero tx_done status (not acknowledged) does not end the handshake:
     * the authenticator retransmits M1/M3, as 802.11 and hostapd do. */
    int (*transmit)(void *, uint64_t, uint64_t, const uint8_t *, size_t);
    int (*random)(void *, uint8_t *, size_t);
};
/* The AP's elements from the beacon/probe response the association used: M3 must carry this
 * RSN element byte for byte and this RSNXE (or none if the beacon had none), as wpa_supplicant. */
struct snap_wpa2_ap {
    uint8_t rsn[SNAP_RSN_MAX_ELEMENT], rsnxe[SNAP_RSN_MAX_RSNXE];
    uint8_t rsn_length, rsnxe_length;
};
struct snap_wpa2 {
    struct snap_station *station;
    struct snap_wpa2_ops ops;
    void *context;
    uint64_t generation, link, deadline_ms, tx_transaction, control_transaction;
    uint8_t phase, in_callback, tx_pending, tx_is_m4, key_index, kck_valid, m4_wanted, reason;
    uint8_t pmk[32], ptk[48], kck[16], snonce[32], anonce[32], gtk[16], pn[6];
    uint8_t rsn[SNAP_RSN_OWN_LENGTH], rsn_length, replay[8], m1_replay[8], m3_replay[8];
    struct snap_wpa2_ap ap;
    uint8_t tx[SNAP_WPA2_MAX_FRAME];
    uint16_t tx_length;
    /* counters for logs */
    uint32_t m1_received, m2_sent, m3_received, m4_sent, tx_failures, ignored;
};
/* station->pending must be the CONNECT whose request element is snap_rsn_own; ap must pass
 * snap_rsn_ap_policy. The PMK is kept until the handshake ends (a new ANonce re-derives). */
int snap_wpa2_start(struct snap_wpa2 *, struct snap_station *,
                   const struct snap_wpa2_ops *, void *, const uint8_t pmk[32],
                   const struct snap_wpa2_ap *ap, uint64_t now_ms);
int snap_wpa2_receive(struct snap_wpa2 *, const uint8_t *, size_t, uint64_t now_ms);
int snap_wpa2_tx_done(struct snap_wpa2 *, uint64_t generation, uint64_t transaction,
                     int status);
/* Deliver only after snap_station_event has accepted the CONTROL_DONE. */
int snap_wpa2_control_done(struct snap_wpa2 *, const struct snap_station_event *);
int snap_wpa2_tick(struct snap_wpa2 *, uint64_t now_ms);
/* Returns BUSY while accepted transmit still borrows state storage. After a
 * successful provider stop, the caller may pass quiesced=1 to release it. */
int snap_wpa2_abort(struct snap_wpa2 *, int quiesced);
/* PBKDF2-HMAC-SHA1(passphrase, ssid, 4096, 32) for 8..63 printable ASCII characters, or the
 * PSK itself for 64 hex digits. Returns 0, or SNAP_STATION_INVALID without touching pmk.
 * Intermediates are wiped; the caller owns and wipes passphrase and pmk. */
int snap_wpa2_pmk(const uint8_t *passphrase, size_t length, const uint8_t *ssid, size_t ssid_length,
                  uint8_t pmk[32]);
const char *snap_wpa2_reason(unsigned reason);
#ifdef __cplusplus
}
#endif
#endif

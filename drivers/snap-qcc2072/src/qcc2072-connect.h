/* SPDX-License-Identifier: MIT */
#ifndef SNAP_QCC2072_CONNECT_H
#define SNAP_QCC2072_CONNECT_H
#include "native-wpa2.h"
#ifdef __cplusplus
extern "C" {
#endif
/* The WPA2 connect engine both bridges run (re/host-proxy glue and the kext controller):
 * snap_station <-> snap_wpa2 <-> the provider's data path. Failure inventory:
 * re/connect/FAILURES.md 17-31.
 *
 * Nothing acts inside a callback. station_event (from the bridge's snap_station event
 * callback), rx and tx_done (from the provider's dp-io callbacks, inside provider poll) only
 * copy; qcc2072_connect_service, called by the owner after qcc2072_provider_poll returned and
 * outside every callback, delivers TX completions, then station events, then EAPOL frames to
 * snap_wpa2. EAPOL goes out through transmit WITHOUT QCC2072_DPIO_TX_PROTECTED (M4 included);
 * the bridge's transmit must copy the frame (dp-io does). Received EAPOL reaches snap_wpa2
 * only after eapol_admit accepted it; frames that arrive before ASSOCIATED wait (4 kept). */
enum { QCC2072_CONNECT_IDLE, QCC2072_CONNECT_ARMED, QCC2072_CONNECT_HANDSHAKE, QCC2072_CONNECT_CONNECTED,
       QCC2072_CONNECT_FAILED, QCC2072_CONNECT_DISCONNECTED };
#define QCC2072_CONNECT_TAG 0x4541504f00000000ULL   /* dp-io tag space of EAPOL frames ("EAPO") */
#define QCC2072_CONNECT_TAG_MASK 0xffffffff00000000ULL
#define QCC2072_CONNECT_RX_SLOTS 4U
/* note codes: (a, b) meaning in qcc2072_connect_note_name's comment */
enum { QCC2072_CONNECT_N_ARMED = 1, QCC2072_CONNECT_N_ASSOCIATED, QCC2072_CONNECT_N_START,
       QCC2072_CONNECT_N_RX, QCC2072_CONNECT_N_TX, QCC2072_CONNECT_N_TX_DONE, QCC2072_CONNECT_N_CONTROL_DONE,
       QCC2072_CONNECT_N_CONNECTED, QCC2072_CONNECT_N_FAILED, QCC2072_CONNECT_N_DISCONNECTED,
       QCC2072_CONNECT_N_DISCONNECT, QCC2072_CONNECT_N_FOREIGN, QCC2072_CONNECT_N_DROPPED,
       QCC2072_CONNECT_N_COUNT };
struct qcc2072_connect_ops {
    void *context;
    /* qcc2072_provider_data_tx(frame, length, tag, tid 0, flags 0); the frame is copied. */
    int (*transmit)(void *, const uint8_t *frame, size_t length, uint64_t tag);
    int (*random)(void *, uint8_t *, size_t);
    /* qcc2072_assoc_eapol_admit on the provider's link: 0 admits. */
    int (*eapol_admit)(void *, const uint8_t *frame, size_t length, int transmit);
    /* The AP's RSN element and RSNXE of the link the association used. */
    int (*link_security)(void *, struct snap_wpa2_ap *);
    /* Provider-level teardown of a link snap_station already dropped (snap_wpa2 failed). */
    int (*disconnect)(void *, uint64_t link_transaction, uint16_t reason);
    /* Optional. Codes and numbers only, never key material. */
    void (*note)(void *, unsigned code, int64_t a, int64_t b);
};
struct qcc2072_connect_event { uint64_t generation, transaction, link_transaction; uint32_t type; int32_t status; };
struct qcc2072_connect {
    struct qcc2072_connect_ops ops;
    struct snap_station *station;
    struct snap_wpa2 wpa;
    struct snap_station_event scratch;
    uint8_t pmk[32], bssid[6], own[6];
    uint64_t transaction, link, tx_tag, tx_transaction, now_ms;
    uint32_t tx_sequence;
    uint8_t state, has_pmk, in_service, disconnect_due, reason, initialized;
    uint16_t disconnect_reason;
    struct qcc2072_connect_event events[16];
    unsigned event_count;
    struct { uint64_t tag; int32_t status; } done[8];
    unsigned done_count;
    struct { uint16_t length; uint8_t frame[SNAP_WPA2_MAX_FRAME]; } rx[QCC2072_CONNECT_RX_SLOTS];
    unsigned rx_count;
    uint32_t rx_dropped, events_dropped, done_dropped, foreign, admitted;
};
void qcc2072_connect_init(struct qcc2072_connect *, struct snap_station *, const struct qcc2072_connect_ops *);
/* After snap_station_submit(CONNECT) returned OK: the PMK is copied and handed to snap_wpa2
 * at ASSOCIATED; the caller wipes its own copy. */
int qcc2072_connect_arm(struct qcc2072_connect *, uint64_t transaction, const uint8_t bssid[6],
                        const uint8_t own[6], const uint8_t pmk[32]);
/* Copy only (the bridge's snap_station event callback). */
void qcc2072_connect_station_event(struct qcc2072_connect *, const struct snap_station_event *);
/* dp-io rx callback: 1 if the frame was EAPOL for this connect (copied or counted), else 0. */
int qcc2072_connect_rx(struct qcc2072_connect *, const uint8_t *frame, size_t length);
/* dp-io tx_done callback: 1 if the tag is ours. status: QCC2072_DPIO_TX_* (0 = acknowledged). */
int qcc2072_connect_tx_done(struct qcc2072_connect *, uint64_t tag, int status);
/* Owner queue, after provider poll, outside every callback. Returns the engine state. */
int qcc2072_connect_service(struct qcc2072_connect *, uint64_t now_ms);
/* Wipes the PMK, snap_wpa2 and queued frames; state IDLE. */
void qcc2072_connect_abort(struct qcc2072_connect *);
const char *qcc2072_connect_note_name(unsigned code);
const char *qcc2072_connect_state_name(unsigned state);
#ifdef __cplusplus
}
#endif
#endif

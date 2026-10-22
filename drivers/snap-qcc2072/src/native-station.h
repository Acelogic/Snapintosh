/* SPDX-License-Identifier: MIT */
#ifndef SNAP_NATIVE_STATION_H
#define SNAP_NATIVE_STATION_H
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Internal normalized ABI. These are NOT Apple or Qualcomm wire structures. */
enum {
    SNAP_STATION_OK = 0, SNAP_STATION_INVALID = -1,
    SNAP_STATION_NOT_READY = -2, SNAP_STATION_BUSY = -3,
    SNAP_STATION_STALE = -4, SNAP_STATION_CANCELLED = -5,
    SNAP_STATION_UNSUPPORTED = -6
};
enum {
    SNAP_STATION_MAX_CHANNELS = 64, SNAP_STATION_MAX_IE = 1024,
    SNAP_STATION_CAP_SCAN = 1, SNAP_STATION_CAP_CONNECT = 2,
    SNAP_STATION_CAP_PRIVATE_SCAN = 4,
    SNAP_STATION_READY_SERVICE = 1, SNAP_STATION_READY_WMI_READY = 2,
    SNAP_STATION_READY_MAC = 4, SNAP_STATION_READY_REGULATORY = 8,
    SNAP_STATION_READY_ALL = 15
};
enum { SNAP_STATION_SCAN = 1, SNAP_STATION_CONNECT = 2 };
enum {
    SNAP_STATION_BSS = 1, SNAP_STATION_SCAN_DONE, SNAP_STATION_ASSOCIATED,
    SNAP_STATION_CONNECTED, SNAP_STATION_DISCONNECTED,
    SNAP_STATION_CANCEL_ACK, SNAP_STATION_ERROR, SNAP_STATION_CONTROL_DONE
};
struct snap_station_ready {
    uint64_t generation;
    uint32_t observed, capabilities;
    uint8_t mac[6], country[2];
};
struct snap_station_request {
    /* generation is supplied by the bridge; transaction must increase. */
    uint64_t generation, transaction;
    uint32_t type;
    uint8_t ssid_length, ssid[32], bssid[6];
    uint16_t channel_count, channels_mhz[SNAP_STATION_MAX_CHANNELS];
    uint16_t ie_length;
    uint8_t ies[SNAP_STATION_MAX_IE];
    struct {
        uint8_t private_mac;
        uint32_t home_away_ms, mode, flags, active_dwell_ms, passive_dwell_ms;
        /* Preserved Apple policy fields; backend must reject unknown values. */
        uint32_t bss_type, parameter_50;
    } scan;
};
enum {
    SNAP_STATION_BSS_INTERVAL = 1, SNAP_STATION_BSS_CAPABILITY = 2,
    SNAP_STATION_BSS_RSSI = 4, SNAP_STATION_BSS_REQUIRED = 7
};
struct snap_station_bss {
    uint8_t bssid[6], ssid_length, ssid[32];
    uint16_t frequency_mhz;
    int16_t rssi_dbm;
    /* Set only for fields decoded from qualified firmware/frame metadata. */
    uint32_t observed;
    uint16_t beacon_interval_tu, capability;
    uint16_t ie_length;
    uint8_t ies[SNAP_STATION_MAX_IE];
};
enum {
    SNAP_STATION_KEY_INSTALL = 1, SNAP_STATION_KEY_REMOVE,
    SNAP_STATION_PORT_AUTHORIZE, SNAP_STATION_LINK_DISCONNECT,
    SNAP_STATION_CIPHER_CCMP128 = 1
};
struct snap_station_control {
    uint64_t generation, transaction, link_transaction;
    uint32_t type, cipher;
    uint8_t index, pairwise, key_length, peer[6], key[16], rx_pn[6];
    uint16_t reason;
};
struct snap_station_event {
    uint64_t generation, transaction;
    uint32_t type;
    int32_t status;
    uint64_t link_transaction; /* CONTROL_DONE only: connection ownership. */
    struct snap_station_bss bss;
};
struct snap_station_ops {
    /* Called on the owner's serialized work queue, never concurrently.
     * submit/cancel enqueue work; they MUST defer event delivery until return.
     * submit may borrow the immutable bridge-owned request until a terminal
     * event or successful stop. It must not retain it beyond that boundary.
     * stop returns OK only after DMA/callback quiescence for this generation.
     * CONNECTED means authentication AND required keys are installed; merely
     * receiving association success must emit ASSOCIATED instead.
     * Backend validates channel/security capabilities against actual firmware.
     * It must implement every supplied scan policy field or reject the request;
     * PRIVATE_SCAN capability attests real randomized probe MAC programming.
     */
    int (*submit)(void *, const struct snap_station_request *);
    int (*cancel)(void *, uint64_t generation, uint64_t transaction);
    int (*stop)(void *, uint64_t generation);
    /* Must consume the event synchronously; no reentry or retained pointer. */
    void (*event)(void *, const struct snap_station_event *);
    /* Optional explicit security/control path. Immutable borrow ends only at
     * matching CONTROL_DONE or successful stop. Never deliver inline. A link
     * disconnect does not release an independently borrowed key command.
     * PORT_AUTHORIZE completion attests the controlled port is programmed;
     * backend still emits CONNECTED separately. No key bytes may be logged. */
    int (*control)(void *, const struct snap_station_control *);
};
struct snap_station {
    struct snap_station_ops ops;
    void *context;
    uint64_t generation, last_transaction, link_transaction;
    struct snap_station_ready ready;
    struct snap_station_request pending;
    struct snap_station_control control;
    uint8_t peer[6], secure, pairwise_key, group_keys, authorized;
    uint8_t admitted, connected, cancelling, quarantined, in_callback, associated;
};
void snap_station_init(struct snap_station *, const struct snap_station_ops *, void *);
int snap_station_admit(struct snap_station *, const struct snap_station_ready *);
int snap_station_submit(struct snap_station *, const struct snap_station_request *);
int snap_station_control_submit(struct snap_station *, const struct snap_station_control *);
int snap_station_cancel(struct snap_station *, uint64_t transaction);
int snap_station_event(struct snap_station *, const struct snap_station_event *);
int snap_station_stop(struct snap_station *);

#ifdef __cplusplus
}
#endif
#endif

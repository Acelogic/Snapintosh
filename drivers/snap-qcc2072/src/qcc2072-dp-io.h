/* SPDX-License-Identifier: MIT */
#ifndef SNAP_QCC2072_DP_IO_H
#define SNAP_QCC2072_DP_IO_H
#include "qcc2072-datapath.h"
#ifdef __cplusplus
extern "C" {
#endif
/* QCC2072 data frame TX/RX on the rings qcc2072-datapath/-reo already programmed.
 * Failure inventory: re/dp-io/FAILURES.md. Byte reference: pinned ath12k
 * wifi7/dp_tx.c, wifi7/dp_rx.c, wifi7/hal_rx.c, wifi7/hal_tx.c (independent code).
 *
 * Frames in both directions are Ethernet II (DA, SA, ethertype, payload).
 * All calls share the provider's serialized owner queue. The rx/tx_done
 * callbacks may call qcc2072_dpio_tx and qcc2072_dpio_htt_t2h, nothing else.
 * Delivered RX bytes are borrowed for the callback only. TX bytes are copied. */

#define QCC2072_DPIO_TX_SLOTS 512U        /* cookies 0..511 (SPT page 0) */
#define QCC2072_DPIO_TX_SLOT_BYTES 2048U
#define QCC2072_DPIO_TX_ARENA 0x1a00000U  /* datapath-arena offset of TX slots */
#define QCC2072_DPIO_QDESC_ARENA 0x1b00000U
#define QCC2072_DPIO_QDESC_STRIDE 2048U
#define QCC2072_DPIO_TIDS 17U             /* 0..15 + non-QoS TID 16 */
#define QCC2072_DPIO_RX_BUFFERS 4095U
#define QCC2072_DPIO_MAX_FRAME 1600U      /* Ethernet frame accepted by tx */
#define QCC2072_DPIO_PEERS 8U

enum { QCC2072_DPIO_ENCAP_NATIVE_WIFI = 1, QCC2072_DPIO_ENCAP_ETHERNET = 2 };
/* tx flags */
enum { QCC2072_DPIO_TX_PROTECTED = 1U };
enum qcc2072_dpio_tx_status {
    QCC2072_DPIO_TX_ACKED = 0, QCC2072_DPIO_TX_NOT_ACKED = 1,
    QCC2072_DPIO_TX_DROPPED = 2, QCC2072_DPIO_TX_ERROR = 3
};
enum { QCC2072_DPIO_RX_REO = 0, QCC2072_DPIO_RX_NULL_QUEUE = 1 };

struct qcc2072_dpio_tx_result {
    uint64_t tag;
    uint8_t status, release_source, reason, transmit_count;
    uint8_t ack_rssi, tid, eapol, cookie_converted;
    uint16_t peer_id, slot;
};
struct qcc2072_dpio_rx_info {
    uint8_t source, ring, decap, tid;
    uint8_t first_msdu, last_msdu, mcast, decrypted;
    uint8_t from_ds, to_ds, addr2_valid, encrypt_type;
    uint8_t reo_error, l3_pad;
    uint16_t peer_id, sw_peer_id, msdu_length;
    uint32_t peer_metadata, cookie;
    uint8_t addr2[6];
};
struct qcc2072_dpio_callbacks {
    void *context;
    void (*rx)(void *, const uint8_t *frame, size_t length, const struct qcc2072_dpio_rx_info *);
    void (*tx_done)(void *, const struct qcc2072_dpio_tx_result *);
};
/* Must match what WMI configured for the vdev: TX_ENCAP_TYPE/RX_DECAP_TYPE =
 * encap, the pdev id used in VDEV_CREATE, lmac 0 (single-pdev QCC2072). */
struct qcc2072_dpio_vdev {
    uint8_t vdev_id, pdev_id, lmac_id, bank_id, encap, qos;
    uint8_t mac[6];
};
struct qcc2072_dpio_peer {
    uint8_t mac[6], vdev_id, valid, ast_valid, map_type;
    uint16_t peer_id, ast_hash, hw_peer_id;
};
struct qcc2072_dpio_stats {
    uint32_t tx_enqueued, tx_eapol, tx_full, tx_refused, tx_completed[4];
    uint32_t rx_delivered, rx_null_queue, rx_drop_push, rx_drop_error, rx_drop_decap;
    uint32_t rx_drop_length, rx_drop_not_done, rx_drop_chain, rx_drop_rbm;
    uint32_t rx_drop_wbm_other, rx_exception_msdu, rx_exception_link, rx_exception_skipped;
    uint32_t refill_posted, refill_deferred, link_returned, link_deferred;
    uint32_t peer_maps, peer_unmaps, htt_ignored;
    uint32_t last_bad[8];
};
struct qcc2072_dpio {
    struct qcc2072_datapath *dp;
    struct qcc2072_reo *reo;
    struct qcc2072_dpio_callbacks cb;
    struct qcc2072_dpio_vdev vdev;
    struct qcc2072_dpio_peer peers[QCC2072_DPIO_PEERS];
    struct qcc2072_dpio_stats stats;
    uint8_t bssid[6];
    uint8_t initialized, vdev_set, dscp_done, bss_set, busy, in_tx, in_callback;
    uint8_t quarantined, peer_metadata_version, reo_chain[8], wbm_chain;
    int quarantine_reason;
    uint32_t tcl_hp, sw2wbm_hp, refill_hp, comp_tp, rxerr_tp, exc_tp, reo_tp[8];
    uint32_t tx_free_count, rx_pending_count;
    uint8_t tx_state[QCC2072_DPIO_TX_SLOTS];
    uint8_t tx_eapol[QCC2072_DPIO_TX_SLOTS];
    uint64_t tx_tag[QCC2072_DPIO_TX_SLOTS];
    uint16_t tx_free[QCC2072_DPIO_TX_SLOTS];
    uint8_t rx_state[QCC2072_DPIO_RX_BUFFERS + 1];
    uint16_t rx_pending[QCC2072_DPIO_RX_BUFFERS + 1];
};

/* After datapath rx_prepare and all eight HTT ring setups, REO activated.
 * peer_metadata_version: the value WMI INIT carried (V1B=3 on QCC2072). */
int qcc2072_dpio_init(struct qcc2072_dpio *, struct qcc2072_datapath *,
    struct qcc2072_reo *, const struct qcc2072_dpio_callbacks *,
    uint8_t peer_metadata_version);
/* Programs the 32 DSCP-TID tables once and the vdev's TCL bank register
 * (ath12k ath12k_dp_vdev_tx_attach). Call after VDEV_CREATE + encap params. */
int qcc2072_dpio_set_vdev(struct qcc2072_dpio *, const struct qcc2072_dpio_vdev *);
/* Selects the AP. TX needs its HTT PEER_MAP2/3 (vdev, mac) for the AST index. */
int qcc2072_dpio_set_bss(struct qcc2072_dpio *, const uint8_t bssid[6]);
int qcc2072_dpio_clear_bss(struct qcc2072_dpio *);
/* HTT T2H message (bytes[0] = type). 0 consumed; RUNTIME_UNSUPPORTED not a
 * peer-map message (caller keeps its own handling); BAD_WIRE malformed. */
int qcc2072_dpio_htt_t2h(struct qcc2072_dpio *, const uint8_t *, size_t);
int qcc2072_dpio_peer_ready(const struct qcc2072_dpio *);
/* ath12k_wifi7_hal_reo_qdesc_setup(tid, ba 1, ssn 0, PN none) in the arena. */
int qcc2072_dpio_reo_qdesc(struct qcc2072_dpio *, unsigned tid, uint32_t *iova);
/* WMI command frames for qcc2072_service_send_wmi: u32 command id + TLV struct.
 * Return bytes written, 0 if the buffer is too small or arguments invalid. */
size_t qcc2072_dpio_wmi_reorder_setup(uint8_t *, size_t, uint32_t vdev_id,
    const uint8_t mac[6], unsigned tid, uint32_t queue_iova);
size_t qcc2072_dpio_wmi_default_routing(uint8_t *, size_t, uint32_t vdev_id,
    const uint8_t mac[6]);
size_t qcc2072_dpio_wmi_vdev_encap(uint8_t *, size_t, uint32_t vdev_id,
    int rx_decap, uint32_t value);
/* Ethernet II frame. tid applies to non-EAPOL frames (EAPOL uses 7 on a QoS
 * BSS, as mac80211 does). RUNTIME_FULL: nothing consumed, retry later. */
int qcc2072_dpio_tx(struct qcc2072_dpio *, const uint8_t *, size_t, uint64_t tag,
    unsigned tid, unsigned flags);
unsigned qcc2072_dpio_tx_pending(const struct qcc2072_dpio *);
int qcc2072_dpio_poll(struct qcc2072_dpio *, unsigned budget);
int qcc2072_dpio_abort(struct qcc2072_dpio *, int reason);
#ifdef __cplusplus
}
#endif
#endif

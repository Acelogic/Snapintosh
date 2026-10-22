/* SPDX-License-Identifier: MIT */
#ifndef SNAP_QCC2072_ASSOC_H
#define SNAP_QCC2072_ASSOC_H
#include <stddef.h>
#include <stdint.h>
#include "qcc2072-runtime.h"
#include "native-station.h"
#include "native-rsn.h"
#ifdef __cplusplus
extern "C" {
#endif
struct qcc2072_assoc;
/* Station connect for the QCC2072 STA vdev, as pinned ath12k (c03c1a14) and
 * mac80211 issue it for a WCN7850-family single-pdev chip (vdev_start_delay):
 *
 *   [radio pdev params] [VDEV_CREATE] [vdev config] TXPOWER, BEACON_INTERVAL,
 *   PEER_CREATE -> HTT PEER_MAP, DEFAULT_ROUTING, 17x REORDER_QUEUE_SETUP,
 *   VDEV_START -> VDEV_START_RESP, MGMT_TX(auth) -> auth resp,
 *   MGMT_TX(assoc req) -> assoc resp, BSS params, SET_HEMU_MODE,
 *   PEER_ASSOC -> PEER_ASSOC_CONF, MIMO_PS_STATE, VDEV_UP, [AUTHORIZE if open],
 *   OBSS_SPR, DTIM_POLICY  => ASSOCIATED
 *   controls: INSTALL_KEY -> INSTALL_KEY_COMPLETE (PTK, then GTK), AUTHORIZE
 *   teardown: [deauth] [key deletes] VDEV_DOWN, VDEV_STOP -> STOPPED,
 *             PEER_DELETE -> PEER_DELETE_RESP + HTT unmap
 *
 * Failure inventory: re/assoc/FAILURES.md. Byte-for-byte evidence: re/assoc/replay.py.
 * Every builder returns the size of a complete WMI frame (4-byte command id, then
 * TLVs) or 0 if it does not fit in min(cap, 2040). Nothing here touches hardware;
 * the provider sends the frames and feeds events back on its serialized poll loop. */

/* Pinned ath12k WMI ids (asserted against wmi.h by the replay). */
enum {
    QCC2072_ASSOC_CMD_VDEV_DELETE = 0x5002, QCC2072_ASSOC_CMD_VDEV_START = 0x5003,
    QCC2072_ASSOC_CMD_VDEV_UP = 0x5005, QCC2072_ASSOC_CMD_VDEV_STOP = 0x5006,
    QCC2072_ASSOC_CMD_VDEV_DOWN = 0x5007, QCC2072_ASSOC_CMD_VDEV_SET_PARAM = 0x5008,
    QCC2072_ASSOC_CMD_VDEV_INSTALL_KEY = 0x5009, QCC2072_ASSOC_CMD_PEER_CREATE = 0x6001,
    QCC2072_ASSOC_CMD_PEER_DELETE = 0x6002, QCC2072_ASSOC_CMD_PEER_SET_PARAM = 0x6004,
    QCC2072_ASSOC_CMD_PEER_ASSOC = 0x6005, QCC2072_ASSOC_CMD_PEER_REORDER_QUEUE_SETUP = 0x6013,
    QCC2072_ASSOC_CMD_PDEV_SET_PARAM = 0x4003, QCC2072_ASSOC_CMD_OBSS_SPR = 0x40001,
    QCC2072_ASSOC_CMD_STA_PS_MODE = 0x9001, QCC2072_ASSOC_CMD_STA_PS_PARAM = 0x9002,
    QCC2072_ASSOC_CMD_MGMT_TX_SEND = 0x7008,
    QCC2072_ASSOC_EV_SERVICE_READY = 0x1, QCC2072_ASSOC_EV_SERVICE_READY_EXT = 0x4009,
    QCC2072_ASSOC_EV_VDEV_START_RESP = 0x5001, QCC2072_ASSOC_EV_VDEV_STOPPED = 0x5002,
    QCC2072_ASSOC_EV_INSTALL_KEY_COMPLETE = 0x5003, QCC2072_ASSOC_EV_PEER_STA_KICKOUT = 0x6001,
    QCC2072_ASSOC_EV_PEER_ASSOC_CONF = 0x6006, QCC2072_ASSOC_EV_PEER_DELETE_RESP = 0x6007,
    QCC2072_ASSOC_EV_MGMT_RX = 0x7001, QCC2072_ASSOC_EV_MGMT_TX_COMPLETION = 0x7006,
    QCC2072_ASSOC_EV_ROAM = 0xb001, QCC2072_ASSOC_ROAM_REASON_BEACON_MISS = 2,
    /* HTT T2H message types (dp_htt.h) */
    QCC2072_ASSOC_HTT_PEER_MAP = 0x3, QCC2072_ASSOC_HTT_PEER_UNMAP = 0x4,
    QCC2072_ASSOC_HTT_PEER_MAP2 = 0x1e, QCC2072_ASSOC_HTT_PEER_UNMAP2 = 0x1f,
    QCC2072_ASSOC_HTT_PEER_MAP3 = 0x2b
};
/* Parameter ids and values the sequence uses (wmi.h enums). */
enum {
    QCC2072_ASSOC_VDEV_PARAM_RTS_THRESHOLD = 0x1, QCC2072_ASSOC_VDEV_PARAM_BEACON_INTERVAL = 0x3,
    QCC2072_ASSOC_VDEV_PARAM_SLOT_TIME = 0x7, QCC2072_ASSOC_VDEV_PARAM_PREAMBLE = 0x8,
    QCC2072_ASSOC_VDEV_PARAM_DTIM_PERIOD = 0xd, QCC2072_ASSOC_VDEV_PARAM_MGMT_RATE = 0x19,
    QCC2072_ASSOC_VDEV_PARAM_PROTECTION_MODE = 0x1a, QCC2072_ASSOC_VDEV_PARAM_NSS = 0x22,
    QCC2072_ASSOC_VDEV_PARAM_TX_ENCAP_TYPE = 0x30, QCC2072_ASSOC_VDEV_PARAM_DTIM_POLICY = 0x47,
    QCC2072_ASSOC_VDEV_PARAM_RX_DECAP_TYPE = 0x5b, QCC2072_ASSOC_VDEV_PARAM_BEACON_RATE = 0x5e,
    QCC2072_ASSOC_VDEV_PARAM_SET_HEMU_MODE = 0x8002,
    QCC2072_ASSOC_PDEV_PARAM_TXPOWER_LIMIT2G = 0x3, QCC2072_ASSOC_PDEV_PARAM_TXPOWER_LIMIT5G = 0x4,
    QCC2072_ASSOC_PDEV_PARAM_DYNAMIC_BW = 0xa, QCC2072_ASSOC_PDEV_PARAM_PMF_QOS = 0x22,
    QCC2072_ASSOC_PDEV_PARAM_ARP_AC_OVERRIDE = 0x23, QCC2072_ASSOC_PDEV_PARAM_IDLE_PS_CONFIG = 0x2c,
    QCC2072_ASSOC_PDEV_PARAM_MESH_MCAST_ENABLE = 0x8f,
    QCC2072_ASSOC_STA_PS_PARAM_RX_WAKE_POLICY = 0, QCC2072_ASSOC_STA_PS_PARAM_TX_WAKE_THRESHOLD = 1,
    QCC2072_ASSOC_STA_PS_PARAM_PSPOLL_COUNT = 2,
    QCC2072_ASSOC_PEER_PARAM_MIMO_PS_STATE = 0x1, QCC2072_ASSOC_PEER_PARAM_AUTHORIZE = 0x3,
    QCC2072_ASSOC_PEER_PARAM_SET_DEFAULT_ROUTING = 0x13,
    QCC2072_ASSOC_KEY_PAIRWISE = 0, QCC2072_ASSOC_KEY_GROUP = 1,
    QCC2072_ASSOC_CIPHER_NONE = 0, QCC2072_ASSOC_CIPHER_AES_CCM = 4,
    QCC2072_ASSOC_TXRX_RAW = 0, QCC2072_ASSOC_TXRX_NATIVE_WIFI = 1, QCC2072_ASSOC_TXRX_ETHERNET = 2,
    QCC2072_ASSOC_SERVICE_11D_OFFLOAD = 118, QCC2072_ASSOC_SERVICE_11BE = 289,
    QCC2072_ASSOC_SERVICE_ETH_OFFLOAD = 461
};
/* enum wmi_phy_mode values used for a 20 MHz station. */
enum {
    QCC2072_ASSOC_MODE_11A = 0, QCC2072_ASSOC_MODE_11G = 1, QCC2072_ASSOC_MODE_11B = 2,
    QCC2072_ASSOC_MODE_11NA_HT20 = 4, QCC2072_ASSOC_MODE_11NG_HT20 = 5,
    QCC2072_ASSOC_MODE_11AX_HE20 = 16, QCC2072_ASSOC_MODE_11AX_HE160 = 20,
    QCC2072_ASSOC_MODE_11AX_HE20_2G = 21, QCC2072_ASSOC_MODE_11BE_EHT20 = 24,
    QCC2072_ASSOC_MODE_11BE_EHT160 = 28, QCC2072_ASSOC_MODE_11BE_EHT320 = 30,
    QCC2072_ASSOC_MODE_11BE_EHT20_2G = 31
};
#define QCC2072_ASSOC_MGMT_SLOT_BYTES 512U
#define QCC2072_ASSOC_MGMT_SLOTS 8U
#define QCC2072_ASSOC_MGMT_DMA_BYTES (QCC2072_ASSOC_MGMT_SLOT_BYTES * QCC2072_ASSOC_MGMT_SLOTS)
#define QCC2072_ASSOC_REO_TIDS 17U       /* IEEE80211_NUM_TIDS + 1 (non-QoS) */
#define QCC2072_ASSOC_MAX_LEGACY 12U
#define QCC2072_ASSOC_MAX_HT_RATES 32U
#define QCC2072_ASSOC_MAX_HE_MCS 3U      /* WMI_HOST_MAX_HE_RATE_SET */
#define QCC2072_ASSOC_MAX_EHT_MCS 3U     /* WMI_MAX_EHTCAP_RATE_SET */
#define QCC2072_ASSOC_MAX_AP_IES 1024U
#define QCC2072_ASSOC_MAX_RESP_IES 512U

/* ---------------------------------------------------------------- WMI encoders */
struct qcc2072_assoc_vdev_start_args {
    /* ath12k wmi_vdev_start_req_arg fields that reach the wire. Powers in dBm. */
    uint32_t vdev_id, freq_mhz, center_freq1, center_freq2, mode;
    uint32_t beacon_interval, dtim_period, bcn_tx_rate, num_noa_descriptors;
    uint32_t pref_tx_streams, pref_rx_streams, cac_duration_ms, regdomain, he_ops;
    uint32_t punct_bitmap, mbssid_flags, mbssid_tx_vdev_id;
    uint32_t max_power, max_reg_power, max_antenna_gain;
    uint8_t passive, allow_ibss, allow_ht, allow_vht, allow_he, ht40plus, chan_radar, freq2_radar;
    uint8_t hidden_ssid, pmf_enabled, ssid_length;
    const uint8_t *ssid; /* NULL: no SSID (ath12k sets one only for AP vdevs) */
};
struct qcc2072_assoc_ppet { uint32_t numss_m1, ru_bit_mask, ppet16_ppet8_ru3_ru0[8]; };
struct qcc2072_assoc_peer_args {
    /* ath12k_wmi_peer_assoc_arg, minus MLO (never enabled here). */
    uint32_t vdev_id, peer_new_assoc, peer_associd, peer_caps, peer_listen_intval;
    uint32_t peer_ht_caps, peer_max_mpdu, peer_mpdu_density, peer_rate_caps, peer_nss;
    uint32_t peer_vht_caps, peer_phymode, peer_bw_rxnss_override, punct_bitmap;
    uint8_t min_data_rate; /* u8 in ath12k's arg */
    uint8_t peer_mac[6];
    uint8_t legacy_count, legacy[QCC2072_ASSOC_MAX_LEGACY];
    uint8_t ht_count, ht[QCC2072_ASSOC_MAX_HT_RATES];
    uint8_t vht_capable;
    uint32_t rx_max_rate, rx_mcs_set, tx_max_rate, tx_mcs_set;
    uint32_t he_cap_macinfo[2], he_cap_macinfo_internal, he_caps_6ghz, he_ops, he_cap_phyinfo[3];
    uint32_t he_mcs_count, he_rx_mcs[QCC2072_ASSOC_MAX_HE_MCS], he_tx_mcs[QCC2072_ASSOC_MAX_HE_MCS];
    struct qcc2072_assoc_ppet he_ppet, eht_ppet;
    uint32_t eht_cap_mac[2], eht_cap_phy[3], eht_mcs_count;
    uint32_t eht_rx_mcs[QCC2072_ASSOC_MAX_EHT_MCS], eht_tx_mcs[QCC2072_ASSOC_MAX_EHT_MCS];
    /* ath12k_wmi_copy_peer_flags inputs */
    uint8_t is_wme_set, qos_flag, apsd_flag, ht_flag, bw_40, bw_80, bw_160, bw_320;
    uint8_t stbc_flag, ldpc_flag, static_mimops_flag, dynamic_mimops_flag, spatial_mux_flag;
    uint8_t vht_flag, he_flag, twt_requester, twt_responder, eht_flag, auth_flag;
    uint8_t need_ptk_4_way, need_gtk_2_way, safe_mode_enabled, is_pmf_enabled, is_assoc;
    uint8_t eht_disable_mcs15, hw_crypto_disabled;
};
size_t qcc2072_assoc_vdev_start(uint8_t *, size_t, const struct qcc2072_assoc_vdev_start_args *);
size_t qcc2072_assoc_peer_create(uint8_t *, size_t, uint32_t vdev_id, const uint8_t peer[6]);
size_t qcc2072_assoc_peer_delete(uint8_t *, size_t, uint32_t vdev_id, const uint8_t peer[6]);
size_t qcc2072_assoc_mgmt_send(uint8_t *, size_t, uint32_t vdev_id, uint32_t desc_id,
                               uint32_t chanfreq, uint64_t paddr, const uint8_t *frame, size_t frame_len);
size_t qcc2072_assoc_peer_assoc(uint8_t *, size_t, const struct qcc2072_assoc_peer_args *);
size_t qcc2072_assoc_vdev_up(uint8_t *, size_t, uint32_t vdev_id, uint32_t aid, const uint8_t bssid[6]);
/* key == NULL with key_len 0 is ath12k's DISABLE_KEY form (cipher 0, empty array). */
size_t qcc2072_assoc_install_key(uint8_t *, size_t, uint32_t vdev_id, const uint8_t mac[6],
                                 uint32_t key_idx, uint32_t key_flags, uint32_t cipher,
                                 const uint8_t *key, uint32_t key_len);
size_t qcc2072_assoc_peer_set_param(uint8_t *, size_t, uint32_t vdev_id, const uint8_t mac[6],
                                    uint32_t param, uint32_t value);
size_t qcc2072_assoc_vdev_set_param(uint8_t *, size_t, uint32_t vdev_id, uint32_t param, uint32_t value);
size_t qcc2072_assoc_pdev_set_param(uint8_t *, size_t, uint32_t pdev_id, uint32_t param, uint32_t value);
size_t qcc2072_assoc_sta_ps_param(uint8_t *, size_t, uint32_t vdev_id, uint32_t param, uint32_t value);
size_t qcc2072_assoc_sta_ps_mode(uint8_t *, size_t, uint32_t vdev_id, uint32_t enable);
size_t qcc2072_assoc_vdev_down(uint8_t *, size_t, uint32_t vdev_id);
size_t qcc2072_assoc_vdev_stop(uint8_t *, size_t, uint32_t vdev_id);
size_t qcc2072_assoc_vdev_delete(uint8_t *, size_t, uint32_t vdev_id);
size_t qcc2072_assoc_reorder_queue_setup(uint8_t *, size_t, uint32_t vdev_id, const uint8_t mac[6],
                                         uint32_t tid, uint64_t queue, uint32_t ba_window_valid,
                                         uint32_t ba_window);
size_t qcc2072_assoc_obss_spr(uint8_t *, size_t, uint32_t vdev_id, uint32_t enable,
                              int32_t min_offset, int32_t max_offset);
/* peer_flags/peer_flags_ext exactly as ath12k_wmi_copy_peer_flags. */
void qcc2072_assoc_peer_flags(const struct qcc2072_assoc_peer_args *, uint32_t *flags, uint32_t *ext);

/* ---------------------------------------------------------------- event parsers */
/* Each takes the full WMI event (4-byte id + TLVs) and returns 0 if it is that event
 * and well formed (fixed TLV present, last occurrence wins, at least ath12k's
 * min_len), QCC2072_BAD_STATE if it is a different event, QCC2072_BAD_WIRE if bad. */
struct qcc2072_assoc_vdev_start_resp { uint32_t vdev_id, requestor_id, resp_type, status, chain_mask,
    smps_mode, pdev_id, cfgd_tx_streams, cfgd_rx_streams; int32_t max_allowed_tx_power; };
struct qcc2072_assoc_key_complete { uint32_t vdev_id, key_idx, key_flags, status; uint8_t mac[6]; };
struct qcc2072_assoc_peer_event { uint32_t vdev_id, reason; int32_t rssi; uint8_t mac[6]; };
struct qcc2072_assoc_mgmt_tx_done { uint32_t desc_id, status, pdev_id, ppdu_id, ack_rssi; };
struct qcc2072_assoc_mgmt_rx {
    uint32_t channel, snr, rate, phy_mode, status, flags, pdev_id, chan_freq;
    int32_t rssi;
    const uint8_t *frame; uint32_t length; /* points into the event bytes */
};
int qcc2072_assoc_parse_vdev_start_resp(const uint8_t *, size_t, struct qcc2072_assoc_vdev_start_resp *);
int qcc2072_assoc_parse_vdev_stopped(const uint8_t *, size_t, uint32_t *vdev_id);
int qcc2072_assoc_parse_key_complete(const uint8_t *, size_t, struct qcc2072_assoc_key_complete *);
/* PEER_ASSOC_CONF, PEER_DELETE_RESP (vdev, mac) and PEER_STA_KICKOUT (mac, reason, rssi). */
int qcc2072_assoc_parse_peer_event(const uint8_t *, size_t, struct qcc2072_assoc_peer_event *);
int qcc2072_assoc_parse_mgmt_tx_done(const uint8_t *, size_t, struct qcc2072_assoc_mgmt_tx_done *);
/* WMI_ROAM_EVENTID: reason masked with WMI_ROAM_REASON_MASK (BEACON_MISS = 2). */
int qcc2072_assoc_parse_roam(const uint8_t *, size_t, struct qcc2072_assoc_peer_event *);
int qcc2072_assoc_parse_mgmt_rx(const uint8_t *, size_t, struct qcc2072_assoc_mgmt_rx *);
struct qcc2072_assoc_peer_map {
    uint32_t type, vdev_id, peer_id, ast_hash, hw_peer_id;
    uint8_t mac[6], unmap;
};
/* HTT T2H message as delivered on service 0x300 (byte 0 is the type). */
int qcc2072_assoc_parse_htt_peer(const uint8_t *, size_t, struct qcc2072_assoc_peer_map *);

/* ---------------------------------------------------------------- capabilities */
struct qcc2072_assoc_caps {
    uint8_t service_ready, ext_ready;
    uint32_t num_rf_chains, hw_min_tx_power, hw_max_tx_power;
    uint32_t preferred_hw_mode, supported_bands, ampdu_density;
    uint32_t ht_cap_info[2], vht_cap, tx_chainmask, rx_chainmask; /* [0]=2 GHz, [1]=5 GHz */
};
/* SERVICE_READY (num_rf_chains, hw min/max tx power) and SERVICE_READY_EXT
 * (mac/phy caps of ath12k's preferred hw mode, as ath12k_pull_mac_phy_cap_svc_ready_ext). */
int qcc2072_assoc_parse_caps(const uint8_t *, size_t, struct qcc2072_assoc_caps *);
/* ath12k_create_ht_cap(), then mac80211's assoc-request adjustments for a 20 MHz
 * limit (no 20/40, no SGI40) and SM power save disabled. Returns 0 if HT. */
struct qcc2072_assoc_ht {
    uint16_t cap; uint8_t ampdu_factor, ampdu_density, rx_mask[10], tx_params;
};
int qcc2072_assoc_own_ht(const struct qcc2072_assoc_caps *, unsigned band, struct qcc2072_assoc_ht *sband,
                         struct qcc2072_assoc_ht *assoc_request);

/* ---------------------------------------------------------------- 802.11 frames */
enum { QCC2072_ASSOC_IE_SSID, QCC2072_ASSOC_IE_RATES, QCC2072_ASSOC_IE_DS, QCC2072_ASSOC_IE_TIM,
       QCC2072_ASSOC_IE_ERP, QCC2072_ASSOC_IE_HT_CAP, QCC2072_ASSOC_IE_RSN, QCC2072_ASSOC_IE_EXT_RATES,
       QCC2072_ASSOC_IE_TIMEOUT, QCC2072_ASSOC_IE_HT_OP, QCC2072_ASSOC_IE_PWR_CONSTRAINT,
       QCC2072_ASSOC_IE_WMM_PARAM, QCC2072_ASSOC_IE_WMM_INFO, QCC2072_ASSOC_IE_WPA,
       QCC2072_ASSOC_IE_COUNT };
struct qcc2072_assoc_ies {
    const uint8_t *ie[QCC2072_ASSOC_IE_COUNT]; /* element body (after id/len) */
    uint8_t len[QCC2072_ASSOC_IE_COUNT];
    uint8_t duplicates, rsn_count, truncated;
};
/* Bounded walk; duplicates keep the first (mac80211); returns QCC2072_BAD_WIRE if truncated. */
int qcc2072_assoc_parse_ies(const uint8_t *, size_t, struct qcc2072_assoc_ies *);
size_t qcc2072_assoc_auth_frame(uint8_t *, size_t, const uint8_t bssid[6], const uint8_t sa[6], uint16_t seq_ctrl);
size_t qcc2072_assoc_deauth_frame(uint8_t *, size_t, const uint8_t bssid[6], const uint8_t sa[6],
                                  uint16_t seq_ctrl, uint16_t reason);
struct qcc2072_assoc_req_args {
    const uint8_t *bssid, *sa, *ssid, *rsn, *ap_ies;
    uint8_t ssid_length, rsn_length; /* rsn: whole element incl. id/len, or 0 */
    uint16_t ap_ie_length, ap_capability, seq_ctrl, listen_interval;
    uint16_t freq_mhz;
    int8_t max_power_dbm;
    const struct qcc2072_assoc_ht *ht; /* NULL: no HT capabilities element */
    uint8_t wmm, ext_capa_length;
    const uint8_t *ext_capa;
};
size_t qcc2072_assoc_request_frame(uint8_t *, size_t, const struct qcc2072_assoc_req_args *);
struct qcc2072_assoc_auth_resp { uint16_t algorithm, transaction, status; };
struct qcc2072_assoc_resp {
    uint16_t capability, status, aid_raw, aid; uint8_t reassoc;
    const uint8_t *ies; uint16_t ie_length; uint32_t comeback_tu;
};
/* addr1 = own, addr2 = addr3 = bssid, unprotected, exact subtype; QCC2072_BAD_STATE if
 * not that frame for this link, QCC2072_BAD_WIRE if short. */
int qcc2072_assoc_parse_auth(const uint8_t *, size_t, const uint8_t own[6], const uint8_t bssid[6],
                             struct qcc2072_assoc_auth_resp *);
int qcc2072_assoc_parse_assoc_resp(const uint8_t *, size_t, const uint8_t own[6], const uint8_t bssid[6],
                                   struct qcc2072_assoc_resp *);
/* Deauthentication or disassociation from the BSSID to us (or broadcast). */
int qcc2072_assoc_parse_deauth(const uint8_t *, size_t, const uint8_t own[6], const uint8_t bssid[6],
                               uint16_t *reason, uint8_t *disassoc);
/* RSN (re/connect/FAILURES.md 7-16): the connect request and M2 carry our own
 * element (snap_rsn_own); the AP's element from its beacon/probe response must pass
 * snap_rsn_ap_policy (WPA2-PSK CCMP, PSK among the AKMs, no PMF required).
 * qcc2072_assoc_ap_rsn copies the AP's RSN element (and its RSNXE, if any) when joinable and
 * returns the RSN element length, else 0 with *reason a SNAP_RSN_* code.
 * qcc2072_assoc_link_security gives the same for the link being connected or associated: the
 * elements snap_wpa2 must find in M3. */
size_t qcc2072_assoc_ap_rsn(const uint8_t *ap_ies, size_t ap_ie_length, uint8_t rsn[SNAP_RSN_MAX_ELEMENT],
                            uint8_t rsnxe[SNAP_RSN_MAX_RSNXE], size_t *rsnxe_length, int *reason);
int qcc2072_assoc_link_security(const struct qcc2072_assoc *, uint8_t rsn[SNAP_RSN_MAX_ELEMENT], size_t *rsn_length,
                                uint8_t rsnxe[SNAP_RSN_MAX_RSNXE], size_t *rsnxe_length);

/* ---------------------------------------------------------------- state machine */
struct qcc2072_assoc_hooks {
    void *context;
    /* At least QCC2072_ASSOC_MGMT_DMA_BYTES of device-visible memory for management
     * frames; slot i is at cpu + i*512 / iova + i*512. sync publishes CPU writes. */
    struct qcc2072_dma_buffer mgmt;
    int (*sync)(void *, const struct qcc2072_dma_buffer *, size_t offset, size_t length,
                uint32_t direction);
    /* ath12k_dp_rx_peer_tid_setup for (peer, tid 0..16), BA window 1, SSN 0, no PN:
     * prepare the REO queue descriptor and return its device address (paddr_aligned).
     * NULL is accepted only with QCC2072_ASSOC_F_ASSOC_ONLY (no data path). */
    int (*reo_queue)(void *, const uint8_t peer[6], uint32_t peer_id, unsigned tid, uint64_t *queue);
    /* ath12k_dp_peer_cleanup after VDEV_STOPPED, before PEER_DELETE. Optional. */
    int (*reo_release)(void *, const uint8_t peer[6], uint32_t peer_id);
};
enum {
    QCC2072_ASSOC_F_VDEV_CREATED = 1,  /* VDEV_CREATE already sent (scan path) */
    QCC2072_ASSOC_F_RADIO_PARAMS = 2,  /* send ath12k_mac_start's pdev params once */
    QCC2072_ASSOC_F_IDLE_PS = 4,       /* ... including IDLE_PS_CONFIG=1 (IMPS) */
    QCC2072_ASSOC_F_ETH_OFFLOAD = 8,   /* WMI service ETH_OFFLOAD: Ethernet encap/decap */
    QCC2072_ASSOC_F_EHT = 16,          /* WMI service 11BE: EHT vdev modes */
    QCC2072_ASSOC_F_ASSOC_ONLY = 32    /* hardware test: no REO hook, stop at ASSOCIATED */
};
struct qcc2072_assoc_connect_args {
    uint64_t transaction;
    uint32_t vdev_id, pdev_id, flags;
    uint8_t own_mac[6], bssid[6], ssid_length, ssid[32];
    uint16_t freq_mhz, beacon_interval_tu, capability;
    int8_t max_power_dbm, max_reg_power_dbm; /* channel limits (regulatory), dBm */
    uint8_t passive;                         /* NO_IR or DFS channel (ath12k: WMI_CHAN_INFO_PASSIVE) */
    uint8_t rsn_length, rsn[64]; /* request RSN element (id, len, body), 0 = open */
    uint16_t ie_length;
    uint8_t ies[QCC2072_ASSOC_MAX_AP_IES]; /* AP beacon/probe-response elements (scan) */
};
enum qcc2072_assoc_state {
    QCC2072_ASSOC_IDLE, QCC2072_ASSOC_CONNECTING, QCC2072_ASSOC_ASSOCIATED,
    QCC2072_ASSOC_AUTHORIZED, QCC2072_ASSOC_TEARDOWN, QCC2072_ASSOC_WEDGED
};
enum {
    QCC2072_ASSOC_N_ASSOCIATED = 1, QCC2072_ASSOC_N_CONNECTED, QCC2072_ASSOC_N_CONTROL_DONE,
    QCC2072_ASSOC_N_FAILED, QCC2072_ASSOC_N_CANCELLED, QCC2072_ASSOC_N_DISCONNECTED
};
/* Failure details (notice.detail): step that failed in the low byte. */
enum {
    QCC2072_ASSOC_E_TIMEOUT = 0x100, QCC2072_ASSOC_E_FIRMWARE = 0x200, QCC2072_ASSOC_E_AP = 0x300,
    QCC2072_ASSOC_E_NO_ACK = 0x400, QCC2072_ASSOC_E_DEAUTH = 0x500, QCC2072_ASSOC_E_KICKOUT = 0x600,
    QCC2072_ASSOC_E_HOOK = 0x700, QCC2072_ASSOC_E_LOCAL = 0x800, QCC2072_ASSOC_E_UNAUTHORIZED = 0x900
};
struct qcc2072_assoc_notice {
    uint32_t type; int32_t status;
    uint64_t transaction, link_transaction;
    uint16_t reason, aid; uint32_t detail;
};
struct qcc2072_assoc_step { uint8_t op, wait; uint16_t pad; uint32_t a, b; };
struct qcc2072_assoc {
    struct qcc2072_assoc_hooks hooks;
    struct qcc2072_assoc_caps caps;
    struct qcc2072_assoc_connect_args link, next;   /* current link; connect queued behind a teardown */
    struct qcc2072_assoc_peer_args peer;
    struct qcc2072_assoc_step prog[48];
    struct qcc2072_assoc_notice notices[8];
    struct snap_station_control control;            /* pending control, key bytes cleared */
    uint8_t cmd[2040], resp_ies[QCC2072_ASSOC_MAX_RESP_IES], key[16];
    size_t cmd_length;
    uint64_t deadline, slot_deadline, mgmt_retry_at, authorize_deadline;
    uint32_t slot_desc[QCC2072_ASSOC_MGMT_SLOTS], next_desc, wait_desc, comeback_ms;
    uint32_t txpower_2g, txpower_5g, tx_encap, rx_decap, peer_id, ast_hash, hw_peer_id;
    uint32_t unknown_events, foreign_events, bad_events, last_detail;
    uint16_t seq, aid, resp_ie_length, assoc_capability, disconnect_reason, status_code;
    uint8_t state, prog_len, pc, prog_kind, wait, response, acked, tries, cmd_has_key;
    uint8_t notice_read, notice_count, slot_busy, radio_done, vdev_created, vdev_configured;
    uint8_t vdev_started, vdev_up, peer_exists, peer_mapped, peer_unmapped, assoc_ok;
    uint8_t ptk, gtk_mask, authorized, secure, control_pending, has_next, teardown_notice, cancel;
    uint8_t ht, wmm, short_slot, short_preamble, cts_prot, dtim_period, basic_rate;
    uint8_t initialized, in_call;
};
int qcc2072_assoc_init(struct qcc2072_assoc *, const struct qcc2072_assoc_hooks *);
/* Every accepted WMI event (4-byte id + TLVs) and every HTT T2H message. Unknown and
 * foreign events are counted and ignored; they never fail the provider. */
int qcc2072_assoc_wmi_event(struct qcc2072_assoc *, uint64_t now_ms, const uint8_t *, size_t);
int qcc2072_assoc_htt_event(struct qcc2072_assoc *, uint64_t now_ms, const uint8_t *, size_t);
/* SNAP_STATION_* result. A connect while a link exists tears it down first. */
int qcc2072_assoc_connect(struct qcc2072_assoc *, uint64_t now_ms, const struct qcc2072_assoc_connect_args *);
/* KEY_INSTALL/KEY_REMOVE/PORT_AUTHORIZE/LINK_DISCONNECT from snap_station; completes with
 * an N_CONTROL_DONE notice carrying the control's transaction and link transaction. */
int qcc2072_assoc_control(struct qcc2072_assoc *, uint64_t now_ms, const struct snap_station_control *);
int qcc2072_assoc_cancel(struct qcc2072_assoc *, uint64_t now_ms, uint64_t transaction);
/* One command per provider poll. The returned frame and length (0 = nothing to send) stay valid and
 * unchanged until qcc2072_assoc_sent() or abort; on CE FULL send the same bytes later. */
int qcc2072_assoc_poll(struct qcc2072_assoc *, uint64_t now_ms, const uint8_t **frame, size_t *length);
int qcc2072_assoc_sent(struct qcc2072_assoc *, uint64_t now_ms);
/* Returns 1 and pops the oldest notice, 0 if none. Deliver after poll, never inline. */
int qcc2072_assoc_take_notice(struct qcc2072_assoc *, struct qcc2072_assoc_notice *);
/* Logical stop (provider quarantine/stop): wipes keys and the pending command. */
int qcc2072_assoc_abort(struct qcc2072_assoc *);
/* Names for the provider's connect trace: state, program, step op (prog[pc].op), wait, and the
 * failure kind of a notice detail (detail & 0xff00; the low byte is the step op). */
const char *qcc2072_assoc_state_name(unsigned state);
const char *qcc2072_assoc_prog_name(unsigned prog);
const char *qcc2072_assoc_op_name(unsigned op);
const char *qcc2072_assoc_wait_name(unsigned wait);
const char *qcc2072_assoc_kind_name(uint32_t detail);

/* ---------------------------------------------------------------- data path hook */
/* Contract for qcc2072-dp-io (EAPOL over TCL/REO), from ath12k + mac80211:
 *  - TX: snap_wpa2 frames are Ethernet II (dst = BSSID, src = own, type 0x888E). Send on
 *    vdev link.vdev_id using link.tx_encap; for a STA vdev TCL needs link.ast_hash and
 *    link.hw_peer_id (ath12k arvif->ast_hash/ast_idx from PEER_MAP). EAPOL must go out
 *    UNENCRYPTED (HAL encrypt type OPEN), also after the PTK is installed: snap_wpa2
 *    installs keys before M4. Report completion only on WBM release with ACK status.
 *  - RX: frames from link.peer_id decapsulated per link.rx_decap; deliver ethertype
 *    0x888E to snap_wpa2_receive only if qcc2072_assoc_eapol_admit(rx) returns 0.
 *  - Data other than EAPOL only while link.authorized. */
struct qcc2072_assoc_link {
    uint32_t state, vdev_id, pdev_id, freq_mhz, tx_encap, rx_decap;
    uint32_t peer_id, ast_hash, hw_peer_id;
    uint16_t aid; uint8_t bssid[6], own_mac[6];
    uint8_t peer_mapped, associated, authorized, ptk, gtk_mask, secure, qos, ht;
    uint64_t link_transaction;
};
int qcc2072_assoc_link_info(const struct qcc2072_assoc *, struct qcc2072_assoc_link *);
int qcc2072_assoc_eapol_admit(const struct qcc2072_assoc *, const uint8_t *eth, size_t n, int transmit);
#ifdef __cplusplus
}
#endif
#endif

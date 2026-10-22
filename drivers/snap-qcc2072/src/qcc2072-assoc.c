/* SPDX-License-Identifier: MIT */
/* QCC2072 station connect: WMI encoders, 802.11 frames, event parsers and the connect
 * state machine. Wire layouts and values follow pinned ath12k c03c1a14 (wmi.c builders,
 * mac.c sequencing, dp.c/dp_rx.c peer setup, dp_htt.c peer map); mac80211 behaviour that
 * is not in the pin is marked "mac80211". Failure inventory: re/assoc/FAILURES.md;
 * byte-for-byte replay against ath12k's own functions: re/assoc/replay.py. */
#include "qcc2072-assoc.h"
#include "qcc2072-scan.h"

#define HTC_SEND_MAX 2040U
/* wmi.h enum wmi_tlv_tag */
#define TAG_ARRAY_BYTE 0x11U
#define TAG_ARRAY_STRUCT 0x12U
#define TAG_SERVICE_READY 0x20U
#define TAG_VDEV_START_RESP 0x28U
#define TAG_VDEV_STOPPED 0x29U
#define TAG_INSTALL_KEY_COMPLETE 0x2aU
#define TAG_PEER_STA_KICKOUT 0x2bU
#define TAG_MGMT_RX_HDR 0x2cU
#define TAG_ROAM_EVENT 0x30U
#define TAG_CHANNEL 0x50U
#define TAG_PDEV_SET_PARAM 0x52U
#define TAG_VDEV_DELETE 0x57U
#define TAG_VDEV_START 0x58U
#define TAG_VDEV_UP 0x5cU
#define TAG_VDEV_STOP 0x5dU
#define TAG_VDEV_DOWN 0x5eU
#define TAG_VDEV_SET_PARAM 0x5fU
#define TAG_INSTALL_KEY 0x60U
#define TAG_PEER_CREATE 0x61U
#define TAG_PEER_DELETE 0x62U
#define TAG_PEER_SET_PARAM 0x64U
#define TAG_PEER_ASSOC 0x65U
#define TAG_VHT_RATE_SET 0x66U
#define TAG_STA_PS_MODE 0x6cU
#define TAG_STA_PS_PARAM 0x6dU
#define TAG_MGMT_TX_SEND 0x1a6U
#define TAG_MGMT_TX_COMPL 0x1a7U
#define TAG_SERVICE_READY_EXT 0x1acU
#define TAG_PEER_ASSOC_CONF 0x1b2U
#define TAG_PEER_DELETE_RESP 0x1c3U
#define TAG_MAC_PHY_CAPS 0x210U
#define TAG_HW_MODE_CAPS 0x211U
#define TAG_SOC_HW_MODE_CAPS 0x212U
#define TAG_REORDER_QUEUE_SETUP 0x225U
#define TAG_HE_RATE_SET 0x285U
#define TAG_OBSS_SPR 0x2efU
#define TAG_EHT_RATE_SET 0x3c4U
#define TAG_MLO_PEER_CREATE 0x3d5U
/* wmi.h struct sizes, TLV header included where ath12k's struct has one. */
#define VDEV_START_BYTES 116U   /* wmi_vdev_start_request_cmd */
#define CHANNEL_BYTES 28U       /* ath12k_wmi_channel_params */
#define PEER_CREATE_BYTES 20U   /* wmi_peer_create_cmd */
#define MLO_CREATE_BYTES 8U     /* wmi_peer_create_mlo_params */
#define MGMT_SEND_BYTES 36U     /* wmi_mgmt_send_cmd */
#define PEER_ASSOC_BYTES 248U   /* wmi_peer_assoc_complete_cmd */
#define VHT_RATE_BYTES 24U      /* ath12k_wmi_vht_rate_set_params */
#define HE_RATE_BYTES 12U       /* ath12k_wmi_he_rate_set_params */
#define EHT_RATE_BYTES 12U      /* ath12k_wmi_eht_rate_set_params */
#define VDEV_UP_BYTES 36U       /* wmi_vdev_up_cmd */
#define INSTALL_KEY_BYTES 104U  /* wmi_vdev_install_key_cmd */
#define PEER_PARAM_BYTES 24U    /* wmi_peer_set_param_cmd */
#define PARAM_BYTES 16U         /* vdev/pdev set param, sta powersave param */
#define PS_MODE_BYTES 12U       /* wmi_pdev_set_ps_mode_cmd */
#define VDEV_ID_BYTES 8U        /* vdev down/stop/delete */
#define PEER_DELETE_BYTES 16U   /* wmi_peer_delete_cmd */
#define REORDER_BYTES 40U       /* wmi_peer_reorder_queue_setup_cmd */
#define OBSS_BYTES 24U          /* wmi_obss_spatial_reuse_params_cmd */
#define MGMT_DOWNLOAD 64U       /* WMI_MGMT_SEND_DOWNLD_LEN */
/* wmi.h peer flags */
#define PEER_AUTH 0x1U
#define PEER_QOS 0x2U
#define PEER_NEED_PTK_4_WAY 0x4U
#define PEER_NEED_GTK_2_WAY 0x10U
#define PEER_HE 0x400U
#define PEER_APSD 0x800U
#define PEER_HT 0x1000U
#define PEER_40MHZ 0x2000U
#define PEER_STBC 0x8000U
#define PEER_LDPC 0x10000U
#define PEER_DYN_MIMOPS 0x20000U
#define PEER_STATIC_MIMOPS 0x40000U
#define PEER_SPATIAL_MUX 0x200000U
#define PEER_TWT_REQ 0x400000U
#define PEER_TWT_RESP 0x800000U
#define PEER_VHT 0x2000000U
#define PEER_80MHZ 0x4000000U
#define PEER_PMF 0x8000000U
#define PEER_160MHZ 0x40000000U
#define PEER_EXT_EHT 0x1U
#define PEER_EXT_320MHZ 0x2U
/* timeouts (ms): ath12k waits and mac80211 auth/assoc timers */
#define T_PEER_MAP 3000U        /* ath12k_wait_for_peer_created (peer.c, unpinned) */
#define T_VDEV 5000U            /* ATH12K_VDEV_SETUP_TIMEOUT_HZ */
#define T_ASSOC_CONF 1000U      /* ath12k_mac_peer_assoc */
#define T_KEY 1000U             /* ath12k_install_key */
#define T_PEER_DELETE 3000U     /* ath12k_wait_for_peer_delete_done (peer.c, unpinned) */
#define T_MGMT 500U             /* IEEE80211_{AUTH,ASSOC}_TIMEOUT_LONG (mac80211) */
#define T_MGMT_ACKED 100U       /* IEEE80211_{AUTH,ASSOC}_TIMEOUT_SHORT (mac80211) */
#define MGMT_TRIES 3U           /* IEEE80211_{AUTH,ASSOC}_MAX_TRIES (mac80211) */
#define T_DEAUTH 1000U
#define T_SLOT 1000U
#define T_AUTHORIZE 20000U
#define T_COMEBACK_MAX 2000U
#define LISTEN_INTERVAL 5U      /* ATH12K_MAX_HW_LISTEN_INTERVAL -> hw.conf.listen_interval */

/* ------------------------------------------------------------------ helpers */
static void put16(uint8_t *p, uint32_t v) { p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8); }
static void put32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8); p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24);
}
static uint32_t get16(const uint8_t *p) { return (uint32_t)p[0] | (uint32_t)p[1] << 8; }
static uint32_t get32(const uint8_t *p)
{
    return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}
static void zero(void *v, size_t n) { volatile uint8_t *p = (volatile uint8_t *)v; while (n--) *p++ = 0; }
static void copy(void *d, const void *s, size_t n)
{
    uint8_t *a = (uint8_t *)d; const uint8_t *b = (const uint8_t *)s;
    while (n--) *a++ = *b++;
}
static int same(const uint8_t *a, const uint8_t *b, size_t n)
{
    unsigned d = 0;
    while (n--) d |= (unsigned)(*a++ ^ *b++);
    return !d;
}
static int unicast(const uint8_t *m) { return !(m[0] & 1) && (m[0] | m[1] | m[2] | m[3] | m[4] | m[5]); }
static uint32_t tlv(uint32_t tag, uint32_t len) { return tag << 16 | (len & 0xffffU); }
/* ath12k_wmi_tlv_cmd_hdr: the length excludes the TLV header itself. */
static uint32_t cmd_tlv(uint32_t tag, uint32_t bytes) { return tlv(tag, bytes - 4U); }
static uint32_t round4(uint32_t n) { return (n + 3U) & ~3U; }
static unsigned popcount(uint32_t v) { unsigned n = 0; while (v) { n += v & 1U; v >>= 1; } return n; }
static uint8_t *begin(uint8_t *out, size_t cap, size_t total, uint32_t id)
{
    if (!out || total > cap || total > HTC_SEND_MAX) return 0;
    zero(out, total);
    put32(out, id);
    return out + 4;
}
static void mac8(uint8_t *p, const uint8_t *mac) { copy(p, mac, 6); } /* + 2 pad bytes left zero */

/* ------------------------------------------------------------------ WMI encoders */
size_t qcc2072_assoc_vdev_start(uint8_t *out, size_t cap, const struct qcc2072_assoc_vdev_start_args *a)
{
    if (!a || a->ssid_length > 32 || (a->ssid_length && !a->ssid)) return 0;
    size_t total = 4U + VDEV_START_BYTES + CHANNEL_BYTES + 4U;
    uint8_t *p = begin(out, cap, total, QCC2072_ASSOC_CMD_VDEV_START);
    if (!p) return 0;
    put32(p, cmd_tlv(TAG_VDEV_START, VDEV_START_BYTES));
    put32(p + 4, a->vdev_id); put32(p + 12, a->beacon_interval); put32(p + 60, a->bcn_tx_rate);
    put32(p + 16, a->dtim_period); put32(p + 68, a->num_noa_descriptors);
    put32(p + 80, a->pref_rx_streams); put32(p + 76, a->pref_tx_streams);
    put32(p + 88, a->cac_duration_ms); put32(p + 92, a->regdomain); put32(p + 84, a->he_ops);
    put32(p + 112, a->punct_bitmap); put32(p + 100, a->mbssid_flags); put32(p + 104, a->mbssid_tx_vdev_id);
    uint32_t flags = 0;
    if (a->ssid) { put32(p + 24, a->ssid_length); copy(p + 28, a->ssid, a->ssid_length); }
    if (a->hidden_ssid) flags |= 1U;        /* WMI_VDEV_START_HIDDEN_SSID */
    if (a->pmf_enabled) flags |= 2U;        /* WMI_VDEV_START_PMF_ENABLED */
    flags |= 8U;                            /* WMI_VDEV_START_LDPC_RX_ENABLED, always */
    put32(p + 20, flags);
    uint8_t *c = p + VDEV_START_BYTES;      /* ath12k_wmi_put_wmi_channel */
    uint32_t f1 = a->center_freq1, f2 = 0;
    if (a->mode == QCC2072_ASSOC_MODE_11BE_EHT320) {
        f2 = a->center_freq1; f1 = a->freq_mhz > a->center_freq1 ? a->center_freq1 + 80 : a->center_freq1 - 80;
    } else if (a->mode == QCC2072_ASSOC_MODE_11BE_EHT160 || a->mode == QCC2072_ASSOC_MODE_11AX_HE160) {
        f2 = a->center_freq1; f1 = a->freq_mhz > a->center_freq1 ? a->center_freq1 + 40 : a->center_freq1 - 40;
    }
    uint32_t info = a->mode & 0x3fU;
    if (a->passive) info |= 1U << 7;
    if (a->allow_ibss) info |= 1U << 8;
    if (a->allow_ht) info |= 1U << 11;
    if (a->allow_vht) info |= 1U << 12;
    if (a->allow_he) info |= 1U << 17;
    if (a->ht40plus) info |= 1U << 6;
    if (a->chan_radar) info |= 1U << 10;
    if (a->freq2_radar) info |= 1U << 16;
    put32(c, cmd_tlv(TAG_CHANNEL, CHANNEL_BYTES));
    put32(c + 4, a->freq_mhz); put32(c + 8, f1); put32(c + 12, f2); put32(c + 16, info);
    put32(c + 20, (a->max_power & 0xffU) << 8 | (a->max_reg_power & 0xffU) << 16);
    put32(c + 24, (a->max_antenna_gain & 0xffU) | (a->max_power & 0xffU) << 8);
    put32(c + CHANNEL_BYTES, tlv(TAG_ARRAY_STRUCT, 0)); /* empty NoA descriptor array */
    return total;
}

size_t qcc2072_assoc_peer_create(uint8_t *out, size_t cap, uint32_t vdev_id, const uint8_t peer[6])
{
    size_t total = 4U + PEER_CREATE_BYTES + 4U + MLO_CREATE_BYTES;
    uint8_t *p = peer ? begin(out, cap, total, QCC2072_ASSOC_CMD_PEER_CREATE) : 0;
    if (!p) return 0;
    put32(p, cmd_tlv(TAG_PEER_CREATE, PEER_CREATE_BYTES));
    put32(p + 4, vdev_id); mac8(p + 8, peer); put32(p + 16, 0U /* WMI_PEER_TYPE_DEFAULT */);
    p += PEER_CREATE_BYTES;
    put32(p, tlv(TAG_ARRAY_STRUCT, MLO_CREATE_BYTES));        /* always present */
    put32(p + 4, cmd_tlv(TAG_MLO_PEER_CREATE, MLO_CREATE_BYTES)); /* flags 0: not MLO */
    return total;
}

size_t qcc2072_assoc_peer_delete(uint8_t *out, size_t cap, uint32_t vdev_id, const uint8_t peer[6])
{
    uint8_t *p = peer ? begin(out, cap, 4U + PEER_DELETE_BYTES, QCC2072_ASSOC_CMD_PEER_DELETE) : 0;
    if (!p) return 0;
    put32(p, cmd_tlv(TAG_PEER_DELETE, PEER_DELETE_BYTES)); put32(p + 4, vdev_id); mac8(p + 8, peer);
    return 4U + PEER_DELETE_BYTES;
}

size_t qcc2072_assoc_mgmt_send(uint8_t *out, size_t cap, uint32_t vdev_id, uint32_t desc_id,
                               uint32_t chanfreq, uint64_t paddr, const uint8_t *frame, size_t frame_len)
{
    if (!frame || !frame_len || frame_len > 0xffffU) return 0;
    uint32_t inline_len = frame_len < MGMT_DOWNLOAD ? (uint32_t)frame_len : MGMT_DOWNLOAD;
    uint32_t aligned = round4(inline_len);
    size_t total = 4U + MGMT_SEND_BYTES + 4U + aligned;
    uint8_t *p = begin(out, cap, total, QCC2072_ASSOC_CMD_MGMT_TX_SEND);
    if (!p) return 0;
    put32(p, cmd_tlv(TAG_MGMT_TX_SEND, MGMT_SEND_BYTES));
    put32(p + 4, vdev_id); put32(p + 8, desc_id); put32(p + 12, chanfreq);
    put32(p + 16, (uint32_t)paddr); put32(p + 20, (uint32_t)(paddr >> 32));
    put32(p + 24, (uint32_t)frame_len); put32(p + 28, inline_len); /* tx_params_valid 0 */
    put32(p + MGMT_SEND_BYTES, tlv(TAG_ARRAY_BYTE, aligned));
    copy(p + MGMT_SEND_BYTES + 4, frame, inline_len);
    return total;
}

void qcc2072_assoc_peer_flags(const struct qcc2072_assoc_peer_args *a, uint32_t *flags, uint32_t *ext)
{
    uint32_t f = 0, e = 0;
    if (a->is_wme_set) {
        if (a->qos_flag) f |= PEER_QOS;
        if (a->apsd_flag) f |= PEER_APSD;
        if (a->ht_flag) f |= PEER_HT;
        if (a->bw_40) f |= PEER_40MHZ;
        if (a->bw_80) f |= PEER_80MHZ;
        if (a->bw_160) f |= PEER_160MHZ;
        if (a->bw_320) e |= PEER_EXT_320MHZ;
        if (a->stbc_flag) f |= PEER_STBC;
        if (a->ldpc_flag) f |= PEER_LDPC;
        if (a->static_mimops_flag) f |= PEER_STATIC_MIMOPS;
        if (a->dynamic_mimops_flag) f |= PEER_DYN_MIMOPS;
        if (a->spatial_mux_flag) f |= PEER_SPATIAL_MUX;
        if (a->vht_flag) f |= PEER_VHT;
        if (a->he_flag) f |= PEER_HE;
        if (a->twt_requester) f |= PEER_TWT_REQ;
        if (a->twt_responder) f |= PEER_TWT_RESP;
        if (a->eht_flag) e |= PEER_EXT_EHT;
    }
    /* 4-way handshake suppresses authorization; it comes with key installation. */
    if (a->auth_flag) f |= PEER_AUTH;
    if (a->need_ptk_4_way) {
        f |= PEER_NEED_PTK_4_WAY;
        if (!a->hw_crypto_disabled && a->is_assoc) f &= ~PEER_AUTH;
    }
    if (a->need_gtk_2_way) f |= PEER_NEED_GTK_2_WAY;
    if (a->safe_mode_enabled) f &= ~(PEER_NEED_PTK_4_WAY | PEER_NEED_GTK_2_WAY);
    if (a->is_pmf_enabled) f |= PEER_PMF;
    /* Target asserts if the node is HT with every MCS disabled. */
    if (!a->ht_count) f &= ~PEER_HT;
    *flags = f; *ext = e;
}

static void put_ppet(uint8_t *p, const struct qcc2072_assoc_ppet *t)
{
    put32(p, t->numss_m1); put32(p + 4, t->ru_bit_mask);
    for (unsigned i = 0; i < 8; i++) put32(p + 8 + 4 * i, t->ppet16_ppet8_ru3_ru0[i]);
}

size_t qcc2072_assoc_peer_assoc(uint8_t *out, size_t cap, const struct qcc2072_assoc_peer_args *a)
{
    if (!a || a->legacy_count > QCC2072_ASSOC_MAX_LEGACY || a->ht_count > QCC2072_ASSOC_MAX_HT_RATES ||
        a->he_mcs_count > QCC2072_ASSOC_MAX_HE_MCS || a->eht_mcs_count > QCC2072_ASSOC_MAX_EHT_MCS)
        return 0;
    uint32_t la = round4(a->legacy_count), ha = round4(a->ht_count);
    size_t total = 4U + PEER_ASSOC_BYTES + 4U + la + 4U + ha + VHT_RATE_BYTES +
                   4U + HE_RATE_BYTES * a->he_mcs_count + 4U + EHT_RATE_BYTES * a->eht_mcs_count + 8U;
    uint8_t *p = begin(out, cap, total, QCC2072_ASSOC_CMD_PEER_ASSOC);
    if (!p) return 0;
    uint32_t flags, ext;
    qcc2072_assoc_peer_flags(a, &flags, &ext);
    put32(p, cmd_tlv(TAG_PEER_ASSOC, PEER_ASSOC_BYTES));
    mac8(p + 4, a->peer_mac);
    put32(p + 12, a->vdev_id); put32(p + 16, a->peer_new_assoc); put32(p + 20, a->peer_associd);
    put32(p + 24, flags); put32(p + 28, a->peer_caps); put32(p + 32, a->peer_listen_intval);
    put32(p + 36, a->peer_ht_caps); put32(p + 40, a->peer_max_mpdu); put32(p + 44, a->peer_mpdu_density);
    put32(p + 48, a->peer_rate_caps); put32(p + 52, a->peer_nss); put32(p + 56, a->peer_vht_caps);
    put32(p + 60, a->peer_phymode);         /* +64 peer_ht_info[2] stays 0 */
    put32(p + 72, a->legacy_count); put32(p + 76, a->ht_count); put32(p + 80, a->peer_bw_rxnss_override);
    put_ppet(p + 84, &a->he_ppet);
    put32(p + 124, a->he_cap_macinfo[0]); put32(p + 128, a->he_ops);
    for (unsigned i = 0; i < 3; i++) put32(p + 132 + 4 * i, a->he_cap_phyinfo[i]);
    put32(p + 144, a->he_mcs_count); put32(p + 148, a->he_cap_macinfo[1]);
    put32(p + 152, a->he_cap_macinfo_internal); put32(p + 156, a->min_data_rate);
    put32(p + 160, a->he_caps_6ghz);        /* +164 sta_type, +168 bss_max_idle, +172 auth_mode: 0 */
    put32(p + 176, ext); put32(p + 180, a->punct_bitmap);
    put32(p + 184, a->eht_cap_mac[0]); put32(p + 188, a->eht_cap_mac[1]);
    for (unsigned i = 0; i < 3; i++) put32(p + 192 + 4 * i, a->eht_cap_phy[i]);
    if (a->eht_disable_mcs15) put32(p + 204, 0x40U); /* IEEE80211_EHT_OPER_MCS15_DISABLE */
    put_ppet(p + 208, &a->eht_ppet);
    uint8_t *q = p + PEER_ASSOC_BYTES;
    put32(q, tlv(TAG_ARRAY_BYTE, la)); copy(q + 4, a->legacy, a->legacy_count); q += 4 + la;
    put32(q, tlv(TAG_ARRAY_BYTE, ha)); copy(q + 4, a->ht, a->ht_count); q += 4 + ha;
    put32(q, cmd_tlv(TAG_VHT_RATE_SET, VHT_RATE_BYTES));
    if (a->vht_capable) { /* the firmware reads tx_mcs_set as the peer's RX capability */
        put32(q + 4, a->tx_max_rate); put32(q + 8, a->tx_mcs_set);
        put32(q + 12, a->rx_max_rate); put32(q + 16, a->rx_mcs_set);
    }
    q += VHT_RATE_BYTES;
    put32(q, tlv(TAG_ARRAY_STRUCT, HE_RATE_BYTES * a->he_mcs_count)); q += 4;
    for (unsigned i = 0; i < a->he_mcs_count; i++, q += HE_RATE_BYTES) {
        put32(q, cmd_tlv(TAG_HE_RATE_SET, HE_RATE_BYTES)); put32(q + 4, a->he_rx_mcs[i]); put32(q + 8, a->he_tx_mcs[i]);
    }
    put32(q, tlv(TAG_ARRAY_STRUCT, 0)); q += 4;                    /* ML params: none */
    put32(q, tlv(TAG_ARRAY_STRUCT, EHT_RATE_BYTES * a->eht_mcs_count)); q += 4;
    for (unsigned i = 0; i < a->eht_mcs_count; i++, q += EHT_RATE_BYTES) {
        put32(q, cmd_tlv(TAG_EHT_RATE_SET, EHT_RATE_BYTES)); put32(q + 4, a->eht_rx_mcs[i]); put32(q + 8, a->eht_tx_mcs[i]);
    }
    put32(q, tlv(TAG_ARRAY_STRUCT, 0));                             /* ML partners: none */
    return total;
}

size_t qcc2072_assoc_vdev_up(uint8_t *out, size_t cap, uint32_t vdev_id, uint32_t aid, const uint8_t bssid[6])
{
    uint8_t *p = bssid ? begin(out, cap, 4U + VDEV_UP_BYTES, QCC2072_ASSOC_CMD_VDEV_UP) : 0;
    if (!p) return 0;
    put32(p, cmd_tlv(TAG_VDEV_UP, VDEV_UP_BYTES)); put32(p + 4, vdev_id); put32(p + 8, aid); mac8(p + 12, bssid);
    return 4U + VDEV_UP_BYTES;
}

size_t qcc2072_assoc_install_key(uint8_t *out, size_t cap, uint32_t vdev_id, const uint8_t mac[6],
                                 uint32_t key_idx, uint32_t key_flags, uint32_t cipher,
                                 const uint8_t *key, uint32_t key_len)
{
    if (!mac || (key_len && !key) || key_len > 32) return 0;
    uint32_t aligned = round4(key_len);
    size_t total = 4U + INSTALL_KEY_BYTES + 4U + aligned;
    uint8_t *p = begin(out, cap, total, QCC2072_ASSOC_CMD_VDEV_INSTALL_KEY);
    if (!p) return 0;
    put32(p, cmd_tlv(TAG_INSTALL_KEY, INSTALL_KEY_BYTES));
    put32(p + 4, vdev_id); mac8(p + 8, mac); put32(p + 16, key_idx); put32(p + 20, key_flags);
    put32(p + 24, cipher);                  /* +28 key_rsc_counter: ath12k leaves it 0 */
    put32(p + 84, key_len);                 /* txmic/rxmic 0 for CCMP */
    put32(p + INSTALL_KEY_BYTES, tlv(TAG_ARRAY_BYTE, aligned));
    if (key_len) copy(p + INSTALL_KEY_BYTES + 4, key, key_len);
    return total;
}

size_t qcc2072_assoc_peer_set_param(uint8_t *out, size_t cap, uint32_t vdev_id, const uint8_t mac[6],
                                    uint32_t param, uint32_t value)
{
    uint8_t *p = mac ? begin(out, cap, 4U + PEER_PARAM_BYTES, QCC2072_ASSOC_CMD_PEER_SET_PARAM) : 0;
    if (!p) return 0;
    put32(p, cmd_tlv(TAG_PEER_SET_PARAM, PEER_PARAM_BYTES));
    put32(p + 4, vdev_id); mac8(p + 8, mac); put32(p + 16, param); put32(p + 20, value);
    return 4U + PEER_PARAM_BYTES;
}

static size_t three(uint8_t *out, size_t cap, uint32_t id, uint32_t tag, uint32_t a, uint32_t b, uint32_t c)
{
    uint8_t *p = begin(out, cap, 4U + PARAM_BYTES, id);
    if (!p) return 0;
    put32(p, cmd_tlv(tag, PARAM_BYTES)); put32(p + 4, a); put32(p + 8, b); put32(p + 12, c);
    return 4U + PARAM_BYTES;
}
size_t qcc2072_assoc_vdev_set_param(uint8_t *out, size_t cap, uint32_t vdev_id, uint32_t param, uint32_t value)
{
    return three(out, cap, QCC2072_ASSOC_CMD_VDEV_SET_PARAM, TAG_VDEV_SET_PARAM, vdev_id, param, value);
}
size_t qcc2072_assoc_pdev_set_param(uint8_t *out, size_t cap, uint32_t pdev_id, uint32_t param, uint32_t value)
{
    return three(out, cap, QCC2072_ASSOC_CMD_PDEV_SET_PARAM, TAG_PDEV_SET_PARAM, pdev_id, param, value);
}
size_t qcc2072_assoc_sta_ps_param(uint8_t *out, size_t cap, uint32_t vdev_id, uint32_t param, uint32_t value)
{
    return three(out, cap, QCC2072_ASSOC_CMD_STA_PS_PARAM, TAG_STA_PS_PARAM, vdev_id, param, value);
}
size_t qcc2072_assoc_sta_ps_mode(uint8_t *out, size_t cap, uint32_t vdev_id, uint32_t enable)
{
    uint8_t *p = begin(out, cap, 4U + PS_MODE_BYTES, QCC2072_ASSOC_CMD_STA_PS_MODE);
    if (!p) return 0;
    put32(p, cmd_tlv(TAG_STA_PS_MODE, PS_MODE_BYTES)); put32(p + 4, vdev_id); put32(p + 8, enable);
    return 4U + PS_MODE_BYTES;
}
static size_t vdev_only(uint8_t *out, size_t cap, uint32_t id, uint32_t tag, uint32_t vdev_id)
{
    uint8_t *p = begin(out, cap, 4U + VDEV_ID_BYTES, id);
    if (!p) return 0;
    put32(p, cmd_tlv(tag, VDEV_ID_BYTES)); put32(p + 4, vdev_id);
    return 4U + VDEV_ID_BYTES;
}
size_t qcc2072_assoc_vdev_down(uint8_t *out, size_t cap, uint32_t vdev_id)
{
    return vdev_only(out, cap, QCC2072_ASSOC_CMD_VDEV_DOWN, TAG_VDEV_DOWN, vdev_id);
}
size_t qcc2072_assoc_vdev_stop(uint8_t *out, size_t cap, uint32_t vdev_id)
{
    return vdev_only(out, cap, QCC2072_ASSOC_CMD_VDEV_STOP, TAG_VDEV_STOP, vdev_id);
}
size_t qcc2072_assoc_vdev_delete(uint8_t *out, size_t cap, uint32_t vdev_id)
{
    return vdev_only(out, cap, QCC2072_ASSOC_CMD_VDEV_DELETE, TAG_VDEV_DELETE, vdev_id);
}
size_t qcc2072_assoc_reorder_queue_setup(uint8_t *out, size_t cap, uint32_t vdev_id, const uint8_t mac[6],
                                         uint32_t tid, uint64_t queue, uint32_t ba_window_valid, uint32_t ba_window)
{
    uint8_t *p = mac ? begin(out, cap, 4U + REORDER_BYTES, QCC2072_ASSOC_CMD_PEER_REORDER_QUEUE_SETUP) : 0;
    if (!p) return 0;
    put32(p, cmd_tlv(TAG_REORDER_QUEUE_SETUP, REORDER_BYTES));
    put32(p + 4, vdev_id); mac8(p + 8, mac); put32(p + 16, tid);
    put32(p + 20, (uint32_t)queue); put32(p + 24, (uint32_t)(queue >> 32));
    put32(p + 28, tid); put32(p + 32, ba_window_valid); put32(p + 36, ba_window);
    return 4U + REORDER_BYTES;
}
size_t qcc2072_assoc_obss_spr(uint8_t *out, size_t cap, uint32_t vdev_id, uint32_t enable,
                              int32_t min_offset, int32_t max_offset)
{
    uint8_t *p = begin(out, cap, 4U + OBSS_BYTES, QCC2072_ASSOC_CMD_OBSS_SPR);
    if (!p) return 0;
    put32(p, cmd_tlv(TAG_OBSS_SPR, OBSS_BYTES)); /* +4 pdev_id: ath12k leaves it 0 */
    put32(p + 8, enable); put32(p + 12, (uint32_t)min_offset); put32(p + 16, (uint32_t)max_offset);
    put32(p + 20, vdev_id);
    return 4U + OBSS_BYTES;
}

/* ------------------------------------------------------------------ event parsers */
/* ath12k_wmi_tlv_parse: top-level TLVs, tb[tag] = last occurrence, min_len per policy. */
static int fixed(const uint8_t *ev, size_t n, uint32_t id, uint32_t tag, uint32_t min_len,
                 const uint8_t **body, uint32_t *len)
{
    if (!ev || n < 4 || n > HTC_SEND_MAX) return QCC2072_BAD_WIRE;
    if ((get32(ev) & 0xffffffU) != id) return QCC2072_BAD_STATE;
    const uint8_t *p = ev + 4, *found = 0;
    size_t left = n - 4;
    uint32_t found_len = 0;
    while (left) {
        if (left < 4) return QCC2072_BAD_WIRE;
        uint32_t h = get32(p), t = h >> 16, l = h & 0xffffU;
        p += 4; left -= 4;
        if (l > left) return QCC2072_BAD_WIRE;
        if (t == tag) {
            if (l < min_len) return QCC2072_BAD_WIRE;
            found = p; found_len = l;
        }
        p += l; left -= l;
    }
    if (!found) return QCC2072_BAD_WIRE;
    *body = found; *len = found_len;
    return 0;
}

int qcc2072_assoc_parse_vdev_start_resp(const uint8_t *ev, size_t n, struct qcc2072_assoc_vdev_start_resp *o)
{
    const uint8_t *b = 0; uint32_t l = 0;
    int rc = o ? fixed(ev, n, QCC2072_ASSOC_EV_VDEV_START_RESP, TAG_VDEV_START_RESP, 40, &b, &l) : QCC2072_INVALID_ARGUMENT;
    if (rc) return rc;
    o->vdev_id = get32(b); o->requestor_id = get32(b + 4); o->resp_type = get32(b + 8);
    o->status = get32(b + 12); o->chain_mask = get32(b + 16); o->smps_mode = get32(b + 20);
    o->pdev_id = get32(b + 24); o->cfgd_tx_streams = get32(b + 28); o->cfgd_rx_streams = get32(b + 32);
    o->max_allowed_tx_power = (int32_t)get32(b + 36);
    return 0;
}
int qcc2072_assoc_parse_vdev_stopped(const uint8_t *ev, size_t n, uint32_t *vdev_id)
{
    const uint8_t *b = 0; uint32_t l = 0;
    int rc = vdev_id ? fixed(ev, n, QCC2072_ASSOC_EV_VDEV_STOPPED, TAG_VDEV_STOPPED, 4, &b, &l) : QCC2072_INVALID_ARGUMENT;
    if (!rc) *vdev_id = get32(b);
    return rc;
}
int qcc2072_assoc_parse_key_complete(const uint8_t *ev, size_t n, struct qcc2072_assoc_key_complete *o)
{
    const uint8_t *b = 0; uint32_t l = 0;
    int rc = o ? fixed(ev, n, QCC2072_ASSOC_EV_INSTALL_KEY_COMPLETE, TAG_INSTALL_KEY_COMPLETE, 24, &b, &l)
               : QCC2072_INVALID_ARGUMENT;
    if (rc) return rc;
    o->vdev_id = get32(b); copy(o->mac, b + 4, 6); o->key_idx = get32(b + 12);
    o->key_flags = get32(b + 16); o->status = get32(b + 20);
    return 0;
}
int qcc2072_assoc_parse_peer_event(const uint8_t *ev, size_t n, struct qcc2072_assoc_peer_event *o)
{
    const uint8_t *b = 0; uint32_t l = 0;
    if (!o || !ev || n < 4) return o ? QCC2072_BAD_WIRE : QCC2072_INVALID_ARGUMENT;
    zero(o, sizeof(*o));
    uint32_t id = get32(ev) & 0xffffffU;
    int rc;
    if (id == QCC2072_ASSOC_EV_PEER_STA_KICKOUT) {
        if ((rc = fixed(ev, n, id, TAG_PEER_STA_KICKOUT, 16, &b, &l))) return rc;
        copy(o->mac, b, 6); o->reason = get32(b + 8); o->rssi = (int32_t)get32(b + 12);
        return 0;
    }
    if (id == QCC2072_ASSOC_EV_PEER_ASSOC_CONF) rc = fixed(ev, n, id, TAG_PEER_ASSOC_CONF, 12, &b, &l);
    else if (id == QCC2072_ASSOC_EV_PEER_DELETE_RESP) rc = fixed(ev, n, id, TAG_PEER_DELETE_RESP, 12, &b, &l);
    else return QCC2072_BAD_STATE;
    if (rc) return rc;
    o->vdev_id = get32(b); copy(o->mac, b + 4, 6);
    return 0;
}
int qcc2072_assoc_parse_mgmt_tx_done(const uint8_t *ev, size_t n, struct qcc2072_assoc_mgmt_tx_done *o)
{
    const uint8_t *b = 0; uint32_t l = 0;
    int rc = o ? fixed(ev, n, QCC2072_ASSOC_EV_MGMT_TX_COMPLETION, TAG_MGMT_TX_COMPL, 20, &b, &l)
               : QCC2072_INVALID_ARGUMENT;
    if (rc) return rc;
    o->desc_id = get32(b); o->status = get32(b + 4); o->pdev_id = get32(b + 8);
    o->ppdu_id = get32(b + 12); o->ack_rssi = get32(b + 16);
    return 0;
}
int qcc2072_assoc_parse_roam(const uint8_t *ev, size_t n, struct qcc2072_assoc_peer_event *o)
{
    const uint8_t *b = 0; uint32_t l = 0;
    if (!o) return QCC2072_INVALID_ARGUMENT;
    zero(o, sizeof(*o));
    int rc = fixed(ev, n, QCC2072_ASSOC_EV_ROAM, TAG_ROAM_EVENT, 12, &b, &l);
    if (rc) return rc;
    o->vdev_id = get32(b); o->reason = get32(b + 4) & 0xfU; o->rssi = (int32_t)get32(b + 8);
    return 0;
}
/* ath12k_pull_mgmt_rx_params_tlv: MGMT_RX_HDR + the first ARRAY_BYTE is the frame. */
int qcc2072_assoc_parse_mgmt_rx(const uint8_t *ev, size_t n, struct qcc2072_assoc_mgmt_rx *o)
{
    if (!o) return QCC2072_INVALID_ARGUMENT;
    zero(o, sizeof(*o));
    if (!ev || n < 4 || n > HTC_SEND_MAX) return QCC2072_BAD_WIRE;
    if ((get32(ev) & 0xffffffU) != QCC2072_ASSOC_EV_MGMT_RX) return QCC2072_BAD_STATE;
    const uint8_t *p = ev + 4, *hdr = 0, *frame = 0;
    size_t left = n - 4;
    uint32_t frame_space = 0;
    while (left) {
        if (left < 4) return QCC2072_BAD_WIRE;
        uint32_t h = get32(p), t = h >> 16, l = h & 0xffffU;
        p += 4; left -= 4;
        if (l > left) return QCC2072_BAD_WIRE;
        if (t == TAG_MGMT_RX_HDR) { if (l < 68) return QCC2072_BAD_WIRE; hdr = p; }
        else if (t == TAG_ARRAY_BYTE && !frame) { frame = p; frame_space = l; }
        p += l; left -= l;
    }
    if (!hdr || !frame) return QCC2072_BAD_WIRE;
    o->channel = get32(hdr); o->snr = get32(hdr + 4); o->rate = get32(hdr + 8); o->phy_mode = get32(hdr + 12);
    o->length = get32(hdr + 16); o->status = get32(hdr + 20); o->flags = get32(hdr + 40);
    o->rssi = (int32_t)get32(hdr + 44); o->pdev_id = get32(hdr + 60); o->chan_freq = get32(hdr + 64);
    if (o->length > frame_space) return QCC2072_BAD_WIRE;
    o->frame = frame;
    return 0;
}
int qcc2072_assoc_parse_htt_peer(const uint8_t *m, size_t n, struct qcc2072_assoc_peer_map *o)
{
    if (!o) return QCC2072_INVALID_ARGUMENT;
    zero(o, sizeof(*o));
    if (!m || n < 4) return QCC2072_BAD_WIRE;
    uint32_t info = get32(m), type = info & 0xffU;
    o->type = type;
    if (type == QCC2072_ASSOC_HTT_PEER_UNMAP || type == QCC2072_ASSOC_HTT_PEER_UNMAP2) {
        if (n < 12) return QCC2072_BAD_WIRE;
        o->unmap = 1; o->vdev_id = (info >> 8) & 0xffU; o->peer_id = info >> 16;
        copy(o->mac, m + 4, 4); put16(o->mac + 4, get32(m + 8) & 0xffffU);
        return 0;
    }
    if (type != QCC2072_ASSOC_HTT_PEER_MAP && type != QCC2072_ASSOC_HTT_PEER_MAP2 &&
        type != QCC2072_ASSOC_HTT_PEER_MAP3) return QCC2072_BAD_STATE;
    if (n < (type == QCC2072_ASSOC_HTT_PEER_MAP ? 12U : 16U)) return QCC2072_BAD_WIRE;
    uint32_t info1 = get32(m + 8), info2 = n >= 16 ? get32(m + 12) : 0;
    o->vdev_id = (info >> 8) & 0xffU; o->peer_id = info >> 16;
    copy(o->mac, m + 4, 4); put16(o->mac + 4, info1 & 0xffffU); /* ath12k_dp_get_mac_addr */
    if (type == QCC2072_ASSOC_HTT_PEER_MAP2) { o->ast_hash = info2 & 0xffffU; o->hw_peer_id = info1 >> 16; }
    else if (type == QCC2072_ASSOC_HTT_PEER_MAP3) { o->ast_hash = info2 >> 16; o->hw_peer_id = info2 & 0xffffU; }
    return 0;
}

/* ------------------------------------------------------------------ capabilities */
static const int8_t hw_mode_priority[6] = {5, 1, 4, 3, 0, 2}; /* ath12k_hw_mode_pri_map */

static unsigned fls32(uint32_t v) { unsigned n = 0; while (v) { n++; v >>= 1; } return n; }

int qcc2072_assoc_parse_caps(const uint8_t *ev, size_t n, struct qcc2072_assoc_caps *c)
{
    const uint8_t *b = 0; uint32_t l = 0;
    if (!c) return QCC2072_INVALID_ARGUMENT;
    if (!fixed(ev, n, QCC2072_ASSOC_EV_SERVICE_READY, TAG_SERVICE_READY, 60, &b, &l)) {
        c->num_rf_chains = get32(b + 36); c->hw_min_tx_power = get32(b + 52); c->hw_max_tx_power = get32(b + 56);
        c->service_ready = 1;
        return 0;
    }
    int rc = fixed(ev, n, QCC2072_ASSOC_EV_SERVICE_READY_EXT, TAG_SERVICE_READY_EXT, 4, &b, &l);
    if (rc) return rc;
    /* Walk the top-level arrays: HW_MODE_CAPABILITIES and MAC_PHY_CAPABILITIES entries. */
    const uint8_t *modes[16], *phys[16];
    unsigned mode_count = 0, phy_count = 0, num_hw_modes = 0;
    const uint8_t *p = ev + 4;
    size_t left = n - 4;
    while (left >= 4) {
        uint32_t h = get32(p), t = h >> 16, tl = h & 0xffffU;
        p += 4; left -= 4;
        if (tl > left) return QCC2072_BAD_WIRE;
        if (t == TAG_SOC_HW_MODE_CAPS && tl >= 8) num_hw_modes = get32(p);
        if (t == TAG_ARRAY_STRUCT) {
            const uint8_t *q = p; size_t r = tl;
            while (r >= 4) {
                uint32_t ih = get32(q), it = ih >> 16, il = ih & 0xffffU;
                q += 4; r -= 4;
                if (il > r) return QCC2072_BAD_WIRE;
                if (it == TAG_HW_MODE_CAPS && il >= 12 && mode_count < 16) modes[mode_count++] = q;
                if (it == TAG_MAC_PHY_CAPS && il >= 88 && phy_count < 16) phys[phy_count++] = q;
                q += il; r -= il;
            }
        }
        p += tl; left -= tl;
    }
    if (!mode_count || !phy_count) return QCC2072_BAD_WIRE;
    if (num_hw_modes && num_hw_modes < mode_count) mode_count = num_hw_modes;
    /* ath12k_wmi_hw_mode_caps: lowest priority value among known modes. */
    uint32_t preferred = 0xffffffffU; int best = 99;
    for (unsigned i = 0; i < mode_count; i++) {
        uint32_t m = get32(modes[i]);
        if (m < 6 && hw_mode_priority[m] < best) { best = hw_mode_priority[m]; preferred = m; }
    }
    if (preferred == 0xffffffffU) return QCC2072_RUNTIME_UNSUPPORTED;
    /* ath12k_pull_mac_phy_cap_svc_ready_ext: phy_idx = fls(phy_map of the previous mode). */
    unsigned idx = 0, hw = 0, phy_map = 0;
    for (; hw < mode_count; hw++) {
        if (get32(modes[hw]) == preferred) { phy_map = get32(modes[hw] + 4); break; }
        idx = fls32(get32(modes[hw] + 4));
    }
    zero(c->ht_cap_info, sizeof(c->ht_cap_info));
    c->supported_bands = 0; c->vht_cap = 0; c->tx_chainmask = c->rx_chainmask = 0;
    for (unsigned phy = 0; phy < 32 && (phy_map >> phy); phy++) {
        if (!(phy_map & (1U << phy))) continue;
        if (idx + phy >= phy_count) break;
        const uint8_t *m = phys[idx + phy];
        uint32_t bands = get32(m + 16);
        c->supported_bands |= bands; c->ampdu_density = get32(m + 20);
        if (bands & 1U) { c->tx_chainmask = get32(m + 48); c->rx_chainmask = get32(m + 52); c->ht_cap_info[0] = get32(m + 28); }
        if (bands & 2U) {
            c->vht_cap = get32(m + 64); c->tx_chainmask = get32(m + 80); c->rx_chainmask = get32(m + 84);
            c->ht_cap_info[1] = get32(m + 60);
        }
    }
    if (!(c->supported_bands & 3U)) return QCC2072_BAD_WIRE;
    c->preferred_hw_mode = preferred; c->ext_ready = 1;
    return 0;
}

int qcc2072_assoc_own_ht(const struct qcc2072_assoc_caps *c, unsigned band, struct qcc2072_assoc_ht *sband,
                         struct qcc2072_assoc_ht *req)
{
    if (!c || !sband || band > 1) return QCC2072_INVALID_ARGUMENT;
    zero(sband, sizeof(*sband));
    if (req) zero(req, sizeof(*req));
    uint32_t w = c->ht_cap_info[band];
    if (!c->ext_ready || !(c->supported_bands & (1U << band)) || !(w & 0x1U)) return QCC2072_RUNTIME_UNSUPPORTED;
    /* ath12k_create_ht_cap */
    uint16_t cap = 0x0002U | 0x1000U;         /* SUP_WIDTH_20_40 | DSSSCCK40; SM_PS static (0) */
    if (w & 0x2U) cap |= 0x0020U;             /* HT20_SGI -> SGI_20 */
    if (w & 0x800U) cap |= 0x0040U;           /* HT40_SGI -> SGI_40 */
    if (w & 0x4U) cap |= 1U << 2;             /* DYNAMIC_SMPS -> SM_PS dynamic */
    if (w & 0x8U) cap |= 0x0080U;             /* TX_STBC */
    if (w & 0x30U) cap |= (uint16_t)((((w & 0x30U) >> 4) << 8) & 0x0300U);
    if (w & 0x1000U) cap |= 0x0001U;          /* RX_LDPC -> LDPC_CODING */
    if (w & 0x80U) cap |= 0x8000U;            /* L_SIG_TXOP_PROT */
    if (c->vht_cap & 0x3U) cap |= 0x0800U;    /* WMI_VHT_CAP_MAX_MPDU_LEN_MASK -> MAX_AMSDU */
    sband->cap = cap; sband->ampdu_factor = 3; sband->ampdu_density = 0; sband->tx_params = 1;
    unsigned shift = 0;
    while (shift < 32 && c->rx_chainmask && !(c->rx_chainmask & (1U << shift))) shift++;
    uint32_t mask = shift < 32 ? c->rx_chainmask >> shift : 0, chains = popcount(c->rx_chainmask);
    for (unsigned i = 0; i < chains && i < 10; i++) if (mask & (1U << i)) sband->rx_mask[i] = 0xff;
    if (req) { /* mac80211 ieee80211_add_ht_ie: 20 MHz limit, SMPS off */
        *req = *sband;
        req->cap &= (uint16_t)~(0x0002U | 0x0040U | 0x000cU);
        req->cap |= 3U << 2;
    }
    return 0;
}

/* ------------------------------------------------------------------ 802.11 */
int qcc2072_assoc_parse_ies(const uint8_t *p, size_t n, struct qcc2072_assoc_ies *o)
{
    if (!o) return QCC2072_INVALID_ARGUMENT;
    zero(o, sizeof(*o));
    if (!p && n) return QCC2072_INVALID_ARGUMENT;
    size_t i = 0;
    while (i < n) {
        if (n - i < 2 || p[i + 1] > n - i - 2) { o->truncated = 1; return QCC2072_BAD_WIRE; }
        unsigned id = p[i], len = p[i + 1];
        const uint8_t *b = p + i + 2;
        int k = -1;
        switch (id) {
        case 0: k = QCC2072_ASSOC_IE_SSID; break;
        case 1: k = QCC2072_ASSOC_IE_RATES; break;
        case 3: k = QCC2072_ASSOC_IE_DS; break;
        case 5: k = QCC2072_ASSOC_IE_TIM; break;
        case 32: k = QCC2072_ASSOC_IE_PWR_CONSTRAINT; break;
        case 42: k = QCC2072_ASSOC_IE_ERP; break;
        case 45: k = QCC2072_ASSOC_IE_HT_CAP; break;
        case 48: k = QCC2072_ASSOC_IE_RSN; o->rsn_count++; break;
        case 50: k = QCC2072_ASSOC_IE_EXT_RATES; break;
        case 56: k = QCC2072_ASSOC_IE_TIMEOUT; break;
        case 61: k = QCC2072_ASSOC_IE_HT_OP; break;
        case 221: /* Microsoft OUI: type 1 WPA, type 2 WMM (subtype 0 info, 1 parameter) */
            if (len >= 4 && b[0] == 0x00 && b[1] == 0x50 && b[2] == 0xf2) {
                if (b[3] == 1) k = QCC2072_ASSOC_IE_WPA;
                else if (b[3] == 2 && len >= 5 && b[4] == 0) k = QCC2072_ASSOC_IE_WMM_INFO;
                else if (b[3] == 2 && len >= 5 && b[4] == 1) k = QCC2072_ASSOC_IE_WMM_PARAM;
            }
            break;
        default: break;
        }
        if (k >= 0) {
            if (o->ie[k]) o->duplicates++;
            else { o->ie[k] = b; o->len[k] = (uint8_t)len; }
        }
        i += 2U + len;
    }
    return 0;
}

static void header(uint8_t *f, uint32_t fc, const uint8_t *da, const uint8_t *sa, const uint8_t *bssid, uint16_t seq)
{
    put16(f, fc); put16(f + 2, 0); /* duration: the firmware fills NAV for its own TX */
    copy(f + 4, da, 6); copy(f + 10, sa, 6); copy(f + 16, bssid, 6); put16(f + 22, seq);
}
size_t qcc2072_assoc_auth_frame(uint8_t *out, size_t cap, const uint8_t bssid[6], const uint8_t sa[6], uint16_t seq)
{
    if (!out || !bssid || !sa || cap < 30) return 0;
    zero(out, 30);
    header(out, 0x00b0U, bssid, sa, bssid, seq);
    put16(out + 24, 0); put16(out + 26, 1); put16(out + 28, 0); /* open system, transaction 1 */
    return 30;
}
size_t qcc2072_assoc_deauth_frame(uint8_t *out, size_t cap, const uint8_t bssid[6], const uint8_t sa[6],
                                  uint16_t seq, uint16_t reason)
{
    if (!out || !bssid || !sa || cap < 26) return 0;
    zero(out, 26);
    header(out, 0x00c0U, bssid, sa, bssid, seq);
    put16(out + 24, reason);
    return 26;
}

/* sband bitrates in 100 kbps, ath12k_legacy_rates order (5 GHz uses entries 4..11). */
static const uint16_t legacy_bitrates[12] = {10, 20, 55, 110, 60, 90, 120, 180, 240, 360, 480, 540};
static unsigned sband_first(unsigned band) { return band ? 4U : 0U; }
/* mac80211 ieee80211_parse_bitrates/ieee80211_get_rates over Supported + Extended rates:
 * bit i = sband rate i; basic collects the 0x80 flags. */
static uint32_t rate_bits(unsigned band, const struct qcc2072_assoc_ies *e, uint32_t *basic)
{
    uint32_t rates = 0, b = 0;
    for (unsigned w = 0; w < 2; w++) {
        unsigned k = w ? QCC2072_ASSOC_IE_EXT_RATES : QCC2072_ASSOC_IE_RATES;
        for (unsigned i = 0; e->ie[k] && i < e->len[k]; i++) {
            unsigned r = e->ie[k][i] & 0x7fU;
            for (unsigned j = sband_first(band); j < 12; j++)
                if (legacy_bitrates[j] == r * 5U) {
                    rates |= 1U << (j - sband_first(band));
                    if (e->ie[k][i] & 0x80U) b |= 1U << (j - sband_first(band));
                }
        }
    }
    if (basic) *basic = b;
    return rates;
}
static uint8_t rate_byte(uint16_t bitrate) { return (uint8_t)((bitrate + 4U) / 5U); } /* DIV_ROUND_UP */

/* 5 GHz and 2.4 GHz channel tables of ath12k mac.c (sband->channels), for Supported Channels. */
static const uint8_t channels_5g[28] = {36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120,
                                        124, 128, 132, 136, 140, 144, 149, 153, 157, 161, 165, 169, 173, 177};

size_t qcc2072_assoc_request_frame(uint8_t *out, size_t cap, const struct qcc2072_assoc_req_args *a)
{
    if (!out || !a || !a->bssid || !a->sa || !a->ssid || !a->ssid_length || a->ssid_length > 32 ||
        (a->rsn_length && (!a->rsn || a->rsn_length < 2 || a->rsn[0] != 48 || a->rsn[1] + 2U != a->rsn_length)) ||
        (a->ext_capa_length && !a->ext_capa) || a->ext_capa_length > 32 || (a->ap_ie_length && !a->ap_ies))
        return 0;
    struct qcc2072_assoc_ies ap;
    if (qcc2072_assoc_parse_ies(a->ap_ies, a->ap_ie_length, &ap)) return 0;
    unsigned band = a->freq_mhz < 3000 ? 0U : 1U, n_rates = band ? 8U : 12U;
    uint8_t f[QCC2072_ASSOC_MGMT_SLOT_BYTES];
    zero(f, sizeof(f));
    header(f, 0x0000U, a->bssid, a->sa, a->bssid, a->seq_ctrl);
    /* capability (mac80211 ieee80211_send_assoc / assoc link elems) */
    uint32_t capab = 0x0001U;                                    /* ESS */
    if (!band) capab |= 0x0400U | 0x0020U;                       /* short slot, short preamble */
    if (a->ap_capability & 0x0010U) capab |= 0x0010U;            /* privacy */
    if (a->ap_capability & 0x0100U) capab |= 0x0100U;            /* spectrum mgmt (hw SPECTRUM_MGMT) */
    put16(f + 24, capab); put16(f + 26, a->listen_interval);
    size_t i = 28;
    f[i++] = 0; f[i++] = a->ssid_length; copy(f + i, a->ssid, a->ssid_length); i += a->ssid_length;
    /* rates: AP's rates intersected with ours; all of ours if the AP gave none */
    uint32_t rates = rate_bits(band, &ap, 0);
    if (!ap.ie[QCC2072_ASSOC_IE_RATES] && !ap.ie[QCC2072_ASSOC_IE_EXT_RATES]) rates = 0xfffU;
    unsigned count = 0;
    for (unsigned j = 0; j < n_rates; j++) if (rates & (1U << j)) count++;
    unsigned first = count < 8 ? count : 8U, k = 0;
    f[i++] = 1; f[i++] = (uint8_t)first;
    for (unsigned j = 0; j < n_rates && k < first; j++)
        if (rates & (1U << j)) { f[i++] = rate_byte(legacy_bitrates[j + sband_first(band)]); k++; }
    if (count > 8) {
        f[i++] = 50; f[i++] = (uint8_t)(count - 8); k = 0;
        for (unsigned j = 0; j < n_rates; j++)
            if (rates & (1U << j)) { if (k++ >= 8) f[i++] = rate_byte(legacy_bitrates[j + sband_first(band)]); }
    }
    if (capab & 0x0100U) {
        f[i++] = 33; f[i++] = 2; f[i++] = 0; f[i++] = (uint8_t)a->max_power_dbm; /* power capability */
        unsigned nch = band ? 28U : 14U;                                       /* supported channels */
        f[i++] = 36; f[i++] = (uint8_t)(2 * nch);
        for (unsigned c = 0; c < nch; c++) { f[i++] = band ? channels_5g[c] : (uint8_t)(c + 1); f[i++] = 1; }
    }
    if (a->rsn_length) { copy(f + i, a->rsn, a->rsn_length); i += a->rsn_length; }
    if (a->ht) {
        f[i++] = 45; f[i++] = 26;
        put16(f + i, a->ht->cap); f[i + 2] = (uint8_t)(a->ht->ampdu_factor | a->ht->ampdu_density << 2);
        copy(f + i + 3, a->ht->rx_mask, 10); f[i + 15] = a->ht->tx_params; /* rx_highest 0, rest 0 */
        i += 26;
    }
    if (a->ext_capa_length) { f[i++] = 127; f[i++] = a->ext_capa_length; copy(f + i, a->ext_capa, a->ext_capa_length); i += a->ext_capa_length; }
    if (a->wmm) { /* ieee80211_add_wmm_info_ie, QoS info 0 (no U-APSD) */
        static const uint8_t wmm[9] = {221, 7, 0x00, 0x50, 0xf2, 2, 0, 1, 0};
        copy(f + i, wmm, 9); i += 9;
    }
    if (i > cap || i > QCC2072_ASSOC_MGMT_SLOT_BYTES) return 0;
    copy(out, f, i);
    return i;
}

static int frame_for_us(const uint8_t *f, size_t n, size_t min, uint32_t subtype, const uint8_t *own,
                        const uint8_t *bssid, int allow_broadcast)
{
    if (!f || !own || !bssid) return QCC2072_INVALID_ARGUMENT;
    if (n < 24) return QCC2072_BAD_WIRE;
    uint32_t fc = get16(f);
    if ((fc & 0x00fcU) != subtype) return QCC2072_BAD_STATE;
    if (fc & 0x4300U) return QCC2072_BAD_STATE;                  /* DS bits or protected */
    static const uint8_t bcast[6] = {255, 255, 255, 255, 255, 255};
    if (!same(f + 4, own, 6) && !(allow_broadcast && same(f + 4, bcast, 6))) return QCC2072_BAD_STATE;
    if (!same(f + 10, bssid, 6) || !same(f + 16, bssid, 6)) return QCC2072_BAD_STATE;
    return n < min ? QCC2072_BAD_WIRE : 0;
}
int qcc2072_assoc_parse_auth(const uint8_t *f, size_t n, const uint8_t own[6], const uint8_t bssid[6],
                             struct qcc2072_assoc_auth_resp *o)
{
    int rc = o ? frame_for_us(f, n, 30, 0xb0U, own, bssid, 0) : QCC2072_INVALID_ARGUMENT;
    if (rc) return rc;
    o->algorithm = (uint16_t)get16(f + 24); o->transaction = (uint16_t)get16(f + 26); o->status = (uint16_t)get16(f + 28);
    return 0;
}
int qcc2072_assoc_parse_assoc_resp(const uint8_t *f, size_t n, const uint8_t own[6], const uint8_t bssid[6],
                                   struct qcc2072_assoc_resp *o)
{
    if (!o) return QCC2072_INVALID_ARGUMENT;
    zero(o, sizeof(*o));
    int rc = frame_for_us(f, n, 30, 0x10U, own, bssid, 0);
    if (rc == QCC2072_BAD_STATE && !frame_for_us(f, n, 30, 0x30U, own, bssid, 0)) { rc = 0; o->reassoc = 1; }
    if (rc) return rc;
    o->capability = (uint16_t)get16(f + 24); o->status = (uint16_t)get16(f + 26); o->aid_raw = (uint16_t)get16(f + 28);
    o->aid = o->aid_raw & 0x3fffU;
    if (!o->aid || o->aid > 2007) o->aid = 0; /* mac80211: invalid AID, carry on as broken AP */
    o->ies = f + 30; o->ie_length = (uint16_t)(n - 30);
    struct qcc2072_assoc_ies e;
    if (qcc2072_assoc_parse_ies(o->ies, o->ie_length, &e)) return QCC2072_BAD_WIRE;
    const uint8_t *t = e.ie[QCC2072_ASSOC_IE_TIMEOUT];
    if (t && e.len[QCC2072_ASSOC_IE_TIMEOUT] >= 5 && t[0] == 3) o->comeback_tu = get32(t + 1);
    return 0;
}
int qcc2072_assoc_parse_deauth(const uint8_t *f, size_t n, const uint8_t own[6], const uint8_t bssid[6],
                               uint16_t *reason, uint8_t *disassoc)
{
    if (!reason || !disassoc) return QCC2072_INVALID_ARGUMENT;
    int rc = frame_for_us(f, n, 26, 0xc0U, own, bssid, 1);
    *disassoc = 0;
    if (rc == QCC2072_BAD_STATE) { rc = frame_for_us(f, n, 26, 0xa0U, own, bssid, 1); *disassoc = 1; }
    if (rc) return rc;
    *reason = (uint16_t)get16(f + 24);
    return 0;
}

/* The AP's RSN element (and RSNXE) as the beacon/probe response carried it, if we can join it
 * without PMF (native-rsn.h). The request carries snap_rsn_own; snap_wpa2 compares M3 with this. */
size_t qcc2072_assoc_ap_rsn(const uint8_t *ap_ies, size_t n, uint8_t rsn[SNAP_RSN_MAX_ELEMENT],
                            uint8_t rsnxe[SNAP_RSN_MAX_RSNXE], size_t *rsnxe_length, int *reason)
{
    const uint8_t *r, *x;
    size_t rn, xn;
    int why = snap_rsn_find(ap_ies, n, &r, &rn, &x, &xn);
    if (!why) why = snap_rsn_ap_policy(r, rn, 0);
    if (!why && x && xn > SNAP_RSN_MAX_RSNXE) why = SNAP_RSN_TOO_LONG;
    if (reason) *reason = why;
    if (rsnxe_length) *rsnxe_length = 0;
    if (why || !rsn) return 0;
    copy(rsn, r, rn);
    if (x && rsnxe && rsnxe_length) { copy(rsnxe, x, xn); *rsnxe_length = xn; }
    return rn;
}
int qcc2072_assoc_link_security(const struct qcc2072_assoc *s, uint8_t rsn[SNAP_RSN_MAX_ELEMENT], size_t *rsn_length,
                                uint8_t rsnxe[SNAP_RSN_MAX_RSNXE], size_t *rsnxe_length)
{
    if (!s || !rsn || !rsn_length || !rsnxe || !rsnxe_length) return QCC2072_INVALID_ARGUMENT;
    *rsn_length = 0; *rsnxe_length = 0;
    if (s->state != QCC2072_ASSOC_CONNECTING && s->state != QCC2072_ASSOC_ASSOCIATED &&
        s->state != QCC2072_ASSOC_AUTHORIZED) return QCC2072_BAD_STATE;
    if (!s->link.rsn_length) return QCC2072_BAD_STATE;
    *rsn_length = qcc2072_assoc_ap_rsn(s->link.ies, s->link.ie_length, rsn, rsnxe, rsnxe_length, 0);
    return *rsn_length ? 0 : QCC2072_BAD_STATE;
}


/* ------------------------------------------------------------------ state machine */
enum { OP_NONE, OP_PDEV, OP_VDEV_PARAM, OP_STA_PS, OP_PS_MODE, OP_VDEV_CREATE, OP_PEER_CREATE,
       OP_PEER_PARAM, OP_REO, OP_VDEV_START, OP_AUTH, OP_ASSOC, OP_DEAUTH, OP_PEER_ASSOC,
       OP_VDEV_UP, OP_OBSS, OP_KEY, OP_KEY_DELETE, OP_AUTHORIZE, OP_VDEV_DOWN, OP_VDEV_STOP,
       OP_REO_RELEASE, OP_PEER_DELETE, OP_MARK };
enum { W_NONE, W_PEER_MAP, W_START, W_ASSOC_CONF, W_KEY, W_STOPPED, W_DELETED, W_MGMT, W_MGMT_DONE };
enum { PROG_NONE, PROG_CONNECT, PROG_ASSOCIATE, PROG_CONTROL, PROG_TEARDOWN };
const char *qcc2072_assoc_state_name(unsigned v)
{
    static const char *const n[] = {"IDLE", "CONNECTING", "ASSOCIATED", "AUTHORIZED", "TEARDOWN", "WEDGED"};
    return v < sizeof(n) / sizeof(n[0]) ? n[v] : "?";
}
const char *qcc2072_assoc_op_name(unsigned v)
{
    static const char *const n[] = {"-", "PDEV_SET_PARAM", "VDEV_SET_PARAM", "STA_PS_PARAM", "STA_PS_MODE",
        "VDEV_CREATE", "PEER_CREATE", "PEER_SET_PARAM", "REORDER_QUEUE_SETUP", "VDEV_START", "AUTH", "ASSOC_REQ",
        "DEAUTH", "PEER_ASSOC", "VDEV_UP", "OBSS_SPR", "INSTALL_KEY", "DELETE_KEY", "AUTHORIZE", "VDEV_DOWN",
        "VDEV_STOP", "REO_RELEASE", "PEER_DELETE", "MARK"};
    return v < sizeof(n) / sizeof(n[0]) ? n[v] : "?";
}
const char *qcc2072_assoc_wait_name(unsigned v)
{
    static const char *const n[] = {"-", "HTT_PEER_MAP", "VDEV_START_RESP", "PEER_ASSOC_CONF", "INSTALL_KEY_COMPLETE",
        "VDEV_STOPPED", "PEER_DELETE_RESP+UNMAP", "MGMT_TX_COMPLETION+RESPONSE", "MGMT_TX_COMPLETION"};
    return v < sizeof(n) / sizeof(n[0]) ? n[v] : "?";
}
const char *qcc2072_assoc_kind_name(uint32_t detail)
{
    static const char *const n[] = {"none", "timeout", "firmware refused", "AP refused", "not acknowledged",
        "AP deauth/disassoc", "kickout/beacon miss", "hook failed", "local", "not authorized in time"};
    unsigned k = (detail >> 8) & 0xffU;
    return k < sizeof(n) / sizeof(n[0]) ? n[k] : "?";
}
const char *qcc2072_assoc_prog_name(unsigned v)
{
    static const char *const n[] = {"-", "connect", "associate", "control", "teardown"};
    return v < sizeof(n) / sizeof(n[0]) ? n[v] : "?";
}
enum { MARK_RADIO = 1, MARK_VDEV_CONFIG, MARK_TXPOWER_2G, MARK_TXPOWER_5G };
/* s->response for the current wait: 0 none, 1 done, 2 refused, 3 comeback (assoc status 30). */

static void notify(struct qcc2072_assoc *s, uint32_t type, int32_t status, uint64_t transaction,
                   uint64_t link, uint16_t reason, uint32_t detail)
{
    if (s->notice_count >= 8) { s->bad_events++; return; }
    struct qcc2072_assoc_notice *n = &s->notices[(s->notice_read + s->notice_count) & 7U];
    zero(n, sizeof(*n));
    n->type = type; n->status = status; n->transaction = transaction; n->link_transaction = link;
    n->reason = reason; n->aid = s->aid; n->detail = detail;
    s->notice_count++;
}
static void add(struct qcc2072_assoc *s, uint8_t op, uint8_t wait, uint32_t a, uint32_t b)
{
    if (s->prog_len < sizeof(s->prog) / sizeof(s->prog[0])) {
        struct qcc2072_assoc_step *t = &s->prog[s->prog_len++];
        t->op = op; t->wait = wait; t->pad = 0; t->a = a; t->b = b;
    }
}
static void program(struct qcc2072_assoc *s, uint8_t kind)
{
    zero(s->prog, sizeof(s->prog));
    s->prog_len = 0; s->pc = 0; s->prog_kind = kind; s->wait = W_NONE; s->deadline = 0;
    s->slot_deadline = 0; s->mgmt_retry_at = 0;
}
static void wipe_cmd(struct qcc2072_assoc *s) { zero(s->cmd, sizeof(s->cmd)); s->cmd_length = 0; s->cmd_has_key = 0; }
static unsigned band_of(const struct qcc2072_assoc *s) { return s->link.freq_mhz < 3000 ? 0U : 1U; }
static int channel_ok(uint16_t mhz) { return (mhz >= 2412 && mhz <= 2484) || (mhz >= 5150 && mhz <= 5885); }
static unsigned lowest(uint32_t v) { unsigned i = 0; if (!v) return 0; while (!(v & 1U)) { v >>= 1; i++; } return i; }

/* ath12k_mac_get_rate_hw_value(sband->bitrates[__ffs(basic_rates)]):
 * ATH12K_HW_RATE_CODE(hw_value, 0, CCK or OFDM preamble). hw.h ATH12K_HW_RATE_* values. */
static uint32_t hw_rate_code(unsigned band, unsigned index)
{
    static const uint8_t hw_value[12] = {3, 2, 1, 0, 3, 7, 2, 6, 1, 5, 0, 4};
    unsigned j = index + sband_first(band);
    if (j >= 12) j = sband_first(band);
    return 1U << 28 | (j < 4 ? 1U : 0U) << 8 | hw_value[j];
}

/* ath12k_peer_assoc_prepare for a 20 MHz legacy/HT link (mac.c peer_assoc_h_*), with
 * mac80211's link_sta derived from the association response (beacon fallback for
 * missing elements), plus the BSS parameters mac80211 notifies at association. */
static void derive_peer(struct qcc2072_assoc *s)
{
    struct qcc2072_assoc_peer_args *a = &s->peer;
    struct qcc2072_assoc_ies resp, bcn;
    struct qcc2072_assoc_ht own;
    unsigned band = band_of(s);
    zero(a, sizeof(*a));
    (void)qcc2072_assoc_parse_ies(s->resp_ies, s->resp_ie_length, &resp);
    (void)qcc2072_assoc_parse_ies(s->link.ies, s->link.ie_length, &bcn);
    if (!resp.ie[QCC2072_ASSOC_IE_RATES] && !resp.ie[QCC2072_ASSOC_IE_EXT_RATES]) {
        resp.ie[QCC2072_ASSOC_IE_RATES] = bcn.ie[QCC2072_ASSOC_IE_RATES];
        resp.len[QCC2072_ASSOC_IE_RATES] = bcn.len[QCC2072_ASSOC_IE_RATES];
        resp.ie[QCC2072_ASSOC_IE_EXT_RATES] = bcn.ie[QCC2072_ASSOC_IE_EXT_RATES];
        resp.len[QCC2072_ASSOC_IE_EXT_RATES] = bcn.len[QCC2072_ASSOC_IE_EXT_RATES];
    }
    /* mac80211 "AP bug" recovery: WMM parameter, HT capability/operation from the beacon */
    static const uint8_t fallback[] = {QCC2072_ASSOC_IE_HT_CAP, QCC2072_ASSOC_IE_HT_OP, QCC2072_ASSOC_IE_WMM_PARAM};
    for (unsigned i = 0; i < sizeof(fallback); i++)
        if (!resp.ie[fallback[i]]) { resp.ie[fallback[i]] = bcn.ie[fallback[i]]; resp.len[fallback[i]] = bcn.len[fallback[i]]; }
    /* h_basic */
    copy(a->peer_mac, s->link.bssid, 6); a->vdev_id = s->link.vdev_id; a->peer_new_assoc = 1;
    a->peer_associd = s->aid; a->auth_flag = 1; a->peer_listen_intval = LISTEN_INTERVAL; a->peer_nss = 1;
    a->peer_caps = s->assoc_capability;
    /* h_crypto: RSN element present -> 4-way handshake; no PMF */
    a->need_ptk_4_way = s->secure;
    /* h_rates: link_sta->supp_rates[band] in sband order, ath12k_mac_bitrate_to_rate */
    uint32_t basic, rates = rate_bits(band, &resp, &basic);
    for (unsigned j = 0; j + sband_first(band) < 12; j++)
        if (rates & (1U << j)) {
            uint16_t br = legacy_bitrates[j + sband_first(band)];
            a->legacy[a->legacy_count++] = (uint8_t)(rate_byte(br) | (j + sband_first(band) < 4 ? 0x80U : 0U));
        }
    s->basic_rate = (uint8_t)lowest(basic);
    /* h_ht: link_sta->ht_cap = ieee80211_ht_cap_ie_to_sta_ht_cap(own sband cap, AP element) */
    const uint8_t *ht = resp.ie[QCC2072_ASSOC_IE_HT_CAP];
    if (s->ht && ht && resp.len[QCC2072_ASSOC_IE_HT_CAP] >= 26 && !qcc2072_assoc_own_ht(&s->caps, band, &own, 0)) {
        uint32_t cap = get16(ht) & (own.cap | ~(0x0001U | 0x0002U | 0x0010U | 0x0020U | 0x0040U | 0x1000U)) & 0xffffU;
        if (!(own.cap & 0x0080U)) cap &= ~0x0300U;  /* no own TX STBC: drop the peer's RX STBC */
        if (!(own.cap & 0x0300U)) cap &= ~0x0080U;  /* no own RX STBC: drop the peer's TX STBC */
        uint8_t rx[10];
        zero(rx, sizeof(rx));
        for (unsigned i = 0; i < 4; i++) rx[i] = own.rx_mask[i] & ht[3 + i];
        if (own.rx_mask[4] & ht[3 + 4] & 1U) rx[4] |= 1U;
        static const uint8_t density[8] = {0, 1, 1, 1, 2, 4, 8, 16}; /* ath12k_parse_mpdudensity */
        a->ht_flag = 1;
        a->peer_max_mpdu = (1U << (13U + (ht[2] & 3U))) - 1U;
        a->peer_mpdu_density = density[(ht[2] >> 2) & 7U];
        a->peer_ht_caps = cap;
        a->peer_rate_caps |= 0x08U;                                  /* WMI_HOST_RC_HT_FLAG */
        if (cap & 0x0001U) a->ldpc_flag = 1;
        if (cap & (0x0020U | 0x0040U)) a->peer_rate_caps |= 0x04U;   /* SGI */
        if (cap & 0x0080U) { a->peer_rate_caps |= 0x20U; a->stbc_flag = 1; }
        if (cap & 0x0300U) { a->peer_rate_caps |= ((cap & 0x0300U) >> 8) << 6; a->stbc_flag = 1; }
        if (rx[1] && rx[2]) a->peer_rate_caps |= 0x200U;             /* TS */
        else if (rx[1]) a->peer_rate_caps |= 0x01U;                  /* DS */
        unsigned n = 0, max_nss = 0, rx_nss = 0;
        for (unsigned i = 0; i < 80; i++)
            if (rx[i / 8] & (1U << (i % 8))) { max_nss = i / 8 + 1; if (n < QCC2072_ASSOC_MAX_HT_RATES) a->ht[n++] = (uint8_t)i; }
        for (unsigned i = 0; i < 4; i++) if (rx[i]) rx_nss++;        /* ieee80211_sta_init_nss */
        if (!rx_nss) rx_nss = 1;
        if (!n) { a->ht_count = 8; for (unsigned i = 0; i < 8; i++) a->ht[i] = (uint8_t)i; }
        else { a->ht_count = (uint8_t)n; a->peer_nss = rx_nss < max_nss ? rx_nss : max_nss; }
        unsigned smps = (cap >> 2) & 3U;                             /* h_smps */
        if (smps == 0) a->static_mimops_flag = 1;
        else if (smps == 1) a->dynamic_mimops_flag = 1;
        else if (smps == 3) a->spatial_mux_flag = 1;
    }
    /* h_qos: sta->wme when the response carries a WMM parameter element we asked for */
    if (s->wmm && resp.ie[QCC2072_ASSOC_IE_WMM_PARAM]) { a->is_wme_set = 1; a->qos_flag = 1; }
    /* h_phymode at 20 MHz */
    if (!band) a->peer_phymode = a->ht_flag ? QCC2072_ASSOC_MODE_11NG_HT20 :
                                 (rates >> 4) ? QCC2072_ASSOC_MODE_11G : QCC2072_ASSOC_MODE_11B;
    else a->peer_phymode = a->ht_flag ? QCC2072_ASSOC_MODE_11NA_HT20 : QCC2072_ASSOC_MODE_11A;
    a->is_assoc = 1;
    /* mac80211 ieee80211_handle_bss_capability(assoc_capability, the BSS's (beacon) ERP) */
    const uint8_t *erp = bcn.ie[QCC2072_ASSOC_IE_ERP];
    unsigned erp_valid = erp && bcn.len[QCC2072_ASSOC_IE_ERP] >= 1;
    s->cts_prot = erp_valid && (erp[0] & 0x02U);
    s->short_preamble = erp_valid ? !(erp[0] & 0x04U) : !!(s->assoc_capability & 0x0020U);
    s->short_slot = band == 1 || (s->assoc_capability & 0x0400U);
}

static void plan_connect(struct qcc2072_assoc *s)
{
    const struct qcc2072_assoc_connect_args *c = &s->link;
    struct qcc2072_assoc_ies bcn;
    unsigned band = band_of(s);
    program(s, PROG_CONNECT);
    if ((c->flags & QCC2072_ASSOC_F_RADIO_PARAMS) && !s->radio_done) { /* ath12k_mac_start */
        add(s, OP_PDEV, W_NONE, QCC2072_ASSOC_PDEV_PARAM_PMF_QOS, 1);
        add(s, OP_PDEV, W_NONE, QCC2072_ASSOC_PDEV_PARAM_DYNAMIC_BW, 1);
        add(s, OP_PDEV, W_NONE, QCC2072_ASSOC_PDEV_PARAM_ARP_AC_OVERRIDE, 0);
        add(s, OP_PDEV, W_NONE, QCC2072_ASSOC_PDEV_PARAM_MESH_MCAST_ENABLE, 1);
        if (c->flags & QCC2072_ASSOC_F_IDLE_PS) add(s, OP_PDEV, W_NONE, QCC2072_ASSOC_PDEV_PARAM_IDLE_PS_CONFIG, 1);
        add(s, OP_MARK, W_NONE, MARK_RADIO, 0);
    }
    if (!s->vdev_created) add(s, OP_VDEV_CREATE, W_NONE, 0, 0);
    if (!s->vdev_configured) { /* ath12k_mac_vdev_create + update_vif_offload, STA branch */
        uint32_t nss = popcount(s->caps.tx_chainmask);
        add(s, OP_VDEV_PARAM, W_NONE, QCC2072_ASSOC_VDEV_PARAM_TX_ENCAP_TYPE, s->tx_encap);
        add(s, OP_VDEV_PARAM, W_NONE, QCC2072_ASSOC_VDEV_PARAM_RX_DECAP_TYPE, s->rx_decap);
        add(s, OP_VDEV_PARAM, W_NONE, QCC2072_ASSOC_VDEV_PARAM_NSS, nss ? nss : 1U);
        add(s, OP_STA_PS, W_NONE, QCC2072_ASSOC_STA_PS_PARAM_RX_WAKE_POLICY, 0 /* WAKE */);
        add(s, OP_STA_PS, W_NONE, QCC2072_ASSOC_STA_PS_PARAM_TX_WAKE_THRESHOLD, 1 /* ALWAYS */);
        add(s, OP_STA_PS, W_NONE, QCC2072_ASSOC_STA_PS_PARAM_PSPOLL_COUNT, 0 /* NO_MAX */);
        add(s, OP_PS_MODE, W_NONE, 0, 0);
        add(s, OP_VDEV_PARAM, W_NONE, QCC2072_ASSOC_VDEV_PARAM_RTS_THRESHOLD, 0xffffffffU);
        add(s, OP_MARK, W_NONE, MARK_VDEV_CONFIG, 0);
    }
    /* BSS_CHANGED_TXPOWER on channel assignment: ath12k_mac_txpower_recalc, 2 units/dBm */
    int32_t tp = c->max_power_dbm;
    if (tp < (int32_t)s->caps.hw_min_tx_power) tp = (int32_t)s->caps.hw_min_tx_power;
    if (s->caps.hw_max_tx_power && tp > (int32_t)s->caps.hw_max_tx_power) tp = (int32_t)s->caps.hw_max_tx_power;
    if (tp > 0) {
        uint32_t units = (uint32_t)tp * 2U;
        if ((s->caps.supported_bands & 1U) && s->txpower_2g != units) {
            add(s, OP_PDEV, W_NONE, QCC2072_ASSOC_PDEV_PARAM_TXPOWER_LIMIT2G, units);
            add(s, OP_MARK, W_NONE, MARK_TXPOWER_2G, units);
        }
        if ((s->caps.supported_bands & 2U) && s->txpower_5g != units) {
            add(s, OP_PDEV, W_NONE, QCC2072_ASSOC_PDEV_PARAM_TXPOWER_LIMIT5G, units);
            add(s, OP_MARK, W_NONE, MARK_TXPOWER_5G, units);
        }
    }
    /* mac80211 prep_connection: BSSID | BASIC_RATES | BEACON_INT (from the scanned BSS) */
    uint32_t basic = 0;
    (void)qcc2072_assoc_parse_ies(c->ies, c->ie_length, &bcn);
    (void)rate_bits(band, &bcn, &basic);
    s->basic_rate = (uint8_t)lowest(basic);
    add(s, OP_VDEV_PARAM, W_NONE, QCC2072_ASSOC_VDEV_PARAM_BEACON_INTERVAL, c->beacon_interval_tu);
    add(s, OP_VDEV_PARAM, W_NONE, QCC2072_ASSOC_VDEV_PARAM_MGMT_RATE, hw_rate_code(band, s->basic_rate));
    add(s, OP_VDEV_PARAM, W_NONE, QCC2072_ASSOC_VDEV_PARAM_BEACON_RATE, hw_rate_code(band, s->basic_rate));
    /* ath12k_mac_station_add with vdev_start_delay: peer, dp peer setup, then vdev start */
    add(s, OP_PEER_CREATE, W_PEER_MAP, 0, 0);
    add(s, OP_PEER_PARAM, W_NONE, QCC2072_ASSOC_PEER_PARAM_SET_DEFAULT_ROUTING, 1U | (1U << 1));
    if (s->hooks.reo_queue && !(c->flags & QCC2072_ASSOC_F_ASSOC_ONLY))
        for (unsigned tid = 0; tid < QCC2072_ASSOC_REO_TIDS; tid++) add(s, OP_REO, W_NONE, tid, 0);
    add(s, OP_VDEV_START, W_START, band, 0);
    add(s, OP_AUTH, W_MGMT, 0, 0);
    add(s, OP_ASSOC, W_MGMT, 0, 0);
}

static void plan_associate(struct qcc2072_assoc *s)
{
    struct qcc2072_assoc_ies bcn;
    uint8_t prep_basic = s->basic_rate;
    derive_peer(s);
    (void)qcc2072_assoc_parse_ies(s->link.ies, s->link.ie_length, &bcn);
    const uint8_t *tim = bcn.ie[QCC2072_ASSOC_IE_TIM];
    s->dtim_period = tim && bcn.len[QCC2072_ASSOC_IE_TIM] >= 2 && tim[1] ? tim[1] : 1;
    program(s, PROG_ASSOCIATE);
    /* link changes (ath12k_mac_bss_info_changed handler order), then vif ASSOC */
    add(s, OP_VDEV_PARAM, W_NONE, QCC2072_ASSOC_VDEV_PARAM_DTIM_PERIOD, s->dtim_period);
    if (s->cts_prot) add(s, OP_VDEV_PARAM, W_NONE, QCC2072_ASSOC_VDEV_PARAM_PROTECTION_MODE, 1);
    if (s->short_slot) add(s, OP_VDEV_PARAM, W_NONE, QCC2072_ASSOC_VDEV_PARAM_SLOT_TIME, 2 /* SHORT */);
    if (s->short_preamble) add(s, OP_VDEV_PARAM, W_NONE, QCC2072_ASSOC_VDEV_PARAM_PREAMBLE, 2 /* SHORT */);
    if (s->basic_rate != prep_basic) {
        add(s, OP_VDEV_PARAM, W_NONE, QCC2072_ASSOC_VDEV_PARAM_MGMT_RATE, hw_rate_code(band_of(s), s->basic_rate));
        add(s, OP_VDEV_PARAM, W_NONE, QCC2072_ASSOC_VDEV_PARAM_BEACON_RATE, hw_rate_code(band_of(s), s->basic_rate));
    }
    /* ath12k_bss_assoc */
    add(s, OP_VDEV_PARAM, W_NONE, QCC2072_ASSOC_VDEV_PARAM_SET_HEMU_MODE, 0 /* no HE */);
    add(s, OP_PEER_ASSOC, W_ASSOC_CONF, 0, 0);
    /* ath12k_setup_peer_smps: HT SM PS field, else the (zero) 6 GHz capability = static */
    static const uint8_t smps_map[4] = {1 /* STATIC */, 2 /* DYNAMIC */, 0, 0 /* PS_NONE */};
    unsigned smps = s->peer.ht_flag ? (s->peer.peer_ht_caps >> 2) & 3U : 0U;
    add(s, OP_PEER_PARAM, W_NONE, QCC2072_ASSOC_PEER_PARAM_MIMO_PS_STATE, smps_map[smps]);
    add(s, OP_VDEV_UP, W_NONE, 0, 0);
    if (!s->secure) add(s, OP_AUTHORIZE, W_NONE, 0, 0); /* open: AUTHORIZED precedes set_associated */
    add(s, OP_OBSS, W_NONE, 0, 0);
    add(s, OP_VDEV_PARAM, W_NONE, QCC2072_ASSOC_VDEV_PARAM_DTIM_POLICY, 3 /* STICK: supports_sta_ps */);
}

static int slot_take(struct qcc2072_assoc *s, uint32_t desc, unsigned *slot)
{
    for (unsigned i = 0; i < QCC2072_ASSOC_MGMT_SLOTS; i++)
        if (!(s->slot_busy & (1U << i))) { s->slot_busy |= (uint8_t)(1U << i); s->slot_desc[i] = desc; *slot = i; return 0; }
    return QCC2072_RUNTIME_FULL;
}

/* The 802.11 frame goes into a DMA slot; MGMT_TX_SEND inlines its first 64 bytes. */
static int build_mgmt(struct qcc2072_assoc *s, unsigned op)
{
    uint8_t frame[QCC2072_ASSOC_MGMT_SLOT_BYTES];
    size_t n;
    if (op == OP_AUTH) n = qcc2072_assoc_auth_frame(frame, sizeof(frame), s->link.bssid, s->link.own_mac, s->seq);
    else if (op == OP_DEAUTH)
        n = qcc2072_assoc_deauth_frame(frame, sizeof(frame), s->link.bssid, s->link.own_mac, s->seq, s->disconnect_reason);
    else {
        struct qcc2072_assoc_ht sband, req;
        static const uint8_t ext_capa[8] = {0x04, 0, 0, 0, 0, 0, 0, 0x40}; /* mac80211: ECSA, opmode notif */
        struct qcc2072_assoc_req_args r;
        zero(&r, sizeof(r));
        r.bssid = s->link.bssid; r.sa = s->link.own_mac; r.ssid = s->link.ssid; r.ssid_length = s->link.ssid_length;
        r.rsn = s->link.rsn_length ? s->link.rsn : 0; r.rsn_length = s->link.rsn_length;
        r.ap_ies = s->link.ies; r.ap_ie_length = s->link.ie_length; r.ap_capability = s->link.capability;
        r.seq_ctrl = s->seq; r.listen_interval = LISTEN_INTERVAL; r.freq_mhz = s->link.freq_mhz;
        r.max_power_dbm = s->link.max_power_dbm; r.wmm = s->wmm; r.ext_capa = ext_capa; r.ext_capa_length = 8;
        if (s->ht && !qcc2072_assoc_own_ht(&s->caps, band_of(s), &sband, &req)) r.ht = &req;
        n = qcc2072_assoc_request_frame(frame, sizeof(frame), &r);
    }
    if (!n) return QCC2072_OUTPUT_TOO_SMALL;
    unsigned slot;
    uint32_t desc = s->next_desc % 512U; /* ath12k idr range ATH12K_TX_MGMT_NUM_PENDING_MAX */
    if (slot_take(s, desc, &slot)) return QCC2072_RUNTIME_FULL;
    size_t off = (size_t)slot * QCC2072_ASSOC_MGMT_SLOT_BYTES;
    copy(s->hooks.mgmt.cpu + off, frame, n);
    s->cmd_length = s->hooks.sync(s->hooks.context, &s->hooks.mgmt, off, n, QCC2072_SYNC_DEVICE) ? 0 :
        qcc2072_assoc_mgmt_send(s->cmd, sizeof(s->cmd), s->link.vdev_id, desc, 0, s->hooks.mgmt.iova + off, frame, n);
    if (!s->cmd_length) { s->slot_busy &= (uint8_t)~(1U << slot); return QCC2072_DMA_INVALID; }
    s->next_desc++; s->seq = (uint16_t)(s->seq + 0x10U); s->wait_desc = desc; /* mac80211 sequence */
    return 0;
}

/* Builds step pc into s->cmd. 0: built (cmd_length > 0) or a bookkeeping step consumed
 * (cmd_length 0, pc advanced); RUNTIME_FULL: no management slot yet; else an error. */
static int build(struct qcc2072_assoc *s)
{
    struct qcc2072_assoc_step *t = &s->prog[s->pc];
    const struct qcc2072_assoc_connect_args *c = &s->link;
    uint8_t *o = s->cmd;
    size_t cap = sizeof(s->cmd);
    uint32_t v = c->vdev_id;
    s->cmd_length = 0; s->response = 0; s->acked = 0;
    switch (t->op) {
    case OP_MARK:
        if (t->a == MARK_RADIO) s->radio_done = 1;
        else if (t->a == MARK_VDEV_CONFIG) s->vdev_configured = 1;
        else if (t->a == MARK_TXPOWER_2G) s->txpower_2g = t->b;
        else s->txpower_5g = t->b;
        s->pc++;
        return 0;
    case OP_REO_RELEASE:
        if (s->hooks.reo_release) (void)s->hooks.reo_release(s->hooks.context, c->bssid, s->peer_id);
        s->pc++;
        return 0;
    case OP_PDEV: s->cmd_length = qcc2072_assoc_pdev_set_param(o, cap, c->pdev_id, t->a, t->b); break;
    case OP_VDEV_PARAM: s->cmd_length = qcc2072_assoc_vdev_set_param(o, cap, v, t->a, t->b); break;
    case OP_STA_PS: s->cmd_length = qcc2072_assoc_sta_ps_param(o, cap, v, t->a, t->b); break;
    case OP_PS_MODE: s->cmd_length = qcc2072_assoc_sta_ps_mode(o, cap, v, 0); break;
    case OP_VDEV_CREATE:
        s->cmd_length = qcc2072_scan_vdev_create(o, cap, v, c->pdev_id, c->own_mac, s->caps.num_rf_chains);
        break;
    case OP_PEER_CREATE:
        s->peer_mapped = 0; s->peer_unmapped = 0;
        s->cmd_length = qcc2072_assoc_peer_create(o, cap, v, c->bssid);
        break;
    case OP_PEER_PARAM: s->cmd_length = qcc2072_assoc_peer_set_param(o, cap, v, c->bssid, t->a, t->b); break;
    case OP_AUTHORIZE:
        s->cmd_length = qcc2072_assoc_peer_set_param(o, cap, v, c->bssid, QCC2072_ASSOC_PEER_PARAM_AUTHORIZE, 1);
        break;
    case OP_REO: {
        uint64_t q = 0;
        if (!s->hooks.reo_queue || s->hooks.reo_queue(s->hooks.context, c->bssid, s->peer_id, t->a, &q) || !q)
            return QCC2072_DMA_INVALID;
        s->cmd_length = qcc2072_assoc_reorder_queue_setup(o, cap, v, c->bssid, t->a, q, 1, 1);
        break;
    }
    case OP_VDEV_START: {
        struct qcc2072_assoc_vdev_start_args a;
        unsigned eht = (c->flags & QCC2072_ASSOC_F_EHT) != 0;
        zero(&a, sizeof(a));
        a.vdev_id = v; a.freq_mhz = c->freq_mhz; a.center_freq1 = c->freq_mhz;
        /* ath12k_phymodes[band][20 MHz], downgraded to HE without an EHT capability */
        a.mode = t->a == 0 ? (eht ? QCC2072_ASSOC_MODE_11BE_EHT20_2G : QCC2072_ASSOC_MODE_11AX_HE20_2G)
                           : (eht ? QCC2072_ASSOC_MODE_11BE_EHT20 : QCC2072_ASSOC_MODE_11AX_HE20);
        a.beacon_interval = c->beacon_interval_tu; /* dtim_period 0 until BEACON_INFO */
        a.max_power = (uint32_t)(int32_t)c->max_power_dbm; a.max_reg_power = (uint32_t)(int32_t)c->max_reg_power_dbm;
        a.pref_tx_streams = popcount(s->caps.tx_chainmask); a.pref_rx_streams = popcount(s->caps.rx_chainmask);
        a.mbssid_flags = 1;              /* WMI_VDEV_MBSSID_FLAGS_NON_MBSSID_AP */
        a.punct_bitmap = 0xffffffffU;    /* ~arvif->punct_bitmap, nothing punctured */
        a.passive = c->passive;          /* chandef->chan->flags & IEEE80211_CHAN_NO_IR */
        s->cmd_length = qcc2072_assoc_vdev_start(o, cap, &a);
        break;
    }
    case OP_AUTH: case OP_ASSOC: case OP_DEAUTH: {
        int rc = build_mgmt(s, t->op);
        if (rc) return rc;
        break;
    }
    case OP_PEER_ASSOC: s->cmd_length = qcc2072_assoc_peer_assoc(o, cap, &s->peer); break;
    case OP_VDEV_UP: s->cmd_length = qcc2072_assoc_vdev_up(o, cap, v, s->aid, c->bssid); break;
    case OP_OBSS: s->cmd_length = qcc2072_assoc_obss_spr(o, cap, v, 0, 0, 0); break;
    case OP_KEY:
        s->cmd_length = qcc2072_assoc_install_key(o, cap, v, c->bssid, t->a, t->b, QCC2072_ASSOC_CIPHER_AES_CCM, s->key, 16);
        s->cmd_has_key = 1; zero(s->key, sizeof(s->key));
        break;
    case OP_KEY_DELETE: /* ath12k DISABLE_KEY: cipher left 0, empty key */
        s->cmd_length = qcc2072_assoc_install_key(o, cap, v, c->bssid, t->a, t->b, QCC2072_ASSOC_CIPHER_NONE, 0, 0);
        break;
    case OP_VDEV_DOWN: s->cmd_length = qcc2072_assoc_vdev_down(o, cap, v); break;
    case OP_VDEV_STOP: s->cmd_length = qcc2072_assoc_vdev_stop(o, cap, v); break;
    case OP_PEER_DELETE:
        s->peer_unmapped = 0;
        s->cmd_length = qcc2072_assoc_peer_delete(o, cap, v, c->bssid);
        break;
    default:
        return QCC2072_BAD_STATE;
    }
    return s->cmd_length ? 0 : QCC2072_OUTPUT_TOO_SMALL;
}

static uint32_t wait_timeout(unsigned w)
{
    switch (w) {
    case W_PEER_MAP: return T_PEER_MAP;
    case W_START: case W_STOPPED: return T_VDEV;
    case W_ASSOC_CONF: return T_ASSOC_CONF;
    case W_KEY: return T_KEY;
    case W_DELETED: return T_PEER_DELETE;
    case W_MGMT: return T_MGMT;
    case W_MGMT_DONE: return T_DEAUTH;
    default: return 0;
    }
}

static void finish_control(struct qcc2072_assoc *s, int32_t status)
{
    if (!s->control_pending) return;
    notify(s, QCC2072_ASSOC_N_CONTROL_DONE, status, s->control.transaction, s->control.link_transaction, 0, 0);
    s->control_pending = 0;
    zero(&s->control, sizeof(s->control));
}

static void start_connect(struct qcc2072_assoc *s);

static void reset_link(struct qcc2072_assoc *s)
{
    s->peer_exists = 0; s->vdev_started = 0; s->vdev_up = 0; s->authorized = 0; s->ptk = 0; s->gtk_mask = 0;
    s->peer_mapped = 0; s->assoc_ok = 0; s->authorize_deadline = 0; s->tries = 0;
    zero(&s->peer, sizeof(s->peer)); zero(s->resp_ies, sizeof(s->resp_ies)); s->resp_ie_length = 0;
}

/* The current program ran to its end. */
static void complete(struct qcc2072_assoc *s, uint64_t now)
{
    switch (s->prog_kind) {
    case PROG_CONNECT:      /* the association response was accepted */
        plan_associate(s);
        break;
    case PROG_ASSOCIATE:
        program(s, PROG_NONE);
        s->state = QCC2072_ASSOC_ASSOCIATED;
        notify(s, QCC2072_ASSOC_N_ASSOCIATED, 0, s->link.transaction, s->link.transaction, 0, 0);
        if (!s->secure) {
            s->state = QCC2072_ASSOC_AUTHORIZED;
            notify(s, QCC2072_ASSOC_N_CONNECTED, 0, s->link.transaction, s->link.transaction, 0, 0);
        } else {
            s->authorize_deadline = now + T_AUTHORIZE; /* also ends an association-only test */
        }
        break;
    case PROG_CONTROL:
        program(s, PROG_NONE);
        if (s->control.type == SNAP_STATION_PORT_AUTHORIZE) {
            s->authorized = 1; s->state = QCC2072_ASSOC_AUTHORIZED; s->authorize_deadline = 0;
        }
        finish_control(s, 0);
        break;
    case PROG_TEARDOWN:
        program(s, PROG_NONE);
        finish_control(s, s->control.type == SNAP_STATION_LINK_DISCONNECT ? 0 : SNAP_STATION_CANCELLED);
        if (s->teardown_notice == QCC2072_ASSOC_N_DISCONNECTED)
            notify(s, QCC2072_ASSOC_N_DISCONNECTED, 0, s->link.transaction, s->link.transaction,
                   s->disconnect_reason, s->last_detail);
        else if (s->teardown_notice && s->cancel)
            notify(s, QCC2072_ASSOC_N_CANCELLED, 0, s->link.transaction, 0, 0, s->last_detail);
        else if (s->teardown_notice)
            notify(s, QCC2072_ASSOC_N_FAILED, SNAP_STATION_NOT_READY, s->link.transaction, 0,
                   s->disconnect_reason, s->last_detail);
        s->teardown_notice = 0; s->cancel = 0;
        reset_link(s);
        s->state = QCC2072_ASSOC_IDLE;
        if (s->has_next) { s->has_next = 0; s->link = s->next; zero(&s->next, sizeof(s->next)); start_connect(s); }
        break;
    default:
        program(s, PROG_NONE);
        break;
    }
}

static void advance(struct qcc2072_assoc *s, uint64_t now)
{
    s->wait = W_NONE; s->deadline = 0; s->pc++;
    if (s->pc >= s->prog_len) complete(s, now);
}

static void wedge(struct qcc2072_assoc *s, uint32_t detail)
{
    s->last_detail = detail;
    finish_control(s, SNAP_STATION_CANCELLED);
    if (s->teardown_notice == QCC2072_ASSOC_N_DISCONNECTED)
        notify(s, QCC2072_ASSOC_N_DISCONNECTED, 0, s->link.transaction, s->link.transaction, s->disconnect_reason, detail);
    else if (s->teardown_notice)
        notify(s, QCC2072_ASSOC_N_FAILED, SNAP_STATION_NOT_READY, s->link.transaction, 0, s->disconnect_reason, detail);
    if (s->has_next) notify(s, QCC2072_ASSOC_N_FAILED, SNAP_STATION_NOT_READY, s->next.transaction, 0, 0, detail);
    s->teardown_notice = 0; s->has_next = 0;
    wipe_cmd(s); zero(s->key, sizeof(s->key));
    program(s, PROG_NONE);
    s->state = QCC2072_ASSOC_WEDGED;
}

/* mac80211 disconnect + ath12k station removal for a STA vdev. */
static void teardown(struct qcc2072_assoc *s, uint32_t detail, uint16_t reason, int send_deauth)
{
    if (s->state == QCC2072_ASSOC_TEARDOWN || s->state == QCC2072_ASSOC_WEDGED || s->state == QCC2072_ASSOC_IDLE) return;
    s->teardown_notice = s->state == QCC2072_ASSOC_ASSOCIATED || s->state == QCC2072_ASSOC_AUTHORIZED
                         ? QCC2072_ASSOC_N_DISCONNECTED : QCC2072_ASSOC_N_FAILED;
    s->last_detail = detail; s->disconnect_reason = reason;
    wipe_cmd(s); zero(s->key, sizeof(s->key));
    if (s->control_pending && s->control.type != SNAP_STATION_LINK_DISCONNECT) finish_control(s, SNAP_STATION_CANCELLED);
    s->state = QCC2072_ASSOC_TEARDOWN;
    program(s, PROG_TEARDOWN);
    if (send_deauth && s->assoc_ok) add(s, OP_DEAUTH, W_MGMT_DONE, 0, 0);
    if (s->ptk) add(s, OP_KEY_DELETE, W_KEY, 0, QCC2072_ASSOC_KEY_PAIRWISE);      /* ath12k_clear_peer_keys */
    for (unsigned i = 1; i < 4; i++) if (s->gtk_mask & (1U << i)) add(s, OP_KEY_DELETE, W_KEY, i, QCC2072_ASSOC_KEY_GROUP);
    if (s->vdev_started) {           /* ath12k_mac_station_remove: bss_disassoc + vdev_stop */
        add(s, OP_VDEV_DOWN, W_NONE, 0, 0);
        add(s, OP_VDEV_STOP, W_STOPPED, 0, 0);
    }
    if (s->peer_exists) {            /* ath12k_dp_peer_cleanup + ath12k_peer_delete */
        add(s, OP_REO_RELEASE, W_NONE, 0, 0);
        add(s, OP_PEER_DELETE, W_DELETED, 0, 0);
    }
    s->ptk = 0; s->gtk_mask = 0; s->authorized = 0; s->authorize_deadline = 0;
}

static void fail_step(struct qcc2072_assoc *s, uint64_t now, uint32_t kind, uint16_t reason)
{
    uint32_t detail = kind | (s->pc < s->prog_len ? s->prog[s->pc].op : 0U);
    if (s->prog_kind == PROG_TEARDOWN) {
        /* Teardown continues past a lost deauth or key delete; silence on VDEV_STOP or
         * PEER_DELETE leaves firmware state unknown: wedge, never reuse the vdev/peer. */
        if (s->wait == W_STOPPED || (s->wait == W_DELETED && s->response != 1)) { wedge(s, detail); return; }
        if (!s->last_detail) s->last_detail = detail;
        advance(s, now);
        return;
    }
    if (s->prog_kind == PROG_CONTROL) {
        finish_control(s, SNAP_STATION_NOT_READY);
        program(s, PROG_NONE);
        return;
    }
    teardown(s, detail, reason, 1);
}

static int current_is(const struct qcc2072_assoc *s, unsigned op)
{
    return s->pc < s->prog_len && s->prog[s->pc].op == op;
}

static void mgmt_try_again(struct qcc2072_assoc *s, uint64_t now, uint32_t kind, uint64_t when)
{
    if (++s->tries >= MGMT_TRIES) { s->tries = 0; fail_step(s, now, kind, 0); return; }
    s->wait = W_NONE; s->deadline = 0; s->mgmt_retry_at = when ? when : 1; /* the step builds a fresh frame */
}

static void check_wait(struct qcc2072_assoc *s, uint64_t now)
{
    unsigned w = s->wait;
    if (w == W_NONE) return;
    if (w == W_PEER_MAP && s->peer_mapped) { advance(s, now); return; }
    if (w == W_START && s->response == 1) { s->vdev_started = 1; advance(s, now); return; }
    if (w == W_START && s->response == 2) { fail_step(s, now, QCC2072_ASSOC_E_FIRMWARE, 0); return; }
    if (w == W_ASSOC_CONF && s->response == 1) { advance(s, now); return; }
    if (w == W_STOPPED && s->response == 1) { s->vdev_started = 0; s->vdev_up = 0; advance(s, now); return; }
    if (w == W_KEY && s->response == 1) {
        const struct qcc2072_assoc_step *t = &s->prog[s->pc];
        if (s->prog_kind == PROG_CONTROL) {
            uint8_t bit = (uint8_t)(1U << t->a);
            if (t->op == OP_KEY) { if (t->b == QCC2072_ASSOC_KEY_PAIRWISE) s->ptk = 1; else s->gtk_mask |= bit; }
            else { if (t->b == QCC2072_ASSOC_KEY_PAIRWISE) s->ptk = 0; else s->gtk_mask &= (uint8_t)~bit; }
        }
        advance(s, now);
        return;
    }
    if (w == W_KEY && s->response == 2) { fail_step(s, now, QCC2072_ASSOC_E_FIRMWARE, 0); return; }
    if (w == W_DELETED && s->response == 1 && (s->peer_unmapped || now >= s->deadline)) {
        if (!s->peer_unmapped) s->last_detail = QCC2072_ASSOC_E_TIMEOUT | OP_PEER_DELETE; /* noted only */
        s->peer_exists = 0; advance(s, now);
        return;
    }
    if (w == W_MGMT_DONE && s->acked) { advance(s, now); return; }
    if (w == W_MGMT) {
        if (s->response == 1) { s->tries = 0; if (current_is(s, OP_ASSOC)) s->assoc_ok = 1; advance(s, now); return; }
        if (s->response == 2) { s->tries = 0; fail_step(s, now, QCC2072_ASSOC_E_AP, s->status_code); return; }
        if (s->response == 3) {
            uint32_t ms = s->comeback_ms > T_COMEBACK_MAX ? T_COMEBACK_MAX : s->comeback_ms;
            mgmt_try_again(s, now, QCC2072_ASSOC_E_AP, now + ms);
            return;
        }
        if (s->acked == 2) { mgmt_try_again(s, now, QCC2072_ASSOC_E_NO_ACK, now); return; }
    }
    if (now < s->deadline) return;
    if (w == W_MGMT) mgmt_try_again(s, now, s->acked ? QCC2072_ASSOC_E_TIMEOUT : QCC2072_ASSOC_E_NO_ACK, now);
    else if (w == W_MGMT_DONE) advance(s, now);
    else fail_step(s, now, QCC2072_ASSOC_E_TIMEOUT, 0);
}

static int validate_connect(const struct qcc2072_assoc *s, const struct qcc2072_assoc_connect_args *c)
{
    struct qcc2072_assoc_ies e;
    if (!c->transaction || c->vdev_id > 15 || !unicast(c->own_mac) || !unicast(c->bssid) ||
        !c->ssid_length || c->ssid_length > 32 || c->ie_length > QCC2072_ASSOC_MAX_AP_IES ||
        c->rsn_length > sizeof(c->rsn) || !c->beacon_interval_tu || !channel_ok(c->freq_mhz) || c->passive > 1)
        return SNAP_STATION_INVALID;
    if (!(c->capability & 0x0001U)) return SNAP_STATION_UNSUPPORTED;            /* not an ESS */
    if (!s->caps.ext_ready || !s->caps.service_ready) return SNAP_STATION_NOT_READY;
    if (!s->hooks.reo_queue && !(c->flags & QCC2072_ASSOC_F_ASSOC_ONLY)) return SNAP_STATION_NOT_READY;
    if (qcc2072_assoc_parse_ies(c->ies, c->ie_length, &e) || !e.ie[QCC2072_ASSOC_IE_SSID] ||
        e.len[QCC2072_ASSOC_IE_SSID] != c->ssid_length || !same(e.ie[QCC2072_ASSOC_IE_SSID], c->ssid, c->ssid_length))
        return SNAP_STATION_INVALID;                                             /* not this BSS's scan data */
    if (e.ie[QCC2072_ASSOC_IE_WPA]) return SNAP_STATION_UNSUPPORTED;
    if (!c->rsn_length) return e.rsn_count || (c->capability & 0x0010U) ? SNAP_STATION_UNSUPPORTED : SNAP_STATION_OK;
    /* Our element goes into the request and M2 (snap_rsn_own); the AP's own element, as the scan
     * cache kept it, must be one we can join without PMF. M3 is checked against the AP's. */
    if (!snap_rsn_is_own(c->rsn, c->rsn_length) || !(c->capability & 0x0010U)) return SNAP_STATION_UNSUPPORTED;
    uint8_t ap[SNAP_RSN_MAX_ELEMENT], x[SNAP_RSN_MAX_RSNXE];
    size_t xn;
    if (!qcc2072_assoc_ap_rsn(c->ies, c->ie_length, ap, x, &xn, 0)) return SNAP_STATION_UNSUPPORTED;
    return SNAP_STATION_OK;
}

static void start_connect(struct qcc2072_assoc *s)
{
    struct qcc2072_assoc_ies e;
    struct qcc2072_assoc_ht own;
    (void)qcc2072_assoc_parse_ies(s->link.ies, s->link.ie_length, &e);
    reset_link(s);
    s->secure = s->link.rsn_length != 0;
    s->wmm = e.ie[QCC2072_ASSOC_IE_WMM_PARAM] || e.ie[QCC2072_ASSOC_IE_WMM_INFO];
    /* mac80211: HT needs the AP's HT capability + operation elements and WMM */
    s->ht = s->wmm && e.ie[QCC2072_ASSOC_IE_HT_CAP] && e.len[QCC2072_ASSOC_IE_HT_CAP] >= 26 &&
            e.ie[QCC2072_ASSOC_IE_HT_OP] && e.len[QCC2072_ASSOC_IE_HT_OP] >= 22 &&
            !qcc2072_assoc_own_ht(&s->caps, band_of(s), &own, 0);
    s->tx_encap = s->rx_decap = (s->link.flags & QCC2072_ASSOC_F_ETH_OFFLOAD) ? QCC2072_ASSOC_TXRX_ETHERNET
                                                                              : QCC2072_ASSOC_TXRX_NATIVE_WIFI;
    if (s->link.flags & QCC2072_ASSOC_F_VDEV_CREATED) s->vdev_created = 1;
    s->aid = 0; s->assoc_capability = 0; s->disconnect_reason = 0; s->status_code = 0;
    s->peer_id = s->ast_hash = s->hw_peer_id = 0; s->last_detail = 0; s->cancel = 0;
    s->state = QCC2072_ASSOC_CONNECTING;
    plan_connect(s);
}

int qcc2072_assoc_init(struct qcc2072_assoc *s, const struct qcc2072_assoc_hooks *h)
{
    if (!s || !h || !h->sync || !h->mgmt.cpu || h->mgmt.capacity < QCC2072_ASSOC_MGMT_DMA_BYTES || (h->mgmt.iova & 3U))
        return QCC2072_INVALID_ARGUMENT;
    zero(s, sizeof(*s));
    s->hooks = *h; s->initialized = 1;
    return 0;
}

int qcc2072_assoc_connect(struct qcc2072_assoc *s, uint64_t now, const struct qcc2072_assoc_connect_args *c)
{
    (void)now;
    if (!s || !c || !s->initialized) return SNAP_STATION_INVALID;
    if (s->in_call) return SNAP_STATION_BUSY;
    int rc = validate_connect(s, c);
    if (rc) return rc;
    switch (s->state) {
    case QCC2072_ASSOC_IDLE:
        s->link = *c; start_connect(s);
        return SNAP_STATION_OK;
    case QCC2072_ASSOC_ASSOCIATED: case QCC2072_ASSOC_AUTHORIZED:
        if (s->control_pending || s->prog_kind != PROG_NONE) return SNAP_STATION_BUSY;
        s->next = *c; s->has_next = 1;
        teardown(s, QCC2072_ASSOC_E_LOCAL, 3 /* deauth leaving */, 1);
        return SNAP_STATION_OK;
    case QCC2072_ASSOC_TEARDOWN:
        if (s->has_next) return SNAP_STATION_BUSY;
        s->next = *c; s->has_next = 1;
        return SNAP_STATION_OK;
    default:
        return s->state == QCC2072_ASSOC_WEDGED ? SNAP_STATION_NOT_READY : SNAP_STATION_BUSY;
    }
}

int qcc2072_assoc_control(struct qcc2072_assoc *s, uint64_t now, const struct snap_station_control *c)
{
    static const uint8_t group[6] = {255, 255, 255, 255, 255, 255};
    (void)now;
    if (!s || !c || !s->initialized) return SNAP_STATION_INVALID;
    if (s->in_call) return SNAP_STATION_BUSY;
    if (s->state != QCC2072_ASSOC_ASSOCIATED && s->state != QCC2072_ASSOC_AUTHORIZED) return SNAP_STATION_NOT_READY;
    if (s->control_pending || s->prog_kind != PROG_NONE) return SNAP_STATION_BUSY;
    if (!c->transaction || c->link_transaction != s->link.transaction) return SNAP_STATION_STALE;
    if (c->type == SNAP_STATION_LINK_DISCONNECT) {
        s->control = *c; s->control_pending = 1;
        teardown(s, QCC2072_ASSOC_E_LOCAL, c->reason ? c->reason : 3, 1);
        return SNAP_STATION_OK;
    }
    if (c->type == SNAP_STATION_PORT_AUTHORIZE) {
        if (s->authorized) return SNAP_STATION_STALE;
        if (s->secure && (!s->ptk || !s->gtk_mask)) return SNAP_STATION_NOT_READY;
        s->control = *c; s->control_pending = 1;
        program(s, PROG_CONTROL); add(s, OP_AUTHORIZE, W_NONE, 0, 0);
        return SNAP_STATION_OK;
    }
    if (c->type != SNAP_STATION_KEY_INSTALL && c->type != SNAP_STATION_KEY_REMOVE) return SNAP_STATION_UNSUPPORTED;
    if (!s->secure || c->cipher != SNAP_STATION_CIPHER_CCMP128) return SNAP_STATION_UNSUPPORTED;
    if (c->pairwise > 1 || c->index > 3 || (c->pairwise && c->index) || (!c->pairwise && !c->index) ||
        !same(c->peer, c->pairwise ? s->link.bssid : group, 6) ||
        c->key_length != (c->type == SNAP_STATION_KEY_INSTALL ? 16 : 0))
        return SNAP_STATION_INVALID;
    /* WCN7850-family firmware needs the pairwise key first (ath12k caches an early GTK) */
    if (c->type == SNAP_STATION_KEY_INSTALL && !c->pairwise && !s->ptk) return SNAP_STATION_NOT_READY;
    uint32_t flags = c->pairwise ? QCC2072_ASSOC_KEY_PAIRWISE : QCC2072_ASSOC_KEY_GROUP;
    s->control = *c; s->control_pending = 1;
    zero(s->control.key, sizeof(s->control.key));
    program(s, PROG_CONTROL);
    if (c->type == SNAP_STATION_KEY_INSTALL) { copy(s->key, c->key, 16); add(s, OP_KEY, W_KEY, c->index, flags); }
    else add(s, OP_KEY_DELETE, W_KEY, c->index, flags);
    return SNAP_STATION_OK;
}

int qcc2072_assoc_cancel(struct qcc2072_assoc *s, uint64_t now, uint64_t transaction)
{
    (void)now;
    if (!s || !s->initialized) return SNAP_STATION_INVALID;
    if (s->in_call) return SNAP_STATION_BUSY;
    if (s->state != QCC2072_ASSOC_CONNECTING || transaction != s->link.transaction) return SNAP_STATION_STALE;
    teardown(s, QCC2072_ASSOC_E_LOCAL, 3, 1);
    s->cancel = 1;
    return SNAP_STATION_OK;
}

int qcc2072_assoc_poll(struct qcc2072_assoc *s, uint64_t now, const uint8_t **frame, size_t *length)
{
    if (!s || !frame || !length || !s->initialized) return QCC2072_INVALID_ARGUMENT;
    *frame = 0; *length = 0;
    if (s->in_call) return QCC2072_BAD_STATE;
    if (s->cmd_length) { *frame = s->cmd; *length = s->cmd_length; return 0; }
    if (s->authorize_deadline && now >= s->authorize_deadline && s->state == QCC2072_ASSOC_ASSOCIATED &&
        s->prog_kind == PROG_NONE)
        teardown(s, QCC2072_ASSOC_E_UNAUTHORIZED, 3, 1);
    for (unsigned guard = 0; guard < 96; guard++) {
        check_wait(s, now);
        if (s->wait != W_NONE || s->prog_kind == PROG_NONE) return 0;
        if (s->mgmt_retry_at) { if (now < s->mgmt_retry_at) return 0; s->mgmt_retry_at = 0; }
        if (s->pc >= s->prog_len) { complete(s, now); continue; }
        int rc = build(s);
        if (rc == QCC2072_RUNTIME_FULL) {      /* every management slot still owned by the firmware */
            if (!s->slot_deadline) s->slot_deadline = now + T_SLOT;
            if (now < s->slot_deadline) return 0;
            s->slot_deadline = 0;
            fail_step(s, now, QCC2072_ASSOC_E_TIMEOUT, 0);
            continue;
        }
        s->slot_deadline = 0;
        if (rc) { fail_step(s, now, QCC2072_ASSOC_E_HOOK, 0); continue; }
        if (s->cmd_length) { *frame = s->cmd; *length = s->cmd_length; return 0; }
    }
    return 0;
}

int qcc2072_assoc_sent(struct qcc2072_assoc *s, uint64_t now)
{
    if (!s || !s->initialized) return QCC2072_INVALID_ARGUMENT;
    if (!s->cmd_length || s->pc >= s->prog_len) return QCC2072_BAD_STATE;
    const struct qcc2072_assoc_step *t = &s->prog[s->pc];
    if (s->cmd_has_key) zero(s->cmd, sizeof(s->cmd));
    s->cmd_length = 0; s->cmd_has_key = 0;
    if (t->op == OP_VDEV_CREATE) s->vdev_created = 1;
    else if (t->op == OP_PEER_CREATE) s->peer_exists = 1;
    else if (t->op == OP_VDEV_UP) s->vdev_up = 1;
    else if (t->op == OP_AUTHORIZE && s->prog_kind == PROG_ASSOCIATE) s->authorized = 1;
    if (t->wait == W_NONE) { advance(s, now); return 0; }
    s->wait = t->wait; s->deadline = now + wait_timeout(t->wait);
    check_wait(s, now);
    return 0;
}

int qcc2072_assoc_take_notice(struct qcc2072_assoc *s, struct qcc2072_assoc_notice *n)
{
    if (!s || !n || !s->notice_count) return 0;
    *n = s->notices[s->notice_read & 7U];
    zero(&s->notices[s->notice_read & 7U], sizeof(*n));
    s->notice_read = (uint8_t)((s->notice_read + 1U) & 7U); s->notice_count--;
    return 1;
}

int qcc2072_assoc_abort(struct qcc2072_assoc *s)
{
    if (!s) return QCC2072_INVALID_ARGUMENT;
    wipe_cmd(s); zero(s->key, sizeof(s->key)); zero(&s->control, sizeof(s->control));
    zero(&s->next, sizeof(s->next));
    program(s, PROG_NONE);
    s->control_pending = 0; s->has_next = 0; s->notice_count = 0;
    if (s->state != QCC2072_ASSOC_IDLE) s->state = QCC2072_ASSOC_WEDGED;
    return 0;
}

/* ------------------------------------------------------------------ events */
static int link_active(const struct qcc2072_assoc *s)
{
    return s->state == QCC2072_ASSOC_CONNECTING || s->state == QCC2072_ASSOC_ASSOCIATED ||
           s->state == QCC2072_ASSOC_AUTHORIZED || s->state == QCC2072_ASSOC_TEARDOWN;
}

static void mgmt_rx(struct qcc2072_assoc *s, const struct qcc2072_assoc_mgmt_rx *m)
{
    const uint8_t *own = s->link.own_mac, *bssid = s->link.bssid;
    uint16_t reason; uint8_t disassoc;
    /* ath12k_mgmt_rx_event drops CRC, decrypt and key-cache-miss errors */
    if (m->status & (0x01U | 0x08U | 0x20U)) { s->foreign_events++; return; }
    if (!qcc2072_assoc_parse_deauth(m->frame, m->length, own, bssid, &reason, &disassoc)) {
        if (s->state != QCC2072_ASSOC_TEARDOWN) teardown(s, QCC2072_ASSOC_E_DEAUTH | disassoc, reason, 0);
        return;
    }
    if (s->wait != W_MGMT) { s->foreign_events++; return; }
    if (current_is(s, OP_AUTH)) {
        struct qcc2072_assoc_auth_resp a;
        if (qcc2072_assoc_parse_auth(m->frame, m->length, own, bssid, &a) || a.algorithm || a.transaction != 2) {
            s->foreign_events++; return;
        }
        s->status_code = a.status; s->response = a.status ? 2 : 1;
        return;
    }
    if (current_is(s, OP_ASSOC)) {
        struct qcc2072_assoc_resp r;
        if (qcc2072_assoc_parse_assoc_resp(m->frame, m->length, own, bssid, &r) || r.reassoc) { s->foreign_events++; return; }
        s->status_code = r.status;
        if (r.status == 30 && r.comeback_tu) {   /* refused temporarily: come back (mac80211) */
            s->comeback_ms = (uint32_t)(((uint64_t)r.comeback_tu * 1024U) / 1000U); s->response = 3;
            return;
        }
        if (r.status) { s->response = 2; return; }
        s->aid = r.aid; s->assoc_capability = r.capability;
        s->resp_ie_length = r.ie_length > QCC2072_ASSOC_MAX_RESP_IES ? (uint16_t)QCC2072_ASSOC_MAX_RESP_IES : r.ie_length;
        copy(s->resp_ies, r.ies, s->resp_ie_length);
        s->response = 1;
    }
}

int qcc2072_assoc_wmi_event(struct qcc2072_assoc *s, uint64_t now, const uint8_t *ev, size_t n)
{
    if (!s || !ev || !s->initialized) return QCC2072_INVALID_ARGUMENT;
    if (s->in_call) return QCC2072_BAD_STATE;
    if (n < 4) { s->bad_events++; return 0; }
    uint32_t id = get32(ev) & 0xffffffU;
    s->in_call = 1;
    switch (id) {
    case QCC2072_ASSOC_EV_SERVICE_READY: case QCC2072_ASSOC_EV_SERVICE_READY_EXT:
        if (qcc2072_assoc_parse_caps(ev, n, &s->caps)) s->bad_events++;
        break;
    case QCC2072_ASSOC_EV_MGMT_TX_COMPLETION: {
        struct qcc2072_assoc_mgmt_tx_done d;
        unsigned hit = 0;
        if (qcc2072_assoc_parse_mgmt_tx_done(ev, n, &d)) { s->bad_events++; break; }
        for (unsigned i = 0; i < QCC2072_ASSOC_MGMT_SLOTS; i++)
            if ((s->slot_busy & (1U << i)) && s->slot_desc[i] == d.desc_id) { s->slot_busy &= (uint8_t)~(1U << i); hit = 1; }
        if (!hit) { s->foreign_events++; break; }
        if ((s->wait == W_MGMT || s->wait == W_MGMT_DONE) && d.desc_id == s->wait_desc) {
            s->acked = d.status ? 2 : 1;
            if (s->wait == W_MGMT_DONE) s->acked = 1;
            else if (!d.status && s->deadline > now + T_MGMT_ACKED) s->deadline = now + T_MGMT_ACKED;
        }
        break;
    }
    case QCC2072_ASSOC_EV_MGMT_RX: {
        struct qcc2072_assoc_mgmt_rx m;
        if (qcc2072_assoc_parse_mgmt_rx(ev, n, &m)) { s->bad_events++; break; }
        if (link_active(s) && m.length >= 24) mgmt_rx(s, &m);
        break;
    }
    case QCC2072_ASSOC_EV_VDEV_START_RESP: {
        struct qcc2072_assoc_vdev_start_resp r;
        if (qcc2072_assoc_parse_vdev_start_resp(ev, n, &r)) { s->bad_events++; break; }
        if (s->wait != W_START || r.vdev_id != s->link.vdev_id || r.resp_type) { s->foreign_events++; break; }
        s->response = r.status ? 2 : 1; s->status_code = (uint16_t)r.status;
        break;
    }
    case QCC2072_ASSOC_EV_VDEV_STOPPED: {
        uint32_t v;
        if (qcc2072_assoc_parse_vdev_stopped(ev, n, &v)) { s->bad_events++; break; }
        if (v != s->link.vdev_id || !link_active(s)) { s->foreign_events++; break; }
        s->slot_busy = 0;   /* a stopped vdev holds no management frame */
        if (s->wait == W_STOPPED) s->response = 1;
        break;
    }
    case QCC2072_ASSOC_EV_INSTALL_KEY_COMPLETE: {
        struct qcc2072_assoc_key_complete k;
        if (qcc2072_assoc_parse_key_complete(ev, n, &k)) { s->bad_events++; break; }
        const struct qcc2072_assoc_step *t = s->pc < s->prog_len ? &s->prog[s->pc] : 0;
        if (s->wait != W_KEY || !t || k.vdev_id != s->link.vdev_id || !same(k.mac, s->link.bssid, 6) ||
            k.key_idx != t->a || k.key_flags != t->b) { s->foreign_events++; break; }
        s->response = (!k.status || s->prog_kind == PROG_TEARDOWN) ? 1 : 2;
        break;
    }
    case QCC2072_ASSOC_EV_PEER_ASSOC_CONF: case QCC2072_ASSOC_EV_PEER_DELETE_RESP:
    case QCC2072_ASSOC_EV_PEER_STA_KICKOUT: {
        struct qcc2072_assoc_peer_event p;
        if (qcc2072_assoc_parse_peer_event(ev, n, &p)) { s->bad_events++; break; }
        if (!link_active(s) || !same(p.mac, s->link.bssid, 6) ||
            (id != QCC2072_ASSOC_EV_PEER_STA_KICKOUT && p.vdev_id != s->link.vdev_id)) { s->foreign_events++; break; }
        if (id == QCC2072_ASSOC_EV_PEER_ASSOC_CONF && s->wait == W_ASSOC_CONF) s->response = 1;
        else if (id == QCC2072_ASSOC_EV_PEER_DELETE_RESP && s->wait == W_DELETED) {
            s->response = 1;
            if (s->deadline < now + T_PEER_DELETE) s->deadline = now + T_PEER_DELETE; /* then the unmap */
        } else if (id == QCC2072_ASSOC_EV_PEER_STA_KICKOUT && s->state != QCC2072_ASSOC_TEARDOWN)
            teardown(s, QCC2072_ASSOC_E_KICKOUT | (p.reason & 0xffU), 4 /* inactivity */, 1);
        else s->foreign_events++;
        break;
    }
    case QCC2072_ASSOC_EV_ROAM: { /* ath12k_roam_event: beacon miss -> mac80211 connection loss */
        struct qcc2072_assoc_peer_event r;
        if (qcc2072_assoc_parse_roam(ev, n, &r)) { s->bad_events++; break; }
        if (r.vdev_id != s->link.vdev_id || r.reason != QCC2072_ASSOC_ROAM_REASON_BEACON_MISS ||
            (s->state != QCC2072_ASSOC_ASSOCIATED && s->state != QCC2072_ASSOC_AUTHORIZED)) { s->foreign_events++; break; }
        teardown(s, QCC2072_ASSOC_E_KICKOUT | 0x80U, 4 /* inactivity */, 1);
        break;
    }
    default:
        s->unknown_events++;
        break;
    }
    s->in_call = 0;
    return 0;
}

int qcc2072_assoc_htt_event(struct qcc2072_assoc *s, uint64_t now, const uint8_t *m, size_t n)
{
    struct qcc2072_assoc_peer_map p;
    (void)now;
    if (!s || !m || !s->initialized) return QCC2072_INVALID_ARGUMENT;
    int rc = qcc2072_assoc_parse_htt_peer(m, n, &p);
    if (rc == QCC2072_BAD_STATE) { s->unknown_events++; return 0; }
    if (rc) { s->bad_events++; return 0; }
    if (p.unmap) {
        if (s->peer_mapped && p.peer_id == s->peer_id) { s->peer_unmapped = 1; s->peer_mapped = 0; }
        else s->foreign_events++;
        return 0;
    }
    /* ath12k_dp_link_peer_map_event for the BSS peer we created on our vdev */
    if (!link_active(s) || !s->peer_exists || s->peer_mapped || p.vdev_id != s->link.vdev_id ||
        !same(p.mac, s->link.bssid, 6)) { s->foreign_events++; return 0; }
    s->peer_id = p.peer_id; s->ast_hash = p.ast_hash; s->hw_peer_id = p.hw_peer_id; s->peer_mapped = 1;
    return 0;
}

/* ------------------------------------------------------------------ data path hook */
int qcc2072_assoc_link_info(const struct qcc2072_assoc *s, struct qcc2072_assoc_link *l)
{
    if (!s || !l) return QCC2072_INVALID_ARGUMENT;
    zero(l, sizeof(*l));
    l->state = s->state; l->vdev_id = s->link.vdev_id; l->pdev_id = s->link.pdev_id; l->freq_mhz = s->link.freq_mhz;
    l->tx_encap = s->tx_encap; l->rx_decap = s->rx_decap;
    l->peer_id = s->peer_id; l->ast_hash = s->ast_hash; l->hw_peer_id = s->hw_peer_id; l->aid = s->aid;
    copy(l->bssid, s->link.bssid, 6); copy(l->own_mac, s->link.own_mac, 6);
    l->peer_mapped = s->peer_mapped;
    l->associated = s->state == QCC2072_ASSOC_ASSOCIATED || s->state == QCC2072_ASSOC_AUTHORIZED;
    l->authorized = s->authorized && l->associated; l->ptk = s->ptk; l->gtk_mask = s->gtk_mask; l->secure = s->secure;
    l->qos = s->peer.qos_flag; l->ht = s->peer.ht_flag;
    l->link_transaction = l->associated ? s->link.transaction : 0;
    return 0;
}

int qcc2072_assoc_eapol_admit(const struct qcc2072_assoc *s, const uint8_t *eth, size_t n, int transmit)
{
    if (!s || !eth) return QCC2072_INVALID_ARGUMENT;
    if (s->state != QCC2072_ASSOC_ASSOCIATED && s->state != QCC2072_ASSOC_AUTHORIZED) return QCC2072_BAD_STATE;
    if (n < 18 || eth[12] != 0x88 || eth[13] != 0x8e) return QCC2072_BAD_WIRE;
    const uint8_t *dst = eth, *src = eth + 6;
    if (transmit) return same(dst, s->link.bssid, 6) && same(src, s->link.own_mac, 6) ? 0 : QCC2072_FOREIGN_PEER;
    return same(src, s->link.bssid, 6) && same(dst, s->link.own_mac, 6) ? 0 : QCC2072_FOREIGN_PEER;
}

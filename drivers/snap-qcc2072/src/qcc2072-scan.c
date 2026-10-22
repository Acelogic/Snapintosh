/* SPDX-License-Identifier: MIT */
/* Station-scan WMI encoders. Layouts and values follow pinned ath12k wmi.c
 * (ath12k_wmi_send_scan_chan_list_cmd, ath12k_wmi_vdev_create,
 * ath12k_wmi_send_scan_start_cmd, ath12k_wmi_start_scan_init) and reg.c
 * (ath12k_reg_update_chan_list). Failure inventory: re/scan/FAILURES.md. */
#include "qcc2072-scan.h"
#include "qcc2072-wmi.h"

#define TAG_ARRAY_UINT32 16U
#define TAG_ARRAY_BYTE 17U
#define TAG_ARRAY_STRUCT 18U
#define TAG_ARRAY_FIXED_STRUCT 19U
#define TAG_START_SCAN 77U
#define TAG_SCAN_CHAN_LIST 79U
#define TAG_CHANNEL 80U
#define TAG_VDEV_CREATE 86U
#define TAG_VDEV_TXRX_STREAMS 411U
/* ath12k wmi.h fixed structs, TLV header included. */
#define START_SCAN_BYTES 160U   /* wmi_start_scan_cmd */
#define CHAN_LIST_BYTES 16U     /* wmi_scan_chan_list_cmd */
#define CHANNEL_BYTES 28U       /* ath12k_wmi_channel_params */
#define VDEV_CREATE_BYTES 48U   /* wmi_vdev_create_cmd */
#define TXRX_STREAMS_BYTES 16U  /* ath12k_wmi_vdev_txrx_streams_params */
#define SSID_BYTES 36U          /* ath12k_wmi_ssid_params */
#define MAC_BYTES 8U            /* ath12k_wmi_mac_addr_params */
#define HTC_SEND_MAX 2040U

static void put32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8); p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24);
}
static void zero(uint8_t *p, size_t n) { while (n--) *p++ = 0; }
static uint32_t tlv(uint32_t tag, uint32_t len) { return tag << 16 | len; }
/* ath12k_wmi_tlv_cmd_hdr: the length excludes the TLV header itself. */
static uint32_t cmd_tlv(uint32_t tag, uint32_t bytes) { return tlv(tag, bytes - 4U); }

unsigned qcc2072_scan_default_channels(struct qcc2072_scan_channel *c, unsigned capacity)
{
    /* 2.4 GHz 1-11, UNII-1, UNII-2/2e (DFS: passive), UNII-3. 20 dBm, in half-dB units. */
    static const uint16_t active[] = {2412, 2417, 2422, 2427, 2432, 2437, 2442, 2447, 2452, 2457,
                                      2462, 5180, 5200, 5220, 5240, 5745, 5765, 5785, 5805, 5825};
    static const uint16_t dfs[] = {5260, 5280, 5300, 5320, 5500, 5520, 5540, 5560, 5580, 5600,
                                   5620, 5640, 5660, 5680, 5700, 5720};
    unsigned n = 0;
    for (unsigned i = 0; i < sizeof(active) / sizeof(active[0]) && n < capacity; i++)
        c[n++] = (struct qcc2072_scan_channel){active[i], 0, 0, 40};
    for (unsigned i = 0; i < sizeof(dfs) / sizeof(dfs[0]) && n < capacity; i++)
        c[n++] = (struct qcc2072_scan_channel){dfs[i], 1, 1, 40};
    return n;
}

unsigned qcc2072_scan_channels_from_rules(const struct qcc2072_wmi_reg_rule *r, unsigned rules,
                                          struct qcc2072_scan_channel *c, unsigned capacity)
{
    static const uint16_t centers[] = {
        2412, 2417, 2422, 2427, 2432, 2437, 2442, 2447, 2452, 2457, 2462, 2467, 2472,
        5180, 5200, 5220, 5240, 5260, 5280, 5300, 5320, 5500, 5520, 5540, 5560, 5580, 5600,
        5620, 5640, 5660, 5680, 5700, 5720, 5745, 5765, 5785, 5805, 5825, 5845, 5865, 5885};
    unsigned n = 0;
    if (!r || !c) return 0;
    for (unsigned i = 0; i < sizeof(centers) / sizeof(centers[0]) && n < capacity; i++) {
        unsigned f = centers[i];
        for (unsigned j = 0; j < rules; j++) {
            if (r[j].start_mhz > f - 10 || f + 10 > r[j].end_mhz) continue;
            if (r[j].flags & 1U) break; /* REGULATORY_CHAN_DISABLED */
            unsigned power = r[j].power_dbm * 2U;
            c[n++] = (struct qcc2072_scan_channel){(uint16_t)f, (uint8_t)((r[j].flags & 2U) != 0),
                                                   (uint8_t)((r[j].flags & 8U) != 0),
                                                   (uint8_t)(power > 255 ? 255 : power)};
            break;
        }
    }
    return n;
}

size_t qcc2072_scan_chan_list(uint8_t *out, size_t cap, uint32_t pdev_id,
                              const struct qcc2072_scan_channel *c, unsigned n)
{
    size_t total = 4U + CHAN_LIST_BYTES + 4U + (size_t)n * CHANNEL_BYTES;
    if (!out || !c || !n || n > QCC2072_SCAN_MAX_CHANNELS || total > cap || total > HTC_SEND_MAX)
        return 0;
    zero(out, total);
    uint8_t *p = out;
    put32(p, QCC2072_WMI_SCAN_CHAN_LIST); p += 4;
    put32(p, cmd_tlv(TAG_SCAN_CHAN_LIST, CHAN_LIST_BYTES));
    put32(p + 4, n); put32(p + 8, 0); put32(p + 12, pdev_id); p += CHAN_LIST_BYTES;
    /* ath12k builds this array header with tlv_cmd_hdr as well, so its length reads
     * n*28-4; the firmware it is proven against accepts that, so keep it. */
    put32(p, cmd_tlv(TAG_ARRAY_STRUCT, n * CHANNEL_BYTES)); p += 4;
    for (unsigned i = 0; i < n; i++, p += CHANNEL_BYTES) {
        /* ALLOW_HE; MODE_11G (1) on 2.4 GHz, MODE_11A (0) otherwise; PASSIVE; DFS. */
        uint32_t info = 1U << 17 | (c[i].mhz < 3000 ? 1U : 0U);
        if (c[i].passive || c[i].dfs) info |= 1U << 7;
        if (c[i].dfs) info |= 1U << 10;
        uint32_t power = c[i].max_power_half_db;
        put32(p, cmd_tlv(TAG_CHANNEL, CHANNEL_BYTES));
        put32(p + 4, c[i].mhz); put32(p + 8, c[i].mhz); put32(p + 12, 0); put32(p + 16, info);
        put32(p + 20, power << 8 | power << 16);  /* max power, max regulatory power */
        put32(p + 24, power << 8);                 /* max tx power */
    }
    return total;
}

size_t qcc2072_scan_vdev_create(uint8_t *out, size_t cap, uint32_t vdev_id, uint32_t pdev_id,
                                const uint8_t mac[6], uint32_t chains)
{
    size_t total = 4U + VDEV_CREATE_BYTES + 4U + 2U * TXRX_STREAMS_BYTES;
    if (!out || !mac || !chains || total > cap) return 0;
    zero(out, total);
    uint8_t *p = out;
    put32(p, QCC2072_WMI_VDEV_CREATE); p += 4;
    put32(p, cmd_tlv(TAG_VDEV_CREATE, VDEV_CREATE_BYTES));
    put32(p + 4, vdev_id); put32(p + 8, 2U /* WMI_VDEV_TYPE_STA */); put32(p + 12, 0U /* SUBTYPE_NONE */);
    for (unsigned i = 0; i < 6; i++) p[16 + i] = mac[i];
    put32(p + 24, 2U /* WMI_NUM_SUPPORTED_BAND_MAX */); put32(p + 28, pdev_id);
    put32(p + 44, 0xffU /* ATH12K_INVAL_VDEV_STATS_ID; stats_id_valid stays 0 */);
    p += VDEV_CREATE_BYTES;
    put32(p, tlv(TAG_ARRAY_STRUCT, 2U * TXRX_STREAMS_BYTES)); p += 4;
    for (uint32_t band = 0; band < 2; band++, p += TXRX_STREAMS_BYTES) { /* 2G, 5G */
        put32(p, cmd_tlv(TAG_VDEV_TXRX_STREAMS, TXRX_STREAMS_BYTES));
        put32(p + 4, band); put32(p + 8, chains); put32(p + 12, chains);
    }
    return total;
}

size_t qcc2072_scan_start(uint8_t *out, size_t cap, const struct qcc2072_scan_start_args *a)
{
    if (!out || !a || !a->channels_mhz || !a->channel_count ||
        a->channel_count > QCC2072_SCAN_MAX_CHANNELS || a->ssid_count > 1 ||
        a->ssid_length > 32 || (a->ssid_length && !a->ssid))
        return 0;
    size_t total = 4U + START_SCAN_BYTES + 4U + a->channel_count * 4U +
                   4U + a->ssid_count * SSID_BYTES + 4U + MAC_BYTES + 4U;
    if (total > cap || total > HTC_SEND_MAX) return 0;
    zero(out, total);
    uint8_t *p = out;
    put32(p, QCC2072_WMI_START_SCAN); p += 4;
    put32(p, cmd_tlv(TAG_START_SCAN, START_SCAN_BYTES));
    put32(p + 4, QCC2072_SCAN_ID); put32(p + 8, QCC2072_SCAN_REQ_ID); put32(p + 12, a->vdev_id);
    /* +16 scan_priority stays 0: ath12k sets arg->scan_priority but never copies it. */
    put32(p + 20, QCC2072_SCAN_STARTED | QCC2072_SCAN_COMPLETED | QCC2072_SCAN_BSS_CHANNEL |
                  QCC2072_SCAN_FOREIGN_CHANNEL | QCC2072_SCAN_DEQUEUED);
    put32(p + 24, 50); put32(p + 28, 150); put32(p + 32, 50); put32(p + 36, 500); /* dwell, rest */
    put32(p + 52, QCC2072_SCAN_MAX_TIME_MS); put32(p + 56, 5);                    /* probe_delay */
    put32(p + 60, 0x10U | (a->ssid_count ? 0U : 1U)); /* CHAN_STAT_EVENT; PASSIVE without SSIDs */
    put32(p + 68, a->channel_count); put32(p + 72, 1); put32(p + 76, a->ssid_count);
    put32(p + 148, 70); put32(p + 152, 70);           /* 6 GHz active/passive dwell */
    p += START_SCAN_BYTES;
    put32(p, tlv(TAG_ARRAY_UINT32, a->channel_count * 4U)); p += 4;
    for (unsigned i = 0; i < a->channel_count; i++, p += 4) put32(p, a->channels_mhz[i]);
    put32(p, tlv(TAG_ARRAY_FIXED_STRUCT, a->ssid_count * SSID_BYTES)); p += 4;
    if (a->ssid_count) {
        put32(p, a->ssid_length);
        for (unsigned i = 0; i < a->ssid_length; i++) p[4 + i] = a->ssid[i];
        p += SSID_BYTES;
    }
    /* One broadcast BSSID, as ath12k_wmi_start_scan_init does. */
    put32(p, tlv(TAG_ARRAY_FIXED_STRUCT, MAC_BYTES)); p += 4;
    for (unsigned i = 0; i < 6; i++) p[i] = 0xff;
    p += MAC_BYTES;
    put32(p, tlv(TAG_ARRAY_BYTE, 0));
    return total;
}

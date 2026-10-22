/* SPDX-License-Identifier: MIT */
#include "native-wcl-event.h"

static void put16(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8);
}
static void put32(uint8_t *p, uint32_t v)
{
    for (unsigned i = 0; i < 4; ++i) p[i] = (uint8_t)(v >> (8 * i));
}
static int matching_ssid(const struct snap_station_bss *b)
{
    unsigned pos = 0, ssids = 0;
    while (pos < b->ie_length) {
        if (b->ie_length - pos < 2) return 0;
        unsigned id = b->ies[pos++], n = b->ies[pos++];
        if (n > b->ie_length - pos) return 0;
        if (!id) {
            if (++ssids != 1 || n != b->ssid_length) return 0;
            for (unsigned i = 0; i < n; ++i)
                if (b->ssid[i] != b->ies[pos + i]) return 0;
        }
        pos += n;
    }
    return ssids == 1;
}
static int primary_spec(uint16_t mhz, uint16_t *spec, uint8_t *channel)
{
    /* Exact ChanSpecGetPrimarySpec: (band & 0xc000) | channel | 0x1000.
     * ChanSpecConvToApple80211Channel identifies band0=2GHz, band3=5GHz.
     * This describes the observed primary receive channel, not AP bandwidth.
     * Regulatory admission remains the backend's responsibility.
     */
    unsigned c;
    if (mhz == 2484) c = 14;
    else if (mhz >= 2412 && mhz <= 2472 && !((mhz - 2407) % 5))
        c = (mhz - 2407) / 5;
    else if (mhz >= 5160 && mhz <= 5885 && !((mhz - 5000) % 5)) {
        c = (mhz - 5000) / 5;
        *channel = (uint8_t)c;
        *spec = (uint16_t)(0xd000 | c);
        return SNAP_STATION_OK;
    } else return SNAP_STATION_UNSUPPORTED;
    *channel = (uint8_t)c;
    *spec = (uint16_t)(0x1000 | c);
    return SNAP_STATION_OK;
}
int snap_wcl_event_encode(const struct snap_station_event *e, uint8_t *out,
                         size_t capacity, uint32_t *message, size_t *bytes)
{
    if (message) *message = 0;
    if (bytes) *bytes = 0;
    if (!e || !out || !message || !bytes) return SNAP_STATION_INVALID;
    if (e->type == SNAP_STATION_SCAN_DONE ||
        e->type == SNAP_STATION_CANCEL_ACK || e->type == SNAP_STATION_ERROR) {
        if (capacity < 4 || (e->type == SNAP_STATION_ERROR && !e->status) ||
            (e->type != SNAP_STATION_ERROR && e->status))
            return SNAP_STATION_INVALID;
        uint32_t status = e->type == SNAP_STATION_SCAN_DONE ? 0 :
            (e->type == SNAP_STATION_CANCEL_ACK || e->status == SNAP_STATION_CANCELLED)
            ? UINT32_C(0xe00002eb) : UINT32_C(0xe00002bc);
        put32(out, status);
        *message = 0xed; *bytes = 4;
        return SNAP_STATION_OK;
    }
    if (e->type != SNAP_STATION_BSS) return SNAP_STATION_UNSUPPORTED;
    const struct snap_station_bss *b = &e->bss;
    if (e->status || b->ssid_length > 32 || b->ie_length > SNAP_STATION_MAX_IE ||
        b->rssi_dbm > 0 || b->rssi_dbm < -127 || (b->bssid[0] & 1) ||
        capacity < (size_t)SNAP_WCL_BEACON_META_BYTES + b->ie_length)
        return SNAP_STATION_INVALID;
    unsigned address = 0;
    for (unsigned i = 0; i < 6; ++i) address |= b->bssid[i];
    if (!address || !matching_ssid(b)) return SNAP_STATION_INVALID;
    if ((b->observed & SNAP_STATION_BSS_REQUIRED) != SNAP_STATION_BSS_REQUIRED)
        return SNAP_STATION_NOT_READY;
    uint16_t spec;
    uint8_t channel;
    int status = primary_spec(b->frequency_mhz, &spec, &channel);
    if (status) return status;
    /* All validation precedes the first payload write. Unobserved optional
     * fields/flags remain absent, including noise, SNR and cached-RSSI flags.
     */
    for (unsigned i = 0; i < SNAP_WCL_BEACON_META_BYTES; ++i) out[i] = 0;
    put32(out, b->ie_length);
    put16(out + 4, spec);
    for (unsigned i = 0; i < b->ssid_length; ++i) out[6 + i] = b->ssid[i];
    out[0x26] = b->ssid_length;
    out[0x27] = channel;
    for (unsigned i = 0; i < 6; ++i) out[0x29 + i] = b->bssid[i];
    put32(out + 0x30, (uint32_t)(int32_t)b->rssi_dbm);
    put16(out + 0x38, b->beacon_interval_tu);
    put16(out + 0x3a, b->capability);
    put32(out + 0x40, 0x4002); /* supplied SSID; current RSSI */
    for (unsigned i = 0; i < b->ie_length; ++i)
        out[SNAP_WCL_BEACON_META_BYTES + i] = b->ies[i];
    *message = 0xc9;
    *bytes = SNAP_WCL_BEACON_META_BYTES + b->ie_length;
    return SNAP_STATION_OK;
}

/* SPDX-License-Identifier: MIT */
#include "native-wcl-scan.h"

static uint32_t u32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}
int snap_wcl_scan_submit(struct snap_station *station, const void *payload,
                         size_t bytes, uint64_t transaction,
                         snap_wcl_channel_resolver resolve, void *context)
{
    const uint8_t *p = (const uint8_t *)payload;
    struct snap_station_request request = {0};
    uint32_t ssid_bytes, count, i;
    if (!station || !p || bytes < SNAP_WCL_SCAN_26A428_BYTES || !transaction)
        return SNAP_STATION_INVALID;
    /* Exact producer writes at these offsets; no historical packed struct is
     * dereferenced. Unknown schema versions are not translated optimistically. */
    if (u32(p) != 1) return SNAP_STATION_UNSUPPORTED;
    ssid_bytes = u32(p + 0x1c);
    count = u32(p + 0x54);
    if (ssid_bytes > 32 || count > 400 || p[4] > 1)
        return SNAP_STATION_INVALID;
    if (count > SNAP_STATION_MAX_CHANNELS || u32(p + 0xc) ||
        u32(p + 0x1318) || u32(p + 0x154c))
        return SNAP_STATION_UNSUPPORTED;
    if (count && !resolve) return SNAP_STATION_NOT_READY;
    request.type = SNAP_STATION_SCAN;
    request.transaction = transaction;
    request.ssid_length = (uint8_t)ssid_bytes;
    for (i = 0; i < ssid_bytes; ++i) request.ssid[i] = p[0x20 + i];
    for (i = 0; i < 6; ++i) request.bssid[i] = p[0x14 + i];
    request.scan.private_mac = p[4];
    request.scan.home_away_ms = u32(p + 8);
    request.scan.bss_type = u32(p + 0x10);
    request.scan.mode = u32(p + 0x40);
    request.scan.flags = p[0x44] | ((uint32_t)p[0x45] << 8);
    request.scan.active_dwell_ms = u32(p + 0x48);
    request.scan.passive_dwell_ms = u32(p + 0x4c);
    request.scan.parameter_50 = u32(p + 0x50);
    request.channel_count = (uint16_t)count;
    for (i = 0; i < count; ++i) {
        const uint8_t *channel = p + 0x58 + 12 * i;
        int result = resolve(context, u32(channel), u32(channel + 4),
                             u32(channel + 8), &request.channels_mhz[i]);
        if (result != SNAP_STATION_OK) return result;
    }
    return snap_station_submit(station, &request);
}

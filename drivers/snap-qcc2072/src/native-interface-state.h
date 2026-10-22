/* SPDX-License-Identifier: MIT */
#ifndef SNAP_NATIVE_INTERFACE_STATE_H
#define SNAP_NATIVE_INTERFACE_STATE_H
/* Exact 26A428 payloads the native interface answers for the Wi-Fi menu path.
 * Layouts were recovered from the exact IO80211Family / AppleBCMWLANCore
 * binaries (re/wifi-ui/ABI-26A428.md, recover-wifi-ui-abi.py); failure modes
 * are in re/wifi-ui/FAILURES.md. Header-only so the kext and the host replay
 * compile the same code without a build-script change.
 *
 * Rules: every encoder writes only inside the exact recovered size; fields
 * whose meaning is not recovered stay zero; fields Apple's own driver leaves
 * to the caller are left untouched. Nothing here reads hardware: callers pass
 * facts the station bridge already admitted.
 */
#include "native-station.h"
#include "native-wcl-scan.h"
#include "native-wcl-event.h"
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

enum {
    SNAP_IF_POWER_BYTES = 0x18,            /* apple80211_power_data */
    SNAP_IF_CAPABILITY_BYTES = 0x1c,       /* apple80211_capability_data */
    SNAP_IF_VERSION_BYTES = 0x188,         /* apple80211_version_data */
    SNAP_IF_VERSION_TEXT_BYTES = 0x180,
    SNAP_IF_COUNTRY_BYTES = 0x8,           /* apple80211_country_code_data */
    SNAP_IF_HW_ADDR_BYTES = 0xc,           /* apple80211_hw_mac_address */
    SNAP_IF_OPMODE_BYTES = 0x8,            /* apple80211_opmode_data */
    SNAP_IF_SUP_CHANNEL_BYTES = 0x12d8,    /* apple80211_sup_channel_data */
    SNAP_IF_SUP_CHANNEL_MAX = 400,
    SNAP_IF_WCL_CHANNEL_INFO_BYTES = 0xc86,/* apple80211ChannelInfo */
    SNAP_IF_WCL_CHANNEL_MAX = 400,
    SNAP_IF_DRIVER_AVAILABLE_BYTES = 0xf8,
    SNAP_IF_RESET_INTERFACE_BYTES = 0x4,
    /* Bounded by the station bridge's channel array. */
    SNAP_IF_CHANNEL_CAPACITY = SNAP_STATION_MAX_CHANNELS
};
/* APPLE80211_M_* numbers from 26A428 gAppleMIndexToString. */
enum {
    SNAP_IF_M_POWER_CHANGED = 1, SNAP_IF_M_RESET_INTERFACE = 49,
    SNAP_IF_M_DRIVER_AVAILABLE = 55, SNAP_IF_M_WCL_SCAN_RESULT = 0xc9,
    SNAP_IF_M_WCL_SCAN_DONE = 0xed
};
/* WCLSystemStateManager::setPowerHandler: 0 off, 1..3 on, anything else panics. */
enum { SNAP_IF_POWER_OFF = 0, SNAP_IF_POWER_ON = 1, SNAP_IF_POWER_MAX = 3 };
/* WCLScanManager::sendRequest refuses op mode bits 0x8 (HOSTAP) | 0x10 (MONITOR). */
enum { SNAP_IF_OPMODE_NONE = 0, SNAP_IF_OPMODE_STA = 1 };
/* RESET_INTERFACE u32: 1 = firmware loaded (WCL FW_LOADED); 0 = driver reset.
 * Any other value panics WCLSystemStateManager::resetInterfaceHandler. */
enum { SNAP_IF_RESET_FW_LOADED = 1 };
/* DRIVER_AVAILABLE reason that WCL ignores (Apple uses it at chip boot). We use
 * AppleBCMWLANCore::powerOn's reason for "radio available". */
#define SNAP_IF_DRIVER_AVAILABLE_IGNORED_REASON 0xe0822803U
#define SNAP_IF_DRIVER_AVAILABLE_POWER_ON_REASON 0xe0821803U

/* AppleChannelSpec band field (bits 14..15) and apple80211_channel flags as
 * produced by exact ChanSpecConvToApple80211Channel for a 20 MHz chanspec. */
enum {
    SNAP_IF_BAND_2GHZ = 0, SNAP_IF_BAND_5GHZ = 3,
    SNAP_IF_CHANSPEC_20MHZ = 0x1000,
    SNAP_IF_CHANNEL_FLAG_20MHZ = 0x2, SNAP_IF_CHANNEL_FLAG_2GHZ = 0x8,
    SNAP_IF_CHANNEL_FLAG_5GHZ = 0x10, SNAP_IF_CHANNEL_FLAG_DFS = 0x100,
    SNAP_IF_CHANNEL_INFO_DFS = 0x2  /* entry byte 7 bit 1: WCLDeviceConfiguration::isDFSChannel */
};
struct snap_if_channel {
    uint8_t number, band;
    uint16_t mhz;
};

static inline void snap_if_put16(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8);
}
static inline void snap_if_put32(uint8_t *p, uint32_t v)
{
    for (unsigned i = 0; i < 4; ++i) p[i] = (uint8_t)(v >> (8 * i));
}
static inline uint32_t snap_if_get32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) |
           ((uint32_t)p[3] << 24);
}
static inline void snap_if_zero(uint8_t *p, size_t n)
{
    while (n--) *p++ = 0;
}

/* AppleBCMWLANCore::getPOWER writes num_radios (+4) and power_state[0] (+8). */
static inline int snap_if_power_encode(void *out, size_t bytes, uint32_t state)
{
    uint8_t *p = (uint8_t *)out;
    if (!p || bytes < SNAP_IF_POWER_BYTES || state > SNAP_IF_POWER_MAX)
        return SNAP_STATION_INVALID;
    snap_if_put32(p + 4, 1);
    snap_if_put32(p + 8, state);
    return SNAP_STATION_OK;
}
/* Decodes power_state[0]; WCL accepts 0..3 (1..3 mean on). */
static inline int snap_if_power_decode(const void *in, size_t bytes, uint32_t *state)
{
    const uint8_t *p = (const uint8_t *)in;
    uint32_t v;
    if (!p || !state || bytes < SNAP_IF_POWER_BYTES) return SNAP_STATION_INVALID;
    v = snap_if_get32(p + 8);
    if (v > SNAP_IF_POWER_MAX) return SNAP_STATION_INVALID;
    *state = v ? SNAP_IF_POWER_ON : SNAP_IF_POWER_OFF;
    return SNAP_STATION_OK;
}
/* version 1 and an all-zero bitmap: nothing is advertised (FAILURES.md 6). */
static inline int snap_if_capability_encode(void *out, size_t bytes)
{
    uint8_t *p = (uint8_t *)out;
    if (!p || bytes < SNAP_IF_CAPABILITY_BYTES) return SNAP_STATION_INVALID;
    snap_if_zero(p, SNAP_IF_CAPABILITY_BYTES);
    snap_if_put32(p, 1);
    return SNAP_STATION_OK;
}
/* AppleBCMWLANCore::getDRIVER_VERSION: u16 length at +4, text at +6 (<0x180). */
static inline int snap_if_version_encode(void *out, size_t bytes, const char *text)
{
    uint8_t *p = (uint8_t *)out;
    unsigned n = 0;
    if (!p || !text || bytes < SNAP_IF_VERSION_BYTES) return SNAP_STATION_INVALID;
    while (text[n] && n < SNAP_IF_VERSION_TEXT_BYTES - 1) ++n;
    if (text[n]) return SNAP_STATION_INVALID;
    snap_if_zero(p + 6, SNAP_IF_VERSION_TEXT_BYTES);
    for (unsigned i = 0; i < n; ++i) p[6 + i] = (uint8_t)text[i];
    snap_if_put16(p + 4, (uint16_t)n);
    return SNAP_STATION_OK;
}
/* AppleBCMWLANCore::getCOUNTRY_CODE writes cc[3] at +4; IO80211 publishes it
 * as a C string, so the third byte is the terminator for a two-letter code. */
static inline int snap_if_country_encode(void *out, size_t bytes, const uint8_t cc[2])
{
    uint8_t *p = (uint8_t *)out;
    if (!p || !cc || bytes < SNAP_IF_COUNTRY_BYTES ||
        cc[0] < 'A' || cc[0] > 'Z' || cc[1] < 'A' || cc[1] > 'Z')
        return SNAP_STATION_INVALID;
    p[4] = cc[0]; p[5] = cc[1]; p[6] = 0;
    return SNAP_STATION_OK;
}
static inline int snap_if_country_matches(const void *in, size_t bytes, const uint8_t cc[2])
{
    const uint8_t *p = (const uint8_t *)in;
    if (!p || !cc || bytes < SNAP_IF_COUNTRY_BYTES) return SNAP_STATION_INVALID;
    if (p[4] != cc[0] || p[5] != cc[1] || (p[6] && p[6] != ' '))
        return SNAP_STATION_UNSUPPORTED;
    return SNAP_STATION_OK;
}
/* AppleBCMWLANCore::getHW_ADDR: version 1, MAC at +4. */
static inline int snap_if_hw_addr_encode(void *out, size_t bytes, const uint8_t mac[6])
{
    uint8_t *p = (uint8_t *)out;
    if (!p || !mac || bytes < SNAP_IF_HW_ADDR_BYTES || (mac[0] & 1) ||
        !(mac[0] | mac[1] | mac[2] | mac[3] | mac[4] | mac[5]))
        return SNAP_STATION_INVALID;
    snap_if_zero(p, SNAP_IF_HW_ADDR_BYTES);
    snap_if_put32(p, 1);
    for (unsigned i = 0; i < 6; ++i) p[4 + i] = mac[i];
    return SNAP_STATION_OK;
}
/* AppleBCMWLANCore::getOP_MODE: version 1; mode 0 while unassociated. */
static inline int snap_if_opmode_encode(void *out, size_t bytes, uint32_t mode)
{
    uint8_t *p = (uint8_t *)out;
    if (!p || bytes < SNAP_IF_OPMODE_BYTES ||
        (mode != SNAP_IF_OPMODE_NONE && mode != SNAP_IF_OPMODE_STA))
        return SNAP_STATION_INVALID;
    snap_if_put32(p, 1);
    snap_if_put32(p + 4, mode);
    return SNAP_STATION_OK;
}

static inline int snap_if_channel_dfs(const struct snap_if_channel *c)
{
    return c->band == SNAP_IF_BAND_5GHZ && c->number >= 52 && c->number <= 144;
}
static inline uint16_t snap_if_chanspec(const struct snap_if_channel *c)
{
    return (uint16_t)(((unsigned)c->band << 14) | SNAP_IF_CHANSPEC_20MHZ | c->number);
}
static inline uint32_t snap_if_channel_flags(const struct snap_if_channel *c)
{
    uint32_t f = SNAP_IF_CHANNEL_FLAG_20MHZ;
    f |= c->band == SNAP_IF_BAND_2GHZ ? SNAP_IF_CHANNEL_FLAG_2GHZ : SNAP_IF_CHANNEL_FLAG_5GHZ;
    if (snap_if_channel_dfs(c)) f |= SNAP_IF_CHANNEL_FLAG_DFS;
    return f;
}
/* Lists every 20 MHz channel the backend resolver admits. The resolver only
 * accepts the firmware's regulatory-derived scan set; a resolver that is not
 * ready yields no list, and any inconsistent answer fails the whole list. */
static inline int snap_if_channels(snap_wcl_channel_resolver resolve, void *context,
                                   struct snap_if_channel *out, unsigned capacity,
                                   unsigned *count)
{
    unsigned n = 0, pass, ch;
    if (count) *count = 0;
    if (!resolve || !out || !count) return SNAP_STATION_INVALID;
    for (pass = 0; pass < 2; ++pass) {
        unsigned first = pass ? 32 : 1, last = pass ? 177 : 14;
        uint32_t flags = pass ? SNAP_IF_CHANNEL_FLAG_5GHZ : SNAP_IF_CHANNEL_FLAG_2GHZ;
        for (ch = first; ch <= last; ++ch) {
            uint16_t mhz = 0, want;
            int status = resolve(context, 1, ch, flags, &mhz);
            if (status == SNAP_STATION_UNSUPPORTED) continue;
            if (status != SNAP_STATION_OK) return status;
            want = (uint16_t)(pass ? 5000 + 5 * ch : (ch == 14 ? 2484 : 2407 + 5 * ch));
            if (mhz != want || n >= capacity) return SNAP_STATION_INVALID;
            out[n].number = (uint8_t)ch;
            out[n].band = pass ? SNAP_IF_BAND_5GHZ : SNAP_IF_BAND_2GHZ;
            out[n].mhz = mhz;
            ++n;
        }
    }
    if (!n) return SNAP_STATION_NOT_READY;
    *count = n;
    return SNAP_STATION_OK;
}
/* apple80211_sup_channel_data: version, count, then {version 1, channel,
 * flags} entries of 12 bytes (logBandSupportedChannels, ChanSpecConv...). */
static inline int snap_if_sup_channels_encode(void *out, size_t bytes,
                                              const struct snap_if_channel *c, unsigned n)
{
    uint8_t *p = (uint8_t *)out;
    if (!p || !c || !n || n > SNAP_IF_SUP_CHANNEL_MAX || bytes < SNAP_IF_SUP_CHANNEL_BYTES)
        return SNAP_STATION_INVALID;
    snap_if_zero(p, 8 + (size_t)n * 12);
    snap_if_put32(p, 1);
    snap_if_put32(p + 4, n);
    for (unsigned i = 0; i < n; ++i) {
        uint8_t *e = p + 8 + 12 * i;
        snap_if_put32(e, 1);
        snap_if_put32(e + 4, c[i].number);
        snap_if_put32(e + 8, snap_if_channel_flags(&c[i]));
    }
    return SNAP_STATION_OK;
}
/* apple80211ChannelInfo: 8-byte entries {chanspec u16, unknown[4], channel u8,
 * flags u8}, u16 count at 0xc80. Only chanspec, channel and the DFS flag have
 * recovered consumers; bytes 2..5, other flags and 0xc82..0xc85 stay zero. */
static inline int snap_if_wcl_channel_info_encode(void *out, size_t bytes,
                                                  const struct snap_if_channel *c, unsigned n)
{
    uint8_t *p = (uint8_t *)out;
    if (!p || !c || !n || n > SNAP_IF_WCL_CHANNEL_MAX || bytes < SNAP_IF_WCL_CHANNEL_INFO_BYTES)
        return SNAP_STATION_INVALID;
    snap_if_zero(p, SNAP_IF_WCL_CHANNEL_INFO_BYTES);
    for (unsigned i = 0; i < n; ++i) {
        uint8_t *e = p + 8 * i;
        snap_if_put16(e, snap_if_chanspec(&c[i]));
        e[6] = c[i].number;
        e[7] = snap_if_channel_dfs(&c[i]) ? SNAP_IF_CHANNEL_INFO_DFS : 0;
    }
    snap_if_put16(p + 0xc80, (uint16_t)n);
    return SNAP_STATION_OK;
}
/* DRIVER_AVAILABLE: 0xf8 bytes; version 3 (+0), available (+8), reason (+0x10). */
static inline int snap_if_driver_available_encode(void *out, size_t bytes,
                                                  uint32_t available, uint32_t reason)
{
    uint8_t *p = (uint8_t *)out;
    if (!p || bytes < SNAP_IF_DRIVER_AVAILABLE_BYTES || available > 1 ||
        (available && reason == SNAP_IF_DRIVER_AVAILABLE_IGNORED_REASON))
        return SNAP_STATION_INVALID;
    snap_if_zero(p, SNAP_IF_DRIVER_AVAILABLE_BYTES);
    snap_if_put32(p, 3);
    snap_if_put32(p + 8, available);
    snap_if_put32(p + 0x10, reason);
    return SNAP_STATION_OK;
}

/* RSSI provenance for an accepted BSS event (FAILURES.md 9). */
enum { SNAP_IF_RSSI_NONE = 0, SNAP_IF_RSSI_OBSERVED = 1, SNAP_IF_RSSI_ESTIMATED = 2 };
static inline int snap_if_bss_rssi(const struct snap_station_bss *b)
{
    const uint32_t frame = SNAP_STATION_BSS_INTERVAL | SNAP_STATION_BSS_CAPABILITY;
    if ((b->observed & SNAP_STATION_BSS_REQUIRED) == SNAP_STATION_BSS_REQUIRED)
        return SNAP_IF_RSSI_OBSERVED;
    if ((b->observed & frame) == frame && b->rssi_dbm < 0 && b->rssi_dbm >= -127)
        return SNAP_IF_RSSI_ESTIMATED;
    return SNAP_IF_RSSI_NONE;
}
/* Encodes an accepted station event as exact WCL 0xc9/0xed. An estimated RSSI
 * is passed through the unchanged qualified encoder via a caller-owned copy
 * (scratch), which marks only RSSI as present; provenance is reported. */
static inline int snap_if_wcl_event_encode(const struct snap_station_event *e,
                                           struct snap_station_event *scratch,
                                           uint8_t *out, size_t capacity,
                                           uint32_t *message, size_t *bytes,
                                           int *provenance)
{
    int rssi = SNAP_IF_RSSI_NONE;
    if (provenance) *provenance = SNAP_IF_RSSI_NONE;
    if (!e || !scratch || !provenance) {
        if (message) *message = 0;
        if (bytes) *bytes = 0;
        return SNAP_STATION_INVALID;
    }
    if (e->type == SNAP_STATION_BSS) {
        rssi = snap_if_bss_rssi(&e->bss);
        if (rssi == SNAP_IF_RSSI_ESTIMATED) {
            *scratch = *e;
            scratch->bss.observed |= SNAP_STATION_BSS_RSSI;
            e = scratch;
        }
    }
    int status = snap_wcl_event_encode(e, out, capacity, message, bytes);
    if (status == SNAP_STATION_OK) *provenance = rssi;
    return status;
}

#ifdef __cplusplus
}
#endif
#endif

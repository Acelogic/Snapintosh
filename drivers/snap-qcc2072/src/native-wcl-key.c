/* SPDX-License-Identifier: MIT */
#include "native-wcl-key.h"
#include <string.h>

static uint32_t get32(const uint8_t *p)
{
    return (uint32_t)p[0] | (uint32_t)p[1] << 8 |
           (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}

int snap_wcl_key_submit(struct snap_station *s, const void *payload,
                       size_t length, uint64_t transaction)
{
    const uint8_t *p = (const uint8_t *)payload;
    struct snap_station_control r;
    if (!s || !p || length != SNAP_WCL_KEY_26A428_BYTES)
        return SNAP_STATION_INVALID;
    /* The exact consumer ignores the version word at +0. Lengths, cipher,
     * key flags/index and peer offsets are pinned by its 26A428 disassembly. */
    uint32_t pn = get32(p + 0x50);
    uint16_t flags = (uint16_t)p[12] | (uint16_t)p[13] << 8;
    uint16_t index = (uint16_t)p[14] | (uint16_t)p[15] << 8;
    if (get32(p + 4) != 16 || get32(p + 8) != 5 ||
        (flags != 13 && flags != 10) || index > 3 ||
        (flags == 13 && index) || (pn != 0 && pn != 6 && pn != 8) ||
        (pn == 8 && (p[0x5a] || p[0x5b])) ||
        get32(p + 0x64) || get32(p + 0x78))
        return SNAP_STATION_UNSUPPORTED;
    for (unsigned i = 0x8c; i < SNAP_WCL_KEY_26A428_BYTES; ++i)
        if (p[i]) return SNAP_STATION_UNSUPPORTED;
    memset(&r, 0, sizeof(r));
    r.generation = s->generation;
    r.transaction = transaction;
    r.link_transaction = s->link_transaction;
    r.type = SNAP_STATION_KEY_INSTALL;
    r.cipher = SNAP_STATION_CIPHER_CCMP128;
    r.pairwise = flags == 13;
    r.index = (uint8_t)index;
    r.key_length = 16;
    memcpy(r.peer, p + 0x5c, 6);
    memcpy(r.key, p + 0x10, 16);
    if (pn) memcpy(r.rx_pn, p + 0x54, 6);
    int result = snap_station_control_submit(s, &r);
    volatile uint8_t *secret = (volatile uint8_t *)&r;
    for (unsigned i = 0; i < sizeof(r); ++i) secret[i] = 0;
    return result;
}

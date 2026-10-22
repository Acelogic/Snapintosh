/* SPDX-License-Identifier: MIT */
#ifndef SNAP_NATIVE_WCL_EVENT_H
#define SNAP_NATIVE_WCL_EVENT_H
#include "native-station.h"
#include <stddef.h>
#ifdef __cplusplus
extern "C" {
#endif
enum {
    SNAP_WCL_BEACON_META_BYTES = 0x44,
    SNAP_WCL_EVENT_MAX_BYTES = SNAP_WCL_BEACON_META_BYTES + SNAP_STATION_MAX_IE
};
/* Caller must first validate event generation/transaction through its station
 * and ensure ERROR/CANCEL_ACK belongs to its accepted scan, not association.
 * Produces exact 26A428 message 0xc9 or 0xed. Unknown channel/schema is refused.
 * Does not publish, allocate, attest source metadata, or fabricate a result.
 * On failure output is untouched and message/bytes are reset to zero.
 */
int snap_wcl_event_encode(const struct snap_station_event *, uint8_t *output,
                         size_t capacity, uint32_t *message, size_t *bytes);
#ifdef __cplusplus
}
#endif
#endif

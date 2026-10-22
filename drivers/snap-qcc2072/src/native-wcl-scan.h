/* SPDX-License-Identifier: MIT */
#ifndef SNAP_NATIVE_WCL_SCAN_H
#define SNAP_NATIVE_WCL_SCAN_H
#include "native-station.h"
#include <stddef.h>
#ifdef __cplusplus
extern "C" {
#endif
/* Minimum produced extent observed in exact 26A428 getScanRequestForDriver.
 * This is not a definition of every field or a reusable cross-version ABI. */
#define SNAP_WCL_SCAN_26A428_BYTES 0x1550U
typedef int (*snap_wcl_channel_resolver)(void *, uint32_t version,
                                        uint32_t channel, uint32_t flags,
                                        uint16_t *frequency_mhz);
/* Called only from the exact 26A428 native setWCL_SCAN_REQ dispatch slot.
 * The caller supplies an ownership transaction, not an unproven Apple ID.
 * Resolver must check every channel flag against firmware/regulatory support.
 * Partial layouts, multi-SSID requests and unknown extensions are refused.
 */
int snap_wcl_scan_submit(struct snap_station *, const void *, size_t,
                         uint64_t transaction, snap_wcl_channel_resolver, void *);
#ifdef __cplusplus
}
#endif
#endif

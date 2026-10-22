/* SPDX-License-Identifier: MIT */
#ifndef SNAP_NATIVE_WCL_KEY_H
#define SNAP_NATIVE_WCL_KEY_H
#include "native-station.h"
#include <stddef.h>
#ifdef __cplusplus
extern "C" {
#endif
#define SNAP_WCL_KEY_26A428_BYTES 0x94U
/* Exact 26A428 setCIPHER_KEY payload; initial supported subset is CCMP128.
 * PMK/password requests belong to the supplicant, never a temporal-key slot. */
int snap_wcl_key_submit(struct snap_station *, const void *, size_t, uint64_t);
#ifdef __cplusplus
}
#endif
#endif

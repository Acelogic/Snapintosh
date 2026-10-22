/* SPDX-License-Identifier: MIT */
#ifndef SNAP_QCC2072_SCAN_H
#define SNAP_QCC2072_SCAN_H
#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
/* Station-scan WMI commands, encoded as pinned ath12k wmi.c does. Each output is a
 * complete WMI frame (4-byte command header, then TLVs) for service_send_wmi.
 * Failure inventory: re/scan/FAILURES.md. Zero means the frame did not fit. */
#define QCC2072_WMI_START_SCAN 0x3001U
#define QCC2072_WMI_SCAN_CHAN_LIST 0x3003U
#define QCC2072_WMI_VDEV_CREATE 0x5001U
#define QCC2072_SCAN_ID 0xa000U         /* ATH12K_SCAN_ID */
#define QCC2072_SCAN_REQ_ID 1U          /* ath12k_wmi_start_scan_init */
#define QCC2072_SCAN_MAX_TIME_MS 20000U /* ath12k_wmi_start_scan_init */
#define QCC2072_SCAN_MAX_CHANNELS 64U
/* WMI_SCAN_EVENT_* bits. */
enum { QCC2072_SCAN_STARTED = 1, QCC2072_SCAN_COMPLETED = 2, QCC2072_SCAN_BSS_CHANNEL = 4,
       QCC2072_SCAN_FOREIGN_CHANNEL = 8, QCC2072_SCAN_DEQUEUED = 16,
       QCC2072_SCAN_PREEMPTED = 32, QCC2072_SCAN_START_FAILED = 64 };
struct qcc2072_scan_channel {
    uint16_t mhz;
    uint8_t passive, dfs, max_power_half_db;
};
struct qcc2072_scan_start_args {
    uint32_t vdev_id;
    const uint16_t *channels_mhz;
    unsigned channel_count;
    /* ssid_count 0 is a passive scan; 1 with length 0 is a wildcard probe. */
    unsigned ssid_count, ssid_length;
    const uint8_t *ssid;
};
/* US channel set (re/scan/FAILURES.md item 8); returns the count written. */
unsigned qcc2072_scan_default_channels(struct qcc2072_scan_channel *, unsigned capacity);
/* 2.4 and 5 GHz 20 MHz channels that fit inside the firmware's own regulatory rules
 * (WMI regulatory event): NO_IR (2) -> passive, RADAR (8) -> DFS, DISABLED (1) skipped,
 * power from the rule (dBm, sent in half-dB). 6 GHz is not scanned yet. */
struct qcc2072_wmi_reg_rule;
unsigned qcc2072_scan_channels_from_rules(const struct qcc2072_wmi_reg_rule *, unsigned rules,
                                          struct qcc2072_scan_channel *, unsigned capacity);
size_t qcc2072_scan_chan_list(uint8_t *, size_t, uint32_t pdev_id,
                              const struct qcc2072_scan_channel *, unsigned count);
size_t qcc2072_scan_vdev_create(uint8_t *, size_t, uint32_t vdev_id, uint32_t pdev_id,
                                const uint8_t mac[6], uint32_t chains);
size_t qcc2072_scan_start(uint8_t *, size_t, const struct qcc2072_scan_start_args *);
#ifdef __cplusplus
}
#endif
#endif

/* SPDX-License-Identifier: MIT */
#ifndef SNAP_QCC2072_WMI_H
#define SNAP_QCC2072_WMI_H
#include "qcc2072-runtime.h"
#include "native-station.h"
#ifdef __cplusplus
extern "C" {
#endif
/* This bounded WMI control stage never advertises native scan/connect. INIT
 * admission must come from the provider's actual REO/DMA setup, not FW_READY. */
enum qcc2072_wmi_state {
 QCC2072_WMI_WAIT_SERVICE, QCC2072_WMI_WAIT_EXT, QCC2072_WMI_INIT_ELIGIBLE,
 QCC2072_WMI_WAIT_READY, QCC2072_WMI_READY, QCC2072_WMI_QUARANTINE
};
struct qcc2072_wmi_config {
 void *context;
 int (*validate_owner)(void *,uint64_t generation,uint64_t owner_cookie);
 /* Zero only after actual REO receive rings and DMA dependencies are configured.
  * This callback is a trusted assertion, never an independent hardware proof. */
 int (*admit_datapath)(void *,uint64_t generation,uint64_t owner_cookie);
};
struct qcc2072_wmi_reg_rule {uint16_t start_mhz,end_mhz,max_bw_mhz;uint16_t flags;uint8_t power_dbm,antenna_gain;};
struct qcc2072_wmi {
 struct qcc2072_wmi_config config;
 uint64_t generation,owner_cookie,last_ms,deadline_ms;
 uint32_t timeout_ms,fw_build,rf_chains,max_scan_channels,default_hw_mode;
 uint32_t services[16],available_segments,unknown_events,reg_revision;
 struct qcc2072_wmi_reg_rule reg_rules[20];
 uint32_t reg_rule_count,reg_phy_id,peer_metadata_version;
 uint8_t mac[6],country[2],service_seen,ext_seen,ext2_seen,ready_seen,reg_seen;
 enum qcc2072_wmi_state state;int quarantine_reason;
};
enum qcc2072_wmi_event_kind {
 QCC2072_WMI_EVENT_NONE,QCC2072_WMI_EVENT_BOOT,QCC2072_WMI_EVENT_REGULATORY,
 QCC2072_WMI_EVENT_BSS,QCC2072_WMI_EVENT_SCAN,QCC2072_WMI_EVENT_UNKNOWN,
 /* re/assoc: an auth/(re)assoc-response/deauth/disassoc frame at bytes+frame_offset, and
  * a validated connect-path event for qcc2072_assoc_wmi_event. */
 QCC2072_WMI_EVENT_MGMT,QCC2072_WMI_EVENT_STATION
};
struct qcc2072_wmi_event {
 enum qcc2072_wmi_event_kind kind;uint32_t id;
 struct snap_station_bss bss;
 /* These are wire fields; neither establishes an absolute calibrated RSSI.
  * BSS.observed deliberately lacks SNAP_STATION_BSS_RSSI until qualification. */
 int32_t raw_rssi;uint32_t snr,rate,flags,pdev_id;uint64_t beacon_tsf;
 uint32_t scan_type,scan_reason,scan_frequency,scan_request_id,scan_id,vdev_id,scan_tsf;
 uint32_t frame_offset,frame_length,mgmt_subtype; /* MGMT: frame within the received bytes */
};
int qcc2072_wmi_init(struct qcc2072_wmi *,const struct qcc2072_wmi_config *,uint64_t generation,uint64_t owner_cookie,uint64_t now_ms,uint32_t timeout_ms);
/* Bytes are an actual HTC service0x100 payload including its 4-byte WMI header.
 * Serialized owner queue only; result copied out, no event callback/reentrancy. */
int qcc2072_wmi_receive(struct qcc2072_wmi *,uint64_t generation,uint64_t owner_cookie,uint64_t now_ms,uint16_t htc_service,const void *,size_t,struct qcc2072_wmi_event *);
/* Emits exact QCC2072 INIT as committed send intent once. Caller retains bytes
 * across HTC/CE backpressure, then aborts on uncertain IO. No hardware writes. */
int qcc2072_wmi_init_command(struct qcc2072_wmi *,uint64_t now_ms,void *,size_t,size_t *);
int qcc2072_wmi_poll(struct qcc2072_wmi *,uint64_t now_ms);
/* Observations only. Native capabilities always zero in this implementation. */
int qcc2072_wmi_snapshot(const struct qcc2072_wmi *,struct snap_station_ready *);
int qcc2072_wmi_abort(struct qcc2072_wmi *,int reason);
#ifdef __cplusplus
}
#endif
#endif

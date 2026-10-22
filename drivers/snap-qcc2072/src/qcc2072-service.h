/* SPDX-License-Identifier: MIT */
#ifndef SNAP_QCC2072_SERVICE_H
#define SNAP_QCC2072_SERVICE_H
#include "qcc2072-qrtr.h"
#include "qcc2072-wlfw.h"
#include "qcc2072-ce.h"
#include "qcc2072-htc.h"
#ifdef __cplusplus
extern "C" {
#endif
#define QCC2072_SERVICE_RX_SLOTS 64U
enum qcc2072_service_state { QCC2072_SERVICE_PREPARED, QCC2072_SERVICE_BOOTING,
 QCC2072_SERVICE_DISCOVERY, QCC2072_SERVICE_WLFW, QCC2072_SERVICE_FW_READY,
 QCC2072_SERVICE_QUARANTINE, QCC2072_SERVICE_WLAN_CONFIG,
 QCC2072_SERVICE_HTC, QCC2072_SERVICE_HTC_SETUP };
struct qcc2072_service_config {
 struct qcc2072_runtime_ops io;
 struct qcc2072_wlfw_ops memory;
 struct qcc2072_runtime_boot boot;
 struct qcc2072_wlfw_config firmware;
 uint32_t local_node,local_port,discovery_timeout_ms;
 void *event_context;
 void (*state_changed)(void *,enum qcc2072_service_state,int reason);
 /* Actual decoded HTC service payload; deferred outside CE callbacks. */
 int (*firmware_event)(void *,uint16_t service,const uint8_t *,size_t);
};
/* Provider allocates this object (over 512KiB), never on kernel stack. All public
 * entrypoints are serialized on one owner workloop. Init copies configuration;
 * pointed-to admission/maps/buffers/images remain immutable and alive. Provider
 * runtime receive/state_changed callbacks are replaced by this service. Other
 * callbacks retain their original contexts. Event callback cannot reenter.
 * FW_READY means observed WLFW indication only, not HTC/WMI or Wi-Fi admission. */
struct qcc2072_service {
 struct qcc2072_service_config config;
 struct qcc2072_runtime runtime;
 struct qcc2072_qrtr qrtr;
 struct qcc2072_wlfw wlfw;
 struct qcc2072_ce ce;struct qcc2072_htc htc;
 uint8_t ce_rx[32][2048],ce_pending[2048];
 uint16_t ce_rx_length[32];uint8_t ce_rx_pipe[32];
 uint32_t ce_rx_count,ce_pending_pipe;size_t ce_pending_length;
 uint8_t ce_initialized;
 uint8_t rx[QCC2072_SERVICE_RX_SLOTS][QCC2072_RUNTIME_MTU];
 uint16_t rx_length[QCC2072_SERVICE_RX_SLOTS];
 uint8_t pending[QCC2072_RUNTIME_MTU],qmi[QCC2072_RUNTIME_MTU];
 size_t pending_length;
 uint32_t rx_read,rx_write,rx_count;
 uint64_t last_ms,discovery_deadline;
 enum qcc2072_service_state state,reported_state;
 int quarantine_reason;
 uint8_t in_call,wlfw_initialized;
};
int qcc2072_service_init(struct qcc2072_service *,const struct qcc2072_service_config *);
/* Optional second stage: exact CE arena, all live firmware buffers protected.
 * Requires FW_READY and at least1MiB admitted BAR0. Caller keeps MHI awake. */
int qcc2072_service_enable_wlan(struct qcc2072_service *,const struct qcc2072_dma_buffer *ce_arena);
int qcc2072_service_begin(struct qcc2072_service *);
/* Poll 1..32 MHI events plus bounded deferred packets. No sleep, no allocation
 * except actual WLFW memory requests via caller allocator. FULL is backpressure,
 * not fabricated completion; pending committed frames remain in the service. */
int qcc2072_service_poll(struct qcc2072_service *,uint32_t budget);
/* Submit a complete WMI header+TLVs after poll returns, never from firmware_event.
 * Zero transfers ownership of a copied frame, including while CE is full. FULL
 * means no acceptance or credit debit; retry the same immutable command later.
 * Success is not a firmware acknowledgement. One pending frame is retained. */
int qcc2072_service_send_wmi(struct qcc2072_service *,const void *,size_t);
/* Same copied-frame/backpressure contract, negotiated HTT endpoint on CE4. */
int qcc2072_service_send_htt(struct qcc2072_service *,const void *,size_t);

/* Abort is logical quarantine only. DMA remains owned; provider must prove actual
 * reset/quiescence before stopping mappings or releasing any object/buffer. */
int qcc2072_service_abort(struct qcc2072_service *,int reason);
#ifdef __cplusplus
}
#endif
#endif

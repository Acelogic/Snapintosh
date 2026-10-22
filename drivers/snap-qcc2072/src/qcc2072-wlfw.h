/* SPDX-License-Identifier: MIT */
#ifndef SNAP_QCC2072_WLFW_H
#define SNAP_QCC2072_WLFW_H
#include "qcc2072-qmi.h"
#include "qcc2072-runtime.h"
#ifdef __cplusplus
extern "C" {
#endif
#define QCC2072_WLFW_MAX_MEMORY 52U
struct qcc2072_wlfw_memory_request { uint32_t bytes, type; };
struct qcc2072_wlfw_ops {
    void *context;
    int (*validate_owner)(void *, uint64_t, uint64_t);
    /* Allocate in the pre-admitted arena; retain until provider reset proof.
     * Repeated memory types are valid, each allocation must be distinct. */
    int (*allocate)(void *,const struct qcc2072_wlfw_memory_request *,struct qcc2072_dma_buffer *);
    int (*sync)(void *,const struct qcc2072_dma_buffer *,size_t,size_t,uint32_t);
};
struct qcc2072_wlfw_config {
    const struct qcc2072_dma_admission *admission;
    const struct qcc2072_dma_buffer *protected_buffers;
    uint32_t protected_count;
    struct qcc2072_slice board,regdb,m3_image,aux_image;
    struct qcc2072_dma_buffer m3,aux;
    uint32_t memory_budget_bytes,timeout_ms;
    uint8_t exact_inputs_verified;
    /* Only provider-supported host capabilities. Memory-mode0 is this bounded
     * cold boot; internal clock and host-cstate bits match QCC2072 hw.c.
     * Bit3 claims a real provider PCIe global reset; leave clear if unavailable. */
    uint8_t supports_global_reset;
};
enum qcc2072_wlfw_state {
    QCC2072_WLFW_NEW, QCC2072_WLFW_WAIT_IND, QCC2072_WLFW_IND_DONE,
    QCC2072_WLFW_WAIT_HOST, QCC2072_WLFW_WAIT_MEMORY,
    QCC2072_WLFW_MEMORY_REQUESTED, QCC2072_WLFW_WAIT_MEMORY_ACK,
    QCC2072_WLFW_WAIT_MEM_READY, QCC2072_WLFW_MEM_READY,
    QCC2072_WLFW_WAIT_CAP, QCC2072_WLFW_CAP_DONE,
    QCC2072_WLFW_REGDB, QCC2072_WLFW_BOARD_NEXT, QCC2072_WLFW_BOARD,
    QCC2072_WLFW_M3_NEXT, QCC2072_WLFW_WAIT_M3,
    QCC2072_WLFW_AUX_NEXT, QCC2072_WLFW_WAIT_AUX,
    QCC2072_WLFW_WAIT_FW_READY, QCC2072_WLFW_FW_READY,
    QCC2072_WLFW_INI_NEXT, QCC2072_WLFW_WAIT_INI,
    QCC2072_WLFW_CONFIG_NEXT, QCC2072_WLFW_WAIT_CONFIG,
    QCC2072_WLFW_MODE_NEXT, QCC2072_WLFW_WAIT_MODE, QCC2072_WLFW_WLAN_ENABLED,
    QCC2072_WLFW_QUARANTINE
};
struct qcc2072_wlfw {
    struct qcc2072_wlfw_ops ops;
    struct qcc2072_wlfw_config config;
    struct qcc2072_qmi_session qmi;
    struct qcc2072_wlfw_memory_request requested[QCC2072_WLFW_MAX_MEMORY];
    struct qcc2072_dma_buffer memory[QCC2072_WLFW_MAX_MEMORY];
    uint64_t last_ms,deadline_ms,generation,owner_cookie;
    uint32_t node,port,memory_count,memory_bytes;
    uint16_t transaction,pending_transaction,pending_message;
    enum qcc2072_wlfw_state state;
    uint8_t memory_ready_seen,fw_ready_seen,in_call;
    int quarantine_reason;
};
int qcc2072_wlfw_init(struct qcc2072_wlfw *,const struct qcc2072_wlfw_ops *,
                      const struct qcc2072_wlfw_config *,uint32_t node,uint32_t port,uint64_t now_ms);
/* next emits at most one real QMI request; no pending work returns written=0.
 * Send once after success; failed/uncertain send requires abort, not retry.
 * Call receive only for data from the discovered QRTR endpoint. */
int qcc2072_wlfw_next(struct qcc2072_wlfw *,uint64_t now_ms,void *,size_t,size_t *written);
int qcc2072_wlfw_receive(struct qcc2072_wlfw *,uint32_t node,uint32_t port,
                         uint64_t generation,uint64_t owner_cookie,uint64_t now_ms,const void *,size_t);
/* Only after real FW_READY and successfully published CE rings. */
int qcc2072_wlfw_enable(struct qcc2072_wlfw *,uint64_t now_ms);
int qcc2072_wlfw_abort(struct qcc2072_wlfw *,int reason);
#ifdef __cplusplus
}
#endif
#endif

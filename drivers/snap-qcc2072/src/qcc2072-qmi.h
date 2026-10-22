/* SPDX-License-Identifier: MIT */
#ifndef SNAP_QCC2072_QMI_H
#define SNAP_QCC2072_QMI_H
#include "qcc2072-dma.h"
#ifdef __cplusplus
extern "C" {
#endif
#define QCC2072_QMI_CAP 0x0024U
#define QCC2072_QMI_BDF 0x0025U
#define QCC2072_QMI_MEM_READY 0x0037U
#define QCC2072_QMI_FW_READY 0x0038U
#define QCC2072_QMI_DATA_MAX 6144U
#define QCC2072_QMI_REQUEST_MAX (QCC2072_QMI_DATA_MAX + 45U)
#define QCC2072_QMI_PACKET_MAX 8192U

enum qcc2072_qmi_state {
    QCC2072_QMI_WAIT_MEMORY, QCC2072_QMI_MEMORY_OBSERVED,
    QCC2072_QMI_WAIT_CAP, QCC2072_QMI_CAP_OBSERVED,
    QCC2072_QMI_BDF_NEXT, QCC2072_QMI_WAIT_BDF_ACK,
    QCC2072_QMI_BDF_ACKED, QCC2072_QMI_QUARANTINE
};
/* A single caller serializes all calls and owns immutable board memory. The
 * endpoint is learned by future QRTR WLFW discovery; it is never inferred here.
 * The future provider validates exact-board provenance/content before board_begin.
 * Calling these APIs is protocol work only: no QRTR/MHI I/O or native Wi-Fi I/O.
 */
struct qcc2072_qmi_device_memory { uint64_t start,size; };
struct qcc2072_qmi_session {
    enum qcc2072_qmi_state state;
    uint32_t node, port, chip_id, chip_family, board_id;
    struct qcc2072_qmi_device_memory device_memory[4];
    uint8_t device_memory_observed;
    uint64_t generation, owner_cookie, last_ms, deadline_ms;
    uint32_t timeout_ms, segment_id;
    uint8_t bdf_type;
    uint16_t next_transaction, pending_transaction, pending_message;
    uint16_t last_peer_result, last_peer_error;
    const uint8_t *board;
    size_t board_size, acknowledged_bytes, pending_bytes;
    int quarantine_reason;
};
int qcc2072_qmi_init(struct qcc2072_qmi_session *, uint32_t node, uint32_t port,
                     uint64_t generation, uint64_t owner_cookie, uint64_t now_ms,
                     uint32_t timeout_ms);
int qcc2072_qmi_tick(struct qcc2072_qmi_session *, uint64_t now_ms);
int qcc2072_qmi_abort(struct qcc2072_qmi_session *);
int qcc2072_qmi_cap_request(struct qcc2072_qmi_session *, uint64_t now_ms,
                            void *packet, size_t capacity, size_t *written);
int qcc2072_qmi_receive(struct qcc2072_qmi_session *, uint32_t node, uint32_t port,
                        uint64_t generation, uint64_t owner_cookie, uint64_t now_ms,
                        const void *packet, size_t length);
/* exact_board_provenance_verified is a trusted caller receipt, not a replacement
 * for hashing the payload and validating its hardware identity in the provider.
 * The code deliberately neither invents a QMI board ID nor accepts an alias.
 */
int qcc2072_qmi_board_begin(struct qcc2072_qmi_session *, const void *board,
                            size_t length, uint32_t pci_id, uint32_t pci_subsystem,
                            uint8_t exact_board_provenance_verified);
/* Regulatory bytes must be independently selected from an admitted QCC2072
 * REGDB record. This is a separate type4 transfer, never board calibration. */
int qcc2072_qmi_regdb_begin(struct qcc2072_qmi_session *, const void *, size_t,
                            uint8_t regdb_provenance_verified);
int qcc2072_qmi_board_request(struct qcc2072_qmi_session *, uint64_t now_ms,
                              void *packet, size_t capacity, size_t *written);
#ifdef __cplusplus
}
#endif
#endif

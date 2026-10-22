/* SPDX-License-Identifier: MIT */
#ifndef SNAP_QCC2072_DMA_H
#define SNAP_QCC2072_DMA_H
#include "qcc2072-firmware.h"
#ifdef __cplusplus
extern "C" {
#endif
#define QCC2072_DMA_SID 0x40100U
#define QCC2072_DMA_MAX_MAPS 64U
#define QCC2072_DMA_READ 1U
#define QCC2072_DMA_WRITE 2U
#define QCC2072_DMA_PRIVATE_STE 1U
#define QCC2072_DMA_INVALIDATED 2U
#define QCC2072_DMA_COHERENT 4U
#define QCC2072_DMA_RESERVED 8U
#define QCC2072_DMA_BME_OFF 16U
#define QCC2072_DMA_REQUIRED_PROOFS 31U

enum qcc2072_backend_result {
    QCC2072_DMA_INVALID = -20, QCC2072_SESSION_STALE = -21,
    QCC2072_DMA_PROOF_MISSING = -22, QCC2072_BAD_STATE = -23,
    QCC2072_BAD_WIRE = -24, QCC2072_FOREIGN_PEER = -25,
    QCC2072_STALE_TRANSACTION = -26, QCC2072_PEER_FAILED = -27,
    QCC2072_DEADLINE = -28, QCC2072_QUARANTINED = -29,
    QCC2072_OUTPUT_TOO_SMALL = -30
};
struct qcc2072_dma_map {
    uint64_t iova, physical, length;
    uint32_t permissions;
};
/* Receipts must come from the future trusted monitor provider. This validator
 * checks consistency only; flags cannot establish actual hardware isolation.
 * The immutable manifest and buffers are borrowed for the session lifetime.
 */
struct qcc2072_dma_admission {
    uint32_t pci_id, pci_subsystem, sid, proofs;
    uint64_t generation, owner_cookie;
    uint64_t reserved_physical, reserved_bytes, guest_physical, guest_bytes;
    const struct qcc2072_dma_map *maps;
    uint32_t map_count;
};
struct qcc2072_dma_buffer {
    uint8_t *cpu;
    size_t capacity;
    uint64_t iova, physical;
};
int qcc2072_dma_validate(const struct qcc2072_dma_admission *, uint64_t generation,
                         uint64_t owner_cookie);
int qcc2072_dma_buffer_validate(const struct qcc2072_dma_admission *,
                                const struct qcc2072_dma_buffer *, size_t length,
                                uint32_t alignment);
#ifdef __cplusplus
}
#endif
#endif

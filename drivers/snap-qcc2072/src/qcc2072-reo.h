/* SPDX-License-Identifier: MIT */
#ifndef SNAP_QCC2072_REO_H
#define SNAP_QCC2072_REO_H
#include "qcc2072-runtime.h"
#ifdef __cplusplus
extern "C" {
#endif
#define QCC2072_REO_ARENA_BYTES 0x100000U
#define QCC2072_REO_RING_COUNT 12U
struct qcc2072_reo_ops {
    void *context;
    int (*validate_owner)(void *,uint64_t,uint64_t);
    int (*read32)(void *,uint32_t,uint32_t *);
    int (*write32)(void *,uint32_t,uint32_t);
    int (*sync)(void *,const struct qcc2072_dma_buffer *,size_t,size_t,uint32_t);
};
struct qcc2072_reo {
    struct qcc2072_reo_ops ops;
    const struct qcc2072_dma_admission *admission;
    struct qcc2072_dma_buffer arena;
    uint32_t ring_offset[QCC2072_REO_RING_COUNT];
    uint8_t initialized,in_call,staged,activated,quarantined;
    int quarantine_reason;
};
/* Exact QCC2072 geometry only. Caller holds serialized BAR-window ownership and
 * M0 wake; admission/CPU-to-physical correspondence remain caller attestations.
 * Reserve the arena before WLFW memory requests. All concurrent buffers must be
 * protected. init prepares bytes without MMIO; stage publishes disabled rings
 * only after every ring was observed disabled. No engine/MSI is enabled, no
 * command posted, no cookie/routing register touched, and no DMA is freed.
 * activate requires the caller to have published the admitted cookie tables,
 * WBM link descriptors and common TCL/WBM rings. RXDMA buffers are configured
 * after WMI READY/HTT negotiation, matching the pinned driver boot ordering.
 * Caller prerequisites are attestations; this module cannot prove other engines. */
int qcc2072_reo_init(struct qcc2072_reo *,const struct qcc2072_reo_ops *,
    const struct qcc2072_dma_admission *,const struct qcc2072_dma_buffer *,
    const struct qcc2072_dma_buffer *protected_buffers,uint32_t protected_count,
    uint32_t bar_bytes);
int qcc2072_reo_stage(struct qcc2072_reo *);
int qcc2072_reo_activate(struct qcc2072_reo *);
int qcc2072_reo_abort(struct qcc2072_reo *,int reason);
#ifdef __cplusplus
}
#endif
#endif

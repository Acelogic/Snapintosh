/* SPDX-License-Identifier: MIT */
#ifndef SNAP_QCC2072_CE_H
#define SNAP_QCC2072_CE_H
#include "qcc2072-runtime.h"
#ifdef __cplusplus
extern "C" {
#endif
#define QCC2072_CE_ARENA_BYTES 0x200000U
#define QCC2072_CE_RING_COUNT 7U
struct qcc2072_ce_ops {
 void *context;
 int (*validate_owner)(void *,uint64_t,uint64_t);
 int (*read32)(void *,uint32_t,uint32_t *);
 int (*write32)(void *,uint32_t,uint32_t);
 int (*sync)(void *,const struct qcc2072_dma_buffer *,size_t,size_t,uint32_t);
 uint64_t (*now_ms)(void *);
 /* Borrowed buffer, valid during callback only. Cannot reenter CE. */
 int (*receive)(void *,uint32_t pipe,const uint8_t *,size_t);
};
struct qcc2072_ce_ring {
 uint32_t base,r2,offset,writeback,data_offset,entries,entry_dwords,pipe,id;
 uint32_t head,tail,pending,completed;
 uint8_t status;
};
struct qcc2072_ce {
 struct qcc2072_ce_ops ops;
 const struct qcc2072_dma_admission *admission;
 struct qcc2072_dma_buffer arena;
 struct qcc2072_ce_ring rings[QCC2072_CE_RING_COUNT];
 uint16_t rx_slots[2][512];uint32_t rx_read[2],rx_consumed[2];
 uint64_t tx_deadline[3][2048],last_ms;
 uint32_t bar_bytes,timeout_ms;
 uint8_t begun,in_call,quarantined;
 int quarantine_reason;
};
/* Caller must hold device M0 awake and exclusive serialized window ownership.
 * All other active DMA buffers must be included in protected ranges, including
 * firmware allocations. CPU->physical/IOVA identity remains caller attestation.
 * Polling config deliberately leaves MSI disabled. Direct R2 pointer writes are
 * used; no shadow-register configuration is advertised. No DMA release occurs. */
int qcc2072_ce_init(struct qcc2072_ce *,const struct qcc2072_ce_ops *,
 const struct qcc2072_dma_admission *,const struct qcc2072_dma_buffer *arena,
 const struct qcc2072_dma_buffer *protected_buffers,uint32_t protected_count,
 uint32_t bar_bytes,uint32_t timeout_ms);
int qcc2072_ce_begin(struct qcc2072_ce *);
int qcc2072_ce_poll(struct qcc2072_ce *,uint32_t budget);
int qcc2072_ce_send(struct qcc2072_ce *,uint32_t pipe,const void *,size_t);
int qcc2072_ce_abort(struct qcc2072_ce *,int reason);
#ifdef __cplusplus
}
#endif
#endif

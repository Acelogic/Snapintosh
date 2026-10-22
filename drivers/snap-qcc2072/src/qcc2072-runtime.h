/* SPDX-License-Identifier: MIT */
#ifndef SNAP_QCC2072_RUNTIME_H
#define SNAP_QCC2072_RUNTIME_H
#include "qcc2072-mhi.h"
#ifdef __cplusplus
extern "C" {
#endif
#define QCC2072_RUNTIME_ARENA_BYTES 0x120000U
#define QCC2072_RUNTIME_MTU 8192U
#define QCC2072_RUNTIME_TX_SLOTS 64U
#define QCC2072_RUNTIME_RX_SLOTS 64U
#define QCC2072_SYNC_DEVICE 1U
#define QCC2072_SYNC_CPU 2U

enum qcc2072_runtime_result {
    QCC2072_RUNTIME_IO = -40, QCC2072_RUNTIME_RING = -41,
    QCC2072_RUNTIME_FULL = -42, QCC2072_RUNTIME_UNSUPPORTED = -43
};
enum qcc2072_runtime_state {
    QCC2072_RUNTIME_PREPARED, QCC2072_RUNTIME_BOOTING,
    QCC2072_RUNTIME_START_TX, QCC2072_RUNTIME_START_RX,
    QCC2072_RUNTIME_IPCR, QCC2072_RUNTIME_QUARANTINE
};
/* All callbacks run on one serialized provider workloop. They must be bounded,
 * non-reentrant and return zero only for actual success. No callback may fabricate
 * read data, completion, ownership, or cache maintenance. The provider retains
 * every buffer until its own reset/quiescence proof, including on callback error.
 * validate_owner checks live generation/cookie and private SID 0x40100 isolation.
 * enable_dma is the ONLY bus-master transition, after all input syncs; it must
 * recheck ownership and isolation, then enable PCI DMA. No runtime function frees.
 * sync must implement the real coherence/cache contract and publication barriers.
 * Every supplied pointer-to-PA/IOVA correspondence remains a provider attestation.
 */
struct qcc2072_runtime_ops {
    void *context;
    int (*validate_owner)(void *, uint64_t generation, uint64_t owner_cookie);
    int (*enable_dma)(void *, uint64_t generation, uint64_t owner_cookie);
    int (*read32)(void *, uint32_t bar_offset, uint32_t *value);
    int (*write32)(void *, uint32_t bar_offset, uint32_t value);
    int (*sync)(void *, const struct qcc2072_dma_buffer *, size_t offset,
                size_t length, uint32_t direction);
    uint64_t (*now_ms)(void *);
    /* RX bytes valid only during callback; copy if needed. Callback cannot call
     * this runtime recursively. Queue any response and submit after poll returns. */
    int (*receive)(void *, const uint8_t *, size_t);
    void (*state_changed)(void *, enum qcc2072_runtime_state, int reason);
};
struct qcc2072_runtime_boot {
    struct qcc2072_dma_buffer arena, sbl, vectors;
    const struct qcc2072_dma_buffer *segments;
    uint32_t segment_count;
    struct qcc2072_mhi_image image;
    uint32_t bar_bytes, sequence, timeout_ms;
    /* Actual MSI event vector indices programmed by the provider. These are MHI
     * vector numbers, not host IRQ numbers. Polling still requires truthful config. */
    uint32_t event_msi[2];
};
struct qcc2072_runtime {
    struct qcc2072_runtime_ops ops;
    const struct qcc2072_dma_admission *admission;
    struct qcc2072_runtime_boot boot;
    uint64_t generation, owner_cookie, last_ms, deadline_ms;
    uint32_t bhi, bhie, chdb, erdb, reglen, mhi_state, ee;
    uint32_t event_read[2], event_write[2], tx_read, tx_write, rx_read, rx_write;
    uint32_t cmd_read, cmd_write, cmd_channel;
    uint32_t tx_length[64];
    uint64_t tx_deadline[64];
    uint8_t rx_buffer_slot[64];
    enum qcc2072_runtime_state state;
    int quarantine_reason;
    uint8_t active, context_published, bhie_sent, bhi_done, bhie_done;
    uint8_t tx_started, rx_started, in_call;
};
/* init writes only admitted CPU memory; begin starts real callback MMIO/DMA.
 * No external ready setter exists. begin permits only observed PBL/EDL cold boot.
 * MHI IPCR state means two channels started, never WLAN/scan readiness. */
int qcc2072_runtime_init(struct qcc2072_runtime *,
                         const struct qcc2072_runtime_ops *,
                         const struct qcc2072_dma_admission *,
                         const struct qcc2072_runtime_boot *);
int qcc2072_runtime_begin(struct qcc2072_runtime *);
int qcc2072_runtime_poll(struct qcc2072_runtime *, uint32_t event_budget);
int qcc2072_runtime_send(struct qcc2072_runtime *, const void *, size_t);
int qcc2072_runtime_abort(struct qcc2072_runtime *, int reason);
#ifdef __cplusplus
}
#endif
#endif

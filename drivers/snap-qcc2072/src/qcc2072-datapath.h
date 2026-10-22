/* SPDX-License-Identifier: MIT */
#ifndef SNAP_QCC2072_DATAPATH_H
#define SNAP_QCC2072_DATAPATH_H
#include "qcc2072-reo.h"
#include "qcc2072-qmi.h"
#ifdef __cplusplus
extern "C" {
#endif
#define QCC2072_DATAPATH_ARENA_BYTES 0x2000000U
/* Arena tail [0x1a00000,0x1b08800) is unused here and owned by qcc2072-dp-io
 * (TX slots, REO queue descriptors); keep new datapath allocations below it. */
#define QCC2072_DATAPATH_COMMON_RINGS 9U
struct qcc2072_datapath {
    struct qcc2072_reo_ops ops;
    const struct qcc2072_dma_admission *admission;
    struct qcc2072_dma_buffer arena;
    uint32_t offsets[QCC2072_DATAPATH_COMMON_RINGS];
    uint32_t cmem;
    uint8_t initialized,in_call,active,rx_prepared,quarantined;
    /* Set only by qcc2072_dpio_init (qcc2072-dp-io.c): that module then owns
     * TCL/WBM/REO completions, so poll stops treating them as unexpected. */
    uint8_t io_attached;
    int quarantine_reason;
};
/* Reserve before WLFW allocations. SPT IOVAs and descriptor CPU VAs are distinct.
 * All callbacks run under one serialized owner; admission mapping/cache proofs
 * remain caller contracts. This owns common rings/cookie tables only. RXDMA and
 * native capabilities require later actual HTT/pdev/VDEV configuration. */
int qcc2072_datapath_init(struct qcc2072_datapath *,const struct qcc2072_reo_ops *,
    const struct qcc2072_dma_admission *,const struct qcc2072_dma_buffer *,
    const struct qcc2072_dma_buffer *,uint32_t protected_count);
int qcc2072_datapath_begin(struct qcc2072_datapath *,const struct qcc2072_qmi_session *);
/* After observed HTT version3 only. Posts owned buffers and encodes six SRING
 * commands plus two filters. Caller retains each command until accepted by CE;
 * no command submission is a firmware response or native-readiness proof. */
int qcc2072_datapath_rx_prepare(struct qcc2072_datapath *);
int qcc2072_datapath_htt_command(struct qcc2072_datapath *,unsigned index,void *,size_t,size_t *);
int qcc2072_datapath_poll(struct qcc2072_datapath *);
int qcc2072_datapath_abort(struct qcc2072_datapath *,int reason);
#ifdef __cplusplus
}
#endif
#endif

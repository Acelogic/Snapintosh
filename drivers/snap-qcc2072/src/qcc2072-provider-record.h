/* SPDX-License-Identifier: MIT */
#ifndef SNAP_QCC2072_PROVIDER_RECORD_H
#define SNAP_QCC2072_PROVIDER_RECORD_H
#include <stdint.h>
#define QCC2072_PROVIDER_MAGIC UINT64_C(0x31304e574f434351) /* QCCOWN01 */
#define QCC2072_PROVIDER_RECORD_BYTES 256U
#define QCC2072_PROVIDER_DMA_BYTES UINT64_C(0x4000000)
/* Produced only after real private-SMMU publication and reservation admission.
 * Copy in DT is a locator; the independently mapped monitor-owned read-only
 * page must match every word throughout this generation. It is not a callback.
 * reg indices: BAR0, DMA, BAR2, endpoint ECAM, monitor control page.
 */
struct qcc2072_provider_record {
    uint64_t magic,version,bytes,state,generation,cookie,pci_id,pci_subsystem,sid,proofs;
    uint64_t bar_pa,bar_bytes,bar2_pa,bar2_bytes,ecam_pa;
    uint64_t dma_pa,dma_iova,dma_bytes,control_pa;
    uint64_t firmware_offset,firmware_bytes,board_offset,board_bytes,regdb_offset,regdb_bytes;
    uint64_t allocate_offset,guest_pa,guest_bytes,cache_line,reserved[3];
};
#endif

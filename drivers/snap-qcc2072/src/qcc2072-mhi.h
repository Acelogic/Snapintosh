/* SPDX-License-Identifier: MIT */
#ifndef SNAP_QCC2072_MHI_H
#define SNAP_QCC2072_MHI_H
#include "qcc2072-dma.h"
#ifdef __cplusplus
extern "C" {
#endif
#define QCC2072_MHI_CHUNK 0x80000U
#define QCC2072_MHI_MAX_SEGMENTS 64U
struct qcc2072_mhi_image {
    uint64_t bhi_iova, bhie_vectors_iova;
    uint32_t bhi_bytes, vector_bytes, vector_count;
    size_t source_offset, bhie_bytes;
};
/* Prepares actual BHI prefix and BHIe vectors in caller-owned CPU buffers only.
 * No MMIO, cache operations, bus mastering, memory release or readiness claims.
 * The provider must publish all prepared bytes with the admitted cache contract
 * before issuing BHI/BHIe doorbells; those runtime operations are not here.
 * No output byte changes on admission/bounds/alias failures. Output metadata
 * must be distinct from the manifest, buffer descriptors and input slice.
 */
int qcc2072_mhi_prepare(const struct qcc2072_dma_admission *, uint64_t generation,
                        uint64_t owner_cookie, const struct qcc2072_slice *amss,
                        const struct qcc2072_dma_buffer *sbl,
                        const struct qcc2072_dma_buffer *segments, uint32_t segment_count,
                        const struct qcc2072_dma_buffer *vectors,
                        struct qcc2072_mhi_image *out);
#ifdef __cplusplus
}
#endif
#endif

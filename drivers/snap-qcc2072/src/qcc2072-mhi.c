/* SPDX-License-Identifier: MIT */
#include "qcc2072-mhi.h"
static void copy(uint8_t *d, const uint8_t *s, size_t n)
{ size_t i; for (i = 0; i < n; ++i) d[i] = s[i]; }
static void put64(uint8_t *d, uint64_t n)
{ unsigned i; for (i = 0; i != 8; ++i) { d[i] = (uint8_t)n; n >>= 8; } }
static int overlaps(uint64_t a, uint64_t an, uint64_t b, uint64_t bn)
{ return a < b + bn && b < a + an; }
int qcc2072_mhi_prepare(const struct qcc2072_dma_admission *a, uint64_t generation,
                        uint64_t owner_cookie, const struct qcc2072_slice *amss,
                        const struct qcc2072_dma_buffer *sbl,
                        const struct qcc2072_dma_buffer *segments, uint32_t count,
                        const struct qcc2072_dma_buffer *vectors,
                        struct qcc2072_mhi_image *out)
{
    struct qcc2072_mhi_image result = {0};
    const struct qcc2072_dma_buffer *buffers[QCC2072_MHI_MAX_SEGMENTS + 2];
    size_t lengths[QCC2072_MHI_MAX_SEGMENTS + 2];
    size_t skip = 0, remaining, offset;
    uint32_t i, j, needed;
    int r;
    if (!out) return QCC2072_INVALID_ARGUMENT;
    if ((uintptr_t)out > UINTPTR_MAX - sizeof(*out)) return QCC2072_INVALID_ARGUMENT;
    r = qcc2072_dma_validate(a, generation, owner_cookie);
    if (r) return r;
    if (!amss || !amss->bytes || amss->length < QCC2072_MHI_CHUNK ||
        amss->length > QCC2072_MAX_FIRMWARE_BYTES || !sbl || !segments || !vectors ||
        (uintptr_t)amss->bytes > UINTPTR_MAX - amss->length)
        return QCC2072_INVALID_ARGUMENT;
    if (overlaps((uintptr_t)out, sizeof(*out), (uintptr_t)amss->bytes, amss->length))
        return QCC2072_INVALID_ARGUMENT;
    if (amss->length >= QCC2072_MHI_CHUNK + 4U) {
        const uint8_t *p = amss->bytes + QCC2072_MHI_CHUNK;
        if (p[0] == 0x7fU && p[1] == 'E' && p[2] == 'L' && p[3] == 'F')
            skip = QCC2072_MHI_CHUNK;
    }
    remaining = amss->length - skip;
    needed = (uint32_t)((remaining + QCC2072_MHI_CHUNK - 1U) / QCC2072_MHI_CHUNK);
    if (!count || count != needed || count > QCC2072_MHI_MAX_SEGMENTS)
        return QCC2072_INVALID_ARGUMENT;
    buffers[0] = sbl; lengths[0] = QCC2072_MHI_CHUNK;
    buffers[1] = vectors; lengths[1] = (size_t)count * 16U;
    for (i = 0; i < count; ++i) {
        buffers[i + 2] = &segments[i];
        lengths[i + 2] = remaining > QCC2072_MHI_CHUNK ? QCC2072_MHI_CHUNK : remaining;
        remaining -= lengths[i + 2];
    }
    for (i = 0; i < count + 2U; ++i) {
        r = qcc2072_dma_buffer_validate(a, buffers[i], lengths[i], 16U);
        if (r) return r;
        if (overlaps((uintptr_t)out, sizeof(*out), (uintptr_t)buffers[i]->cpu, lengths[i]) ||
            overlaps((uintptr_t)buffers[i]->cpu, lengths[i], (uintptr_t)amss->bytes, amss->length))
            return QCC2072_DMA_INVALID;
        for (j = 0; j < i; ++j)
            if (overlaps(buffers[i]->iova, lengths[i], buffers[j]->iova, lengths[j]) ||
                overlaps(buffers[i]->physical, lengths[i], buffers[j]->physical, lengths[j]) ||
                overlaps((uintptr_t)buffers[i]->cpu, lengths[i], (uintptr_t)buffers[j]->cpu, lengths[j]))
                return QCC2072_DMA_INVALID;
    }
    /* All checks precede mutation. Image source and output metadata may not alias. */
    copy(sbl->cpu, amss->bytes, QCC2072_MHI_CHUNK);
    offset = skip;
    for (i = 0; i < count; ++i) {
        copy(segments[i].cpu, amss->bytes + offset, lengths[i + 2]);
        put64(vectors->cpu + (size_t)i * 16U, segments[i].iova);
        put64(vectors->cpu + (size_t)i * 16U + 8U, lengths[i + 2]);
        offset += lengths[i + 2];
    }
    result.bhi_iova = sbl->iova; result.bhi_bytes = QCC2072_MHI_CHUNK;
    result.bhie_vectors_iova = vectors->iova; result.vector_bytes = count * 16U;
    result.vector_count = count; result.source_offset = skip;
    result.bhie_bytes = amss->length - skip;
    *out = result;
    return QCC2072_OK;
}

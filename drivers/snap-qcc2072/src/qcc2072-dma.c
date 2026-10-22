/* SPDX-License-Identifier: MIT */
#include "qcc2072-dma.h"

static int range(uint64_t base, uint64_t length)
{ return length && base <= UINT64_MAX - length; }
static int overlap(uint64_t a, uint64_t an, uint64_t b, uint64_t bn)
{ return a < b + bn && b < a + an; }
int qcc2072_dma_validate(const struct qcc2072_dma_admission *a,
                         uint64_t generation, uint64_t owner_cookie)
{
    uint32_t i, j;
    if (!a || !generation || !owner_cookie) return QCC2072_INVALID_ARGUMENT;
    if (a->generation != generation || a->owner_cookie != owner_cookie)
        return QCC2072_SESSION_STALE;
    if (a->pci_id != 0x111217cbU || a->pci_subsystem != 0xe14f105bU ||
        a->sid != QCC2072_DMA_SID) return QCC2072_WRONG_DEVICE;
    if ((a->proofs & QCC2072_DMA_REQUIRED_PROOFS) != QCC2072_DMA_REQUIRED_PROOFS)
        return QCC2072_DMA_PROOF_MISSING;
    if (!a->maps || !a->map_count || a->map_count > QCC2072_DMA_MAX_MAPS ||
        !range(a->reserved_physical, a->reserved_bytes) ||
        !range(a->guest_physical, a->guest_bytes) ||
        (a->reserved_physical & 4095U) || (a->reserved_bytes & 4095U) ||
        overlap(a->reserved_physical, a->reserved_bytes, a->guest_physical, a->guest_bytes))
        return QCC2072_DMA_INVALID;
    for (i = 0; i < a->map_count; ++i) {
        const struct qcc2072_dma_map *m = &a->maps[i];
        if (!range(m->iova, m->length) || !range(m->physical, m->length) ||
            !m->iova || ((m->iova | m->physical | m->length) & 4095U) ||
            m->iova + m->length > UINT64_C(0x100000000) ||
            m->physical < a->reserved_physical ||
            m->physical + m->length > a->reserved_physical + a->reserved_bytes ||
            !m->permissions || (m->permissions & ~(QCC2072_DMA_READ | QCC2072_DMA_WRITE)))
            return QCC2072_DMA_INVALID;
        for (j = 0; j < i; ++j)
            if (overlap(m->iova, m->length, a->maps[j].iova, a->maps[j].length) ||
                overlap(m->physical, m->length, a->maps[j].physical, a->maps[j].length))
                return QCC2072_DMA_INVALID;
    }
    return QCC2072_OK;
}
int qcc2072_dma_buffer_validate(const struct qcc2072_dma_admission *a,
                                const struct qcc2072_dma_buffer *b,
                                size_t length, uint32_t alignment)
{
    uint32_t i;
    int admission_result;
    if (!a) return QCC2072_INVALID_ARGUMENT;
    admission_result = qcc2072_dma_validate(a, a->generation, a->owner_cookie);
    if (admission_result) return admission_result;
    if (!a->maps || !a->map_count || a->map_count > QCC2072_DMA_MAX_MAPS ||
        !b || !b->cpu || !length || length > b->capacity ||
        !alignment || (alignment & (alignment - 1U)) ||
        ((b->iova | b->physical) & (alignment - 1U)) ||
        !range(b->iova, length) || !range(b->physical, length) ||
        (uintptr_t)b->cpu > UINTPTR_MAX - length)
        return QCC2072_DMA_INVALID;
    for (i = 0; i < a->map_count; ++i) {
        const struct qcc2072_dma_map *m = &a->maps[i];
        if (!range(m->iova, m->length) || !range(m->physical, m->length))
            return QCC2072_DMA_INVALID;
        if ((m->permissions & QCC2072_DMA_READ) && b->iova >= m->iova &&
            b->iova + length <= m->iova + m->length &&
            b->physical >= m->physical && b->physical + length <= m->physical + m->length &&
            b->iova - m->iova == b->physical - m->physical)
            return QCC2072_OK;
    }
    return QCC2072_DMA_INVALID;
}

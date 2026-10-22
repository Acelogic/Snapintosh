/* SPDX-License-Identifier: MIT */
#ifndef SNAP_COMPAT_DART_H
#define SNAP_COMPAT_DART_H
#include <stdint.h>

#define DART_STREAMS 256
struct dart_state {
    uint32_t initialized_ids, powered_ids;
    uint32_t enabled[8], tcr[DART_STREAMS], ttbr[DART_STREAMS];
    uint32_t error, error_mask, error_streams[8];
    uint64_t error_address;
    uint32_t protect, protect_lock, tlb_op, tlb_start, tlb_end;
    uint64_t translations, faults, flushes;
};
enum dart_result {
    DART_OK, DART_BAD_CONFIG, DART_BAD_WIDTH, DART_BAD_VALUE,
    DART_UNKNOWN_REGISTER, DART_READ_ONLY, DART_FAULT
};
/* Every virtual DMA producer must supply both callbacks. A translated or
 * bypassed address never authorizes host MMIO or unowned physical memory.
 * read64 returns zero on success and reads guest memory, not host registers.
 * allow returns nonzero only for a wholly permitted physical byte range. */
struct dart_memory {
    void *ctx;
    int (*read64)(void *ctx, uint64_t pa, uint64_t *value);
    int (*allow)(void *ctx, uint64_t pa, uint64_t size, int write);
};
void dart_init(struct dart_state *s);
int dart_sep_iova_range(unsigned sid,uint64_t iova,uint64_t size);
enum dart_result dart_access(struct dart_state *s, unsigned streams,
    uint64_t offset, unsigned width, int write, uint64_t *value);
/* Translate one nonempty transfer contained within a 16 KiB IOVA page.
 * No translation cache or asynchronous transaction exists in this backend.
 * Failure leaves *physical untouched and latches the first hardware fault. */
enum dart_result dart_translate(struct dart_state *s, unsigned streams,
    const struct dart_memory *m, unsigned sid, uint64_t iova, uint64_t size,
    int write, uint64_t *physical);
int dart_irq_pending(const struct dart_state *s);
#endif

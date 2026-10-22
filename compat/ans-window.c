/* SPDX-License-Identifier: MIT */
#include "ans-window.h"

static void copy(volatile uint8_t *dst, const volatile uint8_t *src, uint64_t n)
{
    for (uint64_t i = 0; i < n; i++) dst[i] = src[i];
}
static int valid(const struct ans_window_backend *b, uint64_t lba, uint64_t n)
{
    return b->blocks >= 2 * ANS_WINDOW_EDGE_BLOCKS && n && n <= ANS_TRANSFER_BYTES / ANS_BLOCK &&
        lba < b->blocks && n <= b->blocks - lba && b->blocks <= UINT64_MAX / (ANS_BLOCK / 512);
}
static uint64_t chunk_blocks(const struct ans_window_backend *b)
{
    uint64_t bytes = b->params->max_transfer;
    if (bytes > NVMEH_DATA_BYTES) bytes = NVMEH_DATA_BYTES;
    return bytes / ANS_BLOCK;
}
int ans_window_read_blocks(const struct ans_window_backend *b, uint64_t lba, uint64_t n,
                          volatile uint8_t **data)
{
    const uint64_t edge = ANS_WINDOW_EDGE_BLOCKS, chunk = chunk_blocks(b);
    if (!valid(b, lba, n) || !chunk) return 1;
    for (uint64_t i = 0; i < n;) {
        uint64_t at = lba + i, run = n - i;
        if (at < edge || at >= b->blocks - edge) {
            const volatile uint8_t *src;
            if (at < edge) {
                if (run > edge - at) run = edge - at;
                src = b->head + at * ANS_BLOCK;
            } else src = b->tail + (at - (b->blocks - edge)) * ANS_BLOCK;
            copy(b->stage + i * ANS_BLOCK, src, run * ANS_BLOCK);
        } else {
            if (run > b->blocks - edge - at) run = b->blocks - edge - at;
            if (run > chunk) run = chunk;
            if (nvmeh_read(b->ops, b->params, b->state, at * (ANS_BLOCK / 512),
                           (uint32_t)(run * (ANS_BLOCK / 512)), 0)) return 1;
            copy(b->stage + i * ANS_BLOCK, b->bounce, run * ANS_BLOCK);
        }
        i += run;
    }
    *data = b->stage;
    return 0;
}
int ans_window_prepare_write(const struct ans_window_backend *b, uint64_t lba, uint64_t n,
                            volatile uint8_t **data)
{
    const uint64_t edge = ANS_WINDOW_EDGE_BLOCKS;
    if (!(b->params->flags & NVMEH_F_WRITE) || !valid(b, lba, n) || !chunk_blocks(b) ||
        lba < edge || lba >= b->blocks - edge || n > b->blocks - edge - lba) return 0x20;
    /* Physical policy must cover the complete request before the first chunk. */
    uint64_t first = b->params->first_lba, relative = lba * (ANS_BLOCK / 512);
    uint64_t count = n * (ANS_BLOCK / 512);
    if (relative > UINT64_MAX - first) return 0x20;
    first += relative;
    if (first < b->params->write_first_lba || first > b->params->write_last_lba ||
        count - 1 > b->params->write_last_lba - first) return 0x20;
    *data = b->stage;
    return 0;
}
int ans_window_write_blocks(const struct ans_window_backend *b, uint64_t lba, uint64_t n)
{
    volatile uint8_t *stage;
    if (ans_window_prepare_write(b, lba, n, &stage)) return 1;
    const uint64_t chunk = chunk_blocks(b);
    for (uint64_t i = 0; i < n;) {
        uint64_t run = n - i;
        if (run > chunk) run = chunk;
        copy(b->bounce, stage + i * ANS_BLOCK, run * ANS_BLOCK);
        if (nvmeh_write(b->ops, b->params, b->state, (lba + i) * (ANS_BLOCK / 512),
                        (uint32_t)(run * (ANS_BLOCK / 512)), 0)) return 1;
        i += run;
    }
    return 0;
}

#if SNAP_ANS_ASYNC
/* ans-window.h. Every buffer here is block aligned (stage + i blocks, bounce, head/tail + blocks), so the copies
 * move 8-byte words: an eighth of the byte loop's iterations under the lock (N10). */
static void copy_words(volatile uint8_t *dst, const volatile uint8_t *src, uint64_t n)
{
    volatile uint64_t *d = (volatile uint64_t *)(volatile void *)dst;
    const volatile uint64_t *s = (const volatile uint64_t *)(const volatile void *)src;
    for (uint64_t i = 0; i < n / 8; i++) d[i] = s[i];
}
/* The synchronous loops' bodies from block i on: edge runs at once, then submit the next physical command.
 * 0 when every block is done, ANS_WINDOW_PENDING with one in flight, 1 on failure. */
static int advance(const struct ans_window_backend *b, struct ans_window_flight *w)
{
    const uint64_t edge = ANS_WINDOW_EDGE_BLOCKS, chunk = chunk_blocks(b);
    while (w->i < w->n) {
        uint64_t at = w->lba + w->i, run = w->n - w->i;
        if (w->op == 2 && (at < edge || at >= b->blocks - edge)) {
            const volatile uint8_t *src;
            if (at < edge) {
                if (run > edge - at) run = edge - at;
                src = b->head + at * ANS_BLOCK;
            } else src = b->tail + (at - (b->blocks - edge)) * ANS_BLOCK;
            copy_words(b->stage + w->i * ANS_BLOCK, src, run * ANS_BLOCK);
            w->i += run;
            continue;
        }
        if (w->op == 2 && run > b->blocks - edge - at) run = b->blocks - edge - at;
        if (run > chunk) run = chunk;
        if (w->op == 1) copy_words(b->bounce, b->stage + w->i * ANS_BLOCK, run * ANS_BLOCK);
        if (nvmeh_submit(b->ops, b->params, b->state, &w->f, w->op, at * (ANS_BLOCK / 512),
                         (uint32_t)(run * (ANS_BLOCK / 512)), 0)) return 1;
        w->run = run; w->phys = 1;
        return ANS_WINDOW_PENDING;
    }
    return 0;
}
int ans_window_start(const struct ans_window_backend *b, unsigned op, uint64_t lba, uint64_t n)
{
    struct ans_window_flight *w = b->flight;
    volatile uint8_t *stage;
    if (!w || w->phys || w->f.active) return 1;
    w->op = op; w->lba = lba; w->n = n; w->i = 0; w->run = 0;
    if (op == 0) {                                           /* ans_window_flush */
        w->n = 0;
        if (nvmeh_submit(b->ops, b->params, b->state, &w->f, 0, 0, 0, 0)) return 1;
        w->phys = 1;
        return ANS_WINDOW_PENDING;
    }
    if (op == 2 ? !valid(b, lba, n) || !chunk_blocks(b) :    /* ans_window_read_blocks' check */
        op != 1 || ans_window_prepare_write(b, lba, n, &stage)) return 1;   /* ans_window_write_blocks' */
    return advance(b, w);
}
int ans_window_poll(const struct ans_window_backend *b, volatile uint8_t **data)
{
    struct ans_window_flight *w = b->flight;
    if (!w) return 1;
    if (w->phys) {
        int r = nvmeh_reap(b->ops, b->params, b->state, &w->f);
        if (r == NVMEH_PENDING) return ANS_WINDOW_PENDING;
        w->phys = 0;
        if (r) { w->n = w->i; return 1; }
        if (w->op == 2) copy_words(b->stage + w->i * ANS_BLOCK, b->bounce, w->run * ANS_BLOCK);
        w->i += w->run; w->run = 0;
    }
    int r = advance(b, w);
    if (!r && w->op == 2 && data) *data = b->stage;
    return r;
}
int ans_window_ready(const struct ans_window_backend *b)
{
    const struct ans_window_flight *w = b->flight;
    return w && w->phys && nvmeh_ready(b->ops, b->params, b->state);
}
int ans_window_quiesce(const struct ans_window_backend *b)
{
    struct ans_window_flight *w = b->flight;
    if (!w || !w->phys) return 0;
    while (nvmeh_reap(b->ops, b->params, b->state, &w->f) == NVMEH_PENDING) {}
    w->phys = 0; w->n = w->i;
    return 1;
}
#endif

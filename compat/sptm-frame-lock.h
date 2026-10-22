/* SPDX-License-Identifier: MIT */
#pragma once
#include <stdint.h>
/* SNAP_SPTM_FINE_RETYPE (compat/fine-lock.h; agents/sptm-locks/FAILURE-MODES.md
 * S3, S5, S13, S24, S25): private per-frame locks, the monitor's own stand-in
 * for the SPTM frame-table lock that serializes a retype against the
 * operations reading the frame's type.
 *
 * One 32-bit word per hash class of a 16K frame: bit 31 exclusive, bits 0..30
 * the number of shared holders. Monitor-private (root_ext), never the guest's
 * frame-table bytes 0..1, so no existing check sees them.
 *  - A converted call takes a frame shared before it reads the frame's type or
 *    counts (sptm-refs.c first touch; the input list and pointer-batch frames
 *    in probes/xnuboot.c), and keeps it until after its last TLBI.
 *  - A converted RETYPE takes the frame exclusive.
 * Both are tries: a conflict makes the call decline (nothing changed), so no CPU
 * ever waits for a frame lock and they add no edge to the lock order. Two
 * frames of one class exclude each other more often (a spurious decline),
 * never less. The token path takes none: the gate drains every converted call,
 * and every converted call releases all of its frame locks before it leaves
 * the gate, so every word is zero whenever a token holder runs. */
#ifndef SPTM_FRAME_LOCKS
#define SPTM_FRAME_LOCKS 4096u
#endif
_Static_assert(SPTM_FRAME_LOCKS && !(SPTM_FRAME_LOCKS&(SPTM_FRAME_LOCKS-1)) && SPTM_FRAME_LOCKS<=65536u,
               "frame-lock index is a power-of-two mask that fits 16 bits");
#define SPTM_FRAME_LOCK_EXCLUSIVE UINT32_C(0x80000000)
/* A reference batch (SPTM_REF_MAX 2,052 entries) plus the input frames. */
#define SPTM_FRAME_HELD 2064u
struct sptm_frame_locks { uint32_t word[SPTM_FRAME_LOCKS]; } __attribute__((aligned(64)));
/* This CPU's locks for the converted call in progress. */
struct sptm_frame_held {
    struct sptm_frame_locks *locks;   /* 0: frame locks off for this call */
    uint32_t count;                   /* shared words held, in index[] */
    uint32_t exclusive;               /* the exclusive word + 1, or 0 */
    uint16_t index[SPTM_FRAME_HELD];
};
static inline unsigned sptm_frame_lock_index(uint64_t pa)
{
    return (unsigned)(((pa >> 14) * UINT64_C(0x9e3779b97f4a7c15)) >> 40) & (SPTM_FRAME_LOCKS - 1);
}
/* 1: held shared (or locks off); 0: the frame is held exclusive, or the list
 * is full -- the caller refuses before any store. */
static inline int sptm_frame_share(struct sptm_frame_held *h, uint64_t pa)
{
    if (!h || !h->locks) return 1;
    if (h->count >= SPTM_FRAME_HELD) return 0;
    unsigned i = sptm_frame_lock_index(pa);
    uint32_t *w = &h->locks->word[i], v = __atomic_load_n(w, __ATOMIC_RELAXED);
    do {
        if (v & SPTM_FRAME_LOCK_EXCLUSIVE) return 0;
    } while (!__atomic_compare_exchange_n(w, &v, v + 1, 1, __ATOMIC_ACQUIRE, __ATOMIC_RELAXED));
    h->index[h->count++] = (uint16_t)i;
    return 1;
}
/* 1: this call now holds pa's word exclusive; 0: anyone holds it (or this
 * call already holds a frame lock): decline. */
static inline int sptm_frame_exclusive(struct sptm_frame_held *h, uint64_t pa)
{
    if (!h || !h->locks || h->exclusive || h->count) return 0;
    unsigned i = sptm_frame_lock_index(pa);
    uint32_t v = 0;
    if (!__atomic_compare_exchange_n(&h->locks->word[i], &v, SPTM_FRAME_LOCK_EXCLUSIVE, 0,
                                     __ATOMIC_ACQUIRE, __ATOMIC_RELAXED)) return 0;
    h->exclusive = i + 1;
    return 1;
}
/* Every lock this call holds, released (the one release point, after the
 * call's last TLBI). Release order: every store the call made happens before
 * a later holder's acquire. */
static inline void sptm_frame_release(struct sptm_frame_held *h)
{
    if (!h || !h->locks) return;
    for (uint32_t n = h->count; n--;)
        __atomic_fetch_sub(&h->locks->word[h->index[n]], 1, __ATOMIC_RELEASE);
    h->count = 0;
    if (h->exclusive) {
        __atomic_store_n(&h->locks->word[h->exclusive - 1], 0, __ATOMIC_RELEASE);
        h->exclusive = 0;
    }
}

/* SPDX-License-Identifier: MIT */
/* The monitor's side of the guest network (compat/guest-net.h,
 * docs/GUEST-NETWORK-20261019.md): ATTACH/DETACH from the guest's HVC, the net
 * view before each host poll and the index commit after it.
 *
 * Everything runs under the service lock: the HVC is a locked trap and the
 * host poll runs on CPU0 inside the locked timer tick, so attach, detach,
 * prepare and commit never overlap.
 *
 * The ring's frames stay XNU_DEFAULT data while attached: ATTACH takes a
 * device (DART data-leaf) reference on each, as the virtual ANS does for DMA,
 * so the SPTM refuses to retype them until DETACH drops it. The guest's two
 * indices are read once per poll and checked; the monitor's own two are kept
 * here and only published to the ring, never read back from it.
 *
 * Nothing here touches hardware or monitor globals: the monitor supplies frame
 * references, the range rule and the guest-physical mapping (guest_net_ops),
 * so tools/test-guest-net.c drives the same code natively against a model
 * SPTM and hostile rings. */
#ifndef SNAP_GUEST_NET_LINK_H
#define SNAP_GUEST_NET_LINK_H
#include <stdint.h>
#include "guest-net.h"

struct guest_net_ops {
    void *ctx;
    uint64_t mem_low, mem_high;                          /* guest RAM [low, high) */
    int (*monitor_page)(void *ctx, uint64_t pa);         /* 1: a page the monitor owns (arena, loader ranges) */
    int (*frame_ref)(void *ctx, uint64_t pa, int release);  /* 0: device reference taken / dropped */
    volatile void *(*map)(void *ctx, uint64_t pa);       /* the monitor's pointer to guest physical pa */
};

struct guest_net_link {
    uint64_t attached, ring_pa, generation;
    uint64_t tx_tail, rx_head;                           /* authoritative; published to the ring */
    uint64_t attaches, detaches, refusals, last_refusal;
    uint64_t polls, views, frames_out, frames_in;
    uint64_t ring_lost, protocol_errors, ref_failures, poll2_unsupported;
    uint64_t taken_clamped, filled_clamped;
    uint64_t reserved[5];
};
#define GUEST_NET_LINK_WORDS 24
_Static_assert(sizeof(struct guest_net_link) == 8 * GUEST_NET_LINK_WORDS, "guest net report layout");

static inline volatile struct guest_net_ring *guest_net_header(const struct guest_net_ops *o, uint64_t pa)
{
    return (volatile struct guest_net_ring *)o->map(o->ctx, pa);
}

/* Drop the references of pages [0, pages). */
static inline void guest_net_release(const struct guest_net_ops *o, uint64_t pa, uint64_t pages)
{
    for (uint64_t n = 0; n < pages; n++) o->frame_ref(o->ctx, pa + n * GUEST_NET_ALIGN, 1);
}

static inline void guest_net_detach(struct guest_net_link *l, const struct guest_net_ops *o)
{
    if (!l->attached) return;
    guest_net_release(o, l->ring_pa, GUEST_NET_PAGES);
    l->attached = 0;
    l->ring_pa = 0;
    l->detaches++;
}

static inline int guest_net_refuse(struct guest_net_link *l, int e)
{
    l->refusals++;
    l->last_refusal = (uint64_t)(int64_t)e;
    return e;
}

/* ATTACH: 0 with *generation set, or GUEST_NET_E_* with nothing attached and
 * no reference held. A second ATTACH detaches the first, whatever it names. */
static inline int guest_net_attach(struct guest_net_link *l, const struct guest_net_ops *o,
                                   uint64_t pa, uint64_t bytes, uint64_t *generation)
{
    guest_net_detach(l, o);
    if (bytes != GUEST_NET_RING_BYTES || (pa & (GUEST_NET_ALIGN - 1)) || pa < o->mem_low ||
        o->mem_high < GUEST_NET_RING_BYTES || pa > o->mem_high - GUEST_NET_RING_BYTES)
        return guest_net_refuse(l, GUEST_NET_E_RANGE);
    for (uint64_t n = 0; n < GUEST_NET_PAGES; n++)
        if (o->monitor_page(o->ctx, pa + n * GUEST_NET_ALIGN)) return guest_net_refuse(l, GUEST_NET_E_RANGE);
    for (uint64_t n = 0; n < GUEST_NET_PAGES; n++)
        if (o->frame_ref(o->ctx, pa + n * GUEST_NET_ALIGN, 0)) {
            guest_net_release(o, pa, n);
            l->ref_failures++;
            return guest_net_refuse(l, GUEST_NET_E_FRAME);
        }
    volatile struct guest_net_ring *r = guest_net_header(o, pa);
    if (!r || !guest_net_header_ok(r)) {
        guest_net_release(o, pa, GUEST_NET_PAGES);
        return guest_net_refuse(l, GUEST_NET_E_HEADER);
    }
    l->attached = 1;
    l->ring_pa = pa;
    l->tx_tail = l->rx_head = 0;
    l->generation++;
    l->attaches++;
    r->generation = l->generation;
    *generation = l->generation;
    return 0;
}

/* Before a poll: fill v for q1n1, or return 0 (not attached, or the ring was
 * found broken and is now detached). v's counters (owner onwards) belong to
 * q1n1 and are kept. */
static inline int guest_net_prepare(struct guest_net_link *l, const struct guest_net_ops *o,
                                    struct guest_net_view *v)
{
    l->polls++;
    if (!l->attached) return 0;
    volatile struct guest_net_ring *r = guest_net_header(o, l->ring_pa);
    if (!r || r->magic != GUEST_NET_RING_MAGIC || r->version != GUEST_NET_RING_VERSION ||
        r->slots != GUEST_NET_SLOTS || r->slot_bytes != GUEST_NET_SLOT_BYTES) {
        l->ring_lost++;
        guest_net_detach(l, o);
        return 0;
    }
    uint64_t tx_head = __atomic_load_n(&r->tx_head, __ATOMIC_ACQUIRE);
    uint64_t rx_tail = __atomic_load_n(&r->rx_tail, __ATOMIC_ACQUIRE);
    struct guest_net_window w;
    if (guest_net_window(tx_head, l->tx_tail, l->rx_head, rx_tail, &w)) {
        l->protocol_errors++;
        guest_net_detach(l, o);
        return 0;
    }
    v->magic = GUEST_NET_VIEW_MAGIC;
    v->version = GUEST_NET_VIEW_VERSION;
    v->tx_base = (uint64_t)(uintptr_t)o->map(o->ctx, l->ring_pa + guest_net_tx_offset(0));
    v->rx_base = (uint64_t)(uintptr_t)o->map(o->ctx, l->ring_pa + guest_net_rx_offset(0));
    v->slots = GUEST_NET_SLOTS;
    v->slot_bytes = GUEST_NET_SLOT_BYTES;
    v->frame_max = GUEST_NET_FRAME_MAX;
    v->tx_first = w.tx_first;
    v->tx_avail = w.tx_avail;
    v->rx_first = w.rx_first;
    v->rx_room = w.rx_room;
    v->tx_taken = v->rx_filled = 0;
    if (!v->tx_base || !v->rx_base) {
        l->ring_lost++;
        guest_net_detach(l, o);
        return 0;
    }
    l->views++;
    return 1;
}

/* After the poll that carried v: advance by what q1n1 moved, never by more
 * than was offered, and publish. The slot stores q1n1 made come before the
 * index stores (release). */
static inline void guest_net_commit(struct guest_net_link *l, const struct guest_net_ops *o,
                                    const struct guest_net_view *v)
{
    if (!l->attached) return;
    uint64_t taken = v->tx_taken, filled = v->rx_filled;
    if (taken > v->tx_avail) {taken = v->tx_avail; l->taken_clamped++;}
    if (filled > v->rx_room) {filled = v->rx_room; l->filled_clamped++;}
    volatile struct guest_net_ring *r = guest_net_header(o, l->ring_pa);
    l->tx_tail += taken;
    l->rx_head += filled;
    l->frames_out += taken;
    l->frames_in += filled;
    if (!r) return;
    __atomic_store_n(&r->tx_tail, l->tx_tail, __ATOMIC_RELEASE);
    __atomic_store_n(&r->rx_head, l->rx_head, __ATOMIC_RELEASE);
}

#endif /* SNAP_GUEST_NET_LINK_H */

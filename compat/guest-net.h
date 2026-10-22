/* SPDX-License-Identifier: MIT */
/* Guest network over the call-service link (docs/GUEST-NETWORK-20261019.md).
 *
 * The guest's SnapintoshVirtualEthernet keeps a TX and an RX ring in its own
 * wired RAM and attaches it once with HVC #0xad16 ADRENO_GUEST_NET. Before each
 * host poll CPU0 describes the published frames and the free RX slots in a net
 * view and hands it to q1n1 (Q1N1_CALL_POLL2); q1n1 copies frames between the
 * slots and the Mac's Q1SN/Q1SM datagrams and reports how many it moved; after
 * the poll the monitor advances its own indices by those counts and publishes
 * them. Best effort, like Ethernet: a frame may be lost, never duplicated.
 *
 * Header-only and freestanding: the monitor, the kext (C++) and the host tests
 * (tools/test-guest-net.c) compile the same definitions and helpers. */
#ifndef SNAP_GUEST_NET_H
#define SNAP_GUEST_NET_H
#include <stdint.h>

/* HVC #0xad16 (compat/adreno-guest.h ADRENO_GUEST_HVC), x0 = ADRENO_GUEST_NET, x1 = sub-op.
 * Advertised only by GPU-node property GUEST_NET_PROPERTY = <GUEST_NET_ABI>; admitted only when the launch
 * enabled the network, at EL1, for an HVC in the loaded AuxKC's bytes.
 *   ATTACH  x2 = ring IPA (GUEST_NET_ALIGN aligned), x3 = GUEST_NET_RING_BYTES; the header carries magic,
 *           version, slots and slot size, every index zero. A second ATTACH replaces the first.
 *           Out: x0 = 0 or GUEST_NET_E_*, x1 = GUEST_NET_LINK_UP, x2 = GUEST_NET_MTU, x3 = attach generation.
 *   DETACH  the monitor stops touching the ring before the call returns. Out: x0 = 0, x1..x3 = 0. */
#define ADRENO_GUEST_NET 0x00010007
#define GUEST_NET_ABI 1
#define GUEST_NET_PROPERTY "snapintosh,guest-net-abi"
#define GUEST_NET_ATTACH 1u
#define GUEST_NET_DETACH 2u
#define GUEST_NET_LINK_UP 1u

#define GUEST_NET_E_DISABLED (-1)   /* the launch did not enable the network */
#define GUEST_NET_E_ORIGIN   (-2)   /* not EL1, or the HVC is not in the AuxKC */
#define GUEST_NET_E_OP       (-3)   /* unknown sub-op */
#define GUEST_NET_E_RANGE    (-4)   /* IPA alignment, size, RAM, monitor ranges */
#define GUEST_NET_E_FRAME    (-5)   /* a ring page is not an XNU_DEFAULT frame */
#define GUEST_NET_E_HEADER   (-6)   /* magic, version, geometry or nonzero indices */

/* The ring: one header page, then GUEST_NET_SLOTS TX slots, then as many RX slots. */
#define GUEST_NET_RING_MAGIC 0x31524e53u          /* "SNR1" */
#define GUEST_NET_RING_VERSION 1u
#define GUEST_NET_ALIGN 16384u                    /* the guest's page size */
#define GUEST_NET_HEADER_BYTES 16384u
#define GUEST_NET_SLOTS 32u                       /* a power of two */
#define GUEST_NET_SLOT_BYTES 2048u
#define GUEST_NET_SLOT_DATA (GUEST_NET_SLOT_BYTES - 8u)
#define GUEST_NET_RING_BYTES (GUEST_NET_HEADER_BYTES + 2u * GUEST_NET_SLOTS * GUEST_NET_SLOT_BYTES)
#define GUEST_NET_PAGES (GUEST_NET_RING_BYTES / GUEST_NET_ALIGN)
#define GUEST_NET_MTU 1500u                       /* standard Ethernet; slots hold 2040 bytes */
#define GUEST_NET_FRAME_MIN 14u
#define GUEST_NET_FRAME_MAX (GUEST_NET_MTU + 14u)

/* Each index has exactly one writer and its own cache line; all are monotonic. */
struct guest_net_ring {
    uint32_t magic, version, slots, slot_bytes;
    uint8_t mac[8];
    uint64_t reserved0[5];
    uint64_t tx_head;           /* guest: frames published */
    uint64_t pad_tx_head[7];
    uint64_t tx_tail;           /* monitor: frames consumed */
    uint64_t pad_tx_tail[7];
    uint64_t rx_head;           /* monitor: frames published */
    uint64_t pad_rx_head[7];
    uint64_t rx_tail;           /* guest: frames consumed */
    uint64_t pad_rx_tail[7];
    uint64_t generation;        /* monitor: the attach generation */
    uint64_t pad_generation[7];
};
_Static_assert(sizeof(struct guest_net_ring) == 6 * 64, "guest net ring header layout");
_Static_assert(__builtin_offsetof(struct guest_net_ring, tx_head) == 64, "tx_head line");
_Static_assert(__builtin_offsetof(struct guest_net_ring, tx_tail) == 128, "tx_tail line");
_Static_assert(__builtin_offsetof(struct guest_net_ring, rx_head) == 192, "rx_head line");
_Static_assert(__builtin_offsetof(struct guest_net_ring, rx_tail) == 256, "rx_tail line");

struct guest_net_slot {
    uint32_t length, flags;
    uint8_t data[GUEST_NET_SLOT_DATA];
};
_Static_assert(sizeof(struct guest_net_slot) == GUEST_NET_SLOT_BYTES, "guest net slot layout");
_Static_assert((GUEST_NET_SLOTS & (GUEST_NET_SLOTS - 1u)) == 0, "slots must be a power of two");
_Static_assert(GUEST_NET_RING_BYTES % GUEST_NET_ALIGN == 0, "ring is whole guest pages");

static inline uint64_t guest_net_tx_offset(uint64_t index)
{return GUEST_NET_HEADER_BYTES + (index % GUEST_NET_SLOTS) * GUEST_NET_SLOT_BYTES;}
static inline uint64_t guest_net_rx_offset(uint64_t index)
{return GUEST_NET_HEADER_BYTES + (GUEST_NET_SLOTS + index % GUEST_NET_SLOTS) * GUEST_NET_SLOT_BYTES;}

/* The header an ATTACH must name: freshly initialized by the guest. */
static inline int guest_net_header_ok(const volatile struct guest_net_ring *r)
{
    return r->magic == GUEST_NET_RING_MAGIC && r->version == GUEST_NET_RING_VERSION &&
           r->slots == GUEST_NET_SLOTS && r->slot_bytes == GUEST_NET_SLOT_BYTES &&
           !r->tx_head && !r->tx_tail && !r->rx_head && !r->rx_tail;
}

/* q1n1 platform/uefi/call-service.h struct q1n1_net_view, word for word. The
 * monitor fills magic..rx_room and zeroes tx_taken/rx_filled before each
 * POLL2; q1n1 sets those two and keeps the counters after them. */
#define GUEST_NET_VIEW_MAGIC UINT64_C(0x00315654454e3151)   /* "Q1NETV1\0" */
#define GUEST_NET_VIEW_VERSION 1u
struct guest_net_view {
    uint64_t magic, version;
    uint64_t tx_base, rx_base;                  /* slot 0 of each array */
    uint64_t slots, slot_bytes, frame_max;
    uint64_t tx_first, tx_avail;                /* published guest frames [tx_first, +tx_avail) */
    uint64_t rx_first, rx_room;                 /* free RX slots [rx_first, +rx_room) */
    uint64_t tx_taken, rx_filled;               /* q1n1: frames sent; RX slots written from rx_first */
    uint64_t owner, owner_changes;
    uint64_t requests, refused, frames_in, frames_out, rx_full, bad_frames, reply_failures, polls_seen;
};
#define GUEST_NET_VIEW_WORDS 23
_Static_assert(sizeof(struct guest_net_view) == 8 * GUEST_NET_VIEW_WORDS, "q1n1 net view layout");

/* q1n1 struct q1n1_poll_views: POLL2's a3. */
#define GUEST_NET_VIEWS_MAGIC UINT64_C(0x3153574549563151)   /* "Q1VIEWS1" */
#define GUEST_NET_VIEWS_VERSION 1u
struct guest_net_poll_views {
    uint64_t magic, version;
    uint64_t console, net;                      /* struct console_link_view *, struct guest_net_view * (or 0) */
};
_Static_assert(sizeof(struct guest_net_poll_views) == 32, "q1n1 poll views layout");

/* Ring indices as the monitor sees them at one poll. The monitor's own tx_tail
 * and rx_head are authoritative; the guest's tx_head and rx_tail are read
 * once each and checked here. 0, or GUEST_NET_E_HEADER on an impossible pair. */
struct guest_net_window { uint64_t tx_first, tx_avail, rx_first, rx_room; };
static inline int guest_net_window(uint64_t tx_head, uint64_t tx_tail, uint64_t rx_head, uint64_t rx_tail,
                                   struct guest_net_window *w)
{
    uint64_t tx = tx_head - tx_tail, rx = rx_head - rx_tail;
    if (tx > GUEST_NET_SLOTS || rx > GUEST_NET_SLOTS) return GUEST_NET_E_HEADER;
    w->tx_first = tx_tail;
    w->tx_avail = tx;
    w->rx_first = rx_head;
    w->rx_room = GUEST_NET_SLOTS - rx;
    return 0;
}

#endif /* SNAP_GUEST_NET_H */

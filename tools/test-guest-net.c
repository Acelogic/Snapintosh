/* SPDX-License-Identifier: MIT */
/* compat/guest-net-link.h: the monitor's side of the guest network
 * (docs/GUEST-NETWORK-20261019.md), run natively against a model SPTM frame
 * table, a model q1n1 (the Q1SN/Q1SM rules applied to the net view) and a
 * model guest driver.
 *
 * Failure inventory (the design's 1-5, 8, 11), each as checks:
 *   - ATTACH: wrong size, unaligned, below/above/straddling RAM, overflowing
 *     pa + size, a monitor page anywhere in the ring, a frame that refuses a
 *     reference (any page: the references already taken are released), a bad
 *     header (magic, version, geometry, a nonzero index); every refusal
 *     leaves nothing attached and no reference held; a second ATTACH
 *     releases the first ring; DETACH releases every reference;
 *   - the guest's indices: tx_head beyond tx_tail + slots, tx_head behind
 *     tx_tail, rx_tail beyond rx_head, rx_tail behind rx_head - slots: the
 *     link detaches (protocol_errors), drops its references and never
 *     publishes again; a header scribbled while attached (ring_lost);
 *   - commit: q1n1 over-reporting tx_taken or rx_filled is clamped to what
 *     was offered; the monitor's own indices never come from the ring (a
 *     guest that overwrites tx_tail/rx_head changes nothing);
 *   - end to end over random traffic, link refusals and several requests a
 *     poll: every guest frame reaches the host once, in order, none lost
 *     (a refused reply leaves its frames queued); every host frame is either
 *     delivered once, in order, or counted refused for want of room.
 *
 * cc -std=gnu11 -O1 -g -Wall -Wextra -Werror -fsanitize=address,undefined \
 *    -fno-sanitize-recover=all -Icompat tools/test-guest-net.c -o build/test-guest-net && build/test-guest-net */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "guest-net-link.h"

static unsigned long checks, failures;
#define CHECK(cond, ...) do { checks++; if (!(cond)) { failures++; \
    if (failures < 20) { printf("FAIL %s:%d: ", __FILE__, __LINE__); printf(__VA_ARGS__); printf("\n"); } } } while (0)

/* ---- model guest RAM and SPTM frames ---------------------------------- */
#define RAM_PAGES 64u
#define T_DEFAULT 1u
#define T_TABLE 7u
struct model {
    uint8_t *ram;
    uint64_t low, high;
    unsigned type[RAM_PAGES], refs[RAM_PAGES], monitor[RAM_PAGES];
    unsigned refuse_at;          /* 1-based page index whose reference fails, 0 = none */
    unsigned ref_calls;
};
static unsigned page_of(struct model *m, uint64_t pa) {return (unsigned)((pa - m->low) / GUEST_NET_ALIGN);}
static int m_monitor(void *ctx, uint64_t pa) {struct model *m = ctx; return m->monitor[page_of(m, pa)];}
static int m_ref(void *ctx, uint64_t pa, int release)
{
    struct model *m = ctx;
    unsigned p = page_of(m, pa);
    if (pa < m->low || pa >= m->high || (pa & (GUEST_NET_ALIGN - 1))) return 1;
    if (release) {
        if (!m->refs[p]) {printf("FAIL release without a reference, page %u\n", p); failures++; return 1;}
        m->refs[p]--;
        return 0;
    }
    m->ref_calls++;
    if (m->type[p] != T_DEFAULT || (m->refuse_at && m->refuse_at == p + 1)) return 1;
    m->refs[p]++;
    return 0;
}
static volatile void *m_map(void *ctx, uint64_t pa)
{
    struct model *m = ctx;
    return pa >= m->low && pa < m->high ? (volatile void *)(uintptr_t)pa : 0;
}
static void model_init(struct model *m, struct guest_net_ops *o)
{
    memset(m, 0, sizeof *m);
    m->ram = aligned_alloc(GUEST_NET_ALIGN, RAM_PAGES * GUEST_NET_ALIGN);
    memset(m->ram, 0, RAM_PAGES * GUEST_NET_ALIGN);
    m->low = (uint64_t)(uintptr_t)m->ram;
    m->high = m->low + RAM_PAGES * GUEST_NET_ALIGN;
    for (unsigned p = 0; p < RAM_PAGES; p++) m->type[p] = T_DEFAULT;
    *o = (struct guest_net_ops){m, m->low, m->high, m_monitor, m_ref, m_map};
}
static unsigned total_refs(struct model *m)
{
    unsigned n = 0;
    for (unsigned p = 0; p < RAM_PAGES; p++) n += m->refs[p];
    return n;
}
static void ring_init(struct model *m, unsigned page)
{
    struct guest_net_ring *r = (struct guest_net_ring *)(m->ram + page * GUEST_NET_ALIGN);
    memset(r, 0, GUEST_NET_RING_BYTES);
    r->magic = GUEST_NET_RING_MAGIC;
    r->version = GUEST_NET_RING_VERSION;
    r->slots = GUEST_NET_SLOTS;
    r->slot_bytes = GUEST_NET_SLOT_BYTES;
}
static uint64_t pa_of(struct model *m, unsigned page) {return m->low + (uint64_t)page * GUEST_NET_ALIGN;}

/* ---- ATTACH / DETACH --------------------------------------------------- */
static void attach_cases(void)
{
    struct model m; struct guest_net_ops o; struct guest_net_link l = {0}; uint64_t g = 0;
    model_init(&m, &o);
    ring_init(&m, 4);
    struct { uint64_t pa, bytes; int want; const char *what; } cases[] = {
        {pa_of(&m, 4), GUEST_NET_RING_BYTES - 1, GUEST_NET_E_RANGE, "short"},
        {pa_of(&m, 4), GUEST_NET_RING_BYTES + GUEST_NET_ALIGN, GUEST_NET_E_RANGE, "long"},
        {pa_of(&m, 4) + 4096, GUEST_NET_RING_BYTES, GUEST_NET_E_RANGE, "unaligned"},
        {m.low - GUEST_NET_ALIGN, GUEST_NET_RING_BYTES, GUEST_NET_E_RANGE, "below RAM"},
        {m.high - GUEST_NET_ALIGN, GUEST_NET_RING_BYTES, GUEST_NET_E_RANGE, "straddles the end"},
        {m.high, GUEST_NET_RING_BYTES, GUEST_NET_E_RANGE, "above RAM"},
        {UINT64_MAX & ~(uint64_t)(GUEST_NET_ALIGN - 1), GUEST_NET_RING_BYTES, GUEST_NET_E_RANGE, "wraps"},
    };
    for (unsigned i = 0; i < sizeof cases / sizeof cases[0]; i++) {
        int e = guest_net_attach(&l, &o, cases[i].pa, cases[i].bytes, &g);
        CHECK(e == cases[i].want && !l.attached && !total_refs(&m), "%s: %d attached %llu refs %u",
              cases[i].what, e, (unsigned long long)l.attached, total_refs(&m));
    }
    /* A monitor page at each position, then a refusing frame at each position. */
    for (unsigned k = 0; k < GUEST_NET_PAGES; k++) {
        m.monitor[4 + k] = 1;
        CHECK(guest_net_attach(&l, &o, pa_of(&m, 4), GUEST_NET_RING_BYTES, &g) == GUEST_NET_E_RANGE &&
              !l.attached && !total_refs(&m), "monitor page %u", k);
        m.monitor[4 + k] = 0;
        m.type[4 + k] = T_TABLE;
        CHECK(guest_net_attach(&l, &o, pa_of(&m, 4), GUEST_NET_RING_BYTES, &g) == GUEST_NET_E_FRAME &&
              !l.attached && !total_refs(&m), "table frame %u: refs %u", k, total_refs(&m));
        m.type[4 + k] = T_DEFAULT;
        m.refuse_at = 4 + k + 1;
        CHECK(guest_net_attach(&l, &o, pa_of(&m, 4), GUEST_NET_RING_BYTES, &g) == GUEST_NET_E_FRAME &&
              !l.attached && !total_refs(&m), "refusing frame %u", k);
        m.refuse_at = 0;
    }
    /* Bad headers. */
    struct guest_net_ring *r = (struct guest_net_ring *)(m.ram + 4 * GUEST_NET_ALIGN);
    uint32_t *fields[] = {&r->magic, &r->version, &r->slots, &r->slot_bytes};
    for (unsigned f = 0; f < 4; f++) {
        uint32_t keep = *fields[f];
        *fields[f] ^= 1;
        CHECK(guest_net_attach(&l, &o, pa_of(&m, 4), GUEST_NET_RING_BYTES, &g) == GUEST_NET_E_HEADER &&
              !l.attached && !total_refs(&m), "header field %u", f);
        *fields[f] = keep;
    }
    uint64_t *indices[] = {&r->tx_head, &r->tx_tail, &r->rx_head, &r->rx_tail};
    for (unsigned f = 0; f < 4; f++) {
        *indices[f] = 1;
        CHECK(guest_net_attach(&l, &o, pa_of(&m, 4), GUEST_NET_RING_BYTES, &g) == GUEST_NET_E_HEADER &&
              !l.attached && !total_refs(&m), "nonzero index %u", f);
        *indices[f] = 0;
    }
    CHECK(l.refusals == 7 + 3 * GUEST_NET_PAGES + 8, "refusals %llu", (unsigned long long)l.refusals);
    /* Success, then a second ATTACH elsewhere releases the first ring. */
    CHECK(!guest_net_attach(&l, &o, pa_of(&m, 4), GUEST_NET_RING_BYTES, &g) && l.attached && g == 1 &&
          r->generation == 1 && total_refs(&m) == GUEST_NET_PAGES, "attach: refs %u", total_refs(&m));
    for (unsigned k = 0; k < GUEST_NET_PAGES; k++) CHECK(m.refs[4 + k] == 1, "page %u referenced", k);
    ring_init(&m, 20);
    CHECK(!guest_net_attach(&l, &o, pa_of(&m, 20), GUEST_NET_RING_BYTES, &g) && g == 2 &&
          total_refs(&m) == GUEST_NET_PAGES && !m.refs[4] && m.refs[20] == 1, "re-attach moves the references");
    /* A failed re-attach leaves nothing attached (the old ring was detached). */
    CHECK(guest_net_attach(&l, &o, pa_of(&m, 20) + 4096, GUEST_NET_RING_BYTES, &g) == GUEST_NET_E_RANGE &&
          !l.attached && !total_refs(&m), "failed re-attach");
    ring_init(&m, 20);
    CHECK(!guest_net_attach(&l, &o, pa_of(&m, 20), GUEST_NET_RING_BYTES, &g), "attach again");
    guest_net_detach(&l, &o);
    CHECK(!l.attached && !total_refs(&m) && l.detaches == 3, "detach releases: %llu", (unsigned long long)l.detaches);
    guest_net_detach(&l, &o);
    CHECK(l.detaches == 3, "detach twice is one detach");
    struct guest_net_view v = {0};
    CHECK(!guest_net_prepare(&l, &o, &v) && v.magic == 0, "no view while detached");
    free(m.ram);
}

/* ---- hostile indices and headers while attached ------------------------- */
static void hostile_cases(void)
{
    struct { int field; int64_t delta; const char *what; } cases[] = {
        {0, GUEST_NET_SLOTS + 1, "tx_head beyond tx_tail + slots"},
        {0, -1, "tx_head behind tx_tail"},
        {1, 1, "rx_tail beyond rx_head"},
        {1, -(int64_t)GUEST_NET_SLOTS - 1, "rx_tail behind rx_head - slots"},
        {2, 0, "magic scribbled"},
        {3, 0, "geometry scribbled"},
    };
    for (unsigned i = 0; i < sizeof cases / sizeof cases[0]; i++) {
        struct model m; struct guest_net_ops o; struct guest_net_link l = {0}; uint64_t g;
        model_init(&m, &o);
        ring_init(&m, 8);
        CHECK(!guest_net_attach(&l, &o, pa_of(&m, 8), GUEST_NET_RING_BYTES, &g), "attach");
        volatile struct guest_net_ring *r = (volatile struct guest_net_ring *)(m.ram + 8 * GUEST_NET_ALIGN);
        struct guest_net_view v = {0};
        CHECK(guest_net_prepare(&l, &o, &v) && v.tx_avail == 0 && v.rx_room == GUEST_NET_SLOTS, "clean view");
        if (cases[i].field == 0) r->tx_head = (uint64_t)cases[i].delta;
        else if (cases[i].field == 1) r->rx_tail = (uint64_t)cases[i].delta;
        else if (cases[i].field == 2) r->magic = 0;
        else r->slots = 64;
        uint64_t published_tx = r->tx_tail, published_rx = r->rx_head;
        CHECK(!guest_net_prepare(&l, &o, &v), "%s: no view", cases[i].what);
        CHECK(!l.attached && !total_refs(&m), "%s: detached, references released", cases[i].what);
        CHECK(cases[i].field < 2 ? l.protocol_errors == 1 : l.ring_lost == 1, "%s: counted", cases[i].what);
        guest_net_commit(&l, &o, &v);
        CHECK(r->tx_tail == published_tx && r->rx_head == published_rx, "%s: nothing published", cases[i].what);
        free(m.ram);
    }
    /* Over-reporting q1n1 is clamped; ring copies of monitor indices are ignored. */
    struct model m; struct guest_net_ops o; struct guest_net_link l = {0}; uint64_t g;
    model_init(&m, &o);
    ring_init(&m, 8);
    guest_net_attach(&l, &o, pa_of(&m, 8), GUEST_NET_RING_BYTES, &g);
    volatile struct guest_net_ring *r = (volatile struct guest_net_ring *)(m.ram + 8 * GUEST_NET_ALIGN);
    r->tx_head = 3;
    struct guest_net_view v = {0};
    CHECK(guest_net_prepare(&l, &o, &v) && v.tx_first == 0 && v.tx_avail == 3, "three published");
    v.tx_taken = 9; v.rx_filled = GUEST_NET_SLOTS + 5;
    guest_net_commit(&l, &o, &v);
    CHECK(l.tx_tail == 3 && l.rx_head == GUEST_NET_SLOTS && r->tx_tail == 3 && r->rx_head == GUEST_NET_SLOTS &&
          l.taken_clamped == 1 && l.filled_clamped == 1, "clamped commit");
    r->tx_tail = 0; r->rx_head = 0;            /* the guest overwrites the monitor's indices */
    r->rx_tail = GUEST_NET_SLOTS;
    CHECK(guest_net_prepare(&l, &o, &v) && v.tx_first == 3 && v.tx_avail == 0 && v.rx_first == GUEST_NET_SLOTS &&
          v.rx_room == GUEST_NET_SLOTS, "own indices: tx_first %llu rx_first %llu", (unsigned long long)v.tx_first,
          (unsigned long long)v.rx_first);
    free(m.ram);
}

/* ---- end to end: guest driver, monitor, model q1n1, host ----------------- */
static uint64_t rng = 0x9e3779b97f4a7c15ull;
static uint64_t next(void) {rng ^= rng << 13; rng ^= rng >> 7; rng ^= rng << 17; return rng;}

/* A frame's bytes are a function of (direction, sequence) so receivers check order and content. */
static unsigned frame_fill(uint8_t *d, unsigned dir, uint64_t seq)
{
    unsigned n = GUEST_NET_FRAME_MIN + (unsigned)((seq * 2654435761u + dir) % (GUEST_NET_FRAME_MAX - GUEST_NET_FRAME_MIN + 1));
    for (unsigned i = 0; i < n; i++) d[i] = (uint8_t)(seq * 31 + i * 7 + dir);
    memcpy(d, &seq, 8);
    d[8] = (uint8_t)dir;
    return n;
}
static int frame_check(const uint8_t *d, unsigned n, unsigned dir, uint64_t seq)
{
    uint8_t want[GUEST_NET_FRAME_MAX];
    unsigned w = frame_fill(want, dir, seq);
    return w == n && !memcmp(want, d, n);
}

/* The model consumer (the Wi-Fi back end): one batch against the view, per the design's rules. */
#define REPLY_ROOM (4u * (GUEST_NET_FRAME_MAX + 2u))   /* one consumer batch: up to four full frames */
static void q1n1_exchange(struct guest_net_view *v, uint8_t (*in)[GUEST_NET_FRAME_MAX], unsigned *in_len,
                          unsigned n_in, uint64_t *out_seq, unsigned *n_out, int link_ok, unsigned *refused)
{
    for (unsigned k = 0; k < n_in; k++) {
        if (v->rx_filled >= v->rx_room || in_len[k] < GUEST_NET_FRAME_MIN || in_len[k] > v->frame_max) {
            (*refused)++;
            continue;
        }
        struct guest_net_slot *s = (struct guest_net_slot *)(uintptr_t)(v->rx_base +
            ((v->rx_first + v->rx_filled) % v->slots) * v->slot_bytes);
        memcpy(s->data, in[k], in_len[k]);
        s->flags = 0;
        __atomic_store_n(&s->length, in_len[k], __ATOMIC_RELAXED);
        v->rx_filled++;
    }
    unsigned bytes = 0, taken = 0;
    *n_out = 0;
    while (v->tx_taken + taken < v->tx_avail) {
        const struct guest_net_slot *s = (const struct guest_net_slot *)(uintptr_t)(v->tx_base +
            ((v->tx_first + v->tx_taken + taken) % v->slots) * v->slot_bytes);
        uint32_t len = __atomic_load_n(&s->length, __ATOMIC_RELAXED);
        if (len >= GUEST_NET_FRAME_MIN && len <= v->frame_max) {
            if (bytes + 2 + len > REPLY_ROOM) break;
            uint64_t seq; memcpy(&seq, s->data, 8);
            CHECK(frame_check(s->data, len, 1, seq), "guest frame %llu intact in its slot", (unsigned long long)seq);
            out_seq[(*n_out)++] = seq;
            bytes += 2 + len;
        }
        taken++;
    }
    if (link_ok) v->tx_taken += taken;
    else *n_out = 0;
}

static void end_to_end(unsigned trials, unsigned polls)
{
    unsigned long delivered_out = 0, delivered_in = 0, refused_in = 0, refusals_link = 0, multi = 0;
    for (unsigned t = 0; t < trials; t++) {
        struct model m; struct guest_net_ops o; struct guest_net_link l = {0}; uint64_t g;
        model_init(&m, &o);
        unsigned page = 1 + (unsigned)(next() % (RAM_PAGES - GUEST_NET_PAGES - 1));
        ring_init(&m, page);
        CHECK(!guest_net_attach(&l, &o, pa_of(&m, page), GUEST_NET_RING_BYTES, &g), "attach");
        struct guest_net_ring *r = (struct guest_net_ring *)(m.ram + page * GUEST_NET_ALIGN);
        uint64_t g_tx_seq = 0, host_rx_seq = 0;      /* guest -> host: produced, received */
        uint64_t h_tx_seq = 0, guest_rx_expect = 0;  /* host -> guest: produced, next expected by the guest */
        uint64_t host_refused_seqs = 0;
        uint8_t *refused_map = calloc((size_t)polls * 3 * 4 + 64, 1);   /* host frames refused for room, by sequence */
        struct guest_net_view v = {0};
        for (unsigned p = 0; p < polls; p++) {
            /* The guest driver: publish up to a few frames when there is room. */
            unsigned burst = (unsigned)(next() % 6);
            for (unsigned k = 0; k < burst; k++) {
                uint64_t tail = __atomic_load_n(&r->tx_tail, __ATOMIC_ACQUIRE);
                if (r->tx_head - tail >= GUEST_NET_SLOTS) break;
                struct guest_net_slot *s = (struct guest_net_slot *)((uint8_t *)r + guest_net_tx_offset(r->tx_head));
                s->length = frame_fill(s->data, 1, g_tx_seq++);
                __atomic_store_n(&r->tx_head, r->tx_head + 1, __ATOMIC_RELEASE);
            }
            /* The poll. */
            if (guest_net_prepare(&l, &o, &v)) {
                unsigned requests = 1 + (unsigned)(next() % 3);
                multi += requests > 1;
                for (unsigned q = 0; q < requests; q++) {
                    uint8_t in[8][GUEST_NET_FRAME_MAX]; unsigned in_len[8], n_in = (unsigned)(next() % 5);
                    uint64_t in_seq[8];
                    for (unsigned k = 0; k < n_in; k++) {in_seq[k] = h_tx_seq; in_len[k] = frame_fill(in[k], 2, h_tx_seq++);}
                    uint64_t out_seq[16]; unsigned n_out = 0, refused = 0, before = (unsigned)v.rx_filled;
                    int link_ok = next() % 7 != 0;
                    refusals_link += !link_ok;
                    q1n1_exchange(&v, in, in_len, n_in, out_seq, &n_out, link_ok, &refused);
                    /* Which of this request's frames were refused, in order (all after the room ran out). */
                    unsigned accepted = (unsigned)v.rx_filled - before;
                    for (unsigned k = accepted; k < n_in; k++) refused_map[in_seq[k]] = 1;
                    host_refused_seqs += refused;
                    for (unsigned k = 0; k < n_out; k++) {
                        CHECK(out_seq[k] == host_rx_seq, "guest frame order: got %llu want %llu",
                              (unsigned long long)out_seq[k], (unsigned long long)host_rx_seq);
                        host_rx_seq = out_seq[k] + 1;
                        delivered_out++;
                    }
                }
                guest_net_commit(&l, &o, &v);
            }
            /* The guest driver drains its RX ring. */
            uint64_t head = __atomic_load_n(&r->rx_head, __ATOMIC_ACQUIRE);
            while (r->rx_tail < head) {
                if (!(next() % 4)) break;   /* a slow guest leaves the rest for later */
                const struct guest_net_slot *s = (const struct guest_net_slot *)((uint8_t *)r + guest_net_rx_offset(r->rx_tail));
                uint64_t seq; memcpy(&seq, s->data, 8);
                /* Skip host frames refused for want of room: they never arrive. */
                while (refused_map[guest_rx_expect]) guest_rx_expect++;
                CHECK(seq == guest_rx_expect && frame_check(s->data, s->length, 2, seq),
                      "host frame order: got %llu want %llu", (unsigned long long)seq, (unsigned long long)guest_rx_expect);
                guest_rx_expect = seq + 1;
                delivered_in++;
                __atomic_store_n(&r->rx_tail, r->rx_tail + 1, __ATOMIC_RELEASE);
            }
        }
        /* Drain: every guest frame arrives once the link stops refusing. */
        for (unsigned p = 0; p < 64 && host_rx_seq < g_tx_seq; p++)
            if (guest_net_prepare(&l, &o, &v)) {
                uint64_t out_seq[16]; unsigned n_out = 0, refused = 0;
                q1n1_exchange(&v, 0, 0, 0, out_seq, &n_out, 1, &refused);
                for (unsigned k = 0; k < n_out; k++) {
                    CHECK(out_seq[k] == host_rx_seq, "drain order");
                    host_rx_seq = out_seq[k] + 1;
                    delivered_out++;
                }
                guest_net_commit(&l, &o, &v);
            }
        CHECK(host_rx_seq == g_tx_seq, "trial %u: guest frames lost: %llu of %llu", t,
              (unsigned long long)host_rx_seq, (unsigned long long)g_tx_seq);
        CHECK(l.frames_out == g_tx_seq && l.attached && !l.protocol_errors && !l.ring_lost,
              "trial %u: counters out %llu", t, (unsigned long long)l.frames_out);
        refused_in += host_refused_seqs;
        free(refused_map);
        guest_net_detach(&l, &o);
        CHECK(!total_refs(&m), "trial %u: references released", t);
        free(m.ram);
    }
    printf("end to end: %u trials x %u polls; %lu guest frames delivered, %lu host frames delivered, "
           "%lu refused for room, %lu link refusals, %lu polls with several requests\n",
           trials, polls, delivered_out, delivered_in, refused_in, refusals_link, multi);
    CHECK(delivered_out > 1000 && delivered_in > 1000 && refused_in > 0 && refusals_link > 0 && multi > 0,
          "coverage");
}

int main(void)
{
    attach_cases();
    hostile_cases();
    end_to_end(40, 4000);
    if (failures) {printf("FAIL: %lu of %lu checks\n", failures, checks); return 1;}
    printf("PASS: %lu checks\n", checks);
    return 0;
}

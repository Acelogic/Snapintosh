/* SPDX-License-Identifier: MIT */
/* Linked-AuxKC observation counters: range bounds, execute transitions,
 * the event budget, retype accounting and the decoder's field layout. */
#include <stddef.h>
#include <stdio.h>
#include "../compat/auxkc-observe.h"

static unsigned failures, checks;
#define CHECK(x) do { checks++; if (!(x)) { failures++; \
    fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #x); } } while (0)

#define BASE 0xfffffe000e358000UL
#define PA 0x8ced00000UL
#define SPAN 0x68000UL
#define RX (PA | 0x40bUL)                 /* valid page, AF, EL1 RW, PXN clear */
#define NX (RX | PT_PXN | PT_UXN)

int main(void)
{
    const struct auxkc_range none = {0};
    const struct auxkc_range r = {BASE, BASE + SPAN, PA, PA + SPAN};
    struct auxkc_exec_state s = {0};

    /* Layout pinned for tools/auxkc_counters.py (13 u64 words, this order). */
    CHECK(sizeof(struct auxkc_exec_state) == 13 * 8);
    CHECK(offsetof(struct auxkc_exec_state, map_exec_gained) == 8);
    CHECK(offsetof(struct auxkc_exec_state, retypes) == 32);
    CHECK(offsetof(struct auxkc_exec_state, last_kind) == 48);
    CHECK(offsetof(struct auxkc_exec_state, last_retype_types) == 96);
    CHECK(sizeof(struct auxkc_range) == 32);

    /* No linked collection: nothing is counted, whatever the address. */
    CHECK(!auxkc_observe_leaf(&s, &none, AUXKC_KIND_MAP, 1, BASE, 0, RX));
    CHECK(!auxkc_observe_retype(&s, &none, PA, 0xb, 0x10));
    CHECK(!auxkc_overlaps(&none, BASE, 1));
    CHECK(s.map_pages == 0 && s.retypes == 0);

    /* Bounds are [base, end). */
    CHECK(!auxkc_observe_leaf(&s, &r, AUXKC_KIND_MAP, 1, BASE - 0x4000, 0, RX));
    CHECK(!auxkc_observe_leaf(&s, &r, AUXKC_KIND_MAP, 1, BASE + SPAN, 0, RX));
    CHECK(s.map_pages == 0);

    /* Execute permission: valid leaf with PXN clear. */
    CHECK(auxkc_el1_exec(RX) && !auxkc_el1_exec(NX) && !auxkc_el1_exec(RX & ~3UL) &&
          !auxkc_el1_exec((RX & ~3UL) | 1));

    /* NX -> NX and RX -> RX count as touches, not transitions. */
    CHECK(!auxkc_observe_leaf(&s, &r, AUXKC_KIND_MAP, 1, BASE, NX, NX));
    CHECK(!auxkc_observe_leaf(&s, &r, AUXKC_KIND_UPDATE, 1, BASE + 0x4000, RX, RX));
    CHECK(s.map_pages == 1 && s.update_entries == 1 && !s.map_exec_gained &&
          !s.update_exec_gained && !s.last_kind);

    /* Invalid -> RX and NX -> RX are transitions, logged and remembered. */
    CHECK(auxkc_observe_leaf(&s, &r, AUXKC_KIND_MAP, 0x111, BASE + 0x2c000, 0, RX));
    CHECK(s.map_exec_gained == 1 && s.last_kind == AUXKC_KIND_MAP &&
          s.last_va == BASE + 0x2c000 && s.last_new == RX && s.last_elr == 0x111);
    CHECK(auxkc_observe_leaf(&s, &r, AUXKC_KIND_UPDATE, 0x222, BASE + 0x30000, NX, RX));
    CHECK(s.update_exec_gained == 1 && s.last_kind == AUXKC_KIND_UPDATE && s.last_old == NX);

    /* RX -> NX is a touch only; the last transition is kept. */
    CHECK(!auxkc_observe_leaf(&s, &r, AUXKC_KIND_UPDATE, 0x333, BASE + 0x30000, RX, NX));
    CHECK(s.last_elr == 0x222 && s.update_entries == 3);

    /* The event budget stops logging, never counting. */
    for (unsigned n = 2; n < AUXKC_EXEC_LOGGED; n++)
        CHECK(auxkc_observe_leaf(&s, &r, AUXKC_KIND_MAP, n, BASE, 0, RX));
    CHECK(!auxkc_observe_leaf(&s, &r, AUXKC_KIND_MAP, 99, BASE, 0, RX));
    CHECK(s.map_exec_gained + s.update_exec_gained == AUXKC_EXEC_LOGGED + 1);
    CHECK(s.last_elr == 99);

    /* UPDATE_REGION prefilter. */
    CHECK(auxkc_overlaps(&r, BASE - 0x4000, 2) && !auxkc_overlaps(&r, BASE - 0x4000, 1));
    CHECK(auxkc_overlaps(&r, BASE + SPAN - 0x4000, 64) && !auxkc_overlaps(&r, BASE + SPAN, 64));
    CHECK(!auxkc_overlaps(&r, BASE, 0) && !auxkc_overlaps(&r, UINT64_MAX & ~0x3fffUL, 64));

    /* RETYPE: its frames only, with the requested types. */
    CHECK(!auxkc_observe_retype(&s, &r, PA - 0x4000, 0xb, 0x10));
    CHECK(!auxkc_observe_retype(&s, &r, PA + SPAN, 0xb, 0x10));
    CHECK(auxkc_observe_retype(&s, &r, PA + 0x2c000, 0xb, 0x10));
    CHECK(s.retypes == 1 && s.last_retype_pa == PA + 0x2c000 &&
          s.last_retype_types == ((0xbUL << 32) | 0x10));

    /* Saturating counters. */
    s.map_pages = UINT64_MAX;
    auxkc_observe_leaf(&s, &r, AUXKC_KIND_MAP, 1, BASE, RX, RX);
    CHECK(s.map_pages == UINT64_MAX);

    printf("auxkc-observe: %u checks, %u failures\n", checks, failures);
    return failures != 0;
}

/* SPDX-License-Identifier: MIT */
/* The real SPTM model under a concurrent table reader
 * (tools/test-descriptor-stores.py).
 *
 *   test-descriptor-stores-model ROUNDS
 *
 * Each round builds tools/test-sptm-user-unmap.c's live format-1 fixture (the
 * 4K user tables the hardware walks with SNAP_USER_HW_WALK), maps 64 fresh
 * leaves with sptm_mac_map_user_page and removes them with one
 * sptm_mac_unmap_user_region, while a second thread reads the 64 level-3
 * slots with single 64-bit loads, as another CPU's table walker would. A slot
 * only ever holds 0 or its own leaf; any other value the reader sees is a
 * torn descriptor (v67: a leaf seen with its low four bytes written and its
 * high four still zero). Prints "torn N of M reads; F failed checks" and
 * exits nonzero if any fixture check failed. */
#define SPTM_UNMAP_FIXTURE
#include "test-sptm-user-unmap.c"
#include <inttypes.h>
#include <pthread.h>
#include <stdlib.h>

#define LEAVES 64u
static volatile uint64_t *slots[LEAVES];
static uint64_t legit[LEAVES];
static volatile int stop;
static uint64_t reads, torn, torn_value;

static void *reader(void *arg)
{
    (void)arg;
    while (!__atomic_load_n(&stop, __ATOMIC_ACQUIRE))
        for (unsigned i = 0; i < LEAVES; i++) {
            uint64_t v = __atomic_load_n(slots[i], __ATOMIC_RELAXED);
            reads++;
            if (v && v != legit[i]) {torn++; torn_value = v;}
        }
    return 0;
}

int main(int argc, char **argv)
{
    unsigned rounds = argc > 1 ? (unsigned)strtoul(argv[1], 0, 0) : 2000;
    const unsigned fmt = 1;
    (void)hw_slot;                      /* the fixture's, unused here */
    const uint64_t size = 4096, va = 0x4000;
    setup_remove(fmt);
    for (unsigned i = 0; i < LEAVES; i++) {
        uint64_t pa = source_slot(fmt, va + i * size);
        slots[i] = (volatile uint64_t *)(ram + (pa - BASE));
        legit[i] = (DATA + (uint64_t)(i & 3) * 4096) | 0x0060000000000e43UL | ((i & 1) ? 0x80 : 0);
    }
    pthread_t t;
    if (pthread_create(&t, 0, reader, 0)) return 2;
    for (unsigned r = 0; r < rounds; r++) {
        if (r) setup_remove(fmt);
        for (unsigned i = 0; i < LEAVES; i++)
            if (insert(fmt, va + i * size, i & 1, i & 3) != legit[i]) failures++;
        if (remove_pages(va, LEAVES, 1, BASE) != SPTM_OK) failures++;
    }
    __atomic_store_n(&stop, 1, __ATOMIC_RELEASE);
    pthread_join(t, 0);
    printf("torn %" PRIu64 " of %" PRIu64 " reads (last %#" PRIx64 "); %u failed checks of %u\n",
           torn, reads, torn_value, failures, checks);
    return failures ? 1 : 0;
}

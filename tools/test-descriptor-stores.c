/* SPDX-License-Identifier: MIT */
/* Concurrent reader stress for the SPTM model's descriptor stores
 * (compat/sptm-access.h; tools/test-descriptor-stores.py).
 *
 *   test-descriptor-stores STORE MILLIONS
 *
 * STORE is "bytes" (the helper every model file had until v67: eight volatile
 * byte stores, lowest first) or "put64" (sptm_put64). One thread writes a
 * table slot the way MAP_PAGE and UNMAP do (empty, then v67's leaf, then
 * empty again, and a second leaf whose high half differs) while another
 * reads it with single 64-bit loads, as the hardware walker does, and counts
 * every value it saw that was never written: a torn descriptor. Prints
 * "torn N of M reads" and exits 0; the caller decides what N must be. A
 * misaligned slot exercises the byte fallback for its value only. */
#include <inttypes.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sptm-access.h"

static void put_bytes_v67(volatile uint8_t *p, uint64_t v)
{
    for (unsigned i = 0; i < 8; i++) p[i] = (uint8_t)(v >> (8 * i));
}

static _Alignas(64) volatile uint64_t slot[8];
static volatile int done;
static uint64_t reads, torn, last_torn;
static uint64_t written[4];

static void *reader(void *arg)
{
    (void)arg;
    while (!__atomic_load_n(&done, __ATOMIC_ACQUIRE)) {
        uint64_t v = __atomic_load_n(&slot[0], __ATOMIC_RELAXED);
        reads++;
        if (v != written[0] && v != written[1] && v != written[2] && v != written[3]) {torn++; last_torn = v;}
    }
    return 0;
}

int main(int argc, char **argv)
{
    if (argc != 3) {fprintf(stderr, "usage: test-descriptor-stores bytes|put64 MILLIONS\n"); return 2;}
    int old = !strcmp(argv[1], "bytes");
    if (!old && strcmp(argv[1], "put64")) return 2;
    uint64_t n = strtoull(argv[2], 0, 0) * 1000000;
    /* v67's leaf (OA 0x960e3f000, a user RW page) and one whose OA's high
     * half differs; empty slots between them, as an unmap and a map. */
    written[0] = 0;
    written[1] = UINT64_C(0x0060000960e3f7c3);
    written[2] = 0;
    written[3] = UINT64_C(0x00e000a5a5ce37c3);
    pthread_t t;
    if (pthread_create(&t, 0, reader, 0)) return 2;
    volatile uint8_t *p = (volatile uint8_t *)&slot[0];
    for (uint64_t i = 0; i < n; i++) {
        uint64_t v = written[i & 3];
        if (old) put_bytes_v67(p, v); else sptm_put64(p, v);
    }
    __atomic_store_n(&done, 1, __ATOMIC_RELEASE);
    pthread_join(t, 0);
    /* The byte fallback, misaligned, still writes the whole value. */
    volatile uint8_t *odd = (volatile uint8_t *)&slot[2] + 3;
    sptm_put64(odd, UINT64_C(0x0123456789abcdef));
    int fallback_ok = sptm_get64(odd) == UINT64_C(0x0123456789abcdef) &&
                      sptm_get64((volatile uint8_t *)&slot[0]) == slot[0];
    printf("torn %" PRIu64 " of %" PRIu64 " reads (last %#" PRIx64 "); fallback %s\n",
           torn, reads, last_torn, fallback_ok ? "ok" : "WRONG");
    return fallback_ok ? 0 : 1;
}

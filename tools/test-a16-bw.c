/* SPDX-License-Identifier: MIT */
/* tools/a16-bw-stub.S, the same instructions the A16 runs at EL2, assembled with -DBW_HOST and run on this Mac at
 * EL0 (CNTVCT for CNTPCT): argument refusals, every kernel, the report layout the host tool decodes, the chase's
 * full cycle. Writes the report words to argv[1] for tools/measure-a16-memory-bandwidth.py --decode-host.
 *
 *   clang -O1 -g -Wall -Wextra -Werror -DBW_HOST tools/test-a16-bw.c tools/a16-bw-stub.S -o /tmp/test-a16-bw && /tmp/test-a16-bw R.bin
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void a16_bw(uint64_t *report, void *base, uint64_t bytes, uint64_t passes_kernels);

static unsigned checks, failures;
#define CHECK(c, ...) do { checks++; if (!(c)) { failures++; fprintf(stderr, "FAIL: " __VA_ARGS__); fputc('\n', stderr); } } while (0)

int main(int argc, char **argv)
{
    uint64_t report[80];
    void *base = NULL;
    uint64_t bytes = 64ull << 20;
    CHECK(!posix_memalign(&base, 1 << 16, 2 * bytes), "allocate");
    memset(base, 0x5a, 2 * bytes);
    /* Refusals: passes 0 and 17, bytes not a power of two, below 4 KiB, misaligned base. */
    const struct { uint64_t bytes, arg; uintptr_t off; } bad[] = {
        {bytes, 0 | 15u << 16, 0}, {bytes, 17 | 15u << 16, 0}, {3u << 20, 1 | 15u << 16, 0},
        {2048, 1 | 15u << 16, 0}, {bytes, 1 | 15u << 16, 8}};
    for (unsigned i = 0; i < sizeof bad / sizeof *bad; i++) {
        memset(report, 0xee, sizeof report);
        a16_bw(report, (char *)base + bad[i].off, bad[i].bytes, bad[i].arg);
        CHECK(report[1] == 3 && report[10] == 1, "bad argument case %u refused with status 3 (got %llu)", i,
              (unsigned long long)report[1]);
    }
    memset(report, 0, sizeof report);
    a16_bw(report, base, bytes, 6 | 15u << 16);
    CHECK(report[0] == 0x3130305742363141ull, "magic A16BW001");
    CHECK(report[1] == 0 && report[10] == 1, "status 0, done");
    CHECK(report[3] > 0 && report[4] == bytes && report[5] == 6 && report[6] == 15, "header fields");
    double hz = (double)report[3];
    const char *names[3] = {"read", "write", "copy"};
    for (unsigned k = 0; k < 3; k++) {
        double best = 0;
        for (unsigned p = 0; p < 6; p++) {
            uint64_t t = report[16 + 16 * k + p];
            CHECK(t > 0, "%s pass %u timed", names[k], p);
            double gbs = (double)bytes / ((double)t / hz) / 1e9;
            if (gbs > best) best = gbs;
        }
        printf("host %s: best %.1f GB/s over %llu MiB\n", names[k], best, (unsigned long long)(bytes >> 20));
        CHECK(best > 1.0, "%s faster than 1 GB/s on this Mac", names[k]);
    }
    uint64_t lines = bytes >> 6;
    CHECK(report[8] == lines && report[9] == (uint64_t)(uintptr_t)base, "chase: %llu steps, one cycle back to A",
          (unsigned long long)lines);
    double ns = (double)report[65] / hz * 1e9 / (double)lines;
    double seq_ns = (double)report[16] / hz * 1e9 / (double)lines;
    printf("host chase: %.1f ns per dependent load (sequential read: %.2f ns per line)\n", ns, seq_ns);
    CHECK(ns > 4 * seq_ns, "the chase defeats the prefetcher (%.1f ns vs %.2f ns sequential)", ns, seq_ns);
    /* Every line visited exactly once: follow the chain and mark. */
    unsigned char *seen = calloc(lines, 1);
    uint64_t at = (uint64_t)(uintptr_t)base, n = 0, dup = 0;
    do {
        uint64_t idx = (at - (uint64_t)(uintptr_t)base) >> 6;
        if (seen[idx]) dup++;
        seen[idx] = 1;
        at = *(uint64_t *)(uintptr_t)at;
        n++;
    } while (at != (uint64_t)(uintptr_t)base && n <= lines);
    CHECK(n == lines && !dup, "the chain is one cycle over every line (%llu steps, %llu repeats)",
          (unsigned long long)n, (unsigned long long)dup);
    free(seen);
    if (argc > 1) {
        FILE *f = fopen(argv[1], "wb");
        if (f) { fwrite(report, 1, sizeof report, f); fclose(f); }
    }
    free(base);
    printf("%s: %u checks, %u failures\n", failures ? "FAIL" : "PASS", checks, failures);
    return failures != 0;
}

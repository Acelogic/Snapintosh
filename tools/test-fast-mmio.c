/* SPDX-License-Identifier: MIT */
/* SNAP_FAST_IDLE_POLL (compat/fast-mmio.h): the lock-free idle-poll answer must
 * be exactly what the locked model access returns, for every access it takes.
 * Every offset, width and direction of several model kinds goes through the
 * match predicate and through device_models_access_power_at on a copy of all
 * model states: a match must be a DEVICE_OK read of zero that leaves every
 * state byte-identical, and every ACC perf model's +0x20 read must match.
 *
 * Failure inventory this covers (docs/FAST-TRAP-BATCH2-20261016.md failure
 * mode 1): another offset, width or a write of an ACC perf model taken fast;
 * another model kind taken fast; an access the model refuses or answers with
 * a nonzero value or a state change taken fast; the idle poll itself missed.
 *
 * cc -std=gnu11 -O1 -g -fsanitize=address,undefined -fno-sanitize-recover=all \
 *    -Icompat -Ishadow tools/test-fast-mmio.c compat/device.c compat/mmio.c \
 *    compat/sep-bootstrap.c compat/sep-pnon.c compat/aes.c compat/aic.c compat/dart.c \
 *    compat/sep-sks-endpoint.c compat/sep-xars.c compat/watchdog.c \
 *    -o build/test-fast-mmio && build/test-fast-mmio
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "fast-mmio.h"

static unsigned long long checks;
#define CHECK(x) do {checks++;if(!(x)){fprintf(stderr,"line %d: %s\n",__LINE__,#x);exit(1);}}while(0)

static int gfx_idle(void *ctx) {(void)ctx;return 1;}

int main(void)
{
    static const struct device_model models[] = {
        {DEVICE_PMGR_ACC_PERF_RESTORE_V1, 0x210e20000UL, 0x2000, {0,0,0,0,0}},
        {DEVICE_PMGR_ACC_PERF_RESTORE_V1, 0x211e20000UL, 0x2000, {1,0,0,0,0}},
        {DEVICE_PMGR_SOC_PERF_RESTORE_V1, 0x210e30000UL, 0x2000, {0,0,0,0,0}},
        {DEVICE_PMGR_ACC_BOOT_POLICY_V1, 0x210e40000UL, 0x1000, {0,0,0,0,0}},
        {DEVICE_WATCHDOG_WD1_V1, 0x3082b0000UL, 0x4000, {24000000,0,0,0,0}},
    };
    enum {COUNT = sizeof models / sizeof *models};
    static struct device_state states[COUNT], copy[COUNT];
    CHECK(device_models_valid(models, COUNT, 0, 0));
    for (unsigned i = 0; i < COUNT; i++)
        CHECK(device_model_start(&models[i], &states[i], 100, 24000000) == DEVICE_OK);
    const struct device_power_resources resources = {0, gfx_idle};
    static const unsigned widths[] = {1, 2, 4, 8};
    unsigned matches = 0, acc_models = 0, ok_reads = 0, compared = 0;
    for (unsigned i = 0; i < COUNT; i++) {
        acc_models += models[i].kind == DEVICE_PMGR_ACC_PERF_RESTORE_V1;
        for (uint64_t offset = 0; offset < models[i].span; offset++)
        for (unsigned w = 0; w < 4; w++)
        for (int write = 0; write < 2; write++) {
            if ((offset & 3) && widths[w] > 1 && offset > 0x40) continue;   /* unaligned: near the poll only */
            int match = fast_idle_poll_model(&models[i], offset, widths[w], write);
            memcpy(copy, states, sizeof copy);
            uint64_t value = write ? 0x1122334455667788ULL : 0xdeadbeefcafef00dULL;
            enum device_result r = device_models_access_power_at(models, copy, COUNT, i, 1000,
                offset, widths[w], write, &value, &resources);
            compared++;
            if (r == DEVICE_OK && !write) ok_reads++;
            if (match) {
                CHECK(r == DEVICE_OK && !write && value == 0);
                CHECK(!memcmp(copy, states, sizeof copy));
                CHECK(models[i].kind == DEVICE_PMGR_ACC_PERF_RESTORE_V1 && offset == FAST_IDLE_POLL_OFFSET);
                matches++;
            }
        }
    }
    /* Exactly the idle poll of each ACC perf model, and nothing else. */
    CHECK(matches == acc_models && acc_models == 2);
    for (unsigned i = 0; i < COUNT; i++)
        CHECK(fast_idle_poll_model(&models[i], FAST_IDLE_POLL_OFFSET, 8, 0) ==
              (models[i].kind == DEVICE_PMGR_ACC_PERF_RESTORE_V1));
    printf("PASS: %llu fast-mmio checks over %u accesses (%u idle-poll matches, %u locked successful reads)\n",
           checks, compared, matches, ok_reads);
    return 0;
}

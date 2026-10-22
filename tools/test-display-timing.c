/* SPDX-License-Identifier: MIT */
/* compat/display-timing.h: the monitor's allow-list for --present-beam's read-only INTF_5 page
 * (agents/tear-free FAILURE-MODES.md A1 A3 E3).
 *   xcrun clang -std=c11 -Wall -Wextra -Werror -fsanitize=address,undefined -Ishadow -Icompat \
 *       tools/test-display-timing.c -o /tmp/test-display-timing && /tmp/test-display-timing */
#include <stdio.h>
#include <string.h>
#include "display-timing.h"

static unsigned checks, failures;
#define CHECK(c) do { checks++; if (!(c)) { failures++; fprintf(stderr, "FAIL %s:%d %s\n", __FILE__, __LINE__, #c); } } while (0)

static int refused(struct display_timing_params p)
{
    struct stage2_range out[2];
    memset(out, 0x5a, sizeof out);
    int rows = display_timing_rows(&p, out);
    unsigned char untouched = 1;
    for (size_t i = 0; i < sizeof out; i++) untouched &= ((unsigned char *)out)[i] == 0x5a;
    return rows == -1 && untouched && !display_timing_window(&p, DPU_INTF_PA);
}

int main(void)
{
    const struct display_timing_params good = {DISPLAY_TIMING_MAGIC, DISPLAY_TIMING_F_INTF, DPU_INTF_PA,
                                               DPU_INTF_PA + DPU_INTF_PAGE};
    /* A1: one page, at the derived address */
    CHECK(DPU_INTF_PA == 0x0AE3A000ULL && DPU_INTF_PA == DPU_MDP_PA + DPU_INTF_FIRST + 5 * DPU_INTF_STRIDE);
    CHECK(DISPLAY_TIMING_MAGIC == 0x3155504450414e53ULL && !memcmp(&good.magic, "SNAPDPU1", 8));
    struct stage2_range out[DISPLAY_TIMING_STAGE2_MAX + 1];
    memset(out, 0, sizeof out);
    CHECK(display_timing_rows(&good, out) == 1);
    /* A3: read-only, Device-nGnRE, execute-never, identity */
    CHECK(out[0].lo == 0x0AE3A000ULL && out[0].hi == 0x0AE3B000ULL);
    CHECK(out[0].low == (S2_AP_RO | S2_ATTRS_DEVICE) && out[0].upper == S2_XN && out[0].low == 0x744);
    CHECK(!(out[0].low & (2UL << 6)));                                     /* S2AP write bit clear */
    CHECK(out[1].lo == 0 && out[1].hi == 0);                               /* exactly one row */
    CHECK(display_timing_window(&good, DPU_INTF_PA) && display_timing_window(&good, DPU_INTF_PA + 0xffc));
    CHECK(!display_timing_window(&good, DPU_INTF_PA - 4) && !display_timing_window(&good, DPU_INTF_PA + 0x1000));
    CHECK(!display_timing_window(&good, DPU_MDSS_PA) && !display_timing_window(&good, DPU_MDP_PA));
    /* E3: anything else refuses, and writes nothing */
    struct display_timing_params p = good; p.magic ^= 1; CHECK(refused(p));
    struct display_timing_params zero; memset(&zero, 0, sizeof zero); CHECK(refused(zero));   /* a loader without the block */
    p = good; p.flags = 0; CHECK(refused(p));
    p = good; p.flags = 3; CHECK(refused(p));
    p = good; p.intf_pa = DPU_INTF_PA + 0x1000; p.intf_end = p.intf_pa + 0x1000; CHECK(refused(p));   /* intf_6 */
    p = good; p.intf_pa = DPU_MDP_PA; p.intf_end = DPU_MDP_PA + 0x1000; CHECK(refused(p));           /* mdp top */
    p = good; p.intf_end = DPU_INTF_PA + 0x2000; CHECK(refused(p));                                  /* wider */
    p = good; p.intf_end = DPU_INTF_PA; CHECK(refused(p));                                           /* empty */
    printf("{\"display_timing_checks\":%u,\"display_timing_failures\":%u}\n", checks, failures);
    return failures != 0;
}

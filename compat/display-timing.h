/* SPDX-License-Identifier: MIT */
/*
 * Opt-in read-only passthrough of the eDP interface's timing engine page (DPU INTF_5, compat/dpu-intf.h) for the
 * AdrenoDisplay kext's beam (-DADRENO_BEAM=1, --present-beam): -DSNAP_DISPLAY_TIMING=1 only. Without the define
 * probes/xnuboot.c does not include this header and the monitor is the same binary as before.
 *
 * What the guest reaches: exactly one 4 KiB page, 0x0AE3A000, identity-mapped at stage 2 as Device-nGnRE, READ-ONLY,
 * execute-never. The kext reads LINE_COUNT, FRAME_COUNT and the timing registers; a guest store anywhere in it is a
 * stage-2 permission fault that stops the run, never a bus write, and every other MDSS address stays absent (a
 * stage-2 fault with the IPA). Nothing in the DPU is written by the monitor either. agents/tear-free FAILURE-MODES.md A.
 *
 * The loader (probes/displaytiming.py) appends struct display_timing_params after struct params (after the QCC2072
 * block when -DSNAP_QCC2072_WIFI=1 is built in too) and advertises the page on the GPU node. The monitor maps nothing
 * from the loader's numbers: it checks them against the constants below and refuses the boot (-43 from the stage-2
 * preparation) on any difference, so a loader without the block (magic mismatch) cannot be read as a window.
 */
#pragma once
#include <stdint.h>
#include "stage2.h"
#include "dpu-intf.h"

/* "SNAPDPU1", little-endian: the loader appended these words on purpose. */
#define DISPLAY_TIMING_MAGIC        0x3155504450414e53ULL
#define DISPLAY_TIMING_F_INTF       1u      /* INTF_5's page, read-only */
#define DISPLAY_TIMING_PARAMS_WORDS 4
#define DISPLAY_TIMING_STAGE2_MAX   1u

struct display_timing_params {
    uint64_t magic;                         /* DISPLAY_TIMING_MAGIC */
    uint64_t flags;                         /* DISPLAY_TIMING_F_INTF */
    uint64_t intf_pa, intf_end;             /* DPU_INTF_PA, DPU_INTF_PA + DPU_INTF_PAGE */
};
_Static_assert(sizeof(struct display_timing_params) == 8 * DISPLAY_TIMING_PARAMS_WORDS,
               "probes/displaytiming.py PARAMS_WORDS");
_Static_assert(DPU_INTF_PA == 0x0AE3A000ULL && !(DPU_INTF_PA & 0xfff), "INTF_5: mdp 0x0ae01000 + 0x39000");

/* The stage-2 row of a valid parameter block, written to out (room for DISPLAY_TIMING_STAGE2_MAX). Returns 1, or -1
 * when the magic, the flags or the page differ from the constants. Writes nothing on -1. */
static inline int display_timing_rows(const struct display_timing_params *p, struct stage2_range *out)
{
    if (p->magic != DISPLAY_TIMING_MAGIC || p->flags != DISPLAY_TIMING_F_INTF ||
        p->intf_pa != DPU_INTF_PA || p->intf_end != DPU_INTF_PA + DPU_INTF_PAGE)
        return -1;
    out[0] = (struct stage2_range){DPU_INTF_PA, DPU_INTF_PA + DPU_INTF_PAGE, S2_AP_RO | S2_ATTRS_DEVICE, S2_XN};
    return 1;
}

/* Whether pa lies in the page of a valid block (MAP_PAGE's evidence classification only). */
static inline int display_timing_window(const struct display_timing_params *p, uint64_t pa)
{
    struct stage2_range row[DISPLAY_TIMING_STAGE2_MAX];
    return display_timing_rows(p, row) == 1 && pa >= row[0].lo && pa < row[0].hi;
}

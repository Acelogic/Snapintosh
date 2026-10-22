/* SPDX-License-Identifier: MIT */
/*
 * Opt-in built-in keyboard (and, once qualified, touchpad) passthrough for the
 * SnapI2CHID kext (drivers/snap-i2c-hid/): -DSNAP_I2C_INPUT=1 only. Without the
 * define probes/xnuboot.c does not include this header and the monitor is the
 * same binary as before.
 *
 * What the guest reaches: exactly one 4 KiB page of each enabled GENI serial
 * engine, identity-mapped at stage 2 as Device-nGnRE, read-write, execute-never.
 * Every register the driver touches is in that page (GENI_HW_PARAM_1 at 0xe28 is
 * the highest). The rest of each 16 KiB QUP window (the SE DMA interface at
 * +0x2000 and up), the TLMM, the GIC and every other address stay absent, so a
 * touch outside the page is a stage-2 fault that stops the run (EV_S2_FAULT with
 * the IPA). No interrupt is routed: the kext polls with M_IRQ_EN = 0.
 *
 * The loader (probes/i2cinput.py) appends struct i2c_input_params to struct
 * params and adds the matching device-tree node. The monitor maps nothing from
 * the loader's numbers: it checks them against the allow-list below and refuses
 * the boot (-41 from the stage-2 preparation) on any difference, so a params
 * blob shorter than this structure (a loader without input) cannot be read as
 * a window. docs/A16-INPUT-INSTALLED-20261017.md.
 */
#pragma once
#include <stdint.h>
#include "stage2.h"

/* "SNAPI2C1", little-endian: the loader appended these words on purpose. */
#define I2C_INPUT_MAGIC        0x3143324950414e53ULL
#define I2C_INPUT_F_KEYBOARD   1u   /* ECKB/QTEC0001, IC20 (QUP_2_SE_3), address 0x15 */
#define I2C_INPUT_F_TOUCHPAD   2u   /* TCPD/ASUF1209, I2C1 (Linux i2c0), address 0x15 */
#define I2C_INPUT_F_ALL        (I2C_INPUT_F_KEYBOARD | I2C_INPUT_F_TOUCHPAD)
#define I2C_INPUT_KEYBOARD_PA  0x0088C000ULL   /* A16 DSDT IC20 _CRS; glymur.dtsi i2c19 */
#define I2C_INPUT_TOUCHPAD_PA  0x00B80000ULL   /* A16 DSDT I2C1 _CRS; glymur.dtsi i2c0 */
#define I2C_INPUT_PAGE         0x1000ULL
#define I2C_INPUT_STAGE2_MAX   2u
#define I2C_INPUT_PARAMS_WORDS 6

struct i2c_input_params {
    uint64_t magic;                      /* I2C_INPUT_MAGIC */
    uint64_t flags;                      /* I2C_INPUT_F_*, at least one */
    uint64_t keyboard_pa, keyboard_end;  /* the page, or 0, 0 when disabled */
    uint64_t touchpad_pa, touchpad_end;
};
_Static_assert(sizeof(struct i2c_input_params) == 8 * I2C_INPUT_PARAMS_WORDS,
               "probes/i2cinput.py PARAMS_WORDS");

/* The stage-2 rows of a valid parameter block, written to out (room for
 * I2C_INPUT_STAGE2_MAX). Returns the row count, or -1 when the magic, the
 * flags or any address differs from the allow-list. Writes nothing on -1. */
static inline int i2c_input_rows(const struct i2c_input_params *p, struct stage2_range *out)
{
    const uint64_t pa[2] = {I2C_INPUT_KEYBOARD_PA, I2C_INPUT_TOUCHPAD_PA};
    const uint64_t lo[2] = {p->keyboard_pa, p->touchpad_pa};
    const uint64_t hi[2] = {p->keyboard_end, p->touchpad_end};
    int n = 0;

    if (p->magic != I2C_INPUT_MAGIC || !p->flags || (p->flags & ~(uint64_t)I2C_INPUT_F_ALL))
        return -1;
    for (unsigned i = 0; i < 2; i++) {
        if (p->flags & (1u << i)) {
            if (lo[i] != pa[i] || hi[i] != pa[i] + I2C_INPUT_PAGE)
                return -1;
        } else if (lo[i] || hi[i]) {
            return -1;
        }
    }
    for (unsigned i = 0; i < 2; i++)
        if (p->flags & (1u << i))
            out[n++] = (struct stage2_range){pa[i], pa[i] + I2C_INPUT_PAGE,
                                             S2_AP_RW | S2_ATTRS_DEVICE, S2_XN};
    return n;
}

/* Whether pa lies in an enabled page of a valid block (MAP_PAGE's evidence
 * classification only; nothing is admitted or refused by it). */
static inline int i2c_input_window(const struct i2c_input_params *p, uint64_t pa)
{
    struct stage2_range rows[I2C_INPUT_STAGE2_MAX];
    int n = i2c_input_rows(p, rows);
    for (int i = 0; i < n; i++)
        if (pa >= rows[i].lo && pa < rows[i].hi)
            return 1;
    return 0;
}

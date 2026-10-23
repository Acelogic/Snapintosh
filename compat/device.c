/* SPDX-License-Identifier: MIT */
#include "device.h"
#include "ans.h"

_Static_assert(sizeof(struct device_model) == DEVICE_MODEL_WORDS * 8,
               "device descriptor loader ABI");

static int sep_binding(const struct device_model *models, unsigned count,
                       unsigned *pmgr, unsigned *pmp, unsigned *dart);
static int ane_binding(const struct device_model *models, unsigned count,
                       unsigned *pmgr, unsigned *pmp, unsigned banks[3]);
static int sep_asc_valid(const struct device_sep_asc *s, unsigned transport);
static enum device_result sep_asc_receive(struct device_sep_asc *s, uint64_t values[2]);
static enum device_result spmi_access(const struct device_model *d,
    struct device_state *s, uint64_t now, uint64_t offset, unsigned width,
    int write, uint64_t *value);

#include "device/device_core.c"
#include "device/device_rtc.c"
#include "device/device_dock_dart.c"
#include "device/device_asc.c"
#include "device/device_i2c.c"
#include "device/device_pmgr.c"
#include "device/device_power.c"
#include "device/device_state.c"

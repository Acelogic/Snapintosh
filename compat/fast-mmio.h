/* SPDX-License-Identifier: MIT */
/* Lock-free answers to device reads whose model keeps no state for them
 * (SNAP_FAST_IDLE_POLL, probes/xnuboot.c). The monitor routes the data abort
 * exactly as its locked path does (device windows first, then
 * device_model_find) and asks this predicate about the model it found.
 * docs/FAST-TRAP-BATCH2-20261016.md; tools/test-fast-mmio.c checks every
 * offset, width and direction of several model kinds against the locked
 * device_models_access_power_at. */
#pragma once
#include <stdint.h>
#include "device.h"

/* cpuComplexIdleEnter polls the ACC DVFS command interlock before every idle
 * entry (5.8M of a 600 s boot's data aborts). DEVICE_PMGR_ACC_PERF_RESTORE_V1
 * answers an aligned 8-byte read of +0x20 with zero and touches no state. */
#define FAST_IDLE_POLL_OFFSET 0x20u
static inline int fast_idle_poll_model(const struct device_model *m,uint64_t offset,
                                       unsigned size,int write)
{
    return m && m->kind==DEVICE_PMGR_ACC_PERF_RESTORE_V1 && !write && size==8 &&
           offset==FAST_IDLE_POLL_OFFSET;
}

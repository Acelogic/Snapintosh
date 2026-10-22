/* SPDX-License-Identifier: MIT */
#ifndef SNAP_CPU_RUNTIME_H
#define SNAP_CPU_RUNTIME_H
#include "cpu.h"
#define GUEST_RUNTIME_PAGE UINT64_C(0x1000)
#define GUEST_RUNTIME_STACK UINT64_C(0x10000)
struct guest_cpu_storage { uint64_t vncr, output, stack_low, stack_high; };
/* Plan one VNCR per CPU and output/stack storage for each secondary before
 * publishing any pointer. CPU0 retains its caller stack/output. Failure leaves
 * the plan and end unchanged. The caller zeros and owns the allocated range. */
int guest_cpu_storage_plan(uint64_t begin, uint64_t limit,
    struct guest_cpu_storage out[GUEST_CPU_COUNT], uint64_t *end);
#endif

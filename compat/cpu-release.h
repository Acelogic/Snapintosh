/* SPDX-License-Identifier: MIT */
#ifndef SNAP_CPU_RELEASE_H
#define SNAP_CPU_RELEASE_H
#include <stdint.h>
struct guest_cpu_release { uint64_t armed, issued; };
/* A live backend accepts one release at a time. No reads or power-completion
 * values are fabricated. Offsets are relative to the PMGR CPU-start block;
 * global bits 1..5 map to E-cluster bits1..3 and P-cluster bits0..1. */
int guest_cpu_release_write(struct guest_cpu_release *state,uint64_t allowed,
    uint64_t offset,unsigned width,uint64_t value,
    int (*launch)(void *,unsigned),void *context);
#endif
